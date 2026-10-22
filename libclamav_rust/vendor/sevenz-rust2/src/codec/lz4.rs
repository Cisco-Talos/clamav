#[cfg(feature = "compress")]
use std::io::Write;
use std::io::{Cursor, Read};

use lz4_flex::frame::FrameDecoder;
#[cfg(feature = "compress")]
use lz4_flex::frame::{FrameEncoder, FrameInfo};

#[cfg(feature = "compress")]
use crate::ByteWriter;
use crate::{ByteReader, Error};

/// Magic bytes of a skippable frame as used in LZ4 by zstdmt.
const SKIPPABLE_FRAME_MAGIC: u32 = 0x184D2A50;

/// Custom decoder to support the custom format first implemented by zstdmt, which allows to have
/// optional skippable frames.
pub(crate) struct Lz4Decoder<R: Read> {
    inner: Option<FrameDecoder<InnerReader<R>>>,
}

impl<R: Read> Lz4Decoder<R> {
    pub(crate) fn new(mut input: R) -> Result<Self, Error> {
        let mut header = [0u8; 12];
        let header_read = match Read::read(&mut input, &mut header) {
            Ok(n) if n >= 4 => n,
            Ok(_) => return Err(Error::other("Input too short")),
            Err(e) => return Err(e.into()),
        };

        let magic_value = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);

        let inner_reader = if magic_value == SKIPPABLE_FRAME_MAGIC && header_read >= 12 {
            let skippable_size = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);
            if skippable_size != 4 {
                return Err(Error::other("Invalid lz4 skippable frame size"));
            }

            let compressed_size =
                u32::from_le_bytes([header[8], header[9], header[10], header[11]]);

            InnerReader::new_skippable(input, compressed_size)
        } else {
            InnerReader::new_standard(input, header[..header_read].to_vec())
        };

        let decoder = FrameDecoder::new(inner_reader);

        Ok(Lz4Decoder {
            inner: Some(decoder),
        })
    }
}

impl<R: Read> Read for Lz4Decoder<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if let Some(inner) = &mut self.inner {
            match inner.read(buf) {
                Ok(0) => {
                    let inner_reader = inner.get_mut();

                    if inner_reader.read_next_frame_header()? {
                        let reader = std::mem::replace(inner_reader, InnerReader::empty());
                        let mut deencoder = FrameDecoder::new(reader);
                        let result = deencoder.read(buf);
                        self.inner = Some(deencoder);
                        result
                    } else {
                        self.inner = None;
                        Ok(0)
                    }
                }
                result => result,
            }
        } else {
            Ok(0)
        }
    }
}

enum InnerReader<R: Read> {
    Empty,
    Standard {
        reader: R,
        header_buffer: Cursor<Vec<u8>>,
        header_finished: bool,
    },
    Skippable {
        reader: R,
        remaining_in_frame: u32,
        frame_finished: bool,
    },
}

impl<R: Read> InnerReader<R> {
    fn empty() -> Self {
        InnerReader::Empty
    }

    fn new_standard(reader: R, header: Vec<u8>) -> Self {
        InnerReader::Standard {
            reader,
            header_buffer: Cursor::new(header),
            header_finished: false,
        }
    }

    fn new_skippable(reader: R, remaining_in_frame: u32) -> Self {
        InnerReader::Skippable {
            reader,
            remaining_in_frame,
            frame_finished: false,
        }
    }

    fn read_next_frame_header(&mut self) -> std::io::Result<bool> {
        match self {
            InnerReader::Empty => Ok(false),
            InnerReader::Standard { .. } => Ok(false),
            InnerReader::Skippable {
                reader,
                remaining_in_frame,
                frame_finished,
            } => {
                if !*frame_finished {
                    return Ok(false);
                }

                match reader.read_u32() {
                    Ok(magic) => {
                        if magic != SKIPPABLE_FRAME_MAGIC {
                            return Ok(false);
                        }

                        let skippable_size = reader.read_u32()?;
                        if skippable_size != 4 {
                            return Ok(false);
                        }

                        let compressed_size = reader.read_u32()?;

                        *remaining_in_frame = compressed_size;
                        *frame_finished = false;

                        Ok(true)
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(false),
                    Err(e) => Err(e),
                }
            }
        }
    }
}

impl<R: Read> Read for InnerReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            InnerReader::Empty => Ok(0),
            InnerReader::Standard {
                reader,
                header_buffer,
                header_finished,
            } => {
                if !*header_finished {
                    let bytes_read = header_buffer.read(buf)?;
                    if bytes_read > 0 {
                        return Ok(bytes_read);
                    }
                    *header_finished = true;
                }
                reader.read(buf)
            }
            InnerReader::Skippable {
                reader,
                remaining_in_frame,
                frame_finished,
            } => {
                if *frame_finished || *remaining_in_frame == 0 {
                    return Ok(0);
                }

                let bytes_to_read = std::cmp::min(*remaining_in_frame as usize, buf.len());
                let bytes_read = reader.read(&mut buf[..bytes_to_read])?;

                if bytes_read == 0 {
                    *frame_finished = true;
                    return Ok(0);
                }

                *remaining_in_frame -= bytes_read as u32;
                if *remaining_in_frame == 0 {
                    *frame_finished = true;
                }

                Ok(bytes_read)
            }
        }
    }
}

/// Custom encoder to support the custom format first implemented by zstdmt, which allows to have
/// optional skippable frames.
#[cfg(feature = "compress")]
pub(crate) struct Lz4Encoder<W: Write> {
    inner: InnerWriter<W>,
}

#[cfg(feature = "compress")]
enum InnerWriter<W: Write> {
    Standard(FrameEncoder<W>),
    Framed {
        writer: W,
        frame_size: usize,
        compressed_data: Vec<u8>,
        uncompressed_data: Vec<u8>,
        uncompressed_data_size: usize,
    },
}

#[cfg(feature = "compress")]
impl<W: Write> Lz4Encoder<W> {
    pub(crate) fn new(writer: W, frame_size: usize) -> Result<Self, Error> {
        let inner = if frame_size == 0 {
            let encoder = FrameEncoder::new(writer);
            InnerWriter::Standard(encoder)
        } else {
            InnerWriter::Framed {
                writer,
                frame_size,
                compressed_data: Vec::with_capacity(frame_size),
                uncompressed_data: vec![0; frame_size],
                uncompressed_data_size: 0,
            }
        };

        Ok(Self { inner })
    }

    fn write_frame(
        writer: &mut W,
        compressed_data: &mut Vec<u8>,
        uncompressed_data: &[u8],
    ) -> std::io::Result<()> {
        if uncompressed_data.is_empty() {
            return Ok(());
        }
        compressed_data.clear();

        // zstdmt expects that the content size is set when using skippable frames with LZ4.
        let frame_info = FrameInfo::default().content_size(Some(uncompressed_data.len() as u64));
        let mut frame_encoder = FrameEncoder::with_frame_info(frame_info, compressed_data);
        frame_encoder.write_all(uncompressed_data)?;
        let compressed_data = frame_encoder.finish()?;

        if compressed_data.is_empty() {
            return Ok(());
        }

        writer.write_u32(SKIPPABLE_FRAME_MAGIC)?;
        writer.write_u32(4)?;
        writer.write_u32(compressed_data.len() as u32)?;
        writer.write_all(compressed_data.as_slice())?;

        Ok(())
    }

    pub fn finish(self) -> std::io::Result<W> {
        match self.inner {
            InnerWriter::Standard(encoder) => Ok(encoder.finish()?),
            InnerWriter::Framed {
                mut writer,
                mut compressed_data,
                uncompressed_data,
                uncompressed_data_size,
                ..
            } => {
                Self::write_frame(
                    &mut writer,
                    &mut compressed_data,
                    &uncompressed_data[..uncompressed_data_size],
                )?;
                Ok(writer)
            }
        }
    }
}

#[cfg(feature = "compress")]
impl<W: Write> Write for Lz4Encoder<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match &mut self.inner {
            InnerWriter::Standard(encoder) => encoder.write(buf),
            InnerWriter::Framed {
                writer,
                frame_size,
                compressed_data,
                uncompressed_data,
                uncompressed_data_size,
            } => {
                let mut bytes_consumed = 0;
                let total_bytes = buf.len();

                while bytes_consumed < total_bytes {
                    let available_space = *frame_size - *uncompressed_data_size;
                    let bytes_to_copy =
                        std::cmp::min(total_bytes - bytes_consumed, available_space);

                    uncompressed_data
                        [*uncompressed_data_size..*uncompressed_data_size + bytes_to_copy]
                        .copy_from_slice(&buf[bytes_consumed..bytes_consumed + bytes_to_copy]);

                    *uncompressed_data_size += bytes_to_copy;
                    bytes_consumed += bytes_to_copy;

                    if *uncompressed_data_size >= *frame_size {
                        Self::write_frame(
                            writer,
                            compressed_data,
                            &uncompressed_data[..*uncompressed_data_size],
                        )?;
                        *uncompressed_data_size = 0;
                    }
                }

                Ok(total_bytes)
            }
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match &mut self.inner {
            InnerWriter::Standard(encoder) => encoder.flush(),
            InnerWriter::Framed {
                writer,
                compressed_data,
                uncompressed_data,
                uncompressed_data_size,
                ..
            } => {
                Self::write_frame(
                    writer,
                    compressed_data,
                    &uncompressed_data[..*uncompressed_data_size],
                )?;
                *uncompressed_data_size = 0;
                writer.flush()
            }
        }
    }
}

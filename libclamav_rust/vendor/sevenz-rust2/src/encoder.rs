use std::io::Write;

use lzma_rust2::{
    Lzma2Writer, Lzma2WriterMt, LzmaWriter,
    filter::{bcj::BcjWriter, delta::DeltaWriter},
};

#[cfg(feature = "brotli")]
use crate::codec::brotli::BrotliEncoder;
#[cfg(feature = "lz4")]
use crate::codec::lz4::Lz4Encoder;
#[cfg(feature = "brotli")]
use crate::encoder_options::BrotliOptions;
#[cfg(feature = "bzip2")]
use crate::encoder_options::Bzip2Options;
#[cfg(feature = "deflate")]
use crate::encoder_options::DeflateOptions;
#[cfg(feature = "lz4")]
use crate::encoder_options::Lz4Options;
#[cfg(feature = "ppmd")]
use crate::encoder_options::PpmdOptions;
#[cfg(feature = "zstd")]
use crate::encoder_options::ZstandardOptions;
#[cfg(feature = "aes256")]
use crate::encryption::Aes256Sha256Encoder;
use crate::{
    Error,
    archive::{EncoderConfiguration, EncoderMethod},
    encoder_options::{DeltaOptions, EncoderOptions, Lzma2Options, LzmaOptions},
    writer::CountingWriter,
};

pub(crate) enum Encoder<W: Write> {
    Copy(CountingWriter<W>),
    Bcj(Option<BcjWriter<CountingWriter<W>>>),
    Delta(DeltaWriter<CountingWriter<W>>),
    Lzma(Option<LzmaWriter<CountingWriter<W>>>),
    Lzma2(Option<Lzma2Writer<CountingWriter<W>>>),
    Lzma2Mt(Option<Lzma2WriterMt<CountingWriter<W>>>),
    #[cfg(feature = "ppmd")]
    Ppmd(Option<Box<ppmd_rust::Ppmd7Encoder<CountingWriter<W>>>>),
    #[cfg(feature = "brotli")]
    Brotli(BrotliEncoder<CountingWriter<W>>),
    #[cfg(feature = "bzip2")]
    Bzip2(Option<bzip2::write::BzEncoder<CountingWriter<W>>>),
    #[cfg(feature = "deflate")]
    Deflate(Option<flate2::write::DeflateEncoder<CountingWriter<W>>>),
    #[cfg(feature = "lz4")]
    Lz4(Option<Lz4Encoder<CountingWriter<W>>>),
    #[cfg(feature = "zstd")]
    Zstd(Option<zstd::Encoder<'static, CountingWriter<W>>>),
    #[cfg(feature = "aes256")]
    Aes(Aes256Sha256Encoder<CountingWriter<W>>),
}

impl<W: Write> Write for Encoder<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // Some encoder need to finish the encoding process. Because of lifetime limitations on
        // dynamic dispatch, we need to implement an implicit contract, where empty writes with
        // "&[]" trigger the call to "finish()". We need to also make sure to propagate the empty
        // write into the inner writer, so that the whole chain of encoders can properly finish
        // their data stream. Not a great way to do it, but I couldn't get a proper dynamic
        // dispatch based approach to work.
        match self {
            Encoder::Copy(w) => w.write(buf),
            Encoder::Delta(w) => w.write(buf),
            Encoder::Bcj(w) => match buf.is_empty() {
                true => {
                    let writer = w.take().unwrap();
                    let mut inner = writer.finish()?;
                    inner.write(buf)?;
                    Ok(0)
                }
                false => w.as_mut().unwrap().write(buf),
            },
            Encoder::Lzma(w) => match buf.is_empty() {
                true => {
                    let writer = w.take().unwrap();
                    let mut inner = writer.finish()?;
                    let _ = inner.write(buf);
                    Ok(0)
                }
                false => w.as_mut().unwrap().write(buf),
            },
            Encoder::Lzma2(w) => match buf.is_empty() {
                true => {
                    let writer = w.take().unwrap();
                    let mut inner = writer.finish()?;
                    let _ = inner.write(buf);
                    Ok(0)
                }
                false => w.as_mut().unwrap().write(buf),
            },
            Encoder::Lzma2Mt(w) => match buf.is_empty() {
                true => {
                    let writer = w.take().unwrap();
                    let mut inner = writer.finish()?;
                    let _ = inner.write(buf);
                    Ok(0)
                }
                false => w.as_mut().unwrap().write(buf),
            },
            #[cfg(feature = "ppmd")]
            Encoder::Ppmd(w) => match buf.is_empty() {
                true => {
                    let writer = w.take().unwrap();
                    let mut inner = writer.finish(false)?;
                    let _ = inner.write(buf);
                    Ok(0)
                }
                false => w.as_mut().unwrap().write(buf),
            },
            // TODO: Also add a proper "finish" method here.
            #[cfg(feature = "brotli")]
            Encoder::Brotli(w) => w.write(buf),
            #[cfg(feature = "bzip2")]
            Encoder::Bzip2(w) => match buf.is_empty() {
                true => {
                    let writer = w.take().unwrap();
                    let mut inner = writer.finish()?;
                    let _ = inner.write(buf);
                    Ok(0)
                }
                false => w.as_mut().unwrap().write(buf),
            },
            #[cfg(feature = "deflate")]
            Encoder::Deflate(w) => match buf.is_empty() {
                true => {
                    let writer = w.take().unwrap();
                    let mut inner = writer.finish()?;
                    let _ = inner.write(buf);
                    Ok(0)
                }
                false => w.as_mut().unwrap().write(buf),
            },
            #[cfg(feature = "lz4")]
            Encoder::Lz4(w) => match buf.is_empty() {
                true => {
                    let writer = w.take().unwrap();
                    let mut inner = writer.finish()?;
                    let _ = inner.write(buf);
                    Ok(0)
                }
                false => w.as_mut().unwrap().write(buf),
            },
            #[cfg(feature = "zstd")]
            Encoder::Zstd(w) => match buf.is_empty() {
                true => {
                    let writer = w.take().unwrap();
                    let mut inner = writer.finish()?;
                    let _ = inner.write(buf);
                    Ok(0)
                }
                false => w.as_mut().unwrap().write(buf),
            },
            #[cfg(feature = "aes256")]
            Encoder::Aes(w) => w.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Encoder::Copy(w) => w.flush(),
            Encoder::Bcj(w) => w.as_mut().unwrap().flush(),
            Encoder::Delta(w) => w.flush(),
            Encoder::Lzma(w) => w.as_mut().unwrap().flush(),
            Encoder::Lzma2(w) => w.as_mut().unwrap().flush(),
            Encoder::Lzma2Mt(w) => w.as_mut().unwrap().flush(),
            #[cfg(feature = "brotli")]
            Encoder::Brotli(w) => w.flush(),
            #[cfg(feature = "ppmd")]
            Encoder::Ppmd(w) => w.as_mut().unwrap().flush(),
            #[cfg(feature = "bzip2")]
            Encoder::Bzip2(w) => w.as_mut().unwrap().flush(),
            #[cfg(feature = "deflate")]
            Encoder::Deflate(w) => w.as_mut().unwrap().flush(),
            #[cfg(feature = "lz4")]
            Encoder::Lz4(w) => w.as_mut().unwrap().flush(),
            #[cfg(feature = "zstd")]
            Encoder::Zstd(w) => w.as_mut().unwrap().flush(),
            #[cfg(feature = "aes256")]
            Encoder::Aes(w) => w.flush(),
        }
    }
}

pub(crate) fn add_encoder<W: Write>(
    input: CountingWriter<W>,
    method_config: &EncoderConfiguration,
) -> Result<Encoder<W>, Error> {
    let method = method_config.method;

    match method.id() {
        EncoderMethod::ID_COPY => Ok(Encoder::Copy(input)),
        EncoderMethod::ID_DELTA => {
            let options = match method_config.options {
                Some(EncoderOptions::Delta(options)) => options,
                _ => DeltaOptions::default(),
            };
            let dw = DeltaWriter::new(input, options.0 as usize);
            Ok(Encoder::Delta(dw))
        }
        EncoderMethod::ID_BCJ_X86 => Ok(Encoder::Bcj(Some(BcjWriter::new_x86(input, 0)))),
        EncoderMethod::ID_BCJ_ARM => Ok(Encoder::Bcj(Some(BcjWriter::new_arm(input, 0)))),
        EncoderMethod::ID_BCJ_ARM_THUMB => {
            Ok(Encoder::Bcj(Some(BcjWriter::new_arm_thumb(input, 0))))
        }
        EncoderMethod::ID_BCJ_ARM64 => Ok(Encoder::Bcj(Some(BcjWriter::new_arm64(input, 0)))),
        EncoderMethod::ID_BCJ_IA64 => Ok(Encoder::Bcj(Some(BcjWriter::new_ia64(input, 0)))),
        EncoderMethod::ID_BCJ_SPARC => Ok(Encoder::Bcj(Some(BcjWriter::new_sparc(input, 0)))),
        EncoderMethod::ID_BCJ_PPC => Ok(Encoder::Bcj(Some(BcjWriter::new_ppc(input, 0)))),
        EncoderMethod::ID_BCJ_RISCV => Ok(Encoder::Bcj(Some(BcjWriter::new_riscv(input, 0)))),
        EncoderMethod::ID_LZMA => {
            let options = match &method_config.options {
                Some(EncoderOptions::Lzma(options)) => options.clone(),
                _ => LzmaOptions::default(),
            };
            let lz = LzmaWriter::new_no_header(input, &options.0, false)?;
            Ok(Encoder::Lzma(Some(lz)))
        }
        EncoderMethod::ID_LZMA2 => {
            let lzma2_options = match &method_config.options {
                Some(EncoderOptions::Lzma2(options)) => options.clone(),
                _ => Lzma2Options::default(),
            };

            let encoder = match lzma2_options.threads {
                0 | 1 => Encoder::Lzma2(Some(Lzma2Writer::new(input, lzma2_options.options))),
                _ => {
                    let threads = lzma2_options.threads;
                    Encoder::Lzma2Mt(Some(Lzma2WriterMt::new(
                        input,
                        lzma2_options.options,
                        threads,
                    )?))
                }
            };

            Ok(encoder)
        }
        #[cfg(feature = "ppmd")]
        EncoderMethod::ID_PPMD => {
            let options = match method_config.options {
                Some(EncoderOptions::Ppmd(options)) => options,
                _ => PpmdOptions::default(),
            };

            let ppmd_encoder =
                ppmd_rust::Ppmd7Encoder::new(input, options.order, options.memory_size)
                    .map_err(|err| Error::other(err.to_string()))?;

            Ok(Encoder::Ppmd(Some(Box::new(ppmd_encoder))))
        }
        #[cfg(feature = "brotli")]
        EncoderMethod::ID_BROTLI => {
            let options = match method_config.options {
                Some(EncoderOptions::Brotli(options)) => options,
                _ => BrotliOptions::default(),
            };

            let brotli_encoder = BrotliEncoder::new(
                input,
                options.quality,
                options.window,
                options.skippable_frame_size as usize,
            )?;

            Ok(Encoder::Brotli(brotli_encoder))
        }
        #[cfg(feature = "bzip2")]
        EncoderMethod::ID_BZIP2 => {
            let options = match method_config.options {
                Some(EncoderOptions::Bzip2(options)) => options,
                _ => Bzip2Options::default(),
            };

            let bzip2_encoder =
                bzip2::write::BzEncoder::new(input, bzip2::Compression::new(options.0));

            Ok(Encoder::Bzip2(Some(bzip2_encoder)))
        }
        #[cfg(feature = "deflate")]
        EncoderMethod::ID_DEFLATE => {
            let options = match method_config.options {
                Some(EncoderOptions::Deflate(options)) => options,
                _ => DeflateOptions::default(),
            };

            let deflate_encoder =
                flate2::write::DeflateEncoder::new(input, flate2::Compression::new(options.0));
            Ok(Encoder::Deflate(Some(deflate_encoder)))
        }
        #[cfg(feature = "lz4")]
        EncoderMethod::ID_LZ4 => {
            let options = match method_config.options.as_ref() {
                Some(EncoderOptions::Lz4(options)) => *options,
                _ => Lz4Options::default(),
            };

            let lz4_encoder = Lz4Encoder::new(input, options.skippable_frame_size as usize)?;

            Ok(Encoder::Lz4(Some(lz4_encoder)))
        }
        #[cfg(feature = "zstd")]
        EncoderMethod::ID_ZSTD => {
            let options = match method_config.options.as_ref() {
                Some(EncoderOptions::Zstd(options)) => *options,
                _ => ZstandardOptions::default(),
            };

            let zstd_encoder = zstd::Encoder::new(input, options.0 as i32)?;

            Ok(Encoder::Zstd(Some(zstd_encoder)))
        }
        #[cfg(feature = "aes256")]
        EncoderMethod::ID_AES256_SHA256 => {
            let options = match method_config.options.as_ref() {
                Some(EncoderOptions::Aes(p)) => p,
                _ => return Err(Error::PasswordRequired),
            };
            Ok(Encoder::Aes(Aes256Sha256Encoder::new(input, options)?))
        }
        _ => Err(Error::UnsupportedCompressionMethod(
            method.name().to_string(),
        )),
    }
}

pub(crate) fn get_options_as_properties<'a>(
    method: EncoderMethod,
    options: Option<&EncoderOptions>,
    out: &'a mut [u8],
) -> &'a [u8] {
    match method.id() {
        EncoderMethod::ID_DELTA => {
            let options = match options {
                Some(EncoderOptions::Delta(options)) => *options,
                _ => DeltaOptions::default(),
            };

            out[0] = options.0.saturating_sub(1) as u8;
            &out[0..1]
        }
        EncoderMethod::ID_LZMA2 => {
            let options = match options {
                Some(EncoderOptions::Lzma2(options)) => options,
                _ => &Lzma2Options::default(),
            };
            let dict_size = options.options.lzma_options.dict_size;
            let lead = dict_size.leading_zeros();
            let second_bit = (dict_size >> (30u32.wrapping_sub(lead))).wrapping_sub(2);
            let prop = (19u32.wrapping_sub(lead) * 2 + second_bit) as u8;
            out[0] = prop;
            &out[0..1]
        }
        EncoderMethod::ID_LZMA => {
            let options = match options {
                Some(EncoderOptions::Lzma(options)) => options,
                _ => &LzmaOptions::default(),
            };
            let dict_size = options.0.dict_size;
            out[0] = options.0.get_props();
            out[1..5].copy_from_slice(dict_size.to_le_bytes().as_ref());
            &out[0..5]
        }
        #[cfg(feature = "ppmd")]
        EncoderMethod::ID_PPMD => {
            let options = match options {
                Some(EncoderOptions::Ppmd(options)) => *options,
                _ => PpmdOptions::default(),
            };

            out[0] = options.order as u8;
            out[1..5].copy_from_slice(&options.memory_size.to_le_bytes());
            &out[0..5]
        }
        #[cfg(feature = "brotli")]
        EncoderMethod::ID_BROTLI => {
            let version_major = brotli::VERSION;
            let version_minor = 0;
            let options = match options {
                Some(EncoderOptions::Brotli(options)) => *options,
                _ => BrotliOptions::default(),
            };

            out[0] = version_major;
            out[1] = version_minor;
            out[2] = options.quality as u8;
            &out[0..3]
        }
        #[cfg(feature = "lz4")]
        EncoderMethod::ID_LZ4 => {
            // Since we use lz4_flex, we only support one compression level
            // and set the version to 1.0 for best compatibility.
            out[0] = 1; // Major version
            out[1] = 0; // Minor version
            out[2] = 3; // Fast compression
            &out[0..3]
        }
        #[cfg(feature = "zstd")]
        EncoderMethod::ID_ZSTD => {
            let version_major = zstd::zstd_safe::VERSION_MAJOR;
            let version_minor = zstd::zstd_safe::VERSION_MINOR;
            let options = match options {
                Some(EncoderOptions::Zstd(options)) => *options,
                _ => ZstandardOptions::default(),
            };

            out[0] = version_major as u8;
            out[1] = version_minor as u8;
            out[2] = options.0 as u8;
            &out[0..3]
        }
        #[cfg(feature = "aes256")]
        EncoderMethod::ID_AES256_SHA256 => {
            let options = match options.as_ref() {
                Some(EncoderOptions::Aes(p)) => p,
                _ => return &[],
            };
            options.write_properties(out);
            &out[..34]
        }
        _ => &[],
    }
}

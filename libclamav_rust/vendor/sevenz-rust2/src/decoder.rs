use std::{io, io::Read};

#[cfg(feature = "bzip2")]
use bzip2::read::BzDecoder;
#[cfg(feature = "deflate")]
use flate2::bufread::DeflateDecoder;
use lzma_rust2::{
    Lzma2Reader, Lzma2ReaderMt, LzmaReader,
    filter::{bcj::BcjReader, delta::DeltaReader},
    lzma_get_memory_usage_by_props, lzma2_get_memory_usage,
};
#[cfg(feature = "ppmd")]
use ppmd_rust::{
    PPMD7_MAX_MEM_SIZE, PPMD7_MAX_ORDER, PPMD7_MIN_MEM_SIZE, PPMD7_MIN_ORDER, Ppmd7Decoder,
};

#[cfg(feature = "brotli")]
use crate::codec::brotli::BrotliDecoder;
#[cfg(feature = "lz4")]
use crate::codec::lz4::Lz4Decoder;
#[cfg(feature = "aes256")]
use crate::encryption::Aes256Sha256Decoder;
use crate::{ByteReader, Password, archive::EncoderMethod, block::Coder, error::Error};

pub struct OutputBoundReader<R> {
    inner: R,
    remaining: u64,
}

impl<R> OutputBoundReader<R> {
    fn new(inner: R, remaining: u64) -> Self {
        Self { inner, remaining }
    }
}

impl<R: Read> Read for OutputBoundReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.remaining == 0 {
            return Ok(0);
        }
        let bound = buf
            .len()
            .min(usize::try_from(self.remaining).unwrap_or(usize::MAX));
        let size = self.inner.read(&mut buf[..bound])?;
        self.remaining -= size as u64;
        Ok(size)
    }
}

pub enum Decoder<R: Read> {
    Copy(R),
    Lzma(Box<LzmaReader<R>>),
    Lzma2(Box<Lzma2Reader<R>>),
    Lzma2Mt(Box<Lzma2ReaderMt<R>>),
    #[cfg(feature = "ppmd")]
    Ppmd(Box<OutputBoundReader<Ppmd7Decoder<R>>>),
    Bcj(BcjReader<R>),
    Delta(DeltaReader<R>),
    #[cfg(feature = "brotli")]
    Brotli(Box<BrotliDecoder<R>>),
    #[cfg(feature = "bzip2")]
    Bzip2(BzDecoder<R>),
    #[cfg(feature = "deflate")]
    Deflate(DeflateDecoder<std::io::BufReader<R>>),
    #[cfg(feature = "lz4")]
    Lz4(Lz4Decoder<R>),
    #[cfg(feature = "zstd")]
    Zstd(zstd::Decoder<'static, std::io::BufReader<R>>),
    #[cfg(feature = "aes256")]
    Aes256Sha256(Box<Aes256Sha256Decoder<R>>),
}

impl<R: Read> Read for Decoder<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Decoder::Copy(r) => r.read(buf),
            Decoder::Lzma(r) => r.read(buf),
            Decoder::Lzma2(r) => r.read(buf),
            Decoder::Lzma2Mt(r) => r.read(buf),
            #[cfg(feature = "ppmd")]
            Decoder::Ppmd(r) => r.read(buf),
            Decoder::Bcj(r) => r.read(buf),
            Decoder::Delta(r) => r.read(buf),
            #[cfg(feature = "brotli")]
            Decoder::Brotli(r) => r.read(buf),
            #[cfg(feature = "bzip2")]
            Decoder::Bzip2(r) => r.read(buf),
            #[cfg(feature = "deflate")]
            Decoder::Deflate(r) => r.read(buf),
            #[cfg(feature = "lz4")]
            Decoder::Lz4(r) => r.read(buf),
            #[cfg(feature = "zstd")]
            Decoder::Zstd(r) => r.read(buf),
            #[cfg(feature = "aes256")]
            Decoder::Aes256Sha256(r) => r.read(buf),
        }
    }
}

pub fn add_decoder<I: Read>(
    input: I,
    uncompressed_len: u64,
    coder: &Coder,
    #[allow(unused)] password: &Password,
    max_mem_limit_kb: usize,
    threads: u32,
) -> Result<Decoder<I>, Error> {
    let method = EncoderMethod::by_id(coder.encoder_method_id());
    let method = if let Some(m) = method {
        m
    } else {
        return Err(Error::UnsupportedCompressionMethod(format!(
            "{:?}",
            coder.encoder_method_id()
        )));
    };
    match method.id() {
        EncoderMethod::ID_COPY => Ok(Decoder::Copy(input)),
        EncoderMethod::ID_LZMA => {
            // Validate the length before touching the properties: `get_lzma_dic_size`
            // slices `[1..5]`, which would panic on an attacker-supplied short field.
            if coder.properties.len() < 5 {
                return Err(Error::Other("LZMA properties too short".into()));
            }
            let dict_size = get_lzma_dic_size(coder)?;
            let props = coder.properties[0];
            let mem_size = lzma_get_memory_usage_by_props(dict_size, props)
                .map_err(|e| Error::bad_password(e, !password.is_empty()))?
                as usize;
            if mem_size > max_mem_limit_kb {
                return Err(Error::MaxMemLimited {
                    max_kb: max_mem_limit_kb,
                    actaul_kb: mem_size,
                });
            }
            let mut lz =
                LzmaReader::new_with_props(input, uncompressed_len, props, dict_size, None)
                    .map_err(|e| Error::bad_password(e, !password.is_empty()))?;
            // Raw 7z LZMA commonly omits an end marker, so its declared size is
            // required for termination. Do not merely trust it: require the
            // range coder to be in a valid terminal state at that boundary.
            lz.set_relaxed_end_condition(false);
            Ok(Decoder::Lzma(Box::new(lz)))
        }
        EncoderMethod::ID_LZMA2 => {
            let dic_size = get_lzma2_dic_size(coder)?;
            let mem_size = lzma2_get_memory_usage(dic_size) as usize;
            if mem_size > max_mem_limit_kb {
                return Err(Error::MaxMemLimited {
                    max_kb: max_mem_limit_kb,
                    actaul_kb: mem_size,
                });
            }

            let lz = if threads < 2 {
                Decoder::Lzma2(Box::new(Lzma2Reader::new(input, dic_size, None)))
            } else {
                Decoder::Lzma2Mt(Box::new(Lzma2ReaderMt::new(input, dic_size, None, threads)))
            };

            Ok(lz)
        }
        #[cfg(feature = "ppmd")]
        EncoderMethod::ID_PPMD => {
            let (order, memory_size) = get_ppmd_order_memory_size(coder, max_mem_limit_kb)?;
            let ppmd = Ppmd7Decoder::new(input, order, memory_size)
                .map_err(|err| Error::other(err.to_string()))?;
            // PPMd7 streams may omit an end marker and therefore intrinsically
            // require the folder size for framing. CRC and block validation
            // still verify that boundary; policy limits never use this value.
            Ok(Decoder::Ppmd(Box::new(OutputBoundReader::new(
                ppmd,
                uncompressed_len,
            ))))
        }
        #[cfg(feature = "brotli")]
        EncoderMethod::ID_BROTLI => {
            let de = BrotliDecoder::new(input, 4096)?;
            Ok(Decoder::Brotli(Box::new(de)))
        }
        #[cfg(feature = "bzip2")]
        EncoderMethod::ID_BZIP2 => {
            let de = BzDecoder::new(input);
            Ok(Decoder::Bzip2(de))
        }
        #[cfg(feature = "deflate")]
        EncoderMethod::ID_DEFLATE => {
            let buf_read = std::io::BufReader::new(input);
            let de = DeflateDecoder::new(buf_read);
            Ok(Decoder::Deflate(de))
        }
        #[cfg(feature = "lz4")]
        EncoderMethod::ID_LZ4 => {
            let de = Lz4Decoder::new(input)?;
            Ok(Decoder::Lz4(de))
        }
        #[cfg(feature = "zstd")]
        EncoderMethod::ID_ZSTD => {
            let zs = zstd::Decoder::new(input)?;
            Ok(Decoder::Zstd(zs))
        }
        EncoderMethod::ID_BCJ_X86 => {
            let de = BcjReader::new_x86(input, 0);
            Ok(Decoder::Bcj(de))
        }
        EncoderMethod::ID_BCJ_ARM => {
            let de = BcjReader::new_arm(input, 0);
            Ok(Decoder::Bcj(de))
        }
        EncoderMethod::ID_BCJ_ARM64 => {
            let de = BcjReader::new_arm64(input, 0);
            Ok(Decoder::Bcj(de))
        }
        EncoderMethod::ID_BCJ_ARM_THUMB => {
            let de = BcjReader::new_arm_thumb(input, 0);
            Ok(Decoder::Bcj(de))
        }
        EncoderMethod::ID_BCJ_PPC => {
            let de = BcjReader::new_ppc(input, 0);
            Ok(Decoder::Bcj(de))
        }
        EncoderMethod::ID_BCJ_IA64 => {
            let de = BcjReader::new_ia64(input, 0);
            Ok(Decoder::Bcj(de))
        }
        EncoderMethod::ID_BCJ_SPARC => {
            let de = BcjReader::new_sparc(input, 0);
            Ok(Decoder::Bcj(de))
        }
        EncoderMethod::ID_BCJ_RISCV => {
            let de = BcjReader::new_riscv(input, 0);
            Ok(Decoder::Bcj(de))
        }
        EncoderMethod::ID_DELTA => {
            // The distance is `properties[0] + 1` in the range 1..=256. Widen to `usize`
            // before the `+1` so a property byte of `0xFF` yields 256, not 0 (a `u8`
            // `wrapping_add` would wrap to a zero distance and mis-decode / divide by zero).
            let d = coder.properties.first().map_or(1, |b| *b as usize + 1);
            let de = DeltaReader::new(input, d);
            Ok(Decoder::Delta(de))
        }
        #[cfg(feature = "aes256")]
        EncoderMethod::ID_AES256_SHA256 => {
            if password.is_empty() {
                return Err(Error::PasswordRequired);
            }
            let de = Aes256Sha256Decoder::new(input, &coder.properties, password)?;
            Ok(Decoder::Aes256Sha256(Box::new(de)))
        }
        _ => Err(Error::UnsupportedCompressionMethod(
            method.name().to_string(),
        )),
    }
}

#[cfg(feature = "ppmd")]
fn get_ppmd_order_memory_size(coder: &Coder, max_mem_limit_kb: usize) -> Result<(u32, u32), Error> {
    if coder.properties.len() < 5 {
        return Err(Error::other("PPMD properties too short"));
    }
    let order = coder.properties[0] as u32;
    let memory_size = u32::from_le_bytes([
        coder.properties[1],
        coder.properties[2],
        coder.properties[3],
        coder.properties[4],
    ]);

    if order < PPMD7_MIN_ORDER {
        return Err(Error::other("PPMD order smaller than PPMD7_MIN_ORDER"));
    }

    if order > PPMD7_MAX_ORDER {
        return Err(Error::other("PPMD order larger than PPMD7_MAX_ORDER"));
    }

    if memory_size < PPMD7_MIN_MEM_SIZE {
        return Err(Error::other(
            "PPMD memory size smaller than PPMD7_MIN_MEM_SIZE",
        ));
    }

    if memory_size > PPMD7_MAX_MEM_SIZE {
        return Err(Error::other(
            "PPMD memory size larger than PPMD7_MAX_MEM_SIZE",
        ));
    }

    let memory_size_kb = (memory_size as usize).saturating_add(1023) / 1024;
    if memory_size_kb > max_mem_limit_kb {
        return Err(Error::MaxMemLimited {
            max_kb: max_mem_limit_kb,
            actaul_kb: memory_size_kb,
        });
    }

    Ok((order, memory_size))
}

fn get_lzma2_dic_size(coder: &Coder) -> Result<u32, Error> {
    if coder.properties.is_empty() {
        return Err(Error::other("LZMA2 properties too short"));
    }
    let dict_size_bits = 0xFF & coder.properties[0] as u32;
    if (dict_size_bits & (!0x3F)) != 0 {
        return Err(Error::other("Unsupported LZMA2 property bits"));
    }
    if dict_size_bits > 40 {
        return Err(Error::other("Dictionary larger than 4GiB maximum size"));
    }
    if dict_size_bits == 40 {
        return Ok(0xFFFFFFFF);
    }
    let size = (2 | (dict_size_bits & 0x1)) << (dict_size_bits / 2 + 11);
    Ok(size)
}

fn get_lzma_dic_size(coder: &Coder) -> io::Result<u32> {
    let mut props = &coder.properties[1..5];
    props.read_u32()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn coder(method: &[u8], properties: Vec<u8>) -> Coder {
        let mut coder = Coder::default();
        coder.id_size = method.len();
        coder.decompression_method_id_mut().copy_from_slice(method);
        coder.properties = properties;
        coder
    }

    #[test]
    fn lzma_dictionary_is_checked_before_decoder_allocation() {
        let coder = coder(EncoderMethod::ID_LZMA, vec![93, 0, 0, 0, 0x10]);
        let result = add_decoder(
            Cursor::new(Vec::<u8>::new()),
            1,
            &coder,
            &Password::empty(),
            1024,
            1,
        );
        assert!(matches!(result, Err(Error::MaxMemLimited { .. })));
    }

    #[test]
    fn lzma2_dictionary_is_checked_before_decoder_allocation() {
        let coder = coder(EncoderMethod::ID_LZMA2, vec![40]);
        let result = add_decoder(
            Cursor::new(Vec::<u8>::new()),
            1,
            &coder,
            &Password::empty(),
            1024,
            1,
        );
        assert!(matches!(result, Err(Error::MaxMemLimited { .. })));
    }

    #[cfg(feature = "ppmd")]
    #[test]
    fn ppmd_byte_size_is_compared_to_kibibyte_limit() {
        let coder = coder(
            EncoderMethod::ID_PPMD,
            [6u8]
                .into_iter()
                .chain((2u32 << 20).to_le_bytes())
                .collect(),
        );
        assert!(matches!(
            get_ppmd_order_memory_size(&coder, 1024),
            Err(Error::MaxMemLimited { .. })
        ));
        assert!(get_ppmd_order_memory_size(&coder, 2048).is_ok());
    }
}

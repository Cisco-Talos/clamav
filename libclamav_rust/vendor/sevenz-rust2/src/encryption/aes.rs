use std::{
    borrow::Cow,
    io::{Read, Seek, Write},
};

#[cfg(feature = "compress")]
use aes::cipher::BlockModeEncrypt;
use aes::{
    Aes256,
    cipher::{BlockModeDecrypt, KeyIvInit, array::Array},
};
use sha2::Digest;

use crate::Password;
#[cfg(feature = "compress")]
use crate::encoder_options::AesEncoderOptions;

type Aes256CbcDec = cbc::Decryptor<Aes256>;

#[cfg(feature = "compress")]
type Aes256CbcEnc = cbc::Encryptor<Aes256>;

pub(crate) struct Aes256Sha256Decoder<R> {
    cipher: Cipher,
    input: R,
    done: bool,
    obuffer: Vec<u8>,
    ostart: usize,
    ofinish: usize,
    pos: usize,
}

impl<R: Read> Aes256Sha256Decoder<R> {
    pub(crate) fn new(
        input: R,
        properties: &[u8],
        password: &Password,
    ) -> Result<Self, crate::Error> {
        let cipher = Cipher::from_properties(properties, password.as_slice())?;
        Ok(Self {
            input,
            cipher,
            done: false,
            obuffer: Default::default(),
            ostart: 0,
            ofinish: 0,
            pos: 0,
        })
    }

    fn get_more_data(&mut self) -> std::io::Result<usize> {
        if self.done {
            Ok(0)
        } else {
            self.ofinish = 0;
            self.ostart = 0;
            self.obuffer.clear();
            let mut ibuffer = [0; 512];
            let readin = self.input.read(&mut ibuffer)?;
            if readin == 0 {
                self.done = true;
                self.ofinish = self.cipher.do_final(&mut self.obuffer)?;
                Ok(self.ofinish)
            } else {
                let n = self
                    .cipher
                    .update(&mut ibuffer[..readin], &mut self.obuffer)?;
                self.ofinish = n;
                Ok(n)
            }
        }
    }
}

impl<R: Read> Read for Aes256Sha256Decoder<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.ostart >= self.ofinish {
            let mut n: usize;
            n = self.get_more_data()?;
            while n == 0 && !self.done {
                n = self.get_more_data()?;
            }
            if n == 0 {
                return Ok(0);
            }
        }

        if buf.is_empty() {
            return Ok(0);
        }
        let buf_len = self.ofinish - self.ostart;
        let size = buf_len.min(buf.len());
        buf[..size].copy_from_slice(&self.obuffer[self.ostart..self.ostart + size]);
        self.ostart += size;
        self.pos += size;
        Ok(size)
    }
}

impl<R: Read + Seek> Seek for Aes256Sha256Decoder<R> {
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        let len = self.ofinish - self.ostart;
        match pos {
            std::io::SeekFrom::Start(p) => {
                let n = (p as i64 - self.pos as i64).min(len as i64);

                if n < 0 {
                    Ok(0)
                } else {
                    self.ostart += n as usize;
                    Ok(p)
                }
            }
            std::io::SeekFrom::End(_) => Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "Aes256 decoder unsupport seek from end",
            )),
            std::io::SeekFrom::Current(n) => {
                let n = n.min(len as i64);
                if n < 0 {
                    Ok(0)
                } else {
                    self.ostart += n as usize;
                    Ok(self.pos as u64 + n as u64)
                }
            }
        }
    }
}

fn get_aes_key(properties: &[u8], password: &[u8]) -> Result<([u8; 32], [u8; 16]), crate::Error> {
    let properties = match properties.len() {
        0 => {
            return Err(crate::Error::other("AES256 properties too short"));
        }
        1 => {
            // It seems that there are encrypted files that include the K_END (0x00) symbol as a
            // property byte.
            let mut prop = vec![0u8; 2];
            prop[0] = properties[0];
            Cow::Owned(prop)
        }
        _ => Cow::Borrowed(properties),
    };

    let b0 = properties[0];
    let num_cycles_power = b0 & 63;
    let b1 = properties[1];
    let iv_size = (((b0 >> 6) & 1) + (b1 & 15)) as usize;
    let salt_size = (((b0 >> 7) & 1) + (b1 >> 4)) as usize;
    if 2 + salt_size + iv_size > properties.len() {
        return Err(crate::Error::other("Salt size + IV size too long"));
    }
    let mut salt = vec![0u8; salt_size];
    salt.copy_from_slice(&properties[2..(2 + salt_size)]);
    let mut iv = [0u8; 16];
    iv[0..iv_size].copy_from_slice(&properties[(2 + salt_size)..(2 + salt_size + iv_size)]);
    if password.is_empty() {
        return Err(crate::Error::PasswordRequired);
    }
    let aes_key = if num_cycles_power == 0x3F {
        // "Raw key" mode: the 32-byte key is `salt` followed by the password (both
        // truncated to fit). `salt_size` is at most 16, so copy only that prefix.
        // `aes_key.copy_from_slice(&salt)` would panic on the 32-vs-<=16 length mismatch.
        let mut aes_key = [0u8; 32];
        aes_key[..salt_size].copy_from_slice(&salt[..salt_size]);
        let n = password.len().min(aes_key.len() - salt_size);
        aes_key[salt_size..n + salt_size].copy_from_slice(&password[0..n]);
        aes_key
    } else {
        // Cap the work factor: `derive_key` runs `2^num_cycles_power` SHA-256 rounds, so
        // a crafted large power is a CPU-exhaustion DoS (and `1 << power` also overflows
        // the shift for power >= 32). No real archive uses a power above this bound.
        if num_cycles_power > MAX_AES_CYCLES_POWER {
            return Err(crate::Error::other(
                "AES num_cycles_power exceeds the supported maximum",
            ));
        }
        derive_key_cached(num_cycles_power, &salt, password)
    };
    Ok((aes_key, iv))
}

/// Maximum accepted AES-256 key-derivation work factor. `derive_key` runs
/// `2^num_cycles_power` SHA-256 rounds; 7-Zip's own encoder never exceeds this, so a
/// larger value only ever comes from a malicious archive trying to burn CPU. Keeping it
/// below 32 also makes the `1 << num_cycles_power` shift safe.
const MAX_AES_CYCLES_POWER: u8 = 24;

fn derive_key(num_cycles_power: u8, salt: &[u8], password: &[u8]) -> [u8; 32] {
    let mut sha = sha2::Sha256::default();
    let mut extra = [0u8; 8];
    for _ in 0..(1u64 << num_cycles_power) {
        sha.update(salt);
        sha.update(password);
        sha.update(extra);
        for item in &mut extra {
            *item = item.wrapping_add(1);
            if *item != 0 {
                break;
            }
        }
    }
    sha.finalize().into()
}

/// Cache last derived key.
fn derive_key_cached(num_cycles_power: u8, salt: &[u8], password: &[u8]) -> [u8; 32] {
    static KEY_CACHE: std::sync::Mutex<Option<([u8; 32], [u8; 32])>> = std::sync::Mutex::new(None);

    let fingerprint: [u8; 32] = {
        let mut sha = sha2::Sha256::default();
        sha.update([num_cycles_power, salt.len() as u8]);
        sha.update(salt);
        sha.update(password);
        sha.finalize().into()
    };
    if let Some(key) = KEY_CACHE
        .lock()
        .unwrap()
        .as_ref()
        .and_then(|(cached_fp, key)| (*cached_fp == fingerprint).then_some(*key))
    {
        return key;
    }

    let key = derive_key(num_cycles_power, salt, password);
    *KEY_CACHE.lock().unwrap() = Some((fingerprint, key));
    key
}

struct Cipher {
    dec: Aes256CbcDec,
    buf: Vec<u8>,
}

impl Cipher {
    fn from_properties(properties: &[u8], password: &[u8]) -> Result<Self, crate::Error> {
        let (aes_key, iv) = get_aes_key(properties, password)?;
        Ok(Self {
            dec: Aes256CbcDec::new(&Array::from(aes_key), &iv.into()),
            buf: Default::default(),
        })
    }

    fn update<W: Write>(&mut self, mut data: &mut [u8], mut output: W) -> std::io::Result<usize> {
        let mut n = 0;
        if !self.buf.is_empty() {
            assert!(self.buf.len() < 16);
            let end = 16 - self.buf.len();
            if data.len() < end {
                // A short read (e.g. AES layered on top of another coder, whose reader can
                // return fewer than 16 bytes) delivered less than what is needed to complete
                // the pending block. Buffer what we have and wait for more; slicing
                // `data[..end]` here would panic.
                self.buf.extend_from_slice(data);
                return Ok(n);
            }
            self.buf.extend_from_slice(&data[..end]);
            data = &mut data[end..];
            let block: &mut Array<u8, _> = self.buf.as_mut_slice().try_into().unwrap();
            self.dec.decrypt_block(block);
            let out = block.as_slice();
            output.write_all(out)?;
            n += out.len();
            self.buf.clear();
        }

        let (blocks, remainder) = Array::<u8, _>::slice_as_chunks_mut(data);
        if !blocks.is_empty() {
            self.dec.decrypt_blocks(blocks);
            let out = Array::slice_as_flattened(blocks);
            output.write_all(out)?;
            n += out.len();
        }
        self.buf.extend_from_slice(remainder);
        Ok(n)
    }

    fn do_final(&mut self, output: &mut Vec<u8>) -> std::io::Result<usize> {
        if self.buf.is_empty() {
            output.clear();
            Ok(0)
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "IllegalBlockSize",
            ))
        }
    }
}

#[cfg(feature = "compress")]
pub(crate) struct Aes256Sha256Encoder<W> {
    output: W,
    enc: Aes256CbcEnc,
    buffer: Vec<u8>,
    finished: bool,
    write_size: u32,
}

#[cfg(feature = "compress")]
impl<W> Aes256Sha256Encoder<W> {
    pub(crate) fn new(output: W, options: &AesEncoderOptions) -> Result<Self, crate::Error> {
        let (key, iv) = crate::encryption::aes::get_aes_key(
            &options.properties(),
            options.password.as_slice(),
        )?;

        Ok(Self {
            output,
            enc: Aes256CbcEnc::new(&Array::from(key), &iv.into()),
            buffer: Default::default(),
            finished: false,
            write_size: 0,
        })
    }

    #[inline(always)]
    fn write_block(&mut self, block: &mut [u8]) -> std::io::Result<()>
    where
        W: Write,
    {
        let block2: &mut Array<u8, _> = (&mut *block).try_into().unwrap();
        self.enc.encrypt_block(block2);
        self.output.write_all(block)?;
        self.write_size += block.len() as u32;
        Ok(())
    }
}

#[cfg(feature = "compress")]
impl<W: Write> Write for Aes256Sha256Encoder<W> {
    fn write(&mut self, mut buf: &[u8]) -> std::io::Result<usize> {
        if self.finished && !buf.is_empty() {
            return Ok(0);
        }
        if buf.is_empty() {
            self.finished = true;
            self.flush()?;
            return self.output.write(buf);
        }
        let len = buf.len();
        if !self.buffer.is_empty() {
            assert!(self.buffer.len() < 16);
            if buf.len() + self.buffer.len() >= 16 {
                let buffer = &self.buffer[..];
                let end = 16 - buffer.len();

                let mut block = [0u8; 16];
                block[0..buffer.len()].copy_from_slice(buffer);
                block[buffer.len()..16].copy_from_slice(&buf[..end]);
                self.write_block(&mut block)?;
                self.buffer.clear();
                buf = &buf[end..];
            } else {
                self.buffer.extend_from_slice(buf);
                return Ok(len);
            }
        }

        for data in buf.chunks(16) {
            if data.len() < 16 {
                self.buffer.extend_from_slice(data);
                break;
            }
            let mut block = [0u8; 16];
            block.copy_from_slice(data);
            self.write_block(&mut block)?;
        }

        Ok(len)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if !self.buffer.is_empty() && self.finished {
            assert!(self.buffer.len() < 16);
            let mut block = [0u8; 16];
            block[..self.buffer.len()].copy_from_slice(&self.buffer);
            self.write_block(&mut block)?;
            self.buffer.clear();
        }
        Ok(())
    }
}

#[cfg(test)]
mod key_derivation_tests {
    use super::*;

    const CYCLES: u8 = 4;

    #[test]
    fn cached_derivation_matches_reference() {
        let (salt, password) = (b"salt".as_slice(), b"p\0a\0s\0s\0".as_slice());
        let expected = derive_key(CYCLES, salt, password);
        assert_eq!(derive_key_cached(CYCLES, salt, password), expected);
        assert_eq!(derive_key_cached(CYCLES, salt, password), expected);
    }

    #[test]
    fn cache_never_crosses_inputs() {
        let a = (b"salt-a".as_slice(), b"pw-a".as_slice());
        let b = (b"salt-a".as_slice(), b"pw-b".as_slice());
        let c = (b"salt-c".as_slice(), b"pw-a".as_slice());
        let ka = derive_key(CYCLES, a.0, a.1);
        let kb = derive_key(CYCLES, b.0, b.1);
        let kc = derive_key(CYCLES, c.0, c.1);
        assert_eq!(derive_key_cached(CYCLES, a.0, a.1), ka);
        assert_eq!(derive_key_cached(CYCLES, b.0, b.1), kb);
        assert_eq!(derive_key_cached(CYCLES, a.0, a.1), ka);
        assert_eq!(derive_key_cached(CYCLES, c.0, c.1), kc);
        assert_eq!(derive_key_cached(CYCLES, b.0, b.1), kb);
    }

    #[test]
    fn cycle_count_is_part_of_the_identity() {
        let (salt, password) = (b"salt".as_slice(), b"pw".as_slice());
        let k4 = derive_key_cached(4, salt, password);
        let k5 = derive_key_cached(5, salt, password);
        assert_ne!(k4, k5);
        assert_eq!(derive_key_cached(4, salt, password), k4);
    }
}

#[cfg(all(test, feature = "compress"))]
mod tests {
    use std::io::{Cursor, Read};

    use super::*;

    struct FragmentedReader<R> {
        inner: R,
        read_sizes: &'static [usize],
        next_read: usize,
    }

    impl<R> FragmentedReader<R> {
        fn new(inner: R, read_sizes: &'static [usize]) -> Self {
            Self {
                inner,
                read_sizes,
                next_read: 0,
            }
        }
    }

    impl<R: Read> Read for FragmentedReader<R> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let read_size = self.read_sizes[self.next_read % self.read_sizes.len()];
            self.next_read += 1;
            let len = read_size.min(buf.len());
            self.inner.read(&mut buf[..len])
        }
    }

    fn encode(original: &[u8]) -> (Vec<u8>, AesEncoderOptions, Password) {
        let mut encoded = vec![];
        let writer = Cursor::new(&mut encoded);
        let password: Password = "1234".into();
        let options = AesEncoderOptions::new(password.clone());
        let mut enc = Aes256Sha256Encoder::new(writer, &options).unwrap();
        enc.write_all(original).expect("encode data");
        let _ = enc.write(&[]).unwrap();
        drop(enc);
        (encoded, options, password)
    }

    fn assert_decodes<R: Read>(input: R, properties: &[u8], password: &Password, original: &[u8]) {
        let mut dec = Aes256Sha256Decoder::new(input, properties, password).unwrap();

        let mut decoded = vec![];
        let _ = std::io::copy(&mut dec, &mut decoded).unwrap();
        assert_eq!(&decoded[..original.len()], original);
    }

    #[test]
    fn test_aes_codec() {
        let original = include_bytes!("aes.rs");
        let (encoded, options, password) = encode(original);
        let properties = options.properties();
        assert_decodes(
            Cursor::new(encoded.as_slice()),
            &properties,
            &password,
            original,
        );
    }

    #[test]
    fn test_aes_codec_with_fragmented_input() {
        let original = include_bytes!("aes.rs");
        let (encoded, options, password) = encode(original);
        let properties = options.properties();

        for read_sizes in [&[1, 511][..], &[15, 17], &[7, 503, 31, 511]] {
            let input = FragmentedReader::new(Cursor::new(encoded.as_slice()), read_sizes);
            assert_decodes(input, &properties, &password, original);
        }
    }
}

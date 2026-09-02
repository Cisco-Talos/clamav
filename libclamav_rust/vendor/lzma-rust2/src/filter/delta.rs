//! Delta filter.

#[cfg(feature = "encoder")]
use alloc::vec::Vec;

use crate::Read;
#[cfg(feature = "encoder")]
use crate::Write;

const MAX_DISTANCE: usize = 256;
const _MIN_DISTANCE: usize = 1;
const DIS_MASK: usize = MAX_DISTANCE - 1;

pub(crate) struct Delta {
    distance: usize,
    history: [u8; MAX_DISTANCE],
    pos: u8,
}

impl Delta {
    pub(crate) fn new(distance: usize) -> Self {
        Self {
            distance,
            history: [0; MAX_DISTANCE],
            pos: 0,
        }
    }

    pub(crate) fn decode(&mut self, buf: &mut [u8]) {
        for item in buf {
            let pos = self.pos as usize;
            let h = self.history[(self.distance.wrapping_add(pos)) & DIS_MASK];
            *item = item.wrapping_add(h);
            self.history[pos & DIS_MASK] = *item;
            self.pos = self.pos.wrapping_sub(1);
        }
    }

    #[cfg(feature = "encoder")]
    fn encode(&mut self, buf: &mut [u8]) {
        for item in buf {
            let pos = self.pos as usize;
            let h = self.history[(self.distance.wrapping_add(pos)) & DIS_MASK];
            let original = *item;
            *item = item.wrapping_sub(h);
            self.history[pos & DIS_MASK] = original;
            self.pos = self.pos.wrapping_sub(1);
        }
    }
}

/// Reader that applies delta filtering to decompress data.
pub struct DeltaReader<R> {
    inner: R,
    delta: Delta,
}

impl<R> DeltaReader<R> {
    /// Creates a new delta reader with the specified distance.
    pub fn new(inner: R, distance: usize) -> Self {
        Self {
            inner,
            delta: Delta::new(distance),
        }
    }

    /// Unwraps the reader, returning the underlying reader.
    pub fn into_inner(self) -> R {
        self.inner
    }

    /// Returns a reference to the inner reader.
    pub fn inner(&self) -> &R {
        &self.inner
    }

    /// Returns a mutable reference to the inner reader.
    pub fn inner_mut(&mut self) -> &mut R {
        &mut self.inner
    }
}

impl<R: Read> Read for DeltaReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> crate::Result<usize> {
        let n = self.inner.read(buf)?;
        if n == 0 {
            return Ok(n);
        }
        self.delta.decode(&mut buf[..n]);
        Ok(n)
    }
}

#[cfg(feature = "encoder")]
/// Writer that applies delta filtering before compression.
pub struct DeltaWriter<W> {
    inner: W,
    delta: Delta,
    buffer: Vec<u8>,
}

#[cfg(feature = "encoder")]
impl<W> DeltaWriter<W> {
    /// Creates a new delta writer with the specified distance.
    pub fn new(inner: W, distance: usize) -> Self {
        Self {
            inner,
            delta: Delta::new(distance),
            buffer: Vec::with_capacity(4096),
        }
    }

    /// Unwraps the writer, returning the underlying writer.
    pub fn into_inner(self) -> W {
        self.inner
    }

    /// Returns a reference to the inner writer.
    pub fn inner(&self) -> &W {
        &self.inner
    }

    /// Returns a mutable reference to the inner writer.
    pub fn inner_mut(&mut self) -> &mut W {
        &mut self.inner
    }
}

#[cfg(feature = "encoder")]
impl<W: Write> Write for DeltaWriter<W> {
    fn write(&mut self, buf: &[u8]) -> crate::Result<usize> {
        let data_size = buf.len();

        if data_size > self.buffer.len() {
            self.buffer.resize(data_size, 0);
        }

        self.buffer[..data_size].copy_from_slice(buf);
        self.delta.encode(&mut self.buffer[..data_size]);
        self.inner.write(&self.buffer[..data_size])
    }

    fn flush(&mut self) -> crate::Result<()> {
        self.inner.flush()
    }
}

#[cfg(all(feature = "encoder", feature = "std"))]
#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn test_delta_roundtrip() {
        let test_cases = [
            vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
            vec![1, 2, 3, 1, 2, 3, 1, 2, 3],
            vec![42, 13, 255, 0, 128, 64, 32, 99, 200, 150],
            vec![100; 20],
            vec![0, 255, 0, 255, 0, 255, 0, 255],
            (0..300).map(|i| (i % 256) as u8).collect(),
        ];

        let distances = vec![1, 2, 4, 8, 16, 32, 64, 128, 256];

        for distance in distances {
            for (i, original_data) in test_cases.iter().enumerate() {
                let mut encoded_buffer = Vec::new();
                let mut writer = DeltaWriter::new(Cursor::new(&mut encoded_buffer), distance);
                std::io::copy(&mut original_data.as_slice(), &mut writer)
                    .expect("Failed to encode data");

                let mut decoded_data = Vec::new();
                let mut reader = DeltaReader::new(Cursor::new(&encoded_buffer), distance);
                std::io::copy(&mut reader, &mut decoded_data).expect("Failed to decode data");

                assert_eq!(
                    original_data, &decoded_data,
                    "Roundtrip failed for distance {distance} with data set {i}",
                );
            }
        }
    }
}

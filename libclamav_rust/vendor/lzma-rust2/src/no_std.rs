use alloc::{collections::TryReserveError, vec::Vec};

/// `no_std` compatible error type.
///
/// Will get removed once `std::io::Read` and `std::io::Write` are available for `no_std`.
#[derive(Debug, Copy, Clone)]
pub enum Error {
    /// End of file reached unexpectedly.
    Eof,
    /// Operation was interrupted.
    Interrupted,
    /// Invalid data encountered.
    InvalidData(&'static str),
    /// Invalid input provided.
    InvalidInput(&'static str),
    /// Out of memory error.
    OutOfMemory(&'static str),
    /// Other error.
    Other(&'static str),
    /// Unsupported operation.
    Unsupported(&'static str),
    /// Could not write any bytes.
    WriteZero(&'static str),
}

impl From<TryReserveError> for Error {
    fn from(_value: TryReserveError) -> Self {
        Self::OutOfMemory("TryReserveError")
    }
}

/// `no_std` compatible `std::io::Read` trait
///
/// Will get removed once there is a standard way in either `core` or `alloc`.
pub trait Read {
    /// Read some bytes from this source into the specified buffer.
    fn read(&mut self, buf: &mut [u8]) -> crate::Result<usize>;

    /// Read the exact number of bytes required to fill the buffer.
    fn read_exact(&mut self, buf: &mut [u8]) -> crate::Result<()> {
        default_read_exact(self, buf)
    }
}

fn default_read_exact<R: Read + ?Sized>(this: &mut R, mut buf: &mut [u8]) -> crate::Result<()> {
    while !buf.is_empty() {
        match this.read(buf) {
            Ok(0) => break,
            Ok(n) => {
                buf = &mut buf[n..];
            }
            Err(Error::Interrupted) => {}
            Err(e) => return Err(e),
        }
    }

    if !buf.is_empty() {
        Err(Error::Eof)
    } else {
        Ok(())
    }
}

impl<R: Read> Read for &mut R {
    #[inline(always)]
    fn read(&mut self, buf: &mut [u8]) -> crate::Result<usize> {
        (**self).read(buf)
    }

    #[inline(always)]
    fn read_exact(&mut self, buf: &mut [u8]) -> crate::Result<()> {
        (**self).read_exact(buf)
    }
}

impl Read for &[u8] {
    #[inline(always)]
    fn read(&mut self, buf: &mut [u8]) -> crate::Result<usize> {
        let length = self.len().min(buf.len());
        let (left, right) = self.split_at(length);
        buf[..length].copy_from_slice(left);
        *self = right;
        Ok(length)
    }
}

/// `no_std` compatible `std::io::Write trait`
///
/// Will get removed once there is a standard way in either `core` or `alloc`.
pub trait Write {
    /// Write a buffer into this writer.
    fn write(&mut self, buf: &[u8]) -> crate::Result<usize>;
    /// Flush this output stream.
    fn flush(&mut self) -> crate::Result<()>;

    /// Attempts to write an entire buffer into this writer.
    fn write_all(&mut self, mut buf: &[u8]) -> crate::Result<()> {
        while !buf.is_empty() {
            match self.write(buf) {
                Ok(0) => {
                    return Err(Error::WriteZero("could not write any byte"));
                }
                Ok(n) => buf = &buf[n..],
                Err(Error::Interrupted) => {}
                Err(e) => return Err(e),
            }
        }

        Ok(())
    }
}

impl<W: Write> Write for &mut W {
    #[inline(always)]
    fn write(&mut self, buf: &[u8]) -> crate::Result<usize> {
        (**self).write(buf)
    }

    #[inline(always)]
    fn flush(&mut self) -> crate::Result<()> {
        (**self).flush()
    }
}

impl Write for &mut [u8] {
    #[inline(always)]
    fn write(&mut self, buf: &[u8]) -> crate::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        if self.is_empty() {
            return Err(Error::WriteZero("&mut [u8] is too small"));
        }

        let write_len = buf.len().min(self.len());
        self[..write_len].copy_from_slice(&buf[..write_len]);

        let remaining = core::mem::take(self);
        *self = &mut remaining[write_len..];

        Ok(write_len)
    }

    #[inline(always)]
    fn flush(&mut self) -> crate::Result<()> {
        Ok(())
    }
}

impl Write for Vec<u8> {
    #[inline(always)]
    fn write(&mut self, buf: &[u8]) -> crate::Result<usize> {
        self.extend_from_slice(buf);
        Ok(buf.len())
    }

    #[inline(always)]
    fn flush(&mut self) -> crate::Result<()> {
        Ok(())
    }
}

impl<R: Read + ?Sized> Read for alloc::boxed::Box<R> {
    #[inline(always)]
    fn read(&mut self, buf: &mut [u8]) -> crate::Result<usize> {
        (**self).read(buf)
    }

    #[inline(always)]
    fn read_exact(&mut self, buf: &mut [u8]) -> crate::Result<()> {
        (**self).read_exact(buf)
    }
}

impl<W: Write + ?Sized> Write for alloc::boxed::Box<W> {
    #[inline(always)]
    fn write(&mut self, buf: &[u8]) -> crate::Result<usize> {
        (**self).write(buf)
    }

    #[inline(always)]
    fn flush(&mut self) -> crate::Result<()> {
        (**self).flush()
    }
}

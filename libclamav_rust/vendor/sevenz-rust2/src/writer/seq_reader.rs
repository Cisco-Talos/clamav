use std::{io::Read, ops::Deref};

pub(crate) struct SeqReader<R> {
    readers: Vec<R>,
    current: usize,
}

impl<R> Deref for SeqReader<R> {
    type Target = [R];

    fn deref(&self) -> &Self::Target {
        &self.readers
    }
}

impl<R> SeqReader<R> {
    pub(crate) fn new(readers: Vec<R>) -> Self {
        Self {
            readers,
            current: 0,
        }
    }

    pub(crate) fn reader_len(&self) -> usize {
        self.readers.len()
    }
}

impl<R: Read> Read for SeqReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut i = 0;
        while self.current < self.readers.len() {
            let r = &mut self.readers[self.current];
            i = r.read(buf)?;
            if i == 0 {
                self.current += 1;
            } else {
                break;
            }
        }

        Ok(i)
    }
}

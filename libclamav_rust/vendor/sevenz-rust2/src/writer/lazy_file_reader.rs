use std::{fs::File, io::Read, path::PathBuf};

pub(crate) struct LazyFileReader {
    path: PathBuf,
    reader: Option<File>,
    end: bool,
}

impl LazyFileReader {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            reader: None,
            end: false,
        }
    }
}

impl Read for LazyFileReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.end {
            return Ok(0);
        }
        if self.reader.is_none() {
            self.reader = Some(File::open(&self.path)?);
        }
        let n = self.reader.as_mut().unwrap().read(buf)?;
        if n == 0 {
            self.end = true;
            self.reader = None;
        }
        Ok(n)
    }
}

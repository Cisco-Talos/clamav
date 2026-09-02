use std::io::{Read, Seek, SeekFrom, Write};

use js_sys::*;
use wasm_bindgen::prelude::*;

use crate::*;

/// Decompresses a 7z archive in WebAssembly environment.
///
/// This function is specifically designed for WASM targets and uses JavaScript interop
/// to handle the decompression process with a callback function.
///
/// # Arguments
/// * `src` - Uint8Array containing the compressed archive data
/// * `pwd` - Password string for encrypted archives (use empty string for unencrypted)
/// * `f` - JavaScript callback function to handle extracted entries
#[wasm_bindgen]
pub fn decompress(src: Uint8Array, pwd: &str, f: &Function) -> Result<(), String> {
    let mut src_reader = Uint8ArrayStream::new(src);
    let pos = src_reader.stream_position().map_err(|e| e.to_string())?;
    src_reader
        .seek(SeekFrom::Start(pos))
        .map_err(|e| e.to_string())?;
    let mut seven =
        ArchiveReader::new(src_reader, Password::from(pwd)).map_err(|e| e.to_string())?;
    seven
        .for_each_entries(|entry, reader| {
            if !entry.is_directory() {
                let path =
                    sanitize_entry_name(entry.name()).map_err(|e| std::io::Error::other(e))?;

                if entry.size() > 0 {
                    let mut writer = Vec::new();
                    std::io::copy(reader, &mut writer)?;
                    let _ = f.call2(
                        &JsValue::NULL,
                        &JsValue::from(path),
                        &Uint8Array::from(&writer[..]),
                    );
                }
            }
            Ok(true)
        })
        .map_err(|e| e.to_string())?;
    Ok(())
}

/// Validates an untrusted archive entry name and returns a safe *relative* path.
///
/// Both `/` and `\` are treated as separators, and any `..`, root, or drive-prefix
/// component is rejected so the host cannot be tricked into writing outside its
/// destination directory.
fn sanitize_entry_name(entry_name: &str) -> Result<String, String> {
    use std::path::{Component, Path, PathBuf};

    let normalized = entry_name.replace('\\', "/");
    let mut result = PathBuf::new();
    for component in Path::new(&normalized).components() {
        match component {
            Component::Normal(part) => result.push(part),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(format!(
                    "unsafe entry path escapes destination: {entry_name}"
                ));
            }
        }
    }
    Ok(result.to_string_lossy().into_owned())
}

/// Compresses multiple entries into a 7z archive in WebAssembly environment.
///
/// This function creates a compressed archive from multiple file entries,
/// designed specifically for WASM targets.
///
/// # Arguments
/// * `entries` - Vector of JavaScript strings representing file names/paths
/// * `datas` - Vector of Uint8Arrays containing the file data corresponding to entries
#[wasm_bindgen]
pub fn compress(entries: Vec<JsString>, datas: Vec<Uint8Array>) -> Result<Uint8Array, String> {
    let output = Uint8Array::new_with_length(32);
    let writer = Uint8ArrayStream::new(output);

    let mut sz = ArchiveWriter::new(writer).map_err(|e| e.to_string())?;
    let reader: Vec<SourceReader<_>> = datas
        .into_iter()
        .map(|d| Uint8ArrayStream::new(d))
        .map(SourceReader::new)
        .collect();
    let entries = entries
        .into_iter()
        .map(|name| ArchiveEntry {
            name: name.into(),
            has_stream: true,
            ..Default::default()
        })
        .collect();

    sz.push_archive_entries(entries, reader)
        .map_err(|e| e.to_string())?;
    let out = sz.finish().map_err(|e| e.to_string())?;

    Ok(out.data)
}

struct Uint8ArrayStream {
    data: Uint8Array,
    pos: usize,
}

impl Seek for Uint8ArrayStream {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        match pos {
            SeekFrom::Start(n) => {
                self.pos = n as usize;
            }
            SeekFrom::End(i) => {
                let posi = self.data.length() as i64 + i;
                if posi < 0 {
                    self.pos = 0;
                } else if posi >= self.data.length() as i64 {
                    self.pos = self.data.length() as usize;
                } else {
                    self.pos = posi as usize;
                }
            }
            SeekFrom::Current(i) => {
                if i != 0 {
                    let posi = self.pos as i64 + i;
                    if posi < 0 {
                        self.pos = 0;
                    } else if posi >= self.data.length() as i64 {
                        self.pos = self.data.length() as usize;
                    } else {
                        self.pos = posi as usize;
                    }
                }
            }
        }
        Ok(self.pos as u64)
    }
}

impl Uint8ArrayStream {
    fn new(data: Uint8Array) -> Self {
        Self { data, pos: 0 }
    }
}

impl Read for Uint8ArrayStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let end = (self.pos + buf.len()).min(self.data.length() as usize);
        let len = end - self.pos;
        if len == 0 {
            return Ok(0);
        }
        self.data
            .slice(self.pos as u32, end as u32)
            .copy_to(&mut buf[..len]);
        self.pos = end;
        Ok(len)
    }
}

impl Write for Uint8ArrayStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let end = (self.pos + buf.len()).min(self.data.length() as usize);
        let len = end - self.pos;
        if len == 0 {
            return Ok(0);
        }
        self.data
            .slice(self.pos as u32, end as u32)
            .copy_from(&buf[..len]);
        self.pos = end;
        Ok(len)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(target_os = "macos")]
use std::os::macos::fs::FileTimesExt;
#[cfg(windows)]
use std::os::windows::fs::FileTimesExt;
use std::{
    fs::FileTimes,
    io::{Read, Seek},
    path::{Path, PathBuf},
};

use crate::{Error, Password, *};

/// Decompresses an archive file to a destination directory.
///
/// This is a convenience function for decompressing archive files directly from the filesystem.
///
/// # Arguments
/// * `src_path` - Path to the source archive file
/// * `dest` - Path to the destination directory where files will be extracted
pub fn decompress_file(src_path: impl AsRef<Path>, dest: impl AsRef<Path>) -> Result<(), Error> {
    let file = std::fs::File::open(src_path.as_ref())
        .map_err(|e| Error::file_open(e, src_path.as_ref().to_string_lossy().to_string()))?;
    decompress(file, dest)
}

/// Decompresses an archive file to a destination directory with a custom extraction function.
///
/// The extraction function is called for each entry in the archive, allowing custom handling
/// of individual files and directories during extraction.
///
/// # Arguments
/// * `src_path` - Path to the source archive file
/// * `dest` - Path to the destination directory where files will be extracted
/// * `extract_fn` - Custom function to handle each archive entry during extraction
pub fn decompress_file_with_extract_fn(
    src_path: impl AsRef<Path>,
    dest: impl AsRef<Path>,
    extract_fn: impl FnMut(&ArchiveEntry, &mut dyn Read, &PathBuf) -> Result<bool, Error>,
) -> Result<(), Error> {
    let file = std::fs::File::open(src_path.as_ref())
        .map_err(|e| Error::file_open(e, src_path.as_ref().to_string_lossy().to_string()))?;
    decompress_with_extract_fn(file, dest, extract_fn)
}

/// Decompresses an archive from a reader to a destination directory.
///
/// # Arguments
/// * `src_reader` - Reader containing the archive data
/// * `dest` - Path to the destination directory where files will be extracted
pub fn decompress<R: Read + Seek>(src_reader: R, dest: impl AsRef<Path>) -> Result<(), Error> {
    decompress_with_extract_fn(src_reader, dest, default_entry_extract_fn)
}

/// Decompresses an archive from a reader to a destination directory with a custom extraction function.
///
/// This provides the most flexibility, allowing both custom input sources and custom extraction logic.
///
/// # Arguments
/// * `src_reader` - Reader containing the archive data
/// * `dest` - Path to the destination directory where files will be extracted
/// * `extract_fn` - Custom function to handle each archive entry during extraction
#[cfg(not(target_arch = "wasm32"))]
pub fn decompress_with_extract_fn<R: Read + Seek>(
    src_reader: R,
    dest: impl AsRef<Path>,
    extract_fn: impl FnMut(&ArchiveEntry, &mut dyn Read, &PathBuf) -> Result<bool, Error>,
) -> Result<(), Error> {
    decompress_impl(src_reader, dest, Password::empty(), extract_fn)
}

/// Decompresses an encrypted archive file with the given password.
///
/// # Arguments
/// * `src_path` - Path to the encrypted source archive file
/// * `dest` - Path to the destination directory where files will be extracted
/// * `password` - Password to decrypt the archive
#[cfg(all(feature = "aes256", not(target_arch = "wasm32")))]
pub fn decompress_file_with_password(
    src_path: impl AsRef<Path>,
    dest: impl AsRef<Path>,
    password: Password,
) -> Result<(), Error> {
    let file = std::fs::File::open(src_path.as_ref())
        .map_err(|e| Error::file_open(e, src_path.as_ref().to_string_lossy().to_string()))?;
    decompress_with_password(file, dest, password)
}

/// Decompresses an encrypted archive from a reader with the given password.
///
/// # Arguments
/// * `src_reader` - Reader containing the encrypted archive data
/// * `dest` - Path to the destination directory where files will be extracted
/// * `password` - Password to decrypt the archive
#[cfg(all(feature = "aes256", not(target_arch = "wasm32")))]
pub fn decompress_with_password<R: Read + Seek>(
    src_reader: R,
    dest: impl AsRef<Path>,
    password: Password,
) -> Result<(), Error> {
    decompress_impl(src_reader, dest, password, default_entry_extract_fn)
}

/// Decompresses an encrypted archive from a reader with a custom extraction function and password.
///
/// This provides maximum flexibility for encrypted archives, allowing custom input sources,
/// custom extraction logic, and password decryption.
///
/// # Arguments
/// * `src_reader` - Reader containing the encrypted archive data
/// * `dest` - Path to the destination directory where files will be extracted
/// * `password` - Password to decrypt the archive
/// * `extract_fn` - Custom function to handle each archive entry during extraction
#[cfg(all(feature = "aes256", not(target_arch = "wasm32")))]
pub fn decompress_with_extract_fn_and_password<R: Read + Seek>(
    src_reader: R,
    dest: impl AsRef<Path>,
    password: Password,
    extract_fn: impl FnMut(&ArchiveEntry, &mut dyn Read, &PathBuf) -> Result<bool, Error>,
) -> Result<(), Error> {
    decompress_impl(src_reader, dest, password, extract_fn)
}

#[cfg(not(target_arch = "wasm32"))]
fn decompress_impl<R: Read + Seek>(
    mut src_reader: R,
    dest: impl AsRef<Path>,
    password: Password,
    mut extract_fn: impl FnMut(&ArchiveEntry, &mut dyn Read, &PathBuf) -> Result<bool, Error>,
) -> Result<(), Error> {
    use std::io::SeekFrom;

    let pos = src_reader.stream_position()?;
    src_reader.seek(SeekFrom::Start(pos))?;
    let mut seven = ArchiveReader::new(src_reader, password)?;
    let dest = PathBuf::from(dest.as_ref());
    if !dest.exists() {
        std::fs::create_dir_all(&dest)?;
    }
    seven.for_each_entries(|entry, reader| {
        let dest_path = safe_join(&dest, entry.name())?;
        extract_fn(entry, reader, &dest_path)
    })?;

    Ok(())
}

/// Joins an untrusted archive entry name onto `dest`, rejecting any path that would
/// escape the destination directory (Zip-Slip / CWE-22).
///
/// Both `/` and `\` are treated as separators so Windows-style names are validated on
/// every platform, and any `..`, root, or drive-prefix component causes rejection.
#[cfg(not(target_arch = "wasm32"))]
fn safe_join(dest: &Path, entry_name: &str) -> Result<PathBuf, Error> {
    use std::path::Component;

    // Treat backslashes as separators too, so `..\..\x` from a Windows-authored
    // archive is caught when extracting on Unix.
    let normalized = entry_name.replace('\\', "/");
    let mut result = dest.to_path_buf();
    for component in Path::new(&normalized).components() {
        match component {
            Component::Normal(part) => result.push(part),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(Error::other(format!(
                    "unsafe entry path escapes destination: {entry_name}"
                )));
            }
        }
    }
    Ok(result)
}

/// Default extraction function that handles standard file and directory extraction.
///
/// # Security
/// `dest` must already be a path you have validated as staying inside your destination
/// directory. This function only rejects `..` components as a last line of defense;
/// because it receives the already-joined path it cannot detect an absolute entry name
/// that discarded the destination root (`root.join("/etc/x")` == `/etc/x`), so do not
/// build `dest` with `root.join(entry.name())`. Prefer the higher-level [`decompress`]
/// helpers, which perform the full traversal check for you.
///
/// # Arguments
/// * `entry` - Archive entry being processed
/// * `reader` - Reader for the entry's data
/// * `dest` - Destination path for the entry (already validated by the caller)
#[cfg(not(target_arch = "wasm32"))]
pub fn default_entry_extract_fn(
    entry: &ArchiveEntry,
    reader: &mut dyn Read,
    dest: &PathBuf,
) -> Result<bool, Error> {
    use std::{fs::File, io::BufWriter, path::Component};

    // Reject any `..` component so a relative-traversal path can never reach a write.
    // (An absolute escape cannot be detected here, as the destination root is unknown.)
    if dest.components().any(|c| c == Component::ParentDir) {
        return Err(Error::other(format!(
            "unsafe entry path contains a parent-directory component: {}",
            dest.to_string_lossy()
        )));
    }

    if entry.is_directory() {
        let dir = dest;
        if !dir.exists() {
            std::fs::create_dir_all(dir)?;
        }
    } else {
        let path = dest;
        path.parent().and_then(|p| {
            if !p.exists() {
                std::fs::create_dir_all(p).ok()
            } else {
                None
            }
        });
        let file = File::create(path)
            .map_err(|e| Error::file_open(e, path.to_string_lossy().to_string()))?;
        if entry.size() > 0 {
            let mut writer = BufWriter::new(file);
            std::io::copy(reader, &mut writer)?;

            let file = writer.get_mut();
            let file_times = FileTimes::new()
                .set_accessed(entry.access_date().into())
                .set_modified(entry.last_modified_date().into());

            #[cfg(any(windows, target_os = "macos"))]
            let file_times = file_times.set_created(entry.creation_date().into());

            let _ = file.set_times(file_times);
        }
    }

    Ok(true)
}

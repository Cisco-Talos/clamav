use std::{
    fs::File,
    io::Write,
    path::{Component, Path, PathBuf},
};

/// Joins an untrusted archive entry name onto `dest`, rejecting any path that would escape
/// the destination directory (Zip-Slip / CWE-22). Both `/` and `\` are treated as
/// separators, and any `..`, root, or drive-prefix component is rejected. Always route
/// `entry.name()` through a check like this instead of using `dest.join(entry.name())`.
fn safe_join(dest: &Path, entry_name: &str) -> std::io::Result<PathBuf> {
    let normalized = entry_name.replace('\\', "/");
    let mut result = dest.to_path_buf();
    for component in Path::new(&normalized).components() {
        match component {
            Component::Normal(part) => result.push(part),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("unsafe entry path escapes destination: {entry_name}"),
                ));
            }
        }
    }
    Ok(result)
}

fn main() {
    let mut sz =
        sevenz_rust2::ArchiveReader::open("examples/data/sample.7z", "pass".into()).unwrap();
    let total_size: u64 = sz
        .archive()
        .files
        .iter()
        .filter(|e| e.has_stream())
        .map(|e| e.size())
        .sum();
    let mut uncompressed_size = 0;
    let dest = PathBuf::from("examples/data/sample");
    sz.for_each_entries(|entry, reader| {
        let mut buf = [0u8; 1024];
        let path = safe_join(&dest, entry.name())?;
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let mut file = File::create(path).unwrap();
        loop {
            let read_size = reader.read(&mut buf)?;
            if read_size == 0 {
                break Ok(true);
            }
            file.write_all(&buf[..read_size])?;
            uncompressed_size += read_size;
            println!(
                "progress:{:.2}%",
                (uncompressed_size as f64 / total_size as f64) * 100f64
            );
        }
    })
    .unwrap();
}

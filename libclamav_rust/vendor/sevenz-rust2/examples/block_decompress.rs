use std::path::{Component, Path, PathBuf};

use sevenz_rust2::{Archive, BlockDecoder, Password};

/// Joins an untrusted archive entry name onto `dest`, rejecting any path that would escape
/// the destination directory (Zip-Slip / CWE-22). Always route `entry.name()` through a
/// check like this instead of using `dest.join(entry.name())`.
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
    let mut file = std::fs::File::open("examples/data/sample.7z").unwrap();
    let password = Password::empty();
    let archive = Archive::read(&mut file, &password).unwrap();
    let block_count = archive.blocks.len();
    let my_file_name = "7zFormat.txt";

    for block_index in 0..block_count {
        let forder_dec = BlockDecoder::new(1, block_index, &archive, &password, &mut file);

        if !forder_dec
            .entries()
            .iter()
            .any(|entry| entry.name() == my_file_name)
        {
            // skip the folder if it does not contain the file we want
            continue;
        }
        let dest = PathBuf::from("examples/data/sample_mt/");

        forder_dec
            .for_each_entries(&mut |entry, reader| {
                if entry.name() == my_file_name {
                    //only extract the file we want
                    let dest = safe_join(&dest, entry.name())?;
                    sevenz_rust2::default_entry_extract_fn(entry, reader, &dest)?;
                } else {
                    //skip other files
                    std::io::copy(reader, &mut std::io::sink())?;
                }
                Ok(true)
            })
            .expect("ok");
    }
}

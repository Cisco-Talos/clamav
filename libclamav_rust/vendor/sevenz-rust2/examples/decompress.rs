use std::{fs::File, time::Instant};

use sevenz_rust2::default_entry_extract_fn;

fn main() {
    let instant = Instant::now();
    sevenz_rust2::decompress_with_extract_fn_and_password(
        File::open("examples/data/sample.7z").unwrap(),
        "examples/data/sample",
        "pass".into(),
        |entry, reader, dest| {
            println!("start extract {}", entry.name());
            let r = default_entry_extract_fn(entry, reader, dest);
            println!("complete extract {}", entry.name());
            r
        },
    )
    .expect("complete");
    println!("decompress done:{:?}", instant.elapsed());
}

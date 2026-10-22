use std::{
    env,
    fs::File,
    io::{self, BufReader},
    time::Instant,
};

use lzma_rust2::XzReader;

fn main() -> io::Result<()> {
    let mut args = env::args();

    let input = BufReader::new(File::open(args.nth(1).unwrap())?);
    let mut output = File::create(args.next().unwrap())?;
    let input_len = input.get_ref().metadata()?.len();
    let start = Instant::now();
    let mut reader = XzReader::new(input, true);
    io::copy(&mut reader, &mut output)?;
    let output_len = output.metadata()?.len();
    let elapsed = start.elapsed();

    println!("{input_len} in");
    println!("{output_len} out");
    println!("{elapsed:?}");
    Ok(())
}

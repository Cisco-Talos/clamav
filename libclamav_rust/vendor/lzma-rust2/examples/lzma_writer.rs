use std::{
    env,
    fs::File,
    io::{self, BufReader},
    time::Instant,
};

use lzma_rust2::{LzmaOptions, LzmaWriter};

fn main() -> io::Result<()> {
    let mut args = env::args();

    let mut input = BufReader::new(File::open(args.nth(1).unwrap())?);
    let output = File::create(args.next().unwrap())?;
    let input_len = input.get_ref().metadata()?.len();
    let start = Instant::now();
    let mut writer = LzmaWriter::new_use_header(output, &LzmaOptions::default(), Some(input_len))?;
    io::copy(&mut input, &mut writer)?;
    let output_len = writer.finish()?.metadata()?.len();
    let elapsed = start.elapsed();

    println!("{input_len} in");
    println!("{output_len} out");
    println!("{elapsed:?}");
    Ok(())
}

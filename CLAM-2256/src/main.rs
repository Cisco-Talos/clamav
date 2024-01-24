use std::fs;
use std::io;

/*
fn readFile(fileName: &String) ->Vec<u8> {
    let bytes = fs::read(fileName);

    return bytes;
}
*/


fn main() {
    let args: Vec<_> = std::env::args().collect();
    if args.len() < 3 {
        println!("Usage: {} <filename> <outdir>", args[0]);
    }
    let fileName = &args[1];
    let outDir = &args[2];
    println!("Filename = {}", fileName);
    println!("Outdir = {}", outDir);

    let fname = std::path::Path::new(fileName);
    let file = fs::File::open(fname).unwrap();
    let bytes: Vec<u8> = fs::read(fileName).unwrap();


    println!("{:02X?} {:02X?} {:02X?} {:02X?} ", bytes[0], bytes[1], bytes[2], bytes[3]);


}

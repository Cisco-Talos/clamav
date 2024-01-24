use std::fs;
use std::io;

/* Check for the ALZ file header. */
fn isAlz(fileContents: &Vec<u8>) -> bool {
    if (4 >= fileContents.len()){
        return false;
    }

    return (0x41 == fileContents[0])
        && (0x4c == fileContents[1])
        && (0x5a == fileContents[2])
        && (0x01 == fileContents[3])
        ;
}

fn main() {
    let args: Vec<_> = std::env::args().collect();
    if args.len() < 3 {
        println!("Usage: {} <filename> <outdir>", args[0]);
    }
    let fileName = &args[1];
    let outDir = &args[2];
    println!("Filename = {}", fileName);
    println!("Outdir = {}", outDir);

//    let fname = std::path::Path::new(fileName);
//    let file = fs::File::open(fname).unwrap();
    let bytes: Vec<u8> = fs::read(fileName).unwrap();

    if (!isAlz(&bytes)){
        println!("NOT ALZ, need to return an exit status here");

        /*Need an exit status for wrong file type.*/
        return;
    }

    println!("Is ALZ (so far), continuing");
}





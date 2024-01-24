use std::fs;
//use std::io;
use std::io::Cursor;
use byteorder::{LittleEndian, ReadBytesExt};

struct AlzLocalFileHeader {
    file_name_length: u16,

    file_attribute: u8,

    file_time_date: u32,

    file_descriptor: u8,

    unknown: u8,
}

const ALZ_FILE_HEADER: u32 = 0x015a4c41;
const ALZ_LOCAL_FILE_HEADER: u32 = 0x015a4c42;

/* Check for the ALZ file header. */
fn is_alz(cursor: &mut std::io::Cursor<&Vec<u8>>) -> bool {
    if 4 >= cursor.get_ref().len(){
        return false;
    }

    return ALZ_FILE_HEADER == cursor.read_u32::<LittleEndian>().unwrap();
}

fn is_alz_local_file_header(cursor: &mut std::io::Cursor<&Vec<u8>>) -> bool {
    if 4 >= cursor.get_ref().len(){
        return false;
    }

    return ALZ_LOCAL_FILE_HEADER == cursor.read_u32::<LittleEndian>().unwrap();
}


fn parse_file_header(cursor: &mut std::io::Cursor<&Vec<u8>>) -> i32{
    /*TODO: Return an error, and don't have to mess with signed types.*/
    let idx: i32 = 0;
    println!("TODO: chagne return type to not have to mess with signedness");

    if !is_alz_local_file_header(cursor){
        println!("Parse ERROR: Not a local file header");
        return -1;
    }

    return idx;
}

fn process_file(bytes: &Vec<u8>, out_dir: &String){

    println!("Outdir = {}", out_dir);

    /*The first file header should start at 8,
     * assuming this is actualy an alz file.*/
    let mut idx: usize = 8;
    let mut cursor = Cursor::new(bytes);

    if !is_alz(&mut cursor){
        println!("NOT ALZ, need to return an exit status here");

        /*Need an exit status for wrong file type.*/
        return;
    }
    cursor.read_u32::<LittleEndian>().unwrap(); //ignore results, just doing this to skip 4 bytes.

    while idx < bytes.len(){
        let val: i32 = parse_file_header(&mut cursor);
        if -1 == val{
            break;
        }
        idx += val as usize;

        break;
    }

//    println!("bytes : {:02X} {:02x} {:02x}", sv[0], sv[1], sv[2]);


    println!("Is ALZ (so far), continuing");

    /*After reading the initial header, appears to be skipping 4 bytes  (maybe they are ignored) */


}

fn main() {
    let args: Vec<_> = std::env::args().collect();

    if args.len() < 3 {
        println!("Usage: {} <filename> <outdir>", args[0]);
        return;
    }
    let file_name = &args[1];
    let out_dir = &args[2];

    let bytes: Vec<u8> = fs::read(file_name).unwrap();
    process_file(&bytes, out_dir);

}





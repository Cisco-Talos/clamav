use std::fs;
//use std::io;
use std::io::Cursor;
use byteorder::{LittleEndian, ReadBytesExt};

#[derive(Debug)]
struct ALZParseError {
}

struct AlzLocalFileHeader {
    _file_name_length: u16,

    _file_attribute: u8,

    _file_time_date: u32,

    _file_descriptor: u8,

    _unknown: u8,
}


impl AlzLocalFileHeader {
    pub fn new( cursor: &mut std::io::Cursor<&Vec<u8>> ) -> Result<Self, ALZParseError> {
        let mut is_encrypted : bool = false;
        let mut is_data_descriptor : bool = false;

        if std::mem::size_of::<AlzLocalFileHeader>() >= cursor.get_ref().len(){
            return Err(ALZParseError{});
        }

        let ret = Self {
                /*TODO: Is it safe to call unwrap here, since I already checked that there is
                 * enough space in the buffer?
                 */
                _file_name_length : cursor.read_u16::<LittleEndian>().unwrap(),
                _file_attribute : cursor.read_u8::<>().unwrap(),
                _file_time_date: cursor.read_u32::<LittleEndian>().unwrap(),
                _file_descriptor : cursor.read_u8::<>().unwrap(),
                _unknown : cursor.read_u8::<>().unwrap(),
            };

        if 0 != (ret._file_descriptor & 0x1 ) {
            is_encrypted = true;
        }

        if 0 != (ret._file_descriptor  & 0x8) {
            is_data_descriptor = true;
        }

        println!("TODO: MAY need to move these flags to the struct");
        println!("is_encrypted = {}", is_encrypted);
        println!("is_data_descriptor = {}", is_data_descriptor);

        return Ok(ret);
    }
}

const ALZ_FILE_HEADER: u32 = 0x015a4c41;
const ALZ_LOCAL_FILE_HEADER: u32 = 0x015a4c42;

/* Check for the ALZ file header. */
fn is_alz(cursor: &mut std::io::Cursor<&Vec<u8>>) -> bool {

    if std::mem::size_of::<u32>() >= cursor.get_ref().len(){
        return false;
    }

    return ALZ_FILE_HEADER == cursor.read_u32::<LittleEndian>().unwrap();
}

fn is_alz_local_file_header(cursor: &mut std::io::Cursor<&Vec<u8>>) -> bool {
    if std::mem::size_of::<u32>() >= cursor.get_ref().len(){
        return false;
    }

    return ALZ_LOCAL_FILE_HEADER == cursor.read_u32::<LittleEndian>().unwrap();
}


fn parse_local_file_header(cursor: &mut std::io::Cursor<&Vec<u8>>) -> bool{

    if !is_alz_local_file_header(cursor){
        println!("Parse ERROR: Not a local file header");
        return false;
    }

    let res = AlzLocalFileHeader::new(cursor);
    if res.is_err(){
        println!("Parse ERROR: Not a local file header (2)");
        return false;
    }

    /*TODO: Is it safe to call unwrap here, since I already called 'is_err' */
    let alfh = res.unwrap();
    println!("fnl = {}", alfh._file_name_length);

    println!("HERE HERE HERE, continue parsing the headers");

    return true;
}

fn process_file(bytes: &Vec<u8>, out_dir: &String){

    println!("Outdir = {}", out_dir);

    /*The first file header should start at 8,
     * assuming this is actualy an alz file.*/
    let idx: usize = 8;
    let mut cursor = Cursor::new(bytes);

    if !is_alz(&mut cursor){
        println!("NOT ALZ, need to return an exit status here");

        /*Need an exit status for wrong file type.*/
        return;
    }
    cursor.read_u32::<LittleEndian>().unwrap(); //ignore results, just doing this to skip 4 bytes.

    while idx < bytes.len(){
        if !parse_local_file_header(&mut cursor){
            break;
        }

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





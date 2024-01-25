use std::fs;
//use std::io;
use std::io::Cursor;
use byteorder::{LittleEndian, ReadBytesExt};
use std::mem::size_of;

//use std::io::Read;

#[derive(Debug)]
struct ALZParseError {
}

struct AlzLocalFileHeaderHead {
    _file_name_length: u16,

    _file_attribute: u8,

    _file_time_date: u32,

    _file_descriptor: u8,

    _unknown: u8,

    }

struct AlzLocalFileHeader {
    _head: AlzLocalFileHeaderHead,

    _compression_method: u8,
    _unknown: u8,
    _file_crc: u32,

    /* Can be smaller sizes, depending on _file_descriptor/0x10 .*/
    _compressed_size: u64,
    _uncompressed_size: u64,

    _file_name: String,

}


impl AlzLocalFileHeader {
    pub fn new( cursor: &mut std::io::Cursor<&Vec<u8>> ) -> Result<Self, ALZParseError> {
        let mut is_encrypted : bool = false;
        let mut is_data_descriptor : bool = false;

        if size_of::<AlzLocalFileHeaderHead>() >= cursor.get_ref().len(){
            return Err(ALZParseError{});
        }

        let mut ret = Self {
                /*TODO: Is it safe to call unwrap here, since I already checked that there is
                 * enough space in the buffer?
                 */
                _head : AlzLocalFileHeaderHead {
                    _file_name_length : cursor.read_u16::<LittleEndian>().unwrap(),
                    _file_attribute : cursor.read_u8::<>().unwrap(),
                    _file_time_date: cursor.read_u32::<LittleEndian>().unwrap(),
                    _file_descriptor : cursor.read_u8::<>().unwrap(),
                    _unknown : cursor.read_u8::<>().unwrap(),
                },

                _compression_method : 0,
                _unknown : 0,
                _file_crc : 0,
                _compressed_size : 0,
                _uncompressed_size : 0,
                _file_name : "".to_string(),

            };

        if 0 == ret._head._file_name_length {
            println!("Filename length cannot be zero");
            return Err(ALZParseError{});
        }

        if 0 != (ret._head._file_descriptor & 0x1 ) {
            is_encrypted = true;
        }

        if 0 != (ret._head._file_descriptor  & 0x8) {
            is_data_descriptor = true;
        }

        if is_encrypted {
            assert!(false, "ENCRYPTION UNIMPLEMENTED");
        }

        if is_data_descriptor {
            assert!(false, "IS DATA DESCRIPTOR UNIMPLEMENTED");
        }

        let byte_len = ret._head._file_descriptor / 0x10;
        println!("byte_len = {}", byte_len);
        if byte_len > 0 {

            if (size_of::<u8>() + size_of::<u8>() + size_of::<u32>()) >= cursor.get_ref().len(){
                return Err(ALZParseError{});
            }

            ret._compression_method = cursor.read_u8::<>().unwrap();
            ret._unknown = cursor.read_u8::<>().unwrap();
            ret._file_crc = cursor.read_u32::<LittleEndian>().unwrap();

            match byte_len {
                1 => {
                    if (size_of::<u8>() * 2) >= cursor.get_ref().len() {
                        return Err(ALZParseError{});
                    }
                    ret._compressed_size = cursor.read_u8::<>().unwrap() as u64;
                    ret._uncompressed_size = cursor.read_u8::<>().unwrap() as u64;
                },
                2 => {
                    if (size_of::<u16>() * 2) >= cursor.get_ref().len() {
                        return Err(ALZParseError{});
                    }
                    ret._compressed_size = cursor.read_u16::<LittleEndian>().unwrap() as u64;
                    ret._uncompressed_size = cursor.read_u16::<LittleEndian>().unwrap() as u64;
                },
                4 => {
                    if (size_of::<u32>() * 2) >= cursor.get_ref().len() {
                        return Err(ALZParseError{});
                    }
                    ret._compressed_size = cursor.read_u32::<LittleEndian>().unwrap() as u64;
                    ret._uncompressed_size = cursor.read_u32::<LittleEndian>().unwrap() as u64;
                },
                8 => {
                    if (size_of::<u64>() * 2) >= cursor.get_ref().len() {
                        return Err(ALZParseError{});
                    }
                    ret._compressed_size = cursor.read_u64::<LittleEndian>().unwrap() as u64;
                    ret._uncompressed_size = cursor.read_u64::<LittleEndian>().unwrap() as u64;
                },
                _ => return Err(ALZParseError{}),
            }
        } else {
            println!("DON'T THINK THIS IS EVER POSSIBLE, SEE IF IT COMES OUT IN TESTING!!!!!");
            assert!(false, "EXITING HERE");
            /*
             * TODO: In 'unalz', (UnAlz.cpp, CUnAlz::ReadLocalFileheader), the condition where
             * byte_len (byteLen) is zero is treated as a condition that can be ignored, and
             * processing can continue.  I think it's probably a parse error when that
             * happens and it never causes an issue because the file then fails crc and an error is
             * reported, rather than just stopping parsing when that happens.  I would like to look
             * for a file that has that condition and see if unalz (or other unpackers) are able to
             * extract anything from the file.  If not, we can just return here.
             */
        }

        if ret._head._file_name_length as usize >= cursor.get_ref().len() {
            return Err(ALZParseError{});
        }

        let mut filename = vec![0u8, 1];
        /*TODO: Figure out the correct way to allocate a vector of dynamic size and call
         * cursor.read_exact, instead of having a loop of reads.*/
        for _i in 0..ret._head._file_name_length {
            filename.push( cursor.read_u8::<>().unwrap());
        }
        let res = String::from_utf8(filename);
        if res.is_ok(){
            ret._file_name = res.unwrap();
        } else {
            assert!(false, "NOT sure if other filename formats are supported here");
        }

        println!("ret._head._file_name_length = {:x}", ret._head._file_name_length);
        println!("ret._head._file_attribute = {:02x}", ret._head._file_attribute);
        println!("ret._head._file_time_date = {:x}", ret._head._file_time_date);
        println!("ret._head._file_descriptor = {:x}", ret._head._file_descriptor);
        println!("ret._head._unknown = {:x}", ret._head._unknown);

        println!("ret._compression_method = {:x}", ret._compression_method);
        println!("ret._unknown = {:x}", ret._unknown);
        println!("ret._file_crc = {:x}", ret._file_crc);
        println!("ret._compressed_size = {:x}", ret._compressed_size);
        println!("ret._uncompressed_size = {:x}", ret._uncompressed_size);

        println!("ret._file_name = {}", ret._file_name);

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
    println!("fnl = {}", alfh._head._file_name_length);

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





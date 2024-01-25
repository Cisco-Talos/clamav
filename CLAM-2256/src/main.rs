use std::fs;
//use std::io;
use std::io::Cursor;
use byteorder::{LittleEndian, ReadBytesExt};
use std::mem::size_of;

use std::io::Read;

#[derive(Debug)]
struct ALZParseError {
}

const ALZ_FILE_HEADER: u32 = 0x015a4c41;
const ALZ_LOCAL_FILE_HEADER: u32 = 0x015a4c42;
const ALZ_CENTRAL_DIRECTORY_HEADER: u32 = 0x015a4c43;
const ALZ_END_OF_CENTRAL_DIRECTORY_HEADER : u32 = 0x025a4c43;


struct AlzLocalFileHeaderHead {
    _file_name_length: u16,

    _file_attribute: u8,

    _file_time_date: u32,

    _file_descriptor: u8,

    _unknown: u8,

}

const ALZ_ENCR_HEADER_LEN: u32 = 12;

struct AlzLocalFileHeader {
    _head: AlzLocalFileHeaderHead,

    _compression_method: u8,
    _unknown: u8,
    _file_crc: u32,

    /* Can be smaller sizes, depending on _file_descriptor/0x10 .*/
    _compressed_size: u64,
    _uncompressed_size: u64,

    _file_name: String,

    _enc_chk: [u8; ALZ_ENCR_HEADER_LEN as usize],

    _start_of_compressed_data: u64,
}


impl AlzLocalFileHeader {
    fn is_encrypted(&mut self) -> bool {
        return 0 != (self._head._file_descriptor & 0x1 );
    }

    fn is_data_descriptor(&mut self) -> bool {
        return 0 != (self._head._file_descriptor & 0x8 );
    }

    pub fn new( cursor: &mut std::io::Cursor<&Vec<u8>> ) -> Result<Self, ALZParseError> {
        //let mut is_data_descriptor : bool = false;

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
                _enc_chk: [0; ALZ_ENCR_HEADER_LEN as usize],
                _start_of_compressed_data: 0,
            };

        if 0 == ret._head._file_name_length {
            println!("Filename length cannot be zero");
            return Err(ALZParseError{});
        }

        //if 0 != (ret._head._file_descriptor  & 0x8) {
            //is_data_descriptor = true;
        //}


        //if is_data_descriptor {
            //assert!(false, "IS DATA DESCRIPTOR UNIMPLEMENTED");
        //}

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
            /*TODO: Other formats*/
            assert!(false, "NOT sure if other filename formats are supported here");
        }

        if ret.is_encrypted() {
            if ALZ_ENCR_HEADER_LEN as usize > cursor.get_ref().len() {
                return Err(ALZParseError{});
            }

            /*TODO: Is it safe to call unwrap here, since I already checked that there are enough
             * bytes?
             */
            cursor.read_exact(&mut ret._enc_chk).unwrap();
        }

        ret._start_of_compressed_data = cursor.position();
        println!("ret._start_of_compressed_data = {}", ret._start_of_compressed_data );
        println!("ret._compressed_size = {}", ret._compressed_size );

        cursor.set_position(ret._start_of_compressed_data + ret._compressed_size);
        println!("cursor.position() = {}", cursor.position() );

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

        print!("ret._enc_chk = ");
        for i in 0..ALZ_ENCR_HEADER_LEN {
            if 0 != i {
                print!(" ");
            }
            print!("{}", ret._enc_chk[i as usize]);
        }
        println!("");


        println!("is_encrypted = {}", ret.is_encrypted());
        println!("is_data_descriptor = {}", ret.is_data_descriptor());

        println!("ret._start_of_compressed_data = {}", ret._start_of_compressed_data);

        if ret.is_encrypted() {
            assert!(false, "ENCRYPTION UNIMPLEMENTED");
        }

        if ret.is_data_descriptor() {
            assert!(false, "IS DATA DESCRIPTOR UNIMPLEMENTED");
        }

        return Ok(ret);
    }
}

/* Check for the ALZ file header. */
fn is_alz(cursor: &mut std::io::Cursor<&Vec<u8>>) -> bool {

    /*
    if std::mem::size_of::<u32>() >= cursor.get_ref().len(){
        return false;
    }

    return ALZ_FILE_HEADER == cursor.read_u32::<LittleEndian>().unwrap();
    */
    let ret = cursor.read_u32::<LittleEndian>();
    if ret.is_ok() {
        return ALZ_FILE_HEADER == ret.unwrap();
    }
    return false;
}

fn parse_local_file_header(cursor: &mut std::io::Cursor<&Vec<u8>>) -> bool{

    let res = AlzLocalFileHeader::new(cursor);
    if res.is_err(){
        println!("Parse ERROR: Not a local file header (2)");
        return false;
    }

    /*TODO: Is it safe to call unwrap here, since I already called 'is_err' */
    let local_file_header = res.unwrap();

    println!("HERE HERE HERE, continue parsing the headers {}", local_file_header._start_of_compressed_data);

    return true;
}


fn parse_central_directory_header(cursor: &mut std::io::Cursor<&Vec<u8>>) -> bool{
    /*
     * This is ignored in unalz (UnAlz.cpp ReadCentralDirectoryStructure).
     *
     * It actually reads 12 bytes, and I think it happens to work because EOF is hit on the next
     * read, which it does not consider an error.
     */
    let ret = cursor.read_u64::<LittleEndian>();
    return ret.is_ok();
}

fn process_file(bytes: &Vec<u8>, out_dir: &String) -> bool {

    println!("Outdir = {}", out_dir);

    let mut cursor = Cursor::new(bytes);

    if !is_alz(&mut cursor){
        println!("NOT ALZ, need to return an exit status here");

        /*Need an exit status for wrong file type.*/
        return false;
    }
    cursor.read_u32::<LittleEndian>().unwrap(); //ignore results, just doing this to skip 4 bytes.

    while 0 < cursor.get_ref().len() {

        let ret = cursor.read_u32::<LittleEndian>();
        if ret.is_err(){
            break;
        }
        let sig = ret.unwrap();

        match sig {
            ALZ_LOCAL_FILE_HEADER=>{
                if parse_local_file_header(&mut cursor){
                    println!("Found a local file header\n");
                    continue;
                }
            }
            ALZ_CENTRAL_DIRECTORY_HEADER=>{
                if parse_central_directory_header(&mut cursor){
                    println!("Found a central directory header\n");
                    continue;
                }
            }
            ALZ_END_OF_CENTRAL_DIRECTORY_HEADER=>{
                /*This is the end, nothing really to do here.*/
                    println!("Found an end of central directory header\n");
            }
            _ => {
                /*Parse error, maybe try and extract what is there???*/
                assert!(false, "NOT A VALID FILE IN MATCH");
            }
        }
    }

    println!("Is ALZ (so far), need to decompress/decrypt the file and check the crc.");

    return true;

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





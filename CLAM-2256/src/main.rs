use std::fs;
//use std::io;
use std::io::Cursor;
use byteorder::{LittleEndian, ReadBytesExt};
//use std::mem::size_of;

//use deflate::deflate_bytes;
//use flate2::Decompress;
//use flate2::FlushDecompress;
use flate2::read::GzDecoder;

//use flate2::write::{GzEncoder};
//use flate2::read::{GzDecoder};


use std::io::Read;

#[derive(Debug)]
struct ALZParseError {
}

#[derive(Debug)]
struct ALZExtractError {
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

    pub fn new() -> Self {

        Self {
                _head : AlzLocalFileHeaderHead {
                    _file_name_length : 0,
                    _file_attribute : 0,
                    _file_time_date: 0,
                    _file_descriptor : 0,
                    _unknown : 0,
                },

                _compression_method : 0,
                _unknown : 0,
                _file_crc : 0,
                _compressed_size : 0,
                _uncompressed_size : 0,
                _file_name : "".to_string(),
                _enc_chk: [0; ALZ_ENCR_HEADER_LEN as usize],
                _start_of_compressed_data: 0,
            }
    }

    pub fn parse( &mut self, cursor: &mut std::io::Cursor<&Vec<u8>> ) -> Result<(), ALZParseError> {
        /*
         * TODO: Should probably rename this to parse_header or something.
         */

        let mut tu16 = cursor.read_u16::<LittleEndian>();
        if tu16.is_err(){
            return Err(ALZParseError{});
        }
        self._head._file_name_length = tu16.unwrap();

        let mut tu8 = cursor.read_u8::<>();
        if tu8.is_err() {
            return Err(ALZParseError{});
        }
        self._head._file_attribute = tu8.unwrap();

        let mut tu32 = cursor.read_u32::<LittleEndian>();
        if tu32.is_err() {
            return Err(ALZParseError{});
        }
        self._head._file_time_date = tu32.unwrap();

        tu8 = cursor.read_u8::<>();
        if tu8.is_err() {
            return Err(ALZParseError{});
        }
        self._head._file_descriptor = tu8.unwrap();

        tu8 = cursor.read_u8::<>();
        if tu8.is_err() {
            return Err(ALZParseError{});
        }
        self._head._unknown = tu8.unwrap();

        if 0 == self._head._file_name_length {
            println!("Filename length cannot be zero");
            return Err(ALZParseError{});
        }

        let byte_len = self._head._file_descriptor / 0x10;
        if byte_len > 0 {

            tu8 = cursor.read_u8::<>();
            if tu8.is_err() {
                return Err(ALZParseError{});
            }
            self._compression_method = tu8.unwrap();

            tu8 = cursor.read_u8::<>();
            if tu8.is_err() {
                return Err(ALZParseError{});
            }
            self._unknown = tu8.unwrap();

            tu32 = cursor.read_u32::<LittleEndian>();
            if tu32.is_err() {
                return Err(ALZParseError{});
            }
            self._file_crc = tu32.unwrap();

            match byte_len {
                1 => {
                    tu8 = cursor.read_u8::<>();
                    if tu8.is_err() {
                        return Err(ALZParseError{});
                    }
                    self._compressed_size = tu8.unwrap() as u64;

                    tu8 = cursor.read_u8::<>();
                    if tu8.is_err() {
                        return Err(ALZParseError{});
                    }
                    self._uncompressed_size = tu8.unwrap() as u64;
                },
                2 => {
                    tu16 = cursor.read_u16::<LittleEndian>();
                    if tu16.is_err() {
                        return Err(ALZParseError{});
                    }
                    self._compressed_size = tu16.unwrap() as u64;

                    tu16 = cursor.read_u16::<LittleEndian>();
                    if tu16.is_err() {
                        return Err(ALZParseError{});
                    }
                    self._uncompressed_size = tu16.unwrap() as u64;

                },
                4 => {
                    tu32 = cursor.read_u32::<LittleEndian>();
                    if tu32.is_err() {
                        return Err(ALZParseError{});
                    }
                    self._compressed_size = tu32.unwrap() as u64;

                    tu32 = cursor.read_u32::<LittleEndian>();
                    if tu32.is_err() {
                        return Err(ALZParseError{});
                    }
                    self._uncompressed_size = tu32.unwrap() as u64;
                },
                8 => {
                    let mut tu64 = cursor.read_u64::<LittleEndian>();
                    if tu64.is_err() {
                        return Err(ALZParseError{});
                    }
                    self._compressed_size = tu64.unwrap() as u64;

                    tu64 = cursor.read_u64::<LittleEndian>();
                    if tu64.is_err() {
                        return Err(ALZParseError{});
                    }
                    self._uncompressed_size = tu64.unwrap() as u64;
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

        if self._head._file_name_length as usize >= cursor.get_ref().len() {
            return Err(ALZParseError{});
        }

        let mut filename: Vec<u8> = Vec::new();
        /*TODO: Figure out the correct way to allocate a vector of dynamic size and call
         * cursor.read_exact, instead of having a loop of reads.*/
        for _i in 0..self._head._file_name_length {
            let ret = cursor.read_u8::<>();
            if ret.is_err() {
                println!("Error reading contents of the file name");
                return Err(ALZParseError{});
            }
            
            filename.push( ret.unwrap());
        }


        let res = String::from_utf8(filename);
        if res.is_ok(){
            self._file_name = res.unwrap();
        } else {
            /*TODO: Other formats*/
            assert!(false, "NOT sure if other filename formats are supported here");
        }

        if self.is_encrypted() {
            if ALZ_ENCR_HEADER_LEN as usize > cursor.get_ref().len() {
                return Err(ALZParseError{});
            }

            /*TODO: Is it safe to call unwrap here, since I already checked that there are enough
             * bytes?
             */
            cursor.read_exact(&mut self._enc_chk).unwrap();
        }

        self._start_of_compressed_data = cursor.position();
        println!("self._start_of_compressed_data = {}", self._start_of_compressed_data );

        cursor.set_position(self._start_of_compressed_data + self._compressed_size);
        println!("cursor.position() = {}", cursor.position() );

        println!("self._head._file_name_length = {:x}", self._head._file_name_length);
        println!("self._head._file_attribute = {:02x}", self._head._file_attribute);
        println!("self._head._file_time_date = {:x}", self._head._file_time_date);
        println!("self._head._file_descriptor = {:x}", self._head._file_descriptor);
        println!("self._head._unknown = {:x}", self._head._unknown);

        println!("self._compression_method = {:x}", self._compression_method);
        println!("self._unknown = {:x}", self._unknown);
        println!("self._file_crc = {:x}", self._file_crc);
        println!("self._compressed_size = {:x}", self._compressed_size);
        println!("self._uncompressed_size = {:x}", self._uncompressed_size);

        println!("self._file_name = {}", self._file_name);

        print!("self._enc_chk = ");
        for i in 0..ALZ_ENCR_HEADER_LEN {
            if 0 != i {
                print!(" ");
            }
            print!("{}", self._enc_chk[i as usize]);
        }
        println!("");


        println!("is_encrypted = {}", self.is_encrypted());
        println!("is_data_descriptor = {}", self.is_data_descriptor());

        println!("self._start_of_compressed_data = {}", self._start_of_compressed_data);

        if self.is_encrypted() {
            assert!(false, "ENCRYPTION UNIMPLEMENTED");
        }

        if self.is_data_descriptor() {
            assert!(false, "IS DATA DESCRIPTOR UNIMPLEMENTED");
        }

        return Ok(());
    }

    fn extract_file_deflate(&mut self, cursor: &mut std::io::Cursor<&Vec<u8>>, out_dir: &String) -> Result<(), ALZExtractError>{
        println!("Outdir = {}", out_dir);
        println!("start of compressed data  = {}", self._start_of_compressed_data);
        cursor.set_position(self._start_of_compressed_data);

        let mut contents: Vec<u8> = Vec::new();

        //TODO: Consider putting a header on and formatting this properly, so
        //we don't have to implement deflate.
        //https://en.wikipedia.org/wiki/Gzip


contents.push(0x1f);
contents.push(0x8b );
contents.push(0x08 );
contents.push(0x08 );
contents.push(0xc6 );
contents.push(0xa7 );
contents.push(0x1c );
contents.push(0x4a );
contents.push(0x00 );
contents.push(0x03 );
contents.push(0x61 );
contents.push(0x6c );
contents.push(0x7a );
contents.push(0x20 );
contents.push(0x74 );
contents.push(0x65 );
contents.push(0x73 );
contents.push(0x74 );
contents.push(0x20 );
contents.push(0x66 );
contents.push(0x69 );
contents.push(0x6c );
contents.push(0x65 );
contents.push(0x2e );
contents.push(0x74 );
contents.push(0x78 );
contents.push(0x74 );
contents.push(0x00 );



        /*TODO: Figure out the correct way to allocate a vector of dynamic size and call
         * cursor.read_exact, instead of having a loop of reads.*/
        for _i in 0..self._compressed_size {
            let ret = cursor.read_u8::<>();
            if ret.is_err() {
                println!("Cannot read full amount of data");
                return Err(ALZExtractError{});
            }

            contents.push( ret.unwrap());
        }

contents.push(0x17 );
contents.push(0x5f );
contents.push(0x58 );
contents.push(0xf7 );
contents.push(0x5d );
contents.push(0x00 );
contents.push(0x00 );
contents.push(0x00);

        //let mut data:Vec<u8> = Vec::new();





        let mut d = GzDecoder::new(&*contents);
        let mut s = String::new();
        let ret = d.read_to_string(&mut s);
        if ret.is_err() {
            assert!(false, "ERROR in decompress");
        }
        println!("Extracted data = '{}'", s);

        println!("TODO!!!!!  FIGURE OUT HOW TO DECOMPRESS WITHOUT THE HEADER AND FOOTER THAT I HARDCODED");

        return Ok(());
    }

    fn extract_file(&mut self, cursor: &mut std::io::Cursor<&Vec<u8>>, out_dir: &String) -> Result<(), ALZExtractError>{
        const ALZ_COMP_NOCOMP: u8 = 0;
        const ALZ_COMP_BZIP2: u8 = 1;
        const ALZ_COMP_DEFLATE: u8 = 2;

        /*TODO: Consider extracting encrypted data to separate files.  Maybe
         *      someone is interested in signaturing those files???
         */
        if self.is_encrypted(){
            println!("Figure out if we can support encryption");
            return Err(ALZExtractError{});
        }

        match self._compression_method {
            ALZ_COMP_NOCOMP=>{
                assert!(false, "Nocomp Unimplemented");
            }
            ALZ_COMP_BZIP2=>{
                assert!(false, "Bzip2 Unimplemented");
            }
            ALZ_COMP_DEFLATE=>{
                return self.extract_file_deflate(cursor, out_dir);
            }
            _=>{
                println!("Unsupported compression");
                return Err(ALZExtractError{});
            }
        }

        return Ok(());
    }
}

/* Check for the ALZ file header. */
fn is_alz(cursor: &mut std::io::Cursor<&Vec<u8>>) -> bool {
    let ret = cursor.read_u32::<LittleEndian>();
    if ret.is_ok() {
        return ALZ_FILE_HEADER == ret.unwrap();
    }
    return false;
}

fn parse_local_file_header(cursor: &mut std::io::Cursor<&Vec<u8>>, out_dir: &String) -> bool{

    let mut local_file_header = AlzLocalFileHeader::new();

    let res = local_file_header.parse(cursor);
    if res.is_err(){
        println!("Parse ERROR: Not a local file header (2)");
        return false;
    }

    let res2 = local_file_header.extract_file(cursor, out_dir);
    if res2.is_err() {
        println!("Extract ERROR: ");
        return false;
    }

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

    loop {

        let ret = cursor.read_u32::<LittleEndian>();
        if ret.is_err(){
            break;
        }
        let sig = ret.unwrap();

        match sig {
            ALZ_LOCAL_FILE_HEADER=>{
                if parse_local_file_header(&mut cursor, out_dir){
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





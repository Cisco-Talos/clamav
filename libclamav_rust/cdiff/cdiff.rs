/*
 *  Copyright (C) 2021 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *
 *  Authors: John Humlick
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA 02110-1301, USA.
 */

extern crate hex;
extern crate openssl;

use std::{
    ffi::CString,
    fs::{self, File, OpenOptions},
    io::{prelude::*, BufReader, Read, Seek, SeekFrom},
    iter::*,
    os::unix::io::FromRawFd,
    process,
};

use flate2::read::GzDecoder;
// use crypto instead of openssl
use openssl::sha;
use thiserror::Error;

const MAX_DSIG_SIZE: usize = 350;
const FILEBUFF: usize = 8192;

const PSS_NSTR: &str = "14783905874077467090262228516557917570254599638376203532031989214105552847269687489771975792123442185817287694951949800908791527542017115600501303394778618535864845235700041590056318230102449612217458549016089313306591388590790796515819654102320725712300822356348724011232654837503241736177907784198700834440681124727060540035754699658105895050096576226753008596881698828185652424901921668758326578462003247906470982092298106789657211905488986281078346361469524484829559560886227198091995498440676639639830463593211386055065360288422394053998134458623712540683294034953818412458362198117811990006021989844180721010947\0";
const PSS_ESTR: &str = "100002053\0";

struct DelNode {
    line_no: usize,
    del_line: String,
}

struct XchgNode {
    line_no: usize,
    orig_line: String,
    new_line: String,
}

struct Context {
    open_db: Option<String>,
    add_start: Option<Vec<String>>,
    del_start: Option<Vec<DelNode>>,
    xchg_start: Option<Vec<XchgNode>>,
}

/// CdiffError enumerates all possible errors returned by this library.
#[derive(Error, Debug)]
pub enum CdiffError {
    #[error("No DB open for action {0}")]
    NoDBForAction(String),

    #[error("File {0} not closed before calling action {1}")]
    NotClosedBeforeAction(String, String),

    #[error("File {0} not closed before opening {1}")]
    NotClosedBeforeOpening(String, String),

    #[error("Forbidden characters found in database name {0}")]
    ForbiddenCharactersInDB(String),

    #[error("Invalid command provided: {0}")]
    InvalidCommand(String),

    #[error("Unexpected end of line while parsing field: {0}")]
    NoMoreData(String),

    #[error("File contains fewer than {0} bytes")]
    NotEnoughBytes(usize),

    #[error("Incorrect file format - {0}")]
    MalformedFile(String),

    #[error("Move operation failed")]
    MoveOpFailed,

    #[error("Failed to parse string as a number")]
    ParseIntError(#[from] std::num::ParseIntError),

    #[error("Cannot perform action {0} on line {1} in file {2}. Pattern does not match.")]
    PatternDoesNotMatch(String, usize, String),

    #[error("Failed to parse dsig!")]
    ParseDsigError,

    #[error("Not all delete lines processed at file end")]
    NotAllDeleteProcessed,

    #[error("Not all exchange lines processed at file end")]
    NotAllExchangeProcessed,

    /// Represents all other cases of `std::io::Error`.
    #[error(transparent)]
    IOError(#[from] std::io::Error),

    #[error(transparent)]
    FromUtf8Error(#[from] std::string::FromUtf8Error),
}

#[derive(Debug)]
pub struct DelOp<'a> {
    line_no: usize,
    del_line: &'a str,
}

// Method to parse the cdiff line describing a delete operation
impl<'a> DelOp<'a> {
    pub fn new(data: &'a str) -> Result<Self, CdiffError> {
        // Extract src db, dst db, start line no, start line, end line no, end line
        let mut iter = data.split_whitespace();

        Ok(DelOp {
            line_no: iter
                .next()
                .ok_or_else(|| CdiffError::NoMoreData("line_no".to_string()))?
                .parse::<usize>()?,
            del_line: iter
                .next()
                .ok_or_else(|| CdiffError::NoMoreData("del_line".to_string()))?,
        })
    }
}

#[derive(Debug)]
pub struct MoveOp<'a> {
    src: &'a str,
    dst: &'a str,
    start_line_no: usize,
    start_line: &'a str,
    end_line_no: usize,
    end_line: &'a str,
}

// Method to parse the cdiff line describing a move operation
impl<'a> MoveOp<'a> {
    pub fn new(data: &'a str) -> Result<Self, CdiffError> {
        // Extract src db, dst db, start line no, start line, end line no, end line
        let mut iter = data.split_whitespace();

        Ok(MoveOp {
            src: iter
                .next()
                .ok_or_else(|| CdiffError::NoMoreData("src".to_string()))?,
            dst: iter
                .next()
                .ok_or_else(|| CdiffError::NoMoreData("dst".to_string()))?,
            start_line_no: iter
                .next()
                .ok_or_else(|| CdiffError::NoMoreData("start_line_no".to_string()))?
                .parse::<usize>()?,
            start_line: iter
                .next()
                .ok_or_else(|| CdiffError::NoMoreData("start_line".to_string()))?,
            end_line_no: iter
                .next()
                .ok_or_else(|| CdiffError::NoMoreData("end_line_no".to_string()))?
                .parse::<usize>()?,
            end_line: iter
                .next()
                .ok_or_else(|| CdiffError::NoMoreData("end_line".to_string()))?,
        })
    }
}

#[derive(Debug)]
pub struct XchgOp<'a> {
    line_no: usize,
    orig_line: &'a str,
    new_line: &'a str,
}

/// Todo: rewrite this code so that it can handle multiple whitespaces between fields

// Method to parse the cdiff line describing an exchange operation
impl<'a> XchgOp<'a> {
    pub fn new(data: &'a str) -> Result<Self, CdiffError> {
        // Extract start line no, orig line, and new line
        let mut iter = data.splitn(3, char::is_whitespace);

        Ok(XchgOp {
            line_no: iter
                .next()
                .ok_or_else(|| CdiffError::NoMoreData("line_no".to_string()))?
                .parse::<usize>()?,
            orig_line: iter
                .next()
                .ok_or_else(|| CdiffError::NoMoreData("orig_line".to_string()))?,
            new_line: iter
                .next()
                .ok_or_else(|| CdiffError::NoMoreData("new_line".to_string()))?,
        })
    }
}

// int cli_versig2(const unsigned char *sha256, const char *dsig_str, const char *n_str, const char *e_str)
extern "C" {
    fn cli_versig2(digest: *const u8, dsig: *const i8, n: *const u8, e: *const u8) -> i32;
    fn logg(fmt: *const u8, args: ...) -> i32;
}

#[no_mangle]
pub fn cdiff_apply(file_descriptor: i32, mode: u16) -> i32 {
    eprintln!(
        "cdiff_apply called with file_descriptor={}, mode={}",
        file_descriptor, mode
    );
    let path = std::env::current_dir().unwrap();
    println!("The current directory is {}", path.display());

    eprintln!("Opening file descriptor");

    let mut file = unsafe { File::from_raw_fd(file_descriptor) };
    eprintln!("Printing contents of file...");

    let dsig = read_dsig(&mut file);
    let dsig = match dsig {
        Ok(dsig) => dsig,
        Err(e) => {
            eprintln!("{:?}", e.to_string());
            return -1;
        }
    };
    eprintln!("Final dsig length is {}", dsig.len());
    print_file_data(dsig.clone(), dsig.len() as usize);

    // Get file length
    let file_len = match file.metadata() {
        Ok(file_len) => file_len.len() as usize,
        Err(e) => {
            eprint!("Failed to get file length: {}", e.to_string());
            return -1;
        }
    };
    let footer_offset = file_len - dsig.len() - 1;

    // The SHA is calculated from the contents of the beginning of the file
    // up until the ':' before the dsig at the end of the file.
    let sha256 = get_hash(&mut file, footer_offset);
    let sha256 = match sha256 {
        Ok(sha256) => sha256,
        Err(e) => {
            eprint!("Failed to calculate sha256: {}", e.to_string());
            return -1;
        }
    };

    //eprintln!("sha256 is {} bytes", sha256.len());
    eprintln!("sha256: {}", hex::encode(sha256));

    // cli_versig2 will expect dsig to be a null-terminated string
    let dsig_cstring = CString::new(dsig);
    let dsig_cstring = match dsig_cstring {
        Ok(dsig_cstring) => dsig_cstring,
        Err(e) => {
            eprint!("Failed to parse dsig: {}", e.to_string());
            return -1;
        }
    };

    // Verfify cdiff
    let versig_result = unsafe {
        cli_versig2(
            sha256.to_vec().as_ptr(),
            dsig_cstring.as_ptr(),
            PSS_NSTR.as_ptr(),
            PSS_ESTR.as_ptr(),
        )
    };
    if versig_result != 0 {
        eprintln!("cdiff_apply: Incorrect digital signature");
        return -1;
    }

    // Read file length from header
    let header_result = read_size(&mut file);
    let (header_len, header_offset) = match header_result {
        Ok(hl) => hl,
        Err(e) => {
            eprint!("{}", e.to_string());
            return -1;
        }
    };
    eprintln!(
        "Header len is {}, file len is {}, header offset is {}",
        header_len, file_len, header_offset
    );

    let current_pos = file.seek(SeekFrom::Start(header_offset as u64));
    let current_pos = match current_pos {
        Ok(current_pos) => current_pos as usize,
        Err(e) => {
            eprintln!("{}", e.to_string());
            return -1;
        }
    };
    eprintln!("Current file offset is {}", current_pos);
    let gz = GzDecoder::new(file);
    let reader = BufReader::new(gz);

    // Create contextual data structure
    let mut ctx: Context = Context {
        open_db: None,
        add_start: None,
        del_start: None,
        xchg_start: None,
    };

    match process_lines(&mut ctx, reader, header_len as usize) {
        Ok(_) => 0,
        Err(e) => {
            eprintln!("{}", e.to_string());
            -1
        }
    }
}

fn cmd_open(ctx: &mut Context, db_name: std::string::String) -> Result<(), CdiffError> {
    // Test for existing open db
    if let Some(x) = &ctx.open_db {
        return Err(CdiffError::NotClosedBeforeOpening(x.to_string(), db_name));
    }

    if !db_name
        .chars()
        .all(|x: char| x.is_alphanumeric() || x == '\\' || x == '/' || x == '.')
    {
        return Err(CdiffError::ForbiddenCharactersInDB(db_name));
    }
    ctx.open_db = Some(db_name);

    eprintln!("data {:?}", ctx.open_db);
    Ok(())
}

fn cmd_add(ctx: &mut Context, signature: std::string::String) -> Result<(), CdiffError> {
    // Test for add without an open db
    match &ctx.open_db {
        Some(_x) => (),
        _ => return Err(CdiffError::NoDBForAction("ADD".to_string())),
    }

    // Create a new vector or append to existing one
    match &mut ctx.add_start {
        Some(add_start) => {
            (*add_start).push(signature);
        }
        _ => {
            let add_start = vec![signature];
            ctx.add_start = Some(add_start);
        }
    }

    Ok(())
    // eprintln!("signature {:?}", ctx.add_start);
}

fn cmd_del(mut ctx: &mut Context, del_op: DelOp) -> Result<(), CdiffError> {
    // Test for add without an open db
    match &ctx.open_db {
        Some(_x) => (),
        _ => return Err(CdiffError::NoDBForAction("DEL".to_string())),
    }

    eprintln!("Deleting {} on line {}", del_op.del_line, del_op.line_no);

    // Create a new node for deletion
    let del_node = DelNode {
        line_no: del_op.line_no,
        del_line: del_op.del_line.to_string(),
    };

    // Create a new vector or append to existing one in order
    match &mut ctx.del_start {
        Some(del_start) => {
            let n = (*del_start).len() - 1;
            for i in 0..=n {
                // eprintln!(
                //     "Deletion: Inserting line_no {} with current line_no {}",
                //     del_op.line_no, del_start[i].line_no
                // );
                if del_op.line_no < del_start[i].line_no {
                    //eprintln!("Deletion: Inserting into element {}", i);
                    (*del_start).insert(i, del_node);
                    break;
                } else if i == n {
                    //eprintln!("Deletion: Appending to node list");
                    (*del_start).push(del_node);
                    break;
                }
            }
        }
        _ => {
            let del_start = vec![del_node];
            //eprintln!("Deletion: Creating new node list");
            ctx.del_start = Some(del_start);
        }
    }
    Ok(())
}

fn cmd_xchg(mut ctx: &mut Context, xchg_op: XchgOp) -> Result<(), CdiffError> {
    // Test for add without an open db
    match &ctx.open_db {
        Some(_x) => (),
        _ => return Err(CdiffError::NoDBForAction("XCHG".to_string())),
    }

    eprintln!(
        "Exchanging {} with {} on line {}",
        xchg_op.orig_line, xchg_op.new_line, xchg_op.line_no
    );

    // Create a new node for exchange
    let xchg_node = XchgNode {
        line_no: xchg_op.line_no,
        orig_line: xchg_op.orig_line.to_string(),
        new_line: xchg_op.new_line.to_string(),
    };

    // Create a new vector or append to existing one
    match &mut ctx.xchg_start {
        Some(xchg_start) => {
            (*xchg_start).push(xchg_node);
        }
        _ => {
            let mut xchg_start = Vec::new();
            eprintln!("Exchange: Creating new node list");
            xchg_start.push(xchg_node);
            ctx.xchg_start = Some(xchg_start);
        }
    }
    Ok(())
}

fn cmd_move(ctx: &mut Context, move_op: MoveOp) -> Result<(), CdiffError> {
    #[derive(PartialEq)]
    enum State {
        Init,
        Move,
        End,
    }

    let mut state = State::Init;

    // Test for move with open db
    if let Some(x) = &ctx.open_db {
        return Err(CdiffError::NotClosedBeforeAction(
            x.to_string(),
            "MOVE".to_string(),
        ));
    }

    // Open src in read-only mode
    let src_file = File::open(move_op.src)?;

    // Open dst in append mode
    let mut dst_file = OpenOptions::new().append(true).open(move_op.dst)?;

    // Create tmp file and open for writing
    let mut tmp_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open("_tmp_move_file")?;

    // Create a buffered reader and loop over src, line by line
    let src_reader = BufReader::new(src_file);

    for (line_no, line) in src_reader.lines().enumerate() {
        let line = line?;

        if state == State::Init && line_no == move_op.start_line_no {
            if line.starts_with(move_op.start_line) {
                state = State::Move;
            } else {
                return Err(CdiffError::PatternDoesNotMatch(
                    "MOVE".to_string(),
                    line_no,
                    move_op.src.to_string(),
                ));
            }
        }
        // Write everything between start and end to dst
        else if state == State::Move {
            writeln!(dst_file, "{}", line)?;
            if line_no == move_op.end_line_no {
                if line.starts_with(move_op.end_line) {
                    state = State::End;
                } else {
                    return Err(CdiffError::PatternDoesNotMatch(
                        "MOVE".to_string(),
                        line_no,
                        move_op.dst.to_string(),
                    ));
                }
            }
        }
        // Write everything outside of start and end to tmp
        else {
            writeln!(tmp_file, "{}", line)?;
        }
    }

    // Check that we handled start and end
    if state != State::End {
        return Err(CdiffError::MoveOpFailed);
    }

    // Delete src and replace it with tmp
    fs::remove_file(move_op.src)?;
    fs::rename("_tmp_move_file", move_op.src)?;

    Ok(())
}

fn cmd_close(mut ctx: &mut Context) -> Result<(), CdiffError> {
    // Test for existing open db
    match &ctx.open_db {
        Some(_x) => (),
        _ => return Err(CdiffError::NoDBForAction("CLOSE".to_string())),
    }

    let open_db = ctx.open_db.as_ref().unwrap();
    eprintln!("Close DB {}", open_db);

    let mut delete_lines: bool = false;
    let mut xchg_lines: bool = false;

    if ctx.del_start.is_some() {
        delete_lines = true;
        println!("Found lines to delete");
    }

    if ctx.xchg_start.is_some() {
        xchg_lines = true;
    }

    if delete_lines || xchg_lines {
        // Open src in read-only mode
        let src_file = File::open(open_db)?;

        // Create a buffered reader and loop over src, line by line
        let src_reader = BufReader::new(src_file);

        // Create tmp file and open for writing
        // let mut tmp_file = OpenOptions::new()
        //     .write(true)
        //     .create_new(true)
        //     .open("_tmp_move_file")?;
        let tmp_named_file = tempfile::Builder::new()
            .prefix("_tmp_move_file")
            .tempfile_in("./")?;
        let mut tmp_file = tmp_named_file.as_file();

        let mut cur_del_node: usize = 0;
        let mut cur_xchg_node: usize = 0;

        let mut del_vec: Vec<DelNode> = vec![];
        let mut xchg_vec: Vec<XchgNode> = vec![];

        // Test for lines to delete
        let mut del_vec_len: usize = 0;
        if let Some(del_vec_ref) = &mut ctx.del_start {
            del_vec = std::mem::take(del_vec_ref);
            del_vec_len = del_vec.len();
        }

        // Test for lines to exchange
        let mut xchg_vec_len: usize = 0;
        if let Some(xchg_vec_ref) = &mut ctx.xchg_start {
            xchg_vec = std::mem::take(xchg_vec_ref);
            xchg_vec_len = xchg_vec.len();
        }

        for (mut line_no, line) in src_reader.lines().enumerate() {
            let line = line?;

            // cdiff lines start at 1
            line_no += 1;

            // if delete_lines {
            //     println!("First element in delete list: cur_line == {} line_no == {} del_line = {}",
            //     line_no, del_vec[0].line_no, del_vec[0].del_line);
            //     println!("is_empty {}, cur_del_node {}, del_vec_len {}",
            //     !del_vec.is_empty(), cur_del_node, del_vec_len);
            // }

            if delete_lines
                && !del_vec.is_empty()
                && cur_del_node < del_vec_len
                && line_no == del_vec[cur_del_node].line_no
            {
                let del_line = &del_vec[cur_del_node].del_line;

                eprintln!(
                    "deleting line on line_no starting with: {} {} {}",
                    line, line_no, del_line
                );
                // Make sure that the line we are deleting matches what is expected
                if !line.starts_with(del_line.as_str()) {
                    return Err(CdiffError::PatternDoesNotMatch(
                        "delete".to_string(),
                        line_no,
                        open_db.to_string(),
                    ));
                }
                // Increment del node
                cur_del_node += 1;
                if cur_del_node > del_vec_len {
                    del_vec_len = 0;
                }
                // Do nothing - Do not write this line to file
            } else if xchg_lines
                && !xchg_vec.is_empty()
                && cur_xchg_node < xchg_vec_len
                && line_no == xchg_vec[cur_xchg_node].line_no
            {
                let orig_line = &xchg_vec[cur_xchg_node].orig_line;
                let new_line = &xchg_vec[cur_xchg_node].new_line;

                eprintln!("Comparing line with orig_line: {} == {}", line, orig_line);
                if !line.starts_with(orig_line.as_str()) {
                    return Err(CdiffError::PatternDoesNotMatch(
                        "exchange".to_string(),
                        line_no,
                        open_db.to_string(),
                    ));
                }
                // Write exchange line to file
                writeln!(tmp_file, "{}", new_line)?;

                // Increment xchange node
                cur_xchg_node += 1;
                if cur_xchg_node > xchg_vec_len {
                    xchg_vec_len = 0;
                }
            }
            // Write the line as is
            else {
                writeln!(tmp_file, "{}", line)?;
            }
        }
        // Make sure that all delete and exchange lines were processed
        if delete_lines && cur_del_node < del_vec.len() {
            return Err(CdiffError::NotAllDeleteProcessed);
        }

        if xchg_lines && cur_xchg_node < xchg_vec.len() {
            return Err(CdiffError::NotAllExchangeProcessed);
        }

        // Delete the old file and replace it with tmp
        fs::remove_file(open_db.clone())?;
        //fs::rename("_tmp_move_file", open_db.clone())?;
        fs::rename(tmp_named_file.path(), open_db.clone())?;
    }

    // Test for lines to add
    if let Some(add_start) = &ctx.add_start {
        let mut db_file = OpenOptions::new().append(true).open(open_db.clone())?;
        for sig in add_start {
            eprintln!("Writing signature {} to file {}", sig, open_db);
            writeln!(db_file, "{}", sig)?;
        }
        ctx.add_start = None;
    }
    ctx.open_db = None;
    ctx.del_start = None;
    ctx.xchg_start = None;
    eprintln!("Close finished");
    Ok(())
}

fn cmd_unlink(ctx: &mut Context) -> Result<(), CdiffError> {
    match &ctx.open_db {
        Some(open_db) => fs::remove_file(open_db.clone())?,
        _ => return Err(CdiffError::NoDBForAction("UNLINK".to_string())),
    }
    Ok(())
}

fn process_line(ctx: &mut Context, line: String) -> Result<(), CdiffError> {
    // Find the index at the end of the command (note that the CLOSE command has no trailing data)
    let spc_idx = match line.find(|c: char| c.is_whitespace()) {
        Some(spc_idx) => spc_idx,
        None => match line == "CLOSE" {
            true => 0,
            _ => {
                unsafe { logg(b"Unable to parse cmd\n".as_ptr()) };
                process::abort();
            }
        },
    };

    // Get the command
    let cmd: String = if spc_idx > 0 {
        line.chars().take(spc_idx).collect()
    } else {
        line.clone()
    };

    // Get the data and clean it up
    let data: String = line.chars().skip(spc_idx + 1).collect::<String>();
    let data: String = data.trim().to_owned();

    eprintln!("cmd = {}", cmd);

    // Call the appropriate command function
    match cmd.as_str() {
        "OPEN" => cmd_open(ctx, data),
        "ADD" => cmd_add(ctx, data),
        "DEL" => {
            let del_op = DelOp::new(data.as_str())?;
            cmd_del(ctx, del_op)
        }
        "XCHG" => {
            let xchg_op = XchgOp::new(data.as_str())?;
            cmd_xchg(ctx, xchg_op)
        }
        "CLOSE" => cmd_close(ctx),
        "MOVE" => {
            let move_op = MoveOp::new(data.as_str())?;
            cmd_move(ctx, move_op)
        }
        "UNLINK" => cmd_unlink(ctx),
        _ => Err(CdiffError::InvalidCommand(cmd.to_string())),
    }
}

fn process_lines<T>(
    ctx: &mut Context,
    reader: T,
    uncompressed_size: usize,
) -> Result<(), CdiffError>
where
    T: BufRead,
{
    let mut decompressed_bytes = 0;
    let mut n = 0;
    for line in reader.lines() {
        match line {
            Ok(line) => {
                n += 1;
                decompressed_bytes = decompressed_bytes + line.len() + 1;
                eprintln!("Line {}: {:?}", n, line);
                process_line(ctx, line)?;
            }
            Err(e) => {
                return Err(CdiffError::MalformedFile(e.to_string()));
            }
        }
    }
    eprintln!(
        "Expected {} decompressed bytes, read {} decompressed bytes",
        uncompressed_size, decompressed_bytes
    );
    Ok(())
}

/*
Find the signature at the end of the file, prefixed by ':'
To Do: write unit tests
*/
fn read_dsig(file: &mut File) -> Result<Vec<u8>, CdiffError> {
    // Verify file length
    if file.metadata()?.len() < MAX_DSIG_SIZE as u64 {
        return Err(CdiffError::NotEnoughBytes(MAX_DSIG_SIZE));
    }
    // Seek to the dsig_offset
    file.seek(SeekFrom::End(-(MAX_DSIG_SIZE as i64)))?;
    // Read from dsig_offset to EOF
    let mut dsig: Vec<u8> = vec![];
    file.read_to_end(&mut dsig)?;
    eprintln!("dsig length is {}", dsig.len());
    // Find the signature
    let offset: usize = MAX_DSIG_SIZE + 1;
    // Read in reverse until the delimiter ':' is found
    // let offset = dsig.iter().enumerate().rev().find(|(i, value)| **value == b':');
    if let Some(dsig) = dsig.rsplit(|v| *v == b':').next() {
        if dsig.len() > MAX_DSIG_SIZE {
            Err(CdiffError::ParseDsigError)
        } else {
            Ok(dsig.to_vec())
        }
    } else {
        Ok(dsig[offset..].to_vec())
    }
}

// Returns the parsed, uncompressed file size from the header, as well
// as the offset in the file that the header ends.
fn read_size(file: &mut File) -> Result<(u32, usize), CdiffError> {
    // Seek to beginning of file.
    file.seek(SeekFrom::Start(0))?;

    // File should always start with "ClamAV-Diff".
    let prefix = b"ClamAV-Diff";
    let mut buf = Vec::with_capacity(prefix.len());
    file.take(prefix.len() as u64).read_to_end(&mut buf)?;
    if buf.as_slice() != prefix.to_vec().as_slice() {
        return Err(CdiffError::MalformedFile("malformed header".to_string()));
    }

    // Read up to FILEBUFF to parse out the file size.
    let n = file.take(FILEBUFF as u64).read_to_end(&mut buf)?;
    let mut colons = 0;
    let mut file_size_vec = Vec::new();
    eprintln!("n == {}", n);
    //for i in 0..=n {
    for (i, value) in buf.iter().enumerate().take(n + 1) {
        // Colon found, increment count.
        if *value == b':' {
            colons += 1;
        }
        // We are reading the file size now.
        else if colons == 2 {
            file_size_vec.push(*value);
        }

        // We are done reading the file size.
        if colons == 3 {
            let file_size_str = String::from_utf8(file_size_vec)?;
            eprintln!("file_size_str == {}", file_size_str);
            return Ok((file_size_str.parse::<u32>()?, i + 1));
        }
    }
    Err(CdiffError::MalformedFile("insufficient colons".to_string()))
}

// Sha256 read instead of update

// Calculate the sha256 of the first len bytes of a file
fn get_hash(file: &mut File, len: usize) -> Result<[u8; 32], CdiffError> {
    let mut hasher = sha::Sha256::new();

    // Seek to beginning of file
    file.seek(SeekFrom::Start(0))?;

    let mut sum: usize = 0;

    // Read FILEBUFF (8192) bytes at a time,
    // calculating the hash along the way. Stop
    // after signature is reached.
    loop {
        let mut buf = Vec::with_capacity(FILEBUFF);
        let n = file.take(FILEBUFF as u64).read_to_end(&mut buf)?;
        if sum + n >= len {
            // update with len - sum
            hasher.update(&buf[..(len - sum)]);
            //print_file_data(buf, len - sum);
            let hash = hasher.finish();
            return Ok(hash);
        } else {
            // update with n
            hasher.update(&buf);
            //print_file_data(buf, n);
        }
        sum += n;
    }
}

fn print_file_data(buf: Vec<u8>, len: usize) {
    for (i, value) in buf.iter().enumerate().take(len) {
        eprint!("{:#02X} ", value);
        if (i + 1) % 16 == 0 {
            eprintln!();
        }
    }
    eprintln!("\n");
}

#[cfg(test)]
mod tests {
    use super::*;

    /// CdiffTestError enumerates all possible errors returned by this testing library.
    #[derive(Error, Debug)]
    pub enum CdiffTestError {
        /// Represents all other cases of `std::io::Error`.
        #[error(transparent)]
        IOError(#[from] std::io::Error),

        #[error(transparent)]
        FromUtf8Error(#[from] std::string::FromUtf8Error),
    }

    #[test]
    fn parse_move_works() {
        eprintln!("MOVE was called!");

        let move_op = MoveOp::new("a b 1 hello 2 world").expect("Should've worked!");

        println!("{:?}", move_op);

        assert_eq!(move_op.src, "a");
        assert_eq!(move_op.dst, "b");
        assert_eq!(move_op.start_line_no, 1);
        assert_eq!(move_op.start_line, "hello");
        assert_eq!(move_op.end_line_no, 2);
        assert_eq!(move_op.end_line, "world");
    }

    #[test]
    fn parse_move_fail_int() {
        eprintln!("MOVE was called!");

        let err = MoveOp::new("a b NOTANUMBER hello 2 world").expect_err("Should've failed!");
        let parse_string = "NOTANUMBER".to_string();
        let parse_error = parse_string.parse::<usize>().unwrap_err();
        let number_error = CdiffError::ParseIntError(parse_error);
        println!("{:?}", err.to_string());
        assert_eq!(err.to_string(), number_error.to_string());
    }

    #[test]
    fn parse_move_fail_eof() {
        eprintln!("MOVE was called!");

        let err = MoveOp::new("a b 1").expect_err("Should've failed!");
        let start_line_err = CdiffError::NoMoreData("start_line".to_string());
        println!("{:?}", err.to_string());
        assert_eq!(err.to_string(), start_line_err.to_string());
    }

    /*
     * Helper function to set up a test folder and initialize a pseudo-db file
     * with specified data.
     */
    fn initialize_db_file_with_data(
        initial_data: Vec<String>,
    ) -> Result<tempfile::TempPath, CdiffTestError> {
        let mut file = tempfile::Builder::new()
            .tempfile_in("./")
            .expect("Failed to create temp file");
        for line in initial_data {
            writeln!(file, "{}", line).expect("Failed to write line to temp file");
        }
        Ok(file.into_temp_path())
    }

    fn compare_file_with_expected(
        temp_file_path: tempfile::TempPath,
        expected_data: &mut Vec<String>,
    ) {
        let db_file = File::open(temp_file_path).unwrap();
        let reader = BufReader::new(db_file);
        // We will be popping lines off a stack, so we need to reverse the vec
        expected_data.reverse();
        for (index, line) in reader.lines().enumerate() {
            let expected_line = expected_data
                .pop()
                .expect("Expected data ran out before file!");
            assert_eq!(
                expected_line,
                line.expect("Failed to read line from temp file")
            );
            eprintln!(
                "Data \"{}\" matches expected result on line {}",
                expected_line, index
            );
        }
        // expected_data should be empty here
        assert_eq!(expected_data.len(), 0);
    }

    fn construct_ctx_from_path(path: &tempfile::TempPath) -> Context {
        let ctx: Context = Context {
            open_db: Some(path.to_str().unwrap().to_string()),
            add_start: None,
            del_start: None,
            xchg_start: None,
        };
        ctx
    }

    #[test]
    fn delete_first_line() {
        let initial_data = vec![
            "ClamAV-VDB:14 Jul 2021 14-29 -0400".to_string(),
            "AAAA".to_string(),
            "BBBB".to_string(),
            "CCCC".to_string(),
        ];
        let mut expected_data = vec!["AAAA".to_string(), "BBBB".to_string(), "CCCC".to_string()];

        let db_file_path = initialize_db_file_with_data(initial_data).unwrap();

        // Create contextual data structure with open_db path
        let mut ctx = construct_ctx_from_path(&db_file_path);

        let del_op = DelOp::new("1 ClamAV-VDB:14").unwrap();
        cmd_del(&mut ctx, del_op).expect("cmd_del failed");
        match cmd_close(&mut ctx) {
            Ok(_) => (),
            Err(e) => panic!("cmd_close failed with: {}", e.to_string()),
        }
        compare_file_with_expected(db_file_path, &mut expected_data);
    }

    #[test]
    fn delete_second_line() {
        let initial_data = vec![
            "ClamAV-VDB:14 Jul 2021 14-29 -0400".to_string(),
            "AAAA".to_string(),
            "BBBB".to_string(),
            "CCCC".to_string(),
        ];
        let mut expected_data = vec![
            "ClamAV-VDB:14 Jul 2021 14-29 -0400".to_string(),
            "BBBB".to_string(),
            "CCCC".to_string(),
        ];

        let db_file_path = initialize_db_file_with_data(initial_data).unwrap();

        // Create contextual data structure with open_db path
        let mut ctx = construct_ctx_from_path(&db_file_path);

        let del_op = DelOp::new("2 AAAA").unwrap();
        cmd_del(&mut ctx, del_op).expect("cmd_del failed");
        match cmd_close(&mut ctx) {
            Ok(_) => (),
            Err(e) => panic!("cmd_close failed with: {}", e.to_string()),
        }
        compare_file_with_expected(db_file_path, &mut expected_data);
    }

    #[test]
    fn delete_last_line() {
        let initial_data = vec![
            "ClamAV-VDB:14 Jul 2021 14-29 -0400".to_string(),
            "AAAA".to_string(),
            "BBBB".to_string(),
            "CCCC".to_string(),
        ];
        let mut expected_data = vec![
            "ClamAV-VDB:14 Jul 2021 14-29 -0400".to_string(),
            "AAAA".to_string(),
            "BBBB".to_string(),
        ];

        let db_file_path = initialize_db_file_with_data(initial_data).unwrap();

        // Create contextual data structure with open_db path
        let mut ctx = construct_ctx_from_path(&db_file_path);

        let del_op = DelOp::new("4 CCCC").unwrap();
        cmd_del(&mut ctx, del_op).expect("cmd_del failed");
        match cmd_close(&mut ctx) {
            Ok(_) => (),
            Err(e) => panic!("cmd_close failed with: {}", e.to_string()),
        }
        compare_file_with_expected(db_file_path, &mut expected_data);
    }

    #[test]
    fn delete_line_not_match() {
        let initial_data = vec![
            "ClamAV-VDB:14 Jul 2021 14-29 -0400".to_string(),
            "AAAA".to_string(),
            "BBBB".to_string(),
            "CCCC".to_string(),
        ];

        let db_file_path = initialize_db_file_with_data(initial_data).unwrap();

        // Create contextual data structure with open_db path
        let mut ctx = construct_ctx_from_path(&db_file_path);

        let del_op = DelOp::new("1 CCCC").unwrap();
        cmd_del(&mut ctx, del_op).expect("cmd_del failed");
        match cmd_close(&mut ctx) {
            Ok(_) => panic!("cmd_close should have failed!"),
            Err(e) => {
                assert!(e
                    .to_string()
                    .starts_with("Cannot perform action delete on line"));
            }
        }
    }

    #[test]
    fn delete_out_of_bounds() {
        let initial_data = vec![
            "ClamAV-VDB:14 Jul 2021 14-29 -0400".to_string(),
            "AAAA".to_string(),
            "BBBB".to_string(),
            "CCCC".to_string(),
        ];

        let db_file_path = initialize_db_file_with_data(initial_data).unwrap();

        // Create contextual data structure with open_db path
        let mut ctx = construct_ctx_from_path(&db_file_path);

        let del_op = DelOp::new("5 CCCC").unwrap();
        cmd_del(&mut ctx, del_op).expect("cmd_del failed");
        match cmd_close(&mut ctx) {
            Ok(_) => panic!("cmd_close should have failed!"),
            Err(e) => {
                assert_eq!(e.to_string(), "Not all delete lines processed at file end");
            }
        }
    }

    #[test]
    fn exchange_first_line() {
        let initial_data = vec![
            "ClamAV-VDB:14 Jul 2021 14-29 -0400".to_string(),
            "AAAA".to_string(),
            "BBBB".to_string(),
            "CCCC".to_string(),
        ];
        let mut expected_data = vec![
            "ClamAV-VDB:15 Aug 2021 14-29 -0400".to_string(),
            "AAAA".to_string(),
            "BBBB".to_string(),
            "CCCC".to_string(),
        ];

        let db_file_path = initialize_db_file_with_data(initial_data).unwrap();

        // Create contextual data structure with open_db path
        let mut ctx = construct_ctx_from_path(&db_file_path);

        let xchg_op = XchgOp::new("1 ClamAV-VDB:14 ClamAV-VDB:15 Aug 2021 14-29 -0400").unwrap();
        cmd_xchg(&mut ctx, xchg_op).expect("cmd_xchg failed");
        match cmd_close(&mut ctx) {
            Ok(_) => (),
            Err(e) => panic!("cmd_close failed with: {}", e.to_string()),
        }
        compare_file_with_expected(db_file_path, &mut expected_data);
    }

    #[test]
    fn exchange_second_line() {
        let initial_data = vec![
            "ClamAV-VDB:14 Jul 2021 14-29 -0400".to_string(),
            "AAAA".to_string(),
            "BBBB".to_string(),
            "CCCC".to_string(),
        ];
        let mut expected_data = vec![
            "ClamAV-VDB:14 Jul 2021 14-29 -0400".to_string(),
            "DDDD".to_string(),
            "BBBB".to_string(),
            "CCCC".to_string(),
        ];

        let db_file_path = initialize_db_file_with_data(initial_data).unwrap();

        // Create contextual data structure with open_db path
        let mut ctx = construct_ctx_from_path(&db_file_path);

        let xchg_op = XchgOp::new("2 AAAA DDDD").unwrap();
        cmd_xchg(&mut ctx, xchg_op).expect("cmd_xchg failed");
        match cmd_close(&mut ctx) {
            Ok(_) => (),
            Err(e) => panic!("cmd_close failed with: {}", e.to_string()),
        }
        compare_file_with_expected(db_file_path, &mut expected_data);
    }

    #[test]
    fn exchange_last_line() {
        let initial_data = vec![
            "ClamAV-VDB:14 Jul 2021 14-29 -0400".to_string(),
            "AAAA".to_string(),
            "BBBB".to_string(),
            "CCCC".to_string(),
        ];
        let mut expected_data = vec![
            "ClamAV-VDB:14 Jul 2021 14-29 -0400".to_string(),
            "AAAA".to_string(),
            "BBBB".to_string(),
            "DDDD".to_string(),
        ];

        let db_file_path = initialize_db_file_with_data(initial_data).unwrap();

        // Create contextual data structure with open_db path
        let mut ctx = construct_ctx_from_path(&db_file_path);

        let xchg_op = XchgOp::new("4 CCCC DDDD").unwrap();
        cmd_xchg(&mut ctx, xchg_op).expect("cmd_xchg failed");
        match cmd_close(&mut ctx) {
            Ok(_) => (),
            Err(e) => panic!("cmd_close failed with: {}", e.to_string()),
        }
        compare_file_with_expected(db_file_path, &mut expected_data);
    }

    #[test]
    fn exchange_out_of_bounds() {
        let initial_data = vec![
            "ClamAV-VDB:14 Jul 2021 14-29 -0400".to_string(),
            "AAAA".to_string(),
            "BBBB".to_string(),
            "CCCC".to_string(),
        ];

        let db_file_path = initialize_db_file_with_data(initial_data).unwrap();

        // Create contextual data structure with open_db path
        let mut ctx = construct_ctx_from_path(&db_file_path);

        let xchg_op = XchgOp::new("5 DDDD EEEE").unwrap();
        cmd_xchg(&mut ctx, xchg_op).expect("cmd_xchg failed");
        match cmd_close(&mut ctx) {
            Ok(_) => panic!("cmd_close should have failed!"),
            Err(e) => {
                assert_eq!(
                    e.to_string(),
                    "Not all exchange lines processed at file end"
                );
            }
        }
    }

    #[test]
    fn add_delete_exchange() {
        let initial_data = vec![
            "ClamAV-VDB:14 Jul 2021 14-29 -0400".to_string(),
            "AAAA".to_string(),
            "BBBB".to_string(),
            "CCCC".to_string(),
        ];
        let mut expected_data = vec![
            "ClamAV-VDB:14 Jul 2021 14-29 -0400".to_string(),
            "DDDD".to_string(),
            "CCCC".to_string(),
            "EEEE".to_string(),
        ];

        let db_file_path = initialize_db_file_with_data(initial_data).unwrap();

        // Create contextual data structure with open_db path
        let mut ctx = construct_ctx_from_path(&db_file_path);

        // Add a line
        cmd_add(&mut ctx, "EEEE".to_string()).unwrap();

        // Delete the 2nd line
        let del_op = DelOp::new("2 AAAA").unwrap();
        cmd_del(&mut ctx, del_op).expect("cmd_del failed");

        // Exchange the 3rd line
        let xchg_op = XchgOp::new("3 BBBB DDDD").unwrap();
        cmd_xchg(&mut ctx, xchg_op).expect("cmd_xchg failed");

        // Perform all operations and close the file
        match cmd_close(&mut ctx) {
            Ok(_) => (),
            Err(e) => panic!("cmd_close failed with: {}", e.to_string()),
        }
        compare_file_with_expected(db_file_path, &mut expected_data);
    }

    // Todo: Write a unit test to handle an xchgop with multiple whitespace entries between fields.

    /*
    TO DO: Add unit tests that describe how we think a move operation will work, since they are extremely rare
    */
}

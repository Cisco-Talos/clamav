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

use std::{
    collections::BTreeMap,
    ffi::{CStr, CString},
    fs::{self, File, OpenOptions},
    io::{prelude::*, BufReader, BufWriter, Read, Seek, SeekFrom, Write},
    iter::*,
    os::raw::{c_char, c_uchar},
    process,
};

use crate::util;
use flate2::{read::GzDecoder, write::GzEncoder, Compression};
use log::{debug, error, warn};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Maximum size of a digital signature
const MAX_SIG_SIZE: usize = 350;

/// A sane buffer size for various read operations
const READ_SIZE: usize = 8192;

/// Acceptable public key for signing CDiffs. The C API expects these to be
/// represented as a [large] ASCII-encoded decimal number.
const PUBLIC_KEY_MODULUS: &str = concat!(
    "1478390587407746709026222851655791757025459963837620353203198921410555284726",
    "9687489771975792123442185817287694951949800908791527542017115600501303394778",
    "6185358648452357000415900563182301024496122174585490160893133065913885907907",
    "9651581965410232072571230082235634872401123265483750324173617790778419870083",
    "4440681124727060540035754699658105895050096576226753008596881698828185652424",
    "9019216687583265784620032479064709820922981067896572119054889862810783463614",
    "6952448482955956088622719809199549844067663963983046359321138605506536028842",
    "2394053998134458623712540683294034953818412458362198117811990006021989844180",
    "721010947",
);
const PUBLIC_KEY_EXPONENT: &str = "100002053";

pub enum ApplyMode {
    Cdiff,
    Script,
}

#[derive(Debug)]
struct EditNode {
    line_no: usize,
    orig_line: String,
    new_line: Option<String>,
}

#[derive(Default)]
struct Context {
    // The database currently being adjusted
    open_db: Option<String>,

    // In-place changes (remove or change a line)
    // This is currently implemented as a BTreeMap to ensure ordering of the
    // records. However, CDiffs are supposed to have ordered entries, so this
    // could probably be implemented more-simply as a vector (and throw an
    // error if out-of-order line indices are detected).
    edits: BTreeMap<usize, EditNode>,

    // Lines to append to the database
    additions: Vec<String>,
}

/// Possible errores returned by cdiff_apply()
#[derive(Error, Debug)]
pub enum CdiffError {
    #[error("No DB open for action {0}")]
    NoDBForAction(&'static str),

    #[error("File {0} not closed before calling action MOVE")]
    NotClosedBeforeAction(String),

    #[error("File {0} not closed before opening {1}")]
    NotClosedBeforeOpening(String, String),

    #[error("Forbidden characters found in database name {0}")]
    ForbiddenCharactersInDB(String),

    #[error("Invalid command provided: {0}")]
    InvalidCommand(String),

    #[error("Unexpected end of line while parsing field: {0}")]
    NoMoreData(&'static str),

    #[error("File contains fewer than {0} bytes")]
    NotEnoughBytes(usize),

    #[error("Incorrect file format - {0}")]
    MalformedFile(String),

    #[error("Move operation failed")]
    MoveOpFailed,

    #[error("Failed to parse string as a number")]
    ParseIntError(#[from] std::num::ParseIntError),

    #[error("Cannot perform action {0} on line {1} in file {2}. Pattern does not match")]
    PatternDoesNotMatch(&'static str, usize, String),

    #[error("Failed to parse dsig!")]
    ParseDsigError,

    #[error("Not all edit processed at file end ({0} remaining)")]
    NotAllEditProcessed(&'static str),

    /// Represents all other cases of `std::io::Error`.
    #[error(transparent)]
    IOError(#[from] std::io::Error),

    #[error(transparent)]
    FromUtf8Error(#[from] std::string::FromUtf8Error),

    #[error("NUL found within buffer to be interpreted as NUL-terminated string")]
    NulError(#[from] std::ffi::NulError),

    #[error("Incorrect digital signature")]
    InvalidDigitalSignature,

    #[error("Conflicting actions found for line {0}")]
    ConflictingAction(usize),

    //
    // These are particular to script2cdiff()
    //
    #[error("Provided file name does not contain a hyphen")]
    FilenameMissingHyphen,

    #[error("Provided file name does not contain version")]
    FilenameMissingVersion,

    #[error("Unable to parse version number: {0}")]
    VersionParse(std::num::ParseIntError),

    #[error("Unable to create file {0}: {1}")]
    FileCreate(String, std::io::Error),

    #[error("Unable to open file {0}: {1}")]
    FileOpen(String, std::io::Error),

    #[error("Unable to query metadata for {0}: {1}")]
    FileMeta(String, std::io::Error),

    #[error("Unable to write to file {0}: {1}")]
    FileWrite(String, std::io::Error),

    #[error("Unable to read from file {0}: {1}")]
    FileRead(String, std::io::Error),
}

#[derive(Debug)]
pub struct DelOp<'a> {
    line_no: usize,
    del_line: &'a str,
}

/// Method to parse the cdiff line describing a delete operation
impl<'a> DelOp<'a> {
    pub fn new(data: &'a str) -> Result<Self, CdiffError> {
        let mut iter = data.split_whitespace();

        Ok(DelOp {
            line_no: iter
                .next()
                .ok_or_else(|| CdiffError::NoMoreData("line_no"))?
                .parse::<usize>()?,
            del_line: iter
                .next()
                .ok_or_else(|| CdiffError::NoMoreData("del_line"))?,
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

/// Method to parse the cdiff line describing a move operation
impl<'a> MoveOp<'a> {
    pub fn new(data: &'a str) -> Result<Self, CdiffError> {
        let mut iter = data.split_whitespace();

        Ok(MoveOp {
            src: iter.next().ok_or_else(|| CdiffError::NoMoreData("src"))?,
            dst: iter.next().ok_or_else(|| CdiffError::NoMoreData("dst"))?,
            start_line_no: iter
                .next()
                .ok_or_else(|| CdiffError::NoMoreData("start_line_no"))?
                .parse::<usize>()?,
            start_line: iter
                .next()
                .ok_or_else(|| CdiffError::NoMoreData("start_line"))?,
            end_line_no: iter
                .next()
                .ok_or_else(|| CdiffError::NoMoreData("end_line_no"))?
                .parse::<usize>()?,
            end_line: iter
                .next()
                .ok_or_else(|| CdiffError::NoMoreData("end_line"))?,
        })
    }
}

#[derive(Debug)]
pub struct XchgOp<'a> {
    line_no: usize,
    orig_line: &'a str,
    new_line: &'a str,
}

/// Method to parse the cdiff line describing an exchange operation
impl<'a> XchgOp<'a> {
    pub fn new(data: &'a str) -> Result<Self, CdiffError> {
        let mut iter = data.splitn(3, char::is_whitespace);

        Ok(XchgOp {
            line_no: iter
                .next()
                .ok_or_else(|| CdiffError::NoMoreData("line_no"))?
                .parse::<usize>()?,
            orig_line: iter
                .next()
                .ok_or_else(|| CdiffError::NoMoreData("orig_line"))?,
            new_line: iter
                .next()
                .ok_or_else(|| CdiffError::NoMoreData("new_line"))?,
        })
    }
}

extern "C" {
    fn cli_versig2(
        digest: *const c_uchar,
        dsig: *const c_char,
        n: *const c_char,
        e: *const c_char,
    ) -> i32;

    fn cli_getdsig(
        host: *const u8,
        user: *const u8,
        data: *const u8,
        datalen: u32,
        mode: u8,
    ) -> *const c_char;

    fn cli_get_debug_flag() -> u8;
}

fn is_debug_enabled() -> bool {
    unsafe {
        let debug_flag = cli_get_debug_flag();
        // Return true if debug_flag is not 0
        !matches!(debug_flag, 0)
    }
}

/// Verify that the given parameter is not NULL, and valid UTF-8, returning a &str or forcing a return with -1
macro_rules! validate_str_param {
    ($ptr:ident) => {
        if $ptr.is_null() {
            warn!("{} is NULL", stringify!($ptr));
            return -1;
        } else {
            match unsafe { CStr::from_ptr($ptr) }.to_str() {
                Err(e) => {
                    warn!("{} is not valid unicode: {}", stringify!($ptr), e);
                    return -1;
                }
                Ok(s) => s,
            }
        }
    };
}

#[export_name = "script2cdiff"]
pub extern "C" fn _script2cdiff(
    script: *const c_char,
    builder: *const c_char,
    server: *const c_char,
) -> i32 {
    // validate_str_param! generates a false alarm here.  Marking the entire
    // function as unsafe triggers a different warning
    #![allow(clippy::not_unsafe_ptr_arg_deref)]
    let script_file_name = validate_str_param!(script);
    let builder = validate_str_param!(builder);
    let server = validate_str_param!(server);
    match script2cdiff(script_file_name, builder, server) {
        Ok(_) => 0,
        Err(e) => {
            error!("{}", e);
            -1
        }
    }
}

/// Convert a plaintext script file of cdiff commands into a cdiff formatted file
///
/// This function makes a single C call to cli_getdsig to obtain a signed
/// signature from the sha256 of the contents written.
///
/// This function will panic if any of the &str parameters contain interior NUL bytes
pub fn script2cdiff(script_file_name: &str, builder: &str, server: &str) -> Result<(), CdiffError> {
    // Make a copy of the script file name to use for the cdiff file
    let cdiff_file_name_string = script_file_name.to_string();
    let mut cdiff_file_name = cdiff_file_name_string.as_str();
    debug!("script2cdiff() - script file name: {:?}", cdiff_file_name);

    // Remove the "".script" suffix
    if let Some(file_name) = cdiff_file_name.strip_suffix(".script") {
        cdiff_file_name = file_name;
    }

    // Get right-most hyphen index
    let hyphen_index = cdiff_file_name
        .rfind('-')
        .ok_or(CdiffError::FilenameMissingHyphen)?;

    // Get the version, which should be to the right of the hyphen
    let version_string = cdiff_file_name
        .get((hyphen_index + 1)..)
        .ok_or(CdiffError::FilenameMissingVersion)?;

    // Parse the version into usize
    let version = version_string
        .to_string()
        .parse::<usize>()
        .map_err(CdiffError::VersionParse)?;

    // Add .cdiff suffix
    let cdiff_file_name = format!("{}.{}", cdiff_file_name, "cdiff");
    debug!("script2cdiff() - writing to: {:?}", &cdiff_file_name);

    // Open cdiff_file_name for writing
    let mut cdiff_file: File = File::create(&cdiff_file_name)
        .map_err(|e| CdiffError::FileCreate(cdiff_file_name.to_owned(), e))?;

    // Open the original script file for reading
    let script_file: File = File::open(&script_file_name)
        .map_err(|e| CdiffError::FileOpen(script_file_name.to_owned(), e))?;

    // Get file length
    let script_file_len = script_file
        .metadata()
        .map_err(|e| CdiffError::FileMeta(script_file_name.to_owned(), e))?
        .len();

    // Write header to cdiff file
    write!(cdiff_file, "ClamAV-Diff:{}:{}:", version, script_file_len)
        .map_err(|e| CdiffError::FileWrite(script_file_name.to_owned(), e))?;

    // Set up buffered reader and gz writer
    let reader = BufReader::new(script_file);
    let mut gz = GzEncoder::new(cdiff_file, Compression::default());

    // Read lines from script_file, compress and write to cdiff_file
    for line in reader.lines() {
        let mut line = line.map_err(|e| CdiffError::FileRead(script_file_name.to_owned(), e))?;
        // Each line written must be newline separated per cdiff spec
        line.push('\n');
        gz.write_all(line.as_bytes())
            .map_err(|e| CdiffError::FileWrite(cdiff_file_name.to_owned(), e))?;
    }

    // Get cdiff file writer back from flate2
    let mut cdiff_file = gz
        .finish()
        .map_err(|e| CdiffError::FileWrite(cdiff_file_name.to_owned(), e))?;

    // Get the new cdiff file len
    let cdiff_file_len = cdiff_file
        .metadata()
        .map_err(|e| CdiffError::FileMeta(cdiff_file_name.to_owned(), e))?
        .len();
    debug!(
        "script2cdiff() - wrote {} bytes to {}",
        cdiff_file_len, cdiff_file_name
    );

    // Calculate SHA2-256 to get the sigature
    // TODO: Do this while the file is being written
    let bytes = std::fs::read(&cdiff_file_name)
        .map_err(|e| CdiffError::FileRead(cdiff_file_name.to_owned(), e))?;
    let sha256 = {
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        hasher.finalize()
    };

    let dsig = unsafe {
        // These strings should not contain interior NULs
        let server = CString::new(server).unwrap();
        let builder = CString::new(builder).unwrap();
        let dsig_ptr = cli_getdsig(
            server.as_c_str().as_ptr() as *const u8,
            builder.as_c_str().as_ptr() as *const u8,
            sha256.to_vec().as_ptr(),
            32,
            2,
        );
        assert!(!dsig_ptr.is_null());
        CStr::from_ptr(dsig_ptr)
    };

    // Write cdiff footer delimiter
    cdiff_file
        .write_all(b":")
        .map_err(|e| CdiffError::FileWrite(cdiff_file_name.to_owned(), e))?;

    // Write dsig to cdiff footer
    cdiff_file
        .write_all(dsig.to_bytes())
        .map_err(|e| CdiffError::FileWrite(cdiff_file_name, e))?;

    // Exit success
    Ok(())
}

/// This function is only meant to be called from sigtool.c
#[export_name = "cdiff_apply"]
pub extern "C" fn _cdiff_apply(fd: i32, mode: u16) -> i32 {
    debug!(
        "cdiff_apply() - called with file_descriptor={}, mode={}",
        fd, mode
    );

    let mode = if mode == 1 {
        ApplyMode::Cdiff
    } else {
        ApplyMode::Script
    };

    let mut file = util::file_from_fd_or_handle(fd);

    if let Err(e) = cdiff_apply(&mut file, mode) {
        error!("{}", e);
        -1
    } else {
        0
    }
}

/// Apply cdiff (patch) file to all database files described in the cdiff.
///
/// A cdiff file contains a header consisting of a description, version, and
/// script file length (in bytes), all delimited by ':'
///
/// A cdiff file contains a gzipped body between the header and the footer, the
/// contents of which must be newline delimited. The body consists of all bytes
/// after the last ':' in the header and before the first ':' in the footer. The
/// body consists of cdiff commands.
///
/// A cdiff file contains a footer that is the signed signature of the sha256
/// file contains of the header and the body. The footer begins after the first
/// ':' character to the left of EOF.
pub fn cdiff_apply(file: &mut File, mode: ApplyMode) -> Result<(), CdiffError> {
    let path = std::env::current_dir().unwrap();
    debug!("cdiff_apply() - current directory is {}", path.display());

    // Only read dsig, header, etc. if this is a cdiff file
    let header_length = match mode {
        ApplyMode::Script => 0,
        ApplyMode::Cdiff => {
            let dsig = read_dsig(file)?;
            debug!("cdiff_apply() - final dsig length is {}", dsig.len());
            if is_debug_enabled() {
                print_file_data(dsig.clone(), dsig.len() as usize);
            }

            // Get file length
            let file_len = file.metadata()?.len() as usize;
            let footer_offset = file_len - dsig.len() - 1;

            // The SHA is calculated from the contents of the beginning of the file
            // up until the ':' before the dsig at the end of the file.
            let sha256 = get_hash(file, footer_offset)?;

            debug!("cdiff_apply() - sha256: {}", hex::encode(sha256));

            // cli_versig2 will expect dsig to be a null-terminated string
            let dsig_cstring = CString::new(dsig)?;

            // Verify cdiff
            let n = CString::new(PUBLIC_KEY_MODULUS).unwrap();
            let e = CString::new(PUBLIC_KEY_EXPONENT).unwrap();
            let versig_result = unsafe {
                cli_versig2(
                    sha256.to_vec().as_ptr(),
                    dsig_cstring.as_ptr(),
                    n.as_ptr() as *const c_char,
                    e.as_ptr() as *const c_char,
                )
            };
            debug!("cdiff_apply() - cli_versig2() result = {}", versig_result);
            if versig_result != 0 {
                return Err(CdiffError::InvalidDigitalSignature);
            }

            // Read file length from header
            let (header_len, header_offset) = read_size(file)?;
            debug!(
                "cdiff_apply() - header len = {}, file len = {}, header offset = {}",
                header_len, file_len, header_offset
            );

            let current_pos = file.seek(SeekFrom::Start(header_offset as u64))?;
            debug!("cdiff_apply() - current file offset = {}", current_pos);
            header_len as usize
        }
    };

    // Set reader according to whether this is a script or cdiff
    let reader: Box<dyn BufRead> = match mode {
        ApplyMode::Cdiff => {
            let gz = GzDecoder::new(file);
            Box::new(BufReader::new(gz))
        }
        ApplyMode::Script => Box::new(BufReader::new(file)),
    };

    // Create contextual data structure
    let mut ctx: Context = Context::default();

    process_lines(&mut ctx, reader, header_length)
}

/// Set up Context structure with data parsed from command open
fn cmd_open(ctx: &mut Context, db_name: std::string::String) -> Result<(), CdiffError> {
    // Test for existing open db
    if let Some(x) = &ctx.open_db {
        return Err(CdiffError::NotClosedBeforeOpening(x.into(), db_name));
    }

    if !db_name
        .chars()
        .all(|x: char| x.is_alphanumeric() || x == '\\' || x == '/' || x == '.')
    {
        return Err(CdiffError::ForbiddenCharactersInDB(db_name));
    }
    ctx.open_db = Some(db_name);

    Ok(())
}

/// Set up Context structure with data parsed from command add
fn cmd_add(ctx: &mut Context, signature: std::string::String) -> Result<(), CdiffError> {
    // Test for add without an open db
    if !ctx.open_db.is_some() {
        return Err(CdiffError::NoDBForAction("ADD"));
    }
    ctx.additions.push(signature);

    Ok(())
}

/// Set up Context structure with data parsed from command delete
fn cmd_del(ctx: &mut Context, del_op: DelOp) -> Result<(), CdiffError> {
    // Test for add without an open db
    if !ctx.open_db.is_some() {
        return Err(CdiffError::NoDBForAction("DEL"));
    }

    ctx.edits.insert(
        del_op.line_no,
        EditNode {
            line_no: del_op.line_no,
            orig_line: del_op.del_line.to_string(),
            new_line: None,
        },
    );
    Ok(())
}

/// Set up Context structure with data parsed from command exchange
fn cmd_xchg(ctx: &mut Context, xchg_op: XchgOp) -> Result<(), CdiffError> {
    // Test for add without an open db
    if !ctx.open_db.is_some() {
        return Err(CdiffError::NoDBForAction("XCHG"));
    }

    ctx.edits.insert(
        xchg_op.line_no,
        EditNode {
            line_no: xchg_op.line_no,
            orig_line: xchg_op.orig_line.to_string(),
            new_line: Some(xchg_op.new_line.to_string()),
        },
    );
    Ok(())
}

/// Move range of lines from one DB file into another
fn cmd_move(ctx: &mut Context, move_op: MoveOp) -> Result<(), CdiffError> {
    #[derive(PartialEq, Debug)]
    enum State {
        Init,
        Move,
        End,
    }

    let mut state = State::Init;

    // Test for move with open db
    if let Some(x) = &ctx.open_db {
        return Err(CdiffError::NotClosedBeforeAction(x.into()));
    }

    // Open src in read-only mode
    let src_file = File::open(move_op.src)?;

    // Open dst in append mode
    let mut dst_file = OpenOptions::new().append(true).open(move_op.dst)?;

    // Create tmp file and open for writing
    let tmp_named_file = tempfile::Builder::new()
        .prefix("_tmp_move_file")
        .tempfile_in("./")?;
    let mut tmp_file = tmp_named_file.as_file();

    // Create a buffered reader and loop over src, line by line
    let src_reader = BufReader::new(src_file);

    for (mut line_no, line) in src_reader.lines().enumerate() {
        let line = line?;

        // cdiff files start at line 1
        line_no += 1;
        if state == State::Init && line_no == move_op.start_line_no {
            if line.starts_with(move_op.start_line) {
                state = State::Move;
                dst_file.write_all(line.as_bytes())?;
                dst_file.write_all(b"\n")?;
            } else {
                error!("{} does not match {}", line, move_op.start_line);
                return Err(CdiffError::PatternDoesNotMatch(
                    "MOVE",
                    line_no,
                    move_op.src.to_string(),
                ));
            }
        }
        // Write everything between start and end to dst
        else if state == State::Move {
            dst_file.write_all(line.as_bytes())?;
            dst_file.write_all(b"\n")?;
            if line_no == move_op.end_line_no {
                if line.starts_with(move_op.end_line) {
                    state = State::End;
                } else {
                    return Err(CdiffError::PatternDoesNotMatch(
                        "MOVE",
                        line_no,
                        move_op.dst.to_string(),
                    ));
                }
            }
        }
        // Write everything outside of start and end to tmp
        else {
            tmp_file.write_all(line.as_bytes())?;
            tmp_file.write_all(b"\n")?;
        }
    }

    // Check that we handled start and end
    if state != State::End {
        return Err(CdiffError::MoveOpFailed);
    }

    // Delete src and replace it with tmp
    #[cfg(windows)]
    fs::remove_file(move_op.src)?;
    fs::rename(tmp_named_file.path(), move_op.src)?;

    Ok(())
}

/// Utilize Context structure built by various prior command calls to perform I/O on open file
fn cmd_close(ctx: &mut Context) -> Result<(), CdiffError> {
    let open_db = ctx
        .open_db
        .take()
        .ok_or_else(|| CdiffError::NoDBForAction("CLOSE"))?;

    let mut edits = ctx.edits.iter_mut();
    let mut next_edit = edits.next();

    if next_edit.is_some() {
        // Open src in read-only mode
        let src_file = File::open(&open_db)?;

        // Create a buffered reader and loop over src, line by line
        let src_reader = BufReader::new(src_file);

        // Create tmp file and open for writing
        let tmp_named_file = tempfile::Builder::new()
            .prefix("_tmp_move_file")
            .tempfile_in("./")?;
        let tmp_file = tmp_named_file.as_file();
        let mut tmp_file = BufWriter::new(tmp_file);

        for (line_no, line) in src_reader
            .lines()
            .enumerate()
            // Line numbers in the CDiff file begin at 1, not zero
            .map(|(i, line)| (i + 1, line))
        {
            let cur_line = line?;

            let new_line = if let Some((_, edit)) = &next_edit {
                if line_no == edit.line_no {
                    // Matching line.  Check for content match
                    if cur_line.starts_with(&edit.orig_line) {
                        let new_line = next_edit.unwrap().1.new_line.take();
                        next_edit = edits.next();
                        new_line
                    } else {
                        return Err(CdiffError::PatternDoesNotMatch(
                            if edit.new_line.is_some() {
                                "exchange"
                            } else {
                                "delete"
                            },
                            line_no,
                            open_db,
                        ));
                    }
                } else {
                    Some(cur_line)
                }
            } else {
                Some(cur_line)
            };

            // Anything to output?
            if let Some(new_line) = new_line {
                tmp_file.write_all(new_line.as_bytes())?;
                tmp_file.write_all(b"\n")?;
            }
        }

        // Make sure that all delete and exchange lines were processed
        if let Some((_, edit)) = next_edit {
            return Err(CdiffError::NotAllEditProcessed(
                if edit.new_line.is_some() {
                    "exchange"
                } else {
                    "delete"
                },
            ));
        }

        // Clean up the context
        ctx.edits.clear();

        // Replace the file in-place
        #[cfg(windows)]
        fs::remove_file(&open_db)?;
        fs::rename(tmp_named_file.path(), &open_db)?;

        tmp_file.flush()?;
    }

    // Test for lines to add
    if !ctx.additions.is_empty() {
        let mut db_file = OpenOptions::new().append(true).open(&open_db)?;
        for sig in &ctx.additions {
            debug!(
                "cmd_close() - writing signature {} to file {}",
                sig, &open_db
            );
            db_file.write_all(sig.as_bytes())?;
            db_file.write_all(b"\n")?;
        }
        ctx.additions.clear();
    }

    debug!("cmd_close() - finished");

    Ok(())
}

/// Set up Context structure with data parsed from command unlink
fn cmd_unlink(ctx: &mut Context) -> Result<(), CdiffError> {
    if let Some(open_db) = &ctx.open_db {
        fs::remove_file(open_db)?
    } else {
        return Err(CdiffError::NoDBForAction("UNLINK"));
    }
    Ok(())
}

/// Handle a specific command line in a cdiff file, calling the appropriate handler function
fn process_line(ctx: &mut Context, line: String) -> Result<(), CdiffError> {
    // Find the index at the end of the command (note that the CLOSE command has no trailing data)
    let spc_idx = match line.find(|c: char| c.is_whitespace()) {
        Some(spc_idx) => spc_idx,
        None => match line == "CLOSE" {
            true => 0,
            _ => {
                error!("Unable to parse cmd");
                process::abort();
            }
        },
    };

    // Get the data and clean it up
    let data: String = line.chars().skip(spc_idx + 1).collect::<String>();
    let data: String = data.trim().to_owned();

    // Get the command
    let cmd: String = if spc_idx > 0 {
        line.chars().take(spc_idx).collect()
    } else {
        line
    };

    debug!("cmd = {}", cmd);

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

/// Main loop for iterating over cdiff command lines and handling them
fn process_lines<T>(
    ctx: &mut Context,
    reader: T,
    uncompressed_size: usize,
) -> Result<(), CdiffError>
where
    T: BufRead,
{
    let mut decompressed_bytes = 0;
    for (n, line) in reader.lines().enumerate() {
        match line {
            Ok(line) => {
                if line.starts_with('#') {
                    continue;
                }
                decompressed_bytes = decompressed_bytes + line.len() + 1;
                debug!("process_lines()  - line {}: {:?}", n, line);
                process_line(ctx, line)?;
            }
            Err(e) => {
                return Err(CdiffError::MalformedFile(e.to_string()));
            }
        }
    }
    debug!(
        "Expected {} decompressed bytes, read {} decompressed bytes",
        uncompressed_size, decompressed_bytes
    );
    Ok(())
}

/// Find the signature at the end of the file, prefixed by ':'
fn read_dsig(file: &mut File) -> Result<Vec<u8>, CdiffError> {
    // Verify file length
    if file.metadata()?.len() < MAX_SIG_SIZE as u64 {
        return Err(CdiffError::NotEnoughBytes(MAX_SIG_SIZE));
    }

    // Seek to the dsig_offset
    file.seek(SeekFrom::End(-(MAX_SIG_SIZE as i64)))?;

    // Read from dsig_offset to EOF
    let mut dsig: Vec<u8> = vec![];
    file.read_to_end(&mut dsig)?;
    debug!("read_dsig() - dsig length is {}", dsig.len());

    // Find the signature
    let offset: usize = MAX_SIG_SIZE + 1;

    // Read in reverse until the delimiter ':' is found
    // let offset = dsig.iter().enumerate().rev().find(|(i, value)| **value == b':');
    if let Some(dsig) = dsig.rsplit(|v| *v == b':').next() {
        if dsig.len() > MAX_SIG_SIZE {
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

    // Read up to READ_SIZE to parse out the file size.
    let n = file.take(READ_SIZE as u64).read_to_end(&mut buf)?;
    let mut colons = 0;
    let mut file_size_vec = Vec::new();
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
            debug!("read_size() - file_size_str == {}", file_size_str);
            return Ok((file_size_str.parse::<u32>()?, i + 1));
        }
    }
    Err(CdiffError::MalformedFile("insufficient colons".to_string()))
}

/// Calculate the sha256 of the first len bytes of a file
fn get_hash(file: &mut File, len: usize) -> Result<[u8; 32], CdiffError> {
    let mut hasher = Sha256::new();

    // Seek to beginning of file
    file.seek(SeekFrom::Start(0))?;

    let mut sum: usize = 0;

    // Read READ_SIZE bytes at a time,
    // calculating the hash along the way. Stop
    // after signature is reached.
    loop {
        let mut buf = Vec::with_capacity(READ_SIZE);
        let n = file.take(READ_SIZE as u64).read_to_end(&mut buf)?;
        if sum + n >= len {
            // update with len - sum
            hasher.update(&buf[..(len - sum)]);
            let hash = hasher.finalize();
            return Ok(hash.into());
        } else {
            // update with n
            hasher.update(&buf);
        }
        sum += n;
    }
}

fn print_file_data(buf: Vec<u8>, len: usize) {
    for (i, value) in buf.iter().enumerate().take(len) {
        eprint!("{:#02X} ", value);
        if (i + 1) % 16 == 0 {
            eprint!("");
        }
    }
    eprintln!();
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
        println!("MOVE was called!");

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
        println!("MOVE was called!");

        let err = MoveOp::new("a b NOTANUMBER hello 2 world").expect_err("Should've failed!");
        let parse_string = "NOTANUMBER".to_string();
        let parse_error = parse_string.parse::<usize>().unwrap_err();
        let number_error = CdiffError::ParseIntError(parse_error);
        println!("{:?}", err.to_string());
        assert_eq!(err.to_string(), number_error.to_string());
    }

    #[test]
    fn parse_move_fail_eof() {
        println!("MOVE was called!");

        let err = MoveOp::new("a b 1").expect_err("Should've failed!");
        let start_line_err = CdiffError::NoMoreData("start_line");
        println!("{:?}", err.to_string());
        assert_eq!(err.to_string(), start_line_err.to_string());
    }

    /// Helper function to set up a test folder and initialize a pseudo-db file with specified data.
    fn initialize_db_file_with_data(
        initial_data: Vec<&str>,
    ) -> Result<tempfile::TempPath, CdiffTestError> {
        let mut file = tempfile::Builder::new()
            .tempfile_in("./")
            .expect("Failed to create temp file");
        for line in initial_data {
            file.write_all(line.as_bytes())
                .expect("Failed to write line to temp file");
            file.write_all(b"\n")?;
        }
        Ok(file.into_temp_path())
    }

    /// Compare provided vector data with file contents
    fn compare_file_with_expected(
        temp_file_path: tempfile::TempPath,
        expected_data: &mut Vec<&str>,
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
            debug!(
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
            ..Default::default()
        };
        ctx
    }

    #[test]
    fn delete_first_line() {
        let initial_data = vec!["ClamAV-VDB:14 Jul 2021 14-29 -0400", "AAAA", "BBBB", "CCCC"];
        let mut expected_data = vec!["AAAA", "BBBB", "CCCC"];

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
        let initial_data = vec!["ClamAV-VDB:14 Jul 2021 14-29 -0400", "AAAA", "BBBB", "CCCC"];
        let mut expected_data = vec!["ClamAV-VDB:14 Jul 2021 14-29 -0400", "BBBB", "CCCC"];

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
        let initial_data = vec!["ClamAV-VDB:14 Jul 2021 14-29 -0400", "AAAA", "BBBB", "CCCC"];
        let mut expected_data = vec!["ClamAV-VDB:14 Jul 2021 14-29 -0400", "AAAA", "BBBB"];

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
        let initial_data = vec!["ClamAV-VDB:14 Jul 2021 14-29 -0400", "AAAA", "BBBB", "CCCC"];

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
        let initial_data = vec!["ClamAV-VDB:14 Jul 2021 14-29 -0400", "AAAA", "BBBB", "CCCC"];

        let db_file_path = initialize_db_file_with_data(initial_data).unwrap();

        // Create contextual data structure with open_db path
        let mut ctx = construct_ctx_from_path(&db_file_path);

        let del_op = DelOp::new("5 CCCC").unwrap();
        cmd_del(&mut ctx, del_op).expect("cmd_del failed");
        match cmd_close(&mut ctx) {
            Ok(_) => panic!("cmd_close should have failed!"),
            Err(e) => {
                assert!(matches!(e, CdiffError::NotAllEditProcessed("delete")));
            }
        }
    }

    #[test]
    fn exchange_first_line() {
        let initial_data = vec!["ClamAV-VDB:14 Jul 2021 14-29 -0400", "AAAA", "BBBB", "CCCC"];
        let mut expected_data = vec!["ClamAV-VDB:15 Aug 2021 14-29 -0400", "AAAA", "BBBB", "CCCC"];

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
        let initial_data = vec!["ClamAV-VDB:14 Jul 2021 14-29 -0400", "AAAA", "BBBB", "CCCC"];
        let mut expected_data = vec!["ClamAV-VDB:14 Jul 2021 14-29 -0400", "DDDD", "BBBB", "CCCC"];

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
        let initial_data = vec!["ClamAV-VDB:14 Jul 2021 14-29 -0400", "AAAA", "BBBB", "CCCC"];
        let mut expected_data = vec!["ClamAV-VDB:14 Jul 2021 14-29 -0400", "AAAA", "BBBB", "DDDD"];

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
        let initial_data = vec!["ClamAV-VDB:14 Jul 2021 14-29 -0400", "AAAA", "BBBB", "CCCC"];

        let db_file_path = initialize_db_file_with_data(initial_data).unwrap();

        // Create contextual data structure with open_db path
        let mut ctx = construct_ctx_from_path(&db_file_path);

        let xchg_op = XchgOp::new("5 DDDD EEEE").unwrap();
        cmd_xchg(&mut ctx, xchg_op).expect("cmd_xchg failed");
        match cmd_close(&mut ctx) {
            Ok(_) => panic!("cmd_close should have failed!"),
            Err(e) => {
                assert!(matches!(e, CdiffError::NotAllEditProcessed("exchange")));
            }
        }
    }

    #[test]
    fn add_delete_exchange() {
        let initial_data = vec!["ClamAV-VDB:14 Jul 2021 14-29 -0400", "AAAA", "BBBB", "CCCC"];
        let mut expected_data = vec!["ClamAV-VDB:14 Jul 2021 14-29 -0400", "DDDD", "CCCC", "EEEE"];

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

    #[test]
    fn move_db() {
        // Define initial databases
        let dst_data = vec!["ClamAV-VDB:15 Aug 2021 14-30 -0400", "AAAA", "BBBB", "CCCC"];

        let src_data = vec![
            "ClamAV-VDB:14 Jul 2021 14-29 -0400",
            "AAAA",
            "BBBB",
            "CCCC",
            "DDDD",
            "EEEE",
            "FFFF",
            "GGGG",
        ];

        // Define expected databases after move operation
        let mut expected_dst_data = vec![
            "ClamAV-VDB:15 Aug 2021 14-30 -0400",
            "AAAA",
            "BBBB",
            "CCCC",
            "DDDD",
            "EEEE",
            "FFFF",
        ];

        let mut expected_src_data = vec![
            "ClamAV-VDB:14 Jul 2021 14-29 -0400",
            "AAAA",
            "BBBB",
            "CCCC",
            "GGGG",
        ];

        // Initialize databases
        let dst_file_path = initialize_db_file_with_data(dst_data).unwrap();
        let src_file_path = initialize_db_file_with_data(src_data).unwrap();

        let mut ctx: Context = Context::default();

        let move_args = format!(
            "{} {} 5 DDDD 7 FFFF",
            src_file_path.to_str().unwrap(),
            dst_file_path.to_str().unwrap()
        );

        // Move lines 5-7 from src to dst
        let move_op = MoveOp::new(move_args.as_str()).unwrap();

        match cmd_move(&mut ctx, move_op) {
            Ok(_) => (),
            Err(e) => panic!("cmd_move failed with: {}", e.to_string()),
        }

        compare_file_with_expected(src_file_path, &mut expected_src_data);
        compare_file_with_expected(dst_file_path, &mut expected_dst_data);
    }

    #[test]
    fn script2cdiff_missing_hyphen() {
        assert!(matches!(
            script2cdiff("", "", ""),
            Err(CdiffError::FilenameMissingHyphen)
        ));
    }
}

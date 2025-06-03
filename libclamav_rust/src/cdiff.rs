/*
 *  Copyright (C) 2021-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
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
    ffi::{c_void, CStr, CString},
    fs::{self, File, OpenOptions},
    io::{prelude::*, BufReader, BufWriter, Read, Seek, SeekFrom, Write},
    iter::*,
    mem::ManuallyDrop,
    os::raw::c_char,
    path::{Path, PathBuf},
    str::{self, FromStr},
};

use crate::{
    codesign::{self, Verifier},
    ffi_error,
    ffi_util::FFIError,
    sys, validate_str_param,
};

use flate2::{read::GzDecoder, write::GzEncoder, Compression};
use log::{debug, error, warn};
use sha2::{Digest, Sha256};

/// Size of a digital signature
const SIG_SIZE: usize = 350;

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
    orig_line: Vec<u8>,
    new_line: Option<Vec<u8>>,
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
    additions: Vec<u8>,
}

/// Possible errors returned by cdiff_apply() and script2cdiff
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Error in header: {0}")]
    Header(#[from] HeaderError),

    /// An error encountered while handling CDIFF input
    ///
    /// This error *may* wrap a processing error if the command has side effects
    /// (e.g., MOVE or CLOSE)
    #[error("{err} on line {line}: {operation}")]
    Input {
        line: usize,
        err: InputError,
        operation: String,
    },

    /// An error encountered while handling a particular CDiff command
    #[error("processing {1} command on line {2}: {0}")]
    Processing(ProcessingError, &'static str, usize),

    /// An error encountered while handling the digital signature
    #[error("processing signature: {0}")]
    Signature(#[from] SignatureError),

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

    #[error("Incorrect digital signature")]
    InvalidDigitalSignature,

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("NUL found within CString")]
    CstringNulError(#[from] std::ffi::NulError),

    #[error("Can't verify: {0}")]
    CannotVerify(String),
}

/// Errors particular to input handling (i.e., syntax, or side effects from
/// handling input)
#[derive(thiserror::Error, Debug)]
pub enum InputError {
    #[error("Unsupported command provided: {0}")]
    UnknownCommand(String),

    #[error("No DB open for action {0}")]
    NoDBForAction(&'static str),

    #[error("Invalid DB \"{0}\" open for action {1}")]
    InvalidDBForAction(String, &'static str),

    #[error("File {0} not closed before opening {1}")]
    NotClosedBeforeOpening(String, String),

    #[error("{0} not Unicode")]
    NotUnicode(&'static str),

    #[error("Invalid database name {0}. Characters must be alphanumeric or '.'")]
    InvalidDBNameForbiddenCharacters(String),

    #[error("Invalid database name {0}. Must not specify parent directory.")]
    InvalidDBNameNoParentDirectory(String),

    #[error("{0} missing for {1}")]
    MissingParameter(&'static str, &'static str),

    #[error("Command missing")]
    MissingCommand,

    #[error("Invalid line number: {0}")]
    InvalidLineNo(InvalidNumber),

    /// the line, when taken as a whole, is not valid unicode
    #[error("not unicode")]
    LineNotUnicode(#[from] std::str::Utf8Error),

    /// Errors encountered while executing a command
    #[error("Processing: {0}")]
    Processing(#[from] ProcessingError),

    /// Errors encountered while executing a command
    #[error("Processing: {0}")]
    ProcessingString(String),

    #[error("no final newline")]
    MissingNL,

    #[error("Database file is still open: {0}")]
    DBStillOpen(String),
}

/// Errors encountered while processing
#[derive(thiserror::Error, Debug)]
pub enum ProcessingError {
    #[error("File {0} not closed before calling action MOVE")]
    NotClosedBeforeAction(String),

    #[error("Unexpected end of line while parsing field: {0}")]
    NoMoreData(&'static str),

    #[error("Move operation failed")]
    MoveOpFailed,

    #[error("Failed to parse string as a number")]
    ParseIntError(#[from] std::num::ParseIntError),

    #[error("Cannot perform action {0} on line {1} in file {2}. Pattern does not match")]
    PatternDoesNotMatch(&'static str, usize, PathBuf),

    #[error("Not all edit processed at file end ({0} remaining)")]
    NotAllEditProcessed(&'static str),

    #[error(transparent)]
    FromUtf8Error(#[from] std::string::FromUtf8Error),

    #[error(transparent)]
    FromUtf8StrError(#[from] std::str::Utf8Error),

    #[error("NUL found within buffer to be interpreted as NUL-terminated string")]
    NulError(#[from] std::ffi::NulError),

    #[error("Conflicting actions found for line {0}")]
    ConflictingAction(usize),

    ///
    /// Generic remaps
    ///
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

#[derive(thiserror::Error, Debug)]
pub enum HeaderError {
    #[error("invalid magic")]
    BadMagic,

    #[error("too-few colon-separated fields")]
    TooFewFields,

    #[error("invalid size")]
    InvalidSize(#[from] InvalidNumber),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

#[derive(thiserror::Error, Debug)]
pub enum SignatureError {
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Fewer than {SIG_SIZE} bytes remaining for signature")]
    TooSmall,

    #[error("Digital signature larger than {SIG_SIZE} bytes")]
    TooLarge,
}

#[derive(thiserror::Error, Debug)]
pub enum InvalidNumber {
    #[error("not unicode")]
    NotUnicode(#[from] std::str::Utf8Error),

    #[error("unparseable")]
    Unparseable(#[from] std::num::ParseIntError),
}

#[derive(Debug)]
pub struct DelOp<'a> {
    line_no: usize,
    del_line: &'a [u8],
}

/// Method to parse the cdiff line describing a delete operation
impl<'a> DelOp<'a> {
    pub fn new(data: &'a [u8]) -> Result<Self, InputError> {
        let mut iter = data.split(|b| *b == b' ');
        let line_no = str::from_utf8(
            iter.next()
                .ok_or(InputError::MissingParameter("DEL", "line_no"))?,
        )
        .map_err(|e| InputError::InvalidLineNo(e.into()))?
        .parse::<usize>()
        .map_err(|e| InputError::InvalidLineNo(e.into()))?;
        let del_line = iter
            .next()
            .ok_or(InputError::MissingParameter("DEL", "orig_line"))?;

        Ok(DelOp { line_no, del_line })
    }
}

#[derive(Debug)]
pub struct UnlinkOp<'a> {
    db_name: &'a str,
}

/// Method to parse the cdiff line describing an unlink operation
impl<'a> UnlinkOp<'a> {
    pub fn new(data: &'a [u8]) -> Result<Self, InputError> {
        let mut iter = data.split(|b| *b == b' ');
        let db_name = str::from_utf8(
            iter.next()
                .ok_or(InputError::MissingParameter("UNLINK", "db_name"))?,
        )
        .map_err(|_| InputError::NotUnicode("database name"))?;

        if !db_name
            .chars()
            .all(|x: char| x.is_alphanumeric() || x == '.' || x == '_')
        {
            // DB Name contains invalid characters.
            return Err(InputError::InvalidDBNameForbiddenCharacters(
                db_name.to_owned(),
            ));
        }

        let db_path = PathBuf::from_str(db_name).unwrap();
        if db_path.parent() != Some(Path::new("")) {
            // DB Name must be not include a parent directory.
            return Err(InputError::InvalidDBNameNoParentDirectory(
                db_name.to_owned(),
            ));
        }

        Ok(UnlinkOp { db_name })
    }
}

#[derive(Debug)]
pub struct MoveOp<'a> {
    src: PathBuf,
    dst: PathBuf,
    start_line_no: usize,
    start_line: &'a [u8],
    end_line_no: usize,
    end_line: &'a [u8],
}

/// Method to parse the cdiff line describing a move operation
impl<'a> MoveOp<'a> {
    pub fn new(data: &'a [u8]) -> Result<Self, InputError> {
        let mut iter = data.split(|b| *b == b' ');

        let src = PathBuf::from(str::from_utf8(
            iter.next()
                .ok_or(InputError::MissingParameter("MOVE", "src"))?,
        )?);

        let dst = PathBuf::from(str::from_utf8(
            iter.next()
                .ok_or(InputError::MissingParameter("MOVE", "dst"))?,
        )?);

        let start_line_no = str::from_utf8(
            iter.next()
                .ok_or(InputError::MissingParameter("MOVE", "start_line_no"))?,
        )
        .map_err(|e| InputError::InvalidLineNo(e.into()))?
        .parse::<usize>()
        .map_err(|e| InputError::InvalidLineNo(e.into()))?;

        let start_line = iter
            .next()
            .ok_or(InputError::MissingParameter("MOVE", "start_line"))?;

        let end_line_no = str::from_utf8(
            iter.next()
                .ok_or(InputError::MissingParameter("MOVE", "end_line"))?,
        )
        .map_err(|e| InputError::InvalidLineNo(e.into()))?
        .parse::<usize>()
        .map_err(|e| InputError::InvalidLineNo(e.into()))?;

        let end_line = iter
            .next()
            .ok_or(InputError::MissingParameter("MOVE", "end_line"))?;

        Ok(MoveOp {
            src,
            dst,
            start_line_no,
            start_line,
            end_line_no,
            end_line,
        })
    }
}

#[derive(Debug)]
pub struct XchgOp<'a> {
    line_no: usize,
    orig_line: &'a [u8],
    new_line: &'a [u8],
}

/// Method to parse the cdiff line describing an exchange operation
impl<'a> XchgOp<'a> {
    pub fn new(data: &'a [u8]) -> Result<Self, InputError> {
        let mut iter = data.splitn(3, |b| *b == b' ');
        let line_no = str::from_utf8(
            iter.next()
                .ok_or(InputError::MissingParameter("XCHG", "line_no"))?,
        )
        .map_err(|e| InputError::InvalidLineNo(e.into()))?
        .parse::<usize>()
        .map_err(|e| InputError::InvalidLineNo(e.into()))?;

        Ok(XchgOp {
            line_no,
            orig_line: iter
                .next()
                .ok_or(InputError::MissingParameter("XCHG", "orig_line"))?,
            new_line: iter
                .next()
                .ok_or(InputError::MissingParameter("XCHG", "new_line"))?,
        })
    }
}

fn is_debug_enabled() -> bool {
    unsafe {
        let debug_flag = sys::cli_get_debug_flag();
        // Return true if debug_flag is not 0
        !matches!(debug_flag, 0)
    }
}

#[export_name = "script2cdiff"]
pub extern "C" fn _script2cdiff(
    script: *const c_char,
    builder: *const c_char,
    server: *const c_char,
) -> bool {
    // validate_str_param! generates a false alarm here.  Marking the entire
    // function as unsafe triggers a different warning
    #![allow(clippy::not_unsafe_ptr_arg_deref)]
    let script_file_name = validate_str_param!(script);
    let builder = validate_str_param!(builder);
    let server = validate_str_param!(server);
    match script2cdiff(script_file_name, builder, server) {
        Ok(_) => true,
        Err(e) => {
            error!("{}", e);
            false
        }
    }
}

/// Convert a plaintext script file of cdiff commands into a cdiff formatted file
///
/// This function makes a single C call to cli_getdsig to obtain a signed
/// signature from the sha2-256 of the contents written.
///
/// This function will panic if any of the &str parameters contain interior NUL bytes
pub fn script2cdiff(script_file_name: &str, builder: &str, server: &str) -> Result<(), Error> {
    // Make a copy of the script file name to use for the cdiff file
    let cdiff_file_name_string = script_file_name.to_string();
    let mut cdiff_file_name = cdiff_file_name_string.as_str();
    debug!("script2cdiff: script file name: {:?}", cdiff_file_name);

    // Remove the "".script" suffix
    if let Some(file_name) = cdiff_file_name.strip_suffix(".script") {
        cdiff_file_name = file_name;
    }

    // Get right-most hyphen index
    let hyphen_index = cdiff_file_name
        .rfind('-')
        .ok_or(Error::FilenameMissingHyphen)?;

    // Get the version, which should be to the right of the hyphen
    let version_string = cdiff_file_name
        .get((hyphen_index + 1)..)
        .ok_or(Error::FilenameMissingVersion)?;

    // Parse the version into usize
    let version = version_string
        .to_string()
        .parse::<usize>()
        .map_err(Error::VersionParse)?;

    // Add .cdiff suffix
    let cdiff_file_name = format!("{}.{}", cdiff_file_name, "cdiff");
    debug!("script2cdiff: writing to: {:?}", &cdiff_file_name);

    // Open cdiff_file_name for writing
    let mut cdiff_file: File = File::create(&cdiff_file_name)
        .map_err(|e| Error::FileCreate(cdiff_file_name.to_owned(), e))?;

    // Open the original script file for reading
    let script_file: File = File::open(script_file_name)
        .map_err(|e| Error::FileOpen(script_file_name.to_owned(), e))?;

    // Get file length
    let script_file_len = script_file
        .metadata()
        .map_err(|e| Error::FileMeta(script_file_name.to_owned(), e))?
        .len();

    // Write header to cdiff file
    write!(cdiff_file, "ClamAV-Diff:{}:{}:", version, script_file_len)
        .map_err(|e| Error::FileWrite(script_file_name.to_owned(), e))?;

    // Set up buffered reader and gz writer
    let mut reader = BufReader::new(script_file);
    let mut gz = GzEncoder::new(cdiff_file, Compression::default());

    // Pipe the input into the compressor
    std::io::copy(&mut reader, &mut gz)?;

    // Get cdiff file writer back from flate2
    let mut cdiff_file = gz
        .finish()
        .map_err(|e| Error::FileWrite(cdiff_file_name.to_owned(), e))?;

    // Get the new cdiff file len
    let cdiff_file_len = cdiff_file
        .metadata()
        .map_err(|e| Error::FileMeta(cdiff_file_name.to_owned(), e))?
        .len();
    debug!(
        "script2cdiff: wrote {} bytes to {}",
        cdiff_file_len, cdiff_file_name
    );

    // Calculate SHA2-256 to get the signature
    // TODO: Do this while the file is being written
    let bytes = std::fs::read(&cdiff_file_name)
        .map_err(|e| Error::FileRead(cdiff_file_name.to_owned(), e))?;
    let sha2_256 = {
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        hasher.finalize()
    };

    let dsig = unsafe {
        // These strings should not contain interior NULs
        let server = CString::new(server).unwrap();
        let builder = CString::new(builder).unwrap();
        let dsig_ptr = sys::cli_getdsig(
            server.as_c_str().as_ptr() as *const c_char,
            builder.as_c_str().as_ptr() as *const c_char,
            sha2_256.to_vec().as_ptr(),
            32,
            2,
        );
        assert!(!dsig_ptr.is_null());
        CStr::from_ptr(dsig_ptr)
    };

    // Write cdiff footer delimiter
    cdiff_file
        .write_all(b":")
        .map_err(|e| Error::FileWrite(cdiff_file_name.to_owned(), e))?;

    // Write dsig to cdiff footer
    cdiff_file
        .write_all(dsig.to_bytes())
        .map_err(|e| Error::FileWrite(cdiff_file_name, e))?;

    // Exit success
    Ok(())
}

/// C interface for cdiff_apply() (below).
/// This function is for use in sigtool.c and libfreshclam_internal.c
///
/// # Safety
///
/// No parameters may be NULL.
#[export_name = "cdiff_apply"]
pub unsafe extern "C" fn _cdiff_apply(
    cdiff_file_path_str: *const c_char,
    verifier_ptr: *const c_void,
    mode: u16,
    err: *mut *mut FFIError,
) -> bool {
    let cdiff_file_path_str = validate_str_param!(cdiff_file_path_str);
    let cdiff_file_path = match Path::new(cdiff_file_path_str).canonicalize() {
        Ok(p) => p,
        Err(e) => {
            return ffi_error!(
                err = err,
                Error::CannotVerify(format!(
                    "Invalid cdiff file path '{}': {}",
                    cdiff_file_path_str, e
                ))
            );
        }
    };

    let verifier = ManuallyDrop::new(Box::from_raw(verifier_ptr as *mut Verifier));

    let mode = if mode == 1 {
        ApplyMode::Cdiff
    } else {
        ApplyMode::Script
    };

    if let Err(e) = cdiff_apply(&cdiff_file_path, &verifier, mode) {
        error!("Failed to apply {:?}: {}", cdiff_file_path, e);
        ffi_error!(err = err, e)
    } else {
        true
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
/// A cdiff file contains a footer that is the signed signature of the sha2-256
/// file contains of the header and the body. The footer begins after the first
/// ':' character to the left of EOF.
pub fn cdiff_apply(
    cdiff_file_path: &Path,
    verifier: &Verifier,
    mode: ApplyMode,
) -> Result<(), Error> {
    let path = std::env::current_dir().unwrap();
    debug!("cdiff_apply: applying {}", cdiff_file_path.display());
    debug!("cdiff_apply: current directory is {}", path.display());

    // Open cdiff file for reading
    let mut file = File::open(cdiff_file_path).map_err(Error::IoError)?;

    // Only read dsig, header, etc. if this is a cdiff file
    let header_length = match mode {
        ApplyMode::Script => 0,
        ApplyMode::Cdiff => {
            // Get file length
            let file_len = file.metadata()?.len() as usize;

            // Check if there is an external digital signature
            // The filename would be the same as the cdiff file with an extra .sign extension
            let sign_file_path = cdiff_file_path.with_extension("cdiff.sign");
            let verify_result =
                codesign::verify_signed_file(cdiff_file_path, &sign_file_path, verifier);
            let verified = match verify_result {
                Ok(signer) => {
                    debug!(
                        "cdiff_apply: external signature verified. Signed by: {}",
                        signer
                    );
                    true
                }
                Err(codesign::Error::InvalidDigitalSignature(m)) => {
                    debug!("cdiff_apply: invalid external signature: {}", m);
                    return Err(Error::InvalidDigitalSignature);
                }
                Err(e) => {
                    debug!("cdiff_apply: error validating external signature: {:?}", e);

                    // If the external signature could not be validated (e.g. does not exist)
                    // then continue on and try to validate the internal signature.
                    false
                }
            };

            if !verified {
                // try to verify the internal (legacy) digital signature
                let dsig = read_dsig(&mut file)?;
                debug!("cdiff_apply: final dsig length is {}", dsig.len());
                if is_debug_enabled() {
                    print_file_data(dsig.clone(), dsig.len());
                }

                let footer_offset = file_len - dsig.len() - 1;

                // The SHA is calculated from the contents of the beginning of the file
                // up until the ':' before the dsig at the end of the file.
                let sha2_256 = get_hash(&mut file, footer_offset)?;

                debug!("cdiff_apply: sha2-256: {}", hex::encode(sha2_256));

                // cli_versig2 will expect dsig to be a null-terminated string
                let dsig_cstring = CString::new(dsig)?;

                // Verify cdiff
                let n = CString::new(PUBLIC_KEY_MODULUS).unwrap();
                let e = CString::new(PUBLIC_KEY_EXPONENT).unwrap();
                let versig_result = unsafe {
                    sys::cli_versig2(
                        sha2_256.to_vec().as_ptr(),
                        dsig_cstring.as_ptr(),
                        n.as_ptr() as *const c_char,
                        e.as_ptr() as *const c_char,
                    )
                };
                debug!("cdiff_apply: cli_versig2() result = {}", versig_result);
                if versig_result != 0 {
                    return Err(Error::InvalidDigitalSignature);
                }
            }

            // Read file length from header
            let (header_len, header_offset) = read_size(&mut file)?;
            debug!(
                "cdiff_apply: header len = {}, file len = {}, header offset = {}",
                header_len, file_len, header_offset
            );

            let current_pos = file.seek(SeekFrom::Start(header_offset as u64))?;
            debug!("cdiff_apply: current file offset = {}", current_pos);
            header_len as usize
        }
    };

    // Set reader according to whether this is a script or cdiff
    let mut reader: Box<dyn BufRead> = match mode {
        ApplyMode::Cdiff => {
            let gz = GzDecoder::new(file);
            Box::new(BufReader::new(gz))
        }
        ApplyMode::Script => Box::new(BufReader::new(file)),
    };

    // Create contextual data structure
    let mut ctx: Context = Context::default();

    process_lines(&mut ctx, &mut reader, header_length)
}

/// Set up Context structure with data parsed from command open
fn cmd_open(ctx: &mut Context, db_name: Option<&[u8]>) -> Result<(), InputError> {
    let db_name = db_name.ok_or(InputError::MissingParameter("OPEN", "line_no"))?;
    let db_name = str::from_utf8(db_name).map_err(|_| InputError::NotUnicode("database name"))?;
    // Test for existing open db
    if let Some(x) = &ctx.open_db {
        return Err(InputError::NotClosedBeforeOpening(
            x.into(),
            db_name.to_owned(),
        ));
    }

    if !db_name
        .chars()
        .all(|x: char| x.is_alphanumeric() || x == '.' || x == '_')
    {
        // DB Name contains invalid characters.
        return Err(InputError::InvalidDBNameForbiddenCharacters(
            db_name.to_owned(),
        ));
    }

    let db_path = PathBuf::from_str(db_name).unwrap();
    if db_path.parent() != Some(Path::new("")) {
        // DB Name must be not include a parent directory.
        return Err(InputError::InvalidDBNameNoParentDirectory(
            db_name.to_owned(),
        ));
    }

    ctx.open_db = Some(db_name.to_owned());

    Ok(())
}

/// Set up Context structure with data parsed from command add
fn cmd_add(ctx: &mut Context, signature: &[u8]) -> Result<(), InputError> {
    // Test for add without an open db
    if ctx.open_db.is_none() {
        return Err(InputError::NoDBForAction("ADD"));
    }
    ctx.additions.extend_from_slice(signature);

    Ok(())
}

/// Set up Context structure with data parsed from command delete
fn cmd_del(ctx: &mut Context, del_op: DelOp) -> Result<(), InputError> {
    // Test for add without an open db
    if ctx.open_db.is_none() {
        return Err(InputError::NoDBForAction("DEL"));
    }

    ctx.edits.insert(
        del_op.line_no,
        EditNode {
            line_no: del_op.line_no,
            orig_line: del_op.del_line.to_owned(),
            new_line: None,
        },
    );
    Ok(())
}

/// Set up Context structure with data parsed from command exchange
fn cmd_xchg(ctx: &mut Context, xchg_op: XchgOp) -> Result<(), InputError> {
    // Test for add without an open db
    if ctx.open_db.is_none() {
        return Err(InputError::NoDBForAction("XCHG"));
    }

    ctx.edits.insert(
        xchg_op.line_no,
        EditNode {
            line_no: xchg_op.line_no,
            orig_line: xchg_op.orig_line.to_owned(),
            new_line: Some(xchg_op.new_line.to_owned()),
        },
    );
    Ok(())
}

/// Move range of lines from one DB file into another
fn cmd_move(ctx: &mut Context, move_op: MoveOp) -> Result<(), InputError> {
    #[derive(PartialEq, Debug)]
    enum State {
        Init,
        Move,
        End,
    }

    let mut state = State::Init;

    // Test for move with open db
    if let Some(x) = &ctx.open_db {
        return Err(ProcessingError::NotClosedBeforeAction(x.into()).into());
    }

    // Open dst in append mode
    let mut dst_file = OpenOptions::new()
        .append(true)
        .open(&move_op.dst)
        .map_err(|e| {
            InputError::ProcessingString(format!(
                "Failed to open destination file {:?} for MOVE command: {}",
                &move_op.dst, e
            ))
        })?;

    // Create tmp file and open for writing
    let tmp_named_file = tempfile::Builder::new()
        .prefix("_tmp_move_file")
        .tempfile_in("./")
        .map_err(|e| {
            InputError::ProcessingString(format!(
                "Failed to create temp file in current directory {:?} for MOVE command: {}",
                std::env::current_dir(),
                e
            ))
        })?;
    let mut tmp_file = tmp_named_file.as_file();

    // Open src in read-only mode
    let mut src_reader = BufReader::new(File::open(&move_op.src).map_err(|e| {
        InputError::ProcessingString(format!(
            "Failed to open source file {:?}: {} for MOVE command",
            &move_op.src, e
        ))
    })?);

    let mut line = vec![];
    let mut line_no = 0;
    loop {
        // cdiff files start at line 1
        line_no += 1;
        line.clear();
        let n_read = src_reader.read_until(b'\n', &mut line).map_err(|e| {
            InputError::ProcessingString(format!(
                "Failed to read from source file {:?} for MOVE command: {}",
                &move_op.src, e
            ))
        })?;
        if n_read == 0 {
            break;
        }
        if state == State::Init && line_no == move_op.start_line_no {
            if line.starts_with(move_op.start_line) {
                state = State::Move;
                dst_file.write_all(&line).map_err(ProcessingError::from)?;
            } else {
                return Err(
                    ProcessingError::PatternDoesNotMatch("MOVE", line_no, move_op.src).into(),
                );
            }
        }
        // Write everything between start and end to dst
        else if state == State::Move {
            dst_file.write_all(&line).map_err(ProcessingError::from)?;
            if line_no == move_op.end_line_no {
                if line.starts_with(move_op.end_line) {
                    state = State::End;
                } else {
                    return Err(
                        ProcessingError::PatternDoesNotMatch("MOVE", line_no, move_op.dst).into(),
                    );
                }
            }
        }
        // Write everything outside of start and end to tmp
        else {
            tmp_file.write_all(&line).map_err(|e| {
                InputError::ProcessingString(format!(
                    "Failed to write line to temp file {:?} for MOVE command: {}",
                    tmp_named_file.path(),
                    e
                ))
            })?;
        }
    }

    // Ensure the file is no longer open for read so that Windows will be willing
    // to allow it to be overwritten.
    drop(src_reader);

    // Check that we handled start and end
    if state != State::End {
        return Err(ProcessingError::MoveOpFailed.into());
    }

    // Delete src and replace it with tmp
    #[cfg(windows)]
    fs::remove_file(&move_op.src).map_err(|e| {
        InputError::ProcessingString(format!(
            "Failed to remove original source file {:?} for MOVE command: {}",
            &move_op.src, e
        ))
    })?;
    fs::rename(tmp_named_file.path(), &move_op.src).map_err(|e| {
        InputError::ProcessingString(format!(
            "Failed to rename temp file {:?} to {:?} for MOVE command: {}",
            tmp_named_file.path(),
            &move_op.src,
            e
        ))
    })?;

    Ok(())
}

/// Utilize Context structure built by various prior command calls to perform I/O on open file
fn cmd_close(ctx: &mut Context) -> Result<(), InputError> {
    let open_db = ctx
        .open_db
        .take()
        .ok_or(InputError::NoDBForAction("CLOSE"))?;

    let mut edits = ctx.edits.iter_mut();
    let mut next_edit = edits.next();

    if next_edit.is_some() {
        // Open src in read-only mode
        let mut src_reader = BufReader::new(File::open(&open_db).map_err(|e| {
            InputError::ProcessingString(format!(
                "Failed to open db file {:?} for CLOSE command: {}",
                &open_db, e
            ))
        })?);

        // Create tmp file and open for writing
        let tmp_named_file = tempfile::Builder::new()
            .prefix("_tmp_move_file")
            .tempfile_in("./")
            .map_err(|e| {
                InputError::ProcessingString(format!(
                    "Failed to create temp file in current directory {:?} for CLOSE command: {}",
                    std::env::current_dir(),
                    e
                ))
            })?;
        let tmp_file = tmp_named_file.as_file();
        let mut tmp_file = BufWriter::new(tmp_file);

        let mut linebuf = Vec::new();
        for line_no in 1.. {
            linebuf.clear();
            let n_read = src_reader.read_until(b'\n', &mut linebuf).map_err(|e| {
                InputError::ProcessingString(format!(
                    "Failed to read temp file {:?} for CLOSE command: {}",
                    tmp_named_file.path(),
                    e
                ))
            })?;
            if n_read == 0 {
                // No more input
                break;
            }

            match linebuf.pop() {
                Some(b'\n') => (),
                Some(_) => return Err(InputError::MissingNL),
                None => unreachable!(),
            }
            let cur_line = &linebuf;

            // This is a placeholder so that we can provide a reference to
            // something in the same scope
            let repl_line;
            let new_line = if let Some((_, edit)) = &next_edit {
                if line_no == edit.line_no {
                    // Matching line.  Check for content match
                    if cur_line.starts_with(&edit.orig_line) {
                        repl_line = next_edit.unwrap().1.new_line.take();
                        next_edit = edits.next();

                        repl_line.as_deref()
                    } else {
                        dbg!(&cur_line, &edit.orig_line);
                        return Err(ProcessingError::PatternDoesNotMatch(
                            if edit.new_line.is_some() {
                                "exchange"
                            } else {
                                "delete"
                            },
                            line_no,
                            open_db.into(),
                        )
                        .into());
                    }
                } else {
                    Some(&cur_line[..])
                }
            } else {
                Some(&cur_line[..])
            };

            // Anything to output?
            if let Some(new_line) = new_line {
                tmp_file.write_all(new_line).map_err(|e| {
                    InputError::ProcessingString(format!(
                        "Failed to write line to temp file {:?} for CLOSE command: {}",
                        tmp_named_file.path(),
                        e
                    ))
                })?;
                tmp_file.write_all(b"\n").map_err(|e| {
                    InputError::ProcessingString(format!(
                        "Failed to write new line to temp file {:?} for CLOSE command: {}",
                        tmp_named_file.path(),
                        e
                    ))
                })?;
            }
        }

        // Make sure the source file is closed; Windows doth protest
        drop(src_reader);

        // Make sure that all delete and exchange lines were processed
        if let Some((_, edit)) = next_edit {
            return Err(
                ProcessingError::NotAllEditProcessed(if edit.new_line.is_some() {
                    "exchange"
                } else {
                    "delete"
                })
                .into(),
            );
        }

        // Clean up the context
        ctx.edits.clear();

        // Flush and close the temporary file.
        // On Windows, it must be closed before it can be renamed.
        let tmpfile_path = {
            let _ = tmp_file.into_inner().unwrap();
            let (_, path) = tmp_named_file.into_parts();
            path
        };

        // Replace the file in-place
        #[cfg(windows)]
        if let Err(e) = fs::remove_file(&open_db) {
            // Try to remove the tempfile, since we failed to remove the original
            fs::remove_file(&tmpfile_path).map_err(|e| {
                InputError::ProcessingString(format!(
                    "Failed to remove the temp file file {:?} for CLOSE command: {}",
                    tmpfile_path, e
                ))
            })?;
            return Err(InputError::ProcessingString(format!(
                "Failed to remove open db file {:?} for CLOSE command: {}",
                &open_db, e
            ))
            .into());
        }
        if let Err(e) = fs::rename(&tmpfile_path, &open_db) {
            fs::remove_file(&tmpfile_path).map_err(|e| {
                InputError::ProcessingString(format!(
                    "Failed to remove temp file {:?}: {} for CLOSE command",
                    &tmpfile_path, e
                ))
            })?;
            return Err(InputError::ProcessingString(format!(
                "Failed to rename temp file {:?} to {:?} for CLOSE command: {}",
                tmpfile_path, &open_db, e
            )));
        }
    }

    // Test for lines to add
    if !ctx.additions.is_empty() {
        let mut db_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&open_db)
            .map_err(|e| {
                InputError::ProcessingString(format!(
                    "Failed to open db file {:?} for CLOSE command: {}",
                    open_db, e
                ))
            })?;
        db_file.write_all(&ctx.additions).map_err(|e| {
            InputError::ProcessingString(format!(
                "Failed to write add lines to db {:?} for CLOSE command: {}",
                open_db, e
            ))
        })?;
        ctx.additions.clear();
    }

    debug!("cmd_close: finished");

    Ok(())
}

/// Set up Context structure with data parsed from command unlink
fn cmd_unlink(ctx: &mut Context, unlink_op: UnlinkOp) -> Result<(), InputError> {
    if let Some(open_db) = &ctx.open_db {
        return Err(InputError::DBStillOpen(open_db.clone()));
    }

    // We checked that the db_name doesn't have any '/' or '\\' in it before
    // adding to the UnlinkOp struct, so it's safe to say the path is just a local file and
    // won't accidentally delete something in a different directory.
    fs::remove_file(unlink_op.db_name).map_err(|e| {
        InputError::ProcessingString(format!(
            "Failed to remove db file {:?} for UNLINK command: {}",
            unlink_op.db_name, e
        ))
    })?;

    Ok(())
}

/// Handle a specific command line in a cdiff file, calling the appropriate handler function
fn process_line(ctx: &mut Context, line: &[u8]) -> Result<(), InputError> {
    let mut tokens = line.splitn(2, |b| *b == b' ' || *b == b'\n');
    let cmd = tokens.next().ok_or(InputError::MissingCommand)?;
    let remainder_with_nl = tokens.next();
    let remainder = remainder_with_nl.and_then(|s| s.strip_suffix(b"\n"));

    // Call the appropriate command function
    match cmd {
        b"OPEN" => cmd_open(ctx, remainder),
        b"ADD" => cmd_add(ctx, remainder_with_nl.unwrap()),
        b"DEL" => {
            let del_op = DelOp::new(remainder.unwrap())?;
            cmd_del(ctx, del_op)
        }
        b"XCHG" => {
            let xchg_op = XchgOp::new(remainder.unwrap())?;
            cmd_xchg(ctx, xchg_op)
        }
        b"MOVE" => {
            let move_op = MoveOp::new(remainder.unwrap())?;
            cmd_move(ctx, move_op)
        }
        b"CLOSE" => cmd_close(ctx),
        b"UNLINK" => {
            let unlink_op = UnlinkOp::new(remainder.unwrap())?;
            cmd_unlink(ctx, unlink_op)
        }
        _ => Err(InputError::UnknownCommand(
            String::from_utf8_lossy(cmd).to_string(),
        )),
    }
}

/// Main loop for iterating over cdiff command lines and handling them
fn process_lines<T>(
    ctx: &mut Context,
    reader: &mut T,
    uncompressed_size: usize,
) -> Result<(), Error>
where
    T: BufRead,
{
    let mut decompressed_bytes = 0;
    let mut linebuf = vec![];
    let mut line_no = 0;
    loop {
        line_no += 1;
        linebuf.clear();
        match reader.read_until(b'\n', &mut linebuf)? {
            0 => break,
            n_read => {
                decompressed_bytes = decompressed_bytes + n_read + 1;
                match linebuf.first() {
                    // Skip comment lines
                    Some(b'#') => continue,
                    _ => process_line(ctx, &linebuf).map_err(|e| Error::Input {
                        line: line_no,
                        err: e,
                        operation: String::from_utf8_lossy(&linebuf).to_string(),
                    })?,
                }
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
fn read_dsig(file: &mut File) -> Result<Vec<u8>, SignatureError> {
    // Verify file length
    if file.metadata()?.len() < SIG_SIZE as u64 {
        return Err(SignatureError::TooSmall);
    }

    // Seek to the dsig_offset
    file.seek(SeekFrom::End(-(SIG_SIZE as i64)))?;

    // Read from dsig_offset to EOF
    let mut dsig: Vec<u8> = vec![];
    file.read_to_end(&mut dsig)?;
    debug!("read_dsig: dsig length is {}", dsig.len());

    // Find the signature
    let offset: usize = SIG_SIZE + 1;

    // Read in reverse until the delimiter ':' is found
    if let Some(dsig) = dsig.rsplit(|v| *v == b':').next() {
        if dsig.len() > SIG_SIZE {
            Err(SignatureError::TooLarge)
        } else {
            Ok(dsig.to_vec())
        }
    } else {
        Ok(dsig[offset..].to_vec())
    }
}

// Returns the parsed, uncompressed file size from the header, as well
// as the offset in the file that the header ends.
fn read_size(file: &mut File) -> Result<(u32, usize), HeaderError> {
    // Seek to beginning of file.
    file.rewind()?;

    // File should always start with "ClamAV-Diff".
    let prefix = b"ClamAV-Diff";
    let mut buf = Vec::with_capacity(prefix.len());
    file.take(prefix.len() as u64).read_to_end(&mut buf)?;
    if buf.as_slice() != prefix.to_vec().as_slice() {
        return Err(HeaderError::BadMagic);
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
            let file_size_str =
                str::from_utf8(&file_size_vec).map_err(|e| HeaderError::InvalidSize(e.into()))?;
            return Ok((
                file_size_str
                    .parse::<u32>()
                    .map_err(|e| HeaderError::InvalidSize(e.into()))?,
                i + 1,
            ));
        }
    }

    Err(HeaderError::TooFewFields)
}

/// Calculate the sha2-256 of the first len bytes of a file
fn get_hash(file: &mut File, len: usize) -> Result<[u8; 32], Error> {
    let mut hasher = Sha256::new();

    // Seek to beginning of file
    file.rewind()?;

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
    use std::path::Path;

    /// CdiffTestError enumerates all possible errors returned by this testing library.
    #[derive(thiserror::Error, Debug)]
    pub enum CdiffTestError {
        /// Represents all other cases of `std::io::Error`.
        #[error(transparent)]
        IOError(#[from] std::io::Error),

        #[error(transparent)]
        FromUtf8Error(#[from] std::string::FromUtf8Error),
    }

    #[test]
    fn parse_move_works() {
        let move_op = MoveOp::new(b"a b 1 hello 2 world").expect("Should've worked!");

        println!("{:?}", move_op);

        assert_eq!(move_op.src, Path::new("a"));
        assert_eq!(move_op.dst, Path::new("b"));
        assert_eq!(move_op.start_line_no, 1);
        assert_eq!(move_op.start_line, b"hello");
        assert_eq!(move_op.end_line_no, 2);
        assert_eq!(move_op.end_line, b"world");
    }

    #[test]
    fn parse_move_fail_int() {
        assert!(matches!(
            MoveOp::new(b"a b NOTANUMBER hello 2 world"),
            Err(InputError::InvalidLineNo(InvalidNumber::Unparseable(_)))
        ));
    }

    #[test]
    fn parse_move_fail_eof() {
        assert!(matches!(
            MoveOp::new(b"a b 1"),
            Err(InputError::MissingParameter("MOVE", "start_line"))
        ));
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

        let del_op = DelOp::new(b"1 ClamAV-VDB:14").unwrap();
        cmd_del(&mut ctx, del_op).expect("cmd_del failed");
        match cmd_close(&mut ctx) {
            Ok(_) => (),
            Err(e) => panic!("cmd_close failed with: {}", e),
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

        let del_op = DelOp::new(b"2 AAAA").unwrap();
        cmd_del(&mut ctx, del_op).expect("cmd_del failed");
        match cmd_close(&mut ctx) {
            Ok(_) => (),
            Err(e) => panic!("cmd_close failed with: {}", e),
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

        let del_op = DelOp::new(b"4 CCCC").unwrap();
        cmd_del(&mut ctx, del_op).expect("cmd_del failed");
        match cmd_close(&mut ctx) {
            Ok(_) => (),
            Err(e) => panic!("cmd_close failed with: {}", e),
        }
        compare_file_with_expected(db_file_path, &mut expected_data);
    }

    #[test]
    fn delete_line_not_match() {
        let initial_data = vec!["ClamAV-VDB:14 Jul 2021 14-29 -0400", "AAAA", "BBBB", "CCCC"];

        let db_file_path = initialize_db_file_with_data(initial_data).unwrap();

        // Create contextual data structure with open_db path
        let mut ctx = construct_ctx_from_path(&db_file_path);

        let del_op = DelOp::new(b"1 CCCC").unwrap();
        cmd_del(&mut ctx, del_op).unwrap();
        assert!(matches!(
            cmd_close(&mut ctx),
            Err(InputError::Processing(
                ProcessingError::PatternDoesNotMatch(_, _, _)
            ))
        ));
    }

    #[test]
    fn delete_out_of_bounds() {
        let initial_data = vec!["ClamAV-VDB:14 Jul 2021 14-29 -0400", "AAAA", "BBBB", "CCCC"];

        let db_file_path = initialize_db_file_with_data(initial_data).unwrap();

        // Create contextual data structure with open_db path
        let mut ctx = construct_ctx_from_path(&db_file_path);

        let del_op = DelOp::new(b"5 CCCC").unwrap();
        cmd_del(&mut ctx, del_op).unwrap();
        assert!(matches!(
            cmd_close(&mut ctx),
            Err(InputError::Processing(
                ProcessingError::NotAllEditProcessed("delete")
            ))
        ));
    }

    #[test]
    fn exchange_first_line() {
        let initial_data = vec!["ClamAV-VDB:14 Jul 2021 14-29 -0400", "AAAA", "BBBB", "CCCC"];
        let mut expected_data = vec!["ClamAV-VDB:15 Aug 2021 14-29 -0400", "AAAA", "BBBB", "CCCC"];

        let db_file_path = initialize_db_file_with_data(initial_data).unwrap();

        // Create contextual data structure with open_db path
        let mut ctx = construct_ctx_from_path(&db_file_path);

        let xchg_op = XchgOp::new(b"1 ClamAV-VDB:14 ClamAV-VDB:15 Aug 2021 14-29 -0400").unwrap();
        cmd_xchg(&mut ctx, xchg_op).expect("cmd_xchg failed");
        match cmd_close(&mut ctx) {
            Ok(_) => (),
            Err(e) => panic!("cmd_close failed with: {}", e),
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

        let xchg_op = XchgOp::new(b"2 AAAA DDDD").unwrap();
        cmd_xchg(&mut ctx, xchg_op).expect("cmd_xchg failed");
        match cmd_close(&mut ctx) {
            Ok(_) => (),
            Err(e) => panic!("cmd_close failed with: {}", e),
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

        let xchg_op = XchgOp::new(b"4 CCCC DDDD").unwrap();
        cmd_xchg(&mut ctx, xchg_op).expect("cmd_xchg failed");
        match cmd_close(&mut ctx) {
            Ok(_) => (),
            Err(e) => panic!("cmd_close failed with: {}", e),
        }
        compare_file_with_expected(db_file_path, &mut expected_data);
    }

    #[test]
    fn exchange_out_of_bounds() {
        let initial_data = vec!["ClamAV-VDB:14 Jul 2021 14-29 -0400", "AAAA", "BBBB", "CCCC"];

        let db_file_path = initialize_db_file_with_data(initial_data).unwrap();

        // Create contextual data structure with open_db path
        let mut ctx = construct_ctx_from_path(&db_file_path);

        let xchg_op = XchgOp::new(b"5 DDDD EEEE").unwrap();
        cmd_xchg(&mut ctx, xchg_op).expect("cmd_xchg failed");
        assert!(matches!(
            cmd_close(&mut ctx),
            Err(InputError::Processing(
                ProcessingError::NotAllEditProcessed("exchange")
            ))
        ));
    }

    #[test]
    fn add_delete_exchange() {
        let initial_data = vec!["ClamAV-VDB:14 Jul 2021 14-29 -0400", "AAAA", "BBBB", "CCCC"];
        let mut expected_data = vec!["ClamAV-VDB:14 Jul 2021 14-29 -0400", "DDDD", "CCCC", "EEEE"];

        let db_file_path = initialize_db_file_with_data(initial_data).unwrap();

        // Create contextual data structure with open_db path
        let mut ctx = construct_ctx_from_path(&db_file_path);

        // Add a line
        cmd_add(&mut ctx, b"EEEE").unwrap();

        // Delete the 2nd line
        let del_op = DelOp::new(b"2 AAAA").unwrap();
        cmd_del(&mut ctx, del_op).expect("cmd_del failed");

        // Exchange the 3rd line
        let xchg_op = XchgOp::new(b"3 BBBB DDDD").unwrap();
        cmd_xchg(&mut ctx, xchg_op).expect("cmd_xchg failed");

        // Perform all operations and close the file
        match cmd_close(&mut ctx) {
            Ok(_) => (),
            Err(e) => panic!("cmd_close failed with: {}", e),
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
        let move_op = MoveOp::new(move_args.as_bytes()).unwrap();

        match cmd_move(&mut ctx, move_op) {
            Ok(_) => (),
            Err(e) => panic!("cmd_move failed with: {}", e),
        }

        compare_file_with_expected(src_file_path, &mut expected_src_data);
        compare_file_with_expected(dst_file_path, &mut expected_dst_data);
    }

    #[test]
    fn script2cdiff_missing_hyphen() {
        assert!(matches!(
            script2cdiff("", "", ""),
            Err(Error::FilenameMissingHyphen)
        ));
    }
}

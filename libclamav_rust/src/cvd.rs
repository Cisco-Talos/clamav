/*
 *  Copyright (C) 2024 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *
 *  Authors: Micah Snyder
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
    ffi::{CStr, CString},
    fs::File,
    io::{prelude::*, BufReader},
    mem::ManuallyDrop,
    os::raw::{c_char, c_void},
    path::{Path, PathBuf},
    str::FromStr,
    time::{Duration, SystemTime},
};

#[cfg(any(unix))]
use std::os::fd::AsRawFd;

#[cfg(any(windows))]
use std::os::windows::io::AsRawHandle;

use crate::codesign::Verifier;
use flate2::read::GzDecoder;
use hex;
use log::{debug, error, warn};
use tar::Archive;

use crate::{
    codesign, ffi_error, ffi_error_null, ffi_util::FFIError, sys, validate_str_param,
    validate_str_param_null,
};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Error parsing CVD file: {0}")]
    Parse(String),

    #[error("Error verifying signature: {0}")]
    InvalidDigitalSignature(String),

    #[error("Can't verify: {0}")]
    CannotVerify(String),

    #[error("Signature verification failed: signature is invalid")]
    VerifyFailed,

    #[error("Unpacking error: {0}")]
    UnpackFailed(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

pub struct CVD {
    pub name: String,
    pub time_creation: SystemTime,
    pub version: u32,
    pub num_sigs: u32,
    pub min_flevel: u32,
    pub rsa_dsig: Option<String>,
    pub md5: Option<String>,
    pub builder: String,
    pub file: File,
    pub path: PathBuf,
    pub is_compressed: bool,
}

impl CVD {
    pub fn from_file(file_path: &Path) -> Result<Self, Error> {
        let file = File::open(file_path)
            .map_err(|_| Error::Parse(format!("Failed to open file: {:?}", file_path)))?;
        let mut reader = BufReader::new(&file);

        // We need to extract the name from the filename.
        // CVD filenames are usually either:
        //   name.cvd
        // or:
        //   name-version.cvd
        // where version is a number.
        let database_file_stem = file_path.file_stem().ok_or_else(|| {
            Error::Parse("Failed to get database file stem from CVD file path".to_string())
        })?;
        let database_file_stem_str = database_file_stem
            .to_str()
            .ok_or_else(|| Error::Parse("Database file stem is not valid unicode".to_string()))?;
        let name = database_file_stem_str
            .split(['-', '.'])
            .next()
            .ok_or_else(|| {
                Error::Parse("Failed to get database name from database file stem".to_string())
            })?
            .to_string();

        // read the 512 byte header
        let mut header: [u8; 512] = [0; 512];
        reader
            .read_exact(&mut header)
            .map_err(|_| Error::Parse("File is smaller than 512-byte CVD header".to_string()))?;

        let mut maybe_copying: [u8; 7] = [0; 7];
        reader.read_exact(&mut maybe_copying).map_err(|_| {
            Error::Parse(
                "Can't read first 7 bytes of the tar file following the header.".to_string(),
            )
        })?;

        let is_compressed = if &maybe_copying == b"COPYING" {
            // Able to read the contents of the first file, which must be COPYING.
            // This means the CVD is not compressed.
            false
        } else {
            true
        };

        let mut fields = header.split(|&n| n == b':');

        let magic = fields
            .next()
            .ok_or_else(|| Error::Parse("Invalid CVD file".to_string()))?;
        if magic != b"ClamAV-VDB" {
            return Err(Error::Parse(
                "Invalid CVD file: First field does not match magic bytes for CVD file".to_string(),
            ));
        }

        let _ = fields.next().ok_or_else(|| {
            Error::Parse("Invalid CVD file: Missing creation time stamp".to_string())
        })?;
        // let time_str = std::str::from_utf8(time_bytes)
        //     .map_err(|_| Error::Parse("Time string is not valid unicode".to_string()))?;

        let version_bytes = fields
            .next()
            .ok_or_else(|| Error::Parse("Invalid CVD file: Missing version".to_string()))?;
        let version_str = std::str::from_utf8(version_bytes)
            .map_err(|_| Error::Parse("Version string is not valid unicode".to_string()))?;
        let version: u32 = version_str.parse().map_err(|_| {
            Error::Parse(format!(
                "Version string is not an unsigned integer: {}",
                version_str
            ))
        })?;

        let num_sigs_bytes = fields.next().ok_or_else(|| {
            Error::Parse("Invalid CVD file: Missing number of signatures".to_string())
        })?;
        let num_sigs_str = std::str::from_utf8(num_sigs_bytes)
            .map_err(|_| Error::Parse("Signature Count string is not valid unicode".to_string()))?;
        let num_sigs: u32 = num_sigs_str.parse().map_err(|_| {
            Error::Parse(format!(
                "Signature count is not an unsigned integer: {}",
                num_sigs_str
            ))
        })?;

        let min_flevel_bytes = fields.next().ok_or_else(|| {
            Error::Parse("Invalid CVD file: Missing minimum feature level".to_string())
        })?;
        let min_flevel_str = std::str::from_utf8(min_flevel_bytes).map_err(|_| {
            Error::Parse("Minimum Functionality Level string is not valid unicode".to_string())
        })?;
        let min_flevel: u32 = min_flevel_str.parse().map_err(|_| {
            Error::Parse(format!(
                "Minimum Functionality Level is not an unsigned integer: {}",
                min_flevel_str
            ))
        })?;

        let md5_bytes = fields.next().ok_or_else(|| {
            Error::Parse(
                "Invalid CVD file: Missing MD5 hash field for the compressed archive".to_string(),
            )
        })?;
        let md5_str = std::str::from_utf8(md5_bytes)
            .map_err(|_| Error::Parse("MD5 hash string is not valid unicode".to_string()))?;
        let md5: Option<String> = if md5_str.len() != 32 {
            debug!("MD5 hash string not present.");
            None
        } else {
            Some(md5_str.to_string())
        };

        let rsa_dsig_bytes = fields.next().ok_or_else(|| {
            Error::Parse("Invalid CVD file: Missing minimum feature level".to_string())
        })?;
        let rsa_dsig_str = std::str::from_utf8(rsa_dsig_bytes)
            .map_err(|_| {
                Error::Parse(
                    "MD5-based RSA digital signature string is not valid unicode".to_string(),
                )
            })?
            .to_string();

        // the rsa dsig field might be empty or like just 'x'
        let rsa_dsig = if rsa_dsig_str.len() > 1 {
            Some(rsa_dsig_str)
        } else {
            None
        };

        let builder_bytes = fields
            .next()
            .ok_or_else(|| Error::Parse("Invalid CVD file: Missing builder string".to_string()))?;
        let builder = std::str::from_utf8(builder_bytes)
            .map_err(|_| Error::Parse("Builder string is not valid unicode".to_string()))?
            .to_string();

        let time_bytes = fields
            .next()
            .ok_or_else(|| Error::Parse("Invalid CVD file: Missing creation time".to_string()))?;
        let time_str = std::str::from_utf8(time_bytes)
            .map_err(|_| Error::Parse("Time string is not valid unicode".to_string()))?;
        // trim any trailing whitespace, since this is the last field and the rest should be padding
        let time_str = time_str.trim_end();
        let time_seconds: u64 = time_str.parse().map_err(|_| {
            Error::Parse(format!(
                "Time string is not an unsigned integer: {}",
                time_str
            ))
        })?;
        let time_creation = SystemTime::UNIX_EPOCH + Duration::from_secs(time_seconds);

        Ok(Self {
            name,
            time_creation,
            version,
            num_sigs,
            min_flevel,
            rsa_dsig,
            md5,
            builder,
            file,
            path: file_path.to_path_buf(),
            is_compressed,
        })
    }

    pub fn unpack_to(&mut self, path: &Path) -> Result<(), Error> {
        debug!("Unpacking CVD file to {:?}", path);

        // skip the 512 byte header
        self.file
            .seek(std::io::SeekFrom::Start(512))
            .map_err(|_| Error::Parse("Failed to seek past CVD header".to_string()))?;

        let mut file_bytes = Vec::<u8>::new();
        let bytes_read = self
            .file
            .read_to_end(&mut file_bytes)
            .map_err(|_| Error::Parse("Failed to read CVD file".to_string()))?;

        debug!("Read {} bytes from CVD file", bytes_read);

        let mut archive: Archive<Box<dyn Read>> = if self.is_compressed {
            tar::Archive::new(Box::new(GzDecoder::new(file_bytes.as_slice())))
        } else {
            tar::Archive::new(Box::new(BufReader::new(file_bytes.as_slice())))
        };

        archive
            .entries()
            .map_err(|e| {
                Error::Parse(format!(
                    "Failed to enumerate files in signature archive: {}",
                    e
                ))
            })?
            // .filter_map(|e| e.ok())
            .for_each(|entry| {
                let mut entry = match entry {
                    Ok(entry) => entry,
                    Err(e) => {
                        error!("Failed to get entry in signature archive: {}", e);
                        return;
                    }
                };

                let file_path = match entry.path() {
                    Ok(file_path) => file_path,
                    Err(e) => {
                        error!("Failed to get path for file in signature archive: {}", e);
                        return;
                    }
                };

                let filename = match file_path.file_name() {
                    Some(filename) => filename,
                    None => {
                        error!(
                            "Failed to get filename for file in signature archive: {:?}",
                            file_path
                        );
                        return;
                    }
                };

                let destination_file_path = path.join(filename);

                debug!("Unpacking {:?} to: {:?}", filename, destination_file_path);

                if let Err(e) = entry.unpack(&destination_file_path) {
                    error!("Unpack failed: {}", e);
                }
            });

        Ok(())
    }

    pub fn verify_rsa_dsig(&mut self) -> Result<(), Error> {
        let mut file_bytes = Vec::<u8>::new();

        self.file
            .seek(std::io::SeekFrom::Start(512))
            .map_err(|_| Error::Parse("Failed to seek past CVD header".to_string()))?;

        let bytes_read = self
            .file
            .read_to_end(&mut file_bytes)
            .map_err(|_| Error::Parse("Failed to read CVD file".to_string()))?;

        debug!("Read {} bytes from CVD file", bytes_read);

        let digest = md5::compute(&file_bytes);
        let calculated_md5 = digest.as_slice();
        let calculated_md5 = hex::encode(calculated_md5);

        debug!("MD5 hash: {}", calculated_md5);

        if let Some(md5) = &self.md5 {
            if calculated_md5 != md5[..] {
                warn!("MD5 hash does not match the expected hash");
                return Err(Error::InvalidDigitalSignature(
                    "MD5 hash does not match the expected hash".to_string(),
                ));
            }
        } else {
            debug!("MD5 hash is not present in the CVD file");
        }

        if let Some(rsa_dsig) = &self.rsa_dsig {
            debug!("RSA digital signature: {:?}", rsa_dsig);

            // versig2 will expect dsig to be a null-terminated string
            let dsig_cstring = CString::new(rsa_dsig.as_bytes()).map_err(|_| {
                Error::Parse("Failed to convert RSA digital signature to CString".to_string())
            })?;

            // convert the calculated MD5 hash to a null-terminated string
            let calculated_md5_cstring = CString::new(calculated_md5).map_err(|_| {
                Error::Parse("Failed to convert calculated MD5 hash to CString".to_string())
            })?;

            // Verify cdiff
            let versig_result =
                unsafe { sys::cli_versig(calculated_md5_cstring.as_ptr(), dsig_cstring.as_ptr()) };

            debug!("verify_rsa_dsig: versig() result = {}", versig_result);
            if versig_result != 0 {
                warn!("RSA digital signature verification failed");
                return Err(Error::InvalidDigitalSignature(
                    "RSA digital signature verification failed".to_string(),
                ));
            }

            debug!("RSA digital signature verification succeeded");
        } else {
            warn!("RSA digital signature is not present in the CVD file");
            return Err(Error::InvalidDigitalSignature(
                "RSA digital signature is not present in the CVD file".to_string(),
            ));
        }

        Ok(())
    }

    pub fn verify_external_sign_file(&mut self, verifier: &Verifier) -> Result<String, Error> {
        let database_directory = self.path.parent().ok_or_else(|| {
            Error::Parse("Failed to get database directory from CVD file path".to_string())
        })?;

        // The signature file for a CVD should be "databasename-<version>.cvd.sign"
        // This is true regardless of whethe ror not the CVD filename has a version number in it.
        let database_file_stem = self.path.file_stem().ok_or_else(|| {
            Error::Parse("Failed to get database file stem from CVD file path".to_string())
        })?;
        let database_file_stem_str = database_file_stem
            .to_str()
            .ok_or_else(|| Error::Parse("Database file stem is not valid unicode".to_string()))?;
        let database_name = database_file_stem_str
            .split(['-', '.'])
            .next()
            .ok_or_else(|| {
                Error::Parse("Failed to get database name from database file stem".to_string())
            })?;

        let signature_file_name = format!("{}-{}.cvd.sign", database_name, self.version);
        let signature_file_path = database_directory.join(signature_file_name);

        match codesign::verify_signed_file(&self.path, &signature_file_path, verifier) {
            Ok(signer) => {
                debug!("Successfully verified {:?} signed by {}", self.path, signer);
                Ok(signer)
            }
            Err(codesign::Error::InvalidDigitalSignature(m)) => {
                warn!(
                    "Failed to verify {:?} with {:?}: Signature is invalid: {}",
                    self.path, signature_file_path, m
                );
                Err(Error::InvalidDigitalSignature(m))
            }
            Err(e) => {
                debug!(
                    "Failed to verify {:?} with {:?}: {}",
                    self.path, signature_file_path, e
                );
                Err(Error::CannotVerify(e.to_string()))
            }
        }
    }

    pub fn verify(
        &mut self,
        verifier: Option<&Verifier>,
        disable_legacy_dsig: bool,
    ) -> Result<String, Error> {
        // First try to verify the CVD with the detached signature file.
        // If that fails, fall back to verifying with the MD5-based attached RSA digital signature.
        if let Some(verifier) = verifier {
            match self.verify_external_sign_file(verifier) {
                Ok(signer) => {
                    debug!("CVD verified successfully with detached signature file");
                    return Ok(signer);
                }
                Err(Error::InvalidDigitalSignature(e)) => {
                    warn!("Detached CVD signature is invalid: {}", e);
                    return Err(Error::InvalidDigitalSignature(e));
                }
                Err(e) => {
                    debug!(
                        "Failed to verify {:?} with detached signature file: {}",
                        self.path, e
                    );

                    // If the error because of an invalid signature, fall back to verifying with the MD5-based attached RSA digital signature
                }
            }
        } else {
            debug!("No certs directory provided. Skipping external signature verification.");
        }

        if disable_legacy_dsig {
            warn!("Unable to verify CVD with detached signature file and MD5 verification is disabled");
            return Err(Error::CannotVerify("Unable to verify CVD with detached signature file and MD5 verification is disabled".to_string()));
        }

        // Fall back to verifying with the MD5-based attached RSA digital signature
        match self.verify_rsa_dsig() {
            Ok(()) => {
                debug!("CVD verified successfully with Legacy ClamAV RSA Public Key");
                Ok("Legacy ClamAV RSA Public Key".to_string())
            }
            Err(e) => {
                warn!(
                    "Failed to verify CVD with MD5-based RSA digital signature: {}",
                    e
                );
                Err(e)
            }
        }
    }
}

/// C interface for checking a CVD. This includes parsing the header, and (optionally) verifying the digital signature.
/// Handles all the unsafe ffi stuff.
///
/// # Safety
///
/// No parameters may be NULL
#[export_name = "cvd_check"]
pub unsafe extern "C" fn cvd_check(
    cvd_file_path_str: *const c_char,
    certs_directory_str: *const c_char,
    skip_sign_verify: bool,
    disable_legacy_dsig: bool,
    signer_name: *mut *mut c_char,
    err: *mut *mut FFIError,
) -> bool {
    let cvd_file_path_str = validate_str_param!(cvd_file_path_str);
    let cvd_file_path = match Path::new(cvd_file_path_str).canonicalize() {
        Ok(p) => p,
        Err(e) => {
            return ffi_error!(
                err = err,
                Error::CannotVerify(format!("Invalid CVD file path: {}", e))
            );
        }
    };

    let certs_directory_str = validate_str_param!(certs_directory_str);
    let certs_directory = match PathBuf::from_str(certs_directory_str) {
        Ok(p) => p,
        Err(e) => {
            return ffi_error!(
                err = err,
                Error::CannotVerify(format!("Invalid certs directory path: {}", e))
            );
        }
    };

    let verifier = match Verifier::new(&certs_directory) {
        Ok(v) => v,
        Err(e) => {
            return ffi_error!(err = err, e);
        }
    };

    match CVD::from_file(&cvd_file_path) {
        Ok(mut cvd) => {
            if skip_sign_verify {
                debug!("CVD parsed successfully, but we're skipping signature verification.");
                return true;
            }

            match cvd.verify(Some(&verifier), disable_legacy_dsig) {
                Ok(signer) => {
                    let signer_cstr = std::ffi::CString::new(signer).unwrap();
                    *signer_name = signer_cstr.into_raw();
                    true
                }
                Err(e) => {
                    ffi_error!(err = err, e)
                }
            }
        }
        Err(e) => {
            ffi_error!(
                err = err,
                Error::CannotVerify(format!("Failed to parse CVD: {}", e))
            )
        }
    }
}

/// C interface for unpacking a CVD. This includes parsing the header, verifying the digital signature, and unpacking the archive.
/// Handles all the unsafe ffi stuff.
///
/// # Safety
///
/// No parameters may be NULL
/// The CVD pointer must be valid
/// The destination path must be a valid path
#[export_name = "cvd_unpack"]
pub unsafe extern "C" fn cvd_unpack(
    cvd: *mut c_void,
    destination_path_str: *const c_char,
    err: *mut *mut FFIError,
) -> bool {
    let mut cvd = ManuallyDrop::new(Box::from_raw(cvd as *mut CVD));

    let destination_path_str = validate_str_param!(destination_path_str);
    let destination_path = match Path::new(destination_path_str).canonicalize() {
        Ok(p) => p,
        Err(e) => {
            return ffi_error!(
                err = err,
                Error::CannotVerify(format!("Invalid destination path: {}", e))
            );
        }
    };

    match cvd.unpack_to(&destination_path) {
        Ok(()) => {
            debug!("CVD unpacked successfully");
            true
        }
        Err(e) => {
            ffi_error!(err = err, e);
            false
        }
    }
}

/// C interface for opening a CVD file. This includes parsing the header.
/// Handles all the unsafe ffi stuff.
/// Returns a pointer to the CVD struct.
///
/// # Safety
///
/// No parameters may be NULL
/// The returned pointer must be freed with `cli_cvd_free`
#[export_name = "cvd_open"]
pub unsafe extern "C" fn cvd_open(
    cvd_file_path_str: *const c_char,
    err: *mut *mut FFIError,
) -> *mut c_void {
    let cvd_file_path_str = validate_str_param_null!(cvd_file_path_str);
    let cvd_file_path = match Path::new(cvd_file_path_str).canonicalize() {
        Ok(p) => p,
        Err(e) => {
            return ffi_error_null!(
                err = err,
                Error::CannotVerify(format!("Invalid CVD file path: {}", e))
            );
        }
    };

    match CVD::from_file(&cvd_file_path) {
        Ok(cvd) => Box::into_raw(Box::<CVD>::new(cvd)) as sys::cvd_t,
        Err(e) => {
            ffi_error_null!(
                err = err,
                Error::CannotVerify(format!("Failed to parse CVD: {}", e))
            )
        }
    }
}

/// C interface for verifying a CVD. This includes verifying the digital signature.
/// Handles all the unsafe ffi stuff.
///
/// If `certs_directory_str` is NULL, then only the MD5-based RSA digital signature will be verified.
///
/// # Safety
///
/// No parameters may be NULL except for `certs_directory_str`.
/// The CVD pointer must be valid
#[export_name = "cvd_verify"]
pub unsafe extern "C" fn cvd_verify(
    cvd: *const c_void,
    verifier_ptr: *const c_void,
    disable_legacy_dsig: bool,
    signer_name: *mut *mut c_char,
    err: *mut *mut FFIError,
) -> bool {
    let mut cvd = ManuallyDrop::new(Box::from_raw(cvd as *mut CVD));

    if verifier_ptr.is_null() {
        match cvd.verify(None, disable_legacy_dsig) {
            Ok(signer) => {
                let signer_cstr = std::ffi::CString::new(signer).unwrap();
                *signer_name = signer_cstr.into_raw();
                true
            }
            Err(e) => {
                ffi_error!(err = err, e)
            }
        }
    } else {
        let verifier = ManuallyDrop::new(Box::from_raw(verifier_ptr as *mut Verifier));

        match cvd.verify(Some(&verifier), disable_legacy_dsig) {
            Ok(signer) => {
                let signer_cstr = std::ffi::CString::new(signer).unwrap();
                *signer_name = signer_cstr.into_raw();
                true
            }
            Err(e) => {
                ffi_error!(err = err, e)
            }
        }
    }
}

/// C interface for freeing a CVD struct.
/// Handles all the unsafe ffi stuff.
/// Frees the CVD struct.
///
/// # Safety
///
/// The CVD pointer must be valid
/// The CVD pointer must not be used after calling this function
#[export_name = "cvd_free"]
pub unsafe extern "C" fn cvd_free(cvd: *mut c_void) {
    if cvd.is_null() {
        warn!("Attempted to free a NULL CVD pointer. Please report this at: https://github.com/Cisco-Talos/clamav/issues");
    } else {
        let _ = unsafe { Box::from_raw(cvd as *mut CVD) };
    }
}

/// C interface for getting the creation time of a CVD.
/// Handles all the unsafe ffi stuff.
/// Returns the creation time as a u64.
///
/// # Safety
///
/// No parameters may be NULL
/// The CVD pointer must be valid
#[export_name = "cvd_get_time_creation"]
pub unsafe extern "C" fn cvd_get_time_creation(cvd: *const c_void) -> u64 {
    let cvd = ManuallyDrop::new(Box::from_raw(cvd as *mut CVD));
    cvd.time_creation
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// C interface for getting the version of a CVD.
/// Handles all the unsafe ffi stuff.
/// Returns the version as a u32.
///
/// # Safety
///
/// No parameters may be NULL
/// The CVD pointer must be valid
#[export_name = "cvd_get_version"]
pub unsafe extern "C" fn cvd_get_version(cvd: *const c_void) -> u32 {
    let cvd = ManuallyDrop::new(Box::from_raw(cvd as *mut CVD));
    cvd.version
}

/// C interface for getting the name of a CVD.
/// Handles all the unsafe ffi stuff.
/// Returns the version as a C string (aka char *).
///
/// # Safety
///
/// No parameters may be NULL
/// The CVD pointer must be valid
/// The caller is responsible for freeing the C string. See `ffi_cstring_free`.
#[export_name = "cvd_get_name"]
pub unsafe extern "C" fn cvd_get_name(cvd: *const c_void) -> *mut c_char {
    let cvd = ManuallyDrop::new(Box::from_raw(cvd as *mut CVD));

    CString::new(cvd.name.clone()).unwrap().into_raw()
}

/// C interface for getting the number of signatures in a CVD.
/// Handles all the unsafe ffi stuff.
/// Returns the number of signatures as a u32.
///
/// # Safety
///
/// No parameters may be NULL
/// The CVD pointer must be valid
#[export_name = "cvd_get_num_sigs"]
pub unsafe extern "C" fn cvd_get_num_sigs(cvd: *const c_void) -> u32 {
    let cvd = ManuallyDrop::new(Box::from_raw(cvd as *mut CVD));
    cvd.num_sigs
}

/// C interface for getting the minimum feature level of a CVD.
/// Handles all the unsafe ffi stuff.
/// Returns the minimum feature level as a u32.
///
/// # Safety
///
/// No parameters may be NULL
/// The CVD pointer must be valid
#[export_name = "cvd_get_min_flevel"]
pub unsafe extern "C" fn cvd_get_min_flevel(cvd: *const c_void) -> u32 {
    let cvd = ManuallyDrop::new(Box::from_raw(cvd as *mut CVD));
    cvd.min_flevel
}

/// C interface for getting the CVD builder.
/// Handles all the unsafe ffi stuff.
/// Returns the builder as a CString.
/// The caller is responsible for freeing the CString. See `ffi_cstring_free`.
///
/// # Safety
///
/// No parameters may be NULL
/// The CVD pointer must be valid
#[export_name = "cvd_get_builder"]
pub unsafe extern "C" fn cvd_get_builder(cvd: *const c_void) -> *mut c_char {
    let cvd = ManuallyDrop::new(Box::from_raw(cvd as *mut CVD));
    CString::new(cvd.builder.clone()).unwrap().into_raw()
}

/// C interface for getting the file handle of a CVD.
/// Handles all the unsafe ffi stuff.
/// Returns the file handle an integer.
/// The caller must not close the file handle.
/// The file handle is not guaranteed to be valid after the CVD struct is freed.
///
/// # Safety
///
/// No parameters may be NULL
/// The CVD pointer must be valid
#[cfg(any(unix))]
#[export_name = "cvd_get_file_descriptor"]
pub unsafe extern "C" fn cvd_get_file_descriptor(cvd: *const c_void) -> i32 {
    let cvd = ManuallyDrop::new(Box::from_raw(cvd as *mut CVD));

    cvd.file.as_raw_fd()
}

/// C interface for getting the file handle of a CVD.
/// Handles all the unsafe ffi stuff.
/// Returns the file handle an integer.
/// The caller must not close the file handle.
/// The file handle is not guaranteed to be valid after the CVD struct is freed.
///
/// # Safety
///
/// No parameters may be NULL
/// The CVD pointer must be valid
#[cfg(any(windows))]
#[export_name = "cvd_get_file_handle"]
pub unsafe extern "C" fn cvd_get_file_handle(cvd: *const c_void) -> *mut c_void {
    let cvd = ManuallyDrop::new(Box::from_raw(cvd as *mut CVD));

    cvd.file.as_raw_handle()
}

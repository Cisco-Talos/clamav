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
    ffi::{c_void, CStr},
    fs::File,
    io::{prelude::*, BufReader},
    mem::ManuallyDrop,
    os::raw::c_char,
    path::{Path, PathBuf},
};

use openssl::{
    pkcs7::{Pkcs7, Pkcs7Flags},
    pkey::{PKey, Private},
    stack::{self, Stack},
    x509::{
        store::{X509Store, X509StoreBuilder},
        X509,
    },
};

use clam_sigutil::{
    sigbytes::{AppendSigBytes, SigBytes},
    signature::{digital_sig::DigitalSig, parse_from_cvd_with_meta},
    SigType, Signature,
};

use log::{debug, error, warn};

use crate::{ffi_error, ffi_util::FFIError, sys::cl_retflevel, validate_str_param};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Can't verify: {0}")]
    CannotVerify(String),

    #[error("Can't sign: {0}")]
    SignFailed(String),

    #[error("Signature verification failed")]
    VerifyFailed,

    #[error("File is not signed")]
    NotSigned,

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Cert Store: {0}")]
    CertificateStore(String),

    #[error("OpenSSL error: {0}")]
    OpenSSLError(#[from] openssl::error::ErrorStack),

    #[error("Error converting digital signature to .sign file line: {0}")]
    SigBytesError(#[from] clam_sigutil::signature::ToSigBytesError),

    #[error("Error verifying signature: {0}")]
    InvalidDigitalSignature(String),

    #[error(
        "Incorrect public key, does not match any serial number in the signature's signers chain"
    )]
    IncorrectPublicKey,
}

/// C interface for verify_signed_file() which verifies a file's external digital signature.
/// Handles all the unsafe ffi stuff.
///
/// # Safety
///
/// No parameters may be NULL.
#[export_name = "codesign_sign_file"]
pub unsafe extern "C" fn codesign_sign_file(
    target_file_path_str: *const c_char,
    signature_file_path_str: *const c_char,
    signing_key_path_str: *const c_char,
    cert_paths_str: *const *const c_char,
    cert_paths_len: usize,
    append: bool,
    err: *mut *mut FFIError,
) -> bool {
    let target_file_path_str = validate_str_param!(target_file_path_str);
    let target_file_path = match Path::new(target_file_path_str).canonicalize() {
        Ok(p) => p,
        Err(e) => {
            return ffi_error!(
                err = err,
                Error::SignFailed(format!(
                    "Invalid target file path '{}': {}",
                    target_file_path_str, e
                ))
            );
        }
    };

    let signature_file_path_str = validate_str_param!(signature_file_path_str);
    let signature_file_path = Path::new(signature_file_path_str);

    let cert_path_strs: &[*const c_char] =
        std::slice::from_raw_parts(cert_paths_str, cert_paths_len);

    // now convert the cert_path_strs to a Vec<&Path>
    let mut cert_paths: Vec<PathBuf> = Vec::with_capacity(cert_paths_len);

    for &path_str in cert_path_strs {
        if path_str.is_null() {
            return ffi_error!(
                err = err,
                Error::SignFailed("Intermediate certificate path is NULL".to_string())
            );
        }

        #[allow(unused_unsafe)]
        let path_str = CStr::from_ptr(path_str)
            .to_str()
            .map_err(|e| {
                warn!("Intermediate path string is not valid unicode: {e}");
                ffi_error!(
                    err = err,
                    Error::SignFailed("Intermediate certificate path is NULL".to_string())
                )
            })
            .unwrap();

        match Path::new(path_str).canonicalize() {
            Ok(path) => cert_paths.push(path),
            Err(e) => {
                warn!("Invalid intermediate certificate path: '{path_str}' {e}",);
                return ffi_error!(
                    err = err,
                    Error::SignFailed(format!(
                        "Invalid intermediate certificate path: '{path_str}': {e}",
                    ))
                );
            }
        }
    }

    let signing_key_path_str = validate_str_param!(signing_key_path_str);
    let signing_key_path = match Path::new(signing_key_path_str).canonicalize() {
        Ok(p) => p,
        Err(e) => {
            return ffi_error!(
                err = err,
                Error::SignFailed(format!(
                    "Invalid signing key path '{signing_key_path_str}': {e}",
                ))
            );
        }
    };

    match sign_file(
        &target_file_path,
        signature_file_path,
        &cert_paths,
        &signing_key_path,
        append,
    ) {
        Ok(()) => {
            debug!("File signed successfully");
            true
        }
        Err(e) => {
            ffi_error!(err = err, e)
        }
    }
}

/// Signs a file.
/// The signature is appended to the signature file.
pub fn sign_file<P>(
    target_file_path: &Path,
    signature_file_path: &Path,
    cert_paths: &[P],
    signing_key_path: &Path,
    append: bool,
) -> Result<(), Error>
where
    P: AsRef<Path>,
{
    let signer = Signer::new(signing_key_path, cert_paths)?;

    let data = std::fs::read(target_file_path)?;
    let pkcs7 = signer.sign(&data)?;

    // Now convert the pkcs7 to a DigitalSig struct which may be converted to a .sign file signature line.
    let signature = DigitalSig::Pkcs7(pkcs7);
    let mut sig_bytes: SigBytes = SigBytes::new();
    signature.append_sigbytes(&mut sig_bytes)?;

    let mut writer = {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true);

        let need_header = if signature_file_path.exists() {
            if append {
                options.append(true);
                false
            } else {
                options.truncate(true);
                true
            }
        } else {
            true
        };

        let mut writer = std::io::BufWriter::new(options.open(signature_file_path)?);

        // TODO: When introducing next clamsign-version, may need to re-write the header if
        // adding a signature to an existing file where the clamsign-version is older.
        // Or potentially fail out if the new format is not backwards compatible.

        if need_header {
            writer.write_all(b"#clamsign-1.0\n")?;
        } else {
            writer.write_all(b"\n")?;
        }

        writer
    };

    writer.write_all(sig_bytes.as_bytes())?;

    // Write a newline after the signature
    writer.write_all(b"\n")?;

    Ok(())
}

/// C interface for verify_signed_file() which verifies a file's external digital signature.
/// Handles all the unsafe ffi stuff.
///
/// The signer_name output parameter is a pointer to a pointer to a C string.
/// The caller is responsible for freeing the CString. See `ffi_cstring_free`.
///
/// # Safety
///
/// No parameters may be NULL.
#[export_name = "codesign_verify_file"]
pub unsafe extern "C" fn codesign_verify_file(
    signed_file_path_str: *const c_char,
    signature_file_path_str: *const c_char,
    verifier_ptr: *const c_void,
    signer_name: *mut *mut c_char,
    err: *mut *mut FFIError,
) -> bool {
    let signed_file_path_str = validate_str_param!(signed_file_path_str);
    let signed_file_path = match Path::new(signed_file_path_str).canonicalize() {
        Ok(p) => p,
        Err(e) => {
            return ffi_error!(
                err = err,
                Error::CannotVerify(format!(
                    "Invalid signed file path '{}': {}",
                    signed_file_path_str, e
                ))
            );
        }
    };

    let signature_file_path_str = validate_str_param!(signature_file_path_str);
    let signature_file_path = match Path::new(signature_file_path_str).canonicalize() {
        Ok(p) => p,
        Err(e) => {
            return ffi_error!(
                err = err,
                Error::CannotVerify(format!(
                    "Invalid signature file path '{}': {}",
                    signature_file_path_str, e
                ))
            );
        }
    };

    let verifier = ManuallyDrop::new(Box::from_raw(verifier_ptr as *mut Verifier));

    // verify that signer_name is not NULL
    if signer_name.is_null() {
        // invalid parameter
        return ffi_error!(
            err = err,
            Error::CannotVerify("signer_name output parameter is NULL".to_string())
        );
    }

    match verify_signed_file(&signed_file_path, &signature_file_path, &verifier) {
        Ok(signer) => {
            debug!("CVD verified successfully");
            // convert the signer_name to a CString and store it in the output parameter
            let signer_cstr = std::ffi::CString::new(signer).unwrap();
            *signer_name = signer_cstr.into_raw();
            true
        }
        Err(e) => {
            ffi_error!(err = err, e)
        }
    }
}

/// C interface for creating a new Verifier.
/// Handles all the unsafe ffi stuff.
/// The verifier output parameter is a pointer to a pointer to a Verifier.
///
/// # Safety
///
/// No parameters may be NULL.
#[export_name = "codesign_verifier_new"]
pub unsafe extern "C" fn codesign_verifier_new(
    certs_directory_str: *const c_char,
    verifier: *mut *mut c_void,
    err: *mut *mut FFIError,
) -> bool {
    let certs_directory_str = validate_str_param!(certs_directory_str, err = err);
    let certs_directory = match Path::new(certs_directory_str).canonicalize() {
        Ok(p) => p,
        Err(e) => {
            return ffi_error!(
                err = err,
                Error::CannotVerify(format!(
                    "Invalid certs directory '{}': {}",
                    certs_directory_str, e
                ))
            );
        }
    };

    // verify that verifier is not NULL
    if verifier.is_null() {
        // invalid parameter
        return ffi_error!(
            err = err,
            Error::CannotVerify("verifier output parameter is NULL".to_string())
        );
    }

    let new_verifier = Verifier::new(&certs_directory);
    match new_verifier {
        Ok(new_verifier) => {
            debug!("Verifier created successfully");
            *verifier = Box::into_raw(Box::new(new_verifier)) as *mut c_void;
            true
        }
        Err(e) => {
            ffi_error!(err = err, e)
        }
    }
}

/// C interface for freeing a Verifier.
/// Handles all the unsafe ffi stuff.
///
/// # Safety
///
/// No parameters may be NULL.
#[export_name = "codesign_verifier_free"]
pub unsafe extern "C" fn codesign_verifier_free(verifier: *mut c_void) {
    if verifier.is_null() {
    } else {
        let _ = unsafe { Box::from_raw(verifier as *mut Verifier) };
    }
}

/// Verifies a signed file.
/// The signature file is expected to be in the ClamAV '.sign' format.
/// The certificates directory is expected to contain the public keys of the signers.
/// Returns the name of the signer.
pub fn verify_signed_file(
    signed_file_path: &Path,
    signature_file_path: &Path,
    verifier: &Verifier,
) -> Result<String, Error> {
    let signature_file: File = File::open(signature_file_path)?;

    let mut signed_file: File = File::open(signed_file_path)?;

    let mut file_data = Vec::<u8>::new();
    let read_result = signed_file.read_to_end(&mut file_data);
    if let Err(e) = read_result {
        return Err(Error::CannotVerify(format!(
            "Error reading file '{:?}': {}",
            signed_file_path, e
        )));
    }

    let reader = BufReader::new(signature_file);

    for (index, line) in reader.lines().enumerate() {
        // First line should be "#clamsign-MAJOR.MINOR"
        if index == 0 {
            let line = line?;
            if !line.starts_with("#clamsign") {
                return Err(Error::CannotVerify(
                    "Unsupported signature file format, expected first line start with '#clamsign-1.0'".to_string(),
                ));
            }

            // Check clamsign version
            let version = line.split('-').nth(1).unwrap();
            if version != "1.0" {
                return Err(Error::CannotVerify(
                    "Unsupported signature file version, expected '1.0'".to_string(),
                ));
            }

            continue;
        }

        // Skip empty lines
        let line = line?;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        // Skip lines starting with '#'
        if line.starts_with('#') {
            continue;
        }

        // Convert line to bytes, which is preferred by our signature parser.
        let data = line.as_bytes();

        match parse_from_cvd_with_meta(SigType::DigitalSignature, &data.into()) {
            Ok((sig, meta)) => {
                let sig = sig.downcast::<DigitalSig>().unwrap();

                sig.validate(&meta).map_err(|e| {
                    Error::CannotVerify(format!(
                        "{:?}:{}: Invalid signature: {}",
                        signature_file_path, index, e
                    ))
                })?;

                // verify the flevel bounds of this signature compared with the current flevel
                let current_flevel = unsafe { cl_retflevel() };
                let sig_flevel_range = meta.f_level.unwrap();
                if !sig_flevel_range.contains(&current_flevel) {
                    debug!(
                        "{:?}:{}: Signature feature level range {:?} does not include current feature level {}",
                        signature_file_path, index, sig_flevel_range, current_flevel
                    );
                    continue;
                }

                match *sig {
                    DigitalSig::Pkcs7(pkcs7) => {
                        match verifier.verify(&file_data, &pkcs7) {
                            Ok(signer) => {
                                return Ok(signer);
                            }
                            Err(Error::InvalidDigitalSignature(m)) => {
                                warn!(
                                    "Invalid digital signature for {:?}: {}",
                                    signed_file_path, m
                                );
                                return Err(Error::InvalidDigitalSignature(m));
                            }
                            Err(e) => {
                                debug!(
                                    "Error verifying signature with the certs found in {:?}: {:?}",
                                    verifier.certs_directory, e
                                );

                                // Try the next certificate
                            }
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!(
                    "{:?}:{}: Error parsing signature: {}",
                    signature_file_path, index, e
                );
                return Err(Error::CannotVerify(e.to_string()));
            }
        };
    }

    Err(Error::CannotVerify(
        "Unable to verify any digital signatures".to_string(),
    ))
}

pub struct Signer {
    cert: X509,
    certs: Stack<X509>,
    key: PKey<Private>,
}

impl Signer {
    pub fn new<P>(key_path: &Path, cert_paths: &[P]) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        let mut signing_cert: Option<X509> = None;

        // take the first cert from the vec of certs to use as the signing cert
        let mut cert_stack: Stack<X509> = Stack::new()?;

        for cert_path in cert_paths {
            let cert_bytes = std::fs::read(cert_path)?;
            let certs = X509::stack_from_pem(&cert_bytes)?;

            for cert in certs {
                if signing_cert.is_none() {
                    debug!("Signing cert: {:?}", cert);
                    signing_cert = Some(cert.clone());
                } else {
                    debug!("Trust chain cert: {:?}", cert);
                    cert_stack.push(cert.clone())?;
                }
            }
        }

        let signing_cert = if let Some(cert) = signing_cert {
            cert
        } else {
            return Err(Error::SignFailed(
                "No signing certificate found in the provided certificate file".to_string(),
            ));
        };

        let signing_key_bytes = std::fs::read(key_path)?;
        let key = PKey::private_key_from_pem(&signing_key_bytes)?;
        debug!("Signing key: {:?}", key);

        Ok(Signer {
            cert: signing_cert,
            certs: cert_stack,
            key,
        })
    }

    pub fn sign(&self, data: &[u8]) -> Result<Pkcs7, Error> {
        let flags = Pkcs7Flags::DETACHED | Pkcs7Flags::BINARY;

        Pkcs7::sign(&self.cert, &self.key, &self.certs, data, flags).map_err(Error::OpenSSLError)
    }
}

pub struct Verifier {
    store: X509Store,
    certs_directory: PathBuf,
}

impl Verifier {
    pub fn new(certs_directory: &Path) -> Result<Self, Error> {
        // create store with root CA
        let mut store_builder = X509StoreBuilder::new()?;

        let mut root_common_names = Vec::<String>::new();

        for file in std::fs::read_dir(certs_directory)? {
            let file = file?;
            let path = file.path();
            if path.is_file() {
                let ext = path.extension();
                if ext.is_some() && (ext.unwrap() == "pem" || ext.unwrap() == "crt") {
                    let certs_in_file = X509::stack_from_pem(&std::fs::read(path)?)?;
                    for cert in certs_in_file {
                        // get cert common name
                        let common_name = cert
                            .subject_name()
                            .entries()
                            .find(|name_entry| {
                                name_entry.object().nid() == openssl::nid::Nid::COMMONNAME
                            })
                            .map(|name_entry| name_entry.data().as_utf8().unwrap().to_string())
                            .unwrap();

                        if root_common_names.contains(&common_name) {
                            return Err(Error::CertificateStore(format!(
                                "More than one certificate with the same common name '{}' found in the certs directory. Ref: https://github.com/openssl/openssl/issues/16304", common_name)));
                        }
                        root_common_names.push(common_name.clone());

                        debug!("Adding certificate to verifier store: {:?}", cert);
                        store_builder.add_cert(cert.clone())?;
                    }
                }
            }
        }

        let store = store_builder.build();
        Ok(Verifier {
            store,
            certs_directory: certs_directory.to_path_buf(),
        })
    }

    pub fn verify(&self, data: &[u8], pkcs7: &Pkcs7) -> Result<String, Error> {
        if let Some(_signed) = pkcs7.signed() {
            // verify signature
            let certs = stack::Stack::new()?;
            let flags = Pkcs7Flags::DETACHED | Pkcs7Flags::BINARY | Pkcs7Flags::NOCRL;
            let mut output = Vec::new();

            let result = pkcs7.verify(&certs, &self.store, Some(data), Some(&mut output), flags);

            // get the signer's common name
            let signer = pkcs7.signers(&certs, flags)?;
            let signers: Vec<String> = signer
                .iter()
                .map(|cert| {
                    cert.subject_name()
                        .entries()
                        .find(|name_entry| {
                            name_entry.object().nid() == openssl::nid::Nid::COMMONNAME
                        })
                        .map(|name_entry| name_entry.data().as_utf8().unwrap().to_string())
                        .unwrap()
                })
                .collect();

            match result {
                Ok(()) => {
                    debug!("Successfully verified signature signed by: {:?}", signers);

                    Ok(signers.join(", "))
                }
                Err(e) => {
                    // TODO: add more error handling here in case we have the wrong CA.

                    eprintln!("Error verifying signature signed by {:?}: {}", signers, e);
                    Err(Error::InvalidDigitalSignature(e.to_string()))
                }
            }
        } else {
            Err(Error::NotSigned)
        }
    }
}

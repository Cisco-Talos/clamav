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
    ffi::CStr,
    fs::File,
    io::{prelude::*, BufReader},
    os::raw::c_char,
    path::{Path, PathBuf},
};

use openssl::{
    pkcs7::{Pkcs7, Pkcs7Flags},
    pkey::{PKey, Private},
    stack,
    stack::Stack,
    x509::{store::X509StoreBuilder, X509},
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

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

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
    signing_cert_path_str: *const c_char,
    intermediate_cert_paths_str: *const *const c_char,
    intermediate_cert_paths_len: usize,
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

    let signing_cert_path_str = validate_str_param!(signing_cert_path_str);
    let signing_cert_path = match Path::new(signing_cert_path_str).canonicalize() {
        Ok(p) => p,
        Err(e) => {
            return ffi_error!(
                err = err,
                Error::SignFailed(format!(
                    "Invalid signing certificate path '{}': {}",
                    signing_cert_path_str, e
                ))
            );
        }
    };

    let intermediate_cert_path_strs: &[*const i8] =
        std::slice::from_raw_parts(intermediate_cert_paths_str, intermediate_cert_paths_len);
    // now convert the intermediate_cert_path_strs to a Vec<&Path>
    let intermediate_cert_paths: Vec<PathBuf> = intermediate_cert_path_strs
        .iter()
        .filter_map(|&path_str| -> Option<PathBuf> {
            let path_str = if path_str.is_null() {
                warn!("Intermiediate path string is NULL");
                return None;
            } else {
                #[allow(unused_unsafe)]
                match unsafe { CStr::from_ptr(path_str) }.to_str() {
                    Err(e) => {
                        warn!("Intermediate path string is not valid unicode: {}", e);
                        return None;
                    }
                    Ok(s) => Some(s),
                }
            };

            if let Some(path_str) = path_str {
                match Path::new(path_str).canonicalize() {
                    Ok(path) => Some(path),
                    Err(e) => {
                        warn!(
                            "Invalid intermediate certificate path: '{}' {}",
                            path_str, e
                        );
                        None
                    }
                }
            } else {
                None
            }
        })
        .collect();

    let signing_key_path_str = validate_str_param!(signing_key_path_str);
    let signing_key_path = match Path::new(signing_key_path_str).canonicalize() {
        Ok(p) => p,
        Err(e) => {
            return ffi_error!(
                err = err,
                Error::SignFailed(format!(
                    "Invalid signing key path '{}': {}",
                    signing_key_path_str, e
                ))
            );
        }
    };

    match sign_file(
        &target_file_path,
        signature_file_path,
        &signing_cert_path,
        &intermediate_cert_paths,
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
    signing_cert_path: &Path,
    intermediate_cert_paths: &[P],
    signing_key_path: &Path,
    append: bool,
) -> Result<(), Error>
where
    P: AsRef<Path>,
{
    let signer = Signer::new(signing_key_path, signing_cert_path, intermediate_cert_paths)?;

    let data = std::fs::read(target_file_path)?;
    let pkcs7 = signer.sign(&data)?;

    // Now convert the pkcs7 to a DigitalSig struct which may be converted to a .sign file signature line.
    let signature = DigitalSig::Pkcs7(pkcs7);
    let mut sig_bytes: SigBytes = SigBytes::new();
    signature.append_sigbytes(&mut sig_bytes)?;

    let mut writer = {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true);

        if signature_file_path.exists() {
            if append {
                options.append(true);
            } else {
                options.truncate(true);
            }
        }

        let mut writer = std::io::BufWriter::new(options.open(signature_file_path)?);

        if !signature_file_path.exists() || !append {
            writer.write_all(b"#clamsign-1.0\n")?;
        } else if append {
            writer.seek(std::io::SeekFrom::End(0))?;
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
    certs_directory_str: *const c_char,
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

    let certs_directory_str = validate_str_param!(certs_directory_str);
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

    // verify that signer_name is not NULL
    if signer_name.is_null() {
        // invalid parameter
        return ffi_error!(
            err = err,
            Error::CannotVerify("signer_name output parameter is NULL".to_string())
        );
    }

    match verify_signed_file(&signed_file_path, &signature_file_path, &certs_directory) {
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

/// Verifies a signed file.
/// The signature file is expected to be in the ClamAV '.sign' format.
/// The certificates directory is expected to contain the public keys of the signers.
/// Returns the name of the signer.
pub fn verify_signed_file(
    signed_file_path: &Path,
    signature_file_path: &Path,
    certs_directory: &Path,
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
                        // Try to verify with each certificate in the certs directory.
                        for cert in certs_directory.read_dir()? {
                            let cert = cert?;
                            let cert_path = cert.path();

                            debug!("Verifying with certificate: {:?}", cert_path);

                            let verifier = Verifier::new(&cert_path)?;
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
                                        "Error verifying signature with {:?}: {:?}",
                                        cert_path, e
                                    );

                                    // Try the next certificate
                                }
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
    pub fn new<P>(
        key_path: &Path,
        cert_path: &Path,
        intermediate_cert_paths: &[P],
    ) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        let mut certs: Stack<X509> = Stack::new()?;

        let cert_bytes = std::fs::read(cert_path)?;
        let cert = X509::from_pem(&cert_bytes)?;
        debug!("Signing certificate: {:?}", cert);
        certs.push(cert.clone())?;

        let signing_key_bytes = std::fs::read(key_path)?;
        let key = PKey::private_key_from_pem(&signing_key_bytes)?;
        debug!("Signing key: {:?}", key);

        for intermediate_cert_path in intermediate_cert_paths {
            let intermediate_cert_bytes = std::fs::read(intermediate_cert_path)?;
            let intermediate_cert = X509::from_pem(&intermediate_cert_bytes)?;
            debug!("Intermediate certificate: {:?}", &intermediate_cert);
            certs.push(intermediate_cert)?;
        }

        Ok(Signer { cert, certs, key })
    }

    pub fn sign(&self, data: &[u8]) -> Result<Pkcs7, Error> {
        let flags = Pkcs7Flags::DETACHED | Pkcs7Flags::BINARY;

        Pkcs7::sign(&self.cert, &self.key, &self.certs, data, flags).map_err(Error::OpenSSLError)
    }
}

pub struct Verifier {
    root_ca: X509,
}

impl Verifier {
    pub fn new(root_ca_path: &Path) -> Result<Self, Error> {
        let root_ca_bytes = std::fs::read(root_ca_path)?;
        let root_ca: X509 = X509::from_pem(&root_ca_bytes)?;

        debug!("Root CA: {:?}", root_ca);

        Ok(Verifier { root_ca })
    }

    pub fn verify(&self, data: &[u8], pkcs7: &Pkcs7) -> Result<String, Error> {
        if let Some(signed) = pkcs7.signed() {
            if let Some(cert_stack) = signed.certificates() {
                let root_ca_serial = self.root_ca.serial_number().to_bn()?;
                debug!("Checking if the root CA's serial matches any in the signature's certificate stack...");
                let mut top_level_signer: Option<String> = None;

                // Check each cert in the pkcs7 cert stack to see if it matches the root CA.
                // If we can't find a matching serial number, then we can't verify the pkcs7 signature.
                // That doesn't mean the signature is invalid, only that we don't have the required public key to verify it.
                for cert in cert_stack {
                    let serial = cert.serial_number().to_bn()?;
                    if top_level_signer.is_none() {
                        let signer = cert
                            .subject_name()
                            .entries()
                            .find(|name_entry| {
                                name_entry.object().nid() == openssl::nid::Nid::COMMONNAME
                            })
                            .ok_or(Error::InvalidDigitalSignature(
                                "Certificate in the signature's cert stack does not have a Common Name entry".to_string(),
                            ))?
                            .data()
                            .as_utf8()?
                            .to_string();
                        debug!("Top level signer serial: {}", signer);
                        top_level_signer = Some(signer);
                    }

                    if root_ca_serial == serial {
                        // found a matching serial number in the pkcs7 cert stack matching the provided root CA.
                        // We can verify the signature.
                        debug!("Certificate serial is a match: {:?}. We should be able to use this root CA to verify this signature.", serial.to_dec_str()?);

                        // create store with root CA
                        let mut store_builder = X509StoreBuilder::new()?;
                        store_builder.add_cert(self.root_ca.clone())?;
                        let store = store_builder.build();

                        // verify signature
                        let certs = stack::Stack::new()?;
                        let flags = Pkcs7Flags::DETACHED | Pkcs7Flags::BINARY;
                        let mut output = Vec::new();

                        let result =
                            pkcs7.verify(&certs, &store, Some(data), Some(&mut output), flags);

                        match result {
                            Ok(()) => {
                                debug!("Signature verified");
                                return Ok(top_level_signer.unwrap());
                            }
                            Err(e) => {
                                eprintln!("Error verifying signature: {}", e);
                                return Err(Error::InvalidDigitalSignature(e.to_string()));
                            }
                        }
                    } else {
                        debug!(
                            "Certificate serial does not match: {:?}",
                            serial.to_dec_str()?
                        );
                    }
                }
            }
        }

        debug!("The serial for this public key does not match any serial number in the signature's certificate chain.");
        Err(Error::IncorrectPublicKey)
    }
}

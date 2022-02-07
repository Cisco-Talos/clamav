/*
 *  Fuzzy hash implementations, matching, and signature support
 *
 *  Copyright (C) 2022 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
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

use image::imageops::FilterType::Lanczos3;
use rustdct::DctPlanner;
use std::collections::HashMap;
use std::convert::{TryFrom, TryInto};
use std::ffi::CStr;
use std::mem::ManuallyDrop;
use std::os::raw::c_char;
use std::slice;

use log::{debug, error, warn};
use thiserror::Error;

use crate::{sys, validate_str_param};

/// CdiffError enumerates all possible errors returned by this library.
#[derive(Error, Debug)]
pub enum FuzzyHashError {
    #[error("Invalid format")]
    Format,

    #[error("Unknown algorithm: {0}")]
    UnknownAlgorithm(String),

    #[error("Failed to convert hamming distance to unsigned 32bit integer: {0}")]
    FormatHammingDistance(String),

    #[error("Invalid hamming distance: {0}")]
    InvalidHammingDistance(u32),

    #[error("Invalid hash: {0}")]
    FormatHashBytes(String),

    #[error("Failed to load image: {0}")]
    ImageLoad(image::ImageError),
}

#[derive(PartialEq, Eq, Hash, Debug)]
pub struct ImageFuzzyHash {
    bytes: [u8; 8],
}

#[derive(PartialEq, Eq, Hash, Debug)]
pub enum FuzzyHash {
    Image(ImageFuzzyHash),
}

impl TryFrom<&str> for ImageFuzzyHash {
    type Error = &'static str;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if value.len() != 16 {
            return Err("Image fuzzy hash must be 16 characters in length");
        }

        let mut hashbytes = [0; 8];
        if hex::decode_to_slice(value, &mut hashbytes).is_ok() {
            Ok(ImageFuzzyHash { bytes: hashbytes })
        } else {
            Err("Failed to decode image fuzzy hash bytes from hex to bytes")
        }
    }
}

impl std::fmt::Display for FuzzyHash {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            FuzzyHash::Image(hash_bytes) => {
                write!(f, "{}", hex::encode(hash_bytes.bytes))
            }
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub struct FuzzyHashMeta {
    lsigid: u32,
    subsigid: u32,
    #[cfg(feature = "not_ready")]
    hamming_distance: u32,
}

/// Initialize the hashmap
#[no_mangle]
pub extern "C" fn fuzzy_hash_init_hashmap() -> sys::hashmap_ptr_t {
    let hashmap: HashMap<FuzzyHash, Vec<FuzzyHashMeta>> = HashMap::new();
    let hashmap = Box::new(hashmap);
    Box::into_raw(hashmap) as sys::hashmap_ptr_t
}

/// Free the hashmap
#[no_mangle]
pub extern "C" fn fuzzy_hash_free_hashmap(fuzzy_hashmap: sys::hashmap_ptr_t) {
    if fuzzy_hashmap.is_null() {
        warn!("Attempted to free a NULL hashmap pointer. Please report this at: https://github.com/Cisco-Talos/clamav/issues");
    } else {
        let _ =
            unsafe { Box::from_raw(fuzzy_hashmap as *mut HashMap<FuzzyHash, Vec<FuzzyHashMeta>>) };
    }
}

/// C interface for fuzzy_hash_check().
/// Handles all the unsafe ffi stuff.
#[export_name = "fuzzy_hash_check"]
pub extern "C" fn _fuzzy_hash_check(
    fuzzy_hashmap: sys::hashmap_ptr_t,
    mdata: *mut sys::cli_ac_data,
    image_fuzzy_hash: sys::image_fuzzy_hash_t,
) -> bool {
    let hash_bytes = image_fuzzy_hash.hash;

    let hashmap = unsafe {
        ManuallyDrop::new(Box::from_raw(
            fuzzy_hashmap as *mut HashMap<FuzzyHash, Vec<FuzzyHashMeta>>,
        ))
    };

    debug!(
        "Checking image fuzzy hash '{}' for signature match",
        hex::encode(hash_bytes)
    );

    if let Some(meta_vec) = fuzzy_hash_check(&hashmap, hash_bytes) {
        for meta in meta_vec {
            unsafe {
                sys::lsig_increment_subsig_match(mdata, meta.lsigid, meta.subsigid);
            }
        }
    }

    true
}

/// Check for fuzzy hash matches.
///
/// In this initial version, we're just doing a simple hash lookup and the
/// hamming distance is not considered.
///
/// TODO: In a future version, replace this with an implementation that can find
/// any hashes within the signature meta.hamming_distance.
pub fn fuzzy_hash_check(
    hashmap: &HashMap<FuzzyHash, Vec<FuzzyHashMeta>>,
    hash: [u8; 8],
) -> Option<&Vec<FuzzyHashMeta>> {
    let hash = FuzzyHash::Image(ImageFuzzyHash { bytes: hash });
    hashmap.get(&hash)
}

/// C interface for fuzzy_hash_load_subsignature().
/// Handles all the unsafe ffi stuff.
#[export_name = "fuzzy_hash_load_subsignature"]
pub extern "C" fn _fuzzy_hash_load_subsignature(
    fuzzy_hashmap: sys::hashmap_ptr_t,
    hexsig: *const c_char,
    lsig_id: u32,
    subsig_id: u32,
) -> sys::cl_error_t {
    let hexsig = validate_str_param!(hexsig);

    let mut hashmap = unsafe {
        ManuallyDrop::new(Box::from_raw(
            fuzzy_hashmap as *mut HashMap<FuzzyHash, Vec<FuzzyHashMeta>>,
        ))
    };

    let result: sys::cl_error_t =
        match fuzzy_hash_load_subsignature(&mut hashmap, hexsig, lsig_id, subsig_id) {
            Ok(_) => sys::cl_error_t_CL_SUCCESS,
            Err(error) => {
                error!(
                    "Error when loading fuzzy hash logical subsignature '{}': {}",
                    hexsig, error
                );

                error!("Expected format: algorithm#hash[#hammingdistance]");
                error!("  where");
                error!("   - algorithm:       Must be 'fuzzy_img'");
                error!("   - hash:            Must be an 8-byte hex string");
                error!("   - hammingdistance: (optional) Must be an unsigned integer");

                sys::cl_error_t_CL_EFORMAT
            }
        };

    result
}

/// Load a fuzzy hash subsignature
/// Parse a fuzzy hash logical sig subsignature.
/// Add the fuzzy hash to the matcher so it can be matched.
pub fn fuzzy_hash_load_subsignature(
    hashmap: &mut Box<HashMap<FuzzyHash, Vec<FuzzyHashMeta>>>,
    hexsig: &str,
    lsig_id: u32,
    subsig_id: u32,
) -> Result<(), FuzzyHashError> {
    let mut hexsig_split = hexsig.split('#');

    let algorithm = match hexsig_split.next() {
        Some(x) => x,
        None => return Err(FuzzyHashError::Format),
    };

    let hash = match hexsig_split.next() {
        Some(x) => x,
        None => return Err(FuzzyHashError::Format),
    };

    let distance: u32 = match hexsig_split.next() {
        Some(x) => match x.parse::<u32>() {
            Ok(n) => n,
            Err(_) => {
                return Err(FuzzyHashError::FormatHammingDistance(x.to_string()));
            }
        },
        None => 0,
    };

    // TODO: Support non-zero distance
    if distance != 0 {
        error!(
            "Non-zero hamming distances for image fuzzy hashes are not supported in this version."
        );
        return Err(FuzzyHashError::InvalidHammingDistance(distance));
    }

    match algorithm {
        "fuzzy_img" => {
            // Convert the hash string to an image fuzzy hash bytes struct
            let image_fuzzy_hash = hash
                .try_into()
                .map_err(|e| FuzzyHashError::FormatHashBytes(format!("{}: {}", e, hash)))?;

            let fuzzy_hash = FuzzyHash::Image(image_fuzzy_hash);

            let meta: FuzzyHashMeta = FuzzyHashMeta {
                lsigid: lsig_id,
                subsigid: subsig_id,
                #[cfg(feature = "not_ready")]
                hamming_distance: distance,
            };

            // If the hash key does not exist in the hashmap, insert an empty vec.
            // Then add the current meta struct to the entry.
            hashmap
                .entry(fuzzy_hash)
                .or_insert_with(Vec::new)
                .push(meta);

            Ok(())
        }
        _ => {
            error!("Unknown fuzzy hash algorithm: {}", algorithm);
            Err(FuzzyHashError::UnknownAlgorithm(algorithm.to_string()))
        }
    }
}

/// C interface for fuzzy_hash_calculate_image().
/// Handles all the unsafe ffi stuff.
#[export_name = "fuzzy_hash_calculate_image"]
pub extern "C" fn _fuzzy_hash_calculate_image(
    file_bytes: *const u8,
    file_size: usize,
    hash_out: *mut u8,
    hash_out_len: usize,
) -> bool {
    if file_bytes.is_null() {
        error!("invalid NULL pointer for image input buffer");
        return false;
    }
    if hash_out.is_null() {
        error!("invalid NULL pointer for hash output buffer");
        return false;
    }

    let buffer: &[u8] = unsafe { slice::from_raw_parts(file_bytes, file_size) };

    let hash_result = fuzzy_hash_calculate_image(buffer);
    let hash_bytes = match hash_result {
        Ok(hash) => hash,
        Err(err) => {
            error!("Failed to calculate image fuzzy hash: {}", err);
            return false;
        }
    };

    if hash_out_len < hash_bytes.len() {
        error!("output buffer is too small to hold the hash.");
        return false;
    }
    unsafe {
        hash_out.copy_from(hash_bytes.as_ptr(), hash_bytes.len());
    }

    true
}

/// Given a buffer and size, generate an image fuzzy hash
/// param: hash_out is an output variable
/// param: hash_out_len indicates the size of the hash_out buffer
pub fn fuzzy_hash_calculate_image(buffer: &[u8]) -> Result<Vec<u8>, FuzzyHashError> {
    let image = image::load_from_memory(buffer).map_err(|e| FuzzyHashError::ImageLoad(e.into()))?;

    // convert image to grayscale, then resize
    let image_gs = image.grayscale();

    let imgbuff_tmp = image::DynamicImage::resize_exact(&image_gs, 32, 32, Lanczos3).to_bytes();
    let mut imgbuff: Vec<f32> = imgbuff_tmp.into_iter().map(|x| x as f32).collect();

    // perform discrete cosine transform (dct2) on image
    DctPlanner::new().plan_dct2(1024).process_dct2(&mut imgbuff);

    // construct a low frequency dct vector using the topmost 8x8 terms
    let mut dct_low_freq: Vec<f32> = Vec::new();

    for i in 0..8 {
        let idx = i * 32;
        dct_low_freq.extend_from_slice(&imgbuff[idx..idx + 8]);
    }

    // take the low frequency averages, excluding the first term
    let sum: f32 = dct_low_freq.iter().sum();
    let sum = sum - dct_low_freq[0];
    let mean = sum / (dct_low_freq.len() - 1) as f32;

    // construct hash vector by reducing DCT values to 1 or 0 by comparing terms vs mean
    let hashvec: Vec<u64> = dct_low_freq
        .into_iter()
        .map(|x| if x > mean { 1 } else { 0 })
        .collect();

    // construct hash integer from bits
    let hash: u64 = hashvec.iter().fold(0, |res, &bit| (res << 1) ^ bit);

    debug!("Image hash: {:?}", hex::encode(hash_bytes));

    Ok(hash_bytes.to_vec())
}

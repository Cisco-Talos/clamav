/*
 *  Fuzzy hash implementations, matching, and signature support
 *
 *  Copyright (C) 2022-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *
 *  Authors: Micah Snyder, Mickey Sola, Scott Hutton
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
    collections::HashMap,
    convert::{TryFrom, TryInto},
    ffi::CStr,
    mem::ManuallyDrop,
    os::raw::c_char,
    panic, slice,
};

use image::{imageops::FilterType::Lanczos3, DynamicImage, ImageBuffer, Luma, Pixel, Rgb};
use log::{debug, error, warn};
use num_traits::{NumCast, ToPrimitive, Zero};
use rustdct::DctPlanner;
use transpose::transpose;

use crate::{ffi_error, ffi_util::FFIError, rrf_call, sys, validate_str_param};

/// Error enumerates all possible errors returned by this library.
#[derive(thiserror::Error, Debug)]
pub enum Error {
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

    #[error("Failed to load image due to bug in image decoder")]
    ImageLoadPanic(),

    #[error("Invalid parameter: {0}")]
    InvalidParameter(String),

    #[error("{0} parameter is NULL")]
    NullParam(&'static str),

    #[error("{0} hash must be {1} characters in length")]
    InvalidHashLength(&'static str, usize),
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
    type Error = Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if value.len() != 16 {
            return Err(Error::InvalidHashLength("ImageFuzzyHash", 16));
        }

        let mut hashbytes = [0; 8];
        if hex::decode_to_slice(value, &mut hashbytes).is_ok() {
            Ok(ImageFuzzyHash { bytes: hashbytes })
        } else {
            Err(Error::FormatHashBytes(value.to_string()))
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

#[derive(Debug, Default)]
pub struct FuzzyHashMap {
    hashmap: HashMap<FuzzyHash, Vec<FuzzyHashMeta>>,
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
pub extern "C" fn fuzzy_hashmap_new() -> sys::fuzzyhashmap_t {
    Box::into_raw(Box::<FuzzyHashMap>::default()) as sys::fuzzyhashmap_t
}

/// Free the hashmap
#[no_mangle]
pub extern "C" fn fuzzy_hash_free_hashmap(fuzzy_hashmap: sys::fuzzyhashmap_t) {
    if fuzzy_hashmap.is_null() {
        warn!("Attempted to free a NULL hashmap pointer. Please report this at: https://github.com/Cisco-Talos/clamav/issues");
    } else {
        let _ = unsafe { Box::from_raw(fuzzy_hashmap as *mut FuzzyHashMap) };
    }
}

/// C interface for FuzzyHashMap::check().
/// Handles all the unsafe ffi stuff.
///
/// # Safety
///
/// No parameters may be NULL
#[export_name = "fuzzy_hash_check"]
pub unsafe extern "C" fn _fuzzy_hash_check(
    fuzzy_hashmap: sys::fuzzyhashmap_t,
    mdata: *mut sys::cli_ac_data,
    image_fuzzy_hash: sys::image_fuzzy_hash_t,
) -> bool {
    let hash_bytes = image_fuzzy_hash.hash;

    let hashmap = ManuallyDrop::new(Box::from_raw(fuzzy_hashmap as *mut FuzzyHashMap));

    debug!(
        "Checking image fuzzy hash '{}' for signature match",
        hex::encode(hash_bytes)
    );

    if let Some(meta_vec) = hashmap.check(hash_bytes) {
        for meta in meta_vec {
            sys::lsig_increment_subsig_match(mdata, meta.lsigid, meta.subsigid);
        }
    }

    true
}

/// C interface for FuzzyHashMap::load_subsignature().
/// Handles all the unsafe ffi stuff.
///
/// # Safety
///
/// `hexsig` and `err` must not be NULL
#[export_name = "fuzzy_hash_load_subsignature"]
pub unsafe extern "C" fn _fuzzy_hash_load_subsignature(
    fuzzy_hashmap: sys::fuzzyhashmap_t,
    hexsig: *const c_char,
    lsig_id: u32,
    subsig_id: u32,
    err: *mut *mut FFIError,
) -> bool {
    let hexsig = validate_str_param!(hexsig, err = err);

    let mut hashmap = ManuallyDrop::new(Box::from_raw(fuzzy_hashmap as *mut FuzzyHashMap));

    rrf_call!(
        err = err,
        hashmap.load_subsignature(hexsig, lsig_id, subsig_id)
    )
}

/// C interface for fuzzy_hash_calculate_image().
/// Handles all the unsafe ffi stuff.
///
/// # Safety
///
/// `file_bytes` and `hash_out` must not be NULL
#[export_name = "fuzzy_hash_calculate_image"]
pub unsafe extern "C" fn _fuzzy_hash_calculate_image(
    file_bytes: *const u8,
    file_size: usize,
    hash_out: *mut u8,
    hash_out_len: usize,
    err: *mut *mut FFIError,
) -> bool {
    if hash_out.is_null() {
        return ffi_error!(err = err, Error::NullParam("hash_out"));
    }

    let buffer = if file_bytes.is_null() {
        return ffi_error!(err = err, Error::NullParam("file_bytes"));
    } else {
        slice::from_raw_parts(file_bytes, file_size)
    };

    let hash_result = fuzzy_hash_calculate_image(buffer);
    let hash_bytes = match hash_result {
        Ok(hash) => hash,
        Err(error) => return ffi_error!(err = err, error),
    };

    if hash_out_len < hash_bytes.len() {
        return ffi_error!(
            err = err,
            Error::InvalidParameter(format!(
                "hash_bytes output parameter too small to hold the hash: {} < {}",
                hash_out_len,
                hash_bytes.len()
            ))
        );
    }

    hash_out.copy_from(hash_bytes.as_ptr(), hash_bytes.len());

    true
}

impl FuzzyHashMap {
    /// Check for fuzzy hash matches.
    ///
    /// In this initial version, we're just doing a simple hash lookup and the
    /// hamming distance is not considered.
    ///
    /// TODO: In a future version, replace this with an implementation that can find
    /// any hashes within the signature meta.hamming_distance.
    pub fn check(&self, hash: [u8; 8]) -> Option<&Vec<FuzzyHashMeta>> {
        let hash = FuzzyHash::Image(ImageFuzzyHash { bytes: hash });
        self.hashmap.get(&hash)
    }

    /// Load a fuzzy hash subsignature
    /// Parse a fuzzy hash logical sig subsignature.
    /// Add the fuzzy hash to the matcher so it can be matched.
    pub fn load_subsignature(
        &mut self,
        hexsig: &str,
        lsig_id: u32,
        subsig_id: u32,
    ) -> Result<(), Error> {
        let mut hexsig_split = hexsig.split('#');

        let algorithm = match hexsig_split.next() {
            Some(x) => x,
            None => return Err(Error::Format),
        };

        let hash = match hexsig_split.next() {
            Some(x) => x,
            None => return Err(Error::Format),
        };

        let distance: u32 = match hexsig_split.next() {
            Some(x) => match x.parse::<u32>() {
                Ok(n) => n,
                Err(_) => {
                    return Err(Error::FormatHammingDistance(x.to_string()));
                }
            },
            None => 0,
        };

        // TODO: Support non-zero distance
        if distance != 0 {
            error!(
            "Non-zero hamming distances for image fuzzy hashes are not supported in this version."
        );
            return Err(Error::InvalidHammingDistance(distance));
        }

        match algorithm {
            "fuzzy_img" => {
                // Convert the hash string to an image fuzzy hash bytes struct
                let image_fuzzy_hash = hash
                    .try_into()
                    .map_err(|e| Error::FormatHashBytes(format!("{}: {}", e, hash)))?;

                let fuzzy_hash = FuzzyHash::Image(image_fuzzy_hash);

                let meta: FuzzyHashMeta = FuzzyHashMeta {
                    lsigid: lsig_id,
                    subsigid: subsig_id,
                    #[cfg(feature = "not_ready")]
                    hamming_distance: distance,
                };

                // If the hash key does not exist in the hashmap, insert an empty vec.
                // Then add the current meta struct to the entry.
                self.hashmap.entry(fuzzy_hash).or_default().push(meta);

                Ok(())
            }
            _ => {
                error!("Unknown fuzzy hash algorithm: {}", algorithm);
                Err(Error::UnknownAlgorithm(algorithm.to_string()))
            }
        }
    }
}

/// Given a buffer and size, generate an image fuzzy hash
///
/// This algorithm attempts to reproduce the results of the `phash()` function
/// from the Python `imagehash` package.
///
/// # Notes
///
/// 1) I found that `image.grayscale() uses different RGB coefficients than
/// the python `image.convert("L"). The docs for PIL.Image.convert() state:
///
///     When translating a color image to greyscale (mode "L"),
///     the library uses the ITU-R 601-2 luma transform::
///
///         L = R * 299/1000 + G * 587/1000 + B * 114/1000
///
/// You can get near-identical** grayscale results by making a clone (or forking)
/// the image-rs crate, and changing the coefficients to match those above:
///
///     diff --git a/src/color.rs b/src/color.rs
///     index 78b5c587..92c99337 100644
///     --- a/src/color.rs
///     +++ b/src/color.rs
///     @@ -462,7 +462,7 @@ where
///      }
///
///      /// Coefficients to transform from sRGB to a CIE Y (luminance) value.
///     -const SRGB_LUMA: [f32; 3] = [0.2126, 0.7152, 0.0722];
///     +const SRGB_LUMA: [f32; 3] = [0.299, 0.587, 0.114];
///
///      #[inline]
///      fn rgb_to_luma<T: Primitive>(rgb: &[T]) -> T {
///
/// **Note that I say "near-identical" because rounding
/// appears to be slightly different and values are sometimes off-by-one.
///
/// This change doesn't appear to be required to match the phash_simple()
/// function, but to match the phash() function where the median is used instead
/// of the mean -- this change is required.
///
/// 2) scipy.fftpack.dct behaves differently on twodimensional arrays than
///    single-dimensional arrays.
///    See https://docs.scipy.org/doc/scipy/reference/generated/scipy.fftpack.dct.html:
///
///     Note the optional "axis" argument:
///         Axis along which the dct is computed; the default is over the last axis
///         (i.e., axis=-1).
///
/// For the Python `imagehash` package:
/// - The `phash_simple()` function is doing a DCT-2 transform on a 2-dimensional
///   32x32 array which means, just on the 2nd axis (just the rows).
/// - The `phash()` function is doing a 2D DCT-2 transform, by running the DCT-2 on
///   both X and Y axis, which is the same as transposing before or after each
///   DCT-2 call.
///
/// 3) I observed that the DCT2 results from Python are consistently 2x greater
///    than those from Rust. If I multiply every value by 2 after running the DCT,
///    then the results are the same.
///
/// 4) We need to get a subset of the 2-D array representing the lower
///    frequencies of the image, the same way the Python implementation does it.
///
/// The way the python implementation does this is with this line:
/// ```python
/// dctlowfreq = dct[:hash_size, :hash_size]
/// ```
///
/// You can't actually do that with a Python array of arrays... this is numpy
/// 2-D array manipulation magic, where you can index 2-D arrays in slices.
/// It works like this:
/// ```ipython3
/// In [0]: x = [[0, 1, 2, 3, 4], [4, 5, 6, 7, 8], [8, 9, 10, 11, 12], [12, 13, 14, 15, 16], [16, 17, 18, 19, 20]]
/// In [1]: h = 3
/// In [2]: n = np.asarray(x)
/// In [3]: lf = n[:h, 1:h+1]
/// In [4]: n
/// array([[ 0,  1,  2,  3,  4],
///        [ 4,  5,  6,  7,  8],
///        [ 8,  9, 10, 11, 12],
///        [12, 13, 14, 15, 16],
///        [16, 17, 18, 19, 20]])
///
/// In [5]: lf
/// array([[ 0,  1,  2],
///        [ 4,  5,  6],
///        [ 8,  9, 10]])
/// ```
///
/// We can do something similar, manually, to get the low-frequency selection.
///
/// param: hash_out is an output variable
/// param: hash_out_len indicates the size of the hash_out buffer
pub fn fuzzy_hash_calculate_image(buffer: &[u8]) -> Result<Vec<u8>, Error> {
    // Load image and attempt to catch panics in case the decoders encounter unexpected issues
    let result = panic::catch_unwind(|| -> Result<DynamicImage, Error> {
        let image = image::load_from_memory(buffer).map_err(Error::ImageLoad)?;
        Ok(image)
    });

    let og_image = match result {
        Ok(image) => image?,
        Err(_) => return Err(Error::ImageLoadPanic()),
    };

    // Drop the alpha channel (if exists).
    let buff_rgb8 = og_image.to_rgb8();

    // Convert image to grayscale.
    let buff_luma8 = grayscale(&buff_rgb8);

    // Convert back to a DynamicImage type so we can resize it.
    let image_gs = DynamicImage::ImageLuma8(buff_luma8);

    // Shrink to a 32x32 (1024 pixel) image.
    let image_small = image::DynamicImage::resize_exact(&image_gs, 32, 32, Lanczos3);

    // Convert the data to a Vec of floats.
    let mut imgbuff_f32 = image_small.to_luma32f().into_raw();

    //
    // Compute a 2D DCT-2 in-place.
    //
    let dct2 = DctPlanner::new().plan_dct2(32);

    // Use a scratch space so we can transpose and run DCT's without allocating any extra space.
    // We'll switch back and forth between the buffer for the original small image (buffer1) and the scratch buffer (buffer2).
    let buffer1: &mut [f32] = imgbuff_f32.as_mut_slice();
    let buffer2: &mut [f32] = &mut [0.0; 1024];

    // Transpose the image so we can run DCT on the X axis (columns) first.
    transpose(buffer1, buffer2, 32, 32);

    // Run DCT2 on the columns.
    for (row_in, row_out) in buffer2.chunks_mut(32).zip(buffer1.chunks_mut(32)) {
        dct2.process_dct2_with_scratch(row_in, row_out);
    }
    // Multiply each value x2, to match results from scipy.fftpack.dct() implementation.
    // Note: Unsure why this is required, but it is.
    buffer2.iter_mut().for_each(|f| *f *= 2.0);

    // Transpose the image back so we can run DCT on the Y axis (rows).
    transpose(buffer2, buffer1, 32, 32);

    // Run DCT2 on the rows.
    for (row_in, row_out) in buffer1.chunks_mut(32).zip(buffer2.chunks_mut(32)) {
        dct2.process_dct2_with_scratch(row_in, row_out);
    }
    // Multiply each value x2, to match results from scipy.fftpack.dct() implementation.
    // Note: Unsure why this is required, but it is.
    buffer1.iter_mut().for_each(|f| *f *= 2.0);

    //
    // Construct a DCT low frequency vector using the top-left most 8x8 values of the 32x32 DCT array.
    //
    let dct_low_freq = buffer1
        // 2D array is 32-elements wide.
        .chunks(32)
        // Grab the first 8 rows.
        .take(8)
        // But only take the first 8 elements (columns) from each row.
        .flat_map(|chunk| chunk.chunks(8).take(1))
        // Flatten the 8x8 selection down to a vector of floats.
        .flatten()
        .copied()
        .collect::<Vec<f32>>();

    // Calculate average (median) of the DCT low frequency vector.
    let mut dct_low_freq_copy = dct_low_freq.clone();
    dct_low_freq_copy.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let median: f32 = (dct_low_freq_copy[31] + dct_low_freq_copy[32]) / 2.0;

    // Construct hash vector by reducing DCT values to 1 or 0 by comparing terms vs median.
    let hashvec: Vec<u64> = dct_low_freq
        .into_iter()
        .map(|x| if x > median { 1 } else { 0 })
        .collect();

    // Construct hash vec<u8> from bits.
    let hash_bytes: Vec<u8> = hashvec
        .chunks(8)
        .map(|chunk| {
            let chunk = chunk.to_owned();
            chunk
                .iter()
                .rev()
                .enumerate()
                .fold(None, |accum, (n, val)| {
                    accum.or(Some(0)).map(|accum| accum | ((*val as u8) << n))
                })
        })
        .take_while(|x| x.is_some())
        .flatten()
        .collect();

    debug!("Image hash: {}", hex::encode(&hash_bytes));

    Ok(hash_bytes)
}

/// Use these instead:
///         L = R * 299/1000 + G * 587/1000 + B * 114/1000
const SRGB_LUMA: [f32; 3] = [299.0 / 1000.0, 587.0 / 1000.0, 114.0 / 1000.0];

#[inline]
fn rgb_to_luma(rgb: &[u8]) -> u8 {
    let l = SRGB_LUMA[0] * rgb[0].to_f32().unwrap()
        + SRGB_LUMA[1] * rgb[1].to_f32().unwrap()
        + SRGB_LUMA[2] * rgb[2].to_f32().unwrap();
    NumCast::from(l.round()).unwrap()
}

/// Convert the supplied image to grayscale. Alpha channel is discarded.
///
/// This is a customized implementation of the grayscale feature from the `image` crate.
/// This allows us to:
/// - use RGB->LUMA constants that match those used by the Python Pillow package.
/// - round the luma floating point value to the nearest integer rather than truncating.
///
/// See also: https://github.com/image-rs/image/issues/1554
fn grayscale(image: &ImageBuffer<Rgb<u8>, Vec<u8>>) -> ImageBuffer<Luma<u8>, Vec<u8>> {
    let (width, height) = image.dimensions();
    let mut out = ImageBuffer::new(width, height);

    for y in 0..height {
        for x in 0..width {
            let pixel = image.get_pixel(x, y);

            let mut pix = Luma([Zero::zero()]);
            let gray = pix.channels_mut();
            let rgb = pixel.channels();
            gray[0] = rgb_to_luma(rgb);

            let pixel = Luma::from_slice(gray); //.into_color(); // no-op for luma->luma

            out.put_pixel(x, y, *pixel);
        }
    }

    out
}

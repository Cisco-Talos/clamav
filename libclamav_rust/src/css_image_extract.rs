/*
 *  Extract images from CSS stylesheets.
 *
 *  Copyright (C) 2023 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
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

use std::{ffi::CStr, mem::ManuallyDrop, os::raw::c_char};

use log::{debug, error, warn};
use thiserror::Error;

use crate::sys;

/// CdiffError enumerates all possible errors returned by this library.
#[derive(Error, Debug)]
pub enum CssExtractError {
    #[error("Invalid format")]
    Format,

    #[error("Invalid parameter: {0}")]
    InvalidParameter(String),

    #[error("{0} parmeter is NULL")]
    NullParam(&'static str),

    #[error("Failed to decode base64: {0}")]
    Base64Decode(String),
}

///
/// Extract images from HTML style CSS blocks
///
/// Process the CSS contents of an HTML <style> </style> block to find url() function
/// parameters that actually contain base64'd image contents directly and not a URL.
///
pub struct CssImageExtractor<'a> {
    remaining: &'a str,
}

impl<'a> CssImageExtractor<'a> {
    pub fn new(css: &'a str) -> Result<Self, CssExtractError> {
        Ok(Self { remaining: css })
    }

    fn next_base64_image(&mut self) -> Option<&str> {
        'outer: loop {
            // Find occurence of "url" with
            if let Some(pos) = self.remaining.find("url") {
                (_, self.remaining) = self.remaining.split_at(pos + "url".len());
                 // Found 'url'.
            } else {
                // No occurence of "url"
                 // No more 'url's.
                self.remaining = "";
                return None;
            };

            // Skip whitespace until we find '('
            for (pos, c) in self.remaining.chars().enumerate() {
                if c == '(' {
                     // Found left-paren.
                    (_, self.remaining) = self.remaining.split_at(pos + 1);
                    break;
                } else if char::is_whitespace(c) {
                     // Skipping whitespace.
                    continue;
                } else {
                     // Missing left-paren after 'url'.
                    continue 'outer;
                }
            }

            // Find closing ')'
            let mut depth = 1;
            let mut url_parameter: Option<&str> = None;
            for (pos, c) in self.remaining.chars().enumerate() {
                if c == '(' {
                    // Found nested left-paren.
                    depth += 1;
                } else if c == ')' {
                    if depth > 1 {
                        // Found nested right-paren.
                        depth -= 1;
                    } else {
                        // Found right-paren.
                        let (contents, remaining) = self.remaining.split_at(pos);
                        url_parameter = Some(contents);

                        // Set the remaining bytes so we can look for more later.
                        self.remaining = remaining;
                        break;
                    }
                }
            }

            let mut url_parameter = if let Some(c) = url_parameter {
                c
            } else {
                // Never found a closing paren.  We're done here.
                self.remaining = "";
                return None;
            };

            // Strip optional whitespace and quotes from front and back.

            // Trim off whitespace at beginning
            for (pos, c) in url_parameter.chars().enumerate() {
                if char::is_whitespace(c) {
                    // Skipping whitespace before url contents.
                    continue;
                } else {
                    (_, url_parameter) = url_parameter.split_at(pos);
                    break;
                }
            }

            // Trim off whitespace at end
            for (pos, c) in url_parameter.chars().rev().enumerate() {
                if char::is_whitespace(c) {
                    // Skipping whitespace after url contents.
                    continue;
                } else {
                    (url_parameter, _) = url_parameter.split_at(url_parameter.len() - pos);
                    break;
                }
            }

            // Trim off " at beginning.
            let c = url_parameter.chars().next();
            if let Some(c) = c {
                if c == '"' {
                    (_, url_parameter) = url_parameter.split_at(1);
                }
            };

            // Trim off " at end.
            let c = url_parameter.chars().rev().next();
            if let Some(c) = c {
                if c == '"' {
                    (url_parameter, _) = url_parameter.split_at(url_parameter.len() - 1);
                }
            };

            // Trim off whitespace at beginning.
            for (pos, c) in url_parameter.chars().enumerate() {
                if char::is_whitespace(c) {
                    // Skipping whitespace before url contents.
                    continue;
                } else {
                    (_, url_parameter) = url_parameter.split_at(pos);
                    break;
                }
            }

            // Trim off whitespace at end.
            for (pos, c) in url_parameter.chars().rev().enumerate() {
                if char::is_whitespace(c) {
                    // Skipping whitespace after url contents.
                    continue;
                } else {
                    (url_parameter, _) = url_parameter.split_at(url_parameter.len() - pos);
                    break;
                }
            }

            // Check for embedded image data for the "url"
            if !url_parameter.starts_with("data:image/") {
                // It's not embeded image data, let's move along.
                continue 'outer;
            }

            // Found "data:image/"
            (_, url_parameter) = url_parameter.split_at("data:image/".len());

            // Find contents after ";base64,"
            if let Some(pos) = url_parameter.find(";base64,") {
                (_, url_parameter) = url_parameter.split_at(pos + ";base64,".len());
                // Found ";base64,"
            } else {
                // No occurence of ";base64," in the url() parameter.
                // I guess image data isn't base64'd? We'll move along...
                continue 'outer;
            };

            debug!("Found base64'd image data CSS url() function args.");
            return Some(url_parameter);
        }
    }
}

impl<'a> Iterator for CssImageExtractor<'a> {
    type Item = Vec<u8>;

    fn next(&mut self) -> Option<Vec<u8>> {
        // Find the next base64 encoded image
        if let Some(base64_image) = self.next_base64_image() {
            // Decode the base64 encoded image
            match base64::decode(base64_image)
                .map_err(|e| CssExtractError::Base64Decode(format!("{}", e)))
            {
                Ok(image) => Some(image),
                _ => None,
            }
        } else {
            return None;
        }
    }
}

/// C interface for CssImageExtractor::new().
/// Handles all the unsafe ffi stuff.
///
/// # Safety
///
/// `file_bytes` and `hash_out` must not be NULL
#[export_name = "new_css_image_extractor"]
pub unsafe extern "C" fn new_css_image_extractor(
    file_bytes: *const c_char,
) -> sys::css_image_extractor_t {
    let css_input = if file_bytes.is_null() {
        warn!("{} is NULL", stringify!(file_bytes));
        return 0 as sys::css_image_extractor_t;
    } else {
        #[allow(unused_unsafe)]
        match unsafe { CStr::from_ptr(file_bytes) }.to_str() {
            Err(e) => {
                warn!("{} is not valid unicode: {}", stringify!(file_bytes), e);
                return 0 as sys::css_image_extractor_t;
            }
            Ok(s) => s,
        }
    };

    if let Ok(extractor) = CssImageExtractor::new(css_input) {
        return Box::into_raw(Box::new(extractor)) as sys::css_image_extractor_t;
    } else {
        return 0 as sys::css_image_extractor_t;
    }
}

/// Free the css image extractor
#[no_mangle]
pub extern "C" fn free_css_image_extractor(extractor: sys::css_image_extractor_t) {
    if extractor.is_null() {
        warn!("Attempted to free an image extractor pointer. Please report this at: https://github.com/Cisco-Talos/clamav/issues");
    } else {
        let _ = unsafe { Box::from_raw(extractor as *mut CssImageExtractor) };
    }
}

/// C interface for CssImageExtractor::next().
/// Handles all the unsafe ffi stuff.
///
/// # Safety
///
/// `file_bytes` and `hash_out` must not be NULL
#[export_name = "css_image_extract_next"]
pub unsafe extern "C" fn css_image_extract_next(
    extractor: sys::css_image_extractor_t,
    image_out: *mut *const u8,
    image_out_len: *mut usize,
    image_out_handle: *mut sys::css_image_handle_t,
) -> bool {
    let mut extractor = ManuallyDrop::new(Box::from_raw(extractor as *mut CssImageExtractor));

    let image_result = extractor.next();
    match image_result {
        Some(image) => {
            *image_out = image.as_ptr();
            *image_out_len = image.len();
            *image_out_handle = Box::into_raw(Box::new(image)) as sys::css_image_handle_t;
            return true;
        }
        None => {
            return false;
        }
    }
}

/// Free an extracted image
///
/// # Safety
///
/// Only call this once you're done using the image_out bytes.
#[no_mangle]
pub extern "C" fn free_extracted_image(image: sys::css_image_handle_t) {
    if image.is_null() {
        warn!("Attempted to free an image pointer. Please report this at: https://github.com/Cisco-Talos/clamav/issues");
    } else {
        let _ = unsafe { Box::from_raw(image as *mut Vec<u8>) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha1::{Digest, Sha1};

    #[test]
    fn extract_data_image_gif() {
        let doc = "
            url {
                background: url(data:image/gif;base64,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);
            }
            ";

        let mut extractor = CssImageExtractor::new(&doc).unwrap();

        let image = extractor.next().unwrap();

        let mut hasher = Sha1::new();
        hasher.update(&image);
        let hash = hasher.finalize();

        assert_eq!(
            hash.as_slice(),
            [
                100, 170, 89, 45, 242, 93, 238, 12, 90, 181, 195, 223, 148, 123, 222, 106, 39, 76,
                74, 77
            ]
        )
    }

    #[test]
    fn extract_data_image_gif_in_quotes() {
        let doc = "
            url {
                background: url( \" data:image/gif;base64,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 \" );
            }
            ";

        let mut extractor = CssImageExtractor::new(&doc).unwrap();

        let image = extractor.next().unwrap();

        let mut hasher = Sha1::new();
        hasher.update(&image);
        let hash = hasher.finalize();

        assert_eq!(
            hash.as_slice(),
            [
                100, 170, 89, 45, 242, 93, 238, 12, 90, 181, 195, 223, 148, 123, 222, 106, 39, 76,
                74, 77
            ]
        );
    }

    #[test]
    fn extract_data_image_gif_and_png_in_quotes() {
        let doc = "
            url {
                background: url( \" data:image/gif;base64,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 \" );
                background: url( \"   data:image/png;base64,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  \"  );
            }
            ";

        let mut extractor = CssImageExtractor::new(&doc).unwrap();

        let image = extractor.next().unwrap();

        let mut hasher = Sha1::new();
        hasher.update(&image);
        let hash = hasher.finalize();

        assert_eq!(
            hash.as_slice(),
            [
                100, 170, 89, 45, 242, 93, 238, 12, 90, 181, 195, 223, 148, 123, 222, 106, 39, 76,
                74, 77
            ]
        );

        let image = extractor.next().unwrap();

        let mut hasher = Sha1::new();
        hasher.update(&image);
        let hash = hasher.finalize();

        assert_eq!(
            hash.as_slice(),
            [
                127, 44, 70, 143, 148, 237, 88, 201, 162, 82, 121, 211, 72, 66, 248, 201, 215, 6,
                242, 112
            ]
        );
    }

    #[test]
    fn extract_data_image_gif_and_png_in_quotes_2() {
        let doc = "
            url {
                background: url( \" data:image/gif;base64,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 \" );
            }
            url {
                background: url( \"   data:image/png;base64,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  \"  );
            }
            ";

        let mut extractor = CssImageExtractor::new(&doc).unwrap();

        let image = extractor.next().unwrap();

        let mut hasher = Sha1::new();
        hasher.update(&image);
        let hash = hasher.finalize();

        assert_eq!(
            hash.as_slice(),
            [
                100, 170, 89, 45, 242, 93, 238, 12, 90, 181, 195, 223, 148, 123, 222, 106, 39, 76,
                74, 77
            ]
        );

        let image = extractor.next().unwrap();

        let mut hasher = Sha1::new();
        hasher.update(&image);
        let hash = hasher.finalize();

        assert_eq!(
            hash.as_slice(),
            [
                127, 44, 70, 143, 148, 237, 88, 201, 162, 82, 121, 211, 72, 66, 248, 201, 215, 6,
                242, 112
            ]
        );
    }
}

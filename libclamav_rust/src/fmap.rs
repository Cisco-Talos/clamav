/*
 *  Rust interface for libclamav FMap module
 *
 *  Copyright (C) 2023-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
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

use std::convert::TryFrom;

use log::{debug, error};

use crate::{sys, util::str_from_ptr};

/// Error enumerates all possible errors returned by this library.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Invalid parameter: {0}")]
    InvalidParameter(String),

    #[error("{0} parameter is NULL")]
    NullParam(&'static str),

    #[error("Offset {0} and length {1} not contained in FMap of size {2}")]
    NotContained(usize, usize, usize),

    #[error("FMap pointer not initialized: {0}")]
    UninitializedPtr(&'static str),

    #[error("Attempted to create Rust FMap interface from NULL pointer")]
    Null,
}

#[derive(PartialEq, Eq, Hash, Debug)]
pub struct FMap {
    fmap_ptr: *mut sys::cl_fmap_t,
}

impl TryFrom<*mut sys::cl_fmap_t> for FMap {
    type Error = Error;

    fn try_from(value: *mut sys::cl_fmap_t) -> Result<Self, Self::Error> {
        if value.is_null() {
            return Err(Error::Null);
        }

        Ok(FMap { fmap_ptr: value })
    }
}

impl<'a> FMap {
    /// Simple wrapper around C FMAP module's fmap.need() method.
    pub fn need_off(&'a self, at: usize, len: usize) -> Result<&'a [u8], Error> {
        // Get the need() method function pointer from the fmap.
        let need_fn = match unsafe { *self.fmap_ptr }.need {
            Some(ptr) => ptr,
            None => return Err(Error::UninitializedPtr("need()")),
        };

        let ptr: *const u8 = unsafe { need_fn(self.fmap_ptr, at, len, 1) } as *const u8;

        if ptr.is_null() {
            let fmap_size = unsafe { *self.fmap_ptr }.len;
            debug!(
                "need_off at {:?} len {:?} for fmap size {:?} returned NULL",
                at, len, fmap_size
            );
            return Err(Error::NotContained(at, len, fmap_size));
        }

        let slice: &[u8] = unsafe { std::slice::from_raw_parts(ptr, len) };

        Ok(slice)
    }

    pub fn len(&self) -> usize {
        unsafe { (*self.fmap_ptr).len }
    }

    pub fn is_empty(&self) -> bool {
        unsafe { (*self.fmap_ptr).len == 0 }
    }

    pub fn name(&self) -> &'static str {
        unsafe {
            str_from_ptr((*self.fmap_ptr).name)
                .unwrap_or(Some("<invalid-utf8>"))
                .unwrap_or("<unnamed>")
        }
    }
}

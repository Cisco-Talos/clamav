/*
 *  Functions and structures for recording, reporting evidence towards a scan verdict.
 *
 *  Copyright (C) 2022-2024 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
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

use std::{collections::HashMap, ffi::CStr, mem::ManuallyDrop, os::raw::c_char};

use log::{debug, error, warn};

use crate::{ffi_util::FFIError, rrf_call, sys, validate_str_param};

/// Error enumerates all possible errors returned by this library.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Invalid format")]
    Format,

    #[error("Invalid parameter: {0}")]
    InvalidParameter(String),

    #[error("{0} parameter is NULL")]
    NullParam(&'static str),
}

#[repr(C)]
pub enum IndicatorType {
    /// For hash-based indicators.
    Strong,
    /// For potentially unwanted applications/programs that are not malicious but may be used maliciously.
    PotentiallyUnwanted,

    #[cfg(feature = "not_ready")]
    /// Weak indicators that together with other indicators can be used to form a stronger indicator.
    /// This type of indicator should NEVER alert the user on its own.
    Weak,
}

#[derive(Debug, Default, Clone)]
pub struct Evidence {
    strong: HashMap<String, Vec<IndicatorMeta>>,
    pua: HashMap<String, Vec<IndicatorMeta>>,
    #[cfg(feature = "not_ready")]
    weak: HashMap<String, Vec<IndicatorMeta>>,
}

#[derive(Debug, Clone)]
pub struct IndicatorMeta {
    /// The original string pointer for the "virname", to pass back.
    static_virname: *const c_char,
}

/// Initialize a match vector
#[no_mangle]
pub extern "C" fn evidence_new() -> sys::evidence_t {
    Box::into_raw(Box::<Evidence>::default()) as sys::evidence_t
}

/// Free the evidence
#[no_mangle]
pub extern "C" fn evidence_free(evidence: sys::evidence_t) {
    if evidence.is_null() {
        warn!("Attempted to free a NULL evidence pointer. Please report this at: https://github.com/Cisco-Talos/clamav/issues");
    } else {
        let _ = unsafe { Box::from_raw(evidence as *mut Evidence) };
    }
}

/// C interface for Evidence::render_verdict().
/// Handles all the unsafe ffi stuff.
///
/// Render a verdict based on the evidence, depending on the severity of the
/// indicators found and the scan configuration.
///
/// The individual alerting-indicators would have already been printed at this point.
///
/// # Safety
///
/// No parameters may be NULL
#[export_name = "evidence_render_verdict"]
pub unsafe extern "C" fn _evidence_render_verdict(evidence: sys::evidence_t) -> bool {
    let evidence = ManuallyDrop::new(Box::from_raw(evidence as *mut Evidence));

    evidence.render_verdict()
}

/// C interface to get a string name for one of the alerts.
/// Will first check for one from the strong indicators, then pua.
///
/// # Safety
///
/// Returns a string that is either static, or allocated when reading the database.
/// So the lifetime of the string is good at least until you reload or unload the databases.
///
/// No parameters may be NULL
#[export_name = "evidence_get_last_alert"]
pub unsafe extern "C" fn _evidence_get_last_alert(evidence: sys::evidence_t) -> *const c_char {
    let evidence = ManuallyDrop::new(Box::from_raw(evidence as *mut Evidence));

    if let Some(meta) = evidence.strong.values().last() {
        meta.last().unwrap().static_virname as *const c_char
    } else if let Some(meta) = evidence.pua.values().last() {
        meta.last().unwrap().static_virname as *const c_char
    } else {
        // no alerts, return NULL
        std::ptr::null()
    }
}

/// C interface to get a string name for one of the alerts.
/// Will first check for one from the strong indicators, then pua.
///
/// # Safety
///
/// Returns a string that is either static, or allocated when reading the database.
/// So the lifetime of the string is good at least until you reload or unload the databases.
///
/// No parameters may be NULL
#[export_name = "evidence_get_indicator"]
pub unsafe extern "C" fn _evidence_get_indicator(
    evidence: sys::evidence_t,
    indicator_type: IndicatorType,
    index: usize,
) -> *const c_char {
    let evidence = ManuallyDrop::new(Box::from_raw(evidence as *mut Evidence));

    match indicator_type {
        IndicatorType::Strong => {
            if let Some(meta) = evidence.strong.values().nth(index) {
                return meta.last().unwrap().static_virname as *const c_char;
            } else {
                // no alert at that index. return NULL
                std::ptr::null()
            }
        }
        IndicatorType::PotentiallyUnwanted => {
            if let Some(meta) = evidence.pua.values().nth(index) {
                return meta.last().unwrap().static_virname as *const c_char;
            } else {
                // no alert at that index. return NULL
                std::ptr::null()
            }
        }
    }
}

/// C interface to check number of alerting indicators in evidence.
///
/// # Safety
///
/// No parameters may be NULL
#[export_name = "evidence_num_alerts"]
pub unsafe extern "C" fn _evidence_num_alerts(evidence: sys::evidence_t) -> usize {
    let evidence = ManuallyDrop::new(Box::from_raw(evidence as *mut Evidence));

    evidence.strong.len() + evidence.pua.len()
}

/// C interface to check number of indicators in evidence.
/// Handles all the unsafe ffi stuff.
///
/// # Safety
///
/// No parameters may be NULL
#[export_name = "evidence_num_indicators_type"]
pub unsafe extern "C" fn _evidence_num_indicators_type(
    evidence: sys::evidence_t,
    indicator_type: IndicatorType,
) -> usize {
    let evidence = ManuallyDrop::new(Box::from_raw(evidence as *mut Evidence));

    match indicator_type {
        IndicatorType::Strong => evidence.strong.len(),
        IndicatorType::PotentiallyUnwanted => evidence.pua.len(),
        #[cfg(feature = "not_ready")]
        // TODO: Implement a way to record, report number of indicators in the tree (you know, after making this a tree).
        IndicatorType::Weak => evidence.weak.len(),
    }
}

/// C interface for Evidence::add_indicator().
/// Handles all the unsafe ffi stuff.
///
/// Add an indicator to the evidence.
///
/// # Safety
///
/// `hexsig` and `err` must not be NULL
#[export_name = "evidence_add_indicator"]
pub unsafe extern "C" fn _evidence_add_indicator(
    evidence: sys::evidence_t,
    name: *const c_char,
    indicator_type: IndicatorType,
    err: *mut *mut FFIError,
) -> bool {
    let name_str = validate_str_param!(name, err = err);

    let mut evidence = ManuallyDrop::new(Box::from_raw(evidence as *mut Evidence));

    rrf_call!(
        err = err,
        evidence.add_indicator(name_str, name, indicator_type)
    )
}

impl Evidence {
    /// Check if we have any indicators that should alert the user.
    pub fn render_verdict(&self) -> bool {
        debug!("Checking verdict...");

        let num_alerting_indicators = self.strong.len() + self.pua.len();

        if num_alerting_indicators > 0 {
            debug!("Found {} alerting indicators", num_alerting_indicators);
            return true;
        }
        false
    }

    /// Add an indicator to the evidence.
    pub fn add_indicator(
        &mut self,
        name: &str,
        static_virname: *const c_char,
        indicator_type: IndicatorType,
    ) -> Result<(), Error> {
        let meta: IndicatorMeta = IndicatorMeta { static_virname };

        match indicator_type {
            IndicatorType::Strong => {
                self.strong.entry(name.to_string()).or_default().push(meta);
            }

            IndicatorType::PotentiallyUnwanted => {
                self.pua.entry(name.to_string()).or_default().push(meta);
            }

            #[cfg(feature = "not_ready")]
            // TODO: Implement a tree structure for recording weak indicators, to
            // match the archive/extraction level at which each was found.
            // This will be required for alerting signatures to depend on weak-indicators for embedded content.
            IndicatorType::Weak => {
                self.weak.entry(name.to_string()).or_default().push(meta);
            }
        }

        Ok(())
    }
}

/*
 *  Functions and structures for recording, reporting evidence towards a scan verdict.
 *
 *  Copyright (C) 2022-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
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

use indexmap::IndexMap;

use crate::{ffi_error, ffi_util::FFIError, rrf_call, sys, validate_str_param};

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

    /// Weak indicators that together with other indicators can be used to form a stronger indicator.
    /// This type of indicator should NEVER alert the user on its own.
    Weak,
}

#[derive(Debug, Default, Clone)]
pub struct Evidence {
    strong: IndexMap<String, Vec<IndicatorMeta>>,
    pua: IndexMap<String, Vec<IndicatorMeta>>,
    weak: IndexMap<String, Vec<IndicatorMeta>>,
}

#[derive(Debug, Clone)]
pub struct IndicatorMeta {
    /// The original string pointer for the "virname", to pass back.
    static_virname: *const c_char,

    /// The scan recursion depth at which this indicator was found, relative to the current layer.
    depth: usize,

    /// Object ID for the layer this indicator was found in.
    object_id: usize,
}

/// Initialize a match vector
#[no_mangle]
pub extern "C" fn evidence_new() -> sys::evidence_t {
    Box::into_raw(Box::<Evidence>::default()) as sys::evidence_t
}

/// C interface for Evidence::from_child().
/// Handles all the unsafe ffi stuff.
///
/// Create a new Evidence instance for a parent layer, given Evidence from a child layer.
///
/// # Safety
/// /// No parameters may be NULL
#[export_name = "evidence_new_from_child"]
pub unsafe extern "C" fn _evidence_new_from_child(
    child: sys::evidence_t,
    evidence_out: *mut sys::evidence_t,
    from_normalized: bool,
    err: *mut *mut FFIError,
) -> bool {
    if child.is_null() {
        error!("Attempted to create evidence from a NULL child pointer. Please report this at: https://github.com/Cisco-Talos/clamav/issues");
        return false;
    }
    if evidence_out.is_null() {
        error!("evidence_out pointer is NULL. Please report this at: https://github.com/Cisco-Talos/clamav/issues");
        return false;
    }

    // The caller must remain responsible for freeing the child evidence.
    let child = ManuallyDrop::new(Box::from_raw(child as *mut Evidence));

    match Evidence::from_child(&child, from_normalized) {
        Ok(evidence) => {
            // Write the new evidence to the output pointer
            *evidence_out = Box::into_raw(Box::new(evidence)) as sys::evidence_t;
            true
        }
        Err(error) => return ffi_error!(err = err, error),
    }
}

/// C interface for Evidence::add_child_evidence().
/// Handles all the unsafe ffi stuff.
///
/// Add evidence from a child layer to this evidence instance.
///
/// # Safety
///
/// No parameters may be NULL
#[export_name = "evidence_add_child_evidence"]
pub unsafe extern "C" fn _evidence_add_child_evidence(
    evidence: sys::evidence_t,
    child: sys::evidence_t,
    from_normalized: bool,
    err: *mut *mut FFIError,
) -> bool {
    if evidence.is_null() {
        error!("Attempted to add child evidence to a NULL evidence pointer. Please report this at: https://github.com/Cisco-Talos/clamav/issues");
        return false;
    }
    if child.is_null() {
        error!("Attempted to add NULL child evidence. Please report this at: https://github.com/Cisco-Talos/clamav/issues");
        return false;
    }

    // The caller must remain responsible for freeing the parent evidence.
    let mut evidence = ManuallyDrop::new(Box::from_raw(evidence as *mut Evidence));

    // The caller must remain responsible for freeing the child evidence.
    let child = ManuallyDrop::new(Box::from_raw(child as *mut Evidence));

    let add_result = evidence.add_child_evidence(&child, from_normalized);
    match add_result {
        Ok(_) => true,
        Err(error) => ffi_error!(err = err, error),
    }
}

/// Free the evidence
#[no_mangle]
pub extern "C" fn evidence_free(evidence: sys::evidence_t) {
    if !evidence.is_null() {
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

/// C interface to get a string name for an indicator by indicator_type and index.
/// You would use evidence_num_indicators_type() first to check how many indicators
/// there are for any given type, and then use this function to get the name of each indicator.
///
/// # Safety
///
/// Returns a string that is either static, or allocated when reading the database.
/// So the lifetime of the string is good at least until you reload or unload the databases.
/// The out_depth and out_object_id parameters are optional, and will be size_t pointers for depth and object_id.
///
/// No parameters may be NULL
#[export_name = "evidence_get_indicator"]
pub unsafe extern "C" fn _evidence_get_indicator(
    evidence: sys::evidence_t,
    indicator_type: IndicatorType,
    index: usize,
    out_depth: *mut usize,
    out_object_id: *mut usize,
) -> *const c_char {
    let evidence = ManuallyDrop::new(Box::from_raw(evidence as *mut Evidence));

    match indicator_type {
        IndicatorType::Strong => {
            if let Some(meta) = evidence.strong.values().nth(index) {
                // Set out_depth and out_object_id, if they are not NULL
                if !out_depth.is_null() {
                    *out_depth = meta.last().unwrap().depth;
                }
                if !out_object_id.is_null() {
                    *out_object_id = meta.last().unwrap().object_id;
                }

                return meta.last().unwrap().static_virname as *const c_char;
            } else {
                // no alert at that index. return NULL
                std::ptr::null()
            }
        }
        IndicatorType::PotentiallyUnwanted => {
            if let Some(meta) = evidence.pua.values().nth(index) {
                // Set out_depth and out_object_id, if they are not NULL
                if !out_depth.is_null() {
                    *out_depth = meta.last().unwrap().depth;
                }
                if !out_object_id.is_null() {
                    *out_object_id = meta.last().unwrap().object_id;
                }

                return meta.last().unwrap().static_virname as *const c_char;
            } else {
                // no alert at that index. return NULL
                std::ptr::null()
            }
        }
        IndicatorType::Weak => {
            if let Some(meta) = evidence.weak.values().nth(index) {
                // Set out_depth and out_object_id, if they are not NULL
                if !out_depth.is_null() {
                    *out_depth = meta.last().unwrap().depth;
                }
                if !out_object_id.is_null() {
                    *out_object_id = meta.last().unwrap().object_id;
                }

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
    // If the pointer is NULL, return 0. Because there if there is no evidence, there are no indicators.
    if evidence.is_null() {
        return 0;
    }

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
    // If the pointer is NULL, return 0. Because there if there is no evidence, there are no indicators.
    if evidence.is_null() {
        return 0;
    }

    let evidence = ManuallyDrop::new(Box::from_raw(evidence as *mut Evidence));

    match indicator_type {
        IndicatorType::Strong => evidence.strong.len(),
        IndicatorType::PotentiallyUnwanted => evidence.pua.len(),
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
    object_id: usize,
    err: *mut *mut FFIError,
) -> bool {
    let name_str = validate_str_param!(name, err = err);

    let mut evidence = ManuallyDrop::new(Box::from_raw(evidence as *mut Evidence));

    rrf_call!(
        err = err,
        evidence.add_indicator(
            name_str,
            name,
            indicator_type,
            0, // depth is always 0 when first adding an indicator
            object_id
        )
    )
}

/// C interface for Evidence::remove_indicator().
/// Handles all the unsafe ffi stuff.
///
/// Remove an indicator from the evidence.
///
/// # Safety
///
/// `hexsig` and `err` must not be NULL
#[export_name = "evidence_remove_indicator"]
pub unsafe extern "C" fn _evidence_remove_indicator(
    evidence: sys::evidence_t,
    name: *const c_char,
    indicator_type: IndicatorType,
    err: *mut *mut FFIError,
) -> bool {
    let name_str = validate_str_param!(name, err = err);

    let mut evidence = ManuallyDrop::new(Box::from_raw(evidence as *mut Evidence));

    rrf_call!(
        err = err,
        evidence.remove_indicator(name_str, indicator_type)
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
        depth: usize,
        object_id: usize,
    ) -> Result<(), Error> {
        let meta: IndicatorMeta = IndicatorMeta {
            static_virname,
            depth,
            object_id,
        };

        match indicator_type {
            IndicatorType::Strong => {
                self.strong.entry(name.to_string()).or_default().push(meta);
            }

            IndicatorType::PotentiallyUnwanted => {
                self.pua.entry(name.to_string()).or_default().push(meta);
            }

            IndicatorType::Weak => {
                self.weak.entry(name.to_string()).or_default().push(meta);
            }
        }

        Ok(())
    }

    /// Create a new Evidence instance for a parent layer, given Evidence from a child layer.
    pub fn from_child(child: &Evidence, from_normalized: bool) -> Result<Self, Error> {
        if child.strong.is_empty() && child.pua.is_empty() && child.weak.is_empty() {
            return Err(Error::InvalidParameter(
                "Child evidence must contain at least one indicator".to_string(),
            ));
        }

        // Create a new Evidence instance for the parent
        let mut parent = Evidence::default();

        // Copy indicators from child to parent, increasing depth by 1
        parent.add_child_evidence(child, from_normalized)?;

        Ok(parent)
    }

    /// Add evidence from a child layer to this evidence instance.
    pub fn add_child_evidence(
        &mut self,
        child: &Evidence,
        from_normalized: bool,
    ) -> Result<(), Error> {
        if child.strong.is_empty() && child.pua.is_empty() && child.weak.is_empty() {
            return Err(Error::InvalidParameter(
                "Child evidence must contain at least one indicator".to_string(),
            ));
        }

        let depth_increment = if from_normalized {
            0 // If from_normalized is true, we do not increase the depth.
        } else {
            1 // Otherwise, we increase the depth by 1.
        };

        // Copy indicators from child to parent, increasing depth by 1 (unless from_normalized is true).
        for (name, metas) in &child.strong {
            for meta in metas {
                self.add_indicator(
                    name,
                    meta.static_virname,
                    IndicatorType::Strong,
                    meta.depth + depth_increment,
                    meta.object_id,
                )?;
            }
        }

        for (name, metas) in &child.pua {
            for meta in metas {
                self.add_indicator(
                    name,
                    meta.static_virname,
                    IndicatorType::PotentiallyUnwanted,
                    meta.depth + depth_increment,
                    meta.object_id,
                )?;
            }
        }
        for (name, metas) in &child.weak {
            for meta in metas {
                self.add_indicator(
                    name,
                    meta.static_virname,
                    IndicatorType::Weak,
                    meta.depth + depth_increment,
                    meta.object_id,
                )?;
            }
        }

        Ok(())
    }

    /// Remove an indicator from the evidence.
    pub fn remove_indicator(
        &mut self,
        name: &str,
        indicator_type: IndicatorType,
    ) -> Result<(), Error> {
        match indicator_type {
            IndicatorType::Strong => {
                if let Some(metas) = self.strong.get_mut(name) {
                    metas.pop();
                    if metas.is_empty() {
                        self.strong.shift_remove(name);
                    }
                }
            }

            IndicatorType::PotentiallyUnwanted => {
                if let Some(metas) = self.pua.get_mut(name) {
                    metas.pop();
                    if metas.is_empty() {
                        self.pua.shift_remove(name);
                    }
                }
            }

            IndicatorType::Weak => {
                if let Some(metas) = self.weak.get_mut(name) {
                    metas.pop();
                    if metas.is_empty() {
                        self.weak.shift_remove(name);
                    }
                }
            }
        }

        Ok(())
    }
}

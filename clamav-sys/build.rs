// Copyright (C) 2020-2023 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
//
// Authors: Jonas Zaddach, Scott Hutton
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License version 2 as
// published by the Free Software Foundation.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
// MA 02110-1301, USA.

mod build_internal;

use std::env;
use std::io::Write as _;
use std::path::{Path, PathBuf};

// Write the public bindings to this file in maintainer mode
const BINDGEN_OUTPUT_FILE: &str = "no-libclang/bindings.rs";

// Generate bindings for these functions:
const BINDGEN_FUNCTIONS: &[&str] = &[
    "cl_cleanup_crypto",
    "cl_cvdfree",
    "cl_cvdparse",
    "cl_debug",
    "cl_engine_addref",
    "cl_engine_compile",
    "cl_engine_free",
    "cl_engine_get_num",
    "cl_engine_get_str",
    "cl_engine_new",
    "cl_engine_set_clcb_engine_compile_progress",
    "cl_engine_set_clcb_engine_free_progress",
    "cl_engine_set_clcb_file_inspection",
    "cl_engine_set_clcb_file_props",
    "cl_engine_set_clcb_hash",
    "cl_engine_set_clcb_meta",
    "cl_engine_set_clcb_post_scan",
    "cl_engine_set_clcb_pre_cache",
    "cl_engine_set_clcb_pre_scan",
    "cl_engine_set_clcb_sigload",
    "cl_engine_set_clcb_sigload_progress",
    "cl_engine_set_clcb_stats_add_sample",
    "cl_engine_set_clcb_stats_decrement_count",
    "cl_engine_set_clcb_stats_flush",
    "cl_engine_set_clcb_stats_get_hostid",
    "cl_engine_set_clcb_stats_get_num",
    "cl_engine_set_clcb_stats_get_size",
    "cl_engine_set_clcb_stats_remove_sample",
    "cl_engine_set_clcb_stats_submit",
    "cl_engine_set_clcb_virus_found",
    "cl_engine_set_num",
    "cl_engine_set_stats_set_cbdata",
    "cl_engine_set_str",
    "cl_engine_settings_apply",
    "cl_engine_settings_copy",
    "cl_engine_settings_free",
    "cl_engine_stats_enable",
    "cl_fmap_close",
    "cl_fmap_open_handle",
    "cl_fmap_open_memory",
    "cl_init",
    "cl_initialize_crypto",
    "cl_load",
    "cl_retdbdir",
    "cl_retflevel",
    "cl_retver",
    "cl_scandesc",
    "cl_scandesc_callback",
    "cl_scanfile",
    "cl_scanfile_callback",
    "cl_scanmap_callback",
    "cl_set_clcb_msg",
    "cl_strerror",
    "cli_append_virus",
    "cli_ctx",
    "cli_dbgmsg_no_inline",
    "cli_errmsg",
    "cli_get_debug_flag",
    "cli_getdsig",
    "cli_infomsg_simple",
    "cli_versig2",
    "cli_warnmsg",
    "lsig_increment_subsig_match",
];

// Generate bindings for these types (structs, prototypes, etc.):
const BINDGEN_TYPES: &[&str] = &[
    "cl_cvd",
    "clcb_file_props",
    "clcb_meta",
    "clcb_post_scan",
    "clcb_pre_scan",
    "cli_ac_data",
    "cli_ac_result",
    "cli_matcher",
    "time_t",
];

// Generate "newtype" enums for these C enums
const BINDGEN_ENUMS: &[&str] = &["cl_engine_field", "cl_error_t", "cl_msg"];

const BINDGEN_CONSTANTS: &[&str] = &[
    "CL_DB_.*",
    "CL_INIT_DEFAULT",
    "CL_SCAN_.*",
    "ENGINE_OPTIONS_.*",
    "LAYER_ATTRIBUTES_.*",
];

const CLAMAV_LIBRARY_NAME: &str = "clamav";

fn generate_bindings(
    output_path: &Path,
    customize_bindings: &dyn Fn(bindgen::Builder) -> bindgen::Builder,
) {
    let mut bindings = bindgen::Builder::default();
    for function in BINDGEN_FUNCTIONS {
        bindings = bindings.allowlist_function(function);
    }

    for typename in BINDGEN_TYPES {
        bindings = bindings.allowlist_type(typename);
    }

    for typename in BINDGEN_ENUMS {
        bindings = bindings.newtype_enum(typename);
    }

    for constant in BINDGEN_CONSTANTS {
        bindings = bindings.allowlist_var(constant);
    }

    bindings = bindings
        .header("wrapper.h")
        // Tell cargo to invalidate the built crate whenever any of the
        // included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()));

    bindings = customize_bindings(bindings);

    bindings
        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings")
        .write_to_file(output_path)
        .expect("Couldn't write bindings!");
}

fn cargo_common() {
    if local_clamav_include_path().is_none() {
        println!("cargo:rustc-link-lib=dylib={}", CLAMAV_LIBRARY_NAME);
    }

    // Tell cargo to invalidate the built crate whenever the wrapper changes
    println!("cargo:rerun-if-changed=wrapper.h");
}

fn main() -> anyhow::Result<()> {
    let mut include_paths = vec![];

    // Test whether being built as part of ClamAV source
    let local_include_path = local_clamav_include_path();

    // Generate temporary path for the generated "internal" module
    let mut output_path_intmod = PathBuf::from(env::var("OUT_DIR")?);
    output_path_intmod.push("sys.rs");

    if let Some(include_path) = &local_include_path {
        // It seems we're being compiled from within the ClamAV source tree.
        // Confirm that clamav.h is there, too

        include_paths.push(include_path.clone());

        build_internal::bindgen_internal(&output_path_intmod)?;
    } else {
        // This crate is being referenced from an external project. Utilize the
        // system-installed copy of libclamav (as located using pkg-config).

        #[cfg(not(windows))]
        {
            let libclamav = pkg_config::Config::new()
                .atleast_version("0.103")
                .probe("libclamav")
                .unwrap();

            include_paths.extend_from_slice(&libclamav.include_paths);
        }

        #[cfg(windows)]
        match vcpkg::find_package("clamav") {
            Ok(pkg) => include_paths.extend_from_slice(&pkg.include_paths),
            Err(err) => {
                println!(
                    "cargo:warning=Either vcpkg is not installed, or an error occurred in vcpkg: {}",
                    err
                );
                // Attempt to examine user-supplied variables to find the dependencies
                let clamav_source = PathBuf::from(env::var("CLAMAV_SOURCE").expect("CLAMAV_SOURCE environment variable must be set and point to ClamAV's source directory"));
                let clamav_build = PathBuf::from(env::var("CLAMAV_BUILD").expect("CLAMAV_BUILD environment variable must be set and point to ClamAV's build directory"));
                let openssl_include = PathBuf::from(env::var("OPENSSL_INCLUDE").expect("OPENSSL_INCLUDE environment variable must be set and point to openssl's include directory"));
                let profile = env::var("PROFILE").unwrap();

                let library_path = match profile.as_str() {
                    "debug" => std::path::Path::new(&clamav_build).join("libclamav/Debug"),
                    "release" => std::path::Path::new(&clamav_build).join("libclamav/Release"),
                    _ => panic!("Unexpected build profile"),
                };

                println!(
                    "cargo:rustc-link-search=native={}",
                    library_path.to_str().unwrap()
                );

                include_paths.push(clamav_source.join("libclamav"));
                include_paths.push(clamav_build);
                include_paths.push(openssl_include);
            }
        };

        // Build a vestigial `sys` module, as there will be no access to
        // internal APIs.
        let mut fh = std::fs::File::create(&output_path_intmod)?;
        writeln!(fh, "// This file intentionally left blank").expect("write");
    }

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let mut output_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    output_path.push("bindings.rs");
    if local_include_path.is_none() || (local_include_path.is_some() && in_maintainer_mode()) {
        cargo_common();
        generate_bindings(
            &output_path,
            &|builder: bindgen::Builder| -> bindgen::Builder {
                let mut builder = builder;
                for include_path in &include_paths {
                    builder = builder
                        .clang_arg("-I")
                        .clang_arg(include_path.to_str().unwrap());
                }
                builder
            },
        );
        // And place a copy in the source tree (for potential check-in)
        std::fs::copy(&output_path, BINDGEN_OUTPUT_FILE)?;
    } else {
        // Otherwise, just copy the pre-generated file to the specified
        // location.
        std::fs::copy(BINDGEN_OUTPUT_FILE, &output_path)?;
    }

    Ok(())
}

fn local_clamav_include_path() -> Option<PathBuf> {
    let manifest_dir =
        PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("get CARGO_MANIFEST_DIR env"));
    let mut libclamav_dir = manifest_dir
        .parent()
        .expect("get manifest dir parent")
        .to_path_buf();
    libclamav_dir.push("libclamav");
    if libclamav_dir.metadata().is_ok_and(|md| md.is_dir()) {
        // It seems we're being compiled from within the ClamAV source tree.
        // Just confirm that clamav.h is there, too
        let mut clamav_h_path = libclamav_dir.clone();
        clamav_h_path.push("clamav.h");
        if clamav_h_path.metadata().is_ok_and(|md| md.is_file()) {
            return Some(libclamav_dir);
        }
    }

    None
}

pub(crate) fn in_maintainer_mode() -> bool {
    env::var("MAINTAINER_MODE").unwrap_or_default() == "ON"
}

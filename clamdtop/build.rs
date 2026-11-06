// Copyright (C) 2026 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
// SPDX-License-Identifier: GPL-2.0-only

use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-env-changed=CARGO_CFG_TARGET_OS");
    if !matches!(env::var("CARGO_CFG_TARGET_OS").as_deref(), Ok("windows")) {
        return;
    }

    let crate_dir =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("Cargo sets manifest dir"));
    let clamav_dir = crate_dir
        .parent()
        .expect("clamdtop crate has ClamAV as its parent");
    let resources = clamav_dir.join("win32").join("res");
    let common_resource = resources.join("common.rc");
    if !common_resource.exists() {
        println!("cargo:warning=Skipping Windows resources because CMake has not generated win32/res/common.rc");
        return;
    }
    if let Some(build_dir) = env::var_os("CLAMAV_CMAKE_BUILD_DIR") {
        let build_dir = build_dir.to_string_lossy();
        let existing_include = env::var("INCLUDE").unwrap_or_default();
        let include = if existing_include.is_empty() {
            build_dir.to_string()
        } else {
            format!("{build_dir};{existing_include}")
        };
        env::set_var("INCLUDE", include);
        println!("cargo:rerun-if-env-changed=CLAMAV_CMAKE_BUILD_DIR");
    }
    let resource_script =
        PathBuf::from(env::var_os("OUT_DIR").expect("Cargo sets OUT_DIR")).join("clamdtop.rc");
    let manifest = resources.join("clam.manifest");
    let icon_and_version = resources.join("clamdtop.rc");
    let script = format!(
        "1 24 \"{}\"\n#include \"{}\"\n",
        manifest.display(),
        icon_and_version.display()
    );
    fs::write(&resource_script, script).expect("write clamdtop Windows resource script");
    println!("cargo:rerun-if-changed={}", manifest.display());
    println!("cargo:rerun-if-changed={}", icon_and_version.display());
    println!("cargo:rerun-if-changed={}", common_resource.display());
    println!(
        "cargo:rerun-if-changed={}",
        resources.join("clam.ico").display()
    );

    embed_resource::compile(resource_script, embed_resource::NONE)
        .manifest_required()
        .expect("embed clamdtop icon, version information, and manifest");
}

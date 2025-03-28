use std::env;
use std::path::{Path, PathBuf};

use bindgen::builder;

// Note to maintainers: this is currently a hybrid of examination of the
// CMake environment, and leaning on Rust `cfg` elements. Ideally, it
// should be possible to work in this space (e.g., execute tests from an
// IDE) without having to rely on CMake elements to properly link the
// unit tests). Hence the bizarre mix of CMake inspection and Cargo-based
// elements.
//
// It's handy to know that all the `cfg` goodies are defined here:
//
// https://doc.rust-lang.org/reference/conditional-compilation.html

// A list of environment variables to query to determine additional libraries
// that need to be linked to resolve dependencies.
const LIB_ENV_LINK: &[&str] = &[
    "LIBSSL",
    "LIBCRYPTO",
    "LIBZ",
    "LIBBZ2",
    "LIBPCRE2",
    "LIBXML2",
    "LIBCURL",
    "LIBJSONC",
    "LIBCLAMMSPACK",
    "LIBCLAMUNRARIFACE",
    "LIBCLAMUNRAR",
    "LIBICONV",
];

// The same, but additional values to check on Windows platforms
const LIB_ENV_LINK_WINDOWS: &[&str] = &["LIBPTHREADW32", "LIBWIN32COMPAT"];

// Additional [verbatim] libraries to link on Windows platforms
const LIB_LINK_WINDOWS: &[&str] = &["wsock32", "ws2_32", "Shell32", "User32"];

// Windows library names that must have the leading `lib` trimmed (if encountered)
const WINDOWS_TRIM_LOCAL_LIB: &[&str] = &["libclamav", "libclammspack"];

// Generate bindings for these functions:
const BINDGEN_FUNCTIONS: &[&str] = &[
    "cl_retflevel",
    "cli_ctx",
    "cli_warnmsg",
    "cli_dbgmsg_no_inline",
    "cli_infomsg_simple",
    "cli_errmsg",
    "cli_append_virus",
    "lsig_increment_subsig_match",
    "cli_versig",
    "cli_versig2",
    "cli_getdsig",
    "cli_get_debug_flag",
    "cli_magic_scan_buff",
    "cli_checklimits",
    "cli_matchmeta",
];

// Generate bindings for these types (structs, enums):
const BINDGEN_TYPES: &[&str] = &[
    "cli_matcher",
    "cli_ac_data",
    "cli_ac_result",
    "onedump_t",
    "cvd_t",
];

// Find the required functions and types in these headers:
const BINDGEN_HEADERS: &[&str] = &[
    "../libclamav/matcher.h",
    "../libclamav/matcher-ac.h",
    "../libclamav/others.h",
    "../libclamav/dsig.h",
    "../libclamav/htmlnorm.h",
    "../libclamav/fmap.h",
    "../libclamav/scanners.h",
];

// Find the required headers in these directories:
const BINDGEN_INCLUDE_PATHS: &[&str] = &[
    "-I../libclamav",
    "-I../libclamunrar_iface",
    "-I../libclammspack",
];

// Write the bindings to this file:
const BINDGEN_OUTPUT_FILE: &str = "src/sys.rs";

const C_HEADER_OUTPUT: &str = "clamav_rust.h";

// Environment variable name prefixes worth including for diags
const ENV_PATTERNS: &[&str] = &["CARGO_", "RUST", "LIB"];

fn main() -> Result<(), &'static str> {
    // Dump the command line and interesting environment variables for diagnostic
    // purposes. These will end up in a 'stderr' file under the target directory,
    // in a ".../clamav_rust-<hex>" subdirectory

    eprintln!("build.rs command line: {:?}", std::env::args());
    eprintln!("Environment:");
    std::env::vars()
        .filter(|(k, _)| ENV_PATTERNS.iter().any(|prefix| k.starts_with(prefix)))
        .for_each(|(k, v)| eprintln!("  {}={:?}", k, v));

    detect_clamav_build()?;

    // We only want to generate bindings for `cargo build`, not `cargo test`.
    // FindRust.cmake defines $CARGO_CMD so we can differentiate.
    let cargo_cmd = env::var("CARGO_CMD").unwrap_or_else(|_| "".into());
    if cargo_cmd == "build" {
        // Always generate the C-headers when CMake kicks off a build.
        execute_cbindgen()?;

        // Only generate the `.rs` bindings when maintainer-mode is enabled.
        //
        // Bindgen requires libclang, which may not readily available, so we
        // will commit the bindings to version control and use maintainer-mode
        // to update them, as needed.
        // On the plus-side, this means that our `.rs` file is present before our
        // first build, so at least rust-analyzer will be happy.
        let maintainer_mode = env::var("MAINTAINER_MODE").unwrap_or_else(|_| "".into());
        if maintainer_mode == "ON" {
            execute_bindgen()?;
        }
    } else {
        eprintln!("NOTE: Not generating bindings because CARGO_CMD != build");
    }

    Ok(())
}

/// Use bindgen to generate Rust bindings to call into C libraries.
fn execute_bindgen() -> Result<(), &'static str> {
    let build_dir = PathBuf::from(env::var("CARGO_TARGET_DIR").unwrap_or_else(|_| ".".into()));
    let build_include_path = format!("-I{}", build_dir.join(".").to_str().unwrap());
    let has_include_directories = env::var("CARGO_INCLUDE_DIRECTORIES").ok();

    // Configure and generate bindings.
    let mut builder = builder()
        // Silence code-style warnings for generated bindings.
        .raw_line("#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]")
        // Make the bindings pretty.
        .formatter(bindgen::Formatter::Rustfmt)
        // Disable the layout tests.
        // We're committing to source control. Pointer width, integer size, etc
        // are probably not the same when generated as when compiled.
        .layout_tests(false)
        // Enable bindgen to find generated headers in the build directory, too.
        .clang_arg(build_include_path);

    // If include directories were specified, add them to the builder.
    if let Some(include_directories) = has_include_directories {
        for include_directory in include_directories.split(';') {
            // Enable bindgen to find dependencies headers.
            builder = builder.clang_arg(format!("-I{include_directory}"));
        }
    }

    for &include_path in BINDGEN_INCLUDE_PATHS {
        builder = builder.clang_arg(include_path);
    }
    for &header in BINDGEN_HEADERS {
        builder = builder.header(header);
    }
    for &c_function in BINDGEN_FUNCTIONS {
        builder = builder.allowlist_function(c_function);
    }
    for &c_type in BINDGEN_TYPES {
        builder = builder.allowlist_type(c_type);
    }

    // Generate!
    builder
        .generate()
        .expect("Generating Rust bindings for C code")
        .write_to_file(BINDGEN_OUTPUT_FILE)
        .expect("Writing Rust bindings to output file");

    eprintln!("bindgen outputting \"{}\"", BINDGEN_OUTPUT_FILE);

    Ok(())
}

/// Use cbindgen to generate C-header's for Rust static libraries.
fn execute_cbindgen() -> Result<(), &'static str> {
    let crate_dir = env::var("CARGO_MANIFEST_DIR").or(Err("CARGO_MANIFEST_DIR not specified"))?;
    let build_dir = PathBuf::from(env::var("CARGO_TARGET_DIR").unwrap_or_else(|_| ".".into()));
    let outfile_path = build_dir.join(C_HEADER_OUTPUT);

    // Useful for build diagnostics
    eprintln!("cbindgen outputting {:?}", &outfile_path);
    cbindgen::generate(crate_dir)
        .expect("Unable to generate bindings")
        .write_to_file(&outfile_path);

    Ok(())
}

fn detect_clamav_build() -> Result<(), &'static str> {
    println!("cargo:rerun-if-env-changed=LIBCLAMAV");

    if search_and_link_lib("LIBCLAMAV")? {
        eprintln!("NOTE: LIBCLAMAV defined. Examining LIB* environment variables");
        // Need to link with libclamav dependencies

        // LLVM is optional, and don't have a path to each library like we do with the other libs.
        let llvm_libs = env::var("LLVM_LIBS").unwrap_or("".into());
        if !llvm_libs.is_empty() {
            match env::var("LLVM_DIRS") {
                Err(env::VarError::NotPresent) => eprintln!("LLVM_DIRS not set"),
                Err(env::VarError::NotUnicode(_)) => return Err("environment value not unicode"),
                Ok(s) => {
                    if s.is_empty() {
                        eprintln!("LLVM_DIRS not set");
                    } else {
                        s.split(',').for_each(|dirpath| {
                            println!("cargo:rustc-link-search={}", dirpath);
                        });
                    }
                }
            };

            llvm_libs
                .split(',')
                .for_each(|filepath_str| match parse_lib_path(filepath_str) {
                    Ok(parsed_path) => {
                        println!("cargo:rustc-link-search={}", parsed_path.dir);
                        eprintln!("  - requesting that rustc link {:?}", &parsed_path.libname);
                        println!("cargo:rustc-link-lib={}", parsed_path.libname);
                    }
                    Err(_) => {
                        eprintln!("  - requesting that rustc link {:?}", filepath_str);
                        println!("cargo:rustc-link-lib={}", filepath_str);
                    }
                });
        }

        for var in LIB_ENV_LINK {
            let _ = search_and_link_lib(var);
        }

        if cfg!(windows) {
            for var in LIB_ENV_LINK_WINDOWS {
                let _ = search_and_link_lib(var);
            }
            for lib in LIB_LINK_WINDOWS {
                println!("cargo:rustc-link-lib={}", lib);
            }
        } else {
            // Link the test executable with libstdc++ on unix systems,
            // This is needed for fully-static build where clamav & 3rd party
            // dependencies excluding the std libs are static.
            if cfg!(target_os = "linux") {
                eprintln!("NOTE: linking libstdc++ (linux target)");
                println!("cargo:rustc-link-lib=stdc++");
            } else {
                eprintln!("NOTE: NOT linking libstdc++ (non-linux target)");
            }
        }
    } else {
        println!("NOTE: LIBCLAMAV not defined");
    }

    Ok(())
}

//
// Return whether the specified environment variable has been set, and output
// linking directives as a side-effect
//
fn search_and_link_lib(environment_variable: &str) -> Result<bool, &'static str> {
    eprintln!("  - checking for {:?} in environment", environment_variable);
    let filepath_str = match env::var(environment_variable) {
        Err(env::VarError::NotPresent) => return Ok(false),
        Err(env::VarError::NotUnicode(_)) => return Err("environment value not unicode"),
        Ok(s) => {
            if s.is_empty() {
                return Ok(false);
            } else {
                s
            }
        }
    };

    let parsed_path = parse_lib_path(&filepath_str)?;
    eprintln!(
        "  - adding {:?} to rustc library search path",
        &parsed_path.dir
    );
    println!("cargo:rustc-link-search={}", parsed_path.dir);
    eprintln!("  - requesting that rustc link {:?}", &parsed_path.libname);
    println!("cargo:rustc-link-lib={}", parsed_path.libname);

    Ok(true)
}

struct ParsedLibraryPath {
    dir: String,
    libname: String,
}

// Parse a library path, returning the portion expected after the `-l`, and the
// directory containing the library
fn parse_lib_path(path: &str) -> Result<ParsedLibraryPath, &'static str> {
    let path = PathBuf::from(path);
    let file_name = path
        .file_name()
        .ok_or("file name not found")?
        .to_str()
        .ok_or("file name not unicode")?;

    // This can't fail because it came from a &str
    let dir = path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .to_str()
        .unwrap()
        .to_owned();

    // Grab the portion up to the first '.'
    let full_libname = file_name
        .split('.')
        .next()
        .ok_or("no '.' found in file name")?;

    // Windows typically requires the full filename when linking system libraries,
    // but not when it's one of the locally-generated libraries.
    let should_trim_leading_lib =
        !cfg!(windows) || WINDOWS_TRIM_LOCAL_LIB.iter().any(|s| *s == full_libname);

    let libname = if should_trim_leading_lib {
        full_libname
            .strip_prefix("lib")
            .ok_or(r#"file name doesn't begin with "lib""#)?
    } else {
        full_libname
    }
    .to_owned();

    Ok(ParsedLibraryPath { dir, libname })
}

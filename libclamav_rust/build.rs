use std::env;
use std::path::{Path, PathBuf};

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
const LIB_ENV_LINK: [&str; 12] = [
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
const LIB_ENV_LINK_WINDOWS: [&str; 2] = ["LIBPTHREADW32", "LIBWIN32COMPAT"];

// Additional [verbatim] libraries to link on Windows platforms
const LIB_LINK_WINDOWS: [&str; 4] = ["wsock32", "ws2_32", "Shell32", "User32"];

// Windows library names that must have the leading `lib` trimmed (if encountered)
const WINDOWS_TRIM_LOCAL_LIB: [&str; 2] = ["libclamav", "libclammspack"];

const C_HEADER_OUTPUT: &str = "clamav_rust.h";

fn main() -> Result<(), &'static str> {
    detect_clamav_build()?;
    execute_cbindgen()?;
    Ok(())
}

fn execute_cbindgen() -> Result<(), &'static str> {
    let crate_dir = env::var("CARGO_MANIFEST_DIR").or(Err("CARGO_MANIFEST_DIR not specified"))?;
    let build_dir = PathBuf::from(env::var("BUILD").unwrap_or(".".into()));
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
        for var in &LIB_ENV_LINK {
            let _ = search_and_link_lib(var);
        }

        if cfg!(windows) {
            for var in &LIB_ENV_LINK_WINDOWS {
                let _ = search_and_link_lib(var);
            }
            for lib in &LIB_LINK_WINDOWS {
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

    return Ok(true);
}

struct ParsedLibraryPath {
    dir: String,
    libname: String,
}

// Parse a library path, returning the portion expected after the `-l`, and the
// directory containing the library
fn parse_lib_path<'a>(path: &'a str) -> Result<ParsedLibraryPath, &'static str> {
    let path = PathBuf::from(path);
    let file_name = path
        .file_name()
        .ok_or("file name not found")?
        .to_str()
        .ok_or("file name not unicode")?;

    // This can't fail because it came from a &str
    let dir = path
        .parent()
        .unwrap_or(Path::new("."))
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

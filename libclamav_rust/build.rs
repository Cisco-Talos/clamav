use std::env;
use std::path::PathBuf;

use anyhow::anyhow;

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

const C_HEADER_OUTPUT: &str = "clamav_rust.h";

// Environment variable name prefixes worth including for diags
const ENV_PATTERNS: &[&str] = &["CARGO_", "RUST", "LIB"];

pub fn main() -> anyhow::Result<()> {
    // Dump the command line and interesting environment variables for diagnostic
    // purposes. These will end up in a 'stderr' file under the target directory,
    // in a ".../clamav_rust-<hex>" subdirectory

    eprintln!("build.rs command line: {:?}", std::env::args());
    eprintln!("Environment:");
    std::env::vars()
        .filter(|(k, _)| ENV_PATTERNS.iter().any(|prefix| k.starts_with(prefix)))
        .for_each(|(k, v)| eprintln!("  {}={:?}", k, v));

    // We only want to generate bindings for `cargo build`, not `cargo test`.
    // FindRust.cmake defines $CARGO_CMD so we can differentiate.
    let cargo_cmd = env::var("CARGO_CMD").unwrap_or_else(|_| "".into());
    if cargo_cmd == "build" {
        // Always generate the C-headers when CMake kicks off a build.
        execute_cbindgen()?;
    } else {
        eprintln!("NOTE: Not generating bindings because CARGO_CMD != build");
    }

    Ok(())
}

/// Use cbindgen to generate C-header's for Rust static libraries.
fn execute_cbindgen() -> anyhow::Result<()> {
    let crate_dir =
        env::var("CARGO_MANIFEST_DIR").or(Err(anyhow!("CARGO_MANIFEST_DIR not specified")))?;
    let build_dir = PathBuf::from(env::var("CARGO_TARGET_DIR").unwrap_or_else(|_| ".".into()));
    let outfile_path = build_dir.join(C_HEADER_OUTPUT);

    // Useful for build diagnostics
    eprintln!("cbindgen outputting {:?}", &outfile_path);
    cbindgen::generate(crate_dir)
        .expect("Unable to generate bindings")
        .write_to_file(&outfile_path);

    Ok(())
}

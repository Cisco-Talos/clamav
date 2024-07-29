# clamav-sys

clamav-sys is a minimal Rust interface around [libclamav](https://www.clamav.net).
This package is not supposed to be used stand-alone, but only through its safe wrapper,
clamav-rs.


## Building

### Unix (anything but Windows)
You should have the `clamav-dev` package of your distribution installed (ClamAV
with headers). The headers and library should be picked up automatically via
pkg-config.

### Windows
#### vcpkg
The preferred way of handling dependencies is `vcpkg`.
Point `$env:VCPKG_ROOT` to your `vcpkg` installation, and set
`$env:VCPKGRS_DYNAMIC=1` to use dynamic linking (the default method of linking will
likely not work, as `pdcurses` doesn't support the `x64-windows-static-md` triplet).

See the [vcpkg crate's documentation](https://docs.rs/vcpkg) for more details. 

Gotchas:
- Windows has its own version of a zlib dll that is incompatbile with vcpkg. If
  you get a message such as "The procedure entry point gzdirect could not be
  located in the dynamic link library", you'll want to make sure that the vcpkg
  dynamic libraries in your PATH variable are preceding the Windows one.
  ```
  $env:PATH="$env:VCPKG_ROOT\installed\x64-windows\bin\;$env:PATH"
  ```
  This error is especially hard to diagnose in PowerShell, as the process will
  just hang without any output. In cmd.exe you'll get the aforementioned dialog
  box telling you about the error.


#### Manual
If `vcpkg` is not available or cannot be found on your system, the build defaults
to a manual specification of dependencies.
You will need to define the following environment variables:
- `CLAMAV_SOURCE`: Points to the directory where the ClamAV source is located.
- `CLAMAV_BUILD`: Points to the ClamAV build directory.
- `OPENSSL_INCLUDE`: Points to the include directory containing `openssl/ssl.h`.

### MacOS
Install the development dependencies via `homebrew`:
```
brew install clamav openssl@1.1
```

OpenSSL is not included in the environment to avoid shadowing Apple's one, so
you need to tell the build script where it is located:
```
export OPENSSL_ROOT_DIR=/usr/local/Cellar/openssl@1.1/1.1.1i/
```

## Versioning
The version number of `libclamav-sys` tracks ClamAV's version number. That is,
you'll require at least ClamAV 1.0.0 to build `libclamav-sys` 1.0.0. As ClamAV
usually doesn't do breaking API changes, you'll be able to use `libclamav-sys`
with newer ClamAV versions.

No attempt at preserving downward compatibility (using a `libclamav-sys` with
a version number greater than ClamAV's) is made.

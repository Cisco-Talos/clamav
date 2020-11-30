# clamav-sys

clamav-sys is a minimal Rust interface around [libclamav](https://www.clamav.net).
This package is not supposed to be used stand-alone, but only through its safe wrapper,
clamav-rs.


## Building

### Unix (anything but Windows)
You should have the `clamav-dev` package of your distribution installed (ClamAV
with headers). The headers and library should be picked up automatically.

### Windows
#### vcpkg
The preferred way of handling dependencies is `vcpkg`.
Point `$env:VCPKG_ROOT` to your `vcpkg` installation, and set
`$env:VCPKGRS_DYNAMIC=1` to use dynamic linking (the default method of linking will
likely not work, as `pdcurses` doesn't support the `x64-windows-static-md` triplet).

See the [vcpkg crate's documentation](https://docs.rs/vcpkg) for more details. 

#### Manual
If `vcpkg` is not available or cannot be found on your system, the build defaults
to a manual specification of dependencies.
You will need to define the following environment variables:
- `CLAMAV_SOURCE`: Points to the directory where the ClamAV source is located.
- `CLAMAV_BUILD`: Points to the ClamAV build directory.
- `OPENSSL_INCLUDE`: Points to the include directory containing `openssl/ssl.h`.


# clamav-sys

clamav-sys is a minimal Rust interface around libclamav](https://www.clamav.net).
This package is not supposed to be used stand-alone, but only through its safe wrapper,
clamav-rs.


## Building

### Unix (anything but Windows)
You should have the `clamav-dev` package of your distribution installed (ClamAV
with headers). The headers and library should be picked up automatically.

### Windows
You will need to define the following environment variables:
- `CLAMAV_SOURCE`: Points to the directory where the ClamAV source is located.
- `CLAMAV_BUILD`: Points to the ClamAV build directory.
- `OPENSSL_INCLUDE`: Points to the include directory containing `openssl/ssl.h`.


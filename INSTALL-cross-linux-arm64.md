# Cross-compiling ClamAV on Linux for arm64

These are instructions to cross-compile ClamAV on Linux amd64 (`x86_64-unknown-linux-gnu`) with GCC for Linux arm64 (`aarch64-unknown-linux-gnu`).

> _Note_: These build instructions were written for Ubuntu. You may need to change a few steps to work with your distro.

## Install build tools, if missing

Install the GCC/G++ and Rust toolchains needed to cross-compile to aarch64:

```bash
# Install toolchain
sudo apt install -y g++-aarch64-linux-gnu
rustup target add aarch64-unknown-linux-gnu
```

## Install build dependencies

If you have a sysroot for your `aarch64-unknown-linux-gnu` target platform with the required dependencies installed, skip this step. Else, do these things to install arm64 (aarch64) versions of the ClamAV library dependencies on the local host.

```bash
sudo dpkg --add-architecture arm64
```

Create a new .list file in `/etc/apt/sources.list.d`:

```bash
sudo vim  /etc/apt/sources.list.d/arm-cross-compile-sources.list
```

Add arm64 package sources to this new list:
```
deb [arch=arm64] http://ports.ubuntu.com/ focal main restricted
deb [arch=arm64] http://ports.ubuntu.com/ focal-updates main restricted
deb [arch=arm64] http://ports.ubuntu.com/ focal universe
deb [arch=arm64] http://ports.ubuntu.com/ focal-updates universe
deb [arch=arm64] http://ports.ubuntu.com/ focal multiverse
deb [arch=arm64] http://ports.ubuntu.com/ focal-updates multiverse
deb [arch=arm64] http://ports.ubuntu.com/ focal-backports main restricted universe multiverse
```

> _Tip_: "focal" is for Ubuntu 20.04LTS. You may need to swap to another to match your release:
> - focal (20.04LTS)
> - jammy (22.04LTS)
> - kinetic (22.10)
> - lunar (23.04)
> - mantic (23.10)
>
> See https://packages.ubuntu.com/ for more.

Now install the arm64 libraries:

```bash
apt-get update && apt-get install -y \
  check:arm64 \
  libbz2-dev:arm64 \
  libcurl4-openssl-dev:arm64 \
  libjson-c-dev:arm64 \
  libmilter-dev:arm64 \
  libncurses5-dev:arm64 \
  libpcre2-dev:arm64 \
  libssl-dev:arm64 \
  libxml2-dev:arm64 \
  zlib1g-dev:arm64
```

After install, the `.a` and `.so` libraries will be found under `/usr/lib/aarch64-linux-gnu/`. The headers are the same as for any other arch, so those will be under `/usr/include/` as per usual.

## Create a CMake toolchain file

A CMake toolchain file specifies some toolchain specific variables.

Note: The `CMAKE_SYSROOT` variable may **not** be set using the `cmake -D CMAKE_SYROOT=PATH` method and must be in this file. Meanwhile, some other variables (namely `CMAKE_INSTALL_PREFIX`) *cannot* be set in the toolchain file, and should be passed as a command parameter.

## Help Cargo find GCC (possibly needed)

On some systems, `cargo` does not find the right GCC executable and emits this error:
```
 = note: cc: error: unrecognized command-line option '-m64'
```

**If** this error occurs during the build, set the following environment variables and then try again:
```sh
export HOST_CC=gcc
export CC_x86_64_unknown_linux_gnu=/usr/bin/x86_64-linux-gnu-gcc
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=/usr/bin/x86_64-linux-gnu-gcc
```

> _Note_: Your specific path to and executable name for GCC may vary depending on your platform.

> _Credit_: [Kornel on Stack Overflow](https://stackoverflow.com/a/72546887/3430496)

### If using a sysroot

`CMAKE_TOOLCHAIN_ARM64.cmake`:
```cmake
# Platform
set(CMAKE_SYSTEM_NAME       Linux)
set(CMAKE_SYSTEM_PROCESSOR  arm64)
set(CMAKE_C_COMPILER        "aarch64-linux-gnu-gcc")
set(CMAKE_CXX_COMPILER      "aarch64-linux-gnu-g++")
set(RUST_COMPILER_TARGET    "aarch64-unknown-linux-gnu")

# Project Variables needed to cross compile
set(HAVE_ATTRIB_ALIGNED     1)
set(HAVE_ATTRIB_PACKED      1)
set(HAVE_UNAME_SYSCALL      1)
set(HAVE_SAR                1)
set(HAVE_FD_PASSING         1)
set(MMAP_FOR_CROSSCOMPILING ON)
set(ENABLE_SYSTEMD          OFF)

set( test_run_result
     "PLEASE_FILL_OUT-FAILED_TO_RUN"
     CACHE STRING "Result from try_run" FORCE)

set( test_run_result__TRYRUN_OUTPUT
     "PLEASE_FILL_OUT-NOTFOUND"
     CACHE STRING "Output from try_run" FORCE)

#
# Dependencies
#

# If using a sysroot / rootfs for the target, set these.
set(CMAKE_SYSROOT           /opt/aarch64-wrs-linux-sysroot)

# If your CMAKE_SYSROOT directory is readonly, or for some reason you want to install to a different staging prefix before copying  to your host, set this:
#set(CMAKE_STAGING_PREFIX    /home/user/stage)

# Note, you may need to set ENABLE_JSON_SHARED if your sysroot provides libjson-c.so instead of libjson-c.a.
#set(ENABLE_JSON_SHARED      ON)

# You may need to set the following if CMake has some trouble finding the dependencies.
# For example if you have `libjson-c.a` in your sysroot, here: `/opt/aarch64-wrs-linux-sysroot/usr/lib64/libjson-c.a`
# then you would set:
#set(JSONC_LIBRARY           "/usr/lib64/libjson-c.a")

#
# Uncomment these as needed:
#
#set(JSONC_INCLUDE_DIR       "/usr/include/json-c")
#set(JSONC_LIBRARY           "/usr/lib64/libjson-c.a")
#set(ENABLE_JSON_SHARED      OFF)

#set(BZIP2_INCLUDE_DIR       "/usr/include/")
#set(BZIP2_LIBRARY_RELEASE   "/usr/lib64/libbz2.a")

#set(OPENSSL_ROOT_DIR        "/usr/")
#set(OPENSSL_INCLUDE_DIR     "/usr/include/")
#set(OPENSSL_CRYPTO_LIBRARY  "/usr/lib64/libcrypto.so")
#set(OPENSSL_SSL_LIBRARY     "/usr/lib64/libssl.so")

#set(LIBXML2_INCLUDE_DIR     "/usr/include/libxml2")
#set(LIBXML2_LIBRARY         "/usr/lib64/libxml2.so")

#set(PCRE2_INCLUDE_DIR       "/usr/include/")
#set(PCRE2_LIBRARY           "/usr/lib64/libpcre2-8.so")

set(NCURSES_INCLUDE_DIR      "/usr/include/")
set(CURSES_LIBRARY          "/usr/lib/aarch64-linux-gnu/libncurses.a")
set(TINFO_LIBRARY           "/usr/lib/aarch64-linux-gnu/libtinfo.a")
# Tip: You may not need to also link with libtinfo.a, depending on what your distribution provides.

# Tip 2: Alternatively, you could link with the shared libraries:
#set(CURSES_LIBRARY          "/usr/lib/aarch64-linux-gnu/libncurses.so")
#set(TINFO_LIBRARY          "/usr/lib/aarch64-linux-gnu/libtinfo.so")

#set(ZLIB_INCLUDE_DIR        "/usr/include/")
#set(ZLIB_LIBRARY            "/usr/lib64/libz.so")

#set(LIBCHECK_INCLUDE_DIR    "/usr/include/")
#set(LIBCHECK_LIBRARY        "/usr/lib64/libcheck.a")
```

### If not using a sysroot

Without a sysroot, you must tell CMake exactly where to find the library dependencies built for aarch64.

> _IMPORTANT_: Without a sysroot, your runtime platform must have these EXACT SAME libraries.

`CMAKE_TOOLCHAIN_ARM64.cmake`:
```cmake
# Platform
set(CMAKE_SYSTEM_NAME       Linux)
set(CMAKE_SYSTEM_PROCESSOR  arm64)
set(CMAKE_C_COMPILER        "aarch64-linux-gnu-gcc")
set(CMAKE_CXX_COMPILER      "aarch64-linux-gnu-g++")
set(RUST_COMPILER_TARGET    "aarch64-unknown-linux-gnu")

# Project Variables needed to cross compile
set(HAVE_ATTRIB_ALIGNED     1)
set(HAVE_ATTRIB_PACKED      1)
set(HAVE_UNAME_SYSCALL      1)
set(HAVE_SAR                1)
set(HAVE_FD_PASSING         1)
set(MMAP_FOR_CROSSCOMPILING ON)
set(ENABLE_SYSTEMD          OFF)

set( test_run_result
     "PLEASE_FILL_OUT-FAILED_TO_RUN"
     CACHE STRING "Result from try_run" FORCE)

set( test_run_result__TRYRUN_OUTPUT
     "PLEASE_FILL_OUT-NOTFOUND"
     CACHE STRING "Output from try_run" FORCE)

#
# Dependencies
#

set(JSONC_INCLUDE_DIR       "/usr/include/json-c")
set(JSONC_LIBRARY           "/usr/lib/aarch64-linux-gnu/libjson-c.a")
set(ENABLE_JSON_SHARED      OFF)

set(BZIP2_INCLUDE_DIR       "/usr/include/")
set(BZIP2_LIBRARY_RELEASE   "/usr/lib/aarch64-linux-gnu/libbz2.a")

set(OPENSSL_ROOT_DIR        "/usr/")
set(OPENSSL_INCLUDE_DIR     "/usr/include/")
set(OPENSSL_CRYPTO_LIBRARY  "/usr/lib/aarch64-linux-gnu/libcrypto.so")
set(OPENSSL_SSL_LIBRARY     "/usr/lib/aarch64-linux-gnu/libssl.so")

set(LIBXML2_INCLUDE_DIR     "/usr/include/libxml2")
set(LIBXML2_LIBRARY         "/usr/lib/aarch64-linux-gnu/libxml2.so")

set(PCRE2_INCLUDE_DIR       "/usr/include/")
set(PCRE2_LIBRARY           "/usr/lib/aarch64-linux-gnu/libpcre2-8.so")

set(NCURSES_INCLUDE_DIR      "/usr/include/")
set(CURSES_LIBRARY          "/usr/lib/aarch64-linux-gnu/libncurses.a")
set(TINFO_LIBRARY           "/usr/lib/aarch64-linux-gnu/libtinfo.a")
# Tip: You may not need to also link with libtinfo.a, depending on what your distribution provides.

# Tip 2: Alternatively, you could link with the shared libraries:
#set(CURSES_LIBRARY          "/usr/lib/aarch64-linux-gnu/libncurses.so")
#set(TINFO_LIBRARY          "/usr/lib/aarch64-linux-gnu/libtinfo.so")

set(ZLIB_INCLUDE_DIR        "/usr/include/")
set(ZLIB_LIBRARY            "/usr/lib/aarch64-linux-gnu/libz.so")

set(LIBCHECK_INCLUDE_DIR    "/usr/include/")
set(LIBCHECK_LIBRARY        "/usr/lib/aarch64-linux-gnu/libcheck.a")
```

## Build ClamAV

You may need to adjust the paths in the command below to suit your needs.

You'll definitely need to set `CMAKE_STAGING_PREFIX` to your own path, or maybe remove it (see the note, below).

You may wish to set `CMAKE_INSTALL_PREFIX` to some directory other than `/usr`

> _Note_: If using a sysroot and `CMAKE_SYSROOT` is set in your `CMAKE_TOOLCHAIN_ARM64.cmake` file, then the `make install` command will install to that sysroot directory. If you want, you can override it with `CMAKE_STAGING_PREFIX`. After the `make install`, it will be on you to copy the stuff from your staging directory to target system. The instructions below do this, because you may not wish to contaminate your sysroot with output from this build, or because your sysroot may be read-only.

```bash
mkdir build-arm64 && cd build-arm64

cmake .. \
    -D CMAKE_TOOLCHAIN_FILE=(pwd)/../CMAKE_TOOLCHAIN_ARM64.cmake \
    -D ENABLE_STATIC_LIB=OFF \
    -D ENABLE_SHARED_LIB=ON \
    -D MAINTAINER_MODE=OFF \
    -D ENABLE_EXAMPLES=OFF \
    -D BYTECODE_RUNTIME=interpreter \
    -D CMAKE_BUILD_TYPE=Release \
    -D CMAKE_INSTALL_PREFIX="/usr" \
    -D CMAKE_STAGING_PREFIX=/home/user/stage/usr

make
make install
```

## Verify it built for right platform

We cannot run the ClamAV unit test suite, because we're cross compiling and can't run the programs we build. But we can do a very small test with the Unix `file` command to see that it built for the right platform. For example:

```bash
file install/bin/clamscan
```

Example output:
`install/bin/clamscan: ELF 64-bit LSB shared object, ARM aarch64, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux-aarch64.so.1, BuildID[sha1]=289a6b738e7421c5bb09c7ee5fc5bb20bfe98025, for GNU/Linux 3.7.0, with debug_info, not stripped`

If everything looks good, you can probably copy the install files to your system and run it.

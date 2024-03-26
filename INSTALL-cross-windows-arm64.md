# Cross-compiling ClamAV on Windows for ARM64

These are instructions to cross-compile ClamAV on Windows x64 (`x86_64-pc-windows-msvc`) with GCC for Linux arm64 (`aarch64-pc-windows-msvc`).

## Install build tools, if missing

Use the Visual Studio Installer tools to add the ARM64 components. E.g. this stuff:
- MSVC v143 - VS 2022 C++ ARM build tools (Latest)
- MSVC v143 - VS 2022 C++ ARM Spectre-mitigated libs (Latest)
- MSVC v143 - VS 2022 C++ ARM64/ARM64EC build tools (Latest)
- MSVC v143 - VS 2022 C++ ARM64/ARM64EC Spectre-mitigated libs (Latest)
- C++ ATL for latest v143 build tools (ARM)
- C++ ATL for latest v143 build tools (ARM64/ARM64EC)
- C++ ATL for latest v143 build tools with Spectre-Mitigations (ARM)
- C++ ATL for latest v143 build tools with Spectre-Mitigations (ARM64/ARM64EC)
- C++ MFC for latest v143 build tools (ARM)
- C++ MFC for latest v143 build tools (ARM64/ARM64EC)
- C++ MFC for latest v143 build tools with Spectre-Mitigations (ARM)
- C++ MFC for latest v143 build tools with Spectre-Mitigations (ARM64/ARM64EC)

Install the Rust toolchains needed to cross-compile to arm64:

```powershell
rustup target add aarch64-pc-windows-msvc
```

## Use Mussels to build ARM64 C-based library dependencies

See the [online documentation regarding building dependencies with Mussels](https://docs.clamav.net/manual/Development/build-installer-packages.html#windows). To build for ARM64, change the commands to build like this:

```powershell
msl build -t arm64 clamav_deps
```

Once the build is complete, you'll find the ARM64 compiled libraries under `~\.mussels\install\arm64\`.

## Create a CMake toolchain file

A CMake toolchain file specifies some toolchain specific variables.

`CMAKE_TOOLCHAIN_ARM64.cmake`:
```cmake
# Platform
set(CMAKE_SYSTEM_NAME       Windows)
set(CMAKE_SYSTEM_PROCESSOR  arm64)
set(RUST_COMPILER_TARGET    "aarch64-pc-windows-msvc")

# Project Variables needed to cross compile
set(HAVE_PRAGMA_PACK        1)
set(HAVE_SAR                1)
set(MMAP_FOR_CROSSCOMPILING OFF)
set(ENABLE_SYSTEMD          OFF)

set( test_run_result
     "PLEASE_FILL_OUT-FAILED_TO_RUN"
     CACHE STRING "Result from try_run" FORCE)

set( test_run_result__TRYRUN_OUTPUT
     "PLEASE_FILL_OUT-NOTFOUND"
     CACHE STRING "Output from try_run" FORCE)
```

## Build ClamAV

You may need to adjust the paths in the command below to suit your needs.

```powershell
mkdir build-arm64
cd build-arm64

cmake .. -G "Visual Studio 17 2022" -A arm64 `
    -D JSONC_INCLUDE_DIR="$HOME\\.mussels\\install\\arm64\\include\\json-c" `
    -D JSONC_LIBRARY="$HOME\\.mussels\\install\\arm64\\lib\\json-c.lib" `
    -D BZIP2_INCLUDE_DIR="$HOME\\.mussels\\install\\arm64\\include" `
    -D BZIP2_LIBRARY_RELEASE="$HOME\\.mussels\\install\\arm64\\lib\\libbz2.lib" `
    -D CURL_INCLUDE_DIR="$HOME\\.mussels\\install\\arm64\\include" `
    -D CURL_LIBRARY="$HOME\\.mussels\\install\\arm64\\lib\\libcurl_imp.lib" `
    -D OPENSSL_ROOT_DIR="$HOME\\.mussels\\install\\arm64\\" `
    -D OPENSSL_INCLUDE_DIR="$HOME\\.mussels\\install\\arm64\\include" `
    -D LIB_EAY_DEBUG="$HOME\\.mussels\\install\\arm64\\lib\\libcrypto.lib" `
    -D SSL_EAY_DEBUG="$HOME\\.mussels\\install\\arm64\\lib\\libssl.lib" `
    -D ZLIB_LIBRARY="$HOME\\.mussels\\install\\arm64\\lib\\libssl.lib" `
    -D LIBXML2_INCLUDE_DIR="$HOME\\.mussels\\install\\arm64\\include\\libxml" `
    -D LIBXML2_LIBRARY="$HOME\\.mussels\\install\\arm64\\lib\\libxml2.lib" `
    -D PCRE2_INCLUDE_DIR="$HOME\\.mussels\\install\\arm64\\include" `
    -D PCRE2_LIBRARY="$HOME\\.mussels\\install\\arm64\\lib\\pcre2-8.lib" `
    -D PDCURSES_INCLUDE_DIR="$HOME\\.mussels\\install\\arm64\\include" `
    -D CURSES_LIBRARY="$HOME\\.mussels\\install\\arm64\\lib\\pdcurses.lib" `
    -D PThreadW32_INCLUDE_DIR="$HOME\\.mussels\\install\\arm64\\include" `
    -D PThreadW32_LIBRARY="$HOME\\.mussels\\install\\arm64\\lib\\pthreadVC3.lib" `
    -D ZLIB_INCLUDE_DIR="$HOME\\.mussels\\install\\arm64\\include" `
    -D ZLIB_LIBRARY="$HOME\\.mussels\\install\\arm64\\lib\\zlibstatic.lib" `
    -D LIBCHECK_INCLUDE_DIR="$HOME\\.mussels\\install\\arm64\\include" `
    -D LIBCHECK_LIBRARY="$HOME\\.mussels\\install\\arm64\\lib\\checkDynamic.lib" `
    -D CMAKE_TOOLCHAIN_FILE=$pwd\\..\\CMAKE_TOOLCHAIN_ARM64.cmake `
    -D ENABLE_STATIC_LIB=OFF `
    -D ENABLE_SHARED_LIB=ON `
    -D MAINTAINER_MODE=OFF `
    -D ENABLE_EXAMPLES=OFF `
    -D BYTECODE_RUNTIME=interpreter `
    -D HAVE_PRAGMA_PACK=1 `
    -D HAVE_SAR=1 `
    -D CMAKE_INSTALL_PREFIX="install"

cmake --build . --config Release --target install
```

## Verify it built for right platform

We cannot run the ClamAV unit test suite, because we're cross compiling and can't run the programs we build. But we can do a very small test to see that it built for the right platform.

Pop into WSL2 (Windows Subsystem for Linux 2) to make use of the `file` utility:

```powershell
❯ wsl
Welcome to fish, the friendly interactive shell
Type `help` for instructions on how to use fish

clamav-micah-2/build-arm64 on  main [$] via C v9.4.0-gcc via △ v3.27.2
❯ file install/clamscan.exe
install/clamscan.exe: PE32+ executable (console) Aarch64, for MS Windows
```

If everything looks good, you can probably copy the install files to your system and run it.

# Installation Instructions

**CAUTION**: ClamAV CMake support is experimental in this release and is not
recommended for production systems!!!

Please help us stabilize it so we can deprecate autotools and Visual Studio.

_Known Issues / To-do:_

- Support for building unit tests / feature tests and running with CTest
  - A portion of this task will involve converting the shell scripts portions
    to Python unit tests.
- Build fuzz targets.
- LLVM bytecode runtime support.
  - Presently only the bytecode intepreter is supported. LLVM is preferable
    because it is faster. This task also requires updating to use a modern
    version of LLVM. Currently ClamAV is limited to LLVM 3.6.
  - The built-in LLVM runtime is not supported in the CMake tooling with no
    plans to add support. It will likely be removed when system-LLVM support
    is updated.
- Complete the MAINTAINER_MODE option to generate jsparse files with GPerf.

- [Installation Instructions](#installation-instructions)
  - [CMake Basics](#cmake-basics)
    - [Basic Release build & system install](#basic-release-build--system-install)
    - [Basic Debug build](#basic-debug-build)
    - [Build and install to a specific install location (prefix)](#build-and-install-to-a-specific-install-location-prefix)
    - [Build using Ninja](#build-using-ninja)
    - [Build and run tests](#build-and-run-tests)
  - [Custom CMake options](#custom-cmake-options)
  - [Custom Library Paths](#custom-library-paths)
    - [Example Build Commands](#example-build-commands)
      - [Linux release build, install to system](#linux-release-build-install-to-system)
      - [macOS debug build, custom OpenSSL path, build examples, local install](#macos-debug-build-custom-openssl-path-build-examples-local-install)
      - [Windows Build](#windows-build)
    - [External Depedencies](#external-depedencies)
      - [libclamav dependencies](#libclamav-dependencies)
      - [libfreshclam dependencies](#libfreshclam-dependencies)
      - [Application dependencies](#application-dependencies)
      - [Dependency build options](#dependency-build-options)
        - [bzip2](#bzip2)
        - [zlib](#zlib)
        - [libxml2](#libxml2)
        - [libpcre2](#libpcre2)
        - [openssl (libcrypto, libssl)](#openssl-libcrypto-libssl)
        - [libjson-c](#libjson-c)
        - [libmspack](#libmspack)
        - [iconv (POSIX-only)](#iconv-posix-only)
        - [pthreads-win32 (Windows-only)](#pthreads-win32-windows-only)
        - [llvm (optional, _see "Bytecode Runtime" section_)](#llvm-optional-see-bytecode-runtime-section)
        - [libcurl](#libcurl)
        - [ncurses or pdcurses, for clamdtop](#ncurses-or-pdcurses-for-clamdtop)
        - [Bytecode Runtime](#bytecode-runtime)
  - [Compilers and Options](#compilers-and-options)
  - [Compiling For Multiple Architectures](#compiling-for-multiple-architectures)

## CMake Basics

Build requirements:

- CMake 3.13+
- A C-toolchain such as gcc, clang, or Microsoft Visual Studio.
- Flex and Bison. On Windows, `choco install winflexbison`.

_Important_: The following instructions assume that you have created a `build`
subdirectory and that subsequent commands are performed from said directory,
like so:

```sh
mkdir build && cd build
```

### Basic Release build & system install

```sh
cmake .. -DCMAKE_BUILD_TYPE="Release"
cmake --build . --config Release
sudo cmake --build . --config Release --target install
```

### Basic Debug build

In CMake, "Debug" builds mean that symbols are compiled in.

```sh
cmake .. -DCMAKE_BUILD_TYPE="Debug"
cmake --build . --config Debug
```

You will likely also wish to disable compiler/linker optimizations, which you
can do like so, using our custom `OPTIMIZE` option:

```sh
cmake .. -DCMAKE_BUILD_TYPE="Debug" -DOPTIMIZE=OFF
cmake --build . --config Debug
```

### Build and install to a specific install location (prefix)

```sh
cmake -DCMAKE_INSTALL_PREFIX:PATH=install ..
cmake --build . --target install --config Release
```

### Build using Ninja

This build uses Ninja (ninja-build) instead of Make. It's _really_ fast.

```sh
cmake .. -G Ninja
cmake --build . --config Release
```

### Build and run tests

_TODO_: We have not yet added unit test support for CMake.

- `-V`: Verbose

- `-C <config>`: Specify build configuration (i.e. Debug / Release), required
                 for Windows builds

```sh
cmake ..
cmake --build . --config Release
ctest -C Release -V
```

## Custom CMake options

The following CMake options can be selected by using `-D`. For example:

```sh
cmake .. -DENABLE_EXAMPLES
cmake --build . --config Debug
```

- `APP_CONFIG_DIRECTORY`: App Config directory.

  _Default: Windows: `{prefix}`, POSIX: `{prefix}/etc`_

- `DATABASE_DIRECTORY`: Database directory.

  _Default: Windows: `{prefix}/database`, POSIX: `{prefix}/share/clamav`_

- `CLAMAV_USER`: ClamAV User (POSIX-only).

  _Default: `clamav`_

- `CLAMAV_GROUP`: ClamAV Group (POSIX-only).

  _Default: `clamav`_

- `MMAP_FOR_CROSSCOMPILING`: Force MMAP support for cross-compiling.

  _Default: `OFF`_

- `DISABLE_MPOOL`: Disable mpool support entirely.

  _Default: `OFF`_

- `BYTECODE_RUNTIME`: Bytecode Runtime, may be: `llvm`, `interpreter`, `none`.

  _Default: `interpreter`_

- `OPTIMIZE`: Allow compiler optimizations (eg. `-O3`). Set to `OFF` to disable
  them (`-O0`).

  _Default: `ON`_

- `ENABLE_WERROR`: Compile time warnings will cause build failures (i.e.
  `-Werror`)

  _Default: `OFF`_

- `ENABLE_ALL_THE_WARNINGS`: By default we use `-Wall -Wextra -Wformat-security`
  for clamav libs and apps. This option enables a whole lot more.

  _Default: `OFF`_

- `ENABLE_DEBUG`: Turn on extra debug output.

  _Default: `OFF`_

- `ENABLE_FUZZ`: Build fuzz targets. Will enable `ENABLE_STATIC_LIB` for you.

  _Default: `OFF`_

- `ENABLE_EXTERNAL_MSPACK`: Use external mspack instead of internal libclammspack.

  _Default: `OFF`_

- `ENABLE_JSON_SHARED`: Prefer linking with libjson-c shared library instead of
  static. Please set this to `OFF` if you're an application developer that uses
  a different JSON library in your app, or if you provide libclamav to others.

  _Default: `ON`_

- `ENABLE_APP`: Build applications (clamscan, clamd, clamdscan, sigtool,
  clambc, clamdtop, clamsubmit, clamconf).

  _Default: `ON`_

- `ENABLE_CLAMONACC`: (Linux-only) Build the clamonacc on-access scanning daemon.
  Requires: `ENABLE_APP`

  _Default: `ON`_

- `ENABLE_MILTER`: (Posix-only) Build the clamav-milter mail filter daemon.
  Requires: `ENABLE_APP`

  _Default: `OFF`_

- `ENABLE_UNRAR`: Build & install libclamunrar (UnRAR) and libclamunrar_iface.

  _Default: `ON`_

- `ENABLE_DOCS`: Generate man pages.

  _Default: `OFF`_

- `ENABLE_DOXYGEN`: Generate doxygen HTML documentation for clamav.h,
  libfreshclam.h. Requires doxygen.

  _Default: `OFF`_

- `ENABLE_EXAMPLES`: Build examples.

  _Default: `OFF`_

- `ENABLE_LIBCLAMAV_ONLY`: Build libclamav only. Excludes libfreshclam too!

  _Default: `OFF`_

- `ENABLE_STATIC_LIB`: Build libclamav and/or libfreshclam static libraries.

  _Default: `OFF`_

- `ENABLE_SHARED_LIB`: Build libclamav and/or libfreshclam shared libraries.

  _Default: `ON`_

- `ENABLE_SYSTEMD`: Install systemd service files if systemd is found.

  _Default: `ON`_

- `MAINTAINER_MODE`: Generate Yara lexer and grammar C source with Flex & Bison.
  TODO: Also generate JS parse source with Gperf.

  _Default: `OFF`_

- `SYSTEMD_UNIT_DIR`: Install systemd service files to a specific directory.
  This will fail the build if systemd not found.

  _Default: not set_

## Custom Library Paths

### Example Build Commands

#### Linux release build, install to system

This example sets the build system to Ninja instead of using Make, for speed.
You may need to first use `apt`/`dnf`/`pkg` to install `ninja-build`

```sh
cmake .. -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DENABLE_JSON_SHARED=OFF
ninja
sudo ninja install
```

#### macOS debug build, custom OpenSSL path, build examples, local install

macOS builds use Homebrew to install `flex`, `bison`, and each of the library
dependencies.

Note that explicit paths for OpenSSL are requires so as to avoid using an older
OpenSSL install provided by the operating system.

This example also:

- Build system to Ninja instead of using Make.
  - You may need to first use `brew` to install `ninja`.
- Sets build type to "Debug" and explicitly disables compiler optimizations.
- Builds static libraries (and also shared libraries, which are on by default).
- Builds the example programs, just to test them out.
- Sets the install path (prefix) to ./install

```sh
cmake .. -G Ninja                                                              \
  -DCMAKE_BUILD_TYPE=Debug                                                     \
  -DOPTIMIZE=OFF                                                               \
  -DENABLE_JSON_SHARED=OFF                                                     \
  -DOPENSSL_ROOT_DIR=/usr/local/opt/openssl@1.1/                               \
  -DOPENSSL_CRYPTO_LIBRARY=/usr/local/opt/openssl@1.1/lib/libcrypto.1.1.dylib  \
  -DOPENSSL_SSL_LIBRARY=/usr/local/opt/openssl@1.1/lib/libssl.1.1.dylib        \
  -DENABLE_STATIC_LIB=ON                                                       \
  -DENABLE_EXAMPLES=ON                                                         \
  -DCMAKE_INSTALL_PREFIX=install
ninja
ninja install
```

#### Windows Build

Chocolatey (`choco`) is used to install `winflexbison` and `cmake`.
Visual Studio 2015+ is required, 2017+ recommended.

These instructions assume that `$env:CLAMAV_DEPENDENCIES` is set to your
[Mussels](https://github.com/Cisco-Talos/Mussels) `install\x64` directory and
that you've used Mussels to build the `clamav_deps` collection which will
provide the required libraries.

_Tip_: Instead of building manually, try using Mussels to automate your build!

```ps1
$env:CLAMAV_DEPENDENCIES="$env:userprofile\.mussels\install\x64"
cmake ..  -G "Visual Studio 15 2017" -A x64 `
    -DJSONC_INCLUDE_DIR="$env:CLAMAV_DEPENDENCIES\include\json-c"         `
    -DJSONC_LIBRARY="$env:CLAMAV_DEPENDENCIES\lib\json-c.lib"             `
    -DBZIP2_INCLUDE_DIR="$env:CLAMAV_DEPENDENCIES\include"                `
    -DBZIP2_LIBRARY_RELEASE="$env:CLAMAV_DEPENDENCIES\lib\libbz2.lib"     `
    -DCURL_INCLUDE_DIR="$env:CLAMAV_DEPENDENCIES\include"                 `
    -DCURL_LIBRARY="$env:CLAMAV_DEPENDENCIES\lib\libcurl_imp.lib"         `
    -DOPENSSL_ROOT_DIR="$env:CLAMAV_DEPENDENCIES"                         `
    -DOPENSSL_INCLUDE_DIR="$env:CLAMAV_DEPENDENCIES\include"              `
    -DOPENSSL_CRYPTO_LIBRARY="$env:CLAMAV_DEPENDENCIES\lib\libcrypto.lib" `
    -DZLIB_LIBRARY="$env:CLAMAV_DEPENDENCIES\lib\libssl.lib"              `
    -DLIBXML2_INCLUDE_DIR="$env:CLAMAV_DEPENDENCIES\include"              `
    -DLIBXML2_LIBRARY="$env:CLAMAV_DEPENDENCIES\lib\libxml2.lib"          `
    -DPCRE2_INCLUDE_DIR="$env:CLAMAV_DEPENDENCIES\include"                `
    -DPCRE2_LIBRARY="$env:CLAMAV_DEPENDENCIES\lib\pcre2-8.lib"            `
    -DCURSES_INCLUDE_DIR="$env:CLAMAV_DEPENDENCIES\include"               `
    -DCURSES_LIBRARY="$env:CLAMAV_DEPENDENCIES\lib\pdcurses.lib"          `
    -DPThreadW32_INCLUDE_DIR="$env:CLAMAV_DEPENDENCIES\include"           `
    -DPThreadW32_LIBRARY="$env:CLAMAV_DEPENDENCIES\lib\pthreadVC2.lib"    `
    -DZLIB_INCLUDE_DIR="$env:CLAMAV_DEPENDENCIES\include"                 `
    -DZLIB_LIBRARY="$env:CLAMAV_DEPENDENCIES\lib\zlibstatic.lib"          `
    -DCMAKE_INSTALL_PREFIX="install"
cmake --build . --config Release --target install
copy $env:CLAMAV_DEPENDENCIES\lib\* .\install
```

_Tip_: If you're having include-path issues, try building with detailed verbosity:

```ps1
cmake --build . --config Release --target install -- /verbosity:detailed
```

### External Depedencies

The CMake tooling is good about finding installed dependencies on POSIX systems.

_Important_: Linux users will want the "-dev" or "-devel" package variants
which include C headers. For macOS, Homebrew doesn't separate the headers.

#### libclamav dependencies

App developers that only need libclamav can use the `-DENABLE_LIBCLAMAV_ONLY`
option to bypass ClamAV app dependencies.

libclamav requires these library dependencies:

- bzip2
- zlib
- libxml2
- libpcre2
- openssl
- libjson-c
- iconv (POSIX-only, may be provided by system)
- pthreads (or on Windows: pthreads-win32)
- llvm (optional, _see [Bytecode Runtime](#bytecode-runtime))

#### libfreshclam dependencies

If you want libclamav _and_ libfreshclam for your app, then use the
`-DENABLE_APP=OFF` option instead.

libfreshclam adds these additional library dependencies:

- libcurl

#### Application dependencies

For regular folk who want the ClamAV apps, you'll also need:

- ncurses (or pdcurses), for clamdtop.
- systemd, so clamd, freshclam, clamonacc may run as a systemd service (Linux).
- libsystemd, so clamd will support the clamd.ctl socket (Linux).

#### Dependency build options

If you have custom install paths for the dependencies on your system or are
on Windows, you may need to use the following options...

##### bzip2

```sh
  -DBZIP2_INCLUDE_DIR="_filepath of bzip2 header directory_"
  -DBZIP2_LIBRARIES="_filepath of bzip2 library_"
```

##### zlib

```sh
  -DZLIB_INCLUDE_DIR="_filepath of zlib header directory_"
  -DZLIB_LIBRARY="_filepath of zlib library_"
```

##### libxml2

```sh
  -DLIBXML2_INCLUDE_DIR="_filepath of libxml2 header directory_"
  -DLIBXML2_LIBRARY="_filepath of libxml2 library_"
```

##### libpcre2

```sh
  -DPCRE2_INCLUDE_DIR="_filepath of libpcre2 header directory_"
  -DPCRE2_LIBRARY="_filepath of libcpre2 library_"
```

##### openssl (libcrypto, libssl)

Hints to find openssl package:

```sh
  -DOPENSSL_ROOT_DIR="_path to openssl install root_"
```

```sh
  -DOPENSSL_INCLUDE_DIR="_filepath of openssl header directory_"
  -DOPENSSL_CRYPTO_LIBRARY="_filepath of libcrypto library_"
  -DOPENSSL_SSL_LIBRARY="_filepath of libcrypto library_"
```

##### libjson-c

Tip: You're strongly encouraged to link with the a static json-c library.

```sh
  -DJSONC_INCLUDE_DIR="_path to json-c header directory_"
  -DJSONC_LIBRARY="_filepath of json-c library_"
```

##### libmspack

These options only apply if you use the `-DENABLE_EXTERNAL_MSPACK=ON` option.

```sh
  -DMSPack_INCLUDE_DIR="_path to mspack header directory_"
  -DMSPack_LIBRARY="_filepath of libmspack library_"
```

##### iconv (POSIX-only)

On POSIX platforms, iconv might be part of the C library in which case you
would not want to specify an external iconv library.

```sh
  -DIconv_INCLUDE_DIR="_path to iconv header directory_"
  -DIconv_LIBRARY="_filepath of iconv library_"
```

##### pthreads-win32 (Windows-only)

On POSIX platforms, pthread support is detected automatically.  On Windows, you
need to specify the following:

```sh
  -DPThreadW32_INCLUDE_DIR="_path to pthread-win32 header directory_"
  -DPThreadW32_LIBRARY="_filepath of pthread-win32 library_"
```

##### llvm (optional, _see "Bytecode Runtime" section_)

```sh
  -DBYTECODE_RUNTIME="llvm"
  -DLLVM_ROOT_DIR="_path to llvm install root_" -DLLVM_FIND_VERSION="3.6.0"
```

##### libcurl

```sh
  -DCURL_INCLUDE_DIR="_path to curl header directory_"
  -DCURL_LIBRARY="_filepath of curl library_"
```

##### ncurses or pdcurses, for clamdtop

```sh
  -DCURSES_INCLUDE_DIR="_path to curses header directory_"
  -DCURSES_LIBRARY="_filepath of curses library_"
```

##### Bytecode Runtime

Bytecode signatures are a type of executable plugin that provide extra
detection capabilities.

ClamAV has two bytecode runtimes:

- *LLVM*: LLVM is the preferred runtime.

  With LLVM, ClamAV JIT compiles bytecode signatures at database load time.
  Bytecode signature execution is faster with LLVM.

- *Interpreter*: The bytecode interpreter is an option on systems where a
  a supported LLVM version is not available.

  With the interpreter, signature database (re)loads are faster, but execution
  time is slower.

At the moment, the interpreter is the default runtime, while we work out
compatibility issues with libLLVM. This default equates to:

```sh
cmake .. -DBYTECODE_RUNTIME="interpreter"
```

To build using LLVM instead of the intereter, use:

```sh
cmake .. \
  -DBYTECODE_RUNTIME="llvm"       \
  -DLLVM_ROOT_DIR="/opt/llvm/3.6" \
  -DLLVM_FIND_VERSION="3.6.0"
```

To disable bytecode signature support entire, you may build with this option:

```sh
cmake .. -DBYTECODE_RUNTIME="none"
```

## Compilers and Options

_TODO_: Describe how to customize compiler toolchain with CMake.

## Compiling For Multiple Architectures

_TODO_: Describe how to cross-compile with CMake.

# Installation Instructions

CMake the preferred build system going forwards. The Windows Visual Studio
solution has been removed, and the Autotools build system will likely be
removed in the near future.

_Known Issues / To-do:_

- LLVM bytecode runtime support.
  - Presently only the bytecode intepreter is supported. LLVM is preferable
    because it is faster. This task also requires updating to use a modern
    version of LLVM. Currently ClamAV is limited to LLVM 3.6.
  - The built-in LLVM runtime is not supported in the CMake tooling with no
    plans to add support. It will likely be removed when system-LLVM support
    is updated.
- Complete the MAINTAINER_MODE option to generate jsparse files with GPerf.

**Table Of Contents**

- [Installation Instructions](#installation-instructions)
  - [CMake Basics](#cmake-basics)
    - [Build requirements](#build-requirements)
    - [Optional build requirements (Maintainer-Mode)](#optional-build-requirements-maintainer-mode)
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
      - [Windows builds](#windows-builds)
        - [Windows build (with Mussels)](#windows-build-with-mussels)
        - [Windows build (with vcpkg)](#windows-build-with-vcpkg)
        - [Build the Installer](#build-the-installer)
    - [External Depedencies](#external-depedencies)
      - [libclamav dependencies](#libclamav-dependencies)
      - [libfreshclam dependencies](#libfreshclam-dependencies)
      - [Application dependencies](#application-dependencies)
      - [Dependency build options](#dependency-build-options)
        - [`libcheck`](#libcheck)
        - [`bzip2`](#bzip2)
        - [`zlib`](#zlib)
        - [`libxml2`](#libxml2)
        - [`libpcre2`](#libpcre2)
        - [`openssl` (`libcrypto`, `libssl`)](#openssl-libcrypto-libssl)
        - [`libjson-c`](#libjson-c)
        - [`libmspack`](#libmspack)
        - [`iconv` (POSIX-only)](#iconv-posix-only)
        - [`pthreads-win32` (Windows-only)](#pthreads-win32-windows-only)
        - [`llvm` (optional, _see "Bytecode Runtime" section_)](#llvm-optional-see-bytecode-runtime-section)
        - [`libcurl`](#libcurl)
        - [`ncurses` or `pdcurses`, for `clamdtop`](#ncurses-or-pdcurses-for-clamdtop)
        - [Bytecode Runtime](#bytecode-runtime)
  - [Compilers and Options](#compilers-and-options)
  - [Compiling For Multiple Architectures](#compiling-for-multiple-architectures)

## CMake Basics

### Build requirements

- CMake 3.14+
- A C compiler toolchain such as gcc, clang, or Microsoft Visual Studio.
- Python 3 (to run the test suite)

### Optional build requirements (Maintainer-Mode)

- GPerf, Flex and Bison. On Windows, `choco install winflexbison`.

**_Important_**: The following instructions assume that you have created a `build`
subdirectory and that subsequent commands are performed from said directory,
like so:

```sh
mkdir build && cd build
```

### Basic Release build & system install

```sh
cmake .. -D CMAKE_BUILD_TYPE="Release"
cmake --build . --config Release
sudo cmake --build . --config Release --target install
```

### Basic Debug build

In CMake, "Debug" builds mean that symbols are compiled in.

```sh
cmake .. -D CMAKE_BUILD_TYPE="Debug"
cmake --build . --config Debug
```

You will likely also wish to disable compiler/linker optimizations, which you
can do like so, using our custom `OPTIMIZE` option:

```sh
cmake .. -D CMAKE_BUILD_TYPE="Debug" -D OPTIMIZE=OFF
cmake --build . --config Debug
```

_Tip_: CMake provides four build configurations which you can set using the
`CMAKE_BUILD_TYPE` variable or the `--config` (`-C`) command line option.
These are:
- `Debug`
- `Release`
- `MinSizeRel`
- `RelWithDebInfo`

For multi-config generators, such as "Visual Studio" and "Ninja Multi-Config",
you should not specify the config when you initially configure the project but
you _will_ need to specify the config when you build the project and when
running `ctest` or `cpack`.

For single-config generators, such as "Make" or "Ninja", you will need to
specify the config when you configure the project, and should _not_ specify the
config when you build the project or run `ctest`.

### Build and install to a specific install location (prefix)

```sh
cmake -D CMAKE_INSTALL_PREFIX:PATH=install ..
cmake --build . --target install --config Release
```

### Build using Ninja

This build uses Ninja (ninja-build) instead of Make. It's _really_ fast.

```sh
cmake .. -G Ninja
cmake --build . --config Release
```

### Build and run tests

The option to build and run tests is enabled by default, which requires that
you provide libcheck (i.e. `check`, `check-devel`, `check-dev`, etc).

If you're building with `ENABLE_LIBCLAMAV_ONLY=ON` or `ENABLE_APP=OFF`, then
libcheck will still be required and you can still run the tests, but it will
skip all app tests and only run the libclamav unit tests.

If you wish to disable test support, then configure with `-D ENABLE_TESTS=OFF`.


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
cmake .. -D ENABLE_EXAMPLES
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

- `ENABLE_FUZZ`: Build statically linked fuzz targets _and nothing else_.
  This feature is for fuzzing with OSS-Fuzz and reproducing fuzz bug reports
  and requires the following environment variables to be set:
  - CC = `which clang`
  - CXX = `which clang++`
  - SANITIZER = "address" _or_ "undefined" _or_ "memory"

  _Default: `OFF`_

- `ENABLE_EXTERNAL_MSPACK`: Use external mspack instead of internal libclammspack.

  _Default: `OFF`_

- `ENABLE_JSON_SHARED`: Prefer linking with libjson-c shared library instead of
  static.

  **Important**: Please set this to `OFF` if you're an application developer
  that uses a different JSON library in your app _OR_ if you provide libclamav
  that others may use in their apps. If you link libclamav with the json-c
  shared library then downstream applications which use a different JSON
  library may crash!

  _Default: `ON`_

- `ENABLE_APP`: Build applications (clamscan, clamd, clamdscan, sigtool,
  clambc, clamdtop, clamsubmit, clamconf).

  _Default: `ON`_

- `ENABLE_CLAMONACC`: (Linux-only) Build the clamonacc on-access scanning daemon.
  Requires: `ENABLE_APP`

  _Default: `ON`_

- `ENABLE_MILTER`: (Posix-only) Build the clamav-milter mail filter daemon.
  Requires: `ENABLE_APP`

  _Default: `OFF` for Mac & Windows, `ON` for Linux/Unix_

- `ENABLE_UNRAR`: Build & install libclamunrar (UnRAR) and libclamunrar_iface.

  _Default: `ON`_

- `ENABLE_MAN_PAGES`: Generate man pages.

  _Default: `OFF`_

- `ENABLE_DOXYGEN`: Generate doxygen HTML documentation for clamav.h,
  libfreshclam.h. Requires doxygen.

  _Default: `OFF`_

- `ENABLE_EXAMPLES`: Build examples.

  _Default: `OFF`_

- `ENABLE_TESTS`: Build examples.

  _Default: `ON`_

- `ENABLE_LIBCLAMAV_ONLY`: Build libclamav only. Excludes libfreshclam too!

  _Default: `OFF`_

- `ENABLE_STATIC_LIB`: Build libclamav and/or libfreshclam static libraries.

  Tip: If you wish to build `clamscan` and the other apps statically, you must
  also set ENABLE_SHARED_LIB=OFF.

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

This example sets the build generator to Ninja instead of using Make, for speed.
You may need to first use `apt`/`dnf`/`pkg` to install `ninja-build`

```sh
cmake .. -G Ninja \
  -D CMAKE_BUILD_TYPE=Release \
  -D ENABLE_JSON_SHARED=OFF
ninja
sudo ninja install
```

#### macOS debug build, custom OpenSSL path, build examples, local install

For macOS builds, we recommend using Homebrew to install the build tools, such
as `cmake`, `flex`, `bison`, as well as ClamAV's library dependencies.

Note that explicit paths for OpenSSL are requires so as to avoid using an older
OpenSSL install provided by the operating system.

This example also:
- Sets the build generator to Ninja instead of using Make.
  - You may need to first use `brew` to install `ninja`.
- Sets build config to "Debug" and explicitly disables compiler optimizations.
- Builds static libraries (and also shared libraries, which are on by default).
- Builds the example programs, just to test them out.
- Sets the install path (prefix) to `./install`.

```sh
cmake .. -G Ninja                                                             \
  -D CMAKE_BUILD_TYPE=Debug                                                    \
  -D OPTIMIZE=OFF                                                              \
  -D ENABLE_JSON_SHARED=OFF                                                    \
  -D OPENSSL_ROOT_DIR=/usr/local/opt/openssl@1.1/                              \
  -D OPENSSL_CRYPTO_LIBRARY=/usr/local/opt/openssl@1.1/lib/libcrypto.1.1.dylib \
  -D OPENSSL_SSL_LIBRARY=/usr/local/opt/openssl@1.1/lib/libssl.1.1.dylib       \
  -D ENABLE_STATIC_LIB=ON                                                      \
  -D ENABLE_EXAMPLES=ON                                                        \
  -D CMAKE_INSTALL_PREFIX=install
ninja
ninja install
```

#### Windows builds

At a minimum you will need Visual Studio 2015 or newer, and CMake.
If you want to build the installer, you'll also need WiX Toolset.

If you're using Chocolatey, you can install CMake and WiX simply like this:

```ps1
choco install cmake wixtoolset
```

Then open a new terminal so that CMake and WiX will be in your `$PATH`.
**The following commands for building on Windows are written for Powershell**.

There are two options for building and supplying the library dependencies.
These are Mussels and vcpkg.

Mussels is an open source project developed in-house by the ClamAV team.
It offers great flexibility for defining your own collections (cookbooks) of
build instructions (recipes) instead of solely relying on a centralized
repository of ports. And unlike vcpkg, Mussels does not implement CMake build
tooling for projects that don't support CMake, but instead leverages whatever
build system is provided by the project. This means that Mussels builds may
require installing additional tools, like NMake and ActivePerl rather than
simply requiring CMake. The advantage is that you'll be building those projects
the same way that those developers intended, and that Mussels recipes are
generally very light weight. Mussels has some sharp edges because it's a newer
and much smaller project than vcpkg.

Vcpkg is an open source project developed by Microsoft and is heavily oriented
towards CMake projects. Vcpkg offers a very large collection of "ports" for
almost any project you may need to build.
It is very easy to get started with vcpkg.

Mussels is the preferred tool to supply the library dependencies at least until
such time as the vcpkg Debug-build libclamav unit test heap-corruption crash
is resolved [(see below)](#windows-build-with-vcpkg).

##### Windows build (with Mussels)

Much like `vcpkg`, [Mussels](https://github.com/Cisco-Talos/Mussels) can be
used to automatically build the ClamAV library dependencies. Unlike `vcpkg`,
Mussels does not provide a mechanism for CMake to automatically detect the
library paths.

**Preprequisites:**

To build the library dependencies with Mussels, use Python's `pip` package
manager to install Mussels:

```ps1
python3 -m pip install mussels
```

Update the Mussels cookbooks to get the latest build recipes and set the
`clamav` cookbook to be trusted:

```ps1
msl update
msl cookbook trust clamav
```

Use `msl list` if you wish to see the recipes provided by the `clamav` cookbook.

**Building the libraries and ClamAV:**

Build the `clamav_deps` recipe to compile ClamAV's library dependencies.
By default, Mussels will install them to `~\.mussels\install\<target>`

```ps1
msl build clamav_deps
```

Next, set `$env:CLAMAV_DEPENDENCIES` to the location where Mussels built your
library dependencies:

```ps1
$env:CLAMAV_DEPENDENCIES="$env:userprofile\.mussels\install\x64"
```

To configure the project, run:

```ps1
cmake ..  -G "Visual Studio 15 2017" -A x64 `
  -D JSONC_INCLUDE_DIR="$env:CLAMAV_DEPENDENCIES\include\json-c"         `
  -D JSONC_LIBRARY="$env:CLAMAV_DEPENDENCIES\lib\json-c.lib"             `
  -D ENABLE_JSON_SHARED=OFF                                              `
  -D BZIP2_INCLUDE_DIR="$env:CLAMAV_DEPENDENCIES\include"                `
  -D BZIP2_LIBRARY_RELEASE="$env:CLAMAV_DEPENDENCIES\lib\libbz2.lib"     `
  -D CURL_INCLUDE_DIR="$env:CLAMAV_DEPENDENCIES\include"                 `
  -D CURL_LIBRARY="$env:CLAMAV_DEPENDENCIES\lib\libcurl_imp.lib"         `
  -D OPENSSL_ROOT_DIR="$env:CLAMAV_DEPENDENCIES"                         `
  -D OPENSSL_INCLUDE_DIR="$env:CLAMAV_DEPENDENCIES\include"              `
  -D OPENSSL_CRYPTO_LIBRARY="$env:CLAMAV_DEPENDENCIES\lib\libcrypto.lib" `
  -D OPENSSL_SSL_LIBRARY="$env:CLAMAV_DEPENDENCIES\lib\libssl.lib"       `
  -D ZLIB_LIBRARY="$env:CLAMAV_DEPENDENCIES\lib\libssl.lib"              `
  -D LIBXML2_INCLUDE_DIR="$env:CLAMAV_DEPENDENCIES\include"              `
  -D LIBXML2_LIBRARY="$env:CLAMAV_DEPENDENCIES\lib\libxml2.lib"          `
  -D PCRE2_INCLUDE_DIR="$env:CLAMAV_DEPENDENCIES\include"                `
  -D PCRE2_LIBRARY="$env:CLAMAV_DEPENDENCIES\lib\pcre2-8.lib"            `
  -D CURSES_INCLUDE_DIR="$env:CLAMAV_DEPENDENCIES\include"               `
  -D CURSES_LIBRARY="$env:CLAMAV_DEPENDENCIES\lib\pdcurses.lib"          `
  -D PThreadW32_INCLUDE_DIR="$env:CLAMAV_DEPENDENCIES\include"           `
  -D PThreadW32_LIBRARY="$env:CLAMAV_DEPENDENCIES\lib\pthreadVC2.lib"    `
  -D ZLIB_INCLUDE_DIR="$env:CLAMAV_DEPENDENCIES\include"                 `
  -D ZLIB_LIBRARY="$env:CLAMAV_DEPENDENCIES\lib\zlibstatic.lib"          `
  -D LIBCHECK_INCLUDE_DIR="$env:CLAMAV_DEPENDENCIES\include"             `
  -D LIBCHECK_LIBRARY="$env:CLAMAV_DEPENDENCIES\lib\checkDynamic.lib"    `
  -D CMAKE_INSTALL_PREFIX="install"
```

Now, go ahead and build the project:

```ps1
cmake --build . --config Release
```

_Tip_: If you're having include-path issues when building, try building with
detailed verbosity so you can verify that the paths are correct:

```ps1
cmake --build . --config Release -- /verbosity:detailed
```

You can run the test suite with CTest:

```ps1
ctest -C Release
```

And you can install to the `install` (set above) like this:

```ps1
cmake --build . --config Release --target install
```

##### Windows build (with vcpkg)

`vcpkg` can be used to build the ClamAV library dependencies automatically.

`vcpkg` integrates really well with CMake, enabling CMake to find your compiled
libraries automatically, so you don't have to specify the include & library
paths manually as you do when using Mussels.

_DISCLAIMER_: There is a known issue with the unit tests when building with
vcpkg in Debug mode. When you run the libclamav unit tests (check_clamav), the
program will crash and a popup will claim there was heap corruption. If you use
Task Manager to kill the `check_clamav.exe` process, the rest of the tests pass
just fine. This issue does not occur when using Mussels to supply the library
dependencies. Commenting out the following lines in `readdb.c` resolves the
heap corruption crash when running `check_clamav`, but of course introduces a
memory leak:
```c
    if (engine->stats_data)
        free(engine->stats_data);
```
If anyone has time to figure out the real cause of the vcpkg Debug-build crash
in check_clamav, it would be greatly appreciated.

**Preprequisites:**

You'll need to install [vcpkg](https://github.com/microsoft/vcpkg).
See the `vcpkg` README for installation instructions.

Once installed, set the variable `$VCPKG_PATH` to the location where you
installed `vcpkg`:

```ps1
$VCPKG_PATH="..." # Path to your vcpkg installation
```

By default, CMake and `vcpkg` build for 32-bit. If you want to build for 64-bit,
set the `VCPKG_DEFAULT_TRIPLET` environment variable:

```ps1
$env:VCPKG_DEFAULT_TRIPLET="x64-windows"
```

**Building the libraries and ClamAV:**

Next, use `vcpkg` to build the required library dependencies:

```ps1
& "$VCPKG_PATH\vcpkg" install 'curl[openssl]' 'json-c' 'libxml2' 'pcre2' 'pthreads' 'zlib' 'pdcurses' 'bzip2' 'check'
```

Now configure the ClamAV build using the `CMAKE_TOOLCHAIN_FILE` variable which
will enable CMake to automatically find the libraries we built with `vcpkg`.

```ps1
cmake .. -A x64 `
  -D CMAKE_TOOLCHAIN_FILE="$VCPKG_PATH\scripts\buildsystems\vcpkg.cmake" `
  -D CMAKE_INSTALL_PREFIX="install"
```

_Tip_: You have to drop the `-A x64` arguments if you're building for 32-bits,
and correct the package paths accordingly.

Now, go ahead and build the project:

```ps1
cmake --build . --config Release
```

You can run the test suite with CTest:

```ps1
ctest -C Release
```

And you can install to the `install` directory (set above) like this:

```ps1
cmake --build . --config Release --target install
```

##### Build the Installer

To build the installer, you must have WIX Toolset installed. If you're using
Chocolatey, you can install it simply with `choco install wixtoolset` and then
open a new terminal so that WIX will be in your PATH.

```ps1
cpack -C Release
```

### External Depedencies

The CMake tooling is good about finding installed dependencies on POSIX systems.

_Important_: Linux users will want the "-dev" or "-devel" package variants
which include C headers. For macOS, Homebrew doesn't separate the headers.

#### libclamav dependencies

App developers that only need libclamav can use the `-D ENABLE_LIBCLAMAV_ONLY`
option to bypass ClamAV app dependencies.

libclamav requires these library dependencies:

- `bzip2`
- `zlib`
- `libxml2`
- `libpcre2`
- `openssl`
- `json-c`
- `iconv` (POSIX-only, may be provided by system)
- `pthreads` (Provided by the system on POSIX; Use `pthreads-win32` on Windows)
- `llvm` (optional, _see [Bytecode Runtime](#bytecode-runtime))

#### libfreshclam dependencies

If you want libclamav _and_ libfreshclam for your app, then use the
`-D ENABLE_APP=OFF` option instead.

libfreshclam adds these additional library dependencies:

- `libcurl`

#### Application dependencies

For regular folk who want the ClamAV apps, you'll also need:

- `ncurses` (or `pdcurses`), for `clamdtop`.
- `systemd`, so `clamd`, `freshclam`, `clamonacc` may run as a `systemd`
  service (Linux).
- `libsystemd`, so `clamd` will support the `clamd.ctl` socket (Linux).

#### Dependency build options

If you have custom install paths for the dependencies on your system or are
on Windows, you may need to use the following options...

##### `libcheck`

```sh
  -D LIBCHECK_ROOT_DIR="_path to libcheck install root_"
  -D LIBCHECK_INCLUDE_DIR="_filepath of libcheck header directory_"
  -D LIBCHECK_LIBRARY="_filepath of libcheck library_"
```

##### `bzip2`

```sh
  -D BZIP2_INCLUDE_DIR="_filepath of bzip2 header directory_"
  -D BZIP2_LIBRARIES="_filepath of bzip2 library_"
```

##### `zlib`

```sh
  -D ZLIB_INCLUDE_DIR="_filepath of zlib header directory_"
  -D ZLIB_LIBRARY="_filepath of zlib library_"
```

##### `libxml2`

```sh
  -D LIBXML2_INCLUDE_DIR="_filepath of libxml2 header directory_"
  -D LIBXML2_LIBRARY="_filepath of libxml2 library_"
```

##### `libpcre2`

```sh
  -D PCRE2_INCLUDE_DIR="_filepath of libpcre2 header directory_"
  -D PCRE2_LIBRARY="_filepath of libcpre2 library_"
```

##### `openssl` (`libcrypto`, `libssl`)

```sh
  -D OPENSSL_ROOT_DIR="_path to openssl install root_"
  -D OPENSSL_INCLUDE_DIR="_filepath of openssl header directory_"
  -D OPENSSL_CRYPTO_LIBRARY="_filepath of libcrypto library_"
  -D OPENSSL_SSL_LIBRARY="_filepath of libssl library_"
```

##### `libjson-c`

_Tip_: You're strongly encouraged to link with the a static json-c library.

```sh
  -D JSONC_INCLUDE_DIR="_path to json-c header directory_"
  -D JSONC_LIBRARY="_filepath of json-c library_"
```

##### `libmspack`

These options only apply if you use the `-D ENABLE_EXTERNAL_MSPACK=ON` option.

```sh
  -D MSPack_INCLUDE_DIR="_path to mspack header directory_"
  -D MSPack_LIBRARY="_filepath of libmspack library_"
```

##### `iconv` (POSIX-only)

On POSIX platforms, iconv might be part of the C library in which case you
would not want to specify an external iconv library.

```sh
  -D Iconv_INCLUDE_DIR="_path to iconv header directory_"
  -D Iconv_LIBRARY="_filepath of iconv library_"
```

##### `pthreads-win32` (Windows-only)

On POSIX platforms, pthread support is detected automatically.  On Windows, you
need to specify the following:

```sh
  -D PThreadW32_INCLUDE_DIR="_path to pthread-win32 header directory_"
  -D PThreadW32_LIBRARY="_filepath of pthread-win32 library_"
```

##### `llvm` (optional, _see "Bytecode Runtime" section_)

```sh
  -D BYTECODE_RUNTIME="llvm"
  -D LLVM_ROOT_DIR="_path to llvm install root_" -D LLVM_FIND_VERSION="3.6.0"
```

##### `libcurl`

```sh
  -D CURL_INCLUDE_DIR="_path to curl header directory_"
  -D CURL_LIBRARY="_filepath of curl library_"
```

##### `ncurses` or `pdcurses`, for `clamdtop`

```sh
  -D CURSES_INCLUDE_DIR="_path to curses header directory_"
  -D CURSES_LIBRARY="_filepath of curses library_"
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
cmake .. -D BYTECODE_RUNTIME="interpreter"
```

To build using LLVM instead of the intereter, use:

```sh
cmake .. \
  -D BYTECODE_RUNTIME="llvm"       \
  -D LLVM_ROOT_DIR="/opt/llvm/3.6" \
  -D LLVM_FIND_VERSION="3.6.0"
```

To disable bytecode signature support entirely, you may build with this option:

```sh
cmake .. -D BYTECODE_RUNTIME="none"
```

## Compilers and Options

_TODO_: Describe how to customize compiler toolchain with CMake.

## Compiling For Multiple Architectures

_TODO_: Describe how to cross-compile with CMake.

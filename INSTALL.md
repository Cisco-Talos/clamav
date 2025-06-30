# Installing ClamAV

See our online documentation for installation instructions:
- [Installing ClamAV Main Page](https://docs.clamav.net/manual/Installing.html)
- [Third-Party Package Installation](https://docs.clamav.net/manual/Installing/Packages.html)

**For step-by-step compiling instructions** for each major operating system
and distribution, see:
- [Unix/Linux/Mac](https://docs.clamav.net/manual/Installing/Installing-from-source-Unix.html)
- [Windows](https://docs.clamav.net/manual/Installing/Installing-from-source-Windows.html)

You can find additional tips for development builds in our
[online documentation](https://docs.clamav.net/manual/Development/development-builds.html).

> _Tip_: If you have a source tarball from an official release, you can find
> a copy of the online documentation in the `docs/html` directory.

The rest of this document serves as a reference, detailing each of the build
configuration options.

**Table Of Contents**

- [Installing ClamAV](#installing-clamav)
  - [Known Issues / To-do's:](#known-issues--to-dos)
  - [Build Requirements](#build-requirements)
    - [Build Tools](#build-tools)
    - [External Library Dependencies](#external-library-dependencies)
      - [libclamav dependencies](#libclamav-dependencies)
      - [libfreshclam dependencies](#libfreshclam-dependencies)
      - [Program dependencies](#program-dependencies)
  - [Getting Started](#getting-started)
  - [CMake Basics](#cmake-basics)
    - [CMake Generators](#cmake-generators)
    - [CMake Build Types](#cmake-build-types)
    - [Customizing the Install Directories](#customizing-the-install-directories)
    - [Running the Public Test Suite](#running-the-public-test-suite)
  - [Custom CMake Config Options](#custom-cmake-config-options)
  - [External Library Dependency Configuration Options](#external-library-dependency-configuration-options)
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
      - [Interpreter Bytecode Runtime](#interpreter-bytecode-runtime)
      - [LLVM JIT Bytecode Runtime](#llvm-jit-bytecode-runtime)
      - [Disabling the Bytecode Runtime](#disabling-the-bytecode-runtime)
  - [Compiling For Multiple Architectures (Cross-Compiling)](#compiling-for-multiple-architectures-cross-compiling)
  - [Un-install](#un-install)

## Known Issues / To-do's:

- Complete the `MAINTAINER_MODE` option to generate jsparse files with GPerf.

- The test suite will fail to run if you have `pytest` from Python2 installed
  and you don't have `pytest` from Python3 installed. If this happens, run:
  `python3 -m pip install pytest` and then delete your build directory before
  recompiling clamav and trying again.

- The documentation generated using Doxygen isn't very good.

## Build Requirements

### Build Tools

As of ClamAV 0.104, CMake is required to build ClamAV.

The Windows Visual Studio and Autotools build systems have been removed.

You will need:
- CMake (3.14+ for Unix/Linux; 3.16+ for Windows)
- A C compiler toolchain such as `gcc`, `clang`, or Microsoft Visual Studio.
- The Rust compiler toolchain.

Recommended tools:
- pkg-config
- Python 3 (to run the test suite)

For Maintainer-mode only (not recommended):
- Flex
- Bison
- Gperf

On systems with multiple implementations of build-time tools it may be
desirable to select a specific implementation to use rather than relying on
CMake's logic. See [Custom CMake Config Options](#custom-cmake-config-options)
for information on this topic.

### External Library Dependencies

For installation instructions, see our online documentation:

- [Dependencies - Unix/Linux/Mac ](https://docs.clamav.net/manual/Installing/Installing-from-source-Unix.html#install-prerequisites)

- [Dependencies - Windows](https://docs.clamav.net/manual/Installing/Installing-from-source-Windows.html#building-the-library-dependencies)

> _Important_: Linux users will need the "-dev" or "-devel" package variants
> which include C headers. For macOS, Homebrew doesn't separate the headers.

#### libclamav dependencies

App developers that only need libclamav can use the `-D ENABLE_LIBCLAMAV_ONLY`
option to bypass the libfreshclam and program dependencies.

libclamav requires these library dependencies:

- `libbz2` / `bzip2`
- `libz` / `zlib`
- `libxml2`
- `libpcre2`
- `openssl`
- `json-c`
- `libjson-c` / `json-c`
- `libmspack` (built-in by default, enable with `ENABLE_EXTERNAL_MSPACK=ON`)
- `libiconv` (built-in to `libc` 99% of the time, not requires on Windows)
- `pthreads` (provided by Linux/Unix; requires `pthreads-win32` on Windows)
- `llvm` (optional, see: [Bytecode Runtime](#bytecode-runtime), below)
- `libcheck` (default, disable with `ENABLE_TESTS=OFF`)

#### libfreshclam dependencies

If you are building an app and need libclamav _and_ libfreshclam but don't need
to build the ClamAV programs, configure the build with `-D ENABLE_APP=OFF`.

libfreshclam adds these additional library dependencies:

- `libcurl`

#### Program dependencies

For regular folk who want the ClamAV apps, you'll also need:

- `libmilter` (Unix/Linux-only, disable with `ENABLE_MILTER=OFF`)
- `ncurses` or `pdcurses`, for ClamDTop.

Optionally, if on a Linux distro with SystemD:

- `systemd`, so ClamD, FreshClam, ClamOnAcc SystemD service.
- `libsystemd`, so ClamD will support the `clamd.ctl` socket.

## Getting Started

***Important***: The following instructions assume that you have created a
`build` subdirectory and that subsequent commands are performed from said
directory, like so:

```sh
mkdir build && cd build
```

## CMake Basics

CMake isn't actually a build system. It is a meta-build system. In other words,
CMake is a build system *generator*.

On Unix systems, CMake generates Makefiles by default, just like Autotools.
On Windows, it generates Visual Studio projects by default.

The process for using CMake is very similar to Autotools:
1. *Configure*: Generate the build system.
2. *Build*: Compile the project.
3. *Install*: Install to the "prefix" directory.

### CMake Generators

You can choose to use a different generator using the `-G` option.
For example, on macOS you can generate Xcode projects.

Ninja is a popular build system, available on both Unix and Windows.
If you want to use Ninja, you could configure the project with:

```sh
cmake .. -G Ninja
```

For more information about generators, refer to the
[CMake documentation](https://cmake.org/cmake/help/latest/manual/cmake-generators.7.html)

### CMake Build Types

CMake provides four build types. These are:
- `Release`: Optimized for speed, with no debugging info, code or asserts.
- `Debug`: No optimization, asserts enabled, debugging info included.
- `RelWithDebInfo`: Like `Release`, but *with* debug info, but no asserts.
- `MinSizeRel`: Like `Release` but optimizing for size rather than speed.

There are two basic types of generators. How you select the build type for
your build will depend on which type of generator you're using:

1. **Single-config generators** (Unix Makefiles, Ninja)

  These generate a build system that can only build a single build type.

  With a single-config generator, you need to specify the build type up
  front. You can do this using the `-G` option. For example:
  ```sh
  # Configure
  cmake .. -G Ninja -D CMAKE_BUILD_TYPE=RelWithDebInfo
  # Build
  cmake --build .
  ```

2. **Multi-config generators** (Xcode, Visual Studio, Ninja Multi-Config)

  These generate a build system capable of building more than one build type.

  With a multi-config generator, the generated build system can build all
  of CMake's different build types. It's up to you to decide which type, or
  "config" you want to build at build time instead of at configuration time.
  You can do that with the `--config` option. For example:
  ```sh
  # Configure
  cmake .. -G "Ninja Multi-Config"
  # Build
  cmake --build . --config RelWithDebInfo
  ```

> _Tip_: `RelWithDebInfo` is probably the best option for open source projects.
> It will have the speed optimizations you need. And, if a crash occurs, the
> crash backtrace you obtain with a debugger will significantly help in
> identifying the bug.

For multi-config generators, you _will_ also need to specify the config when
you use `ctest` to run the test suite, or if using `cpack` to build a package.

> _Tip_: When using the default generator on Unix operating systems, you can
> also simply call `make` after the first `cmake` command, like so:
> ```sh
> # Configure
> cmake ..
> # Build
> make -j12
> # Install
> sudo make install
> ```
>
> Similarly, if using Ninja, you could call `ninja` directly instead.
> ```sh
> # Configure
> cmake .. -G Ninja
> # Build
> ninja
> # Install
> sudo ninja install
> ```
>
> And for Windows & Mac developers, if generating Visual Studio or Xcode
> projects, you're free to open those project solutions in Visual Studio or
> Xcode after the configure step, to use for compiling AND debugging, which
> may be very useful.

### Customizing the Install Directories

A default from-source install on a Unix system will go in `/usr/local`, with:
- applications in `bin`,
- daemons in `sbin`,
- libraries in `lib`,
- headers in `include`,
- configs in `etc`,
- and databases in `share/clamav`.

Use the following variables to customize the install paths:

- `CMAKE_INSTALL_PREFIX`: Customize the install prefix.
- `APP_CONFIG_DIRECTORY`: Customize the config directory, may be relative.
- `DATABASE_DIRECTORY`: Customize the database directory, may be relative.
- `CVD_CERTS_DIRECTORY`: Customize the ClamAV CA certificates directory, may be relative.
- `SYSTEMD_UNIT_DIR`: Install SystemD service files to a specific directory.

This example configuration should be familiar if you've used the ClamAV
packages provided by Debian, Ubuntu, Alpine, and some other distributions:
```sh
# Configure
cmake .. \
    -D CMAKE_BUILD_TYPE=RelWithDebInfo \
    -D CMAKE_INSTALL_PREFIX=/usr \
    -D CMAKE_INSTALL_LIBDIR=/usr/lib \
    -D APP_CONFIG_DIRECTORY=/etc/clamav \
    -D CVD_CERTS_DIRECTORY=/etc/clamav/certs \
    -D DATABASE_DIRECTORY=/var/lib/clamav \
    -D ENABLE_JSON_SHARED=OFF # require libjson-c to be static
# Build
cmake --build .
# Install
sudo cmake --build . --target install
```

ClamAV has a couple other important paths you can configure. At this time,
these are only configurable through the `clamd.conf` application config file:

- `LocalSocket`: You may configure ClamD to listen on a TCP socket or on a
  "local" socket (a Unix socket). A local socket is probably best, for safety.
  But that means you'll need to select a path for the local socket. The sample
  config suggests using the `/tmp` directory, but you may wish to select
  a directory like `/var/run/clamav`.

- `TemporaryDirectory`: ClamAV creates a lot of temp files when scanning.
  By default, ClamD and ClamScan will use the system's default temp directory,
  which is typically `/tmp` or `/var/tmp`. But it may be best to give ClamAV
  its own directory. Maybe `/var/lib/clamav-tmp`.

### Running the Public Test Suite

The option to build so that you can run the tests is enabled by default.
It requires that you provide `python3` and `libcheck`.

If you're building with `ENABLE_LIBCLAMAV_ONLY=ON` or `ENABLE_APP=OFF`, then
`libcheck` will still be required and you can still run the tests, but it will
skip all app tests and only run the libclamav unit tests.

To run the tests, first build ClamAV, then run `ctest`.
Use the following options as needed:

- `-V`: Verbose

  This option will show the test output. You may wish to use Pip (`pip3`) to
  install `pytest` as well. If detected at configure-time, `pytest` will be
  used to run the tests and will make it so you only see output from failed
  tests.

- `-C <config>`: Specify which build type to test (e.g. `RelWithDebInfo`).

  This option is *only* required if using a multi-config generator, such as
  "Visual Studio", "Xcode", or "Ninja Multi-Config".

On a typical Linux system, you'll probably just run this:
```sh
# Configure
cmake .. -D CMAKE_BUILD_TYPE=RelWithDebInfo #... other options snipped
# Build
cmake --build .
# Test
ctest
```

On Windows, you may run something like this:
```sh
# Configure
cmake .. #... other options snipped
# Build
cmake --build . --config RelWithDebInfo
# Test
ctest -C RelWithDebInfo -V
```

If you encounter a test failure, please re-run `ctest` with `-V` enabled and
submit the output in a bug report
[on GitHub Issues](https://github.com/Cisco-Talos/clamav/issues).
The test output is also saved to log files in the `unit_tests` directory.
You can zip those up and attach those instead.

> _Tip_: You can configure with `-D ENABLE_TESTS=OFF` to disable test support.
> This will also remove the dependency on Python and libcheck.

## Custom CMake Config Options

The following is a complete list of CMake options unique to configuring ClamAV:

- `APP_CONFIG_DIRECTORY`: Program config directory.
  Relative to the `CMAKE_INSTALL_PREFIX` unless an absolute path is given.

  _Default: Windows: `.`, POSIX: `etc`_

- `DATABASE_DIRECTORY`: Database directory.
  Relative to the `CMAKE_INSTALL_PREFIX` unless an absolute path is given.

  _Default: Windows: `database`, POSIX: `share/clamav`_

- `CVD_CERTS_DIRECTORY`: ClamAV CA certificates directory.
  Relative to the `CMAKE_INSTALL_PREFIX` unless an absolute path is given.

  _Default: Windows: `certs`, POSIX: `etc/certs`_

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

- `DO_NOT_SET_RPATH`: By default RPATH is set in executables resulting using
  paths set at build time instead of using system defaults. By setting this
  `ON` system defaults are used.

  _Default: `OFF`_

- `ENABLE_WERROR`: Compile time warnings will cause build failures (i.e.
  `-Werror`)

  _Default: `OFF`_

- `ENABLE_ALL_THE_WARNINGS`: By default we use `-Wall -Wextra -Wformat-security`
  for ClamAV libraries and programs. This option enables a whole lot more.

  _Default: `OFF`_

- `ENABLE_DEBUG`: Turn on extra debug output.
  Disclaimer: Does nothing in the current version.

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

  This option is default "ON" only because the libjson-c static library is not
  available on many systems by default.

  _Default: `ON`_

- `ENABLE_APP`: Build the ClamAV programs (clamscan, clamd, clamdscan, sigtool,
  clambc, clamdtop, clamsubmit, clamconf).

  _Default: `ON`_

- `ENABLE_CLAMONACC`: (Linux-only) Build the ClamOnAcc on-access scanning
  daemon. Requires: `ENABLE_APP`

  ClamOnAcc will not compile on MUSL-based Linux distros such as Alpine.

  _Default: `ON`_

- `ENABLE_MILTER`: (Posix-only) Build the clamav-milter Sendmail filter daemon.
  Requires: `ENABLE_APP`

  _Default: `OFF` for Mac & Windows, `ON` for Linux/Unix_

- `ENABLE_UNRAR`: Build & install libclamunrar (UnRAR) and libclamunrar_iface.

  _Default: `ON`_

- `ENABLE_MAN_PAGES`: Generate man pages.

  _Default: `ON` for Linux/Unix, `OFF` for Windows_

- `ENABLE_DOXYGEN`: Generate Doxygen HTML documentation for `clamav.h`,
  and `libfreshclam.h`. Requires Doxygen. *To-do*: Needs work.

  _Default: `OFF`_

- `ENABLE_EXAMPLES`: Build the example programs.

  _Default: `OFF`_

- `ENABLE_TESTS`: Enable support for running the test suite with `ctest`.

  _Default: `ON`_

- `ENABLE_LIBCLAMAV_ONLY`: Build libclamav only.

  > _Tip_: This Excludes libfreshclam too! Use `ENABLE_APP=OFF` instead if
  > you want libclamav and libfreshclam.

  _Default: `OFF`_

- `ENABLE_STATIC_LIB`: Build libclamav and/or libfreshclam static libraries.

  > _Tip_: If you wish to build `clamscan` and the other programs statically,
  > you must also set `ENABLE_SHARED_LIB=OFF`.

  _Default: `OFF`_

- `ENABLE_SHARED_LIB`: Build libclamav and/or libfreshclam shared libraries.

  _Default: `ON`_

- `ENABLE_SYSTEMD`: Install SystemD service files if SystemD is found.

  _Default: `ON`_

- `MAINTAINER_MODE`: Generate Yara lexer and grammar C source with Flex & Bison.
  Generate Rust bindings (`libclamav_rust/src/sys.rs`).
  *To-do*: Also generate JS parse source with Gperf.

  _Default: `OFF`_

- `SYSTEMD_UNIT_DIR`: Install SystemD service files to a specific directory.
  This will fail the build if SystemD not found.

  _Default: not set_

- `PYTHON_FIND_VER`: Select a specific implementation of Python that will
  be called during the test phase.

  _Default: not set_

- `RUST_COMPILER_TARGET`: Use a custom target triple to build the Rust components.
  Needed for cross-compiling. You must also have installed the target toolchain.
  See: https://doc.rust-lang.org/nightly/rustc/platform-support.html

  _Default: not set_

## External Library Dependency Configuration Options

The CMake tooling is good about finding installed dependencies on POSIX systems
provided that you have pkg-config installed, and the dependencies are installed
in the standard locations (i.e. `/usr` and `/usr/local`).

But if you:
- have custom install paths for the dependencies,
- want to target static libraries, or
- are building on Windows...

... you may need to use the following build configuration options.

### `libcheck`

```sh
  -D LIBCHECK_ROOT_DIR="_path to libcheck install root_"
  -D LIBCHECK_INCLUDE_DIR="_filepath of libcheck header directory_"
  -D LIBCHECK_LIBRARY="_filepath of libcheck library_"
```

### `bzip2`

```sh
  -D BZIP2_INCLUDE_DIR="_filepath of bzip2 header directory_"
  -D BZIP2_LIBRARY_RELEASE="_filepath of bzip2 library_"
```

### `zlib`

```sh
  -D ZLIB_INCLUDE_DIR="_filepath of zlib header directory_"
  -D ZLIB_LIBRARY="_filepath of zlib library_"
```

### `libxml2`

```sh
  -D LIBXML2_INCLUDE_DIR="_filepath of libxml2 header directory_"
  -D LIBXML2_LIBRARY="_filepath of libxml2 library_"
```

### `libpcre2`

```sh
  -D PCRE2_INCLUDE_DIR="_filepath of libpcre2 header directory_"
  -D PCRE2_LIBRARY="_filepath of libcpre2 library_"
```

### `openssl` (`libcrypto`, `libssl`)

```sh
  -D OPENSSL_ROOT_DIR="_path to openssl install root_"
  -D OPENSSL_INCLUDE_DIR="_filepath of openssl header directory_"
  -D OPENSSL_CRYPTO_LIBRARY="_filepath of libcrypto library_"
  -D OPENSSL_SSL_LIBRARY="_filepath of libssl library_"
```

_Tip_: For Windows, you may need to do this instead:
```sh
  -D OPENSSL_ROOT_DIR="_path to openssl install root_"
  -D OPENSSL_INCLUDE_DIR="_filepath of openssl header directory_"
  -D LIB_EAY_RELEASE="_filepath of libcrypto library_"  # or LIB_EAY_DEBUG for Debug builds
  -D SSL_EAY_RELEASE="_filepath of libssl library_"     # or SSL_EAY_DEBUG for Debug builds
```

### `libjson-c`

_Tip_: You're strongly encouraged to link with the a static json-c library.

```sh
  -D JSONC_INCLUDE_DIR="_path to json-c header directory_"
  -D JSONC_LIBRARY="_filepath of json-c library_"
```

### `libmspack`

These options only apply if you use the `-D ENABLE_EXTERNAL_MSPACK=ON` option.

```sh
  -D MSPack_INCLUDE_DIR="_path to mspack header directory_"
  -D MSPack_LIBRARY="_filepath of libmspack library_"
```

### `iconv` (POSIX-only)

On POSIX platforms, iconv might be part of the C library in which case you
would not want to specify an external iconv library.

```sh
  -D Iconv_INCLUDE_DIR="_path to iconv header directory_"
  -D Iconv_LIBRARY="_filepath of iconv library_"
```

### `pthreads-win32` (Windows-only)

On POSIX platforms, pthread support is detected automatically.  On Windows, you
need to specify the following:

```sh
  -D PThreadW32_INCLUDE_DIR="_path to pthread-win32 header directory_"
  -D PThreadW32_LIBRARY="_filepath of pthread-win32 library_"
```

### `llvm` (optional, _see "Bytecode Runtime" section_)

Set:
```sh
  -D BYTECODE_RUNTIME="llvm"
```

Options for a custom LLVM install path, or to select a specific version if you
have multiple LLVM installations:
```sh
  -D LLVM_ROOT_DIR="_path to llvm install root_"
  -D LLVM_FIND_VERSION="8.0.1"
```

### `libcurl`

```sh
  -D CURL_INCLUDE_DIR="_path to curl header directory_"
  -D CURL_LIBRARY="_filepath of curl library_"
```

### `ncurses` or `pdcurses`, for `clamdtop`

```sh
  -D NCURSES_INCLUDE_DIR="_path to ncurses header directory_"
```

or:
```sh
  -D PDCURSES_INCLUDE_DIR="_path to pdcurses header directory_"
```

and:
```sh
  -D CURSES_LIBRARY="_filepath of curses library_"
```

and, if tinfo is separate from ncurses:
```sh
  -D TINFO_LIBRARY="_filepath of tinfo library_"
```

### Bytecode Runtime

Bytecode signatures are a type of executable plugin that provide extra
detection capabilities.

ClamAV has two bytecode runtimes:

1. **Interpreter**: The bytecode interpreter evaluates and executes bytecode
   instructions one by one.

   With the interpreter, signature database (re)loads are faster, but execution
   time for scans that make use of the bytecode signatures is slower.

2. **LLVM**: LLVM can be used to Just-in-Time (JIT) compile bytecode signatures
   at database load time.

   With LLVM, signature database loading is slower, but bytecode signature
   execution should be faster. Not all scans will run bytecode signatures, so
   performance testing will depend heavily depending on what files are tested.

   We can work with LLVM 8.0 to 13.x.

#### Interpreter Bytecode Runtime

At the moment, the *interpreter* is the default runtime, while we work out
compatibility issues with newer versions of libLLVM. This default equates to:

```sh
cmake .. -D BYTECODE_RUNTIME="interpreter"
```

#### LLVM JIT Bytecode Runtime

If you wish to build using LLVM JIT for the bytecode runtime instead of the
bytecode interpreter, you will need to install the LLVM development libraries.
ClamAV currently supports LLVM versions 8.0 through 13.x.

To build with LLVM for the bytecode runtime, build with this option:
```sh
cmake .. \
  -D BYTECODE_RUNTIME="llvm"
```

If you have multiple LLVM installations, or have a custom path for the LLVM
installation, you may also set `LLVM_ROOT_DIR` and `LLVM_FIND_VERSION` options
to help CMake find the right LLVm installation. For example:
```sh
  -D LLVM_ROOT_DIR="/opt/llvm/8.0"
  -D LLVM_FIND_VERSION="8.0.1"
```

If the build fails to detect LLVM or linking with LLVM fails using the above
options, you may try adding this CMake parameter to enable
[CMake's package-config feature](https://cmake.org/cmake/help/latest/variable/CMAKE_FIND_PACKAGE_PREFER_CONFIG.html):
```
  -D CMAKE_FIND_PACKAGE_PREFER_CONFIG=TRUE
```
Normally, ClamAV would use the `FindLLVM.cmake` module in our `<src>/cmake`
directory to find LLVM. With this option enabled, it will instead try to use
`<LLVM_ROOT_DIR>/lib/cmake/llvm/LLVMConfig.cmake` to determine the LLVM package
configuration.

> _Known Issues_: Known issues building with LLVM:
> - Enabling `CMAKE_FIND_PACKAGE_PREFER_CONFIG` may fail to build with some LLVM
>   packages that are missing the `libPolly.a` library. This includes some LLVM
>   packages distributed by Debian, Ubuntu, and OpenSUSE.
> - Not enabling `CMAKE_FIND_PACKAGE_PREFER_CONFIG` may fail to build with some
>   LLVM packages using `gcc` when RTTI was disabled for the LLVM build, but is
>   enabled for the ClamAV build. Using `clang` instead of `gcc` may have better
>   results.
> - Building ClamAV in Debug-mode with a Release-LLVM build may fail, and
>   building ClamAV in Release-mode with a Debug-LLVM build may fail.
> - The unit tests may fail in Debug-mode builds on the `libclamav` "bytecode"
>   test due to an assertion/abort.
> - Windows-only: CMake fails to collect library dependencies when building with
>   LLVM. That is, the tests will fail because it can't load libssl.dll and
>   other DLL dependencies. This issue only applies when not using VCPkg.

#### Disabling the Bytecode Runtime

To disable bytecode signature support entirely, you may build with this option:

```sh
cmake .. -D BYTECODE_RUNTIME="none"
```

## Compiling For Multiple Architectures (Cross-Compiling)

Cross-compiling in ClamAV with CMake & Rust is experimental at this time.
If you have a need to cross-compile, your help and feedback testing and
validating cross-compilation support would be appreciated.

The CMake cross-compiling documentation can be found here:
[CMake Manual](https://cmake.org/cmake/help/latest/manual/cmake-toolchains.7.html)

For a cross-build, the library dependencies must have also been built for the
target platform, and the CMake options set to target these libraries.

ClamAV's Rust toolchain integration also complicates the build.
In addition to specifying the toolchain for C/C++ through the CMake options
described in the CMake Manual, you will need to also select the target triple
for the Rust compiler toolchain. If you have a mismatch of targets between the
C and Rust toolchains, it will fail to compile properly.

The ClamAV project provides a CMake option `-D RUST_COMPILER_TARGET=<triple>`
that mimics the CMake option when using Clang to cross-compile.

Rust installations typically only come with the target for your current system.
So you will need to install the desired toolchain using `rustup target add`.
Run `rustup target add --help` for help.
For a list of available target triples, see:
https://doc.rust-lang.org/nightly/rustc/platform-support.html

Step-by-step instructions for cross-compiling ClamAV:
- [Linux GCC amd64 to arm64](./INSTALL-cross-linux-arm64.md)
- [Windows MSVC x64 to arm64](./INSTALL-cross-windows-arm64.md)

## Un-install

CMake doesn't provide a simple command to uninstall. However, CMake does build
an `install_manifest.txt` file when you do the install. You can use the
manifest to remove the installed files.

You will find the manifest in the directory where you compiled ClamAV. If you
followed the recommendations (above), then you will find it at
`<clamav source directory>/build/install_manifest.txt`.

Feel free to inspect the file so you're comfortable knowing what you're about
to delete.

Open a terminal and `cd` to that `<clamav source directory>/build` directory.
Then run:
```bash
xargs rm < install_manifest.txt
```

This will leave behind the directories, and will leave behind any files added
after install including the signature databases and any config files. You will
have to delete these extra files yourself.

> _Tip_: You may need to use `sudo`, depending on where you installed to.

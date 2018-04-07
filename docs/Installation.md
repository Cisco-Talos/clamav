# Installation

## Requirements

The following components are required to compile ClamAV under UNIX:=

- zlib and zlib-devel packages
- openssl version 0.9.8 or higher and libssl-devel packages
- gcc compiler suite (tested with 2.9x, 3.x and 4.x series) **If you are compiling with higher optimization levels than the default one ( for gcc), be aware that there have been reports of misoptimizations. The build system of ClamAV only checks for bugs affecting the default settings, it is your responsibility to check that your compiler version doesn’t have any bugs.**
- GNU make (gmake)

The following packages are optional but **highly recommended**:

- bzip2 and bzip2-devel library
- libxml2 and libxml2-dev library
- `check` unit testing framework \[3\].

The following packages are optional, but **required for bytecode JIT support**:

- GCC C and C++ compilers (minimum 4.1.3, recommended 4.3.4 or newer) the package for these compilers are usually called: gcc, g++, or gcc-c++. \[5\]
- OSX Xcode versions prior to 5.0 use a g++ compiler frontend (llvm-gcc) that is not compatible with ClamAV JIT. It is recommended to either compile ClamAV JIT with clang++ or to compile ClamAV without JIT.
- A supported CPU for the JIT, either of: X86, X86-64, PowerPC, PowerPC64

The following packages are optional, but needed for the JIT unit tests:

- GNU Make (version 3.79, recommended 3.81)
- Python (version 2.5.4 or newer), for running the JIT unit tests

The following packages are optional, but required for clamsubmit:

- libcurl-devel library
- libjson-c-dev library

## Installing on shell account

To install ClamAV locally on an unprivileged shell account you need not create any additional users or groups. Assuming your home directory is `/home/gary` you should build it as follows:

```bash
    $ ./configure --prefix=/home/gary/clamav --disable-clamav
    $ make; make install
```

To test your installation execute:

```bash
    $ ~/clamav/bin/freshclam
    $ ~/clamav/bin/clamscan ~
```

The `--disable-clamav` switch disables the check for existence of the *clamav* user and group but `clamscan` would still require an unprivileged account to work in a superuser mode.

## Adding new system user and group

If you are installing ClamAV for the first time, you have to add a new user and group to your system:

```bash
    # groupadd clamav
    # useradd -g clamav -s /bin/false -c "Clam AntiVirus" clamav
```

Consult a system manual if your OS has not *groupadd* and *useradd* utilities. **Don’t forget to lock access to the account\!**

## Compilation of base package

Once you have created the clamav user and group, please extract the archive:

```bash
    $ zcat clamav-x.yz.tar.gz | tar xvf -
    $ cd clamav-x.yz
```

Assuming you want to install the configuration files in /etc, configure and build the software as follows:

```bash
    $ ./configure --sysconfdir=/etc
    $ make
    $ su -c "make install"
```

In the last step the software is installed into the /usr/local directory and the config files into /etc. **WARNING: Never enable the SUID or SGID bits for Clam AntiVirus binaries.**

## Compilation with clamav-milter enabled

libmilter and its development files are required. To enable clamav-milter, configure ClamAV with

```bash
    $ ./configure --enable-milter
```

See section /refsec:clamavmilter for more details on clamav-milter.

## Using the system LLVM

Some problems have been reported when compiling ClamAV’s built-in LLVM with recent C++ compiler releases. These problems may be avoided by installing and using an external LLVM system library. To configure ClamAV to use LLVM that is installed as a system library instead of the built-in LLVM JIT, use following:

```bash
    $ ./configure --with-system-llvm=/myllvm/bin/llvm-config
    $ make
    $ sudo make install
```

The argument to `--with-system-llvm` is optional, indicating the path name of the LLVM configuration utility (llvm-config). With no argument to `--with-system-llvm`, `./configure` will search for LLVM in /usr/local/ and then /usr.

Recommended versions of LLVM are 3.2, 3.3, 3.4, 3.5, and 3.6. Some installations have reported problems using earlier LLVM versions. Versions of LLVM beyond 3.6 are not currently supported in ClamAV.

## Running unit tests

ClamAV includes unit tests that allow you to test that the compiled binaries work correctly on your platform.

The first step is to use your OS’s package manager to install the `check` package. If your OS doesn’t have that package, you can download it from <http://check.sourceforge.net/>, build it and install it.

To help clamav’s configure script locate `check`, it is recommended that you install `pkg-config`, preferably using your OS’s package manager, or from <http://pkg-config.freedesktop.org>.

The recommended way to run unit-tests is the following, which ensures you will get an error if unit tests cannot be built: \[6\]

```bash
     $ ./configure --enable-check
     $ make
     $ make check
```

When `make check` is finished, you should get a message similar to this:

```bash
==================
All 8 tests passed
==================
```

If a unit test fails, you get a message similar to the following. Note that in older versions of make check may report failures due to the absence of optional packages. Please make sure you have the latest versions of the components noted in section /refsec:components. See the next section on how to report a bug when a unit test fails.

```bash
========================================
1 of 8 tests failed
Please report to https://bugzilla.clamav.net/
========================================
```

If unit tests are disabled (and you didn’t use –enable-check), you will get this message:

```bash
*** Unit tests disabled in this build
*** Use ./configure --enable-check to enable them

SKIP: check_clamav
PASS: check_clamd.sh
PASS: check_freshclam.sh
PASS: check_sigtool.sh
PASS: check_clamscan.sh
======================
All 4 tests passed
(1 tests were not run)
======================
```

Running `./configure --enable-check` should tell you why.

## Reporting a unit test failure bug

If `make check` says that some tests failed we encourage you to report a bug on our bugzilla: <https://bugzilla.clamav.net>. The information we need is:

- The exact output from `make check`
- Output of `uname -mrsp`
- your `config.log`
- The following files from the `unit_tests/` directory:
  - `test.log`
  - `clamscan.log`
  - `clamdscan.log`

- `/tmp/clamd-test.log` if it exists
- where and how you installed the check package
- Output of `pkg-config check --cflags --libs`
- Optionally if `valgrind` is available on your platform, the output of the following:
    ```bash
    $ make check
    $ CK_FORK=no ./libtool --mode=execute valgrind unit_tests/check_clamav
    ```

## Obtain Latest ClamAV anti-virus signature databases

Before you can run ClamAV in daemon mode (clamd), ’clamdscan’, or ’clamscan’ which is ClamAV’s command line virus scanner, you must have ClamAV Virus Database (.cvd) file(s) installed in the appropriate location on your system. The default location for these database files are /usr/local/share/clamav (in Linux/Unix).

Here is a listing of currently available ClamAV Virus Database Files:

- bytecode.cvd (signatures to detect bytecode in files)
- main.cvd (main ClamAV virus database file)
- daily.cvd (daily update file for ClamAV virus databases)
- safebrowsing.cvd (virus signatures for safe browsing)

These files can be downloaded via HTTP from the main ClamAV website or via the ’freshclam’ utility on a periodic basis. Using ’freshclam’ is the preferred method of keeping the ClamAV virus database files up to date without manual intervention (see the [freshclam configuration](Configuration.md#Setting-up-auto\-updating) section for information on how to configure ’freshclam’ for automatic updating and the main [freshclam](Usage.md#freshclam) section for additional details on freshclam).

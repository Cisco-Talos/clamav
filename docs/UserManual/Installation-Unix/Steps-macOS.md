# Installation on macOS (Mac OS X)

Below are the steps for installing ClamAV from source on Apple macOS.

## Install prerequisites

The easiest way to install prerequisites on macOS is to use [Homebrew](https://brew.sh/)

1. Install Homebrew
    ```bash
    /usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
    ```

2. Install ClamAV dependencies
    1. Install XCode's Command Line Tools
        ```bash
        xcode-select --install
        ```
    2. Install library dependencies
        ```bash
        brew install pcre2 openssl json-c
        ```

3. Install the unit testing dependencies
    ```bash
    sudo apt-get valgrind check
    ```

    _Tip_: Valgrind may not be available in Homebrew for the latest version of macOS.

_Note_: LLVM is also an optional dependency. LLVM will not provide any additional features, but is an alternative method for executing bytecode signatures versus using the built-in bytecode interpreter. Limited performance testing between LLVM and the bytecode interpreter did not yield conclusive evidence that one is "better" than the other. For the sake of simplicity, it is not recommended to install LLVM.

## Download the latest stable release

1. Open a browser and navigate to [the ClamAV downloads page](http://www.clamav.net/downloads)
2. Click `clamav-<version>.tar.gz` link to download the latest stable release.

## Extract the source archive

```bash
cd ~/Downloads
tar xzf clamav-<ver>.tar.gz
cd clamav-<ver>.tar.gz
```

## Configure the build

Homebrew installs libraries and applications under `/usr/local/Cellar/<app>/<ver>/`.

To configure the ClamAV build using our homebrew-installed dependencies, you may need to reference some of them explicitly. Others may be detected automatically.

### Typical `./configure` usage

*_Note_: Your Homebrew-installed package version directories may differ slightly.

```bash
./configure --with-openssl=/usr/local/Cellar/openssl/1.0.2l --with-libjson=yes --enable-check
```

Once `./configure` completes, it will print a summary. Verify that the packages you installed are in fact being detected.

Example configure summary output:

```bash
configure: Summary of detected features follows
            OS          : darwin17.2.0
            pthreads    : yes ()
configure: Summary of miscellaneous features
            check       : -L/usr/local/lib -lcheck -R/usr/local/lib  (auto)
            fanotify    : no (disabled)
            fdpassing   : 1
            IPv6        : yes
configure: Summary of optional tools
            clamdtop    : -lncurses (auto)
            milter      : yes (disabled)
            clamsubmit  : yes (libjson-c-dev found at /usr/local), libcurl-devel found at /usr)
configure: Summary of engine performance features
            release mode: yes
            llvm        : no (disabled)
            mempool     : yes
configure: Summary of engine detection features
            bzip2       : ok
            zlib        : /usr
            unrar       : yes
            preclass    : yes (libjson-c-dev found at /usr/local)
            pcre        : /usr/local/Cellar/pcre2/10.32
            libmspack   : yes (Internal)
            libxml2     : yes, from /usr
            yara        : yes
            fts         : yes (libc)
```

If you experience an error wherein `configure` output claims that `gcc` is unable to build an executable -- please see the [Troubleshooting section at the bottom](#configure----gcc-failed-to-build-executable).

### Additional popular `./configure` options

* `--sysconfdir` - Install the configuration files to `/etc` instead of `/usr/local/etc`:
    ```bash
    ./configure -–sysconfdir=/etc
    ```
* `--prefix` - Install ClamAV to a directory other than `/usr/local/`:
    * Example 1: Install to a local `./install` directory.
        ```bash
        ./configure --prefix=`pwd`/install
        ```
    * Example 2: Install ClamAV locally on an unprivileged shell account.
        ```bash
        ./configure --prefix=$HOME/clamav --disable-clamav
        ```
* `--disable-clamav` - _Don't_ drop super-user priveleges to run `freshclam` or `clamd` as the `clamav`* user.
    ```bash
    ./configure --disable-clamav
    ```
    *_Tip_: Using this `--disable-clamav` means that `freshclam` and `clamd` will run with _root privleges_ if invoked using `sudo`. Running `clamd` or `clamscan` as root is **not recommended**. Instead of using this option, you can configure `freshclam` or `clamd` to drop to any other user by:
    * setting the `DatabaseOwner` option in `freshclam.conf` and
    * setting the `User` option in `clamd.conf`.

Please see the `./configure --help` for additional options.

### Compile ClamAV

Compile ClamAV with:
```bash
make -j2
```

If you experience error messages wherein the compiler is unable to find the correct openssl header or library files, you may need to reconfigure and provide explicit header and library paths. See the [Troubleshooting section below for details](#make----failed-to-find-correct-openssl-header-or-library-files).

### Run ClamAV Unit Tests (Optional)

For peace of mind, it can be helpful to run a small suite of unit and system tests.

Run:
```bash
make check
```

All tests should pass.* Output will look something like this:

```bash.
    ...
PASS: check_clamav
PASS: check_freshclam.sh
PASS: check_sigtool.sh
PASS: check_unit_vg.sh
PASS: check1_clamscan.sh
PASS: check2_clamd.sh
PASS: check3_clamd.sh
PASS: check4_clamd.sh
PASS: check5_clamd_vg.sh
PASS: check6_clamd_vg.sh
SKIP: check7_clamd_hg.sh
PASS: check8_clamd_hg.sh
PASS: check9_clamscan_vg.sh
    ...
============================================================================
Testsuite summary for ClamAV 0.100.2
============================================================================
# TOTAL: 13
# PASS:  12
# SKIP:  1
# XFAIL: 0
# FAIL:  0
# XPASS: 0
# ERROR: 0
```

_Notes_:

* The `*.vg.sh` tests will be skipped unless you run `make check VG=1`.
  * _Under macOS_, `*.vg.sh` (valgrind) tests _will fail_ due to false alerts.
  * Valgrind may not be available via Homebrew for the latest version of macOS.
* The `check7_clamd.hg.sh` (helgrind) is presently disabled and will be skipped.
  * For details, see: [the Git commit](https://github.com/Cisco-Talos/clamav-devel/commit/2a5d51809a56be9a777ded02969a7427a3c26713)

If you have a failure or an error in the unit tests, it could be that you are missing one or more of the prerequisites or that there is miss-match in the header files after upgrading to a newer version of macOS. If the latter, please see the [Troubleshooting section at the bottom](#make-check----unit-tests-failed-for-seemingly-no-reason).

If you are investigating a failure, please do the following:

`cd unit_tests`

Use `less` to read the log for the failed test.
Example:

```bash
less check4_clamd.sh.log`
```

To submit a bug report regarding unit text failures, please follow these [bug reporting steps](../Installation-Unix.md#Reporting-a-unit-test-failure-bug).

### Install ClamAV

Install ClamAV with:
```bash
make install
```

_Tip_: If installing to the default or other system-owned directory, you may need to use `sudo`.

### First time set-up

_Note_: The following instructions assume you used the default install paths (i.e. `/usr/local`). If you modified the install locations using `--prefix` or `--sysconfdir` options, replace `/usr/local` with your chosen install path.

#### `freshclam` config

Before you can use `freshclam` to download updates, you need to create a `freshclam` config. A sample config is provided for you.

1. Copy the sample config. You may need to use `sudo`:
    ```bash
    cp /usr/local/etc/freshclam.conf.sample /usr/local/etc/freshclam.conf
    ```
2. Modify the config file using your favourite text editor. Again, you may need to use `sudo`.
    * At a minimum, remove the `Example` line so `freshclam` can use the config.

    Take the time to look through the options. You can enable the sample options by deleting the `#` comment characters.

    Some popular options to enable include:

    * `LogTime`
    * `LogRotate`
    * `NotifyClamd`
    * `DatabaseOwner`

3. Create the database directory. *Tip: _You may need to use `sudo`._
    ```bash
    mkdir /usr/local/share/clamav
    ```

#### `clamd` config (optional)

You can run `clamscan` without setting the config options for `clamd`. However, the `clamd` scanning daemon allows you to use `clamdscan` to perform faster a-la-carte scans, allows you to run multi-threaded scans, and allows you to use `clamav-milter` if you want to use ClamAV as a mail filter if you host an email server.

1. Copy the sample config. You may need to use `sudo`:
    ```bash
    cp /usr/local/etc/clamd.conf.sample /usr/local/etc/clamd.conf
    ```
2. Modify the config file using your favourite text editor. Again, you may need to use `sudo`.
    * At a minimum, remove the `Example` line so `freshclam` can use the config.
    * You also _need_ to select a Socket option for `clamd` so `clamdscan` and other utilities can communicate with `clamd`. You must enable _one_ of the following.
        * `LocalSocket`
        * `TCPSocket`

    Take the time to look through the options. You can enable the sample options by deleting the `#` comment characters.

    Some popular options to enable include:

    * `LogTime`
    * `LogClean`
    * `LogRotate`
    * `User`

#### Download / Update the signature database

Before you can run a scan, you'll need to download the signature databases. Once again, you may need to run with `sudo`/root privileges.

If you installed to a location in your system PATH:
```bash
freshclam
```

If you installed to another location:
```bash
/<path>/<to>/<clamav>/<bin>/freshclam
```

#### Users and on user privileges

If you are running `freshclam` and `clamd` as root or with `sudo`, and you did not explicitely configure with `--disable-clamav`, you will want to ensure that the `DatabaseOwner` user specified in `freshclam.conf` owns the database directory so it can download signature udpates.

The user that `clamd`, `clamdscan`, and `clamscan` run as may be the same user, but if it isn't -- it merely needs _read_ access to the database directory.

If you choose to use the default `clamav` user to run `freshclam` and `clamd`, you'll need to create the clamav group and the clamav user account the first time you install ClamAV.

Prep by identifying an unused group id (gid), and an unused user UniqueID.

This command will display all current group PrimaryGroupIDs:
```bash
dscl . list /Groups PrimaryGroupID | tr -s ' ' | sort -n -t ' ' -k2,2
```

This command will display all current user UniqueIDs:
```bash
dscl . list /Users UniqueID | tr -s ' ' | sort -n -t ' ' -k2,2
```

Then, these commands can be used to create the `clamav` group and `clamav` user.
```bash
sudo dscl . create /Groups/clamav
sudo dscl . create /Groups/clamav RealName "Clam Antivirus Group"
sudo dscl . create /Groups/clamav gid 799           # Ensure this is unique!
sudo dscl . create /Users/clamav
sudo dscl . create /Users/clamav RealName "Clam Antivirus User"
sudo dscl . create /Users/clamav UserShell /bin/false
sudo dscl . create /Users/clamav UniqueID 599       # Ensure this is unique!
sudo dscl . create /Users/clamav PrimaryGroupID 799 # Must match the above gid!
```

Finally, you will want to set user ownership of the database directory.
For example:
```bash
sudo chown -R clamav:clamav /usr/local/share/clamav
```

### Usage

You should be all set up to run scans.

Take a look at our [usage documentation](../Usage.md) to learn about how to use ClamAV each of the utilities.

### Troubleshooting

#### Configure -- `gcc` failed to build executable

It is possible that `gcc`/`clang` is misconfigured. This is particularly likely after an upgrade to a newer versions of macOS (e.g after an upgrade from macOS High Sierra to macOS Mojave).

Open Terminal, and run the following:

```bash
xcode-select --install
```

This will download and install xcode developer tools and fix the problem. _You will be prompted (in the macOS GUI) to accept the license agreement before it will continue._
As a follow on step, you _may_ need to reset the path to Xcode if you have several versions or want the command line tools to run without Xcode.

```bash
xcode-select --switch /Applications/Xcode.app
xcode-select --switch /Library/Developer/CommandLineTools
```

> Solution shamelessly lifted from [apple stackexchange](https://apple.stackexchange.com/questions/254380/macos-mojave-invalid-active-developer-path)

#### Make -- failed to find correct openssl header or library files

Homebrew provides symlinks in `/usr/local/opt` to aid in the linking process:

```bash
$ ls -l /usr/local/opt/openssl*

lrwxr-xr-x  1 gary  admin    24B Aug 21 12:39 /usr/local/opt/openssl@ -> ../Cellar/openssl/1.0.2p
lrwxr-xr-x  1 gary  admin    24B Aug 21 12:39 /usr/local/opt/openssl@1.0@ -> ../Cellar/openssl/1.0.2p
lrwxr-xr-x  1 gary  admin    28B Nov 20  2017 /usr/local/opt/openssl@1.1@ -> ../Cellar/openssl@1.1/1.1.0g
```

If they aren't automatically detected you may experience issues linking openssl. You can work around this by explicitly listing the include `-I` and library `-L` paths.

For example:

```bash
./configure --with-openssl=/usr/local/Cellar/openssl/1.0.2l --with-libjson=yes --enable-check CPPFLAGS="-I/usr/local/opt/openssl@1.0/include" LDFLAGS="-L/usr/local/opt/openssl@1.0/lib/"
```

#### Make check -- unit tests failed for seemingly no reason

Similar to the above issue, it is possible for a mismatch in your development header files resulting in a working build that may fail the `check` test suite.

If you're seeing one or more failed tests on a stable release of ClamAV on macOS, the following may resolve the issue:

Open Terminal, and run the following:

```bash
sudo installer -pkg /Library/Developer/CommandLineTools/Packages/macOS_SDK_headers_for_macOS_10.14.pkg -target /
```

> Solution shamelessly lifted from [the pyenv github issue tracker](https://github.com/pyenv/pyenv/issues/1219)

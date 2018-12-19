# Installation on Redhat and CentOS Linux Distributions

Below are the steps for installing ClamAV from source on Redhat and CentOS Linux.

## Install prerequisites

1. Install ClamAV dependencies
    1. Install the developer tools
        ```bash
        sudo yum groupinstall "Development Tools"
        ```
    2. Install library dependencies
        ```bash
        sudo yum install openssl openssl-devel libcurl-devel zlib-devel libpng-devel libxml2-devel json-c-devel bzip2-devel pcre2-devel ncurses-devel
        ```
    3. (very optional) Those wishing to use clamav-milter may wish to install the following
        ```bash
        sudo yum install sendmail sendmail-devel
        ```

2. Install the unit testing dependencies
    ```bash
    sudo yum valgrind check
    ```

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

ClamAV's configure script should detect each of the above dependencies automatically.

### Typical `./configure` usage

```bash
./configure --enable-check
```

Once `./configure` completes, it will print a summary. Verify that the packages you installed are in fact being detected.

Example configure summary output:

```bash
configure: Summary of detected features follows
              OS          : linux-gnu
              pthreads    : yes (-lpthread)
configure: Summary of miscellaneous features
              check       : -lcheck_pic -pthread -lrt -lm -lsubunit
              fanotify    : yes
              fdpassing   : 1
              IPv6        : yes
configure: Summary of optional tools
              clamdtop    : -lncurses (auto)
              milter      : yes (disabled)
              clamsubmit  : yes (libjson-c-dev found at /usr), libcurl-devel found at /usr)
configure: Summary of engine performance features
              release mode: yes
              llvm        : no (disabled)
              mempool     : yes
configure: Summary of engine detection features
              bzip2       : ok
              zlib        : /usr
              unrar       : yes
              preclass    : yes (libjson-c-dev found at /usr)
              pcre        : /usr
              libmspack   : yes (Internal)
              libxml2     : yes, from /usr
              yara        : yes
              fts         : yes (libc)

```

### Additional popular `./configure` options

* `--with-systemdsystemunitdir` - Do not install `systemd` socket files. This option disables systemd support, but will allow you to `make install` to a user-owned directory without requiring `sudo`/root privileges:
    ```bash
    ./configure --with-systemdsystemunitdir=no
    ```
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
        ./configure --prefix=$HOME/clamav --disable-clamav --with-systemdsystemunitdir=no
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
* The `check7_clamd.hg.sh` (helgrind) is presently disabled and will be skipped.
  * For details, see: [the Git commit](https://github.com/Cisco-Talos/clamav-devel/commit/2a5d51809a56be9a777ded02969a7427a3c26713)

If you have a failure or an error in the unit tests, it could be that you are missing one or more of the prerequisites.

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

Additionally, if you are a running modern versions of Linux where the FANOTIFY kernel feature is enabled, `clamd` has a feature run with On-Access Scanning*. *When properly configured*, On-Access Scanning can scan files as they are accessed and optionally block access to the file in the event that a signature alerted.

  _Note_: At this time, for On-Access Scanning to work, `clamd` must run with `sudo`/root privileges. For more details, please see our documentation on On-Access Scanning.

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
    * `ScanOnAccess`
        * `OnAccessIncludePath`
        * `OnAccessExcludePath`
        * `OnAccessPrevention`

#### Configure SELinux for ClamAV

Certain distributions (notably RedHat variants) when operating with SELinux enabled use the non-standard `antivirus_can_scan_system` SELinux option instead of `clamd_can_scan_system`.

At this time, libclamav only sets the `clamd_can_scan_system` option, so you may need to manually enable `antivirus_can_scan_system`. If you don't perform this step, freshclam will log something like this when it tests the newly downloaded signature databases:

```
During database load : LibClamAV Warning: RWX mapping denied: Can't allocate RWX Memory: Permission denied
```

To allow ClamAV to operate under SELinux, run the following:
```bash
setsebool -P antivirus_can_scan_system 1
```

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

```
groupadd clamav
useradd -g clamav -s /bin/false -c "Clam Antivirus" clamav
```

Finally, you will want to set user ownership of the database directory.
For example:
```bash
sudo chown -R clamav:clamav /usr/local/share/clamav
```

### Usage

You should be all set up to run scans.

Take a look at our [usage documentation](../Usage.md) to learn about how to use ClamAV each of the utilities.

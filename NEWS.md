# ClamAV News

Note: This file refers to the source tarball. Things described here may differ
 slightly from the binary packages.

## 0.101.4

ClamAV 0.101.4 is a security patch release that addresses the following issues.

- An out of bounds write was possible within ClamAV's NSIS bzip2 library when
  attempting decompression in cases where the number of selectors exceeded the
  max limit set by the library (CVE-2019-12900). The issue has been resolved
  by respecting that limit.

  Thanks to Martin Simmons for reporting the issue [here](https://bugzilla.clamav.net/show_bug.cgi?id=12371)

- The zip bomb vulnerability mitigated in 0.101.3 has been assigned the
  CVE identifier CVE-2019-12625. Unfortunately, a workaround for the zip-bomb
  mitigation was immediately identified. To remediate the zip-bomb scantime
  issue, a scan time limit has been introduced in 0.101.4. This limit now
  resolves ClamAV's vulnerability to CVE-2019-12625.

  The default scan time limit is 2 minutes (120000 milliseconds).

  To customize the time limit:

  - use the `clamscan` `--max-scantime` option
  - use the `clamd` `MaxScanTime` config option

  Libclamav users may customize the time limit using the `cl_engine_set_num`
  function. For example:

  ```c
      cl_engine_set_num(engine, CL_ENGINE_MAX_SCANTIME, time_limit_milliseconds)
  ```

  Thanks to David Fifield for reviewing the zip-bomb mitigation in 0.101.3
  and reporting the issue.

## 0.101.3

ClamAV 0.101.3 is a patch release to address a vulnerability to non-recursive
zip bombs.

A Denial-of-Service (DoS) vulnerability may occur when scanning a zip bomb as a
result of excessively long scan times. The issue is resolved by detecting the
overlapping local file headers which characterize the non-recursive zip bomb
described by David Fifield,
[here](https://www.bamsoftware.com/hacks/zipbomb/).

Thank you to Hanno Böck for reporting the issue as it relates to ClamAV,
[here](https://bugzilla.clamav.net/show_bug.cgi?id=12356).

Also included in 0.101.3:

- Update of bundled the libmspack library from 0.8alpha to 0.10alpha, to
  address a buffer overflow vulnerability in libmspack < 0.9.1α.

## 0.101.2

ClamAV 0.101.2 is a patch release to address a handful of security related bugs.

This patch release is being released alongside the 0.100.3 patch so that users
who are unable to upgrade to 0.101 due to libclamav API changes are protected.

This release includes 3 extra security related bug fixes that do not apply to
prior versions.  In addition, it includes a number of minor bug fixes and
improvements.

- Fixes for the following vulnerabilities affecting 0.101.1 and prior:
  - [CVE-2019-1787](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-1787):
    An out-of-bounds heap read condition may occur when scanning PDF
    documents. The defect is a failure to correctly keep track of the number
    of bytes remaining in a buffer when indexing file data.
  - [CVE-2019-1789](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-1789):
    An out-of-bounds heap read condition may occur when scanning PE files
    (i.e. Windows EXE and DLL files) that have been packed using Aspack as a
    result of inadequate bound-checking.
  - [CVE-2019-1788](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-1788):
    An out-of-bounds heap write condition may occur when scanning OLE2 files
    such as Microsoft Office 97-2003 documents. The invalid write happens when
    an invalid pointer is mistakenly used to initialize a 32bit integer to
    zero. This is likely to crash the application.

- Fixes for the following vulnerabilities affecting 0.101.1 and 0.101.0 only:
  - [CVE-2019-1786](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-1786):
    An out-of-bounds heap read condition may occur when scanning malformed PDF
    documents as a result of improper bounds-checking.
  - [CVE-2019-1785](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-1785):
    A path-traversal write condition may occur as a result of improper input
    validation when scanning RAR archives. Issue reported by aCaB.
  - [CVE-2019-1798](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-1798):
    A use-after-free condition may occur as a result of improper error
    handling when scanning nested RAR archives. Issue reported by David L.

- Fixes for the following assorted bugs:
  - Added checks to prevent shifts from causing undefined behavior in HTML
    normalizer, UPX unpacker, ARJ extractor, CPIO extractor, OLE2 parser,
    LZW decompressor used in the PDF parser, Xz decompressor, and UTF-16 to
    ASCII transcoder.
  - Added checks to prevent integer overflow in UPX unpacker.
  - Fix for minor memory leak in OLE2 parser.
  - Fix to speed up PDF parser when handling truncated (or malformed) PDFs.
  - Fix for memory leak in ARJ decoder failure condition.
  - Fix for potential memory and file descriptor leak in HTML normalization code.

- Removed use of problematic feature that converted file descriptors to
  file paths. The feature was intended to improve performance when scanning
  file types, notably RAR archives, for which the API requires a file path.
  This feature caused issues in environments where the ClamAV engine is run
  in a low-permissions or sandboxed process. RAR archives are still supported
  with this change, but performance may suffer slightly if the file path is not
  provided in calls to `cl_scandesc_callback()`.
  - Added filename and tempfile names to scandesc calls in clamd.
  - Added general scan option `CL_SCAN_GENERAL_UNPRIVILEGED` to treat the scan
    engine as unprivileged, meaning that the scan engine will not have read
    access to the file. Provided file paths are for logging purposes only.
  - Added ability to create a temp file when scanning RAR archives when the
    process does not have read access to the file path provided (i.e.
    unprivileged is set, or an access check fails).

Thank you to the Google OSS-Fuzz project for identifying and reporting many of
the bugs patched in this release.

Additional thanks to the following community members for submitting bug reports:

- aCaB
- David L.

## 0.101.1

ClamAV 0.101.1 is an urgent patch release to address an issue in 0.101.0
specifically for developers that depend on libclamav.

The issue in 0.101.0 is that `clamav.h` required supporting headers that were
not provided on `make install`.

To address this issue, the internal `cltypes.h` header has been replaced by
a `clamav-types.h` that is generated on `./configure` and will be installed
alongside `clamav.h`.

### Other changes

- Increased the default CommandReadTimeout to reduce the chance of mail loss
  if using clamav-milter with the TCP socket. Contribution by Scott Kitterman.
- Fixes for `--with-libjson` and `--with-libcurl` to correctly accept library
  install path arguments.

### Acknowledgements

The ClamAV team thanks the following individuals for their code submissions:

- Scott Kitterman

## 0.101.0

ClamAV 0.101.0 is a feature release with an assortment of improvements that
we've cooked up over the past 6 months.

### Some of the more obvious changes

- Our user manual has been converted from latex/pdf/html into **Markdown**!
  Markdown is easier to read & edit than latex, and is easier to contribute
  to as it eliminates the need to generate documents (the PDF, HTML).
  Find the user manual under docs/UserManual[.md].
  [Check it out!](https://github.com/Cisco-Talos/clamav-devel/blob/dev/0.101/docs/UserManual.md)
- Support for RAR v5 archive extraction! We replaced the legacy C-based unrar
  implementation with RarLabs UnRAR 5.6.5 library. Licensing is the same as
  before, although our `libclamunrar_iface` supporting library has changed from
  LGPL to the BSD 3-Clause license.
- Libclamav API changes:
  - The following scanning functions now require a filename argument.
    This will enable ClamAV to report more details warning and error
    information in the future, and will also allow for more sensible temp
    file names. The filename argument may be `NULL` if a filename is not
    available.
    - `cl_scandesc`
    - `cl_scandesc_callback`
    - `cl_scanmap_callback`
  - Scanning options have been converted from a single flag bit-field into
    a structure of multiple categorized flag bit-fields. This change enabled
    us to add new scanning options requested by the community. In addition,
    the name of each scan option has changed a little.
    As a result, the API changes will require libclamav users to modify
    how they initialize and pass scan options into calls such as `cl_scandesc()`.
    For details:
    - [example code](https://github.com/Cisco-Talos/clamav-devel/blob/dev/0.101/examples/ex1.c#L89)
    - [documentation](https://github.com/Cisco-Talos/clamav-devel/blob/dev/0.101/docs/UserManual/libclamav.md#data-scan-functions)
  - With our move to openssl versions >1.0.1, the `cl_cleanup_crypto()` function
    has been deprecated. This is because cleanup of open-ssl init functions is
    now handled by an auto-deinit procedure within the openssl library, meaning
    the call to `EVP_cleanup()` may cause problems to processes external to Clam.
  - `CL_SCAN_HEURISTIC_ENCRYPTED` scan option was replaced by 2 new scan options:
    - `CL_SCAN_HEURISTIC_ENCRYPTED_ARCHIVE`
    - `CL_SCAN_HEURISTIC_ENCRYPTED_DOC`
- `clamd.conf` and command line interface (CLI) changes:
  - As in 0.100.2, the clamd.conf `OnAccessExtraScanning` has been temporarily
    disabled in order to prevent resource cleanup issues from impacting clamd
    stability. As noted below, `OnAccessExtraScanning` is an opt-in minor
    feature of on-access scanning on Linux systems and its loss does not
    significantly impact the effectiveness of on-access scanning.
    The option still exists, but the feature will not be enabled and a warning
    will show if `LogVerbose` is enabled.
    For details, see: https://bugzilla.clamav.net/show_bug.cgi?id=12048
  - "Heuristic Alerts" (aka "Algorithmic Detection") options have been changed
    to make the names more consistent. The original options are deprecated in
    0.101, and will be removed in a future feature release.
  - In addition, _two new scan options_ were added to alert specifically on
    encrypted archives or encrypted docs. Previous functionality did both, even
    though it claimed to be specific to archives:
  - Scan option details:

    | Old `clamd.conf` option          | *New* `clamd.conf` option    |
    | -------------------------------- | ---------------------------- |
    | `AlgorithmicDetection`           | `HeuristicAlerts`            |
    | `DetectBrokenExecutables`        | `AlertBrokenExecutables`     |
    | `PhishingAlwaysBlockCloak`       | `AlertPhishingCloak`         |
    | `PhishingAlwaysBlockSSLMismatch` | `AlertPhishingSSLMismatch`   |
    | `PartitionIntersection`          | `AlertPartitionIntersection` |
    | `BlockMax`                       | `AlertExceedsMax`            |
    | `OLE2BlockMacros`                | `AlertOLE2Macros`            |
    | `ArchiveBlockEncrypted`          | `AlertEncrypted`             |
    |                                  | `AlertEncryptedArchive`      |
    |                                  | `AlertEncryptedDoc`          |

    | Old `clamscan` option      | *New* `clamscan` option          |
    | -------------------------- | -------------------------------- |
    | `--algorithmic-detection`  | `--heuristic-alerts`             |
    | `--detect-broken`          | `--alert-broken`                 |
    | `--phishing-cloak`         | `--alert-phishing-cloak`         |
    | `--phishing-ssl`           | `--alert-phishing-ssl`           |
    | `--partition-intersection` | `--alert-partition-intersection` |
    | `--block-max`              | `--alert-exceeds-max`            |
    | `--block-macros`           | `--alert-macros`                 |
    | `--block-encrypted`        | `--alert-encrypted`              |
    |                            | `--alert-encrypted-archive`      |
    |                            | `--alert-encrypted-doc`          |

### Some more subtle improvements

- Logical signatures have been extended with a new subsignature type which
  allows for numerical byte sequence comparison. For those familiar with
  Snort, this byte comparison feature works similarly to the byte_extract
  and byte_test feature, in that it allows signature writers to extract and
  compare a specified number of bytes (offset from a match) against another
  numeric value. You can read more about this feature, see how it works, and
  look over examples in [our documentation](docs/UserManual/Signatures.md).
- Backwards compatibility improvements for detecting the OpenSSL dependency.
- Freshclam updated to match exit codes defined in the freshclam.1 man page.
- Upgrade from libmspack 0.5alpha to libmspack 0.7.1alpha. As a reminder, we
  support system-installed versions of libmspack. _However_, at this time the
  ClamAV-provided version of libmspack provides additional abilities to parse
  broken or non-standard CAB files beyond what the stock libmspack 0.7.1alpha
  provides. We are working with the upstream project to incorporate our
  modifications, and hopefully these changes will appear in a future release
  of libmspack.
- Updated the bundled 3rd party library libxml2 included for Windows builds to
  version 2.9.8.
- Updated the bundled 3rd party library pcre included for Windows builds to
  pcre2 version 10.31.
- Upgraded Aspack PE unpacking capability with support up to version 2.42.
- Improvements to PDF parsing capability.
- Replaced the Windows installer with a new installer built using InnoSetup 5.
- Improved `curl-config` detection logic.
  GitHub pull-request by Thomas Petazzoni.
- Added file type `CL_TYPE_LNK` to more easily identify Windows Shortcut files
  when writing signatures.
- Improved parsing of Windows executable (PE) Authenticode signatures. Pull-
  request by Andrew Williams.
  - Added support for Authenticode signature properties commonly used by
    Windows system files. These files are now much more likely to be
    whitelisted correctly.
  - Signature parsing now works correctly on big endian systems.

- Some simplification to freshclam mirror management code, including changes
  to reduce timeout on ignoring mirrors after errors, and to make freshclam
  more tolerant when there is a delay between the time the new signature
  database content is announced and the time that the content-delivery-network
  has the content available for download.
- Email MIME Header parsing changes to accept argument values with unbalanced
  quotes. Improvement should improve detection of attachments on malformed
  emails.
  GitHub pull-request by monnerat.
- Included the config filename when reporting errors parsing ClamAV configs.
  GitHub pull-request by Josh Soref.
- Improvement to build scripts for clamav-milter.
  GitHub pull-request by Renato Botelho.

### Other changes

- Removed option handler for `AllowSupplementaryGroups` from libfreshclam.
  This option was previously deprecated from freshclam in ClamAV 0.100.0 but
  remained in libfreshclam by mistake.
- In older versions of pcre2 and in pcre, a higher `PCRERecMatchLimit` may
  cause `clamd` to crash on select files. We have lowered the default
  `PCRERecMatchLimit` to 2000 to reduce the likelihood of a crash and have
  added warnings to recommend using pcre2 v10.30 or higher to eliminate
  the issue.

### Supporting infrastructure

As you might imagine, ClamAV is much more than just the tarball or EXE you
download and install. Here at Talos, we've been working hard on the support
infrastructure that's so easy to take for granted.

- Test Frameworks
  - Feature Testing:
    Throughout the development of ClamAV 0.101, our quality assurance engineers
    have been hard at work rebuilding our QA automation framework in Python from
    the ground up to test ClamAV features on 32-and-64bit versions:
    - Linux: Ubuntu, Debian, CentOS, Fedora
    - FreeBSD 11
    - Windows 10

    In addition to building out the framework, they've written over 260
    individual feature tests to validate correctness of the new features going
    into 0.101 as well as to validate many existing features.

  - Build Acceptance Testing:
    Another major task accomplished during the development of 0.101 was the
    creation of a build acceptance test framework that we run from our Jenkins
    CI server.

    Similar to the feature testing framework, our build acceptance framework
    tests accross 64bit and 32bit (where available):
    - macOS 10 (.10, .11, .13)
    - Windows (7, 10)
    - Debian (8, 9), Ubuntu (16.04, 18.04), CentOS (6, 7)
    - FreeBSD (10, 11)

    This pipeline creates our release materials including the Windows installers,
    and then validates that the basic install, update, start, scan, and stop
    procedures all work as expected each time commits are made to our
    development branches.

- Signature Database Distribution:
  During the course of ClamAV 0.101 development, our web and ops teams have been
  able to migrate us from a network of third-party mirrors over to use the
  services of CloudFlare to provide a more unified content-delivery-network.

  With CloudFlare, some users in geographic regions that had few mirrors
  will notice much improved signature update speeds and reliability.
  In addition, we're excited to be able to finally see user metrics that will
  help us continue to improve ClamAV.

  We are of course grateful to all of the community members who have donated
  their server bandwidth to mirror the ClamAV signature databases over the
  years. Thank-you so much!

- Development Processes:
  As many of you know, ClamAV 0.100 was in development for a good two years.
  Not only was this frustrating for users awaiting new features and bug-fixes,
  it also made for a difficult transition for users that weren't expecting two
  years worth of change when 0.100 landed.

  We have learned from the experience and are committed to providing shorter
  and more responsive ClamAV development cycles.

  ClamAV 0.101 is the first of many smaller feature releases where we created
  a roadmap with distinct deadlines and with specific planned features. We based
  the feature list on both community requests and our own needs and then
  executed that plan.

  We're very proud of ClamAV 0.101 and we hope you enjoy it.

### Acknowledgements

The ClamAV team thanks the following individuals for their code submissions:

- Andrew Williams
- Craig Andrews
- Josh Soref
- monnerat
- Renato Botelho
- tchernomax
- Thomas Petazzoni

## 0.100.2

ClamAV 0.100.2 is a patch release to address a set of vulnerabilities.

- Fixes for the following ClamAV vulnerabilities:
  - [CVE-2018-15378](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15378):
    Vulnerability in ClamAV's MEW unpacking feature that could allow an
    unauthenticated, remote attacker to cause a denial of service (DoS)
    condition on an affected device.
    Reported by Secunia Research at Flexera.
  - Fix for a 2-byte buffer over-read bug in ClamAV's PDF parsing code.
    Reported by Alex Gaynor.
- Fixes for the following vulnerabilities in bundled third-party libraries:
  - [CVE-2018-14680](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-14680):
    An issue was discovered in mspack/chmd.c in libmspack before 0.7alpha. It
    does not reject blank CHM filenames.
  - [CVE-2018-14681](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-14681):
    An issue was discovered in kwajd_read_headers in mspack/kwajd.c in
    libmspack before 0.7alpha. Bad KWAJ file header extensions could cause
    a one or two byte overwrite.
  - [CVE-2018-14682](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-14682):
    An issue was discovered in mspack/chmd.c in libmspack before 0.7alpha.
    There is an off-by-one error in the TOLOWER() macro for CHM decompression.
  - Additionally, 0.100.2 reverted 0.100.1's patch for CVE-2018-14679, and applied
    libmspack's version of the fix in its place.
- Other changes:
  - Some users have reported freshclam signature update failures as a result of
    a delay between the time the new signature database content is announced and
    the time that the content-delivery-network has the content available for
    download. To mitigate these errors, this patch release includes some
    modifications to freshclam to make it more lenient, and to reduce the time
    that freshclam will ignore a mirror when it detects an issue.
  - On-Access "Extra Scanning", an opt-in minor feature of OnAccess scanning on
    Linux systems, has been disabled due to a known issue with resource cleanup.
    OnAccessExtraScanning will be re-enabled in a future release when the issue
    is resolved. In the mean-time, users who enabled the feature in clamd.conf
    will see a warning informing them that the feature is not active.
    For details, see: https://bugzilla.clamav.net/show_bug.cgi?id=12048

Thank you to the following ClamAV community members for your code submissions
and bug reports!

- Alex Gaynor
- Hiroya Ito
- Laurent Delosieres, Secunia Research at Flexera

## 0.100.1

ClamAV 0.100.1 is a hotfix release to patch a set of vulnerabilities.

- Fixes for the following CVE's:
  - [CVE-2017-16932](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-16932):
    Vulnerability in libxml2 dependency (affects ClamAV on Windows only).
  - [CVE-2018-0360](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-0360):
    HWP integer overflow, infinite loop vulnerability.
    Reported by Secunia Research at Flexera.
  - [CVE-2018-0361](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-0361):
    ClamAV PDF object length check, unreasonably long time to parse relatively
    small file.  Reported by aCaB.
- Fixes for a few additional bugs:
  - Buffer over-read in unRAR code due to missing max value checks in table
    initialization.  Reported by Rui Reis.
  - Libmspack heap buffer over-read in CHM parser. Reported by Hanno Böck.
  - PDF parser bugs reported by Alex Gaynor.
    - Buffer length checks when reading integers from non-NULL terminated strings.
    - Buffer length tracking when reading strings from dictionary objects.
- HTTPS support for clamsubmit.
- Fix for DNS resolution for users on IPv4-only machines where IPv6 is not
  available or is link-local only.  Patch provided by Guilherme Benkenstein.

Thank you to the following ClamAV community members for your code submissions
and bug reports!

- aCaB
- Alex Gaynor
- Guilherme Benkenstein
- Hanno Böck
- Rui Reis
- Laurent Delosieres, Secunia Research at Flexera

## 0.100.0

ClamAV 0.100.0 is a feature release which includes many code submissions
 from the ClamAV community.  As always, it can be downloaded from our downloads
 page on clamav.net. Some of the more prominent submissions include:

- Interfaces to the Prelude SIEM open source package for collecting
  ClamAV virus events.
- Support for Visual Studio 2015 for Windows builds.  Please note that we
  have deprecated support for Windows XP, and while Vista may still work,
  we no longer test ClamAV on Windows XP or Vista.
- Support libmspack internal code or as a shared object library.
  The internal library is the default and includes modifications to enable
  parsing of CAB files that do not entirely adhere to the CAB file format.
- Linking with OpenSSL 1.1.0.
- Deprecation of the AllowSupplementaryGroups parameter statement
  in clamd, clamav-milter, and freshclam. Use of supplementary
  is now in effect by default.
- Numerous bug fixes, typo corrections, and compiler warning fixes.

Additionally, we have introduced important changes and new features in
ClamAV 0.100, including but not limited to:

- Deprecating internal LLVM code support. The configure script has changed
  to search the system for an installed instance of the LLVM development
  libraries, and to otherwise use the bytecode interpreter for ClamAV
  bytecode signatures. To use the LLVM Just-In-Time compiler for
  executing bytecode signatures, please ensure that the LLVM development
  package at version 3.6 or lower is installed. Using the deprecated LLVM
  code is possible with the command: `./configure --with-system-llvm=no`,
  but it no longer compiles on all platforms.
- Compute and check PE import table hash (a.k.a. "imphash") signatures.
- Support file property collection and analysis for MHTML files.
- Raw scanning of PostScript files.
- Fix clamsubmit to use the new virus and false positive submission web
  interface.
- Optionally, flag files with the virus "Heuristics.Limits.Exceeded" when
  size limitations are exceeded.
- Improved decoders for PDF files.
- Reduced number of compile time warnings.
- Improved support for C++11.
- Improved detection of system installed libraries.
- Fixes to ClamAV's Container system and the introduction of Intermediates
  for more descriptive signatures.
- Improvements to clamd's On-Access scanning capabilities for Linux.

### Acknowledgements

The ClamAV team thanks the following individuals for their code submissions:

- Andreas Schulze
- Anthony Chan
- Bill Parker
- Chris Miserva
- Daniel J. Luke
- Georgy Salnikov
- James Ralston
- Jonas Zaddach
- Keith Jones
- Marc Deslauriers
- Mark Allan
- Matthew Boedicker
- Michael Pelletier
- Ningirsu
- Sebastian Andrzej Siewior
- Stephen Welker
- Tuomo Soini

### Known Issues

ClamAV has an active issue queue and enjoys continual improvement but as sad as
 I am to say it, we couldn't address every bug in this release.  I want to draw
 your attention a couple bugs in particular so as not to frustrate users
 setting up ClamAV:

- Platform: macOS:
  - Bug:  If you attempt to build ClamAV with a system installed LLVM you may
    receive a linker error.  We recently changed default linking behavior to
    prefer dynamic linking over static linking.  As a result, we've uncovered a
    bug in building on macOS where dynamic linking against the LLVM libraries
    fails.  To work around this bug, please add the --with-llvm-linking=static
    option to your ./configure call.

- Platform: CentOS 6 32bit, older versions of AIX:
  - Bug:  On CentOS 6 32bit we observed that specific versions of zlib fail to
    correctly decompress the CVD signature databases.  If you are on an older
    system such as CentoOS 6 32bit and observe failures loading the signature
    database, please consider upgrading to a newer version of zlib.

- Platform: Miscellaneous
  - Bug:  When cross compiling on certain legacy systems (Solaris, AIX, OSX)
    against older system libraries that do not support strn functions linking
    may fail during compile time. While automatic checking is done during
    configure time to check for unsupported libs, this problem can be manually
    avoided using the --enable-strni configure flag if it is encountered.

## 0.99.4

ClamAV 0.99.4 is a hotfix release to patch a set of vulnerabilities.

- fixes for the following CVE's: CVE-2012-6706, CVE-2017-6419,
  CVE-2017-11423, CVE-2018-0202, and CVE-2018-1000085.
- also included are 2 fixes for file descriptor leaks as well fixes for
  a handful of other important bugs, including patches to support g++ 6, C++11.

Thank you to the following ClamAV community members for your code
submissions and bug reports!

Alberto Garcia
Bernhard Vogel
Francisco Oca
Hanno Böck
Jeffrey Yasskin
Keith Jones
mtowalski
Suleman Ali
yongji.oy
xrym

## 0.99.3

ClamAV 0.99.3 is a hotfix release to patch a set of vulnerabilities.

- fixes for the following CVE's: CVE-2017-6418, CVE-2017-6420,
  CVE-2017-12374, CVE-2017-12375, CVE-2017-12376, CVE-2017-12377,
  CVE-2017-12378, CVE-2017-12379, CVE-2017-12380.
- also included are 2 minor fixes to properly detect openssl install
  locations on FreeBSD 11, and prevent false warnings about zlib 1.2.1#
  version numbers.

Thank you to the following ClamAV community members for your code
submissions and bug reports!

- Alberto Garcia
- Daniel J. Luke
- Francisco Oca
- Sebastian A. Siewior
- Suleman Ali

Special thanks to Offensive Research at Salesforce.com for responsible disclosure.

## 0.99.2

ClamAV 0.99.2 is a release of bug fixes and minor enhancements.

- fix ups improving the reliability of several ClamAV file parsers.
- sigtool now decodes file type signatures (e.g., daily.ftm CVD file).
- now supporting libpcre2 in addition to libpcre.
- systemd support for clamd and freshclam. Patch provided by
  Andreas Cadhalpun.
- fixed builds on Mac OS X 10.10 & 10.11.
- improved debug info for certificate metadata.
- improved freshclam messaging when using a proxy.
- fixed some freshclam functionality when using private mirrors.
- clamd refinements of open file limitations on Solaris. Patch by
  Jim Morris
- clamav-milter signal handling for improved clean up during
  termination.

Thank you to the following ClamAV community members for your code
submissions and bug reports!

- Brandon Perry
- Sebastian Andrzej Siewior
- Andreas Cadhalpun
- Jim Morris
- Kai Risku
- Bill Parker
- Tomasz Kojm
- Steve Basford
- Daniel J. Luke
- James Ralston
- John Dodson

## 0.99.1

ClamAV 0.99.1 contains a new feature for parsing Hancom Office files
including extracting and scanning embedded objects. ClamAV 0.99.1
also contains important bug fixes. Please see ChangeLog for details.

Thanks to the following community members for code submissions used in
ClamAV 0.99.1:

- Jim Morris
- Andreas Cadhalpun
- Mark Allan
- Sebastian Siewior

## 0.99

ClamAV 0.99 contains major new features and changes. YARA rules,
Perl Compatible Regular Expressions, revamped on-access scanning
for Linux, and other new features join the many great features of ClamAV:

- Processing of YARA rules(some limitations- see signatures.pdf).
- Support in ClamAV logical signatures for many of the features
  added for YARA, such as Perl Compatible Regular Expressions,
  alternate strings, and YARA string attributes. See signatures.pdf
  for full details.
- New and improved on-access scanning for Linux. See the recent blog
  post and clamdoc.pdf for details on the new on-access capabilities.
- A new ClamAV API callback function that is invoked when a virus
  is found. This is intended primarily for applications running in
  all-match mode. Any applications using all-match mode must use
  the new callback function to record and report detected viruses.
- Configurable default password list to attempt zip file decryption.
- TIFF file support.
- Upgrade Windows pthread library to 2.9.1.
- A new signature target type for designating signatures to run
  against files with unknown file types.
- Improved fidelity of the "data loss prevention" heuristic
  algorithm. Code supplied by Bill Parker.
- Support for LZMA decompression within Adobe Flash files.
- Support for MSO attachments within Microsoft Office 2003 XML files.
- A new sigtool option(--ascii-normalize) allowing signature authors
  to more easily generate normalized versions of ascii files.
- Windows installation directories changed from \Program Files\Sourcefire\
  ClamAV to \Program Files\ClamAV or \Program Files\ClamAV-x64.

PLEASE NOTE:  If you are using clamd on-access scanning or have applications
using all-match mode, you will want to review the changes and make any necessary
adjustments before using ClamAV 0.99. Users of windows binaries need to be
aware of the change of installation directories.

Thank you to the ClamAV community members who sent patches and bug reports
included for ClamAV 0.99:

- Steve Basford
- Sebastian Andrzej Siewior
- Bill Parker
- Andreas Schulze
- Yann E. Morin
- Andreas Cadhalpun
- Dmitry Marakasov
- Michael Pelletier
- Felix Groebert
- Stephen Welker

## 0.98.7

ClamAV 0.98.7 is here! This release contains new scanning features
and bug fixes.

- Improvements to PDF processing: decryption, escape sequence
  handling, and file property collection.
- Scanning/analysis of additional Microsoft Office 2003 XML format.
- Fix infinite loop condition on crafted y0da cryptor file. Identified
  and patch suggested by Sebastian Andrzej Siewior. CVE-2015-2221.
- Fix crash on crafted petite packed file. Reported and patch
  supplied by Sebastian Andrzej Siewior. CVE-2015-2222.
- Fix false negatives on files within iso9660 containers. This issue
  was reported by Minzhuan Gong.
- Fix a couple crashes on crafted upack packed file. Identified and
  patches supplied by Sebastian Andrzej Siewior.
- Fix a crash during algorithmic detection on crafted PE file.
  Identified and patch supplied by Sebastian Andrzej Siewior.
- Fix an infinite loop condition on a crafted "xz" archive file.
  This was reported by Dimitri Kirchner and Goulven Guiheux.
  CVE-2015-2668.
- Fix compilation error after ./configure --disable-pthreads.
  Reported and fix suggested by John E. Krokes.
- Apply upstream patch for possible heap overflow in Henry Spencer's
  regex library. CVE-2015-2305.
- Fix crash in upx decoder with crafted file. Discovered and patch
  supplied by Sebastian Andrzej Siewior. CVE-2015-2170.
- Fix segfault scanning certain HTML files. Reported with sample by
  Kai Risku.
- Improve detections within xar/pkg files.

As always, we appreciate contributions of bug reports, code fixes,
and sample submission from the ClamAV community members:

Sebastian Andrzej Siewior
Minzhuan Gong
Dimitri Kirchner
Goulven Guiheux
John E. Krokes
Kai Risku

## 0.98.6

ClamAV 0.98.6 is a bug fix release correcting the following:

- library shared object revisions.
- installation issues on some Mac OS X and FreeBSD platforms.
- includes a patch from Sebastian Andrzej Siewior making
  ClamAV pid files compatible with systemd.
- Fix a heap out of bounds condition with crafted Yoda's
  crypter files. This issue was discovered by Felix Groebert
  of the Google Security Team.
- Fix a heap out of bounds condition with crafted mew packer
  files. This issue was discovered by Felix Groebert of the
  Google Security Team.
- Fix a heap out of bounds condition with crafted upx packer
  files. This issue was discovered by Kevin Szkudlapski of
  Quarkslab.
- Fix a heap out of bounds condition with crafted upack packer
  files. This issue was discovered by Sebastian Andrzej Siewior.
  CVE-2014-9328.
- Compensate a crash due to incorrect compiler optimization when
  handling crafted petite packer files. This issue was discovered
  by Sebastian Andrzej Siewior.

Thanks to the following ClamAV community members for code submissions
and bug reporting included in ClamAV 0.98.6:

Sebastian Andrzej Siewior
Felix Groebert
Kevin Szkudlapski
Mark Pizzolato
Daniel J. Luke

## 0.98.5

Welcome to ClamAV 0.98.5! ClamAV 0.98.5 includes important new features
for collecting and analyzing file properties. Software developers and
analysts may collect file property meta data using the ClamAV API for
subsequent analysis by ClamAV bytecode programs. Using these features
will require that libjson-c is installed, but otherwise libjson-c is not
needed.

Look for our upcoming series of blog posts to learn more about using the
ClamAV API and bytecode facilities for collecting and analyzing file
properties.

ClamAV 0.98.5 also includes these new features and bug fixes:

- Support for the XDP file format and extracting, decoding, and
  scanning PDF files within XDP files.
- Addition of shared library support for LLVM versions 3.1 - 3.5
  for the purpose of just-in-time(JIT) compilation of ClamAV
  bytecode signatures. Andreas Cadhalpun submitted the patch
  implementing this support.
- Enhancements to the clambc command line utility to assist
  ClamAV bytecode signature authors by providing introspection
  into compiled bytecode programs.
- Resolution of many of the warning messages from ClamAV compilation.
- Improved detection of malicious PE files.
- Security fix for ClamAV crash when using 'clamscan -a'. This issue
  was identified by Kurt Siefried of Red Hat.
- Security fix for ClamAV crash when scanning maliciously crafted
  yoda's crypter files. This issue, as well as several other bugs
  fixed in this release, were identified by Damien Millescamp of
  Oppida.
- ClamAV 0.98.5 now works with OpenSSL in FIPS compliant mode.
  Thanks to Reinhard Max for supplying the patch.
- Bug fixes and other feature enhancements. See Changelog or
  git log for details.

Thanks to the following ClamAV community members for code submissions
and bug reporting included in ClamAV 0.98.5:

Andreas Cadhalpun
Sebastian Andrzej Siewior
Damien Millescamp
Reinhard Max
Kurt Seifried

## 0.98.4

ClamAV 0.98.4 is a bug fix release. The following issues are now resolved:

- Various build problems on Solaris, OpenBSD, AIX.
- Crashes of clamd on Windows and Mac OS X platforms when reloading
  the virus signature database.
- Infinite loop in clamdscan when clamd is not running.
- Freshclam failure on Solaris 10.
- Buffer underruns when handling multi-part MIME email attachments.
- Configuration of OpenSSL on various platforms.
- Name collisions on Ubuntu 14.04, Debian sid, and Slackware 14.1.

Thanks to the following individuals for testing, writing patches, and
initiating quality improvements in this release:

Tuomo Soini
Scott Kitterman
Jim Klimov
Curtis Smith
Steve Basford
Martin Preen
Lars Hecking
Stuart Henderson
Ismail Paruk
Larry Rosenbaum
Dave Simonson
Sebastian Andrzej Siewior

## 0.98.2

Here are the new features and improvements in ClamAV 0.98.2:

- Support for common raw disk image formats using 512 byte sectors,
  specifically GPT, APM, and MBR partitioning.
- Experimental support of OpenIOC files. ClamAV will now extract file
  hashes from OpenIOC files residing in the signature database location,
  and generate ClamAV hash signatures. ClamAV uses no other OpenIOC
  features at this time. No OpenIOC files will be delivered through
  freshclam. See openioc.org and iocbucket.com for additional information
  about OpenIOC.
- All ClamAV sockets (clamd, freshclam, clamav-milter, clamdscan, clamdtop)
  now support IPV6 addresses and configuration parameters.
- Use OpenSSL file hash functions for improved performance. OpenSSL
  is now prerequisite software for ClamAV 0.98.2.
- Improved detection of malware scripts within image files. Issue reported
  by Maarten Broekman.
- Change to circumvent possible denial of service when processing icons within
  specially crafted PE files. Icon limits are now in place with corresponding
  clamd and clamscan configuration parameters. This issue was reported by
  Joxean Koret.
- Improvements to the fidelity of the ClamAV pattern matcher, an issue
  reported by Christian Blichmann.
- Opt-in collection of statistics. Statistics collected are: sizes and MD5
  hashes of files, PE file section counts and section MD5 hashes, and names
  and counts of detected viruses. Enable statistics collection with the
  --enable-stats clamscan flag or StatsEnabled clamd configuration
  parameter.
- Improvements to ClamAV build process, unit tests, and platform support with
  assistance and suggestions by Sebastian Andrzej Siewior, Scott Kitterman,
  and Dave Simonson.
- Patch by Arkadiusz Miskiewicz to improve error handling in freshclam.
- ClamAV 0.98.2 also includes miscellaneous bug fixes and documentation
  improvements.

Thanks to the following ClamAV community members for sending patches or reporting
bugs and issues that are addressed in ClamAV 0.98.2:

Sebastian Andrzej Siewior
Scott Kitterman
Joxean Koret
Arkadiusz Miskiewicz
Dave Simonson
Maarten Broekman
Christian Blichmann

--

REGARDING OPENSSL

In addition, as a special exception, the copyright holders give
permission to link the code of portions of this program with the
OpenSSL library under certain conditions as described in each
individual source file, and distribute linked combinations
including the two.

You must obey the GNU General Public License in all respects
for all of the code used other than OpenSSL.  If you modify
file(s) with this exception, you may extend this exception to your
version of the file(s), but you are not obligated to do so.  If you
do not wish to do so, delete this exception statement from your
version.  If you delete this exception statement from all source
files in the program, then also delete it here.

## 0.98.1

ClamAV 0.98.1 provides improved support of Mac OS X platform, support for new file types, and
quality improvements. These include:

- Extraction, decompression, and scanning of files within Apple Disk Image (DMG) format.

- Extraction, decompression, and scanning of files within Extensible Archive (XAR) format.
  XAR format is commonly used for software packaging, such as PKG and RPM, as well as
  general archival.

- Decompression and scanning of files in "Xz" compression format.

- Recognition of Open Office XML formats.

- Improvements and fixes to extraction and scanning of ole formats.

- Option to force all scanned data to disk. This impacts only a few file types where
  some embedded content is normally scanned in memory. Enabling this option
  ensures that a file descriptor exists when callback functions are used, at a small
  performance cost. This should only be needed when callback functions are used
  that need file access.

- Various improvements to ClamAV configuration, support of third party libraries,
  and unit tests.

## 0.98

ClamAV 0.98 includes many new features, across all the different components
of ClamAV. There are new scanning options, extensions to the libclamav API,
support for additional filetypes, and internal upgrades.

- Signature improvements: New signature targets have been added for
  PDF files, Flash files and Java class files. (NOTE: Java archive files
  (JAR) are not part of the Java target.) Hash signatures can now specify
  a '*' (wildcard)  size if the size is unknown. Using wildcard size
  requires setting the minimum engine FLEVEL to avoid backwards
  compatibility issues. For more details read the ClamAV Signatures
  guide.

- Scanning enhancements: New filetypes can be unpacked and scanned,
  including ISO9660, Flash, and self-extracting 7z files. PDF
  handling is now more robust and better handles encrypted PDF files.

- Authenticode: ClamAV is now aware of the certificate chains when
  scanning signed PE files. When the database contains signatures for
  trusted root certificate authorities, the engine can whitelist
  PE files with a valid signature. The same database file can also
  include known compromised certificates to be rejected! This
  feature can also be disabled in clamd.conf (DisableCertCheck) or
  the command-line (nocerts).

- New options: Several new options for clamscan and clamd have been
  added. For example, ClamAV can be set to print infected files and
  error files, and suppress printing OK results. This can be helpful
  when scanning large numbers of files. This new option is "-o" for
  clamscan and "LogClean" for clamd. Check clamd.conf or the clamscan
  help message for specific details.

- New callbacks added to the API: The libclamav API has additional hooks
  for developers to use when wrapping ClamAV scanning. These function
  types are prefixed with "clcb_" and allow developers to add logic at
  certain steps of the scanning process without directly modifying the
  library. For more details refer to the clamav.h file.

- More configurable limits: Several hardcoded values are now configurable
  parameters, providing more options for tuning the engine to match your
  needs. Check clamd.conf or the clamscan help message for specific
  details.

- Performance improvements: This release furthers the use of memory maps
  during scanning and unpacking, continuing the conversion started in
  prior releases. Complex math functions have been switched from
  libtommath to tomsfastmath functions. The A/C matcher code has also
  been optimized to provide a speed boost.

- Support for on-access scanning using Clamuko/Dazuko has been replaced
  with fanotify. Accordingly, clamd.conf settings related to on-access
  scanning have had Clamuko removed from the name. Clamuko-specific
  configuration items have been marked deprecated and should no longer
  be used.

There are also fixes for other minor issues and code quality changes. Please
see the ChangeLog file for details.

--
The ClamAV team (https://www.clamav.net/about.html#credits)

## 0.97.8

ClamAV 0.97.8 addresses several reported potential security bugs. Thanks to
Felix Groebert of the Google Security Team for finding and reporting these
issues.

## 0.97.7

ClamAV 0.97.7 addresses several reported potential security bugs. Thanks to
Felix Groebert, Mateusz Jurczyk and Gynvael Coldwind of the Google Security
Team for finding and reporting these issues.

## 0.97.6

ClamAV 0.97.6 includes minor bug fixes and detection improvements.
ClamAV 0.97.6 corrects bug 5252 "CL_EFORMAT: Bad format or broken data ERROR
reported as scan result."

## 0.97.5

ClamAV 0.97.5 addresses possible evasion cases in some archive formats
(CVE-2012-1457, CVE-2012-1458, CVE-2012-1459). It also addresses stability
issues in portions of the bytecode engine. This release is recommended for
all users.

## 0.97.4

ClamAV 0.97.4 includes minor bugfixes, detection improvements and initial
support for on-access scanning under Mac OS X (see contrib/ClamAuth).
This update is recommended for all users.

## 0.97.3

ClamAV 0.97.3 is a minor bugfix release and is recommended for all
users. Please refer to the ChangeLog file for details.

## 0.97.2

ClamAV 0.97.2 fixes problems with the bytecode engine, Safebrowsing detection,
hash matcher, and other minor issues. Please see the ChangeLog file for
details.

## 0.97.1

This is a bugfix release recommended for all users. Please refer to the
ChangeLog file for details.

--
The ClamAV team (https://www.clamav.net/about.html#credits)

## 0.97

ClamAV 0.97 brings many improvements, including complete Windows support
(all major components compile out-of-box under Visual Studio), support for
signatures based on SHA1 and SHA256, better error detection, as well as
speed and memory optimizations. The complete list of changes is available
in the ChangeLog file. For upgrade notes and tips please see:
https://wiki.clamav.net/Main/UpgradeNotes097

With Sourcefire, Inc. acquisition of Immunet Corp., ClamAV for Windows
3.0 has been renamed Immunet 3.0, powered by ClamAV. This release
contains the fully integrated LibClamAV 0.97 engine for offline,
OnDemand, and OnAccess scanning. Immunet 3.0 users can now utilize
the full power of the LibClamAV engine, all the ClamAV signatures,
and creation of custom signatures on any platform running Immunet 3.0,
powered by ClamAV. If you run Windows systems in your environment and
need an AV solution to protect them, give Immunet 3.0, powered by ClamAV
a try; you can download it from https://www.clamav.net/download.html#otherversions

--
The ClamAV team (https://www.clamav.net/about.html#credits)

## 0.96.5

ClamAV 0.96.5 includes bugfixes and minor feature enhancements, such as
improved handling of detection statistics, better file logging,
and support for custom database URLs in freshclam. Please refer to the
ChangeLog for details.

--
The ClamAV team (https://www.clamav.net/about.html#credits)

## 0.96.4

ClamAV 0.96.4 is a bugfix release recommended for all users.

--
The ClamAV team (https://www.clamav.net/about.html#credits)

## 0.96.3

This release fixes problems with the PDF parser and the internal bzip2
library. A complete list of changes is available in the Changelog file.

--
The ClamAV team (https://www.clamav.net/about.html#credits)

## 0.96.2

ClamAV 0.96.2 brings a new PDF parser, performance and memory improvements,
and a number of bugfixes and minor enhancements. This upgrade is recommended
for all users.

## 0.96.1

This is a bugfix release, please refer to the ChangeLog for the complete
list of changes.

--
The ClamAV team (https://www.clamav.net/about.html#credits)

## 0.96

This release of ClamAV introduces new malware detection mechanisms and other
significant improvements to the scan engine. The key features include:

- The Bytecode Interpreter: the interpreter built into LibClamAV allows
  the signature writers to create and distribute very complex detection
  routines and remotely enhance the scanner's functionality

- Heuristic improvements: improve the PE heuristics detection engine by
  adding support of bogus icons and fake PE header information. In a
  nutshell, ClamAV can now detect malware that tries to disguise itself
  as a harmless application by using the most common Windows program icons.

- Signature Improvements: logical signature improvements to allow more
  detailed matching and referencing groups of signatures. Additionally,
  improvements to wildcard matching on word boundaries and newlines.

- Support for new archives: 7zip, InstallShield and CPIO. LibClamAV
  can now transparently unpack and inspect their contents.

- Support for new executable file formats: 64-bit ELF files and OS X
  Universal Binaries with Mach-O files. Additionally, the PE module
  can now decompress and inspect executables packed with UPX 3.0.

- Support for DazukoFS in clamd

- Performance improvements: overall performance improvements and memory
  optimizations for a better overall resource utilization experience.

- Native Windows Support: ClamAV will now build natively under Visual
  Studio. This will allow 3rd Party application developers on Windows
  to easily integrate LibClamAV into their applications.

The complete list of changes is available in the ChangeLog file. For upgrade
notes and tips please see: https://wiki.clamav.net/Main/UpgradeNotes096

--
The ClamAV team (https://www.clamav.net/about.html#credits)

## 0.95.3

ClamAV 0.95.3 is a bugfix release recommended for all users.
Please refer to the ChangeLog included in the source distribution
for the list of changes.

--
The ClamAV team (https://www.clamav.net/about.html#credits)

## 0.95.2

This version improves handling of archives, adds support for --file-list
in clamscan and clamdscan, and fixes various issues found in previous
releases.

--
The ClamAV team (https://www.clamav.net/about.html#credits)

## 0.95.1

This is a bugfix release only, please see the ChangeLog for details.

--
The ClamAV team (https://www.clamav.net/about.html#credits)

## 0.95

ClamAV 0.95 introduces many bugfixes, improvements and additions. To make
the transition easier, we put various tips and upgrade notes on this page:
https://wiki.clamav.net/Main/UpgradeNotes095. For detailed list of changes
and bugfixes, please see the ChangeLog.

The following are the key features of this release:

- Google Safe Browsing support: in addition to the heuristic and signature
  based phishing detection mechanisms already available in ClamAV, the
  scanner can now make use of the Google's blacklists of suspected
  phishing and malware sites. The ClamAV Project distributes a constantly
  updated Safe Browsing database, which can be automatically fetched by
  freshclam. For more information, please see freshclam.conf(5) and
  https://www.clamav.net/documents/safebrowsing.

- New clamav-milter: The program has been redesigned and rewritten from
  scratch. The most notable difference is that the internal mode has been
  dropped which means that now a working clamd companion is required.
  The milter now also has its own configuration file.

- Clamd extensions: The protocol has been extended to lighten the load
  that clamd puts on the system, solve limitations of the old protocol,
  and reduce latency when signature updates are received. For more
  information about the new extensions please see the official
  documentation and the upgrade notes.

- Improved API: The API used to program ClamAV's engine (libclamav) has
  been redesigned to use modern object-oriented techniques and solves
  various API/ABI compatibility issues between old and new releases.
  You can find more information in Section 6 of clamdoc.pdf and in
  the upgrade notes.

- ClamdTOP: This is a new program that allows system administrators to
  monitor clamd. It provides information about the items in the clamd's
  queue, clamd's memory usage, and the version of the signature database,
  all in real-time and in nice curses-based interface.

- Memory Pool Allocator: Libclamav now includes its own memory pool
  allocator based on memory mapping. This new solution replaces the
  traditional malloc/free system for the copy of the signatures that
  is kept in memory. As a result, clamd requires much less memory,
  particularly when signature updates are received and the database is
  loaded into memory.

- Unified Option Parser: Prior to version 0.95 each program in ClamAV's
  suite of programs had its own set of runtime options. The new general
  parser brings consistency of use and validation to these options across
  the suite. Some command line switches of clamscan have been renamed
  (the old ones will still be accepted but will have no effect and will
  result in warnings), please see clamscan(1) and clamscan --help for
  the details.

--
The ClamAV team (https://www.clamav.net/about.html#credits)

## 0.94.2

This is a bugfix release, please refer to the ChangeLog for a complete
list of changes.

--
The ClamAV team (https://www.clamav.net/about.html#credits)

## 0.94.1

ClamAV 0.94.1 fixes some issues that were found in previous releases and
includes one new feature, "Malware Statistics Gathering." This is an optional
feature that allows ClamAV users optionally to submit statistics to us about
what they detect in the field. We will then use these data to determine what
types of malware are the most detected in the field and in what geographic
area they are. It will also allow us to publish summary data on www.clamav.net
where our users will be able to monitor the latest threats. You can help us
by enabling SubmitDetectionStats in freshclam.conf.

For more details, please refer to the ChangeLog

--
The ClamAV team (https://www.clamav.net/about.html#credits)

## 0.94

Sourcefire and the ClamAV team are pleased to announce the release of
ClamAV 0.94. The following are the key features and improvements of this
version:

- Logical Signatures: The logical signature technology uses operators
  such as AND, OR and NOT to allow the combination of more than one
  signature into one entry in the signature database resulting in
  more detailed and flexible pattern matching.

- Anti-phishing Technology: Users can now change the priority and reporting
  of ClamAV's heuristic anti-phishing scanner within the detection engine
  process. They can choose whether, when scanning a suspicious file, ClamAV
  should stop scanning and report the phish, or continue to scan in case the
  file contains other malware (clamd: HeuristicScanPrecedence,
  clamscan: --heuristic-scan-precedence)

- Disassembly Engine: The initial version of the disassembly engine improves
  ClamAV's detection abilities.

- PUA Detection: Users can now decide which PUA signatures should be loaded
  (clamd: ExcludePUA, IncludePUA; clamscan: --exclude-pua, --include-pua)

- Data Loss Prevention (DLP): This version includes a new module that, when
  enabled, scans data for the inclusion of US formated Social Security
  Numbers and credit card numbers (clamd: StructuredDataDetection,
  clamscan: --detect-structured; additional fine-tuning options are available)

- IPv6 Support: Freshclam now supports IPv6

- Improved Scanning of Scripts: The normalization of scripts now covers
  JavaScript

- Improved QA and Unit Testing: The improved QA process now includes
  API testing and new library of test files in various formats that are
  tested on a wide variety of systems (try running 'make check' in the source
  directory)

You may need to run 'ldconfig' after installing this version.

** This version drops the special support for Cygwin. Our QA process showed
** serious problems with ClamAV builds under Cygwin due to some low-level
** incompatibilities in the POSIX compatibility layer, resulting in unreliable
** ClamAV behaviour.

--
The ClamAV team (https://www.clamav.net/about.html#credits)

## 0.93.3

This release fixes a problem in handling of .cld files introduced in 0.93.2.

--
The ClamAV team (https://www.clamav.net/about.html#credits)

## 0.93.2

This release fixes and re-enables the Petite unpacker, improves database
loading and solves some other minor issues.

## 0.93.1

This version improves handling of PDF, CAB, RTF, OLE2 and HTML files
and includes various bugfixes for 0.93 issues.

--
The ClamAV team (https://www.clamav.net/about.html#credits)

## 0.93

This release introduces many new features and engine enhancements, please
see the notes below for the list of major changes. The most visible one
is the new logic in scan limits which affects some command line and config
options of clamscan and clamd. Please see clamscan(1) and clamd.conf(5)
and the example config file for more information on the new options.

Most important changes include:

- libclamav:
  - New logic in scan limits: provides much more efficient protection against
    DoS attacks but also results in different command line and config options
    to clamscan and clamd (see below)
  - New/improved modules: unzip, SIS, cabinet, CHM, SZDD, text normalisator,
    entity converter
  - Improved filetype detection; filetype definitions can be remotely updated
  - Support for .cld containers (which replace .inc directories)
  - Improved pattern matcher and signature formats
  - More efficient scanning of HTML files
  - Many other improvements

- clamd:
  - NEW CONFIG FILE OPTIONS: MaxScanSize, MaxFileSize, MaxRecursion, MaxFiles
  - ** THE FOLLOWING OPTIONS ARE NO LONGER SUPPORTED **: MailMaxRecursion,
    ArchiveMaxFileSize, ArchiveMaxRecursion, ArchiveMaxFiles,
    ArchiveMaxCompressionRatio, ArchiveBlockMax

- clamscan:
  - NEW CMDLINE OPTIONS: --max-filesize, --max-scansize
  - REMOVED OPTIONS: --block-max, --max-space, --max-ratio

- freshclam:
  - NEW CONFIG OPTION CompressLocalDatabase
  - NEW CMDLINE SWITCH --no-warnings
  - main.inc and daily.inc directories are no longer used by ClamAV; please
    remove them manually from your database directory

--
The ClamAV team (https://www.clamav.net/about.html#credits)

## 0.92.1

This is a bugfix release, please refer to the ChangeLog for a complete
list of changes.

--
The ClamAV team (https://www.clamav.net/about.html#credits)

## 0.92

This release provides various bugfixes, optimizations and improvements
to the scanning engine. The new features include support for ARJ and
SFX-ARJ archives, AutoIt, basic SPF parser in clamav-milter (to reduce
phishing false-positives), faster scanning and others (see ChangeLog).
To get a consistent behaviour of the anti-phishing module on all platforms,
libclamav now includes the regex library from OpenBSD.

--
The ClamAV team (https://www.clamav.net/about.html#credits)

## 0.91.2

This release fixes various bugs in libclamav, freshclam and clamav-milter,
and adds support for PUA (Potentially Unwanted Application) signatures
(clamscan: --detect-pua, clamd: DetectPUA).

** Announcement **

Dear ClamAV users,

On August 17, Sourcefire, the creators of Snort, acquired the ClamAV project.
The full announcement is available here:

http://www.sourcefire.com/products/clamav/

We'd like to thank everyone in the ClamAV community for their dedication to
the project. The acquisition by Sourcefire is a testament to the hard work of
the entire ClamAV community in developing cutting edge technology that truly
showcases the promise of the open source model. With the additional resources
Sourcefire will provide we look forward to working with the community to
continue the advancement of ClamAV.

Sourcefire now owns ClamAV project and related trademarks, as well as the
source code copyrights held by the five principal members of the ClamAV team.
Sourcefire will also assume control of the ClamAV project including: the
ClamAV.org domain, web site and web site content; and the ClamAV Sourceforge
project page.

What's most important is that from the end-user perspective very little will
change beyond the additional resources Sourcefire will provide in our
continued efforts to advance the ClamAV technology and improve our ability to
interact with the open source community. The core team will continue to lead
the advancement of ClamAV and the CVD as employees of Sourcefire. Both the
ClamAV engine and the signature database will remain under GPL.

--
The ClamAV team (https://www.clamav.net/about.html#credits)

## 0.91.1

This release fixes stability and other issues of 0.91.

--
The ClamAV team (https://www.clamav.net/about.html#credits)

## 0.91

ClamAV 0.91 is the first release to enable the anti-phishing technology
in default builds. This technology combines heuristics with special
signatures and provides effective protection against phishing threats.
Other important changes and add-ons in this version include:

- unpacker for NSIS (Nullsoft Scriptable Install System) self-extracting
  archives
- unpacker for ASPack 2.12
- new implementation of the Aho-Corasick pattern matcher providing
  better detection for wildcard enabled signatures
- support for nibble matching and floating offsets
- improved handling of .mdb files (fixes long startup times)
- extraction of PE files embedded into other executables
- better handling of PE & UPX
- removed dependency on libcurl (improves stability)
- libclamav.dll available under Windows
- IPv6 support in clamav-milter
- many other improvements and bugfixes

--
The ClamAV team (https://www.clamav.net/about.html#credits)

## 0.90.3

This release fixes some security bugs in libclamav and improves stability
under Solaris. Please see ChangeLog for complete list of changes.

If your system is suffering from long clamscan startup times, please
consider installing 0.91rc1 which is due to be released shortly
after 0.90.3.

--
The ClamAV team (https://www.clamav.net/about.html#credits)

## 0.90.2

This release fixes many problems in libclamav and freshclam.

--
The ClamAV team (https://www.clamav.net/about.html#credits)

## 0.90.1

This release includes various bugfixes and code enhancements. Please
see ChangeLog for complete list of changes.

** Important note **: please run 'ldconfig' after installing this version.

--
The ClamAV team (https://www.clamav.net/about.html#credits)

## 0.90

The ClamAV team is proud to announce the long awaited ClamAV 0.90.
This version introduces lots of new interesting features and marks
a big step forward in the development of our antivirus engine.

The most important change is the introduction of scripted updates.
Instead of transferring the whole cvd file at each update, only the
differences between the latest cvds and the previous versions will be
transferred.

In case the local copy of the latest cvd is corrupted or the scripted
update fails for some reason, freshclam will fallback to the old method.
Similarly to cvd files, scripted updates are compressed and digitally signed
and are already being distributed. They will dramatically reduce traffic on
our mirrors and will allow us to release even more updates in the future.

Another noticeable change is the new configuration syntax: you can now turn
single options on and off, the old crude hack of "DisableDefaultScanOptions"
is no longer required.

Cosmetic changes apart, the 0.9x series introduces lots of new code, but some
parts are not compiled in by default because they are not ready for production
systems yet. You are encouraged to pass the --enable-experimental flag to
./configure when compiling ClamAV. The experimental code introduces many
improvements in terms of detection rate and performances. If you find a bug,
please take some time to report it on our bugzilla: https://bugzilla.clamav.net.
Your help in testing the new code is really appreciated. The experimental code
introduces many improvements in terms of detection rate and performances.

RAR3, SIS and SFX archives support is finally available together with
new unpackers and decryptors: pespin, sue, yc, wwpack32, nspack, mew, upack
and others. Additionally, ClamAV now includes better mechanisms for scanning
ELF, PDF and tar files. The email decoding has been improved to reduce both
the memory requirements and the time taken to process attachments.

As part of the Google Summer of Code program, we have introduced support for
a new phishing signatures format that has proved very effective in detecting
phishing emails. The ClamAV phishing module allows better and more generic
detection of phishing emails by searching for URLs in email messages, and
comparing the real site with the URL displayed to the user in the message.

On the performance side, support for the MULTISCAN command has been
implemented in clamd, allowing to scan multiple files simultaneously.
Support for Sensory Networks' NodalCore acceleration technology
(https://www.clamav.net/nodalcore/) is now available in ClamAV and will be
compiled in if the ncore libraries are detected at compile time. NodalCore
acceleration allows highly improved scan speeds on systems equipped with
NodalCore cards.

Detailed list of changes:

- libclamav:
  - New unpacker for RAR3, RAR2 and RAR1
  - Rewritten unpackers for Zip and CAB files
  - Support for RAR-SFX, Zip-SFX and CAB-SFX archives
  - New PE parsing model:
    - Accurate virtual and raw size and offset calculations
    - Proper parsing of executables with weird/handcrafted/uncommon headers
    - Proper handling (or skipping) of ghost sections at various places in the
      code
    - Rebuild improvements for various unpackers
    - Adjusted alignment on rebuilt executables
    - Proper handling of out of sections offsets
    - Broken exe detection now mimics the XPSP2 loader
    - Lots of misc improvements and fixes
  - Support for PE32+ (64-bit) executables
  - Support for MD5 signatures based on PE sections (.mdb)
  - ELF file parser
  - Support for Sensory Networks' NodalCore hardware acceleration technology
  - Advanced phishing detection module (experimental)
  - Signatures are stored in separate trees depending on their target type
  - Algorithmic detection can be controlled with CL_SCAN_GENERAL_HEURISTICS
  - Support for new obfuscators: SUE, Y0da Cryptor, CryptFF
  - Support for new packers: NsPack, wwpack32, MEW, Upack
  - Support for SIS files (SymbianOS packages)
  - Support for PDF and RTF files
  - New encoding and entity normalizer (experimental)

- clamd:
  - New config file parser:
    - all options require arguments (options without args must be now followed
      by boolean values: (yes, no), (1, 0), or (true, false)
    - optional arguments (as in NotifyClamd) are no longer supported
    - removed "DisableDefaultScanOptions" option (scan options can be
      configured individually)
  - TCP and local sockets can be operated simultaneously
  - New command: MULTISCAN (scan directory with multiple threads)
  - New option AlgorithmicDetection
  - New option ScanELF
  - New option NodalCoreAcceleration (requires hardware accelerator)
  - New option PhishingSignatures
  - New options to control the phishing module:
    - PhishingRestrictedScan
    - PhishingScanURLs
    - PhishingAlwaysBlockSSLMismatch
    - PhishingAlwaysBlockCloak

- clamav-milter:
  - Black list mode: optionally black lists an IP for a configurable amount
    of time
  - Black hole mode: detects emails that will be discarded and refrains from
    scanning them
  - Reporting: ability to report phishing attempts to anti-phishing
    organisations to help close the sites
  - Improved load balancing for scanning with clusters
  - Removed -b option (enable BOUNCE compile time option to re-enable the
    option)

- clamscan:
  - New options: --no-phishing-sigs, --no-algorithmic (disable phishing and
    algorithmic detection respectively)
  - New options to control the phishing module: --no-phishing-scan-urls,
    --no-phishing-restrictedscan, --phishing-ssl, --phishing-cloak
  - New option: --ncore (requires hardware accelerator)
  - New option: --no-elf
  - New option: --copy

- freshclam:
  - Interpreter for .cdiff files (scripted updates)
  - Initial version of mirror manager
  - New option: --list-mirrors (list details on mirrors accessed by the mirror
    manager)
  - New option HTTPUserAgent to force different User-Agent header

- sigtool:
  - New option: --utf16-decode (decode UTF16 encoded files)
  - New options: --diff, --run-cdiff, --verify-cdiff (update script management)
  - New option: --mdb (generated .mdb compatible signatures)

- clamconf: initial version of configuration utility for clamd and freshclam

We are happy to announce new interesting software with support for ClamAV:

- AqMail - a POP3 client with additional filtering
- ClamFS - a FUSE-based file system with on-access anti-virus scanning
- c-icap - an ICAP server coded in C with support for ClamAV
- MailCleaner - a complete email filtering gateway
- mod_streamav - a ClamAV based antivirus filter for Apache 2
- pyClamd - a python interface to Clamd

More information at https://www.clamav.net/download.html#tools

--
The ClamAV team (https://www.clamav.net/about.html#credits)

## 0.88.7

This version improves scanning of mail and tar files.

--
The ClamAV team (https://www.clamav.net/about.html#credits)

## 0.88.6

Changes in this release include better handling of network problems in
freshclam and other minor bugfixes.

The ClamAV developers encourage all users to give a try to the latest
beta version of 0.90!

--
The ClamAV team (https://www.clamav.net/about.html#credits)

## 0.88.5

This version fixes a crash in the CHM unpacker and a heap overflow in the
function rebuilding PE files after unpacking.

--
The ClamAV team (https://www.clamav.net/about.html#credits)

## 0.88.4

This release fixes a possible heap overflow in the UPX code.

--
The ClamAV team (https://www.clamav.net/about.html#credits)

## 0.88.3

This version fixes handling of large binhex files and multiple alternatives in
virus signatures.

--
The ClamAV team (https://www.clamav.net/about.html#credits)

## 0.88.2

This release improves virus detection, fixes zip handling on 64-bit
architectures and possible security problem in freshclam.

Following the 0.88.1 release some portals and security related websites
published incorrect information on security problems of 0.88. To avoid
such incidents in the future, every new ClamAV package will be released
together with detailed information about security bugs it fixes.

--
The ClamAV team (https://www.clamav.net/about.html#credits)

## 0.88.1

This version fixes a number of minor bugs and provides code updates
to improve virus detection.

--
The ClamAV team (https://www.clamav.net/about.html#credits)

## 0.88

A possible heap overflow in the UPX code has been fixed. General improvements
include better zip and mail processing, and support for a self-protection mode.
The security of the UPX, FSG and Petite modules has been improved, too.

--
The ClamAV team (https://www.clamav.net/about.html#credits)

## 0.87.1

This release includes major bugfixes for problems with handling TNEF
attachments, cabinet files and FSG compressed executables.

--
The ClamAV team (https://www.clamav.net/about.html#credits)

## 0.87

This version fixes vulnerabilities in handling of UPX and FSG compressed
executables. Support for PE files, Zip and Cabinet archives has been improved
and other small bugfixes have been made. The new option "--on-outdated-execute"
allows freshclam to run a command when system reports a new engine version.

--
The ClamAV team (https://www.clamav.net/about.html#credits)

## 0.86.2

Changes in this release include fixes for three possible integer overflows
in libclamav, improved scanning of Cabinet and FSG compressed files, better
database handling in clamav-milter, and others.

--
The ClamAV team (https://www.clamav.net/about.html#credits)

## 0.86.1

A possible crash in the libmspack's Quantum decompressor has been fixed.

--
The ClamAV team (https://www.clamav.net/about.html#credits)

## 0.86

This release introduces a number of bugfixes and cleanups. Possible descriptor
leaks in archive unpackers and mishandling of fast track uuencoded files have
been fixed in libclamav. Database reloading in clamav-milter has been improved.

--
The ClamAV team (https://www.clamav.net/about.html#credits)

## 0.85.1

A problem where an email with more than one content-disposition type line,
one or more of which was empty, could crash libclamav has been fixed. Other
minor bugfixes have been made.

--
The ClamAV team (https://www.clamav.net/about.html#credits)

## 0.85

Bugfixes in this release include correct signature offset calculation in large
files, proper handling of encrypted zip archives, and others.

--
The ClamAV team (https://www.clamav.net/about.html#credits)

## 0.84

This version improves detection of JPEG (MS04-028) based exploits, introduces
support for TNEF files and new detection mechanisms. Various bugfixes
(including problems with scanning of digest mail files) and improvements
have been made.

- libclamav:
  - JPEG exploit detector now also checks embedded Photoshop thumbnail images
  - archive meta-data scanner (improves malware detection within encrypted
    archives)
  - support for TNEF (winmail.dat) decoding
  - support for all tar archive formats
  - MD5 implementation replaced with a slightly faster one
  - improved database reloading with reference counter
  - database updateable false positive eliminator
  - speed improvements
  - various bugfixes

- clamd:
  - VirusEvent now sets CLAM_VIRUSEVENT_FILENAME and CLAM_VIRUSEVENT_VIRUSNAME
    environment variables

- clamav-milter:
  - improved database update detection when not --external

- clamscan:
  - new options --include-dir and exclude-dir
  - new option --max-dir-recursion

- freshclam:
  - new directive LocalIPAddress

- contrib:
  - clamdmon 1.0 - clamdwatch replacement written in C

- 3rd party software:
  - hMailServer - open source e-mail server for Microsoft Window
  - pop3.proxy - proxy server for the POP3 protocol
  - HTTP Anti Virus Proxy
  - SmarterMail Filter - ClamAV based plugin for SmarterMail Mail Server
  - smf-clamd - small & fast virus filter for Sendmail
  - Squidclam - replacement for SquidClamAV-Redirector.py written in C
  - QtClamAVclient - remote clamd client based on the Qt Toolkit
  - qpsmtp - flexible smtpd daemon written in Perl

News:

Palo Alto, Calif. March 31st 2005 - Clam AntiVirus, the leading Open Source
antivirus toolkit, and Sensory Networks, the leading provider of hardware
acceleration for network security applications, announced a partnership
to provide hardware acceleration support for the Clam AntiVirus suite.
[...]
Support for Sensory Networks' NodalCore acceleration in ClamAV will be
available in version 0.90 of the software suite in Q3 2005. For more
information please visit:
http://www.sensorynetworks.com/

The ClamAV project announces the opening of the official merchandise store:

http://www.cafepress.com/clamav/

A big thank you to Finndesign (http://www.finndesign.fi) which
volunteered to design the whole line of products, including:

- t-shirts (for women and men)
- golf shirt
- sweatshirt
- coffee mug
- mousepad
- stickers
- scrapbook

By purchasing our merchandise, you contribute to the development of ClamAV.

--
The ClamAV team (https://www.clamav.net/about.html#credits)

## 0.83

Due to a high number of bad files produced by broken software, the MS05-002
exploit detector now only checks specific RIFF files. This version also fixes
a stability problem of clamav-milter/clamd and improves e-mail scanning.

--
The ClamAV team (https://www.clamav.net/about.html#credits)

## 0.82

This release adds generic detection of MS05-002 ("Vulnerability in Cursor and
Icon Format Handling Could Allow Remote Code Execution") based exploits.
Fixes include correct attachment scanning in e-mails generated by some
Internet worms (broken in 0.81), removed false positive "Suspect.Zip"
warning on non-standard zip archives created by ICEOWS, better proxy support
in freshclam, and speed improvements.

--
The ClamAV team (https://www.clamav.net/about.html#credits)

## 0.81

Scan engine improvements were made. The internal mail scanner now supports
multipart/partial messages, and support for decoding non-standard mail files
was greatly enhanced. clamav-milter by default uses libclamav and scans emails
itself without the use of clamd. libclamav can now extract RFC2397 encoded
data within HTML documents, block zip archives with modified information in
local header, and scan HQX files. PE file structure rebuilding from compressed
executables was improved.

Important note to clamdwatch users: please upgrade to the latest version
(contrib/clamdwatch) as soon as possible.

- libclamav:
  - major improvements in the mail scanning engine:
  - support for multipart/partial messages
  - improved support for non-standard quoted-printable attachments
  - in some situations it will try to guess a correct mode (e.g.
    a good type for an incorrect content-type, a best guess for an
    unknown encoding type, etc.)
  - handling of RFC822 comments in the commands (e.g.: Co(foo)ntent-Type:
    text/plain)
  - better recovery if memory softlimit is hit
  - new test code that decodes emails without parsing them first (must
    be enabled manually before compilation)

    - support for extracting RFC2397 encoded data within HTML documents
    - blocking of zip archives with modified information in local header
    - improved PE structure rebuilding from compressed executables
    - improved support for zip archives
    - support for Mac's HQX file format
    - stability and (minor) security fixes
    - a lot of minor improvements, including support for new platforms

- clamd:
  - new directive ExitOnOOM (stop the deamon when libclamav reports an out of
    memory condition)
  - new directives StreamMinPort and StreamMaxPort (port range specification
    for a stream mode)
  - support for passing of file descriptors

- clamdscan:
  - added support for --move and --remove

- clamav-milter:
  - by default uses libclamav to scan e-mails
  - new option --external (enables the use of clamd)
  - various optimizations

- freshclam:
  - the DNS mode is now enabled by default (no need for DNSDatabaseInfo in
    freshclam.conf)
  - --no-dns uses a If-Modified-Since method instead of a range GET
  - added support for AllowSupplementaryGroups

- sigtool:
  - new options --vba and --vba-hex (extract VBA/Word6 macros and optionally
    display the corresponding hex values; Word6 binary code will be
    disassembled)

- The list of third party programs with support for ClamAV is growing
  rapidly. Here are the latest additions (see clamdoc.pdf for details):

  - AVScan - a libclamav based GUI a-v scanner for Unix
  - clamailfilter - a Python script that provides a-v scanning via procmailrc
  - ClamAVPlugin - A ClamAV plugin for SpamAssassin 3.x
  - ClamCour - an e-mail filter for Courier
  - clamfilter - a small, secure, and efficient content filter for Postfix
  - ClamMail - an anti-virus POP3 proxy for Windows
  - ClamShell - a Java GUI for clamscan
  - ClamTk - a perl-tk GUI for ClamAV
  - clapf - a virus scanning and antispam content filter for Postfix
  - D bindings for ClamAV - ClamAV bindings for the D programming language
  - Frox - a transparent FTP proxy
  - KMail - a fully-featured email client now supports ClamAV out of box
  - Mail Avenger - a highly-configurable SMTP server with a-v support
  - Mailnees - a mail content filter for Sendmail and Postfix
  - Maverix - anti-spam and anti-virus solution for AOLServer
  - Moodle - scan files submitted by students for viruses!
  - php-clamav - scan files from within PHP
  - pymavis - a powerful email parser, similar to the old amavis-perl
  - QClam - a simple program to plug ClamAV to a qmail mailbox
  - qmailmrtg7 - display graphs of viruses found by ClamAV
  - qSheff - an e-mail filter for qmail
  - SafeSquid - a feature rich content filtering internet proxy
  - Scrubber - a server-side daemon for filtering mail content
  - simscan - an e-mail and spam filter for qmail
  - smtpfilter - scan SMTP session for viruses
  - snort-inline - scan your network traffic for viruses with ClamAV
  - SquidClamAV Redirector - a Squid helper script which adds virus scanning
  - WRAVLib - a library for a-v integration with Mono/.NET applications

--
The ClamAV team (https://www.clamav.net/about.html#credits)

## 0.80

Stable version. Please read the release notes for the candidate versions below.

--
The ClamAV team (https://www.clamav.net/about.html#credits)

## 0.80rc4

Improvements in this release include better JPEG exploit verification,
faster base64 decoding, support for GNU tar files, updated on-access scanner,
and others.

--
The ClamAV team (https://www.clamav.net/about.html#credits)

## 0.80rc3

This release candidate eliminates possible false positive alerts in UPX/FSG
compressed files and clarifies behaviour of default actions in clamd and
freshclam.

We encourage users to take advantage of our new mirror structure. In order to
download the database from the closest mirror you should configure freshclam
to use db.XY.clamav.net where XY is your country code (see
http://www.iana.org/cctld/cctld-whois.htm for the full list). Please add
the following lines to freshclam.conf:

    DNSDatabaseInfo current.cvd.clamav.net
    DatabaseMirror db.XY.clamav.net
    DatabaseMirror database.clamav.net

DNSDatabaseInfo enables database and software version verification through
DNS TXT records, and the second database mirror acts as a fallback in case
a connection to the first mirror fails for some reason.

## 0.80rc2

This update fixes a serious bug in e-mail scanner.

## 0.80rc

The development version of ClamAV is ready for general testing! New mechanisms
have already proved very nasty to Internet worms successfully protecting
against the new versions R, S, T, U, V and W of the infamous Mydoom worm
and detecting them as Worm.Mydoom.Gen before they were analysed and specific
signatures added by the ClamAV database maintainers. That means servers running
the new version of ClamAV have detected and blocked 100% of Mydoom attacks!

New features in this release include:

- libclamav
  - Portable Executable analyser (CL_SCAN_PARSE_PE) featuring:
  - UPX decompression (all versions)
  - Petite decompression (2.x)
  - FSG decompression (1.3, 1.31, 1.33)
  - detection of broken executables (CL_SCAN_HEURISTIC_BROKEN)
  - new, memory efficient, pattern matching algorithm (multipattern variant
    of Boyer-Moore) - it's now primary matcher and Aho-Corasick is only used
    for regular expression extended signatures
  - new signature format with advanced target type and offset specification
  - support for MD5 based signatures
  - extended regular expression scanner
  - added support for MS cabinet files
  - added support for CHM files
  - added support for POSIX tar archives
  - scanning inside PowerPoint documents
  - HTML normaliser with support for decoding of MS Script Encoder code
  - great improvements in e-mail scanner (now handles even more worm tricks)
  - new method of mail files detection
  - all e-mail attachments are now scanned (previously only the first ten
    attachments were scanned)
  - added support for scanning URLs in e-mails (CL_SCAN_PARSE_MAILURL)
  - detection of Worm.Mydoom.M.log
  - updated API (still backward compatible but please consult clamdoc.pdf
    (Section 6) and adapt your software)

- clamd
  - new directive ScanHTML (enables HTML normalisator and ScrEnc decoder)
  - new directive ScanPE (win32 executable analyser and decompressor)
  - new directive DetectBrokenExecutables (try to detect broken executables
    and mark them as Broken.Executable)
  - new directive MailFollowURLs (try to download and scan files from URLs
    in mails. BE CAREFUL! DO NOT ENABLE IT ON LOADED MAIL SERVERS)
  - new directive ArchiveBlockMax (archives that exceed limits will be
    marked as viruses)
  - clamav.conf was renamed clamd.conf

- clamscan
  - mail files are scanned by default, use --no-mail to disable it
  - new option --no-html (disables HTML normalisator)
  - new option --no-pe (disables PE analyser)
  - new option --detect-broken
  - new option --block-max
  - new option --mail-follow-urls (download and scan files from URLs in mails)

- clamdscan
  - now prints warnings if some activated command line options are only
    supported by clamscan
  - added support for archive scanning in stdin mode

- clamav-milter
  - improved template file format
  - quarantined file names now contain virus names
  - initial support for SESSION mode of clamd

- freshclam:
  - new directive DNSDatabaseInfo that enables ultra lightweight version
    verification method through DNS (using TXT records). Based on idea by
    Christopher X. Candreva and enabled by default.
    (see http://www.gossamer-threads.com/lists/clamav/users/11102)
  - new option --no-dns (quick option to disable DNS method without editing
    freshclam.conf)

- sigtool
  - removed ability of automatic signature generation (use MD5 sums to
    create your own signatures, see signatures.pdf for details)
  - new option --md5
  - new option --html-normalise (saves HTML normalisation and decryption
    results in three html files in current directory)

- configure:
  - new option --disable-gethostbyname_r (try enabling it if clamav-milter
    compilation fails)
  - new option --disable-dns (try enabling it if freshclam compilation fails)
  - extended regular expression scanner

- documentation
  - included new Mac OS X installation instructions
  - official documentation rewritten and outdated docs removed

- new 3rd party software with support for ClamAV:
  - OdeiaVir - an e-mail filter for qmail and Exim
  - ClamSMTP - a lightweight (written in C) and simple filter for Postfix
  - Protea AntiVirus Tools - a virus filter for Lotus Domino
  - PTSMail Utilities - an e-mail filter for Sendmail
  - mxGuard for IMail - a mail filter for Ipswitch IMail (W32)
  - Zabit - a content and attachment filter for qmail
  - BeClam - ClamAV port for BeOS
  - clamXav - a virus scanner with GUI for Mac OS X

Special thanks to aCaB for his work on UPX, FSG and Petite decompressors.

Thanks to good reaction times on new threats ClamAV was awarded as best
security tool for 2004 by Linux Journal: "...With this year's outbreak of
e-mail worms for non-Linux platforms, ClamAV has been getting quite a workout,
and Linux admins on mailing lists report that database update times are keeping
up with or beating the proprietary alternatives." Thanks!

SourceWear.com is selling some very nice t-shirts and polo shirts powered by
ClamAV. Wear them and virus writers will stay away from you :- A quarter out
of every dollar profited from the sale of these shirts will go to the ClamAV
project. Visit http://www.sourcewear.com and click on ClamAV logo!

--
The ClamAV team (https://www.clamav.net/about.html#credits)

## 0.75

This release fixes detection of e-mails generated by Worm.Mydoom.I.

Important notice for people using ClamAV 0.60:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Our logs show that there is still a small percentage of ClamAV 0.60
installations updating their database. ClamAV 0.60 was released on
July 29th, 2003 and it was the last release to use the old database
format. Starting from version 0.65, released on November 12nd, ClamAV
uses a new database format, which is compressed and digitally signed.
We have been distributing the database in both formats till now, but
we plan to drop support for ClamAV 0.60 on September 1st.

We encourage _all_ users to upgrade to the latest release available.
People running an old version of ClamAV are missing many viruses and
may experience stability problems.

On non-production systems you can try the latest development version.
The new engine not only speeds up the scanning process but also limits
memory usage by about 8 MB ! It's able to scan new formats, including
CAB, CHM, UPX, HTML (normalisation), PowerPoint macros and can detect
annoying e-mails with empty attachments generated by new Bagle variants.

--
The ClamAV team (https://www.clamav.net/about.html#credits)

## 0.74

Bugfixes in this version include crashes with multipart/mixed messages
and corrupted OLE2 and Zip files. Improvements include various optimizations
of mail scanning and clamav-milter and clamdscan behaviour.

New members of our "3rd party software" list:

  - MyClamMailFilter   an e-mail filter for procmail (written in C)
  - clamaktion         scan files from the right-click Konqueror menu
  - QMVC               Qmail Mail and Virus Control
  - pyclamav           Python binding for ClamAV
  - FETCAV             Front End To Clam AntiVirus based on Xdialog
  - Famuko             an on-access scanner working in a userspace
  - SoftlabsAV         a generic anti-virus filter for procmail

Japanese users can take an advantage of the new ClamAV related site:
    http://clamav-jp.sourceforge.jp/
and join the clamav-jp-users mailing list.

--
The ClamAV team (https://www.clamav.net/about.html#credits)

## 0.73

This version fixes memory management problems in the OLE2 decoder and
improves mail scanning.

Thank you for using ClamAV !

--
The ClamAV team (https://www.clamav.net/about.html#credits)

## 0.72

Major bugfixes in this release include crashes with corrupted BinHex messages
and some Excel documents. Protection against archive bombs (not fully
functional since 0.70) was improved and a number of other improvements were
made.

--
The ClamAV team (https://www.clamav.net/about.html#credits)

## 0.71

This release fixes all bugs found in 0.70 and introduces a few new features -
the noteworthy changes include:

- libclamav:
  - support nested OLE2 files
  - support Word6 macro code
  - ignore popular file types (media, graphics)
  - support compress.exe (SZDD) compression (test/test.msc)
  - improve virus detection in e-mails

- clamscan:
  - automatically decide (by comparing daily.cvd version numbers) which
    database directory (hardcoded or clamav.conf's one) to use
  - support compression ratio feature (--max-ratio)
  - allow regular expressions in --[in|ex]clude
  - do not overwrite old files in a quarantine directory but add a numerical
    extension to new files
  - respect --tempdir in libclamav
  - fix access problem when calling external unpackers in a superuser mode
  - fix file permission corruption with --deb in a superuser mode

- clamd
  - support log facility specification in syslog's style (LogFacility)
  - new directive LeaveTemporaryFiles (Debug no longer leaves temporary
    files not removed)

- clamav-milter:
  - include the virus name in the 550 rejection
  - support user defined template for virus notifications (--template-file)
  - sort quarantine messages by date
  - improve thread management
  - add X-Virus-Scanned and X-Infected-Received-From: headers
  - improve load balancing (when using remote servers with --server)
  - send 554 after DATA received, not 550
  - save PID (--pidfile)

- documentation:
  - German clamdoc.pdf translation (Rupert Roesler-Schmidt and Karina
    Schwarz, uplink coherent solutions, http://www.uplink.at)
  - new Japanese documentation (Masaki Ogawa)

--
The ClamAV team (https://www.clamav.net/about.html#credits)

## 0.70

The two major changes in this version are new thread manager in clamd
and support for decoding MS Office VBA macros. Both of them have been
implemented by Trog. Besides, there are many improvements and bugfixes
(all listed in ChangeLog), a short summary:

- clamd
  - new thread manager (with better SMP support)
  - on-access scanning now also available on FreeBSD (with Dazuko 2.0)
  - new directive ArchiveBlockEncrypted
  - new directive ReadTimeout (replaces ThreadTimeout)
  - handle SIGHUP (re-open logfile) and SIGUSR2 (reload database)
  - respect TCPAddr in stream scanner

- clamav-milter:
  - TCPWrappers support

- libclamav:
  - support MS Office documents (OLE2) and VBA macro decoding
  - support encrypted archive detection
  - new flags: CL_OLE2, CL_ENCRYPTED (see clamdoc.pdf, Section 6.1)
  - improve virus detection in big files
  - improve support for multipart, bounce and embedded RFC822 messages
  - improve RAR support
  - include backup snprintf implementation

- clamscan:
  - new option: --block-encrypted

- freshclam
  - new option: --pid, -p (write pid file if run as daemon)
  - handle SIGHUP (re-open logfile), SIGTERM (terminate with log message),
    SIGALRM and SIGUSR1 (wake up and check mirror)
  - fix bug with -u and -c handling

- contrib
  - windows clamd client now available with source code

- documentation:
  - new Polish documentation on ClamAV and Samba integration
  - official documentation updated

Special thanks to Dirk Mueller <mueller*kde.org> for his code review,
many bugfixes and cleanups.

Thanks to the help of many companies we have 49 very fast and reliable
virus database mirrors in 22 regions and the number is still growing.
As of March 2004 we attempt to redirect our users to the closest pool
of mirrors by looking at their ip source address when they try to resolve
database.clamav.net. Our DNS servers can answer with a CNAME to:
db.europe.clamav.net, db.america.clamav.net, db.asia.clamav.net or
db.other.clamav.net. Our advanced push-mirroring mechanism (maintained by
Luca Gibelli) allows database maintainers to update all the mirrors in less
than one minute !

There will be no major feature enhancements in the 0.7x series. Our work
will be concentrated on a new scanning engine and preliminary heuristics -
please help us and test CVS snapshots from time to time.

We are happy to announce new programs with support for ClamAV (all of them
have been reviewed by our team - more info in the documentation and
on our website: https://www.clamav.net/download.html#tools):

- ClamWin - a GUI for Windows (!)
- KlamAV - a collection of GUI tools for using ClamAV on KDE
- clamscan-procfilter - a Perl procmail filter
- j-chkmail - a powerful filter for sendmail
- qscanq - Virus Scanning for Qmail
- clamavr - a Ruby binding for ClamAV
- DansGuardian Anti-Virus Plugin
- Viralator - a Perl script that virus scans http downloads
- ClamAssassin - a filter for procmail
- Gadoyanvirus - a filter for Qmail
- OpenProtect - a complete e-mail protection solution
- RevolSys SMTP kit for Postfix - an antispam/antivirus tools installation
- POP3 Virus Scanner Daemon
- mailman-clamav - a virus filter for Mailman
- wbmclamav - a webmin module to manage ClamAV
- Scan Log Analyzer
- mailgraph - a RRDtool frontend for Postfix Statistics
- INSERT - a security toolkit on a credit card size CD
- Local Area Security - a Live CD Linux distribution

--
The ClamAV team (https://www.clamav.net/about.html#credits)
April 17, 2004

## 0.68-1

Fixed RAR support.

## 0.68

This version fixes a crash with some RAR archives generated by the Bagle worm,
also a few important fixes have been backported from CVS.

We strongly encourage users to install the 0.70-rc version (released today).

## 0.67

This release fixes a memory management problem (platform dependent; can lead
to a DoS attack) with messages that only have attachments (reported by Oliver
Brandmueller). It also contains patches for a few problems found in 0.66 and
has better Cygwin support.

## 0.66

This version is a response to the "clamav 0.65 remote DOS exploit" information
published on popular security-related mailing lists. Unfortunately we had
not been contacted by the author before he published that and had to release
this (unplanned) package very quickly (it should be mentioned that CVS version
was not vulnerable to the exploit). Untested code has been disabled also
the Dazuko support is temporarily not available (if you really need it please
use a CVS version or wait for a next stable release). Other noteworthy changes:

- clamd:
  - fixed database timestamp handling (and a double reload problem reported
    by Alex Pleiner and Ole Stanstrup)
  - new directive: ArchiveMaxCompressionRatio
  - new command: SESSION (starts a clamd session and allows to do multiple
    commands per TCP session)
  - new directives: TemporaryDirectory, LogClean (Andrey V. Malyshev)

- clamav-milter: (Nigel Horne)
  - added support for AllowSupplementaryGroups and ThreadTimeout
  - added --quarantine-dir (thanks to Michael Dankov)
  - added --noreject (thanks to Vijay Sarvepalli)
  - added --headers (thanks Leonid Zeitlin)
  - added --sign option

- libclamav:
  - detect Worm.SCO.A bounces (Nigel)
  - prevent buffer overflow in broken uuencoded files (Nigel)
  - scan multipart alternatives that have no boundaries (Nigel)
  - better handling of encapsulated messages (Nigel)
  - locate uuencoded viruses hidden in text portions of multipart/mixed
    mime messages (Nigel)
  - initial support for BinHex (Nigel)
  - fixed a mail recursion loop (problem reported by Alex Kah and Kristof
    Petr)
  - fixed bzip2 memory limit (improper call suggested by the buggy libbz2
    documentation, problem reported by Tomasz Klim)
  - fixed on error descriptor leak in CVD unpacker (Thomas Lamy)
  - fixed memory leak in digital signature verification code (Thomas Lamy)
  - added maximal compression ratio limit (cl_limits->maxratio)

- clamscan:
  - support for multiple arguments on command line (Thomas Lamy)
  - fixed buffer overflow in --move (Denis De Messemacker)
  - removed support for sendfile() under Linux

- freshclam:
  - support for freshclam.conf (that may be optionally merged with
    clamav.conf, command line options overwrite config settings)
  - work-around for potential database downgrade (subtle problem
    in r-r dns handling) - reported by Daniel Mario Vega and patched
    by Luca Gibelli

- sigtool:
  - list virus names with --list-sigs (-l)

- contrib:
  - clamdwatch (by Mike Cathey)
  - windows clamd client with drag&drop support (Nigel Horne)

- documentation:
  - complete clamdoc.pdf French translation by Stephane Jeannenot
  - Polish how-to on ClamAV and Sendmail integration (with clamav-milter)
    by Przemyslaw Holowczyc

News:

ClamAV was the first anti-virus protecting against Worm.SCO.A (aka MyDoom.A) !
The signature was published by Diego d'Ambra in the daily update 105,
26-Jan-2004 20:23 GMT and we were at least two hours faster than "big" AV
vendors:
http://sourceforge.net/mailarchive/forum.php?thread_id=3764826&forum_id=34654
http://www.pcwelt.de/news/viren_bugs/37278/4.html

clamav-devel is finally able to decode OLE2 (Microsoft Office) files and
decompress VBA streams ! The code is developed by Trog, official ClamAV
developer. Also we're testing new clamd implementation that will solve
several important problems (especially that "Time out" related). Please
help us and test the latest CVS version.

The virus database now contains more than 20.000 signatures ! On January 8,
Denis De Messemacker (who joined our team 3 months ago) added signatures for
about 7700 new viruses. Also special thanks go to Tomasz Papszun for his
hard work on daily submissions and forcing us to keep ClamAV quality on
the highest possible level.

New mirroring mechanisms. Luca Gibelli (ClamAV) and mirror administrators
(22 sites) are converting mirrors to new "push mirroring"
method. It uses advanced techniques to ensure all the mirrors are up to date.
More info: https://www.clamav.net/documents/introduction

We would like to thank our donors:

- Jeremy Garcia (http://www.linuxquestions.org)
- Andries Filmer (http://www.netexpo.nl)
- David Eriksson (http://www.2good.nu)
- Dynamic Network Services, Inc (http://www.dyndns.org)
- epublica
- Invisik Corporation (http://www.invisik.com)
- Keith (http://www.textpad.com)
- Explido Software USA Inc. (http://www.explido.us)
- cheahch from Singapore
- Electric Embers
- Stephane Rault
- Brad Koehn
- David Farrick
- ActiveIntra.net Inc. (http://www.activeintra.net)
- An anonymous donor from Colorado, US

--
Tomasz Kojm <tkojm*clamav.net>
February 10, 2004

## 0.65

IMPORTANT NOTE: The project has been moved into SourceForge. The only official
ClamAV's homepage is www.clamav.net (however clamav.elektrapro.
com still works). We would like to thank ElektraPro.com for
their support for the open-source community  - THANKS !

ClamAV 0.65 introduces a new database container file format (called CVD) with
support for digital signatures and compression. Please remove the old
databases from your database directory before the installation. And the most
important thing: clamd stability has been greatly improved (especially under
FreeBSD) ! Also we have a new mirror infrastructure - you will find all the
details in clamdoc.pdf. If you want to become an official ClamAV mirror
(with entry in database.clamav.net) please read the clamav-mirror-howto.pdf
document and contact our administrator - Luca Gibelli <nervous*clamav.net>.

Noteworthy changes in this version:

- clamd:
  - fixed a race condition in database reloading code (random crashes
    under high load)
  - fixed a race condition with the improperly initialized session start time
    (thanks to Michael Dankov)
  - fixed PidFile permissions (Magnus Ekdahl, bug reported by Tomasz Papszun)
  - fixed LogFile permissions (Magnus Ekdahl)
  - new directive ScanRAR (because RAR support is now disabled by default)
  - new directive VirusEvent
  - new directive FixStaleSocket (Thomas Lamy and Mark Mielke)
  - new directive TCPAddr (Bernard Quatermass, fixed by Damien Curtain)
  - new directive Debug

- clamav-milter: (Nigel Horne <njh*clamav.net>)
  - new --force-scan flag
  - new -P and -q flags by Nicholas M. Kirsch
    WARNING: clamav-milter and our mail scanner are still in high development
    and may be unstable. You should always use the CVS version.

- libclamav:
  - support for a new database container format (CVD) - compressed and
    digitally signed
  - better protection against malformed zip archives (such as Mimail)
  - mail decoder fixes (thanks to Rene Bellora, Bernd Kuhls, Thomas Lamy,
    Tomasz Papszun) (Nigel Horne)
  - memory leak fixes (Thomas Lamy)
  - new scan option CL_DISABLERAR (disables built-in RAR unpacker)

- freshclam:
  - fixed --on-error-execute behaviour (David Woakes)
  - new option --user (-u) USER - run as USER instead of the default user.
    Patch by Damien Curtain.
  - rewritten to use database.clamav.net and CVD

- documentation:
  - new Spanish documentation on ClamAV and Sendmail integration by
    Erick Ivaan Lopez Carreon
  - included clamdoc.pdf Turkish translation by yavuz kaya and �brahim erken
  - included clamav-mirror-howto.pdf by Luca Gibelli
  - included clamd+daemontools HOWTO by Jesse D. Guardiani
  - included signatures.pdf
  - man pages: updated
  - clamdoc.pdf: rewritten

New members of our list of ClamAV certified software (see clamdoc.pdf for
details):
  - cgpav
  - smtp-vilter
  - IVS Milter
  - scanexi
  - Mail::ClamAV
  - OpenAntiVirus samba-vscan
  - Sylpheed Claws
  - nclamd

Thanks to Mia Kalenius and Sergei Pronin we have a new official logo !

Thank you for using ClamAV !

--
Tomasz Kojm <tkojm*clamav.net>
November 12, 2003

## 0.60

Hello again...

This is a new, (very?) stable release of Clam AntiVirus. 0.60 was developed
and stabilized for over seven months and many people had contributed to the
final release. This version introduces many enhancements and a new program:
clamav-milter written by ClamAV developer Nigel Horne. This is a mail scanner
for Sendmail/milter written entirely in C, which uses clamd for virus scanning.
Clamav-milter and clamd duet is a powerful solution for systems where high
performance is required. Please check clamdoc for more detail.

    Many people get confused with ClamAV database status because of
    the OpenAntiVirus update information at:
    http://openantivirus.org/latest.php
    (last update at 17 October, 2002). The ClamAV virus database contains
    the OAV database (with some signatures fixed or removed) but we
    develop it independently of the OAV project. Our database is updated
    frequently (on average 4-5 times a week). You can help (or join) us -
    will find some basic but useful instructions at
    http://clamav.elektrapro.com/doc/signatures.pdf

News from ClamAV world:

- New email address for virus submitting: virus@clamav.elektrapro.com
   You don't need to encrypt a virus sample, but if your system doesn't allow
   you to send infected files just put it into an encrypted zip archive
   (password: virus)

   Special thanks to Nicholas Chua, Diego D'Ambra, Hrvoje Habjanic, Nigel Kukard
   and Chris van Meerendonk for a big number of samples submitted.

- New mailing list: virusdb@clamav.elektrapro.com
   After each update an email with subject "[clamav-virusdb] Update" and a list
   of viruses added is sent to it. You can set up a procmail rule for freshclam
   to react on such a mails (and update the database just after an update).

- New official mirrors:
  - clamav.ozforces.com: database mirror updated manually (thanks to
    Andrew <andrew@ozforces.com>)
  - clamav.essentkabel.com: full (automatic) mirror of clamav.elektrapro.com
    (thanks to Chris van Meerendonk <cvm@castel.nl>)
  - clamav.linux-sxs.org: database mirror - rsync from clamav.ozforces.com
    (thanks to Douglas J Hunley <doug@hunley.homeip.net>)

    Freshclam will automatically use them when the main server is not
    accessible.

- Official port in FreeBSD available ! (maintained by Masahiro Teramoto
   <markun@onohara.to>)

- Unofficial port for OpenBSD is available at:
	http://www.activeintra.net/openbsd/article.php?id=5
  (maintained by Flinn Mueller <flinn@activeintra.net>)

- there are many new programs that use ClamAV, eg. mod_clamav (Apache
  virus scanning filter), clamdmail or Sagator. You will find more
  info in clamdoc.

Changes:

- libclamav:
  - fixed buffer overflow in unrarlib (patch by Robbert Kouprie
    <robbert@exx.nl>)

  - various mbox code updates (fixed memory leak; added support for decoding
    viruses sent in message bodies, detection of viruses that put their
    payloads after the end of message marker (thanks to Stephen White
    <stephen@earth.li> for the bug report and useful CGI tools);

  - zziplib updated to 0.10.81 (some problems with older version were reported
    by Martin Schitter)
  - direct scanning of mbox/maildir files (new directive CL_MAIL)
  - file scanner optimization (patch by Hendrik Muhs
    <Hendrik.Muhs@student.uni-magdeburg.de>)
  - bzip2 support
  - faster detection of malformed Zip archives (eg. 'Zip of Death'), they are
    reported as a viruses
  - fixed strcasecmp() compile problem in zziplib on Free/NetBSD and others

- clamd:
  - fixed descriptor leak in directory scanner - it was causing random
    clamd crashes and locks, especially on highly loaded servers. Reported
    by Kristof Petr <Kristof.P@fce.vutbr.cz>.

  - fixed crash with archive scanning on BSD (increased thread stack size)
    (Nigel Horne)
  - fixed CONTSCAN command (used by clamdscan) - it had archive support
    disabled (hardcoded)
  - fixed SelfCheck option (there was a logic bug, and the option was
    disabled) it now checks a databases time stamps and reloads them
    if needed.
  - fixed possible writing to undefined descriptors (bug found by
    Brian May <bam@debian.org>)
  - new STREAM command (scanning data on socket) and directives:
    StreamSaveToDisk (save stream to disk to allow scanning within archives),
    StreamMaxLength. This option allows scanning data on socket (might be
    sent from another host), currently only clamav-milter uses this.

  - new ScanMail directive for scanning into mbox/Maildir files
  - new directive: ArchiveLimitMemoryUsage (limit memory usage with bzip2)
  - new directive: AllowSupplementaryGroups (feature requested by Exiscan
    users)
  - syslog support (LogSyslog) (patch by Hrvoje Habjanic
    <hrvoje.habjanic@zg.hinet.hr>)
  - fixed parser segfault with extra space between option and argument
    in config file (Magnus Ekdahl <magnus@debian.org>)

- clamscan:
  - fixed --remove option (didn't work when the file was scanned with an
    internal unpacker) (patch by Damien Curtain <damien@pagefault.org>)
  - --move option for moving infected files into a specified directory
    (by Damien Curtain <damien@pagefault.org>)
  - --mbox enables a direct support for mbox files
    (ex. clamscan --mbox /var/spool/mail)
  - fixed --log (-l) option
  - fixed -i option (patch by Magnus Ekdahl <magnus@debian.org>)
  - enabled default archive limits (max-files = 500, max-size = 10M,
    max-recursion = 5)
  - use arj instead of non-free unarj (patch by Magnus Ekdahl)
  - use unzoo instead of non-free zoo (patch by Magnus Ekdahl)
  - removed thread support

freshclam:
  - mirror support (implemented by Damien Curtain <damien@pagefault.org>)
  - --proxy-user: proxy authorization support (implemented by Gernot Tenchio
    <g.tenchio@telco-tech.de>)
  - new options --on-error-execute, --on-update-execute
    (ex. freshclam -d -c 6 --on-error-execute "sendsms 23332243 Can't
    update virus database"). Idea by Douglas J Hunley <doug@hunley.homeip.net>

configure:
  - --disable-cr (don't link with C reentrant library (needed on some newer
    versions of OpenBSD))

- Enhanced AIX (thanks to Mike Loewen <mloewen@sturgeon.cac.psu.edu>) and
   Tru64 support (thanks to Christophe Varoqui <ext.devoteam.varoqui@sncf.fr>)

- documentation:
  - included how-to in Portugese by Alexandre de Jesus Marcolino
  - clamdoc.pdf and system manual updates

Many thanks to Luca 'NERvOus' Gibelli from ElektraPro for his support,
to Ken McKittrick from USA DataNet for a fully accessible FreeBSD box and
to mailing list subscribers for a constructive discussions.

--
Tomasz Kojm
June 21, 2003

## 0.54

Many major changes this time...

- libclamav:
  - fixed segfault with some strange zip archives (there is a bug in zziplib,
    libclamav contains a work around for it) (the problem was reported by
    Oliver Paukstadt <pstadt@stud.fh-heilbronn.de>)
  - engine improvements (better support for a detection of new viruses,
    limited memory usage (consumes ~ 5 Mb now))
  - mbox code updated and moved into the library: fixed core dump when an
    embedded message includes a mime header with the line Content-Type:
    without specifying the type of content, fixed (theoretical) memory leak,
    support for multipart/report messages, fixed bug causing some formats to
    fail to scan) (Nigel)
- clamd:
  - new commands: CONTSCAN (it doesn't stop scanning even when virus is
    found), VERSION
  - disable logging of a unnecessary time stamps with LogTime when
    LogVerbose isn't used (patch by Ed Phillips <ed@UDel.Edu>)
- freshclam:
  - "Cache-Control: no-cache" enabled by default
  - Cygwin support fix
- clamdscan:
  - initial version
- all tools:
  - removed huge printf() in help() (there was a buffer overflow problem with
    --help option under Windows and SCO Unix (reported by Wojciech Noworyta
    <wnow@konarski.edu.pl> and Nigel respectively)
- configure:
  - allow configuration of the clamav user and group with --with-user and
    --with-group (patch by Patrick Bihan-Faou <patrick@mindstep.com>)
  - --enable-id-check - it uses the check procedure from Jason Englander
    <jason@englanders.cc>, currently it will fail on systems with getent
    which doesn't detect clamav group.
  - do not overwrite the existing config file

There are initial packages for Windows available at:
    http://clamav.elektrapro.com/binary

--tk

## 0.53

This release has removed the limit for a file name length in clamscan. Some
viruses (eg. W32/Yaha.E) are using very long file names, and they were
ignored in mbox mode. Users of AMaViS-ng and other wrappers were not
vulnerable to this problem, because that programs don't use original
attachement file names.

- clamscan:
  - removed limit for a file name length (thanks to Odhiambo Washington
    <wash@wananchi.com> for the test files and extensive mbox testing)
  - mbox: adapted to the new changes, enabled thread support (Nigel),
    re-enabled temporary directory removing.

## 0.52

This version contains a portability fixes - it should compile on OpenBSD,
MacOSX and NetBSD (support for them was broken in 0.51).

- clamd: various fixes:
  - drop supplementary groups (suggested by Enrico Scholz
    <enrico.scholz@informatik.tu-chemnitz.de>) (this has been implemented
    in freshclam, too)
  - work-around for the segmentation fault at QUIT under FreeBSD
  - check timeouts when waiting for threads in RELOAD mode
  - SelfCheck - internal integrity check (by default every 1 hour)
  - fixed problem with directory scanning on non typical file systems
    (bug reported by Jason Englander <jason@englanders.cc>)
  - clamd is a system command (clamd.1 -> clamd.8, /usr/local/bin ->
    /usr/local/sbin) (Magnus Ekdahl)
- clamscan:
  - mbox code updates (Nigel Horne) - it fixes some problems on *BSD
    systems (see mailing lists archives for the details)
  - enable core dumping (Nigel Horne) [ with --enable-debug ]
- freshclam:
  - applied http-proxy patch from http://bugs.debian.org/clamav (by
    Martin Lesser <admin-debian@bettercom.de>)
  - when configured with --disable-cache, freshclam forces 'no-cache'
    option in proxy servers (patch by Ant La Porte <ant@dvere.net>)

- HPUX (10.20/11.0 tested) support (thanks to Joe Oaks <joe.oaks@hp.com>)
- fixed support for SCO Unix and BeOS (Nigel Horne)
- support/mboxscan: new version with SpamAssassin support (Nigel Horne)
- re-included TrashScan 0.08 (by Trashware <trashware@gmx.de>) - the security
  issue has been fixed.
- included "Installing qmail-scanner, Clam Antivirus and SpamAssassin under
  FreeBSD" how-to by Paul Hoadley and Eric Parsonage

## 0.51

OAV database is up to date ! There was a problem with signature parsing,
because some hex strings were upper case. Anyway, I still recommend you
freshclam for a database updating.

- support for the genuine OAV database
- limited memory usage (at the cost of speed, increase CL_MIN_LENGTH in
  libclamav/clamav.h to make it faster, it's safe to set it on 3-4 for
  the OAV database)
- fixed compile problem on TurboLinux 6.5 (probably others, too), the bug
  was reported by Henk Kuipers <henk@opensourcesolutions.nl>.
- clamd: fixed THREXIT (thanks to Piotr Gackiewicz <gacek@intertele.pl>)
- clamd: fixed serious bug with thread argument type
- clamscan: mbox: don't scan empty attachments (Nigel Horne)
- configure: --with-db1, --with-db2 (suggested by Magnus Ekdahl)

## 0.50

Here it is...
Clam AntiVirus 0.50 contains an anti-virus library - libclamav, a fully
multi-threaded daemon clamd(1) and a quite long list of changes. The
documentation was rewritten and you _should_ review it. By courtesy of
NERvOus <nervous@nervous.it> and ElektraPro, there are three mailing lists
available - you can subscribe via www at http://clamav.elektrapro.com/ml.
Please check the manual for more information.

New software:

- libclamav with RAR, Zip and Gzip support built-in. The library is thread
  safe and should be very secure, also. It uses UniquE RAR File
  Library by Christian Scheurer and Johannes Winkelmann (RAR 2.0 support only)
  and zziplib library by Guido Draheim and Tomi Ollila. Both of them are
  included and slightly modified in the clamav sources. You need the zlib
  library for the Zip/Gzip support, though. The API is described with
  examples in the clamdoc.

- clamd: a modern anti-virus daemon. It uses configuration file clamav.conf
  described in the clamav.conf(5) manual. The program was written with
  security as a goal.

- clamuko: on-access scanning under Linux. It utilizes Dazuko kernel module
  (GPL, http://dazuko.org) and is clamd-based.

New features / improvements:

- enhanced scanner engine (better detection of some complex polymorphic
  viruses)

- clamscan: Nigel Horne <njh@bandsman.co.uk> has added the ability to scan
  mail attachments in a filter. For example:

  $ clamscan -i --mbox - < /var/spool/mail/john
  /tmp/aa6b9fc06bc477ae/setup.exe: Worm/Klez.H FOUND

  Nigel is the author of the whole mbox code in clamscan. Currently it only
  works in a filter mode, but there are plans to move the code into the
  libclamav and allow clamd using it. Please check support/mboxscan, also.

- clamscan: support for including and excluding multiple patterns with
  --include and --exclude (patch by Alejandro Dubrovsky
  <s328940@student.uq.edu.au>).
  Example: clamscan --include .exe --include .obj --include .scr /mnt/windows

- clamscan: don't scan /proc files (Linux, st_dev comparing). No more
  /proc/kcore related mails :))

- clamscan: use libclamav's archive support by default (it's enabled by default
  and may be disabled with --disable-archive) and switch to the external
  unpackers (if specified) in the case of libclamav archive code error.

- freshclam: proxy support (via $http_proxy variable and --http-proxy).
  I started implementing proxy support some time ago, but never finished.
  Nigel Horne did the great job and has finished the proxy support !

- freshclam: --daemon-notify. freshclam will send the RELOAD command to the
  daemon after database update (supports both tcp and local sockets, it reads
  clamav.conf to determine the socket type).

- freshclam: support for viruses.db2

Bug fixes:

- freshclam: log 'Database updated' message (thanks to Jeffrey Moskot
  <jef@math.miami.edu> for the bug report). It now prints a number
  of signatures in a database, also.

- clamscan: fixed compile problem on Solaris 8 and some other systems -
  #include <signal.h> lack in others.c (thanks Mike Loewen
  <mloewen@sturgeon.cac.psu.edu> for the bug report)

Documentation:

- included Japanese documentation by Masaki Ogawa <proc@mac.com>

- updated Spanish "Sendmail + Amavis + ClamAv - Como" by Erick I. Lopez
   Carreon <elopezc@technitrade.com>

- rewritten clamdoc, included clamdoc-html, removed PostScript version (.ps)

- Clam-Mutant ;) logo update by Michal Hajduczenia <michalis@mat.uni.torun.pl>

- new man pages: clamd(1), clamav.conf(5); others updated

!!!
    Please don't use the oav-update script with this version. It doesn't
update viruses.db2 and supports OpenAntiVirus.org site only (the last
update of the OAV database was 1 July !). Nicholas Chua <nicholas@ncmbox.net>
has generated over 200 new signatures, ClamAV's database is also frequently
updated (expecially when new wild virus/worm appears, eg. W32/BugBear.A).

    This software is still in developement (new software == new bugs), however
clamscan should be very stable. You shouldn't use clamd/clamuko (well, clamd is
stable, clamuko isn't) on production systems, yet. Please wait for 0.51 at
least ;). ClamAV 0.50 was tested on Linux and Solaris and should work fine.
There is a problem with clamd on FreeBSD (tested on my FreeBSD 5.0-CURRENT) -
the daemon crashes with Zip/Gzip files (disabling ScanArchive should help).

Enjoy !
--
Tomasz Kojm
October 5, 2002

## 0.24

- fixed threads deadlock in a critical error situation (bug found by David
  Sanchez <dsanchez@veloxia.com>)
- fixed sigtool bug (negative seeking)
- fixed potential clamscan segfault in the case of memory allocation error
- unpacker execution error is no longer treated as critical - a few programs
  (eg. Qmail-Scanner, TrashScan) have clamscan command hardcoded with all
  archive options turned on. Now, if unpacker can't be executed, raw file is
  scanned and scan process is continued.
- reverted to pthread.h detection
- TrashScan 0.07 (Trashware <trashware@gmx.net>)
- --exclude (regular expressions are not supported !)
  [ex: clamscan --exclude="/proc/kcore" /], but please use it with care.
- included html documentation

IMPORTANT NOTE:
~~~~~~~~~~~~~~~
You will probably have a problem with a default Qmail-Scanner (1.13 or newer)
installation. You need to increase qmail-smtpd softlimit or disable it. You
can force clamscan to use only half of the memory which it uses by default, too.
Please change the following line in the clamscan/matcher.h file:
    #define MIN_LENGTH 5
to:
    #define MIN_LENGTH 3
and recompile the program. Unhappily, scanning may be a little slower in some
cases, but it shouldn't be significant. Then you can safely set the qmail
softlimit to 8 MB. I want to thank Doug Monroe <doug@planetconnect.com> for
his contribution in the problem analysis.
---

New ClamAV version is in a heavy development. It has currently built-in
support for RAR, Zip, Gzip and tar. The daemon will support only built-in
compression/archive support. Snapshot will be available for a few days.

## 0.23

- fixed compile problem on FreeBSD (thanks to Wieslaw Glod <wkg@x2.pl> and
  Ken McKittrick <klmac@usadatanet.com>)
- clamscan reads all .db files from data directory, so you can put your
  own databases there and they won't be overwrited by the updaters. viruses.db
  is still the main database file (if --database isn't used).
- --deb (debian binary packages scanning) by Magnus Ekdahl <magnus@debian.org>
- --remove option, but be careful with it !
- new clam logo ;) (GPL) by Michal Hajduczenia <michalis@mat.uni.torun.pl>.
- TrashScan 0.06 (by Trashware <trashware@gmx.net>) - a script for scanning
  mail with procmail. I recommend it. (support/trashscan)
- documentation updates

0.30 release will contain a daemon and an anti-virus library (with simple API),
so you can use it directly in your projects. I want to build in zip and rar
support, also.

There are binary packages for AIX available. Please check the documentation.

## 0.22

This release fixes bug with scanning archives in unaccessible directories with
*superuser* priviledges (after dropping priviledges scanner wasn't able to
access the archive, although the same archive was accessible), thanks
for Sergei Pronin <sp@finndesign.fi> for the problem description. Now all
archives unaccessible directly by the clamav user are copied (with a respect to
--max-space) to the temporary directory. All old filesystem tricks were removed.

Other fixes / improvements:

- better error handling, new error codes
- improved -i (--infected) option
- removed --strange-unzip option
- removed eicar test files and logos from the documentation due to the GPL
  (thanks for Magnus Ekdahl <magnus@debian.org>), ClamAV-Test-Signature is
  used instead
- removed Qmail-Scanner patch, ClamAV is supported by Q-S 1.13 (thanks guys!)
- code cleanups

## 0.21 Release

It fixes following problems:

- database downloading in freshclam/0.20
- malformed amavis-perl patch from 0.20
- clamscan problems with some unzip versions, please try --strange-unzip
  option

ClamAV 0.21 source package contains initial support for NetBSD
(thanks to Marc Baudoin <babafou@babafou.eu.org>, Jean-Edouard BABIN
<Jeb@jeb.com.fr>), better support for Mac OS X (Masaki Ogawa <proc@mac.com>),
and clamdoc documentation corrected by Dennis Leeuw <dleeuw@made-it.com>.

## 0.20 Release

The most important change in this release is a new, linear pattern matching
algorithm. You will find more informations about it in clamscan/matcher.c -
in the sources and in clamdoc. Summary (since 0.15):

New features:

- fast pattern matching algorithm
- sigtool utility, check `man sigtool` and clamdoc
- Linux: threads autodetection on various architectures
  (Magnus Ekdahl <magnus@debian.org>)
- -i, --infected: clamscan prints only infected files
- 'Data scanned' in summary, size in megabytes with 16 Kb precision
- configure: --with-dbdir sets the database location
- support/sigmake shell script by Dennis Leeuw <leeuw@stone-it.com>
- Spanish "Sendmail+Amavis+ClamAv installation how-to" by
  Erick I. Lopez Carreon <elopezc@technitrade.com>

Updates:

- "Debian GNU/Linux Mail Server v. 0.2.0" by Dennis Leeuw <leeuw@stone-it.com>
- qmail-scanner patch from Kazuhiko <kazuhiko@fdiary.net>
- general documentation cleanups / updates
- freshclam / Internet database location

Fixes:

- threads autodetection on not-x86 Linux systems
- gcc 3.x support (David Ford <david+cert@blue-labs.org>)
- data type fix on Mac OS X (Peter N Lewis <peter@stairways.com.au>)
- removed -w, --whole-file, now clamscan scans whole files by default
  -w is still supported by internal getopt(), because it is used in
  various patches
- removed --one-virus, still supported by getopt(); removed 'Found viruses'
  from summary, clamscan stops file scanning after first virus
- fixed old problem with scanning stdin
- removed amavisd-patch - strange problems have been reported

OpenAntiVirus Update is a great tool written by Matthew A. Grant
<grantma@anathoth.gen.nz> and it will be the primary updater for ClamAV
in the near future. In contrast to freshclam it has proxy support and many
specific features. Please check clamdoc for more informations and how to
obtain it.

## 0.15 Notes

This version contains minor bugfixes only, such as:
- multiple fixes in freshclam (it has problems, when one of the
  hosts wasn't accessible), there were logic flaws in the code
- fixed problem with password protected archives (unpackers were waiting
  for password)

New features:
- OpenBSD support (thanks to Kamil Andrusz <wizz@mniam.net>)
- added support for amavisd, qmail-scanner (see ./support)

There were no major bugs and I was very busy, that's why new version is
released just today. In the next 2 months, clamav development will be much
faster. Here are some of my plans:

~ 0.20 : New pattern-matching algorithm
~ 0.30 : clamlib; clamscan and the daemon based on it

There is a new homepage:
- http://clamav.elektrapro.com

Thanks to ElektraPro.com for sponsoring this site (it's very fast).
Thanks to NERvOus <nervous@nervous.it>.

If you are interested in current development versions, please check
snapshots link.

### Resource usage limits in 0.14

Two new features: --max-files, --max-space have been implemented. If you have
enabled one of this options, clamscan monitors resource usage (number of
created files and used space) and stops extractor when it has exceeded
the limit. You should use these options to protect your machine against
Denial of Service attacks. In the near future --max-levels (limit for
recursive archives extracting) and --max-time (spent on checking/extracting
files) will be implemented.

### FreeBSD: AMaViS compile problems

Please check FAQ.

### !!! Strange signatures in VirusSignatures-2002.04.15.10.51.zip !!!

Last version of signatures was ~90 kb, this version is ~474 kb.
But I don't understand, why some signatures are mega-huge. When I decoded
them, they looked like regular files. In CA they were removed from the
database and I probably add them later, in normal sizes.

### Installation :

Please view documentation in ./docs. There are several formats - pdf, ps
and plain latex, if you want to compile it yourself.

You need GNU make (on Solaris you should have gmake).
It was tested only with gcc 2.9x compilers.

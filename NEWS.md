# ClamAV News

Note: This file refers to the official packages. Things described here may
differ slightly from third-party binary packages.

## 1.6.0

ClamAV 1.6.0 includes the following improvements and changes:

### Major changes

### Other improvements

### Bug fixes

### Acknowledgments

Special thanks to the following people for code contributions and bug reports:

## 1.5.0

ClamAV 1.5.0 includes the following improvements and changes:

### Major changes

- Added checks to determine if an OLE2-based Microsoft Office document is
  encrypted.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1295)

- Added the ability to record URIs found in HTML if the generate-JSON-metadata
  feature is enabled.
  Also adds an option to disable this in case you want the JSON metadata
  feature but do not want to record HTML URIs.
  The ClamScan command-line option is `--json-store-html-uris=no`.
  The `clamd.conf` config option is `JsonStoreHTMLURIs no`.
  The libclamav general scan option is `CL_SCAN_GENERAL_STORE_HTML_URIS`

  [GitHub pull request #1](https://github.com/Cisco-Talos/clamav/pull/1281)

  [GitHub pull request #2](https://github.com/Cisco-Talos/clamav/pull/1482)

  [GitHub pull request #3](https://github.com/Cisco-Talos/clamav/pull/1514)

- Added the ability to record URIs found in PDFs if the generate-JSON-metadata
  feature is enabled.
  Also adds an option to disable this in case you want the JSON metadata
  feature but do not want to record PDF URIs.
  The ClamScan command-line option is `--json-store-pdf-uris=no`.
  The `clamd.conf` config option is `JsonStorePDFURIs no`.
  The libclamav general scan option is `CL_SCAN_GENERAL_STORE_PDF_URIS`

  [GitHub pull request #1](https://github.com/Cisco-Talos/clamav/pull/1482)

  [GitHub pull request #2](https://github.com/Cisco-Talos/clamav/pull/1514)

  [GitHub pull request #3](https://github.com/Cisco-Talos/clamav/pull/1559)

  [GitHub pull request #4](https://github.com/Cisco-Talos/clamav/pull/1572)

- Added regex support for the `clamd.conf` `OnAccessExcludePath` config option.
  This change courtesy of GitHub user b1tg.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1314)

- Added CVD signing/verification with external `.sign` files.

  Freshclam will now attempt to download external signature files to accompany
  existing `.cvd` databases and `.cdiff` patch files. Sigtool now has commands
  to sign and verify using the external signatures.

  ClamAV now installs a 'certs' directory in the app config directory
  (e.g., `<prefix>/etc/certs`). The install path is configurable.
  The CMake option to configure the CVD certs directory is
  `-D CVD_CERTS_DIRECTORY=PATH`

  New options to set an alternative CVD certs directory:
  - The command-line option for Freshclam, ClamD, ClamScan, and Sigtool is
    `--cvdcertsdir PATH`
  - The environment variable for Freshclam, ClamD, ClamScan, and Sigtool is
    `CVD_CERTS_DIR`
  - The config option for Freshclam and ClamD is
    `CVDCertsDirectory PATH`

  Added two new APIs to the public clamav.h header:
  ```c
  cl_error_t cl_cvdverify_ex(
      const char *file,
      const char *certs_directory,
      uint32_t dboptions);

  cl_error_t cl_cvdunpack_ex(
      const char *file,
      const char *dir,
      const char *certs_directory,
      uint32_t dboptions);
  ```
  The original `cl_cvdverify` and `cl_cvdunpack` are deprecated.

  Added a `cl_engine_field` enum option `CL_ENGINE_CVDCERTSDIR`.
  You may set this option with `cl_engine_set_str` and get it with
  `cl_engine_get_str`, to override the compiled in default CVD certs directory.

  Thank you to Mark Carey at SAP for inspiring work on this feature with an
  initial proof of concept for external-signature FIPS compliant CVD signing.

  [GitHub pull request #1](https://github.com/Cisco-Talos/clamav/pull/1417)

  [GitHub pull request #2](https://github.com/Cisco-Talos/clamav/pull/1478)

  [GitHub pull request #3](https://github.com/Cisco-Talos/clamav/pull/1489)

  [GitHub pull request #4](https://github.com/Cisco-Talos/clamav/pull/1491)

- Freshclam, ClamD, ClamScan, and Sigtool: Added an option to enable FIPS-like
  limits disabling MD5 and SHA1 from being used for verifying digital signatures
  or for being used to trust a file when checking for false positives (FPs).

  For `freshclam.conf` and `clamd.conf` set this config option:
  ```
  FIPSCryptoHashLimits yes
  ```

  For `clamscan` and `sigtool` use this command-line option:
  ```
  --fips-limits
  ```

  For libclamav: Enable FIPS-limits for a ClamAV engine like this:
  ```C
  cl_engine_set_num(engine, CL_ENGINE_FIPS_LIMITS, 1);
  ```

  ClamAV will also attempt to detect if FIPS-mode is enabled. If so, it will
  automatically enable the FIPS-limits feature.

  This change mitigates safety concerns over the use of MD5 and SHA1 algorithms
  to trust files and is required to enable ClamAV to operate legitimately in
  FIPS-mode enabled environments.

  Note: ClamAV may still calculate MD5 or SHA1 hashes as needed for detection
  purposes or for informational purposes in FIPS-enabled environments and when
  the FIPS-limits option is enabled.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1532)

- Upgraded the clean-file scan cache to use SHA2-256 (prior versions use MD5).
  The clean-file cache algorithm is not configurable.

  This change resolves safety concerns over the use of MD5 to trust files and
  is required to enable ClamAV to operate legitimately in FIPS-mode enabled
  environments.

  [GitHub pull request #1](https://github.com/Cisco-Talos/clamav/pull/1532)

  [GitHub pull request #2](https://github.com/Cisco-Talos/clamav/pull/1560)

- ClamD: Added an option to disable select administrative commands including
  `SHUTDOWN`, `RELOAD`, `STATS` and `VERSION`.

  The new `clamd.conf` options are:
  ```
  EnableShutdownCommand yes
  EnableReloadCommand yes
  EnableStatsCommand yes
  EnableVersionCommand yes
  ```
  This change courtesy of GitHub user ChaoticByte.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1502)

- libclamav: Added extended hashing functions with a "flags" parameter that
  allows the caller to choose if they want to bypass FIPS hash algorithm limits:
  ```c
  cl_error_t cl_hash_data_ex(
      const char *alg,
      const uint8_t *data,
      size_t data_len,
      uint8_t **hash,
      size_t *hash_len,
      uint32_t flags);

  cl_error_t cl_hash_init_ex(
      const char *alg,
      uint32_t flags,
      cl_hash_ctx_t **ctx_out);

  cl_error_t cl_update_hash_ex(
      cl_hash_ctx_t *ctx,
      const uint8_t *data,
      size_t length);

  cl_error_t cl_finish_hash_ex(
      cl_hash_ctx_t *ctx,
      uint8_t **hash,
      size_t *hash_len,
      uint32_t flags);

  void cl_hash_destroy(void *ctx);

  cl_error_t cl_hash_file_fd_ex(
      const char *alg,
      int fd,
      size_t offset,
      size_t length,
      uint8_t **hash,
      size_t *hash_len,
      uint32_t flags);
  ```

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1532)

- ClamScan: Improved the precision of the bytes-scanned and bytes-read counters.
  The ClamScan scan summary will now report exact counts in "GiB", "MiB", "KiB",
  or "B" as appropriate. Previously, it always reported "MB".

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1532)

- ClamScan: Add hash & file-type in/out CLI options:
  - `--hash-hint`: The file hash so that libclamav does not need to calculate
    it. The type of hash must match the `--hash-alg`.
  - `--log-hash`: Print the file hash after each file scanned. The type of hash
    printed will match the `--hash-alg`.
  - `--hash-alg`: The hashing algorithm used for either `--hash-hint` or
    `--log-hash`. Supported algorithms are "md5", "sha1", "sha2-256".
    If not specified, the default is "sha2-256".
  - `--file-type-hint`: The file type hint so that libclamav can optimize
    scanning (e.g., "pe", "elf", "zip", etc.). You may also use ClamAV type names
    such as "CL_TYPE_PE". ClamAV will ignore the hint if it is not familiar with
    the specified type.
    See also: https://docs.clamav.net/appendix/FileTypes.html#file-types
  - `--log-file-type`: Print the file type after each file scanned.

  We will not be adding this for ClamDScan, as we do not have a mechanism in the
  ClamD socket API to receive scan options or a way for ClamD to include scan
  metadata in the response.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1532)

- libclamav: Added new scan functions that provide additional functionality:
  ```c
  cl_error_t cl_scanfile_ex(
      const char *filename,
      cl_verdict_t *verdict_out,
      const char **last_alert_out,
      uint64_t *scanned_out,
      const struct cl_engine *engine,
      struct cl_scan_options *scanoptions,
      void *context,
      const char *hash_hint,
      char **hash_out,
      const char *hash_alg,
      const char *file_type_hint,
      char **file_type_out);

  cl_error_t cl_scandesc_ex(
      int desc,
      const char *filename,
      cl_verdict_t *verdict_out,
      const char **last_alert_out,
      uint64_t *scanned_out,
      const struct cl_engine *engine,
      struct cl_scan_options *scanoptions,
      void *context,
      const char *hash_hint,
      char **hash_out,
      const char *hash_alg,
      const char *file_type_hint,
      char **file_type_out);

  cl_error_t cl_scanmap_ex(
      cl_fmap_t *map,
      const char *filename,
      cl_verdict_t *verdict_out,
      const char **last_alert_out,
      uint64_t *scanned_out,
      const struct cl_engine *engine,
      struct cl_scan_options *scanoptions,
      void *context,
      const char *hash_hint,
      char **hash_out,
      const char *hash_alg,
      const char *file_type_hint,
      char **file_type_out);
  ```

  The older `cl_scan*()` functions are now deprecated and may be removed in a
  future release. See `clamav.h` for more details.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1532)

- libclamav: Added a new engine option to toggle temp directory recursion.

  Temp directory recursion is the idea that each object scanned in ClamAV's
  recursive extract/scan process will get a new temp subdirectory, mimicking
  the nesting structure of the file.

  Temp directory recursion was introduced in ClamAV 0.103 and is enabled
  whenever `--leave-temps` / `LeaveTemporaryFiles` is enabled.

  In ClamAV 1.5, an application linking to libclamav can separately enable temp
  directory recursion if they wish.
  For ClamScan and ClamD, it will remain tied to `--leave-temps` /
  `LeaveTemporaryFiles` options.

  The new temp directory recursion option can be enabled with:
  ```c
  cl_engine_set_num(engine, CL_ENGINE_TMPDIR_RECURSION, 1);
  ```

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1532)

- libclamav: Added a class of scan callback functions that can be added with the
  following API function:
  ```c
  void cl_engine_set_scan_callback(struct cl_engine *engine, clcb_scan callback, cl_scan_callback_t location);
  ```

  The scan callback location may be configured using the following five values:
  - `CL_SCAN_CALLBACK_PRE_HASH`: Occurs just after basic file-type detection and
    before any hashes have been calculated either for the cache or the gen-json
    metadata.
  - `CL_SCAN_CALLBACK_PRE_SCAN`: Occurs before parser modules run and before
    pattern matching.
  - `CL_SCAN_CALLBACK_POST_SCAN`: Occurs after pattern matching and after
    running parser modules. A.k.a. the scan is complete for this layer.
  - `CL_SCAN_CALLBACK_ALERT`: Occurs each time an alert (detection) would be
    triggered during a scan.
  - `CL_SCAN_CALLBACK_FILE_TYPE`: Occurs each time the file type determination
    is refined. This may happen more than once per layer.

  Each callback may alter scan behavior using the following return codes:

  - `CL_BREAK`: Scan aborted by callback. The rest of the scan is skipped.
    This does not mark the file as clean or infected, it just skips the rest of
    the scan.

  - `CL_SUCCESS` / `CL_CLEAN`: File scan will continue.

    For `CL_SCAN_CALLBACK_ALERT`: This means you want to ignore this specific
    alert and keep scanning.

    This is different than `CL_VERIFIED` because it does not affect prior or
    future alerts. Return `CL_VERIFIED` instead if you want to remove prior
    alerts for this layer and skip the rest of the scan for this layer.

  - `CL_VIRUS`: This means you do not trust the file. A new alert will be added.

    For `CL_SCAN_CALLBACK_ALERT`: This means you agree with the alert and no
    extra alert is needed.

  - `CL_VERIFIED`: Layer explicitly trusted by the callback and previous alerts
    removed for THIS layer. You might want to do this if you trust the hash or
    verified a digital signature. The rest of the scan will be skipped for THIS
    layer. For contained files, this does NOT mean that the parent or adjacent
    layers are trusted.

  Each callback is given a pointer to the current scan layer from which they can
  get previous layers, can get the layer's fmap, and then various attributes of
  the layer and of the fmap. To make this possible, there are new APIs to
  query scan-layer details and fmap details:
  ```c
    cl_error_t cl_fmap_set_name(cl_fmap_t *map, const char *name);
    cl_error_t cl_fmap_get_name(cl_fmap_t *map, const char **name_out);
    cl_error_t cl_fmap_set_path(cl_fmap_t *map, const char *path);
    cl_error_t cl_fmap_get_path(cl_fmap_t *map, const char **path_out, size_t *offset_out, size_t *len_out);
    cl_error_t cl_fmap_get_fd(const cl_fmap_t *map, int *fd_out, size_t *offset_out, size_t *len_out);
    cl_error_t cl_fmap_get_size(const cl_fmap_t *map, size_t *size_out);
    cl_error_t cl_fmap_set_hash(const cl_fmap_t *map, const char *hash_alg, char hash);
    cl_error_t cl_fmap_have_hash(const cl_fmap_t *map, const char *hash_alg, bool *have_hash_out);
    cl_error_t cl_fmap_will_need_hash_later(const cl_fmap_t *map, const char *hash_alg);
    cl_error_t cl_fmap_get_hash(const cl_fmap_t *map, const char *hash_alg, char **hash_out);
    cl_error_t cl_fmap_get_data(const cl_fmap_t *map, size_t offset, size_t len, const uint8_t **data_out, size_t *data_len_out);
    cl_error_t cl_scan_layer_get_fmap(cl_scan_layer_t *layer, cl_fmap_t **fmap_out);
    cl_error_t cl_scan_layer_get_parent_layer(cl_scan_layer_t *layer, cl_scan_layer_t **parent_layer_out);
    cl_error_t cl_scan_layer_get_type(cl_scan_layer_t *layer, const char **type_out);
    cl_error_t cl_scan_layer_get_recursion_level(cl_scan_layer_t *layer, uint32_t *recursion_level_out);
    cl_error_t cl_scan_layer_get_object_id(cl_scan_layer_t *layer, uint64_t *object_id_out);
    cl_error_t cl_scan_layer_get_last_alert(cl_scan_layer_t *layer, const char **alert_name_out);
    cl_error_t cl_scan_layer_get_attributes(cl_scan_layer_t *layer, uint32_t *attributes_out);
  ```

  This deprecates, but does not immediately remove, the existing scan callbacks:
  ```c
    void cl_engine_set_clcb_pre_cache(struct cl_engine *engine, clcb_pre_cache callback);
    void cl_engine_set_clcb_file_inspection(struct cl_engine *engine, clcb_file_inspection callback);
    void cl_engine_set_clcb_pre_scan(struct cl_engine *engine, clcb_pre_scan callback);
    void cl_engine_set_clcb_post_scan(struct cl_engine *engine, clcb_post_scan callback);
    void cl_engine_set_clcb_virus_found(struct cl_engine *engine, clcb_virus_found callback);
    void cl_engine_set_clcb_hash(struct cl_engine *engine, clcb_hash callback);
  ```

  There is an interactive test program to demonstrate the new callbacks.
  See: `examples/ex_scan_callbacks.c`

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1532)

- Signature names that start with "Weak." will no longer alert.
  Instead, they will be tracked internally and can be found in scan metadata
  JSON. This is a step towards enabling alerting signatures to depend on prior
  Weak indicator matches in the current layer or in child layers.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1532)

- For the "Generate Metadata JSON" feature:

  - The "Viruses" array of alert names has been replaced by two new arrays that
    include additional details beyond just signature name:
    - "Indicators" records three types of indicators:
      - **Strong** indicators are for traditional alerting signature matches and
        will halt the scan, except in all-match mode.
      - **Potentially Unwanted** indicators will only cause an alert at the end of
        the scan unless a Strong indicator is found. They are treated the same
        as Strong indicators in all-match mode.
      - **Weak** indicators do not alert and will be leveraged in a future version
        as a condition for logical signature matches.
    - "Alerts" records only alerting indicators. Events that trust a file, such
      as false positive signatures, will remove affected indicators, and mark
      them as "Ignored" in the "Indicators" array.

  - Add new option to calculate and record additional hash types when the
    "generate metadata JSON" feature is enabled:
    - libclamav option: `CL_SCAN_GENERAL_STORE_EXTRA_HASHES`
    - ClamScan option: `--json-store-extra-hashes` (default off)
    - `clamd.conf` option: `JsonStoreExtraHashes` (default 'no')

  - The file hash is now stored as "sha2-256" instead of "FileMD5". If you
    enable the "extra hashes" option, then it will also record "md5" and "sha1".

  - Each object scanned now has a unique "Object ID".

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1532)

- Sigtool: Renamed the sigtool option `--sha256` to `--sha2-256`.
  The original option is still functional but is deprecated.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1532)

### Other improvements

- Set a limit on the max-recursion config option. Users will no longer be
  able to set max-recursion higher than 100.
  This change prevents errors on start up or crashes if encountering
  a file with that many layers of recursion.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1264)

- Build system: CMake improvements to support compiling for the AIX platform.
  This change is courtesy of GitHub user KamathForAIX.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1387)

- Improve support for extracting malformed zip archives.
  This change is courtesy of Frederick Sell.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1460)

- Windows: Code quality improvement for the ClamScan and ClamDScan `--move`
  and `--remove` options.
  This change is courtesy of Maxim Suhanov.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1470)

- Added file type recognition for an initial set of AI model file types.

  The file type is accessible to applications using libclamav via the scan
  callback functions and as an optional output parameter to the scan functions:
  `cl_scanfile_ex()`, `cl_scanmap_ex()`, and `cl_scandesc_ex()`.

  When scanning these files, type will now show "CL_TYPE_AI_MODEL" instead of
  "CL_TYPE_BINARY_DATA".

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1476)

- Added support for inline comments in ClamAV configuration files.
  This change is courtesy of GitHub user userwiths.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1308)

- Disabled the MyDoom hardcoded/heuristic detection because of false positives.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1495)

- Sigtool: Added support for creating `.cdiff` and `.script` patch files for
  CVDs that have underscores in the CVD name.
  Also improved support for relative paths with the `--diff` command.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1541)

- Windows: Improved support for file names with UTF-8 characters not found in
  the ANSI or OEM code pages when printing scan results or showing activity in
  the ClamDTOP monitoring utility.
  Fixed a bug with opening files with such names with the Sigtool utility.

  [GitHub pull request #1](https://github.com/Cisco-Talos/clamav/pull/1461)

  [GitHub pull request #2](https://github.com/Cisco-Talos/clamav/pull/1537)

- Improved the code quality of the ZIP module. Added inline documentation.

  [GitHub pull request #1](https://github.com/Cisco-Talos/clamav/pull/1548)

  [GitHub pull request #2](https://github.com/Cisco-Talos/clamav/pull/1552)

- Always run scan callbacks for embedded files. Embedded files are found within
  other files through signature matches instead of by parsing. They will now
  be processed the same way and then they can trigger application callbacks
  (e.g., "pre-scan", "post-scan", etc.).

  A consequence of this change is that each embedded file will be pattern-
  matched just like any other extracted file. To minimize excessive pattern
  matching, file header validation checks were added for ZIP, ARJ, and CAB.
  Also fixed a bug with embedded PE file scanning to reduce unnecessary matching.

  This change will impact scans with both the "leave-temps" feature and the
  "force-to-disk" feature enabled, resulting in additional temporary files.

  [GitHub pull request #1](https://github.com/Cisco-Talos/clamav/pull/1532)

  [GitHub pull request #2](https://github.com/Cisco-Talos/clamav/pull/1571)

- Added DevContainer templates to the ClamAV Git repository in order to make it
  easier to set up AlmaLinux or Debian development environments.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1462)

- Removed the "Heuristics.XZ.DicSizeLimit" alert because of potential unintended
  alerts based on system state.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1573)

- Improved support for compiling on Solaris.

  This fix courtesy of Andrew Watkins.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1569)

- Improved support for compiling on GNU/Hurd.

  This fix courtesy of Pino Toscano.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1569)

- Improved support for linking with the NCurses library dependency when
  libtinfo is built as a separate library.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1356)

### Bug fixes

- Reduced email multipart message parser complexity.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1347)

- Fixed possible undefined behavior in inflate64 module.
  The inflate64 module is a modified version of the zlib library, taken from
  version 1.2.3 with some customization and with some cherry-picked fixes.
  This adds one additional fix from zlib 1.2.9.
  Thank you to TITAN Team for reporting this issue.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1469)

- Fixed a bug in ClamD that broke reporting of memory usage on Linux.
  The STATS command can be used to monitor ClamD directly or through ClamDTOP.
  The memory stats feature does not work on all platforms (e.g., Windows).

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1465)

- Windows: Fixed a build issue when the same library dependency is found in
  two different locations.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1453)

- Fixed an infinite loop when scanning some email files in debug-mode.
  This fix is courtesy of Yoann Lecuyer.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1445)

- Fixed a stack buffer overflow bug in the phishing signature load process.
  This fix is courtesy of GitHub user Shivam7-1.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1486)

- Fixed a race condition in the Freshclam feature tests.
  This fix is courtesy of GitHub user rma-x.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1513)

- Windows: Fixed a 5-byte heap buffer overread in the Windows unit tests.
  This fix is courtesy of GitHub user Sophie0x2E.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1542)

- Fix double-extraction of OOXML-based office documents.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1532)

- ClamBC: Fixed crashes on startup.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1532)

- Fixed an assortment of issues found with Coverity static analysis.

  [GitHub pull request #1](https://github.com/Cisco-Talos/clamav/pull/1574)

  [GitHub pull request #2](https://github.com/Cisco-Talos/clamav/pull/1582)

- Fixed libclamav unit test, ClamD, and ClamDScan Valgrind test failures
  affecting some platforms.

  [GitHub pull request #1](https://github.com/Cisco-Talos/clamav/pull/1554)

  [GitHub pull request #2](https://github.com/Cisco-Talos/clamav/pull/1570)

- Fixed crash in the Sigtool program when using the `--html-normalize` option.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1556)

- Fixed some potential NULL-pointer dereference issues if memory allocations
  fail.

  Fix courtesy of GitHUb user JiangJias.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1581)

### Acknowledgments

Special thanks to the following people for code contributions and bug reports:
- Andrew Watkins
- b1tg
- ChaoticByte
- Frederick Sell
- KamathForAIX
- Mark Carey at SAP
- Maxim Suhanov
- Pino Toscano
- rma-x
- Shivam7-1
- Sophie0x2E
- TITAN Team
- userwiths
- Yoann Lecuyer

## 1.4.3

ClamAV 1.4.3 is a patch release with the following fixes:

- [CVE-2025-20260](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-20260):
  Fixed a possible buffer overflow write bug in the PDF file parser that could
  cause a denial-of-service (DoS) condition or enable remote code execution.

  This issue only affects configurations where both:
  1. The max file-size scan limit is set greater than or equal to 1024MB.
  2. The max scan-size scan limit is set greater than or equal to 1025MB.

  The code flaw was present prior to version 1.0.0, but a change in version
  1.0.0 that enables larger allocations based on untrusted data made it
  possible to trigger this bug.

  This issue affects all currently supported versions. It will be fixed in:
  - 1.4.3
  - 1.0.9

  Thank you to Greg Walkup at Sandia National Labs for identifying this issue.

- [CVE-2025-20234](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-20234):
  Fixed a possible buffer overflow read bug in the UDF file parser that may
  write to a temp file and thus disclose information, or it may crash and
  cause a denial-of-service (DoS) condition.

  This issue was introduced in version 1.2.0. It will be fixed in 1.4.3.

  Thank you to volticks (@movx64 on Twitter/X), working with Trend Micro Zero
  Day Initiative, for identifying this issue.

- Fixed a possible use-after-free bug in the Xz decompression module in the
  bundled lzma-sdk library.

  This issue was fixed in the lzma-sdk version 18.03. ClamAV bundles a copy
  of the lzma-sdk with some performance changes specific to libclamav, plus
  select bug fixes like this one in lieu of a full upgrade to newer lzma-sdk.

  This issue affects all ClamAV versions at least as far back as 0.99.4.
  It will be fixed in:
  - 1.4.3
  - 1.0.9

  Thank you to OSS-Fuzz for identifying this issue.

- Windows: Fixed a build install issue when a DLL dependency such as libcrypto
  has the exact same name as one provided by the Windows operating system.

## 1.4.2

ClamAV 1.4.2 is a patch release with the following fixes:

- [CVE-2025-20128](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-20128):
  Fixed a possible buffer overflow read bug in the OLE2 file parser that could
  cause a denial-of-service (DoS) condition.

  This issue was introduced in version 1.0.0 and affects all currently
  supported versions. It will be fixed in:
  - 1.4.2
  - 1.0.8

  Thank you to OSS-Fuzz for identifying this issue.

## 1.4.1

ClamAV 1.4.1 is a critical patch release with the following fixes:

- [CVE-2024-20506](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-20506):
  Changed the logging module to disable following symlinks on Linux and Unix
  systems so as to prevent an attacker with existing access to the 'clamd' or
  'freshclam' services from using a symlink to corrupt system files.

  This issue affects all currently supported versions. It will be fixed in:
  - 1.4.1
  - 1.3.2
  - 1.0.7
  - 0.103.12

  Thank you to Detlef for identifying this issue.

- [CVE-2024-20505](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-20505):
  Fixed a possible out-of-bounds read bug in the PDF file parser that could
  cause a denial-of-service (DoS) condition.

  This issue affects all currently supported versions. It will be fixed in:
  - 1.4.1
  - 1.3.2
  - 1.0.7
  - 0.103.12

  Thank you to OSS-Fuzz for identifying this issue.

- Removed unused Python modules from freshclam tests including deprecated
  'cgi' module that is expected to cause test failures in Python 3.13.

## 1.4.0

ClamAV 1.4.0 includes the following improvements and changes:

### Major changes

- Added support for extracting ALZ archives.
  The new ClamAV file type for ALZ archives is `CL_TYPE_ALZ`.
  Added a [DCONF](https://docs.clamav.net/manual/Signatures/DynamicConfig.html)
  option to enable or disable ALZ archive support.
  > _Tip_: DCONF (Dynamic CONFiguration) is a feature that allows for some
  > configuration changes to be made via ClamAV `.cfg` "signatures".

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1183)

- Added support for extracting LHA/LZH archives.
  The new ClamAV file type for LHA/LZH archives is `CL_TYPE_LHA_LZH`.
  Added a [DCONF](https://docs.clamav.net/manual/Signatures/DynamicConfig.html)
  option to enable or disable LHA/LZH archive support.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1192)

- Added the ability to disable image fuzzy hashing, if needed. For context,
  image fuzzy hashing is a detection mechanism useful for identifying malware
  by matching images included with the malware or phishing email/document.

  New ClamScan options:
  ```
  --scan-image[=yes(*)/no]
  --scan-image-fuzzy-hash[=yes(*)/no]
  ```

  New ClamD config options:
  ```
  ScanImage yes(*)/no
  ScanImageFuzzyHash yes(*)/no
  ```

  New libclamav scan options:
  ```c
  options.parse &= ~CL_SCAN_PARSE_IMAGE;
  options.parse &= ~CL_SCAN_PARSE_IMAGE_FUZZY_HASH;
  ```

  Added a [DCONF](https://docs.clamav.net/manual/Signatures/DynamicConfig.html)
  option to enable or disable image fuzzy hashing support.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1186)

### Other improvements

- Added cross-compiling instructions for targeting ARM64/aarch64 processors for
  [Windows](https://github.com/Cisco-Talos/clamav/blob/main/INSTALL-cross-windows-arm64.md)
  and
  [Linux](https://github.com/Cisco-Talos/clamav/blob/main/INSTALL-cross-linux-arm64.md).

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1116)

- Improved the Freshclam warning messages when being blocked or rate limited
  so as to include the Cloudflare Ray ID, which helps with issue triage.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1195)

- Removed unnecessary memory allocation checks when the size to be allocated
  is fixed or comes from a trusted source.
  We also renamed internal memory allocation functions and macros, so it is
  more obvious what each function does.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1137)

- Improved the Freshclam documentation to make it clear that the `--datadir`
  option must be an absolute path to a directory that already exists, is
  writable by Freshclam, and is readable by ClamScan and ClamD.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1199)

- Added an optimization to avoid calculating the file hash if the clean file
  cache has been disabled. The file hash may still be calculated as needed to
  perform hash-based signature matching if any hash-based signatures exist that
  target a file of the same size, or if any hash-based signatures exist that
  target "any" file size.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1167)

- Added an improvement to the SystemD service file for ClamOnAcc so that the
  service will shut down faster on some systems.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1164)

- Added a CMake build dependency on the version map files so that the build
  will re-run if changes are made to the version map files.
  Work courtesy of Sebastian Andrzej Siewior.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1294)

- Added an improvement to the CMake build so that the RUSTFLAGS settings
  are inherited from the environment.
  Work courtesy of liushuyu.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1301)

### Bug fixes

- Silenced confusing warning message when scanning some HTML files.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1252)

- Fixed minor compiler warnings.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1197)

- Since the build system changed from Autotools to CMake, ClamAV no longer
  supports building with configurations where bzip2, libxml2, libz, libjson-c,
  or libpcre2 are not available. Libpcre is no longer supported in favor of
  libpcre2. In this release, we removed all the dead code associated with those
  unsupported build configurations.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1217)

- Fixed assorted typos. Patch courtesy of RainRat.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1228)

- Added missing documentation for the ClamScan `--force-to-disk` option.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1186)

- Fixed an issue where ClamAV unit tests would prefer an older
  libclamunrar_iface library from the install path, if present, rather than
  the recently compiled library in the build path.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1258)

- Fixed a build issue on Windows with newer versions of Rust.
  Also upgraded GitHub Actions imports to fix CI failures.
  Fixes courtesy of liushuyu.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1307)

- Fixed an unaligned pointer dereference issue on select architectures.
  Fix courtesy of Sebastian Andrzej Siewior.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1293)

- Fixed a bug that prevented loading plaintext (non-CVD) signature files
  when using the `--fail-if-cvd-older-than=DAYS` / `FailIfCvdOlderThan` option.
  Fix courtesy of Bark.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1309)

### Acknowledgments

Special thanks to the following people for code contributions and bug reports:
- Bark
- liushuyu
- Sebastian Andrzej Siewior
- RainRat

## 1.3.2

ClamAV 1.3.2 is a patch release with the following fixes:

- [CVE-2024-20506](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-20506):
  Changed the logging module to disable following symlinks on Linux and Unix
  systems so as to prevent an attacker with existing access to the 'clamd' or
  'freshclam' services from using a symlink to corrupt system files.

  This issue affects all currently supported versions. It will be fixed in:
  - 1.4.1
  - 1.3.2
  - 1.0.7
  - 0.103.12

  Thank you to Detlef for identifying this issue.

- [CVE-2024-20505](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-20505):
  Fixed a possible out-of-bounds read bug in the PDF file parser that could
  cause a denial-of-service (DoS) condition.

  This issue affects all currently supported versions. It will be fixed in:
  - 1.4.1
  - 1.3.2
  - 1.0.7
  - 0.103.12

  Thank you to OSS-Fuzz for identifying this issue.

- Removed unused Python modules from freshclam tests including deprecated
  'cgi' module that is expected to cause test failures in Python 3.13.

- Fix unit test caused by expiring signing certificate.

  Backport of [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1305)

- Fixed a build issue on Windows with newer versions of Rust.
  Also upgraded GitHub Actions imports to fix CI failures.
  Fixes courtesy of liushuyu.

  Backport of [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1307)

- Fixed an unaligned pointer dereference issue on select architectures.
  Fix courtesy of Sebastian Andrzej Siewior.

  Backport of [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1293)

- Fixes to Jenkins CI pipeline.

For details, see [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1330)

## 1.3.1

ClamAV 1.3.1 is a critical patch release with the following fixes:

- [CVE-2024-20380](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-20380):
  Fixed a possible crash in the HTML file parser that could cause a
  denial-of-service (DoS) condition.

  This issue affects version 1.3.0 only and does not affect prior versions.

  Thank you to Błażej Pawłowski for identifying this issue.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1242)

- Updated select Rust dependencies to the latest versions.
  This resolved Cargo audit complaints and included PNG parser bug fixes.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1227)

- Fixed a bug causing some text to be truncated when converting from UTF-16.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1230)

- Fixed assorted complaints identified by Coverity static analysis.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1235)

- Fixed a bug causing CVDs downloaded by the `DatabaseCustomURL` Freshclam
  config option to be pruned and then re-downloaded with every update.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1238)

- Added the new 'valhalla' database name to the list of optional databases in
  preparation for future work.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1238)

- Added symbols to the `libclamav.map` file to enable additional build
  configurations.

  Patch courtesy of Neil Wilson.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1244)

## 1.3.0

ClamAV 1.3.0 includes the following improvements and changes:

### Major changes

- Added support for extracting and scanning attachments found in Microsoft
  OneNote section files.
  OneNote parsing will be enabled by default, but may be optionally disabled
  using one of the following options:
  a. The `clamscan` command line option: `--scan-onenote=no`,
  b. The `clamd.conf` config option: `ScanOneNote no`,
  c. The libclamav scan option `options.parse &= ~CL_SCAN_PARSE_ONENOTE;`,
  d. A signature change to the `daily.cfg` dynamic configuration (DCONF).

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1048)

### Other improvements

- Fixed issue when building ClamAV on the Haiku (BeOS-like) operating system.
  Patch courtesy of Luca D'Amico

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1061)

- ClamD: When starting, ClamD will now check if the directory specified by
  `TemporaryDirectory` in `clamd.conf` exists. If it doesn't, ClamD
  will print an error message and will exit with exit code 1.
  Patch courtesy of Andrew Kiggins.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1037)

- CMake: If configured to build static libraries, CMake will now also
  install the libclamav_rust, libclammspack, libclamunrar_iface, and
  libclamunrar static libraries required by libclamav.

  Note: These libraries are all linked into the clamscan, clamd, sigtool,
  and freshclam programs, which is why they did not need to be installed
  to function. However, these libraries would be required if you wish to
  build some other program that uses the libclamav static library.

  Patch courtesy of driverxdw.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1100)

- Added file type recognition for compiled Python (`.pyc`) files.
  The file type appears as a string parameter for these callback functions:
  - `clcb_pre_cache`
  - `clcb_pre_scan`
  - `clcb_file_inspection`
  When scanning a `.pyc` file, the `type` parameter will now show
  "CL_TYPE_PYTHON_COMPILED" instead of "CL_TYPE_BINARY_DATA".

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1111)

- Improved support for decrypting PDF's with empty passwords.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1141)

- Assorted minor improvements and typo fixes.

### Bug fixes

- Fixed a warning when scanning some HTML files.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1084)

- Fixed an issue decrypting some PDF's with an empty password.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1079)

- ClamOnAcc: Fixed an infinite loop when a watched directory does not exist.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1047)

- ClamOnAcc: Fixed an infinite loop when a file has been deleted before a scan.
  Patch courtesy of gsuehiro.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1150)

- Fixed a possible crash when processing VBA files on HP-UX/IA 64bit.
  Patch courtesy of Albert Chin-A-Young.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/526)

- ClamConf: Fixed an issue printing `MaxScanSize` introduced with the change
  to allow a MaxScanSize greater than 4 GiB.
  Fix courtesy of teoberi.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1121)

- Fixed an issue building a ClamAV RPM in some configurations.
  The issue was caused by faulty CMake logic that intended to create an
  empty database directory during the install.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1144)

### Acknowledgments

Special thanks to the following people for code contributions and bug reports:
- Albert Chin-A-Young
- Andrew Kiggins
- driverxdw
- gsuehiro
- Luca D'Amico
- RainRat
- teoberi

## 1.2.3

ClamAV 1.2.3 is a critical patch release with the following fixes:

- Updated select Rust dependencies to the latest versions.
  This resolved Cargo audit complaints and included PNG parser bug fixes.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1226)

- Fixed a bug causing some text to be truncated when converting from UTF-16.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1231)

- Fixed assorted complaints identified by Coverity static analysis.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1236)

- Fixed a bug causing CVDs downloaded by the `DatabaseCustomURL` Freshclam
  config option to be pruned and then re-downloaded with every update.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1239)

- Added the new 'valhalla' database name to the list of optional databases in
  preparation for future work.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1239)

- Silenced a warning "Unexpected early end-of-file" that occured when
  scanning some PNG files.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1215)

## 1.2.2

ClamAV 1.2.2 is a critical patch release with the following fix:

- [CVE-2024-20290](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-20290):
  Fixed a possible heap overflow read bug in the OLE2 file parser that could
  cause a denial-of-service (DoS) condition.

  Affected versions:
  - 1.0.0 through 1.0.4 (LTS)
  - 1.1 (all patch versions)
  - 1.2.0 and 1.2.1

  Thank you to OSS-Fuzz for identifying this issue.

- [CVE-2024-20328](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-20328):
  Fixed a possible command injection vulnerability in the `VirusEvent` feature
  of ClamAV's ClamD service.

  To fix this issue, we disabled the '%f' format string parameter.
  ClamD administrators may continue to use the `CLAM_VIRUSEVENT_FILENAME`
  environment variable, instead of '%f'. But you should do so only from within
  an executable, such as a Python script, and not directly in the `clamd.conf`
  `VirusEvent` command.

  Affected versions:
  - 0.104 (all patch versions)
  - 0.105 (all patch versions)
  - 1.0.0 through 1.0.4 (LTS)
  - 1.1 (all patch versions)
  - 1.2.0 and 1.2.1

  Thank you to Amit Schendel for identifying this issue.

## 1.2.1

ClamAV 1.2.1 is a patch release with the following fixes:

- Eliminate security warning about unused "atty" dependency.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1033)

- Upgrade the bundled UnRAR library (libclamunrar) to version 6.2.12.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1056)

- Build system: Fix link error with Clang/LLVM/LLD version 17.
  Patch courtesy of Yasuhiro Kimura.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1060)

- Fixed the alert-exceeds-max feature for files greater than 2 GiB and less
  than max file size.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1039)

Special thanks to the following people for code contributions and bug reports:
- Yasuhiro Kimura

## 1.2.0

ClamAV 1.2.0 includes the following improvements and changes:

### Major changes

- Added support for extracting Universal Disk Format (UDF) partitions.

  Specifically, this version adds support for the Beginning Extended Area
  Descriptor (BEA01) type of UDF files.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/941)

- Added an option to customize the size of ClamAV's clean file cache.

  Increasing the size of the clean file cache may improve scan performance
  but will require more RAM. The cache size value should be a square number
  or will be rounded up to the nearest square number.

  The cache size option for `clamd` and `clamscan` is `--cache-size`.
  Alternatively, you can customize the cache size for ClamD by setting
  `CacheSize` in `clamd.conf`.

  Patch courtesy of Craig Andrews.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/882)

- Introduced a SystemD timer for running Freshclam updates, without sending
  Freshclam into the background. This takes the "burden of timing the updates"
  from Freshclam and puts it onto SystemD.
  The timer can be activated, audited, and the logs inspected:
  ```sh
  sudo systemctl enable --now clamav-freshclam-once.timer
  sudo systemctl list-timers
  sudo systemctl status clamav-freshclam-once.timer
  sudo systemctl status clamav-freshclam-once.service
  journalctl -u clamav-freshclam-once.service
  ```
  If you want a different update interval you can edit the timer unit file:
  ```sh
  sudo systemctl edit clamav-freshclam-once.timer
  ```
  Patch courtesy of Nils Werner.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/962)

- Raised the MaxScanSize limit so the total amount of data scanned when
  scanning a file or archive may exceed 4 gigabytes.

  Introduced the ability to suffix the MaxScanSize and other config file size
  options with a "G" or "g" for the number of gigabytes.
  For example, for ClamD you may now specify `MaxScanSize 10G` in `clamd.conf`.
  And for ClamScan, you may now specify `--max-scansize=10g`.

  The `MaxFileSize` is still limited internally in ClamAV to 2 gigabytes.
  Any file, or embedded file, larger than 2GB will be skipped.
  You may use `clamscan --alert-exceeds-max`, or the `clamd.conf` option
  `AlertExceedsMax yes` to tell if a scan is not completed because of
  the scan limits.

  Patch courtesy of matthias-fratz-bsz.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/945)

- Added ability for Freshclam to use a client certificate PEM file and a
  private key PEM file for authentication to a private mirror by setting the
  following environment variables:
  - `FRESHCLAM_CLIENT_CERT`: May be set to the path of a file (PEM) containing
    the client certificate.
  - `FRESHCLAM_CLIENT_KEY`: May be set to the path of a file (PEM) containing
    the client private key.
  - `FRESHCLAM_CLIENT_KEY_PASSWD`: May be set to a password for the client key
    PEM file, if it is password protected.

  Patch courtesy of jedrzej.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/955)

## Other improvements

- Fix an issue extracting files from ISO9660 partitions where the files are
  listed in the plain ISO tree and there also exists an empty Joliet tree.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/938)

- CMake build system improvement to support compiling with OpenSSL 3.x on
  macOS with the Xcode toolchain.

  The official ClamAV installers and packages are now built with OpenSSL 3.1.1
  or newer.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/970)

- The suggested path for the `clamd.pid` and `clamd.sock` file in the sample
  configs have been updated to reflect the recommended locations for these files
  in the Docker images. These are:
  - `/run/clamav/clamd.pid`
  - `/run/clamav/clamd.sock`

  For consistency, it now specifies `clamd.sock` instead of `clamd.socket`.

  Patch courtesy of computersalat.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/931)

### Bug fixes

- Fixed an issue where ClamAV does not abort the signature load process after
  partially loading an invalid signature. The bug would later cause a crash when
  scanning certain files.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/934)

- Fixed a possible buffer over-read bug when unpacking PE files.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/927)

- Removed a warning message showing the HTTP response codes during the
  Freshclam database update process.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/935)

- Added missing command line options to the ClamD and ClamAV-Milter `--help`
  message and manpages.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/936)

- ClamOnAcc: Fixed error message when using `--wait` without `--ping` option.
  Patch courtesy of Răzvan Cojocaru.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/984)

- Fixed an assortment of code quality issues identified by Coverity:

  [GitHub pull request #1](https://github.com/Cisco-Talos/clamav/pull/989)

  [GitHub pull request #2](https://github.com/Cisco-Talos/clamav/pull/998)

- Windows: Fixed a build issue with the CMake-Rust integration regarding
  detecting native static libraries that caused builds to fail with Rust
  version 1.70 and newer.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/992)

- Fixed a bounds check issue in the PDF parser that may result in a 1-byte
  buffer over read but does not cause a crash.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/988)

- Upgraded the bundled UnRAR library (libclamunrar) to version 6.2.10.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1008)

- Fixed a compatibility issue with libjson-c version 0.17.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1002)

### Acknowledgments

Special thanks to the following people for code contributions and bug reports:
- computersalat
- Craig Andrews
- jedrzej
- matthias-fratz-bsz
- Nils Werner
- Răzvan Cojocaru

## 1.1.3

ClamAV 1.1.3 is a patch release with the following fixes:

- Eliminate security warning about unused "atty" dependency.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1034)

- Upgrade the bundled UnRAR library (libclamunrar) to version 6.2.12.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1055)

- Windows: libjson-c 0.17 compatibility fix. with ssize_t type definition.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1063)

- Build system: Fix link error with Clang/LLVM/LLD version 17.
  Patch courtesy of Yasuhiro Kimura.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1059)

- Fix alert-exceeds-max feature for files > 2GB and < max-filesize.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1040)

Special thanks to the following people for code contributions and bug reports:
- Yasuhiro Kimura

## 1.1.2

ClamAV 1.1.2 is a critical patch release with the following fixes:

- Upgrade the bundled UnRAR library (libclamunrar) to version 6.2.10.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1011)

## 1.1.1

ClamAV 1.1.1 is a critical patch release with the following fixes:

- [CVE-2023-20197](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-20197)
  Fixed a possible denial of service vulnerability in the HFS+ file parser.
  This issue affects versions 1.1.0, 1.0.1 through 1.0.0, 0.105.2 through 0.105.0,
  0.104.4 through 0.104.0, and 0.103.8 through 0.103.0.
  Thank you to Steve Smith for reporting this issue.

- Fixed a build issue when using the Rust nightly toolchain, which was
  affecting the oss-fuzz build environment used for regression tests.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/997)

- Fixed a build issue on Windows when using Rust version 1.70 or newer.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/994)

- CMake build system improvement to support compiling with OpenSSL 3.x on
  macOS with the Xcode toolchain.

  The official ClamAV installers and packages are now built with OpenSSL 3.1.1
  or newer.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/972)

- Removed a warning message showing the HTTP response codes during the
  Freshclam database update process.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/939)

Special thanks to the following people for code contributions and bug reports:
- Steve Smith

## 1.1.0

ClamAV 1.1.0 includes the following improvements and changes:

### Major changes

- Added the ability to extract images embedded in HTML CSS `<style>` blocks.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/813)

- Updated to Sigtool so that the `--vba` option will extract VBA code from
  Microsoft Office documents the same way that libclamav extracts VBA.
  This resolves several issues where Sigtool could not extract VBA.
  Sigtool will also now display the normalized VBA code instead of the
  pre-normalized VBA code.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/852)

- Added a new ClamScan and ClamD option: `--fail-if-cvd-older-than=days`.
  Additionally, we introduce `FailIfCvdOlderThan` as a `clamd.conf` synonym for
  `--fail-if-cvd-older-than`. When passed, it causes ClamD to exit on startup
  with a non-zero return code if the virus database is older than the specified
  number of days.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/867)

- Added a new function `cl_cvdgetage()` to the libclamav API.
  This function will retrieve the age in seconds of the youngest file in a
  database directory, or the age of a single CVD (or CLD) file.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/867)

- Added a new function `cl_engine_set_clcb_vba()` to the libclamav API.
  Use this function to set a `cb_vba` callback function.
  The cb_vba callback function will be run whenever VBA is extracted from
  office documents. The provided data will be a normalized copy of the
  extracted VBA.
  This callback was added to support Sigtool so that it can use the same VBA
  extraction logic that ClamAV uses to scan documents.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/852)

## Other improvements

- Removed the vendored TomsFastMath library in favor of using OpenSSL to
  perform "big number"/multiprecision math operations.
  Work courtesy of Sebastian Andrzej Siewior.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/840)

- Build system: Added CMake option `DO_NOT_SET_RPATH` to avoid setting
  `RPATH` on Unix systems.
  Feature courtesy of Sebastian Andrzej Siewior.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/815)

- Build system: Enabled version-scripts with CMake to limit symbol exports for
  libclamav, libfreshclam, libclamunrar_iface, and libclamunrar shared
  libraries on Unix systems, excluding macOS.
  Improvement courtesy of Orion Poplawski and Sebastian Andrzej Siewior.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/776)

- Build system: Enabled users to pass in custom Rust compiler flags using the
  `RUSTFLAGS` CMake variable.
  Feature courtesy of Orion Poplawski.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/835)

- Removed a hard-coded alert for CVE-2004-0597.
  The CVE is old enough that it is no longer a threat and the detection had
  occasional false-positives.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/855)

- Set Git attributes to prevent Git from altering line endings for Rust
  vendored libraries. Third-party Rust libraries are bundled in the ClamAV
  release tarball. We do not commit them to our own Git repository, but
  community package maintainers may now store the tarball contents in Git.
  The Rust build system verifies the library manifest, and this change
  ensures that the hashes are correct.
  Improvement courtesy of Nicolas R.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/800)

- Fixed compile time warnings.
  Improvement courtesy of Răzvan Cojocaru.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/795)

- Added a minor optimization when matching domain name regex signatures for
  PDB, WDB and CDB type signatures.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/837)

- Build system: Enabled the ability to select a specific Python version.
  When building, you may use the CMake option `-D PYTHON_FIND_VER=<version>`
  to choose a specific Python version.
  Feature courtesy of Matt Jolly.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/787)

- Added improvements to the ClamOnAcc process log output so that it is
  easier to diagnose bugs.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/822)

- Windows: Enabled the MSI installer to upgrade between feature versions more
  easily when ClamAV is installed to a location different from the default
  (i.e., not `C:\Program Files\ClamAV`). This means that the MSI installer can
  find a previous ClamAV 1.0.x installation to upgrade to ClamAV 1.1.0.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/872)

- Sigtool: Added the ability to change the location of the temp directory
  using the `--tempdir` option and added the ability to retain the temp files
  created by Sigtool using the `--leave-temps` option.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/852)

- Other minor improvements.

### Bug fixes

- Fixed the broken `ExcludePUA` / `--exclude-pua` feature.
  Fix courtesy of Ged Haywood and Shawn Iverson.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/780)

- Fixed an issue with integer endianness when parsing Windows executables on
  big-endian systems.
  Fix courtesy of Sebastian Andrzej Siewior.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/814)

- Fixed a possible stack overflow read when parsing WDB signatures.
  This issue is not a vulnerability.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/807)

- Fixed a possible index out of bounds when loading CRB signatures.
  This issue is not a vulnerability.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/810)

- Fixed a possible use after free when reading logical signatures.
  This issue is not a vulnerability.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/811)

- Fixed a possible heap overflow read when reading PDB signatures.
  This issue is not a vulnerability.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/812)

- Fixed a possible heap overflow read in javascript normalizer module.
  This issue is not a vulnerability.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/868)

- Fixed two bugs that would cause Freshclam to fail update when applying a
  CDIFF database patch if that patch adds a file to the database archive
  or removes a file from the database archive.
  This bug also caused Sigtool to fail to create such a patch.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/893)

- Fixed an assortment of complaints identified by Coverity static analysis.

  [GitHub pull request #1](https://github.com/Cisco-Talos/clamav/pull/891)

  [GitHub pull request #2](https://github.com/Cisco-Talos/clamav/pull/899)

- Fixed one of the Freshclam tests that was failing on some Fedora systems
  due to a bug printing debug-level log messages to stdout.
  Fix courtesy of Arjen de Korte.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/881)

- Correctly remove temporary files generated by the VBA and XLM extraction
  modules so that the files are not leaked in patched versions of ClamAV
  where temporary files are written directly to the temp-directory instead
  of writing to a unique subdirectory.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/894)

### Acknowledgments

Special thanks to the following people for code contributions and bug reports:
- Arjen de Korte
- Craig Andrews
- Ged Haywood
- Matt Jolly
- Orion Poplawski
- Nicolas R.
- Răzvan Cojocaru
- Red
- Shawn Iverson
- Sebastian Andrzej Siewior
- The OSS-Fuzz project

## 1.0.9

ClamAV 1.0.9 is a patch release with the following fixes:

- [CVE-2025-20260](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-20260):
  Fixed a possible buffer overflow write bug in the PDF file parser that could
  cause a denial-of-service (DoS) condition or enable remote code execution.

  This issue only affects configurations where both:
  1. The max file-size scan limit is set greater than or equal to 1024MB.
  2. The max scan-size scan limit is set greater than or equal to 1025MB.

  The code flaw was present prior to version 1.0.0, but a change in version
  1.0.0 that enables larger allocations based on untrusted data made it
  possible to trigger this bug.

  This issue affects all currently supported versions. It will be fixed in:
  - 1.4.3
  - 1.0.9

  Thank you to Greg Walkup at Sandia National Labs for identifying this issue.

- Fixed a possible use-after-free bug in the Xz decompression module in the
  bundled lzma-sdk library.

  This issue was fixed in the lzma-sdk version 18.03. ClamAV bundles a copy
  of the lzma-sdk with some performance changes specific to libclamav, plus
  select bug fixes like this one in lieu of a full upgrade to newer lzma-sdk.

  This issue affects all ClamAV versions at least as far back as 0.99.4.
  It will be fixed in:
  - 1.4.3
  - 1.0.9

  Thank you to OSS-Fuzz for identifying this issue.

- Windows: Fixed a build install issue when a DLL dependency such as libcrypto
  has the exact same name as one provided by the Windows operating system.

## 1.0.8

ClamAV 1.0.8 is a patch release with the following fixes:

- [CVE-2025-20128](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-20128):
  Fixed a possible buffer overflow read bug in the OLE2 file parser that could
  cause a denial-of-service (DoS) condition.

  This issue was introduced in version 1.0.0 and affects all currently
  supported versions. It will be fixed in:
  - 1.4.2
  - 1.0.8

  Thank you to OSS-Fuzz for identifying this issue.

- ClamOnAcc: Fixed an infinite loop when a watched directory does not exist.
  This is a backport of a fix from ClamAV 1.3.0.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1426)

## 1.0.7

ClamAV 1.0.7 is a patch release with the following fixes:

- [CVE-2024-20506](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-20506):
  Changed the logging module to disable following symlinks on Linux and Unix
  systems so as to prevent an attacker with existing access to the 'clamd' or
  'freshclam' services from using a symlink to corrupt system files.

  This issue affects all currently supported versions. It will be fixed in:
  - 1.4.1
  - 1.3.2
  - 1.0.7
  - 0.103.12

  Thank you to Detlef for identifying this issue.

- [CVE-2024-20505](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-20505):
  Fixed a possible out-of-bounds read bug in the PDF file parser that could
  cause a denial-of-service (DoS) condition.

  This issue affects all currently supported versions. It will be fixed in:
  - 1.4.1
  - 1.3.2
  - 1.0.7
  - 0.103.12

  Thank you to OSS-Fuzz for identifying this issue.

- Removed unused Python modules from freshclam tests including deprecated
  'cgi' module that is expected to cause test failures in Python 3.13.

- Fix unit test caused by expiring signing certificate.
  - Backport of [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1305)

- Fixed a build issue on Windows with newer versions of Rust.
  Also upgraded GitHub Actions imports to fix CI failures.
  Fixes courtesy of liushuyu.
  - Backport of [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1307)

- Fixed an unaligned pointer dereference issue on select architectures.
  Fix courtesy of Sebastian Andrzej Siewior.
  - Backport of [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1293)

- Fixes to Jenkins CI pipeline.

For details, see [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1331)

## 1.0.6

ClamAV 1.0.6 is a critical patch release with the following fixes:

- Updated select Rust dependencies to the latest versions.
  This resolved Cargo audit complaints and included PNG parser bug fixes.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1225)

- Fixed a bug causing some text to be truncated when converting from UTF-16.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1232)

- Fixed assorted complaints identified by Coverity static analysis.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1237)

- Fixed a bug causing CVDs downloaded by the `DatabaseCustomURL` Freshclam
  config option to be pruned and then re-downloaded with every update.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1240)

- Added the new 'valhalla' database name to the list of optional databases in
  preparation for future work.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1240)

- Silenced a warning "Unexpected early end-of-file" that occured when
  scanning some PNG files.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1216)

## 1.0.5

ClamAV 1.0.5 is a critical patch release with the following fixes:

- [CVE-2024-20290](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-20290):
  Fixed a possible heap overflow read bug in the OLE2 file parser that could
  cause a denial-of-service (DoS) condition.

  Affected versions:
  - 1.0.0 through 1.0.4 (LTS)
  - 1.1 (all patch versions)
  - 1.2.0 and 1.2.1

  Thank you to OSS-Fuzz for identifying this issue.

- [CVE-2024-20328](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-20328):
  Fixed a possible command injection vulnerability in the `VirusEvent` feature
  of ClamAV's ClamD service.

  To fix this issue, we disabled the '%f' format string parameter.
  ClamD administrators may continue to use the `CLAM_VIRUSEVENT_FILENAME`
  environment variable, instead of '%f'. But you should do so only from within
  an executable, such as a Python script, and not directly in the `clamd.conf`
  `VirusEvent` command.

  Affected versions:
  - 0.104 (all patch versions)
  - 0.105 (all patch versions)
  - 1.0.0 through 1.0.4 (LTS)
  - 1.1 (all patch versions)
  - 1.2.0 and 1.2.1

  Thank you to Amit Schendel for identifying this issue.

## 1.0.4

ClamAV 1.0.4 is a patch release with the following fixes:

- Eliminate security warning about unused "atty" dependency.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1035)

- Upgrade the bundled UnRAR library (libclamunrar) to version 6.2.12.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1054)

- Windows: libjson-c 0.17 compatibility fix. with ssize_t type definition.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1064)

- Freshclam: Removed a verbose warning printed for each Freshclam HTTP request.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1042)

- Build system: Fix link error with Clang/LLVM/LLD version 17.
  Patch courtesy of Yasuhiro Kimura.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1058)

- Fix alert-exceeds-max feature for files > 2GB and < max-filesize.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1041)

Special thanks to the following people for code contributions and bug reports:
- Yasuhiro Kimura

## 1.0.3

ClamAV 1.0.3 is a critical patch release with the following fixes:

- Upgrade the bundled UnRAR library (libclamunrar) to version 6.2.10.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1010)

## 1.0.2

ClamAV 1.0.2 is a critical patch release with the following fixes:

- [CVE-2023-20197](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-20197)
  Fixed a possible denial of service vulnerability in the HFS+ file parser.
  This issue affects versions 1.1.0, 1.0.1 through 1.0.0, 0.105.2 through 0.105.0,
  0.104.4 through 0.104.0, and 0.103.8 through 0.103.0.
  Thank you to Steve Smith for reporting this issue.

- [CVE-2023-20212](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-20212)
  Fixed a possible denial of service vulnerability in the AutoIt file parser.
  This issue affects versions 1.0.1 and 1.0.0.
  This issue does not affect version 1.1.0.

- Fixed a build issue when using the Rust nightly toolchain, which was
  affecting the oss-fuzz build environment used for regression tests.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/996)

- Fixed a build issue on Windows when using Rust version 1.70 or newer.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/993)

- CMake build system improvement to support compiling with OpenSSL 3.x on
  macOS with the Xcode toolchain.

  The official ClamAV installers and packages are now built with OpenSSL 3.1.1
  or newer.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/973)

- Fixed an issue where ClamAV does not abort the signature load process after
  partially loading an invalid signature.
  The bug would later cause a crash when scanning certain files.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/952)

- Fixed an issue so that ClamAV correctly removes temporary files generated
  by the VBA and XLM extraction modules so that the files are not leaked in
  patched versions of ClamAV where temporary files are written directly to the
  temp-directory instead of writing to a unique subdirectory.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/900)

- Set Git attributes to prevent Git from altering line endings for bundled Rust
  libraries. Third-party Rust libraries are bundled in the ClamAV release
  tarball. We do not commit them to our own Git repository, but community
  package maintainers may now store the tarball contents in Git.
  The Rust build system verifies the library manifest, and this change
  ensures that the hashes are correct.
  Improvement courtesy of Nicolas R.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/856)

- Fixed two bugs that would cause Freshclam to fail update when applying a
  CDIFF database patch if that patch adds a file to the database archive
  or removes a file from the database archive.
  This bug also caused Sigtool to fail to create such a patch.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/901)

Special thanks to the following people for code contributions and bug reports:
- Nicolas R.
- Steve Smith

## 1.0.1

ClamAV 1.0.1 is a critical patch release with the following fixes:

- [CVE-2023-20032](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-20032):
  Fixed a possible remote code execution vulnerability in the HFS+ file parser.
  Issue affects versions 1.0.0 and earlier, 0.105.1 and earlier, and 0.103.7 and
  earlier.
  Thank you to Simon Scannell for reporting this issue.

- [CVE-2023-20052](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-20052):
  Fixed a possible remote information leak vulnerability in the DMG file parser.
  Issue affects versions 1.0.0 and earlier, 0.105.1 and earlier, and 0.103.7 and
  earlier.
  Thank you to Simon Scannell for reporting this issue.

- Fix allmatch detection issue with the preclass bytecode hook.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/825)

- Update vendored libmspack library to version 0.11alpha.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/828)

Special thanks to the following people for code contributions and bug reports:
- Simon Scannell

## 1.0.0

ClamAV 1.0.0 includes the following improvements and changes.

### Major changes

- Support for decrypting read-only OLE2-based XLS files that are encrypted with
  the default password.
  Use of the default password will now appear in the metadata JSON.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/700)

- Overhauled the implementation of the all-match feature. The newer code is more
  reliable and easier to maintain.
  - This project fixed several known issues with signature detection in all-
    match mode:
    - Enabled embedded file-type recognition signatures to match when a malware
      signature also matched in a scan of the same layer.
    - Enabled bytecode signatures to run in all-match mode after a match has
      occurred.
    - Fixed an assortment of all-match edge case issues.
  - Added multiple test cases to verify correct all-match behavior.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/687)

- Added a new callback to the public API for inspecting file content during a
  scan at each layer of archive extraction.
  - The new callback function type is `clcb_file_inspection` defined in
    `clamav.h`.
  - The function `cl_engine_set_clcb_file_inspection()` may be used to enable
    the callback prior to performing a scan.
  - This new callback is to be considered *unstable* for the 1.0 release.
    We may alter this function in a subsequent feature version.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/170)

- Added a new function to the public API for unpacking CVD signature archives.
  - The new function is `cl_cvdunpack()`. The last parameter for the function
    may be set to verify if a CVD's signature is valid before unpacking the CVD
    content to the destination directory.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/690)

- The option to build with an external TomsFastMath library has been removed.
  ClamAV requires non-default build options for TomsFastMath to support bigger
  floating point numbers. Without this change, database and Windows EXE/DLL
  authenticode certificate validation may fail.
  The `ENABLE_EXTERNAL_TOMSFASTMATH` build is now ignored.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/742)

- Moved the Dockerfile and supporting scripts from the main ClamAV repository
  over to a new repository: https://github.com/Cisco-Talos/clamav-docker

  The separate repository will make it easier to update the images and fix
  issues with images for released ClamAV versions.

  Any users building the ClamAV Docker image rather than pulling them from
  Docker Hub will have to get the latest Docker files from the new location.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/764)

- Increased the SONAME major version for libclamav because of ABI changes
  between the 0.103 LTS release and the 1.0 LTS release.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/778)

### Other improvements

- Add checks to limit PDF object extraction recursion.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/629)

- Increased the limit for memory allocations based on untrusted input and
  altered the warning message when the limit is exceeded so that it is more
  helpful and less dramatic.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/723)

- Dramatically improved the build time of libclamav-Rust unit tests.
  The unit test build is included in the time limit for the test itself and was
  timing out on slower systems. The ClamAV Rust code modules now share the same
  build directory, which also reduces the amount of disk space used for the
  build.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/694)

- For Windows: The debugging symbol (PDB) files are now installed alongside the
  DLL and LIB library files when built in "RelWithDebInfo" or "Debug" mode.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/669)

- Relaxed the constraints on the check for overlapping ZIP file entries so as
  not to alert on slightly malformed, but non-malicious, Java (JAR) archives.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/561)

- Increased the time limit in FreshClam before warning if the DNS entry is
  stale. In combination with changes to update the DNS entry more
  frequently, this should prevent false alarms of failures in the database
  publication system.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/597)

- Docker: The C library header files are now included in the Docker image.
  Patch courtesy of GitHub user TerminalFi.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/693)

- Show the BYTECODE_RUNTIME build options when using the `ccmake` GUI for CMake.
  Patch courtesy of Дилян Палаузов.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/678)

- Added explicit minimum and maximum supported LLVM versions so that the build
  will fail if you try to build with a version that is too old or too new and
  will print a helpful message rather than simply failing to compile because of
  compatibility issues. Patch courtesy of Matt Jolly.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/692)

- Moved the ClamAV Docker files for building containers to a new Git repository.
  The Docker files are now in: https://github.com/Cisco-Talos/clamav-docker

  This change enables us to fix issues with the images and with the supporting
  scripts used to publish and update the images without committing changes
  directly to files in the ClamAV release branches.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/764)

- Fixed compiler warnings that may turn into errors in Clang 16.
  Patch courtesy of Michael Orlitzky.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/767)

- Allow building with a custom RPATH so that the executables may be moved after
  build in a development environment to a final installation directory.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/768)

### Bug fixes

- Assorted code quality fixes. These are not security issues and will not be
  backported to prior feature versions:
  - Several heap buffer overflows while loading PDB and WDB databases were found
    by OSS-Fuzz and by Michał Dardas.

    [GitHub pull request #1](https://github.com/Cisco-Talos/clamav/pull/530)

    [GitHub pull request #2](https://github.com/Cisco-Talos/clamav/pull/712)

  - oss-fuzz 43843: heap buffer overflow read (1) cli_sigopts_handler

    [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/560)

  - oss-fuzz 44849: heap buffer overflow read (4) in HTML/js-norm

    [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/503)

  - oss-fuzz 43816: heap buffer overflow read (8) in cli_bcomp_freemeta

    [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/583)

  - oss-fuzz 43832: heap buffer overflow read (2) in cli_parse_add

    [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/611)

  - oss-fuzz 44493: integer overflow in cli_scannulsft

    [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/554)

  - CIFuzz leak detected in IDB parser

    [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/547)

  - oss-fuzz assorted signature parser leaks

    [GitHub pull request #1](https://github.com/Cisco-Talos/clamav/pull/532)

    [GitHub pull request #2](https://github.com/Cisco-Talos/clamav/pull/533)

    [GitHub pull request #3](https://github.com/Cisco-Talos/clamav/pull/535)

  - oss-fuzz 40601: leak detected in pdf_parseobj

    [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/553)

- Fixed a build failure when using LIBCLAMAV_ONLY mode with tests enabled.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/714)

- Fixed an issue verifying EXE/DLL authenticode signatures to determine a given
  file can be trusted (skipped).

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/727)

- Fixed a caching bug relating to the Container and Intermediates logical
  signature condition.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/724)

- Fixed a build issue when build with RAR disabled or when building with an
  external libmspack library rather than the bundled library.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/672)

- Fixed the capitalization of the `-W` option for `clamonacc` in the `clamonacc`
  manpage. Patch courtesy of GitHub user monkz.

  [GitHub pull request #1](https://github.com/Cisco-Talos/clamav/pull/709)

  [GitHub pull request #2](https://github.com/Cisco-Talos/clamav/pull/710)

- macOS: Fixed an issue with memory-map (`mmap`) system call detection affecting
  versions 0.105 and 0.104. Memory maps may be used in ClamAV to improve
  signature load performance and scan performance, as well as RAM usage.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/705)

- Fixed a performance issue with Rust code when the build type is not explicitly
  set to "Release" or "RelWithDebInfo". The Rust default build type is now
  "RelWithDebInfo" just like the C code, instead of Debug.
  This means it is now optimized by default.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/701)

- Fixed an issue loading Yara rules containing regex strings with an escaped
  forward-slash (`\/`) followed by a colon (`:`).

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/696)

- Fixed an issue detecting and scanning ZIP file entries appended to very small
  files. The fix is part of the all-match feature overhaul.

- Fixed a detection issue with EXE/DLL import-address-table hash signatures that
  specify a wildcard (`*`) for the size field. The fix is part of the all-match
  feature overhaul.

- Fixed the default bytecode timeout value listed in the manpages and in the
  sample config files. Patches courtesy of Liam Jarvis and Ben Bodenmiller.

  [GitHub pull request #1](https://github.com/Cisco-Talos/clamav/pull/631)

  [GitHub pull request #2](https://github.com/Cisco-Talos/clamav/pull/661)

- Fixed an issue building the libclamav_rust test program when running `ctest`
  if building with `BYTECODE_RUNTIME=llvm` and when the `FindLLVM.cmake` module
  is used to find the LLVM libraries. Patch courtesy of GitHub user teoberi.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/572)

- Fixed an issue where scans sent to `clamd` with the all-match mode enabled
  caused all subsequent scans to also use all-match mode.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/741)

- Fixed bug when starting `clamonacc` with the `--log=FILE` option that created
  randomly named files in the current directory.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/751)

- Other assorted bug fixes.

### Acknowledgments

Special thanks to the following people for code contributions and bug reports:
- Anthony Chan
- Ben Bodenmiller
- Дилян Палаузов
- Liam Jarvis
- Matt Jolly
- Michael Orlitzky
- monkz
- teoberi
- TerminalFi

## 0.105.2

ClamAV 0.105.2 is a critical patch release with the following fixes:

- [CVE-2023-20032](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-20032):
  Fixed a possible remote code execution vulnerability in the HFS+ file parser.
  Issue affects versions 1.0.0 and earlier, 0.105.1 and earlier, and 0.103.7 and
  earlier.
  Thank you to Simon Scannell for reporting this issue.

- [CVE-2023-20052](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-20052):
  Fixed a possible remote information leak vulnerability in the DMG file parser.
  Issue affects versions 1.0.0 and earlier, 0.105.1 and earlier, and 0.103.7 and
  earlier.
  Thank you to Simon Scannell for reporting this issue.

- Fixed an issue loading Yara rules containing regex strings with an escaped
  forward-slash (`\/`) followed by a colon (`:`).

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/695)

- Moved the ClamAV Docker files for building containers to a new Git repository.
  The Docker files are now in: https://github.com/Cisco-Talos/clamav-docker

  This change enables us to fix issues with the images and with the supporting
  scripts used to publish and update the images without committing changes
  directly to files in the ClamAV release branches.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/765)

- Update vendored libmspack library to version 0.11alpha.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/829)

Special thanks to the following people for code contributions and bug reports:
- Simon Scannell

## 0.105.1

ClamAV 0.105.1 is a critical patch release with the following fixes:

- Upgrade the vendored UnRAR library to version 6.1.7.

- Fix issue building macOS universal binaries in some configurations.

- Silence error message when the logical signature maximum functionality level
  is lower than the current functionality level.

- Fix scan error when scanning files containing malformed images that cannot be
  loaded to calculate an image fuzzy hash.

- Fix logical signature "Intermediates" feature.

- Relax constraints on slightly malformed zip archives that contain overlapping
  file entries.

## 0.105.0

ClamAV 0.105.0 includes the following improvements and changes.

### New Requirements

- Starting with ClamAV v0.105, the Rust toolchain is required to compile ClamAV.

  You can install the Rust toolchain for your development environment by
  following the instructions on the [`rustup`](https://rustup.rs/) website.
  Some binary package distributions do provide relatively up-to-date packages of
  the Rust toolchain, but many do not. Using `rustup` ensures that you have the
  most up-to-date Rust compiler at the time of installation. Keep your toolchain
  updated for new features and bug/security fixes by periodically executing:
  ```sh
  rustup update
  ```

  Building ClamAV requires, at a minimum, Rust compiler version 1.61, as it
  relies on features introduced in the Rust 2021 Edition.

  ClamAV's third-party Rust library dependencies are vendored into the release
  tarball (`clamav-<version>.tar.gz`) file that we publish on
  [clamav.net/downloads](https://www.clamav.net/downloads).
  But, if you build from a Git clone or from an unofficial tarball taken from
  GitHub.com, you will need the internet to download the Rust libraries during
  the build.

### Major changes

- Increased the default limits for file-size and scan-size:
  - MaxScanSize:        100M -> 400M
  - MaxFileSize:        25M  -> 100M
  - StreamMaxLength:    25M  -> 100M
  - PCREMaxFileSize:    25M  -> 100M
  - MaxEmbeddedPE:      10M  -> 40M
  - MaxHTMLNormalize:   10M  -> 40M
  - MaxScriptNormalize: 5M   -> 20M
  - MaxHTMLNoTags:      2M   -> 8M

- Added image fuzzy hash subsignatures for logical signatures.

  Image fuzzy hash subsignatures are a new feature for detecting images known to
  be used in phishing campaigns or otherwise used when distributing malware.

  Image fuzzy hash subsignatures follow this format:
  ```
  fuzzy_img#<hash>
  ```
  For example:
  ```
  logo.png;Engine:150-255,Target:0;0;fuzzy_img#af2ad01ed42993c7
  logo.png-2;Engine:150-255,Target:0;0&1;49484452;fuzzy_img#af2ad01ed42993c7
  ```

  This initial implementation does not support matching with a hamming distance.
  Support for matching with a hamming distance may be added in a future release.

  ClamAV's image fuzzy hash is very close to, but not 100% identical to, the
  fuzzy hash generated by the Python `imagehash` package's `phash()` function.
  Note that these are only clean-room approximations of the pHash™️ algorithm.
  ClamAV's image fuzzy hashes are not expected to match the fuzzy hashes
  generated using other tools. Some images may match, while others do not.

  To generate the image fuzzy hash you can run this command:
  ```
  sigtool --fuzzy-img FILE(S)
  ```
  Or you may generate it through `clamscan` like this:
  ```
  clamscan --gen-json --debug /path/to/file
  ```
  The hash will appear in the JSON above the "SCAN SUMMARY" under the object
  named "ImageFuzzyHash".

- ClamScan & ClamDScan (Windows-only):
  - Added a process memory scanning feature from ClamWin's ClamScan.

    This adds three new options to ClamScan and ClamDScan on Windows:
    * `--memory`
    * `--kill`
    * `--unload`

    Special thanks to:
    - Gianluigi Tiesi for allowing us to integrate the Windows process memory
      scanning feature from ClamWin into the ClamAV.
    - Grace Kang for integrating the ClamScan feature, and for extending it to
      work with ClamDScan in addition.

### Notable changes

- Updated the LLVM bytecode runtime support so that it can use LLVM versions
  8 through 12 and removed support for earlier LLVM versions.
  Using LLVM JIT for the bytecode runtime may improve scan performance over the
  built-in bytecode interpreter runtime, which is the default.
  If you wish to build using LLVM, you must obtain a complete build of
  the LLVM libraries including the development headers and static libraries.

  There are some known issues both compiling and running the test suite with
  some LLVM installations. We are working to further stabilize LLVM bytecode
  runtime support, and document specific edge cases. Your feedback is welcome.

  For details about building ClamAV with the LLVM bytecode runtime, see the
  [install reference documentation](INSTALL.md#bytecode-runtime).

- Added a `GenerateMetadataJson` option to ClamD.
  The functionality is equivalent to the `clamscan --gen-json` option.
  Scan metadata is useful for file analysis and for debugging scan behavior.
  If `Debug` is enabled, ClamD will print out the JSON after each scan.
  If `LeaveTemporaryFiles` is enabled, ClamD will drop a `metadata.json` file
  in the scan-temp directory. You can customize the scan-temp directory path
  using the `TemporaryDirectory` option.

- The `libclamunrar.so` library's SO version now matches that of `libclamav.so`.
  The upstream UnRAR library does not have an SO version that we should match.
  This change is to prevent a possible collision when multiple ClamAV versions
  are installed.

- CMake: Added support for using an external TomsFastMath library (libtfm).

  To use an external TomsFastMath library, configure the build with the new
  option `-D ENABLE_EXTERNAL_TOMSFASTMATH=ON`. The following CMake variables may
  also be set as needed:
  - `-D TomsFastMath_INCLUDE_DIR=<path>` - The directory containing `tfm.h`.
  - `-D TomsFastMath_LIBRARY=<path>` - The path to the TomsFastMath library.

  Also updated the vendored TomsFastMath code to version 0.13.1.

### Other improvements

- Freshclam:
  - Improve `ReceiveTimeout` behavior so that will abort a download attempt if
    the download is not making significant progress. Previously this limit was
    an absolute time limit for the download and could abort prematurely for
    those on a slower connection.
    Special thanks to Simon Arlott for this improvement.

- Rewrote the ClamAV database archive incremental-update feature (CDIFF) from
  scratch in Rust. The new implementation was our first module to be rewritten
  in Rust. It is significantly faster at applying updates that remove large
  numbers of signatures from a database, such as when migrating signatures from
  `daily.cvd` to `main.cvd`.

- Freshclam & ClamD:
  - Increased the maximum line-length for `freshclam.conf` and `clamd.conf` from
    512-characters to 1024-characters. This change was by request to accommodate
    very long `DatabaseMirror` options when using access tokens in the URI.

- Removed the Heuristics.PNG.CVE-2010-1205 detection. This alert had been placed
  behind the `--alert-broken-media` (`SCAN_HEURISTIC_BROKEN_MEDIA`) option in
  0.103.3 and 0.104 because of excessive alerts on slightly malformed but non-
  malicious files. Now it is completely removed.

- Added support for building ClamDTop using ncursesw if ncurses can not be
  found. Patch courtesy of Carlos Velasco.

### Bug fixes

The CVE's fixes below are also addressed in versions 0.104.3 and 0.103.6.

- [CVE-2022-20803](CVE-2022-20803): Fixed a possible double-free vulnerability
  in the OLE2 file parser.
  Issue affects versions 0.104.0 through 0.104.2.
  Issue identified by OSS-Fuzz.

- [CVE-2022-20770](CVE-2022-20770): Fixed a possible infinite loop vulnerability
  in the CHM file parser.
  Issue affects versions 0.104.0 through 0.104.2 and LTS version 0.103.5 and
  prior versions.
  Thank you to Michał Dardas for reporting this issue.

- [CVE-2022-20796](CVE-2022-20796): Fixed a possible NULL-pointer dereference
  crash in the scan verdict cache check.
  Issue affects versions 0.103.4, 0.103.5, 0.104.1, and 0.104.2.
  Thank you to Alexander Patrakov and Antoine Gatineau for reporting this issue.

- [CVE-2022-20771](CVE-2022-20771): Fixed a possible infinite loop vulnerability
  in the TIFF file parser.
  Issue affects versions 0.104.0 through 0.104.2 and LTS version 0.103.5 and
  prior versions.
  The issue only occurs if the "--alert-broken-media" ClamScan option is
  enabled. For ClamD, the affected option is "AlertBrokenMedia yes", and for
  libclamav it is the "CL_SCAN_HEURISTIC_BROKEN_MEDIA" scan option.
  Thank you to Michał Dardas for reporting this issue.

- [CVE-2022-20785](CVE-2022-20785): Fixed a possible memory leak in the
  HTML file parser / Javascript normalizer.
  Issue affects versions 0.104.0 through 0.104.2 and LTS version 0.103.5 and
  prior versions.
  Thank you to Michał Dardas for reporting this issue.

- [CVE-2022-20792](CVE-2022-20792): Fixed a possible multi-byte heap buffer
  overflow write vulnerability in the signature database load module.
  The fix was to update the vendored regex library to the latest version.
  Issue affects versions 0.104.0 through 0.104.2 and LTS version 0.103.5 and
  prior versions.
  Thank you to Michał Dardas for reporting this issue.

- ClamOnAcc: Fixed a number of assorted stability issues and added niceties for
  debugging ClamOnAcc. Patches courtesy of Frank Fegert.

- Fixed an issue causing byte-compare subsignatures to cause an alert when they
  match even if other conditions of the given logical signatures were not met.

- Fixed an issue causing XLM macro false positives when scanning XLS documents
  containing images if the `--alert-macros` (`AlertOLE2Macros`) option was
  enabled.

- Fixed an issue causing signature alerts for images in XLS files to be lost.

- Fixed an issue preventing multiple matches when scanning in all-match mode.

- Docker:
  - Fixed an issue exposing the health check port. Patch courtesy of Sammy Chu.
  - Fixed an issue with health check failure false positives during container
    startup. Patch courtesy of Olliver Schinagl.
  - Set the default time zone to `Etc/UTC`. The `--env` parameter can be used to
    customize the time zone by setting `TZ` environment variable.
    Patch courtesy of Olliver Schinagl.
  - Fixed an issue where ClamD would listen only for IPv4 connections in
    environments where IPv6 is preferred. ClamD will now listen to all
    addresses available (IPv4 and IPv6). This is the default behavior of ClamD.
    Patch courtesy of Andre Breiler.

- Enable support for ncursesw, the wide-character / unicode version of ncurses.

- Added support for detecting the curses library dependency even when the
  associated pkg-config file is not present. This resolves a build issue on some
  BSD distributions. Patch courtesy of Stuart Henderson.

- Windows: Fix utf8 filepath issues affecting both scanning and log messages.

- Assorted bug fixes and improvements.

### Acknowledgments

Special thanks to the following people for code contributions and bug reports:
- Ahmon Dancy
- Alexander Patrakov
- Alexander Sulfrian
- Andre Breiler
- Antoine Gatineau
- Carlos Velasco
- Bernd Kuhls
- David Korczynski
- Fabrice Fontaine
- Frank Fegert
- Gianluigi Tiesi
- Giovanni Bechis
- Grace Kang
- John Humlick
- Jordan Ernst
- JunWei Song
- Michał Dardas
- mko-x
- Olliver Schinagl
- Răzvan Cojocaru
- Sammy Chu
- Sergey Valentey
- Simon Arlott
- Stuart Henderson
- Yann E. Morin

## 0.104.4

ClamAV 0.104.4 is a critical patch release with the following fixes:

- Upgrade the vendored UnRAR library to version 6.1.7.

- Fix logical signature "Intermediates" feature.

- Relax constraints on slightly malformed zip archives that contain overlapping
  file entries.

## 0.104.3

ClamAV 0.104.3 is a critical patch release with the following fixes:

- [CVE-2022-20803](CVE-2022-20803): Fixed a possible double-free vulnerability
  in the OLE2 file parser.
  Issue affects versions 0.104.0 through 0.104.2.
  Issue identified by OSS-Fuzz.

- [CVE-2022-20770](CVE-2022-20770): Fixed a possible infinite loop vulnerability
  in the CHM file parser.
  Issue affects versions 0.104.0 through 0.104.2 and LTS version 0.103.5 and
  prior versions.
  Thank you to Michał Dardas for reporting this issue.

- [CVE-2022-20796](CVE-2022-20796): Fixed a possible NULL-pointer dereference
  crash in the scan verdict cache check.
  Issue affects versions 0.103.4, 0.103.5, 0.104.1, and 0.104.2.
  Thank you to Alexander Patrakov and Antoine Gatineau for reporting this issue.

- [CVE-2022-20771](CVE-2022-20771): Fixed a possible infinite loop vulnerability
  in the TIFF file parser.
  Issue affects versions 0.104.0 through 0.104.2 and LTS version 0.103.5 and
  prior versions.
  The issue only occurs if the "--alert-broken-media" ClamScan option is
  enabled. For ClamD, the affected option is "AlertBrokenMedia yes", and for
  libclamav it is the "CL_SCAN_HEURISTIC_BROKEN_MEDIA" scan option.
  Thank you to Michał Dardas for reporting this issue.

- [CVE-2022-20785](CVE-2022-20785): Fixed a possible memory leak in the
  HTML file parser / Javascript normalizer.
  Issue affects versions 0.104.0 through 0.104.2 and LTS version 0.103.5 and
  prior versions.
  Thank you to Michał Dardas for reporting this issue.

- [CVE-2022-20792](CVE-2022-20792): Fixed a possible multi-byte heap buffer
  overflow write vulnerability in the signature database load module.
  The fix was to update the vendored regex library to the latest version.
  Issue affects versions 0.104.0 through 0.104.2 and LTS version 0.103.5 and
  prior versions.
  Thank you to Michał Dardas for reporting this issue.

- ClamOnAcc: Fixed a number of assorted stability issues and added niceties for
  debugging ClamOnAcc. Patches courtesy of Frank Fegert.

- Enable support for ncursesw, the wide-character / unicode version of ncurses.

- Added support for detecting the curses library dependency even when the
  associated pkg-config file is not present. This resolves a build issue on some
  BSD distributions. Patch courtesy of Stuart Henderson.

- Docker:
  - Fixed an issue exposing the health check port. Patch courtesy of Sammy Chu.
  - Fixed an issue with health check failure false positives during container
    startup. Patch courtesy of Olliver Schinagl.
  - Set the default time zone to `Etc/UTC`. The `--env` parameter can be used to
    customize the time zone by setting `TZ` environment variable.
    Patch courtesy of Olliver Schinagl.

- Fixed an issue causing XLM macro false positives when scanning XLS documents
  containing images if the `--alert-macros` (`AlertOLE2Macros`) option was
  enabled.

- Fixed an issue causing signature alerts for images in XLS files to be lost.

- Fixed an issue causing byte-compare subsignatures to cause an alert when they
  match even if other conditions of the given logical signatures were not met.

- Assorted bug fixes and improvements.

Special thanks to the following people for code contributions and bug reports:
- Alexander Patrakov
- Antoine Gatineau
- Frank Fegert
- Michał Dardas
- Olliver Schinagl
- Sammy Chu
- Stuart Henderson

## 0.104.2

ClamAV 0.104.2 is a critical patch release with the following fixes:

- [CVE-2022-20698](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-20698):
  Fix for invalid pointer read that may cause a crash.
  Affects 0.104.1, 0.103.4 and prior when ClamAV is compiled with libjson-c and
  the `CL_SCAN_GENERAL_COLLECT_METADATA` scan option (the `clamscan --gen-json`
  option) is enabled.

  Cisco would like to thank Laurent Delosieres of ManoMano for reporting this
  vulnerability.

- Fixed ability to disable the file size limit with libclamav C API, like this:
  ```c
    cl_engine_set_num(engine, CL_ENGINE_MAX_FILESIZE, 0);
  ```
  This issue didn't impact ClamD or ClamScan which also can disable the limit by
  setting it to zero using `MaxFileSize 0` in `clamd.conf` for ClamD, or
  `clamscan --max-filesize=0` for ClamScan.

  Note: Internally, the max file size is still set to 2 GiB. Disabling the limit
  for a scan will fall back on the internal 2 GiB limitation.

- Increased the maximum line length for ClamAV config files from 512 bytes to
  1024 bytes to allow for longer config option strings.

Special thanks to the following for code contributions and bug reports:
- Laurent Delosieres

## 0.104.1

ClamAV 0.104.1 is a critical patch release with the following fixes:

- FreshClam:
  - Add a 24-hour cool-down for FreshClam clients that have received an HTTP
    403 (Forbidden) response from the CDN.
    This is to reduce the volume of 403-response data served to blocked
    FreshClam clients that are configured with a tight update-loop.
  - Fixed a bug where FreshClam treats an empty CDIFF as an incremental update
    failure instead of as an intentional request to download the whole CVD.

- ClamDScan: Fix a scan error when broken symlinks are encountered on macOS with
  "FollowDirectorySymlinks" and "FollowFileSymlinks" options disabled.

- Overhauled the scan recursion / nested archive extraction logic and added new
  limits on embedded file-type recognition performed during the "raw" scan of
  each file. This limits embedded file-type misidentification and prevents
  detecting embedded file content that is found/extracted and scanned at other
  layers in the scanning process.

- Fix an issue with the FMap module that failed to read from some nested files.

- Fixed an issue where failing to load some rules from a Yara file containing
  multiple rules may cause a crash.

- Fixed assorted compiler warnings.

- Fixed assorted Coverity static code analysis issues.

- Scan limits:
  - Added virus-name suffixes to the alerts that trigger when a scan limit has
    been exceeded. Rather than simply `Heuristics.Limits.Exceeded`, you may now
    see limit-specific virus-names, to include:
    - `Heuristics.Limits.Exceeded.MaxFileSize`
    - `Heuristics.Limits.Exceeded.MaxScanSize`
    - `Heuristics.Limits.Exceeded.MaxFiles`
    - `Heuristics.Limits.Exceeded.MaxRecursion`
    - `Heuristics.Limits.Exceeded.MaxScanTime`
  - Renamed the `Heuristics.Email.ExceedsMax.*` alerts to align with the other
    limit alerts names. These alerts include:
    - `Heuristics.Limits.Exceeded.EmailLineFoldcnt`
    - `Heuristics.Limits.Exceeded.EmailHeaderBytes`
    - `Heuristics.Limits.Exceeded.EmailHeaders`
    - `Heuristics.Limits.Exceeded.EmailMIMEPartsPerMessage`
    - `Heuristics.Limits.Exceeded.EmailMIMEArguments`
  - Fixed an issue where the Email-related scan limits would alert even when the
    "AlertExceedsMax" (`--alert-exceeds-max`) scan option is not enabled.
  - Fixes an issue in the Zip parser where exceeding the "MaxFiles" limit or
    the "MaxFileSize" limit would abort the scan but would fail to alert.
    The Zip scan limit issues were independently identified and reported by
    Aaron Leliaert and Max Allan.

- Fixed a leak in the Email parser when using the `--gen-json` scan option.

- Fixed an issue where a failure to record metadata in the Email parser when
  using the `--gen-json` scan option could cause the Email parser to abort the
  scan early and fail to extract and scan additional content.

- Fixed a file name memory leak in the Zip parser.

- Fixed an issue where certain signature patterns may cause a crash or cause
  unintended matches on some systems when converting characters to uppercase if
  a UTF-8 unicode single-byte grapheme becomes a multi-byte grapheme.
  Patch courtesy of Andrea De Pasquale.

- CMake:
  - Fix a packaging issue with the Windows `*.msi` installer so that it will
    include all of the required files.
  - Add support for developer code-signing on macOS during the build.
  - Fix an issue finding and linking with the `tinfo` library on systems where
    `tinfo` is separate from `ncurses`. Patch courtesy of Luca Barbato.

- Tests: Improved the Freshclam incremental update tests to verify correct
  behavior when a zero-byte CDIFF is downloaded and the CVD served to FreshClam
  is older than advertised.

- Docker: Remove the `freshclam.dat` file when building the Docker image with
  the databases-included so FreshClam agents running in the container will have
  a unique ID in the HTTP User-Agent.

Special thanks to the following for code contributions and bug reports:
- Aaron Leliaert
- Andrea De Pasquale
- Luca Barbato
- Max Allan

## 0.104.0

ClamAV 0.104.0 includes the following improvements and changes.

### New Requirements

- As of ClamAV 0.104, CMake is required to build ClamAV.

  We have added comprehensive build instructions for using CMake to the new
  [`INSTALL.md`](INSTALL.md) file. The online documentation will also be
  updated to include CMake build instructions.

  The Autotools and the Visual Studio build systems have been removed.

### Major changes

- The built-in LLVM for the bytecode runtime has been removed.

  The bytecode interpreter is the default runtime for bytecode signatures just
  as it was in ClamAV 0.103.

  We wished to add support for newer versions of LLVM but ran out of time.
  If you're building ClamAV from source and you wish to use LLVM instead of the
  bytecode interpreter, you will need to supply the development libraries for
  LLVM version 3.6.2.
  See [the "bytecode runtime" section in `INSTALL.md`](INSTALL.md#bytecode-runtime)
  to learn more.

- There are now official ClamAV images on Docker Hub.

  > _Note_: Until ClamAV 0.104.0 is released, these images are limited to
  > "unstable" versions, which are updated daily with the latest changes in the
  > default branch on GitHub.

  You can find the images on [Docker Hub under `clamav`](https://hub.docker.com/r/clamav/clamav).

  Docker Hub ClamAV tags:

  - `clamav/clamav:<version>`: A release preloaded with signature databases.

    Using this container will save the ClamAV project some bandwidth.
    Use this if you will keep the image around so that you don't download the
    entire database set every time you start a new container. Updating with
    FreshClam from existing databases set does not use much data.

  - `clamav/clamav:<version>_base`: A release with no signature databases.

    Use this container **only** if you mount a volume in your container under
    `/var/lib/clamav` to persist your signature database databases.
    This method is the best option because it will reduce data costs for ClamAV
    and for the Docker registry, but it does require advanced familiarity with
    Linux and Docker.

    > _Caution_: Using this image without mounting an existing database
    directory will cause FreshClam to download the entire database set each
    time you start a new container.

  You can use the `unstable` version (i.e. `clamav/clamav:unstable` or
  `clamav/clamav:unstable_base`) to try the latest from our development branch.

  Please, be kind when using 'free' bandwidth, both for the virus databases
  but also the Docker registry. Try not to download the entire database set or
  the larger ClamAV database images on a regular basis.

  For more details, see
  [the ClamAV Docker documentation](https://docs.clamav.net/manual/Installing/Docker.html).

  Special thanks to Olliver Schinagl for his excellent work creating ClamAV's
  new Docker files, image database deployment tooling, and user documentation.

- `clamd` and `freshclam` are now available as Windows services. To install
  and run them, use the `--install-service` option and `net start [name]` command.

  Special thanks to Gianluigi Tiesi for his original work on this feature.

### Notable changes

The following was added in 0.103.1 and is repeated here for awareness, as
patch versions do not generally introduce new options:

- Added a new scan option to alert on broken media (graphics) file formats.
  This feature mitigates the risk of malformed media files intended to exploit
  vulnerabilities in other software.
  At present media validation exists for JPEG, TIFF, PNG, and GIF files.
  To enable this feature, set `AlertBrokenMedia yes` in clamd.conf, or use
  the `--alert-broken-media` option when using `clamscan`.
  These options are disabled by default in this patch release, but may be
  enabled in a subsequent release.
  Application developers may enable this scan option by enabling
  `CL_SCAN_HEURISTIC_BROKEN_MEDIA` for the `heuristic` scan option bit field.

- Added CL_TYPE_TIFF, CL_TYPE_JPEG types to match GIF, PNG typing behavior.
  BMP and JPEG 2000 files will continue to detect as CL_TYPE_GRAPHICS because
  ClamAV does not yet have BMP or JPEG 2000 format checking capabilities.

- Added progress callbacks to libclamav for:
  - database load:  `cl_engine_set_clcb_sigload_progress()`
  - engine compile: `cl_engine_set_clcb_engine_compile_progress()`
  - engine free:    `cl_engine_set_clcb_engine_free_progress()`

  These new callbacks enable an application to monitor and estimate load,
  compile, and unload progress. See `clamav.h` for API details.

- Added progress bars to ClamScan for the signature load and engine compile
  steps before a scan begins.
  The start-up progress bars won't be enabled if ClamScan isn't running in a
  terminal (i.e. stdout is not a TTY), or if any of these options are used:
    - `--debug`
    - `--quiet`
    - `--infected`
    - `--no-summary`

### Other improvements

- Added the `%f` format string option to the ClamD VirusEvent feature to insert
  the file path of the scan target when a virus-event occurs. This supplements
  the VirusEvent `%v` option which prints the signature (virus) name.
  The ClamD VirusEvent feature also provides two environment variables,
  `$CLAM_VIRUSEVENT_FILENAME` and `$CLAM_VIRUSEVENT_VIRUSNAME` for a similar
  effect.
  Patch courtesy of Vasile Papp.

- Improvements to the AutoIt extraction module. Patch courtesy of cw2k.

- Added support for extracting images from Excel *.xls (OLE2) documents.

- Trusted SHA256-based Authenticode hashes can now be loaded in from *.cat
  files. For more information, visit our
  [Authenticode documentation](https://docs.clamav.net/appendix/Authenticode.html)
  about using *.cat files with *.crb rules to trust signed Windows executables.

### Bug fixes

- Fixed a memory leak affecting logical signatures that use the "byte compare"
  feature. Patch courtesy of Andrea De Pasquale.

- Fixed bytecode match evaluation for PDF bytecode hooks in PDF file scans.

- Other minor bug fixes.

### Acknowledgments

The ClamAV team thanks the following individuals for their code submissions:

- Alexander Golovach
- Andrea De Pasquale
- Andrew Williams
- Arjen de Korte
- Armin Kuster
- Brian Bergstrand
- cw2k
- Duane Waddle
- Gianluigi Tiesi
- Jonas Zaddach
- Kenneth Hau
- Mark Fortescue
- Markus Strehle
- Olliver Schinagl
- Orion Poplawski
- Sergey Valentey
- Sven Rueß
- Tom Briden
- Vasile Papp
- Yasuhiro Kimura

## 0.103.11

ClamAV 0.103.11 is a patch release with the following fixes:

- Upgrade the bundled UnRAR library (libclamunrar) to version 6.2.12.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1053)

- Windows: libjson-c 0.17 compatibility fix. with ssize_t type definition.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1065)

- Windows: Update build system to use OpenSSL 3 and PThreads-Win32 v3.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1057)

## 0.103.10

ClamAV 0.103.10 is a critical patch release with the following fixes:

- Upgrade the bundled UnRAR library (libclamunrar) to version 6.2.10.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/1009)

## 0.103.9

ClamAV 0.103.9 is a critical patch release with the following fixes:

- [CVE-2023-20197](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-20197)
  Fixed a possible denial of service vulnerability in the HFS+ file parser.
  This issue affects versions 1.1.0, 1.0.1 through 1.0.0, 0.105.2 through 0.105.0,
  0.104.4 through 0.104.0, and 0.103.8 through 0.103.0.
  Thank you to Steve Smith for reporting this issue.

- Fixed compiler warnings that may turn into errors in Clang 16.
  Patch courtesy of Michael Orlitzky.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/747)

Special thanks to the following people for code contributions and bug reports:
- Michael Orlitzky
- Steve Smith

## 0.103.8

ClamAV 0.103.8 is a critical patch release with the following fixes:

- [CVE-2023-20032](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-20032):
  Fixed a possible remote code execution vulnerability in the HFS+ file parser.
  Issue affects versions 1.0.0 and earlier, 0.105.1 and earlier, and 0.103.7 and
  earlier.
  Thank you to Simon Scannell for reporting this issue.

- [CVE-2023-20052](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-20052):
  Fixed a possible remote information leak vulnerability in the DMG file parser.
  Issue affects versions 1.0.0 and earlier, 0.105.1 and earlier, and 0.103.7 and
  earlier.
  Thank you to Simon Scannell for reporting this issue.

- Update vendored libmspack library to version 0.11alpha.

  [GitHub pull request](https://github.com/Cisco-Talos/clamav/pull/830)

Special thanks to the following people for code contributions and bug reports:
- Simon Scannell

## 0.103.7

ClamAV 0.103.7 is a critical patch release with the following fixes:

- Upgrade the vendored UnRAR library to version 6.1.7.

- Fix logical signature "Intermediates" feature.

- Relax constraints on slightly malformed zip archives that contain overlapping
  file entries.

## 0.103.6

ClamAV 0.103.6 is a critical patch release with the following fixes:

- [CVE-2022-20770](CVE-2022-20770): Fixed a possible infinite loop vulnerability
  in the CHM file parser.
  Issue affects versions 0.104.0 through 0.104.2 and LTS version 0.103.5 and
  prior versions.
  Thank you to Michał Dardas for reporting this issue.

- [CVE-2022-20796](CVE-2022-20796): Fixed a possible NULL-pointer dereference
  crash in the scan verdict cache check.
  Issue affects versions 0.103.4, 0.103.5, 0.104.1, and 0.104.2.
  Thank you to Alexander Patrakov and Antoine Gatineau for reporting this issue.

- [CVE-2022-20771](CVE-2022-20771): Fixed a possible infinite loop vulnerability
  in the TIFF file parser.
  Issue affects versions 0.104.0 through 0.104.2 and LTS version 0.103.5 and
  prior versions.
  The issue only occurs if the "--alert-broken-media" ClamScan option is
  enabled. For ClamD, the affected option is "AlertBrokenMedia yes", and for
  libclamav it is the "CL_SCAN_HEURISTIC_BROKEN_MEDIA" scan option.
  Thank you to Michał Dardas for reporting this issue.

- [CVE-2022-20785](CVE-2022-20785): Fixed a possible memory leak in the
  HTML file parser / Javascript normalizer.
  Issue affects versions 0.104.0 through 0.104.2 and LTS version 0.103.5 and
  prior versions.
  Thank you to Michał Dardas for reporting this issue.

- [CVE-2022-20792](CVE-2022-20792): Fixed a possible multi-byte heap buffer
  overflow write vulnerability in the signature database load module.
  The fix was to update the vendored regex library to the latest version.
  Issue affects versions 0.104.0 through 0.104.2 and LTS version 0.103.5 and
  prior versions.
  Thank you to Michał Dardas for reporting this issue.

- ClamOnAcc: Fixed a number of assorted stability issues and added niceties for
  debugging ClamOnAcc. Patches courtesy of Frank Fegert.

- Fixed an issue causing byte-compare subsignatures to cause an alert when they
  match even if other conditions of the given logical signatures were not met.

- Fix memleak when using multiple byte-compare subsignatures.
  This fix was backported from 0.104.0.
  Thank you to Andrea De Pasquale for contributing the fix.

- Assorted bug fixes and improvements.

Special thanks to the following people for code contributions and bug reports:
- Alexander Patrakov
- Andrea De Pasquale
- Antoine Gatineau
- Frank Fegert
- Michał Dardas

## 0.103.5

ClamAV 0.103.5 is a critical patch release with the following fixes:

- [CVE-2022-20698](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-20698):
  Fix for invalid pointer read that may cause a crash.
  Affects 0.104.1, 0.103.4 and prior when ClamAV is compiled with libjson-c and
  the `CL_SCAN_GENERAL_COLLECT_METADATA` scan option (the `clamscan --gen-json`
  option) is enabled.

  Cisco would like to thank Laurent Delosieres of ManoMano for reporting this
  vulnerability.

- Fixed ability to disable the file size limit with libclamav C API, like this:
  ```c
    cl_engine_set_num(engine, CL_ENGINE_MAX_FILESIZE, 0);
  ```
  This issue didn't impact ClamD or ClamScan which also can disable the limit by
  setting it to zero using `MaxFileSize 0` in `clamd.conf` for ClamD, or
  `clamscan --max-filesize=0` for ClamScan.

  Note: Internally, the max file size is still set to 2 GiB. Disabling the limit
  for a scan will fall back on the internal 2 GiB limitation.

- Increased the maximum line length for ClamAV config files from 512 bytes to
  1024 bytes to allow for longer config option strings.

- SigTool: Fix insufficient buffer size for `--list-sigs` that caused a failure
  when listing a database containing one or more very long signatures.
  This fix was backported from 0.104.

Special thanks to the following for code contributions and bug reports:
- Laurent Delosieres

## 0.103.4

ClamAV 0.103.4 is a critical patch release with the following fixes:

- FreshClam:
  - Add a 24-hour cool-down for FreshClam clients that have received an HTTP
    403 (Forbidden) response from the CDN.
    This is to reduce the volume of 403-response data served to blocked
    FreshClam clients that are configured with a tight update-loop.
  - Fixed a bug where FreshClam treats an empty CDIFF as an incremental update
    failure instead of as an intentional request to download the whole CVD.

- ClamDScan: Fix a scan error when broken symlinks are encountered on macOS with
  "FollowDirectorySymlinks" and "FollowFileSymlinks" options disabled.

- Overhauled the scan recursion / nested archive extraction logic and added new
  limits on embedded file-type recognition performed during the "raw" scan of
  each file. This limits embedded file-type misidentification and prevents
  detecting embedded file content that is found/extracted and scanned at other
  layers in the scanning process.

- Fix an issue with the FMap module that failed to read from some nested files.

- Fixed an issue where failing to load some rules from a Yara file containing
  multiple rules may cause a crash.

- Fixed assorted compiler warnings.

- Fixed assorted Coverity static code analysis issues.

- Scan limits:
  - Added virus-name suffixes to the alerts that trigger when a scan limit has
    been exceeded. Rather than simply `Heuristics.Limits.Exceeded`, you may now
    see limit-specific virus-names, to include:
    - `Heuristics.Limits.Exceeded.MaxFileSize`
    - `Heuristics.Limits.Exceeded.MaxScanSize`
    - `Heuristics.Limits.Exceeded.MaxFiles`
    - `Heuristics.Limits.Exceeded.MaxRecursion`
    - `Heuristics.Limits.Exceeded.MaxScanTime`
  - Renamed the `Heuristics.Email.ExceedsMax.*` alerts to align with the other
    limit alerts names. These alerts include:
    - `Heuristics.Limits.Exceeded.EmailLineFoldcnt`
    - `Heuristics.Limits.Exceeded.EmailHeaderBytes`
    - `Heuristics.Limits.Exceeded.EmailHeaders`
    - `Heuristics.Limits.Exceeded.EmailMIMEPartsPerMessage`
    - `Heuristics.Limits.Exceeded.EmailMIMEArguments`
  - Fixed an issue where the Email-related scan limits would alert even when the
    "AlertExceedsMax" (`--alert-exceeds-max`) scan option is not enabled.
  - Fixes an issue in the Zip parser where exceeding the "MaxFiles" limit or
    the "MaxFileSize" limit would abort the scan but would fail to alert.
    The Zip scan limit issues were independently identified and reported by
    Aaron Leliaert and Max Allan.

- Fixed a leak in the Email parser when using the `--gen-json` scan option.

- Fixed an issue where a failure to record metadata in the Email parser when
  using the `--gen-json` scan option could cause the Email parser to abort the
  scan early and fail to extract and scan additional content.

- Fixed a file name memory leak in the Zip parser.

- Fixed an issue where certain signature patterns may cause a crash or cause
  unintended matches on some systems when converting characters to uppercase if
  a UTF-8 unicode single-byte grapheme becomes a multi-byte grapheme.
  Patch courtesy of Andrea De Pasquale.

Other fixes backported from 0.104.0:

- Fixed a crash in programs that use libclamav when the programs don't set a
  callback for the "virus found" event.
  Patch courtesy of Markus Strehle.

- Added checks to the SIS archive parser to prevent an SIS file entry from
  pointing to the archive, which would result in a loop. This was not an actual
  infinite loop, as ClamAV's scan recursion limit limits the depth of nested
  archive extraction.

- ClamOnAcc: Fixed a socket file descriptor leak that could result in a crash
  when all available file descriptors are exhausted.

- FreshClam: Fixed an issue where FreshClam would download a CVD repeatedly if a
  zero-byte CDIFF is downloaded or if the incremental update failed and if the
  CVD downloaded after that is older than advertised.
  Patch courtesy of Andrew Williams.

- ClamDScan:
  - Fixed a memory leak of the scan target filename when using the
    `--fdpass` or `--stream` options.
  - Fixed an issue where ClamDScan would fail to scan any file after excluding
    a file with the "ExcludePath" option when using when using the `--multiscan`
    (`-m`) option along with either `--fdpass` or `--stream`.
    Also fixed a memory leak of the accidentally-excluded paths in this case.
  - Fixed a single file path memory leak when using `--fdpass`.
  - Fixed an issue where the "ExcludePath" regex may fail to exclude absolute
    paths when the scan is invoked with a relative path.

Special thanks to the following for code contributions and bug reports:
- Aaron Leliaert
- Andrea De Pasquale
- Andrew Williams
- Markus Strehle
- Max Allan

## 0.103.3

ClamAV 0.103.3 is a patch release with the following fixes:

- Fixed a scan performance issue when ENGINE_OPTIONS_FORCE_TO_DISK is enabled.
  This issue did not impacted most users but for those affected it caused every
  scanned file to be copied to the temp directory before the scan.

- Fix ClamDScan crashes when using the `--fdpass --multiscan` command-line
  options in combination with the ClamD `ExcludePath` config file options.

- Fixed an issue where the `mirrors.dat` file is owned by root when starting as
  root (or with sudo) and using daemon-mode. File ownership will be set to the
  `DatabaseOwner` just before FreshClam switches to run as that user.

- Renamed the `mirrors.dat` file to `freshclam.dat`.

  We used to recommend deleting `mirrors.dat` if FreshClam failed to update.
  This is because `mirrors.dat` used to keep track of offline mirrors and
  network interruptions were known to cause FreshClam to think that all mirrors
  were offline. ClamAV now uses a paid CDN instead of a mirror network, and the
  new FreshClam DAT file no longer stores that kind of information.
  The UUID used in ClamAV's HTTP User-Agent is stored in the FreshClam DAT file
  and we want the UUID to persist between runs, even if there was a failure.

  Unfortunately, some users have FreshClam configured to automatically delete
  `mirrors.dat` if FreshClam failed. Renaming `mirrors.dat` to `freshclam.dat`
  should make it so those scripts don't delete important FreshClam data.

- Disabled the `HTTPUserAgent` config option if the `DatabaseMirror` uses
  clamav.net. This will prevent users from being inadvertently blocked and
  will ensure that we can keep better metrics on which ClamAV versions are
  being used.

  This change effectively deprecates the `HTTPUserAgent` option for most users.

- Moved the detection for Heuristics.PNG.CVE-2010-1205 behind the
  ClamScan `--alert-broken-media` option (ClamD `AlertBrokenMedia yes`) option.
  This type of PNG issue appears to be common enough to be an annoyance, and
  the CVE is old enough that no one should be vulnerable at this point.

- Fix ClamSubmit failures after changes to Cloudflare "__cfduid" cookies.
  See: https://blog.cloudflare.com/deprecating-cfduid-cookie/

Special thanks to the following for code contributions and bug reports:

- Stephen Agate
- Tom Briden

## 0.103.2

ClamAV 0.103.2 is a security patch release with the following fixes:

- [CVE-2021-1386](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-1386):
  Fix for UnRAR DLL load privilege escalation.
  Affects 0.103.1 and prior on Windows only.

- [CVE-2021-1252](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-1252):
  Fix for Excel XLM parser infinite loop.
  Affects 0.103.0 and 0.103.1 only.

- [CVE-2021-1404](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-1404):
  Fix for PDF parser buffer over-read; possible crash.
  Affects 0.103.0 and 0.103.1 only.

- [CVE-2021-1405](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-1405):
  Fix for mail parser NULL-dereference crash.
  Affects 0.103.1 and prior.

- Fix possible memory leak in PNG parser.

- Fix ClamOnAcc scan on file-creation race condition so files are scanned after
  their contents are written.

- FreshClam: Deprecate the `SafeBrowsing` config option.
  The `SafeBrowsing` option will no longer do anything.

  For more details, see:
  https://blog.clamav.net/2020/06/the-future-of-clamav-safebrowsing.html

  > _Tip_: If creating and hosting your own `safebrowsing.gdb` database, you can
  > use the `DatabaseCustomURL` option in `freshclam.conf` to download it.

- FreshClam: Improved HTTP 304, 403, & 429 handling.

- FreshClam: Add back the `mirrors.dat` file to the database directory.
  This new `mirrors.dat` file will store:
  - A randomly generated UUID for the FreshClam User-Agent.
  - A retry-after timestamp that so FreshClam won't try to update after
    having received an HTTP 429 response until the Retry-After timeout has
    expired.

- FreshClam will now exit with a failure in daemon mode if an HTTP 403
  (Forbidden) was received, because retrying later won't help any.
  The FreshClam user will have to take actions to get unblocked.

- Fix the FreshClam mirror-sync issue where a downloaded database is "older
  than the version advertised."

  If a new CVD download gets a version that is older than advertised, FreshClam
  will keep the older version and retry the update so that the incremental
  update process (CDIFF patch process) will update to the latest version.

## 0.103.1

ClamAV 0.103.1 is a patch release with the following fixes and improvements.

### Notable changes

- Added a new scan option to alert on broken media (graphics) file formats.
  This feature mitigates the risk of malformed media files intended to exploit
  vulnerabilities in other software.
  At present media validation exists for JPEG, TIFF, PNG, and GIF files.
  To enable this feature, set `AlertBrokenMedia yes` in clamd.conf, or use
  the `--alert-broken-media` option when using `clamscan`.
  These options are disabled by default in this patch release, but may be
  enabled in a subsequent release.
  Application developers may enable this scan option by enabling
  `CL_SCAN_HEURISTIC_BROKEN_MEDIA` for the `heuristic` scan option bit field.

- Added CL_TYPE_TIFF, CL_TYPE_JPEG types to match GIF, PNG typing behavior.
  BMP and JPEG 2000 files will continue to detect as CL_TYPE_GRAPHICS because
  ClamAV does not yet have BMP or JPEG 2000 format checking capabilities.

### Bug fixes

- Fixed PNG parser logic bugs that caused an excess of parsing errors and fixed
  a stack exhaustion issue affecting some systems when scanning PNG files.
  PNG file type detection was disabled via signature database update for
  ClamAV version 0.103.0 to mitigate the effects from these bugs.

- Fixed an issue where PNG and GIF files no longer work with Target:5 graphics
  signatures if detected as CL_TYPE_PNG/GIF rather than as CL_TYPE_GRAPHICS.
  Target types now support up to 10 possible file types to make way for
  additional graphics types in future releases.

- Fixed clamonacc's `--fdpass` option.

  File descriptor passing (or "fd-passing") is a mechanism by which clamonacc
  and clamdscan may transfer an open file to clamd to scan, even if clamd is
  running as a non-privileged user and wouldn't otherwise have read-access to
  the file. This enables clamd to scan all files without having to run clamd as
  root. If possible, clamd should never be run as root so as to mitigate the
  risk in case clamd is somehow compromised while scanning malware.

  Interprocess file descriptor passing for clamonacc was broken since version
  0.102.0 due to a bug introduced by the switch to curl for communicating with
  clamd. On Linux, passing file descriptors from one process to another is
  handled by the kernel, so we reverted clamonacc to use standard system calls
  for socket communication when fd passing is enabled.

- Fixed a clamonacc stack corruption issue on some systems when using an older
  version of libcurl. Patch courtesy of Emilio Pozuelo Monfort.

- Allow clamscan and clamdscan scans to proceed even if the realpath lookup
  failed. This alleviates an issue on Windows scanning files hosted on file-
  systems that do not support the GetMappedFileNameW() API such as on ImDisk
  RAM-disks.

- Fixed freshclam --on-update-execute=EXIT_1 temporary directory cleanup issue.

- `clamd`'s log output and VirusEvent now provide the scan target's file path
  instead of a file descriptor. The clamd socket API for submitting a scan by
  FD-passing doesn't include a file path, this feature works by looking up the
  file path by file descriptor. This feature works on Mac and Linux but is not
  yet implemented for other UNIX operating systems.
  FD-passing is not available for Windows.

- Fixed an issue where freshclam database validation didn't work correctly when
  run in daemon mode on Linux/Unix.

### Other improvements

- Scanning JPEG, TIFF, PNG, and GIF files will no longer return "parse" errors
  when file format validation fails. Instead, the scan will alert with the
  "Heuristics.Broken.Media" signature prefix and a descriptive suffix to
  indicate the issue, provided that the "alert broken media" feature is enabled.

- GIF format validation will no longer fail if the GIF image is missing the
  trailer byte, as this appears to be a relatively common issue in otherwise
  functional GIF files.

- Added a TIFF dynamic configuration (DCONF) option, which was missing.
  This will allow us to disable TIFF format validation via signature database
  update in the event that it proves to be problematic.
  This feature already exists for many other file types.

### Acknowledgments

The ClamAV team thanks the following individuals for their code submissions:

- Emilio Pozuelo Monfort

## 0.103.0

ClamAV 0.103.0 includes the following improvements and changes.

### Major changes

- Clamd can now reload the signature database without blocking scanning.
  This multi-threaded database reload improvement was made possible thanks to
  a community effort.

  Non-blocking database reloads are now the default behavior. Some systems that
  are more constrained on RAM may need to disable non-blocking reloads as it will
  temporarily consume 2x as much memory. For this purpose we have added a new
  clamd config option `ConcurrentDatabaseReload` which may be set to `no`.

  Special thanks to the following for making this feature a reality:
  - Alberto Wu
  - Alexander Sulfrian
  - Arjen de Korte
  - David Heidelberg
  - Ged Haywood
  - Julius Plenz
  - Michael Orlitzky

  Thank you all for your patience waiting for this feature.

### Notable changes

- The DLP module has been enhanced with additional credit card ranges and a new
  engine option which allows ClamAV to alert only on credit cards (and not, for
  instance, gift cards) when scanning with the DLP module. This feature
  enhancement was made by John Schember, with input from Alexander Sulfrian.

- Support for Adobe Reader X PDF encryption, an overhaul of PNG scanning to
  detect PNG specific exploits, and a major change to GIF parsing which makes
  it more tolerant to problematic files and adds the ability to scan overlays,
  all thanks to work and patches submitted by Aldo Mazzeo.

- `clamdtop.exe` now available for Windows users. Functionality is somewhat
  limited when compared with `clamdtop` on Linux. PDCurses is required to
  build `clamdtop.exe` for ClamAV on Windows.

- The phishing detection module will now print "Suspicious link found!" along
  with the "Real URL" and "Display URL" each time phishing is detected. In a
  future version, we would like to print out alert-related metadata like this
  at the end of a scan, but for now this detail will help users understand why
  a given file is being flagged as phishing.

- Added new *experimental* CMake build tooling. CMake is not yet recommended for
  production builds. Our team would appreciate any assistance improving the
  CMake build tooling so we can one day deprecate Autotools and remove the
  Visual Studio solutions.

  Please see the new [CMake installation instructions](INSTALL.md) for
  detailed instructions on how to build ClamAV with CMake.

- Added `--ping` and `--wait` options to the `clamdscan` and `clamonacc` client
  applications.

  The `--ping` (`-p`) command will attempt to ping `clamd` up to a specified
  maximum number of attempts at an optional interval. If the interval isn't
  specified, a default 1-second interval is used. It will exit with status code
  `0` when it receives a PONG from `clamd` or status code `21` if the timeout
  expires before it receives a response.

  Example:
  `clamdscan -p 120` will attempt to ping `clamd` 120 at a 1 second interval.

  The `--wait` (`-w`) command will wait up to 30 seconds for clamd to start.
  This option may be used in tandem with the `--ping` option to customize the
  max # of attempts and the attempt interval. As with `--ping`, the scanning
  client may exit with status code `21` if the timeout expires before a
  connection is made to `clamd`.

  Example:
  `clamdscan -p 30:2 -w <file>` will attempt a scan, waiting up to 60 seconds
  for clamd to start and receive the scan request.

  The ping-and-wait feature is particularly useful for those wishing to start
  `clamd` and start `clamonacc` at startup, ensuring that `clamd` is ready
  before `clamonacc` starts. It is also useful for those wishing to start
  `clamd` immediately before initiating scans with `clamdscan` rather than
  having the `clamd` service run continuously.

- Added Excel 4.0 (XLM) macro detection and extraction support. Significantly
  improved VBA detection and extraction as well. Work courtesy of Jonas Zaddach.

  This support not yet added to `sigtool`, as the VBA extraction feature in
  `sigtool` is separate from the one used for scanning and will still need to be
  updated or replaced in the future.

- Improvements to the layout and legibility of temp files created during a
  scan. Improvements to legibility and content of the metadata JSON generated
  during a scan.

  To review the scan temp files and metadata JSON, run:
  ```bash
  clamscan --tempdir=<path> --leave-temps --gen-json <target>
  ```

  Viewing the scan temp files and `metadata.json` file provides some insight
  into how ClamAV analyzes a given file and can also be useful to analysts for
  initial triage of potentially malicious files.

### Other improvements

- Added ability for freshclam and clamsubmit to override default use of openssl
  CA bundle with a custom CA bundle. On Linux/Unix platforms (excluding macOS),
  users may specify a custom CA bundle by setting the CURL_CA_BUNDLE environment
  variable. On macOS and Windows, users are expected to add CA certificates to
  their respective system's keychain/certificate store.
  Patch courtesy of Sebastian A. Siewior

- `clamscan` and `clamdscan` now print the scan start and end dates in the scan
  summary.

- The `clamonacc` on-access scanning daemon for Linux now installs to `sbin`
  instead of `bin`.

- Improvements to the freshclam progress bar so the width of the text does not
  shift around as information changes and will not spill exceed 80-characters
  even on very slow connections. Time is now displayed in Xm XXs (or Xh XXm)
  for values of 60 seconds or more. Bytes display now changes units at the
  proper 1024 B/KiB instead of 2048 B/KiB.
  Patch courtesy of Zachary Murden.

- Improve column alignment and line wrap rendering for ClamdTOP. Also fixed
  an issue on Windows where ClamdTOP would occasionally disconnect from clamd
  and fail to reconnect.
  Patch courtesy of Zachary Murden.

- Improvements to the AutoIT parser.

- Loosened the curl version requirements in order to build and use `clamonacc`.
  You may now build ClamAV with any version of libcurl. However `clamonacc`'s
  file descriptor-passing (FD-passing) capability will only be available with
  libcurl 7.40 or newer. FD-passing is ordinarily the default way to perform
  scans with clamonacc as it is significantly faster than streaming.

- Added LZMA and BZip2 decompression routines to the bytecode signature API.

- Disabled embedded type recognition for specific archive and disk image file
  types. This change reduces file type misclassification and improves scan time
  performance by reducing duplicated file scanning.

- Use pkg-config to detect libpcre2-8 before resorting to pcre2-config or
  pcre-config.
  Patch courtesy of Michael Orlitzky.

### Bug fixes

- Fixed issue scanning directories on Windows with `clamdscan.exe` that was
  introduced when mitigating against symlink quarantine attacks.

- Fixed behavior of `freshclam --quiet` option. Patch courtesy of Reio Remma.

- Fixed behavior of `freshclam`'s `OnUpdateExecute`, `OnErrorExecute`, and
  `OnOutdatedExecute` config options on Windows when in daemon-mode so it can
  handle multiple arguments.
  Patch courtesy of Zachary Murden.

- Fixed an error in the heuristic alert mechanism that would cause a single
  detection within an archive to alert once for every subsequent file scanned,
  potentially resulting in thousands of alerts for a single scan.

- Fixed clamd, clamav-milter, and freshclam to create PID files before
  dropping privileges, to avoid the possibility of an unprivileged user
  from changing the PID file so that a service manager will kill a different
  process. This change does make the services unable to clean up the PID
  file on exit.

- Fixed the false positive (.fp) signature feature. In prior versions, the hash
  in a false positive signature would be checked only against the current
  layer of a file being scanned. In 0.103, every file layer is hashed,
  and the hashes for each in the scan recursion list are checked. This ensures
  that .fp signatures containing a hash for any layer in the scan leading
  up to the alert will negate the alert.

  As an example, a hash for a zip containing the file which alerts would not
  prevent the detection in prior versions. Only the hash of the embedded file
  would work. For some file types where the outermost is always an archive,
  eg. docx files, this made .fp signatures next to useless. For certain file
  types where the scanned content was a normalized version of the original
  content, eg. HTML, the normalized version was never hashed and this meant
  that .fp signatures never worked.

- Fixed Trusted & Revoked Windows executable (PE) file signature rules (.crb)
  maximum functionality level (FLEVEL) which had been being treated as the
  minimum FLEVEL. These signatures enable ClamAV to trust executables that
  are digitally signed by trusted publishers, or to alert on executables signed
  with compromised signing-certificates. The minimum and maximum FLEVELS enable
  or disable signatures at load time depending on the current ClamAV version.

- Fixed a bug wherein you could not build ClamAV with `--enable-libclamav-only`
  if curl was not installed on the system.

- Various other bug fixes, improvements, and documentation improvements.

### New Requirements

- Autotools (automake, autoconf, m4, pkg-config, libtool) are now required in
  order to build from a Git clone because the files generated by these tools
  have been removed from the Git repository. To generate theses files before
  you compile ClamAV, run `autogen.sh`.
  Users building with Autotools from the release tarball should be unaffected.

### Acknowledgments

The ClamAV team thanks the following individuals for their code submissions:

- Aldo Mazzeo
- Ángel
- Antonino Cangialosi
- Clement Lecigne
- Jamie Biggar
- Jan Smutny
- Jim Klimov
- John Schember
- Jonathan Sabbe
- lutianxiong
- Michael Orlitzky
- Reio Remma
- Sebastian A. Siewior
- Zachary Murden

## 0.102.4

ClamAV 0.102.4 is a bug patch release to address the following issues.

- [CVE-2020-3350](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-3350):
  Fix a vulnerability wherein a malicious user could replace a scan target's
  directory with a symlink to another path to trick clamscan, clamdscan, or
  clamonacc into removing or moving a different file (eg. a critical system
  file). The issue would affect users that use the --move or --remove options
  for clamscan, clamdscan, and clamonacc.

  For more information about AV quarantine attacks using links, see the
  [RACK911 Lab's report](https://www.rack911labs.com/research/exploiting-almost-every-antivirus-software).

- [CVE-2020-3327](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-3327):
  Fix a vulnerability in the ARJ archive parsing module in ClamAV 0.102.3 that
  could cause a Denial-of-Service (DoS) condition. Improper bounds checking
  results in an out-of-bounds read which could cause a crash.
  The previous fix for this CVE in 0.102.3 was incomplete. This fix correctly
  resolves the issue.

- [CVE-2020-3481](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-3481):
  Fix a vulnerability in the EGG archive module in ClamAV 0.102.0 - 0.102.3
  could cause a Denial-of-Service (DoS) condition. Improper error handling
  may result in a crash due to a NULL pointer dereference.
  This vulnerability is mitigated for those using the official ClamAV
  signature databases because the file type signatures in daily.cvd
  will not enable the EGG archive parser in versions affected by the
  vulnerability.

## 0.102.3

ClamAV 0.102.3 is a bug patch release to address the following issues.

- [CVE-2020-3327](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-3327):
  Fix a vulnerability in the ARJ archive parsing module in ClamAV 0.102.2 that
  could cause a Denial-of-Service (DoS) condition. Improper bounds checking of
  an unsigned variable results in an out-of-bounds read which causes a crash.

  Special thanks to Daehui Chang and Fady Othman for helping identify the ARJ
  parsing vulnerability.

- [CVE-2020-3341](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-3341):
  Fix a vulnerability in the PDF parsing module in ClamAV 0.101 - 0.102.2 that
  could cause a Denial-of-Service (DoS) condition. Improper size checking of
  a buffer used to initialize AES decryption routines results in an out-of-
  bounds read which may cause a crash. Bug found by OSS-Fuzz.

- Fix "Attempt to allocate 0 bytes" error when parsing some PDF documents.

- Fix a couple of minor memory leaks.

- Updated libclamunrar to UnRAR 5.9.2.

## 0.102.2

ClamAV 0.102.2 is a bug patch release to address the following issues.

- [CVE-2020-3123](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-3123):
  An Denial-of-Service (DoS) condition may occur when using the optional credit
  card data-loss-prevention (DLP) feature. Improper bounds checking of an
  unsigned variable resulted in an out-of-bounds read which causes a crash.

- Significantly improved scan speed of PDF files on Windows.

- Re-applied a fix to alleviate file access issues when scanning RAR files in
  downstream projects that use libclamav where the scanning engine is operating
  in a low-privilege process. This bug was originally fixed in 0.101.2 and the
  fix was mistakenly omitted from 0.102.0.

- Fixed an issue wherein freshclam failed to update if the database version
  downloaded is 1 version older than advertised. This situation may occur after
  a new database version is published. The issue affected users downloading the
  whole CVD database file.

- Changed the default freshclam ReceiveTimeout setting to 0 (infinite).
  The ReceiveTimeout had caused needless database update failures for users with
  slower internet connections.

- Correctly display number of kilobytes (KiB) in progress bar and reduced the
  size of the progress bar to accommodate 80-char width terminals.

- Fixed an issue where running freshclam manually causes a daemonized freshclam
  process to fail when it updates because the manual instance deletes the
  temporary download directory. FreshClam temporary files will now download to a
  unique directory created at the time of an update instead of using a hardcoded
  directory created/destroyed at the program start/exit.

- Fixed behavior of `freshclam`'s `OnOutdatedExecute` config option when in
  foreground mode. Previously it would run the `OnUpdateExecute` command instead.
  Patch courtesy of Antoine Deschênes.

- Fixes a memory leak in the error condition handling for the email parser.

- Improved bound checking and error handling in ARJ archive parser.

- Improved error handling in PDF parser.

- Fix for memory leak in byte-compare signature handler.

- Updates to the unit test suite to support libcheck 0.13.

- Updates to support autoconf 2.69 and automake 1.15.

Special thanks to the following for code contributions and bug reports:

- Antoine Deschênes
- Eric Lindblad
- Gianluigi Tiesi
- Tuomo Soini

## 0.102.1

ClamAV 0.102.1 is a security patch release to address the following issues.

- Fix for the following vulnerability affecting 0.102.0 and 0.101.4 and prior:
  - [CVE-2019-15961](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-15961)
    A Denial-of-Service (DoS) vulnerability may occur when scanning a specially
    crafted email file as a result of excessively long scan times. The issue is
    resolved by implementing several maximums in parsing MIME messages and by
    optimizing use of memory allocation.

- Build system fixes to build clamav-milter, to correctly link with libxml2 when
  detected, and to correctly detect fanotify for on-access scanning feature
  support.

- Signature load time is significantly reduced by changing to a more efficient
  algorithm for loading signature patterns and allocating the AC trie.
  Patch courtesy of Alberto Wu.

- Introduced a new configure option to statically link libjson-c with libclamav.
  Static linking with libjson is highly recommended to prevent crashes in
  applications that use libclamav alongside another JSON parsing library.

- Null-dereference fix in email parser when using the `--gen-json` metadata
  option.

- Fixes for Authenticode parsing and certificate signature (.crb database) bugs.

Special thanks to the following for code contributions and bug reports:

- Alberto Wu
- Joran Dirk Greef
- Reio Remma

## 0.102.0

ClamAV 0.102.0 includes an assortment improvements and a couple of significant
changes.

### Major changes

- The On-Access Scanning feature has been migrated out of `clamd` and into
  a brand new utility named `clamonacc`. This utility is similar to
  `clamdscan` and `clamav-milter` in that it acts as a client to `clamd`.
  This separation from `clamd` means that `clamd` no longer needs to run
  with root privileges while scanning potentially malicious files. Instead,
  `clamd` may drop privileges to run under an account that does not have
  super-user. In addition to improving the security posture of running
  `clamd` with On-Access enabled, this update fixed a few outstanding defects:
  - On-Access scanning for created and moved files (Extra-Scanning) is fixed.
  - VirusEvent for On-Access scans is fixed.
  - With `clamonacc`, it is now possible to copy, move, or remove a file if the
    scan triggered an alert, just like with `clamdscan`.
  For details on how to use the new `clamonacc` On-Access scanner, please
  refer to the user manual on [ClamAV.net](https://docs.clamav.net/),
  and keep an eye out for a new blog post on the topic
- The `freshclam` database update utility has undergone a significant update.
  This includes:
  - Added support for HTTPS.
  - Support for database mirrors hosted on ports other than 80.
  - Removal of the mirror management feature (mirrors.dat).
  - An all new libfreshclam library API.

### Notable changes

- Added support for extracting ESTsoft .egg archives.
  This feature is new code developed from scratch using ESTsoft's Egg-archive
  specification and without referencing the UnEgg library provided by ESTsoft.
  This was necessary because the UnEgg library's license includes restrictions
  limiting the commercial use of the UnEgg library.
- The documentation has moved!
  - Users should navigate to [ClamAV.net](https://docs.clamav.net/)
    to view the documentation online.
  - The documentation will continue to be provided in HTML format with each
    release for offline viewing in the `docs/html` directory.
  - The new home for the documentation markdown is in our
    [ClamAV FAQ GitHub repository](https://github.com/Cisco-Talos/clamav-faq)
- To remediate future denial of service conditions caused by excessive scan times,
  we introduced a scan time limit.
  The default value is 2 minutes (120000 milliseconds).

  To customize the time limit:

  - use the `clamscan` `--max-scantime` option
  - use the `clamd` `MaxScanTime` config option

  Libclamav users may customize the time limit using the `cl_engine_set_num`
  function. For example:

  ```c
      cl_engine_set_num(engine, CL_ENGINE_MAX_SCANTIME, time_limit_milliseconds)
  ```

### Other improvements

- Improved Windows executable Authenticode handling, enabling both allowing
  and blocking of files based on code-signing certificates. Additional
  improvements to Windows executable (PE file) parsing.
  Work courtesy of Andrew Williams.
- Added support for creating bytecode signatures for Mach-O and
  ELF executable unpacking. Work courtesy of Jonas Zaddach.
- Re-formatted the entire ClamAV code-base using `clang-format` in conjunction
  with our new ClamAV code style specification. See the
  [clamav.net blog post](https://blog.clamav.net/2019/02/clamav-adopts-clang-format.html)
  for details.
- Integrated ClamAV with Google's [OSS-Fuzz](https://github.com/google/oss-fuzz)
  automated fuzzing service with the help of Alex Gaynor. This work has already
  proven beneficial, enabling us to identify and fix subtle bugs in both legacy
  code and newly developed code.
- The `clamsubmit` tool is now available on Windows.
- The `clamscan` metadata feature (`--gen-json`) is now available on Windows.
- Significantly reduced number of warnings generated when compiling ClamAV with
  "-Wall" and "-Wextra" compiler flags and made many subtle improvements to the
  consistency of variable types throughout the code.
- Updated the majority of third-party dependencies for ClamAV on Windows.
  The source code for each has been removed from the clamav-devel repository.
  This means that these dependencies have to be compiled independently of ClamAV.
  The added build process complexity is offset by significantly reducing the
  difficulty of releasing ClamAV with newer versions of those dependencies.
- During the 0.102 development period, we've also improved our Continuous
  Integration (CI) processes. Most recently, we added a CI pipeline definition
  to the ClamAV Git repository. This chains together our build and quality
  assurance test suites and enables automatic testing of all proposed changes
  to ClamAV, with customizable parameters to suit the testing needs of any
  given code change.
- Added a new `clamav-version.h` generated header to provide version number
  macros in text and numerical format for ClamAV, libclamav, and libfreshclam.
- Improved cross-platform buildability of libxml2. Work courtesy of Eneas U de
  Queiroz with supporting ideas pulled from the work of Jim Klimov.

### Bug fixes

- Fix to prevent a possible crash when loading LDB type signature databases
  and PCRE is not available. Patch courtesy of Tomasz Kojm.
- Fixes to the PDF parser that will improve PDF malware detection efficacy.
  Patch courtesy of Clement Lecigne.
- Fix for regular expression phishing signatures (PDB R-type signatures).
- Various other bug fixes.

### New Requirements

- Libcurl has become a hard-dependency. Libcurl enables HTTPS support for
  `freshclam` and `clamsubmit` as well as communication between `clamonacc`
  and `clamd`.
- Libcurl version >= 7.45 is required when building ClamAV from source with
  the new On-Access Scanning application (`clamonacc`). Users on Linux operating
  systems that package older versions of libcurl (e.g. all versions of CentOS
  and Debian versions <= 8) have a number of options:

  1. Wait for your package maintainer to provide a newer version of libcurl.
  2. Install a newer version of libcurl [from source](https://curl.haxx.se/download.html).
  3. Disable installation of `clamonacc` and On-Access Scanning capabilities
    with the `./configure` flag `--disable-clamonacc`.

  Non-Linux users will need to take no actions as they are unaffected by this
  new requirement.

### Acknowledgments

The ClamAV team thanks the following individuals for their code submissions:

- Alex Gaynor
- Andrew Williams
- Carlo Landmeter
- Chips
- Clement Lecigne
- Eneas U de Queiroz
- Jim Klimov
- Joe Cooper
- Jonas Zaddach
- Markus Kolb
- Orion Poplawski
- Ørjan Malde
- Paul Arthur
- Rick Wang
- Romain Chollet
- Rosen Penev
- Thomas Jarosch
- Tomasz Kojm
- Tuomo Soini

Finally, we'd like to thank Joe McGrath for building our quality assurance test suite
and for working diligently to ensure knowledge transfer up until his last day
on the team. Working with you was a pleasure, Joe, and we wish you the best
of luck in your next adventure!

## 0.101.5

ClamAV 0.101.5 is a security patch release that addresses the following issues.

- Fix for the following vulnerability affecting 0.102.0 and 0.101.4 and prior:
  - [CVE-2019-15961](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-15961)
    A Denial-of-Service (DoS) vulnerability may occur when scanning a specially
    crafted email file as a result of excessively long scan times. The issue is
    resolved by implementing several maximums in parsing MIME messages and by
    optimizing use of memory allocation.

- Added the zip scanning improvements found in v0.102.0 where it scans files
  using zip records from a sorted catalogue which provides deduplication of
  file records resulting in faster extraction and scan time and reducing the
  likelihood of alerting on non-malicious duplicate file entries as overlapping
  files.

- Signature load time is significantly reduced by changing to a more efficient
  algorithm for loading signature patterns and allocating the AC trie.
  Patch courtesy of Alberto Wu.

- Introduced a new configure option to statically link libjson-c with libclamav.
  Static linking with libjson is highly recommended to prevent crashes in
  applications that use libclamav alongside another JSON parsing library.

- Null-dereference fix in email parser when using the `--gen-json` metadata
  option.

Special thanks to the following for code contributions and bug reports:

- Alberto Wu
- Joran Dirk Greef

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
prior versions. In addition, it includes a number of minor bug fixes and
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

### Acknowledgments

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
- FreshClam updated to match exit codes defined in the freshclam.1 man page.
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
    trusted correctly.
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
    tests across 64bit and 32bit (where available):
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

### Acknowledgments

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
    small file. Reported by aCaB.
- Fixes for a few additional bugs:
  - Buffer over-read in unRAR code due to missing max value checks in table
    initialization. Reported by Rui Reis.
  - Libmspack heap buffer over-read in CHM parser. Reported by Hanno Böck.
  - PDF parser bugs reported by Alex Gaynor.
    - Buffer length checks when reading integers from non-NULL terminated strings.
    - Buffer length tracking when reading strings from dictionary objects.
- HTTPS support for clamsubmit.
- Fix for DNS resolution for users on IPv4-only machines where IPv6 is not
  available or is link-local only. Patch provided by Guilherme Benkenstein.

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
 from the ClamAV community. As always, it can be downloaded from our downloads
 page on clamav.net. Some of the more prominent submissions include:

- Interfaces to the Prelude SIEM open source package for collecting
  ClamAV virus events.
- Support for Visual Studio 2015 for Windows builds. Please note that we
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

### Acknowledgments

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
 I am to say it, we couldn't address every bug in this release. I want to draw
 your attention a couple bugs in particular so as not to frustrate users
 setting up ClamAV:

- Platform: macOS:
  - Bug:  If you attempt to build ClamAV with a system installed LLVM you may
    receive a linker error. We recently changed default linking behavior to
    prefer dynamic linking over static linking. As a result, we've uncovered a
    bug in building on macOS where dynamic linking against the LLVM libraries
    fails. To work around this bug, please add the --with-llvm-linking=static
    option to your ./configure call.

- Platform: CentOS 6 32bit, older versions of AIX:
  - Bug:  On CentOS 6 32bit we observed that specific versions of zlib fail to
    correctly decompress the CVD signature databases. If you are on an older
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
- FreshClam failure on Solaris 10.
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
for all of the code used other than OpenSSL. If you modify
file(s) with this exception, you may extend this exception to your
version of the file(s), but you are not obligated to do so. If you
do not wish to do so, delete this exception statement from your
version. If you delete this exception statement from all source
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
  trusted root certificate authorities, the engine can trust
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
  scanner can now make use of the Google's block lists of suspected
  phishing and malware sites. The ClamAV Project distributes a constantly
  updated Safe Browsing database, which can be automatically fetched by
  freshclam. For more information, please see freshclam.conf(5) and
  https://docs.clamav.net/faq/faq-safebrowsing.html.

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
  enabled, scans data for the inclusion of US formatted Social Security
  Numbers and credit card numbers (clamd: StructuredDataDetection,
  clamscan: --detect-structured; additional fine-tuning options are available)

- IPv6 Support: FreshClam now supports IPv6

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
  - Block list mode: optionally block lists an IP for a configurable amount
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
  - new directive ExitOnOOM (stop the daemon when libclamav reports an out of
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
  - --no-dns uses an If-Modified-Since method instead of a range GET
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
method. It uses advanced techniques to ensure all the mirrors are up-to-date.

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

    FreshClam will automatically use them when the main server is not
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
  - included how-to in Portuguese by Alexandre de Jesus Marcolino
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
attachment file names.

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

OAV database is up-to-date ! There was a problem with signature parsing,
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
updated (especially when new wild virus/worm appears, eg. W32/BugBear.A).

    This software is still in development (new software == new bugs), however
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
  own databases there and they won't be overwritten by the updaters. viruses.db
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
*superuser* privileges (after dropping privileges scanner wasn't able to
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

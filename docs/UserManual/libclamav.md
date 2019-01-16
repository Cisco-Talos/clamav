# LibClamAV

Libclamav provides an easy and effective way to add a virus protection into your software. The library is thread-safe and transparently recognizes and scans within archives, mail files, MS Office document files, executables and other special formats.

## License

Libclamav is licensed under the GNU GPL v2 license. This means you are **not allowed** to link commercial, closed-source software against it. All software using libclamav must be GPL compliant.

## Supported formats and features

### Executables

The library has a built-in support for 32- and 64-bit Portable Executable, ELF and Mach-O files. Additionally, it can handle PE files compressed or obfuscated with the following tools:

- Aspack (2.12)
- UPX (all versions)
- FSG (1.3, 1.31, 1.33, 2.0)
- Petite (2.x)
- PeSpin (1.1)
- NsPack
- wwpack32 (1.20)
- MEW
- Upack
- Y0da Cryptor (1.3)

### Mail files

Libclamav can handle almost every mail file format including TNEF (winmail.dat) attachments.

### Archives and compressed files

The following archive and compression formats are supported by internal handlers:

- Zip (+ SFX)
- RAR (+ SFX)
- 7Zip
- Tar
- CPIO
- Gzip
- Bzip2
- DMG
- IMG
- ISO 9660
- PKG
- HFS+ partition
- HFSX partition
- APM disk image
- GPT disk image
- MBR disk image
- XAR
- XZ
- MS OLE2
- MS Cabinet Files (+ SFX)
- MS CHM (Compiled HTML)
- MS SZDD compression format
- BinHex
- SIS (SymbianOS packages)
- AutoIt
- NSIS
- InstallShield

### Documents

The most popular file formats are supported:

- MS Office and MacOffice files
- RTF
- PDF
- HTML

In the case of Office, RTF and PDF files, libclamav will only extract the embedded objects and will not decode the text data itself. The text decoding and normalization is only performed for HTML files.

### Data Loss Prevention

Libclamav includes a DLP module which can detect the following credit card issuers: AMEX, VISA, MasterCard, Discover, Diner’s Club, and JCB and U.S. social security numbers inside text files.

Future versions of Libclamav may include additional features to detect other credit cards and other forms of PII (Personally Identifiable Information) which may be transmitted without the benefit of being encrypted.

### Others

Libclamav can handle various obfuscators, encoders, files vulnerable to security risks such as:

- JPEG (exploit detection)
- RIFF (exploit detection)
- uuencode
- ScrEnc obfuscation
- CryptFF

## API

### Header file

Every program using libclamav must include the header file `clamav.h`:

```c
    #include <clamav.h>
```

### Initialization

Before using libclamav, you should call `cl_init()` to initialize it. `CL_INIT_DEFAULT` is a macro that can be passed to `cl_init()` representing the default initialization settings. When it’s done, you’re ready to create a new scan engine by calling `cl_engine_new()`. To free resources allocated by the engine use `cl_engine_free()`. Function prototypes:

```c
    int cl_init(unsigned int options);
    struct cl_engine *cl_engine_new(void);
    int cl_engine_free(struct cl_engine *engine);
```

`cl_init()` and `cl_engine_free()` return `CL_SUCCESS` on success or another code on error. `cl_engine_new()` return a pointer or NULL if there’s not enough memory to allocate a new engine structure.

### Database loading

The following set of functions provides an interface for loading the virus database:

```c
    const char *cl_retdbdir(void);

    int cl_load(const char *path, struct cl_engine *engine,
            unsigned int *signo, unsigned int options);
```

`cl_retdbdir()` returns the default (hardcoded) path to the directory with ClamAV databases. `cl_load()` loads a single database file or all databases from a given directory (when `path` points to a directory). The second argument is used for passing in the pointer to the engine that should be previously allocated with `cl_engine_new()`. A number of loaded signatures will be **added** to `signo`. The last argument can pass the following flags:

- **CL_DB_STDOPT**
    This is an alias for a recommended set of scan options.
- **CL_DB_PHISHING**
    Load phishing signatures.
- **CL_DB_PHISHING_URLS**
    Initialize the phishing detection module and load .wdb and .pdb
    files.
- **CL_DB_PUA**
    Load signatures for Potentially Unwanted Applications.
- **CL_DB_OFFICIAL_ONLY**
    Only load official signatures from digitally signed databases.
- **CL_DB_BYTECODE**
    Load bytecode.

`cl_load()` returns `CL_SUCCESS` on success and another code on failure.

```c
        ...
        struct cl_engine *engine;
        unsigned int sigs = 0;
        int ret;

    if((ret = cl_init(CL_INIT_DEFAULT)) != CL_SUCCESS) {
        printf("cl_init() error: %s\n", cl_strerror(ret));
        return 1;
    }

    if(!(engine = cl_engine_new())) {
        printf("Can't create new engine\n");
        return 1;
    }

    ret = cl_load(cl_retdbdir(), engine, &sigs, CL_DB_STDOPT);
```

### Error handling

Use `cl_strerror()` to convert error codes into human readable messages. The function returns a statically allocated string:

```c
    if(ret != CL_SUCCESS) {
        printf("cl_load() error: %s\n", cl_strerror(ret));
        cl_engine_free(engine);
        return 1;
    }
```

### Engine structure

When all required databases are loaded you should prepare the detection engine by calling `cl_engine_compile()`. In case of failure you should still free the memory allocated to the engine with `cl_engine_free()`:

```c
    int cl_engine_compile(struct cl_engine *engine);
```

In our example:

```c
    if((ret = cl_engine_compile(engine)) != CL_SUCCESS) {
        printf("cl_engine_compile() error: %s\n", cl_strerror(ret));
        cl_engine_free(engine);
        return 1;
    }
```

### Limits

When you create a new engine with `cl_engine_new()`, it will have all internal settings set to default values as recommended by the ClamAV authors. It’s possible to check and modify the values (numerical and strings) using the following set of functions:

```c
int cl_engine_set_num(struct cl_engine *engine,
  enum cl_engine_field field, long long num);

long long cl_engine_get_num(const struct cl_engine *engine,
  enum cl_engine_field field, int *err);

int cl_engine_set_str(struct cl_engine *engine,
  enum cl_engine_field field, const char *str);

const char *cl_engine_get_str(const struct cl_engine *engine,
  enum cl_engine_field field, int *err);
```

Please don’t modify the default values unless you know what you’re doing. Refer to the ClamAV sources (clamscan, clamd) for examples.

### Database checks

It’s very important to keep the internal instance of the database up to date. You can watch database changes with the `cl_stat..()` family of functions.

```c
    int cl_statinidir(const char *dirname, struct cl_stat *dbstat);
    int cl_statchkdir(const struct cl_stat *dbstat);
    int cl_statfree(struct cl_stat *dbstat);
```

Initialization:

```c
        ...
        struct cl_stat dbstat;

    memset(&dbstat, 0, sizeof(struct cl_stat));
    cl_statinidir(dbdir, &dbstat);
```

To check for a change you just need to call `cl_statchkdir` and check its return value (0 - no change, 1 - some change occurred). Remember to reset the `cl_stat` structure after reloading the database.

```c
    if(cl_statchkdir(&dbstat) == 1) {
        reload_database...;
        cl_statfree(&dbstat);
        cl_statinidir(cl_retdbdir(), &dbstat);
    }
```

Libclamav \(\ge0.96\) includes and additional call to check the number of signatures that can be loaded from a given directory:

```c
    int cl_countsigs(const char *path, unsigned int countoptions,
        unsigned int *sigs);
```

The first argument points to the database directory, the second one specifies what signatures should be counted: `CL_COUNTSIGS_OFFICIAL` (official signatures), `CL_COUNTSIGS_UNOFFICIAL` (third party signatures), `CL_COUNTSIGS_ALL` (all signatures). The last argument points to the counter to which the number of detected signatures will be added (therefore the counter should be initially set to 0). The call returns `CL_SUCCESS` or an error code.

### Data scan functions

It’s possible to scan a file or descriptor using:

```c
    int cl_scanfile(
        const char *filename,
        const char **virname,
        unsigned long int *scanned,
        const struct cl_engine *engine,
        struct cl_scan_options *options);

    int cl_scandesc(
        int desc,
        const char *filename,
        const char **virname,
        unsigned long int *scanned,
        const struct cl_engine *engine,
        struct cl_scan_options *options);
```

Both functions will store a virus name under the pointer `virname`, the virus name is part of the engine structure and must not be released directly. If the third argument (`scanned`) is not NULL, the functions will increase its value with the size of scanned data (in `CL_COUNT_PRECISION` units). The last argument (`options`) requires a pointer to a data structure that specifies the scan options.  The data structure should be `memset()` Each variable in the structure is a bit-flag field.  The structure definition is:

```c
    struct cl_scan_options {
        uint32_t general;
        uint32_t parse;
        uint32_t alert;
        uint32_t heuristic_alert;
        uint32_t mail;
        uint32_t dev;
    };
```

Supported flags for each of the fields are as follows:

`general` - General scanning options.

- **CL_SCAN_GENERAL_ALLMATCHES**
    Scan in all-match mode
- **CL_SCAN_GENERAL_COLLECT_METADATA**
    Collect metadata (--gen-json)
- **CL_SCAN_GENERAL_HEURISTICS**
    Option to enable heuristic alerts.  Required for any of the heuristic alerting options to work.

`parse` - Options to enable/disable specific parsing capabilities.  Generally you will want to enable all parsers.  The easiest way to do this is to set the parse flags to ~0.

- **CL_SCAN_PARSE_ARCHIVE**
    This flag enables transparent scanning of various archive formats.
- **CL_SCAN_PARSE_ELF**
    Enable support for ELF files.
- **CL_SCAN_PARSE_PDF**
    Enables scanning within PDF files.
- **CL_SCAN_PARSE_SWF**
    Enables scanning within SWF files, notably compressed SWF.
- **CL_SCAN_PARSE_HWP**
    Enables scanning of Hangul Word Processor (HWP) files.
- **CL_SCAN_PARSE_XMLDOCS**
    Enables scanning of XML-formatted documents (e.g. Word, Excel, Powerpoint, HWP).
- **CL_SCAN_PARSE_MAIL**
    Enable support for mail files.
- **CL_SCAN_PARSE_OLE2**
    Enables support for OLE2 containers (used by MS Office and .msi files).
- **CL_SCAN_PARSE_HTML**
    This flag enables HTML normalisation (including ScrEnc decryption).
- **CL_SCAN_PARSE_PE**
    This flag enables deep scanning of Portable Executable files and allows libclamav to unpack executables compressed with run-time unpackers.

`heuristic` - Options to enable specific heuristic alerts

- **CL_SCAN_GENERAL_HEURISTIC_PRECEDENCE**
    Allow heuristic match to take precedence. When enabled, if a heuristic scan (such as phishingScan) detects a possible virus/phish it will stop scan immediately. Recommended, saves CPU scan-time. When *disabled*, virus/phish detected by heuristic scans will be reported only at the end of a scan. If an archive contains both a heuristically detected virus/phishing, and a real malware, the real malware will be reported.
- **CL_SCAN_HEURISTIC_ENCRYPTED_ARCHIVE**
    With this flag the library will mark encrypted archives as viruses (encrypted .zip, .7zip, .rar).
- **CL_SCAN_HEURISTIC_ENCRYPTED_DOC**
    With this flag the library will mark encrypted docuemnts as viruses (encrypted .pdf).
- **CL_SCAN_HEURISTIC_BROKEN**
    libclamav will try to detect broken executables and mark them as Broken.Executable.
- **CL_SCAN_HEURISTIC_EXCEEDS_MAX**
    Alert when the scan of any file exceeds maximums such as max filesize, max scansize, max recursion level.
- **CL_SCAN_HEURISTIC_PHISHING_SSL_MISMATCH**
    Heuristic for phishing module: alert on SSL mismatches in URLs.
- **CL_SCAN_HEURISTIC_PHISHING_CLOAK**
    Heuristic for phishing module: alert on cloaked URLs.
- **CL_SCAN_HEURISTIC_MACROS**
    OLE2 containers, which contain VBA macros will be marked infected (Heuristics.OLE2.ContainsMacros).
- **CL_SCAN_HEURISTIC_PARTITION_INTXN**
    alert if partition table size doesn't make sense
- **CL_SCAN_HEURISTIC_STRUCTURED**
    Enable the data loss prevention (DLP) module which scans for credit card and SSN numbers. i.e. alert when detecting personal information
- **CL_SCAN_HEURISTIC_STRUCTURED_SSN_NORMAL**
    Search for [and alert when detecting] SSNs formatted as xx-yy-zzzz.
- **CL_SCAN_HEURISTIC_STRUCTURED_SSN_STRIPPED**
    Search for [and alert when detecting] SSNs formatted as xxyyzzzz.

`mail` - Options to enable specific mail parsing features

- **CL_SCAN_MAIL_PARTIAL_MESSAGE**
    Scan RFC1341 messages split over many emails. You will need to periodically clean up `$TemporaryDirectory/clamav-partial` directory.

`dev` - Options designed for use by ClamAV developers

- **CL_SCAN_DEV_COLLECT_SHA**
    Enables hash output in sha-collect builds - for internal use only
- **CL_SCAN_DEV_COLLECT_PERFORMANCE_INFO**
    Collect performance timings

All functions return `CL_CLEAN` when the file seems clean, `CL_VIRUS` when a virus is detected and another value on failure.

```c
        ...
        const char *virname;

    if((ret = cl_scanfile("/tmp/test.exe", &virname, NULL, engine,
    &options)) == CL_VIRUS) {
        printf("Virus detected: %s\n", virname);
    } else {
        printf("No virus detected.\n");
        if(ret != CL_CLEAN)
            printf("Error: %s\n", cl_strerror(ret));
    }
```

### Memory

Because the engine structure occupies a few megabytes of system memory, you should release it with `cl_engine_free()` if you no longer need to scan files.

### Forking daemons

If you’re using libclamav with a forking daemon you should call `srand()` inside a forked child before making any calls to the libclamav functions. This will avoid possible collisions with temporary filenames created by other processes of the daemon. This procedure is not required for multi-threaded daemons.

### clamav-config

Use `clamav-config` to check compilation information for libclamav.

```bash
    $ clamav-config --libs
    -L/usr/local/lib -lz -lbz2 -lgmp -lpthread
    $ clamav-config --cflags
    -I/usr/local/include -g -O2
```

### Example

You will find an example scanner application in the clamav source package (/example). Provided you have ClamAV already installed, execute the following to compile it:

```bash
    gcc -Wall ex1.c -o ex1 -lclamav
```

## CVD format

CVD (ClamAV Virus Database) is a digitally signed tarball containing one or more databases. The header is a 512-bytes long string with colon separated fields:

```ini
ClamAV-VDB:build time:version:number of signatures:functionality
level required:MD5 checksum:digital signature:builder name:build time (sec)
```

`sigtool --info` displays detailed information on CVD files:

```bash
$ sigtool -i daily.cvd
File: daily.cvd
Build time: 10 Mar 2008 10:45 +0000
Version: 6191
Signatures: 59084
Functionality level: 26
Builder: ccordes
MD5: 6e6e29dae36b4b7315932c921e568330
Digital signature: zz9irc9irupR3z7yX6J+OR6XdFPUat4HIM9ERn3kAcOWpcMFxq
Fs4toG5WJsHda0Jj92IUusZ7wAgYjpai1Nr+jFfXHsJxv0dBkS5/XWMntj0T1ctNgqmiF
+RLU6V0VeTl4Oej3Aya0cVpd9K4XXevEO2eTTvzWNCAq0ZzWNdjc
Verification OK.
```

## Graphics

The current ClamAV logo was created by Alicia Willet, Talos.

## OpenAntiVirus

Our database includes the virus database (about 7000 signatures) from OpenAntiVirus (<http://OpenAntiVirus.org>).

1. Subscribers are not allowed to post to the mailing list

2. For Windows instructions please see win32/README in the main source code directory.

3. See section [3.7](#unit-testing) on how to run the unit tests

4. if not available ClamAV will fall back to an interpreter

5. Note that several versions of GCC have bugs when compiling LLVM, see <http://llvm.org/docs/GettingStarted.html#brokengcc> for a full list.

6. The configure script in ClamAV automatically enables the unit tests, if it finds the check framework, however it doesn’t consider it a fatal error if unit tests cannot be enabled.

7. To get more info on clamscan options run ’man clamscan’

8. man 5 clamd.conf

9. Remember to initialize the virus counter variable with 0.

# Creating signatures for ClamAV

Table of Contents

- [Creating signatures for ClamAV](#creating-signatures-for-clamav)
    - [Introduction](#introduction)
    - [Database formats](#database-formats)
        - [Settings databases](#settings-databases)
        - [Signature databases](#signature-databases)
            - [Body-based Signatures](#body-based-signatures)
            - [Hash-based Signatures](#hash-based-signatures)
            - [Alternative signature support](#alternative-signature-support)
        - [Other database files](#other-database-files)
        - [Signature names](#signature-names)
    - [Signature Writing Tips and Tricks](#signature-writing-tips-and-tricks)
        - [Testing rules with `clamscan`](#testing-rules-with-clamscan)
        - [Debug information from libclamav](#debug-information-from-libclamav)
        - [Writing signatures for special files](#writing-signatures-for-special-files)
            - [HTML](#html)
            - [Text files](#text-files)
            - [Compressed Portable Executable files](#compressed-portable-executable-files)
        - [Using `sigtool`](#using-sigtool)
        - [Inspecting signatures inside a CVD file](#inspecting-signatures-inside-a-cvd-file)
        - [External tools](#external-tools)

## Introduction

In order to detect malware and other file-based threats, ClamAV relies on signatures to differentiate clean and malicious/unwanted files.  ClamAV signatures are primarily text-based and conform to one of the ClamAV-specific signature formats associated with a given method of detection.  These formats are explained in the [Signature formats](#signature-formats) section below.  In addition, ClamAV 0.99 and above support signatures written in the YARA format.  More information on this can be found in the [Using YARA rules in ClamAV](#using-yara-rules-in-clamav) section.

The ClamAV project distributes a collection of signatures in the form of CVD (ClamAV Virus Database) files.  The CVD file format provides a digitally-signed container that encapsulates the signatures and ensures that they can't be modified by a malicious third-party.  This signature set is actively maintained by [Cisco Talos](https://www.talosintelligence.com/) and can be downloaded using the `freshclam` application that ships with ClamAV.  For more details on this, see the [CVD file](#inspecting-signatures-inside-a-CVD-file) section.

## Database formats

ClamAV CVD and CLD database archives may be unpacked to the current directory using `sigtool -u <database name>`. For more details on inspecting CVD and CLD files, see [Inspecting signatures inside a CVD file](#inspecting-signatures-inside-a-cvd-file). Once unpacked, you'll observe a large collection of database files with various extensions described below.

The CVD and CLD database archives may be supplemented with custom database files in the formats described to gain additional detection functionality. This is done simply by adding files of the following formats to the database directory, typically `/usr/local/share/clamav` or `"C:\Program Files\ClamAV\database"`. Alternatively, `clamd` and `clamscan` can be instructed to load the database from an alternative database file or database directory manually using the `clamd` `DatabaseDirectory` config option or the `clamscan -d` command line option.

### Settings databases

ClamAV provides a handful of configuration related databases along side the signature definitions.

`*.cfg`: [Dynamic config settings](Signatures/DynamicConfig.md)

`*.cat` `*.crb`: [Trusted and revoked PE certs](Signatures/AuthenticodeRules.md)

`*.ftm`: [File Type Magic (FTM)](Signatures/FileTypeMagic.md)

### Signature databases

_Note_: Signature databases with an extension ending in `u` are only loaded when Potentially Unwanted Application (PUA) signatures are enabled (default: off).

#### Body-based Signatures

Body-based signature content is a definition that matches not based on a hash but based on the specific sequences of bytes exhibited by the target file.

ClamAV body-based signature content has a [special format](BodySignatureFormat.md) to allow regex-like matching of data that is not entirely known. This format is used extensively in both Extended Signatures and Logical Signatures.

`*.ndb` `*.ndu`: [Extended signatures](Signatures/ExtendedSignatures.md)

`*.ldb` `*.ldu`; `*.idb`: [Logical Signatures](Signatures/LogicalSignatures.md)

`*.cdb`: [Container Metadata Signatures](Signatures/ContainerMetadata.md)

`*.cbc`: [Bytecode Signatures](Signatures/BytecodeSignatures.md)

`*.pdb` `*.gdb` `*.wdb`: [Phishing URL Signatures](Signatures/PhishSigs.md)

#### Hash-based Signatures

`*.hdb` `*.hsb` `*.hdu` `*.hsu`: File hash signatures

`*.mdb` `*.msb` `*.mdu` `*.msu`: PE section hash signatures

[Hash-based Signature format](Signatures/HashSignatures.md)

#### Alternative signature support

`*.yar` `*.yara`: [Yara rules](Signatures/YaraRules.md)

### Other database files

`*.fp` `*.sfp` `*.ign` `*.ign2`: [Whitelisted files, signatures](Signatures/Whitelists.md)

`*.pwdb`: [Encrypted archive passwords](Signatures/EncryptedArchives.md)

`*.info`: [Database information](Signatures/DatabaseInfo.md)`

### Signature names

ClamAV uses the following prefixes for signature names:

- *Worm* for Internet worms
- *Trojan* for backdoor programs
- *Adware* for adware
- *Flooder* for flooders
- *HTML* for HTML files
- *Email* for email messages
- *IRC* for IRC trojans
- *JS* for Java Script malware
- *PHP* for PHP malware
- *ASP* for ASP malware
- *VBS* for VBS malware
- *BAT* for BAT malware
- *W97M*, *W2000M* for Word macro viruses
- *X97M*, *X2000M* for Excel macro viruses
- *O97M*, *O2000M* for generic Office macro viruses
- *DoS* for Denial of Service attack software
- *DOS* for old DOS malware
- *Exploit* for popular exploits
- *VirTool* for virus construction kits
- *Dialer* for dialers
- *Joke* for hoaxes

Important rules of the naming convention:

- always use a -zippwd suffix in the malware name for signatures of type zmd,
- always use a -rarpwd suffix in the malware name for signatures of type rmd,
- only use alphanumeric characters, dash (-), dot (.), underscores (_) in malware names, never use space, apostrophe or quote mark.

## Signature Writing Tips and Tricks

### Testing rules with `clamscan`

To test a new signature, first create a text file with the extension corresponding to the signature type (Ex: `.ldb` for logical signatures).  Then, add the signature as it's own line within the file. This file can be passed to `clamscan` via the `-d` option, which tells ClamAV to load signatures from the file specified.  If the signature is not formatted correctly, ClamAV will display an error - run `clamscan` with `--debug --verbose` to see additional information about the error message.  Some common causes of errors include:

- The signature file has the incorrect extension type for the signatures contained within
- The file has one or more blank lines
- For logical signatures, a semicolon exists at the end of the file

If the rule is formatted correctly, `clamscan` will load the signature(s) in and scan any files specified via the command line invocation (or all files in the current directory if none are specified).  A successful detection will look like the following:

```bash
clamscan -d test.ldb text.exe
test.exe: Win.Malware.Agent.UNOFFICIAL FOUND

----------- SCAN SUMMARY -----------
Known viruses: 1
Engine version: 0.100.0
Scanned directories: 0
Scanned files: 1
Infected files: 1
Data scanned: 17.45 MB
Data read: 17.45 MB (ratio 1.00:1)
Time: 0.400 sec (0 m 0 s)
```

If the rule did not match as intended:

- The file may have exceeded one or more of the default scanning limits built-in to ClamAV.  Try running `clamscan` with the following options to see if raising the limits addresses the issue: `--max-filesize=2000M --max-scansize=2000M --max-files=2000000 --max-recursion=2000000 --max-embeddedpe=2000M --max-htmlnormalize=2000000 --max-htmlnotags=2000000 --max-scriptnormalize=2000000 --max-ziptypercg=2000000 --max-partitions=2000000 --max-iconspe=2000000 --max-rechwp3=2000000 --pcre-match-limit=2000000 --pcre-recmatch-limit=2000000 --pcre-max-filesize=2000M`.
- If matching on HTML or text files, ClamAV might be performing normalization that causes the content of the scanned file to change.  See the [HTML](#html) and [Text file](#text-file) sections for more details.
- libclamav may have been unable to unpack or otherwise process the file.  See [Debug information from libclamav](#debug-information-from-libclamav) for more details.

NOTE: If you run `clamscan` with a `-d` flag, ClamAV will not load in the signatures downloaded via `freshclam`.  This means that:

- some of ClamAV's unpacking support might be disabled, since some unpackers are implemented as bytecode signatures
- PE whitelisting based on Authenticode signatures won't work, since this functionality relies on `.crb` rules

If any of this functionality is needed, load in the CVD files manually with additional `-d` flags.

### Debug information from libclamav

In order to create efficient signatures for ClamAV it’s important to understand how the engine handles input files. The best way to see how it works is having a look at the debug information from libclamav. You can do it by calling `clamscan` with the `--debug` and `--leave-temps` flags. The first switch makes `clamscan` display all the interesting information from libclamav and the second one avoids deleting temporary files so they can be analyzed further.

The now important part of the info is:

```bash
$ clamscan --debug attachment.exe
[...]
LibClamAV debug: Recognized MS-EXE/DLL file
LibClamAV debug: Matched signature for file type PE
LibClamAV debug: File type: Executable
```

The engine recognized a windows executable.

```bash
LibClamAV debug: Machine type: 80386
LibClamAV debug: NumberOfSections: 3
LibClamAV debug: TimeDateStamp: Fri Jan 10 04:57:55 2003
LibClamAV debug: SizeOfOptionalHeader: e0
LibClamAV debug: File format: PE
LibClamAV debug: MajorLinkerVersion: 6
LibClamAV debug: MinorLinkerVersion: 0
LibClamAV debug: SizeOfCode: 0x9000
LibClamAV debug: SizeOfInitializedData: 0x1000
LibClamAV debug: SizeOfUninitializedData: 0x1e000
LibClamAV debug: AddressOfEntryPoint: 0x27070
LibClamAV debug: BaseOfCode: 0x1f000
LibClamAV debug: SectionAlignment: 0x1000
LibClamAV debug: FileAlignment: 0x200
LibClamAV debug: MajorSubsystemVersion: 4
LibClamAV debug: MinorSubsystemVersion: 0
LibClamAV debug: SizeOfImage: 0x29000
LibClamAV debug: SizeOfHeaders: 0x400
LibClamAV debug: NumberOfRvaAndSizes: 16
LibClamAV debug: Subsystem: Win32 GUI
LibClamAV debug: ------------------------------------
LibClamAV debug: Section 0
LibClamAV debug: Section name: UPX0
LibClamAV debug: Section data (from headers - in memory)
LibClamAV debug: VirtualSize: 0x1e000 0x1e000
LibClamAV debug: VirtualAddress: 0x1000 0x1000
LibClamAV debug: SizeOfRawData: 0x0 0x0
LibClamAV debug: PointerToRawData: 0x400 0x400
LibClamAV debug: Section's memory is executable
LibClamAV debug: Section's memory is writeable
LibClamAV debug: ------------------------------------
LibClamAV debug: Section 1
LibClamAV debug: Section name: UPX1
LibClamAV debug: Section data (from headers - in memory)
LibClamAV debug: VirtualSize: 0x9000 0x9000
LibClamAV debug: VirtualAddress: 0x1f000 0x1f000
LibClamAV debug: SizeOfRawData: 0x8200 0x8200
LibClamAV debug: PointerToRawData: 0x400 0x400
LibClamAV debug: Section's memory is executable
LibClamAV debug: Section's memory is writeable
LibClamAV debug: ------------------------------------
LibClamAV debug: Section 2
LibClamAV debug: Section name: UPX2
LibClamAV debug: Section data (from headers - in memory)
LibClamAV debug: VirtualSize: 0x1000 0x1000
LibClamAV debug: VirtualAddress: 0x28000 0x28000
LibClamAV debug: SizeOfRawData: 0x200 0x1ff
LibClamAV debug: PointerToRawData: 0x8600 0x8600
LibClamAV debug: Section's memory is writeable
LibClamAV debug: ------------------------------------
LibClamAV debug: EntryPoint offset: 0x8470 (33904)
```

The section structure displayed above suggests the executable is packed
with UPX.

```bash
LibClamAV debug: ------------------------------------
LibClamAV debug: EntryPoint offset: 0x8470 (33904)
LibClamAV debug: UPX/FSG/MEW: empty section found - assuming
                 compression
LibClamAV debug: UPX: bad magic - scanning for imports
LibClamAV debug: UPX: PE structure rebuilt from compressed file
LibClamAV debug: UPX: Successfully decompressed with NRV2B
LibClamAV debug: UPX/FSG: Decompressed data saved in
                 /tmp/clamav-90d2d25c9dca42bae6fa9a764a4bcede
LibClamAV debug: ***** Scanning decompressed file *****
LibClamAV debug: Recognized MS-EXE/DLL file
LibClamAV debug: Matched signature for file type PE
```

Indeed, libclamav recognizes the UPX data and saves the decompressed
(and rebuilt) executable into
`/tmp/clamav-90d2d25c9dca42bae6fa9a764a4bcede`. Then it continues by
scanning this new file:

```bash
LibClamAV debug: File type: Executable
LibClamAV debug: Machine type: 80386
LibClamAV debug: NumberOfSections: 3
LibClamAV debug: TimeDateStamp: Thu Jan 27 11:43:15 2011
LibClamAV debug: SizeOfOptionalHeader: e0
LibClamAV debug: File format: PE
LibClamAV debug: MajorLinkerVersion: 6
LibClamAV debug: MinorLinkerVersion: 0
LibClamAV debug: SizeOfCode: 0xc000
LibClamAV debug: SizeOfInitializedData: 0x19000
LibClamAV debug: SizeOfUninitializedData: 0x0
LibClamAV debug: AddressOfEntryPoint: 0x7b9f
LibClamAV debug: BaseOfCode: 0x1000
LibClamAV debug: SectionAlignment: 0x1000
LibClamAV debug: FileAlignment: 0x1000
LibClamAV debug: MajorSubsystemVersion: 4
LibClamAV debug: MinorSubsystemVersion: 0
LibClamAV debug: SizeOfImage: 0x26000
LibClamAV debug: SizeOfHeaders: 0x1000
LibClamAV debug: NumberOfRvaAndSizes: 16
LibClamAV debug: Subsystem: Win32 GUI
LibClamAV debug: ------------------------------------
LibClamAV debug: Section 0
LibClamAV debug: Section name: .text
LibClamAV debug: Section data (from headers - in memory)
LibClamAV debug: VirtualSize: 0xc000 0xc000
LibClamAV debug: VirtualAddress: 0x1000 0x1000
LibClamAV debug: SizeOfRawData: 0xc000 0xc000
LibClamAV debug: PointerToRawData: 0x1000 0x1000
LibClamAV debug: Section contains executable code
LibClamAV debug: Section's memory is executable
LibClamAV debug: ------------------------------------
LibClamAV debug: Section 1
LibClamAV debug: Section name: .rdata
LibClamAV debug: Section data (from headers - in memory)
LibClamAV debug: VirtualSize: 0x2000 0x2000
LibClamAV debug: VirtualAddress: 0xd000 0xd000
LibClamAV debug: SizeOfRawData: 0x2000 0x2000
LibClamAV debug: PointerToRawData: 0xd000 0xd000
LibClamAV debug: ------------------------------------
LibClamAV debug: Section 2
LibClamAV debug: Section name: .data
LibClamAV debug: Section data (from headers - in memory)
LibClamAV debug: VirtualSize: 0x17000 0x17000
LibClamAV debug: VirtualAddress: 0xf000 0xf000
LibClamAV debug: SizeOfRawData: 0x17000 0x17000
LibClamAV debug: PointerToRawData: 0xf000 0xf000
LibClamAV debug: Section's memory is writeable
LibClamAV debug: ------------------------------------
LibClamAV debug: EntryPoint offset: 0x7b9f (31647)
LibClamAV debug: Bytecode executing hook id 257 (0 hooks)
attachment.exe: OK
[...]
```

No additional files get created by libclamav. By writing a signature for the decompressed file you have more chances that the engine will detect the target data when it gets compressed with another packer.

This method should be applied to all files for which you want to create signatures. By analyzing the debug information you can quickly see how the engine recognizes and preprocesses the data and what additional files get created. Signatures created for bottom-level temporary files are usually more generic and should help detecting the same malware in different forms.

### Writing signatures for special files

#### HTML

ClamAV contains HTML normalization code which makes it easier to write signatures for HTML data that might differ based on white space, capitalization, and other insignificant differences. Running `sigtool --html-normalise` on a HTML file can be used to see what a file's contents will look like after normalization.  This command should generate the following files:

- nocomment.html - the file is normalized, lower-case, with all comments and superfluous white space removed

- notags.html - as above but with all HTML tags removed

- javascript - any script contents are normalized and the results appended to this file

The code automatically decodes JScript.encode parts and char ref’s (e.g. `&#102;`). To create a successful signature for the input file type, the rule must match on the contents of one of the created files.  Signatures matching on normalized HTML should have a target type of 3.  For reference, see [Target Types](Signatures/FileTypes.md#Target-Types).

#### Text files

Similarly to HTML all ASCII text files get normalized (converted to lower-case, all superfluous white space and control characters removed, etc.) before scanning. Running `sigtool --ascii-normalise` on a text file will result in a normalized version being written to the file named 'normalised\_text'.  Rules matching on normalized ASCII text should have a target type of 7.  For reference, see [Target Types](Signatures/FileTypes.md#Target-Types).

#### Compressed Portable Executable files

If the file is compressed with UPX, FSG, Petite or another PE packer supported by libclamav, ClamAV will attempt to automatically unpack the executable and evaluate signatures against the unpacked executable.  To inspect the executable that results from ClamAV's unpacking process, run `clamscan` with `--debug --leave-temps`. Example output for a FSG compressed file:

```bash
LibClamAV debug: UPX/FSG/MEW: empty section found - assuming compression
LibClamAV debug: FSG: found old EP @119e0
LibClamAV debug: FSG: Unpacked and rebuilt executable saved in
/tmp/clamav-f592b20f9329ac1c91f0e12137bcce6c

```

In the example above, `/tmp/clamav-f592b20f9329ac1c91f0e12137bcce6c` is the unpacked executable, and a signature can be written based off of this file.

### Using `sigtool`

`sigtool` pulls in libclamav and provides shortcuts to doing tasks that `clamscan` does behind the scenes.  These can be really useful when writing a signature or trying to get information about a signature that might be causing FPs or performance problems.

The following `sigtool` flags can be especially useful for signature writing:

- `--md5` / `--sha1` / `--sha256`: Generate the MD5/SHA1/SHA256 hash and calculate the file size, outputting both as a properly-formatted `.hdb`/`.hsb` signature

- `--mdb`: Generate section hashes of the specified file.  This is useful when generating `.mdb` signatures.

- `--decode`: Given a ClamAV signature from STDIN, show a more user-friendly representation of it.  An example usage of this flag is `cat test.ldb | sigtool --decode`.

- `--hex-dump`: Given a sequence of bytes from STDIN, print the hex equivalent. An example usage of this flag is `echo -n "Match on this" | sigtool --hex-dump`.

- `--html-normalise`: Normalize the specified HTML file in the way that `clamscan` will before looking for rule matches.  Writing signatures off of these files makes it easier to write rules for target type HTML (you'll know what white space, capitalization, etc. to expect). See the [HTML](#html) section for more details.

- `--ascii-normalise`: Normalize the specified ASCII text file in the way that `clamscan` will before looking for rule matches. Writing signatures off of this normalized file data makes it easier to write rules for target type Txt (you'll know what white space, capitalization, etc. to expect). See the [Text files](#text-files) sectino for more details.

- `--print-certs`: Print the Authenticode signatures of any PE files specified.
  This is useful when writing signature-based `.crb` rule files.

- `--vba`: Extract VBA/Word6 macro code

- `--test-sigs`: Given a signature and a sample, determine whether the signature matches and, if so, display the offset into the file where the match occurred.  This can be useful for investigating false positive matches in clean files.

### Inspecting signatures inside a CVD file

CVD (ClamAV Virus Database) is a digitally signed container that includes signature databases in various text formats. The header of the container is a 512 bytes long string with colon separated fields:

```
ClamAV-VDB:build time:version:number of signatures:functionality level required:MD5 checksum:digital signature:builder name:build time (sec)
```

`sigtool --info` displays detailed information about a given CVD file:

```bash
zolw@localhost:/usr/local/share/clamav$ sigtool -i main.cvd
File: main.cvd
Build time: 09 Dec 2007 15:50 +0000
Version: 45
Signatures: 169676
Functionality level: 21
Builder: sven
MD5: b35429d8d5d60368eea9630062f7c75a
Digital signature: dxsusO/HWP3/GAA7VuZpxYwVsE9b+tCk+tPN6OyjVF/U8
JVh4vYmW8mZ62ZHYMlM903TMZFg5hZIxcjQB3SX0TapdF1SFNzoWjsyH53eXvMDY
eaPVNe2ccXLfEegoda4xU2TezbGfbSEGoU1qolyQYLX674sNA2Ni6l6/CEKYYh
Verification OK.
```

The ClamAV project distributes a number of CVD files, including `main.cvd` and `daily.cvd`.

To view the signature associated with a given detection name, the CVD files can be unpacked and the underlying text files searched for a rule definition using a tool like `grep`.  To do this, use `sigtool`'s `--unpack` flag as follows:

```bash
$ mkdir /tmp/clamav-sigs
$ cd /tmp/clamav-sigs/
$ sigtool --unpack /var/lib/clamav/main.cvd
$ ls
COPYING   main.fp   main.hsb   main.mdb  main.ndb
main.crb  main.hdb  main.info  main.msb  main.sfp
```

### External tools

Below are tools that can be helpful when writing ClamAV signatures:

- [CASC](https://github.com/Cisco-Talos/CASC) - CASC is a plugin for IDA Pro that allows the user to highlight sections of code and create a signature based on the underlying instructions (with options to ignore bytes associated with registers, addresses, and offsets).  It also contains SigAlyzer, a tool to take an existing signature and locate the regions within the binary that match the subsignatures.

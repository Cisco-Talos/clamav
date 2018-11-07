# File hash signatures

The easiest way to create signatures for ClamAV is to use filehash checksums, however this method can be only used against static malware.

## MD5 hash-based signatures

To create a MD5 signature for `test.exe` use the `--md5` option of
sigtool:

```bash
zolw@localhost:/tmp/test$ sigtool --md5 test.exe > test.hdb
zolw@localhost:/tmp/test$ cat test.hdb
48c4533230e1ae1c118c741c0db19dfb:17387:test.exe
```

That’s it! The signature is ready for use:

```bash
zolw@localhost:/tmp/test$ clamscan -d test.hdb test.exe
test.exe: test.exe FOUND

----------- SCAN SUMMARY -----------
Known viruses: 1
Scanned directories: 0
Engine version: 0.92.1
Scanned files: 1
Infected files: 1
Data scanned: 0.02 MB
Time: 0.024 sec (0 m 0 s)
```

You can change the name (by default sigtool uses the name of the file) and place it inside a `*.hdb` file. A single database file can include any number of signatures. To get them automatically loaded each time `clamscan`/`clamd` starts just copy the database file(s) into the local virus database directory (eg. `/usr/local/share/clamav`).

*The hash-based signatures shall not be used for text files, HTML and any other data that gets internally preprocessed before pattern matching. If you really want to use a hash signature in such a case, run `clamscan` with `--debug` and `--leave-temps` flags as described above and create a signature for a preprocessed file left in `/tmp`. Please keep in mind that a hash signature will stop matching as soon as a single byte changes in the target file.*

## SHA1 and SHA256 hash-based signatures

ClamAV 0.98 has also added support for SHA1 and SHA256 file checksums. The format is the same as for MD5 file checksum. It can differentiate between them based on the length of the hash string in the signature. For best backwards compatibility, these should be placed inside a `*.hsb` file. The format is:

```
HashString:FileSize:MalwareName
```

## Hash signatures with unknown size

ClamAV 0.98 has also added support for hash signatures where the size is not known but the hash is. It is much more performance-efficient to use signatures with specific sizes, so be cautious when using this feature. For these cases, the ’\*’ character can be used in the size field. To ensure proper backwards compatibility with older versions of ClamAV, these signatures must have a minimum functional level of 73 or higher. Signatures that use the wildcard size without this level set will be rejected as malformed.

Sample .hsb signature matching any size:
```
    HashString:*:MalwareName:73
```
Sample .msb signature matching any size:
```
    *:PESectionHash:MalwareName:73
```

## PE section based hash signatures

You can create a hash signature for a specific section in a PE file. Such signatures shall be stored inside `.mdb` (MD5) and `.msb` files in the following format:

```
    PESectionSize:PESectionHash:MalwareName
```

The easiest way to generate MD5 based section signatures is to extract target PE sections into separate files and then run sigtool with the option `--mdb`

ClamAV 0.98 has also added support for SHA1 and SHA256 section based signatures. The format is the same as for MD5 PE section based signatures. It can differentiate between them based on the length of the hash string in the signature. For best backwards compatibility, these should be placed inside a `*.msb` file.

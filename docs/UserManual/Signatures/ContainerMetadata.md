# Signatures based on container metadata

ClamAV 0.96 allows creating generic signatures matching files stored inside different container types which meet specific conditions. The signature format is:

```
    VirusName:ContainerType:ContainerSize:FileNameREGEX:
    FileSizeInContainer:FileSizeReal:IsEncrypted:FilePos:
    Res1:Res2[:MinFL[:MaxFL]]
```

where the corresponding fields are:

- `VirusName:` Virus name to be displayed when signature matches.

- `ContainerType:` The file type containing the target file.  For example:
  - `CL_TYPE_ZIP`,
  - `CL_TYPE_RAR`,
  - `CL_TYPE_ARJ`,
  - `CL_TYPE_MSCAB`,
  - `CL_TYPE_7Z`,
  - `CL_TYPE_MAIL`,
  - `CL_TYPE_(POSIX|OLD)_TAR`,
  - `CL_TYPE_CPIO_(OLD|ODC|NEWC|CRC)`

  Use `*` as a wild card to indicate that container type may be any file type.
  For a full list of ClamAV file types, see the [ClamAV File Types Reference](ClamAVFileTypes.md).

- `ContainerSize:` size of the container file itself (eg. size of the zip archive) specified in bytes as absolute value or range `x-y`.

- `FileNameREGEX:` regular expression describing name of the target file

- `FileSizeInContainer:` usually compressed size; for MAIL, TAR and CPIO == `FileSizeReal`; specified in bytes as absolute value or range.

- `FileSizeReal:` usually uncompressed size; for MAIL, TAR and CPIO == `FileSizeInContainer`; absolute value or range.

- `IsEncrypted:` 1 if the target file is encrypted, 0 if it’s not and `*` to ignore

- `FilePos:` file position in container (counting from 1); absolute value or range.

- `Res1:` when `ContainerType` is `CL_TYPE_ZIP` or `CL_TYPE_RAR` this field is treated as a CRC sum of the target file specified in hexadecimal format; for other container types it’s ignored.

- `Res2:` not used as of ClamAV 0.96.

The signatures for container files are stored inside `.cdb` files.

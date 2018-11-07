# ClamAV File Types

ClamAV maintains it's own file typing format and assigns these types using either:

- Evaluation of a unique sequence of bytes at the start of a file ([File Type Magic](Signatures/FileTypeMagic.md)).
- File type indicators when parsing container files.
  - For example:
    CL_TYPE_SCRIPT may be assigned to data contained in a PDF when the PDF indicates that a stream of bytes is "Javascript"
- File type determination based on the names or characteristics contained within the file.
  - For example:
    CL_TYPE_OOXML_WORD may be assigned to a Zip file containing files with specific names.

## Target Types

A Target Type is an integer that indicates which kind of file the signature will match against. Target Type notation was first created for the purposes writing efficient signatures. A signature with a target type of `0` will be run against every file type, and thus is not ideal. However, the Target Type notation is limited and it may be unavoidable.

Although the newer CL_TYPE string name notation has replaced the Target Type for some signature formats, many signature formats require a target type number.

This is the current list of available Targe Types:

- 0 = any file
- 1 = Portable Executable, both 32- and 64-bit.
- 2 = OLE2 containers, including their specific macros. The OLE2 format is primarily used by MS Office and MSI installation files.
- 3 = HTML (normalized)
- 4 = Mail file
- 5 = Graphics
- 6 = ELF
- 7 = ASCII text file (normalized)
- 8 = Unused
- 9 = Mach-O files
- 10 = PDF files
- 11 = Flash files
- 12 = Java class files

**_Important_: HTML, ASCII, Javascript are all normalized.

- ASCII:
  - All lowercase.
- HTML:
  - Whitespace transformed to spaces, tags/tag attributes normalized, all lowercase.
- Javascript:
  - All strings are normalized (hex encoding is decoded), numbers are parsed and normalized, local variables/function names are normalized to ’n001’ format, argument to eval() is parsed as JS again, unescape() is handled, some simple JS packers are handled, output is whitespace normalized.

## CL_TYPEs

ClamAV Types are prefixed with `CL_TYPE_`.  The following is an exhaustive list of all current CL_TYPE's.

| CL_TYPE                | Description                                                  |
|------------------------|--------------------------------------------------------------|
| `CL_TYPE_7Z`           | 7-Zip Archive                                                |
| `CL_TYPE_7ZSFX`        | Self-Extracting 7-Zip Archive                                |
| `CL_TYPE_APM`          | Disk Image - Apple Partition Map                             |
| `CL_TYPE_ARJ`          | ARJ Archive                                                  |
| `CL_TYPE_ARJSFX`       | Self-Extracting ARJ Archive                                  |
| `CL_TYPE_AUTOIT`       | AutoIt Automation Executable                                 |
| `CL_TYPE_BINARY_DATA`  | binary data                                                  |
| `CL_TYPE_BINHEX`       | BinHex Macintosh 7-bit ASCII email attachment encoding       |
| `CL_TYPE_BZ`           | BZip Compressed File                                         |
| `CL_TYPE_CABSFX`       | Self-Extracting Microsoft CAB Archive                        |
| `CL_TYPE_CPIO_CRC`     | CPIO Archive (CRC)                                           |
| `CL_TYPE_CPIO_NEWC`    | CPIO Archive (NEWC)                                          |
| `CL_TYPE_CPIO_ODC`     | CPIO Archive (ODC)                                           |
| `CL_TYPE_CPIO_OLD`     | CPIO Archive (OLD, Little Endian or Big Endian)              |
| `CL_TYPE_CRYPTFF`      | Files encrypted by CryptFF malware                           |
| `CL_TYPE_DMG`          | Apple DMG Archive                                            |
| `CL_TYPE_ELF`          | ELF Executable (Linux/Unix program or library)               |
| `CL_TYPE_GPT`          | Disk Image - GUID Partition Table                            |
| `CL_TYPE_GRAPHICS`     | TIFF (Little Endian or Big Endian)                           |
| `CL_TYPE_GZ`           | GZip Compressed File                                         |
| `CL_TYPE_HTML_UTF16`   | Wide-Character / UTF16 encoded HTML                          |
| `CL_TYPE_HTML`         | HTML data                                                    |
| `CL_TYPE_HWP3`         | Hangul Word Processor (3.X)                                  |
| `CL_TYPE_HWPOLE2`      | Hangul Word Processor embedded OLE2                          |
| `CL_TYPE_INTERNAL`     | Internal properties                                          |
| `CL_TYPE_ISHIELD_MSI`  | Windows Install Shield MSI installer                         |
| `CL_TYPE_ISO9660`      | ISO 9660 file system for optical disc media                  |
| `CL_TYPE_JAVA`         | Java Class File                                              |
| `CL_TYPE_LNK`          | Microsoft Windows Shortcut File                              |
| `CL_TYPE_MACHO_UNIBIN` | Universal Binary/Java Bytecode                               |
| `CL_TYPE_MACHO`        | Apple/NeXTSTEP Mach-O Executable file format                 |
| `CL_TYPE_MAIL`         | Email file                                                   |
| `CL_TYPE_MBR`          | Disk Image - Master Boot Record                              |
| `CL_TYPE_MHTML`        | MHTML Saved Web Page                                         |
| `CL_TYPE_MSCAB`        | Microsoft CAB Archive                                        |
| `CL_TYPE_MSCHM`        | Microsoft CHM help archive                                   |
| `CL_TYPE_MSEXE`        | Microsoft EXE / DLL Executable file                          |
| `CL_TYPE_MSOLE2`       | Microsoft OLE2 Container file                                |
| `CL_TYPE_MSSZDD`       | Microsoft Compressed EXE                                     |
| `CL_TYPE_NULSFT`       | NullSoft Scripted Installer program                          |
| `CL_TYPE_OLD_TAR`      | TAR archive (old)                                            |
| `CL_TYPE_OOXML_HWP`    | Hangul Office Open Word Processor (5.X)                      |
| `CL_TYPE_OOXML_PPT`    | Microsoft Office Open XML PowerPoint                         |
| `CL_TYPE_OOXML_WORD`   | Microsoft Office Open Word 2007+                             |
| `CL_TYPE_OOXML_XL`     | Microsoft Office Open Excel 2007+                            |
| `CL_TYPE_PART_HFSPLUS` | Apple HFS+ partition                                         |
| `CL_TYPE_PDF`          | Adobe PDF document                                           |
| `CL_TYPE_POSIX_TAR`    | TAR archive                                                  |
| `CL_TYPE_PS`           | Postscript                                                   |
| `CL_TYPE_RAR`          | RAR Archive                                                  |
| `CL_TYPE_RARSFX`       | Self-Extracting RAR Archive                                  |
| `CL_TYPE_RIFF`         | Resource Interchange File Format container formatted file    |
| `CL_TYPE_RTF`          | Rich Text Format document                                    |
| `CL_TYPE_SCRENC`       | Files encrypted by ScrEnc malware                            |
| `CL_TYPE_SCRIPT`       | Generic type for scripts (Javascript, Python, etc)           |
| `CL_TYPE_SIS`          | Symbian OS Software Installation Script Archive              |
| `CL_TYPE_SWF`          | Adobe Flash File (LZMA, Zlib, or uncompressed)               |
| `CL_TYPE_TEXT_ASCII`   | ASCII text                                                   |
| `CL_TYPE_TEXT_UTF16BE` | UTF-16BE text                                                |
| `CL_TYPE_TEXT_UTF16LE` | UTF-16LE text                                                |
| `CL_TYPE_TEXT_UTF8`    | UTF-8 text                                                   |
| `CL_TYPE_TNEF`         | Microsoft Outlook & Exchange email attachment format         |
| `CL_TYPE_UUENCODED`    | UUEncoded (Unix-to-Unix) binary file (Unix email attachment) |
| `CL_TYPE_XAR`          | XAR Archive                                                  |
| `CL_TYPE_XDP`          | Adobe XDP - Embedded PDF                                     |
| `CL_TYPE_XML_HWP`      | Hangul Word Processor XML (HWPML) Document                   |
| `CL_TYPE_XML_WORD`     | Microsoft Word 2003 XML Document                             |
| `CL_TYPE_XML_XL`       | Microsoft Excel 2003 XML Document                            |
| `CL_TYPE_XZ`           | XZ Archive                                                   |
| `CL_TYPE_ZIP`          | Zip Archive                                                  |
| `CL_TYPE_ZIPSFX`       | Self-Extracting Zip Archive                                  |

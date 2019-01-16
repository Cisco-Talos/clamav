# Functionality Levels (FLEVELs)

The Functionality Level (or FLEVEL) is an integer that signatures may use to define which versions of ClamAV the signature features support. It is up to the signature writers to select the correct FLEVEL or range of FLEVELs when writing a signature so that it does not cause failures in older versions of ClamAV.

Setting appropriate FLEVELs in signatures is particularly crucial when using features added in the last 3-4 major release versions.

## ClamAV Version to FLEVEL chart

| flevel | version | release | new signature features                                                 |
|--------|---------|---------|------------------------------------------------------------------------|
| 41     | 0.95.0  | 3/2009  | Ignores use ign format (including line number).                        |
| 51     | 0.96.0  | 3/2010  | Bytecode & CDB sigs. Start using ign2.                                 |
| 56     | 0.96.4  | 10/2010 | Min level for bytecode sigs.                                           |
| 60     | 0.97.0  | 2/2011  |                                                                        |
| 74     | 0.98.0  | 9/2013  | ISO9660 scanning support. All-match feature.                           |
|        |         |         | Wild card bracket notation{} for body-based signatures.                |
|        |         |         | "SE" offset modifier.                                                  |
|        |         |         | Target types 10 - 13: (PDF, (SWF) Flash, Java, Internal).              |
| 76     | 0.98.1  | 1/2014  | XZ support and ForceToDisk scan option.                                |
|        |         |         | Libxml2, XAR, DMG, HFS+/HFSX.                                          |
|        |         |         | FTM type 4 (in-buffer partition magic, analogous to type 0 for files). |
| 79     | 0.98.5  | 11/2014 | File properties (preclass). Target type 13: for preclass feature.      |
| 81     | 0.99.0  | 11/2015 | Yara and PCRE support. Target type 14: non-listed types ("other").     |
| 82     | 0.99.1  | 2/2016  | Hangul Word Processor (HWP) type file parser.                          |
| 90     | 0.100   | 4/2018  | "Intermediates" logical sig expression option.                         |
|        |         |         | MHTML and PostScript types.                                            |
|        |         |         | Substring wildcard (*) fix: order matters, substrings can't overlap.   |
| 100    | 0.101   | 12/2018 | "Byte-Compare" Logical subsignature. Windows Shortcut (LNK) type.      |

For more inforamtion on ClamAV file type support, see the [File Types Reference](FileTypes.md).

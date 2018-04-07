# Introduction

Clam AntiVirus is an open source (GPL) anti-virus toolkit for UNIX, designed especially for e-mail scanning on mail gateways. It provides a number of utilities including a flexible and scalable multi-threaded daemon, a command line scanner and advanced tool for automatic database updates. The core of the package is an anti-virus engine available in a form of shared library.

## Features

- Licensed under the GNU General Public License, Version 2
- POSIX compliant, portable
- Fast scanning
- Supports on-access scanning (Linux only)
- Detects over 1 million viruses, worms and trojans, including Microsoft Office macro viruses, mobile malware, and other threats
- Built-in bytecode interpreter allows the ClamAV signature writers to create and distribute very complex detection routines and remotely enhance the scanner’s functionality
- Scans within archives and compressed files (also protects against archive bombs), built-in support includes:
  - Zip (including SFX)
  - RAR (including SFX)
  - 7Zip
  - ARJ (including SFX)
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
  - MS Cabinet Files (including SFX)
  - MS CHM (Compiled HTML)
  - MS SZDD compression format
  - BinHex
  - SIS (SymbianOS packages)
  - AutoIt
  - InstallShield
- Supports Portable Executable (32/64-bit) files compressed or obfuscated with:
  - AsPack
  - UPX
  - FSG
  - Petite
  - PeSpin
  - NsPack
  - wwpack32
  - MEW
  - Upack
  - Y0da Cryptor
- Supports ELF and Mach-O files (both 32- and 64-bit)
- Supports almost all mail file formats
- Support for other special files/formats includes:
  - HTML
  - RTF
  - PDF
  - Files encrypted with CryptFF and ScrEnc
  - uuencode
  - TNEF (winmail.dat)
- Advanced database updater with support for scripted updates, digital signatures and DNS based database version queries

## Mailing lists and IRC channel

If you have a trouble installing or using ClamAV try asking on our mailing lists. There are four lists available:

- **clamav-announce\*lists.clamav.net** - info about new versions, moderated\[1\].
- **clamav-users\*lists.clamav.net** - user questions
- **clamav-devel\*lists.clamav.net** - technical discussions
- **clamav-virusdb\*lists.clamav.net** - database update announcements, moderated

You can subscribe and search the mailing list archives at: <https://www.clamav.net/contact.html#ml>

Alternatively you can try asking on the `#clamav` IRC channel - launch your favourite irc client and type:

```bash
    /server irc.freenode.net
    /join #clamav
```

## Virus submitting

If you have got a virus which is not detected by your ClamAV with the latest databases, please submit the sample at our website:

<https://www.clamav.net/reports/malware>
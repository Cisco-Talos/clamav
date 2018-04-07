# Introduction

Clam AntiVirus is an open source (GPLv2) anti-virus toolkit, designed especially for e-mail scanning on mail gateways.  It provides a number of utilities including a flexible and scalable multi-threaded daemon, a command line scanner and advanced tool for automatic database updates.  The core of the package is an anti-virus engine available in a form of shared library.

## Features

### Capabilities

- ClamAV is designed to scan files quickly.
- Real time protection (Linux only).  Our scanning daemon supports on-access scanning on modern versions of Linux, including the ability to block file access until a file has been scanned.
- ClamAV detects over 1 million viruses, worms and trojans, including Microsoft Office macro viruses, mobile malware, and other threats.
- The built-in bytecode interpreter allows the ClamAV signature writers to create and distribute very complex detection routines and remotely enhance the scanner’s functionality.
- Signed signature databases ensure that ClamAV will only execute trusted signature definitions.
- ClamAV scans within archives and compressed files but also protects against archive bombs.  Built-in archive extraction capabilities include:
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
- Supports Windows executable file parsing, also known as Portable Executables (PE) both 32/64-bit, including PE files that are compressed or obfuscated with:
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

### License

ClamAV is licensed under the GNU General Public License, Version 2

### Supported platforms

Clam AntiVirus is highly cross-platform.  The development team cannot test every OS, so we have chosen to test ClamAV using the two most recent Long Term Support (LTS) versions of each of the most popular desktop operating systems.  Our regularly tested operating systems include:

- GNU/Linux
  - Ubuntu
    - 14.04
    - 16.04
  - Debian
    - 7
    - 8
  - CentOS
    - 6
    - 7
- UNIX
  - Solaris
    - 10
    - 11
  - FreeBSD
    - 10
    - 11
  - macOS
    - 10.12 (Sierra)
    - 10.13 (High Sierra)
- Windows
  - 7
  - 10

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

## Submitting New or Otherwise Undetected Malware

If you've got a virus which is not detected by the current version of ClamAV using the latest signature databases, please submit the sample at our website:

<https://www.clamav.net/reports/malware>

Likewise, if you have a benign file that is flagging as a virus and you wish to report a False Positive, please submit the sample for reive at our website:

<https://www.clamav.net/reports/fp>
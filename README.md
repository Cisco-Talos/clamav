# ClamAV

<p align="center">
  <img width="250" height="250" src="https://raw.githubusercontent.com/Cisco-Talos/clamav/main/logo.png" alt='Maeve, the ClamAV mascot'>
</p>

<p align="center">
  ClamAV® is an open source antivirus engine for detecting trojans, viruses,
  malware & other malicious threats.
</p>

<p align="center">
  <a href="https://github.com/Cisco-Talos/clamav/actions"><img src="https://github.com/Cisco-Talos/clamav/workflows/CMake%20Build/badge.svg" height="18"></a>
  <a href="https://discord.gg/6vNAqWnVgw"><img src="https://img.shields.io/discord/636023333074370595.svg?logo=discord" height="18"/></a>
  <a href="https://twitter.com/clamav"><img src="https://abs.twimg.com/favicons/twitter.ico" width="18" height="18"></a>
</p>

## Documentation & FAQ

ClamAV documentation is hosted at [docs.clamav.net](https://docs.clamav.net/).
The source archive for each release also includes a copy of the documentation
for [offline](docs/html/index.html) reading.

You can contribute to the documentation by submitting improvements to
[Cisco-Talos/clamav-documentation](https://github.com/Cisco-Talos/clamav-documentation)

## ClamAV News

For information about the features in this and prior releases, read
[the news](NEWS.md).

Catch up on the latest about ClamAV by reading our
[blog](http://blog.clamav.net) and follow us on Twitter `@clamav`.

## ClamAV Signatures

Anyone can learn to read and write ClamAV signatures. To get started, see our
[signature writing manual](https://docs.clamav.net/manual/Signatures.html).

## Installation Instructions

### Using Docker

ClamAV can be run using Docker. For details, visit to the online manual under
["Docker"](https://docs.clamav.net/manual/Installing/Docker.html) and check out
our images on [Docker Hub](https://hub.docker.com/r/clamav/clamav).

### Using a Package Manager

For help installing from a package manager, refer to the online manual under
["Packages"](https://docs.clamav.net/manual/Installing/Packages.html).

### Using an Installer

The following install packages are available for download from
[clamav.net/downloads](https://www.clamav.net/downloads):

- Linux - Debian and RPM packages for x86_64 and i686. *New in v0.104.*
- macOS - PKG installer for x86_64 and arm64 (universal). *New in v0.104.*
- Windows - MSI installers and portable ZIP packages for win32 and x64.

To learn how to use these packages, refer to the online manual under
["Installing"](https://docs.clamav.net/manual/Installing.html#installing-with-an-installer).

### Build from Source

For step-by-step instructions, refer to the online manual:
- [Unix/Linux/Mac](https://docs.clamav.net/manual/Installing/Installing-from-source-Unix.html)
- [Windows](https://docs.clamav.net/manual/Installing/Installing-from-source-Windows.html)

The source archive for each release includes a copy of the documentation for
[offline](docs/html/UserManual.html) reading.

A reference with all of the available build options can be found in the
[INSTALL.md](INSTALL.md) file.

You can find additional advice for developers in the online manual under
["For Developers"](https://docs.clamav.net/manual/Development.html).

### Upgrading from a previous version

Visit [the FAQ](https://docs.clamav.net/faq/faq-upgrade.html) for tips on how
to upgrade from a previous version.

## Join the ClamAV Community

The best way to get in touch with the ClamAV community is to join our
[mailing lists](https://docs.clamav.net/faq/faq-ml.html).

You can also join the community on our
[ClamAV Discord chat server](https://discord.gg/6vNAqWnVgw).

## Want to make a contribution?

The ClamAV development team welcomes
[code contributions](https://github.com/Cisco-Talos/clamav),
improvements to
[our documentation](https://github.com/Cisco-Talos/clamav-documentation),
and also [bug reports](https://github.com/Cisco-Talos/clamav/issues).

Thanks for joining us!

## Licensing

ClamAV is licensed for public/open source use under the GNU General Public
License, Version 2 (GPLv2).

See `COPYING.txt` for a copy of the license.

### 3rd Party Code

ClamAV contains a number of components that include code copied in part or in
whole from 3rd party projects and whose code is not owned by Cisco and which
are licensed differently than ClamAV. These include:

- Yara: Apache 2.0 license
  - Yara has since switched to the BSD 3-Clause License;
    Our source is out-of-date and needs to be updated.
- 7z / lzma: public domain
- libclamav's NSIS/NulSoft parser includes:
  - zlib: permissive free software license
  - bzip2 / libbzip2: BSD-like license
- OpenBSD's libc/regex: BSD license
- file: BSD license
- str.c: Contains BSD licensed modified-implementations of strtol(), stroul()
  functions, Copyright (c) 1990 The Regents of the University of California.
- pngcheck (png.c): MIT/X11-style license
- getopt.c: MIT license
- Curl: license inspired by MIT/X, but not identical
- libmspack: LGPL license
- UnRAR (libclamunrar): a non-free/restricted open source license
  - Note: The UnRAR license is incompatible with GPLv2 because it contains a
    clause that prohibits reverse engineering a RAR compression algorithm from
    the UnRAR decompression code.
    For this reason, libclamunrar/libclamunrar_iface is not linked at all with
    libclamav. It is instead loaded at run-time. If it fails to load, ClamAV
    will continue running without RAR support.

See the `COPYING` directory for a copy of the 3rd party project licenses.

## Acknowledgements

Credit for contributions to each release can be found in the [News](NEWS.md).

ClamAV is brought to you by
[the ClamAV Team](https://www.clamav.net/about.html#credits)

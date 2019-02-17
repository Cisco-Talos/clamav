#
#  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
#  Copyright (C) 2007-2013 Sourcefire, Inc.
#  Copyright (C) 2002-2007 Tomasz Kojm <tkojm@clamav.net>
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#  MA 02110-1301, USA.

ACLOCAL_AMFLAGS=-I m4

SUBDIRS = libltdl libclamav clamscan clamd clamdscan freshclam sigtool clamconf database docs etc clamav-milter test clamdtop clambc unit_tests
EXTRA_DIST = examples shared libclamav.pc.in COPYING.bzip2 COPYING.lzma COPYING.unrar COPYING.LGPL COPYING.llvm COPYING.file COPYING.zlib COPYING.getopt COPYING.regex COPYING.YARA COPYING.pcre platform.h.in libclamunrar libclamunrar_iface libclammspack clamdscan/clamdscan.map win32 ChangeLog.md INSTALL.md NEWS.md README.md

bin_SCRIPTS=clamav-config

if ENABLE_CLAMSUBMIT
SUBDIRS += clamsubmit
endif

if ENABLE_LIBFRESHCLAM
SUBDIRS += libfreshclam
endif

if ENABLE_FUZZ
SUBDIRS += fuzz
endif

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libclamav.pc

nodist_include_HEADERS = clamav-types.h

# don't complain that configuration files and databases are not removed, this is intended
distuninstallcheck_listfiles = find . -type f ! -name clamd.conf ! -name freshclam.conf ! -name daily.cvd ! -name main.cvd -print
DISTCLEANFILES = target.h
DISTCHECK_CONFIGURE_FLAGS=--enable-milter --disable-clamav --enable-all-jit-targets --enable-llvm=yes --with-system-llvm=no --with-systemdsystemunitdir=$$dc_install_base/$(systemdsystemunitdir) CC="$(CC)" CXX="$(CXX)" YACC="$(YACC)" LEX="$(LEX)" AR="$(AR)" AS="$(AS)"
lcov:
	($(MAKE); cd unit_tests; $(MAKE) lcov)
quick-check:
	($(MAKE); cd unit_tests; $(MAKE) quick-check)
fuzz-all:
	($(MAKE); cd fuzz; $(MAKE) all)
fuzz-check:
	($(MAKE); cd fuzz; $(MAKE) check)

dist-hook:
	rm -rf $(distdir)/win32/clamav-for-windows $(distdir)/win32/build

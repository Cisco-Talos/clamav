#
#  Copyright (C) 2002 - 2004 Tomasz Kojm <tkojm@clamav.net>
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
EXTRA_DIST = FAQ examples BUGS shared libclamav.pc.in libclamunrar_iface/Makefile.am libclamunrar_iface/Makefile.in UPGRADE COPYING.bzip2 COPYING.lzma COPYING.unrar COPYING.LGPL COPYING.llvm COPYING.file COPYING.zlib COPYING.getopt COPYING.regex COPYING.sha256 platform.h.in clamdscan/clamdscan.map win32

bin_SCRIPTS=clamav-config

if ENABLE_CLAMSUBMIT
SUBDIRS += clamsubmit
endif

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libclamav.pc

# don't complain that configuration files and databases are not removed, this is intended
distuninstallcheck_listfiles = find . -type f ! -name clamd.conf ! -name freshclam.conf ! -name daily.cvd ! -name main.cvd -print
DISTCLEANFILES = target.h
DISTCHECK_CONFIGURE_FLAGS=--enable-milter --disable-clamav --enable-all-jit-targets --enable-llvm=yes
lcov:
	($(MAKE); cd unit_tests; $(MAKE) lcov)
quick-check:
	($(MAKE); cd unit_tests; $(MAKE) quick-check)

dist-hook:
	rm -rf $(distdir)/win32/clamav-for-windows $(distdir)/win32/build

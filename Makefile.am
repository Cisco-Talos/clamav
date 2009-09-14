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

SUBDIRS = libltdl libclamav clamscan clamd clamdscan freshclam sigtool clamconf database docs etc clamav-milter test unit_tests clamdtop
EXTRA_DIST = FAQ examples BUGS shared libclamav.pc.in libclamunrar_iface/Makefile.am libclamunrar_iface/Makefile.in UPGRADE COPYING.bzip2 COPYING.lzma COPYING.unrar COPYING.LGPL COPYING.file COPYING.zlib COPYING.getopt COPYING.regex COPYING.sha256

bin_SCRIPTS=clamav-config

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libclamav.pc

# don't complain that configuration files and databases are not removed, this is intended
distuninstallcheck_listfiles = find . -type f ! -name clamd.conf ! -name freshclam.conf ! -name daily.cvd ! -name main.cvd -print
DISTCLEANFILES = target.h
if DISTCHECK_ENABLE_FLAGS
DISTCHECK_CONFIGURE_FLAGS=--enable-milter --disable-clamav CFLAGS="-Wno-pointer-sign -Werror-implicit-function-declaration -Werror -Wextra -Wall -Wbad-function-cast -Wcast-align -Wendif-labels -Wfloat-equal -Wformat=2 -Wformat-security -Wmissing-declarations -Wmissing-prototypes -Wno-error=missing-prototypes -Wnested-externs -Wno-error=nested-externs -Wpointer-arith -Wstrict-prototypes -Wno-error=strict-prototypes -Wno-switch -Wno-switch-enum -Wundef -Wwrite-strings -Wstrict-overflow=1 -Winit-self -Wmissing-include-dirs -Wstrict-aliasing -Wdeclaration-after-statement -Waggregate-return -Wmissing-format-attribute -Wno-error=missing-format-attribute -Wno-error=type-limits -Wno-error=unused-value -Wno-error=unused-variable -Wcast-qual -Wno-error=cast-qual -Wno-error=sign-compare -Wshadow -Wno-error=shadow -Wno-error=uninitialized -fdiagnostics-show-option -Wno-unused-parameter -Wno-error=unreachable-code -Winvalid-pch -Wno-error=invalid-pch -O2 -D_FORTIFY_SOURCE=2 -fstack-protector-all -Wstack-protector -Wno-error=aggregate-return"
else
DISTCHECK_CONFIGURE_FLAGS=--enable-milter --disable-clamav
endif
lcov:
	($(MAKE); cd unit_tests; $(MAKE) lcov)
quick-check:
	($(MAKE); cd unit_tests; $(MAKE) quick-check)

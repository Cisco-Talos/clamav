#
#  Copyright (C) 2014 Sourcefire, Inc
#  Author: Shawn Webb
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License version 2 as
#  published by the Free Software Foundation.
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

bin_PROGRAMS = clamsubmit

clamsubmit_SOURCES = \
	clamsubmit.c

AM_CFLAGS=@WERR_CFLAGS@ @CLAMSUBMIT_CFLAGS@
DEFS = @DEFS@
AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/shared -I$(top_srcdir)/libclamav -I$(top_builddir)/libclamav -I$(top_srcdir)/libclamunrar_iface @SSL_CPPFLAGS@ @JSON_CPPFLAGS@ @PCRE_CPPFLAGS@
LIBS = $(top_builddir)/libclamav/libclamav.la $(top_builddir)/shared/libshared.la  @CLAMSUBMIT_LIBS@ @THREAD_LIBS@ @JSON_LIBS@ @SSL_LIBS@

if MACOS
AM_LDFLAGS = -framework CoreFoundation -framework Security
endif

AM_LIBTOOLFLAGS = --tag CXX

AM_INSTALLCHECK_STD_OPTIONS_EXEMPT=clamsubmit$(EXEEXT)
CLEANFILES=*.gcda *.gcno

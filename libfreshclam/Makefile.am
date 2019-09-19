#
#  Copyright (C) 2015-2019 Cisco Systems
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

libfreshclam_la_LIBADD = $(top_builddir)/libclamav/libclamav.la @FRESHCLAM_LIBS@ @ZLIB_LIBS@ @CURL_LIBS@ @SSL_LIBS@ @JSON_LIBS@ @LIBLTDL@ @THREAD_LIBS@ @LIBM@
libfreshclam_la_DEPENDENCIES = @LTDLDEPS@
libfreshclam_la_LDFLAGS = @CURL_LDFLAGS@ @SSL_LDFLAGS@ @TH_SAFE@ @JSON_LDFLAGS@ @LIBICONV@ $(XML_LIBS) -version-info @LIBFRESHCLAM_VERSION@ -no-undefined

if MACOS
libfreshclam_la_LDFLAGS += -framework CoreFoundation -framework Security
endif

if VERSIONSCRIPT
libfreshclam_la_LDFLAGS += -Wl,@VERSIONSCRIPTFLAG@,@top_srcdir@/libfreshclam/libfreshclam.map
endif

AM_LIBTOOLFLAGS = --tag CXX

EXTRA_DIST = libfreshclam.map

include_HEADERS = libfreshclam.h

libfreshclam_la_SOURCES = \
    $(top_srcdir)/shared/output.c \
    $(top_srcdir)/shared/output.h \
    $(top_srcdir)/shared/optparser.c \
    $(top_srcdir)/shared/optparser.h \
    $(top_srcdir)/shared/getopt.c \
    $(top_srcdir)/shared/getopt.h \
    $(top_srcdir)/shared/misc.c \
    $(top_srcdir)/shared/misc.h \
    $(top_srcdir)/shared/cdiff.c \
    $(top_srcdir)/shared/cdiff.h \
    $(top_srcdir)/shared/tar.c \
    $(top_srcdir)/shared/tar.h \
    $(top_srcdir)/shared/cert_util.c \
    $(top_srcdir)/shared/cert_util.h \
    $(top_srcdir)/shared/cert_util_internal.h \
    libfreshclam.c \
    libfreshclam_internal.c \
    libfreshclam_internal.h \
    dns.c \
    dns.h

if MACOS
    libfreshclam_la_SOURCES += \
        $(top_srcdir)/shared/mac/cert_util_mac.m \
        $(top_srcdir)/shared/cert_util.h
endif
if WINDOWS
    libfreshclam_la_SOURCES += \
        $(top_srcdir)/shared/win/cert_util_win.c \
        $(top_srcdir)/shared/cert_util.h
endif
if LINUX
    libfreshclam_la_SOURCES += \
        $(top_srcdir)/shared/linux/cert_util_linux.c \
        $(top_srcdir)/shared/cert_util.h
endif

lib_LTLIBRARIES = libfreshclam.la


AM_CFLAGS=@WERR_CFLAGS@
DEFS = @DEFS@ -DCL_NOTHREADS
AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/shared -I$(top_srcdir)/libclamav @CURL_CPPFLAGS@ @SSL_CPPFLAGS@ @FRESHCLAM_CPPFLAGS@ @ZLIB_CFLAGS@ @JSON_CPPFLAGS@ @PCRE_CPPFLAGS@

CLEANFILES=*.gcda *.gcno

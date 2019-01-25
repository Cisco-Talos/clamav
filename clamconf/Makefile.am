#
#  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
#  Copyright (C) 2007-2013 Sourcefire, Inc.
#  Copyright (C) 2006-2007 Tomasz Kojm <tkojm@clamav.net>
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

bin_PROGRAMS = clamconf

clamconf_SOURCES = \
    $(top_srcdir)/shared/optparser.c \
    $(top_srcdir)/shared/optparser.h \
    $(top_srcdir)/shared/getopt.c \
    $(top_srcdir)/shared/getopt.h \
    $(top_srcdir)/shared/misc.c \
    $(top_srcdir)/shared/misc.h \
    clamconf.c

AM_CFLAGS=@WERR_CFLAGS@ @SSL_CPPFLAGS@

DEFS = @DEFS@ -DCL_NOTHREADS
AM_CPPFLAGS = @CLAMCONF_CPPFLAGS@ -I$(top_srcdir) -I$(top_srcdir)/shared -I$(top_srcdir)/libclamav\
	      @JSON_CPPFLAGS@ @PCRE_CPPFLAGS@\
	      -DBUILD_CPPFLAGS="\"$(CPPFLAGS)\"" -DBUILD_CFLAGS="\"$(CFLAGS)\""\
	      -DBUILD_CXXFLAGS="\"$(CXXFLAGS)\"" -DBUILD_LDFLAGS="\"$(LDFLAGS)\""\
	      -DBUILD_CONFIGURE_FLAGS="\"$(BUILD_CONFIGURE_FLAGS)\""
LIBS = $(top_builddir)/libclamav/libclamav.la @CLAMCONF_LIBS@ @CLAMD_LIBS@ @THREAD_LIBS@ @LIBCLAMAV_LIBS@
CLEANFILES=*.gcda *.gcno

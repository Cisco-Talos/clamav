#  Copyright (C) 2013-2022 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
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

bin_PROGRAMS = clamdscan

clamdscan_SOURCES = \
    clamdscan.c \
    proto.c \
    proto.h \
    client.c \
    client.h

AM_CFLAGS=@WERR_CFLAGS@

AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/clamscan -I$(top_srcdir)/shared -I$(top_srcdir)/libclamav -I$(top_builddir)/libclamav -I$(top_srcdir)/libclamunrar_iface @SSL_CPPFLAGS@ @CLAMDSCAN_CPPFLAGS@ @JSON_CPPFLAGS@ @PCRE_CPPFLAGS@
LIBS = $(top_builddir)/shared/libshared.la $(top_builddir)/libclamav/libclamav.la @CLAMDSCAN_LIBS@ @THREAD_LIBS@

AM_INSTALLCHECK_STD_OPTIONS_EXEMPT=clamdscan$(EXEEXT)
CLEANFILES=*.gcda *.gcno

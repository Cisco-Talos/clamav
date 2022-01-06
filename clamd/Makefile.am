#
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

sbin_PROGRAMS = clamd

clamd_SOURCES = \
    clamd.c \
    tcpserver.c \
    tcpserver.h \
    localserver.c \
    localserver.h \
    session.c \
    session.h \
    thrmgr.c \
    thrmgr.h \
    server-th.c \
    server.h \
    scanner.c \
    scanner.h \
    clamd_others.c \
    clamd_others.h \
    shared.h

AM_CFLAGS=@WERR_CFLAGS@

if INSTALL_SYSTEMD_UNITS
systemdsystemunit_DATA = clamav-daemon.socket clamav-daemon.service
endif

LIBS = $(top_builddir)/libclamav/libclamav.la $(top_builddir)/shared/libshared.la @CLAMD_LIBS@ @THREAD_LIBS@
AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/shared -I$(top_srcdir)/libclamav -I$(top_builddir)/libclamav -I$(top_srcdir)/libclamunrar_iface @SSL_CPPFLAGS@ @JSON_CPPFLAGS@ @PCRE_CPPFLAGS@

# it does support --help and --version but with the default config file
# it outputs an error message which tells us to edit the config files
AM_INSTALLCHECK_STD_OPTIONS_EXEMPT=clamd$(EXEEXT)
CLEANFILES=*.gcda *.gcno

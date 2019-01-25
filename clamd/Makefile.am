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

if BUILD_CLAMD

sbin_PROGRAMS = clamd

clamd_SOURCES = \
    $(top_srcdir)/shared/output.c \
    $(top_srcdir)/shared/output.h \
    $(top_srcdir)/shared/idmef_logging.c \
    $(top_srcdir)/shared/idmef_logging.h \
    $(top_srcdir)/shared/optparser.c \
    $(top_srcdir)/shared/optparser.h \
    $(top_srcdir)/shared/getopt.c \
    $(top_srcdir)/shared/getopt.h \
    $(top_srcdir)/shared/misc.c \
    $(top_srcdir)/shared/misc.h \
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
    others.c \
    others.h \
    shared.h \
    onaccess_others.c \
    onaccess_others.h \
    onaccess_fan.c \
    onaccess_fan.h \
    onaccess_ddd.c \
    onaccess_ddd.h \
    onaccess_hash.c \
    onaccess_hash.h \
    onaccess_scth.c \
    onaccess_scth.h \
    priv_fts.h

if !SYSTEM_LFS_FTS
clamd_SOURCES += fts.c
endif

AM_CFLAGS=@WERR_CFLAGS@

if INSTALL_SYSTEMD_UNITS
systemdsystemunit_DATA = clamav-daemon.socket clamav-daemon.service
endif

endif

LIBS = $(top_builddir)/libclamav/libclamav.la @CLAMD_LIBS@ @THREAD_LIBS@
AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/shared -I$(top_srcdir)/libclamav @SSL_CPPFLAGS@ @JSON_CPPFLAGS@ @PCRE_CPPFLAGS@

# it does support --help and --version but with the default config file
# it outputs an error message which tells us to edit the config files
AM_INSTALLCHECK_STD_OPTIONS_EXEMPT=clamd$(EXEEXT)
CLEANFILES=*.gcda *.gcno

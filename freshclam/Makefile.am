#
#  Copyright (C) 2002 - 2004 Tomasz Kojm <tkojm@clamav.net>
#  Fixes - Arkadiusz Miskiewicz <misiek@pld.org.pl>
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

bin_PROGRAMS = freshclam

freshclam_SOURCES = \
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
    $(top_srcdir)/shared/clamdcom.c \
    $(top_srcdir)/shared/clamdcom.h \
    freshclam.c \
    freshclamcodes.h \
    manager.c \
    manager.h \
    notify.c \
    notify.h \
    dns.c \
    dns.h \
    execute.c \
    execute.h \
    nonblock.c \
    nonblock.h \
    mirman.c \
    mirman.h

AM_CFLAGS=@WERR_CFLAGS@
DEFS = @DEFS@ -DCL_NOTHREADS
AM_CPPFLAGS = @SSL_CPPFLAGS@ -I$(top_srcdir) -I$(top_srcdir)/shared -I$(top_srcdir)/libclamav @FRESHCLAM_CPPFLAGS@
LIBS = @SSL_LDFLAGS@ @SSL_LIBS@ $(top_builddir)/libclamav/libclamav.la @FRESHCLAM_LIBS@ @THREAD_LIBS@

AM_INSTALLCHECK_STD_OPTIONS_EXEMPT=freshclam$(EXEEXT)
CLEANFILES=*.gcda *.gcno

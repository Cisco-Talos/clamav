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
    $(top_srcdir)/shared/clamdcom.c \
    $(top_srcdir)/shared/clamdcom.h \
	$(top_srcdir)/freshclam/freshclamcodes.h \
	$(top_srcdir)/freshclam/manager.c \
	$(top_srcdir)/freshclam/manager.h \
	$(top_srcdir)/freshclam/notify.c \
	$(top_srcdir)/freshclam/notify.h \
	$(top_srcdir)/freshclam/dns.c \
	$(top_srcdir)/freshclam/dns.h \
	$(top_srcdir)/freshclam/execute.c \
	$(top_srcdir)/freshclam/execute.h \
	$(top_srcdir)/freshclam/nonblock.c \
	$(top_srcdir)/freshclam/nonblock.h \
	$(top_srcdir)/freshclam/mirman.c \
	$(top_srcdir)/freshclam/mirman.h \
	libfreshclam.c \
	libfreshclam.h

lib_LTLIBRARIES = libfreshclam.la


AM_CFLAGS=@WERR_CFLAGS@
DEFS = @DEFS@ -DCL_NOTHREADS
AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/shared -I$(top_srcdir)/libclamav @SSL_CPPFLAGS@ @FRESHCLAM_CPPFLAGS@  @JSON_CPPFLAGS@

CLEANFILES=*.gcda *.gcno

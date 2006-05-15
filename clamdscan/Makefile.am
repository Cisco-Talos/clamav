#
#  Copyright (C) 2002 - 2006 Tomasz Kojm <tkojm@clamav.net>
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

bin_PROGRAMS = clamdscan

clamdscan_SOURCES = \
    $(top_srcdir)/shared/output.c \
    $(top_srcdir)/shared/output.h \
    $(top_srcdir)/shared/cfgparser.c \
    $(top_srcdir)/shared/cfgparser.h \
    $(top_srcdir)/shared/memory.c \
    $(top_srcdir)/shared/memory.h \
    $(top_srcdir)/shared/misc.c \
    $(top_srcdir)/shared/misc.h \
    $(top_srcdir)/shared/getopt.c \
    $(top_srcdir)/shared/getopt.h \
    $(top_srcdir)/shared/options.c \
    $(top_srcdir)/shared/options.h \
    clamdscan.c \
    client.c \
    client.h \
    defaults.h

endif

DEFS = @DEFS@ -DCL_NOTHREADS
INCLUDES = -I$(top_srcdir)/clamscan -I$(top_srcdir)/shared -I$(top_srcdir)/libclamav
LIBS = $(top_builddir)/libclamav/libclamav.la @FRESHCLAM_LIBS@ @ADDITIONAL_LIBS@

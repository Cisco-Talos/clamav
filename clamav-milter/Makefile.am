#
#  Copyright (C) 2003 - 2004 Tomasz Kojm <tkojm@clamav.net>
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
#  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

# FIXME: check automake for 'and' (&&)
if BUILD_CLAMD
if HAVE_MILTER

sbin_PROGRAMS = clamav-milter

clamav_milter_SOURCES = \
    $(top_srcdir)/shared/cfgparser.c \
    $(top_srcdir)/shared/cfgparser.h \
    $(top_srcdir)/shared/getopt.c \
    $(top_srcdir)/shared/getopt.h \
    $(top_srcdir)/shared/memory.c \
    $(top_srcdir)/shared/memory.h \
    clamav-milter.c

man_MANS = $(top_srcdir)/docs/man/clamav-milter.8

endif
endif

AM_CFLAGS = -DSENDMAIL_BIN=\"$(SENDMAIL)\"
LIBS = $(top_builddir)/libclamav/libclamav.la @CLAMAV_MILTER_LIBS@
INCLUDES = -I$(top_srcdir)/clamd -I$(top_srcdir)/libclamav -I$(top_srcdir)/shared
EXTRA_DIST = clamav-milter.c INSTALL

#
#  Copyright (C) 2003 Tomasz Kojm <zolw@konarski.edu.pl>
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
if USE_PTHREAD
if HAVE_MILTER

sbin_PROGRAMS = clamav-milter

clamav_milter_SOURCES = clamav-milter.c

clamav_milter_LDADD = ../clamd/cfgfile.o ../clamd/others.o ../clamscan/getopt.o

man_MANS = ../docs/clamav-milter.1

endif
endif

DEFS = @DEFS@
# CLAMD_LIBS is used, because clamav-milter requires the same libraries as clamd
LIBS = -L../libclamav -L/usr/lib/libmilter -lmilter @CLAMD_LIBS@
INCLUDES = -I../clamd -I../libclamav -I../clamscan
EXTRA_DIST = clamav-milter.c clamd.sh clamav-milter.sh INSTALL

#
#  Copyright (C) 2002 Tomasz Kojm <zolw@konarski.edu.pl>
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

if BUILD_CLAMD

sbin_PROGRAMS = clamd

clamd_SOURCES = \
    options.c \
    options.h \
    cfgfile.c \
    cfgfile.h \
    clamd.c \
    defaults.h \
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
    clamuko.c \
    clamuko.h \
    dazukoio_compat12.c \
    dazukoio_compat12.h \
    dazukoio.c \
    dazukoio.h \
    dazuko_xp.h \
    dazukoio_xp.h \
    tests.c \
    tests.h

clamd_LDADD = ../clamscan/getopt.o

endif

DEFS = @DEFS@
LIBS = -L../libclamav -lclamav @CLAMD_LIBS@
INCLUDES = -I../clamscan -I../libclamav

#
#  Copyright (C) 2002 Tomasz Kojm <zolw@konarski.edu.pl>
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
#  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

bin_PROGRAMS = freshclam

freshclam_SOURCES = \
    freshclam.c \
    freshclam.h \
    options.c \
    manager.c \
    manager.h \
    defaults.h \
    notify.c \
    notify.h \
    cfgfile.c

freshclam_LDADD = ../clamscan/getopt.o ../clamscan/others.o

DEFS = @DEFS@
INCLUDES = -I../clamscan -I../clamd -I../libclamav
LIBS = -L../libclamav -lclamav @FRESHCLAM_LIBS@

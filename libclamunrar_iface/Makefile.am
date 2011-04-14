#
#  Copyright (C) 2002 - 2007 Tomasz Kojm <tkojm@clamav.net>
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

AM_CPPFLAGS = -I$(top_srcdir) $(LTDLINCL)
AM_CFLAGS = @WERR_CFLAGS@
EXTRA_DIST =
EXTRA_DIST += @top_srcdir@/libclamunrar/libclamunrar.map @top_srcdir@/libclamunrar_iface/libclamunrar_iface.map
if ENABLE_UNRAR

libclamunrar_la_LDFLAGS = @TH_SAFE@ -version-info @LIBCLAMAV_VERSION@ -no-undefined

if VERSIONSCRIPT
libclamunrar_la_LDFLAGS += -Wl,@VERSIONSCRIPTFLAG@,@top_srcdir@/libclamunrar/libclamunrar.map
endif

libclamunrar_la_SOURCES = \
	../libclamunrar/unrar15.c \
	../libclamunrar/unrar20.h \
	../libclamunrar/unrar.h \
	../libclamunrar/unrar15.h \
	../libclamunrar/unrar.c \
	../libclamunrar/unrar20.c \
	../libclamunrar/unrarcmd.h \
	../libclamunrar/unrarfilter.h \
	../libclamunrar/unrarppm.c \
	../libclamunrar/unrarvm.c \
	../libclamunrar/unrarcmd.c \
	../libclamunrar/unrarfilter.c \
	../libclamunrar/unrar.h \
	../libclamunrar/unrarppm.h \
	../libclamunrar/unrarvm.h \
	../libclamunrar/unrarhlp.c \
	../libclamunrar/unrarhlp.h

lib_LTLIBRARIES = libclamunrar.la
libclamunrar_iface_la_LIBADD = libclamunrar.la
libclamunrar_iface_la_LDFLAGS = -module @TH_SAFE@ -version-info @LIBCLAMAV_VERSION@ -no-undefined

if VERSIONSCRIPT
libclamunrar_iface_la_LDFLAGS += -Wl,@VERSIONSCRIPTFLAG@,@top_srcdir@/libclamunrar_iface/libclamunrar_iface.map
endif

libclamunrar_iface_la_SOURCES = \
	../libclamunrar_iface/unrar_iface.c \
	../libclamunrar_iface/unrar_iface.h

lib_LTLIBRARIES += libclamunrar_iface.la
endif

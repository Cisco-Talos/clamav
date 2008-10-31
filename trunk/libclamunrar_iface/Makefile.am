#
#  Copyright (C) 2007 Sourcefire, Inc.
#

if ENABLE_UNRAR

AM_CPPFLAGS = -I$(top_srcdir)

libclamunrar_iface_la_LIBADD = $(top_builddir)/libclamunrar/libclamunrar.la

libclamunrar_iface_la_LDFLAGS = @TH_SAFE@ -version-info @LIBCLAMAV_VERSION@ -no-undefined

if VERSIONSCRIPT
libclamunrar_iface_la_LDFLAGS += -Wl,@VERSIONSCRIPTFLAG@,@top_srcdir@/libclamunrar_iface/libclamunrar_iface.map
endif

libclamunrar_iface_la_SOURCES = \
	unrar_iface.c \
	unrar_iface.h

lib_LTLIBRARIES = libclamunrar_iface.la
endif

EXTRA_DIST = libclamunrar_iface.map
CLEANFILES=*.gcda *.gcno

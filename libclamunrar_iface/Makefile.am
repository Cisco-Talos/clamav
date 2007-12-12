#
#  Copyright (C) 2007 Sourcefire, Inc.
#

if ENABLE_UNRAR

INCLUDES = -I$(top_srcdir)

libclamunrar_iface_la_LIBADD = $(top_builddir)/libclamunrar/libclamunrar.la

libclamunrar_iface_la_LDFLAGS = @TH_SAFE@ -version-info @LIBCLAMAV_VERSION@ -no-undefined

libclamunrar_iface_la_SOURCES = \
	unrar_iface.c \
	unrar_iface.h

lib_LTLIBRARIES = libclamunrar_iface.la

endif

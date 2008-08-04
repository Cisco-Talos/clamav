#
#  Copyright (C) 2007 Trog <trog@clamav.net>
#

if ENABLE_UNRAR

AM_CPPFLAGS = -I$(top_srcdir)

libclamunrar_la_LDFLAGS = @TH_SAFE@ -version-info @LIBCLAMAV_VERSION@ -no-undefined

if VERSIONSCRIPT
libclamunrar_la_LDFLAGS += -Wl,@VERSIONSCRIPTFLAG@,@top_srcdir@/libclamunrar/libclamunrar.map
endif

libclamunrar_la_SOURCES = \
	unrar15.c \
	unrar20.h \
	unrar.h \
	unrar15.h \
	unrar.c \
	unrar20.c \
	unrarcmd.h \
	unrarfilter.h \
	unrarppm.c \
	unrarvm.c \
	unrarcmd.c \
	unrarfilter.c \
	unrar.h \
	unrarppm.h \
	unrarvm.h \
	unrarhlp.c \
	unrarhlp.h

lib_LTLIBRARIES = libclamunrar.la
endif

EXTRA_DIST = libclamunrar.map
CLEANFILES=*.gcda *.gcno

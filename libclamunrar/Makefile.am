#
#  Copyright (C) 2007 Trog <trog@clamav.net>
#

if ENABLE_UNRAR

INCLUDES = -I$(top_srcdir)

libclamunrar_la_LDFLAGS = @TH_SAFE@ -version-info @LIBCLAMAV_VERSION@ -no-undefined

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

#
#  Copyright (C) 2007 Sourcefire, Inc.
#

AM_CPPFLAGS = -I$(top_srcdir) $(LTDLINCL)

lib_LTLIBRARIES =
EXTRA_DIST = 
if ENABLE_UNRAR
libclamunrar_la_LDFLAGS = -module @TH_SAFE@ -version-info @LIBCLAMAV_VERSION@ -no-undefined

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

lib_LTLIBRARIES += libclamunrar.la
EXTRA_DIST += @top_srcdir@/libclamunrar/libclamunrar.map
endif


libclamunrar_iface_la_LIBADD =  @LIBLTDL@ -dlopen libclamunrar.la
libclamunrar_iface_la_DEPENDENCIES =  @LIBLTDL@ libclamunrar.la
libclamunrar_iface_la_LDFLAGS = @TH_SAFE@ -version-info @LIBCLAMAV_VERSION@ -no-undefined

if VERSIONSCRIPT
libclamunrar_iface_la_LDFLAGS += -Wl,@VERSIONSCRIPTFLAG@,@top_srcdir@/libclamunrar_iface/libclamunrar_iface.map
endif

libclamunrar_iface_la_SOURCES = \
	unrar_iface.c \
	unrar_iface.h

lib_LTLIBRARIES += libclamunrar_iface.la

EXTRA_DIST += libclamunrar_iface.map
CLEANFILES=*.gcda *.gcno

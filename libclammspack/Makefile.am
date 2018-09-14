pkgconfigdir =		$(libdir)/pkgconfig
pkgconfig_DATA = 	libclammspack.pc

dist-hook:
	-rm -f $(distdir)/*.la

ACLOCAL_AMFLAGS =	-I m4
AM_CFLAGS =
# add "-DMSPACK_NO_DEFAULT_SYSTEM" to remove default mspack_system
if DEBUG
AM_CFLAGS +=		-DDEBUG
endif
if GCC
AM_CFLAGS +=		-Wall -Wextra -Wno-unused-parameter
endif
AM_CPPFLAGS =		-I$(top_srcdir)/mspack #-I$(top_srcdir)/test 

lib_LTLIBRARIES =	libclammspack.la
#include_HEADERS =	mspack/mspack.h

noinst_LTLIBRARIES =	libmscabd.la libmschmd.la

libclammspack_la_SOURCES =	mspack/mspack.h \
			mspack/system.h mspack/system.c \
			mspack/cab.h mspack/cabc.c mspack/cabd.c \
			mspack/chm.h mspack/chmc.c mspack/chmd.c \
			mspack/hlp.h mspack/hlpc.c mspack/hlpd.c \
			mspack/lit.h mspack/litc.c mspack/litd.c \
			mspack/kwaj.h mspack/kwajc.c mspack/kwajd.c \
			mspack/szdd.h mspack/szddc.c mspack/szddd.c \
			mspack/oab.h mspack/oabc.c mspack/oabd.c \
			mspack/lzx.h mspack/lzxc.c mspack/lzxd.c \
			mspack/mszip.h mspack/mszipc.c mspack/mszipd.c \
			mspack/qtm.h mspack/qtmd.c \
			mspack/readbits.h mspack/readhuff.h \
			mspack/lzss.h mspack/lzssd.c \
			mspack/des.h mspack/sha.h \
			mspack/crc32.c mspack/crc32.h
libclammspack_la_LDFLAGS =	-export-symbols-regex '^mspack_' -version-info 1:0:1

libmscabd_la_SOURCES =	mspack/mspack.h \
			mspack/system.h mspack/system.c \
			mspack/cab.h mspack/cabd.c \
			mspack/lzx.h mspack/lzxd.c \
			mspack/mszip.h mspack/mszipd.c \
			mspack/qtm.h mspack/qtmd.c \
			mspack/readbits.h mspack/readhuff.h
libmscabd_la_LDFLAGS =	-export-symbols-regex '^mspack_'

libmschmd_la_SOURCES =	mspack/mspack.h \
			mspack/system.h mspack/system.c \
			mspack/chm.h mspack/chmd.c \
			mspack/lzx.h mspack/lzxd.c \
			mspack/readbits.h mspack/readhuff.h
libmschmd_la_LDFLAGS =	-export-symbols-regex '^mspack_'


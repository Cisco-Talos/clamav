EXTRA_DIST =		$(srcdir)/debian/* $(srcdir)/doc/* $(srcdir)/test/test_files/*/*
pkgconfigdir =		$(libdir)/pkgconfig
pkgconfig_DATA = 	libmspack.pc

dist-hook:
	-rm -f $(distdir)/*.la

ACLOCAL_AMFLAGS =	-I m4
AM_CFLAGS =
# add "-DMSPACK_NO_DEFAULT_SYSTEM" to remove default mspack_system
if DEBUG
AM_CFLAGS +=		-DDEBUG
endif
if GCC
AM_CFLAGS +=		-Wall -Wextra -Wno-unused-parameter -Wno-unused-result
endif
AM_CPPFLAGS =		-I$(top_srcdir)/mspack -I$(top_srcdir)/test 

lib_LTLIBRARIES =	libmspack.la
include_HEADERS =	mspack/mspack.h

noinst_LTLIBRARIES =	libmscabd.la libmschmd.la
noinst_PROGRAMS =	test/cabd_md5 test/cabd_memory test/cabd_test \
			test/cabrip test/chmd_md5 test/chmx test/chminfo \
			test/multifh test/expand test/chmd_find \
			test/chmd_order test/oabx

libmspack_la_SOURCES =	mspack/mspack.h \
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
libmspack_la_LDFLAGS =	-export-symbols-regex '^mspack_' -version-info 1:0:1

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

test_chmx_SOURCES =	test/chmx.c test/error.h libmschmd.la
test_chmx_LDADD =	libmschmd.la

test_chmd_md5_SOURCES =	test/chmd_md5.c test/md5.c test/md5.h test/md5_fh.h \
			test/error.h libmschmd.la
test_chmd_md5_LDADD =	libmschmd.la

test_cabd_md5_SOURCES =	test/cabd_md5.c test/md5.c test/md5.h test/md5_fh.h \
			test/error.h libmscabd.la
test_cabd_md5_LDADD =	libmscabd.la

test_cabd_test_SOURCES=	test/cabd_test.c libmscabd.la
test_cabd_test_LDADD = 	libmscabd.la

test_cabrip_SOURCES =	test/cabrip.c libmscabd.la
test_cabrip_LDADD =	libmscabd.la

test_cabd_memory_SOURCES = test/cabd_memory.c libmscabd.la
test_cabd_memory_LDADD = libmscabd.la

test_chminfo_SOURCES =	test/chminfo.c libmschmd.la
test_chminfo_LDADD =	libmschmd.la

test_multifh_SOURCES =	test/multifh.c libmscabd.la
test_multifh_LDADD =	libmscabd.la

test_expand_SOURCES =	test/expand.c test/error.h libmspack.la
test_expand_LDADD =	libmspack.la

test_chmd_find_SOURCES = test/chmd_find.c test/error.h libmschmd.la
test_chmd_find_LDADD =	libmschmd.la

test_chmd_order_SOURCES = test/chmd_order.c test/md5.c test/md5.h test/md5_fh.h \
			test/error.h libmschmd.la
test_chmd_order_LDADD = libmschmd.la

test_oabx_SOURCES =	test/oabx.c test/md5.c test/md5.h test/md5_fh.h \
			test/error.h libmspack.la
test_oabx_LDADD =	libmspack.la

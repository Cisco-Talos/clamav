AUTOMAKE_OPTIONS =      subdir-objects
EXTRA_DIST =            doc test/test_files
pkgconfigdir =          $(libdir)/pkgconfig
TESTS =                 $(check_PROGRAMS)

ACLOCAL_AMFLAGS =       -I m4
AM_CFLAGS =
# add "-DMSPACK_NO_DEFAULT_SYSTEM" to remove default mspack_system
if GCC
AM_CFLAGS +=            -Wall -Wextra -Wno-unused-parameter -Wno-unused-result
endif
AM_CPPFLAGS =           -I$(srcdir)/mspack -I$(srcdir)/test

include_HEADERS =       mspack/mspack.h
lib_LTLIBRARIES =       libmspack.la
pkgconfig_DATA =        libmspack.pc

noinst_LTLIBRARIES =    libmscabd.la libmschmd.la
noinst_PROGRAMS =       examples/cabd_memory examples/cabrip examples/chmextract \
                        examples/msexpand examples/multifh examples/oabextract \
                        test/cabd_md5 test/chmd_find test/chmd_md5 test/chmd_order \
                        test/chminfo
check_PROGRAMS =        test/cabd_test test/chmd_test test/kwajd_test

libmspack_la_SOURCES =  mspack/mspack.h \
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
libmspack_la_LDFLAGS =  -export-symbols-regex '^mspack_' -version-info 1:0:1 -no-undefined

libmscabd_la_SOURCES =  mspack/mspack.h \
                        mspack/system.h mspack/system.c \
                        mspack/cab.h mspack/cabd.c \
                        mspack/lzx.h mspack/lzxd.c \
                        mspack/mszip.h mspack/mszipd.c \
                        mspack/qtm.h mspack/qtmd.c \
                        mspack/readbits.h mspack/readhuff.h
libmscabd_la_LDFLAGS =  -export-symbols-regex '^mspack_'

libmschmd_la_SOURCES =  mspack/mspack.h \
                        mspack/system.h mspack/system.c \
                        mspack/chm.h mspack/chmd.c \
                        mspack/lzx.h mspack/lzxd.c \
                        mspack/readbits.h mspack/readhuff.h
libmschmd_la_LDFLAGS =  -export-symbols-regex '^mspack_'

examples_cabd_memory_SOURCES =  examples/cabd_memory.c libmscabd.la
examples_cabd_memory_LDADD =    libmscabd.la
examples_cabrip_SOURCES =       examples/cabrip.c libmspack.la
examples_cabrip_LDADD =         libmspack.la
examples_chmextract_SOURCES =   examples/chmextract.c test/error.h libmspack.la
examples_chmextract_LDADD =     libmspack.la
examples_msexpand_SOURCES =     examples/msexpand.c test/error.h libmspack.la
examples_msexpand_LDADD =       libmspack.la
examples_multifh_SOURCES =      examples/multifh.c libmscabd.la
examples_multifh_LDADD =        libmscabd.la
examples_oabextract_SOURCES =   examples/oabextract.c test/error.h libmspack.la
examples_oabextract_LDADD =     libmspack.la

test_cabd_md5_SOURCES =         test/cabd_md5.c test/md5.c test/md5.h test/md5_fh.h test/error.h libmscabd.la
test_cabd_md5_LDADD =           libmscabd.la
test_chmd_find_SOURCES =        test/chmd_find.c test/error.h libmschmd.la
test_chmd_find_LDADD =          libmschmd.la
test_chmd_md5_SOURCES =         test/chmd_md5.c test/md5.c test/md5.h test/md5_fh.h test/error.h libmschmd.la
test_chmd_md5_LDADD =           libmschmd.la
test_chmd_order_SOURCES =       test/chmd_order.c test/md5.c test/md5.h test/md5_fh.h test/error.h libmschmd.la
test_chmd_order_LDADD =         libmschmd.la
test_chminfo_SOURCES =          test/chminfo.c libmschmd.la
test_chminfo_LDADD =            libmschmd.la

test_cabd_test_SOURCES =        test/cabd_test.c test/md5.c test/md5.h test/md5_fh.h libmscabd.la
test_cabd_test_CPPFLAGS =       $(AM_CPPFLAGS) -DTEST_FILES=$(abs_srcdir)/test/test_files/cabd
test_cabd_test_LDADD =          libmscabd.la
test_chmd_test_SOURCES =        test/chmd_test.c test/md5.c test/md5.h test/md5_fh.h libmschmd.la
test_chmd_test_CPPFLAGS =       $(AM_CPPFLAGS) -DTEST_FILES=$(abs_srcdir)/test/test_files/chmd
test_chmd_test_LDADD =          libmschmd.la
test_kwajd_test_SOURCES =       test/kwajd_test.c libmspack.la
test_kwajd_test_CPPFLAGS =      $(AM_CPPFLAGS) -DTEST_FILES=$(abs_srcdir)/test/test_files/kwajd
test_kwajd_test_LDADD =         libmspack.la

# Process this file with automake to produce Makefile.in

# By default, use our own standalone_fuzz_target_runner.
# This runner does no fuzzing, but simply executes the inputs
# provided via parameters.
# Run e.g. "make all LIB_FUZZING_ENGINE=/path/to/libFuzzer.a"
# to link the fuzzer(s) against a real fuzzing engine.
#
# OSS-Fuzz will define its own value for LIB_FUZZING_ENGINE.

if ENABLE_FUZZ

LIB_FUZZING_ENGINE ?= standalone_fuzz_target_runner.a

AM_CPPFLAGS = \
    @SSL_CPPFLAGS@ \
    -I$(top_srcdir) -I$(top_srcdir)/shared -I$(top_srcdir)/libclamav \
    -std=c++11 -stdlib=libc++

AM_LDFLAGS = \
    @SSL_LDFLAGS@

fuzzdir = "fuzz-targets"

fuzz_PROGRAMS = \
    clamav_scanmap_fuzzer \
    clamav_scanmap_ARCHIVE_fuzzer \
    clamav_scanmap_MAIL_fuzzer \
    clamav_scanmap_OLE2_fuzzer \
    clamav_scanmap_PDF_fuzzer \
    clamav_scanmap_HTML_fuzzer \
    clamav_scanmap_PE_fuzzer \
    clamav_scanmap_ELF_fuzzer \
    clamav_scanmap_SWF_fuzzer \
    clamav_scanmap_XMLDOCS_fuzzer \
    clamav_scanmap_HWP3_fuzzer \
    clamav_scanfile_fuzzer \
    clamav_scanfile_ARCHIVE_fuzzer \
    clamav_scanfile_MAIL_fuzzer \
    clamav_scanfile_OLE2_fuzzer \
    clamav_scanfile_PDF_fuzzer \
    clamav_scanfile_HTML_fuzzer \
    clamav_scanfile_PE_fuzzer \
    clamav_scanfile_ELF_fuzzer \
    clamav_scanfile_SWF_fuzzer \
    clamav_scanfile_XMLDOCS_fuzzer \
    clamav_scanfile_HWP3_fuzzer \
    clamav_dbload_CDB_fuzzer \
    clamav_dbload_CFG_fuzzer \
    clamav_dbload_CRB_fuzzer \
    clamav_dbload_FP_fuzzer \
    clamav_dbload_FTM_fuzzer \
    clamav_dbload_HDB_fuzzer \
    clamav_dbload_HSB_fuzzer \
    clamav_dbload_IDB_fuzzer \
    clamav_dbload_IGN_fuzzer \
    clamav_dbload_IGN2_fuzzer \
    clamav_dbload_LDB_fuzzer \
    clamav_dbload_MDB_fuzzer \
    clamav_dbload_MSB_fuzzer \
    clamav_dbload_NDB_fuzzer \
    clamav_dbload_PDB_fuzzer \
    clamav_dbload_WDB_fuzzer \
    clamav_dbload_YARA_fuzzer

dist_standalone_fuzz_target_runner_a_SOURCES = standalone_fuzz_target_runner.cpp
noinst_LIBRARIES = standalone_fuzz_target_runner.a

dist_clamav_scanmap_fuzzer_SOURCES = clamav_scanmap_fuzzer.cpp
clamav_scanmap_fuzzer_LDADD = $(LIB_FUZZING_ENGINE) @SSL_LIBS@ $(top_builddir)/libclamav/libclamav.la $(top_builddir)/libclamav/libclammspack.la

dist_clamav_scanmap_ARCHIVE_fuzzer_SOURCES = clamav_scanmap_fuzzer.cpp
clamav_scanmap_ARCHIVE_fuzzer_LDADD = $(LIB_FUZZING_ENGINE) @SSL_LIBS@ $(top_builddir)/libclamav/libclamav.la $(top_builddir)/libclamav/libclammspack.la
clamav_scanmap_ARCHIVE_fuzzer_CPPFLAGS = -DCLAMAV_FUZZ_ARCHIVE $(AM_CPPFLAGS)

dist_clamav_scanmap_MAIL_fuzzer_SOURCES = clamav_scanmap_fuzzer.cpp
clamav_scanmap_MAIL_fuzzer_LDADD = $(LIB_FUZZING_ENGINE) @SSL_LIBS@ $(top_builddir)/libclamav/libclamav.la $(top_builddir)/libclamav/libclammspack.la
clamav_scanmap_MAIL_fuzzer_CPPFLAGS = -DCLAMAV_FUZZ_MAIL $(AM_CPPFLAGS)

dist_clamav_scanmap_OLE2_fuzzer_SOURCES = clamav_scanmap_fuzzer.cpp
clamav_scanmap_OLE2_fuzzer_LDADD = $(LIB_FUZZING_ENGINE) @SSL_LIBS@ $(top_builddir)/libclamav/libclamav.la $(top_builddir)/libclamav/libclammspack.la
clamav_scanmap_OLE2_fuzzer_CPPFLAGS = -DCLAMAV_FUZZ_OLE2 $(AM_CPPFLAGS)

dist_clamav_scanmap_PDF_fuzzer_SOURCES = clamav_scanmap_fuzzer.cpp
clamav_scanmap_PDF_fuzzer_LDADD = $(LIB_FUZZING_ENGINE) @SSL_LIBS@ $(top_builddir)/libclamav/libclamav.la $(top_builddir)/libclamav/libclammspack.la
clamav_scanmap_PDF_fuzzer_CPPFLAGS = -DCLAMAV_FUZZ_PDF $(AM_CPPFLAGS)

dist_clamav_scanmap_HTML_fuzzer_SOURCES = clamav_scanmap_fuzzer.cpp
clamav_scanmap_HTML_fuzzer_LDADD = $(LIB_FUZZING_ENGINE) @SSL_LIBS@ $(top_builddir)/libclamav/libclamav.la $(top_builddir)/libclamav/libclammspack.la
clamav_scanmap_HTML_fuzzer_CPPFLAGS = -DCLAMAV_FUZZ_HTML $(AM_CPPFLAGS)

dist_clamav_scanmap_PE_fuzzer_SOURCES = clamav_scanmap_fuzzer.cpp
clamav_scanmap_PE_fuzzer_LDADD = $(LIB_FUZZING_ENGINE) @SSL_LIBS@ $(top_builddir)/libclamav/libclamav.la $(top_builddir)/libclamav/libclammspack.la
clamav_scanmap_PE_fuzzer_CPPFLAGS = -DCLAMAV_FUZZ_PE $(AM_CPPFLAGS)

dist_clamav_scanmap_ELF_fuzzer_SOURCES = clamav_scanmap_fuzzer.cpp
clamav_scanmap_ELF_fuzzer_LDADD = $(LIB_FUZZING_ENGINE) @SSL_LIBS@ $(top_builddir)/libclamav/libclamav.la $(top_builddir)/libclamav/libclammspack.la
clamav_scanmap_ELF_fuzzer_CPPFLAGS = -DCLAMAV_FUZZ_ELF $(AM_CPPFLAGS)

dist_clamav_scanmap_SWF_fuzzer_SOURCES = clamav_scanmap_fuzzer.cpp
clamav_scanmap_SWF_fuzzer_LDADD = $(LIB_FUZZING_ENGINE) @SSL_LIBS@ $(top_builddir)/libclamav/libclamav.la $(top_builddir)/libclamav/libclammspack.la
clamav_scanmap_SWF_fuzzer_CPPFLAGS = -DCLAMAV_FUZZ_SWF $(AM_CPPFLAGS)

dist_clamav_scanmap_XMLDOCS_fuzzer_SOURCES = clamav_scanmap_fuzzer.cpp
clamav_scanmap_XMLDOCS_fuzzer_LDADD = $(LIB_FUZZING_ENGINE) @SSL_LIBS@ $(top_builddir)/libclamav/libclamav.la $(top_builddir)/libclamav/libclammspack.la
clamav_scanmap_XMLDOCS_fuzzer_CPPFLAGS = -DCLAMAV_FUZZ_XMLDOCS $(AM_CPPFLAGS)

dist_clamav_scanmap_HWP3_fuzzer_SOURCES = clamav_scanmap_fuzzer.cpp
clamav_scanmap_HWP3_fuzzer_LDADD = $(LIB_FUZZING_ENGINE) @SSL_LIBS@ $(top_builddir)/libclamav/libclamav.la $(top_builddir)/libclamav/libclammspack.la
clamav_scanmap_HWP3_fuzzer_CPPFLAGS = -DCLAMAV_FUZZ_HWP3 $(AM_CPPFLAGS)

dist_clamav_scanfile_fuzzer_SOURCES = clamav_scanfile_fuzzer.cpp
clamav_scanfile_fuzzer_LDADD = $(LIB_FUZZING_ENGINE) @SSL_LIBS@ $(top_builddir)/libclamav/libclamav.la $(top_builddir)/libclamav/libclammspack.la

dist_clamav_scanfile_ARCHIVE_fuzzer_SOURCES = clamav_scanfile_fuzzer.cpp
clamav_scanfile_ARCHIVE_fuzzer_LDADD = $(LIB_FUZZING_ENGINE) @SSL_LIBS@ $(top_builddir)/libclamav/libclamav.la $(top_builddir)/libclamav/libclammspack.la
clamav_scanfile_ARCHIVE_fuzzer_CPPFLAGS = -DCLAMAV_FUZZ_ARCHIVE $(AM_CPPFLAGS)

dist_clamav_scanfile_MAIL_fuzzer_SOURCES = clamav_scanfile_fuzzer.cpp
clamav_scanfile_MAIL_fuzzer_LDADD = $(LIB_FUZZING_ENGINE) @SSL_LIBS@ $(top_builddir)/libclamav/libclamav.la $(top_builddir)/libclamav/libclammspack.la
clamav_scanfile_MAIL_fuzzer_CPPFLAGS = -DCLAMAV_FUZZ_MAIL $(AM_CPPFLAGS)

dist_clamav_scanfile_OLE2_fuzzer_SOURCES = clamav_scanfile_fuzzer.cpp
clamav_scanfile_OLE2_fuzzer_LDADD = $(LIB_FUZZING_ENGINE) @SSL_LIBS@ $(top_builddir)/libclamav/libclamav.la $(top_builddir)/libclamav/libclammspack.la
clamav_scanfile_OLE2_fuzzer_CPPFLAGS = -DCLAMAV_FUZZ_OLE2 $(AM_CPPFLAGS)

dist_clamav_scanfile_PDF_fuzzer_SOURCES = clamav_scanfile_fuzzer.cpp
clamav_scanfile_PDF_fuzzer_LDADD = $(LIB_FUZZING_ENGINE) @SSL_LIBS@ $(top_builddir)/libclamav/libclamav.la $(top_builddir)/libclamav/libclammspack.la
clamav_scanfile_PDF_fuzzer_CPPFLAGS = -DCLAMAV_FUZZ_PDF $(AM_CPPFLAGS)

dist_clamav_scanfile_HTML_fuzzer_SOURCES = clamav_scanfile_fuzzer.cpp
clamav_scanfile_HTML_fuzzer_LDADD = $(LIB_FUZZING_ENGINE) @SSL_LIBS@ $(top_builddir)/libclamav/libclamav.la $(top_builddir)/libclamav/libclammspack.la
clamav_scanfile_HTML_fuzzer_CPPFLAGS = -DCLAMAV_FUZZ_HTML $(AM_CPPFLAGS)

dist_clamav_scanfile_PE_fuzzer_SOURCES = clamav_scanfile_fuzzer.cpp
clamav_scanfile_PE_fuzzer_LDADD = $(LIB_FUZZING_ENGINE) @SSL_LIBS@ $(top_builddir)/libclamav/libclamav.la $(top_builddir)/libclamav/libclammspack.la
clamav_scanfile_PE_fuzzer_CPPFLAGS = -DCLAMAV_FUZZ_PE $(AM_CPPFLAGS)

dist_clamav_scanfile_ELF_fuzzer_SOURCES = clamav_scanfile_fuzzer.cpp
clamav_scanfile_ELF_fuzzer_LDADD = $(LIB_FUZZING_ENGINE) @SSL_LIBS@ $(top_builddir)/libclamav/libclamav.la $(top_builddir)/libclamav/libclammspack.la
clamav_scanfile_ELF_fuzzer_CPPFLAGS = -DCLAMAV_FUZZ_ELF $(AM_CPPFLAGS)

dist_clamav_scanfile_SWF_fuzzer_SOURCES = clamav_scanfile_fuzzer.cpp
clamav_scanfile_SWF_fuzzer_LDADD = $(LIB_FUZZING_ENGINE) @SSL_LIBS@ $(top_builddir)/libclamav/libclamav.la $(top_builddir)/libclamav/libclammspack.la
clamav_scanfile_SWF_fuzzer_CPPFLAGS = -DCLAMAV_FUZZ_SWF $(AM_CPPFLAGS)

dist_clamav_scanfile_XMLDOCS_fuzzer_SOURCES = clamav_scanfile_fuzzer.cpp
clamav_scanfile_XMLDOCS_fuzzer_LDADD = $(LIB_FUZZING_ENGINE) @SSL_LIBS@ $(top_builddir)/libclamav/libclamav.la $(top_builddir)/libclamav/libclammspack.la
clamav_scanfile_XMLDOCS_fuzzer_CPPFLAGS = -DCLAMAV_FUZZ_XMLDOCS $(AM_CPPFLAGS)

dist_clamav_scanfile_HWP3_fuzzer_SOURCES = clamav_scanfile_fuzzer.cpp
clamav_scanfile_HWP3_fuzzer_LDADD = $(LIB_FUZZING_ENGINE) @SSL_LIBS@ $(top_builddir)/libclamav/libclamav.la $(top_builddir)/libclamav/libclammspack.la
clamav_scanfile_HWP3_fuzzer_CPPFLAGS = -DCLAMAV_FUZZ_HWP3 $(AM_CPPFLAGS)

dist_clamav_dbload_CDB_fuzzer_SOURCES = clamav_dbload_fuzzer.cpp
clamav_dbload_CDB_fuzzer_LDADD = $(LIB_FUZZING_ENGINE) @SSL_LIBS@ $(top_builddir)/libclamav/libclamav.la $(top_builddir)/libclamav/libclammspack.la
clamav_dbload_CDB_fuzzer_CPPFLAGS = -DCLAMAV_FUZZ_CDB $(AM_CPPFLAGS)

dist_clamav_dbload_CFG_fuzzer_SOURCES = clamav_dbload_fuzzer.cpp
clamav_dbload_CFG_fuzzer_LDADD = $(LIB_FUZZING_ENGINE) @SSL_LIBS@ $(top_builddir)/libclamav/libclamav.la $(top_builddir)/libclamav/libclammspack.la
clamav_dbload_CFG_fuzzer_CPPFLAGS = -DCLAMAV_FUZZ_CFG $(AM_CPPFLAGS)

dist_clamav_dbload_CRB_fuzzer_SOURCES = clamav_dbload_fuzzer.cpp
clamav_dbload_CRB_fuzzer_LDADD = $(LIB_FUZZING_ENGINE) @SSL_LIBS@ $(top_builddir)/libclamav/libclamav.la $(top_builddir)/libclamav/libclammspack.la
clamav_dbload_CRB_fuzzer_CPPFLAGS = -DCLAMAV_FUZZ_CRB $(AM_CPPFLAGS)

dist_clamav_dbload_FP_fuzzer_SOURCES = clamav_dbload_fuzzer.cpp
clamav_dbload_FP_fuzzer_LDADD = $(LIB_FUZZING_ENGINE) @SSL_LIBS@ $(top_builddir)/libclamav/libclamav.la $(top_builddir)/libclamav/libclammspack.la
clamav_dbload_FP_fuzzer_CPPFLAGS = -DCLAMAV_FUZZ_FP $(AM_CPPFLAGS)

dist_clamav_dbload_FTM_fuzzer_SOURCES = clamav_dbload_fuzzer.cpp
clamav_dbload_FTM_fuzzer_LDADD = $(LIB_FUZZING_ENGINE) @SSL_LIBS@ $(top_builddir)/libclamav/libclamav.la $(top_builddir)/libclamav/libclammspack.la
clamav_dbload_FTM_fuzzer_CPPFLAGS = -DCLAMAV_FUZZ_FTM $(AM_CPPFLAGS)

dist_clamav_dbload_HDB_fuzzer_SOURCES = clamav_dbload_fuzzer.cpp
clamav_dbload_HDB_fuzzer_LDADD = $(LIB_FUZZING_ENGINE) @SSL_LIBS@ $(top_builddir)/libclamav/libclamav.la $(top_builddir)/libclamav/libclammspack.la
clamav_dbload_HDB_fuzzer_CPPFLAGS = -DCLAMAV_FUZZ_HDB $(AM_CPPFLAGS)

dist_clamav_dbload_HSB_fuzzer_SOURCES = clamav_dbload_fuzzer.cpp
clamav_dbload_HSB_fuzzer_LDADD = $(LIB_FUZZING_ENGINE) @SSL_LIBS@ $(top_builddir)/libclamav/libclamav.la $(top_builddir)/libclamav/libclammspack.la
clamav_dbload_HSB_fuzzer_CPPFLAGS = -DCLAMAV_FUZZ_HSB $(AM_CPPFLAGS)

dist_clamav_dbload_IDB_fuzzer_SOURCES = clamav_dbload_fuzzer.cpp
clamav_dbload_IDB_fuzzer_LDADD = $(LIB_FUZZING_ENGINE) @SSL_LIBS@ $(top_builddir)/libclamav/libclamav.la $(top_builddir)/libclamav/libclammspack.la
clamav_dbload_IDB_fuzzer_CPPFLAGS = -DCLAMAV_FUZZ_IDB $(AM_CPPFLAGS)

dist_clamav_dbload_IGN_fuzzer_SOURCES = clamav_dbload_fuzzer.cpp
clamav_dbload_IGN_fuzzer_LDADD = $(LIB_FUZZING_ENGINE) @SSL_LIBS@ $(top_builddir)/libclamav/libclamav.la $(top_builddir)/libclamav/libclammspack.la
clamav_dbload_IGN_fuzzer_CPPFLAGS = -DCLAMAV_FUZZ_IGN $(AM_CPPFLAGS)

dist_clamav_dbload_IGN2_fuzzer_SOURCES = clamav_dbload_fuzzer.cpp
clamav_dbload_IGN2_fuzzer_LDADD = $(LIB_FUZZING_ENGINE) @SSL_LIBS@ $(top_builddir)/libclamav/libclamav.la $(top_builddir)/libclamav/libclammspack.la
clamav_dbload_IGN2_fuzzer_CPPFLAGS = -DCLAMAV_FUZZ_IGN2 $(AM_CPPFLAGS)

dist_clamav_dbload_LDB_fuzzer_SOURCES = clamav_dbload_fuzzer.cpp
clamav_dbload_LDB_fuzzer_LDADD = $(LIB_FUZZING_ENGINE) @SSL_LIBS@ $(top_builddir)/libclamav/libclamav.la $(top_builddir)/libclamav/libclammspack.la
clamav_dbload_LDB_fuzzer_CPPFLAGS = -DCLAMAV_FUZZ_LDB $(AM_CPPFLAGS)

dist_clamav_dbload_MDB_fuzzer_SOURCES = clamav_dbload_fuzzer.cpp
clamav_dbload_MDB_fuzzer_LDADD = $(LIB_FUZZING_ENGINE) @SSL_LIBS@ $(top_builddir)/libclamav/libclamav.la $(top_builddir)/libclamav/libclammspack.la
clamav_dbload_MDB_fuzzer_CPPFLAGS = -DCLAMAV_FUZZ_MDB $(AM_CPPFLAGS)

dist_clamav_dbload_MSB_fuzzer_SOURCES = clamav_dbload_fuzzer.cpp
clamav_dbload_MSB_fuzzer_LDADD = $(LIB_FUZZING_ENGINE) @SSL_LIBS@ $(top_builddir)/libclamav/libclamav.la $(top_builddir)/libclamav/libclammspack.la
clamav_dbload_MSB_fuzzer_CPPFLAGS = -DCLAMAV_FUZZ_MSB $(AM_CPPFLAGS)

dist_clamav_dbload_NDB_fuzzer_SOURCES = clamav_dbload_fuzzer.cpp
clamav_dbload_NDB_fuzzer_LDADD = $(LIB_FUZZING_ENGINE) @SSL_LIBS@ $(top_builddir)/libclamav/libclamav.la $(top_builddir)/libclamav/libclammspack.la
clamav_dbload_NDB_fuzzer_CPPFLAGS = -DCLAMAV_FUZZ_NDB $(AM_CPPFLAGS)

dist_clamav_dbload_PDB_fuzzer_SOURCES = clamav_dbload_fuzzer.cpp
clamav_dbload_PDB_fuzzer_LDADD = $(LIB_FUZZING_ENGINE) @SSL_LIBS@ $(top_builddir)/libclamav/libclamav.la $(top_builddir)/libclamav/libclammspack.la
clamav_dbload_PDB_fuzzer_CPPFLAGS = -DCLAMAV_FUZZ_PDB $(AM_CPPFLAGS)

dist_clamav_dbload_WDB_fuzzer_SOURCES = clamav_dbload_fuzzer.cpp
clamav_dbload_WDB_fuzzer_LDADD = $(LIB_FUZZING_ENGINE) @SSL_LIBS@ $(top_builddir)/libclamav/libclamav.la $(top_builddir)/libclamav/libclammspack.la
clamav_dbload_WDB_fuzzer_CPPFLAGS = -DCLAMAV_FUZZ_WDB $(AM_CPPFLAGS)

dist_clamav_dbload_YARA_fuzzer_SOURCES = clamav_dbload_fuzzer.cpp
clamav_dbload_YARA_fuzzer_LDADD = $(LIB_FUZZING_ENGINE) @SSL_LIBS@ $(top_builddir)/libclamav/libclamav.la $(top_builddir)/libclamav/libclammspack.la
clamav_dbload_YARA_fuzzer_CPPFLAGS = -DCLAMAV_FUZZ_YARA $(AM_CPPFLAGS)

all: $(LIB_FUZZING_ENGINE)

check: all
	for type in ARCHIVE MAIL OLE2 PDF HTML PE ELF SWF XMLDOCS HWP3 ; do \
	    builddir="$(builddir)" $(srcdir)/run_fuzzer_tests.py -f clamav_scanmap_fuzzer -c $(top_srcdir)/../clamav-fuzz-corpus/scantype/$$type ; \
	done
	for type in ARCHIVE MAIL OLE2 PDF HTML PE ELF SWF XMLDOCS HWP3 ; do \
	    builddir="$(builddir)" $(srcdir)/run_fuzzer_tests.py -f "clamav_scanfile_"$$type"_fuzzer" -c $(top_srcdir)/../clamav-fuzz-corpus/scantype/$$type ; \
	done
	for type in CDB CFG CRB FP FTM HDB HSB IDB IGN IGN2 LDB MDB MSB NDB PDB WDB YARA ; do \
	    builddir="$(builddir)" $(srcdir)/run_fuzzer_tests.py -f "clamav_dbload_"$$type"_fuzzer" -c $(top_srcdir)/../clamav-fuzz-corpus/database/$$type ; \
	done

else

all:
check:
	@echo "Building fuzz targets is not enabled"
	@echo "Use: ./configure --enable-fuzz --with-libjson=no --with-pcre=no --enable-static=yes --enable-shared=no --disable-llvm"
	@exit 1

endif

CLEANFILES = *.gcda *.gcno
EXTRA_DIST = README.md run_fuzzer_tests.py

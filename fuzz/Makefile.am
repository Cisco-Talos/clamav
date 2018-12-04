# Process this file with automake to produce Makefile.in

# By default, use our own standalone_fuzz_target_runner.
# This runner does no fuzzing, but simply executes the inputs
# provided via parameters.
# Run e.g. "make all LIB_FUZZING_ENGINE=/path/to/libFuzzer.a"
# to link the fuzzer(s) against a real fuzzing engine.
#
# OSS-Fuzz will define its own value for LIB_FUZZING_ENGINE.

if ENABLE_FUZZ

LIB_FUZZING_ENGINE ?= standalone_fuzz_target_runner.o

AM_CPPFLAGS = \
    -I$(top_srcdir) -I$(top_srcdir)/shared -I$(top_srcdir)/libclamav \
    -std=c++11 -O2 -fno-omit-frame-pointer -g \
    -fsanitize=address \
    -fsanitize-coverage=edge,trace-pc-guard,indirect-calls,trace-cmp,trace-div,trace-gep

AM_LDFLAGS = \
    $(top_builddir)/libclamav/libclamav.la $(top_builddir)/libclamav/libclammspack.la \
    -Wc,-fsanitize=address -Wl,-U,_LLVMFuzzerCustomMutator -Wl,-U,_LLVMFuzzerInitialize \
    "-no-undefined"

check_PROGRAMS = \
	clamav_scanmap_fuzzer \
	clamav_scanfile_fuzzer \
	clamav_scanfile_fuzzer_ARCHIVE \
	clamav_scanfile_fuzzer_MAIL \
	clamav_scanfile_fuzzer_OLE2 \
	clamav_scanfile_fuzzer_PDF \
	clamav_scanfile_fuzzer_HTML \
	clamav_scanfile_fuzzer_PE \
	clamav_scanfile_fuzzer_ELF \
	clamav_scanfile_fuzzer_SWF \
	clamav_scanfile_fuzzer_XMLDOCS \
	clamav_scanfile_fuzzer_HWP3 \
	clamav_dbload_fuzzer_CDB \
	clamav_dbload_fuzzer_CFG \
	clamav_dbload_fuzzer_CRB \
	clamav_dbload_fuzzer_FP \
	clamav_dbload_fuzzer_FTM \
	clamav_dbload_fuzzer_HDB \
	clamav_dbload_fuzzer_HSB \
	clamav_dbload_fuzzer_IDB \
	clamav_dbload_fuzzer_IGN \
	clamav_dbload_fuzzer_IGN2 \
	clamav_dbload_fuzzer_LDB \
	clamav_dbload_fuzzer_MDB \
	clamav_dbload_fuzzer_MSB \
	clamav_dbload_fuzzer_NDB \
	clamav_dbload_fuzzer_PDB \
	clamav_dbload_fuzzer_WDB \
	clamav_dbload_fuzzer_YARA

clamav_scanmap_fuzzer_SOURCES = clamav_scanmap_fuzzer.cpp
clamav_scanmap_fuzzer_LDADD = $(LIB_FUZZING_ENGINE)

clamav_scanfile_fuzzer_SOURCES = clamav_scanfile_fuzzer.cpp
clamav_scanfile_fuzzer_LDADD = $(LIB_FUZZING_ENGINE)

clamav_scanfile_fuzzer_ARCHIVE_SOURCES = clamav_scanfile_fuzzer.cpp
clamav_scanfile_fuzzer_ARCHIVE_LDADD = $(LIB_FUZZING_ENGINE)
clamav_scanfile_fuzzer_ARCHIVE_CPPFLAGS = -DCLAMAV_FUZZ_ARCHIVE $(AM_CPPFLAGS)

clamav_scanfile_fuzzer_MAIL_SOURCES = clamav_scanfile_fuzzer.cpp
clamav_scanfile_fuzzer_MAIL_LDADD = $(LIB_FUZZING_ENGINE)
clamav_scanfile_fuzzer_MAIL_CPPFLAGS = -DCLAMAV_FUZZ_MAIL $(AM_CPPFLAGS)

clamav_scanfile_fuzzer_OLE2_SOURCES = clamav_scanfile_fuzzer.cpp
clamav_scanfile_fuzzer_OLE2_LDADD = $(LIB_FUZZING_ENGINE)
clamav_scanfile_fuzzer_OLE2_CPPFLAGS = -DCLAMAV_FUZZ_OLE2 $(AM_CPPFLAGS)

clamav_scanfile_fuzzer_PDF_SOURCES = clamav_scanfile_fuzzer.cpp
clamav_scanfile_fuzzer_PDF_LDADD = $(LIB_FUZZING_ENGINE)
clamav_scanfile_fuzzer_PDF_CPPFLAGS = -DCLAMAV_FUZZ_PDF $(AM_CPPFLAGS)

clamav_scanfile_fuzzer_HTML_SOURCES = clamav_scanfile_fuzzer.cpp
clamav_scanfile_fuzzer_HTML_LDADD = $(LIB_FUZZING_ENGINE)
clamav_scanfile_fuzzer_HTML_CPPFLAGS = -DCLAMAV_FUZZ_HTML $(AM_CPPFLAGS)

clamav_scanfile_fuzzer_PE_SOURCES = clamav_scanfile_fuzzer.cpp
clamav_scanfile_fuzzer_PE_LDADD = $(LIB_FUZZING_ENGINE)
clamav_scanfile_fuzzer_PE_CPPFLAGS = -DCLAMAV_FUZZ_PE $(AM_CPPFLAGS)

clamav_scanfile_fuzzer_ELF_SOURCES = clamav_scanfile_fuzzer.cpp
clamav_scanfile_fuzzer_ELF_LDADD = $(LIB_FUZZING_ENGINE)
clamav_scanfile_fuzzer_ELF_CPPFLAGS = -DCLAMAV_FUZZ_ELF $(AM_CPPFLAGS)

clamav_scanfile_fuzzer_SWF_SOURCES = clamav_scanfile_fuzzer.cpp
clamav_scanfile_fuzzer_SWF_LDADD = $(LIB_FUZZING_ENGINE)
clamav_scanfile_fuzzer_SWF_CPPFLAGS = -DCLAMAV_FUZZ_SWF $(AM_CPPFLAGS)

clamav_scanfile_fuzzer_XMLDOCS_SOURCES = clamav_scanfile_fuzzer.cpp
clamav_scanfile_fuzzer_XMLDOCS_LDADD = $(LIB_FUZZING_ENGINE)
clamav_scanfile_fuzzer_XMLDOCS_CPPFLAGS = -DCLAMAV_FUZZ_XMLDOCS $(AM_CPPFLAGS)

clamav_scanfile_fuzzer_HWP3_SOURCES = clamav_scanfile_fuzzer.cpp
clamav_scanfile_fuzzer_HWP3_LDADD = $(LIB_FUZZING_ENGINE)
clamav_scanfile_fuzzer_HWP3_CPPFLAGS = -DCLAMAV_FUZZ_HWP3 $(AM_CPPFLAGS)

clamav_dbload_fuzzer_CDB_SOURCES = clamav_dbload_fuzzer.cpp
clamav_dbload_fuzzer_CDB_LDADD = $(LIB_FUZZING_ENGINE)
clamav_dbload_fuzzer_CDB_CPPFLAGS = -DCLAMAV_FUZZ_CDB $(AM_CPPFLAGS)

clamav_dbload_fuzzer_CFG_SOURCES = clamav_dbload_fuzzer.cpp
clamav_dbload_fuzzer_CFG_LDADD = $(LIB_FUZZING_ENGINE)
clamav_dbload_fuzzer_CFG_CPPFLAGS = -DCLAMAV_FUZZ_CFG $(AM_CPPFLAGS)

clamav_dbload_fuzzer_CRB_SOURCES = clamav_dbload_fuzzer.cpp
clamav_dbload_fuzzer_CRB_LDADD = $(LIB_FUZZING_ENGINE)
clamav_dbload_fuzzer_CRB_CPPFLAGS = -DCLAMAV_FUZZ_CRB $(AM_CPPFLAGS)

clamav_dbload_fuzzer_FP_SOURCES = clamav_dbload_fuzzer.cpp
clamav_dbload_fuzzer_FP_LDADD = $(LIB_FUZZING_ENGINE)
clamav_dbload_fuzzer_FP_CPPFLAGS = -DCLAMAV_FUZZ_FP $(AM_CPPFLAGS)

clamav_dbload_fuzzer_FTM_SOURCES = clamav_dbload_fuzzer.cpp
clamav_dbload_fuzzer_FTM_LDADD = $(LIB_FUZZING_ENGINE)
clamav_dbload_fuzzer_FTM_CPPFLAGS = -DCLAMAV_FUZZ_FTM $(AM_CPPFLAGS)

clamav_dbload_fuzzer_HDB_SOURCES = clamav_dbload_fuzzer.cpp
clamav_dbload_fuzzer_HDB_LDADD = $(LIB_FUZZING_ENGINE)
clamav_dbload_fuzzer_HDB_CPPFLAGS = -DCLAMAV_FUZZ_HDB $(AM_CPPFLAGS)

clamav_dbload_fuzzer_HSB_SOURCES = clamav_dbload_fuzzer.cpp
clamav_dbload_fuzzer_HSB_LDADD = $(LIB_FUZZING_ENGINE)
clamav_dbload_fuzzer_HSB_CPPFLAGS = -DCLAMAV_FUZZ_HSB $(AM_CPPFLAGS)

clamav_dbload_fuzzer_IDB_SOURCES = clamav_dbload_fuzzer.cpp
clamav_dbload_fuzzer_IDB_LDADD = $(LIB_FUZZING_ENGINE)
clamav_dbload_fuzzer_IDB_CPPFLAGS = -DCLAMAV_FUZZ_IDB $(AM_CPPFLAGS)

clamav_dbload_fuzzer_IGN_SOURCES = clamav_dbload_fuzzer.cpp
clamav_dbload_fuzzer_IGN_LDADD = $(LIB_FUZZING_ENGINE)
clamav_dbload_fuzzer_IGN_CPPFLAGS = -DCLAMAV_FUZZ_IGN $(AM_CPPFLAGS)

clamav_dbload_fuzzer_IGN2_SOURCES = clamav_dbload_fuzzer.cpp
clamav_dbload_fuzzer_IGN2_LDADD = $(LIB_FUZZING_ENGINE)
clamav_dbload_fuzzer_IGN2_CPPFLAGS = -DCLAMAV_FUZZ_IGN2 $(AM_CPPFLAGS)

clamav_dbload_fuzzer_LDB_SOURCES = clamav_dbload_fuzzer.cpp
clamav_dbload_fuzzer_LDB_LDADD = $(LIB_FUZZING_ENGINE)
clamav_dbload_fuzzer_LDB_CPPFLAGS = -DCLAMAV_FUZZ_LDB $(AM_CPPFLAGS)

clamav_dbload_fuzzer_MDB_SOURCES = clamav_dbload_fuzzer.cpp
clamav_dbload_fuzzer_MDB_LDADD = $(LIB_FUZZING_ENGINE)
clamav_dbload_fuzzer_MDB_CPPFLAGS = -DCLAMAV_FUZZ_MDB $(AM_CPPFLAGS)

clamav_dbload_fuzzer_MSB_SOURCES = clamav_dbload_fuzzer.cpp
clamav_dbload_fuzzer_MSB_LDADD = $(LIB_FUZZING_ENGINE)
clamav_dbload_fuzzer_MSB_CPPFLAGS = -DCLAMAV_FUZZ_MSB $(AM_CPPFLAGS)

clamav_dbload_fuzzer_NDB_SOURCES = clamav_dbload_fuzzer.cpp
clamav_dbload_fuzzer_NDB_LDADD = $(LIB_FUZZING_ENGINE)
clamav_dbload_fuzzer_NDB_CPPFLAGS = -DCLAMAV_FUZZ_NDB $(AM_CPPFLAGS)

clamav_dbload_fuzzer_PDB_SOURCES = clamav_dbload_fuzzer.cpp
clamav_dbload_fuzzer_PDB_LDADD = $(LIB_FUZZING_ENGINE)
clamav_dbload_fuzzer_PDB_CPPFLAGS = -DCLAMAV_FUZZ_PDB $(AM_CPPFLAGS)

clamav_dbload_fuzzer_WDB_SOURCES = clamav_dbload_fuzzer.cpp
clamav_dbload_fuzzer_WDB_LDADD = $(LIB_FUZZING_ENGINE)
clamav_dbload_fuzzer_WDB_CPPFLAGS = -DCLAMAV_FUZZ_WDB $(AM_CPPFLAGS)

clamav_dbload_fuzzer_YARA_SOURCES = clamav_dbload_fuzzer.cpp
clamav_dbload_fuzzer_YARA_LDADD = $(LIB_FUZZING_ENGINE)
clamav_dbload_fuzzer_YARA_CPPFLAGS = -DCLAMAV_FUZZ_YARA $(AM_CPPFLAGS)

check: $(LIB_FUZZING_ENGINE)
	for type in ARCHIVE MAIL OLE2 PDF HTML PE ELF SWF XMLDOCS HWP3 ; do \
	    builddir="$(builddir)" $(srcdir)/run_fuzzer_tests.py -f clamav_scanmap_fuzzer -c $(top_srcdir)/../clamav-fuzz-corpus/scantype/$$type ; \
	done
	for type in ARCHIVE MAIL OLE2 PDF HTML PE ELF SWF XMLDOCS HWP3 ; do \
	    builddir="$(builddir)" $(srcdir)/run_fuzzer_tests.py -f clamav_scanfile_fuzzer_$$type -c $(top_srcdir)/../clamav-fuzz-corpus/scantype/$$type ; \
	done
	for type in CDB CFG CRB FP FTM HDB HSB IDB IGN IGN2 LDB MDB MSB NDB PDB WDB YARA ; do \
	    builddir="$(builddir)" $(srcdir)/run_fuzzer_tests.py -f clamav_dbload_fuzzer_$$type -c $(top_srcdir)/../clamav-fuzz-corpus/database/$$type ; \
	done

else

check:
	@echo "Building fuzz targets is not enabled"
	@echo "Use: ./configure --enable-fuzz --with-libjson=no --with-pcre=no --enable-static=yes --enable-shared=no --disable-llvm"
	@exit 1

endif

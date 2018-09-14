SPLIT_DIR=$(top_srcdir)/unit_tests/.split
FILES = clam-phish-exe

check_unit_vg.sh: $(FILES)
check2_clamd.sh: $(FILES)
check3_clamd.sh: $(FILES)
check4_clamd.sh: $(FILES)
check5_clamd_vg.sh: $(FILES)
check6_clamd_vg.sh: $(FILES)
check7_clamd_vg.sh: $(FILES)
check8_clamd_hg.sh: $(FILES)
check9_clamd_hg.sh: $(FILES)
check10_clamd_hg.sh: $(FILES)

$(FILES) :
	cat $(SPLIT_DIR)/split.$@aa $(SPLIT_DIR)/split.$@ab > $@


programs = check_clamav
scripts = check_freshclam.sh check_sigtool.sh check_unit_vg.sh check1_clamscan.sh check2_clamd.sh check3_clamd.sh check4_clamd.sh\
	  check5_clamd_vg.sh check6_clamd_vg.sh check7_clamd_hg.sh check8_clamd_hg.sh check9_clamscan_vg.sh
utils = check_fpu_endian
TESTS_ENVIRONMENT=export abs_srcdir=$(abs_srcdir) AWK=$(AWK);
if ENABLE_UNRAR
else
TESTS_ENVIRONMENT += export unrar_disabled=1;
endif
TESTS = $(programs) $(scripts)
check_PROGRAMS = $(programs) check_clamd $(utils)
check_SCRIPTS = $(scripts)

AM_CFLAGS=@WERR_CFLAGS@
if HAVE_LIBCHECK
check_clamav_SOURCES = check_clamav.c checks.h checks_common.h $(top_builddir)/libclamav/clamav.h\
		       check_jsnorm.c check_str.c check_regex.c\
		       check_disasm.c check_uniq.c check_matchers.c\
		       check_htmlnorm.c check_bytecode.c
check_clamav_CPPFLAGS = -I$(top_srcdir) @CHECK_CPPFLAGS@ @JSON_CPPFLAGS@ @PCRE_CPPFLAGS@ -DSRCDIR=\"$(abs_srcdir)\" -DOBJDIR=\"$(abs_builddir)\"
check_clamav_LDADD = $(top_builddir)/libclamav/libclamav.la @THREAD_LIBS@ @CHECK_LIBS@
check_clamav_LDFLAGS = $(XML_LIBS)
check_clamav_CFLAGS = $(AM_CFLAGS) @XML_CPPFLAGS@
check_clamd_SOURCES = check_clamd.c checks_common.h
check_clamd_CPPFLAGS = -I$(top_srcdir) @CHECK_CPPFLAGS@ @JSON_CPPFLAGS@ @PCRE_CPPFLAGS@ -DSRCDIR=\"$(abs_srcdir)\" -DBUILDDIR=\"$(abs_builddir)\"
check_clamd_LDADD = @CHECK_LIBS@ @CLAMD_LIBS@
else
check_clamd_SOURCES = check_clamav_skip.c
check_clamav_SOURCES = check_clamav_skip.c
endif

check_fpu_endian_SOURCES = check_fpu_endian.c
check_fpu_endian_CPPFLAGS = -I$(top_srcdir) @CHECK_CPPFLAGS@ @JSON_CPPFLAGS@ @PCRE_CPPFLAGS@ -DSRCDIR=\"$(abs_srcdir)\" -DOBJDIR=\"$(abs_builddir)\"
check_fpu_endian_LDADD = $(top_builddir)/libclamav/libclamav.la

check_clamav.c: $(top_builddir)/test/clam.exe clamav.hdb
check_clamd.sh: $(top_builddir)/test/clam.exe check_clamd
check_clamscan.sh: $(top_builddir)/test/clam.exe

clamav.hdb: input/clamav.hdb
	cp $< $@

$(top_builddir)/test/clam.exe:
	(cd $(top_builddir)/test && $(MAKE))

quick-check:
	VALGRIND=no LIBEFENCE=no LIBDUMA=no $(MAKE) check

CLEANFILES=lcov.out *.gcno *.gcda *.log $(FILES) test-stderr.log clamscan.log accdenied clamav.hdb $(utils)
EXTRA_DIST=.split $(srcdir)/*.ref input test-freshclam.conf valgrind.supp virusaction-test.sh $(scripts) preload_run.sh check_common.sh
if ENABLE_COVERAGE
LCOV_OUTPUT = lcov.out
LCOV_HTML = lcov_html
LCOV_LCOV = @LCOV@
LCOV_GCOV = @GCOV@
LCOV_GENHTML = @GENHTML@
lcov: $(LCOV_HTML)
DIRECTORIES=--directory . --directory ../libclamav --directory ../clamd --directory ../freshclam --directory ../sigtool --directory ../clamscan --directory ../clamdscan
.libs/check_clamav.gcda: $(TESTS)
	$(LCOV_LCOV) $(DIRECTORIES) --zerocounters
	@$(MAKE) check VALGRIND= LIBDUMA=no LIBEFENCE=no

$(LCOV_OUTPUT): .libs/check_clamav.gcda
	$(LCOV_LCOV) --capture $(DIRECTORIES) --output-file $@

$(LCOV_HTML): $(LCOV_OUTPUT)
	-$(RM) -r $@
	LANG=C $(LCOV_GENHTML) --output-directory $@ --title "ClamAV Code Coverage" --show-details $<
	@echo "Open `pwd`/$(LCOV_HTML)/index.html in a browser."

clean-local: lcov-clean
.PHONY: lcov-clean
lcov-clean:
	-$(RM) -r $(LCOV_HTML) $(LCOV_OUTPUT)
	$(LCOV_LCOV) $(DIRECTORIES) --zerocounters
else

lcov:
	@echo "Coverage information gathering is not enabled in this build"
	@echo "Use ./configure --enable-coverage to enable it"
	@exit 1
endif

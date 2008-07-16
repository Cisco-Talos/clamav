programs = check_clamav
scripts = check_clamd.sh check_freshclam.sh check_sigtool.sh check_clamscan.sh

TESTS = $(programs) $(scripts)
if ENABLE_UT_INSTALL 
bin_PROGRAMS = $(programs)
dist_bin_SCRIPTS = $(scripts)
else
check_PROGRAMS = $(programs)
check_SCRIPTS = $(scripts)
endif
check_clamav_SOURCES = check_clamav.c check_jsnorm.c check_str.c checks.h $(top_builddir)/libclamav/clamav.h
check_clamav_CFLAGS = @CHECK_CFLAGS@
check_clamav_LDADD = $(top_builddir)/libclamav/libclamav.la @THREAD_LIBS@ @CHECK_LIBS@

check_clamd.sh: $(top_builddir)/test/clam.exe
check_clamscan.sh: $(top_builddir)/test/clam.exe

$(top_builddir)/test/clam.exe:
	(cd $(top_builddir)/test && $(MAKE))

if ENABLE_COVERAGE
LCOV_OUTPUT = lcov.out
LCOV_HTML = lcov_html
LCOV_LCOV = @LCOV@
LCOV_GENHTML = @GENHTML@
CLEANFILES=lcov.out *.gcno *.gcda *.log /tmp/clamd-test.log
EXTRA_DIST=test-clamd.conf test-freshclam.conf
lcov: $(LCOV_HTML)

DIRECTORIES=--directory . --directory ../libclamav --directory ../clamd --directory ../freshclam --directory ../sigtool --directory ../clamscan --directory ../clamdscan
.libs/check_clamav.gcda: $(TESTS)
	lcov $(DIRECTORIES) --zerocounters
	@$(MAKE) check

$(LCOV_OUTPUT): .libs/check_clamav.gcda
	$(LCOV_LCOV) --capture $(DIRECTORIES) --base-directory . --output-file $@

$(LCOV_HTML): $(LCOV_OUTPUT)
	-$(RM) -r $@
	LANG=C $(LCOV_GENHTML) --output-directory $@ --title "ClamAV Code Coverage" --show-details $<
	@echo "Open `pwd`/$(LCOV_HTML)/index.html in a browser."

clean-local: lcov-clean
.PHONY: lcov-clean
lcov-clean:
	-$(RM) -r $(LCOV_HTML) $(LCOV_OUTPUT)
	lcov $(DIRECTORIES) --zerocounters
else

lcov:
	@echo "Coverage information gathering is not enabled in this build"
	@echo "Use ./configure --enable-coverage to enable it"
	@exit 1
endif

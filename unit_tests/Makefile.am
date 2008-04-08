TESTS = check_clamav
bin_PROGRAMS = check_clamav
check_clamav_SOURCES = check_clamav.c $(top_builddir)/libclamav/clamav.h
check_clamav_CFLAGS = 
check_clamav_LDADD = $(top_builddir)/libclamav/libclamav.la @THREAD_LIBS@ @LCHECK@

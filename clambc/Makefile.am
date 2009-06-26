bin_PROGRAMS = clambc
clambc_SOURCES = \
    bcrun.c

AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/shared -I$(top_srcdir)/libclamav
LIBS = $(top_builddir)/libclamav/libclamav.la @THREAD_LIBS@
CLEANFILES=*.gcda *.gcno

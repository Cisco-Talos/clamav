bin_PROGRAMS = clambc
clambc_SOURCES = \
    bcrun.c

AM_CFLAGS=@WERR_CFLAGS@ @SSL_CPPFLAGS@ @JSON_CPPFLAGS@ @PCRE_CPPFLAGS@
AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/shared -I$(top_srcdir)/libclamav -I$(top_builddir)/libclamav -I$(top_srcdir)/libclamunrar_iface
LIBS = $(top_builddir)/libclamav/libclamav.la $(top_builddir)/shared/libshared.la @THREAD_LIBS@
CLEANFILES=*.gcda *.gcno

if HAVE_CURSES
bin_PROGRAMS = clamdtop
man_MANS = $(top_builddir)/docs/man/clamdtop.1
clamdtop_SOURCES = \
    clamdtop.c

AM_CFLAGS=@WERR_CFLAGS@
AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/shared -I$(top_srcdir)/libclamav -I$(top_builddir)/libclamav -I$(top_srcdir)/libclamunrar_iface @SSL_CPPFLAGS@ @CURSES_CPPFLAGS@ @JSON_CPPFLAGS@ @PCRE_CPPFLAGS@
clamdtop_LDADD = @SSL_LDFLAGS@ @SSL_LIBS@ @CURSES_LIBS@ @THREAD_LIBS@ $(top_builddir)/shared/libshared.la $(top_builddir)/libclamav/libclamav.la
endif

DEFS = @DEFS@

# Add clamdtop.c to extra_dist so make dist will include it even if curses
# wasn't detected on this dist builder.
EXTRA_DIST = clamdtop.c

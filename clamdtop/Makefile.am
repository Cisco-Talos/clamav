if HAVE_CURSES
bin_PROGRAMS = clamdtop
man_MANS = $(top_builddir)/docs/man/clamdtop.1
clamdtop_SOURCES = \
    clamdtop.c

AM_CFLAGS=@WERR_CFLAGS@
AM_CPPFLAGS = -I$(top_srcdir) @CURSES_CPPFLAGS@
clamdtop_LDADD = @CURSES_LIBS@ $(top_builddir)/shared/libshared_minimal.la $(top_builddir)/libclamav/libclamav_internal_utils_nothreads.la
endif
EXTRA_DIST = clamdtop.c

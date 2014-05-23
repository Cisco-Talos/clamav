if HAVE_CURSES
bin_PROGRAMS = clamdtop
man_MANS = $(top_builddir)/docs/man/clamdtop.1
clamdtop_SOURCES = \
    $(top_srcdir)/shared/optparser.c \
    $(top_srcdir)/shared/optparser.h \
    $(top_srcdir)/shared/getopt.c \
    $(top_srcdir)/shared/getopt.h \
    $(top_srcdir)/shared/misc.c \
    $(top_srcdir)/shared/misc.h \
    clamdtop.c

AM_CFLAGS=@WERR_CFLAGS@
AM_CPPFLAGS = -I$(top_srcdir) @CURSES_CPPFLAGS@ @SSL_CPPFLAGS@
clamdtop_LDFLAGS= @SSL_LDFLAGS@ @CURSES_LIBS@
clamdtop_LDADD = $(top_builddir)/libclamav/libclamav_internal_utils_nothreads.la
endif
DEFS = @DEFS@ -DCL_NOTHREADS -DCL_NOLIBCLAMAV
EXTRA_DIST = clamdtop.c

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
AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/shared -I$(top_srcdir)/libclamav @SSL_CPPFLAGS@ @CURSES_CPPFLAGS@ @JSON_CPPFLAGS@ @PCRE_CPPFLAGS@
clamdtop_LDADD = @SSL_LDFLAGS@ @SSL_LIBS@ @CURSES_LIBS@ $(top_builddir)/libclamav/libclamav_internal_utils_nothreads.la
endif
DEFS = @DEFS@ -DCL_NOTHREADS -DCL_NOLIBCLAMAV
EXTRA_DIST = clamdtop.c

AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/libclamav

libshared_la_SOURCES=actions.c\
	       cdiff.c\
	       clamdcom.c\
	       getopt.c\
	       idmef_logging.c\
	       misc.c\
	       optparser.c\
	       tar.c

libshared_threads_la_SOURCES=output.c\
			     misc_libclamav.c
libshared_threads_la_LIBADD=libshared.la

libshared_nothreads_la_SOURCES=output.c\
			       misc_libclamav.c
libshared_nothreads_la_LIBADD=libshared.la
libshared_nothreads_la_CFLAGS=-DCL_NOTHREADS

libshared_minimal_la_SOURCES=output.c
libshared_minimal_la_LIBADD=libshared.la
libshared_minimal_la_CFLAGS=-DCL_NOTHREADS

libshared_minimal_threads_la_SOURCES=output.c
libshared_minimal_threads_la_LIBADD=libshared.la

noinst_LTLIBRARIES=libshared.la libshared_threads.la libshared_nothreads.la libshared_minimal.la libshared_minimal_threads.la

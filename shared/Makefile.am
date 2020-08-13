AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/libclamav -I$(top_builddir)/libclamav -I$(top_srcdir)/libclamunrar_iface @JSON_CPPFLAGS@ @CURL_CPPFLAGS@ @SSL_CPPFLAGS@ @PCRE_CPPFLAGS@
LIBS = @SSL_LDFLAGS@ @SSL_LIBS@
AM_LIBTOOLFLAGS = --tag CC

libshared_la_SOURCES= \
    actions.c \
    actions.h \
    cdiff.c \
    cdiff.h \
    cert_util.c \
    cert_util.h \
    cert_util_internal.h \
    clamdcom.c \
    clamdcom.h \
    fdpassing.h \
    getopt.c \
    getopt.h \
    hostid.c \
    hostid.h \
    idmef_logging.c \
    idmef_logging.h \
    misc.c \
    misc.h \
    optparser.c \
    optparser.h \
    output.c \
    output.h \
    tar.c \
    tar.h

if MACOS
    libshared_la_SOURCES += \
        mac/cert_util_mac.m \
        cert_util.h
endif
if WINDOWS
    libshared_la_SOURCES += \
        win/cert_util_win.c \
        cert_util.h
endif
if LINUX
    libshared_la_SOURCES += \
        linux/cert_util_linux.c \
        cert_util.h
endif

noinst_LTLIBRARIES=libshared.la

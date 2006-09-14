MAINTAINERCLEANFILES= Makefile.in aclocal.m4 configure config.h.in config.guess config.sub install-sh ltconfig lt-main.sh mdate-sh missing mkinstalldirs  
CLEANFILES=phishtest_output.xml
clam_builddir=clam
noinst_SUBDIRS=$(clam_builddir)
TESTS=check_phishing
noinst_PROGRAMS=check_phishing 

EXTRA_DIST=regex_test.txt autogen.sh 
check_phishing_SOURCES= urltest.c urltest.h regex_list_test.c regex_list_test.h runner.c pdomain.c pdomain.h
check_phishing_INCLUDES= @CHECK_CFLAGS@
check_phishing_LDADD= @CHECK_LIBS@ $(clam_builddir)/libclamav/libclamav.la
INCLUDES= -I$(top_srcdir) -I$(clam_builddir) -I$(clam_builddir)/shared -I$(clam_builddir)/libclamav

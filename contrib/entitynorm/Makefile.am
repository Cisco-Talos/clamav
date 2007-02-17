MAINTAINERCLEANFILES= Makefile.in aclocal.m4 configure config.h.in config.guess config.sub install-sh ltconfig lt-main.sh mdate-sh missing mkinstalldirs  
clam_builddir=../../
noinst_PROGRAMS=fixdb postprocessdb generate_entitylist generate_encoding_aliases
SUBDIRS=$(clam_builddir)
fixdb_SOURCES= fixdb.c
fixdb_INCLUDES= 
fixdb_LDADD= $(clam_builddir)/libclamav/libclamav.la
postprocessdb_SOURCES = postprocess.c
postprocessdb_INCLUDES= 
postprocessdb_LDADD= $(clam_builddir)/libclamav/libclamav.la

generate_entitylist_SOURCES = generate_entitylist.c
generate_entitylist_INCLUDES= 
generate_entitylist_LDADD= $(clam_builddir)/libclamav/libclamav.la


generate_encoding_aliases_SOURCES = generate_encoding_aliases.c
generate_encoding_aliases_INCLUDES= 
generate_encoding_aliases_LDADD= $(clam_builddir)/libclamav/libclamav.la
INCLUDES= -I$(top_srcdir) -I$(clam_builddir) -I$(clam_builddir)/shared -I$(clam_builddir)/libclamav

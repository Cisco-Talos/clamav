#
#  Copyright (C) 2002 - 2007 Tomasz Kojm <tkojm@clamav.net>
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#  MA 02110-1301, USA.

SUBDIRS = lzma .

AM_CPPFLAGS = -I$(top_srcdir) -I@srcdir@/nsis -I@srcdir@/lzma $(LTDLINCL)

lib_LTLIBRARIES =
EXTRA_DIST =


if ENABLE_UNRAR

AM_CPPFLAGS += -DWARN_DLOPEN_FAIL
libclamunrar_la_LDFLAGS = @TH_SAFE@ -version-info @LIBCLAMAV_VERSION@ -no-undefined

if VERSIONSCRIPT
libclamunrar_la_LDFLAGS += -Wl,@VERSIONSCRIPTFLAG@,@top_srcdir@/libclamunrar/libclamunrar.map
endif

libclamunrar_la_SOURCES = \
	../libclamunrar/unrar15.c \
	../libclamunrar/unrar20.h \
	../libclamunrar/unrar.h \
	../libclamunrar/unrar15.h \
	../libclamunrar/unrar.c \
	../libclamunrar/unrar20.c \
	../libclamunrar/unrarcmd.h \
	../libclamunrar/unrarfilter.h \
	../libclamunrar/unrarppm.c \
	../libclamunrar/unrarvm.c \
	../libclamunrar/unrarcmd.c \
	../libclamunrar/unrarfilter.c \
	../libclamunrar/unrar.h \
	../libclamunrar/unrarppm.h \
	../libclamunrar/unrarvm.h \
	../libclamunrar/unrarhlp.c \
	../libclamunrar/unrarhlp.h

lib_LTLIBRARIES += libclamunrar.la
EXTRA_DIST += @top_srcdir@/libclamunrar/libclamunrar.map


libclamunrar_iface_la_LIBADD = libclamunrar.la
libclamunrar_iface_la_LDFLAGS = -module @TH_SAFE@ -version-info @LIBCLAMAV_VERSION@ -no-undefined

if VERSIONSCRIPT
libclamunrar_iface_la_LDFLAGS += -Wl,@VERSIONSCRIPTFLAG@,@top_srcdir@/libclamunrar_iface/libclamunrar_iface.map
endif

libclamunrar_iface_la_SOURCES = \
	../libclamunrar_iface/unrar_iface.c \
	../libclamunrar_iface/unrar_iface.h

lib_LTLIBRARIES += libclamunrar_iface.la
EXTRA_DIST += @top_srcdir@/libclamunrar_iface/libclamunrar_iface.map

IFACELIBADD = -dlopen libclamunrar_iface.la
IFACEDEP = libclamunrar_iface.la
endif

libclamav_internal_utils_la_SOURCES=str.c\
				    str.h\
				    md5.c\
				    md5.h\
				    others_common.c \
				    others.h \
				    regex/strlcpy.c \
				    regex/regcomp.c \
				    regex/regerror.c \
				    regex/regexec.c \
				    regex/regfree.c \
				    regex/cclass.h \
				    regex/cname.h \
				    regex/regex.h \
				    regex/regex2.h \
				    regex/utils.h

libclamav_internal_utils_la_LDFLAGS=-static
libclamav_internal_utils_la_CFLAGS=  -fPIC -DPIC

libclamav_internal_utils_nothreads_la_SOURCES=str.c\
				    str.h\
				    md5.c\
				    md5.h\
				    others_common.c \
				    others.h \
				    regex/strlcpy.c \
				    regex/regcomp.c \
				    regex/regerror.c \
				    regex/regexec.c \
				    regex/regfree.c \
				    regex/cclass.h \
				    regex/cname.h \
				    regex/regex.h \
				    regex/regex2.h \
				    regex/utils.h

libclamav_internal_utils_nothreads_la_LDFLAGS=-static
libclamav_internal_utils_nothreads_la_CFLAGS=-DCL_NOTHREADS

libclamav_la_LIBADD = @LIBLTDL@ $(IFACELIBADD) lzma/liblzma.la libclamav_internal_utils.la @LIBCLAMAV_LIBS@ @THREAD_LIBS@
libclamav_la_DEPENDENCIES =  @LTDLDEPS@ $(IFACEDEP) libclamav_internal_utils.la
libclamav_la_CFLAGS = -DSEARCH_LIBDIR=\"$(libdir)\"
libclamav_la_LDFLAGS = @TH_SAFE@ -version-info @LIBCLAMAV_VERSION@ -no-undefined

if VERSIONSCRIPT
libclamav_la_LDFLAGS += -Wl,@VERSIONSCRIPTFLAG@,@top_srcdir@/libclamav/libclamav.map
endif

include_HEADERS = clamav.h

libclamav_la_SOURCES = \
	clamav.h \
        matcher-ac.c \
        matcher-ac.h \
        matcher-bm.c \
        matcher-bm.h \
        matcher.c \
        matcher.h \
        others.c \
        others.h \
        readdb.c \
	readdb.h \
	cvd.c \
	cvd.h \
	dsig.c \
	dsig.h \
	scanners.c \
	scanners.h \
	textdet.c \
	textdet.h \
	filetypes.c \
	filetypes.h \
	filetypes_int.h \
	rtf.c \
	rtf.h \
	blob.c \
	blob.h \
	mbox.c \
	mbox.h \
	message.c \
	message.h \
	table.c \
	table.h \
	text.c \
	text.h \
	ole2_extract.c \
	ole2_extract.h \
	vba_extract.c \
	vba_extract.h \
	cltypes.h \
	msexpand.c \
	msexpand.h \
	pe.c \
	pe.h \
	disasm.c \
	disasm.h \
	disasmpriv.h \
	upx.c \
	upx.h \
	htmlnorm.c \
	htmlnorm.h \
	chmunpack.c \
	chmunpack.h \
	rebuildpe.c \
	rebuildpe.h \
	petite.c \
	petite.h \
	wwunpack.c \
	wwunpack.h \
	unsp.c \
	unsp.h \
	aspack.c \
	aspack.h \
	packlibs.c \
	packlibs.h \
	fsg.c \
	fsg.h \
	mew.c \
	mew.h \
	upack.c \
	upack.h \
	line.c \
	line.h \
	untar.c \
	untar.h \
	unzip.c \
	unzip.h \
	inflate64.c \
	inflate64.h \
	inffixed64.h \
	inflate64_priv.h \
	special.c \
	special.h \
	binhex.c \
	binhex.h \
	is_tar.c \
	is_tar.h \
	tnef.c \
	tnef.h \
	autoit.c \
	autoit.h \
	unarj.c \
	unarj.h \
	nsis/bzlib.c \
	nsis/bzlib_private.h \
	nsis/nsis_bzlib.h \
	nsis/nulsft.c \
	nsis/nulsft.h \
	nsis/infblock.c \
	nsis/nsis_zconf.h \
	nsis/nsis_zlib.h \
	nsis/nsis_zutil.h \
	pdf.c \
	pdf.h \
	spin.c \
	spin.h \
	yc.c \
	yc.h \
	elf.c \
	elf.h \
	execs.h \
	sis.c \
	sis.h \
	uuencode.c \
	uuencode.h \
	phishcheck.c \
	phishcheck.h \
	phish_domaincheck_db.c \
	phish_domaincheck_db.h \
	phish_whitelist.c \
	phish_whitelist.h \
	iana_cctld.h \
	iana_tld.h \
	regex_list.c \
	regex_list.h \
	regex_suffix.c \
	regex_suffix.h \
	mspack.c \
	mspack.h \
	cab.c \
	cab.h \
	entconv.c \
	entconv.h \
	entitylist.h \
	encoding_aliases.h \
	hashtab.c \
	hashtab.h \
	dconf.c \
	dconf.h \
	lzma_iface.c \
	lzma_iface.h \
	explode.c \
	explode.h \
	textnorm.c \
	textnorm.h \
	dlp.c \
	dlp.h \
	jsparse/js-norm.c \
	jsparse/js-norm.h \
	jsparse/lexglobal.h \
	jsparse/textbuf.h \
	uniq.c \
	uniq.h \
	version.c\
	version.h\
	mpool.c\
	mpool.h \
	default.h\
	sha256.c\
	sha256.h\
	bignum.h

if !LINK_TOMMATH
libclamav_la_SOURCES += bignum.c \
		     bignum_class.h
endif

.PHONY: version.h.tmp
version.c: version.h
version.h: version.h.tmp
	@if test -f version.h.static; then\
		cp version.h.static version.h;\
	elif ! diff $@ version.h.tmp >/dev/null 2>/dev/null; then\
		cp version.h.tmp $@;\
	fi

version.h.tmp:
	@test -f version.h || touch version.h;\
	rm -f $@;\
	REVISION="$$(LANG=C svnversion "$(top_srcdir)" 2>/dev/null || echo exported)";\
	if test $$REVISION = "exported"; then\
		REVISION="$$(LANG=C cd "$(top_srcdir)"; git svn info configure 2>/dev/null| awk '/Revision:/ { print $$2 }' || echo)";\
		if test -n "$$REVISION"; then\
			REVISION="$$REVISION-$$(LANG=C cd "$(top_srcdir)"; git describe --always 2>/dev/null)";\
		fi;\
	fi;\
	if test -n "$$REVISION"; then\
		echo "#define REPO_VERSION \"devel-r$$REVISION\"" >> $@;\
	else\
		touch version.h.tmp;\
	fi

lib_LTLIBRARIES += libclamav.la
noinst_LTLIBRARIES = libclamav_internal_utils.la libclamav_internal_utils_nothreads.la
EXTRA_DIST += regex/engine.c libclamav.map \
	     jsparse/generated/operators.h jsparse/generated/keywords.h jsparse/future_reserved_words.list\
	     jsparse/keywords.list jsparse/special_keywords.list jsparse/operators.gperf
COMMON_CLEANFILES=version.h version.h.tmp *.gcda *.gcno lzma/*.gcda lzma/*.gcno
if MAINTAINER_MODE
BUILT_SOURCES=jsparse/generated/operators.h jsparse/generated/keywords.h jsparse-keywords.gperf

GPERF_FLAGS=-E -t -L ANSI-C -C -F ', TOK_ERROR' -c

jsparse-keywords.gperf: jsparse/keywords.list jsparse/future_reserved_words.list jsparse/special_keywords.list
	echo -e "struct keyword { const char *name; int val; };\n%%" >keywords-g-tmp
	for i in `cat @srcdir@/jsparse/keywords.list`; do j=`echo $$i |tr \[a-z\] \[A-Z\]`; echo "$$i, TOK_$$j" >>keywords-g-tmp; done
	for i in `cat @srcdir@/jsparse/future_reserved_words.list`; do echo "$$i, TOK_FUTURE_RESERVED_WORD" >>keywords-g-tmp; done
	cat @srcdir@/jsparse/special_keywords.list >>keywords-g-tmp
	mv keywords-g-tmp $@

jsparse/generated/operators.h: jsparse/operators.gperf
	$(GPERF) $(GPERF_FLAGS) -H op_hash -N in_op_set -W oplist $< >operators-tmp-g
	grep -v '^#line' <operators-tmp-g | sed -e 's/^const struct/static const struct/' -e 's/register //g' >operators-tmp
	rm operators-tmp-g
	mv operators-tmp @srcdir@/jsparse/generated/operators.h

jsparse/generated/keywords.h: jsparse-keywords.gperf
	$(GPERF) $(GPERF_FLAGS) $< >keywords-tmp-g
	grep -v '^#line' <keywords-tmp-g |  sed -e 's/^const struct/static const struct/' -e 's/register //g' >keywords-tmp
	rm keywords-tmp-g
	mv keywords-tmp @srcdir@/jsparse/generated/keywords.h

CLEANFILES=$(COMMON_CLEANFILES) @srcdir@/jsparse/generated/operators.h @srcdir@/jsparse/generated/keywords.h
else
CLEANFILES=$(COMMON_CLEANFILES)
endif

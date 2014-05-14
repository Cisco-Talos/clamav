#
#  Copyright (C) 2002 - 2007 Tomasz Kojm <tkojm@clamav.net>
#  Copyright (C) 2008 - 2013 Sourcefire, Inc.
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

AM_CPPFLAGS = -I$(top_srcdir) -I@srcdir@/nsis $(LTDLINCL)
AM_CFLAGS=@WERR_CFLAGS@
lib_LTLIBRARIES =
EXTRA_DIST = c++/Makefile.nollvm.in
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
					conv.c \
					conv.h \
					crypto.c \
					crypto.h \
					clamav.h \
				    iowrap.c \
				    iowrap.h \
				    others_common.c \
				    others.h \
				    qsort.c \
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

libclamav_internal_utils_la_LDFLAGS=-static @SSL_LDFLAGS@
libclamav_internal_utils_la_CFLAGS=$(AM_CFLAGS)  -fPIC -DPIC @SSL_CPPFLAGS@
libclamav_internal_utils_la_LIBADD=@SSL_LIBS@

libclamav_internal_utils_nothreads_la_SOURCES=str.c\
					conv.c \
					conv.h \
					crypto.c \
					crypto.h \
					clamav.h \
				    str.h\
				    iowrap.c \
				    iowrap.h \
				    others_common.c \
				    others.h \
				    qsort.c \
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

libclamav_internal_utils_nothreads_la_LDFLAGS=-static @SSL_LDFLAGS@
libclamav_internal_utils_nothreads_la_CFLAGS=$(AM_CFLAGS) -DCL_NOTHREADS @SSL_CPPFLAGS@
libclamav_internal_utils_nothreads_la_LIBADD=@SSL_LIBS@

if ENABLE_LLVM
LLVMLIBADD=c++/libclamavcxx.la -lstdc++ -lm
LLVMDEP=c++/libclamavcxx.la
SUBDIRS=c++
else
LLVMLIBADD=libclamav_nocxx.la
LLVMDEP=libclamav_nocxx.la
c++/Makefile: c++/Makefile.nollvm.in
	$(AM_V_at) cp $< $@
distclean-recursive distdir maintainer-clean-recursive: c++/Makefile
endif

libclamav_nocxx_la_SOURCES = bytecode_nojit.c
libclamav_nocxx_la_CFLAGS=$(AM_CFLAGS) @SSL_CPPFLAGS@

libclamav_la_LIBADD = @SSL_LIBS@ @LIBCLAMAV_LIBS@ @LIBLTDL@ $(IFACELIBADD) $(LLVMLIBADD) libclamav_internal_utils.la @THREAD_LIBS@ @LIBM@
libclamav_la_DEPENDENCIES =  @LTDLDEPS@ $(IFACEDEP) $(LLVMDEP) libclamav_internal_utils.la
libclamav_la_CFLAGS =$(AM_CFLAGS) $(XML_CPPFLAGS) -DSEARCH_LIBDIR=\"$(libdir)\" @LIBCLAMAV_CPPFLAGS@ @SSL_CPPFLAGS@
libclamav_la_LDFLAGS = @SSL_LDFLAGS@ @TH_SAFE@ $(XML_LIBS) -version-info @LIBCLAMAV_VERSION@ -no-undefined

if VERSIONSCRIPT
libclamav_la_LDFLAGS += -Wl,@VERSIONSCRIPTFLAG@,@top_srcdir@/libclamav/libclamav.map
endif

include_HEADERS = clamav.h

libclamav_la_SOURCES = \
        matcher-ac.c \
        matcher-ac.h \
        matcher-bm.c \
        matcher-bm.h \
        matcher-hash.c \
        matcher-hash.h \
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
	pe_icons.c \
	pe_icons.h \
	disasm.c \
	disasm.h \
	disasm-common.h \
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
	7z_iface.c \
	7z_iface.h \
	7z/7z.h \
	7z/7zAlloc.c \
	7z/7zAlloc.h \
	7z/7zBuf.c \
	7z/7zBuf.h \
	7z/7zBuf2.c \
	7z/7zCrc.c \
	7z/7zCrc.h \
	7z/7zDec.c \
	7z/7zFile.c \
	7z/7zFile.h \
	7z/7zIn.c \
	7z/7zStream.c \
	7z/7zVersion.h \
	7z/Bcj2.c \
	7z/Bcj2.h \
	7z/Bra.c \
	7z/Bra.h \
	7z/Bra86.c \
	7z/CpuArch.h \
	7z/Lzma2Dec.c \
	7z/Lzma2Dec.h \
	7z/LzmaDec.c \
	7z/LzmaDec.h \
	7z/Ppmd.h \
	7z/Ppmd7.c \
	7z/Ppmd7.h \
	7z/Ppmd7Dec.c \
	7z/Types.h \
	7z/Xz.c \
	7z/Xz.h \
	7z/XzCrc64.c \
	7z/XzCrc64.h \
	7z/XzDec.c \
	7z/XzIn.c \
	7z/Delta.c \
	7z/Delta.h \
	7z/Alloc.h \
	7z/BraIA64.c \
	7z/CpuArch.c \
	7z/CpuArch.h \
	7z/7zCrcOpt.c \
	7z/RotateDefs.h \
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
	filtering.h\
	filtering.c\
	fmap.c \
	fmap.h \
	perflogging.c\
	perflogging.h\
	default.h\
	bytecode.c\
	bytecode.h\
	bytecode_vm.c\
	bytecode_priv.h\
	clambc.h \
	cpio.c \
	cpio.h \
	macho.c \
	macho.h \
	ishield.c \
	ishield.h \
	type_desc.h \
	bcfeatures.h \
	bytecode_api.c \
	bytecode_api_decl.c \
	bytecode_api.h \
	bytecode_api_impl.h \
	bytecode_hooks.h \
	cache.c \
	cache.h \
	bytecode_detect.c \
	bytecode_detect.h\
	builtin_bytecodes.h\
	events.c\
	events.h \
	adc.c \
	adc.h \
	dmg.c \
	dmg.h \
	xar.c \
	xar.h \
	mbr.c \
    mbr.h \
	gpt.c \
	gpt.h \
	apm.c \
	apm.h \
	prtn_intxn.c \
	prtn_intxn.h \
	xz_iface.c \
	xz_iface.h \
	sf_base64decode.c \
	sf_base64decode.h \
	hfsplus.c \
	hfsplus.h \
	swf.c \
	swf.h \
	jpeg.c \
	jpeg.h \
	png.c \
	png.h \
	iso9660.c \
	iso9660.h \
	arc4.c \
	arc4.h \
	rijndael.c \
	rijndael.h \
	crtmgr.c \
	crtmgr.h \
	asn1.c \
	asn1.h \
	fpu.c \
	fpu.h \
	stats.c \
	stats.h \
	www.c \
	www.h \
	json.c \
	json.h \
	hostid.c \
	hostid.h \
	openioc.c \
	openioc.h

libclamav_la_SOURCES += bignum.h\
	bignum_fast.h\
        tomsfastmath/addsub/fp_add.c\
        tomsfastmath/addsub/fp_add_d.c\
        tomsfastmath/addsub/fp_addmod.c\
        tomsfastmath/addsub/fp_cmp.c\
        tomsfastmath/addsub/fp_cmp_d.c\
        tomsfastmath/addsub/fp_cmp_mag.c\
        tomsfastmath/addsub/fp_sub.c\
        tomsfastmath/addsub/fp_sub_d.c\
        tomsfastmath/addsub/fp_submod.c\
        tomsfastmath/addsub/s_fp_add.c\
        tomsfastmath/addsub/s_fp_sub.c\
        tomsfastmath/bin/fp_radix_size.c\
        tomsfastmath/bin/fp_read_radix.c\
        tomsfastmath/bin/fp_read_signed_bin.c\
        tomsfastmath/bin/fp_read_unsigned_bin.c\
        tomsfastmath/bin/fp_reverse.c\
        tomsfastmath/bin/fp_s_rmap.c\
        tomsfastmath/bin/fp_signed_bin_size.c\
        tomsfastmath/bin/fp_to_signed_bin.c\
        tomsfastmath/bin/fp_to_unsigned_bin.c\
        tomsfastmath/bin/fp_toradix.c\
        tomsfastmath/bin/fp_toradix_n.c\
        tomsfastmath/bin/fp_unsigned_bin_size.c\
        tomsfastmath/bit/fp_cnt_lsb.c\
        tomsfastmath/bit/fp_count_bits.c\
        tomsfastmath/bit/fp_div_2.c\
        tomsfastmath/bit/fp_div_2d.c\
        tomsfastmath/bit/fp_lshd.c\
        tomsfastmath/bit/fp_mod_2d.c\
        tomsfastmath/bit/fp_rshd.c\
        tomsfastmath/divide/fp_div.c\
        tomsfastmath/divide/fp_div_d.c\
        tomsfastmath/divide/fp_mod.c\
        tomsfastmath/divide/fp_mod_d.c\
        tomsfastmath/exptmod/fp_2expt.c\
        tomsfastmath/exptmod/fp_exptmod.c\
        tomsfastmath/misc/fp_ident.c\
        tomsfastmath/misc/fp_set.c\
        tomsfastmath/mont/fp_montgomery_calc_normalization.c\
        tomsfastmath/mont/fp_montgomery_reduce.c\
        tomsfastmath/mont/fp_montgomery_setup.c\
        tomsfastmath/mul/fp_mul.c\
        tomsfastmath/mul/fp_mul_comba.c\
        tomsfastmath/mul/fp_mul_2.c\
        tomsfastmath/mul/fp_mul_2d.c\
        tomsfastmath/mul/fp_mul_comba_12.c\
        tomsfastmath/mul/fp_mul_comba_17.c\
        tomsfastmath/mul/fp_mul_comba_20.c\
        tomsfastmath/mul/fp_mul_comba_24.c\
        tomsfastmath/mul/fp_mul_comba_28.c\
        tomsfastmath/mul/fp_mul_comba_3.c\
        tomsfastmath/mul/fp_mul_comba_32.c\
        tomsfastmath/mul/fp_mul_comba_4.c\
        tomsfastmath/mul/fp_mul_comba_48.c\
        tomsfastmath/mul/fp_mul_comba_6.c\
        tomsfastmath/mul/fp_mul_comba_64.c\
        tomsfastmath/mul/fp_mul_comba_7.c\
        tomsfastmath/mul/fp_mul_comba_8.c\
        tomsfastmath/mul/fp_mul_comba_9.c\
        tomsfastmath/mul/fp_mul_comba_small_set.c\
        tomsfastmath/mul/fp_mul_d.c\
        tomsfastmath/mul/fp_mulmod.c\
        tomsfastmath/numtheory/fp_invmod.c\
        tomsfastmath/sqr/fp_sqr.c\
        tomsfastmath/sqr/fp_sqr_comba_12.c\
        tomsfastmath/sqr/fp_sqr_comba_17.c\
        tomsfastmath/sqr/fp_sqr_comba_20.c\
        tomsfastmath/sqr/fp_sqr_comba_24.c\
        tomsfastmath/sqr/fp_sqr_comba_28.c\
        tomsfastmath/sqr/fp_sqr_comba_3.c\
        tomsfastmath/sqr/fp_sqr_comba_32.c\
        tomsfastmath/sqr/fp_sqr_comba_4.c\
        tomsfastmath/sqr/fp_sqr_comba_48.c\
        tomsfastmath/sqr/fp_sqr_comba_6.c\
        tomsfastmath/sqr/fp_sqr_comba_64.c\
        tomsfastmath/sqr/fp_sqr_comba_7.c\
        tomsfastmath/sqr/fp_sqr_comba_8.c\
        tomsfastmath/sqr/fp_sqr_comba_9.c\
        tomsfastmath/sqr/fp_sqr_comba_generic.c\
        tomsfastmath/sqr/fp_sqr_comba_small_set.c\
	tomsfastmath/sqr/fp_sqrmod.c

.PHONY: version.h.tmp
version.c: version.h
version.h: version.h.tmp
	$(AM_V_GEN) if test -f version.h.static; then\
		cp version.h.static version.h;\
	elif ! diff $@ version.h.tmp >/dev/null 2>/dev/null; then\
		cp version.h.tmp $@;\
	fi

version.h.tmp:
	$(AM_V_GEN) test -f version.h || touch version.h;\
	rm -f $@;\
	REVISION="$$(LANG=C cd "$(top_srcdir)"; git describe --always 2>/dev/null || echo "exported")";\
	if test "$$REVISION" = "exported"; then\
	    REVISION="";\
	fi;\
	if test -n "$$REVISION"; then\
		echo "#define REPO_VERSION \"devel-$$REVISION\"" >> $@;\
	else\
		touch version.h.tmp;\
	fi

lib_LTLIBRARIES += libclamav.la
noinst_LTLIBRARIES = libclamav_internal_utils.la libclamav_internal_utils_nothreads.la libclamav_nocxx.la
EXTRA_DIST += regex/engine.c tomsfastmath/sqr/fp_sqr_comba.c tomsfastmath/mul/fp_mul_comba.c libclamav.map \
	     jsparse/generated/operators.h jsparse/generated/keywords.h jsparse/future_reserved_words.list\
	     jsparse/keywords.list jsparse/special_keywords.list jsparse/operators.gperf
COMMON_CLEANFILES=version.h version.h.tmp *.gcda *.gcno
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

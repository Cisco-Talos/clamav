#
#  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
#  Copyright (C) 2007-2013 Sourcefire, Inc.
#  Copyright (C) 2002-2007 Tomasz Kojm <tkojm@clamav.net>
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

AM_YFLAGS = -d
AM_CPPFLAGS = -I$(top_srcdir) -I@srcdir@/nsis $(LTDLINCL)
AM_CFLAGS=@WERR_CFLAGS@
lib_LTLIBRARIES =
COMMON_CLEANFILES =
EXTRA_DIST = c++/Makefile.nollvm.in
if ENABLE_UNRAR

AM_CPPFLAGS += -DWARN_DLOPEN_FAIL
libclamunrar_la_CXXFLAGS = $(AM_CPPFLAGS) -DRARDLL -Wno-logical-op-parentheses -Wno-switch -Wno-dangling-else
libclamunrar_la_LDFLAGS = @TH_SAFE@ -version-info @LIBCLAMAV_VERSION@ -no-undefined

if VERSIONSCRIPT
libclamunrar_la_LDFLAGS += -Wl,@VERSIONSCRIPTFLAG@,@top_srcdir@/libclamunrar/libclamunrar.map
endif

libclamunrar_la_SOURCES = \
	../libclamunrar/archive.cpp \
	../libclamunrar/arcread.cpp \
	../libclamunrar/blake2s.cpp \
	../libclamunrar/cmddata.cpp \
	../libclamunrar/consio.cpp \
	../libclamunrar/crc.cpp \
	../libclamunrar/crypt.cpp \
	../libclamunrar/dll.cpp \
	../libclamunrar/encname.cpp \
	../libclamunrar/errhnd.cpp \
	../libclamunrar/extinfo.cpp \
	../libclamunrar/extract.cpp \
	../libclamunrar/filcreat.cpp \
	../libclamunrar/file.cpp \
	../libclamunrar/filefn.cpp \
	../libclamunrar/filestr.cpp \
	../libclamunrar/find.cpp \
	../libclamunrar/getbits.cpp \
	../libclamunrar/global.cpp \
	../libclamunrar/hash.cpp \
	../libclamunrar/headers.cpp \
	../libclamunrar/isnt.cpp \
	../libclamunrar/list.cpp \
	../libclamunrar/match.cpp \
	../libclamunrar/options.cpp \
	../libclamunrar/pathfn.cpp \
	../libclamunrar/qopen.cpp \
	../libclamunrar/rar.cpp \
	../libclamunrar/rarvm.cpp \
	../libclamunrar/rawread.cpp \
	../libclamunrar/rdwrfn.cpp \
	../libclamunrar/recvol.cpp \
	../libclamunrar/resource.cpp \
	../libclamunrar/rijndael.cpp \
	../libclamunrar/rs.cpp \
	../libclamunrar/rs16.cpp \
	../libclamunrar/scantree.cpp \
	../libclamunrar/secpassword.cpp \
	../libclamunrar/sha1.cpp \
	../libclamunrar/sha256.cpp \
	../libclamunrar/smallfn.cpp \
	../libclamunrar/strfn.cpp \
	../libclamunrar/strlist.cpp \
	../libclamunrar/system.cpp \
	../libclamunrar/threadpool.cpp \
	../libclamunrar/timefn.cpp \
	../libclamunrar/ui.cpp \
	../libclamunrar/unicode.cpp \
	../libclamunrar/unpack.cpp \
	../libclamunrar/volume.cpp

lib_LTLIBRARIES += libclamunrar.la
EXTRA_DIST += @top_srcdir@/libclamunrar/libclamunrar.map


libclamunrar_iface_la_LIBADD = libclamunrar.la
libclamunrar_iface_la_LDFLAGS = -module @TH_SAFE@ -version-info @LIBCLAMAV_VERSION@ -no-undefined

if VERSIONSCRIPT
libclamunrar_iface_la_LDFLAGS += -Wl,@VERSIONSCRIPTFLAG@,@top_srcdir@/libclamunrar_iface/libclamunrar_iface.map
endif

libclamunrar_iface_la_SOURCES = \
	../libclamunrar_iface/unrar_iface.cpp \
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
				    regex/utils.h \
					strlcat.c

libclamav_internal_utils_la_LDFLAGS=-static @SSL_LDFLAGS@ @JSON_LDFLAGS@
libclamav_internal_utils_la_CFLAGS=$(AM_CFLAGS)  -fPIC -DPIC @SSL_CPPFLAGS@ @JSON_CPPFLAGS@ @PCRE_CPPFLAGS@ @XML_CPPFLAGS@
libclamav_internal_utils_la_LIBADD=@SSL_LIBS@ @JSON_LIBS@ @PCRE_LIBS@

libclamav_internal_utils_nothreads_la_SOURCES=str.c\
					conv.c \
					conv.h \
					crypto.c \
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
				    regex/utils.h \
					strlcat.c

libclamav_internal_utils_nothreads_la_LDFLAGS=-static @SSL_LDFLAGS@ @JSON_LDFLAGS@
libclamav_internal_utils_nothreads_la_CFLAGS=$(AM_CFLAGS) -DCL_NOTHREADS @SSL_CPPFLAGS@ @JSON_CPPFLAGS@ @PCRE_CPPFLAGS@
libclamav_internal_utils_nothreads_la_LIBADD=@SSL_LIBS@ @JSON_LIBS@ @PCRE_LIBS@
SUBDIRS=

if ENABLE_LLVM
LLVMLIBADD=c++/libclamavcxx.la -lstdc++ -lm
LLVMDEP=c++/libclamavcxx.la
SUBDIRS+=c++
else
LLVMLIBADD=libclamav_nocxx.la
LLVMDEP=libclamav_nocxx.la
c++/Makefile: c++/Makefile.nollvm.in
	$(AM_V_at) cp $< $@
distclean-recursive distdir maintainer-clean-recursive: c++/Makefile
endif

if USE_INTERNAL_MSPACK
# libmspack version: 0.8alpha (1:0:1)
LIBMSPACK_VERSION = 1:0:1

libclammspack_la_CFLAGS = -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64 -Wno-unused-parameter -I@top_srcdir@/libclammspack/mspack
libclammspack_la_LDFLAGS = -version-info $(LIBMSPACK_VERSION) -no-undefined -export-symbols-regex '^mspack_'

# if VERSIONSCRIPT
# libclammspack_la_LDFLAGS += -Wl,@VERSIONSCRIPTFLAG@,@top_srcdir@/libclammspack/libclammspack.map
# endif

libclammspack_la_SOURCES = \
	../libclammspack/mspack/cab.h \
	../libclammspack/mspack/cabc.c \
	../libclammspack/mspack/cabd.c \
	../libclammspack/mspack/chm.h \
	../libclammspack/mspack/chmc.c \
	../libclammspack/mspack/chmd.c \
	../libclammspack/mspack/crc32.c \
	../libclammspack/mspack/crc32.h \
	../libclammspack/mspack/des.h \
	../libclammspack/mspack/hlp.h \
	../libclammspack/mspack/hlpc.c \
	../libclammspack/mspack/hlpd.c \
	../libclammspack/mspack/kwaj.h \
	../libclammspack/mspack/kwajc.c \
	../libclammspack/mspack/kwajd.c \
	../libclammspack/mspack/lit.h \
	../libclammspack/mspack/litc.c \
	../libclammspack/mspack/litd.c \
	../libclammspack/mspack/lzss.h \
	../libclammspack/mspack/lzssd.c \
	../libclammspack/mspack/lzx.h \
	../libclammspack/mspack/lzxc.c \
	../libclammspack/mspack/lzxd.c \
	../libclammspack/mspack/mspack.h \
	../libclammspack/mspack/mszip.h \
	../libclammspack/mspack/mszipc.c \
	../libclammspack/mspack/mszipd.c \
	../libclammspack/mspack/oab.h \
	../libclammspack/mspack/oabc.c \
	../libclammspack/mspack/oabd.c \
	../libclammspack/mspack/qtm.h \
	../libclammspack/mspack/qtmd.c \
	../libclammspack/mspack/readbits.h \
	../libclammspack/mspack/readhuff.h \
	../libclammspack/mspack/sha.h \
	../libclammspack/mspack/system.c \
	../libclammspack/mspack/system.h \
	../libclammspack/mspack/szdd.h \
	../libclammspack/mspack/szddc.c \
	../libclammspack/mspack/szddd.c

lib_LTLIBRARIES += libclammspack.la
# EXTRA_DIST += @top_srcdir@/libclammspack/libclammspack.map

MSPACK_CFLAGS = -I@top_srcdir@/libclammspack/mspack -DHAVE_INTERNAL_MSPACK
MSPACKLIBADD = -lclammspack
MSPACKDEP = libclammspack.la

else
MSPACK_CFLAGS = $(LIBMSPACK_CFLAGS)
MSPACKLIBADD = $(LIBMSPACK_LIBS)
MSPACKDEP =

libmspack/Makefile: 
.PHONY: distdir distclean maintainer-clean
distdir:
	echo "make distdir requires --with-system-libmspack=no"
	exit 1

# nothing to do here, rules must exist for distclean to succeed
distclean:
	-rm -f Makefile
maintainer-clean:

distclean-recursive distdir maintainer-clean-recursive: libmspack/Makefile
endif

if ENABLE_YARA
YARA_CFLAGS=-DHAVE_YARA
endif

libclamav_nocxx_la_SOURCES = bytecode_nojit.c
libclamav_nocxx_la_CFLAGS=$(AM_CFLAGS) @SSL_CPPFLAGS@ @JSON_CPPFLAGS@ @PCRE_CPPFLAGS@

libclamav_la_LIBADD = @SSL_LIBS@ @JSON_LIBS@ @PCRE_LIBS@ @LIBCLAMAV_LIBS@ @LIBLTDL@ $(IFACELIBADD) $(MSPACKLIBADD) $(LLVMLIBADD) libclamav_internal_utils.la @THREAD_LIBS@ @LIBM@
libclamav_la_DEPENDENCIES =  @LTDLDEPS@ $(IFACEDEP) $(LLVMDEP) $(MSPACKDEP) libclamav_internal_utils.la
libclamav_la_CFLAGS = $(MSPACK_CFLAGS) $(AM_CFLAGS) $(YARA_CFLAGS) -DSEARCH_LIBDIR=\"$(libdir)\" @LIBCLAMAV_CPPFLAGS@ @SSL_CPPFLAGS@ @JSON_CPPFLAGS@ @ICONV_CPPFLAGS@ @PCRE_CPPFLAGS@ @XML_CPPFLAGS@
libclamav_la_LDFLAGS = @SSL_LDFLAGS@ @TH_SAFE@ @JSON_LDFLAGS@ @ICONV_LDFLAGS@ $(XML_LIBS) -version-info @LIBCLAMAV_VERSION@ -no-undefined

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
	libmspack.c \
	libmspack.h \
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
	ooxml.c \
	ooxml.h \
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
	pdfng.c \
	pdfdecode.c \
	pdfdecode.h \
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
	xdp.c \
	xdp.h \
	mbr.c \
	mbr.h \
	gpt.c \
	gpt.h \
	apm.c \
	apm.h \
	prtn_intxn.c \
	prtn_intxn.h \
	json_api.c\
	json_api.h\
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
	stats_json.c \
	stats_json.h \
	hostid.c \
	hostid.h \
	openioc.c \
	openioc.h \
	msdoc.c \
	msdoc.h \
	matcher-pcre.c \
	matcher-pcre.h \
	regex_pcre.c \
	regex_pcre.h \
	msxml.c \
	msxml.h \
	msxml_parser.c \
	msxml_parser.h \
	tiff.c \
	tiff.h \
	hwp.c \
	hwp.h \
	lzw/lzwdec.c \
	lzw/lzwdec.h \
	matcher-byte-comp.c \
	matcher-byte-comp.h

if ENABLE_YARA
libclamav_la_SOURCES += yara_arena.c \
	yara_arena.h \
	yara_compiler.c \
	yara_compiler.h \
	yara_exec.c \
	yara_exec.h \
	yara_hash.c \
	yara_hash.h \
	yara_grammar.y \
	yara_lexer.l \
	yara_lexer.h \
	yara_parser.c \
	yara_parser.h \
	yara_clam.h
endif

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
COMMON_CLEANFILES+=version.h version.h.tmp *.gcda *.gcno
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

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

AM_CPPFLAGS = -I$(top_srcdir) -I@srcdir@/nsis -I@srcdir@/lzma

if ENABLE_UNRAR
libclamav_la_LIBADD = @LIBCLAMAV_LIBS@ @THREAD_LIBS@ lzma/liblzma.la $(top_builddir)/libclamunrar_iface/libclamunrar_iface.la
else
libclamav_la_LIBADD = @LIBCLAMAV_LIBS@ @THREAD_LIBS@ lzma/liblzma.la
endif

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
        md5.c \
        md5.h \
        others.c \
        others.h \
        readdb.c \
	readdb.h \
	cvd.c \
	cvd.h \
	dsig.c \
	dsig.h \
        str.c \
	str.h \
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
	iana_tld.h \
	regex_list.c \
	regex_list.h \
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
	textnorm.h

libclamav_internal_utils_la_SOURCES=str.c \
				    str.h \
				    others.c \
				    others.h

libclamav_internal_utils_la_LDFLAGS=-static
libclamav_internal_utils_la_CFLAGS=-DCLI_MEMFUNSONLY
lib_LTLIBRARIES = libclamav.la
noinst_LTLIBRARIES = libclamav_internal_utils.la
EXTRA_DIST = regex/engine.c libclamav.map

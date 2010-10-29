#
# Tag Image File Format Library
#
# Copyright (c) 1988, 1989, 1990, 1991, 1992, 1993, 1994 Sam Leffler
# Copyright (c) 1991, 1992, 1993, 1994 Silicon Graphics, Inc.
# 
# Permission to use, copy, modify, distribute, and sell this software and 
# its documentation for any purpose is hereby granted without fee, provided
# that (i) the above copyright notices and this permission notice appear in
# all copies of the software and related documentation, and (ii) the names of
# Sam Leffler and Silicon Graphics may not be used in any advertising or
# publicity relating to the software without the specific, prior written
# permission of Stanford and Silicon Graphics.
# 
# THE SOFTWARE IS PROVIDED "AS-IS" AND WITHOUT WARRANTY OF ANY KIND, 
# EXPRESS, IMPLIED OR OTHERWISE, INCLUDING WITHOUT LIMITATION, ANY 
# WARRANTY OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.  
# 
# IN NO EVENT SHALL SAM LEFFLER OR SILICON GRAPHICS BE LIABLE FOR
# ANY SPECIAL, INCIDENTAL, INDIRECT OR CONSEQUENTIAL DAMAGES OF ANY KIND,
# OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
# WHETHER OR NOT ADVISED OF THE POSSIBILITY OF DAMAGE, AND ON ANY THEORY OF 
# LIABILITY, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE 
# OF THIS SOFTWARE.
#

#
# Makefile for Mac using MPW 3.2.3 and MPW C 3.2.4
#
COPTS = -model far

.c.o %c4 .c
	{C} {COPTS} {CFLAGS} -s {Default} {DepDir}{Default}.c -o {TargDir}{Default}.c.o

RM = delete -y -i

CONF_LIBRARY= %b6
	-d USE_CONST=0 %b6
	-d BSDTYPES
NULL=

IPATH= -I ::libtiff

CFLAGS=	-w -m {IPATH} {CONF_LIBRARY}

LIBPORT= ::port:libport.o

LOptions= -model far -w -srt -d -c 'MPS ' -t MPST

LIBTIFF= ::libtiff:libtiff.o

LIBS=	{LIBTIFF} %b6
	{LIBPORT} %b6
	"{CLibraries}"CSANELib.o  %b6
	"{CLibraries}"Math.o  %b6
	"{CLibraries}"StdClib.o  %b6
	"{Libraries}"Stubs.o  %b6
	"{Libraries}"Runtime.o  %b6
	"{Libraries}"Interface.o  %b6
	"{Libraries}"ToolLibs.o  %b6
	{NULL}

SRCS= %b6
	pal2rgb.c %b6
	ras2tiff.c %b6
	thumbnail.c %b6
	tiff2bw.c %b6
	tiff2ps.c %b6
	tiffcmp.c %b6
	tiffcp.c %b6
	tiffdither.c %b6
	tiffdump.c %b6
	tiffinfo.c %b6
	tiffmedian.c %b6
	{NULL}
	
MACHALL=ras2tiff

ALL= %b6
	tiffinfo  %b6
	tiffcmp  %b6
	tiffcp  %b6
	tiffdump  %b6
	tiffmedian  %b6
	tiff2bw  %b6
	tiffdither  %b6
	tiff2ps  %b6
	pal2rgb  %b6
	gif2tiff  %b6
	{MACHALL}

all %c4 {ALL}

tiffinfo %c4 tiffinfo.c.o {LIBTIFF} 
	Link {LOptions} tiffinfo.c.o {LIBS} -o tiffinfo
	
tiffcmp %c4 tiffcmp.c.o {LIBTIFF}
	Link {LOptions} tiffcmp.c.o {LIBS} -o tiffcmp
	
tiffcp %c4 tiffcp.c.o {LIBTIFF}
	Link {LOptions} tiffcp.c.o {LIBS} -o tiffcp
	
tiffdump %c4 tiffdump.c.o {LIBTIFF}
	Link {LOptions} tiffdump.c.o {LIBS} -o tiffdump 
	
tiffmedian %c4 tiffmedian.c.o {LIBTIFF}
	Link {LOptions} tiffmedian.c.o {LIBS} -o tiffmedian
	
tiff2ps %c4 tiff2ps.c.o {LIBTIFF}
	Link {LOptions} tiff2ps.c.o {LIBS} -o tiff2ps
	
# junky stuff...
# convert RGB image to B&W
tiff2bw %c4 tiff2bw.c.o {LIBTIFF}
	Link {LOptions} tiff2bw.c.o {LIBS} -o tiff2bw
	
# convert B&W image to bilevel w/ FS dithering
tiffdither %c4 tiffdither.c.o {LIBTIFF}
	Link {LOptions} tiffdither.c.o {LIBS} -o tiffdither
	
# GIF converter
gif2tiff %c4 gif2tiff.c.o {LIBTIFF}
	Link {LOptions} gif2tiff.c.o {LIBS} -o gif2tiff
	
# convert Palette image to RGB
pal2rgb %c4 pal2rgb.c.o {LIBTIFF}
	Link {LOptions} pal2rgb.c.o {LIBS} -o pal2rgb
	
# Sun rasterfile converter
ras2tiff %c4 ras2tiff.c.o {LIBTIFF}
	Link {LOptions} ras2tiff.c.o {LIBS} -o ras2tiff

# generate thumbnail images from fax
thumbnail %c4 thumbnail.c.o {LIBTIFF}
        Link {LOptions} thumbnail.c.o {LIBS} -o thumbnail
	
clean %c4
	{RM} {ALL} %c5.c.o ycbcr

# Tag Image File Format (TIFF) Software
#
# Copyright (C) 2004, Andrey Kiselev <dron@ak4719.spb.edu>
#
# Permission to use, copy, modify, distribute, and sell this software and 
# its documentation for any purpose is hereby granted without fee, provided
# that (i) the above copyright notices and this permission notice appear in
# all copies of the software and related documentation, and (ii) the names of
# Sam Leffler and Silicon Graphics may not be used in any advertising or
# publicity relating to the software without the specific, prior written
# permission of Sam Leffler and Silicon Graphics.
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

# Process this file with automake to produce Makefile.in.

LIBTIFF = $(top_builddir)/libtiff/libtiff.la

#EXTRA_DIST = Makefile.vc

TESTS = $(check_PROGRAMS)

check_PROGRAMS = ascii_tag long_tag short_tag strip_rw

ascii_tag_SOURCES = ascii_tag.c
ascii_tag_LDADD = $(LIBTIFF)
long_tag_SOURCES = long_tag.c check_tag.c
long_tag_LDADD = $(LIBTIFF)
short_tag_SOURCES = short_tag.c check_tag.c
short_tag_LDADD = $(LIBTIFF)
strip_rw_SOURCES = strip_rw.c strip.c test_arrays.c test_arrays.h
strip_rw_LDADD = $(LIBTIFF)

INCLUDES = -I$(top_srcdir)/libtiff


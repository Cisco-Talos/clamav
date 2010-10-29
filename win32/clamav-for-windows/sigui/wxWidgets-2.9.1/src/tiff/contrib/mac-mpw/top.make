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
#
#  Written by: Niles D. Ritter
#

RM= delete -y -i
PORT=:port:
LIBTIFF=:libtiff:
TOOLS=:tools:
CONTRIB=:contrib:mac-mpw:

MACTRANS="{CONTRIB}mactrans"

NULL=

MAKEFILES = %b6
	{PORT}Makefile %b6
	{LIBTIFF}Makefile %b6
	{TOOLS}Makefile %b6
	{NULL}
	
all %c4 PORT LIBTIFF TOOLS

MAKEFILES %c4 {MAKEFILES}
TOOLS %c4 LIBTIFF

LIBTIFF %c4 PORT

# Create the port routines
PORT %c4 {PORT}Makefile
	directory {PORT}
	(make || set status 0) > build.mpw
	set echo 1
	execute build.mpw
	set echo 0
	{RM} build.mpw  || set status 0
	directory ::

# Create the port routines
LIBTIFF %c4 {LIBTIFF}Makefile
	directory {LIBTIFF}
	(make || set status 0) > build.mpw
	set echo 1
	execute build.mpw
	set echo 0
	{RM} build.mpw  || set status 0
	directory ::

# Create the tools
TOOLS %c4 {TOOLS}Makefile
	directory {TOOLS}
	(make || set status 0) > build.mpw
	set echo 1
	execute build.mpw
	set echo 0
	{RM} build.mpw  || set status 0
	directory ::

# Makefile dependencies
{PORT}Makefile  %c4 {CONTRIB}port.make
	catenate {CONTRIB}port.make | {MACTRANS} > {PORT}Makefile

{LIBTIFF}Makefile  %c4 {CONTRIB}libtiff.make
	catenate {CONTRIB}libtiff.make | {MACTRANS} > {LIBTIFF}Makefile

{TOOLS}Makefile  %c4 {CONTRIB}tools.make
	catenate {CONTRIB}tools.make | {MACTRANS} > {TOOLS}Makefile


clean %c4  clean.port clean.contrib clean.libtiff clean.tools clean.make

clean.port %c4
	directory {PORT}
	(make clean || set status 0) > purge
	purge
	{RM} purge  || set status 0
	{RM} Makefile || set status 0
	{RM} build.mpw || set status 0
	cd ::

clean.contrib %c4
	{RM} {MACTRANS} || set status 0
	
clean.libtiff %c4
	directory {LIBTIFF}
	(make clean || set status 0) > purge
	purge
	{RM} purge  || set status 0
	{RM} Makefile || set status 0
	{RM} build.mpw || set status 0
	cd ::

clean.tools %c4
	directory {TOOLS}
	(make clean || set status 0) > purge
	purge
	{RM} purge  || set status 0
	{RM} Makefile || set status 0
	{RM} build.mpw || set status 0
	cd ::

clean.make %c4
	{RM} {MAKEFILES} || set status 0
	{RM} build.mpw || set status 0


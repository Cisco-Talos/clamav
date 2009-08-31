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

AM_CPPFLAGS = -I$(top_srcdir)/../.. -I$(top_srcdir)/..
ACLOCAL_AMFLAGS=-I m4
if DEBUG_BUILD
LLVM_CONFIG=llvm/Debug/bin/llvm-config
else
LLVM_CONFIG=llvm/Release/bin/llvm-config
endif

$(LLVM_CONFIG): build-llvm

libclamavcxx_la_CPPFLAGS = $(AM_CPPFLAGS) `$(LLVM_CONFIG) --cppflags`
libclamavcxx_la_LDFLAGS = `$(LLVM_CONFIG) --ldflags --libs jit nativecodegen`
libclamavcxx_la_SOURCES = bytecode2llvm.cpp dummy.h
noinst_LTLIBRARIES = libclamavcxx.la
bytecode2llvm.cpp: build-llvm

build-llvm:
	+$(GMAKE) -C llvm OPTIMIZE_OPTION=-O2 libs-only

build-llvm-for-check:
	+$(GMAKE) -C llvm OPTIMIZE_OPTION=-O2 tools-only

clean-local:
	+$(GMAKE) -C llvm clean

check-llvm: build-llvm-for-check
	+$(GMAKE) -C llvm check
	+$(GMAKE) -C llvm unittests


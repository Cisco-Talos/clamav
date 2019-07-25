#
#  Copyright (C) 2018 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
#
#  Authors: Mickey Sola
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

bin_PROGRAMS = clamonacc

clamonacc_SOURCES = \
    $(top_srcdir)/shared/output.c \
    $(top_srcdir)/shared/output.h \
    $(top_srcdir)/shared/optparser.c \
    $(top_srcdir)/shared/optparser.h \
    $(top_srcdir)/shared/misc.c \
    $(top_srcdir)/shared/misc.h \
    $(top_srcdir)/shared/getopt.c \
    $(top_srcdir)/shared/getopt.h \
    $(top_srcdir)/shared/actions.c \
    $(top_srcdir)/shared/actions.h \
    clamonacc.c \
    clamonacc.h \
    ./client/client.c \
    ./client/client.h \
    ./client/protocol.c \
    ./client/protocol.h \
    ./client/communication.c \
    ./client/communication.h \
    ./inotif/inotif.c \
    ./inotif/inotif.h \
    ./fanotif/fanotif.c \
    ./fanotif/fanotif.h \
    ./inotif/hash.c \
    ./inotif/hash.h \
    ./misc/utils.c \
    ./misc/utils.h \
    ./misc/priv_fts.h \
    ./scan/thread.c \
    ./scan/thread.h \
    ./scan/queue.c \
    ./scan/queue.h \
    ./c-thread-pool/thpool.c \
    ./c-thread-pool/thpool.h


if !SYSTEM_LFS_FTS
clamonacc_SOURCES += ./misc/fts.c
endif

AM_CFLAGS=@WERR_CFLAGS@

DEFS = @DEFS@ -DCL_NOLIBCLAMAV
LIBS = $(top_builddir)/libclamav/libclamav_internal_utils.la @CURL_LIBS@ @CLAMONACC_LIBS@ @THREAD_LIBS@
AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/clamonacc -I$(top_srcdir)/shared -I$(top_srcdir)/libclamav @CURL_CPPFLAGS@ @SSL_CPPFLAGS@ @CLAMONACC_CPPFLAGS@ @JSON_CPPFLAGS@ @PCRE_CPPFLAGS@

AM_INSTALLCHECK_STD_OPTIONS_EXEMPT=clamonacc$(EXEEXT)
CLEANFILES=*.gcda *.gcno


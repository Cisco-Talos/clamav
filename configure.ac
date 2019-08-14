dnl   Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
dnl   Copyright (C) 2007-2013 Sourcefire, Inc.
dnl   Copyright (C) 2002-2007 Tomasz Kojm <tkojm@clamav.net>
dnl   readdir_r checks (c) COPYRIGHT MIT 1995
dnl   socklen_t check (c) Alexander V. Lukyanov <lav@yars.free.net>
dnl
dnl   This program is free software; you can redistribute it and/or modify
dnl   it under the terms of the GNU General Public License as published by
dnl   the Free Software Foundation; either version 2 of the License, or
dnl   (at your option) any later version.
dnl
dnl   This program is distributed in the hope that it will be useful,
dnl   but WITHOUT ANY WARRANTY; without even the implied warranty of
dnl   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
dnl   GNU General Public License for more details.
dnl
dnl   You should have received a copy of the GNU General Public License
dnl   along with this program; if not, write to the Free Software
dnl   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
dnl   MA 02110-1301, USA.

AC_PREREQ([2.59])
dnl For a release change [devel] to the real version [0.xy]
dnl also change VERSION below
AC_INIT([ClamAV], [0.101.4], [https://bugzilla.clamav.net/], [clamav], [https://www.clamav.net/])

dnl enable C++
AC_PROG_CXX()

AH_BOTTOM([#include "platform.h"])
dnl put configure auxiliary into config
AC_CONFIG_AUX_DIR([config])
AC_CONFIG_HEADERS([clamav-config.h libclammspack/config.h:libclammspack/config.h.in])

dnl safety check, this used to be a parameter to AC_INIT
AC_CONFIG_SRCDIR([clamscan/clamscan.c])
AC_CONFIG_MACRO_DIR([m4])
AC_CREATE_TARGET_H([target.h])

dnl -Wall and -Werror here are NOT CFLAGS, they refer to automake warnings
dnl enable stealth builds and psychedelic tests
AM_INIT_AUTOMAKE([1.11 -Wall -Wportability -Wno-override std-options foreign dist-bzip2 no-define color-tests parallel-tests tar-ustar])
AM_SILENT_RULES([yes])

m4_ifdef([AM_PROG_AR], [AM_PROG_AR])

dnl we told automake to not define these, since we want to include
dnl the date in the version
AC_DEFINE([PACKAGE], PACKAGE_NAME, [Name of package])
AC_USE_SYSTEM_EXTENSIONS

m4_include([m4/reorganization/version.m4])

LT_CONFIG_LTDL_DIR([libltdl])
LT_INIT([dlopen disable-static])
LTDL_INIT([recursive])
PKG_PROG_PKG_CONFIG(0.16)

m4_include([m4/reorganization/build_tools.m4])
m4_include([m4/reorganization/headers.m4])

AC_CONFIG_FILES([libltdl/Makefile])

AC_DEFINE([SCANBUFF], 131072, [scan buffer size])
AC_DEFINE([FILEBUFF], 8192,   [file i/o buffer size])

m4_include([m4/reorganization/c_options.m4])
m4_include([m4/reorganization/compiler_checks.m4])
m4_include([m4/reorganization/linker_checks.m4])

AC_ARG_ENABLE([experimental],
[AS_HELP_STRING([--enable-experimental], [enable experimental code])],
enable_experimental=$enableval, enable_experimental="no")

if test "$enable_experimental" = "yes"; then
  AC_DEFINE([CL_EXPERIMENTAL],1,[enable experimental code])
  VERSION_SUFFIX="$VERSION_SUFFIX-exp"
fi

build_configure_args=`echo "$ac_configure_args" | sed -e 's/[\"]//g'`
AC_SUBST([BUILD_CONFIGURE_FLAGS], [$build_configure_args])

m4_include([m4/reorganization/code_checks/fuzz.m4])
m4_include([m4/reorganization/code_checks/functions.m4])
m4_include([m4/reorganization/code_checks/mpool.m4])
m4_include([m4/reorganization/code_checks/unit_tests.m4])
m4_include([m4/reorganization/code_checks/coverage.m4])

dnl libclamav dependencies
m4_include([m4/reorganization/libs/xml.m4])
m4_include([m4/reorganization/libs/openssl.m4])
m4_include([m4/reorganization/libs/json.m4])
m4_include([m4/reorganization/libs/pcre.m4])
m4_include([m4/reorganization/libs/libmspack.m4])

if test "x$use_internal_mspack" = "xno"; then
    mspack_msg="External, $LIBMSPACK_CFLAGS $LIBMSPACK_LIBS"
fi

AM_MAINTAINER_MODE
m4_include([m4/reorganization/libs/libz.m4])
m4_include([m4/reorganization/libs/bzip.m4])
m4_include([m4/reorganization/libs/unrar.m4])
m4_include([m4/reorganization/libs/systemd.m4])
m4_include([m4/reorganization/code_checks/ipv6.m4])
m4_include([m4/reorganization/code_checks/dns.m4])
m4_include([m4/reorganization/code_checks/fanotify.m4])
m4_include([m4/reorganization/code_checks/setpgrp.m4])
m4_include([m4/reorganization/milter/enable.m4])
m4_include([m4/reorganization/code_checks/iconv.m4])
m4_include([m4/reorganization/code_checks/pthreads.m4])
m4_include([m4/reorganization/code_checks/reentrant.m4])
m4_include([m4/reorganization/utility_checks/id.m4])
m4_include([m4/reorganization/utility_checks/yp.m4])
m4_include([m4/reorganization/usergroup.m4])
m4_include([m4/reorganization/debug.m4])
m4_include([m4/reorganization/customversion.m4])
m4_include([m4/reorganization/nocache.m4])
m4_include([m4/reorganization/dns.m4])
m4_include([m4/reorganization/bigstack.m4])
m4_include([m4/reorganization/dbdir.m4])
m4_include([m4/reorganization/cfgdir.m4])
m4_include([m4/reorganization/code_checks/in_port_t.m4])
m4_include([m4/reorganization/code_checks/in_addr_t.m4])
m4_include([m4/reorganization/os_checks.m4])
m4_include([m4/reorganization/milter/check.m4])
m4_include([m4/reorganization/code_checks/pthread_02.m4])
m4_include([m4/reorganization/code_checks/readdir.m4])
m4_include([m4/reorganization/code_checks/ctime.m4])
m4_include([m4/reorganization/code_checks/socklen_t.m4])
m4_include([m4/reorganization/clamav_user.m4])
m4_include([m4/reorganization/code_checks/compiler_attribs.m4])
m4_include([m4/reorganization/code_checks/select.m4])
m4_include([m4/reorganization/code_checks/stat64.m4])
m4_include([m4/reorganization/code_checks/shift.m4])
m4_include([m4/reorganization/code_checks/features.m4])
m4_include([m4/reorganization/clamdtop.m4])
m4_include([m4/reorganization/distcheck.m4])
m4_include([m4/reorganization/llvm.m4])
m4_include([m4/reorganization/sha_collect.m4])
m4_include([m4/reorganization/yara.m4])
m4_include([m4/reorganization/code_checks/fts.m4])
m4_include([m4/reorganization/libfreshclam.m4])
m4_include([m4/reorganization/prelude.m4])
m4_include([m4/reorganization/bsd.m4])

dnl Freshclam dependencies
m4_include([m4/reorganization/libs/curl.m4])
m4_include([m4/reorganization/substitutions.m4])
m4_include([m4/reorganization/strni.m4])

if test "x$use_internal_mspack" = "xyes"; then
    mspack_msg="Internal"
    AC_SYS_LARGEFILE
else
    mspack_msg="External, $LIBMSPACK_CFLAGS $LIBMSPACK_LIBS"
fi

AC_CONFIG_FILES([
clamscan/Makefile
database/Makefile
docs/Makefile
clamd/Makefile
clamd/clamav-daemon.service
clamd/clamav-daemon.socket
clamdscan/Makefile
clamsubmit/Makefile
clamav-milter/Makefile
freshclam/clamav-freshclam.service
freshclam/Makefile
sigtool/Makefile
clamconf/Makefile
etc/Makefile
test/Makefile
unit_tests/Makefile
fuzz/Makefile
clamdtop/Makefile
clambc/Makefile
libfreshclam/Makefile
Makefile
clamav-config
libclamav.pc
platform.h
docs/man/clamav-milter.8
docs/man/clamav-milter.conf.5
docs/man/clambc.1
docs/man/clamconf.1
docs/man/clamd.8
docs/man/clamd.conf.5
docs/man/clamdscan.1
docs/man/clamscan.1
docs/man/freshclam.1
docs/man/freshclam.conf.5
docs/man/sigtool.1
docs/man/clamdtop.1
docs/man/clamsubmit.1
clamav-types.h
])

# Define variables needed to generate clamav-types.h.
m4_include([m4/reorganization/types.m4])

AC_OUTPUT

if test "$enable_llvm" = "yes" && test "$subdirfailed" != "no"; then
    AC_MSG_ERROR([Failed to configure LLVM, and LLVM was explicitly requested])
fi
if test "$enable_llvm" = "auto" && test "$subdirfailed" != "no"; then
    system_llvm="MIA"
    llvm_linking=""
fi

AM_CONDITIONAL([ENABLE_LLVM],
	       [test "$subdirfailed" != "yes" && test "$enable_llvm" != "no"])
AM_CONDITIONAL([ENABLE_YARA],
	       [test "$enable_yara" != "no"])
AM_CONDITIONAL([ENABLE_CLAMSUBMIT],
	       [test "X$have_curl" = "Xyes" && test "X$have_json" = "Xyes"])
no_recursion="yes";

AC_OUTPUT([libclamav/Makefile])

# Print a summary of what features we enabled
AC_MSG_NOTICE([Summary of detected features follows])

cat <<EOF
              OS          : $target_os
              pthreads    : $have_pthreads ($THREAD_LIBS)
EOF

AC_MSG_NOTICE([Summary of miscellaneous features])
if test "x$CHECK_LIBS" = "x"; then
    check_libs="no"
else
    check_libs="$CHECK_LIBS"
fi
CL_MSG_STATUS([check       ],[$check_libs],[$enable_check_ut])
CL_MSG_STATUS([fanotify    ],[$have_fanotify],[$have_fanotify])
if test "x$ac_cv_have_control_in_msghdr" = "xyes"; then
    CL_MSG_STATUS([fdpassing   ],[$have_fdpass],[$want_fdpassing])
else
    CL_MSG_STATUS([fdpassing   ],[n/a],[])
fi
CL_MSG_STATUS([IPv6        ],[$have_cv_ipv6],[$want_ipv6])

AC_MSG_NOTICE([Summary of optional tools])
CL_MSG_STATUS([clamdtop    ],[$CURSES_LIBS],[$enable_clamdtop])
CL_MSG_STATUS([milter      ],[yes],[$have_milter])
if test "X$have_curl" = "Xyes" && test "X$have_json" = "Xyes"; then
    CL_MSG_STATUS([clamsubmit  ], [yes (libjson-c-dev found at $LIBJSON_HOME), libcurl-devel found at $LIBCURL_HOME)], [yes])
else
    if test "X$have_curl" != "Xyes" && test "X$have_json" != "Xyes"; then
        CL_MSG_STATUS([clamsubmit  ], [no (missing libjson-c-dev AND libcurl-devel. Use the website to submit FPs/FNs.)], [no])
    else
        if test "X$have_curl" = "Xyes"; then
            CL_MSG_STATUS([clamsubmit  ], [no (missing libjson-c-dev. Use the website to submit FPs/FNs.)], [no])
        else
            CL_MSG_STATUS([clamsubmit  ], [no (missing libcurl-devel. Use the website to submit FPs/FNs.)], [no])
        fi
    fi
fi

AC_MSG_NOTICE([Summary of engine performance features])
if test "x$enable_debug" = "xyes"; then
    CL_MSG_STATUS([release mode],[no],[debug build])
else
    CL_MSG_STATUS([release mode],[yes],[yes])
fi
have_jit="no"
if test "$subdirfailed" = "no"; then
    have_jit="yes"
fi
if test "$enable_llvm" = "no"; then
   CL_MSG_STATUS([llvm        ],[$have_jit],[$enable_llvm])
elif test "x$llvmconfig" = "x"; then
   CL_MSG_STATUS([llvm        ],[$have_jit ($llvmver), from internal],[$enable_llvm])
else
   CL_MSG_STATUS([llvm        ],[$have_jit ($llvmver), from $llvmconfig ($llvm_linking)],[$enable_llvm])
fi
CL_MSG_STATUS([mempool     ],[$have_mempool],[$enable_mempool])

AC_MSG_NOTICE([Summary of engine detection features])
CL_MSG_STATUS([bzip2       ],[$bzip_check],[$want_bzip2])
CL_MSG_STATUS([zlib        ],[$ZLIB_HOME],[yes])
CL_MSG_STATUS([unrar       ],[$want_unrar],[$want_unrar])
if test "X$have_json" = "Xyes"; then
    CL_MSG_STATUS([preclass    ],[yes (libjson-c-dev found at $LIBJSON_HOME)],[yes])
else
    CL_MSG_STATUS([preclass    ],[no (missing libjson-c-dev)],[no])
fi
if test "x$PCRE_HOME" = "x"; then
    CL_MSG_STATUS([pcre        ],[no],[$have_pcre])
else
    CL_MSG_STATUS([pcre        ],[$PCRE_HOME],[$have_pcre])
fi
CL_MSG_STATUS([libmspack   ],[yes],[$mspack_msg])
if test "x$XML_LIBS" = "x"; then
    CL_MSG_STATUS([libxml2     ],[no],[])
else
    CL_MSG_STATUS([libxml2     ],[yes, from $XML_HOME],[])
fi
CL_MSG_STATUS([yara        ],[$enable_yara],[$enable_yara])
CL_MSG_STATUS([fts         ],[yes],[$lfs_fts_msg])


# Yep, downgrading the compiler avoids the bug too:
# 4.0.x, and 4.1.0 are the known buggy versions
# 3.4 doesn't have the bug
if test "x$gcc_check" != "xyes"; then
	AC_MSG_WARN([
****** Optimizations disabled to avoid compiler bugs
****** The resulting binaries will be slow!
****** It is recommended to either upgrade or downgrade your compiler
])
fi

if test "x$cross_compiling" != "xno" || test "x$gcc_check" != "xyes" || test "x$zlib_check" = "xno" || test "x$bzip_check" != "xok" ; then
AC_MSG_WARN([
****** WARNING:
****** You are cross compiling to a different host or you are
****** linking to bugged system libraries or you have manually
****** disabled important configure checks.
****** Please be aware that this build may be badly broken.
****** DO NOT REPORT BUGS BASED ON THIS BUILD !!!
])
fi


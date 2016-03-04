# Portability macros for glibc argz.                    -*- Autoconf -*-
#
#   Copyright (C) 2004-2007, 2011-2015 Free Software Foundation, Inc.
#   Written by Gary V. Vaughan <gary@gnu.org>
#
# This file is free software; the Free Software Foundation gives
# unlimited permission to copy and/or distribute it, with or without
# modifications, as long as this notice is preserved.

# serial 1 ltargz.m4

AC_DEFUN([LT_FUNC_ARGZ], [
AC_CHECK_HEADERS([argz.h], [], [], [AC_INCLUDES_DEFAULT])

AC_CHECK_TYPES([error_t],
  [],
  [AC_DEFINE([error_t], [int],
   [Define to a type to use for 'error_t' if it is not otherwise available.])
   AC_DEFINE([__error_t_defined], [1], [Define so that glibc/gnulib argp.h
    does not typedef error_t.])],
  [#if defined(HAVE_ARGZ_H)
#  include <argz.h>
#endif])

LT_ARGZ_H=
AC_CHECK_FUNCS([argz_add argz_append argz_count argz_create_sep argz_insert \
	argz_next argz_stringify], [], [LT_ARGZ_H=lt__argz.h; AC_LIBOBJ([lt__argz])])

dnl if have system argz functions, allow forced use of
dnl libltdl-supplied implementation (and default to do so
dnl on "known bad" systems). Could use a runtime check, but
dnl (a) detecting malloc issues is notoriously unreliable
dnl (b) only known system that declares argz functions,
dnl     provides them, yet they are broken, is cygwin
dnl     releases prior to 16-Mar-2007 (1.5.24 and earlier)
dnl So, it's more straightforward simply to special case
dnl this for known bad systems.
AS_IF([test -z "$LT_ARGZ_H"],
    [AC_CACHE_CHECK(
        [if argz actually works],
        [lt_cv_sys_argz_works],
        [[case $host_os in #(
	 *cygwin*)
	   lt_cv_sys_argz_works=no
	   if test no != "$cross_compiling"; then
	     lt_cv_sys_argz_works="guessing no"
	   else
	     lt_sed_extract_leading_digits='s/^\([0-9\.]*\).*/\1/'
	     save_IFS=$IFS
	     IFS=-.
	     set x `uname -r | sed -e "$lt_sed_extract_leading_digits"`
	     IFS=$save_IFS
	     lt_os_major=${2-0}
	     lt_os_minor=${3-0}
	     lt_os_micro=${4-0}
	     if test 1 -lt "$lt_os_major" \
		|| { test 1 -eq "$lt_os_major" \
		  && { test 5 -lt "$lt_os_minor" \
		    || { test 5 -eq "$lt_os_minor" \
		      && test 24 -lt "$lt_os_micro"; }; }; }; then
	       lt_cv_sys_argz_works=yes
	     fi
	   fi
	   ;; #(
	 *) lt_cv_sys_argz_works=yes ;;
	 esac]])
     AS_IF([test yes = "$lt_cv_sys_argz_works"],
        [AC_DEFINE([HAVE_WORKING_ARGZ], 1,
                   [This value is set to 1 to indicate that the system argz facility works])],
        [LT_ARGZ_H=lt__argz.h
        AC_LIBOBJ([lt__argz])])])

AC_SUBST([LT_ARGZ_H])
])

# ===========================================================================
#      https://www.gnu.org/software/autoconf-archive/ax_func_mkdir.html
# ===========================================================================
#
# SYNOPSIS
#
#   AX_FUNC_MKDIR
#
# DESCRIPTION
#
#   Check whether mkdir() is mkdir or _mkdir, and whether it takes one or
#   two arguments.
#
#   This macro can define HAVE_MKDIR, HAVE__MKDIR, and MKDIR_TAKES_ONE_ARG,
#   which are expected to be used as follows:
#
#     #if HAVE_MKDIR
#     #  if MKDIR_TAKES_ONE_ARG
#          /* MinGW32 */
#     #    define mkdir(a, b) mkdir(a)
#     #  endif
#     #else
#     #  if HAVE__MKDIR
#          /* plain Windows 32 */
#     #    define mkdir(a, b) _mkdir(a)
#     #  else
#     #    error "Don't know how to create a directory on this system."
#     #  endif
#     #endif
#
# LICENSE
#
#   Copyright (c) 2008 Alexandre Duret-Lutz <adl@gnu.org>
#
#   This program is free software; you can redistribute it and/or modify it
#   under the terms of the GNU General Public License as published by the
#   Free Software Foundation; either version 2 of the License, or (at your
#   option) any later version.
#
#   This program is distributed in the hope that it will be useful, but
#   WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
#   Public License for more details.
#
#   You should have received a copy of the GNU General Public License along
#   with this program. If not, see <https://www.gnu.org/licenses/>.
#
#   As a special exception, the respective Autoconf Macro's copyright owner
#   gives unlimited permission to copy, distribute and modify the configure
#   scripts that are the output of Autoconf when processing the Macro. You
#   need not follow the terms of the GNU General Public License when using
#   or distributing such scripts, even though portions of the text of the
#   Macro appear in them. The GNU General Public License (GPL) does govern
#   all other use of the material that constitutes the Autoconf Macro.
#
#   This special exception to the GPL applies to versions of the Autoconf
#   Macro released by the Autoconf Archive. When you make and distribute a
#   modified version of the Autoconf Macro, you may extend this special
#   exception to the GPL to apply to your modified version as well.

#serial 6

AU_ALIAS([AC_FUNC_MKDIR], [AX_FUNC_MKDIR])
AC_DEFUN([AX_FUNC_MKDIR],
[AC_CHECK_FUNCS([mkdir _mkdir])
AC_CACHE_CHECK([whether mkdir takes one argument],
               [ac_cv_mkdir_takes_one_arg],
[AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#include <sys/stat.h>
#if HAVE_UNISTD_H
#  include <unistd.h>
#endif
]], [[mkdir (".");]])],
[ac_cv_mkdir_takes_one_arg=yes], [ac_cv_mkdir_takes_one_arg=no])])
if test x"$ac_cv_mkdir_takes_one_arg" = xyes; then
  AC_DEFINE([MKDIR_TAKES_ONE_ARG], 1,
            [Define if mkdir takes only one argument.])
fi
])

dnl Note:
dnl =====
dnl I have not implemented the following suggestion because I don't have
dnl access to such a broken environment to test the macro.  So I'm just
dnl appending the comments here in case you have, and want to fix
dnl AX_FUNC_MKDIR that way.
dnl
dnl |Thomas E. Dickey (dickey@herndon4.his.com) said:
dnl |  it doesn't cover the problem areas (compilers that mistreat mkdir
dnl |  may prototype it in dir.h and dirent.h, for instance).
dnl |
dnl |Alexandre:
dnl |  Would it be sufficient to check for these headers and #include
dnl |  them in the AC_COMPILE_IFELSE block?  (and is AC_HEADER_DIRENT
dnl |  suitable for this?)
dnl |
dnl |Thomas:
dnl |  I think that might be a good starting point (with the set of recommended
dnl |  ifdef's and includes for AC_HEADER_DIRENT, of course).

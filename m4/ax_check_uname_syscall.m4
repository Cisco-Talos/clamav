# ===========================================================================
#  http://www.gnu.org/software/autoconf-archive/ax_check_uname_syscall.html
# ===========================================================================
#
# SYNOPSIS
#
#   AX_CHECK_UNAME_SYSCALL
#
# DESCRIPTION
#
#   Check that the POSIX compliant uname(2) call works properly.
#
# LICENSE
#
#   Copyright (c) 2008 Bruce Korb <bkorb@gnu.org>
#
#   Copying and distribution of this file, with or without modification, are
#   permitted in any medium without royalty provided the copyright notice
#   and this notice are preserved. This file is offered as-is, without any
#   warranty.

#serial 5

AU_ALIAS([AG_CHECK_UNAME_SYSCALL], [AX_CHECK_UNAME_SYSCALL])
AC_DEFUN([AX_CHECK_UNAME_SYSCALL],[
  AC_MSG_CHECKING([whether uname(2) is POSIX])
  AC_CACHE_VAL([ax_cv_uname_syscall],[
  AC_TRY_RUN([#include <sys/utsname.h>
int main() { struct utsname unm;
return uname( &unm ); }],[ax_cv_uname_syscall=yes],[ax_cv_uname_syscall=no],[ax_cv_uname_syscall=no]
  ) # end of TRY_RUN]) # end of CACHE_VAL

  AC_MSG_RESULT([$ax_cv_uname_syscall])
  if test x$ax_cv_uname_syscall = xyes
  then
    AC_DEFINE(HAVE_UNAME_SYSCALL, 1,
       [Define this if uname(2) is POSIX])
  fi
]) # end of AC_DEFUN of AX_CHECK_UNAME_SYSCALL

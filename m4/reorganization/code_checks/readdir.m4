dnl Check for readdir_r and number of its arguments
dnl Code from libwww/configure.in

AC_MSG_CHECKING([for readdir_r])
if test -z "$ac_cv_readdir_args"; then
    AC_TRY_COMPILE(
    [
#include <sys/types.h>
#include <dirent.h>
    ],
    [
    struct dirent dir, *dirp;
    DIR *mydir;
    dirp = readdir_r(mydir, &dir);
    ], ac_cv_readdir_args=2)
fi
if test -z "$ac_cv_readdir_args"; then
    AC_TRY_COMPILE(
        [
#include <sys/types.h>
#include <dirent.h>
    ],
    [
        struct dirent dir, *dirp;
        DIR *mydir;
        int rc;
        rc = readdir_r(mydir, &dir, &dirp);
    ], ac_cv_readdir_args=3)
fi

AC_ARG_ENABLE([readdir_r],
[AS_HELP_STRING([--enable-readdir_r], [enable support for readdir_r])],
enable_readdir_r=$enableval, enable_readdir_r="no")

if test "$enable_readdir_r" = "no"; then
    AC_MSG_RESULT(support disabled)
elif test -z "$ac_cv_readdir_args"; then
    AC_MSG_RESULT(no)
else
    if test "$ac_cv_readdir_args" = 2; then
	AC_DEFINE([HAVE_READDIR_R_2],1,[readdir_r takes 2 arguments])
    elif test "$ac_cv_readdir_args" = 3; then
	AC_DEFINE([HAVE_READDIR_R_3],1,[readdir_r takes 3 arguments])
    fi
    AC_MSG_RESULT([yes, and it takes $ac_cv_readdir_args arguments])
fi

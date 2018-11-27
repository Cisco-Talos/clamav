
dnl Check for zlib
AC_MSG_CHECKING([for zlib installation])
AC_ARG_WITH([zlib],
[AS_HELP_STRING([--with-zlib@<:@=DIR@:>@], [path to directory containing zlib library
                @<:@default=/usr/local or /usr if not found in /usr/local@:>@])],
[
if test "$withval"; then
  ZLIB_HOME="$withval"
  AC_MSG_RESULT([using $ZLIB_HOME])
fi
], [
ZLIB_HOME=/usr/local
if test ! -f "$ZLIB_HOME/include/zlib.h"
then
  ZLIB_HOME=/usr
fi
AC_MSG_RESULT([$ZLIB_HOME])
])

CLAMDSCAN_LIBS="$FRESHCLAM_LIBS"

AC_ARG_ENABLE([zlib-vcheck],
[AS_HELP_STRING([--disable-zlib-vcheck], [do not check for buggy zlib version])],
zlib_check=$enableval, zlib_check="yes")

if test ! -f "$ZLIB_HOME/include/zlib.h"
then
    AC_MSG_ERROR([Please install zlib and zlib-devel packages])
else

    vuln=`grep "ZLIB_VERSION \"1.2.0\"" $ZLIB_HOME/include/zlib.h`
    if test -z "$vuln"; then
	vuln=`grep "ZLIB_VERSION \"1.2.1\"" $ZLIB_HOME/include/zlib.h`
    fi

    if test -n "$vuln"; then
	if test "$zlib_check" = "yes"; then
	    AC_MSG_ERROR(The installed zlib version may contain a security bug. Please upgrade to 1.2.2 or later: http://www.zlib.net. You can omit this check with --disable-zlib-vcheck but DO NOT REPORT any stability issues then!)
	else
	    AC_MSG_WARN([****** This ClamAV installation may be linked against])
	    AC_MSG_WARN([****** a broken zlib version. Please DO NOT report any])
	    AC_MSG_WARN([****** stability problems to the ClamAV developers!])
	fi
    fi

    save_LIBS="$LIBS"
    if test "$ZLIB_HOME" != "/usr"; then
	CPPFLAGS="$CPPFLAGS -I$ZLIB_HOME/include"
	save_LDFLAGS="$LDFLAGS"
    LDFLAGS="$LDFLAGS -L$ZLIB_HOME/lib"
    AC_CHECK_LIB([z], [inflateEnd], [LIBCLAMAV_LIBS="$LIBCLAMAV_LIBS -L$ZLIB_HOME/lib -lz"; FRESHCLAM_LIBS="$FRESHCLAM_LIBS -L$ZLIB_HOME/lib -lz"], AC_MSG_ERROR([Please install zlib and zlib-devel packages]))
	AC_CHECK_LIB([z], [gzopen], [], AC_MSG_ERROR([Your zlib is missing gzopen()]))
	LDFLAGS="$save_LDFLAGS"
    else
	AC_CHECK_LIB([z], [inflateEnd], [LIBCLAMAV_LIBS="$LIBCLAMAV_LIBS -lz";FRESHCLAM_LIBS="$FRESHCLAM_LIBS -lz"], AC_MSG_ERROR([Please install zlib and zlib-devel packages]))
	AC_CHECK_LIB([z], [gzopen],[], AC_MSG_ERROR([Your zlib is missing gzopen()]))
    fi
    LIBS="$save_LIBS"
fi

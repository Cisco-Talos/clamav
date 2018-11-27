dnl we need to try to link with iconv, otherwise there could be a 
dnl mismatch between a 32-bit and 64-bit lib. Detect this at configure time.
dnl we need to check after zlib/bzip2, because they can change the include path
AC_ARG_WITH([iconv], [AS_HELP_STRING([--with-iconv], [supports iconv() @<:@default=auto@:>@])],
[
 case "$withval" in
	 yes|no) wiconv="$withval";;
	 *) AC_MSG_ERROR([--with-iconv does not take an argument]);;
 esac],
[ wiconv=auto ])
if test "X$wiconv" != "Xno"; then
        save_LDFLAGS="$LDFLAGS"
        LDFLAGS="-L/usr/local/lib -liconv"
        ICONV_HOME=""
        AC_CHECK_LIB([iconv], [libiconv_open], [ICONV_HOME="/usr/local"],
        [
          LDFLAGS="-L/usr/lib -liconv"
          AC_CHECK_LIB([iconv], [libiconv_open], [ICONV_HOME="/usr"], [LDFLAGS="$save_LDFLAGS"])
        ])
        AC_MSG_CHECKING([for iconv])
        save_LIBS="$LIBS"
        save_CPPFLAGS="$CPPFLAGS"
        LIBS="$LIBCLAMAV_LIBS"
        if test "X$ICONV_HOME" != "X"; then
          ICONV_LDFLAGS="$LDFLAGS"
          ICONV_CPPFLAGS="-I$ICONV_HOME/include"
        else
          ICONV_LDFLAGS=""
          ICONV_CPPFLAGS=""
        fi
        CPPFLAGS="$ICONV_CPPFLAGS $LIBCLAMAV_CPPFLAGS"
        AC_TRY_LINK([
		     #include <iconv.h>
        ],[
	  char** xin,**xout;
	  unsigned long il,ol;
	  int rc;
	  iconv_t iconv_struct = iconv_open("UTF-16BE","UTF-8");
	  rc = iconv(iconv_struct,xin,&il,xout,&ol);
	  iconv_close(iconv_struct);
        ],[
          AC_MSG_RESULT(yes)
          AC_DEFINE([HAVE_ICONV], 1, [iconv() available])
          AC_SUBST(ICONV_LDFLAGS)
          AC_SUBST(ICONV_CPPFLAGS)
        ],[
	  AC_MSG_RESULT(no)
        ])
        LIBS="$save_LIBS"
        LDFLAGS="$save_LDFLAGS"
        CPPFLAGS="$save_CPPFLAGS"
fi

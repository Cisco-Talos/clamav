dnl we need to try to link with iconv, otherwise there could be a 
dnl mismatch between a 32-bit and 64-bit lib. Detect this at configure time.
dnl we need to check after zlib/bzip2, because they can change the include path
AC_ARG_WITH([iconv], [  --with-iconv supports iconv() (default=auto)],
[
 case "$withval" in
	 yes|no) wiconv="$withval";;
	 *) AC_MSG_ERROR([--with-iconv does not take an argument]);;
 esac],
[ wiconv=auto ])
if test "X$wiconv" != "Xno"; then
	AC_CHECK_LIB([iconv], [libiconv_open], LIBCLAMAV_LIBS="$LIBCLAMAV_LIBS -liconv")
	AC_MSG_CHECKING([for iconv])
	save_LIBS="$LIBS"
	LIBS="$LIBCLAMAV_LIBS"
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
],[
	AC_MSG_RESULT(no)
])
	LIBS="$save_LIBS"
fi

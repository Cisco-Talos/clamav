dnl Check for iconv

m4_include([m4/reorganization/libs/iconv.m4])

if test "x$with_iconv" != "xno"; then
  AM_ICONV
  AC_CHECK_HEADERS([iconv.h],[],[],[#include <stdlib.h>])
  if test "x$am_cv_func_iconv" = "xyes"; then
    AC_CHECK_HEADERS([localcharset.h])
    am_save_LIBS="$LIBS"
    LIBS="${LIBS} ${LIBICONV}"
    AC_CHECK_FUNCS([locale_charset])
    LIBS="${am_save_LIBS}"
    if test "x$ac_cv_func_locale_charset" != "xyes"; then
      # If locale_charset() is not in libiconv, we have to find libcharset.
      AC_CHECK_LIB(charset,locale_charset)
    fi
  fi
fi

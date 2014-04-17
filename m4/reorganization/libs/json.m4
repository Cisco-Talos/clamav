dnl Check for libjson
AC_MSG_CHECKING([for libjson installation])

AC_ARG_WITH([libjson],
[  --with-libjson=DIR   path to directory containing libjson (default=
    /usr/local or /usr if not found in /usr/local)],
[
if test "$withval"; then
    LIBJSON_HOME="$withval"
fi
], [
LIBJSON_HOME=/usr/local
if test ! -f "$LIBJSON_HOME/include/json/json.h"
then
    LIBJSON_HOME=/usr
fi
AC_MSG_RESULT([$LIBJSON_HOME])
])

have_json="no"

if test ! -f "$LIBJSON_HOME/include/json/json.h"
then
    AC_MSG_WARN([json not found.])
else
JSON_LDFLAGS="-L$LIBJSON_HOME/lib"
JSON_LIBS="-ljson"
JSON_CPPFLAGS="-I$LIBJSON_HOME/include"

save_LDFLAGS="$LDFLAGS"
LDFLAGS="-L$LIBJSON_HOME/lib $JSON_LIBS"

save_CFLAGS="$CFLAGS"
CFLAGS="$JSON_CPPFLAGS"

AC_CHECK_LIB([json], [json_object_new_object], [have_json="yes"], [AC_MSG_ERROR([Your libjson installation is misconfigured or missing])])

LDFLAGS="$save_LDFLAGS"
CFLAGS="$save_CFLAGS"
fi

if test "$have_json" = "yes"; then
AC_DEFINE([HAVE_JSON],1,[Define to 1 if you have the 'libjson' library (-ljson).])
fi


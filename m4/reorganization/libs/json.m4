dnl Check for libjson

AC_ARG_WITH([libjson],
[AS_HELP_STRING([--with-libjson@<:@=DIR@:>@], [path to directory containing libjson
                @<:@default=/usr/local or /usr if not found in /usr/local@:>@])],
[
AC_MSG_CHECKING([for libjson installation])
if test "X$withval" != "Xyes"
then
  LIBJSON_HOME="$withval"
  if test -f "$LIBJSON_HOME/include/json/json.h" -o -f "$LIBJSON_HOME/include/json-c/json.h"
  then
    have_json_header="yes"
  fi
else
  LIBJSON_HOME=/usr/local
  if test -f "$LIBJSON_HOME/include/json/json.h" -o -f "$LIBJSON_HOME/include/json-c/json.h"
  then
    have_json_header="yes"
  else
    LIBJSON_HOME=/usr
    if test -f "$LIBJSON_HOME/include/json/json.h" -o -f "$LIBJSON_HOME/include/json-c/json.h"
    then
      have_json_header="yes"
    else
      have_json_header="no"
      LIBJSON_HOME=""
    fi
  fi
fi
AC_MSG_RESULT([$LIBJSON_HOME])
],
[
have_json_header="no"
])

if test "X$have_json_header" = "Xyes"
then
  if test -f "$LIBJSON_HOME/include/json/json.h"
  then
    JSON_INCLUDE="include/json"
  fi
  if test -f "$LIBJSON_HOME/include/json-c/json.h"
  then
    JSON_INCLUDE="include/json-c"
  fi
  if test -z $JSON_INCLUDE
  then
    AC_MSG_WARN([json header lost.])
  fi

  JSON_CPPFLAGS="-I$LIBJSON_HOME/$JSON_INCLUDE"
  save_LDFLAGS="$LDFLAGS"
  save_CFLAGS="$CFLAGS"
  save_LIBS="$LIBS"
  LIBS=""
  JSON_LIBS=""
  if test "$LIBJSON_HOME" != "/usr"
  then
    JSON_LDFLAGS="-L$LIBJSON_HOME/lib"
    LDFLAGS="$LDFLAGS $JSON_LDFLAGS"
    CFLAGS="$CFLAGS $JSON_CPPFLAGS"
  fi

  AC_SEARCH_LIBS([json_object_object_get_ex], [json-c json], [
have_json="yes"
have_deprecated_json="no"], [
have_json="no"
AC_SEARCH_LIBS([json_object_object_get], [json-c json], [
have_json="yes"
have_deprecated_json="yes"
])
])

  CFLAGS="$save_CFLAGS"
  LDFLAGS="$save_LDFLAGS"
fi

if test "X$have_json" = "Xyes"; then
  AC_DEFINE([HAVE_JSON],1,[Define to 1 if you have the 'libjson' library (-ljson).])
  if test "X$have_deprecated_json" = "Xyes"; then
    AC_DEFINE([HAVE_DEPRECATED_JSON],1,[Define to 1 if you have a deprecated version of the 'libjson' library (-ljson).])
  fi
  JSON_LIBS="$LIBS"
fi

LIBS="$save_LIBS"


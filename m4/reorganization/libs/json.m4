dnl Check for libjson
AC_MSG_CHECKING([for libjson installation])

AC_ARG_WITH([libjson],
[  --with-libjson=DIR   path to directory containing libjson (default=
    /usr/local or /usr if not found in /usr/local)],
[
if test "X$withval" != "Xno"
then
  if test ! -n "$withval"
  then
    LIBJSON_HOME="$withval"
    have_json="yes"
  else
    LIBJSON_HOME=/usr/local
    if test -d "$LIBJSON_HOME/include/json" -o -d "$LIBJSON_HOME/include/json-c"
    then
      have_json="yes"
    else
      LIBJSON_HOME=/usr
      if test -d "$LIBJSON_HOME/include/json" -o -d "$LIBJSON_HOME/include/json-c"
      then
        have_json="yes"
      else
        have_json="no"
      fi
    fi
  fi
fi

AC_MSG_RESULT([$LIBJSON_HOME])
],
[
have_json="no"
])

if test "X$have_json" = "Xyes"
then
  if test -d "$LIBJSON_HOME/include/json"
  then
    JSON_INCLUDE="include/json"
  fi
  if test -d "$LIBJSON_HOME/include/json-c"
  then
    JSON_INCLUDE="include/json-c"
  fi

  if test ! -f "$LIBJSON_HOME/$JSON_INCLUDE/json.h"
  then
      AC_MSG_WARN([json not found.])
  else
    JSON_LDFLAGS="-L$LIBJSON_HOME/lib"
    JSON_LIBS="-ljson-c"
    JSON_CPPFLAGS="-I$LIBJSON_HOME/$JSON_INCLUDE"

    AC_MSG_NOTICE([JSON_CPPFLAGS is $JSON_CPPFLAGS])

    save_LDFLAGS="$LDFLAGS"
    LDFLAGS="-L$LIBJSON_HOME/lib $JSON_LIBS"

    save_CFLAGS="$CFLAGS"
    CFLAGS="$JSON_CPPFLAGS"

    AC_CHECK_LIB([json-c], [json_object_new_object], [have_json="yes"], [have_json="no"])
    if test "X$have_json" = "Xno"
    then 
      JSON_LIBS="-ljson"
      AC_CHECK_LIB([json], [json_object_new_object], [have_json="yes"], [have_json="no"])
    fi

    LDFLAGS="$save_LDFLAGS"
    CFLAGS="$save_CFLAGS"

  fi
fi

if test "X$have_json" = "Xyes"; then
AC_DEFINE([HAVE_JSON],1,[Define to 1 if you have the 'libjson' library (-ljson).])
fi


dnl Check for libjson

have_json_header="no"
AC_MSG_CHECKING([for libjson installation])

AC_ARG_WITH([libjson],
[AS_HELP_STRING([--with-libjson@<:@=DIR@:>@], [path to directory containing libjson
                @<:@default=/usr/local or /usr if not found in /usr/local@:>@])],
[
find_json="no"
if test "X$withval" = "Xyes"; then
    find_json="yes"
else
    if test "X$withval" != "Xno"; then
        if test -f "${withval}/include/json/json.h" -o -f "${withval}/include/json-c/json.h"; then
            LIBJSON_HOME="$withval"
            have_json_header="yes"
        fi
    fi
fi
],
[find_json="yes"])

if test "X$find_json" = "Xyes"; then
    for p in /usr/local /usr ; do
        if test -f "${p}/include/json/json.h" -o -f "${p}/include/json-c/json.h"; then
            LIBJSON_HOME=$p
            have_json_header="yes"
        fi
    done
fi

if test "X$have_json_header" = "Xyes"; then
    AC_MSG_RESULT([$LIBJSON_HOME])
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

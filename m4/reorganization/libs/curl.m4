have_curl="no"
curl_msg="Please use the web interface for submitting FPs/FNs."
AC_MSG_CHECKING([for libcurl installation])

AC_ARG_WITH([libcurl],
[  --with-libcurl=DIR   path to directory containing libcurl (default=
    /usr/local or /usr if not found in /usr/local)],
[
if test "$withval"; then
    LIBCURL_HOME="$withval"
fi
], [
LIBCURL_HOME=/usr/local
if test ! -f "$LIBCURL_HOME/include/curl/curl.h"
then
    LIBCURL_HOME=/usr
fi
AC_MSG_RESULT([$LIBCURL_HOME])
])

if test ! -f "$LIBCURL_HOME/include/curl/curl.h"
then
    AC_MSG_WARN([libcurl not found. Please use the web interface for submitting FPs/FNs.])
else
    if test -f "$LIBCURL_HOME/bin/curl-config"; then
        CURL_LDFLAGS=$($LIBCURL_HOME/bin/curl-config --libs)
        CURL_CPPFLAGS=$($LIBCURL_HOME/bin/curl-config --cflags)
    else
        if test "$LIBCURL_HOME" != "/usr"; then
            CURL_LDFLAGS="-L$LIBCURL_HOME/lib -lcurl"
            CURL_CPPFLAGS="-I$LIBCURL_HOME/include"
        else
            CURL_LDFLAGS="-lcurl"
            CURL_CPPFLAGS=""
        fi
    fi

    save_LDFLAGS="$LDFLAGS"
    LDFLAGS="$CURL_LDFLAGS"
    AC_CHECK_LIB([curl], [curl_easy_init], [curl_msg="";have_curl="yes";CLAMSUBMIT_LIBS="$CLAMSUBMIT_LIBS $CURL_LDFLAGS";CLAMSUBMIT_CFLAGS="$CLAMSUBMIT_CFLAGS $CURL_CPPFLAGS"],
            [AC_MSG_WARN([Your libcurl is misconfigured. Please use the web interface for submitting FPs/FNs.])])
    LDFLAGS="$save_LDFLAGS"
fi

AC_SUBST([CLAMSUBMIT_LIBS])
AC_SUBST([CLAMSUBMIT_CFLAGS])

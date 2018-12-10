dnl Check for libcurl

have_curl="no"
AC_MSG_CHECKING([for libcurl installation])

AC_ARG_WITH([libcurl],
[AS_HELP_STRING([--with-libcurl@<:@=DIR@:>@], [path to directory containing libcurl
                @<:@default=/usr/local or /usr if not found in /usr/local@:>@])],
[
find_curl="no"
if test "X$withval" = "Xyes"; then
    find_curl="yes"
else
    if test "X$withval" != "Xno"; then
        if test -f "${withval}/bin/curl-config"; then
            LIBCURL_HOME="$withval"
            have_curl="yes"
        fi
    fi
fi
],
[find_curl="yes"])

if test "X$find_curl" = "Xyes"; then
    for p in /usr/local /usr ; do
        if test -f "${p}/bin/curl-config"; then
           LIBCURL_HOME=$p
           have_curl="yes"
        fi
    done
fi

if test "X$have_curl" = "Xyes"; then
    AC_MSG_RESULT([$LIBCURL_HOME])
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
        [AC_MSG_WARN([Your libcurl is misconfigured. Please use the web interface for submitting FPs/FNs.])], [$CURL_LDFLAGS])
    LDFLAGS="$save_LDFLAGS"
else
    AC_MSG_WARN([libcurl not found or not requested by ./configure. Please use the web interface for submitting FPs/FNs.])
fi

AC_SUBST([CLAMSUBMIT_LIBS])
AC_SUBST([CLAMSUBMIT_CFLAGS])

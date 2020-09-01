dnl Check for libcurl

have_curl="no"
if test "$enable_libclamav_only" != "yes"; then

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
        CURL_LDFLAGS="$LDFLAGS"
        CURL_LIBS=$($LIBCURL_HOME/bin/curl-config --libs)
        CURL_CPPFLAGS=$($LIBCURL_HOME/bin/curl-config --cflags)
    else
        if test "$LIBCURL_HOME" != "/usr"; then
            CURL_LDFLAGS="-L$LIBCURL_HOME/lib"
            CURL_CPPFLAGS="-I$LIBCURL_HOME/include"
        else
            CURL_LDFLAGS="$LDFLAGS"
            CURL_CPPFLAGS=""
        fi
        CURL_LIBS="-lcurl"
    fi
    save_LDFLAGS="$LDFLAGS"
    LDFLAGS="$CURL_LDFLAGS $CURL_LIBS $SSL_LDFLAGS $SSL_LIBS"

    dnl Following section modified from libcurl, Copyright (C) 2006, David Shaw, license under COPYING.curl
    AC_PROG_AWK

    curl_version_parse="eval $AWK '{split(\$NF,A,\".\"); X=256*256*A[[1]]+256*A[[2]]+A[[3]]; print X;}'"
    AC_PATH_PROG([curl_config],[curl-config],["notfound"],
                     ["$LIBCURL_HOME/bin"])


    awk_curl_version=`$curl_config --version | $AWK '{print $2}'`
    curl_version=`echo $awk_curl_version | $curl_version_parse`
    dnl end of section

    AM_COND_IF([BUILD_CLAMONACC],
        $enable_clamonacc="yes"

        clamonacc_curl = "current"
        dnl if version less than to (7.40 0x072800)
        [if test $curl_version -lt 468992; then
          clamonacc_curl = "deprecated" 
        fi]
    )

    AC_CHECK_LIB(
        [curl],
        [curl_easy_init],
        [
            curl_msg="";
            have_curl="yes";
            CLAMSUBMIT_LIBS="$CLAMSUBMIT_LIBS $CURL_LDFLAGS $CURL_LIBS";
            CLAMSUBMIT_CFLAGS="$CLAMSUBMIT_CFLAGS $CURL_CPPFLAGS";
            FRESHCLAM_LIBS="$FRESHCLAM_LIBS $CURL_LDFLAGS $CURL_LIBS";
            FRESHCLAM_CPPFLAGS="$FRESHCLAM_CPPFLAGS $CURL_CPPFLAGS"
        ],
        [
            AC_MSG_ERROR([Your libcurl is misconfigured. libcurl (e.g. libcurl-devel) is required in order to build freshclam and clamsubmit.])
        ],
        [$CURL_LIBS]
    )

    LDFLAGS="$save_LDFLAGS"
else
    AC_MSG_ERROR([libcurl not found. libcurl (e.g. libcurl-devel) is required in order to build freshclam and clamsubmit.])
fi

AC_SUBST([CLAMSUBMIT_LIBS])
AC_SUBST([CLAMSUBMIT_CFLAGS])
fi

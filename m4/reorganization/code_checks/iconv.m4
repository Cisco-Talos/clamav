dnl we need to try to link with iconv, otherwise there could be a
dnl mismatch between a 32-bit and 64-bit lib. Detect this at configure time.
dnl we need to check after zlib/bzip2, because they can change the include path

want_iconv="sure"
have_iconv="no"
have_iconv_lib="no"

save_LDFLAGS="$LDFLAGS"
save_LIBS="$LIBS"
save_CPPFLAGS="$CPPFLAGS"

ICONV_HOME=""

AC_ARG_WITH(
    [iconv],
    [AS_HELP_STRING([--with-iconv@<:@=DIR@:>@], [path to directory containing libiconv
                    @<:@default=/usr/local or /usr if not found in /usr/local@:>@])],
    [
        if test "X$withval" = "Xno"; then
            want_iconv="no"
        else
            want_iconv="yes"

            if test "X$withval" = "Xyes"; then
                find_iconv="yes"
            else
                LDFLAGS="-L${withval}/lib -liconv"
                AC_CHECK_LIB(
                    [iconv],
                    [libiconv_open],
                    [
                        ICONV_HOME="${withval}"
                        have_iconv_lib="yes"
                    ],
                    [
                        AC_MSG_ERROR([Failed to find iconv (libiconv) in ${withval}])
                    ])
            fi
        fi
    ],
    [
        find_iconv="yes"
    ])

if test "X$want_iconv" != "Xno"; then
    if test "X$find_iconv" = "Xyes"; then
        LDFLAGS="-L/usr/local/lib -liconv"
        AC_CHECK_LIB(
            [iconv],
            [libiconv_open],
            [
                ICONV_HOME="/usr/local"
                have_iconv_lib="yes"
            ],
            [
                LDFLAGS="-L/usr/lib -liconv"
                AC_CHECK_LIB(
                    [iconv],
                    [libiconv_open],
                    [
                        ICONV_HOME="/usr"
                        have_iconv_lib="yes"
                    ],
                    [
                        if test "X$want_iconv" = "Xyes"; then
                            AC_MSG_ERROR([Failed to find iconv (libiconv) in /usr or /usr/local])
                        fi
                    ])
            ])
    fi

    if test "X$have_iconv_lib" = "Xyes"; then
        LIBS="$LIBCLAMAV_LIBS"
        if test "X$ICONV_HOME" != "X"; then
            ICONV_LDFLAGS="$LDFLAGS"
            ICONV_CPPFLAGS="-I$ICONV_HOME/include"
        else
            ICONV_LDFLAGS=""
            ICONV_CPPFLAGS=""
        fi
        CPPFLAGS="$ICONV_CPPFLAGS $LIBCLAMAV_CPPFLAGS"

        AC_TRY_LINK(
            [
                #include <iconv.h>
            ],
            [
                char** xin,**xout;
                unsigned long il,ol;
                int rc;
                iconv_t iconv_struct = iconv_open("UTF-16BE","UTF-8");
                rc = iconv(iconv_struct,xin,&il,xout,&ol);
                iconv_close(iconv_struct);
            ],
            [
                have_iconv="yes"
            ],
            [
                if test "X$want_iconv" = "Xyes"; then
                    AC_MSG_ERROR([The libiconv link test failed. Your libiconv installation may be misconfigured.])
                else
                    AC_MSG_WARN([The libiconv found, but link test failed. Your libiconv installation may be misconfigured. iconv will not be available.])
                fi
            ])
    fi
fi


AC_MSG_CHECKING([for libiconv installation])

if test "X$have_iconv" = "Xno"; then
    AC_MSG_RESULT(no)
else
    AC_MSG_RESULT([$ICONV_HOME])
    AC_DEFINE([HAVE_ICONV], 1, [iconv() available])
    AC_SUBST(ICONV_LDFLAGS)
    AC_SUBST(ICONV_CPPFLAGS)
fi

LIBS="$save_LIBS"
LDFLAGS="$save_LDFLAGS"
CPPFLAGS="$save_CPPFLAGS"

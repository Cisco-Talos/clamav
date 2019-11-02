dnl Check for zlib
AC_ARG_WITH([zlib],
    [
        AS_HELP_STRING([--with-zlib@<:@=DIR@:>@], [path to directory containing zlib library
            @<:@default=/usr/local or /usr if not found in /usr/local@:>@])
    ],
    [
        if test "$withval" != "no" -a "$withval" != "yes"; then
            ZLIB_HOME=$withval
            CPPFLAGS="${CPPFLAGS} -I$withval/include"
            LDFLAGS="${LDFLAGS} -L$withval/lib"
        fi
    ])

FOUND_ZLIB=0
if test "x$ZLIB_HOME" = "x"; then
    PKG_CHECK_MODULES([ZLIB],[zlib],
        [
            FOUND_ZLIB=1
            AC_DEFINE(HAVE_LIBZ, 1)
            AC_CHECK_HEADERS([zlib.h])
        ],
        [:])
fi

if test "$FOUND_ZLIB" = "0"; then
    AC_CHECK_HEADERS(zlib.h,
        [
            FOUND_ZLIB=1
            save_LIBS="$LIBS"
            if test "x${ZLIB_HOME}" != "x"; then
                save_CPPFLAGS="$CPPFLAGS -I$ZLIB_HOME/include"
                save_LDFLAGS="$LDFLAGS"
                CPPFLAGS="$CPPFLAGS -I$ZLIB_HOME/include"
                LDFLAGS="$LDFLAGS -L$ZLIB_HOME/lib"
                AC_CHECK_LIB([z], [inflateEnd], [ZLIB_CFLAGS="-I${ZLIB_HOME}/include"; ZLIB_LIBS="-L${ZLIB_HOME}/lib -lz"], AC_MSG_ERROR([Please install zlib and zlib-devel packages]))
                AC_CHECK_LIB([z], [gzopen], [], AC_MSG_ERROR([Your zlib is missing gzopen()]))
                CPPFLAGS="$save_CPPFLAGS"
                LDFLAGS="$save_LDFLAGS"
            else
                AC_CHECK_LIB([z], [inflateEnd], [ZLIB_LIBS="-lz"], AC_MSG_ERROR([Please install zlib and zlib-devel packages]))
                AC_CHECK_LIB([z], [gzopen],[], AC_MSG_ERROR([Your zlib is missing gzopen()]))
            fi
            LIBS="$save_LIBS"
        ])
fi

if test "$FOUND_ZLIB" = "0"; then
    AC_MSG_ERROR([Please install zlib and zlib-devel packages])
fi

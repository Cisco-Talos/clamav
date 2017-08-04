dnl --enable-milter
if test "$have_milter" = "yes"; then
    dnl libmilter checking code adapted from spamass-milter by
    dnl Tom G. Christensen <tgc@statsbiblioteket.dk>

    dnl Check for libmilter and it's header files in the usual locations
    save_LIBS="$LIBS"
    CLAMAV_MILTER_LIBS="$CLAMAV_MILTER_LIBS $THREAD_LIBS"
    if test -d /usr/lib/libmilter ; then
	CLAMAV_MILTER_LIBS="$CLAMAV_MILTER_LIBS -L/usr/lib/libmilter"
    fi
    LIBS="$LIBS -lmilter $CLAMAV_MILTER_LIBS"
    AC_CHECK_LIB([milter],[mi_stop],[CLAMAV_MILTER_LIBS="-lmilter $CLAMAV_MILTER_LIBS"],[
	dnl Older sendmails require libsm or libsmutil for support functions
	AC_SEARCH_LIBS([strlcpy], [sm smutil], [test "$ac_cv_search_strlcpy" = "none required" || CLAMAV_MILTER_XLIB="$ac_cv_search_strlcpy"])
	LIBS="$save_LIBS $CLAMAV_MILTER_LIBS $CLAMAV_MILTER_XLIB"
	$as_unset ac_cv_lib_milter_mi_stop
	AC_CHECK_LIB([milter],[mi_stop],[CLAMAV_MILTER_LIBS="-lmilter $CLAMAV_MILTER_XLIB $CLAMAV_MILTER_LIBS"],[
	    AC_MSG_ERROR([Cannot find libmilter])
	])
    ])
    LIBS="$save_LIBS"
    AC_CHECK_HEADERS([libmilter/mfapi.h],[have_milter="yes"],[
	AC_MSG_ERROR([Please install mfapi.h from the sendmail distribution])
    ])
fi

AM_CONDITIONAL([BUILD_CLAMD],[test "$have_pthreads" = "yes"])
AM_CONDITIONAL([HAVE_MILTER],[test "$have_milter" = "yes"])

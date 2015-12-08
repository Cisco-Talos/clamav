enable_check_ut=auto
enable_ut_install=no
AC_ARG_ENABLE(check,
[AS_HELP_STRING([--enable-check], [enable check unit tests @<:@default=auto@:>@])], enable_check_ut=$enableval, enable_check_ut="auto" )

if test "$enable_check_ut" != "no" ; then

PKG_CHECK_MODULES(CHECK, [check], [HAVE_LIBCHECK=yes], [HAVE_LIBCHECK=])

if test "X$HAVE_LIBCHECK" == "Xyes"; then
    CHECK_CPPFLAGS=$CHECK_CFLAGS
else

case "$host_os" in
    *linux*)
        save_LDFLAGS="$LDFLAGS"
        LDFLAGS="$LDFLAGS -pthread -Wl,--no-as-needed -lm -Wl,--as-needed -lrt"
        ;;
esac

	AC_LIB_FIND([check],[check.h],
			AC_LANG_PROGRAM([#include <check.h>],[srunner_create(0)]),
			[CHECK_CPPFLAGS="$INCCHECK"; CHECK_LIBS="$LTLIBCHECK $LDFLAGS"],
			[])

case "$host_os" in
    *linux*)
        LDFLAGS="$save_LDFLAGS"
        ;;
esac

fi
fi

AC_SUBST([CHECK_CPPFLAGS])
AC_SUBST([CHECK_LIBS])
AM_CONDITIONAL([HAVE_LIBCHECK],test "X$HAVE_LIBCHECK" = "Xyes")

if test "x$CHECK_LIBS" = "x" -a "$enable_check_ut" = "yes"; then
    AC_MSG_ERROR([

ERROR!  Check was configured, but not found.  Get it from http://check.sf.net/
])
fi

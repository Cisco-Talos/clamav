AC_ARG_ENABLE(clamdtop,
	     [AC_HELP_STRING([--enable-clamdtop], [build clamdtop tool @<:@default=auto@:>@])],
[enable_clamdtop=$enableval], [enable_clamdtop="auto"])

if test "$enable_clamdtop" != "no"; then

AC_LIB_FIND([ncurses], [ncurses/ncurses.h],
	    AC_LANG_PROGRAM([#include <ncurses/ncurses.h>],
			    [initscr(); KEY_RESIZE;]),
	    [CURSES_CPPFLAGS="$INCNCURSES"; CURSES_LIBS="$LTLIBNCURSES";
	     CURSES_INCLUDE="<ncurses/ncurses.h>"],
	    [])

if test "X$HAVE_LIBNCURSES" != "Xyes"; then
    HAVE_LIBNCURSES=
    AC_LIB_FIND([ncurses], [ncurses.h],
	    AC_LANG_PROGRAM([#include <ncurses.h>],
			    [initscr(); KEY_RESIZE;]),
	    [CURSES_CPPFLAGS="$INCNCURSES"; CURSES_LIBS="$LTLIBNCURSES";
	     CURSES_INCLUDE="<ncurses.h>"],
	    [])
fi

if test "X$HAVE_LIBNCURSES" != "Xyes"; then
    AC_LIB_FIND([pdcurses],[curses.h],
			    AC_LANG_PROGRAM([#include <curses.h>],
					    [initscr(); KEY_RESIZE;]),
			    [CURSES_CPPFLAGS="$INCPDCURSES";
			     CURSES_LIBS="$LTLIBPDCURSES";
			     CURSES_INCLUDE="<curses.h>"],
			    [AC_MSG_WARN([****** not building clamdtop: ncurses not found])])
fi

if test "x$CURSES_LIBS" = "x" -a "$enable_clamdtop" = "yes"; then
    AC_MSG_ERROR([

ERROR!  Clamdtop was configured, but not found.  You need to install libncurses5-dev.
])
fi

fi

AC_DEFINE_UNQUOTED([CURSES_INCLUDE], $CURSES_INCLUDE, [curses header location])
AC_SUBST([CURSES_CPPFLAGS])
AC_SUBST([CURSES_LIBS])
AM_CONDITIONAL([HAVE_CURSES],
	       [test "X$HAVE_LIBNCURSES" = "Xyes" || test "X$HAVE_LIBPDCURSES" = "Xyes"])

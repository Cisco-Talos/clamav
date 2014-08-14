dnl Check for PCRE

dnl determine the home of pcre
PCRE_HOME=""
AC_ARG_WITH([pcre],
[  --with-pcre=DIR        path to directory containing libpcre library (default=
                          /usr/local or /usr if not found in /usr/local)],
[
  AC_MSG_CHECKING([for libpcre installation])
dnl --with-pcre=no
  if test "X$withval" = "Xno"; then
    AC_MSG_RESULT([no])
  else
dnl --with-pcre=yes
    if test "X$withval" = "Xyes"; then
      PCRE_HOME=/usr/local
      if test ! -x "$PCRE_HOME/bin/pcre-config"; then
        PCRE_HOME=/usr
        if test ! -x "$PCRE_HOME/bin/pcre-config"; then
          PCRE_HOME=""
        fi
      fi
dnl --with-pcre=something
    elif test "$withval"; then
      PCRE_HOME="$withval"
      if test ! -x "$PCRE_HOME/bin/pcre-config"; then
        PCRE_HOME=""
        AC_MSG_ERROR([cannot locate libpcre at $withval])
      fi
dnl --with-pcre=""
    else
      AC_MSG_ERROR([cannot assign blank value to --with-pcre])
    fi

    if test "x$PCRE_HOME" != "x"; then
      AC_MSG_RESULT([using $PCRE_HOME])
    else
      AC_MSG_RESULT([not found])
      AC_MSG_WARN([cannot locate libpcre at /usr/local or /usr])
    fi
  fi
],[
dnl --with-pcre not specified
  PCRE_HOME=""
])

dnl if pcre has a home, then check if it is valid and get flags
found_pcre="no"
PCRECONF_VERSION=""
PCRE_CPPFLAGS=""
PCRE_LIBS=""
if test "x$PCRE_HOME" != "x"; then
  AC_MSG_CHECKING([pcre-config version])
  PCRECONF_VERSION="`$PCRE_HOME/bin/pcre-config --version`"
  if test "x%PCRECONF_VERSION" != "x"; then
    AC_MSG_RESULT([$PCRECONF_VERSION"])
    found_pcre="yes"
    PCRE_CPPFLAGS="`$PCRE_HOME/bin/pcre-config --cflags`"
    PCRE_LIBS="`$PCRE_HOME/bin/pcre-config --libs`"
  else
    AC_MSG_ERROR([pcre-config failed])
  fi
fi

have_pcre="no"
if test "x$found_pcre" != "xno"; then
  AC_MSG_CHECKING([for pcre.h in $PCRE_HOME])

  if test ! -f "$XML_HOME/include/pcre.h"; then
    AC_MSG_RESULT([not found])
  else
    AC_MSG_RESULT([found])
    save_LIBS="$LIBS"
    save_CPPFLAGS="$CPPFLAGS"
    CPPFLAGS="$CPPFLAGS $PCRE_CPPFLAGS"
    save_LDFLAGS="$LDFLAGS"
    LDFLAGS="$LDFLAGS $PCRE_LIBS"

    AC_CHECK_LIB([pcre], [pcre_compile], [have_pcre="yes"], [have_pcre="no"])

    CPPFLAGS="$save_CPPFLAGS"
    LDFLAGS="$save_LDFLAGS"
    LIBS="$save_LIBS"
  fi
fi

if test "x$have_pcre" = "xyes"; then
  AC_DEFINE([HAVE_PCRE],1,[Define to 1 if you have the 'libpcre' library (-lpcre).])
  AC_MSG_NOTICE([Compiling and linking with libpcre from $PCRE_HOME])
fi

dnl AM_CONDITIONAL([HAVE_PCRE], test "x$HAVE_PCRE" = "xyes")

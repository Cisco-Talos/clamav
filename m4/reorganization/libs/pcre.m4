dnl Check for PCRE

PCRE_HOME=""
dnl handle the --with-pcre flag
AC_ARG_WITH([pcre],
[AS_HELP_STRING([--with-pcre@<:@=DIR@:>@], [path to directory containing libpcre library
                @<:@default=/usr/local or /usr if not found in /usr/local@:>@])],
[
  PCRE_HOME=$withval
],
[
dnl default ON if present
  PCRE_HOME="yes"
])

dnl detemine if specified (or default) is valid
AC_MSG_CHECKING([for libpcre installation])
case "$PCRE_HOME" in
no)
  PCRE_HOME=""
  AC_MSG_RESULT([no])
  ;;
yes)
  PCRE_HOME=/usr/local
  if test ! -x "$PCRE_HOME/bin/pcre-config"; then
    PCRE_HOME=/usr
    if test ! -x "$PCRE_HOME/bin/pcre-config"; then
      PCRE_HOME=""
      AC_MSG_RESULT([no])
      AC_MSG_NOTICE([cannot locate libpcre at /usr/local or /usr])
    fi
  fi
  ;;
"")
  AC_MSG_RESULT([])
  AC_MSG_ERROR([cannot assign blank value to --with-pcre])
  ;;
*)
  PCRE_HOME="$withval"
  if test ! -x "$PCRE_HOME/bin/pcre-config"; then
    PCRE_HOME=""
    AC_MSG_RESULT([not found])
    AC_MSG_ERROR([cannot locate libpcre at $withval])
  fi
  ;;
esac

if test "x$PCRE_HOME" != "x"; then
  AC_MSG_RESULT([using $PCRE_HOME])
fi

dnl if pcre has a home, then check if it is valid and get flags
found_pcre="no"
PCRECONF_VERSION=""
PCRE_CPPFLAGS=""
PCRE_LIBS=""
if test "x$PCRE_HOME" != "x"; then
  AC_MSG_CHECKING([pcre-config version])
  PCRECONF_VERSION="`$PCRE_HOME/bin/pcre-config --version`"

  if test "x$PCRECONF_VERSION" == "x"; then
    AC_MSG_ERROR([pcre-config failed])
  fi

  AC_MSG_RESULT([$PCRECONF_VERSION])
  AC_MSG_CHECKING([for CVE-2015-3210])
  pcrever_major=`echo "$PCRECONF_VERSION" | sed -e 's/\([[0-9]]\).*/\1/'`
  pcrever_minor=`echo "$PCRECONF_VERSION" | sed -e 's/[[0-9]]\.\(.*\)/\1/'`
  if test $pcrever_major -eq 8; then
    if test $pcrever_minor -gt 33 && test $pcrever_minor -lt 38; then
       AC_MSG_RESULT([yes])
       AC_MSG_WARN([The installed pcre version may contain a security bug. Please upgrade to 8.38 or later: http://www.pcre.org.])
    else
       AC_MSG_RESULT([ok])
    fi
  else
    AC_MSG_RESULT([ok]);
  fi
  found_pcre="yes"
  PCRE_CPPFLAGS="`$PCRE_HOME/bin/pcre-config --cflags`"
  PCRE_LIBS="`$PCRE_HOME/bin/pcre-config --libs`"
  
fi

have_pcre="no"
if test "x$found_pcre" != "xno"; then
  AC_MSG_CHECKING([for pcre.h in $PCRE_HOME])

  dnl save_LIBS="$LIBS"
  save_CPPFLAGS="$CPPFLAGS"
  CPPFLAGS="$CPPFLAGS $PCRE_CPPFLAGS"
  save_LDFLAGS="$LDFLAGS"
  LDFLAGS="$LDFLAGS $PCRE_LIBS"

  AC_CHECK_HEADER(pcre.h, [have_pcre="yes"], [have_pcre="no"])
  if test "x$have_pcre" = "xno"; then
    AC_CHECK_HEADER(pcre/pcre.h, [have_pcre="yes"], [have_pcre="no"])
  fi

  if test "x$have_pcre" = "xyes"; then
    AC_CHECK_LIB([pcre], [pcre_compile], [have_pcre="yes"], [have_pcre="no"])
  fi

  if test "x$have_pcre" = "xno"; then
    dnl LIBS="$save_LIBS"
    CPPFLAGS="$save_CPPFLAGS"
    LDFLAGS="$save_LDFLAGS"
  fi
fi

if test "x$have_pcre" = "xyes"; then
  AC_DEFINE([HAVE_PCRE],1,[Define to 1 if you have the 'libpcre' library (-lpcre).])
  AC_MSG_NOTICE([Compiling and linking with libpcre from $PCRE_HOME])
fi

dnl AM_CONDITIONAL([HAVE_PCRE], test "x$HAVE_PCRE" = "xyes")

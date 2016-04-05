dnl Check for PCRE

dnl handle the --with-pcre flag, default ON if present
AC_ARG_WITH([pcre],[AS_HELP_STRING([--with-pcre@<:@=DIR@:>@],
  [path to directory containing libpcre library, prioritizes PCRE2 over PCRE
    @<:@default=search PATH environment variable@:>@])],
  [pcreser=$withval],[pcreser="yes"])

dnl detemine if specified (or default) is valid
case "$pcreser" in
no)
  pcreconfig=""
  ;;
yes)
  dnl default - search PATH
  AC_PATH_PROG([pcreconfig], [pcre2-config])
  if test "x$pcreconfig" = "x"; then
      AC_PATH_PROG([pcreconfig], [pcre-config])
      if test "x$pcreconfig" = "x"; then
          AC_MSG_NOTICE([cannot locate libpcre2 or libpcre within PATH])
      else
         pcrelib="pcre"
      fi
  else
      pcrelib="pcre2"
  fi
  ;;
"")
  AC_MSG_ERROR([cannot assign blank value to --with-pcre])
  ;;
*)
  AC_PATH_PROG([pcreconfig], [pcre2-config], [], [$pcreser/bin])
  if test "x$pcreconfig" = "x"; then
      AC_PATH_PROG([pcreconfig], [pcre-config], [], [$pcreser/bin])
      if test "x$pcreconfig" = "x"; then
          AC_MSG_ERROR([cannot locate libpcre2 or libpcre at $pcreser])
      else
         pcrelib="pcre"
      fi
  else
      pcrelib="pcre2"
  fi
  ;;
esac

dnl use pcre-config to check version, get cflags and libs
found_pcre="no"
if test "x$pcreconfig" != "x"; then
    AC_MSG_CHECKING([pcre-config version])
    pcre_version="`$pcreconfig --version`"

    if test "x$pcre_version" = "x"; then
        AC_MSG_ERROR([$pcreconfig failed])
    fi

    AC_MSG_RESULT([$pcre_version])
    AC_CANONICAL_HOST
    case $host_os in
      darwin* )
        pcrever_major=`echo "$pcre_version" | sed -Ee 's/([[0-9]]+).*/\1/'`
        pcrever_minor=`echo "$pcre_version" | sed -Ee 's/[[0-9]]+\.([[0-9]]+).*/\1/'`
        ;;
      *)
        pcrever_major=`echo "$pcre_version" | sed -re 's/([[0-9]]+).*/\1/'`
        pcrever_minor=`echo "$pcre_version" | sed -re 's/[[0-9]]+\.([[0-9]]+).*/\1/'`
        ;;
    esac

    dnl check for match_limit_recursion support
    if test "$pcrelib" = "pcre"; then
        if test $pcrever_major -lt 6; then
            AC_MSG_ERROR([This pcre version is missing features used by ClamAV. Please upgrade to a newer version: http://www.pcre.org.])
        fi
        if test $pcrever_major -eq 6 && test $pcrever_minor -lt 5; then
            AC_MSG_ERROR([This pcre version is missing features used by ClamAV. Please upgrade to a newer version: http://www.pcre.org.])
        fi
    fi

    AC_MSG_CHECKING([for CVE-2015-3210])
    if test "$pcrelib" = "pcre2"; then
        if test $pcrever_major -eq 10 && test $pcrever_minor -eq 10; then
            AC_MSG_WARN([The installed pcre2 version may contain a security bug. Please upgrade to 10.20 or later: http://www.pcre.org.])
        else
            AC_MSG_RESULT([ok])
        fi
    else
        if test $pcrever_major -eq 8 &&
          test $pcrever_minor -gt 33 && test $pcrever_minor -lt 38; then
            AC_MSG_WARN([The installed pcre version may contain a security bug. Please upgrade to 8.38 or later: http://www.pcre.org.])
        else
            AC_MSG_RESULT([ok])
        fi
    fi

    found_pcre="yes"
    PCRE_HOME="`$pcreconfig --prefix`"
    PCRE_CPPFLAGS="`$pcreconfig --cflags`"
    if test "$pcrelib" = "pcre2"; then
        PCRE_LIBS="`$pcreconfig --libs8`"
    else
        PCRE_LIBS="`$pcreconfig --libs`"
    fi

    AC_MSG_NOTICE([CFLAGS from pcre-config: $PCRE_CPPFLAGS])
    AC_MSG_NOTICE([LIBS from pcre-config: $PCRE_LIBS])
fi

have_pcre="no"
if test "x$found_pcre" != "xno"; then
  dnl save_LIBS="$LIBS"
  save_CPPFLAGS="$CPPFLAGS"
  CPPFLAGS=$PCRE_CPPFLAGS
  save_LDFLAGS="$LDFLAGS"
  LDFLAGS=$PCRE_LIBS

  dnl pcre2 resource detection doesn't work correctly
  if test "$pcrelib" = "pcre2"; then
dnl      AC_CHECK_HEADER([pcre2.h], [have_pcre="yes"], [have_pcre="no"])
dnl      if test "x$have_pcre" = "xno"; then
dnl        AC_CHECK_HEADER(pcre2/pcre2.h, [have_pcre="yes"], [have_pcre="no"])
dnl      fi

dnl      if test "x$have_pcre" = "xyes"; then
dnl        AC_CHECK_LIB(pcre2, [pcre2_compile], [have_pcre="yes"], [have_pcre="no"])
dnl      fi
      have_pcre="yes"
  else
      AC_CHECK_HEADER(pcre.h, [have_pcre="yes"], [have_pcre="no"])
      if test "x$have_pcre" = "xno"; then
        AC_CHECK_HEADER(pcre/pcre.h, [have_pcre="yes"], [have_pcre="no"])
      fi

      if test "x$have_pcre" = "xyes"; then
        AC_CHECK_LIB([pcre], [pcre_compile], [have_pcre="yes"], [have_pcre="no"])
      fi
  fi

  dnl LIBS="$save_LIBS"
  CPPFLAGS="$save_CPPFLAGS"
  LDFLAGS="$save_LDFLAGS"
fi

if test "x$have_pcre" = "xyes"; then
  AC_DEFINE([HAVE_PCRE],1,[Define to 1 if you have a pcre library (-lpcre).])

  if test "$pcrelib" = "pcre2"; then
      AC_DEFINE([USING_PCRE2],1,[Define to 1 if you using the pcre2 library.])
      AC_MSG_NOTICE([Compiling and linking with pcre2 from $PCRE_HOME])
  else
      AC_MSG_NOTICE([Compiling and linking with pcre from $PCRE_HOME])
  fi
fi

dnl AM_CONDITIONAL([HAVE_PCRE], test "x$HAVE_PCRE" = "xyes")

dnl Check for PCRE

dnl handle the --with-pcre flag, default ON if present
AC_ARG_WITH([pcre],[AS_HELP_STRING([--with-pcre@<:@=DIR@:>@],
  [path to directory containing libpcre library, prioritizes PCRE2 over PCRE
    @<:@default=search PATH environment variable@:>@])],
  [pcreser=$withval],[pcreser="yes"])

dnl Look for pcre-config or pcre2-config within the specified path,
dnl or (by default) in the system's default search path. This is
dnl the only place the value of --with-pcre is used.
AS_CASE([$pcreser],
  [no],
  [pcreconfig=""],
dnl
  [yes],
  [ dnl No path was specified, so we execute the default action, which is
    dnl to search for PCRE on the system. First, we try pkg-config; if that
    dnl doesn't work, we search for the pcre-config or pcre2-config programs
    dnl in the system's search path. We look for the 8-bit library because
    dnl that's what the fallback check did when pkg-config was introduced
    dnl here. The name "PCRE" was chosen to match e.g. PCRE_CPPFLAGS from
    dnl the non-pkgconfig branch.
    PKG_CHECK_MODULES([PCRE], [libpcre2-8 >= 10.30], [
      dnl We found libpcre2 with pkg-config. We leave $pcreconfig empty,
      dnl so that the next big "if" branch below is skipped, and we
      dnl therefore don't try to do anything further with pcre-config.
      dnl The subsequent "if" block that tests $found_pcre is also
      dnl skipped, leaving us at the very last conditional for $have_pcre
      dnl and $pcrelib. We set those variables here so that HAVE_PCRE and
      dnl USING_PCRE2 will be defined. Finally, we append the output of
      dnl "pkg-config --libs" to the LIBS variable.
      have_pcre="yes"
      pcrelib="pcre2"

      # PCRE_LIBS contains the output of "pkg-config --libs" here,
      # and likewise for PCRE_CFLAGS which is even more of a misnomer,
      # as pkg-config --cflags outputs preprocessor flags.
      LIBS="${LIBS} ${PCRE_LIBS}"
      PCRE_CPPFLAGS="${PCRE_CPPFLAGS} ${PCRE_CFLAGS}"

      dnl The summary at the end of ./configure checks that this is non-empty.
      PCRE_HOME="pkg-config"
      if test -n "${PCRE_LIBS}" || test -n "${PCRE_CFLAGS}"; then
        PCRE_HOME="${PCRE_HOME} ( ${PCRE_LIBS} ${PCRE_CFLAGS} )"
      fi
    ], [
      dnl We didn't find libpcre2 with pkg-config, fall back to pcre(2)-config.
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
    ])
  ],
dnl
  [""],
  [AC_MSG_ERROR([cannot assign blank value to --with-pcre])],
dnl default case:
  [ AC_PATH_PROG([pcreconfig], [pcre2-config], [], [$pcreser/bin])
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
  ])

dnl At this point we have either found pcre(2)-config, or not, and
dnl the path to it is stored in $pcreconfig. If we found it, we use
dnl it to get the PCRE version, CFLAGS, LIBS, et cetera. Note that
dnl this next "if" will always fail if we found libpcre2 with pkg-
dnl config.
found_pcre="no"
if test "x$pcreconfig" != "x"; then
    AC_MSG_CHECKING([pcre-config version])
    pcre_version="`$pcreconfig --version`"

    if test "x$pcre_version" = "x"; then
        AC_MSG_ERROR([$pcreconfig failed])
    fi

    AC_MSG_RESULT([$pcre_version])

    pcrever_prefix=`expr "$pcre_version" : '\([[^0-9]]*\)'`
    pcrever_frag=${pcre_version#$pcrever_prefix}

    pcrever_major=`expr "$pcrever_frag" : '\([[0-9]]*\)'`
    pcrever_frag=${pcrever_frag#*\.}
    pcrever_minor=`expr "$pcrever_frag" : '\([[0-9]]*\)'`

    dnl check for match_limit_recursion support
    if test "$pcrelib" = "pcre"; then
        if test $pcrever_major -lt 6; then
            AC_MSG_ERROR([This pcre version is missing features used by ClamAV. Please upgrade to a newer version: http://www.pcre.org.])
        fi
        if test $pcrever_major -eq 6 && test $pcrever_minor -lt 5; then
            AC_MSG_ERROR([This pcre version is missing features used by ClamAV. Please upgrade to a newer version: http://www.pcre.org.])
        fi
        AC_MSG_WARN([pcre (original) detected. We recommend upgrading from pcre to pcre2 10.30 or later: http://www.pcre.org.])
    fi

    AC_MSG_CHECKING([for CVE-2017-7186])
    if test "$pcrelib" = "pcre2"; then
        if test $pcrever_major -eq 10 && test $pcrever_minor -lt 24; then
            AC_MSG_WARN([The installed pcre2 version may contain security bugs. Please upgrade to 10.30 or later: http://www.pcre.org.])
        else
            AC_MSG_RESULT([ok])
        fi
    else
        if test $pcrever_major -eq 8 && test $pcrever_minor -lt 41; then
            AC_MSG_WARN([The installed pcre version may contain security bugs. Please upgrade to 8.41+ or _preferably_ install pcre2 10.30+: http://www.pcre.org.])
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

if test "x$have_pcre" != "xyes"; then
    dnl default to "no" only if the pkg-config check hasn't already
    dnl set it to "yes"
    have_pcre="no"
fi

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

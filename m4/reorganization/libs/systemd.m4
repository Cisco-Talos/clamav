dnl Check for systemd-daemon
PKG_CHECK_MODULES(SYSTEMD, [libsystemd], [AC_DEFINE([HAVE_SYSTEMD],,[systemd is supported])],
                  [PKG_CHECK_MODULES(SYSTEMD, [libsystemd-daemon], [AC_DEFINE([HAVE_SYSTEMD],,[systemd-daemon is supported])], [AC_MSG_RESULT([systemd is not supported])])])
CLAMD_LIBS="$CLAMD_LIBS $SYSTEMD_LIBS"
CFLAGS="$CFLAGS $SYSTEMD_CFLAGS"

dnl Check for systemd system unit installation directory (see man 7 daemon)
AC_ARG_WITH([systemdsystemunitdir], AS_HELP_STRING([--with-systemdsystemunitdir=DIR], [Directory for systemd service files]),, [with_systemdsystemunitdir=auto])
AS_IF([test "x$with_systemdsystemunitdir" = "xyes" -o "x$with_systemdsystemunitdir" = "xauto"], [
     def_systemdsystemunitdir=$($PKG_CONFIG --variable=systemdsystemunitdir systemd)
     AS_IF([test "x$def_systemdsystemunitdir" = "x"],
         [AS_IF([test "x$with_systemdsystemunitdir" = "xyes"], [AC_MSG_ERROR([systemd support requested but pkg-config unable to query systemd package])])
          with_systemdsystemunitdir=no],
         [with_systemdsystemunitdir=$def_systemdsystemunitdir])])
AS_IF([test "x$with_systemdsystemunitdir" != "xno"],
      [AC_SUBST([systemdsystemunitdir], [$with_systemdsystemunitdir])])
AM_CONDITIONAL(INSTALL_SYSTEMD_UNITS, [test "x$with_systemdsystemunitdir" != "xno"])
AC_MSG_RESULT([checking for systemd system unit installation directory... $with_systemdsystemunitdir])


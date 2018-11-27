# PRELUDE
AC_ARG_ENABLE(prelude,
              AS_HELP_STRING([--enable-prelude],
                             [Enable Prelude support for alerts.]),
[
  if test "$enableval" != "no"; then
    AM_PATH_LIBPRELUDE(0.9.9, , AC_MSG_ERROR(Cannot find libprelude: Is libprelude-config in the path?), no)
    CPPFLAGS="${CPPFLAGS} ${LIBPRELUDE_CFLAGS}"
    LDFLAGS="${LDFLAGS} ${LIBPRELUDE_LDFLAGS}"
    LDFLAGS="${LDFLAGS} ${LIBPRELUDE_LIBS}"
    AC_DEFINE([PRELUDE], [1], [Libprelude support enabled])
  fi
],)

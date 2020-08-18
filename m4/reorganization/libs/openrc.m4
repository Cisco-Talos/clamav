dnl Should we install our OpenRC service files?
AC_ARG_ENABLE([openrc],
              AS_HELP_STRING([--enable-openrc],
                             [Install OpenRC service files]),
              [],
              [enable_openrc=no])
AM_CONDITIONAL(INSTALL_OPENRC_SERVICES,
               [test "x$enable_openrc" = "xyes"])

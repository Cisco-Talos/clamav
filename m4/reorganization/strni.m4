
AC_ARG_ENABLE([strni],
[AS_HELP_STRING([--enable-strni],
[enables explicit use of internal strn functions to support cross-compilation against older libs])],
enable_strni=$enableval, enable_strni="no")

if test "$enable_strni" = "yes"; then
    AC_DEFINE([HAVE_STRNI],1,[using internal strn functions])
    AC_SUBST([HAVE_STRNI])
fi



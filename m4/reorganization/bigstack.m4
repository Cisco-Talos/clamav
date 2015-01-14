AC_ARG_ENABLE([bigstack],
[AS_HELP_STRING([--enable-bigstack], [increase thread stack size])],
enable_bigstack=$enableval, enable_bigstack="no")

if test "$enable_bigstack" = "yes"; then
  AC_DEFINE([C_BIGSTACK],1,[Increase thread stack size.])
fi


AC_ARG_ENABLE([yara],
[AS_HELP_STRING([--disable-yara],
[do not include yara support])],
enable_yara=$enableval, enable_yara="yes")

if test "$enable_yara" = "yes"; then
    AC_DEFINE([HAVE_YARA],1,[yara sources are compiled in])
    AC_SUBST([HAVE_YARA])
fi



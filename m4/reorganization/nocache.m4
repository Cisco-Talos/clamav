AC_ARG_ENABLE([no-cache],
[AS_HELP_STRING([--enable-no-cache], [use "Cache-Control: no-cache" in freshclam])],
enable_nocache=$enableval, enable_nocache="no")

if test "$enable_nocache" = "yes"; then
  AC_DEFINE([FRESHCLAM_NO_CACHE],1,[use "Cache-Control: no-cache" in freshclam])
fi


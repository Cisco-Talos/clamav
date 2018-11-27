AM_CONDITIONAL([ENABLE_CLAMSUBMIT], [test "$have_curl" = "yes"])

AC_ARG_ENABLE([libfreshclam],
                          [AS_HELP_STRING([--enable-libfreshclam], [enable building of libfreshclam])],
                          enable_libfreshclam=$enableval, enable_libfreshclam="no")

if test "$enable_libfreshclam" = "yes"; then
  AC_DEFINE([ENABLE_LIBFRESHCLAM],1,[enable libfreshclam])
fi
AM_CONDITIONAL([ENABLE_LIBFRESHCLAM], [test "$enable_libfreshclam" = "yes"])

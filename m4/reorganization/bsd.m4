case "$host_os" in
freebsd*)
AC_CHECK_LIB([util], [kinfo_getvmmap], [LIBCLAMAV_LIBS="$LIBCLAMAV_LIBS -lutil"], AC_MSG_ERROR([You are running BSD but you don't have kinfo_getvmmap in the util library. Please fix manually.]))
;;
esac

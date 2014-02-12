if test "$enable_debug" = "yes"; then
  VERSION_SUFFIX="$VERSION_SUFFIX-debug"
  AC_DEFINE([CL_DEBUG],1,[enable debugging])
else
  AC_DEFINE([NDEBUG],1,[disable assertions])
fi

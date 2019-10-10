AC_ARG_ENABLE(libclamav-only,
	     [AC_HELP_STRING([--enable-libclamav-only], [build libclamav library and dependencies @<:@default=no@:>@])],
[enable_libclamav_only=$enableval], [enable_libclamav_only="no"])

AM_CONDITIONAL([BUILD_LIBCLAMAV_ONLY], [test x$enable_libclamav_only = xyes])

if test "$enable_libclamav_only" = "yes"; then
    dnl place all makefile conditionals required in configure.ac and Makefile.am by non-included macros here
    AM_CONDITIONAL([BUILD_CLAMONACC], [test x$enable_libclamav_only = xno])
fi

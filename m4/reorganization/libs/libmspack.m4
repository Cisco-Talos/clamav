dnl Determine whether to use the internal libmspack or to use system-specified libmspack
AC_ARG_WITH([system-libmspack], AC_HELP_STRING([--with-system-libmspack],
[Specify system libmspack location or to use internal package, uses full path to libmspack or bin directory
     (default=search PATH environment variable)]),
[system_libmspack=$withval], [system_libmspack="no"])

if test "x$system_libmspack" = "xno"; then
    use_internal_mspack=yes
    AM_CONDITIONAL([USE_INTERNAL_MSPACK], test TRUE)
else
    PKG_CHECK_MODULES([LIBMSPACK], [libmspack],
        use_internal_mspack=no, use_internal_mspack=yes)
    AM_CONDITIONAL([USE_INTERNAL_MSPACK], test "x$use_internal_mspack" = "xyes")
fi

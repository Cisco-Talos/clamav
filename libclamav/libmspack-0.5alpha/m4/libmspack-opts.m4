dnl Act as a single handler point for libmspack options
dnl Assigns system_libmspack variable

dnl Determine whether to use the internal libmspack or to use system-specified libmspack
AC_ARG_WITH([system-libmspack], AC_HELP_STRING([--with-system-libmspack],
[Specify system libmspack location or to use internal package, uses full path to libmspack or bin directory
     (default=search PATH environment variable)]),
[system_libmspack=$withval], [system_libmspack="no"])

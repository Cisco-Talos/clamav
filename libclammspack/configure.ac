# -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.
AC_PREREQ(2.59)
AC_INIT([libmspack],[0.10.1alpha],[kyzer@cabextract.org.uk])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([1.11])
AM_SILENT_RULES([yes])
AC_CONFIG_SRCDIR([mspack/mspack.h])
AC_CONFIG_HEADER([config.h])

# --enable-debug option
AC_ARG_ENABLE(debug,
  AS_HELP_STRING(--enable-debug,enable debugging),
  enable_debug=$enableval,
  enable_debug=no)
if test x$enable_debug = xyes; then
  AC_DEFINE(DEBUG, 1, [Turn debugging mode on?])
fi

# Checks for programs.
AC_PROG_CC
AM_CONDITIONAL(GCC, test x$GCC = 'xyes')
AM_PROG_AR
AC_PROG_INSTALL
LT_INIT

# Checks for header files.
AC_CHECK_HEADERS([inttypes.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_INLINE
AC_C_BIGENDIAN
AC_TYPE_MODE_T
AC_TYPE_OFF_T
AC_TYPE_SIZE_T
AC_CHECK_SIZEOF([off_t])

# Checks for library functions
AX_FUNC_MKDIR
AC_CHECK_FUNCS([towlower])

# largefile support
AC_SYS_LARGEFILE
AC_FUNC_FSEEKO

AC_CONFIG_FILES([Makefile libmspack.pc])
AC_OUTPUT

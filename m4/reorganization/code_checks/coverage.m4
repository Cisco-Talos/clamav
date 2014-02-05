AC_ARG_ENABLE(coverage,
	      AC_HELP_STRING([--enable-coverage],
			     [turn on test coverage
			      @<:@default=no@:>@]),
[enable_cov=$enableval],[enable_cov="no"])

if test "x$enable_coverage" = "xyes"; then
	if test "x$CHECK_LIBS" = "x"; then
		AC_MSG_ERROR([Coverage testing required, but unit tests not enabled!])
	fi
	if test "x$ac_compiler_gnu" != "xyes"; then
		AC_MSG_ERROR([coverage testing only works if gcc is used])
	fi

	CFLAGS="$CFLAGS -fprofile-arcs -ftest-coverage"
	LDFLAGS="$LDFLAGS -lgcov"
	AC_CHECK_PROGS(GCOV, gcov, false)
	AC_CHECK_PROGS(LCOV, lcov, false)
	AC_CHECK_PROGS(GENHTML, genhtml, false)
fi

AM_CONDITIONAL(ENABLE_COVERAGE, test "x$enable_coverage" = "xyes")

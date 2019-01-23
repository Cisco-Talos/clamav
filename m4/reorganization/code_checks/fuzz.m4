AC_ARG_ENABLE(fuzz,
	      AC_HELP_STRING([--enable-fuzz],
			     [enable building standalone fuzz targets
			      @<:@default=no@:>@]),
[enable_cov=$enableval],[enable_cov="no"])

if test "x$enable_fuzz" = "xyes"; then
    CXXFLAGS="-std=c++11 -stdlib=libc++ $CXXFLAGS"
fi

AM_CONDITIONAL(ENABLE_FUZZ, test "x$enable_fuzz" = "xyes")

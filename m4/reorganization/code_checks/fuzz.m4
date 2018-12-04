AC_ARG_ENABLE(fuzz,
	      AC_HELP_STRING([--enable-fuzz],
			     [enable building standalone fuzz targets
			      @<:@default=no@:>@]),
[enable_cov=$enableval],[enable_cov="no"])

# if test "x$enable_fuzz" = "xyes"; then
#     CPPFLAGS="-O2 -fno-omit-frame-pointer -g -fsanitize=address -fsanitize-coverage=edge,trace-pc-guard,indirect-calls,trace-cmp,trace-div,trace-gep $CPPFLAGS"
#     CFLAGS="-O2 -fno-omit-frame-pointer -g -fsanitize=address -fsanitize-coverage=edge,trace-pc-guard,indirect-calls,trace-cmp,trace-div,trace-gep $CFLAGS"
# #	LDFLAGS="-Wl,-Bstatic -lssl -lcrypto -lz -Wl,-Bdynamic -lc -lpthread -ldl $LDFLAGS"
# fi

AM_CONDITIONAL(ENABLE_FUZZ, test "x$enable_fuzz" = "xyes")

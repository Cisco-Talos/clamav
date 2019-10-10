AC_ARG_ENABLE(clamonacc,
	     [AC_HELP_STRING([--enable-clamonacc], [build clamonacc tool @<:@default=auto@:>@])],
[enable_clamonacc=$enableval], [enable_clamonacc="auto"])

if test "$enable_libclamav_only" != yes; then

if test "$enable_clamonacc" != "no"; then
	AC_CANONICAL_HOST

        case "${host_os}" in
        	linux*)
			AM_CONDITIONAL([BUILD_CLAMONACC], [test x$enable_clamonacc != xno])
			;;
		*)
			if test "$enable_clamonacc" = "yes"; then
				AC_MSG_ERROR([Clamonacc was explicitly requested, but the platform ($host_os) you are trying to build on is not currently supported for this tool.])
			fi
			AM_CONDITIONAL([BUILD_CLAMONACC], [test x$enable_clamonacc = xno])
                        ;;
	esac
else
	AM_CONDITIONAL([BUILD_CLAMONACC], [test x$enable_clamonacc = xyes])
fi
fi

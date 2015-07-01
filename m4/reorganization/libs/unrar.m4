AC_ARG_ENABLE([unrar],
[AS_HELP_STRING([--disable-unrar], [do not build libclamunrar and libclamunrar_iface])],
want_unrar=$enableval, want_unrar="yes")
AM_CONDITIONAL([ENABLE_UNRAR],[test "$want_unrar" = "yes"])

AC_ARG_ENABLE([getaddrinfo],
[AS_HELP_STRING([--disable-getaddrinfo], [do not include support for getaddrinfo])],
want_getaddrinfo=$enableval, want_getaddrinfo="yes")

if test "$want_getaddrinfo" = "yes"
then
    AC_MSG_CHECKING([for getaddrinfo])
    AC_CACHE_VAL([have_cv_gai],[
		AC_TRY_RUN([
		    #include <sys/types.h>
		    #include <sys/socket.h>
		    #include <netdb.h>
		    #include <unistd.h>
		    int main(int argc, char **argv)
		    {
			    struct addrinfo *res;
			    int sd;

			if(getaddrinfo("127.0.0.1", NULL, NULL, &res) < 0)
			    return 1;
			freeaddrinfo(res);

			return 0;
		    }
		],
		[have_cv_gai=yes],
		[have_cv_gai=no],
		[have_cv_gai=no])
		])
    AC_MSG_RESULT([$have_cv_gai])
    if test "$have_cv_gai" = yes; then
	AC_DEFINE(HAVE_GETADDRINFO, 1, [have getaddrinfo()])
    fi
fi

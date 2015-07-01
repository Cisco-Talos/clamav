AC_ARG_ENABLE([ipv6],
[AS_HELP_STRING([--disable-ipv6], [do not include IPv6 support])],
want_ipv6=$enableval, want_ipv6="yes")

if test "$want_ipv6" = "yes"
then
    AC_MSG_CHECKING([for IPv6 support])
    AC_CACHE_VAL([have_cv_ipv6],[
		AC_TRY_RUN([
		    #include <sys/types.h>
		    #include <sys/socket.h>
		    #include <netdb.h>
		    #include <unistd.h>
		    int main(int argc, char **argv)
		    {
			    struct addrinfo *res, hints;
			    int sd;

			if((sd = socket(AF_INET6, SOCK_STREAM, 0)) < 0)
			    return 1;
			close(sd);
			/* also check if getaddrinfo() handles AF_UNSPEC -- bb#1196 */
			memset(&hints, 0, sizeof(hints));
			hints.ai_family = AF_UNSPEC;
			if(getaddrinfo("127.0.0.1", NULL, &hints, &res) < 0)
			    return 1;
			freeaddrinfo(res);
			return 0;
		    }
		],
		[have_cv_ipv6=yes],
		[have_cv_ipv6=no],
		[have_cv_ipv6=no])
		])
    AC_MSG_RESULT([$have_cv_ipv6])
    if test "$have_cv_ipv6" = yes; then
	AC_DEFINE(SUPPORT_IPv6, 1, [Support for IPv6])
    fi
fi

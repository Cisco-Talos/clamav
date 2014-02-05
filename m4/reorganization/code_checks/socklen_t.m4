dnl Determine socklen_t type. Code from lftp.
AC_MSG_CHECKING([for socklen_t])
AC_CACHE_VAL([ac_cv_socklen_t],
[
    ac_cv_socklen_t=no
    AC_TRY_COMPILE([
	#include <sys/types.h>
        #include <sys/socket.h>
    ],
    [
	socklen_t len;
        getpeername(0,0,&len);
    ],
    [
	ac_cv_socklen_t=yes
    ])
])
AC_MSG_RESULT([$ac_cv_socklen_t])
    if test $ac_cv_socklen_t = no; then
    AC_MSG_CHECKING([for socklen_t equivalent])
    AC_CACHE_VAL([ac_cv_socklen_t_equiv],
    [
	ac_cv_socklen_t_equiv=int
        for t in int size_t unsigned long "unsigned long"; do
	    AC_TRY_COMPILE([
		#include <sys/types.h>
		#include <sys/socket.h>
	    ],
            [
		$t len;
		getpeername(0,0,&len);
            ],
            [
		ac_cv_socklen_t_equiv="$t"
		break
            ])
	done
    ])
    AC_MSG_RESULT([$ac_cv_socklen_t_equiv])
    AC_DEFINE_UNQUOTED([socklen_t], $ac_cv_socklen_t_equiv, [Define to "int" if <sys/socket.h> does not define.])
fi

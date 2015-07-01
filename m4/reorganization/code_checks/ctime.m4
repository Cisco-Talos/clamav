AC_MSG_CHECKING([for ctime_r])
if test "$ac_cv_func_ctime_r" = "yes"; then
    AC_TRY_COMPILE([
	#include <time.h>
    ],[
	char buf[31];
	time_t t;
	ctime_r(&t, buf, 30);
    ],[
	ac_cv_ctime_args=3
	AC_DEFINE([HAVE_CTIME_R_3],1,[ctime_r takes 3 arguments])
    ],[
	ac_cv_ctime_args=2
	AC_DEFINE([HAVE_CTIME_R_2],1,[ctime_r takes 2 arguments])
    ])

    AC_MSG_RESULT([yes, and it takes $ac_cv_ctime_args arguments])
fi

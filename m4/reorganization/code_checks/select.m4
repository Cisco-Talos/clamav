dnl Check if <sys/select.h> needs to be included for fd_set
AC_MSG_CHECKING([for fd_set])
AC_HEADER_EGREP([fd_mask], [sys/select.h], [have_fd_set=yes])
if test "$have_fd_set" = yes; then
	AC_DEFINE([HAVE_SYS_SELECT_H], 1, "have <sys/select.h>")
	AC_MSG_RESULT([yes, found in sys/select.h])
else
	AC_TRY_COMPILE([#include <sys/time.h>
			#include <sys/types.h>
			#ifdef HAVE_UNISTD_H
			#include <unistd.h>
			#endif],
		[fd_set readMask, writeMask;], have_fd_set=yes, have_fd_set=no)
	if test "$have_fd_set" = yes; then
		AC_MSG_RESULT([yes, found in sys/types.h])
	else
		AC_DEFINE([NO_FD_SET], 1, "no fd_set")
		AC_MSG_RESULT(no)
	fi
fi

AC_MSG_CHECKING([default FD_SETSIZE value])
AC_TRY_RUN([
#include <stdio.h>
#include <unistd.h>
#include <sys/time.h>
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#include <errno.h>
int main(void) {
        FILE *fp = fopen("conftestval", "w");
	if(fp) {
		if(fprintf (fp, "%d\n", FD_SETSIZE) < 1)  {
			perror("fprintf failed");
			return errno;
		}
	} else {
		perror("fopen failed");
		return errno;
	}
        return 0;
}
],
DEFAULT_FD_SETSIZE=`cat conftestval`,
DEFAULT_FD_SETSIZE=256,
DEFAULT_FD_SETSIZE=256)
AC_MSG_RESULT([$DEFAULT_FD_SETSIZE])
AC_DEFINE_UNQUOTED([DEFAULT_FD_SETSIZE], $DEFAULT_FD_SETSIZE, "default FD_SETSIZE value")

AC_CHECK_HEADERS([stdint.h unistd.h sys/int_types.h dlfcn.h inttypes.h sys/inttypes.h sys/times.h memory.h ndir.h stdlib.h strings.h string.h sys/mman.h sys/param.h sys/stat.h sys/types.h malloc.h poll.h limits.h sys/filio.h sys/uio.h termios.h stdbool.h pwd.h grp.h sys/queue.h sys/cdefs.h])
AC_CHECK_HEADER([syslog.h],AC_DEFINE([USE_SYSLOG],1,[use syslog]),)

have_pthreads=no
AC_CHECK_HEADER([pthread.h],[have_pthreads=yes])
if test "$have_pthreads" = "yes"; then
    AC_DEFINE([HAVE_PTHREAD_H],1,[Define to 1 if you have the <pthread.h> header file])
fi

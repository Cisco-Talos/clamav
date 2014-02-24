have_pthreads=no
AC_CHECK_HEADER([pthread.h],[have_pthreads=yes])

AC_ARG_ENABLE([pthreads],
[  --disable-pthreads      disable POSIX threads support],
have_pthreads=$enableval,)

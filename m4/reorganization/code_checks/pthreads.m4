have_pthreads=no
AC_CHECK_HEADER([pthread.h],[have_pthreads=yes])

AC_ARG_ENABLE([pthreads],
[AS_HELP_STRING([--disable-pthreads], [do not include POSIX threads support])],
have_pthreads=$enableval,)

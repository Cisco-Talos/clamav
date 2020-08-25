if test "$have_pthreads" = "yes"
then
    save_LIBS="$LIBS"
    LIBS="$THREAD_LIBS $LIBS"
    AC_CHECK_FUNCS([sched_yield pthread_yield])
    LIBS="$save_LIBS"
    dnl define these here, so we don't forget any system
    AC_DEFINE([CL_THREAD_SAFE],1,[thread safe])
    AC_DEFINE([_REENTRANT],1,[thread safe])
fi

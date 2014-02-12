dnl Check signed right shift implementation
AC_MSG_CHECKING([whether signed right shift is sign extended])
AC_TRY_RUN([int main(void){int a=-1;int b=a>>1;return(a!=b);}],
    [have_signed_rightshift_extended=yes],
    [have_signed_rightshift_extended=no],
    [have_signed_rightshift_extended=no])
if test $have_signed_rightshift_extended = yes; then
    AC_DEFINE([HAVE_SAR], 1, [Define signed right shift implementation])
fi
AC_MSG_RESULT([$have_signed_rightshift_extended]);

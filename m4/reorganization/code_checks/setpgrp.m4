dnl AC_FUNC_SETPGRP does not work when cross compiling
dnl Instead, assume we will have a prototype for setpgrp if cross compiling.
dnl testcase from gdb/configure.ac
if test "$cross_compiling" = no; then
 AC_FUNC_SETPGRP
else
 AC_CACHE_CHECK([whether setpgrp takes no argument], [ac_cv_func_setpgrp_void],
   [AC_TRY_COMPILE([
#include <unistd.h>
], [
 if (setpgrp(1,1) == -1)
   exit (0);
 else
   exit (1);
], ac_cv_func_setpgrp_void=no, ac_cv_func_setpgrp_void=yes)])
if test $ac_cv_func_setpgrp_void = yes; then
 AC_DEFINE([SETPGRP_VOID], 1)
fi
fi

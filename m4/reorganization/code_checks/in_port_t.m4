dnl check for in_port_t definition
AC_MSG_CHECKING([whether in_port_t is defined])
AC_TRY_COMPILE([
#include <sys/types.h>
#include <netinet/in.h>
],
[in_port_t pt; pt = 0; return pt;],
[
    AC_MSG_RESULT(yes)
    AC_DEFINE([HAVE_IN_PORT_T],1,[in_port_t is defined])
],
AC_MSG_RESULT(no))

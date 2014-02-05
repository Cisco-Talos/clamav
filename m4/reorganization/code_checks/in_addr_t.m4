dnl check for in_addr_t definition
AC_MSG_CHECKING([for in_addr_t definition])
AC_TRY_COMPILE([
#include <sys/types.h>
#include <netinet/in.h>
],
[ in_addr_t pt; pt = 0; return pt; ],
[
    AC_MSG_RESULT(yes)
    AC_DEFINE([HAVE_IN_ADDR_T],1,[in_addr_t is defined])
],
AC_MSG_RESULT(no))

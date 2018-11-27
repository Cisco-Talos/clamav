AC_MSG_CHECKING([stat64])
AC_TRY_RUN([
#define _LARGEFILE_SOURCE
#define _LARGEFILE64_SOURCE
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>

int main(void) {
    struct stat64 sb;

    if (stat64(".", &sb) == -1)
        return errno;

    return 0;
}
],
[enable_stat64=yes],
[enable_stat64=no],
[enable_stat64=no],
)

if test "$enable_stat64" != "no"; then
AC_DEFINE([HAVE_STAT64],1,[enable stat64])
CFLAGS="$CFLAGS -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64"
fi
AC_MSG_RESULT([$enable_stat64])

AC_MSG_CHECKING([LFS safe fts implementation])
AC_COMPILE_IFELSE( [
#include <fts.h>

int main(void) {
    fts_open((void *)0, FTS_PHYSICAL, (void *)0);

    return 0;
}
],
[have_LFS_fts=yes],
[have_LFS_fts=no],
[have_LFS_fts=no]
)
AC_MSG_RESULT([$have_LFS_fts])
AM_CONDITIONAL([SYSTEM_LFS_FTS], [test "x$have_LFS_fts" = "xyes"])
if test "x$have_LFS_fts" = "xyes"; then
	AC_DEFINE([HAVE_SYSTEM_LFS_FTS], [1], [Use libc's fts() implementation])
	lfs_fts_msg="libc"
else
	AC_DEFINE([HAVE_SYSTEM_LFS_FTS], [0], [Use private fts() implementation which is LFS safe])
	lfs_fts_msg="internal, libc's is not LFS compatible"
fi

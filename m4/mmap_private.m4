AC_ARG_ENABLE([mmap-for-cross-compiling],[AS_HELP_STRING([--enable-mmap-for-cross-compiling], [set to "yes" to force enable mmap support without checking under cross-compiling. This could help enable mempool feature.])], enable_mmap_for_cross_compiling=$enableval, mmap_for_cross_compiling="no")
dnl Check for mmap()
dnl AC_FUNC_MMAP checks for private fixed mappings, we don't need
dnl fixed mappings, so check only wether private mappings work.
dnl AC_FUNC_MMAP would fail on HP-UX for example.
AC_DEFUN([AC_C_FUNC_MMAP_PRIVATE],
[
	AC_CACHE_CHECK([for working mmap], [ac_cv_c_mmap_private],
	[
		AC_RUN_IFELSE([AC_LANG_SOURCE([
#include <unistd.h>
#include <stdlib.h>
#include <sys/mman.h>
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#include <fcntl.h>
#define ERR(e) do { status = e; goto done; } while(0)
int main(void)
{
	char *data = NULL, *data2 = MAP_FAILED, *data3 = NULL;
	size_t i, datasize = 1024;
	int fd = -1, status = 0;

  	/* First, make a file with some known garbage in it. */
	data = (char*) malloc(datasize);
	if(!data)
		ERR(1);
	for(i=0;i<datasize;i++)
		*(data + i) = rand();
	umask(0);
	fd = creat("conftest.mmap", 0600);
	if(fd < 0)
		ERR(1);
	if(write (fd, data, datasize) != datasize)
		ERR(1);
	close(fd);
	fd = open("conftest.mmap", O_RDWR);
	if (fd < 0)
		ERR(1);
	/* Next, try to create a private map of the file. If we can, also make sure that
	   we see the same garbage.  */
	data2 = mmap(NULL, datasize, PROT_READ | PROT_WRITE,
		MAP_PRIVATE, fd, 0L);
	if(data2 == MAP_FAILED)
		ERR(2);
	for(i=0;i<datasize;i++)
		if(*(data + i) != *(data2+ i))
			ERR(3);
	/* Finally, make sure that changes to the mapped area do not
	   percolate back to the file as seen by read().
	   (This is a bug on some variants of i386 svr4.0.)  */
	for (i = 0; i < datasize; ++i)
		*(data2 + i) = *(data2 + i) + 1;
	data3 = (char*) malloc(datasize);
	if(!data3)
		ERR(1);
	if(read (fd, data3, datasize) != datasize)
		ERR(1);
	for(i=0;i<datasize;i++)
		if(*(data + i) != *(data3 + i))
			ERR(3);
done:
	if(fd >= 0)
		close(fd);
	if(data3)
		free(data3);
	if(data2 != MAP_FAILED)
		munmap(data2, datasize);
	if(data)
		free(data);
	return status;
}])],
	[ac_cv_c_mmap_private=yes],
	[ac_cv_c_mmap_private=no],
	[
	if test $enable_mmap_for_cross_compiling = yes; then
  ac_cv_c_mmap_private=yes
	else
  ac_cv_c_mmap_private=no
	fi
	])])
if test $ac_cv_c_mmap_private = yes; then
	AC_DEFINE(HAVE_MMAP, 1,
		[Define to 1 if you have a working `mmap' system call that supports MAP_PRIVATE.])
fi
rm -f conftest.mmap
])


AC_DEFUN([AC_C_FUNC_MMAP_ANONYMOUS],
[
	AC_CACHE_CHECK([for MAP_ANON(YMOUS)], [ac_cv_c_mmap_anonymous],[
		ac_cv_c_mmap_anonymous='no'
		AC_LINK_IFELSE(
			[AC_LANG_PROGRAM([[#include <sys/mman.h>]], [[mmap((void *)0, 0, PROT_READ | PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);]])],
			[ac_cv_c_mmap_anonymous='MAP_ANONYMOUS'],
			[
				AC_LINK_IFELSE(
					[AC_LANG_PROGRAM([[
/* OPENBSD WORKAROUND - DND*/
#include <sys/types.h>
/* OPENBSD WORKAROUND - END*/
#include <sys/mman.h>
]], [[mmap((void *)0, 0, PROT_READ | PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0);]])],
					[ac_cv_c_mmap_anonymous='MAP_ANON']
				)
			]
		)
	])
	if test "$ac_cv_c_mmap_anonymous" != "no"; then
		AC_DEFINE_UNQUOTED([ANONYMOUS_MAP],[$ac_cv_c_mmap_anonymous],[mmap flag for anonymous maps])
	fi
])

AC_DEFUN([AC_C_FUNC_PAGESIZE],
[
ac_cv_c_can_get_pagesize="no"
AC_CACHE_CHECK([for sysconf(_SC_PAGESIZE)], [ac_cv_c_sysconf_sc_pagesize], [
	AC_LINK_IFELSE([AC_LANG_PROGRAM([[
#include <sys/types.h>
#if HAVE_UNISTD_H
#include <unistd.h>
#endif]], [[int x = sysconf(_SC_PAGESIZE);]])],
	[ac_cv_c_sysconf_sc_pagesize=yes], [ac_cv_c_sysconf_sc_pagesize=no])
])
if test "$ac_cv_c_sysconf_sc_pagesize" = "yes"; then
	AC_DEFINE([HAVE_SYSCONF_SC_PAGESIZE], 1, [Define to 1 if sysconf(_SC_PAGESIZE) is available])
	ac_cv_c_can_get_pagesize="yes"
fi
AC_CACHE_CHECK([for getpagesize()], [ac_cv_c_getpagesize], [
	AC_LINK_IFELSE([AC_LANG_PROGRAM([[
#if HAVE_UNISTD_H
#include <unistd.h>
#endif]], [[int x = getpagesize();]])],
	[ac_cv_c_getpagesize=yes], [ac_cv_c_getpagesize=no])
])
if test "$ac_cv_c_getpagesize" = "yes"; then
	AC_DEFINE([HAVE_GETPAGESIZE], 1, [Define to 1 if getpagesize() is available])
	ac_cv_c_can_get_pagesize="yes"
fi
])


#ifndef _ZZIP_CONFIG_H
#define _ZZIP_CONFIG_H 1
 
/* tk: adopted for libclamav */

/* Define if you have the <dirent.h> header file, and it defines `DIR'. */
#ifdef HAVE_DIRENT_H 
#ifndef ZZIP_HAVE_DIRENT_H
#define ZZIP_HAVE_DIRENT_H  1 
#endif
#endif

/* Define if you have the <dlfcn.h> header file. */
#ifdef HAVE_DLFCN_H 
#ifndef ZZIP_HAVE_DLFCN_H
#define ZZIP_HAVE_DLFCN_H  1 
#endif
#endif

/* Define if you have the <inttypes.h> header file. */
#ifdef HAVE_INTTYPES_H 
#ifndef ZZIP_HAVE_INTTYPES_H
#define ZZIP_HAVE_INTTYPES_H  1 
#endif
#endif

/* tk: required for FreeBSD 4.x */
#ifdef HAVE_SYS_INTTYPES_H 
#ifndef ZZIP_HAVE_SYS_INTTYPES_H
#define ZZIP_HAVE_SYS_INTTYPES_H  1 
#endif
#endif

/* Define if you have the <memory.h> header file. */
#ifdef HAVE_MEMORY_H 
#ifndef ZZIP_HAVE_MEMORY_H
#define ZZIP_HAVE_MEMORY_H  1 
#endif
#endif

/* Define if you have the <ndir.h> header file, and it defines `DIR'. */
#ifdef HAVE_NDIR_H
#ifndef ZZIP_HAVE_NDIR_H
#define ZZIP_HAVE_NDIR_H 1
#endif
#endif

/* Define if you have the <stdint.h> header file. */
#ifdef HAVE_STDINT_H 
#ifndef ZZIP_HAVE_STDINT_H
#define ZZIP_HAVE_STDINT_H  1 
#endif
#endif

/* Define if you have the <stdlib.h> header file. */
#ifdef HAVE_STDLIB_H 
#ifndef ZZIP_HAVE_STDLIB_H
#define ZZIP_HAVE_STDLIB_H  1 
#endif
#endif

/* Define if you have the <strings.h> header file. */
#ifdef HAVE_STRINGS_H 
#ifndef ZZIP_HAVE_STRINGS_H
#define ZZIP_HAVE_STRINGS_H  1 
#endif
#endif

/* Define if you have the <string.h> header file. */
#ifdef HAVE_STRING_H 
#ifndef ZZIP_HAVE_STRING_H
#define ZZIP_HAVE_STRING_H  1 
#endif
#endif

/* Define if you have the <sys/dir.h> header file, and it defines `DIR'. */
#ifdef HAVE_SYS_DIR_H
#ifndef ZZIP_HAVE_SYS_DIR_H
#define ZZIP_HAVE_SYS_DIR_H 1
#endif
#endif

/* Define if you have the <sys/int_types.h> header file. */
#ifdef HAVE_SYS_INT_TYPES_H
#ifndef ZZIP_HAVE_SYS_INT_TYPES_H
#define ZZIP_HAVE_SYS_INT_TYPES_H 1
#endif
#endif

/* Define if you have the <sys/mman.h> header file. */
#ifdef HAVE_SYS_MMAN_H 
#ifndef ZZIP_HAVE_SYS_MMAN_H
#define ZZIP_HAVE_SYS_MMAN_H  1 
#endif
#endif

/* Define if you have the <sys/ndir.h> header file, and it defines `DIR'. */
#ifdef HAVE_SYS_NDIR_H
#ifndef ZZIP_HAVE_SYS_NDIR_H
#define ZZIP_HAVE_SYS_NDIR_H 1
#endif
#endif

/* Define if you have the <sys/param.h> header file. */
#ifdef HAVE_SYS_PARAM_H 
#ifndef ZZIP_HAVE_SYS_PARAM_H
#define ZZIP_HAVE_SYS_PARAM_H  1 
#endif
#endif

/* Define if you have the <sys/stat.h> header file. */
#ifdef HAVE_SYS_STAT_H 
#ifndef ZZIP_HAVE_SYS_STAT_H
#define ZZIP_HAVE_SYS_STAT_H  1 
#endif
#endif

/* Define if you have the <sys/types.h> header file. */
#ifdef HAVE_SYS_TYPES_H 
#ifndef ZZIP_HAVE_SYS_TYPES_H
#define ZZIP_HAVE_SYS_TYPES_H  1 
#endif
#endif

/* Define if you have the <unistd.h> header file. */
#ifdef HAVE_UNISTD_H 
#ifndef ZZIP_HAVE_UNISTD_H
#define ZZIP_HAVE_UNISTD_H  1 
#endif
#endif

/* Define if you have the <windows.h> header file. */
/* #undef ZZIP_HAVE_WINDOWS_H */

/* Define if you have the <winnt.h> header file. */
/* #undef ZZIP_HAVE_WINNT_H */

/* Define if you have the <zlib.h> header file. */
#ifdef HAVE_ZLIB_H 
#ifndef ZZIP_HAVE_ZLIB_H
#define ZZIP_HAVE_ZLIB_H  1 
#endif
#endif

/* Name of package */
#ifndef ZZIP_PACKAGE 
#define ZZIP_PACKAGE  "zziplib" 
#endif

/* The number of bytes in type int */
#ifndef ZZIP_SIZEOF_INT 
#define ZZIP_SIZEOF_INT  SIZEOF_INT
#endif

/* The number of bytes in type long */
#ifndef ZZIP_SIZEOF_LONG 
#define ZZIP_SIZEOF_LONG  SIZEOF_LONG
#endif

/* The number of bytes in type short */
#ifndef ZZIP_SIZEOF_SHORT 
#define ZZIP_SIZEOF_SHORT  SIZEOF_SHORT
#endif

/* Define if you have the ANSI C header files. */
#ifndef ZZIP_STDC_HEADERS 
#define ZZIP_STDC_HEADERS  1 
#endif

/* Version number of package */
#ifndef ZZIP_VERSION 
#define ZZIP_VERSION  "0.10.27" 
#endif

/* Define to empty if `const' does not conform to ANSI C. */
/* #undef ZZIP_const */

/* Define as `__inline' if that's what the C compiler calls it, or to nothing
   if it is not supported. */
/* #undef ZZIP_inline */

/* Define to `long' if <sys/types.h> does not define. */
/* #undef ZZIP_off_t */
 
/* _ZZIP_CONFIG_H */
#endif

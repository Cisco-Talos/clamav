/* clamav-config.h.  Generated from clamav-config.h.in by update-win32.  */

/* clamav-config.h.in.  Generated from configure.in by autoheader.  */

/* Define if building universal (internal helper macro) */
/* #undef AC_APPLE_UNIVERSAL_BUILD */

/* mmap flag for anonymous maps */
/* #undef ANONYMOUS_MAP */

/* enable bind8 compatibility */
/* #undef BIND_8_COMPAT */

/* "build clamd" */
#define BUILD_CLAMD 1

/* name of the clamav group */
#define CLAMAVGROUP "clamav"

/* name of the clamav user */
#define CLAMAVUSER "clamav"

/* enable debugging */
/* #undef CL_DEBUG */

/* enable experimental code */
/* #undef CL_EXPERIMENTAL */

/* thread safe */
#define CL_THREAD_SAFE 1

/* where to look for the config file */
/* #undef CONFDIR */

/* curses header location */
/* #undef CURSES_INCLUDE */

/* os is aix */
/* #undef C_AIX */

/* os is beos */
/* #undef C_BEOS */

/* Increase thread stack size. */
/* #undef C_BIGSTACK */

/* os is bsd flavor */
/* #undef C_BSD */

/* os is darwin */
/* #undef C_DARWIN */

/* target is gnu-hurd */
/* #undef C_GNU_HURD */

/* os is hpux */
/* #undef C_HPUX */

/* os is interix */
/* #undef C_INTERIX */

/* os is irix */
/* #undef C_IRIX */

/* target is kfreebsd-gnu */
/* #undef C_KFREEBSD_GNU */

/* target is linux */
/* #undef C_LINUX */

/* os is OS/2 */
/* #undef C_OS2 */

/* os is osf/tru64 */
/* #undef C_OSF */

/* os is QNX 6.x.x */
/* #undef C_QNX6 */

/* os is solaris */
/* #undef C_SOLARIS */

/* Path to virus database directory. */
/* #undef DATADIR */

/* "default FD_SETSIZE value" */
#define DEFAULT_FD_SETSIZE 1024

/* use fanotify */
/* #undef FANOTIFY */

/* whether _XOPEN_SOURCE needs to be defined for fd passing to work */
/* #undef FDPASS_NEED_XOPEN */

/* file i/o buffer size */
#define FILEBUFF 8192

/* enable workaround for broken DNS servers */
/* #undef FRESHCLAM_DNS_FIX */

/* use "Cache-Control: no-cache" in freshclam */
/* #undef FRESHCLAM_NO_CACHE */

/* Define to 1 if you have the `argz_add' function. */
/* #undef HAVE_ARGZ_ADD */

/* Define to 1 if you have the `argz_append' function. */
/* #undef HAVE_ARGZ_APPEND */

/* Define to 1 if you have the `argz_count' function. */
/* #undef HAVE_ARGZ_COUNT */

/* Define to 1 if you have the `argz_create_sep' function. */
/* #undef HAVE_ARGZ_CREATE_SEP */

/* Define to 1 if you have the <argz.h> header file. */
/* #undef HAVE_ARGZ_H */

/* Define to 1 if you have the `argz_insert' function. */
/* #undef HAVE_ARGZ_INSERT */

/* Define to 1 if you have the `argz_next' function. */
/* #undef HAVE_ARGZ_NEXT */

/* Define to 1 if you have the `argz_stringify' function. */
/* #undef HAVE_ARGZ_STRINGIFY */

/* attrib aligned */
/* #undef HAVE_ATTRIB_ALIGNED */

/* attrib packed */
/* #undef HAVE_ATTRIB_PACKED */

/* have bzip2 */
#define HAVE_BZLIB_H 1

/* Define to 1 if you have the `closedir' function. */
#define HAVE_CLOSEDIR 1

/* Define to 1 if you have the `ctime_r' function. */
#define HAVE_CTIME_R 1

/* ctime_r takes 2 arguments */
#define HAVE_CTIME_R_2 1

/* ctime_r takes 3 arguments */
/* #undef HAVE_CTIME_R_3 */

/* Define to 1 if you have the declaration of `cygwin_conv_path', and to 0 if
   you don't. */
/* #undef HAVE_DECL_CYGWIN_CONV_PATH */

/* Define to 1 if you have the <dirent.h> header file. */
#define HAVE_DIRENT_H 1

/* Define if you have the GNU dld library. */
/* #undef HAVE_DLD */

/* Define to 1 if you have the <dld.h> header file. */
/* #undef HAVE_DLD_H */

/* Define to 1 if you have the `dlerror' function. */
/* #undef HAVE_DLERROR */

/* Define to 1 if you have the <dlfcn.h> header file. */
#define HAVE_DLFCN_H 1

/* Define to 1 if you have the <dl.h> header file. */
/* #undef HAVE_DL_H */

/* Define if you have the _dyld_func_lookup function. */
/* #undef HAVE_DYLD */

/* Define to 1 if you have the `enable_extended_FILE_stdio' function. */
/* #undef HAVE_ENABLE_EXTENDED_FILE_STDIO */

/* Define to 1 if the system has the type `error_t'. */
/* #undef HAVE_ERROR_T */

/* have working file descriptor passing support */
/* #undef HAVE_FD_PASSING */

/* Define to 1 if fseeko (and presumably ftello) exists and is declared. */
#define HAVE_FSEEKO 1

/* have getaddrinfo() */
#define HAVE_GETADDRINFO 1

/* Define to 1 if getpagesize() is available */
#define HAVE_GETPAGESIZE 1

/* Define to 1 if you have the <grp.h> header file. */
/* #undef HAVE_GRP_H */

/* iconv() available */
/* #undef HAVE_ICONV */

/* Define to 1 if you have the `inet_ntop' function. */
#define HAVE_INET_NTOP 1

/* Define to 1 if you have the `initgroups' function. */
/* #undef HAVE_INITGROUPS */

/* Define to 1 if you have the <inttypes.h> header file. */
/* #undef HAVE_INTTYPES_H */
#define HAVE_INTTYPES_H 1

/* in_addr_t is defined */
/* #undef HAVE_IN_ADDR_T */

/* in_port_t is defined */
#define HAVE_IN_PORT_T 1

/* Define to '1' if you have the check.h library */
/* #undef HAVE_LIBCHECK */

/* Define if you have the libdl library or equivalent. */
#define HAVE_LIBDL 1

/* Define if libdlloader will be built on this platform */
#define HAVE_LIBDLLOADER 1

/* Define to 1 if you have the <libmilter/mfapi.h> header file. */
/* #undef HAVE_LIBMILTER_MFAPI_H */

/* Define to '1' if you have the ncurses.h library */
/* #undef HAVE_LIBNCURSES */

/* Define to '1' if you have the curses.h library */
/* #undef HAVE_LIBPDCURSES */

/* Define to 1 if you have the 'pcre2' library (-lpcre2). */
#define HAVE_PCRE 1
#define USING_PCRE2 1

/* Define to 1 if you have the 'libxml2' library (-lxml2). */
#define HAVE_LIBXML2 1

/* Define to 1 if you have the `z' library (-lz). */
#define HAVE_LIBZ 1

/* Define to 1 if you have the <limits.h> header file. */
#define HAVE_LIMITS_H 1

/* Define this if a modern libltdl is already installed */
#define HAVE_LTDL 1

/* Define to 1 if you have the <mach-o/dyld.h> header file. */
/* #undef HAVE_MACH_O_DYLD_H */

/* Define to 1 if you have the `madvise' function. */
/* #undef HAVE_MADVISE */

/* Define to 1 if you have the `mallinfo' function. */
/* #undef HAVE_MALLINFO */

/* Define to 1 if you have the <malloc.h> header file. */
#define HAVE_MALLOC_H 1

/* Define to 1 if you have the `memcpy' function. */
#define HAVE_MEMCPY 1

/* Define to 1 if you have the <memory.h> header file. */
#define HAVE_MEMORY_H 1

/* Define to 1 if you have the `mkstemp' function. */
#define HAVE_MKSTEMP 1

/* Define to 1 if you have a working `mmap' system call that supports
   MAP_PRIVATE. */
/* #undef HAVE_MMAP */

/* Define to 1 if you have the <ndir.h> header file. */
/* #undef HAVE_NDIR_H */

/* Define to 1 if you have the `opendir' function. */
#define HAVE_OPENDIR 1

/* Define to 1 if you have the `poll' function. */
#define HAVE_POLL 1

/* Define to 1 if you have the <poll.h> header file. */
/* #undef HAVE_POLL_H */

/* "pragma pack" */
#define HAVE_PRAGMA_PACK 1

/* "pragma pack hppa/hp-ux style" */
/* #undef HAVE_PRAGMA_PACK_HPPA */

/* Define if libtool can extract symbol lists from object files. */
/* #undef HAVE_PRELOADED_SYMBOLS */

/* Define to 1 if you have the `pthread_yield' function. */
#define HAVE_PTHREAD_YIELD 1

/* Define to 1 if you have the <pwd.h> header file. */
/* #undef HAVE_PWD_H */

/* Define to 1 if you have the `readdir' function. */
#define HAVE_READDIR 1

/* readdir_r takes 2 arguments */
/* #undef HAVE_READDIR_R_2 */

/* readdir_r takes 3 arguments */
/* #undef HAVE_READDIR_R_3 */

/* Define to 1 if you have the `recvmsg' function. */
#define HAVE_RECVMSG 1

/* have resolv.h */
#define HAVE_RESOLV_H 1

/* Define signed right shift implementation */
#define HAVE_SAR 1

/* Define to 1 if you have the `sched_yield' function. */
/* #undef HAVE_SCHED_YIELD */

/* Define to 1 if you have the `sendmsg' function. */
#define HAVE_SENDMSG 1

/* Define to 1 if you have the `setgroups' function. */
/* #undef HAVE_SETGROUPS */

/* Define to 1 if you have the `setsid' function. */
#define HAVE_SETSID 1

/* Define if you have the shl_load function. */
/* #undef HAVE_SHL_LOAD */

/* Define to 1 if you have the `snprintf' function. */
#define HAVE_SNPRINTF 1

/* Define to 1 if you have the <stdbool.h> header file. */
/* #undef HAVE_STDBOOL_H */

/* Define to 1 if you have the <stdint.h> header file. */
/* #undef HAVE_STDINT_H */
#define HAVE_STDINT_H 1

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define to 1 if you have the `strcasestr' function. */
/* #undef HAVE_STRCASESTR */

/* Define to 1 if you have the `strerror_r' function. */
#define HAVE_STRERROR_R 1

/* Define to 1 if you have the <strings.h> header file. */
/* #undef HAVE_STRINGS_H */

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define to 1 if you have the `strlcat' function. */
/* #undef HAVE_STRLCAT */

/* Define to 1 if you have the `strlcpy' function. */
/* #undef HAVE_STRLCPY */

/* Define to 1 if you have the `strndup' function. */
/* #undef HAVE_STRNDUP */

/* Define to 1 if you have the `strnstr' function. */
/* #undef HAVE_STRNSTR */

/* Define to 1 if sysconf(_SC_PAGESIZE) is available */
/* #undef HAVE_SYSCONF_SC_PAGESIZE */

/* link against system-wide libtommath */
/* #undef HAVE_SYSTEM_TOMMATH */

/* Define to 1 if you have the <sys/dl.h> header file. */
/* #undef HAVE_SYS_DL_H */

/* Define to 1 if you have the <sys/filio.h> header file. */
/* #undef HAVE_SYS_FILIO_H */

/* Define to 1 if you have the <sys/inttypes.h> header file. */
/* #undef HAVE_SYS_INTTYPES_H */

/* Define to 1 if you have the <sys/int_types.h> header file. */
/* #undef HAVE_SYS_INT_TYPES_H */

/* Define to 1 if you have the <sys/mman.h> header file. */
/* #undef HAVE_SYS_MMAN_H */

/* Define to 1 if you have the <sys/param.h> header file. */
/* #undef HAVE_SYS_PARAM_H */

/* "have <sys/select.h>" */
/* #undef HAVE_SYS_SELECT_H */

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/times.h> header file. */
/* #undef HAVE_SYS_TIMES_H */

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* Define to 1 if you have the <sys/uio.h> header file. */
/* #undef HAVE_SYS_UIO_H */

/* Define to 1 if you have the <termios.h> header file. */
/* #undef HAVE_TERMIOS_H */

/* Define this if uname(2) is POSIX */
/* #undef HAVE_UNAME_SYSCALL */

/* Define to 1 if you have the <unistd.h> header file. */
/* #undef HAVE_UNISTD_H */

/* Define to 1 if you have the `vsnprintf' function. */
#define HAVE_VSNPRINTF 1

/* This value is set to 1 to indicate that the system argz facility works */
/* #undef HAVE_WORKING_ARGZ */

/* For internal use only - DO NOT DEFINE */
/* #undef HAVE__INTERNAL__SHA_COLLECT */

/* "Full library version number" */
#define LIBCLAMAV_FULLVER "9.0.1"

/* "Major library version number" */
#define LIBCLAMAV_MAJORVER 9

/* Define if the OS needs help to load dependent libraries for dlopen(). */
/* #undef LTDL_DLOPEN_DEPLIBS */

/* Define to the system default library search path. */
#define LT_DLSEARCH_PATH ""

/* The archive extension */
#define LT_LIBEXT "dll"

/* The archive prefix */
/* #undef LT_LIBPREFIX */

/* Define to the extension used for runtime loadable modules, say, ".so". */
#define LT_MODULE_EXT ".dll"

/* Define to the name of the environment variable that determines the run-time
   module search path. */
#define LT_MODULE_PATH_VAR "LD_LIBRARY_PATH"

/* Define to the sub-directory in which libtool stores uninstalled libraries.
   */
#define LT_OBJDIR ""

/* disable assertions */
#define NDEBUG 1

/* Define if dlsym() requires a leading underscore in symbol names. */
/* #undef NEED_USCORE */

/* bzip funtions do not have bz2 prefix */
/* #undef NOBZ2PREFIX */

/* "no fd_set" */
/* #undef NO_FD_SET */

/* Name of package */
#define PACKAGE PACKAGE_NAME

/* Define to the address where bug reports for this package should be sent. */
#define PACKAGE_BUGREPORT "https://bugzilla.clamav.net/"

/* Define to the full name of this package. */
#define PACKAGE_NAME "ClamAV"

/* Define to the full name and version of this package. */
#define PACKAGE_STRING "ClamAV 0.101.4"

/* Define to the one symbol short name of this package. */
#define PACKAGE_TARNAME "clamav"

/* Define to the home page for this package. */
#define PACKAGE_URL "https://www.clamav.net/"

/* Define to the version of this package. */
#define PACKAGE_VERSION "0.101.4"

/* scan buffer size */
#define SCANBUFF 131072

/* Define to 1 if the `setpgrp' function takes no argument. */
#define SETPGRP_VOID 1

/* The number of bytes in type int */
#define SIZEOF_INT 4

/* The number of bytes in type long */
#define SIZEOF_LONG 4

/* The number of bytes in type long long */
#define SIZEOF_LONG_LONG 8

/* The number of bytes in type short */
#define SIZEOF_SHORT 2

/* The number of bytes in type void * */
/* #undef SIZEOF_VOID_P */

/* Define to 1 if you have the ANSI C header files. */
#define STDC_HEADERS 1

/* Support for IPv6 */
/* #undef SUPPORT_IPv6 */

/* enable memory pools */
#define USE_MPOOL 1

/* use syslog */
/* #undef USE_SYSLOG */

/* Version number of package */
#define VERSION "0.101.4"

/* Version suffix for package */
#define VERSION_SUFFIX ""

/* Define WORDS_BIGENDIAN to 1 if your processor stores words with the most
   significant byte first (like Motorola and SPARC, unlike Intel). */
#if defined AC_APPLE_UNIVERSAL_BUILD
# if defined __BIG_ENDIAN__
#  define WORDS_BIGENDIAN 1
# endif
#else
# ifndef WORDS_BIGENDIAN
#define WORDS_BIGENDIAN 0
# endif
#endif

/* Define to 1 to make fseeko visible on some hosts (e.g. glibc 2.2). */
/* #undef _LARGEFILE_SOURCE */

/* POSIX compatibility */
/* #undef _POSIX_PII_SOCKET */

/* thread safe */
#define _REENTRANT 1

/* thread safe */
/* #undef _THREAD_SAFE */

/* Define so that glibc/gnulib argp.h does not typedef error_t. */
/* #undef __error_t_defined */

/* Define to empty if `const' does not conform to ANSI C. */
/* #undef const */

/* Define to a type to use for `error_t' if it is not otherwise available. */
/* #undef error_t */

/* Define to `__inline__' or `__inline' if that's what the C compiler
   calls it, or to nothing if 'inline' is not supported under any name.  */
#ifndef __cplusplus
#define inline _inline
#endif

/* Define to `long int' if <sys/types.h> does not define. */
/* #undef off_t */

/* Define to the equivalent of the C99 'restrict' keyword, or to
   nothing if this is not supported.  Do not define if restrict is
   supported directly.  */
/* #undef restrict */
/* Work around a bug in Sun C++: it does not support _Restrict or
   __restrict__, even though the corresponding Sun C compiler ends up with
   "#define restrict _Restrict" or "#define restrict __restrict__" in the
   previous line.  Perhaps some future version of Sun C++ will work with
   restrict; if so, hopefully it defines __RESTRICT like Sun C does.  */
#if defined __SUNPRO_CC && !defined __RESTRICT
# define _Restrict
# define __restrict__
#endif

/* Define to "int" if <sys/socket.h> does not define. */
/* #undef socklen_t */

#define LLVM_VERSION 28

/* YARA */
#define HAVE_YARA 1

#include "platform.h"

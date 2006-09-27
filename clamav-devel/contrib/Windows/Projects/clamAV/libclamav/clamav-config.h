/* clamav-config.h.  Generated from clamav-config.h.in by configure.  */
/* clamav-config.h.in.  Generated from configure.in by autoheader.  */

/* enable bind8 compatibility */
/* #undef BIND_8_COMPAT */

/* Define if your snprintf is busted */
#define BROKEN_SNPRINTF	1	/* Use the one in snprintf.h */

/* "build clamd" */
#define BUILD_CLAMD 1

/* name of the clamav group */
#define CLAMAVGROUP "clamav"

/* name of the clamav user */
#define CLAMAVUSER "clamav"

/* enable clamuko */
/* #undef CLAMUKO */

/* enable debugging */
/* #undef CL_DEBUG */

/* enable experimental code */
/* #undef CL_EXPERIMENTAL 1 /*

/* thread safe */
#define CL_THREAD_SAFE 1

/* where to look for the config file */
/* Note: on Windows, the installer can change this! */
#define	CONFDIR	"C:\\Program Files\\clamAV\\conf"

/* os is aix */
/* #undef C_AIX */

/* os is beos */
/* #undef C_BEOS */

/* Increase thread stack size. */
/* #undef C_BIGSTACK */

/* os is bsd flavor */
/* #undef C_BSD */

/* os is cygwin */
/* #undef C_CYGWIN 1 */

/* os is darwin */
/* #undef C_DARWIN */

/* os is hpux */
/* #undef C_HPUX */

/* os is interix */
/* #undef C_INTERIX */

/* os is irix */
/* #undef C_IRIX */

/* target is linux */
/* #undef C_LINUX */

/* os is OS/2 */
/* #undef C_OS2 */

/* os is QNX 6.x.x */
/* #undef C_QNX6 */

/* os is solaris */
/* #undef C_SOLARIS */

/* os is windows */
#ifdef	_MSC_VER
#define	C_WINDOWS	1
#endif

/* Path to virus database directory. */
/* Note: on Windows, the installer can change this! */
#define	DATADIR	"C:\\Program Files\\clamAV\\data"

/* Name of the main database */
#define DB1NAME "main.cvd"

/* Name of the daily database */
#define DB2NAME "daily.cvd"

/* "default FD_SETSIZE value" */
#define DEFAULT_FD_SETSIZE 64

/* file i/o buffer size */
#define FILEBUFF 8192

/* enable workaround for broken DNS servers */
/* #undef FRESHCLAM_DNS_FIX */

/* use "Cache-Control: no-cache" in freshclam */
/* #undef FRESHCLAM_NO_CACHE */

/* access rights in msghdr */
/* #undef HAVE_ACCRIGHTS_IN_MSGHDR */

/* attrib aligned */
#define HAVE_ATTRIB_ALIGNED 1

/* attrib packed */
/* #define HAVE_ATTRIB_PACKED 1 */

/* have bzip2 */
/* #define HAVE_BZLIB_H 1 */

/* ancillary data style fd pass */
#define HAVE_CONTROL_IN_MSGHDR 1

#define	NO_STRTOK_R

/* Define to 1 if you have the `ctime_r' function. */
#define HAVE_CTIME_R 1

/* ctime_r takes 2 arguments */
#define HAVE_CTIME_R_2 1

/* ctime_r takes 3 arguments */
/* #undef HAVE_CTIME_R_3 */

/* Define to 1 if you have the <dlfcn.h> header file. */
#define HAVE_DLFCN_H 1

/* Define to 1 if fseeko (and presumably ftello) exists and is declared. */
/* #define HAVE_FSEEKO 1 */

/* gethostbyname_r takes 3 arguments */
/* #undef HAVE_GETHOSTBYNAME_R_3 */

/* gethostbyname_r takes 5 arguments */
/* #undef HAVE_GETHOSTBYNAME_R_5 */

/* gethostbyname_r takes 6 arguments */
/* #undef HAVE_GETHOSTBYNAME_R_6 */

/* Define to 1 if you have the `getpagesize' function. */
/* #define HAVE_GETPAGESIZE 1 */

/* have gmp installed */
/* #define HAVE_GMP 1 */

/* hardware acceleration */
/* #undef HAVE_HWACCEL */

/* Define to 1 if you have the `inet_ntop' function. */
#define HAVE_INET_NTOP 1

/* Define to 1 if you have the `initgroups' function. */
/* #define HAVE_INITGROUPS 1 */

/* Define to 1 if you have the <inttypes.h> header file. */
/* #define HAVE_INTTYPES_H 1 */

/* in_addr_t is defined */
#define HAVE_IN_ADDR_T 1

/* in_port_t is defined */
#define HAVE_IN_PORT_T 1

/* Define to 1 if you have the <libmilter/mfapi.h> header file. */
/* #undef HAVE_LIBMILTER_MFAPI_H */

/* Define to 1 if you have the <limits.h> header file. */
#define HAVE_LIMITS_H 1

/* Define to 1 if you have the <malloc.h> header file. */
#define HAVE_MALLOC_H 1

/* Define to 1 if you have the `memcpy' function. */
#define HAVE_MEMCPY 1

/* Define to 1 if you have the <memory.h> header file. */
#define HAVE_MEMORY_H 1

/* Define to 1 if you have a working `mmap' system call. */
#define	HAVE_MMAP	1

/* Define to 1 if you have the <ndir.h> header file. */
/* #undef HAVE_NDIR_H */

/* Define to 1 if you have the `poll' function. */
/* #define HAVE_POLL 1 */

/* Define to 1 if you have the <poll.h> header file. */
/* #define HAVE_POLL_H 1 */

/* "pragma pack" */
#define	HAVE_PRAGMA_PACK	1

/* readdir_r takes 2 arguments */
/* #undef HAVE_READDIR_R_2 1

/* readdir_r takes 3 arguments */
#define HAVE_READDIR_R_3 1

/* Define to 1 if you have the `recvmsg' function. */
#define HAVE_RECVMSG 1

/* Define to 1 if you have the <regex.h> header file. */
#define HAVE_REGEX_H 1

/* have resolv.h */
/* #undef HAVE_RESOLV_H */

/* Define to 1 if you have the `sendmsg' function. */
#define HAVE_SENDMSG 1

/* Define to 1 if you have the `setgroups' function. */
/* #define HAVE_SETGROUPS 1 */

/* Define to 1 if you have the `setsid' function. */
/* #define HAVE_SETSID 1 */

/* Define to 1 if you have the `snprintf' function. */
#define HAVE_SNPRINTF 1

/* Define to 1 if you have the <stdint.h> header file. */
/* #define HAVE_STDINT_H 1 */

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define to 1 if you have the `strerror_r' function. */
/* #define HAVE_STRERROR_R 1 */

/* Define to 1 if you have the <strings.h> header file. */
/* #define HAVE_STRINGS_H 1 */

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define to 1 if you have the `strlcat' function. */
#define HAVE_STRLCAT 1

/* Define to 1 if you have the `strlcpy' function. */
#define HAVE_STRLCPY 1

/* Define to 1 if you have the <sys/filio.h> header file. */
/* #undef HAVE_SYS_FILIO_H */

/* Define to 1 if you have the <sys/inttypes.h> header file. */
/* #undef HAVE_SYS_INTTYPES_H */

/* Define to 1 if you have the <sys/int_types.h> header file. */
/* #undef HAVE_SYS_INT_TYPES_H */

/* Define to 1 if you have the <sys/mman.h> header file. */
/*#define HAVE_SYS_MMAN_H 1*/

/* Define to 1 if you have the <sys/param.h> header file. */
/* #undef HAVE_SYS_PARAM_H */

/* "have <sys/select.h>" */
/* #undef HAVE_SYS_SELECT_H */

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* Define to 1 if you have the <sys/uio.h> header file. */
/* #define HAVE_SYS_UIO_H 1 */

/* Define to 1 if you have the <tcpd.h> header file. */
/* #undef HAVE_TCPD_H */

/* Define to 1 if you have the <termios.h> header file. */
/* #define HAVE_TERMIOS_H 1 */

/* Define to 1 if you have the <unistd.h> header file. */
/* #define HAVE_UNISTD_H 1 */

/* Define to 1 if you have the `vsnprintf' function. */
/* #define HAVE_VSNPRINTF 1 */

/* zlib installed */
#define HAVE_ZLIB_H 1

/* Early Linux doesn't set cmsg fields */
/* #undef INCOMPLETE_CMSG */

/* bzip funtions do not have bz2 prefix */
/* #undef NOBZ2PREFIX */

/* "no fd_set" */
/* #undef NO_FD_SET */

/* Name of package */
#define PACKAGE "clamav"

/* Define to the address where bug reports for this package should be sent. */
#define PACKAGE_BUGREPORT "bugs@clamav.net"

/* Define to the full name of this package. */
#define PACKAGE_NAME ""

/* Define to the full name and version of this package. */
#define PACKAGE_STRING ""

/* Define to the one symbol short name of this package. */
#define PACKAGE_TARNAME ""

/* Define to the version of this package. */
#define PACKAGE_VERSION ""

/* scan buffer size */
#define SCANBUFF 131072

/* location of Sendmail binary */
/* #undef SENDMAIL_BIN */

/* major version of Sendmail */
/* #undef SENDMAIL_VERSION_A */

/* minor version of Sendmail */
/* #undef SENDMAIL_VERSION_B */

/* subversion of Sendmail */
/* #undef SENDMAIL_VERSION_C */

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

/* Define to 1 if you have the ANSI C header files. */
#define STDC_HEADERS 1

/* use syslog */
/* #define USE_SYSLOG 1 */

/* Version number of package */
#define VERSION "devel-20060927"

/* use libcurl in mbox code */
/* #define WITH_CURL 1 */

/* tcpwrappers support */
/* #undef WITH_TCPWRAP */

/* endianess */
#define WORDS_BIGENDIAN 0

/* Define to 1 to make fseeko visible on some hosts (e.g. glibc 2.2). */
/* #undef _LARGEFILE_SOURCE */

/* thread safe */
#define _REENTRANT 1

/* Define to empty if `const' does not conform to ANSI C. */
/* #undef const */

/* Define to `__inline__' or `__inline' if that's what the C compiler
   calls it, or to nothing if 'inline' is not supported under any name.  */
#ifndef __cplusplus
/* #undef inline */
#endif

/* Define to `long int' if <sys/types.h> does not define. */
/* #undef off_t */

/* Define to "int" if <sys/socket.h> does not define. */
typedef	int	socklen_t;

#ifdef	C_WINDOWS
#include "compat.h"
#endif

/*
 * CMake file to generate config.h
 */

 /* Turn debugging mode on? */
#cmakedefine DEBUG @ENABLE_DEBUG@

/* Define to 1 if you have the <dlfcn.h> header file. */
#cmakedefine HAVE_DLFCN_H 1

/* Define to 1 if you have the <inttypes.h> header file. */
#cmakedefine HAVE_INTTYPES_H 1

/* Define to 1 if you have the <stdint.h> header file. */
#cmakedefine HAVE_STDINT_H 1

/* Define to 1 if you have the <limits.h> header file. */
#cmakedefine HAVE_LIMITS_H 1

/* Define to 1 if you have the <ctype.h> header file. */
#cmakedefine HAVE_CTYPE_H 1

/* Define to 1 if you have the <wctype.h> header file. */
#cmakedefine HAVE_WCTYPE_H 1

/* Define to 1 if you have the <errno.h> header file. */
#cmakedefine HAVE_ERRNO_H 1

/* Define to 1 if you have the <sys/types.h> header file. */
#cmakedefine HAVE_SYS_TYPES_H 1

/* Define to 1 if you have the <sys/stat.h> header file. */
#cmakedefine HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <fnmatch.h> header file. */
#cmakedefine HAVE_FNMATCH_H 1

/* Define to 1 if you have the <iconv.h> header file. */
#cmakedefine HAVE_ICONV_H 1

/* Define to 1 if you have the <locale.h> header file. */
#cmakedefine HAVE_LOCALE_H 1

/* Define to 1 if you have the <stdarg.h> header file. */
#cmakedefine HAVE_STDARG_H 1

/* Define to 1 if you have the <stdlib.h> header file. */
#cmakedefine HAVE_STDLIB_H 1

/* Define to 1 if you have the <string.h> header file. */
#cmakedefine HAVE_STRING_H 1

/* Define to 1 if you have the <strings.h> header file. */
#cmakedefine HAVE_STRINGS_H 1

/* Define to 1 if you have the <sys/time.h> header file. */
#cmakedefine HAVE_SYS_TIME_H 1

/* Define to 1 if you have the <dirent.h> header file. */
#cmakedefine HAVE_DIRENT_H 1

/* Define to 1 if you have the <unistd.h> header file. */
#cmakedefine HAVE_UNISTD_H 1

/* Define to 1 if you have the ANSI C header files. */
#cmakedefine STDC_HEADERS 1

/* Define to 1 if you have the `fseeko' function. */
#cmakedefine HAVE_FSEEKO 1

/* Define to 1 if you have the `mkdir' function. */
#cmakedefine HAVE_MKDIR 1

/* Define to 1 if you have the `_mkdir' function. */
#cmakedefine HAVE__MKDIR 1

/* Define to 1 if you have the `tolower' function. */
#cmakedefine HAVE_TOWLOWER 1


/* Define to empty if `const' does not conform to ANSI C. */
#cmakedefine ICONV_CONST "@ICONV_CONST@"


/* The size of `off_t', as computed by sizeof. */
#cmakedefine SIZEOF_OFF_T @SIZEOF_OFF_T@

/* The size of `size_t', as computed by sizeof. */
#cmakedefine SIZEOF_SIZE_T @SIZEOF_SIZE_T@

/* The size of `ssize_t', as computed by sizeof. */
#cmakedefine SIZEOF_SSIZE_T @SIZEOF_SSIZE_T@

/* The size of `mode_t', as computed by sizeof. */
#cmakedefine SIZEOF_MODE_T @SIZEOF_MODE_T@


/* Define if mkdir takes only one argument. */
#cmakedefine MKDIR_TAKES_ONE_ARG 1


/* Define to `long int' if <sys/types.h> does not define. */
@OFF_T_DEF@

/* Define to `unsigned int' if <sys/types.h> does not define. */
@SIZE_T_DEF@

/* Define to `int' if <sys/types.h> does not define. */
@SSIZE_T_DEF@

/* Define to `int' if <sys/types.h> does not define. */
@MODE_T_DEF@


/* Define to 1 if you can safely include both <sys/time.h> and <time.h>. */
#ifdef __GNUC__
# define TIME_WITH_SYS_TIME 1
#else
# define TIME_WITH_SYS_TIME 0
#endif

#ifdef __AMIGA__
# define LATIN1_FILENAMES 1
#endif

/* Define WORDS_BIGENDIAN to 1 if your processor stores words with the most
   significant byte first (like Motorola and SPARC, unlike Intel). */
#cmakedefine  WORDS_BIGENDIAN 1

/* Number of bits in a file offset, on hosts where this is settable. */
#cmakedefine  _FILE_OFFSET_BITS @_FILE_OFFSET_BITS@

/* Define to 1 to make fseeko visible on some hosts (e.g. glibc 2.2). */
#cmakedefine  _LARGEFILE_SOURCE 1

/* Define for large files, on AIX-style hosts. */
#cmakedefine  _LARGE_FILES 1

/* Define to `__inline__' or `__inline' if that's what the C compiler
   calls it, or to nothing if 'inline' is not supported under any name.  */
#ifndef __cplusplus
#define inline @INLINE_KEYWORD@
#endif

/* Version number of package */
#cmakedefine VERSION "@VERSION@"

#ifdef _MSC_VER
//not #if defined(_WIN32) || defined(_WIN64) because mingw has strncasecmp
#define strncasecmp _strnicmp
#define strcasecmp _stricmp
#endif

/*
 * Author: 
 *      Guido Draheim <guidod@gmx.de>
 *
 *      Copyright (c) 2001,2002,2003 Guido Draheim
 *          All rights reserved,
 *          use under the restrictions of the
 *          Lesser GNU General Public License
 */

#ifndef _ZZIP_CONF_H
#define _ZZIP_CONF_H 1

#if !defined ZZIP_OMIT_CONFIG_H
# if defined _MSC_VER || defined __BORLANDC__ || defined __WATCOMC__
# include <zzip-msvc.h>
# elif defined ZZIP_1_H
# include "zzip-1.h"
# elif defined ZZIP_2_H
# include "zzip-2.h"
# elif defined ZZIP_3_H
# include "zzip-3.h"
# elif defined ZZIP_4_H
# include "zzip-4.h"
# elif defined ZZIP_5_H
# include "zzip-5.h"
# else /* autoconf generated */
# include <zzip-config.h>
# endif
#endif

/* especially win32 platforms do not declare off_t so far - see zzip-msvc.h */
#ifndef _zzip_off_t
#ifdef   ZZIP_off_t
#define _zzip_off_t ZZIP_off_t
#else
#define _zzip_off_t off_t
#endif
#endif

/* currently unused, all current zziplib-users do have ansi-C94 compilers. */
#ifndef _zzip_const
#ifdef   ZZIP_const
#define _zzip_const ZZIP_const
#else
#define _zzip_const const
#endif
#endif
#ifndef _zzip_inline
#ifdef   ZZIP_inline
#define _zzip_inline ZZIP_inline
#else
#define _zzip_inline inline
#endif
#endif
#ifndef _zzip_size_t
#ifdef   ZZIP_size_t
#define _zzip_size_t ZZIP_size_t
#else
#define _zzip_size_t size_t
#endif
#endif
#ifndef _zzip_ssize_t
#ifdef   ZZIP_ssize_t
#define _zzip_ssize_t ZZIP_ssize_t
#else
#define _zzip_ssize_t ssize_t
#endif
#endif

/* whether this library shall use a 64bit off_t largefile variant in 64on32: */
/* (some exported names must be renamed to avoid bad calls after linking) */
#if defined ZZIP_LARGEFILE_SENSITIVE 
# if _FILE_OFFSET_BITS+0 == 64
# define  ZZIP_LARGEFILE_RENAME
# elif defined  _LARGE_FILES    /* used on older AIX to get at 64bit off_t */
# define  ZZIP_LARGEFILE_RENAME
# elif defined  _ZZIP_LARGEFILE /* or simply use this one for zzip64 runs */
# define  ZZIP_LARGEFILE_RENAME
# endif
#endif

/* if the environment did not setup these for 64bit off_t largefile... */
#ifdef   ZZIP_LARGEFILE_RENAME
# ifndef      _FILE_OFFSET_BITS
#  ifdef ZZIP__FILE_OFFSET_BITS /* == 64 */
#  define     _FILE_OFFSET_BITS ZZIP__FILE_OFFSET_BITS
#  endif
# endif
# ifndef      _LARGE_FILES
#  ifdef ZZIP__LARGE_FILES /* == 1 */
#  define     _LARGE_FILES ZZIP__LARGE_FILES
#  endif
# endif
# ifndef      _LARGEFILE_SOURCE
#  ifdef ZZIP__LARGEFILE_SOURCE /* == 1 */
#  define     _LARGEFILE_SOURCE ZZIP__LARGEFILE_SOURCE
#  endif
# endif
#endif

#include <errno.h>

/* mingw32msvc errno : would be in winsock.h */
#ifndef EREMOTE
#define EREMOTE ESPIPE
#endif

#ifndef ELOOP
#if   defined EILSEQ
#define ELOOP EILSEQ
#else
#define ELOOP ENOEXEC
#endif
#endif

#if defined __WATCOMC__
#undef  _zzip_inline
#define _zzip_inline static
#endif

#if defined _MSC_VER || defined __WATCOMC__
#include <io.h>
#endif

#ifdef _MSC_VER
# if !__STDC__
#  ifndef _zzip_lseek
#  define _zzip_lseek _lseek
#  endif
#  ifndef _zzip_read
#  define _zzip_read _read
#  endif
/*
#  ifndef _zzip_stat
#  define _zzip_stat _stat
#  endif
*/
# endif /* !__STDC__ */
#endif
  /*MSVC*/

#if defined _MSC_VER || defined __WATCOMC__
#  ifndef strcasecmp
#  define strcasecmp _stricmp
#  endif
#endif

#  ifndef _zzip_lseek
#  define _zzip_lseek lseek
#  endif

#  ifndef _zzip_read
#  define _zzip_read  read
#  endif

/*
#  ifndef _zzip_stat
#  define _zzip_stat  stat
#  endif
*/


#if !defined __GNUC__ && !defined __attribute__
#define __attribute__(X) 
#endif

#if defined ZZIP_EXPORTS || defined ZZIPLIB_EXPORTS
# undef ZZIP_DLL
#define ZZIP_DLL 1
#endif

/* based on zconf.h : */
/* compile with -DZZIP_DLL for Windows DLL support */
#if defined ZZIP_DLL
#  if defined _WINDOWS || defined WINDOWS || defined _WIN32
/*#  include <windows.h>*/
#  endif
#  if !defined _zzip_export && defined _MSC_VER && (defined WIN32 || defined _WIN32)
#    define _zzip_export __declspec(dllexport) /*WINAPI*/
#  endif
#  if !defined _zzip_export && defined __BORLANDC__
#    if __BORLANDC__ >= 0x0500 && defined WIN32
#    include <windows.h>
#    define _zzip_export __declspec(dllexport) /*WINAPI*/
#    else
#      if defined _Windows && defined __DLL__
#      define _zzip_export _export
#      endif
#    endif
#  endif
#  if !defined _zzip_export && defined __GNUC__
#    if defined __declspec
#      define _zzip_export extern __declspec(dllexport)
#    else
#      define _zzip_export extern
#    endif
#  endif
#  if !defined _zzip_export && defined __BEOS__
#    define _zzip_export extern __declspec(export)
#  endif
#  if !defined _zzip_export && defined __WATCOMC__
#    define _zzip_export extern __declspec(dllexport)
#    define ZEXPORT __syscall
#    define ZEXTERN extern
#  endif
#endif

#if !defined _zzip_export
#  if defined __GNUC__ /* || !defined HAVE_LIBZZIP */
#  define _zzip_export extern
#  elif defined __declspec || (defined _MSC_VER && defined ZZIP_DLL)
#  define _zzip_export extern __declspec(dllimport)
#  else
#  define _zzip_export extern
#  endif
#endif

#endif



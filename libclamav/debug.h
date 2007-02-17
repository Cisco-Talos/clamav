/*
 *  Copyright (C) 2006 Nigel Horne <njh@clamav.net>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA 02110-1301, USA.
 */
#if	!defined(_DEBUG_H) && !defined(NDEBUG)

#ifdef	CL_DEBUG

#define _DEBUG_H
/*
 * debug.h:
 *	Includes for Nigel Horne's debugging C runtime. All output is
 * via stderr.
 *	To use just link the required object file into your application.
 * For the best results you should include this file (debug.h) in each source
 * file and recompile
 *
 * Version 2.1.1
 *
 * DOS:
 *	Suitable for MSC8.00c (a.k.a. MSVC 1.5)
 * usage: cl /AS test.c dosdbgs.obj /link /noe
 *
 * SCO Unix:
 * Contains debug.o which you should link with your application,
 * and debug.h which you can optionally include in each .c file. This would be
 * the best action as then debug.o will be better at finding which file has
 * gone wrong. The included test.c shows some common problems. To test all
 * is well I suggest you try "cc test.c debug.o -link -z" and see look at the
 * output. Do not link with the shared library "-lc_s" option, as this will
 * cause conflicts with the library.
 *
 * HP\UX:
 * As SCO Unix.
 *
 * AIX 4.1.5
 *	You do not want builtins. Use
 *	cc -DANSI -DAIX -O2 -qroconst -U__STR__ -qro *.c
 *
 * With cc on SunOs
 *	cc -Dsun -O4 -pipe *.c
 *
 * With cc on Solaris
 *	cc -DANSI -Dsolaris -fast -xO4 -fd -mc -v -Xc -xCC -xstrconst *.c
 *
 * Internet: njh@smsltd.demon.co.uk; Fidonet: Nigel Horne @ 2:253/417.49;
 * Packet: G0LOV@GB7SYP.#19.GBR.EDU; Phone: +44-1226-283021.
 */
#if	defined(__STDC__) || defined(_MSC_VER)
#ifndef	ANSI
#define	ANSI
#endif
#else
#define	const
#endif

#include <stdio.h>
/*#include <assert.h>*/
#include <malloc.h>
#include <memory.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#ifndef	SIGINT
#include <signal.h>
#endif

#ifdef	MSDOS
#include <conio.h>
#else
#include <sys/param.h>
#endif

#ifdef	PERPOS
#include <values.h>
#else
#include <limits.h>
#include <stdlib.h>
#endif

#ifdef	LINUX
#include <sys/types.h>
#endif

#ifdef sun
#include <alloca.h>
#ifdef	__STDC__
#include <stdarg.h>
#else
#include <varargs.h>
#endif
#include <unistd.h>

#ifdef	solaris
#include	<sys/sysmacros.h>
#endif

#else	/*!sun*/

#if	defined(PERPOS) || defined(_HPUX_SOURCE)
#include <varargs.h>
#else
#include <stdarg.h>
#endif
#endif

#if	defined(M_I386) || defined(MSDOS)
#pragma function(memset, memcpy, memcmp, strcmp, strcpy, strcat)
#endif

#if	(defined(unix) || defined(sun) || defined(_HPUX_SOURCE)) && !defined(UNIX)
#define	UNIX
#endif

#ifdef	C_LINUX	/* Others??? */
#include <stdbool.h>
#else
#ifdef	FALSE
typedef	unsigned	char	bool;
#else
typedef enum	{ FALSE = 0, TRUE = 1 } bool;
#endif
#endif

#ifdef	alloca
#undef	alloca
#endif

#ifdef	strdup
#undef	strdup
#endif

#ifdef	memcpy
#undef	memcpy
#endif

#define	memcpy(m1, m2, n)	db_memcpy(m1, m2, n, __FILE__, __LINE__)
#define malloc(s)	db_mallocchk(s, __FILE__, __LINE__)
#define calloc(n, s)	db_callocchk(n, s, __FILE__, __LINE__)
#define realloc(o, s)	db_reallocchk(o, s, __FILE__, __LINE__)
#define strdup(s)	db_strdupchk(s, __FILE__, __LINE__)
#define free(s)		db_freechk(s, __FILE__, __LINE__)
#define	alloca(s)	db_alloca(s, __FILE__, __LINE__)
#define heapchk()	db_heapchk(__FILE__, __LINE__)

/*#ifdef	__GNUC__
#define pascal		__attribute__ ((stdcall))
#define _pascal		__attribute__ ((stdcall))
#define	cdecl		__attribute__ ((cdecl))
#define _cdecl		__attribute__ ((cdecl))
#endif*/

#if	defined(_unix) && !defined(unix)
#define unix
#endif

#ifndef	MSDOS
#define	far
#endif

/*#if	!defined(MSDOS) && !defined(M_XENIX) && !defined(__GNUC__)*/
#define _cdecl
#define cdecl
#define _pascal
#define pascal
/*#endif*/

#ifndef	ANSI
void	*_pascal	db_memcpy();
void	*_pascal	db_mallocchk();
void	*_pascal	db_callocchk();
void	*_pascal	db_reallocchk();
char	*_pascal	db_strdupchk();
void	*_pascal	db_alloca();
void	_pascal db_freechk();
void	_pascal db_heapchk();
void	db_setname();
#else
void	*_pascal	db_memcpy(void *m1, const void *m2, size_t n, const char *file, int line);
void	*_pascal	db_mallocchk(size_t size, const char *file, int line);
void	*_pascal	db_callocchk(size_t nelem, size_t size, const char
*file, int line);
void	*_pascal	db_reallocchk(void *oarea, size_t size, const char
*file, int line);
char	*_pascal	db_strdupchk(const char *string, const char *file,
int line);
void	*_pascal	db_alloca(size_t size, const char *file, int line);
void	_pascal		db_freechk(void *memblock, const char *file, int line);
void	_pascal		db_heapchk(const char *file, int line);
void	db_setname(const char *progname);
#endif

extern	bool	check_for_leaks;	/*
					 * check for memory leaks - default
true
					 */

#endif	/* CL_DEBUG */
#endif /* _DEBUG_H */

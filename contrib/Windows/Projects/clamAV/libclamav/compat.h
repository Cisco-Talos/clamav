/*
 *  Copyright (C) 2006 Nigel Horne <njh@bandsman.co.uk>
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
 *
 * Unix/Linux compatibility for Windows
 * Inspired by glib and the cygwin source code
 * Tested under Microsoft Visual Studio 2005
 */
#ifndef	CLAMAV_COMPAT_H

#define	CLAMAV_COMPAT_H

#ifdef	C_WINDOWS

#pragma warning(disable: 4996)	/* turn off warnings about depracated code */

#ifndef	_USE_32BIT_TIME_T
#define	_USE_32BIT_TIME_T
#endif

/*#include	"snprintf.h"*/

#define	inline	/* it's too different in MSVC to bother */

typedef	int	ssize_t;
typedef	int	mode_t;
typedef	char *	caddr_t;
typedef	long	off_t;

#define	X_OK	0
#define	W_OK	2
#define	R_OK	4

#define	PROT_READ	1
#define	MAP_PRIVATE	1
#define	MAP_FAILED	(caddr_t)-1

caddr_t	mmap(caddr_t address, size_t length, int protection, int flags, int fd, off_t offset);
int	munmap(caddr_t addr, size_t length);

#define	strcasecmp(s1, s2)	_stricmp(s1, s2)
#define	strncasecmp(s1, s2, n)	_strnicmp(s1, s2, n)

#define	chdir(d)	_chdir(d)
#define	umask(n)	_umask(n)

#ifndef	S_IRWXU
#define	S_IRWXU	(_S_IREAD|_S_IWRITE|_S_IEXEC)
#endif

#define S_IWUSR	S_IWRITE
#define	S_IRUSR	S_IREAD
#define	S_ISLNK(f)	0
#define S_ISDIR(f)	(((f)&S_IFMT) == S_IFDIR)
#define S_ISREG(f)	(((f)&S_IFMT) == S_IFREG)

#define	fsync(fd)	_commit(fd)
#define	lstat(file, buf)	stat(file, buf)

#define	_CRT_SECURE_NO_DEPRECATE	1

#ifndef _WINSOCKAPI_	/* timeval is in winsock.h */
struct timeval {
	long	tv_sec;
	long	tv_usec;
};
#endif	/* _WINSOCKAPI_ */

/* Maximum filenames under various systems - njh */
#ifndef	NAME_MAX	/* e.g. Linux */
# ifdef	MAXNAMELEN	/* e.g. Solaris */
#   define	NAME_MAX	MAXNAMELEN
# else
#   ifdef	FILENAME_MAX	/* e.g. SCO */
#     define	NAME_MAX	FILENAME_MAX
#   else
#     define	NAME_MAX	256
#   endif
# endif
#endif

struct DIR {
	char    *dir_name;
	int	just_opened;
	void	*find_file_handle;
	void	*find_file_data;	/* LPWIN32_FIND_DATA */
};
typedef struct	DIR	DIR;
struct	dirent {
	char  d_name[NAME_MAX + 1];
};

DIR	*opendir(const char *dirname);
struct	dirent	*readdir(DIR *dir);
int	readdir_r(DIR *dir, struct dirent *dirent, struct dirent **output);
void	rewinddir(DIR *dir);
int	closedir(DIR *dir);
int	gettimeofday(struct timeval* tp, void* tz);

#define	alarm(seconds)
#define	sleep(seconds)	Sleep(seconds * 1000)
#define	pause();

#ifdef	_DEBUG

/* http://msdn2.microsoft.com/en-us/library/e5ewb1h3(VS.80).asp */
#define _CRTDBG_MAP_ALLOC
#include <stdlib.h>
#include <crtdbg.h>

/* breaks mspack/qtmd.c :-( */
/* #define	free(p)	{ _free_dbg(p, _NORMAL_BLOCK); } */

#endif

#endif	/* C_WINDOWS */

#endif	/* CLAMAV_COMPAT_H */

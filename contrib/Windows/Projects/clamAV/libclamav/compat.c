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
#include <windows.h>

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <errno.h>
#include <string.h>

#include "clamav.h"
#include "others.h"

#ifndef	CL_DEBUG
#define	NDEBUG	/* map CLAMAV debug onto standard */
#endif

#include <stdlib.h>
#include <direct.h>
#include <io.h>
#include <pthread.h>

#ifdef	USE_SYSLOG
#include "syslog.h"
#endif

static const char *basename (const char *file_name);

/* Offset between 1/1/1601 and 1/1/1970 in 100 nanosec units */
#define _W32_FT_OFFSET (116444736000000000ULL)

/*
 * Patches for 64 bit support in opendir by
 *	Mark Pizzolato clamav-win32@subscriptions.pizzolato.net
 */
DIR *
opendir(const char *dirname)
{
	DIR *ret = cli_calloc(1, sizeof(DIR));
	char mask[_MAX_PATH + 3];
	size_t i, j;

	if(ret == NULL)
		return NULL;

	/* struct _WIN32_FIND_DATAA is what a LPWIN32_FIND_DATA points to */
	ret->find_file_data = cli_calloc(1, sizeof(struct _WIN32_FIND_DATAA));

	if(ret->find_file_data == NULL) {
		free(ret);
		return NULL;
	}
	ret->dir_name = cli_strdup(dirname);

	if(ret->dir_name == NULL) {
		free(ret->find_file_data);
		free(ret);
		return NULL;
	}

	j = strlen(dirname);
	for(i = 0; i < j; i++)
		if(ret->dir_name[i] == '/')
			ret->dir_name[i] = '\\';

	if(j && dirname[j - 1] == '\\')
		ret->dir_name[--j] = '\0';

	sprintf(mask, "%s\\*", ret->dir_name);

	ret->find_file_handle = FindFirstFile(mask,
				    (LPWIN32_FIND_DATA)ret->find_file_data);

	if(ret->find_file_handle == INVALID_HANDLE_VALUE) {
		free(ret->find_file_data);
		free(ret->dir_name);
		free(ret);

		cli_warnmsg("Can't opendir(%s)\n", dirname);
		return NULL;
	}

	ret->just_opened = TRUE;

	return ret;
}

struct dirent *
readdir(DIR *dir)
{
	/* NOTE: not thread safe */
	static struct dirent result;

	if(dir == NULL)
		return NULL;

	if(dir->just_opened)
		dir->just_opened = FALSE;
	else if(!FindNextFile((HANDLE)dir->find_file_handle, (LPWIN32_FIND_DATA)dir->find_file_data))
		switch(GetLastError ()) {
			case ERROR_NO_MORE_FILES:
				return NULL;
			default:
				errno = EIO;
				return NULL;
		}

	strcpy(result.d_name, basename(((LPWIN32_FIND_DATA)dir->find_file_data)->cFileName));

	return &result;
}

int
readdir_r(DIR *dir, struct dirent *dirent, struct dirent **output)
{
	if(dir == NULL)
		return -1;
	if(dirent == NULL)
		return -1;
	if(output == NULL)
		return -1;

	if(dir->just_opened)
		dir->just_opened = FALSE;
	else if(!FindNextFile((HANDLE)dir->find_file_handle, (LPWIN32_FIND_DATA)dir->find_file_data))
		switch(GetLastError()) {
			case ERROR_NO_MORE_FILES:
				*output = NULL;
				return -1;
			default:
				errno = EIO;
				*output = NULL;
				return -1;
		}

	strcpy(dirent->d_name, basename(((LPWIN32_FIND_DATA)dir->find_file_data)->cFileName));
	*output = dirent;

	return 0;
}

void
rewinddir(DIR *dir)
{
	char mask[_MAX_PATH + 3];

	if(dir == NULL)
		return;

	if(!FindClose((HANDLE)dir->find_file_handle))
		cli_warnmsg("rewinddir(): FindClose() failed\n");

	sprintf(mask, "%s\\*", dir->dir_name);

	dir->find_file_handle = FindFirstFile (mask,
					(LPWIN32_FIND_DATA)dir->find_file_data);

	if(dir->find_file_handle == INVALID_HANDLE_VALUE) {
		errno = EIO;
		return;
	}
	dir->just_opened = TRUE;
}

int
closedir(DIR *dir)
{
	if(dir == NULL)
		return -1;

	if(!FindClose((HANDLE)dir->find_file_handle)) {
		errno = EIO;
		return -1;
	}

	free(dir->dir_name);
	free(dir->find_file_data);
	free(dir);

	return 0;
}

static const char *
basename(const char *file_name)
{
	const char *base;

	if(file_name == NULL)
		return NULL;

	base = strrchr(file_name, '\\');

	if(base)
		return base + 1;

	if(isalpha(file_name[0] & 0xFF) && (file_name[1] == ':'))
		return (const char *)(file_name + 2);

	return file_name;
}

/* From the cygwin source code */
int
gettimeofday(struct timeval *tp, void *tz)
{
	if(tp) {
		union {
			unsigned long long ns100; /*time since 1 Jan 1601 in 100ns units */
			FILETIME ft;
		} _now;

		GetSystemTimeAsFileTime(&_now.ft);
		tp->tv_usec = (long)((_now.ns100 / 10ULL) % 1000000ULL );
		tp->tv_sec = (long)((_now.ns100 - _W32_FT_OFFSET) / 10000000ULL);
	}
	/*
	 * Always return 0 as per Open Group Base Specifications Issue 6.
	 * Do not set errno on error.
	 */
	return 0;
}

/* TODO */
int
geteuid(void)
{
	return 0;
}

int
getuid(void)
{
	return 0;
}

int
getgid(void)
{
	return 0;
}

/*
 * mmap patches for more than one map area by
 *	Mark Pizzolato clamav-win32@subscriptions.pizzolato.net
 */
static pthread_mutex_t mmap_mutex = PTHREAD_MUTEX_INITIALIZER;

static struct mmap_context {
	struct mmap_context *link;
	HANDLE h;
	LPVOID view;
	size_t length;
} *mmaps = NULL;

caddr_t
mmap(caddr_t address, size_t length, int protection, int flags, int fd, off_t offset)
{
	LPVOID addr;
	HANDLE h;
	struct mmap_context *ctx;

	if(flags != MAP_PRIVATE) {
		cli_errmsg("mmap: only MAP_SHARED is supported\n");
		return MAP_FAILED;
	}
	if(protection != PROT_READ) {
		cli_errmsg("mmap: only PROT_READ is supported\n");
		return MAP_FAILED;
	}
	if(address != NULL) {
		cli_errmsg("mmap: only NULL map address is supported\n");
		return MAP_FAILED;
	}
	h = CreateFileMapping((HANDLE)_get_osfhandle(fd), NULL, PAGE_READONLY, 0, 0, NULL);

	if(h == NULL) {
		cli_errmsg("mmap: CreateFileMapping failed - error %d\n",
			GetLastError());
		return MAP_FAILED;
	}
	if(GetLastError() == ERROR_ALREADY_EXISTS) {
		cli_errmsg("mmap: ERROR_ALREADY_EXISTS\n");
		CloseHandle(h);
		return MAP_FAILED;
	}
	addr = MapViewOfFile(h, FILE_MAP_READ,
		(DWORD)0, ((DWORD)offset & 0xFFFFFFFF),
		length);

	if(addr == NULL) {
		cli_errmsg("mmap failed - error %d\n", GetLastError());
		CloseHandle(h);
		return MAP_FAILED;
	}
	pthread_mutex_lock(&mmap_mutex);
	ctx = cli_malloc(sizeof(*ctx));
	if(NULL == ctx) {
		pthread_mutex_unlock(&mmap_mutex);
		cli_errmsg("mmap: can't create context block\n");
		UnmapViewOfFile(addr);
		CloseHandle(h);
		return MAP_FAILED;
	}
	ctx->h = h;
	ctx->view = addr;
	ctx->length = length;
	ctx->link = mmaps;
	mmaps = ctx;
	pthread_mutex_unlock(&mmap_mutex);
	return (caddr_t)addr;
}

int
munmap(caddr_t addr, size_t length)
{
	struct mmap_context *ctx, *lctx = NULL;

	pthread_mutex_lock(&mmap_mutex);
	for(ctx = mmaps; ctx && (ctx->view != addr); ) {
		lctx = ctx;
		ctx = ctx->link;
	}
	if(ctx == NULL) {
		pthread_mutex_unlock(&mmap_mutex);
		cli_warnmsg("munmap with no corresponding mmap\n");
		return -1;
	}
	if(ctx->length != length) {
		pthread_mutex_unlock(&mmap_mutex);
		cli_warnmsg("munmap with incorrect length specified - partial munmap unsupported\n");
		return -1;
	}
	if(NULL == lctx)
		mmaps = ctx->link;
	else
		lctx->link = ctx->link;
	pthread_mutex_unlock(&mmap_mutex);

	UnmapViewOfFile(ctx->view);
	CloseHandle(ctx->h);
	free(ctx);

	return 0;
}

int
chown(const char *filename, short uid, short gid)
{
	return 0;
}

#ifdef	USE_SYSLOG
/*
 * Put into the Windows Event Log (Right Click My Computer->Manage->Event Viewer->Application
 * See http://cybertiggyr.com/gene/wel/src/insert-log.c for inspiration
 */
static	HANDLE	logg_handle;

void
openlog(const char *name, int options, int facility)
{
	logg_handle = RegisterEventSource(NULL, name);
}

void
closelog(void)
{
	if(logg_handle != NULL)
		CloseEventLog(logg_handle);
}

void
syslog(int level, const char *format, ...)
{
	if(logg_handle != NULL) {
		va_list args;
		char buff[512];

		va_start(args, format);
		(void)vsnprintf(buff, sizeof(buff), format, args);
		va_end(args);
		
		/*
		 * Category = 0, eventId = 0, SID = NULL, 1 string
		 */
		(void)ReportEvent(logg_handle, (WORD)level, 0, 0, NULL, 1, 0, (LPCSTR *)buff, NULL);
	}

}
#endif

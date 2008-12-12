/*
 *  Copyright (C) 2007-2008 Sourcefire, Inc.
 *
 *  Authors: Tomasz Kojm, Trog
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
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
 */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#ifdef	HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <sys/types.h>
#include <sys/stat.h>
#ifndef	C_WINDOWS
#include <sys/wait.h>
#include <sys/time.h>
#include <dirent.h>
#endif
#include <time.h>
#include <fcntl.h>
#ifndef	C_WINDOWS
#include <pwd.h>
#endif
#include <errno.h>
#include "target.h"
#ifndef	C_WINDOWS
#include <sys/time.h>
#endif
#ifdef	HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#ifdef	HAVE_MALLOC_H
#include <malloc.h>
#endif
#if	defined(_MSC_VER) && defined(_DEBUG)
#include <crtdbg.h>
#endif

#include "clamav.h"
#include "others.h"
#include "md5.h"
#include "cltypes.h"
#include "regex/regex.h"
#include "ltdl.h"
#include "matcher-ac.h"

#ifdef CL_THREAD_SAFE
#  include <pthread.h>

# ifndef HAVE_CTIME_R
static pthread_mutex_t cli_ctime_mutex = PTHREAD_MUTEX_INITIALIZER;
# endif

#endif
uint8_t cli_debug_flag = 0;

#define MSGCODE(x)					    \
	va_list args;					    \
	int len = sizeof(x) - 1;			    \
	char buff[BUFSIZ];				    \
    strncpy(buff, x, len);				    \
    buff[BUFSIZ-1]='\0';				    \
    va_start(args, str);				    \
    vsnprintf(buff + len, sizeof(buff) - len, str, args);   \
    buff[sizeof(buff) - 1] = '\0';			    \
    fputs(buff, stderr);				    \
    va_end(args)

void cli_warnmsg(const char *str, ...)
{
    MSGCODE("LibClamAV Warning: ");
}

void cli_errmsg(const char *str, ...)
{
    MSGCODE("LibClamAV Error: ");
}

void cli_dbgmsg_internal(const char *str, ...)
{
    MSGCODE("LibClamAV debug: ");
}

int cli_matchregex(const char *str, const char *regex)
{
	regex_t reg;
	int match;

    if(cli_regcomp(&reg, regex, REG_EXTENDED | REG_NOSUB) == 0) {
	match = (cli_regexec(&reg, str, 0, NULL, 0) == REG_NOMATCH) ? 0 : 1;
	cli_regfree(&reg);
	return match;
    }

    return 0;
}
void *cli_malloc(size_t size)
{
	void *alloc;


    if(!size || size > CLI_MAX_ALLOCATION) {
	cli_errmsg("cli_malloc(): Attempt to allocate %lu bytes. Please report to http://bugs.clamav.net\n", (unsigned long int) size);
	return NULL;
    }

#if defined(_MSC_VER) && defined(_DEBUG)
    alloc = _malloc_dbg(size, _NORMAL_BLOCK, __FILE__, __LINE__);
#else
    alloc = malloc(size);
#endif

    if(!alloc) {
	cli_errmsg("cli_malloc(): Can't allocate memory (%lu bytes).\n", (unsigned long int) size);
	perror("malloc_problem");
	return NULL;
    } else return alloc;
}

void *cli_calloc(size_t nmemb, size_t size)
{
	void *alloc;


    if(!size || size > CLI_MAX_ALLOCATION) {
	cli_errmsg("cli_calloc(): Attempt to allocate %lu bytes. Please report to http://bugs.clamav.net\n", (unsigned long int) size);
	return NULL;
    }

#if defined(_MSC_VER) && defined(_DEBUG)
    alloc = _calloc_dbg(nmemb, size, _NORMAL_BLOCK, __FILE__, __LINE__);
#else
    alloc = calloc(nmemb, size);
#endif

    if(!alloc) {
	cli_errmsg("cli_calloc(): Can't allocate memory (%lu bytes).\n", (unsigned long int) (nmemb * size));
	perror("calloc_problem");
	return NULL;
    } else return alloc;
}

void *cli_realloc(void *ptr, size_t size)
{
	void *alloc;


    if(!size || size > CLI_MAX_ALLOCATION) {
	cli_errmsg("cli_realloc(): Attempt to allocate %lu bytes. Please report to http://bugs.clamav.net\n", (unsigned long int) size);
	return NULL;
    }

    alloc = realloc(ptr, size);

    if(!alloc) {
	cli_errmsg("cli_realloc(): Can't re-allocate memory to %lu bytes.\n", (unsigned long int) size);
	perror("realloc_problem");
	return NULL;
    } else return alloc;
}

void *cli_realloc2(void *ptr, size_t size)
{
	void *alloc;


    if(!size || size > CLI_MAX_ALLOCATION) {
	cli_errmsg("cli_realloc2(): Attempt to allocate %lu bytes. Please report to http://bugs.clamav.net\n", (unsigned long int) size);
	return NULL;
    }

    alloc = realloc(ptr, size);

    if(!alloc) {
	cli_errmsg("cli_realloc2(): Can't re-allocate memory to %lu bytes.\n", (unsigned long int) size);
	perror("realloc_problem");
	if(ptr)
	    free(ptr);
	return NULL;
    } else return alloc;
}

char *cli_strdup(const char *s)
{
        char *alloc;


    if(s == NULL) {
        cli_errmsg("cli_strdup(): s == NULL. Please report to http://bugs.clamav.net\n");
        return NULL;
    }

#if defined(_MSC_VER) && defined(_DEBUG)
    alloc = _strdup_dbg(s, _NORMAL_BLOCK, __FILE__, __LINE__);
#else
    alloc = strdup(s);
#endif

    if(!alloc) {
        cli_errmsg("cli_strdup(): Can't allocate memory (%u bytes).\n", (unsigned int) strlen(s));
        perror("strdup_problem");
        return NULL;
    }

    return alloc;
}

/* returns converted timestamp, in case of error the returned string contains at least one character */
const char* cli_ctime(const time_t *timep, char *buf, const size_t bufsize)
{
	const char *ret;
	if(bufsize < 26) {
		/* standard says we must have at least 26 bytes buffer */
		cli_warnmsg("buffer too small for ctime\n");
		return " ";
	}
	if((uint32_t)(*timep) > 0x7fffffff) {
		/* some systems can consider these timestamps invalid */
		strncpy(buf, "invalid timestamp", bufsize-1);
		buf[bufsize-1] = '\0';
		return buf;
	}

#ifdef HAVE_CTIME_R	
# ifdef HAVE_CTIME_R_2
	ret = ctime_r(timep, buf);
# else
	ret = ctime_r(timep, buf, bufsize);
# endif
#else /* no ctime_r */

# ifdef CL_THREAD_SAFE
	pthread_mutex_lock(&cli_ctime_mutex);
# endif
	ret = ctime(timep);
	if(ret) {
		strncpy(buf, ret, bufsize-1);
		buf[bufsize-1] = '\0';
		ret = buf;
	}
# ifdef CL_THREAD_SAFE
	pthread_mutex_unlock(&cli_ctime_mutex);
# endif
#endif
	/* common */
	if(!ret) {
		buf[0] = ' ';
		buf[1] = '\0';
		return buf;
	}
	return ret;
}


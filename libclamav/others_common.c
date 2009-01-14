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

struct dirent_data {
    char *filename;
    struct stat *statbuf;
    int   is_dir;/* 0 - no, 1 - yes */
    long  ino; /* -1: inode not available */
};

/* sort files before directories, and lower inodes before higher inodes */
static int ftw_compare(const void *a, const void *b)
{
    const struct dirent_data *da = a;
    const struct dirent_data *db = b;
    long diff = da->is_dir - db->is_dir;
    if (!diff) {
	diff = da->ino - db->ino;
    }
    return diff;
}

#define FOLLOW_SYMLINK_MASK (CLI_FTW_FOLLOW_FILE_SYMLINK | CLI_FTW_FOLLOW_DIR_SYMLINK)
int cli_ftw(const char *dirname, int flags, int maxdepth, cli_ftw_cb callback, struct cli_ftw_cbdata *data)
{
    DIR *dd;
#if defined(HAVE_READDIR_R_3) || defined(HAVE_READDIR_R_2)
    union {
	struct dirent d;
	char b[offsetof(struct dirent, d_name) + NAME_MAX + 1];
    } result;
#endif
    struct dirent_data *entries = NULL;
    size_t i, entries_cnt = 0;
    int ret;

    if (maxdepth < 0) {
	/* exceeded recursion limit */
	ret = callback(NULL, (char*)dirname, warning_skipped_dir, data);
	return ret;
    }

    if((dd = opendir(dirname)) != NULL) {
	struct dirent *dent;
	errno = 0;
#ifdef HAVE_READDIR_R_3
	while(!readdir_r(dd, &result.d, &dent) && dent) {
#elif defined(HAVE_READDIR_R_2)
	while((dent = (struct dirent *) readdir_r(dd, &result.d))) {
#else
	while((dent = readdir(dd))) {
#endif
	    int is_dir, stated = 0;
	    char *fname;
	    struct stat statbuf;
	    struct stat *statbufp;

	    if(!strcmp(dent->d_name, ".") || !strcmp(dent->d_name, ".."))
		continue;
#ifdef _DIRENT_HAVE_D_TYPE
	    switch (dent->d_type) {
		case DT_DIR:
		    is_dir = 1;
		    break;
		case DT_LNK:
		    if (!(flags & FOLLOW_SYMLINK_MASK)) {
			/* we don't follow symlinks, don't bother
			 * stating it */
			errno = 0;
			continue;
		    }
		    is_dir = -2;
		    break;
		case DT_REG:
		    is_dir = 0;
		    break;
		case DT_UNKNOWN:
		    is_dir = -1;
		    break;
		default:
		    is_dir = -2;
		    break;
	    }
#else
	    is_dir = -1;
#endif
	    fname = (char *) cli_malloc(strlen(dirname) + strlen(dent->d_name) + 2);
	    if(!fname) {
		ret = callback(NULL, (char*)dirname, error_mem, data);
		if (ret != CL_SUCCESS)
		    break;
	    }
	    sprintf(fname, "%s/%s", dirname, dent->d_name);
	    /* TODO: make is_dir an enum, it is getting ugly with -1 and -2 */
	    if (is_dir == -1) {
		/* TODO: factor this out into another function */
		int check_symlink = 0;
		is_dir = -2; /* skip */
		if ((flags & FOLLOW_SYMLINK_MASK) == FOLLOW_SYMLINK_MASK) {
		    /* Following both directory and file symlink.
		     * No need to lstat the link */
		    if (stat(fname, &statbuf) == -1)
			stated = -1;
		    else
			stated = 1;
		} else 	{
		    /* Following only one of directory/file symlinks, or none:
		     * need to lstat */
		    if (lstat(fname, &statbuf) == -1)
			stated = -1;
		    else {
			stated = 1;
			if (S_ISLNK(statbuf.st_mode)) {
			    if (flags & FOLLOW_SYMLINK_MASK) {
				check_symlink = 1;
				if (stat(fname, &statbuf) == -1)
				    stated = -1;
				else
				    stated = 1;
			    }
			    /* default: skip */
			}
		    }
		}

		if (stated == 1) {
		    if (S_ISDIR(statbuf.st_mode) &&
			(!check_symlink || (flags & CLI_FTW_FOLLOW_DIR_SYMLINK))) {
			is_dir = 1;
		    } else if (S_ISREG(statbuf.st_mode) &&
			       (!check_symlink || (flags & CLI_FTW_FOLLOW_FILE_SYMLINK))) {
			is_dir = 0;
		    } else
			is_dir = -2; /* skip */
		}
	    }

	    if (!stated && (flags & CLI_FTW_NEED_STAT)) {
		if (stat(fname, &statbuf) == -1)
		    stated = -1;
		else
		    stated = 1;
	    }

	    if (is_dir == -2) {
		/* skipped filetype */
		ret = callback(stated ? &statbuf : NULL, fname, warning_skipped_special, data);
		if (ret != CL_SUCCESS)
		    break;
	    }

	    if (stated == -1) {
		/*  we failed a stat() or lstat() */
		ret = callback(NULL, fname, error_stat, data);
		if (ret != CL_SUCCESS)
		    break;
		is_dir = -2; /* skip on stat failure */
	    }

	    if (is_dir == -2) { /* skip */
		free(fname);
		errno = 0;
		continue;
	    }

	    if (stated && (flags & CLI_FTW_NEED_STAT)) {
		statbufp = cli_malloc(sizeof(*statbufp));
		if (!statbufp) {
		    ret = callback(stated ? &statbuf : NULL, fname, error_mem, data);
		    free(fname);
		    if (ret != CL_SUCCESS)
			break;
		    else {
			errno = 0;
			continue;
		    }
		}
	    } else {
		statbufp = 0;
	    }

	    entries_cnt++;
	    entries = cli_realloc(entries, entries_cnt*sizeof(*entries));
	    if (!entries) {
		ret = callback(stated ? &statbuf : NULL, fname, error_mem, data);
		free(fname);
		if (statbufp)
		    free(statbufp);
		break;
	    } else {
		struct dirent_data *entry = &entries[entries_cnt-1];
		entry->filename = fname;
		entry->statbuf = statbufp;
		entry->is_dir = is_dir;
#ifdef _XOPEN_UNIX
		entry->ino = dent->d_ino;
#else
		entry->ino = -1;
#endif
	    }
	    errno = 0;
	}
	closedir(dd);

	if (entries) {
	    qsort(entries, entries_cnt, sizeof(*entries), ftw_compare);
	    for (i = 0; i < entries_cnt; i++) {
		struct dirent_data *entry = &entries[i];
		ret = callback(entry->statbuf, entry->filename,
			       entry->is_dir ? visit_directory : visit_file,
			       data);
		if (ret != CL_SUCCESS)
		    break;
		if (entry->is_dir) {
		    ret = cli_ftw(entry->filename, flags, maxdepth-1, callback, data);
		    if (ret != CL_SUCCESS)
			break;
		}
	    }
	    free(entries);
	}
    }
    return ret;
}

#if 0 
static int tst_cb(struct stat *stat_buf, char *filename, enum cli_ftw_reason reason, struct cli_ftw_cbdata *data)
{
    char buf[8192];
    int fd;
    switch (reason) {
	case error_mem:
	    perror("memory allocation failed!");
	    return CL_EMEM;
	case error_stat:
	    if (filename) fprintf(stderr,"%s ",filename);
	    perror("stat failed");
	    return CL_SUCCESS;
	case warning_skipped:
	    if (filename) fprintf(stderr,"%s skipped due to recursion limit\n", filename);
	    return CL_SUCCESS;
	case visit_directory:
	    printf("%s\n", filename);
	    return CL_SUCCESS;
	case visit_file:
	    if (!filename) {
		fprintf(stderr, "Error got no filename!!\n");
		return CL_SUCCESS;
	    }
	    fd = open(filename, O_RDONLY);
	    if (fd >= 0) {
		while (read(fd, buf, sizeof(buf)) > 0) {}
		close(fd);
		printf("%s\n",filename);
	    } else {
		fprintf(stderr,"%s ", filename);
		perror("open failed");
	    }
	    return CL_SUCCESS;
    }
}

int main(int argc, char *argv[])
{
    int files = 0;
    struct cli_ftw_cbdata data;
    if (argc != 2)
	return 1;
    data.data = &files;
    cli_ftw(argv[1], CLI_FTW_STD, 16, tst_cb, &data);
    return 0;
}
#endif

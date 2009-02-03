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
    const char *dirname;
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

enum filetype {
    ft_unknown,
    ft_link,
    ft_directory,
    ft_regular,
    ft_skipped_special,
    ft_skipped_link
};

static inline int ft_skipped(enum filetype ft)
{
    return ft != ft_regular && ft != ft_directory;
}

#define FOLLOW_SYMLINK_MASK (CLI_FTW_FOLLOW_FILE_SYMLINK | CLI_FTW_FOLLOW_DIR_SYMLINK)
static int get_filetype(const char *fname, int flags, int need_stat,
			 struct stat *statbuf, enum filetype *ft)
{
    int stated = 0;

    if (*ft == ft_unknown || *ft == ft_link) {
	need_stat = 1;

	if ((flags & FOLLOW_SYMLINK_MASK) != FOLLOW_SYMLINK_MASK) {
	    /* Following only one of directory/file symlinks, or none, may
	     * need to lstat.
	     * If we're following both file and directory symlinks, we don't need
	     * to lstat(), we can just stat() directly.*/
	    if (*ft != ft_link) {
		/* need to lstat to determine if it is a symlink */
		if (lstat(fname, statbuf) == -1)
		    return -1;
		if (S_ISLNK(statbuf->st_mode)) {
		    *ft = ft_link;
		} else {
		    /* It was not a symlink, stat() not needed */
		    need_stat = 0;
		    stated = 1;
		}
	    }
	    if (*ft == ft_link && !(flags & FOLLOW_SYMLINK_MASK)) {
		/* This is a symlink, but we don't follow any symlinks */
		*ft = ft_skipped_link;
		return 0;
	    }
	}
    }

    if (need_stat) {
	if (stat(fname, statbuf) == -1)
	    return -1;
	stated = 1;
    }

    if (*ft == ft_unknown || *ft == ft_link) {
	if (S_ISDIR(statbuf->st_mode) &&
	    (*ft != ft_link || (flags & CLI_FTW_FOLLOW_DIR_SYMLINK))) {
	    /* A directory, or (a symlink to a directory and we're following dir
	     * symlinks) */
	    *ft = ft_directory;
	} else if (S_ISREG(statbuf->st_mode) &&
		   (*ft != ft_link || (flags & CLI_FTW_FOLLOW_FILE_SYMLINK))) {
	    /* A file, or (a symlink to a file and we're following file symlinks) */
	    *ft = ft_regular;
	} else {
	    /* default: skipped */
	    *ft = S_ISLNK(statbuf->st_mode) ?
		ft_skipped_link : ft_skipped_special;
	}
    }
    return stated;
}

static int handle_filetype(const char *fname, int flags,
			   struct stat *statbuf, int *stated, enum filetype *ft,
			   cli_ftw_cb callback, struct cli_ftw_cbdata *data)
{
    int ret;

    *stated = get_filetype(fname, flags, flags & CLI_FTW_NEED_STAT , statbuf, ft);

    if (*stated == -1) {
	/*  we failed a stat() or lstat() */
	ret = callback(NULL, NULL, fname, error_stat, data);
	if (ret != CL_SUCCESS)
	    return ret;
	*ft = ft_unknown;
    } else if (*ft == ft_skipped_link || *ft == ft_skipped_special) {
	/* skipped filetype */
	ret = callback(stated ? statbuf : NULL, NULL, fname,
		       *ft == ft_skipped_link ?
		       warning_skipped_link : warning_skipped_special, data);
	if (ret != CL_SUCCESS)
	    return ret;
    }
    return CL_SUCCESS;
}

static int cli_ftw_dir(const char *dirname, int flags, int maxdepth, cli_ftw_cb callback, struct cli_ftw_cbdata *data);
static int handle_entry(struct dirent_data *entry, int flags, int maxdepth, cli_ftw_cb callback, struct cli_ftw_cbdata *data)
{
    if (!entry->is_dir) {
	return callback(entry->statbuf, entry->filename, entry->filename, visit_file, data);
    } else {
	return cli_ftw_dir(entry->dirname, flags, maxdepth, callback, data);
    }
}

int cli_ftw(const char *path, int flags, int maxdepth, cli_ftw_cb callback, struct cli_ftw_cbdata *data)
{
    struct stat statbuf;
    enum filetype ft = ft_unknown;
    struct dirent_data entry;
    int stated = 0;

    int ret = handle_filetype(path, flags, &statbuf, &stated, &ft, callback, data);
    if (ret != CL_SUCCESS)
	return ret;
    if (ft_skipped(ft))
	return CL_SUCCESS;
    entry.statbuf = stated ? &statbuf : NULL;
    entry.is_dir = ft == ft_directory;
    entry.filename = entry.is_dir ? NULL : strdup(path);
    entry.dirname = entry.is_dir ? path : NULL;
    if (entry.is_dir) {
	ret = callback(entry.statbuf, NULL, path, visit_directory_toplev, data);
	if (ret != CL_SUCCESS)
	    return ret;
    }
    return handle_entry(&entry, flags, maxdepth, callback, data);
}

static int cli_ftw_dir(const char *dirname, int flags, int maxdepth, cli_ftw_cb callback, struct cli_ftw_cbdata *data)
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
	ret = callback(NULL, NULL, dirname, warning_skipped_dir, data);
	return ret;
    }

    if((dd = opendir(dirname)) != NULL) {
	struct dirent *dent;
	errno = 0;
	ret = CL_SUCCESS;
#ifdef HAVE_READDIR_R_3
	while(!readdir_r(dd, &result.d, &dent) && dent) {
#elif defined(HAVE_READDIR_R_2)
	while((dent = (struct dirent *) readdir_r(dd, &result.d))) {
#else
	while((dent = readdir(dd))) {
#endif
	    int stated = 0;
	    enum filetype ft;
	    char *fname;
	    struct stat statbuf;
	    struct stat *statbufp;

	    if(!strcmp(dent->d_name, ".") || !strcmp(dent->d_name, ".."))
		continue;
#ifdef _DIRENT_HAVE_D_TYPE
	    switch (dent->d_type) {
		case DT_DIR:
		    ft = ft_directory;
		    break;
		case DT_LNK:
		    if (!(flags & FOLLOW_SYMLINK_MASK)) {
			/* we don't follow symlinks, don't bother
			 * stating it */
			errno = 0;
			continue;
		    }
		    ft = ft_link;
		    break;
		case DT_REG:
		    ft = ft_regular;
		    break;
		case DT_UNKNOWN:
		    ft = ft_unknown;
		    break;
		default:
		    ft = ft_skipped_special;
		    break;
	    }
#else
	    ft = ft_unknown;
#endif
	    fname = (char *) cli_malloc(strlen(dirname) + strlen(dent->d_name) + 2);
	    if(!fname) {
		ret = callback(NULL, NULL, dirname, error_mem, data);
		if (ret != CL_SUCCESS)
		    break;
	    }
	    sprintf(fname, "%s/%s", dirname, dent->d_name);

	    ret = handle_filetype(fname, flags, &statbuf, &stated, &ft, callback, data);
	    if (ret != CL_SUCCESS) {
		free(fname);
		break;
	    }

	    if (ft_skipped(ft)) { /* skip */
		free(fname);
		errno = 0;
		continue;
	    }

	    if (stated && (flags & CLI_FTW_NEED_STAT)) {
		statbufp = cli_malloc(sizeof(*statbufp));
		if (!statbufp) {
		    ret = callback(stated ? &statbuf : NULL, NULL, fname, error_mem, data);
		    free(fname);
		    if (ret != CL_SUCCESS)
			break;
		    else {
			errno = 0;
			continue;
		    }
		}
		memcpy(statbufp, &statbuf, sizeof(statbuf));
	    } else {
		statbufp = 0;
	    }

	    entries_cnt++;
	    entries = cli_realloc(entries, entries_cnt*sizeof(*entries));
	    if (!entries) {
		ret = callback(stated ? &statbuf : NULL, NULL, fname, error_mem, data);
		free(fname);
		if (statbufp)
		    free(statbufp);
		break;
	    } else {
		struct dirent_data *entry = &entries[entries_cnt-1];
		entry->filename = fname;
		entry->statbuf = statbufp;
		entry->is_dir = ft == ft_directory;
		entry->dirname = entry->is_dir ? fname : NULL;
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
		ret = handle_entry(entry, flags, maxdepth-1, callback, data);
		if (entry->is_dir)
		    free(entry->filename);
		if (entry->statbuf)
		    free(entry->statbuf);
		if (ret != CL_SUCCESS)
		    break;
	    }
	    free(entries);
	}
    } else {
	ret = callback(NULL, NULL, dirname, error_stat, data);
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
    cli_ftw_dir(argv[1], CLI_FTW_STD, 16, tst_cb, &data);
    return 0;
}
#endif

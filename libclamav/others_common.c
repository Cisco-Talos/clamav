/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
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
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#ifndef _WIN32
#include <sys/wait.h>
#include <sys/time.h>
#endif
#include <time.h>
#include <fcntl.h>
#ifdef HAVE_PWD_H
#include <pwd.h>
#endif
#include <errno.h>
#include "target.h"
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#ifdef HAVE_MALLOC_H
#include <malloc.h>
#endif

#include "clamav.h"
#include "others.h"
#include "platform.h"
#include "regex/regex.h"
#include "ltdl.h"
#include "matcher-ac.h"

static unsigned char name_salt[16] = {16, 38, 97, 12, 8, 4, 72, 196, 217, 144, 33, 124, 18, 11, 17, 253};

#ifdef CL_NOTHREADS
#undef CL_THREAD_SAFE
#endif

#ifdef CL_THREAD_SAFE
#include <pthread.h>

static pthread_mutex_t cli_gentemp_mutex = PTHREAD_MUTEX_INITIALIZER;
#ifndef HAVE_CTIME_R
static pthread_mutex_t cli_ctime_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif
static pthread_mutex_t cli_strerror_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_key_t cli_ctx_tls_key;
static pthread_once_t cli_ctx_tls_key_once = PTHREAD_ONCE_INIT;

static void cli_ctx_tls_key_alloc(void)
{
    pthread_key_create(&cli_ctx_tls_key, NULL);
}

void cli_logg_setup(const cli_ctx* ctx)
{
    pthread_once(&cli_ctx_tls_key_once, cli_ctx_tls_key_alloc);
    pthread_setspecific(cli_ctx_tls_key, ctx);
}

void cli_logg_unsetup(void)
{
    pthread_setspecific(cli_ctx_tls_key, NULL);
}

static inline void* cli_getctx(void)
{
    cli_ctx* ctx;
    pthread_once(&cli_ctx_tls_key_once, cli_ctx_tls_key_alloc);
    ctx = pthread_getspecific(cli_ctx_tls_key);
    return ctx ? ctx->cb_ctx : NULL;
}
#else

static const cli_ctx* current_ctx = NULL;
void cli_logg_setup(const cli_ctx* ctx)
{
    current_ctx = ctx;
}

static inline void* cli_getctx(void)
{
    return current_ctx ? current_ctx->cb_ctx : NULL;
}

void cli_logg_unsetup(void)
{
}
#endif

uint8_t cli_debug_flag              = 0;
uint8_t cli_always_gen_section_hash = 0;

static void fputs_callback(enum cl_msg severity, const char* fullmsg, const char* msg, void* context)
{
    UNUSEDPARAM(severity);
    UNUSEDPARAM(msg);
    UNUSEDPARAM(context);
    fputs(fullmsg, stderr);
}

static clcb_msg msg_callback = fputs_callback;

void cl_set_clcb_msg(clcb_msg callback)
{
    msg_callback = callback;
}

#define MSGCODE(buff, len, x)                             \
    va_list args;                                         \
    size_t len = sizeof(x) - 1;                           \
    char buff[BUFSIZ];                                    \
    strncpy(buff, x, len);                                \
    va_start(args, str);                                  \
    vsnprintf(buff + len, sizeof(buff) - len, str, args); \
    buff[sizeof(buff) - 1] = '\0';                        \
    va_end(args)

void cli_warnmsg(const char* str, ...)
{
    MSGCODE(buff, len, "LibClamAV Warning: ");
    msg_callback(CL_MSG_WARN, buff, buff + len, cli_getctx());
}

void cli_errmsg(const char* str, ...)
{
    MSGCODE(buff, len, "LibClamAV Error: ");
    msg_callback(CL_MSG_ERROR, buff, buff + len, cli_getctx());
}

void cli_infomsg(const cli_ctx* ctx, const char* str, ...)
{
    MSGCODE(buff, len, "LibClamAV info: ");
    msg_callback(CL_MSG_INFO_VERBOSE, buff, buff + len, ctx ? ctx->cb_ctx : NULL);
}

void cli_dbgmsg_internal(const char* str, ...)
{
    MSGCODE(buff, len, "LibClamAV debug: ");
    fputs(buff, stderr);
}

int cli_matchregex(const char* str, const char* regex)
{
    regex_t reg;
    int match, flags = REG_EXTENDED | REG_NOSUB;
#ifdef _WIN32
    flags |= REG_ICASE;
#endif
    if(cli_regcomp(&reg, regex, flags) == 0) {
        match = (cli_regexec(&reg, str, 0, NULL, 0) == REG_NOMATCH) ? 0 : 1;
        cli_regfree(&reg);
        return match;
    }

    return 0;
}
void* cli_malloc(size_t size)
{
    void* alloc;

    if(!size || size > CLI_MAX_ALLOCATION) {
        cli_errmsg("cli_malloc(): Attempt to allocate %lu bytes. Please report to https://bugzilla.clamav.net\n", (unsigned long int)size);
        return NULL;
    }

    alloc = malloc(size);

    if(!alloc) {
        perror("malloc_problem");
        cli_errmsg("cli_malloc(): Can't allocate memory (%lu bytes).\n", (unsigned long int)size);
        return NULL;
    } else
        return alloc;
}

void* cli_calloc(size_t nmemb, size_t size)
{
    void* alloc;

    if(!nmemb || !size || size > CLI_MAX_ALLOCATION || nmemb > CLI_MAX_ALLOCATION || (nmemb * size > CLI_MAX_ALLOCATION)) {
        cli_errmsg("cli_calloc(): Attempt to allocate %lu bytes. Please report to https://bugzilla.clamav.net\n", (unsigned long int)nmemb * size);
        return NULL;
    }

    alloc = calloc(nmemb, size);

    if(!alloc) {
        perror("calloc_problem");
        cli_errmsg("cli_calloc(): Can't allocate memory (%lu bytes).\n", (unsigned long int)(nmemb * size));
        return NULL;
    } else
        return alloc;
}

void* cli_realloc(void* ptr, size_t size)
{
    void* alloc;

    if(!size || size > CLI_MAX_ALLOCATION) {
        cli_errmsg("cli_realloc(): Attempt to allocate %lu bytes. Please report to https://bugzilla.clamav.net\n", (unsigned long int)size);
        return NULL;
    }

    alloc = realloc(ptr, size);

    if(!alloc) {
        perror("realloc_problem");
        cli_errmsg("cli_realloc(): Can't re-allocate memory to %lu bytes.\n", (unsigned long int)size);
        return NULL;
    } else
        return alloc;
}

void* cli_realloc2(void* ptr, size_t size)
{
    void* alloc;

    if(!size || size > CLI_MAX_ALLOCATION) {
        cli_errmsg("cli_realloc2(): Attempt to allocate %lu bytes. Please report to https://bugzilla.clamav.net\n", (unsigned long int)size);
        return NULL;
    }

    alloc = realloc(ptr, size);

    if(!alloc) {
        perror("realloc_problem");
        cli_errmsg("cli_realloc2(): Can't re-allocate memory to %lu bytes.\n", (unsigned long int)size);
        if(ptr)
            free(ptr);
        return NULL;
    } else
        return alloc;
}

char* cli_strdup(const char* s)
{
    char* alloc;

    if(s == NULL) {
        cli_errmsg("cli_strdup(): s == NULL. Please report to https://bugzilla.clamav.net\n");
        return NULL;
    }

    alloc = strdup(s);

    if(!alloc) {
        perror("strdup_problem");
        cli_errmsg("cli_strdup(): Can't allocate memory (%u bytes).\n", (unsigned int)strlen(s));
        return NULL;
    }

    return alloc;
}

/* returns converted timestamp, in case of error the returned string contains at least one character */
const char* cli_ctime(const time_t* timep, char* buf, const size_t bufsize)
{
    const char* ret;
    if(bufsize < 26) {
        /* standard says we must have at least 26 bytes buffer */
        cli_warnmsg("buffer too small for ctime\n");
        return " ";
    }
    if((uint32_t)(*timep) > 0x7fffffff) {
        /* some systems can consider these timestamps invalid */
        strncpy(buf, "invalid timestamp", bufsize - 1);
        buf[bufsize - 1] = '\0';
        return buf;
    }

#ifdef HAVE_CTIME_R
#ifdef HAVE_CTIME_R_2
    ret = ctime_r(timep, buf);
#else
    ret = ctime_r(timep, buf, bufsize);
#endif
#else /* no ctime_r */

#ifdef CL_THREAD_SAFE
    pthread_mutex_lock(&cli_ctime_mutex);
#endif
    ret = ctime(timep);
    if(ret) {
        strncpy(buf, ret, bufsize - 1);
        buf[bufsize - 1] = '\0';
        ret              = buf;
    }
#ifdef CL_THREAD_SAFE
    pthread_mutex_unlock(&cli_ctime_mutex);
#endif
#endif
    /* common */
    if(!ret) {
        buf[0] = ' ';
        buf[1] = '\0';
        return buf;
    }
    return ret;
}

/* Function: readn
        Try hard to read the requested number of bytes
*/
int cli_readn(int fd, void* buff, unsigned int count)
{
    int retval;
    unsigned int todo;
    unsigned char* current;

    todo    = count;
    current = (unsigned char*)buff;

    do {
        retval = read(fd, current, todo);
        if(retval == 0) {
            return (count - todo);
        }
        if(retval < 0) {
            char err[128];
            if(errno == EINTR) {
                continue;
            }
            cli_errmsg("cli_readn: read error: %s\n", cli_strerror(errno, err, sizeof(err)));
            return -1;
        }
        todo -= retval;
        current += retval;
    } while(todo > 0);

    return count;
}

/* Function: writen
        Try hard to write the specified number of bytes
*/
int cli_writen(int fd, const void* buff, unsigned int count)
{
    int retval;
    unsigned int todo;
    const unsigned char* current;

    todo    = count;
    current = (const unsigned char*)buff;

    do {
        retval = write(fd, current, todo);
        if(retval < 0) {
            char err[128];
            if(errno == EINTR) {
                continue;
            }
            cli_errmsg("cli_writen: write error: %s\n", cli_strerror(errno, err, sizeof(err)));
            return -1;
        }
        todo -= retval;
        current += retval;
    } while(todo > 0);

    return count;
}

int cli_filecopy(const char* src, const char* dest)
{

#ifdef _WIN32
    return CopyFileA(src, dest, 0) ? 0 : -1;
#else
    char* buffer;
    int s, d, bytes;

    if((s = open(src, O_RDONLY | O_BINARY)) == -1)
        return -1;

    if((d = open(dest, O_CREAT | O_WRONLY | O_TRUNC | O_BINARY, S_IRWXU)) == -1) {
        close(s);
        return -1;
    }

    if(!(buffer = cli_malloc(FILEBUFF))) {
        close(s);
        close(d);
        return -1;
    }

    while((bytes = cli_readn(s, buffer, FILEBUFF)) > 0)
        cli_writen(d, buffer, bytes);

    free(buffer);
    close(s);

    return close(d);
#endif
}

#ifndef P_tmpdir
#ifdef _WIN32
#define P_tmpdir "C:\\"
#else
#define P_tmpdir "/tmp"
#endif /* _WIN32 */
#endif /* P_tmpdir */

const char* cli_gettmpdir(void)
{
    const char* tmpdir;
    unsigned int i;

#ifdef _WIN32
    char* envs[] = {"TEMP", "TMP", NULL};
#else
    char* envs[] = {"TMPDIR", NULL};
#endif

    for(i = 0; envs[i] != NULL; i++)
        if((tmpdir = getenv(envs[i])))
            return tmpdir;

    return P_tmpdir;
}

struct dirent_data {
    char* filename;
    const char* dirname;
    STATBUF* statbuf;
    long ino;   /* -1: inode not available */
    int is_dir; /* 0 - no, 1 - yes */
};

/* sort files before directories, and lower inodes before higher inodes */
static int ftw_compare(const void* a, const void* b)
{
    const struct dirent_data* da = a;
    const struct dirent_data* db = b;
    long diff                    = da->is_dir - db->is_dir;
    if(!diff) {
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
static int get_filetype(const char* fname, int flags, int need_stat,
                        STATBUF* statbuf, enum filetype* ft)
{
    int stated = 0;

    if(*ft == ft_unknown || *ft == ft_link) {
        need_stat = 1;

        if((flags & FOLLOW_SYMLINK_MASK) != FOLLOW_SYMLINK_MASK) {
            /* Following only one of directory/file symlinks, or none, may
	     * need to lstat.
	     * If we're following both file and directory symlinks, we don't need
	     * to lstat(), we can just stat() directly.*/
            if(*ft != ft_link) {
                /* need to lstat to determine if it is a symlink */
                if(LSTAT(fname, statbuf) == -1)
                    return -1;
                if(S_ISLNK(statbuf->st_mode)) {
                    *ft = ft_link;
                } else {
                    /* It was not a symlink, stat() not needed */
                    need_stat = 0;
                    stated    = 1;
                }
            }
            if(*ft == ft_link && !(flags & FOLLOW_SYMLINK_MASK)) {
                /* This is a symlink, but we don't follow any symlinks */
                *ft = ft_skipped_link;
                return 0;
            }
        }
    }

    if(need_stat) {
        if(CLAMSTAT(fname, statbuf) == -1)
            return -1;
        stated = 1;
    }

    if(*ft == ft_unknown || *ft == ft_link) {
        if(S_ISDIR(statbuf->st_mode) &&
           (*ft != ft_link || (flags & CLI_FTW_FOLLOW_DIR_SYMLINK))) {
            /* A directory, or (a symlink to a directory and we're following dir
	     * symlinks) */
            *ft = ft_directory;
        } else if(S_ISREG(statbuf->st_mode) &&
                  (*ft != ft_link || (flags & CLI_FTW_FOLLOW_FILE_SYMLINK))) {
            /* A file, or (a symlink to a file and we're following file symlinks) */
            *ft = ft_regular;
        } else {
            /* default: skipped */
            *ft = S_ISLNK(statbuf->st_mode) ? ft_skipped_link : ft_skipped_special;
        }
    }
    return stated;
}

static int handle_filetype(const char* fname, int flags,
                           STATBUF* statbuf, int* stated, enum filetype* ft,
                           cli_ftw_cb callback, struct cli_ftw_cbdata* data)
{
    int ret;

    *stated = get_filetype(fname, flags, flags & CLI_FTW_NEED_STAT, statbuf, ft);

    if(*stated == -1) {
        /*  we failed a stat() or lstat() */
        ret = callback(NULL, NULL, fname, error_stat, data);
        if(ret != CL_SUCCESS)
            return ret;
        *ft = ft_unknown;
    } else if(*ft == ft_skipped_link || *ft == ft_skipped_special) {
        /* skipped filetype */
        ret = callback(stated ? statbuf : NULL, NULL, fname,
                       *ft == ft_skipped_link ? warning_skipped_link : warning_skipped_special, data);
        if(ret != CL_SUCCESS)
            return ret;
    }
    return CL_SUCCESS;
}

static int cli_ftw_dir(const char* dirname, int flags, int maxdepth, cli_ftw_cb callback, struct cli_ftw_cbdata* data, cli_ftw_pathchk pathchk);
static int handle_entry(struct dirent_data* entry, int flags, int maxdepth, cli_ftw_cb callback, struct cli_ftw_cbdata* data, cli_ftw_pathchk pathchk)
{
    if(!entry->is_dir) {
        return callback(entry->statbuf, entry->filename, entry->filename, visit_file, data);
    } else {
        return cli_ftw_dir(entry->dirname, flags, maxdepth, callback, data, pathchk);
    }
}

int cli_ftw(char* path, int flags, int maxdepth, cli_ftw_cb callback, struct cli_ftw_cbdata* data, cli_ftw_pathchk pathchk)
{
    STATBUF statbuf;
    enum filetype ft = ft_unknown;
    struct dirent_data entry;
    int stated = 0;
    int ret;

    if(((flags & CLI_FTW_TRIM_SLASHES) || pathchk) && path[0] && path[1]) {
        char* pathend;
        /* trim slashes so that dir and dir/ behave the same when
	 * they are symlinks, and we are not following symlinks */
#ifndef _WIN32
        while(path[0] == *PATHSEP && path[1] == *PATHSEP) path++;
#endif
        pathend = path + strlen(path);
        while(pathend > path && pathend[-1] == *PATHSEP) --pathend;
        *pathend = '\0';
    }
    if(pathchk && pathchk(path, data) == 1)
        return CL_SUCCESS;
    ret = handle_filetype(path, flags, &statbuf, &stated, &ft, callback, data);
    if(ret != CL_SUCCESS)
        return ret;
    if(ft_skipped(ft))
        return CL_SUCCESS;
    entry.statbuf  = stated ? &statbuf : NULL;
    entry.is_dir   = ft == ft_directory;
    entry.filename = entry.is_dir ? NULL : strdup(path);
    entry.dirname  = entry.is_dir ? path : NULL;
    if(entry.is_dir) {
        ret = callback(entry.statbuf, NULL, path, visit_directory_toplev, data);
        if(ret != CL_SUCCESS)
            return ret;
    }
    return handle_entry(&entry, flags, maxdepth, callback, data, pathchk);
}

static int cli_ftw_dir(const char* dirname, int flags, int maxdepth, cli_ftw_cb callback, struct cli_ftw_cbdata* data, cli_ftw_pathchk pathchk)
{
    DIR* dd;
#if defined(HAVE_READDIR_R_3) || defined(HAVE_READDIR_R_2)
    union {
        struct dirent d;
        char b[offsetof(struct dirent, d_name) + NAME_MAX + 1];
    } result;
#endif
    struct dirent_data* entries = NULL;
    size_t i, entries_cnt = 0;
    int ret;

    if(maxdepth < 0) {
        /* exceeded recursion limit */
        ret = callback(NULL, NULL, dirname, warning_skipped_dir, data);
        return ret;
    }

    if((dd = opendir(dirname)) != NULL) {
        struct dirent* dent;
        int err;
        errno = 0;
        ret   = CL_SUCCESS;
#ifdef HAVE_READDIR_R_3
        while(!(err = readdir_r(dd, &result.d, &dent)) && dent) {
#elif defined(HAVE_READDIR_R_2)
        while((dent = (struct dirent*)readdir_r(dd, &result.d))) {
#else
        while((dent = readdir(dd))) {
#endif
            int stated = 0;
            enum filetype ft;
            char* fname;
            STATBUF statbuf;
            STATBUF* statbufp;

            if(!strcmp(dent->d_name, ".") || !strcmp(dent->d_name, ".."))
                continue;
#ifdef _DIRENT_HAVE_D_TYPE
            switch(dent->d_type) {
            case DT_DIR:
                ft = ft_directory;
                break;
            case DT_LNK:
                if(!(flags & FOLLOW_SYMLINK_MASK)) {
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
            fname = (char*)cli_malloc(strlen(dirname) + strlen(dent->d_name) + 2);
            if(!fname) {
                ret = callback(NULL, NULL, dirname, error_mem, data);
                if(ret != CL_SUCCESS)
                    break;
                continue; /* have to skip this one if continuing after error */
            }
            if(!strcmp(dirname, PATHSEP))
                sprintf(fname, PATHSEP "%s", dent->d_name);
            else
                sprintf(fname, "%s" PATHSEP "%s", dirname, dent->d_name);

            if(pathchk && pathchk(fname, data) == 1) {
                free(fname);
                continue;
            }

            ret = handle_filetype(fname, flags, &statbuf, &stated, &ft, callback, data);
            if(ret != CL_SUCCESS) {
                free(fname);
                break;
            }

            if(ft_skipped(ft)) { /* skip */
                free(fname);
                errno = 0;
                continue;
            }

            if(stated && (flags & CLI_FTW_NEED_STAT)) {
                statbufp = cli_malloc(sizeof(*statbufp));
                if(!statbufp) {
                    ret = callback(stated ? &statbuf : NULL, NULL, fname, error_mem, data);
                    free(fname);
                    if(ret != CL_SUCCESS)
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
            entries = cli_realloc(entries, entries_cnt * sizeof(*entries));
            if(!entries) {
                ret = callback(stated ? &statbuf : NULL, NULL, fname, error_mem, data);
                free(fname);
                if(statbufp)
                    free(statbufp);
                break;
            } else {
                struct dirent_data* entry = &entries[entries_cnt - 1];
                entry->filename           = fname;
                entry->statbuf            = statbufp;
                entry->is_dir             = ft == ft_directory;
                entry->dirname            = entry->is_dir ? fname : NULL;
#ifdef _XOPEN_UNIX
                entry->ino = dent->d_ino;
#else
                entry->ino = -1;
#endif
            }
            errno = 0;
        }
#ifndef HAVE_READDIR_R_3
        err = errno;
#endif
        closedir(dd);
        ret = CL_SUCCESS;
        if(err) {
            char errs[128];
            cli_errmsg("Unable to readdir() directory %s: %s\n", dirname,
                       cli_strerror(errno, errs, sizeof(errs)));
            /* report error to callback using error_stat */
            ret = callback(NULL, NULL, dirname, error_stat, data);
            if(ret != CL_SUCCESS) {
                if(entries) {
                    for(i = 0; i < entries_cnt; i++) {
                        struct dirent_data* entry = &entries[i];
                        free(entry->filename);
                        free(entry->statbuf);
                    }
                    free(entries);
                }
                return ret;
            }
        }

        if(entries) {
            cli_qsort(entries, entries_cnt, sizeof(*entries), ftw_compare);
            for(i = 0; i < entries_cnt; i++) {
                struct dirent_data* entry = &entries[i];
                ret                       = handle_entry(entry, flags, maxdepth - 1, callback, data, pathchk);
                if(entry->is_dir)
                    free(entry->filename);
                if(entry->statbuf)
                    free(entry->statbuf);
                if(ret != CL_SUCCESS)
                    break;
            }
            for(i++; i < entries_cnt; i++) {
                struct dirent_data* entry = &entries[i];
                free(entry->filename);
                free(entry->statbuf);
            }
            free(entries);
        }
    } else {
        ret = callback(NULL, NULL, dirname, error_stat, data);
    }
    return ret;
}

/* strerror_r is not available everywhere, (and when it is there are two variants,
 * the XSI, and the GNU one, so provide a wrapper to make sure correct one is
 * used */
const char* cli_strerror(int errnum, char* buf, size_t len)
{
    char* err;
#ifdef CL_THREAD_SAFE
    pthread_mutex_lock(&cli_strerror_mutex);
#endif
    err = strerror(errnum);
    strncpy(buf, err, len);
    buf[len - 1] = '\0'; /* just in case */
#ifdef CL_THREAD_SAFE
    pthread_mutex_unlock(&cli_strerror_mutex);
#endif
    return buf;
}

static char* cli_md5buff(const unsigned char* buffer, unsigned int len, unsigned char* dig)
{
    unsigned char digest[16];
    char *md5str, *pt;
    int i;

    cl_hash_data("md5", buffer, len, digest, NULL);

    if(dig)
        memcpy(dig, digest, 16);

    if(!(md5str = (char*)cli_calloc(32 + 1, sizeof(char))))
        return NULL;

    pt = md5str;
    for(i = 0; i < 16; i++) {
        sprintf(pt, "%02x", digest[i]);
        pt += 2;
    }

    return md5str;
}

unsigned int cli_rndnum(unsigned int max)
{
    if(name_salt[0] == 16) { /* minimizes re-seeding after the first call to cli_gentemp() */
        struct timeval tv;
        gettimeofday(&tv, (struct timezone*)0);
        srand(tv.tv_usec + clock() + rand());
    }

    return 1 + (unsigned int)(max * (rand() / (1.0 + RAND_MAX)));
}

char* cli_sanitize_filepath(const char* filepath, size_t filepath_len)
{
    uint32_t depth           = 0;
    size_t index             = 0;
    size_t sanitized_index   = 0;
    char* sanitized_filepath = NULL;

    if((NULL == filepath) || (0 == filepath_len) || (MAX_PATH < filepath_len)) {
        goto done;
    }

    sanitized_filepath = cli_calloc(filepath_len + 1, sizeof(unsigned char));
    if(NULL == sanitized_filepath) {
        cli_dbgmsg("cli_sanitize_filepath: out of memory\n");
        goto done;
    }

    while(index < filepath_len) {
        char* next_pathsep = NULL;

        if(0 == strncmp(filepath + index, PATHSEP, strlen(PATHSEP))) {
            /*
             * Is "/" (or "\\" on Windows)
             */
            /* Skip leading pathsep in absolute path, or extra pathsep) */
            index += strlen(PATHSEP);
            continue;
        } else if(0 == strncmp(filepath + index, "." PATHSEP, strlen("." PATHSEP))) {
            /*
             * Is "./" (or ".\\" on Windows)
             */
            /* Current directory indicator is meaningless and should not add to the depth. Skip it. */
            index += strlen("." PATHSEP);
            continue;
        } else if(0 == strncmp(filepath + index, ".." PATHSEP, strlen(".." PATHSEP))) {
            /*
             * Is "../" (or "..\\" on Windows)
             */
            if(depth == 0) {
                /* Relative path would traverse parent directory. Skip it. */
                index += strlen(".." PATHSEP);
                continue;
            } else {
                /* Relative path is safe. Allow it. */
                strncpy(sanitized_filepath + sanitized_index, filepath + index, strlen(".." PATHSEP));
                sanitized_index += strlen(".." PATHSEP);
                index += strlen(".." PATHSEP);
                depth--;
            }
        }
#ifdef _WIN32
        /*
         * Windows' POSIX style API's accept both "/" and "\\" style path separators.
         * The following checks using POSIX style path separators on Windows.
         */
        else if(0 == strncmp(filepath + index, "/", strlen("/"))) {
            /*
             * Is "/".
             */
            /* Skip leading pathsep in absolute path, or extra pathsep) */
            index += strlen("/");
            continue;
        } else if(0 == strncmp(filepath + index, "./", strlen("./"))) {
            /*
             * Is "./"
             */
            /* Current directory indicator is meaningless and should not add to the depth. Skip it. */
            index += strlen("./");
            continue;
        } else if(0 == strncmp(filepath + index, "../", strlen("../"))) {
            /*
             * Is "../"
             */
            if(depth == 0) {
                /* Relative path would traverse parent directory. Skip it. */
                index += strlen("../");
                continue;
            } else {
                /* Relative path is safe. Allow it. */
                strncpy(sanitized_filepath + sanitized_index, filepath + index, strlen("../"));
                sanitized_index += strlen("../");
                index += strlen("../");
                depth--;
            }
        }
#endif
        else {
            /*
             * Is not "/", "./", or "../".
             */
            /* Find the next path separator. */
            next_pathsep = cli_strnstr(filepath + index, PATHSEP, filepath_len - index);
            if(NULL == next_pathsep) {
                /* No more path separators, copy the rest (filename) into the sanitized path */
                strncpy(sanitized_filepath + sanitized_index, filepath + index, filepath_len - index);
                break;
            }
            next_pathsep += strlen(PATHSEP); /* Include the path separator in the copy */

            /* Copy next directory name into the sanitized path */
            strncpy(sanitized_filepath + sanitized_index, filepath + index, next_pathsep - (filepath + index));
            sanitized_index += next_pathsep - (filepath + index);
            index += next_pathsep - (filepath + index);
            depth++;
        }
    }

done:
    if((NULL != sanitized_filepath) && (0 == strlen(sanitized_filepath))) {
        free(sanitized_filepath);
        sanitized_filepath = NULL;
    }

    return sanitized_filepath;
}

char* cli_genfname(const char* prefix)
{
    char* sanitized_prefix = NULL;
    char* fname            = NULL;
    unsigned char salt[16 + 32];
    char* tmp;
    int i;
    size_t len;

    if(prefix && (strlen(prefix) > 0)) {
        sanitized_prefix = cli_sanitize_filepath(prefix, strlen(prefix));
        len              = strlen(sanitized_prefix) + 1 + 5 + 1; /* {prefix}.{5}\0 */
    } else {
        len = 6 + 1 + 48 + 4 + 1; /* clamav-{48}.tmp\0 */
    }

    fname = (char*)cli_calloc(len, sizeof(char));
    if(!fname) {
        cli_dbgmsg("cli_genfname: out of memory\n");
        return NULL;
    }

#ifdef CL_THREAD_SAFE
    pthread_mutex_lock(&cli_gentemp_mutex);
#endif

    memcpy(salt, name_salt, 16);

    for(i = 16; i < 48; i++)
        salt[i] = cli_rndnum(255);

    tmp = cli_md5buff(salt, 48, name_salt);

#ifdef CL_THREAD_SAFE
    pthread_mutex_unlock(&cli_gentemp_mutex);
#endif

    if(!tmp) {
        free(fname);
        cli_dbgmsg("cli_genfname: out of memory\n");
        return NULL;
    }

    if(sanitized_prefix && (strlen(sanitized_prefix) > 0)) {
        fname[5] = '\0';
        snprintf(fname, len, "%s.%s", sanitized_prefix, tmp);
        free(sanitized_prefix);
    } else {
        snprintf(fname, len, "clamav-%s.tmp", tmp);
    }

    free(tmp);

    return (fname);
}

char* cli_gentemp_with_prefix(const char* dir, const char* prefix)
{
    char* fname;
    char* fullpath;
    const char* mdir;
    int i;
    size_t len;

    mdir = dir ? dir : cli_gettmpdir();

    fname = cli_genfname(prefix);
    if(!fname) {
        cli_dbgmsg("cli_gentemp('%s'): out of memory\n", mdir);
        return NULL;
    }

    len      = strlen(mdir) + strlen(PATHSEP) + strlen(fname) + 1; /* mdir/fname\0 */
    fullpath = (char*)cli_calloc(len, sizeof(char));
    if(!fullpath) {
        free(fname);
        cli_dbgmsg("cli_gentemp('%s'): out of memory\n", mdir);
        return NULL;
    }

    snprintf(fullpath, len, "%s" PATHSEP "%s", mdir, fname);
    free(fname);

    return (fullpath);
}

char* cli_gentemp(const char* dir)
{
    return cli_gentemp_with_prefix(dir, NULL);
}

cl_error_t cli_gentempfd(const char* dir, char** name, int* fd)
{
    return cli_gentempfd_with_prefix(dir, NULL, name, fd);
}

cl_error_t cli_gentempfd_with_prefix(const char* dir, char* prefix, char** name, int* fd)
{
    *name = cli_gentemp_with_prefix(dir, prefix);
    if(!*name)
        return CL_EMEM;

    *fd = open(*name, O_RDWR | O_CREAT | O_TRUNC | O_BINARY | O_EXCL, S_IRWXU);
    /*
     * EEXIST is almost impossible to occur, so we just treat it as other
     * errors
     */
    if(*fd == -1) {
        if((EILSEQ == errno) || (EINVAL == errno) || (ENAMETOOLONG == errno)) {
            cli_dbgmsg("cli_gentempfd_with_prefix: Can't create temp file using prefix. Using a randomly generated name instead.\n");
            free(*name);
            *name = cli_gentemp(dir);
            if(!*name)
                return CL_EMEM;
            *fd = open(*name, O_RDWR | O_CREAT | O_TRUNC | O_BINARY | O_EXCL, S_IRWXU);
            if(*fd == -1) {
                cli_errmsg("cli_gentempfd_with_prefix: Can't create temporary file %s: %s\n", *name, strerror(errno));
                free(*name);
                *name = NULL;
                return CL_ECREAT;
            }
        } else {
            cli_errmsg("cli_gentempfd_with_prefix: Can't create temporary file %s: %s\n", *name, strerror(errno));
            free(*name);
            *name = NULL;
            return CL_ECREAT;
        }
    }

    return CL_SUCCESS;
}

int cli_regcomp(regex_t* preg, const char* pattern, int cflags)
{
    if(!strncmp(pattern, "(?i)", 4)) {
        pattern += 4;
        cflags |= REG_ICASE;
    }
    return cli_regcomp_real(preg, pattern, cflags);
}

cl_error_t cli_get_filepath_from_filedesc(int desc, char** filepath)
{
    cl_error_t status = CL_EARG;

    if(NULL == filepath) {
        cli_errmsg("cli_get_filepath_from_filedesc: Invalid args.\n");
        goto done;
    }

#ifdef __linux__
    char fname[PATH_MAX];

    char link[32];
    ssize_t linksz;

    memset(&fname, 0, PATH_MAX);

    snprintf(link, sizeof(link), "/proc/self/fd/%u", desc);
    link[sizeof(link) - 1] = '\0';

    if(-1 == (linksz = readlink(link, fname, PATH_MAX - 1))) {
        cli_errmsg("cli_get_filepath_from_filedesc: Failed to resolve filename for descriptor %d (%s)\n", desc, link);
        status = CL_EOPEN;
        goto done;
    }

    /* Success. Add null terminator */
    fname[linksz] = '\0';

    *filepath = cli_strndup(fname, cli_strnlen(fname, PATH_MAX));
    if(NULL == *filepath) {
        cli_errmsg("cli_get_filepath_from_filedesc: Failed to allocate memory to store filename\n");
        status = CL_EMEM;
        goto done;
    }

#elif __APPLE__
    char fname[PATH_MAX];
    memset(&fname, 0, PATH_MAX);

    if(fcntl(desc, F_GETPATH, &fname) < 0) {
        printf("cli_get_filepath_from_filedesc: Failed to resolve filename for descriptor %d\n", desc);
        status = CL_EOPEN;
        goto done;
    }

    *filepath = cli_strndup(fname, cli_strnlen(fname, PATH_MAX));
    if(NULL == *filepath) {
        cli_errmsg("cli_get_filepath_from_filedesc: Failed to allocate memory to store filename\n");
        status = CL_EMEM;
        goto done;
    }

#elif _WIN32
    DWORD dwRet = 0;
    intptr_t hFile = _get_osfhandle(desc);

    dwRet = GetFinalPathNameByHandleA((HANDLE)hFile, NULL, 0, VOLUME_NAME_NT);
    if(dwRet == 0) {
        cli_errmsg("cli_get_filepath_from_filedesc: Failed to resolve filename for descriptor %d\n", desc);
        status = CL_EOPEN;
        goto done;
    }

    *filepath = calloc(dwRet + 1, 1);
    if(NULL == *filepath) {
        cli_errmsg("cli_get_filepath_from_filedesc: Failed to allocate %u bytes to store filename\n", dwRet + 1);
        status = CL_EMEM;
        goto done;
    }

    dwRet = GetFinalPathNameByHandleA((HANDLE)hFile, *filepath, dwRet + 1, VOLUME_NAME_NT);
    if(dwRet == 0) {
        cli_errmsg("cli_get_filepath_from_filedesc: Failed to resolve filename for descriptor %d\n", desc);
        free(*filepath);
        *filepath = NULL;
        status = CL_EOPEN;
        goto done;
    }

#else

    cli_dbgmsg("cli_get_filepath_from_filedesc: No mechanism implemented to determine filename from file descriptor.\n");
    *filepath = NULL;
    status    = CL_BREAK;
    goto done;

#endif

    cli_dbgmsg("cli_get_filepath_from_filedesc: File path for fd [%d] is: %s\n", desc, *filepath);
    status = CL_SUCCESS;

done:

    return status;
}

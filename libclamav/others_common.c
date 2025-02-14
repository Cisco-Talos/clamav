/*
 *  Copyright (C) 2013-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
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
#include "str.h"
#include "platform.h"
#include "regex/regex.h"
#include "matcher-ac.h"
#include "str.h"
#include "entconv.h"
#include "clamav_rust.h"

#define MSGBUFSIZ 8192

static bool rand_seeded            = false;
static unsigned char name_salt[16] = {16, 38, 97, 12, 8, 4, 72, 196, 217, 144, 33, 124, 18, 11, 17, 253};

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

void cli_logg_setup(const cli_ctx *ctx)
{
    pthread_once(&cli_ctx_tls_key_once, cli_ctx_tls_key_alloc);
    pthread_setspecific(cli_ctx_tls_key, ctx);
}

void cli_logg_unsetup(void)
{
    pthread_setspecific(cli_ctx_tls_key, NULL);
}

static inline void *cli_getctx(void)
{
    cli_ctx *ctx;
    pthread_once(&cli_ctx_tls_key_once, cli_ctx_tls_key_alloc);
    ctx = pthread_getspecific(cli_ctx_tls_key);
    return ctx ? ctx->cb_ctx : NULL;
}
#else

static const cli_ctx *current_ctx = NULL;
void cli_logg_setup(const cli_ctx *ctx)
{
    current_ctx = ctx;
}

static inline void *cli_getctx(void)
{
    return current_ctx ? current_ctx->cb_ctx : NULL;
}

void cli_logg_unsetup(void)
{
}
#endif

uint8_t cli_debug_flag              = 0;
uint8_t cli_always_gen_section_hash = 0;

static void clrs_eprint_callback(enum cl_msg severity, const char *fullmsg, const char *msg, void *context)
{
    UNUSEDPARAM(severity);
    UNUSEDPARAM(msg);
    UNUSEDPARAM(context);
    clrs_eprint(fullmsg);
}

static clcb_msg msg_callback = clrs_eprint_callback;

void cl_set_clcb_msg(clcb_msg callback)
{
    msg_callback = callback;
}

#define MSGCODE(buff, len, x)                             \
    va_list args;                                         \
    size_t len = sizeof(x) - 1;                           \
    char buff[MSGBUFSIZ];                                 \
    memcpy(buff, x, len);                                 \
    va_start(args, str);                                  \
    vsnprintf(buff + len, sizeof(buff) - len, str, args); \
    va_end(args)

void cli_warnmsg(const char *str, ...)
{
    MSGCODE(buff, len, "LibClamAV Warning: ");
    msg_callback(CL_MSG_WARN, buff, buff + len, cli_getctx());
}

void cli_errmsg(const char *str, ...)
{
    MSGCODE(buff, len, "LibClamAV Error: ");
    msg_callback(CL_MSG_ERROR, buff, buff + len, cli_getctx());
}

void cli_infomsg(const cli_ctx *ctx, const char *str, ...)
{
    MSGCODE(buff, len, "LibClamAV info: ");
    msg_callback(CL_MSG_INFO_VERBOSE, buff, buff + len, ctx ? ctx->cb_ctx : NULL);
}

/* intended for logging in rust modules */
void cli_infomsg_simple(const char *str, ...)
{
    MSGCODE(buff, len, "LibClamAV info: ");
    msg_callback(CL_MSG_INFO_VERBOSE, buff, buff + len, NULL);
}

inline void cli_dbgmsg(const char *str, ...)
{
    if (UNLIKELY(cli_get_debug_flag())) {
        MSGCODE(buff, len, "LibClamAV debug: ");
        clrs_eprint(buff);
    }
}

void cli_dbgmsg_no_inline(const char *str, ...)
{
    if (UNLIKELY(cli_get_debug_flag())) {
        MSGCODE(buff, len, "LibClamAV debug: ");
        clrs_eprint(buff);
    }
}

size_t cli_eprintf(const char *str, ...)
{
    size_t bytes_written = 0;
    va_list args;
    char buff[MSGBUFSIZ];
    va_start(args, str);
    bytes_written = vsnprintf(buff, sizeof(buff), str, args);
    va_end(args);
    clrs_eprint(buff);

    return bytes_written;
}

int cli_matchregex(const char *str, const char *regex)
{
    regex_t reg;
    int match, flags = REG_EXTENDED | REG_NOSUB;
#ifdef _WIN32
    flags |= REG_ICASE;
#endif
    if (cli_regcomp(&reg, regex, flags) == 0) {
        match = (cli_regexec(&reg, str, 0, NULL, 0) == REG_NOMATCH) ? 0 : 1;
        cli_regfree(&reg);
        return match;
    }

    return 0;
}
void *cli_max_malloc(size_t size)
{
    void *alloc;

    if (0 == size || size > CLI_MAX_ALLOCATION) {
        cli_warnmsg("cli_max_malloc(): File or section is too large to scan (%zu bytes). For your safety, ClamAV limits how much memory an operation can allocate to %d bytes\n",
                    size, CLI_MAX_ALLOCATION);
        return NULL;
    }

    alloc = malloc(size);

    if (!alloc) {
        perror("malloc_problem");
        cli_errmsg("cli_max_malloc(): Can't allocate memory (%zu bytes).\n", size);
        return NULL;
    } else {
        return alloc;
    }
}

void *cli_max_calloc(size_t nmemb, size_t size)
{
    void *alloc;

    if (!nmemb || 0 == size || size > CLI_MAX_ALLOCATION || nmemb > CLI_MAX_ALLOCATION || (nmemb * size > CLI_MAX_ALLOCATION)) {
        cli_warnmsg("cli_max_calloc(): File or section is too large to scan (%zu bytes). For your safety, ClamAV limits how much memory an operation can allocate to %d bytes\n",
                    size, CLI_MAX_ALLOCATION);
        return NULL;
    }

    alloc = calloc(nmemb, size);

    if (!alloc) {
        perror("calloc_problem");
        cli_errmsg("cli_max_calloc(): Can't allocate memory (%lu bytes).\n", (unsigned long int)(nmemb * size));
        return NULL;
    } else {
        return alloc;
    }
}

void *cli_safer_realloc(void *ptr, size_t size)
{
    void *alloc;

    if (0 == size) {
        cli_errmsg("cli_max_realloc(): Attempt to allocate 0 bytes. Please report to https://github.com/Cisco-Talos/clamav/issues\n");
        return NULL;
    }

    alloc = realloc(ptr, size);

    if (!alloc) {
        perror("realloc_problem");
        cli_errmsg("cli_max_realloc(): Can't re-allocate memory to %lu bytes.\n", (unsigned long int)size);
        return NULL;
    } else {
        return alloc;
    }
}

void *cli_safer_realloc_or_free(void *ptr, size_t size)
{
    void *alloc;

    if (0 == size) {
        cli_errmsg("cli_max_realloc_or_free(): Attempt to allocate 0 bytes. Please report to https://github.com/Cisco-Talos/clamav/issues\n");
        return NULL;
    }

    alloc = realloc(ptr, size);

    if (!alloc) {
        perror("realloc_problem");
        cli_errmsg("cli_max_realloc_or_free(): Can't re-allocate memory to %lu bytes.\n", (unsigned long int)size);

        // free the original pointer
        if (ptr) {
            free(ptr);
        }

        return NULL;
    } else {
        return alloc;
    }
}

void *cli_max_realloc(void *ptr, size_t size)
{
    void *alloc;

    if (0 == size || size > CLI_MAX_ALLOCATION) {
        cli_warnmsg("cli_max_realloc(): File or section is too large to scan (%zu bytes). For your safety, ClamAV limits how much memory an operation can allocate to %d bytes\n",
                    size, CLI_MAX_ALLOCATION);
        return NULL;
    }

    alloc = realloc(ptr, size);

    if (!alloc) {
        perror("realloc_problem");
        cli_errmsg("cli_max_realloc(): Can't re-allocate memory to %zu bytes.\n", size);
        return NULL;
    } else {
        return alloc;
    }
}

void *cli_max_realloc_or_free(void *ptr, size_t size)
{
    void *alloc;

    if (0 == size || size > CLI_MAX_ALLOCATION) {
        cli_warnmsg("cli_max_realloc_or_free(): File or section is too large to scan (%zu bytes). For your safety, ClamAV limits how much memory an operation can allocate to %d bytes\n",
                    size, CLI_MAX_ALLOCATION);
        return NULL;
    }

    alloc = realloc(ptr, size);

    if (!alloc) {
        perror("realloc_problem");
        cli_errmsg("cli_max_realloc_or_free(): Can't re-allocate memory to %zu bytes.\n", size);

        // free the original pointer
        if (ptr) {
            free(ptr);
        }

        return NULL;
    } else {
        return alloc;
    }
}

char *cli_safer_strdup(const char *s)
{
    char *alloc;

    if (s == NULL) {
        cli_errmsg("cli_safer_strdup(): passed reference is NULL, nothing to duplicate\n");
        return NULL;
    }

    alloc = strdup(s);

    if (!alloc) {
        perror("strdup_problem");
        cli_errmsg("cli_safer_strdup(): Can't allocate memory (%u bytes).\n", (unsigned int)strlen(s));
        return NULL;
    }

    return alloc;
}

/* returns converted timestamp, in case of error the returned string contains at least one character */
const char *cli_ctime(const time_t *timep, char *buf, const size_t bufsize)
{
    const char *ret;
    if (bufsize < 26) {
        /* standard says we must have at least 26 bytes buffer */
        cli_warnmsg("buffer too small for ctime\n");
        return " ";
    }
    if ((uint32_t)(*timep) > 0x7fffffff) {
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
    if (ret) {
        strncpy(buf, ret, bufsize - 1);
        buf[bufsize - 1] = '\0';
        ret              = buf;
    }
#ifdef CL_THREAD_SAFE
    pthread_mutex_unlock(&cli_ctime_mutex);
#endif
#endif
    /* common */
    if (!ret) {
        buf[0] = ' ';
        buf[1] = '\0';
        return buf;
    }
    return ret;
}

/**
 * @brief  Try hard to read the requested number of bytes
 *
 * @param fd        File descriptor to read from.
 * @param buff      Buffer to read data into.
 * @param count     # of bytes to read.
 * @return size_t   # of bytes read.
 * @return size_t   (size_t)-1 if error.
 */
size_t cli_readn(int fd, void *buff, size_t count)
{
    ssize_t retval;
    size_t todo;
    unsigned char *current;

    todo    = count;
    current = (unsigned char *)buff;

    do {
        retval = read(fd, current, todo);
        if (retval == 0) {
            return (count - todo);
        }
        if (retval < 0) {
            char err[128];
            if (errno == EINTR) {
                continue;
            }
            cli_errmsg("cli_readn: read error: %s\n", cli_strerror(errno, err, sizeof(err)));
            return (size_t)-1;
        }

        if ((size_t)retval > todo) {
            break;
        } else {
            todo -= retval;
        }

        current += retval;
    } while (todo > 0);

    return count;
}

/**
 * @brief  Try hard to write the specified number of bytes
 *
 * @param fd        File descriptor to write to.
 * @param buff      Buffer to write from.
 * @param count     # of bytes to write.
 * @return size_t   # of bytes written
 * @return size_t   (size_t)-1 if error.
 */
size_t cli_writen(int fd, const void *buff, size_t count)
{
    ssize_t retval;
    size_t todo;
    const unsigned char *current;

    if (!buff) {
        cli_errmsg("cli_writen: invalid NULL buff argument\n");
        return (size_t)-1;
    }

    todo    = count;
    current = (const unsigned char *)buff;

    do {
        retval = write(fd, current, todo);
        if (retval < 0) {
            char err[128];
            if (errno == EINTR) {
                continue;
            }
            cli_errmsg("cli_writen: write error: %s\n", cli_strerror(errno, err, sizeof(err)));
            return (size_t)-1;
        }

        if ((size_t)retval > todo) {
            break;
        } else {
            todo -= retval;
        }

        current += retval;
    } while (todo > 0);

    return count;
}

int cli_filecopy(const char *src, const char *dest)
{

#ifdef _WIN32
    return CopyFileA(src, dest, 0) ? 0 : -1;
#else
    char *buffer;
    int s, d;
    size_t bytes;

    if ((s = open(src, O_RDONLY | O_BINARY)) == -1)
        return -1;

    if ((d = open(dest, O_CREAT | O_WRONLY | O_TRUNC | O_BINARY, S_IRUSR | S_IWUSR)) == -1) {
        close(s);
        return -1;
    }

    if (!(buffer = malloc(FILEBUFF))) {
        close(s);
        close(d);
        return -1;
    }

    bytes = cli_readn(s, buffer, FILEBUFF);
    while ((bytes != (size_t)-1) && (bytes != 0)) {
        cli_writen(d, buffer, bytes);
        bytes = cli_readn(s, buffer, FILEBUFF);
    }

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

const char *cli_gettmpdir(void)
{
    const char *tmpdir;
    unsigned int i;

#ifdef _WIN32
    char *envs[] = {"TEMP", "TMP", NULL};
#else
    char *envs[] = {"TMPDIR", NULL};
#endif

    for (i = 0; envs[i] != NULL; i++)
        if ((tmpdir = getenv(envs[i])))
            return tmpdir;

    return P_tmpdir;
}

struct dirent_data {
    char *filename;
    const char *dirname;
    STATBUF *statbuf;
    long ino;   /* -1: inode not available */
    int is_dir; /* 0 - no, 1 - yes */
};

/* sort files before directories, and lower inodes before higher inodes */
static int ftw_compare(const void *a, const void *b)
{
    const struct dirent_data *da = a;
    const struct dirent_data *db = b;
    long diff                    = da->is_dir - db->is_dir;
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
                        STATBUF *statbuf, enum filetype *ft)
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
                if (LSTAT(fname, statbuf) == -1)
                    return -1;
                if (S_ISLNK(statbuf->st_mode)) {
                    *ft = ft_link;
                } else {
                    /* It was not a symlink, stat() not needed */
                    need_stat = 0;
                    stated    = 1;
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
        if (CLAMSTAT(fname, statbuf) == -1)
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
            *ft = S_ISLNK(statbuf->st_mode) ? ft_skipped_link : ft_skipped_special;
        }
    }
    return stated;
}

/**
 * @brief Determine the file type and pass the metadata to the callback as the "reason".
 *
 * The callback may end up doing something or doing nothing, depending on the reason.
 *
 * @param fname         The file path
 * @param flags         CLI_FTW_* bitflag field
 * @param[out] statbuf  the stat metadata for the file.
 * @param[out] stated   1 if statbuf contains stat info, 0 if not. -1 if there was a stat error.
 * @param[out] ft       will indicate if the file was skipped based on the file type.
 * @param callback      the callback (E.g. function that may scan the file)
 * @param data          callback data
 * @return cl_error_t
 */
static cl_error_t handle_filetype(const char *fname, int flags,
                                  STATBUF *statbuf, int *stated, enum filetype *ft,
                                  cli_ftw_cb callback, struct cli_ftw_cbdata *data)
{
    cl_error_t status = CL_EMEM;

    *stated = get_filetype(fname, flags, flags & CLI_FTW_NEED_STAT, statbuf, ft);

    if (*stated == -1) {
        /* we failed a stat() or lstat() */
        char *fname_copy = cli_safer_strdup(fname);
        if (NULL == fname_copy) {
            goto done;
        }

        status = callback(NULL, fname_copy, fname, error_stat, data);
        if (status != CL_SUCCESS) {
            goto done;
        }
        *ft = ft_unknown;
    } else if (*ft == ft_skipped_link || *ft == ft_skipped_special) {
        /* skipped filetype */
        char *fname_copy = cli_safer_strdup(fname);
        if (NULL == fname_copy) {
            goto done;
        }

        status = callback(stated ? statbuf : NULL,
                          fname_copy,
                          fname,
                          *ft == ft_skipped_link ? warning_skipped_link : warning_skipped_special,
                          data);
        if (status != CL_SUCCESS)
            goto done;
    }

    status = CL_SUCCESS;

done:
    return status;
}

static cl_error_t cli_ftw_dir(const char *dirname, int flags, int maxdepth, cli_ftw_cb callback, struct cli_ftw_cbdata *data, cli_ftw_pathchk pathchk);
static int handle_entry(struct dirent_data *entry, int flags, int maxdepth, cli_ftw_cb callback, struct cli_ftw_cbdata *data, cli_ftw_pathchk pathchk)
{
    if (!entry->is_dir) {
        return callback(entry->statbuf, entry->filename, entry->filename, visit_file, data);
    } else {
        return cli_ftw_dir(entry->dirname, flags, maxdepth, callback, data, pathchk);
    }
}

cl_error_t cli_ftw(char *path, int flags, int maxdepth, cli_ftw_cb callback, struct cli_ftw_cbdata *data, cli_ftw_pathchk pathchk)
{
    cl_error_t status = CL_EMEM;
    STATBUF statbuf;
    enum filetype ft               = ft_unknown;
    struct dirent_data entry       = {0};
    int stated                     = 0;
    char *filename_for_callback    = NULL;
    char *filename_for_handleentry = NULL;

    if (((flags & CLI_FTW_TRIM_SLASHES) || pathchk) && path[0] && path[1]) {
        char *pathend;
        /* trim slashes so that dir and dir/ behave the same when
         * they are symlinks, and we are not following symlinks */
#ifndef _WIN32
        while (path[0] == *PATHSEP && path[1] == *PATHSEP) path++;
#endif
        pathend = path + strlen(path);
        while (pathend > path && pathend[-1] == *PATHSEP) --pathend;
        *pathend = '\0';
    }

    if (pathchk && pathchk(path, data) == 1) {
        status = CL_SUCCESS;
        goto done;
    }

    /* Determine if the file should be skipped (special file or symlink).
       This will also get the stat metadata. */
    status = handle_filetype(path, flags, &statbuf, &stated, &ft, callback, data);
    if (status != CL_SUCCESS) {
        goto done;
    }

    /* Bail out if the file should be skipped. */
    if (ft_skipped(ft)) {
        status = CL_SUCCESS;
        goto done;
    }

    entry.statbuf = stated ? &statbuf : NULL;
    entry.is_dir  = ft == ft_directory;

    /*
     * handle_entry() doesn't call the callback for directories, so we'll call it now first.
     */
    if (entry.is_dir) {
        /* Allocate the filename for the callback function. TODO: this FTW code is spaghetti, refactor. */
        filename_for_callback = cli_safer_strdup(path);
        if (NULL == filename_for_callback) {
            goto done;
        }

        status = callback(entry.statbuf, filename_for_callback, path, visit_directory_toplev, data);

        filename_for_callback = NULL; // free'd by the callback

        if (status != CL_SUCCESS) {
            goto done;
        }
    }

    /*
     * Now call handle_entry() to either call the callback for files,
     * or recurse deeper into the file tree walk.
     * TODO: Recursion is bad, this whole thing should be iterative
     */
    if (entry.is_dir) {
        entry.dirname = path;
    } else {
        /* Allocate the filename for the callback function within the handle_entry function. TODO: this FTW code is spaghetti, refactor. */
        filename_for_handleentry = cli_safer_strdup(path);
        if (NULL == filename_for_handleentry) {
            goto done;
        }

        entry.filename = filename_for_handleentry;
    }
    status = handle_entry(&entry, flags, maxdepth, callback, data, pathchk);

    filename_for_handleentry = NULL; // free'd by the callback call in handle_entry()

done:
    if (NULL != filename_for_callback) {
        /* Free-check just in case someone injects additional calls and error handling before callback(). */
        free(filename_for_callback);
    }
    if (NULL != filename_for_handleentry) {
        /* Free-check just in case someone injects additional calls and error handling before handle_entry(). */
        free(filename_for_handleentry);
    }
    return status;
}

static cl_error_t cli_ftw_dir(const char *dirname, int flags, int maxdepth, cli_ftw_cb callback, struct cli_ftw_cbdata *data, cli_ftw_pathchk pathchk)
{
    DIR *dd;
    struct dirent_data *entries = NULL;
    size_t i, entries_cnt = 0;
    cl_error_t ret;

    if (maxdepth < 0) {
        /* exceeded recursion limit */
        ret = callback(NULL, NULL, dirname, warning_skipped_dir, data);
        return ret;
    }

    if ((dd = opendir(dirname)) != NULL) {
        struct dirent *dent;
        errno = 0;
        ret   = CL_SUCCESS;
        while ((dent = readdir(dd))) {
            int stated = 0;
            enum filetype ft;
            char *fname;
            STATBUF statbuf;
            STATBUF *statbufp;

            if (!strcmp(dent->d_name, ".") || !strcmp(dent->d_name, ".."))
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
            fname = (char *)cli_max_malloc(strlen(dirname) + strlen(dent->d_name) + 2);
            if (!fname) {
                ret = callback(NULL, NULL, dirname, error_mem, data);
                if (ret != CL_SUCCESS)
                    break;
                continue; /* have to skip this one if continuing after error */
            }
            if (!strcmp(dirname, PATHSEP))
                sprintf(fname, PATHSEP "%s", dent->d_name);
            else
                sprintf(fname, "%s" PATHSEP "%s", dirname, dent->d_name);

            if (pathchk && pathchk(fname, data) == 1) {
                free(fname);
                continue;
            }

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
                statbufp = malloc(sizeof(*statbufp));
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
            entries = cli_max_realloc(entries, entries_cnt * sizeof(*entries));
            if (!entries) {
                ret = callback(stated ? &statbuf : NULL, NULL, fname, error_mem, data);
                free(fname);
                if (statbufp)
                    free(statbufp);
                break;
            } else {
                struct dirent_data *entry = &entries[entries_cnt - 1];
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
        closedir(dd);
        ret = CL_SUCCESS;

        if (entries) {
            cli_qsort(entries, entries_cnt, sizeof(*entries), ftw_compare);
            for (i = 0; i < entries_cnt; i++) {
                struct dirent_data *entry = &entries[i];
                ret                       = handle_entry(entry, flags, maxdepth - 1, callback, data, pathchk);
                if (entry->is_dir)
                    free(entry->filename);
                if (entry->statbuf)
                    free(entry->statbuf);
                if (ret != CL_SUCCESS) {
                    /* Something went horribly wrong, Skip the rest of the files */
                    cli_errmsg("File tree walk aborted.\n");
                    break;
                }
            }
            for (i++; i < entries_cnt; i++) {
                struct dirent_data *entry = &entries[i];
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
const char *cli_strerror(int errnum, char *buf, size_t len)
{
    const char *err;
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

static char *cli_md5buff(const unsigned char *buffer, unsigned int len, unsigned char *dig)
{
    unsigned char digest[16] = {0};
    char *md5str, *pt;
    int i;

    cl_hash_data("md5", buffer, len, digest, NULL);

    if (dig)
        memcpy(dig, digest, 16);

    if (!(md5str = (char *)cli_max_calloc(32 + 1, sizeof(char))))
        return NULL;

    pt = md5str;
    for (i = 0; i < 16; i++) {
        sprintf(pt, "%02x", digest[i]);
        pt += 2;
    }

    return md5str;
}

unsigned int cli_rndnum(unsigned int max)
{
    if (!rand_seeded) { /* minimizes re-seeding after the first call to cli_gentemp() */
        struct timeval tv;
        gettimeofday(&tv, (struct timezone *)0);
        srand(tv.tv_usec + clock() + rand());
        rand_seeded = true;
    }

    return 1 + (unsigned int)(max * (rand() / (1.0 + RAND_MAX)));
}

char *cli_sanitize_filepath(const char *filepath, size_t filepath_len, char **sanitized_filebase)
{
    uint32_t depth           = 0;
    size_t index             = 0;
    size_t sanitized_index   = 0;
    char *sanitized_filepath = NULL;

    if ((NULL == filepath) || (0 == filepath_len) || (PATH_MAX < filepath_len)) {
        goto done;
    }

    if (NULL != sanitized_filebase) {
        *sanitized_filebase = NULL;
    }

    sanitized_filepath = cli_max_calloc(filepath_len + 1, sizeof(unsigned char));
    if (NULL == sanitized_filepath) {
        cli_dbgmsg("cli_sanitize_filepath: out of memory\n");
        goto done;
    }

    while (index < filepath_len) {
        char *next_pathsep = NULL;

        if (0 == strncmp(filepath + index, PATHSEP, strlen(PATHSEP))) {
            /*
             * Is "/" (or "\\" on Windows)
             */
            /* Skip leading pathsep in absolute path, or extra pathsep) */
            index += strlen(PATHSEP);
            continue;
        } else if (0 == strncmp(filepath + index, "." PATHSEP, strlen("." PATHSEP))) {
            /*
             * Is "./" (or ".\\" on Windows)
             */
            /* Current directory indicator is meaningless and should not add to the depth. Skip it. */
            index += strlen("." PATHSEP);
            continue;
        } else if (0 == strncmp(filepath + index, ".." PATHSEP, strlen(".." PATHSEP))) {
            /*
             * Is "../" (or "..\\" on Windows)
             */
            if (depth == 0) {
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
#ifdef _WIN32
            /*
             * Windows' POSIX style API's accept both "/" and "\\" style path separators.
             * The following checks using POSIX style path separators on Windows.
             */
        } else if (0 == strncmp(filepath + index, "/", strlen("/"))) {
            /*
             * Is "/".
             */
            /* Skip leading pathsep in absolute path, or extra pathsep) */
            index += strlen("/");
            continue;
        } else if (0 == strncmp(filepath + index, "./", strlen("./"))) {
            /*
             * Is "./"
             */
            /* Current directory indicator is meaningless and should not add to the depth. Skip it. */
            index += strlen("./");
            continue;
        } else if (0 == strncmp(filepath + index, "../", strlen("../"))) {
            /*
             * Is "../"
             */
            if (depth == 0) {
                /* Relative path would traverse parent directory. Skip it. */
                index += strlen("../");
                continue;
            } else {
                /* Relative path is safe. Allow it. */
                strncpy(sanitized_filepath + sanitized_index, filepath + index, strlen("../"));
                sanitized_index += strlen("../");
                index += strlen("../");
                depth--;

                /* Convert path separator to Windows separator */
                sanitized_filepath[sanitized_index - 1] = '\\';
            }
#endif
        } else {
            /*
             * Is not "/", "./", or "../".
             */

            /* Find the next path separator. */
#ifdef _WIN32
            char *next_windows_pathsep = NULL;
#endif
            next_pathsep = CLI_STRNSTR(filepath + index, "/", filepath_len - index);

#ifdef _WIN32
            /* Check for both types of separators. */
            next_windows_pathsep = CLI_STRNSTR(filepath + index, "\\", filepath_len - index);
            if (NULL != next_windows_pathsep) {
                if ((NULL == next_pathsep) || (next_windows_pathsep < next_pathsep)) {
                    next_pathsep = next_windows_pathsep;
                }
            }
#endif
            if (NULL == next_pathsep) {
                /* No more path separators, copy the rest (filename) into the sanitized path */
                strncpy(sanitized_filepath + sanitized_index, filepath + index, filepath_len - index);

                if (NULL != sanitized_filebase) {
                    /* Set output variable to point to the file base name */
                    *sanitized_filebase = sanitized_filepath + sanitized_index;
                }
                break;
            }
            next_pathsep += strlen(PATHSEP); /* Include the path separator in the copy */

            /* Copy next directory name into the sanitized path */
            strncpy(sanitized_filepath + sanitized_index, filepath + index, next_pathsep - (filepath + index));
            sanitized_index += next_pathsep - (filepath + index);
            index += next_pathsep - (filepath + index);
            depth++;

#ifdef _WIN32
            /* Convert path separator to Windows separator */
            sanitized_filepath[sanitized_index - 1] = '\\';
#endif
        }
    }

done:
    if ((NULL != sanitized_filepath) && (0 == strlen(sanitized_filepath))) {
        free(sanitized_filepath);
        sanitized_filepath = NULL;
        if (NULL != sanitized_filebase) {
            *sanitized_filebase = NULL;
        }
    }

    return sanitized_filepath;
}

#define SHORT_HASH_LENGTH 10
char *cli_genfname(const char *prefix)
{
    char *sanitized_prefix      = NULL;
    char *sanitized_prefix_base = NULL;
    char *fname                 = NULL;
    unsigned char salt[16 + 32];
    char *tmp;
    int i;
    size_t len;

    if (prefix && (strlen(prefix) > 0)) {
        sanitized_prefix = cli_sanitize_filepath(prefix, strlen(prefix), &sanitized_prefix_base);
    }
    if (NULL != sanitized_prefix_base) {
        len = strlen(sanitized_prefix_base) + strlen(".") + SHORT_HASH_LENGTH + 1; /* {prefix}.{SHORT_HASH_LENGTH}\0 */
    } else {
        len = strlen("clamav-") + 48 + strlen(".tmp") + 1; /* clamav-{48}.tmp\0 */
    }

    fname = (char *)cli_max_calloc(len, sizeof(char));
    if (!fname) {
        cli_dbgmsg("cli_genfname: no memory left for fname\n");
        if (NULL != sanitized_prefix) {
            free(sanitized_prefix);
        }
        return NULL;
    }

#ifdef CL_THREAD_SAFE
    pthread_mutex_lock(&cli_gentemp_mutex);
#endif

    memcpy(salt, name_salt, 16);

    for (i = 16; i < 48; i++)
        salt[i] = cli_rndnum(255);

    tmp = cli_md5buff(salt, 48, name_salt);

#ifdef CL_THREAD_SAFE
    pthread_mutex_unlock(&cli_gentemp_mutex);
#endif

    if (NULL == tmp) {
        free(fname);
        if (NULL != sanitized_prefix) {
            free(sanitized_prefix);
        }
        cli_dbgmsg("cli_genfname: no memory left for cli_md5buff output\n");
        return NULL;
    }

    if (NULL != sanitized_prefix_base) {
        snprintf(fname, len, "%s.%.*s", sanitized_prefix_base, SHORT_HASH_LENGTH, tmp);
    } else {
        snprintf(fname, len, "clamav-%s.tmp", tmp);
    }

    if (NULL != sanitized_prefix) {
        free(sanitized_prefix);
    }
    free(tmp);

    return (fname);
}

char *cli_newfilepath(const char *dir, const char *fname)
{
    char *fullpath;
    const char *mdir;
    size_t len;

    mdir = dir ? dir : cli_gettmpdir();

    if (NULL == fname) {
        cli_dbgmsg("cli_newfilepath('%s'): fname argument must not be NULL\n", mdir);
        return NULL;
    }

    len      = strlen(mdir) + strlen(PATHSEP) + strlen(fname) + 1; /* mdir/fname\0 */
    fullpath = (char *)cli_max_calloc(len, sizeof(char));
    if (NULL == fullpath) {
        cli_dbgmsg("cli_newfilepath('%s'): out of memory\n", mdir);
        return NULL;
    }

    snprintf(fullpath, len, "%s" PATHSEP "%s", mdir, fname);

    return (fullpath);
}

cl_error_t cli_newfilepathfd(const char *dir, char *fname, char **name, int *fd)
{
    if (NULL == name || NULL == fname || NULL == fd) {
        cli_dbgmsg("cli_newfilepathfd('%s'): invalid NULL arguments\n", dir);
        return CL_EARG;
    }

    *name = cli_newfilepath(dir, fname);
    if (!*name) {
        cli_dbgmsg("cli_newfilepathfd('%s'): out of memory\n", dir);
        return CL_EMEM;
    }

    *fd = open(*name, O_RDWR | O_CREAT | O_TRUNC | O_BINARY | O_EXCL, S_IRUSR | S_IWUSR);
    /*
     * EEXIST is almost impossible to occur, so we just treat it as other
     * errors
     */
    if (*fd == -1) {
        cli_errmsg("cli_newfilepathfd: Can't create file %s: %s\n", *name, strerror(errno));
        free(*name);
        *name = NULL;
        return CL_ECREAT;
    }

    return CL_SUCCESS;
}

char *cli_gentemp_with_prefix(const char *dir, const char *prefix)
{
    char *fname;
    char *fullpath;
    const char *mdir;
    size_t len;

    mdir = dir ? dir : cli_gettmpdir();

    fname = cli_genfname(prefix);
    if (!fname) {
        cli_dbgmsg("cli_gentemp_with_prefix('%s'): out of memory\n", mdir);
        return NULL;
    }

    len      = strlen(mdir) + strlen(PATHSEP) + strlen(fname) + 1; /* mdir/fname\0 */
    fullpath = (char *)cli_max_calloc(len, sizeof(char));
    if (!fullpath) {
        free(fname);
        cli_dbgmsg("cli_gentemp_with_prefix('%s'): out of memory\n", mdir);
        return NULL;
    }

    snprintf(fullpath, len, "%s" PATHSEP "%s", mdir, fname);
    free(fname);

    return (fullpath);
}

char *cli_gentemp(const char *dir)
{
    return cli_gentemp_with_prefix(dir, NULL);
}

cl_error_t cli_gentempfd(const char *dir, char **name, int *fd)
{
    return cli_gentempfd_with_prefix(dir, NULL, name, fd);
}

cl_error_t cli_gentempfd_with_prefix(const char *dir, const char *prefix, char **name, int *fd)
{
    *name = cli_gentemp_with_prefix(dir, prefix);
    if (!*name)
        return CL_EMEM;

    *fd = open(*name, O_RDWR | O_CREAT | O_TRUNC | O_BINARY | O_EXCL, S_IRUSR | S_IWUSR);
    /*
     * EEXIST is almost impossible to occur, so we just treat it as other
     * errors
     */
    if (*fd == -1) {
        if ((EILSEQ == errno) || (EINVAL == errno) || (ENAMETOOLONG == errno)) {
            cli_dbgmsg("cli_gentempfd_with_prefix: Can't create temp file using prefix. Using a randomly generated name instead.\n");
            free(*name);
            *name = cli_gentemp(dir);
            if (!*name)
                return CL_EMEM;
            *fd = open(*name, O_RDWR | O_CREAT | O_TRUNC | O_BINARY | O_EXCL, S_IRUSR | S_IWUSR);
            if (*fd == -1) {
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

int cli_regcomp(regex_t *preg, const char *pattern, int cflags)
{
    if (!strncmp(pattern, "(?i)", 4)) {
        pattern += 4;
        cflags |= REG_ICASE;
    }
    return cli_regcomp_real(preg, pattern, cflags);
}

#ifdef _WIN32
cl_error_t cli_get_filepath_from_handle(HANDLE hFile, char **filepath)
{
    cl_error_t status               = CL_EARG;
    char *evaluated_filepath        = NULL;
    DWORD dwRet                     = 0;
    WCHAR *long_evaluated_filepathW = NULL;
    char *long_evaluated_filepathA  = NULL;
    size_t evaluated_filepath_len   = 0;
    cl_error_t conv_result;

    if (NULL == filepath) {
        cli_errmsg("cli_get_filepath_from_handle: Invalid args.\n");
        goto done;
    }

    dwRet = GetFinalPathNameByHandleW((HANDLE)hFile, NULL, 0, VOLUME_NAME_DOS);
    if (dwRet == 0) {
        cli_dbgmsg("cli_get_filepath_from_handle: Failed to resolve handle\n");
        status = CL_EOPEN;
        goto done;
    }

    long_evaluated_filepathW = calloc(dwRet + 1, sizeof(WCHAR));
    if (NULL == long_evaluated_filepathW) {
        cli_errmsg("cli_get_filepath_from_filedesc: Failed to allocate %u bytes to store filename\n", dwRet + 1);
        status = CL_EMEM;
        goto done;
    }

    dwRet = GetFinalPathNameByHandleW((HANDLE)hFile, long_evaluated_filepathW, dwRet + 1, VOLUME_NAME_DOS);
    if (dwRet == 0) {
        cli_dbgmsg("cli_get_filepath_from_handle: Failed to resolve handle\n");
        status = CL_EOPEN;
        goto done;
    }

    if (0 == wcsncmp(L"\\\\?\\UNC", long_evaluated_filepathW, wcslen(L"\\\\?\\UNC"))) {
        conv_result = cli_codepage_to_utf8(
            (char *)long_evaluated_filepathW,
            (wcslen(long_evaluated_filepathW)) * sizeof(WCHAR),
            CODEPAGE_UTF16_LE,
            &evaluated_filepath,
            &evaluated_filepath_len);
        if (CL_SUCCESS != conv_result) {
            cli_errmsg("cli_get_filepath_from_handle: Failed to convert UTF16_LE filename to UTF8\n", dwRet + 1);
            status = CL_EOPEN;
            goto done;
        }
    } else {
        conv_result = cli_codepage_to_utf8(
            (char *)long_evaluated_filepathW + wcslen(L"\\\\?\\") * sizeof(WCHAR),
            (wcslen(long_evaluated_filepathW) - wcslen(L"\\\\?\\")) * sizeof(WCHAR),
            CODEPAGE_UTF16_LE,
            &evaluated_filepath,
            &evaluated_filepath_len);
        if (CL_SUCCESS != conv_result) {
            cli_errmsg("cli_get_filepath_from_handle: Failed to convert UTF16_LE filename to UTF8\n", dwRet + 1);
            status = CL_EOPEN;
            goto done;
        }
    }

    cli_dbgmsg("cli_get_filepath_from_handle: File path for handle %p is: %s\n", (void *)hFile, evaluated_filepath);
    status    = CL_SUCCESS;
    *filepath = evaluated_filepath;

done:
    if (NULL != long_evaluated_filepathW) {
        free(long_evaluated_filepathW);
    }
    return status;
}
#endif

cl_error_t cli_get_filepath_from_filedesc(int desc, char **filepath)
{
    cl_error_t status        = CL_EARG;
    char *evaluated_filepath = NULL;

#ifdef __linux__
    char fname[PATH_MAX];

    char link[32];
    ssize_t linksz;

    memset(&fname, 0, PATH_MAX);

    if (NULL == filepath) {
        cli_errmsg("cli_get_filepath_from_filedesc: Invalid args.\n");
        goto done;
    }

    snprintf(link, sizeof(link), "/proc/self/fd/%u", desc);
    link[sizeof(link) - 1] = '\0';

    if (-1 == (linksz = readlink(link, fname, PATH_MAX - 1))) {
        cli_dbgmsg("cli_get_filepath_from_filedesc: Failed to resolve filename for descriptor %d (%s)\n", desc, link);
        status = CL_EOPEN;
        goto done;
    }

    /* Success. Add null terminator */
    fname[linksz] = '\0';

    evaluated_filepath = CLI_STRNDUP(fname, CLI_STRNLEN(fname, PATH_MAX));
    if (NULL == evaluated_filepath) {
        cli_errmsg("cli_get_filepath_from_filedesc: Failed to allocate memory to store filename\n");
        status = CL_EMEM;
        goto done;
    }

#elif C_DARWIN

    char fname[PATH_MAX];
    memset(&fname, 0, PATH_MAX);

    if (NULL == filepath) {
        cli_errmsg("cli_get_filepath_from_filedesc: Invalid args.\n");
        goto done;
    }

    if (fcntl(desc, F_GETPATH, &fname) < 0) {
        cli_dbgmsg("cli_get_filepath_from_filedesc: Failed to resolve filename for descriptor %d\n", desc);
        status = CL_EOPEN;
        goto done;
    }

    evaluated_filepath = CLI_STRNDUP(fname, CLI_STRNLEN(fname, PATH_MAX));
    if (NULL == evaluated_filepath) {
        cli_errmsg("cli_get_filepath_from_filedesc: Failed to allocate memory to store filename\n");
        status = CL_EMEM;
        goto done;
    }

#elif _WIN32
    intptr_t hFile = _get_osfhandle(desc);
    cl_error_t handle_result;

    if (NULL == filepath) {
        cli_errmsg("cli_get_filepath_from_filedesc: Invalid args.\n");
        goto done;
    }

    handle_result = cli_get_filepath_from_handle((HANDLE)hFile, &evaluated_filepath);
    if (CL_SUCCESS != handle_result) {
        cli_errmsg("cli_get_filepath_from_filedesc: Failed to get file path from handle\n");
        status = CL_EOPEN;
        goto done;
    }

#else

    cli_dbgmsg("cli_get_filepath_from_filedesc: No mechanism implemented to determine filename from file descriptor.\n");
    status = CL_BREAK;
    goto done;

#endif

    cli_dbgmsg("cli_get_filepath_from_filedesc: File path for fd [%d] is: %s\n", desc, evaluated_filepath);
    status    = CL_SUCCESS;
    *filepath = evaluated_filepath;

done:
    return status;
}

cl_error_t cli_realpath(const char *file_name, char **real_filename)
{
    char *real_file_path = NULL;
    cl_error_t status    = CL_EARG;
#ifdef _WIN32
    HANDLE hFile   = INVALID_HANDLE_VALUE;
    wchar_t *wpath = NULL;
    WIN32_FILE_ATTRIBUTE_DATA attrs;

#elif C_DARWIN
    int fd = -1;
#endif

    cli_dbgmsg("Checking realpath of %s\n", file_name);

    if (NULL == file_name || NULL == real_filename) {
        cli_warnmsg("cli_realpath: Invalid arguments.\n");
        goto done;
    }

#ifdef _WIN32

    wpath = uncpath(file_name);
    if (!wpath) {
        errno = ENOMEM;
        return -1;
    }

    hFile = CreateFileW(wpath,                      // file to open
                        GENERIC_READ,               // open for reading
                        FILE_SHARE_READ,            // share for reading
                        NULL,                       // default security
                        OPEN_EXISTING,              // existing file only
                        FILE_FLAG_BACKUP_SEMANTICS, // may be a directory
                        NULL);                      // no attr. template
    if (hFile == INVALID_HANDLE_VALUE) {
        cli_warnmsg("Can't open file %s: %d\n", file_name, GetLastError());
        status = CL_EOPEN;
        goto done;
    }

    status = cli_get_filepath_from_handle(hFile, &real_file_path);

#elif C_DARWIN

    /* Using the filepath from filedesc method on macOS because
       realpath will fail to check the realpath of a symbolic link if
       the link doesn't point to anything.
       Plus, we probably don't wan tot follow the link in this case anyways,
       so this will check the realpath of the link, and not of the thing the
       link points to. */
    fd = open(file_name, O_RDONLY | O_SYMLINK);
    if (fd == -1) {
        char err[128];
        cli_strerror(errno, err, sizeof(err));
        if (errno == EACCES) {
            status = CL_EACCES;
        } else {
            status = CL_EOPEN;
        }
        cli_dbgmsg("Can't open file %s: %s\n", file_name, err);
        goto done;
    }

    status = cli_get_filepath_from_filedesc(fd, &real_file_path);

#else

    real_file_path = realpath(file_name, NULL);
    if (NULL == real_file_path) {
        status = CL_EMEM;
        goto done;
    }

    status = CL_SUCCESS;

#endif

    *real_filename = real_file_path;

done:

#ifdef _WIN32
    if (hFile != INVALID_HANDLE_VALUE) {
        CloseHandle(hFile);
    }
    if (NULL != wpath) {
        free(wpath);
    }
#elif C_DARWIN
    if (fd != -1) {
        close(fd);
    }
#endif

    return status;
}

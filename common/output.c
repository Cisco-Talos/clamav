/*
 *  Copyright (C) 2013-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *
 *  Authors: Tomasz Kojm
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
 */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <fcntl.h>
#include <time.h>
#include <sys/stat.h>
#include <errno.h>
#ifndef _WIN32
#include <sys/time.h>
#include <sys/socket.h>
#endif
#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif

#if defined(USE_SYSLOG) && !defined(C_AIX)
#include <syslog.h>
#endif

// libclamav
#include "clamav.h"
#include "others.h"
#include "str.h"

#include "output.h"

// Define O_NOFOLLOW for systems that don't have it.
// Notably, Windows doesn't have O_NOFOLLOW.
#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif

#ifdef CL_THREAD_SAFE
#include <pthread.h>
pthread_mutex_t logg_mutex     = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t mdprintf_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif

#if defined(C_LINUX) && defined(HAVE_LIBINTL_H)
#include <libintl.h>
#include <locale.h>

#define gettext_noop(s) s
#define _(s) gettext(s)
#define N_(s) gettext_noop(s)

#else

#define _(s) s
#define N_(s) s

#endif

FILE *logg_fp = NULL;

short int logg_verbose = 0, logg_nowarn = 0, logg_lock = 1, logg_time = 0, logg_foreground = 1, logg_noflush = 0, logg_rotate = 0;
off_t logg_size       = 0;
const char *logg_file = NULL;
#if defined(USE_SYSLOG) && !defined(C_AIX)
short logg_syslog;
#endif

short int mprintf_disabled = 0, mprintf_verbose = 0, mprintf_quiet = 0,
          mprintf_stdout = 0, mprintf_nowarn = 0, mprintf_send_timeout = 100, mprintf_progress = 0;

#define ARGLEN(args, str, len)                     \
    {                                              \
        size_t arglen = 1, i;                      \
        char *pt;                                  \
        va_start(args, str);                       \
        len = strlen(str);                         \
        for (i = 0; i < len - 1; i++) {            \
            if (str[i] == '%') {                   \
                switch (str[++i]) {                \
                    case 's':                      \
                        pt = va_arg(args, char *); \
                        if (pt)                    \
                            arglen += strlen(pt);  \
                        break;                     \
                    case 'f':                      \
                        va_arg(args, double);      \
                        arglen += 25;              \
                        break;                     \
                    case 'l':                      \
                        va_arg(args, long);        \
                        arglen += 20;              \
                        break;                     \
                    default:                       \
                        va_arg(args, int);         \
                        arglen += 10;              \
                        break;                     \
                }                                  \
            }                                      \
        }                                          \
        va_end(args);                              \
        len += arglen;                             \
    }

int mdprintf(int desc, const char *str, ...)
{
    va_list args;
    char buffer[512], *abuffer = NULL, *buff;
    int bytes, todo, ret = 0;
    size_t len;

    ARGLEN(args, str, len);
    if (len <= sizeof(buffer)) {
        len  = sizeof(buffer);
        buff = buffer;
    } else {
        abuffer = malloc(len);
        if (!abuffer) {
            len  = sizeof(buffer);
            buff = buffer;
        } else {
            buff = abuffer;
        }
    }
    va_start(args, str);
    bytes = vsnprintf(buff, len, str, args);
    va_end(args);
    buff[len - 1] = 0;

    if (bytes < 0) {
        if (len > sizeof(buffer))
            free(abuffer);
        return bytes;
    }
    if ((size_t)bytes >= len)
        bytes = len - 1;

    todo = bytes;
#ifdef CL_THREAD_SAFE
    /* make sure we don't mix sends from multiple threads,
     * important for IDSESSION */
    pthread_mutex_lock(&mdprintf_mutex);
#endif
    while (todo > 0) {
        ret = send(desc, buff, bytes, 0);
        if (ret < 0) {
            struct timeval tv;
            if (errno != EWOULDBLOCK)
                break;
                /* didn't send anything yet */
#ifdef CL_THREAD_SAFE
            pthread_mutex_unlock(&mdprintf_mutex);
#endif
            tv.tv_sec  = 0;
            tv.tv_usec = mprintf_send_timeout * 1000;
            do {
                fd_set wfds;
                FD_ZERO(&wfds);
                FD_SET(desc, &wfds);
                ret = select(desc + 1, NULL, &wfds, NULL, &tv);
            } while (ret < 0 && errno == EINTR);
#ifdef CL_THREAD_SAFE
            pthread_mutex_lock(&mdprintf_mutex);
#endif
            if (!ret) {
                /* timed out */
                ret = -1;
                break;
            }
        } else {
            todo -= ret;
            buff += ret;
        }
    }
#ifdef CL_THREAD_SAFE
    pthread_mutex_unlock(&mdprintf_mutex);
#endif

    if (len > sizeof(buffer))
        free(abuffer);

    return ret < 0 ? -1 : bytes;
}

static int rename_logg(STATBUF *sb)
{
    char *rotate_file;
    size_t rotate_file_len;
    time_t t;
    struct tm tmp;

    if (!logg_rotate) {
        if (logg_fp) {
            fprintf(logg_fp, "Log size = %lld, max = %lld\n", (long long int)sb->st_size, (long long int)logg_size);
            fprintf(logg_fp, "WARNING: Log size limit met but log file rotation turned off. Forcing log file rotation anyways.\n");
        }

        logg_rotate = 1;
    }

    rotate_file_len = strlen(logg_file) + strlen("-YYYY-MM-DD_HH:MM:SS.log");
    rotate_file     = calloc(1, rotate_file_len + 1);
    if (!rotate_file) {
        if (logg_fp)
            fprintf(logg_fp, "Need to rotate log file due to size but ran out of memory.\n");

        return -1;
    }

    t = time(NULL);

#ifdef _WIN32
    if (0 != localtime_s(&tmp, &t)) {
#else
    if (!localtime_r(&t, &tmp)) {
#endif
        if (logg_fp)
            fprintf(logg_fp, "Need to rotate log file due to size but could not get local time.\n");

        free(rotate_file);
        return -1;
    }

    strcpy(rotate_file, logg_file);
    strftime(rotate_file + strlen(rotate_file) - strlen(".log"), rotate_file_len - strlen(rotate_file), "-%Y%m%d_%H%M%S.log", &tmp);

    if (logg_fp) {
        fclose(logg_fp);
        logg_fp = NULL;
    }

#ifdef _WIN32
    if (0 == MoveFileA(logg_file, rotate_file)) {
        fprintf(stderr, "Failed to rename file with error code: %d\n", GetLastError());
#else
    if (rename(logg_file, rotate_file)) {
#endif
        free(rotate_file);
        return -1;
    }

    free(rotate_file);
    return 0;
}

static int logg_open(void)
{
    STATBUF sb;

    if (logg_file)
        if (logg_size > 0)
            if (CLAMSTAT(logg_file, &sb) != -1)
                if (sb.st_size > logg_size)
                    if (rename_logg(&sb))
                        return -1;

    return 0;
}

void logg_close(void)
{
#if defined(USE_SYSLOG) && !defined(C_AIX)
    if (logg_syslog)
        closelog();
#endif

#ifdef CL_THREAD_SAFE
    pthread_mutex_lock(&logg_mutex);
#endif
    if (logg_fp) {
        fclose(logg_fp);
        logg_fp = NULL;
    }
#ifdef CL_THREAD_SAFE
    pthread_mutex_unlock(&logg_mutex);
#endif
}

int logg(loglevel_t loglevel, const char *str, ...)
{
    va_list args;
    char buffer[1025], *abuffer = NULL, *buff;
    time_t currtime;
    size_t len;
#ifdef F_WRLCK
    struct flock fl;
#endif

    if ((loglevel == LOGG_DEBUG_NV && logg_verbose < 2) ||
        (loglevel == LOGG_DEBUG && !logg_verbose))
        return 0;

    ARGLEN(args, str, len);
    if (len <= sizeof(buffer)) {
        len  = sizeof(buffer);
        buff = buffer;
    } else {
        abuffer = malloc(len);
        if (!abuffer) {
            len  = sizeof(buffer);
            buff = buffer;
        } else {
            buff = abuffer;
        }
    }
    va_start(args, str);
    vsnprintf(buff, len, str, args);
    va_end(args);
    buff[len - 1] = 0;

#ifdef CL_THREAD_SAFE
    pthread_mutex_lock(&logg_mutex);
#endif

    logg_open();

    if (!logg_fp && logg_file) {
        int logg_file_fd = -1;

        logg_file_fd = open(logg_file, O_WRONLY | O_CREAT | O_APPEND | O_NOFOLLOW, 0640);
        if (-1 == logg_file_fd) {
            char errbuf[128];
            cli_strerror(errno, errbuf, sizeof(errbuf));
            printf("ERROR: Failed to open log file %s: %s\n", logg_file, errbuf);

#ifdef CL_THREAD_SAFE
            pthread_mutex_unlock(&logg_mutex);
#endif
            if (abuffer)
                free(abuffer);
            return -1;
        }

        logg_fp = fdopen(logg_file_fd, "at");
        if (NULL == logg_fp) {
            char errbuf[128];
            cli_strerror(errno, errbuf, sizeof(errbuf));
            printf("ERROR: Failed to convert the open log file descriptor for %s to a FILE* handle: %s\n", logg_file, errbuf);

            close(logg_file_fd);
#ifdef CL_THREAD_SAFE
            pthread_mutex_unlock(&logg_mutex);
#endif
            if (abuffer)
                free(abuffer);
            return -1;
        }

#ifdef F_WRLCK
        if (logg_lock) {
            memset(&fl, 0, sizeof(fl));
            fl.l_type = F_WRLCK;
            if (fcntl(fileno(logg_fp), F_SETLK, &fl) == -1) {
#ifdef EOPNOTSUPP
                if (errno == EOPNOTSUPP)
                    printf("WARNING: File locking not supported (NFS?)\n");
                else
#endif
                {
                    char errbuf[128];
                    cli_strerror(errno, errbuf, sizeof(errbuf));
                    printf("ERROR: Failed to lock the log file %s: %s\n", logg_file, errbuf);

#ifdef CL_THREAD_SAFE
                    pthread_mutex_unlock(&logg_mutex);
#endif
                    fclose(logg_fp);
                    logg_fp = NULL;
                    if (abuffer)
                        free(abuffer);
                    return -1;
                }
            }
        }
#endif
    }

    if (logg_fp) {
        char flush = !logg_noflush;
        /* Need to avoid logging time for verbose messages when logverbose
               is not set or we get a bunch of timestamps in the log without
               newlines... */
        if (logg_time && ((loglevel != LOGG_DEBUG) || logg_verbose)) {
            char timestr[32];
            time(&currtime);
            cli_ctime(&currtime, timestr, sizeof(timestr));
            /* cut trailing \n */
            timestr[strlen(timestr) - 1] = '\0';
            fprintf(logg_fp, "%s -> ", timestr);
        }

        if (loglevel == LOGG_ERROR) {
            fprintf(logg_fp, "ERROR: %s", buff);
            flush = 1;
        } else if (loglevel == LOGG_WARNING) {
            if (!logg_nowarn)
                fprintf(logg_fp, "WARNING: %s", buff);
            flush = 1;
        } else if (loglevel == LOGG_DEBUG || loglevel == LOGG_DEBUG_NV) {
            fprintf(logg_fp, "%s", buff);
        } else if (loglevel == LOGG_INFO_NF || loglevel == LOGG_INFO) {
            fprintf(logg_fp, "%s", buff);
        } else
            fprintf(logg_fp, "%s", buff);

        if (flush)
            fflush(logg_fp);
    }

    if (logg_foreground) {
        if (loglevel != LOGG_INFO_NF) {
            if (logg_time) {
                char timestr[32];
                time(&currtime);
                cli_ctime(&currtime, timestr, sizeof(timestr));
                /* cut trailing \n */
                timestr[strlen(timestr) - 1] = '\0';
                mprintf(loglevel, "%s -> %s", timestr, buff);
            } else {
                mprintf(loglevel, "%s", buff);
            }
        }
    }

#if defined(USE_SYSLOG) && !defined(C_AIX)
    if (logg_syslog) {
        cli_chomp(buff);
        if (loglevel == LOGG_ERROR) {
            syslog(LOG_ERR, "%s", buff);
        } else if (loglevel == LOGG_WARNING) {
            if (!logg_nowarn)
                syslog(LOG_WARNING, "%s", buff);
        } else if (loglevel == LOGG_DEBUG || loglevel == LOGG_DEBUG_NV) {
            syslog(LOG_DEBUG, "%s", buff);
        } else
            syslog(LOG_INFO, "%s", buff);
    }
#endif

#ifdef CL_THREAD_SAFE
    pthread_mutex_unlock(&logg_mutex);
#endif

    if (abuffer)
        free(abuffer);

    return 0;
}

void mprintf(loglevel_t loglevel, const char *str, ...)
{
    va_list args;
    FILE *fd;
    char buffer[512], *abuffer = NULL, *buff;
    size_t len;

    if (mprintf_disabled)
        return;

    fd = stdout;

    ARGLEN(args, str, len);
    if (len <= sizeof(buffer)) {
        len  = sizeof(buffer);
        buff = buffer;
    } else {
        abuffer = malloc(len);
        if (!abuffer) {
            len  = sizeof(buffer);
            buff = buffer;
        } else {
            buff = abuffer;
        }
    }
    va_start(args, str);
    vsnprintf(buff, len, str, args);
    va_end(args);
    buff[len - 1] = 0;

    if (loglevel == LOGG_ERROR) {
        if (!mprintf_stdout)
            fd = stderr;
        fprintf(fd, "ERROR: %s", buff);
    } else if (!mprintf_quiet) {
        if (loglevel == LOGG_WARNING) {
            if (!mprintf_nowarn) {
                if (!mprintf_stdout)
                    fd = stderr;
                fprintf(fd, "WARNING: %s", buff);
            }
        } else if (loglevel == LOGG_DEBUG) {
            if (mprintf_verbose)
                fprintf(fd, "%s", buff);
        } else if (loglevel == LOGG_INFO) {
            fprintf(fd, "%s", buff);
        } else
            fprintf(fd, "%s", buff);
    }

    if (fd == stdout)
        fflush(stdout);

    if (len > sizeof(buffer))
        free(abuffer);
}

struct facstruct {
    const char *name;
    int code;
};

#if defined(USE_SYSLOG) && !defined(C_AIX)
static const struct facstruct facilitymap[] = {
#ifdef LOG_AUTH
    {"LOG_AUTH", LOG_AUTH},
#endif
#ifdef LOG_AUTHPRIV
    {"LOG_AUTHPRIV", LOG_AUTHPRIV},
#endif
#ifdef LOG_CRON
    {"LOG_CRON", LOG_CRON},
#endif
#ifdef LOG_DAEMON
    {"LOG_DAEMON", LOG_DAEMON},
#endif
#ifdef LOG_FTP
    {"LOG_FTP", LOG_FTP},
#endif
#ifdef LOG_KERN
    {"LOG_KERN", LOG_KERN},
#endif
#ifdef LOG_LPR
    {"LOG_LPR", LOG_LPR},
#endif
#ifdef LOG_MAIL
    {"LOG_MAIL", LOG_MAIL},
#endif
#ifdef LOG_NEWS
    {"LOG_NEWS", LOG_NEWS},
#endif
#ifdef LOG_AUTH
    {"LOG_AUTH", LOG_AUTH},
#endif
#ifdef LOG_SYSLOG
    {"LOG_SYSLOG", LOG_SYSLOG},
#endif
#ifdef LOG_USER
    {"LOG_USER", LOG_USER},
#endif
#ifdef LOG_UUCP
    {"LOG_UUCP", LOG_UUCP},
#endif
#ifdef LOG_LOCAL0
    {"LOG_LOCAL0", LOG_LOCAL0},
#endif
#ifdef LOG_LOCAL1
    {"LOG_LOCAL1", LOG_LOCAL1},
#endif
#ifdef LOG_LOCAL2
    {"LOG_LOCAL2", LOG_LOCAL2},
#endif
#ifdef LOG_LOCAL3
    {"LOG_LOCAL3", LOG_LOCAL3},
#endif
#ifdef LOG_LOCAL4
    {"LOG_LOCAL4", LOG_LOCAL4},
#endif
#ifdef LOG_LOCAL5
    {"LOG_LOCAL5", LOG_LOCAL5},
#endif
#ifdef LOG_LOCAL6
    {"LOG_LOCAL6", LOG_LOCAL6},
#endif
#ifdef LOG_LOCAL7
    {"LOG_LOCAL7", LOG_LOCAL7},
#endif
    {NULL, -1}};

int logg_facility(const char *name)
{
    int i;

    for (i = 0; facilitymap[i].name; i++)
        if (!strcmp(facilitymap[i].name, name))
            return facilitymap[i].code;

    return -1;
}
#endif

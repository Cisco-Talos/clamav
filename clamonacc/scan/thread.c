/*
 *  Copyright (C) 2015-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *
 *  Authors: Mickey Sola
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
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#include <pthread.h>

#if defined(HAVE_SYS_FANOTIFY_H)
#include <sys/fanotify.h>
#endif

// libclamav
#include "others.h"

// common
#include "optparser.h"
#include "output.h"

#include "../misc/priv_fts.h"
#include "../misc/utils.h"
#include "../client/client.h"
#include "thread.h"

static pthread_mutex_t onas_scan_lock = PTHREAD_MUTEX_INITIALIZER;

static int onas_scan(struct onas_scan_event *event_data, const char *fname, STATBUF sb, int *infected, int *err, cl_error_t *ret_code);
static cl_error_t onas_scan_safe(struct onas_scan_event *event_data, const char *fname, STATBUF sb, int *infected, int *err, cl_error_t *ret_code);
static cl_error_t onas_scan_thread_scanfile(struct onas_scan_event *event_data, const char *fname, STATBUF sb, int *infected, int *err, cl_error_t *ret_code);
static cl_error_t onas_scan_thread_handle_dir(struct onas_scan_event *event_data, const char *pathname);
static cl_error_t onas_scan_thread_handle_file(struct onas_scan_event *event_data, const char *pathname);

/**
 * @brief Safe-scan wrapper, originally used by inotify and fanotify threads, now exists for error checking/convenience.
 *
 * Owned by scanthread to try to force multithreaded client architecture which better avoids kernel level deadlocks from
 * fanotify blocking/prevention.
 */
static int onas_scan(struct onas_scan_event *event_data, const char *fname, STATBUF sb, int *infected, int *err, cl_error_t *ret_code)
{
    int ret                = 0;
    int i                  = 0;
    uint8_t retry_on_error = event_data->bool_opts & ONAS_SCTH_B_RETRY_ON_E;

    ret = onas_scan_safe(event_data, fname, sb, infected, err, ret_code);

    if (*err) {
        switch (*ret_code) {
            case CL_EACCES:
            case CL_ESTAT:
                logg(LOGG_DEBUG, "ClamMisc: Scan issue; Daemon could not find or access: %s)\n", fname);
                break;
                /* TODO: handle other errors */
            case CL_EPARSE:
                logg(LOGG_INFO, "ClamMisc: Internal issue; Failed to parse reply from daemon: %s)\n", fname);
                break;
            case CL_EREAD:
            case CL_EWRITE:
            case CL_EMEM:
            case CL_ENULLARG:
            case CL_ERROR:
            default:
                logg(LOGG_INFO, "ClamMisc: Unexpected issue; Daemon failed to scan: %s\n", fname);
        }
        if (retry_on_error) {
            logg(LOGG_DEBUG, "ClamMisc: reattempting scan ... \n");
            while (*err) {
                ret = onas_scan_safe(event_data, fname, sb, infected, err, ret_code);

                i++;
                if (*err && i == event_data->retry_attempts) {
                    *err = 0;
                }
            }
        }
    }

    return ret;
}

/**
 * @brief Thread-safe scan wrapper to ensure there's no process contention over use of the socket.
 *
 * This is noticeably slower, and I had no issues running smaller scale tests with it off, but better than sorry until more testing can be done.
 *
 * TODO: make this configurable?
 */
static cl_error_t onas_scan_safe(struct onas_scan_event *event_data, const char *fname, STATBUF sb, int *infected, int *err, cl_error_t *ret_code)
{

    int ret = 0;
    int fd  = -1;

#if defined(HAVE_SYS_FANOTIFY_H)
    uint8_t b_fanotify;

    b_fanotify = event_data->bool_opts & ONAS_SCTH_B_FANOTIFY ? 1 : 0;

    if (b_fanotify) {
        fd = event_data->fmd->fd;
    }
#endif

    pthread_mutex_lock(&onas_scan_lock);

    ret = onas_client_scan(event_data->tcpaddr, event_data->portnum, event_data->scantype, event_data->maxstream,
                           fname, fd, event_data->timeout, sb, infected, err, ret_code);

    pthread_mutex_unlock(&onas_scan_lock);

    return ret;
}

static cl_error_t onas_scan_thread_scanfile(struct onas_scan_event *event_data, const char *fname, STATBUF sb, int *infected, int *err, cl_error_t *ret_code)
{

#if defined(HAVE_SYS_FANOTIFY_H)
    struct fanotify_response res;
    uint8_t b_fanotify;
#endif

    int ret = 0;

    uint8_t b_scan;
    uint8_t b_deny_on_error;

    if (NULL == event_data || NULL == fname || NULL == infected || NULL == err || NULL == ret_code) {
        logg(LOGG_ERROR, "ClamWorker: scan failed (NULL arg given)\n");
        return CL_ENULLARG;
    }

    b_scan          = event_data->bool_opts & ONAS_SCTH_B_SCAN ? 1 : 0;
    b_deny_on_error = event_data->bool_opts & ONAS_SCTH_B_DENY_ON_E ? 1 : 0;

#if defined(HAVE_SYS_FANOTIFY_H)
    b_fanotify = event_data->bool_opts & ONAS_SCTH_B_FANOTIFY ? 1 : 0;
    if (b_fanotify) {
        res.fd       = event_data->fmd->fd;
        res.response = FAN_ALLOW;
    }
#endif

    if (b_scan) {
        ret = onas_scan(event_data, fname, sb, infected, err, ret_code);

        if (*err && *ret_code != CL_SUCCESS) {
            logg(LOGG_DEBUG, "ClamWorker: scan failed with error code %d\n", *ret_code);
        }

#if defined(HAVE_SYS_FANOTIFY_H)
        if (b_fanotify) {
            if ((*err && *ret_code && b_deny_on_error) || *infected) {
                res.response = FAN_DENY;
            }
        }
#endif
    }

#if defined(HAVE_SYS_FANOTIFY_H)
    if (b_fanotify) {
        if (event_data->fmd->mask & FAN_ALL_PERM_EVENTS) {
            ret = write(event_data->fan_fd, &res, sizeof(res));
            if (ret == -1) {
                logg(LOGG_ERROR, "ClamWorker: internal error (can't write to fanotify)\n");
                if (errno == ENOENT) {
                    logg(LOGG_DEBUG, "ClamWorker: permission event has already been written ... recovering ...\n");
                } else {
                    ret = CL_EWRITE;
                }
            }
        }
    }

    if (b_fanotify) {

#ifdef ONAS_DEBUG
        logg(LOGG_DEBUG, "ClamWorker: closing fd, %d)\n", event_data->fmd->fd);
#endif
        if (-1 == close(event_data->fmd->fd)) {

            logg(LOGG_ERROR, "ClamWorker: internal error (can't close fanotify meta fd, %d)\n", event_data->fmd->fd);
            if (errno == EBADF) {
                logg(LOGG_DEBUG, "ClamWorker: fd already closed ... recovering ...\n");
            } else {
                ret = CL_EUNLINK;
            }
        }
    }
#endif
    return ret;
}

static cl_error_t onas_scan_thread_handle_dir(struct onas_scan_event *event_data, const char *pathname)
{
    FTS *ftsp        = NULL;
    int32_t ftspopts = FTS_NOCHDIR | FTS_PHYSICAL | FTS_XDEV;
    FTSENT *curr     = NULL;

    int32_t infected    = 0;
    int32_t err         = 0;
    cl_error_t ret_code = CL_SUCCESS;
    cl_error_t ret      = CL_SUCCESS;

    int32_t fres = 0;
    STATBUF sb;

    char *const pathargv[] = {(char *)pathname, NULL};

    if (!(ftsp = _priv_fts_open(pathargv, ftspopts, NULL))) {
        ret = CL_EOPEN;
        goto out;
    }

    while ((curr = _priv_fts_read(ftsp))) {
        if (curr->fts_info != FTS_D) {

            fres = CLAMSTAT(curr->fts_path, &sb);

            if (event_data->sizelimit) {
                if (fres != 0 || (uint64_t)sb.st_size > event_data->sizelimit) {
                    /* okay to skip w/o allow/deny since dir comes from inotify
                     * events and (probably) won't block w/ protection enabled */
                    event_data->bool_opts &= ((uint16_t)~ONAS_SCTH_B_SCAN);
                    logg(LOGG_DEBUG, "ClamWorker: size limit surpassed while doing extra scanning ... skipping object ...\n");
                }
            }

            ret = onas_scan_thread_scanfile(event_data, curr->fts_path, sb, &infected, &err, &ret_code);
        }
    }

out:
    if (ftsp) {
        _priv_fts_close(ftsp);
    }

    return ret;
}

static cl_error_t onas_scan_thread_handle_file(struct onas_scan_event *event_data, const char *pathname)
{

    STATBUF sb;
    int32_t infected    = 0;
    int32_t err         = 0;
    cl_error_t ret_code = CL_SUCCESS;
    int fres            = 0;
    cl_error_t ret      = 0;

    if (NULL == pathname || NULL == event_data) {
        return CL_ENULLARG;
    }

    fres = CLAMSTAT(pathname, &sb);
    if (event_data->sizelimit) {
        if (fres != 0 || (uint64_t)sb.st_size > event_data->sizelimit) {
            /* don't skip so we avoid lockups, but don't scan either;
             * while it should be obvious, this will unconditionally set
             * the bit in the map to 0 regardless of original orientation */
            event_data->bool_opts &= ((uint16_t)~ONAS_SCTH_B_SCAN);
        }
    }

    ret = onas_scan_thread_scanfile(event_data, pathname, sb, &infected, &err, &ret_code);

#ifdef ONAS_DEBUG
    /* very noisy, debug only */
    if (event_data->bool_opts & ONAS_SCTH_B_INOTIFY) {
        logg(LOGG_DEBUG, "ClamWorker: Inotify Scan Results ...\n\tret = %d ...\n\tinfected = %d ...\n\terr = %d ...\n\tret_code = %d\n",
             ret, infected, err, ret_code);
    } else {
        logg(LOGG_DEBUG, "ClamWorker: Fanotify Scan Results ...\n\tret = %d ...\n\tinfected = %d ...\n\terr = %d ...\n\tret_code = %d\n\tfd = %d\n",
             ret, infected, err, ret_code, event_data->fmd->fd);
    }
#endif

    return ret;
}

/**
 * @brief worker thread designed to work with the lovely c-thread-pool library to handle our scanning jobs after our queue thread consumes an event
 *
 * @param arg this should always be an onas_scan_event struct
 */
void *onas_scan_worker(void *arg)
{

    struct onas_scan_event *event_data = (struct onas_scan_event *)arg;

    uint8_t b_dir;
    uint8_t b_file;
    uint8_t b_inotify;
    uint8_t b_fanotify;

    if (NULL == event_data || NULL == event_data->pathname) {
        logg(LOGG_INFO, "ClamWorker: invalid worker arguments for scanning thread\n");
        if (event_data) {
            logg(LOGG_INFO, "ClamWorker: pathname is null\n");
        }
        goto done;
    }

    /* load in boolean info from event struct; makes for easier reading--you're welcome */
    b_dir      = event_data->bool_opts & ONAS_SCTH_B_DIR ? 1 : 0;
    b_file     = event_data->bool_opts & ONAS_SCTH_B_FILE ? 1 : 0;
    b_inotify  = event_data->bool_opts & ONAS_SCTH_B_INOTIFY ? 1 : 0;
    b_fanotify = event_data->bool_opts & ONAS_SCTH_B_FANOTIFY ? 1 : 0;

#if defined(HAVE_SYS_FANOTIFY_H)
    if (b_inotify) {
        logg(LOGG_DEBUG, "ClamWorker: handling inotify event ...\n");

        if (b_dir) {
            logg(LOGG_DEBUG, "ClamWorker: performing (extra) scanning on directory '%s'\n", event_data->pathname);
            onas_scan_thread_handle_dir(event_data, event_data->pathname);
        } else if (b_file) {
            logg(LOGG_DEBUG, "ClamWorker: performing (extra) scanning on file '%s'\n", event_data->pathname);
            onas_scan_thread_handle_file(event_data, event_data->pathname);
        }

    } else if (b_fanotify) {

        logg(LOGG_DEBUG, "ClamWorker: performing scanning on file '%s'\n", event_data->pathname);
        onas_scan_thread_handle_file(event_data, event_data->pathname);
    } else {
        /* something went very wrong, so check if we have an open fd,
         * try to close it to resolve any potential lingering permissions event,
         * then move to cleanup */
        if (event_data->fmd) {
            if (event_data->fmd->fd >= 0) {
                close(event_data->fmd->fd);
                goto done;
            }
        }
    }
#endif
done:
    /* our job to cleanup event data: worker queue just kicks us off in a thread pool, drops the event object
     * from the queue and forgets about us */

    if (NULL != event_data) {
        if (NULL != event_data->pathname) {
            free(event_data->pathname);
            event_data->pathname = NULL;
        }

#if defined(HAVE_SYS_FANOTIFY_H)
        if (NULL != event_data->fmd) {
            free(event_data->fmd);
            event_data->fmd = NULL;
        }
#endif
        free(event_data);
        event_data = NULL;
    }

    return NULL;
}

/**
 * @brief Simple utility function for external interfaces to add relevant context information to scan_event struct.
 *
 * Doing this mapping cuts down significantly on memory overhead when queueing hundreds of these scan_event structs
 * especially vs using a copy of a raw context struct.
 *
 * Other potential design options include giving the event access to the "global" context struct address instead,
 * to further cut down on space used, but (among other thread safety concerns) I'd prefer the worker threads not
 * have the ability to modify it at all to keep down on potential maintenance headaches in the future.
 */
cl_error_t onas_map_context_info_to_event_data(struct onas_context *ctx, struct onas_scan_event **event_data)
{

    if (NULL == ctx || NULL == event_data || NULL == *event_data) {
        logg(LOGG_DEBUG, "ClamScThread: context and scan event struct are null ...\n");
        return CL_ENULLARG;
    }

    (*event_data)->scantype       = ctx->scantype;
    (*event_data)->timeout        = ctx->timeout;
    (*event_data)->maxstream      = ctx->maxstream;
    (*event_data)->fan_fd         = ctx->fan_fd;
    (*event_data)->sizelimit      = ctx->sizelimit;
    (*event_data)->retry_attempts = ctx->retry_attempts;

    if (ctx->retry_on_error) {
        (*event_data)->bool_opts |= ONAS_SCTH_B_RETRY_ON_E;
    }

    if (ctx->deny_on_error) {
        (*event_data)->bool_opts |= ONAS_SCTH_B_DENY_ON_E;
    }

    if (ctx->isremote) {
        (*event_data)->bool_opts |= ONAS_SCTH_B_REMOTE;
        (*event_data)->tcpaddr = optget(ctx->clamdopts, "TCPAddr")->strarg;
        (*event_data)->portnum = ctx->portnum;
    } else {
        (*event_data)->tcpaddr = optget(ctx->clamdopts, "LocalSocket")->strarg;
    }

    return CL_SUCCESS;
}

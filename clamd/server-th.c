/*
 *  Copyright (C) 2013-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *
 *  Authors: Tomasz Kojm, Trog, Török Edvin
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

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <pthread.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#ifndef _WIN32
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <arpa/inet.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <fcntl.h>
#ifdef C_SOLARIS
#include <stdio_ext.h>
#endif

// libclamav
#include "clamav.h"
#include "others.h"
#include "readdb.h"
#include "default.h"

// common
#include "output.h"
#include "optparser.h"
#include "misc.h"
#include "idmef_logging.h"

#include "server.h"
#include "thrmgr.h"
#include "session.h"
#include "clamd_others.h"
#include "shared.h"

#define BUFFSIZE 1024

typedef enum {
    RELOAD_STAGE__IDLE,
    RELOAD_STAGE__RELOADING,
    RELOAD_STAGE__NEW_DB_AVAILABLE,
} reload_stage_t;

struct reload_th_t {
    struct cl_settings *settings;
    char *dbdir;
    unsigned int dboptions;
};

/*
 * Global variables
 */

int progexit                 = 0;
pthread_mutex_t exit_mutex   = PTHREAD_MUTEX_INITIALIZER;
int reload                   = 0;
time_t reloaded_time         = 0;
pthread_mutex_t reload_mutex = PTHREAD_MUTEX_INITIALIZER;
int sighup                   = 0;

static pthread_mutex_t reload_stage_mutex = PTHREAD_MUTEX_INITIALIZER;
static reload_stage_t reload_stage        = RELOAD_STAGE__IDLE; /* protected by reload_stage_mutex */
struct cl_engine *g_newengine             = NULL;               /* protected by reload_stage_mutex */

extern pthread_mutex_t logg_mutex;
static struct cl_stat dbstat;

void *event_wake_recv   = NULL;
void *event_wake_accept = NULL;

static void scanner_thread(void *arg)
{
    client_conn_t *conn = (client_conn_t *)arg;
#ifndef _WIN32
    sigset_t sigset;
#endif
    int ret;
    int virus = 0, errors = 0;

#ifndef _WIN32
    /* ignore all signals */
    sigfillset(&sigset);
    /* The behavior of a process is undefined after it ignores a
     * SIGFPE, SIGILL, SIGSEGV, or SIGBUS signal */
    sigdelset(&sigset, SIGFPE);
    sigdelset(&sigset, SIGILL);
    sigdelset(&sigset, SIGSEGV);
#ifdef SIGBUS
    sigdelset(&sigset, SIGBUS);
#endif
    sigdelset(&sigset, SIGTSTP);
    sigdelset(&sigset, SIGCONT);
    pthread_sigmask(SIG_SETMASK, &sigset, NULL);
#endif

    ret = command(conn, &virus);
    if (ret == -1) {
        pthread_mutex_lock(&exit_mutex);
        progexit = 1;
        pthread_mutex_unlock(&exit_mutex);
        errors = 1;
    } else
        errors = ret;

    thrmgr_setactiveengine(NULL);

    if (conn->filename)
        free(conn->filename);
    logg(LOGG_DEBUG_NV, "Finished scanthread\n");
    enum thrmgr_exit exit_code;
    if (virus != 0) {
        exit_code = EXIT_OTHER;
    } else if (errors != 0) {
        exit_code = EXIT_ERROR;
    } else {
        exit_code = EXIT_OK;
    }
    if (thrmgr_group_finished(conn->group, exit_code)) {
        logg(LOGG_DEBUG_NV, "Scanthread: connection shut down (FD %d)\n", conn->sd);
        /* close connection if we were last in group */
        shutdown(conn->sd, 2);
        closesocket(conn->sd);
    }
    cl_engine_free(conn->engine);
    free(conn);
    return;
}

static int syncpipe_wake_recv_w = -1;

void sighandler_th(int sig)
{
    int action = 0;
    switch (sig) {
        case SIGINT:
        case SIGTERM:
            progexit = 1;
            action   = 1;
            break;

#ifdef SIGHUP
        case SIGHUP:
            sighup = 1;
            action = 1;
            break;
#endif

#ifdef SIGUSR2
        case SIGUSR2:
            reload = 1;
            action = 1;
            break;
#endif

        default:
            break; /* Take no action on other signals - e.g. SIGPIPE */
    }
    /* a signal doesn't always wake poll(), for example on FreeBSD */
    if (action && syncpipe_wake_recv_w != -1)
        if (write(syncpipe_wake_recv_w, "", 1) != 1)
            logg(LOGG_DEBUG_NV, "Failed to write to syncpipe\n");
}

static int need_db_reload(void)
{
    if (!dbstat.entries) {
        logg(LOGG_INFO, "No stats for Database check - forcing reload\n");
        return TRUE;
    }
    if (cl_statchkdir(&dbstat) == 1) {
        logg(LOGG_INFO, "SelfCheck: Database modification detected. Forcing reload.\n");
        return TRUE;
    }
    logg(LOGG_INFO, "SelfCheck: Database status OK.\n");
    return FALSE;
}

/**
 * @brief Thread entry point to load the signature databases & compile a new scanning engine.
 *
 * Once loaded, an event will be set to indicate that the new engine is ready.
 *
 * @param arg   A reload_th_t structure defining the db directory, db settings, engine settings.
 * @return void*
 */
static void *reload_th(void *arg)
{
    cl_error_t status = CL_EMALFDB;

    struct reload_th_t *rldata = arg;
    struct cl_engine *engine   = NULL;
    unsigned int sigs          = 0;
    int retval;

    if (NULL == rldata || NULL == rldata->dbdir || NULL == rldata->settings) {
        logg(LOGG_ERROR, "reload_th: Invalid arguments, unable to load signature databases.\n");
        status = CL_EARG;
        goto done;
    }

    logg(LOGG_INFO, "Reading databases from %s\n", rldata->dbdir);

    if (NULL == (engine = cl_engine_new())) {
        logg(LOGG_ERROR, "reload_th: Can't initialize antivirus engine\n");
        goto done;
    }

    retval = cl_engine_settings_apply(engine, rldata->settings);
    if (CL_SUCCESS != retval) {
        logg(LOGG_ERROR, "reload_th: Failed to apply previous engine settings: %s\n", cl_strerror(retval));
        status = CL_EMEM;
        goto done;
    }

    retval = cl_load(rldata->dbdir, engine, &sigs, rldata->dboptions);
    if (CL_SUCCESS != retval) {
        logg(LOGG_ERROR, "reload_th: Database load failed: %s\n", cl_strerror(retval));
        goto done;
    }

    retval = cl_engine_compile(engine);
    if (CL_SUCCESS != retval) {
        logg(LOGG_ERROR, "reload_th: Database initialization error: can't compile engine: %s\n", cl_strerror(retval));
        goto done;
    }

    logg(LOGG_INFO, "Database correctly reloaded (%u signatures)\n", sigs);
    status = CL_SUCCESS;

done:

    if (NULL != rldata) {
        if (NULL != rldata->settings) {
            cl_engine_settings_free(rldata->settings);
        }
        if (NULL != rldata->dbdir) {
            free(rldata->dbdir);
        }
        free(rldata);
    }

    if (CL_SUCCESS != status) {
        if (NULL != engine) {
            cl_engine_free(engine);
            engine = NULL;
        }
    }

    pthread_mutex_lock(&reload_stage_mutex);
    reload_stage = RELOAD_STAGE__NEW_DB_AVAILABLE; /* New DB available */
    g_newengine  = engine;
    pthread_mutex_unlock(&reload_stage_mutex);

#ifdef _WIN32
    SetEvent(event_wake_recv);
#else
    if (syncpipe_wake_recv_w != -1)
        if (write(syncpipe_wake_recv_w, "", 1) != 1)
            logg(LOGG_DEBUG_NV, "Failed to write to syncpipe\n");
#endif

    return NULL;
}

/**
 * @brief Reload the database.
 *
 * @param[in,out] engine    The current scan engine, used to copy the settings.
 * @param dboptions         The current database options, used to copy the options.
 * @param opts              The command line options, used to get the database directory.
 * @return cl_error_t       CL_SUCCESS if the reload thread was successfully started. This does not mean that the database has reloaded successfully.
 */
static cl_error_t reload_db(struct cl_engine **engine, unsigned int dboptions, const struct optstruct *opts, threadpool_t *thr_pool)
{
    cl_error_t status = CL_EMALFDB;
    cl_error_t retval;
    struct reload_th_t *rldata = NULL;
    pthread_t th;
    pthread_attr_t th_attr;

    if (NULL == opts || NULL == engine) {
        logg(LOGG_ERROR, "reload_db: Invalid arguments, unable to load signature databases.\n");
        status = CL_EARG;
        goto done;
    }

    rldata = malloc(sizeof(struct reload_th_t));
    if (!rldata) {
        logg(LOGG_ERROR, "Failed to allocate reload context\n");
        status = CL_EMEM;
        goto done;
    }
    memset(rldata, 0, sizeof(struct reload_th_t));

    rldata->dboptions = dboptions;

    if (*engine) {
        /* copy current settings */
        rldata->settings = cl_engine_settings_copy(*engine);
        if (!rldata->settings) {
            logg(LOGG_ERROR, "Can't make a copy of the current engine settings\n");
            goto done;
        }
    }

    rldata->dbdir = strdup(optget(opts, "DatabaseDirectory")->strarg);
    if (!rldata->dbdir) {
        logg(LOGG_ERROR, "Can't duplicate the database directory path\n");
        goto done;
    }

    if (dbstat.entries) {
        cl_statfree(&dbstat);
    }
    memset(&dbstat, 0, sizeof(struct cl_stat));

    retval = cl_statinidir(rldata->dbdir, &dbstat);
    if (CL_SUCCESS != retval) {
        logg(LOGG_ERROR, "cl_statinidir() failed: %s\n", cl_strerror(retval));
        goto done;
    }

    if (*engine) {
        if (!optget(opts, "ConcurrentDatabaseReload")->enabled) {
            /*
             * If concurrent reload disabled, we'll NULL out the current engine and deref it.
             * It will only actually be free'd once the last scan finishes.
             */
            thrmgr_setactiveengine(NULL);
            cl_engine_free(*engine);
            *engine = NULL;

            /* Wait for all scans to finish */
            thrmgr_wait_for_threads(thr_pool);
        }
    }

    if (pthread_attr_init(&th_attr)) {
        logg(LOGG_ERROR, "Failed to init reload thread attributes\n");
        goto done;
    }

    if (optget(opts, "ConcurrentDatabaseReload")->enabled) {
        /* For concurrent reloads: set detached, so we don't leak thread resources */
        pthread_attr_setdetachstate(&th_attr, PTHREAD_CREATE_DETACHED);
    }

    retval = pthread_create(&th, &th_attr, reload_th, rldata);
    if (pthread_attr_destroy(&th_attr))
        logg(LOGG_WARNING, "Failed to release reload thread attributes\n");
    if (retval) {
        logg(LOGG_ERROR, "Failed to spawn reload thread\n");
        goto done;
    }

    if (!optget(opts, "ConcurrentDatabaseReload")->enabled) {
        /* For non-concurrent reloads: join the thread */
        int join_ret = pthread_join(th, NULL);
        switch (join_ret) {
            case 0:
                logg(LOGG_INFO, "Database reload completed.\n");
                break;

            case EDEADLK:
                logg(LOGG_ERROR, "A deadlock was detected when waiting for the database reload thread.\n");
                goto done;

            case ESRCH:
                logg(LOGG_ERROR, "Failed to find database reload thread.\n");
                goto done;

            case EINVAL:
                logg(LOGG_ERROR, "The database reload thread is not a joinable thread.\n");
                goto done;

            default:
                logg(LOGG_ERROR, "An unknown error occurred when waiting for the database reload thread: %d\n", join_ret);
                goto done;
        }
    }

    status = CL_SUCCESS;

done:

    if (CL_SUCCESS != status) {
        /*
         * Failed to spawn reload thread, so we're responsible for cleaning up
         * the rldata structure.
         */
        if (NULL != rldata) {
            if (NULL != rldata->settings) {
                cl_engine_settings_free(rldata->settings);
            }
            if (NULL != rldata->dbdir) {
                free(rldata->dbdir);
            }
            free(rldata);
        }
    }

    return status;
}

/*
 * zCOMMANDS are delimited by \0
 * nCOMMANDS are delimited by \n
 * Old-style non-prefixed commands are one packet, optionally delimited by \n,
 * with trailing \r|\n ignored
 */
static const char *get_cmd(struct fd_buf *buf, size_t off, size_t *len, char *term, int *oldstyle)
{
    char *pos;
    if (!buf->off || off >= buf->off) {
        *len = 0;
        return NULL;
    }

    *term = '\n';
    switch (buf->buffer[off]) {
        /* commands terminated by delimiters */
        case 'z':
            *term = '\0';
            /* fall-through */
        case 'n':
            pos = memchr(buf->buffer + off, *term, buf->off - off);
            if (!pos) {
                /* we don't have another full command yet */
                *len = 0;
                return NULL;
            }
            *pos = '\0';
            if (*term) {
                *len = cli_chomp(buf->buffer + off);
            } else {
                *len = pos - buf->buffer - off;
            }
            *oldstyle = 0;
            return buf->buffer + off + 1;
        default:
            /* one packet = one command */
            if (off)
                return NULL;
            pos = memchr(buf->buffer, '\n', buf->off);
            if (pos) {
                *len = pos - buf->buffer;
                *pos = '\0';
            } else {
                *len                  = buf->off;
                buf->buffer[buf->off] = '\0';
            }
            cli_chomp(buf->buffer);
            *oldstyle = 1;
            return buf->buffer;
    }
}

int statinidir(const char *dirname)
{
    if (!dbstat.entries) {
        memset(&dbstat, 0, sizeof(dbstat));
    }

    return cl_statinidir(dirname, &dbstat);
}

struct acceptdata {
    struct fd_data fds;
    struct fd_data recv_fds;
    pthread_cond_t cond_nfds;
    unsigned initial_fds;
    int max_queue;
    int commandtimeout;
    int syncpipe_wake_recv[2];
    int syncpipe_wake_accept[2];
};

#define ACCEPTDATA_INIT(mutex1, mutex2)                                                  \
    {                                                                                    \
        FDS_INIT(mutex1), FDS_INIT(mutex2), PTHREAD_COND_INITIALIZER, 0, 0, 0, {-1, -1}, \
        {                                                                                \
            -1, -1                                                                       \
        }                                                                                \
    }

static void *acceptloop_th(void *arg)
{
    char buff[BUFFSIZE + 1];
    size_t i;
    struct acceptdata *data  = (struct acceptdata *)arg;
    struct fd_data *fds      = &data->fds;
    struct fd_data *recv_fds = &data->recv_fds;
    int max_queue            = data->max_queue;
    int commandtimeout       = data->commandtimeout;

    pthread_mutex_lock(fds->buf_mutex);
    for (;;) {
        /* Block waiting for data to become available for reading */
        int new_sd = fds_poll_recv(fds, -1, 0, event_wake_accept);
#ifdef _WIN32
        ResetEvent(event_wake_accept);
#endif
        /* TODO: what about sockets that get rm-ed? */
        if (!fds->nfds) {
            /* no more sockets to poll, all gave an error */
            logg(LOGG_ERROR, "Main socket gone: fatal\n");
            break;
        }

        if (new_sd == -1 && errno != EINTR) {
            logg(LOGG_ERROR, "Failed to poll sockets, fatal\n");
            pthread_mutex_lock(&exit_mutex);
            progexit = 1;
            pthread_mutex_unlock(&exit_mutex);
            break;
        }

        /* accept() loop */
        for (i = 0; i < fds->nfds && new_sd >= 0; i++) {
            struct fd_buf *buf = &fds->buf[i];
            if (!buf->got_newdata)
                continue;
#ifndef _WIN32
            if (buf->fd == data->syncpipe_wake_accept[0]) {
                /* dummy sync pipe, just to wake us */
                if (read(buf->fd, buff, sizeof(buff)) < 0) {
                    logg(LOGG_WARNING, "Syncpipe read failed\n");
                }
                continue;
            }
#endif
            if (buf->got_newdata == -1) {
                logg(LOGG_DEBUG_NV, "Acceptloop closed FD: %d\n", buf->fd);
                shutdown(buf->fd, 2);
                closesocket(buf->fd);
                buf->fd = -1;
                continue;
            }

            /* don't accept unlimited number of connections, or
             * we'll run out of file descriptors */
            pthread_mutex_lock(recv_fds->buf_mutex);
            while (recv_fds->nfds > (unsigned)max_queue) {
                pthread_mutex_lock(&exit_mutex);
                if (progexit) {
                    pthread_mutex_unlock(&exit_mutex);
                    break;
                }
                pthread_mutex_unlock(&exit_mutex);
                pthread_cond_wait(&data->cond_nfds, recv_fds->buf_mutex);
            }
            pthread_mutex_unlock(recv_fds->buf_mutex);

            pthread_mutex_lock(&exit_mutex);
            if (progexit) {
                pthread_mutex_unlock(&exit_mutex);
                break;
            }
            pthread_mutex_unlock(&exit_mutex);

            /* listen only socket */
            new_sd = accept(fds->buf[i].fd, NULL, NULL);

            if (new_sd >= 0) {
                int ret, flags;
#ifdef F_GETFL
                flags = fcntl(new_sd, F_GETFL, 0);
                if (flags != -1) {
                    if (fcntl(new_sd, F_SETFL, flags | O_NONBLOCK) == -1) {
                        logg(LOGG_WARNING, "Can't set socket to nonblocking mode, errno %d\n",
                             errno);
                    }
                } else {
                    logg(LOGG_WARNING, "Can't get socket flags, errno %d\n", errno);
                }
#else
                logg(LOGG_WARNING, "Nonblocking sockets not available!\n");
#endif
                logg(LOGG_DEBUG_NV, "Got new connection, FD %d\n", new_sd);
                pthread_mutex_lock(recv_fds->buf_mutex);
                ret = fds_add(recv_fds, new_sd, 0, commandtimeout);
                pthread_mutex_unlock(recv_fds->buf_mutex);

                if (ret == -1) {
                    logg(LOGG_ERROR, "fds_add failed\n");
                    closesocket(new_sd);
                    continue;
                }

                /* notify recvloop */
#ifdef _WIN32
                SetEvent(event_wake_recv);
#else
                if (write(data->syncpipe_wake_recv[1], "", 1) == -1) {
                    logg(LOGG_ERROR, "write syncpipe failed\n");
                    continue;
                }
#endif
            } else if (errno != EINTR) {
                /* very bad - need to exit or restart */
                logg(LOGG_ERROR, "accept() failed: %s\n", cli_strerror(errno, buff, BUFFSIZE));
                /* give the poll loop a chance to close disconnected FDs */
                break;
            }
        }

        /* handle progexit */
        pthread_mutex_lock(&exit_mutex);
        if (progexit) {
            pthread_mutex_unlock(&exit_mutex);
            break;
        }
        pthread_mutex_unlock(&exit_mutex);
    }
    pthread_mutex_unlock(fds->buf_mutex);

    if (sd_listen_fds(0) == 0) {
        /* only close the sockets, when not using systemd socket activation */
        for (i = data->initial_fds; i < fds->nfds; i++) {
            if (fds->buf[i].fd == -1)
                continue;
            logg(LOGG_DEBUG_NV, "Shutdown: closed fd %d\n", fds->buf[i].fd);
            shutdown(fds->buf[i].fd, 2);
            closesocket(fds->buf[i].fd);
        }
    }

    fds_free(fds);
    pthread_mutex_destroy(fds->buf_mutex);
    pthread_mutex_lock(&exit_mutex);
    progexit = 1;
    pthread_mutex_unlock(&exit_mutex);
#ifdef _WIN32
    SetEvent(event_wake_recv);
#else
    if (write(data->syncpipe_wake_recv[1], "", 1) < 0) {
        logg(LOGG_DEBUG_NV, "Syncpipe write failed\n");
    }
#endif
    return NULL;
}

static const char *parse_dispatch_cmd(client_conn_t *conn, struct fd_buf *buf, size_t *ppos, int *error, const struct optstruct *opts, int readtimeout)
{
    const char *cmd = NULL;
    int rc;
    size_t cmdlen;
    char term;
    int oldstyle;
    size_t pos = *ppos;
    /* Parse & dispatch commands */
    while ((conn->mode == MODE_COMMAND) &&
           (cmd = get_cmd(buf, pos, &cmdlen, &term, &oldstyle)) != NULL) {
        const char *argument;
        enum commands cmdtype;
        if (conn->group && oldstyle) {
            logg(LOGG_DEBUG_NV, "Received oldstyle command inside IDSESSION: %s\n", cmd);
            conn_reply_error(conn, "Only nCMDS\\n and zCMDS\\0 are accepted inside IDSESSION.");
            *error = 1;
            break;
        }
        cmdtype = parse_command(cmd, &argument, oldstyle);
        logg(LOGG_DEBUG_NV, "got command %s (%u, %u), argument: %s\n",
             cmd, (unsigned)cmdlen, (unsigned)cmdtype, argument ? argument : "");
        if (cmdtype == COMMAND_FILDES) {
            if (buf->buffer + buf->off <= cmd + strlen("FILDES\n")) {
                /* we need the extra byte from recvmsg */
                conn->mode = MODE_WAITANCILL;
                buf->mode  = MODE_WAITANCILL;
                /* put term back */
                buf->buffer[pos + cmdlen] = term;
                cmdlen                    = 0;
                logg(LOGG_DEBUG_NV, "RECVTH: mode -> MODE_WAITANCILL\n");
                break;
            }
            /* eat extra \0 for controlmsg */
            cmdlen++;
            logg(LOGG_DEBUG_NV, "RECVTH: FILDES command complete\n");
        }
        conn->term = term;
        buf->term  = term;

        if ((rc = execute_or_dispatch_command(conn, cmdtype, argument)) < 0) {
            logg(LOGG_ERROR, "Command dispatch failed\n");
            if (rc == -1 && optget(opts, "ExitOnOOM")->enabled) {
                pthread_mutex_lock(&exit_mutex);
                progexit = 1;
                pthread_mutex_unlock(&exit_mutex);
            }
            *error = 1;
        }
        if (thrmgr_group_need_terminate(conn->group)) {
            logg(LOGG_DEBUG_NV, "Receive thread: have to terminate group\n");
            *error = CL_ETIMEOUT;
            break;
        }
        if (*error || !conn->group || rc) {
            if (rc && thrmgr_group_finished(conn->group, EXIT_OK)) {
                logg(LOGG_DEBUG_NV, "Receive thread: closing conn (FD %d), group finished\n", conn->sd);
                /* if there are no more active jobs */
                shutdown(conn->sd, 2);
                closesocket(conn->sd);
                buf->fd     = -1;
                conn->group = NULL;
            } else if (conn->mode != MODE_STREAM) {
                logg(LOGG_DEBUG_NV, "mode -> MODE_WAITREPLY\n");
                /* no more commands are accepted */
                conn->mode = MODE_WAITREPLY;
                /* Stop monitoring this FD, it will be closed either
                 * by us, or by the scanner thread.
                 * Never close a file descriptor that is being
                 * monitored by poll()/select() from another thread,
                 * because this can lead to subtle bugs such as:
                 * Other thread closes file descriptor -> POLLHUP is
                 * set, but the poller thread doesn't wake up yet.
                 * Another client opens a connection and sends some
                 * data. If the socket reuses the previous file descriptor,
                 * then POLLIN is set on the file descriptor too.
                 * When poll() wakes up it sees POLLIN | POLLHUP
                 * and thinks that the client has sent some data,
                 * and closed the connection, so clamd closes the
                 * connection in turn resulting in a bug.
                 *
                 * If we wouldn't have poll()-ed the file descriptor
                 * we closed in another thread, but rather made sure
                 * that we don't put a FD that we're about to close
                 * into poll()'s list of watched fds; then POLLHUP
                 * would be set, but the file descriptor would stay
                 * open, until we wake up from poll() and close it.
                 * Thus a new connection won't be able to reuse the
                 * same FD, and there is no bug.
                 */
                buf->fd = -1;
            }
        }
        /* we received a command, set readtimeout */
        time(&buf->timeout_at);
        buf->timeout_at += readtimeout;
        pos += cmdlen + 1;
        if (conn->mode == MODE_STREAM) {
            /* TODO: this doesn't belong here */
            buf->dumpname = conn->filename;
            buf->dumpfd   = conn->scanfd;
            logg(LOGG_DEBUG_NV, "Receive thread: INSTREAM: %s fd %u\n", buf->dumpname, buf->dumpfd);
        }
        if (conn->mode != MODE_COMMAND) {
            logg(LOGG_DEBUG_NV, "Breaking command loop, mode is no longer MODE_COMMAND\n");
            break;
        }
        conn->id++;
    }
    *ppos      = pos;
    buf->mode  = conn->mode;
    buf->id    = conn->id;
    buf->group = conn->group;
    buf->quota = conn->quota;
    if (conn->scanfd != -1 && conn->scanfd != buf->dumpfd) {
        logg(LOGG_DEBUG_NV, "Unclaimed file descriptor received, closing: %d\n", conn->scanfd);
        close(conn->scanfd);
        /* protocol error */
        conn_reply_error(conn, "PROTOCOL ERROR: ancillary data sent without FILDES.");
        *error = 1;
        return NULL;
    }
    if (!*error) {
        /* move partial command to beginning of buffer */
        if (pos < buf->off) {
            memmove(buf->buffer, &buf->buffer[pos], buf->off - pos);
            buf->off -= pos;
        } else
            buf->off = 0;
        if (buf->off)
            logg(LOGG_DEBUG_NV, "Moved partial command: %lu\n", (unsigned long)buf->off);
        else
            logg(LOGG_DEBUG_NV, "Consumed entire command\n");
        /* adjust pos to account for the buffer shuffle */
        pos = 0;
    }
    *ppos = pos;
    return cmd;
}

/* static const unsigned char* parse_dispatch_cmd(client_conn_t *conn, struct fd_buf *buf, size_t *ppos, int *error, const struct optstruct *opts, int readtimeout) */
static int handle_stream(client_conn_t *conn, struct fd_buf *buf, const struct optstruct *opts, int *error, size_t *ppos, int readtimeout)
{
    int rc;
    size_t pos = *ppos;
    size_t cmdlen;

    logg(LOGG_DEBUG_NV, "mode == MODE_STREAM\n");
    /* we received some data, set readtimeout */
    time(&buf->timeout_at);
    buf->timeout_at += readtimeout;
    while (pos <= buf->off) {
        if (!buf->chunksize) {
            /* read chunksize */
            if (buf->off - pos >= 4) {
                uint32_t cs;
                memmove(&cs, buf->buffer + pos, 4);
                pos += 4;
                buf->chunksize = ntohl(cs);
                logg(LOGG_DEBUG_NV, "Got chunksize: %u\n", buf->chunksize);
                if (!buf->chunksize) {
                    /* chunksize 0 marks end of stream */
                    conn->scanfd = buf->dumpfd;
                    conn->term   = buf->term;
                    buf->dumpfd  = -1;
                    buf->mode    = buf->group ? MODE_COMMAND : MODE_WAITREPLY;
                    if (buf->mode == MODE_WAITREPLY)
                        buf->fd = -1;
                    logg(LOGG_DEBUG_NV, "Chunks complete\n");
                    buf->dumpname = NULL;
                    if ((rc = execute_or_dispatch_command(conn, COMMAND_INSTREAMSCAN, NULL)) < 0) {
                        logg(LOGG_ERROR, "Command dispatch failed\n");
                        if (rc == -1 && optget(opts, "ExitOnOOM")->enabled) {
                            pthread_mutex_lock(&exit_mutex);
                            progexit = 1;
                            pthread_mutex_unlock(&exit_mutex);
                        }
                        *error = 1;
                    } else {
                        memmove(buf->buffer, &buf->buffer[pos], buf->off - pos);
                        buf->off -= pos;
                        *ppos = 0;
                        buf->id++;
                        return 0;
                    }
                }
                if (buf->chunksize > buf->quota) {
                    logg(LOGG_WARNING, "INSTREAM: Size limit reached, (requested: %lu, max: %lu)\n",
                         (unsigned long)buf->chunksize, (unsigned long)buf->quota);
                    conn_reply_error(conn, "INSTREAM size limit exceeded.");
                    *error = 1;
                    *ppos  = pos;
                    return -1;
                } else {
                    buf->quota -= buf->chunksize;
                }
                logg(LOGG_DEBUG_NV, "Quota Remaining: %lu\n", buf->quota);
            } else {
                /* need more data, so return and wait for some */
                memmove(buf->buffer, &buf->buffer[pos], buf->off - pos);
                buf->off -= pos;
                *ppos = 0;
                return -1;
            }
        }
        if (pos + buf->chunksize < buf->off)
            cmdlen = buf->chunksize;
        else
            cmdlen = buf->off - pos;
        buf->chunksize -= cmdlen;
        if (cli_writen(buf->dumpfd, buf->buffer + pos, cmdlen) == (size_t)-1) {
            conn_reply_error(conn, "Error writing to temporary file");
            logg(LOGG_ERROR, "INSTREAM: Can't write to temporary file.\n");
            *error = 1;
        }
        logg(LOGG_DEBUG_NV, "Processed %llu bytes of chunkdata, pos %llu\n", (long long unsigned)cmdlen, (long long unsigned)pos);
        pos += cmdlen;
        if (pos == buf->off) {
            buf->off = 0;
            pos      = 0;
            /* need more data, so return and wait for some */
            *ppos = pos;
            return -1;
        }
    }
    *ppos = pos;
    return 0;
}

int recvloop(int *socketds, unsigned nsockets, struct cl_engine *engine, unsigned int dboptions, const struct optstruct *opts)
{
    int max_threads, max_queue, readtimeout, ret = 0;
    struct cl_scan_options options;
    char timestr[32];
#ifndef _WIN32
    struct sigaction sigact;
    sigset_t sigset;
    struct rlimit rlim;
#endif
    const struct optstruct *opt;
    char buff[BUFFSIZE + 1];
    int idletimeout;
    unsigned long long val;
    size_t i, j, rr_last = 0;
    pthread_t accept_th;
    pthread_mutex_t fds_mutex     = PTHREAD_MUTEX_INITIALIZER;
    pthread_mutex_t recvfds_mutex = PTHREAD_MUTEX_INITIALIZER;
    struct acceptdata acceptdata  = ACCEPTDATA_INIT(&fds_mutex, &recvfds_mutex);
    struct fd_data *fds           = &acceptdata.recv_fds;
    time_t start_time, current_time;
    unsigned int selfchk;
    threadpool_t *thr_pool;

    // Initial sockets will be closed in clamd.c
    acceptdata.initial_fds = nsockets;

#ifndef _WIN32
    memset(&sigact, 0, sizeof(struct sigaction));
#endif

    /* Initialize scan options struct */
    memset(&options, 0, sizeof(struct cl_scan_options));

    /* set up limits */
    if ((opt = optget(opts, "MaxScanTime"))->active) {
        if ((ret = cl_engine_set_num(engine, CL_ENGINE_MAX_SCANTIME, opt->numarg))) {
            logg(LOGG_ERROR, "cl_engine_set_num(CL_ENGINE_MAX_SCANTIME) failed: %s\n", cl_strerror(ret));
            cl_engine_free(engine);
            return 1;
        }
    }
    val = cl_engine_get_num(engine, CL_ENGINE_MAX_SCANTIME, NULL);
    if (val)
        logg(LOGG_INFO, "Limits: Global time limit set to %llu milliseconds.\n", val);
    else
        logg(LOGG_WARNING, "Limits: Global time limit protection disabled.\n");

    if ((opt = optget(opts, "MaxScanSize"))->active) {
        if ((ret = cl_engine_set_num(engine, CL_ENGINE_MAX_SCANSIZE, opt->numarg))) {
            logg(LOGG_ERROR, "cl_engine_set_num(CL_ENGINE_MAX_SCANSIZE) failed: %s\n", cl_strerror(ret));
            cl_engine_free(engine);
            return 1;
        }
    }
    val = cl_engine_get_num(engine, CL_ENGINE_MAX_SCANSIZE, NULL);
    if (val)
        logg(LOGG_INFO, "Limits: Global size limit set to %llu bytes.\n", val);
    else
        logg(LOGG_WARNING, "Limits: Global size limit protection disabled.\n");

    if ((opt = optget(opts, "MaxFileSize"))->active) {
        if ((ret = cl_engine_set_num(engine, CL_ENGINE_MAX_FILESIZE, opt->numarg))) {
            logg(LOGG_ERROR, "cl_engine_set_num(CL_ENGINE_MAX_FILESIZE) failed: %s\n", cl_strerror(ret));
            cl_engine_free(engine);
            return 1;
        }
    }
    val = cl_engine_get_num(engine, CL_ENGINE_MAX_FILESIZE, NULL);
    if (val)
        logg(LOGG_INFO, "Limits: File size limit set to %llu bytes.\n", val);
    else
        logg(LOGG_WARNING, "Limits: File size limit protection disabled.\n");

#ifndef _WIN32
    if (getrlimit(RLIMIT_FSIZE, &rlim) == 0) {
        if (rlim.rlim_cur < (rlim_t)cl_engine_get_num(engine, CL_ENGINE_MAX_FILESIZE, NULL))
            logg(LOGG_WARNING, "System limit for file size is lower than engine->maxfilesize\n");
        if (rlim.rlim_cur < (rlim_t)cl_engine_get_num(engine, CL_ENGINE_MAX_SCANSIZE, NULL))
            logg(LOGG_WARNING, "System limit for file size is lower than engine->maxscansize\n");
    } else {
        logg(LOGG_WARNING, "Cannot obtain resource limits for file size\n");
    }
#endif

    if ((opt = optget(opts, "MaxRecursion"))->active) {
        if ((0 == opt->numarg) || (opt->numarg > CLI_MAX_MAXRECLEVEL)) {
            logg(LOGG_ERROR, "MaxRecursion set to %zu, but cannot be larger than %u, and cannot be 0.\n",
                 (size_t)opt->numarg, CLI_MAX_MAXRECLEVEL);
            cl_engine_free(engine);
            return 1;
        }
        if ((ret = cl_engine_set_num(engine, CL_ENGINE_MAX_RECURSION, opt->numarg))) {
            logg(LOGG_ERROR, "cl_engine_set_num(CL_ENGINE_MAX_RECURSION) failed: %s\n", cl_strerror(ret));
            cl_engine_free(engine);
            return 1;
        }
    }
    val = cl_engine_get_num(engine, CL_ENGINE_MAX_RECURSION, NULL);
    if (val)
        logg(LOGG_INFO, "Limits: Recursion level limit set to %u.\n", (unsigned int)val);
    else
        logg(LOGG_WARNING, "Limits: Recursion level limit protection disabled.\n");

    if ((opt = optget(opts, "MaxFiles"))->active) {
        if ((ret = cl_engine_set_num(engine, CL_ENGINE_MAX_FILES, opt->numarg))) {
            logg(LOGG_ERROR, "cl_engine_set_num(CL_ENGINE_MAX_FILES) failed: %s\n", cl_strerror(ret));
            cl_engine_free(engine);
            return 1;
        }
    }
    val = cl_engine_get_num(engine, CL_ENGINE_MAX_FILES, NULL);
    if (val)
        logg(LOGG_INFO, "Limits: Files limit set to %u.\n", (unsigned int)val);
    else
        logg(LOGG_WARNING, "Limits: Files limit protection disabled.\n");

#ifndef _WIN32
    if (getrlimit(RLIMIT_CORE, &rlim) == 0) {
        logg(LOGG_DEBUG, "Limits: Core-dump limit is %lu.\n", (unsigned long)rlim.rlim_cur);
    }
#endif

    /* Engine max sizes */

    if ((opt = optget(opts, "MaxEmbeddedPE"))->active) {
        if ((ret = cl_engine_set_num(engine, CL_ENGINE_MAX_EMBEDDEDPE, opt->numarg))) {
            logg(LOGG_ERROR, "cli_engine_set_num(CL_ENGINE_MAX_EMBEDDEDPE) failed: %s\n", cl_strerror(ret));
            cl_engine_free(engine);
            return 1;
        }
    }
    val = cl_engine_get_num(engine, CL_ENGINE_MAX_EMBEDDEDPE, NULL);
    logg(LOGG_INFO, "Limits: MaxEmbeddedPE limit set to %llu bytes.\n", val);

    if ((opt = optget(opts, "MaxHTMLNormalize"))->active) {
        if ((ret = cl_engine_set_num(engine, CL_ENGINE_MAX_HTMLNORMALIZE, opt->numarg))) {
            logg(LOGG_ERROR, "cli_engine_set_num(CL_ENGINE_MAX_HTMLNORMALIZE) failed: %s\n", cl_strerror(ret));
            cl_engine_free(engine);
            return 1;
        }
    }
    val = cl_engine_get_num(engine, CL_ENGINE_MAX_HTMLNORMALIZE, NULL);
    logg(LOGG_INFO, "Limits: MaxHTMLNormalize limit set to %llu bytes.\n", val);

    if ((opt = optget(opts, "MaxHTMLNoTags"))->active) {
        if ((ret = cl_engine_set_num(engine, CL_ENGINE_MAX_HTMLNOTAGS, opt->numarg))) {
            logg(LOGG_ERROR, "cli_engine_set_num(CL_ENGINE_MAX_HTMLNOTAGS) failed: %s\n", cl_strerror(ret));
            cl_engine_free(engine);
            return 1;
        }
    }
    val = cl_engine_get_num(engine, CL_ENGINE_MAX_HTMLNOTAGS, NULL);
    logg(LOGG_INFO, "Limits: MaxHTMLNoTags limit set to %llu bytes.\n", val);

    if ((opt = optget(opts, "MaxScriptNormalize"))->active) {
        if ((ret = cl_engine_set_num(engine, CL_ENGINE_MAX_SCRIPTNORMALIZE, opt->numarg))) {
            logg(LOGG_ERROR, "cli_engine_set_num(CL_ENGINE_MAX_SCRIPTNORMALIZE) failed: %s\n", cl_strerror(ret));
            cl_engine_free(engine);
            return 1;
        }
    }
    val = cl_engine_get_num(engine, CL_ENGINE_MAX_SCRIPTNORMALIZE, NULL);
    logg(LOGG_INFO, "Limits: MaxScriptNormalize limit set to %llu bytes.\n", val);

    if ((opt = optget(opts, "MaxZipTypeRcg"))->active) {
        if ((ret = cl_engine_set_num(engine, CL_ENGINE_MAX_ZIPTYPERCG, opt->numarg))) {
            logg(LOGG_ERROR, "cli_engine_set_num(CL_ENGINE_MAX_ZIPTYPERCG) failed: %s\n", cl_strerror(ret));
            cl_engine_free(engine);
            return 1;
        }
    }
    val = cl_engine_get_num(engine, CL_ENGINE_MAX_ZIPTYPERCG, NULL);
    logg(LOGG_INFO, "Limits: MaxZipTypeRcg limit set to %llu bytes.\n", val);

    if ((opt = optget(opts, "MaxPartitions"))->active) {
        if ((ret = cl_engine_set_num(engine, CL_ENGINE_MAX_PARTITIONS, opt->numarg))) {
            logg(LOGG_ERROR, "cli_engine_set_num(MaxPartitions) failed: %s\n", cl_strerror(ret));
            cl_engine_free(engine);
            return 1;
        }
    }
    val = cl_engine_get_num(engine, CL_ENGINE_MAX_PARTITIONS, NULL);
    logg(LOGG_INFO, "Limits: MaxPartitions limit set to %llu.\n", val);

    if ((opt = optget(opts, "MaxIconsPE"))->active) {
        if ((ret = cl_engine_set_num(engine, CL_ENGINE_MAX_ICONSPE, opt->numarg))) {
            logg(LOGG_ERROR, "cli_engine_set_num(MaxIconsPE) failed: %s\n", cl_strerror(ret));
            cl_engine_free(engine);
            return 1;
        }
    }
    val = cl_engine_get_num(engine, CL_ENGINE_MAX_ICONSPE, NULL);
    logg(LOGG_INFO, "Limits: MaxIconsPE limit set to %llu.\n", val);

    if ((opt = optget(opts, "MaxRecHWP3"))->active) {
        if ((ret = cl_engine_set_num(engine, CL_ENGINE_MAX_RECHWP3, opt->numarg))) {
            logg(LOGG_ERROR, "cli_engine_set_num(MaxRecHWP3) failed: %s\n", cl_strerror(ret));
            cl_engine_free(engine);
            return 1;
        }
    }
    val = cl_engine_get_num(engine, CL_ENGINE_MAX_RECHWP3, NULL);
    logg(LOGG_INFO, "Limits: MaxRecHWP3 limit set to %llu.\n", val);

    /* options are handled in main (clamd.c) */
    val = cl_engine_get_num(engine, CL_ENGINE_PCRE_MATCH_LIMIT, NULL);
    logg(LOGG_INFO, "Limits: PCREMatchLimit limit set to %llu.\n", val);

    val = cl_engine_get_num(engine, CL_ENGINE_PCRE_RECMATCH_LIMIT, NULL);
    logg(LOGG_INFO, "Limits: PCRERecMatchLimit limit set to %llu.\n", val);

    if ((opt = optget(opts, "PCREMaxFileSize"))->active) {
        if ((ret = cl_engine_set_num(engine, CL_ENGINE_PCRE_MAX_FILESIZE, opt->numarg))) {
            logg(LOGG_ERROR, "cli_engine_set_num(PCREMaxFileSize) failed: %s\n", cl_strerror(ret));
            cl_engine_free(engine);
            return 1;
        }
    }
    val = cl_engine_get_num(engine, CL_ENGINE_PCRE_MAX_FILESIZE, NULL);
    logg(LOGG_INFO, "Limits: PCREMaxFileSize limit set to %llu.\n", val);

    if (optget(opts, "ScanArchive")->enabled) {
        logg(LOGG_INFO, "Archive support enabled.\n");
        options.parse |= CL_SCAN_PARSE_ARCHIVE;
    } else {
        logg(LOGG_INFO, "Archive support disabled.\n");
    }

    if (optget(opts, "ScanImage")->enabled) {
        logg(LOGG_INFO, "Image (graphics) scanning support enabled.\n");
        options.parse |= CL_SCAN_PARSE_IMAGE;
    } else {
        logg(LOGG_INFO, "Image (graphics) scanning support disabled.\n");
    }

    if (optget(opts, "ScanImageFuzzyHash")->enabled) {
        logg(LOGG_INFO, "Detection using image fuzzy hash enabled.\n");
        options.parse |= CL_SCAN_PARSE_IMAGE_FUZZY_HASH;
    } else {
        logg(LOGG_INFO, "Detection using image fuzzy hash disabled.\n");
    }

    /* TODO: Remove deprecated option in a future feature release. */
    if (optget(opts, "ArchiveBlockEncrypted")->enabled) {
        if (options.parse & CL_SCAN_PARSE_ARCHIVE) {
            logg(
                LOGG_WARNING,
                "Using deprecated option \"ArchiveBlockEncrypted\" to alert on "
                "encrypted archives _and_ documents. Please update your "
                "configuration to use replacement options \"AlertEncrypted\", or "
                "\"AlertEncryptedArchive\" and/or \"AlertEncryptedDoc\".\n");
            options.heuristic |= CL_SCAN_HEURISTIC_ENCRYPTED_ARCHIVE;
            options.heuristic |= CL_SCAN_HEURISTIC_ENCRYPTED_DOC;
        } else {
            logg(
                LOGG_WARNING,
                "Using deprecated option \"ArchiveBlockEncrypted\" to alert on "
                "encrypted documents. Please update your configuration to use "
                "replacement options \"AlertEncrypted\", or "
                "\"AlertEncryptedArchive\" and/or \"AlertEncryptedDoc\".\n");
            options.heuristic |= CL_SCAN_HEURISTIC_ENCRYPTED_DOC;
        }
    }

    if (optget(opts, "AlertEncrypted")->enabled) {
        if (options.parse & CL_SCAN_PARSE_ARCHIVE) {
            logg(LOGG_INFO, "Alerting of encrypted archives _and_ documents enabled.\n");
            options.heuristic |= CL_SCAN_HEURISTIC_ENCRYPTED_ARCHIVE;
            options.heuristic |= CL_SCAN_HEURISTIC_ENCRYPTED_DOC;
        } else {
            logg(LOGG_INFO, "Alerting of encrypted documents enabled.\n");
            options.heuristic |= CL_SCAN_HEURISTIC_ENCRYPTED_DOC;
        }
    }

    if (optget(opts, "AlertEncryptedArchive")->enabled) {
        if (options.parse & CL_SCAN_PARSE_ARCHIVE) {
            logg(LOGG_INFO, "Alerting of encrypted archives enabled.\n");
            options.heuristic |= CL_SCAN_HEURISTIC_ENCRYPTED_ARCHIVE;
        } else {
            logg(LOGG_WARNING, "Encrypted archive alerting requested, but archive support "
                               "is disabled!\n");
        }
    }

    if (optget(opts, "AlertEncryptedDoc")->enabled) {
        logg(LOGG_INFO, "Alerting of encrypted documents enabled.\n");
        options.heuristic |= CL_SCAN_HEURISTIC_ENCRYPTED_DOC;
    }

    /* TODO: Remove deprecated option in a future feature release. */
    if (optget(opts, "BlockMax")->enabled) {
        logg(LOGG_WARNING, "Using deprecated option \"BlockMax\" to enable heuristic alerts "
                           "when scans exceed set maximums. Please update your configuration "
                           "to use replacement option \"AlertExceedsMax\".\n");
        options.heuristic |= CL_SCAN_HEURISTIC_EXCEEDS_MAX;
    } else if (optget(opts, "AlertExceedsMax")->enabled) {
        logg(LOGG_INFO, "Heuristic alerting enabled for scans that exceed set maximums.\n");
        options.heuristic |= CL_SCAN_HEURISTIC_EXCEEDS_MAX;
    } else {
        logg(LOGG_INFO, "AlertExceedsMax heuristic detection disabled.\n");
    }

    /* TODO: Remove deprecated option in a future feature release. */
    if (!optget(opts, "AlgorithmicDetection")->enabled) {
        logg(LOGG_WARNING, "Using deprecated option \"AlgorithmicDetection\" to disable "
                           "heuristic alerts. Please update your configuration to use "
                           "replacement option \"HeuristicAlerts\".\n");
    } else if (!optget(opts, "HeuristicAlerts")->enabled) {
        logg(LOGG_INFO, "Heuristic alerts disabled.\n");
    } else {
        logg(LOGG_INFO, "Heuristic alerts enabled.\n");
        options.general |= CL_SCAN_GENERAL_HEURISTICS;
    }

    if (optget(opts, "ScanPE")->enabled) {
        logg(LOGG_INFO, "Portable Executable support enabled.\n");
        options.parse |= CL_SCAN_PARSE_PE;
    } else {
        logg(LOGG_INFO, "Portable Executable support disabled.\n");
    }

    if (optget(opts, "ScanELF")->enabled) {
        logg(LOGG_INFO, "ELF support enabled.\n");
        options.parse |= CL_SCAN_PARSE_ELF;
    } else {
        logg(LOGG_INFO, "ELF support disabled.\n");
    }

    /* TODO: Remove deprecated option in a future feature release */
    if (optget(opts, "ScanPE")->enabled || optget(opts, "ScanELF")->enabled) {
        if ((optget(opts, "DetectBrokenExecutables")->enabled) ||
            (optget(opts, "AlertBrokenExecutables")->enabled)) {
            logg(LOGG_INFO, "Alerting on broken executables enabled.\n");
            options.heuristic |= CL_SCAN_HEURISTIC_BROKEN;
        }
    }

    if (optget(opts, "AlertBrokenMedia")->enabled) {
        options.heuristic |= CL_SCAN_HEURISTIC_BROKEN_MEDIA;
        logg(LOGG_INFO, "Media (Graphics) Format Validation enabled\n");
    }

    if (optget(opts, "ScanMail")->enabled) {
        logg(LOGG_INFO, "Mail files support enabled.\n");
        options.parse |= CL_SCAN_PARSE_MAIL;

        if (optget(opts, "ScanPartialMessages")->enabled) {
            logg(LOGG_INFO, "Mail: RFC1341 handling enabled.\n");
            options.mail |= CL_SCAN_MAIL_PARTIAL_MESSAGE;
        }

    } else {
        logg(LOGG_INFO, "Mail files support disabled.\n");
    }

    if (optget(opts, "ScanOLE2")->enabled) {
        logg(LOGG_INFO, "OLE2 support enabled.\n");
        options.parse |= CL_SCAN_PARSE_OLE2;

        /* TODO: Remove deprecated option in a future feature release */
        if ((optget(opts, "OLE2BlockMacros")->enabled) ||
            (optget(opts, "AlertOLE2Macros")->enabled)) {
            logg(LOGG_INFO, "OLE2: Alerting on all VBA macros.\n");
            options.heuristic |= CL_SCAN_HEURISTIC_MACROS;
        }
    } else {
        logg(LOGG_INFO, "OLE2 support disabled.\n");
    }

    if (optget(opts, "ScanPDF")->enabled) {
        logg(LOGG_INFO, "PDF support enabled.\n");
        options.parse |= CL_SCAN_PARSE_PDF;
    } else {
        logg(LOGG_INFO, "PDF support disabled.\n");
    }

    if (optget(opts, "ScanSWF")->enabled) {
        logg(LOGG_INFO, "SWF support enabled.\n");
        options.parse |= CL_SCAN_PARSE_SWF;
    } else {
        logg(LOGG_INFO, "SWF support disabled.\n");
    }

    if (optget(opts, "ScanHTML")->enabled) {
        logg(LOGG_INFO, "HTML support enabled.\n");
        options.parse |= CL_SCAN_PARSE_HTML;
    } else {
        logg(LOGG_INFO, "HTML support disabled.\n");
    }

#ifdef PRELUDE
    if (optget(opts, "PreludeEnable")->enabled) {
        if ((opt = optget(opts, "PreludeAnalyzerName"))->enabled) {
            prelude_initialize_client(opt->strarg);
        } else {
            prelude_initialize_client("ClamAV");
        }
    }
#endif

    if (optget(opts, "ScanXMLDOCS")->enabled) {
        logg(LOGG_INFO, "XMLDOCS support enabled.\n");
        options.parse |= CL_SCAN_PARSE_XMLDOCS;
    } else {
        logg(LOGG_INFO, "XMLDOCS support disabled.\n");
    }

    if (optget(opts, "ScanHWP3")->enabled) {
        logg(LOGG_INFO, "HWP3 support enabled.\n");
        options.parse |= CL_SCAN_PARSE_HWP3;
    } else {
        logg(LOGG_INFO, "HWP3 support disabled.\n");
    }

    if (optget(opts, "ScanOneNote")->enabled) {
        logg(LOGG_INFO, "OneNote support enabled.\n");
        options.parse |= CL_SCAN_PARSE_ONENOTE;
    } else {
        logg(LOGG_INFO, "OneNote support disabled.\n");
    }

    if (optget(opts, "PhishingScanURLs")->enabled) {
        /* TODO: Remove deprecated option in a future feature release */
        if ((optget(opts, "PhishingAlwaysBlockCloak")->enabled) ||
            (optget(opts, "AlertPhishingCloak")->enabled)) {
            options.heuristic |= CL_SCAN_HEURISTIC_PHISHING_CLOAK;
            logg(LOGG_INFO, "Phishing: Always checking for cloaked urls\n");
        }
        /* TODO: Remove deprecated option in a future feature release */
        if ((optget(opts, "PhishingAlwaysBlockSSLMismatch")->enabled) ||
            (optget(opts, "AlertPhishingSSLMismatch")->enabled)) {
            options.heuristic |= CL_SCAN_HEURISTIC_PHISHING_SSL_MISMATCH;
            logg(LOGG_INFO, "Phishing: Always checking for ssl mismatches\n");
        }
    }

    /* TODO: Remove deprecated option in a future feature release */
    if ((optget(opts, "PartitionIntersection")->enabled) ||
        (optget(opts, "AlertPartitionIntersection")->enabled)) {
        options.heuristic |= CL_SCAN_HEURISTIC_PARTITION_INTXN;
        logg(LOGG_INFO, "Raw DMG: Alert on partitions intersections\n");
    }

    if (optget(opts, "HeuristicScanPrecedence")->enabled) {
        options.general |= CL_SCAN_GENERAL_HEURISTIC_PRECEDENCE;
        logg(LOGG_INFO, "Heuristic: precedence enabled\n");
    }

    if (optget(opts, "StructuredDataDetection")->enabled) {
        options.heuristic |= CL_SCAN_HEURISTIC_STRUCTURED;

        if ((opt = optget(opts, "StructuredMinCreditCardCount"))->enabled) {
            if ((ret = cl_engine_set_num(engine, CL_ENGINE_MIN_CC_COUNT, opt->numarg))) {
                logg(LOGG_ERROR, "cl_engine_set_num(CL_ENGINE_MIN_CC_COUNT) failed: %s\n", cl_strerror(ret));
                cl_engine_free(engine);
                return 1;
            }
        }
        val = cl_engine_get_num(engine, CL_ENGINE_MIN_CC_COUNT, NULL);
        logg(LOGG_INFO, "Structured: Minimum Credit Card Number Count set to %u\n", (unsigned int)val);

        if (optget(opts, "StructuredCCOnly")->enabled)
            options.heuristic |= CL_SCAN_HEURISTIC_STRUCTURED_CC;

        if ((opt = optget(opts, "StructuredMinSSNCount"))->enabled) {
            if ((ret = cl_engine_set_num(engine, CL_ENGINE_MIN_SSN_COUNT, opt->numarg))) {
                logg(LOGG_ERROR, "cl_engine_set_num(CL_ENGINE_MIN_SSN_COUNT) failed: %s\n", cl_strerror(ret));
                cl_engine_free(engine);
                return 1;
            }
        }
        val = cl_engine_get_num(engine, CL_ENGINE_MIN_SSN_COUNT, NULL);
        logg(LOGG_INFO, "Structured: Minimum Social Security Number Count set to %u\n", (unsigned int)val);

        if (optget(opts, "StructuredSSNFormatNormal")->enabled)
            options.heuristic |= CL_SCAN_HEURISTIC_STRUCTURED_SSN_NORMAL;

        if (optget(opts, "StructuredSSNFormatStripped")->enabled)
            options.heuristic |= CL_SCAN_HEURISTIC_STRUCTURED_SSN_STRIPPED;
    }

    if (optget(opts, "GenerateMetadataJson")->enabled) {
        options.general |= CL_SCAN_GENERAL_COLLECT_METADATA;
    }

    if (optget(opts, "JsonStoreHTMLURIs")->enabled) {
        options.general |= CL_SCAN_GENERAL_STORE_HTML_URIS;
    }

    if (optget(opts, "JsonStorePDFURIs")->enabled) {
        options.general |= CL_SCAN_GENERAL_STORE_PDF_URIS;
    }

    if (optget(opts, "JsonStoreExtraHashes")->enabled) {
        options.general |= CL_SCAN_GENERAL_STORE_EXTRA_HASHES;
    }

    selfchk = optget(opts, "SelfCheck")->numarg;
    if (!selfchk) {
        logg(LOGG_INFO, "Self checking disabled.\n");
    } else {
        logg(LOGG_INFO, "Self checking every %u seconds.\n", selfchk);
    }

    logg(LOGG_DEBUG, "Listening daemon: PID: %u\n", (unsigned int)getpid());
    max_threads               = optget(opts, "MaxThreads")->numarg;
    max_queue                 = optget(opts, "MaxQueue")->numarg;
    acceptdata.commandtimeout = optget(opts, "CommandReadTimeout")->numarg;
    readtimeout               = optget(opts, "ReadTimeout")->numarg;

#if !defined(_WIN32) && defined(RLIMIT_NOFILE)
    if (getrlimit(RLIMIT_NOFILE, &rlim) == 0) {
        /* don't warn if default value is too high, silently fix it */
        unsigned maxrec;
        int max_max_queue;
        unsigned warn             = optget(opts, "MaxQueue")->active;
        const unsigned clamdfiles = 6;
#ifdef C_SOLARIS
        int solaris_has_extended_stdio = 0;
#endif
        /* Condition to not run out of file descriptors:
         * MaxThreads * MaxRecursion + (MaxQueue - MaxThreads) + CLAMDFILES < RLIMIT_NOFILE
         * CLAMDFILES is 6: 3 standard FD + logfile + 2 FD for reloading the DB
         * */
#ifdef C_SOLARIS

        /*
         **  If compiling 64bit, then set the solaris_has_extended_stdio
         **  flag
         */

#if defined(_LP64)
        solaris_has_extended_stdio++;
#endif

#ifdef HAVE_ENABLE_EXTENDED_FILE_STDIO
        if (enable_extended_FILE_stdio(-1, -1) == -1) {
            logg(LOGG_WARNING, "Unable to set extended FILE stdio, clamd will be limited to max 256 open files\n");
            rlim.rlim_cur = rlim.rlim_cur > 255 ? 255 : rlim.rlim_cur;
        } else {
            solaris_has_extended_stdio++;
        }

#elif !defined(_LP64)
        if (solaris_has_extended_stdio && rlim.rlim_cur > 255) {
            rlim.rlim_cur = 255;
            logg(LOGG_WARNING, "Solaris only supports 256 open files for 32-bit processes, you need at least Solaris 10u4, or compile as 64-bit to support more!\n");
        }
#endif

        /*
         **  If compiling in 64bit or the file stdio has been extended,
         **  then increase the soft limit for the number of open files
         **  as the default is usually 256
         */

        if (solaris_has_extended_stdio) {
            rlim_t saved_soft_limit = rlim.rlim_cur;

            rlim.rlim_cur = rlim.rlim_max;
            if (setrlimit(RLIMIT_NOFILE, &rlim) < 0) {
                logg(LOGG_ERROR, "setrlimit() for RLIMIT_NOFILE to %lu failed: %s\n",
                     (unsigned long)rlim.rlim_cur, strerror(errno));
                rlim.rlim_cur = saved_soft_limit;
            }
        } /*  If 64bit or has extended stdio  */

#endif
        opt           = optget(opts, "MaxRecursion");
        maxrec        = opt->numarg;
        max_max_queue = rlim.rlim_cur - maxrec * max_threads - clamdfiles + max_threads;
        if (max_queue < max_threads) {
            max_queue = max_threads;
            if (warn)
                logg(LOGG_WARNING, "MaxQueue value too low, increasing to: %d\n", max_queue);
        }
        if (max_max_queue < max_threads) {
            logg(LOGG_WARNING, "MaxThreads * MaxRecursion is too high: %d, open file descriptor limit is: %lu\n",
                 maxrec * max_threads, (unsigned long)rlim.rlim_cur);
            max_max_queue = max_threads;
        }
        if (max_queue > max_max_queue) {
            max_queue = max_max_queue;
            if (warn)
                logg(LOGG_WARNING, "MaxQueue value too high, lowering to: %d\n", max_queue);
        } else if (max_queue < 2 * max_threads && max_queue < max_max_queue) {
            max_queue = 2 * max_threads;
            if (max_queue > max_max_queue)
                max_queue = max_max_queue;
            /* always warn here */
            logg(LOGG_WARNING, "MaxQueue is lower than twice MaxThreads, increasing to: %d\n", max_queue);
        }
    }
#endif
    logg(LOGG_DEBUG, "MaxQueue set to: %d\n", max_queue);
    acceptdata.max_queue = max_queue;

#ifndef _WIN32
    /* set up signal handling */
    sigfillset(&sigset);
    sigdelset(&sigset, SIGINT);
    sigdelset(&sigset, SIGTERM);
    sigdelset(&sigset, SIGSEGV);
    sigdelset(&sigset, SIGHUP);
    sigdelset(&sigset, SIGPIPE);
    sigdelset(&sigset, SIGUSR2);
    /* The behavior of a process is undefined after it ignores a
     * SIGFPE, SIGILL, SIGSEGV, or SIGBUS signal */
    sigdelset(&sigset, SIGFPE);
    sigdelset(&sigset, SIGILL);
    sigdelset(&sigset, SIGSEGV);
#ifdef SIGBUS
    sigdelset(&sigset, SIGBUS);
#endif
    sigdelset(&sigset, SIGTSTP);
    sigdelset(&sigset, SIGCONT);
    sigprocmask(SIG_SETMASK, &sigset, NULL);

    /* SIGINT, SIGTERM, SIGSEGV */
    sigact.sa_handler = sighandler_th;
    sigemptyset(&sigact.sa_mask);
    sigaddset(&sigact.sa_mask, SIGINT);
    sigaddset(&sigact.sa_mask, SIGTERM);
    sigaddset(&sigact.sa_mask, SIGHUP);
    sigaddset(&sigact.sa_mask, SIGPIPE);
    sigaddset(&sigact.sa_mask, SIGUSR2);
    sigaction(SIGINT, &sigact, NULL);
    sigaction(SIGTERM, &sigact, NULL);
    sigaction(SIGHUP, &sigact, NULL);
    sigaction(SIGPIPE, &sigact, NULL);
    sigaction(SIGUSR2, &sigact, NULL);
#endif

    idletimeout = optget(opts, "IdleTimeout")->numarg;

    for (i = 0; i < nsockets; i++)
        if (fds_add(&acceptdata.fds, socketds[i], 1, 0) == -1) {
            logg(LOGG_ERROR, "fds_add failed\n");
            cl_engine_free(engine);
            return 1;
        }
#ifdef _WIN32
    event_wake_accept = CreateEvent(NULL, TRUE, FALSE, NULL);
    event_wake_recv   = CreateEvent(NULL, TRUE, FALSE, NULL);
#else
    if (pipe(acceptdata.syncpipe_wake_recv) == -1 ||
        (pipe(acceptdata.syncpipe_wake_accept) == -1)) {

        logg(LOGG_ERROR, "pipe failed\n");
        exit(-1);
    }
    syncpipe_wake_recv_w = acceptdata.syncpipe_wake_recv[1];

    if (fds_add(fds, acceptdata.syncpipe_wake_recv[0], 1, 0) == -1 ||
        fds_add(&acceptdata.fds, acceptdata.syncpipe_wake_accept[0], 1, 0)) {
        logg(LOGG_ERROR, "failed to add pipe fd\n");
        exit(-1);
    }
#endif

    if ((thr_pool = thrmgr_new(max_threads, idletimeout, max_queue, scanner_thread)) == NULL) {
        logg(LOGG_ERROR, "thrmgr_new failed\n");
        exit(-1);
    }

    if (pthread_create(&accept_th, NULL, acceptloop_th, &acceptdata)) {
        logg(LOGG_ERROR, "pthread_create failed\n");
        exit(-1);
    }

    time(&start_time);
    for (;;) {
        int new_sd;

        /* Block waiting for connection on any of the sockets */
        pthread_mutex_lock(fds->buf_mutex);
        fds_cleanup(fds);
        /* signal that we can accept more connections */
        if (fds->nfds <= (unsigned)max_queue)
            pthread_cond_signal(&acceptdata.cond_nfds);
        new_sd = fds_poll_recv(fds, selfchk ? (int)selfchk : -1, 1, event_wake_recv);
#ifdef _WIN32
        ResetEvent(event_wake_recv);
#else
        if (!fds->nfds) {
            /* at least the dummy/sync pipe should have remained */
            logg(LOGG_ERROR, "All recv() descriptors gone: fatal\n");
            pthread_mutex_lock(&exit_mutex);
            progexit = 1;
            pthread_mutex_unlock(&exit_mutex);
            pthread_mutex_unlock(fds->buf_mutex);
            break;
        }
#endif
        if (new_sd == -1 && errno != EINTR) {
            logg(LOGG_ERROR, "Failed to poll sockets, fatal\n");
            pthread_mutex_lock(&exit_mutex);
            progexit = 1;
            pthread_mutex_unlock(&exit_mutex);
        }

        if (fds->nfds) i = (rr_last + 1) % fds->nfds;
        for (j = 0; j < fds->nfds && new_sd >= 0; j++, i = (i + 1) % fds->nfds) {
            size_t pos         = 0;
            int error          = 0;
            struct fd_buf *buf = &fds->buf[i];
            if (!buf->got_newdata)
                continue;

#ifndef _WIN32
            if (buf->fd == acceptdata.syncpipe_wake_recv[0]) {
                /* dummy sync pipe, just to wake us */
                if (read(buf->fd, buff, sizeof(buff)) < 0) {
                    logg(LOGG_WARNING, "Syncpipe read failed\n");
                }
                continue;
            }
#endif
            if (buf->got_newdata == -1) {
                if (buf->mode == MODE_WAITREPLY) {
                    logg(LOGG_DEBUG_NV, "mode WAIT_REPLY -> closed\n");
                    buf->fd = -1;
                    thrmgr_group_terminate(buf->group);
                    thrmgr_group_finished(buf->group, EXIT_ERROR);
                    continue;
                } else {
                    logg(LOGG_DEBUG_NV, "client read error or EOF on read\n");
                    error = 1;
                }
            }

            if (buf->fd != -1 && buf->got_newdata == -2) {
                logg(LOGG_DEBUG_NV, "Client read timed out\n");
                mdprintf(buf->fd, "COMMAND READ TIMED OUT\n");
                error = 1;
            }

            rr_last = i;
            if (buf->mode == MODE_WAITANCILL) {
                buf->mode = MODE_COMMAND;
                logg(LOGG_DEBUG_NV, "mode -> MODE_COMMAND\n");
            }
            while (!error && buf->fd != -1 && buf->buffer && pos < buf->off &&
                   buf->mode != MODE_WAITANCILL) {
                client_conn_t conn;
                const char *cmd = NULL;
                int rc;
                /* New data available to read on socket. */

                memset(&conn, 0, sizeof(conn));
                conn.scanfd   = buf->recvfd;
                buf->recvfd   = -1;
                conn.sd       = buf->fd;
                conn.options  = &options;
                conn.opts     = opts;
                conn.thrpool  = thr_pool;
                conn.engine   = engine;
                conn.group    = buf->group;
                conn.id       = buf->id;
                conn.quota    = buf->quota;
                conn.filename = buf->dumpname;
                conn.mode     = buf->mode;
                conn.term     = buf->term;

                /* Parse & dispatch command */
                cmd = parse_dispatch_cmd(&conn, buf, &pos, &error, opts, readtimeout);

                if (conn.mode == MODE_COMMAND && !cmd)
                    break;
                if (!error) {
                    if (buf->mode == MODE_WAITREPLY && buf->off) {
                        /* Client is not supposed to send anything more */
                        logg(LOGG_WARNING, "Client sent garbage after last command: %lu bytes\n", (unsigned long)buf->off);
                        buf->buffer[buf->off] = '\0';
                        logg(LOGG_DEBUG_NV, "Garbage: %s\n", buf->buffer);
                        error = 1;
                    } else if (buf->mode == MODE_STREAM) {
                        rc = handle_stream(&conn, buf, opts, &error, &pos, readtimeout);
                        if (rc == -1)
                            break;
                        else
                            continue;
                    }
                }
                if (error && error != CL_ETIMEOUT) {
                    conn_reply_error(&conn, "Error processing command.");
                }
            }
            if (error) {
                if (buf->dumpfd != -1) {
                    close(buf->dumpfd);
                    if (buf->dumpname) {
                        cli_unlink(buf->dumpname);
                        free(buf->dumpname);
                    }
                    buf->dumpfd = -1;
                }
                thrmgr_group_terminate(buf->group);
                if (thrmgr_group_finished(buf->group, EXIT_ERROR)) {
                    if (buf->fd < 0) {
                        logg(LOGG_DEBUG_NV, "Skipping shutdown of bad socket after error (FD %d)\n", buf->fd);
                    } else {
                        logg(LOGG_DEBUG_NV, "Shutting down socket after error (FD %d)\n", buf->fd);
                        shutdown(buf->fd, 2);
                        closesocket(buf->fd);
                    }
                } else
                    logg(LOGG_DEBUG_NV, "Socket not shut down due to active tasks\n");
                buf->fd = -1;
            }
        }
        pthread_mutex_unlock(fds->buf_mutex);

        /* handle progexit */
        pthread_mutex_lock(&exit_mutex);
        if (progexit) {
            pthread_mutex_unlock(&exit_mutex);
            pthread_mutex_lock(fds->buf_mutex);
            if (sd_listen_fds(0) == 0) {
                /* only close the sockets, when not using systemd socket activation */
                for (i = 0; i < fds->nfds; i++) {
                    if (fds->buf[i].fd == -1)
                        continue;
                    thrmgr_group_terminate(fds->buf[i].group);
                    if (thrmgr_group_finished(fds->buf[i].group, EXIT_ERROR)) {
                        logg(LOGG_DEBUG_NV, "Shutdown closed fd %d\n", fds->buf[i].fd);
                        shutdown(fds->buf[i].fd, 2);
                        closesocket(fds->buf[i].fd);
                        fds->buf[i].fd = -1;
                    }
                }
            }
            pthread_mutex_unlock(fds->buf_mutex);
            break;
        }
        pthread_mutex_unlock(&exit_mutex);

        /* SIGHUP */
        if (sighup) {
            logg(LOGG_INFO, "SIGHUP caught: re-opening log file.\n");
            logg_close();
            sighup = 0;
            if (!logg_file && (opt = optget(opts, "LogFile"))->enabled)
                logg_file = opt->strarg;
        }

        /* SelfCheck */
        if (selfchk) {
            time(&current_time);
            if ((current_time - start_time) >= (time_t)selfchk) {
                if (need_db_reload()) {
                    pthread_mutex_lock(&reload_mutex);
                    reload = 1;
                    pthread_mutex_unlock(&reload_mutex);
                }
                time(&start_time);
            }
        }

        /* DB reload */
        pthread_mutex_lock(&reload_mutex);
        if (reload) {
            pthread_mutex_unlock(&reload_mutex);
            /* Reload was requested */
            pthread_mutex_lock(&reload_stage_mutex);
            if (reload_stage == RELOAD_STAGE__IDLE) {
                /* Reloading not already taking place */
                reload_stage = RELOAD_STAGE__RELOADING;
                pthread_mutex_unlock(&reload_stage_mutex);
                if (CL_SUCCESS != reload_db(&engine, dboptions, opts, thr_pool)) {
                    logg(LOGG_WARNING, "Database reload setup failed, keeping the previous instance\n");
                    pthread_mutex_lock(&reload_mutex);
                    reload = 0;
                    pthread_mutex_unlock(&reload_mutex);
                    pthread_mutex_lock(&reload_stage_mutex);
                    reload_stage = RELOAD_STAGE__IDLE;
                    pthread_mutex_unlock(&reload_stage_mutex);
                }
                pthread_mutex_lock(&reload_stage_mutex);
            }
            if (reload_stage == RELOAD_STAGE__NEW_DB_AVAILABLE) {
                /* New database available */
                if (g_newengine) {
                    /* Reload succeeded */
                    logg(LOGG_INFO, "Activating the newly loaded database...\n");
                    thrmgr_setactiveengine(g_newengine);
                    if (optget(opts, "ConcurrentDatabaseReload")->enabled) {
                        /* If concurrent database reload, we now need to free the old engine. */
                        cl_engine_free(engine);
                    }
                    engine      = g_newengine;
                    g_newengine = NULL;
                } else {
                    logg(LOGG_WARNING, "Database reload failed, keeping the previous instance\n");
                }
                reload_stage = RELOAD_STAGE__IDLE;
                pthread_mutex_unlock(&reload_stage_mutex);
                pthread_mutex_lock(&reload_mutex);
                reload = 0;
                pthread_mutex_unlock(&reload_mutex);
                time(&reloaded_time);
            } else {
                pthread_mutex_unlock(&reload_stage_mutex);
            }
        } else {
            pthread_mutex_unlock(&reload_mutex);
        }
    }

    pthread_mutex_lock(&exit_mutex);
    progexit = 1;
    pthread_mutex_unlock(&exit_mutex);
#ifdef _WIN32
    SetEvent(event_wake_accept);
#else
    if (write(acceptdata.syncpipe_wake_accept[1], "", 1) < 0) {
        logg(LOGG_WARNING, "Write to syncpipe failed\n");
    }
#endif
    /* Destroy the thread manager.
     * This waits for all current tasks to end
     */
    logg(LOGG_DEBUG, "Waiting for all threads to finish\n");
    thrmgr_destroy(thr_pool);
    if (engine) {
        thrmgr_setactiveengine(NULL);
        cl_engine_free(engine);
    }

    pthread_join(accept_th, NULL);
    fds_free(fds);
    pthread_mutex_destroy(fds->buf_mutex);
    pthread_cond_destroy(&acceptdata.cond_nfds);
#ifdef _WIN32
    CloseHandle(event_wake_accept);
    CloseHandle(event_wake_recv);
#else
    close(acceptdata.syncpipe_wake_accept[1]);
    close(acceptdata.syncpipe_wake_recv[1]);
#endif
    if (dbstat.entries)
        cl_statfree(&dbstat);
    if (sd_listen_fds(0) == 0) {
        /* only close the sockets, when not using systemd socket activation */
        logg(LOGG_DEBUG, "Shutting down the main socket%s.\n", (nsockets > 1) ? "s" : "");
        for (i = 0; i < nsockets; i++)
            shutdown(socketds[i], 2);
    }

    if ((opt = optget(opts, "PidFile"))->enabled) {
        if (unlink(opt->strarg) == -1)
            logg(LOGG_ERROR, "Can't unlink the pid file %s\n", opt->strarg);
        else
            logg(LOGG_INFO, "Pid file removed.\n");
    }

    time(&current_time);
    logg(LOGG_INFO, "--- Stopped at %s", cli_ctime(&current_time, timestr, sizeof(timestr)));

    return ret;
}

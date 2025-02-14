/*
 *  Copyright (C) 2019-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
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
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <signal.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifndef _WIN32
#include <sys/time.h>
#endif
#include <time.h>
#include <signal.h>
#if defined(HAVE_SYS_FANOTIFY_H)
#include <sys/fanotify.h>
#endif
#include <fcntl.h>

#include <curl/curl.h>

// libclamav
#include "clamav.h"
#include "others.h"

// common
#include "output.h"
#include "misc.h"
#include "optparser.h"
#include "actions.h"

#include "clamonacc.h"
#include "client/client.h"
#include "fanotif/fanotif.h"
#include "inotif/inotif.h"
#include "scan/onas_queue.h"

pthread_t ddd_pid        = 0;
pthread_t scan_queue_pid = 0;

static void onas_handle_signals(void);
static int startup_checks(struct onas_context *ctx);
static struct onas_context *g_ctx = NULL;

static void onas_clamonacc_exit(int sig)
{
    mprintf(LOGG_DEBUG, "Clamonacc: onas_clamonacc_exit(), signal %d\n", sig);
    if (sig == 11) {
        mprintf(LOGG_ERROR, "Clamonacc: clamonacc has experienced a fatal error, if you continue to see this error, please run clamonacc with --verbose and report the issue and crash report to the developers\n");
    }

    if (g_ctx) {
        if (g_ctx->fan_fd) {
            close(g_ctx->fan_fd);
        }
        g_ctx->fan_fd = 0;
    }

    mprintf(LOGG_DEBUG, "Clamonacc: attempting to stop ddd thread ... \n");
    if (ddd_pid > 0) {
        pthread_cancel(ddd_pid);
        pthread_join(ddd_pid, NULL);
    }
    ddd_pid = 0;

    mprintf(LOGG_DEBUG, "Clamonacc: attempting to stop event consumer thread ...\n");
    if (scan_queue_pid > 0) {
        pthread_cancel(scan_queue_pid);
        pthread_join(scan_queue_pid, NULL);
    }
    scan_queue_pid = 0;

    mprintf(LOGG_INFO, "Clamonacc: stopped\n");
    onas_cleanup(g_ctx);
    pthread_exit(NULL);
}

int main(int argc, char **argv)
{
    const struct optstruct *opts;
    const struct optstruct *opt;
    const struct optstruct *clamdopts;
    struct onas_context *ctx;
    int ret = 0;

    /* Initialize context */
    ctx = onas_init_context();
    if (ctx == NULL) {
        mprintf(LOGG_ERROR, "Clamonacc: can't initialize context\n");
        return 2;
    }

    /* Parse out all our command line options */
    opts = optparse(NULL, argc, argv, 1, OPT_CLAMONACC, OPT_CLAMSCAN, NULL);
    if (opts == NULL) {
        mprintf(LOGG_ERROR, "Clamonacc: can't parse command line options\n");
        return 2;
    }
    ctx->opts = opts;

    /* initialize logger */

    if ((opt = optget(opts, "log"))->enabled) {
        logg_file = opt->strarg;
        if (logg(LOGG_INFO, "--------------------------------------\n")) {
            mprintf(LOGG_ERROR, "ClamClient: problem with internal logger\n");
            return CL_EARG;
        }
    } else {
        logg_file = NULL;
    }

    if (optget(opts, "verbose")->enabled) {
        mprintf_verbose = 1;
        logg_verbose    = 1;
    }

    /* And our config file options */
    clamdopts = optparse(optget(opts, "config-file")->strarg, 0, NULL, 1, OPT_CLAMD, 0, NULL);
    if (clamdopts == NULL) {
        logg(LOGG_ERROR, "Clamonacc: can't parse clamd configuration file %s\n", optget(opts, "config-file")->strarg);
        optfree((struct optstruct *)opts);
        return 2;
    }
    ctx->clamdopts = clamdopts;

    /* Make sure we're good to begin spinup */
    ret = startup_checks(ctx);
    if (ret) {
        if (ret == (int)CL_BREAK) {
            ret = 0;
        }
        goto done;
    }

#ifndef _WIN32
    /* Daemonize if sanity checks are good to go */
    if (!optget(ctx->opts, "foreground")->enabled) {
        if (-1 == daemonize()) {
            logg(LOGG_ERROR, "Clamonacc: could not daemonize\n");
            return 2;
        }
    }
#endif

    /* Setup our client */
    switch (onas_setup_client(&ctx)) {
        case CL_SUCCESS:
            if (CL_SUCCESS == onas_check_client_connection(&ctx)) {
                break;
            }
            /* fall-through */
        case CL_BREAK:
            ret = 0;
            logg(LOGG_DEBUG, "Clamonacc: not setting up client\n");
            goto done;
            break;
        case CL_EWRITE:
            logg(LOGG_ERROR, "Clamonacc: can't set up fd passing, configuration issue -- please ensure your system \
            is capable of fdpassing before specifying the fdpass option\n");
            ret = 2;
            goto done;
        case CL_EARG:
        default:
            logg(LOGG_ERROR, "Clamonacc: can't setup client\n");
            ret = 2;
            goto done;
            break;
    }

    /* Setup our event queue */
    ctx->maxthreads = optget(ctx->clamdopts, "OnAccessMaxThreads")->numarg;

    switch (onas_scan_queue_start(&ctx)) {
        case CL_SUCCESS:
            break;
        case CL_BREAK:
        case CL_EARG:
        case CL_ECREAT:
        default:
            ret = 2;
            logg(LOGG_ERROR, "Clamonacc: can't setup event consumer queue\n");
            goto done;
            break;
    }

#if defined(HAVE_SYS_FANOTIFY_H)
    /* Setup fanotify */
    switch (onas_setup_fanotif(&ctx)) {
        case CL_SUCCESS:
            break;
        case CL_BREAK:
            ret = 0;
            goto done;
            break;
        case CL_EARG:
        default:
            mprintf(LOGG_ERROR, "Clamonacc: can't setup fanotify\n");
            ret = 2;
            goto done;
            break;
    }

    if (ctx->ddd_enabled) {
        /* Setup inotify and kickoff DDD system */
        switch (onas_enable_inotif_ddd(&ctx)) {
            case CL_SUCCESS:
                break;
            case CL_BREAK:
                ret = 0;
                goto done;
                break;
            case CL_EARG:
            default:
                mprintf(LOGG_ERROR, "Clamonacc: can't setup fanotify\n");
                ret = 2;
                goto done;
                break;
        }
    }
#else
    mprintf(LOGG_ERROR, "Clamonacc: currently, this application only runs on linux systems with fanotify enabled\n");
    goto done;
#endif

    /* Setup signal handling */
    g_ctx = ctx;
    onas_handle_signals();

    logg(LOGG_DEBUG, "Clamonacc: beginning event loops\n");
    /*  Kick off event loop(s) */
    ret = onas_start_eloop(&ctx);

done:
    /* Clean up */
    onas_cleanup(ctx);
    exit(ret);
}

static void onas_handle_signals(void)
{
    sigset_t sigset;
    struct sigaction act;

    /* ignore all signals except SIGUSR1 */
    sigfillset(&sigset);
    sigdelset(&sigset, SIGUSR1);
    sigdelset(&sigset, SIGUSR2);
    /* The behavior of a process is undefined after it ignores a
     * SIGFPE, SIGILL, SIGSEGV, or SIGBUS signal */
    sigdelset(&sigset, SIGFPE);
    sigdelset(&sigset, SIGILL);
    sigdelset(&sigset, SIGSEGV);
    sigdelset(&sigset, SIGINT);
    sigdelset(&sigset, SIGTERM);
#ifdef SIGBUS
    sigdelset(&sigset, SIGBUS);
#endif
    pthread_sigmask(SIG_SETMASK, &sigset, NULL);
    memset(&act, 0, sizeof(struct sigaction));
    act.sa_handler = onas_clamonacc_exit;
    sigfillset(&(act.sa_mask));
    sigaction(SIGUSR2, &act, NULL);
    sigaction(SIGTERM, &act, NULL);
    sigaction(SIGSEGV, &act, NULL);
    sigaction(SIGINT, &act, NULL);
}

struct onas_context *onas_init_context(void)
{
    struct onas_context *ctx = (struct onas_context *)malloc(sizeof(struct onas_context));
    if (NULL == ctx) {
        return NULL;
    }

    memset(ctx, 0, sizeof(struct onas_context));
    return ctx;
}

cl_error_t onas_check_client_connection(struct onas_context **ctx)
{

    cl_error_t err = CL_SUCCESS;

    /* 0 local, non-zero remote, errno set on error */
    (*ctx)->isremote = onas_check_remote(ctx, &err);
    if (CL_SUCCESS == err) {
        logg(LOGG_DEBUG, "Clamonacc: ");
        (*ctx)->isremote ? logg(LOGG_DEBUG, "daemon is remote\n") : logg(LOGG_DEBUG, "daemon is local\n");
    }
    return err ? CL_EACCES : CL_SUCCESS;
}

int onas_start_eloop(struct onas_context **ctx)
{
    int ret = 0;

    if (!ctx || !*ctx) {
        mprintf(LOGG_ERROR, "Clamonacc: unable to start clamonacc. (bad context)\n");
        return CL_EARG;
    }

#if defined(HAVE_SYS_FANOTIFY_H)
    ret = onas_fan_eloop(ctx);
#endif

    return ret;
}

static int startup_checks(struct onas_context *ctx)
{
#if defined(HAVE_SYS_FANOTIFY_H)
    char faerr[128];
#endif
    int ret        = 0;
    cl_error_t err = CL_SUCCESS;

    if (optget(ctx->opts, "help")->enabled) {
        help();
        ret = 2;
        goto done;
    }

#if defined(HAVE_SYS_FANOTIFY_H)
#if defined(_GNU_SOURCE)
    ctx->fan_fd = fanotify_init(FAN_CLASS_CONTENT | FAN_UNLIMITED_QUEUE | FAN_UNLIMITED_MARKS, O_LARGEFILE | O_RDONLY);
#else
    ctx->fan_fd = fanotify_init(FAN_CLASS_CONTENT | FAN_UNLIMITED_QUEUE | FAN_UNLIMITED_MARKS, O_RDONLY);
#endif
    if (ctx->fan_fd < 0) {
        logg(LOGG_ERROR, "Clamonacc: fanotify_init failed: %s\n", cli_strerror(errno, faerr, sizeof(faerr)));
        if (errno == EPERM) {
            logg(LOGG_ERROR, "Clamonacc: clamonacc must have elevated permissions ... exiting ...\n");
        }
        ret = 2;
        goto done;
    }
#endif

#if ((LIBCURL_VERSION_MAJOR < 7) || (LIBCURL_VERSION_MAJOR == 7 && LIBCURL_VERSION_MINOR < 40))
    if (optget(ctx->opts, "fdpass")->enabled || !optget(ctx->clamdopts, "TCPSocket")->enabled || !optget(ctx->clamdopts, "TCPAddr")->enabled) {
        logg(LOGG_ERROR, "Clamonacc: Version of curl is too low to use fdpassing. Please use tcp socket streaming instead\n.");
        ret = 2;
        goto done;
    }
#endif

    if (curl_global_init(CURL_GLOBAL_NOTHING)) {
        ret = 2;
        goto done;
    }

    if (optget(ctx->opts, "version")->enabled) {
        onas_print_server_version(&ctx);
        ret = 2;
        goto done;
    }

    if (optget(ctx->opts, "ping")->enabled && !optget(ctx->opts, "wait")->enabled) {
        int16_t ping_result = onas_ping_clamd(&ctx);
        switch (ping_result) {
            case 0:
                ret = (int)CL_BREAK;
                break;
            case 1:
                ret = (int)CL_ETIMEOUT;
                break;
            default:
                ret = 2;
                break;
        }
        goto done;
    }

    if (optget(ctx->opts, "wait")->enabled) {
        int16_t ping_result = onas_ping_clamd(&ctx);
        switch (ping_result) {
            case 0:
                ret = (int)CL_SUCCESS;
                break;
            case 1:
                ret = (int)CL_ETIMEOUT;
                goto done;
            default:
                ret = 2;
                goto done;
        }
    }

    if (0 == onas_check_remote(&ctx, &err)) {
        if (CL_SUCCESS != err) {
            logg(LOGG_ERROR, "Clamonacc: daemon is local, but a connection could not be established\n");
            ret = 2;
            goto done;
        }

        if (!optget(ctx->clamdopts, "OnAccessExcludeUID")->enabled &&
            !optget(ctx->clamdopts, "OnAccessExcludeUname")->enabled && !optget(ctx->clamdopts, "OnAccessExcludeRootUID")->enabled) {
            logg(LOGG_ERROR, "Clamonacc: at least one of OnAccessExcludeUID, OnAccessExcludeUname, or OnAccessExcludeRootUID must be specified ... it is recommended you exclude the clamd instance UID or uname to prevent infinite event scanning loops\n");
            ret = 2;
            goto done;
        }
    }

done:
    return ret;
}

void help(void)
{
    mprintf_stdout = 1;

    mprintf(LOGG_INFO, "\n");
    mprintf(LOGG_INFO, "           ClamAV: On Access Scanning Application and Client %s\n", get_version());
    mprintf(LOGG_INFO, "           By The ClamAV Team: https://www.clamav.net/about.html#credits\n");
    mprintf(LOGG_INFO, "           (C) 2025 Cisco Systems, Inc.\n");
    mprintf(LOGG_INFO, "\n");
    mprintf(LOGG_INFO, "    clamonacc [options] [file/directory/-]\n");
    mprintf(LOGG_INFO, "\n");
    mprintf(LOGG_INFO, "    --help                 -h          Show this help\n");
    mprintf(LOGG_INFO, "    --version              -V          Print version number and exit\n");
    mprintf(LOGG_INFO, "    --verbose              -v          Be verbose\n");
    mprintf(LOGG_INFO, "    --log=FILE             -l FILE     Save scanning output to FILE\n");
    mprintf(LOGG_INFO, "    --foreground           -F          Output to foreground and do not daemonize\n");
    mprintf(LOGG_INFO, "    --watch-list=FILE      -W FILE     Watch directories from FILE\n");
    mprintf(LOGG_INFO, "    --exclude-list=FILE    -e FILE     Exclude directories from FILE\n");
    mprintf(LOGG_INFO, "    --ping                 -p A[:I]    Ping clamd up to [A] times at optional interval [I] until it responds.\n");
    mprintf(LOGG_INFO, "    --wait                 -w          Wait up to 30 seconds for clamd to start. Optionally use alongside --ping to set attempts [A] and interval [I] to check clamd.\n");
    mprintf(LOGG_INFO, "    --remove                           Remove infected files. Be careful!\n");
    mprintf(LOGG_INFO, "    --move=DIRECTORY                   Move infected files into DIRECTORY\n");
    mprintf(LOGG_INFO, "    --copy=DIRECTORY                   Copy infected files into DIRECTORY\n");
    mprintf(LOGG_INFO, "    --config-file=FILE     -c FILE     Read configuration from FILE\n");
    mprintf(LOGG_INFO, "    --allmatch             -z          Continue scanning within file after finding a match.\n");
    mprintf(LOGG_INFO, "    --fdpass                           Pass filedescriptor to clamd (useful if clamd is running as a different user)\n");
    mprintf(LOGG_INFO, "    --stream                           Force streaming files to clamd (for debugging and unit testing)\n");
    mprintf(LOGG_INFO, "\n");

    exit(0);
}

void onas_cleanup(struct onas_context *ctx)
{
    onas_context_cleanup(ctx);
    logg_close();
}

void onas_context_cleanup(struct onas_context *ctx)
{
    close(ctx->fan_fd);
    optfree((struct optstruct *)ctx->opts);
    optfree((struct optstruct *)ctx->clamdopts);
    ctx->opts      = NULL;
    ctx->clamdopts = NULL;
    free(ctx);
}

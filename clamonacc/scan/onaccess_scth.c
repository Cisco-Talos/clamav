/*
 *  Copyright (C) 2015-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
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

#if defined(FANOTIFY)

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#include <pthread.h>
#include <sys/fanotify.h>

#include "shared/optparser.h"
#include "shared/output.h"

#include "libclamav/others.h"
#include "../misc/priv_fts.h"
#include "../misc/onaccess_others.h"
#include "../client/onaccess_client.h"
#include "onaccess_scth.h"
//#include "onaccess_others.h"

#include "libclamav/clamav.h"

static pthread_mutex_t onas_scan_lock = PTHREAD_MUTEX_INITIALIZER;

//static int onas_scan(struct onas_context **ctx, const char *fname, STATBUF sb, int *infected, int *err, cl_error_t *ret_code);
static int onas_scan_safe(struct onas_context **ctx, const char *fname, STATBUF sb, int *infected, int *err, cl_error_t *ret_code);
static int onas_scth_scanfile(struct onas_context **ctx, const char *fname, STATBUF sb, struct onas_scan_event *event_data, int *infected, int *err, cl_error_t *ret_code);
static int onas_scth_handle_dir(struct onas_context **ctx, const char *pathname, struct onas_scan_event *event_data);
//static int onas_scth_handle_file(struct onas_context **ctx, const char *pathname, struct onas_scan_event *event_data);

static void onas_scth_exit(int sig);

static void onas_scth_exit(int sig)
{
    logg("*ScanOnAccess: onas_scth_exit(), signal %d\n", sig);

    pthread_exit(NULL);
}

/**
 * Scan wrapper, used by both inotify and fanotify threads. Owned by scanthread to force multithreaded client archtiecture
 * which better avoids kernel level deadlocks from fanotify blocking/prevention
 */
int onas_scan(struct onas_context **ctx, const char *fname, STATBUF sb, int *infected, int *err, cl_error_t *ret_code)
{
    int ret             = 0;
    int i = 0;

    ret = onas_scan_safe(ctx, fname, sb, infected, err, ret_code);

    if (*err) {
        switch (*ret_code) {
            case CL_EACCES:
            case CL_ESTAT:

                logg("*ClamMisc: internal issue (daemon could not access directory/file %s)\n", fname);
                break;
                /* TODO: handle other errors */
            case CL_EPARSE:
            case CL_EREAD:
            case CL_EWRITE:
            case CL_EMEM:
            case CL_ENULLARG:
            default:
                logg("~ClamMisc: internal issue (client failed to scan)\n");
        }
	    if ((*ctx)->retry_on_error) {
		    logg("*ClamMisc: reattempting scan ... \n");
		    while (err) {
			    ret = onas_scan_safe(ctx, fname, sb, infected, err, ret_code);

			    i++;
			    if (*err && i == (*ctx)->retry_attempts) {
				    *err = 0;
			    }
		    }
	    }
    }

    return ret;
}

/**
 * Thread-safe scan wrapper to ensure there's no processs contention over use of the socket.
 */
static int onas_scan_safe(struct onas_context **ctx, const char *fname, STATBUF sb, int *infected, int *err, cl_error_t *ret_code)
{
	int ret = 0;

	pthread_mutex_lock(&onas_scan_lock);

	ret = onas_client_scan(ctx, fname, sb, infected, err, ret_code);

	pthread_mutex_unlock(&onas_scan_lock);

	return ret;
}

int onas_scth_scanfile(struct onas_context **ctx, const char *fname, STATBUF sb, struct onas_scan_event *event_data, int *infected, int *err, cl_error_t *ret_code)
{
	struct fanotify_response res;
	int ret = 0;
	int i = 0;

	if (event_data->b_fanotify) {
		res.fd = event_data->fmd->fd;
		res.response = FAN_ALLOW;
	}

	if (event_data->b_scan) {
		ret = onas_scan(ctx, fname, sb, infected, err, ret_code);

		if (*err && *ret_code != CL_SUCCESS) {
			logg("*Clamonacc: scan failed with error code %d\n", *ret_code);
		}


		if (event_data->b_fanotify) {
			if ((*err && *ret_code && (*ctx)->deny_on_error) || *infected) {
				res.response = FAN_DENY;
			}
		}
	}


	if (event_data->b_fanotify) {
		if(event_data->fmd->mask & FAN_ALL_PERM_EVENTS) {
			ret = write((*ctx)->fan_fd, &res, sizeof(res));
			if(ret == -1)
				logg("!Clamonacc: internal error (can't write to fanotify)\n");
		}
	}

	return ret;
}

static int onas_scth_handle_dir(struct onas_context **ctx, const char *pathname, struct onas_scan_event *event_data) {
    FTS *ftsp = NULL;
	int32_t ftspopts = FTS_PHYSICAL | FTS_XDEV;
	int32_t infected = 0;
	int32_t err = 0;
        cl_error_t ret_code = CL_SUCCESS;
	int32_t ret = 0;
	int32_t fres = 0;
    FTSENT *curr = NULL;
        STATBUF sb;

    char *const pathargv[] = {(char *)pathname, NULL};
    if (!(ftsp = _priv_fts_open(pathargv, ftspopts, NULL))) return CL_EOPEN;

    while ((curr = _priv_fts_read(ftsp))) {
        if (curr->fts_info != FTS_D) {

			fres = CLAMSTAT(curr->fts_path, &sb);

			if ((*ctx)->sizelimit) {
				if (fres != 0 || sb.st_size > (*ctx)->sizelimit)  {
					//okay to skip, directory from inotify events (probably) won't block w/ protection enabled
                                        //log here later
					continue;
				}
			}

                        ret = onas_scth_scanfile(ctx, curr->fts_path, sb, event_data, &infected, &err, &ret_code);
                        // probs need to error check here later, or at least log
        }
    }

    return ret;
}

int onas_scth_handle_file(struct onas_context **ctx, const char *pathname, struct onas_scan_event *event_data) {

	STATBUF sb;
	int32_t infected = 0;
	int32_t err = 0;
	cl_error_t ret_code = CL_SUCCESS;
	int fres = 0;
	int ret = 0;

	if (!pathname) return CL_ENULLARG;

	fres = CLAMSTAT(pathname, &sb);
	if ((*ctx)->sizelimit) {
		if (fres != 0 || sb.st_size > (*ctx)->sizelimit)  {
			/* don't skip so we avoid lockups, but don't scan either */
			event_data->b_scan = 0;
		}
	}

	ret = onas_scth_scanfile(ctx, pathname, sb, event_data, &infected, &err, &ret_code);
	// probs need to error check here later, or at least log

    return ret;
}

void *onas_scan_th(void *arg) {

    struct scth_thrarg *tharg = (struct scth_thrarg *)arg;
	struct onas_scan_event *event_data = NULL;
	struct onas_context **ctx = NULL;
    sigset_t sigset;
    struct sigaction act;

    /* ignore all signals except SIGUSR1 */
    sigfillset(&sigset);
    sigdelset(&sigset, SIGUSR1);
    /* The behavior of a process is undefined after it ignores a
	 * SIGFPE, SIGILL, SIGSEGV, or SIGBUS signal */
    sigdelset(&sigset, SIGFPE);
    sigdelset(&sigset, SIGILL);
	//sigdelset(&sigset, SIGSEGV);
#ifdef SIGBUS
    sigdelset(&sigset, SIGBUS);
#endif
    pthread_sigmask(SIG_SETMASK, &sigset, NULL);
    memset(&act, 0, sizeof(struct sigaction));
    act.sa_handler = onas_scth_exit;
    sigfillset(&(act.sa_mask));
    sigaction(SIGUSR1, &act, NULL);
    sigaction(SIGSEGV, &act, NULL);

	if (NULL == tharg || NULL == tharg->ctx || NULL == tharg->event_data || NULL == tharg->event_data->pathname || NULL == (*(tharg->ctx))->opts) {
        logg("ScanOnAccess: Invalid thread arguments for extra scanning\n");
        goto done;
    }

        /* this event_data is ours and ours alone */
	event_data = tharg->event_data;

        /* we share this context globally--it's not ours to touch/edit */
	ctx = tharg->ctx;

        if (event_data->b_inotify) {
            if (event_data->extra_options & ONAS_SCTH_ISDIR) {
                logg("*ScanOnAccess: Performing additional scanning on directory '%s'\n", event_data->pathname);
                onas_scth_handle_dir(ctx, event_data->pathname, event_data);
            } else if (event_data->extra_options & ONAS_SCTH_ISFILE) {
                logg("*ScanOnAccess: Performing additional scanning on file '%s'\n", event_data->pathname);
                onas_scth_handle_file(ctx, event_data->pathname, event_data);
            }
        } else if (event_data->b_fanotify) {
            logg("*ScanOnAccess: Performing scanning on file '%s'\n", event_data->pathname);
            onas_scth_handle_file(ctx, event_data->pathname, event_data);
    }
        /* TODO: else something went wrong and we should error out here */

done:
        /* our job to cleanup event data: worker queue just kicks us off, drops the event object
         * from the queue and forgets about us. */

	if (NULL != tharg) {
		if (NULL != tharg->event_data) {
			if (NULL != tharg->event_data->pathname) {
				free(tharg->event_data->pathname);
				event_data->pathname = NULL;
    }
			free(tharg->event_data);
			tharg->event_data = NULL;
    }
		/* don't free context, cleanup for context is handled at the highest layer */
        free(tharg);
    }

    return NULL;
}
#endif

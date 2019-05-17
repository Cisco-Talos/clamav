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
static cl_error_t onas_scan_safe(struct onas_scan_event *event_data, const char *fname, STATBUF sb, int *infected, int *err, cl_error_t *ret_code);
static cl_error_t onas_scth_scanfile(struct onas_scan_event *event_data, const char *fname, STATBUF sb, int *infected, int *err, cl_error_t *ret_code);
static cl_error_t onas_scth_handle_dir(struct onas_scan_event *event_data, const char *pathname);
static cl_error_t onas_scth_handle_file(struct onas_scan_event *event_data, const char *pathname);

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
int onas_scan(struct onas_scan_event *event_data, const char *fname, STATBUF sb, int *infected, int *err, cl_error_t *ret_code)
{
    int ret             = 0;
    int i = 0;
    uint8_t retry_on_error = event_data->bool_opts & ONAS_SCTH_B_RETRY_ON_E;

    ret = onas_scan_safe(event_data, fname, sb, infected, err, ret_code);

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
	    if (retry_on_error) {
		    logg("*ClamMisc: reattempting scan ... \n");
		    while (err) {
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
 * Thread-safe scan wrapper to ensure there's no processs contention over use of the socket.
 */
static cl_error_t onas_scan_safe(struct onas_scan_event *event_data, const char *fname, STATBUF sb, int *infected, int *err, cl_error_t *ret_code) {

	int ret = 0;

	pthread_mutex_lock(&onas_scan_lock);

	ret = onas_client_scan(event_data->tcpaddr, event_data->portnum, event_data->scantype, event_data->maxstream,
                                    fname, event_data->timeout, sb, infected, err, ret_code);

	pthread_mutex_unlock(&onas_scan_lock);

	return ret;
}

static cl_error_t onas_scth_scanfile(struct onas_scan_event *event_data, const char *fname, STATBUF sb, int *infected, int *err, cl_error_t *ret_code) {

	struct fanotify_response res;
	int ret = 0;

	uint8_t b_scan;
	uint8_t b_fanotify;
	uint8_t b_deny_on_error;

	if (NULL == event_data || NULL == fname || NULL == infected || NULL == err || NULL == ret_code) {
		/* TODO: log */
		return CL_ENULLARG;
	}

	b_scan = event_data->bool_opts & ONAS_SCTH_B_SCAN ? 1 : 0;
        b_fanotify = event_data->bool_opts & ONAS_SCTH_B_FANOTIFY ? 1 : 0;
        b_deny_on_error = event_data->bool_opts & ONAS_SCTH_B_DENY_ON_E ? 1 : 0;

	if (b_fanotify) {
		res.fd = event_data->fmd->fd;
		res.response = FAN_ALLOW;
	}

	if (b_scan) {
		ret = onas_scan(event_data, fname, sb, infected, err, ret_code);

		if (*err && *ret_code != CL_SUCCESS) {
			logg("*ClamWorker: scan failed with error code %d\n", *ret_code);
		}


		if (b_fanotify) {
			if ((*err && *ret_code && b_deny_on_error) || *infected) {
				res.response = FAN_DENY;
			}
		}
	}


	if (b_fanotify) {
		if(event_data->fmd->mask & FAN_ALL_PERM_EVENTS) {
			ret = write(event_data->fan_fd, &res, sizeof(res));
			if(ret == -1) {
				logg("!ClamWorker: internal error (can't write to fanotify)\n");
				ret = CL_EWRITE;
			}
		}
	}

        if (b_fanotify) {
            if (-1 == close(event_data->fmd->fd) ) {
                logg("!ClamWorker: internal error (can't close fanotify meta fd)\n");
                ret = CL_EUNLINK;
		}
	}

	return ret;
}

static cl_error_t onas_scth_handle_dir(struct onas_scan_event *event_data, const char *pathname) {
    FTS *ftsp = NULL;
	int32_t ftspopts = FTS_PHYSICAL | FTS_XDEV;
	FTSENT *curr = NULL;

	int32_t infected = 0;
	int32_t err = 0;
        cl_error_t ret_code = CL_SUCCESS;
	cl_error_t ret = CL_SUCCESS;

	int32_t fres = 0;
        STATBUF sb;

    char *const pathargv[] = {(char *)pathname, NULL};

	if (!(ftsp = _priv_fts_open(pathargv, ftspopts, NULL))) {
		return CL_EOPEN;
	}

    while ((curr = _priv_fts_read(ftsp))) {
        if (curr->fts_info != FTS_D) {

			fres = CLAMSTAT(curr->fts_path, &sb);

			if (event_data->sizelimit) {
				if (fres != 0 || sb.st_size > event_data->sizelimit)  {
					/* okay to skip w/o allow/deny since dir comes from inotify
					 * events and (probably) won't block w/ protection enabled */
                                        // TODO: log here later ??
					continue;
				}
			}

                        ret = onas_scth_scanfile(event_data, curr->fts_path, sb, &infected, &err, &ret_code);
                        // TODO: probs need to error check here later, or at least log
        }
    }

    return ret;
}

static cl_error_t onas_scth_handle_file(struct onas_scan_event *event_data, const char *pathname) {

	STATBUF sb;
	int32_t infected = 0;
	int32_t err = 0;
	cl_error_t ret_code = CL_SUCCESS;
	int fres = 0;
	cl_error_t ret = 0;

	if (NULL == pathname || NULL == event_data) {
            return CL_ENULLARG;
        }

	fres = CLAMSTAT(pathname, &sb);
	if (event_data->sizelimit) {
		if (fres != 0 || sb.st_size > event_data->sizelimit)  {
			/* don't skip so we avoid lockups, but don't scan either;
			 * while it should be obvious, this will unconditionally set
			 * the bit in the map to 0 regardless of original orientation */
                        event_data->bool_opts &= ((uint16_t) ~ONAS_SCTH_B_SCAN);
		}
	}

	ret = onas_scth_scanfile(event_data, pathname, sb, &infected, &err, &ret_code);
	// probs need to error check here later, or at least log

    return ret;
}

void *onas_scan_worker(void *arg) {

	struct onas_scan_event *event_data = (struct onas_scan_event *) arg;

	uint8_t b_dir;
	uint8_t b_file;
	uint8_t b_inotify;
	uint8_t b_fanotify;

	if (NULL == event_data || NULL == event_data->pathname) {
		logg("ClamWorker: invalid worker arguments for scanning thread\n");
                if (event_data) {
                    logg("ClamWorker: pathname is null\n");
                }
        goto done;
    }

	/* load in boolean info from event struct; makes for easier reading--you're welcome */
	b_dir = event_data->bool_opts & ONAS_SCTH_B_DIR ? 1 : 0;
	b_file = event_data->bool_opts & ONAS_SCTH_B_FILE ? 1 : 0;
	b_inotify = event_data->bool_opts & ONAS_SCTH_B_INOTIFY ? 1 : 0;
	b_fanotify = event_data->bool_opts & ONAS_SCTH_B_FANOTIFY ? 1 : 0;


	if (b_inotify) {
		logg("*ClamWorker: handling inotify event ...\n");

		if (b_dir) {
			logg("*ClamWorker: performing (extra) scanning on directory '%s'\n", event_data->pathname);
			onas_scth_handle_dir(event_data, event_data->pathname);

		} else if (b_file) {
			logg("*ClamWorker: performing (extra) scanning on file '%s'\n", event_data->pathname);
			onas_scth_handle_file(event_data, event_data->pathname);

            }

	} else if (b_fanotify) {

		logg("*ClamWorker: performing scanning on file '%s'\n", event_data->pathname);
		onas_scth_handle_file(event_data, event_data->pathname);
    }
	/* TODO: else something went wrong and we should probably error out here, maybe try to recover somehow */

done:
	/* our job to cleanup event data: worker queue just kicks us off in a thread pool, drops the event object
	 * from the queue and forgets about us */

	if (NULL != event_data) {
		if (NULL != event_data->pathname) {
			free(event_data->pathname);
				event_data->pathname = NULL;
    }
		free(event_data);
		event_data = NULL;
    }

    return NULL;
}

/* Simple utility function for external interfaces to add relevant context information to scan_event struct;
 * doing this mapping cuts down significantly on memory overhead when queueing hundreds of these scan_event structs */
cl_error_t onas_map_context_info_to_event_data(struct onas_context *ctx, struct onas_scan_event **event_data) {

    if(NULL == ctx || NULL == event_data || NULL == *event_data) {
        logg("*ClamScThread: context and scan event struct are null ...\n");
        return CL_ENULLARG;
    }

    (*event_data)->scantype = ctx->scantype;
    (*event_data)->timeout = ctx->timeout;
    (*event_data)->maxstream = ctx->maxstream;
    (*event_data)->tcpaddr = cli_strdup((optget(ctx->clamdopts, "TCPAddr"))->strarg);
    (*event_data)->portnum = ctx->portnum;
    (*event_data)->fan_fd = ctx->fan_fd;
    (*event_data)->sizelimit = ctx->sizelimit;
    (*event_data)->retry_attempts = ctx->retry_attempts;

    if (ctx->retry_on_error) {
        (*event_data)->bool_opts |= ONAS_SCTH_B_RETRY_ON_E;
    }

    if (ctx->deny_on_error) {
        (*event_data)->bool_opts |= ONAS_SCTH_B_DENY_ON_E;
    }

    return CL_SUCCESS;
}
#endif

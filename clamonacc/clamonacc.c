/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *
 *  Authors: Tomasz Kojm, aCaB, Mickey Sola
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
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifndef _WIN32
#include <sys/time.h>
#endif
#include <time.h>
#include <signal.h>

#include "libclamav/clamav.h"
#include "libclamav/others.h"
#include "shared/output.h"
#include "shared/misc.h"
#include "shared/optparser.h"
#include "shared/actions.h"


#include "clamonacc.h"
#include "./client/onaccess_client.h"
#include "./fanotif/onaccess_fan.h"
#include "./inotif/onaccess_ddd.h"
#include "./scan/onaccess_scque.h"


pthread_t ddd_pid = 0;

int main(int argc, char **argv)
{
	const struct optstruct *opts;
	const struct optstruct *clamdopts;
	struct onas_context *ctx;
	int ret = 0;

	/* Initialize context */
	ctx = onas_init_context();
	if(ctx == NULL) {
		logg("!Clamonacc: can't initialize context\n");
		return 2;
	}

	/* Parse out all our command line options */
	opts = optparse(NULL, argc, argv, 1, OPT_CLAMONACC, OPT_CLAMSCAN, NULL);
	if(opts == NULL) {
		logg("!Clamonacc: can't parse command line options\n");
		return 2;
	}
	ctx->opts = opts;

	clamdopts = optparse(optget(opts, "config-file")->strarg, 0, NULL, 1, OPT_CLAMD, 0, NULL);
	if (clamdopts == NULL) {
		logg("!Clamonacc: can't parse clamd configuration file %s\n", optget(opts, "config-file")->strarg);
		return 2;
	}
	ctx->clamdopts = clamdopts;

        /* Setup our event queue */
        switch(onas_scanque_start(&ctx)) {
            case CL_SUCCESS:
                break;
            case CL_BREAK:
            case CL_EARG:
            case CL_ECREAT:
            default:
                ret = 2;
                logg("!Clamonacc: can't setup event consumer queue\n");
                goto clean_up;
                break;
        }

	/* Setup our client */
	switch(onas_setup_client(&ctx)) {
		case CL_SUCCESS:
			if (CL_SUCCESS == onas_check_client_connection(&ctx)) {
				break;
			}
		case CL_BREAK:
			ret = 0;
			logg("*Clamonacc: not setting up client\n");
			goto clean_up;
			break;
		case CL_EARG:
		default:
			logg("!Clamonacc: can't setup client\n");
			ret = 2;
			goto clean_up;
			break;
	}
#if defined(FANOTIFY)
	/* Setup fanotify */
	switch(onas_setup_fanotif(&ctx)) {
		case CL_SUCCESS:
			break;
		case CL_BREAK:
			ret = 0;
			goto clean_up;
			break;
		case CL_EARG:
		default:
			mprintf("!Clamonacc: can't setup fanotify\n");
			ret = 2;
			goto clean_up;
			break;
	}

	if (ctx->ddd_enabled) {
		/* Setup inotify and kickoff DDD system */
		switch(onas_enable_inotif_ddd(&ctx)) {
			case CL_SUCCESS:
				break;
			case CL_BREAK:
				ret = 0;
				goto clean_up;
				break;
			case CL_EARG:
			default:
				mprintf("!Clamonacc: can't setup fanotify\n");
				ret = 2;
				goto clean_up;
				break;
		}
	}
#else
	mprintf("!Clamonacc: currently, this application only runs on linux systems with fanotify enabled\n");
	goto clean_up;
#endif

        logg("*Clamonacc: beginning event loops\n");
	/*  Kick off event loop(s) */
	ret = onas_start_eloop(&ctx);

	/* Clean up */
clean_up:
	onas_cleanup(ctx);
	exit(ret);
}

struct onas_context *onas_init_context(void) {
    struct onas_context *ctx = (struct onas_context*) cli_malloc(sizeof(struct onas_context));
    if (NULL == ctx) {
        return NULL;
    }

    memset(ctx, 0, sizeof(struct onas_context));
    return ctx;
}

cl_error_t onas_check_client_connection(struct onas_context **ctx) {

	cl_error_t err = CL_SUCCESS;

	/* 0 local, non-zero remote, errno set on error */
	(*ctx)->isremote = onas_check_remote(ctx, &err);
	if (CL_SUCCESS == err ) {
		logg("*Clamonacc: ");
		(*ctx)->isremote ? logg("*daemon is remote\n") : logg("*daemon is local\n");
	}
	return err ? CL_EACCES : CL_SUCCESS;
}

int onas_start_eloop(struct onas_context **ctx) {
	int ret = 0;

	if (!ctx || !*ctx) {
		mprintf("!Clamonacc: unable to start clamonacc. (bad context)\n");
		return CL_EARG;
	}

#ifdef C_LINUX
	ret = onas_fan_eloop(ctx);
#endif

	return ret;
}

void help(void)
{
    mprintf_stdout = 1;

    mprintf("\n");
    mprintf("           ClamAV: On Access Scanning Application and Client %s\n", get_version());
    mprintf("           By The ClamAV Team: https://www.clamav.net/about.html#credits\n");
    mprintf("           (C) 2007-2019 Cisco Systems, Inc.\n");
    mprintf("\n");
    mprintf("    clamonacc [options] [file/directory/-]\n");
    mprintf("\n");
    mprintf("    --help                 -h          Show this help\n");
    mprintf("    --version              -V          Print version number and exit\n");
    mprintf("    --verbose              -v          Be verbose\n");
    mprintf("    --log=FILE             -l FILE     Save scanning output to FILE\n");
    mprintf("    --watch-list=FILE      -w FILE     Watch directories from FILE\n");
    mprintf("    --exclude-list=FILES   -f FILE     Exclude directories from FILE\n");
    mprintf("    --remove                           Remove infected files. Be careful!\n");
    mprintf("    --move=DIRECTORY                   Move infected files into DIRECTORY\n");
    mprintf("    --copy=DIRECTORY                   Copy infected files into DIRECTORY\n");
    mprintf("    --config-file=FILE                 Read configuration from FILE.\n");
    mprintf("    --allmatch             -z          Continue scanning within file after finding a match.\n");
    mprintf("    --infected             -i          Only print infected files\n");
    mprintf("    --fdpass                           Pass filedescriptor to clamd (useful if clamd is running as a different user)\n");
    mprintf("    --stream                           Force streaming files to clamd (for debugging and unit testing)\n");
    mprintf("\n");

    exit(0);
}

void* onas_cleanup(struct onas_context *ctx) {
	onas_context_cleanup(ctx);
	cl_cleanup_crypto();
	logg_close();
}

void* onas_context_cleanup(struct onas_context *ctx) {
	close(ctx->fan_fd);
	optfree((struct optstruct *) ctx->opts);
	optfree((struct optstruct *) ctx->clamdopts);
	ctx->opts = NULL;
	ctx->clamdopts = NULL;
	free(ctx);
}

/*int main(int argc, char **argv)
{
	int ds, dms, ret, infected = 0, err = 0;
	struct timeval t1, t2;
	time_t starttime;
#ifndef _WIN32
	struct sigaction sigact;
#endif

    memset(&sigact, 0, sizeof(struct sigaction));
    sigact.sa_handler = SIG_IGN;
    sigemptyset(&sigact.sa_mask);
    sigaddset(&sigact.sa_mask, SIGPIPE);
    sigaction(SIGPIPE, &sigact, NULL);

    time(&starttime);
    ctime() does \n, but I need it once more

    gettimeofday(&t1, NULL);

    ret = client(opts, &infected, &err);
}*/

/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *
 *  Authors: Tomasz Kojm, aCaB
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

#include "clamav.h"

#include "libclamav/clamav.h"
#include "shared/output.h"
#include "shared/misc.h"
#include "shared/optparser.h"
#include "shared/actions.h"

#include "client.h"

void help(void);

extern int printinfected;
struct optstruct *clamdopts = NULL;

static void print_server_version(const struct optstruct *opt)
{
    if(get_clamd_version(opt)) {
	/* can't get version from server, fallback */
	printf("ClamAV %s\n", get_version());
    }
}

int main(int argc, char **argv)
{
	int ds, dms, ret, infected = 0, err = 0;
	struct timeval t1, t2;
	time_t starttime;
        struct optstruct *opts;
        const struct optstruct *opt;
#ifndef _WIN32
	struct sigaction sigact;
#endif

    if((opts = optparse(NULL, argc, argv, 1, OPT_CLAMDSCAN, OPT_CLAMSCAN, NULL)) == NULL) {
	mprintf("!Can't parse command line options\n");
	return 2;
    }

    if((clamdopts = optparse(optget(opts, "config-file")->strarg, 0, NULL, 1, OPT_CLAMD, 0, NULL)) == NULL) {
	logg("!Can't parse clamd configuration file %s\n", optget(opts, "config-file")->strarg);
	return 2;
    }

    if(optget(opts, "verbose")->enabled) {
	mprintf_verbose = 1;
	logg_verbose = 1;
    }

    if(optget(opts, "quiet")->enabled)
	mprintf_quiet = 1;

    if(optget(opts, "stdout")->enabled)
	mprintf_stdout = 1;

    if(optget(opts, "version")->enabled) {
	print_server_version(opts);
	optfree(opts);
	optfree(clamdopts);
	exit(0);
    }

    if(optget(opts, "help")->enabled) {
	optfree(opts);
	optfree(clamdopts);
    	help();
    }

    if(optget(opts, "infected")->enabled)
	printinfected = 1;

    /* initialize logger */

    if((opt = optget(opts, "log"))->enabled) {
	logg_file = opt->strarg;
	if(logg("--------------------------------------\n")) {
	    mprintf("!Problem with internal logger.\n");
	    optfree(opts);
	    optfree(clamdopts);
	    exit(2);
	}
    } else 
	logg_file = NULL;


    if(optget(opts, "reload")->enabled) {
	ret = reload_clamd_database(opts);
	optfree(opts);
	optfree(clamdopts);
	logg_close();
	exit(ret);
    }

    if(actsetup(opts)) {
	optfree(opts);
	optfree(clamdopts);
	logg_close();
	exit(2);
    }

#ifndef _WIN32
    memset(&sigact, 0, sizeof(struct sigaction));
    sigact.sa_handler = SIG_IGN;
    sigemptyset(&sigact.sa_mask);
    sigaddset(&sigact.sa_mask, SIGPIPE);
    sigaction(SIGPIPE, &sigact, NULL);
#endif

    time(&starttime);
    /* ctime() does \n, but I need it once more */

    gettimeofday(&t1, NULL);

    ret = client(opts, &infected, &err);
    optfree(clamdopts);

    /* TODO: Implement STATUS in clamd */
    if(!optget(opts, "no-summary")->enabled) {
	gettimeofday(&t2, NULL);
	ds = t2.tv_sec - t1.tv_sec;
	dms = t2.tv_usec - t1.tv_usec;
	ds -= (dms < 0) ? (1):(0);
	dms += (dms < 0) ? (1000000):(0);
	logg("\n----------- SCAN SUMMARY -----------\n");
	logg("Infected files: %d\n", infected);
	if(err)
	    logg("Total errors: %d\n", err);
	if(notremoved) {
	    logg("Not removed: %d\n", notremoved);
	}
	if(notmoved) {
	    logg("Not moved: %d\n", notmoved);
	}
	logg("Time: %d.%3.3d sec (%d m %d s)\n", ds, dms/1000, ds/60, ds%60);
    }

    logg_close();
    optfree(opts);
    cl_cleanup_crypto();
    exit(ret);
}

void help(void)
{
    mprintf_stdout = 1;

    mprintf("\n");
    mprintf("                      Clam AntiVirus: Daemon Client %s\n", get_version());
    mprintf("           By The ClamAV Team: https://www.clamav.net/about.html#credits\n");
    mprintf("           (C) 2019 Cisco Systems, Inc.\n");
    mprintf("\n");
    mprintf("    clamdscan [options] [file/directory/-]\n");
    mprintf("\n");
    mprintf("    --help              -h             Show this help\n");
    mprintf("    --version           -V             Print version number and exit\n");
    mprintf("    --verbose           -v             Be verbose\n");
    mprintf("    --quiet                            Be quiet, only output error messages\n");
    mprintf("    --stdout                           Write to stdout instead of stderr\n");
    mprintf("                                       (this help is always written to stdout)\n");
    mprintf("    --log=FILE          -l FILE        Save scan report in FILE\n");
    mprintf("    --file-list=FILE    -f FILE        Scan files from FILE\n");
    mprintf("    --remove                           Remove infected files. Be careful!\n");
    mprintf("    --move=DIRECTORY                   Move infected files into DIRECTORY\n");
    mprintf("    --copy=DIRECTORY                   Copy infected files into DIRECTORY\n");
    mprintf("    --config-file=FILE                 Read configuration from FILE.\n");
    mprintf("    --allmatch            -z           Continue scanning within file after finding a match.\n");
    mprintf("    --multiscan           -m           Force MULTISCAN mode\n");
    mprintf("    --infected            -i           Only print infected files\n");
    mprintf("    --no-summary                       Disable summary at end of scanning\n");
    mprintf("    --reload                           Request clamd to reload virus database\n");
    mprintf("    --fdpass                           Pass filedescriptor to clamd (useful if clamd is running as a different user)\n");
    mprintf("    --stream                           Force streaming files to clamd (for debugging and unit testing)\n");
    mprintf("\n");

    exit(0);
}

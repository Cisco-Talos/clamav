/*
 *  Copyright (C) 2002 - 2005 Tomasz Kojm <tkojm@clamav.net>
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>
#include <signal.h>

#include "options.h"
#include "others.h"
#include "shared.h"
#include "defaults.h"
#include "client.h"
#include "output.h"
#include "misc.h"

void help(void);

short printinfected = 0;

extern int notremoved, notmoved;


void clamscan(struct optstruct *opt)
{
	int ds, dms, ret, infected;
	struct timeval t1, t2;
	struct timezone tz;
	time_t starttime;


    /* initialize some important variables */

    if(optc(opt, 'v')) {
	mprintf_verbose = 1;
	logg_verbose = 1;
    }

    if(optl(opt, "quiet"))
	mprintf_quiet = 1;

    if(optl(opt, "stdout"))
	mprintf_stdout = 1;

    if(optc(opt, 'V')) {
	print_version();
	exit(0);
    }

    if(optc(opt, 'h')) {
	free_opt(opt);
    	help();
    }

    if(optc(opt, 'i'))
	printinfected = 1;

    /* initialize logger */

    if(optc(opt, 'l')) {
	logg_file = getargc(opt, 'l');
	if(logg("--------------------------------------\n")) {
	    mprintf("!Problem with internal logger.\n");
	    exit(2);
	}
    } else 
	logg_file = NULL;


    time(&starttime);
    /* ctime() does \n, but I need it once more */

    gettimeofday(&t1, &tz);

    ret = client(opt, &infected);

/* Implement STATUS in clamd */
    if(!optl(opt, "disable-summary") && !optl(opt, "no-summary")) {
	gettimeofday(&t2, &tz);
	ds = t2.tv_sec - t1.tv_sec;
	dms = t2.tv_usec - t1.tv_usec;
	ds -= (dms < 0) ? (1):(0);
	dms += (dms < 0) ? (1000000):(0);
	logg("\n----------- SCAN SUMMARY -----------\n");
	logg("Infected files: %d\n", infected);
	if(notremoved) {
	    logg("Not removed: %d\n", notremoved);
	}
	if(notmoved) {
	    logg("Not moved: %d\n", notmoved);
	}
	logg("Time: %d.%3.3d sec (%d m %d s)\n", ds, dms/1000, ds/60, ds%60);
    }

    exit(ret);
}

void help(void)
{

    mprintf_stdout = 1;

    mprintf("\n");
    mprintf("                       ClamAV Daemon Client "VERSION"\n");
    mprintf("     (C) 2002 - 2005 ClamAV Team - http://www.clamav.net/team.html\n\n");

    mprintf("    --help              -h             Show help\n");
    mprintf("    --version           -V             Print version number and exit\n");
    mprintf("    --verbose           -v             Be verbose\n");
    mprintf("    --quiet                            Be quiet, only output error messages\n");
    mprintf("    --stdout                           Write to stdout instead of stderr\n");
    mprintf("                                       (this help is always written to stdout)\n");
    mprintf("    --log=FILE          -l FILE        Save scan report in FILE\n");
    mprintf("    --remove                           Remove infected files. Be careful!\n");
    mprintf("    --move=DIRECTORY                   Move infected files into DIRECTORY\n");
    mprintf("    --config-file=FILE                 Read configuration from FILE.\n");
    mprintf("    --no-summary                       Disable summary at end of scanning\n");
    mprintf("\n");

    exit(0);
}

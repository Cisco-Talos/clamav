/*
 *  Copyright (C) 2002, 2003 Tomasz Kojm <zolw@konarski.edu.pl>
 *			     Damien Curtain <damien@pagefault.org>
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
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

/* TODO: Handle SIGALRM more gently */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pwd.h>
#include <grp.h>

#include "options.h"
#include "shared.h"
#include "others.h"
#include "manager.h"
#include "defaults.h"
#include "freshclam.h"

#define TIMEOUT 1200

int freshclam(struct optstruct *opt)
{
	int ret;
	char *newdir, *cfgfile;
	struct cfgstruct *copt, *cpt;
#ifndef C_CYGWIN
	char *unpuser;
	struct passwd *user;
#endif


    /* parse the config file */
    if((cfgfile = getargc(opt, 'c'))) {
	copt = parsecfg(cfgfile);
    } else {
	/* TODO: force strict permissions on freshclam.conf */
	if((copt = parsecfg((cfgfile = CONFDIR"/freshclam.conf"))) == NULL)
	    copt = parsecfg((cfgfile = CONFDIR"/clamav.conf"));
    }

    if(!copt) {
	mprintf("!Can't parse the config file %s\n", cfgfile);
	return 56;
    }

#ifndef C_CYGWIN
    /* freshclam shouldn't work with root priviledges */
    if((cpt = cfgopt(copt, "DatabaseOwner")) == NULL)
	unpuser = UNPUSER;
    else 
	unpuser = cpt->strarg;

    if(!getuid()) {
	if((user = getpwnam(unpuser)) == NULL) {
	    mprintf("@Can't get information about user %s.\n", unpuser);
	    exit(60); /* this is critical problem, so we just exit here */
	}

	setgroups(1, &user->pw_gid);
	setgid(user->pw_gid);
	setuid(user->pw_uid);
    }
#endif

    /* initialize some important variables */

    if(optl(opt, "debug") || cfgopt(copt, "Debug"))
	cl_debug();

    mprintf_disabled = 0;

    if(optc(opt, 'v')) mprintf_verbose = 1;
    else mprintf_verbose = 0;

    if(optl(opt, "quiet")) mprintf_quiet = 1;
    else mprintf_quiet = 0;

    if(optl(opt, "stdout")) mprintf_stdout = 1;
    else mprintf_stdout = 0;

    if(optc(opt, 'V')) {
	mprintf("freshclam / ClamAV version "VERSION"\n");
	mexit(0);
    }

    if(optc(opt, 'h')) {
	free_opt(opt);
    	help();
    }

    /* initialize logger */

    if(optl(opt, "log-verbose") || cfgopt(copt, "LogVerbose"))
	logverbose = 1;
    else
	logverbose = 0;

    if((cpt = cfgopt(copt, "UpdateLogFile"))) {
	logfile = cpt->strarg; 
	if(logg("--------------------------------------\n")) {
	    mprintf("!Problem with internal logger.\n");
	    mexit(1);
	}
    } else
	logfile = NULL;

    /* change the current working directory */
    if(optl(opt, "datadir")) {
	newdir = getargl(opt, "datadir");
    } else {
	if((cpt = cfgopt(copt, "DatabaseDirectory")))
	    newdir = cpt->strarg;
	else
	    newdir = VIRUSDBDIR;
    }

    if(chdir(newdir)) {
	mprintf("Can't change dir to %s\n", newdir);
	exit(50);
    } else
	mprintf("*Current working dir is %s\n", newdir);


    if(optc(opt, 'd')) {
	    int bigsleep, checks;

	if((cpt = cfgopt(copt, "Checks")))
	    checks = cpt->numarg;
	else
	    checks = CL_DEFAULT_CHECKS;

	if(checks <= 0 || checks > 50) {
	    mprintf("@Number of checks must be between 1 and 50.\n");
	    mexit(41);
	}

	bigsleep = 24 * 3600 / checks;
	daemonize();

	while(1) {
	    ret = download(copt);

	    if((cpt = cfgopt(copt, "OnErrorExecute")))
		if(ret > 1)
		    system(cpt->strarg);

	    logg("\n--------------------------------------\n");
	    sleep(bigsleep);
	}

    } else
	ret = download(copt);

    if((cpt = cfgopt(copt, "OnErrorExecute")))
	if(ret > 1)
	    system(cpt->strarg);

    return(ret);
}

void d_timeout(int sig)
{
    mprintf("@Maximal time (%d seconds) reached.\n", TIMEOUT);
    exit(1);
}

int download(const struct cfgstruct *copt)
{
	int ret = 0, try = 0, maxattempts = 0;
	struct sigaction sigalrm;
	struct cfgstruct *cpt;

    memset(&sigalrm, 0, sizeof(struct sigaction));
    sigalrm.sa_handler = d_timeout;
    sigaction(SIGALRM, &sigalrm, NULL);

    if((cpt = cfgopt(copt, "MaxAttempts")))
	maxattempts = cpt->numarg;

    mprintf("*Max retries == %d\n", maxattempts);

    if((cpt = cfgopt(copt, "DatabaseMirror")) == NULL) {
	mprintf("@You must specify at least one database mirror.\n");
	return 57;
    } else {

	while(cpt) {
	    alarm(TIMEOUT);
	    ret = downloadmanager(copt, cpt->strarg);
	    alarm(0);

	    if(ret == 52 || ret == 54) {
		if(try < maxattempts - 1) {
		    mprintf("Trying again...\n");
		    logg("Trying again...\n");
		    try++;
		    sleep(1);
		    continue;
		} else {
		    mprintf("Giving up...\n");
		    logg("Giving up...\n");
		    cpt = (struct cfgstruct *) cpt->nextarg;
		    try = 0;
		}

	    } else {
		return ret;
	    }
	}
    }

    return ret;
}

void daemonize(void)
{
	int i;

    for(i = 0; i < 3; i++)
	close(i);

    umask(0);

    if(fork())
	exit(0);

    setsid();
    mprintf_disabled = 1;
}

void help(void)
{

    mprintf_stdout = 1;

    mprintf("\n");
    mprintf("                          Clam AntiVirus: freshclam  "VERSION"\n");
    mprintf("                (c) 2002, 2003 Tomasz Kojm <tkojm@clamav.net>\n\n");

    mprintf("    --help               -h              show help\n");
    mprintf("    --version            -V              print version number and exit\n");
    mprintf("    --verbose            -v              be verbose\n");
    mprintf("    --debug                              enable debug messages\n");
    mprintf("    --quiet                              be quiet, output only error messages\n");
    mprintf("    --stdout                             write to stdout instead of stderr\n");
    mprintf("                                         (this help is always written to stdout)\n");
    mprintf("\n");
    mprintf("    --daemon             -d              run in daemon mode\n");
    mprintf("    --datadir=DIRECTORY                  download new databases into DIRECTORY\n");
    mprintf("\n");
    exit(0);
}

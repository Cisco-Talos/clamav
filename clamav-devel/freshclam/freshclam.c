/*
 *  Copyright (C) 2002 - 2004 Tomasz Kojm <tkojm@clamav.net>
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


#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pwd.h>
#include <grp.h>

#if defined(USE_SYSLOG) && !defined(C_AIX)
#include <syslog.h>
#endif

#include "options.h"
#include "manager.h"
#include "defaults.h"
#include "freshclam.h"
#include "output.h"

static short terminate = 0;


static void daemon_sighandler(int sig) {
	char *action = NULL;

    switch(sig) {
	case SIGALRM:
	case SIGUSR1:
	    action = "wake up";
	    terminate = -1;
	    break;

	case SIGHUP:
	    action = "re-opening log file";
	    terminate = -2;
	    break;

	default:
	    action = "terminating";
	    terminate = 1;
	    break;
    }

    logg("Received signal %d, %s\n", sig, action);
    return;
}


static void writepid(char *pidfile) {
	FILE *fd;
	int old_umask;
    old_umask = umask(0006);
    if((fd = fopen(pidfile, "w")) == NULL) {
	logg("!Can't save PID to file %s: %s\n", pidfile, strerror(errno));
    } else {
	fprintf(fd, "%d", (int) getpid());
	fclose(fd);
    }
    umask(old_umask);
}


int freshclam(struct optstruct *opt)
{
	int ret = 52;
	char *newdir, *cfgfile;
	char *pidfile = NULL;
	struct cfgstruct *copt, *cpt;
	struct sigaction sigact;
	struct sigaction oldact;
#ifndef C_CYGWIN
	char *unpuser;
	struct passwd *user;
#endif
	struct stat statbuf;

    if(optc(opt, 'h')) {
	free_opt(opt);
    	help();
    }

    /* parse the config file */
    if((cfgfile = getargl(opt, "config-file"))) {
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

    if(optl(opt, "http-proxy") || optl(opt, "proxy-user"))
	mprintf("WARNING: Proxy settings are now only configurable in the config file.\n");

    if(cfgopt(copt, "HTTPProxyPassword")) {
	if(stat(cfgfile, &statbuf) == -1) {
	    mprintf("@Can't stat %s (critical error)\n");
	    return 56;
	}

	if(statbuf.st_mode & (S_IRGRP | S_IWGRP | S_IXGRP | S_IROTH | S_IWOTH | S_IXOTH)) {
	    mprintf("@Insecure permissions (for HTTPProxyPassword): %s must have no more than 0700 permissions.\n", cfgfile);
	    return 56;
	}
    }

#ifndef C_CYGWIN
    /* freshclam shouldn't work with root privileges */
    if(optc(opt, 'u')) {
	unpuser = getargc(opt, 'u');
    } else if((cpt = cfgopt(copt, "DatabaseOwner"))) {
	unpuser = cpt->strarg;
    } else {
	unpuser = UNPUSER;
    }

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

    if(optc(opt, 'v'))
	mprintf_verbose = 1;

    if(optl(opt, "quiet"))
	mprintf_quiet = 1;

    if(optl(opt, "stdout"))
	mprintf_stdout = 1;

    if(optc(opt, 'V')) {
	mprintf("freshclam / ClamAV version "VERSION"\n");
	exit(0);
    }

    /* initialize logger */

    if(cfgopt(copt, "LogVerbose"))
	logg_verbose = 1;

    if(optc(opt, 'l')) {
	logg_file = getargc(opt, 'l');
	if(logg("--------------------------------------\n")) {
	    mprintf("!Problem with internal logger.\n");
	    exit(1);
	}
    } else if((cpt = cfgopt(copt, "UpdateLogFile"))) {
	logg_file = cpt->strarg; 
	if(logg("--------------------------------------\n")) {
	    mprintf("!Problem with internal logger.\n");
	    exit(1);
	}
    } else
	logg_file = NULL;

#if defined(USE_SYSLOG) && !defined(C_AIX)
    if((cpt = cfgopt(copt, "LogSyslog"))) {
	openlog("freshclam", LOG_PID, LOG_LOCAL6);
	logg_syslog = 1;
	syslog(LOG_INFO, "Freshclam started.\n");
    }
#endif

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
	    time_t now, wakeup;

	memset(&sigact, 0, sizeof(struct sigaction));
	sigact.sa_handler = daemon_sighandler;

	if(optc(opt, 'c')) {
	    checks = atoi(getargc(opt, 'c'));
	} else if((cpt = cfgopt(copt, "Checks"))) {
	    checks = cpt->numarg;
	} else {
	    checks = CL_DEFAULT_CHECKS;
	}

	if(checks <= 0 || checks > 50) {
	    mprintf("@Number of checks must be between 1 and 50.\n");
	    exit(41);
	}

	bigsleep = 24 * 3600 / checks;
	daemonize();
	if (optc(opt, 'p')) {
	    pidfile = getargc(opt, 'p');
	} else if ((cpt = cfgopt(copt, "PidFile"))) {
	    pidfile = cpt->strarg;
	}
	if (pidfile) {
	    writepid(pidfile);
	}
	logg("freshclam daemon started (pid=%d)\n", getpid());

	sigaction(SIGTERM, &sigact, NULL);
	sigaction(SIGHUP, &sigact, NULL);
	sigaction(SIGINT, &sigact, NULL);
	while(!terminate) {
	    ret = download(copt, opt);


	    if(optl(opt, "on-error-execute")) {
		if(ret > 1)
		    system(getargl(opt, "on-error-execute"));

	    } else if((cpt = cfgopt(copt, "OnErrorExecute"))) {
		if(ret > 1)
		    system(cpt->strarg);
	    }

	    logg("--------------------------------------\n");
	    sigaction(SIGALRM, &sigact, &oldact);
	    sigaction(SIGUSR1, &sigact, &oldact);
	    time(&wakeup);
	    wakeup += bigsleep;
	    alarm(bigsleep);
	    do {
		pause();
		time(&now);
	    } while (!terminate && now < wakeup);

	    if (terminate == -1) {
		terminate = 0;
	    } else if (terminate == -2) {
		terminate = 0;
		logg_close();
	    }

	    sigaction(SIGALRM, &oldact, NULL);
	    sigaction(SIGUSR1, &oldact, NULL);
	}

    } else
	ret = download(copt, opt);

    if(optl(opt, "on-error-execute")) {
	if(ret > 1)
	    system(getargl(opt, "on-error-execute"));

    } else if((cpt = cfgopt(copt, "OnErrorExecute"))) {
	if(ret > 1)
	    system(cpt->strarg);
    }
    if (pidfile) {
        unlink(pidfile);
    }

    return(ret);
}

int download(const struct cfgstruct *copt, const struct optstruct *opt)
{
	int ret = 0, try = 0, maxattempts = 0;
	struct cfgstruct *cpt;


    if((cpt = cfgopt(copt, "MaxAttempts")))
	maxattempts = cpt->numarg;

    mprintf("*Max retries == %d\n", maxattempts);

    if((cpt = cfgopt(copt, "DatabaseMirror")) == NULL) {
	mprintf("@You must specify at least one database mirror.\n");
	return 56;
    } else {

	while(cpt) {
	    ret = downloadmanager(copt, opt, cpt->strarg);
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
    mprintf("                (C) 2002 - 2004 Tomasz Kojm <tkojm@clamav.net>\n\n");

    mprintf("    --help               -h              show help\n");
    mprintf("    --version            -V              print version number and exit\n");
    mprintf("    --verbose            -v              be verbose\n");
    mprintf("    --debug                              enable debug messages\n");
    mprintf("    --quiet                              be quiet, output only error messages\n");
    mprintf("    --stdout                             write to stdout instead of stderr\n");
    mprintf("                                         (this help is always written to stdout)\n");
    mprintf("\n");
    mprintf("    --config-file=FILE                   read configuration from FILE.\n");
    mprintf("    --log=FILE           -l FILE         log into FILE\n");
    mprintf("    --daemon             -d              run in daemon mode\n");
    mprintf("    --pid=FILE           -p FILE         save daemon's pid in FILE\n");
    mprintf("    --user=USER          -u USER         run as USER\n");
    mprintf("    --checks=#n          -c #n           number of checks per day, 1 <= n <= 50\n");
    mprintf("    --datadir=DIRECTORY                  download new databases into DIRECTORY\n");
#ifdef BUILD_CLAMD
    mprintf("    --daemon-notify[=/path/clamav.conf]  send RELOAD command to clamd\n");
#endif
    mprintf("    --on-update-execute=COMMAND          execute COMMAND after successful update\n");
    mprintf("    --on-error-execute=COMMAND           execute COMMAND if errors occured\n");

    mprintf("\n");
    exit(0);
}

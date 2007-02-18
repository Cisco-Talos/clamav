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
#include <time.h>
#include <sys/types.h>
#include <sys/wait.h>
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
#include "target.h"
#include "misc.h"
#include "execute.h"

static short terminate = 0;
extern int active_children;

static void daemon_sighandler(int sig) {

    switch(sig) {
	case SIGCHLD:
	    waitpid(-1, NULL, WNOHANG);
	    active_children--;
	    break;

	case SIGALRM:
	case SIGUSR1:
	    terminate = -1;
	    break;

	case SIGHUP:
	    terminate = -2;
	    break;

	default:
	    terminate = 1;
	    break;
    }

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
#if !defined(C_CYGWIN)  && !defined(C_OS2)
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
	copt = parsecfg(cfgfile, 1);
    } else {
	/* TODO: force strict permissions on freshclam.conf */
	if((copt = parsecfg((cfgfile = CONFDIR"/freshclam.conf"), 1)) == NULL)
	    copt = parsecfg((cfgfile = CONFDIR"/clamd.conf"), 1);
    }

    if(!copt) {
	mprintf("!Can't parse the config file %s\n", cfgfile);
	return 56;
    }

    if(optl(opt, "http-proxy") || optl(opt, "proxy-user"))
	mprintf("WARNING: Proxy settings are now only configurable in the config file.\n");

    if(cfgopt(copt, "HTTPProxyPassword")) {
	if(stat(cfgfile, &statbuf) == -1) {
	    mprintf("@Can't stat %s (critical error)\n", cfgfile);
	    return 56;
	}
#ifndef C_CYGWIN
	if(statbuf.st_mode & (S_IRGRP | S_IWGRP | S_IXGRP | S_IROTH | S_IWOTH | S_IXOTH)) {
	    mprintf("@Insecure permissions (for HTTPProxyPassword): %s must have no more than 0700 permissions.\n", cfgfile);
	    return 56;
	}
#endif
    }

#if !defined(C_CYGWIN)  && !defined(C_OS2)
    /* freshclam shouldn't work with root privileges */
    if(optc(opt, 'u')) {
	unpuser = getargc(opt, 'u');
    } else if((cpt = cfgopt(copt, "DatabaseOwner"))) {
	unpuser = cpt->strarg;
    } else {
	unpuser = UNPUSER;
    }

    if(!geteuid()) {
	if((user = getpwnam(unpuser)) == NULL) {
	    mprintf("@Can't get information about user %s.\n", unpuser);
	    exit(60); /* this is critical problem, so we just exit here */
	}

	if(cfgopt(copt, "AllowSupplementaryGroups")) {
#ifdef HAVE_INITGROUPS
	    if(initgroups(unpuser, user->pw_gid)) {
		mprintf("@initgroups() failed.\n");
		exit(61);
	    }
#endif
	} else {
#ifdef HAVE_SETGROUPS
	    if(setgroups(1, &user->pw_gid)) {
		mprintf("@setgroups() failed.\n");
		exit(61);
	    }
#endif
	}

	if(setgid(user->pw_gid)) {
	    mprintf("@setgid(%d) failed.\n", (int) user->pw_gid);
	    exit(61);
	}

	if(setuid(user->pw_uid)) {
	    mprintf("@setuid(%d) failed.\n", (int) user->pw_uid);
	    exit(61);
	}
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
	print_version();
	exit(0);
    }

    /* initialize logger */

    if(cfgopt(copt, "LogVerbose"))
	logg_verbose = 1;

    if(optc(opt, 'l')) {
	logg_file = getargc(opt, 'l');
	if(logg("--------------------------------------\n")) {
	    mprintf("!Problem with internal logger.\n");
	    exit(62);
	}
    } else if((cpt = cfgopt(copt, "UpdateLogFile"))) {
	logg_file = cpt->strarg; 
	if(logg("--------------------------------------\n")) {
	    mprintf("!Problem with internal logger.\n");
	    exit(62);
	}
    } else
	logg_file = NULL;

#if defined(USE_SYSLOG) && !defined(C_AIX)
    if(cfgopt(copt, "LogSyslog")) {
	    int fac = LOG_LOCAL6;

	if((cpt = cfgopt(copt, "LogFacility"))) {
	    if((fac = logg_facility(cpt->strarg)) == -1) {
		mprintf("!LogFacility: %s: No such facility.\n", cpt->strarg);
		exit(62);
	    }
	}

	openlog("freshclam", LOG_PID, fac);
	logg_syslog = 1;
	syslog(LOG_INFO, "Daemon started.\n");
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

	if(checks <= 0) {
	    mprintf("@Number of checks must be a positive integer.\n");
	    exit(41);
	}

	if(!cfgopt(copt, "DNSDatabaseInfo")) {
	    if(checks > 50) {
		mprintf("@Number of checks must be between 1 and 50.\n");
		exit(41);
	    }
	}

	bigsleep = 24 * 3600 / checks;

	if(!cfgopt(copt, "Foreground"))
	    daemonize();

	if (optc(opt, 'p')) {
	    pidfile = getargc(opt, 'p');
	} else if ((cpt = cfgopt(copt, "PidFile"))) {
	    pidfile = cpt->strarg;
	}
	if (pidfile) {
	    writepid(pidfile);
	}

	active_children = 0;

	logg("freshclam daemon "VERSION" (OS: "TARGET_OS_TYPE", ARCH: "TARGET_ARCH_TYPE", CPU: "TARGET_CPU_TYPE")\n");

	sigaction(SIGTERM, &sigact, NULL);
	sigaction(SIGHUP, &sigact, NULL);
	sigaction(SIGINT, &sigact, NULL);
        sigaction(SIGCHLD, &sigact, NULL);

	while(!terminate) {
	    ret = download(copt, opt);

            if(ret > 1) {
		    const char *arg = NULL;

	        if(optl(opt, "on-error-execute"))
		    arg = getargl(opt, "on-error-execute");
		else if((cpt = cfgopt(copt, "OnErrorExecute")))
		    arg = cpt->strarg;

		if(arg)
		    execute("OnErrorExecute", arg);
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
		logg("Received signal: wake up\n");
		terminate = 0;
	    } else if (terminate == -2) {
		logg("Received signal: re-opening log file\n");
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
    else
	maxattempts = CL_DEFAULT_MAXATTEMPTS;


    mprintf("*Max retries == %d\n", maxattempts);

    if((cpt = cfgopt(copt, "DatabaseMirror")) == NULL) {
	mprintf("@You must specify at least one database mirror.\n");
	return 56;
    } else {

	while(cpt) {
	    ret = downloadmanager(copt, opt, cpt->strarg);
	    alarm(0);

	    if(ret == 52 || ret == 54 || ret == 58 || ret == 59) {
		if(try < maxattempts - 1) {
		    mprintf("Trying again in 5 secs...\n");
		    logg("Trying again in 5 secs...\n");
		    try++;
		    sleep(5);
		    continue;
		} else {
		    mprintf("Giving up on %s...\n", cpt->strarg);
		    logg("Giving up on %s...\n", cpt->strarg);
		    cpt = (struct cfgstruct *) cpt->nextarg;
		    if(!cpt) {
			mprintf("@Update failed. Your network may be down or none of the mirrors listed in freshclam.conf is working.\n");
			logg("ERROR: Update failed. Your network may be down or none of the mirrors listed in freshclam.conf is working.\n");
		    }
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
    mprintf("                   Clam AntiVirus: freshclam  "VERSION"\n");
    mprintf("    (C) 2002 - 2005 ClamAV Team - http://www.clamav.net/team.html\n\n");

    mprintf("    --help               -h              show help\n");
    mprintf("    --version            -V              print version number and exit\n");
    mprintf("    --verbose            -v              be verbose\n");
    mprintf("    --debug                              enable debug messages\n");
    mprintf("    --quiet                              only output error messages\n");
    mprintf("    --stdout                             write to stdout instead of stderr\n");
    mprintf("\n");
    mprintf("    --config-file=FILE                   read configuration from FILE.\n");
    mprintf("    --log=FILE           -l FILE         log into FILE\n");
    mprintf("    --daemon             -d              run in daemon mode\n");
    mprintf("    --foreground         -f              run daemon in foreground\n");
    mprintf("    --pid=FILE           -p FILE         save daemon's pid in FILE\n");
    mprintf("    --user=USER          -u USER         run as USER\n");
    mprintf("    --no-dns                             force old non-DNS verification method\n");
    mprintf("    --checks=#n          -c #n           number of checks per day, 1 <= n <= 50\n");
    mprintf("    --datadir=DIRECTORY                  download new databases into DIRECTORY\n");
#ifdef BUILD_CLAMD
    mprintf("    --daemon-notify[=/path/clamd.conf]   send RELOAD command to clamd\n");
#endif
    mprintf("    --local-address=IP   -a IP           bind to IP for HTTP downloads\n");
    mprintf("    --on-update-execute=COMMAND          execute COMMAND after successful update\n");
    mprintf("    --on-error-execute=COMMAND           execute COMMAND if errors occured\n");

    mprintf("\n");
    exit(0);
}

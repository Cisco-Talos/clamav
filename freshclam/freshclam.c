/*
 *  Copyright (C) 2002 - 2006 Tomasz Kojm <tkojm@clamav.net>
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
#ifdef	_MSC_VER
#include <winsock.h>
#endif

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#ifdef	HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <sys/types.h>
#ifndef	C_WINDOWS
#include <sys/wait.h>
#endif
#include <sys/stat.h>
#include <fcntl.h>
#ifndef	C_WINDOWS
#include <pwd.h>
#include <grp.h>
#endif

#if defined(USE_SYSLOG) && !defined(C_AIX)
#include <syslog.h>
#endif

#include "target.h"
#include "clamav.h"

#include "shared/options.h"
#include "shared/output.h"
#include "shared/misc.h"

#include "execute.h"
#include "manager.h"
#include "mirman.h"

static short terminate = 0;
extern int active_children;

static short foreground = 1;

static void daemon_sighandler(int sig) {

    switch(sig) {
#ifdef	SIGCHLD
	case SIGCHLD:
	    waitpid(-1, NULL, WNOHANG);
	    active_children--;
	    break;
#endif

#ifdef	SIGALRM
	case SIGALRM:
		terminate = -1;
	    break;
#endif
#ifdef	SIGUSR1
	case SIGUSR1:
		terminate = -1;
	    break;
#endif

#ifdef	SIGHUP
	case SIGHUP:
	    terminate = -2;
	    break;
#endif

	default:
	    terminate = 1;
	    break;
    }

    return;
}

static void writepid(char *pidfile)
{
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

static void help(void)
{
    mprintf_stdout = 1;

    mprintf("\n");
    mprintf("                   Clam AntiVirus: freshclam  %s\n", get_version());
    mprintf("    (C) 2002 - 2007 ClamAV Team - http://www.clamav.net/team\n\n");

    mprintf("    --help               -h              show help\n");
    mprintf("    --version            -V              print version number and exit\n");
    mprintf("    --verbose            -v              be verbose\n");
    mprintf("    --debug                              enable debug messages\n");
    mprintf("    --quiet                              only output error messages\n");
    mprintf("    --no-warnings                        don't print and log warnings\n");
    mprintf("    --stdout                             write to stdout instead of stderr\n");
    mprintf("\n");
    mprintf("    --config-file=FILE                   read configuration from FILE.\n");
    mprintf("    --log=FILE           -l FILE         log into FILE\n");
    mprintf("    --daemon             -d              run in daemon mode\n");
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
    mprintf("    --on-outdated-execute=COMMAND        execute COMMAND when software is outdated\n");
    mprintf("    --list-mirrors                       print mirrors from mirrors.dat\n");

    mprintf("\n");
}

static int download(const struct cfgstruct *copt, const struct optstruct *opt, const char *datadir, const char *cfgfile)
{
	int ret = 0, try = 0, maxattempts = 0;
	const struct cfgstruct *cpt;


    maxattempts = cfgopt(copt, "MaxAttempts")->numarg;
    logg("*Max retries == %d\n", maxattempts);

    if(!(cpt = cfgopt(copt, "DatabaseMirror"))->enabled) {
	logg("^You must specify at least one database mirror in %s\n", cfgfile);
	return 56;
    } else {
	while(cpt) {
	    ret = downloadmanager(copt, opt, cpt->strarg, datadir, try == maxattempts - 1);
	    alarm(0);

	    if(ret == 52 || ret == 54 || ret == 58 || ret == 59) {
		if(try < maxattempts - 1) {
		    logg("Trying again in 5 secs...\n");
		    try++;
		    sleep(5);
		    continue;
		} else {
		    logg("Giving up on %s...\n", cpt->strarg);
		    cpt = (struct cfgstruct *) cpt->nextarg;
		    if(!cpt) {
			logg("Update failed. Your network may be down or none of the mirrors listed in %s is working. Check http://www.clamav.net/support/mirror-problem for possible reasons.\n", cfgfile);
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

int main(int argc, char **argv)
{
	int ret = 52;
	const char *newdir, *cfgfile, *arg = NULL;
	char *pidfile = NULL;
	struct cfgstruct *copt;
	const struct cfgstruct *cpt;
#ifndef	C_WINDOWS
	struct sigaction sigact;
	struct sigaction oldact;
#endif
#if !defined(C_OS2) && !defined(C_WINDOWS)
	char *unpuser;
	struct passwd *user;
#endif
	struct stat statbuf;
	struct mirdat mdat;
	struct optstruct *opt;
	const char *short_options = "hvdp:Vl:c:u:a:";
	static struct option long_options[] = {
	    {"help", 0, 0, 'h'},
	    {"quiet", 0, 0, 0},
	    {"no-warnings", 0, 0, 0},
	    {"verbose", 0, 0, 'v'},
	    {"debug", 0, 0, 0},
	    {"version", 0, 0, 'V'},
	    {"datadir", 1, 0, 0},
	    {"log", 1, 0, 'l'},
	    {"log-verbose", 0, 0, 0}, /* not used */
	    {"stdout", 0, 0, 0},
	    {"daemon", 0, 0, 'd'},
	    {"pid", 1, 0, 'p'},
	    {"user", 1, 0, 'u'}, /* not used */
	    {"config-file", 1, 0, 0},
	    {"no-dns", 0, 0, 0},
	    {"checks", 1, 0, 'c'},
	    {"http-proxy", 1, 0, 0},
	    {"local-address", 1, 0, 'a'},
	    {"proxy-user", 1, 0, 0},
	    {"daemon-notify", 2, 0, 0},
	    {"on-update-execute", 1, 0, 0},
	    {"on-error-execute", 1, 0, 0},
	    {"on-outdated-execute", 1, 0, 0},
	    {"list-mirrors", 0, 0, 0},
	    {0, 0, 0, 0}
    	};


    opt = opt_parse(argc, argv, short_options, long_options, NULL);
    if(!opt) {
	mprintf("!Can't parse the command line\n");
	return 40;
    }

    if(opt_check(opt, "help")) {
    	help();
	opt_free(opt);
	return 0;
    }

    /* parse the config file */
    if((cfgfile = opt_arg(opt, "config-file"))) {
	copt = getcfg(cfgfile, 1);
    } else {
	/* TODO: force strict permissions on freshclam.conf */
	if((copt = getcfg((cfgfile = CONFDIR"/freshclam.conf"), 1)) == NULL)
	    copt = getcfg((cfgfile = CONFDIR"/clamd.conf"), 1);
    }

    if(!copt) {
	logg("!Can't parse the config file %s\n", cfgfile);
	opt_free(opt);
	return 56;
    }

    if(opt_check(opt, "datadir"))
	newdir = opt_arg(opt, "datadir");
    else
	newdir = cfgopt(copt, "DatabaseDirectory")->strarg;

    if(opt_check(opt, "version")) {
	print_version(newdir);
	opt_free(opt);
	freecfg(copt);
	return 0;
    }

#ifdef C_WINDOWS
    if(!pthread_win32_process_attach_np()) {
	mprintf("!Can't start the win32 pthreads layer\n");
	opt_free(opt);
	freecfg(copt);
	return 63;
    }
#endif

    if(opt_check(opt, "http-proxy") || opt_check(opt, "proxy-user"))
	logg("WARNING: Proxy settings are now only configurable in the config file.\n");

    if(cfgopt(copt, "HTTPProxyPassword")->enabled) {
	if(stat(cfgfile, &statbuf) == -1) {
	    logg("^Can't stat %s (critical error)\n", cfgfile);
	    opt_free(opt);
	    freecfg(copt);
	    return 56;
	}

#ifndef C_WINDOWS
	if(statbuf.st_mode & (S_IRGRP | S_IWGRP | S_IXGRP | S_IROTH | S_IWOTH | S_IXOTH)) {
	    logg("^Insecure permissions (for HTTPProxyPassword): %s must have no more than 0700 permissions.\n", cfgfile);
	    opt_free(opt);
	    freecfg(copt);
	    return 56;
	}
#endif
    }

#if !defined(C_OS2) && !defined(C_WINDOWS)
    /* freshclam shouldn't work with root privileges */
    if(opt_check(opt, "user"))
	unpuser = opt_arg(opt, "user");
    else
	unpuser = cfgopt(copt, "DatabaseOwner")->strarg;

    if(!geteuid()) {
	if((user = getpwnam(unpuser)) == NULL) {
	    logg("^Can't get information about user %s.\n", unpuser);
	    opt_free(opt);
	    freecfg(copt);
	    return 60;
	}

	if(cfgopt(copt, "AllowSupplementaryGroups")->enabled) {
#ifdef HAVE_INITGROUPS
	    if(initgroups(unpuser, user->pw_gid)) {
		logg("^initgroups() failed.\n");
		opt_free(opt);
		freecfg(copt);
		return 61;
	    }
#endif
	} else {
#ifdef HAVE_SETGROUPS
	    if(setgroups(1, &user->pw_gid)) {
		logg("^setgroups() failed.\n");
		opt_free(opt);
		freecfg(copt);
		return 61;
	    }
#endif
	}

	if(setgid(user->pw_gid)) {
	    logg("^setgid(%d) failed.\n", (int) user->pw_gid);
	    opt_free(opt);
	    freecfg(copt);
	    return 61;
	}

	if(setuid(user->pw_uid)) {
	    logg("^setuid(%d) failed.\n", (int) user->pw_uid);
	    opt_free(opt);
	    freecfg(copt);
	    return 61;
	}
    }
#endif

    /* initialize some important variables */

    if(opt_check(opt, "debug") || cfgopt(copt, "Debug")->enabled)
	cl_debug();

    if(opt_check(opt, "verbose"))
	mprintf_verbose = 1;

    if(opt_check(opt, "quiet"))
	mprintf_quiet = 1;

    if(opt_check(opt, "no-warnings")) {
	mprintf_nowarn = 1;
	logg_nowarn = 1;
    }

    if(opt_check(opt, "stdout"))
	mprintf_stdout = 1;

    /* initialize logger */
    logg_verbose = cfgopt(copt, "LogVerbose")->enabled;
    logg_time = cfgopt(copt, "LogTime")->enabled;
    logg_size = cfgopt(copt, "LogFileMaxSize")->numarg;

    if(opt_check(opt, "log")) {
	logg_file = opt_arg(opt, "log");
	if(logg("#--------------------------------------\n")) {
	    mprintf("!Problem with internal logger (--log=%s).\n", logg_file);
	    opt_free(opt);
	    freecfg(copt);
	    return 62;
	}
    } else if((cpt = cfgopt(copt, "UpdateLogFile"))->enabled) {
	logg_file = cpt->strarg; 
	if(logg("#--------------------------------------\n")) {
	    mprintf("!Problem with internal logger (UpdateLogFile = %s).\n", logg_file);
	    opt_free(opt);
	    freecfg(copt);
	    return 62;
	}
    } else
	logg_file = NULL;

#if defined(USE_SYSLOG) && !defined(C_AIX)
    if(cfgopt(copt, "LogSyslog")->enabled) {
	    int fac = LOG_LOCAL6;

	if((cpt = cfgopt(copt, "LogFacility"))->enabled) {
	    if((fac = logg_facility(cpt->strarg)) == -1) {
		mprintf("!LogFacility: %s: No such facility.\n", cpt->strarg);
		opt_free(opt);
		freecfg(copt);
		return 62;
	    }
	}

	openlog("freshclam", LOG_PID, fac);
	logg_syslog = 1;
    }
#endif

    /* change the current working directory */
    if(chdir(newdir)) {
	logg("Can't change dir to %s\n", newdir);
	opt_free(opt);
	freecfg(copt);
	return 50;
    } else
	logg("*Current working dir is %s\n", newdir);


    if(opt_check(opt, "list-mirrors")) {
	if(mirman_read("mirrors.dat", &mdat, 1) == -1) {
	    printf("Can't read mirrors.dat\n");
	    opt_free(opt);
	    freecfg(copt);
	    return 55;
	}
	mirman_list(&mdat);
	mirman_free(&mdat);
	opt_free(opt);
	freecfg(copt);
	return 0;
    }

#ifdef	C_WINDOWS
    {
	    WSADATA wsaData;

	if(WSAStartup(MAKEWORD(2,2), &wsaData) != NO_ERROR) {
	    logg("!Error at WSAStartup(): %d\n", WSAGetLastError());
	    opt_free(opt);
	    freecfg(copt);
	    return 1;
	}
    }
#endif

    if(opt_check(opt, "daemon")) {
	    int bigsleep, checks;
#ifndef	C_WINDOWS
	    time_t now, wakeup;

	memset(&sigact, 0, sizeof(struct sigaction));
	sigact.sa_handler = daemon_sighandler;
#endif

	if(opt_check(opt, "checks"))
	    checks = atoi(opt_arg(opt, "checks"));
	else
	    checks = cfgopt(copt, "Checks")->numarg;

	if(checks <= 0) {
	    logg("^Number of checks must be a positive integer.\n");
	    opt_free(opt);
	    freecfg(copt);
	    return 41;
	}

	if(!cfgopt(copt, "DNSDatabaseInfo")->enabled || opt_check(opt, "no-dns")) {
	    if(checks > 50) {
		logg("^Number of checks must be between 1 and 50.\n");
		opt_free(opt);
		freecfg(copt);
		return 41;
	    }
	}

	bigsleep = 24 * 3600 / checks;

#if !defined(C_OS2) && !defined(C_WINDOWS)
	if(!cfgopt(copt, "Foreground")->enabled) {
	    if(daemonize() == -1) {
		logg("!daemonize() failed\n");
		opt_free(opt);
		freecfg(copt);
		return 70; /* FIXME */
	    }
            foreground = 0;
	    mprintf_disabled = 1;
        }
#endif

	if(opt_check(opt, "pid")) {
	    pidfile = opt_arg(opt, "pid");
	} else if ((cpt = cfgopt(copt, "PidFile"))->enabled) {
	    pidfile = cpt->strarg;
	}
	if (pidfile) {
	    writepid(pidfile);
	}

	active_children = 0;

	logg("#freshclam daemon %s (OS: "TARGET_OS_TYPE", ARCH: "TARGET_ARCH_TYPE", CPU: "TARGET_CPU_TYPE")\n", get_version());

#ifdef	C_WINDOWS
	signal(SIGINT, daemon_sighandler);
	terminate = 0;
#else
	sigaction(SIGTERM, &sigact, NULL);
	sigaction(SIGHUP, &sigact, NULL);
	sigaction(SIGINT, &sigact, NULL);
        sigaction(SIGCHLD, &sigact, NULL);
#endif

	while(!terminate) {
	    ret = download(copt, opt, newdir, cfgfile);

            if(ret > 1) {
	        if(opt_check(opt, "on-error-execute"))
		    arg = opt_arg(opt, "on-error-execute");
		else if((cpt = cfgopt(copt, "OnErrorExecute"))->enabled)
		    arg = cpt->strarg;

		if(arg)
		    execute("OnErrorExecute", arg, opt);

		arg = NULL;
	    }

	    logg("#--------------------------------------\n");
#ifdef	SIGALRM
	    sigaction(SIGALRM, &sigact, &oldact);
#endif
#ifdef	SIGUSR1
	    sigaction(SIGUSR1, &sigact, &oldact);
#endif

#ifdef	C_WINDOWS
	    sleep(bigsleep);
#else   
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
#endif

#ifdef	SIGALRM
	    sigaction(SIGALRM, &oldact, NULL);
#endif
#ifdef	SIGUSR1
	    sigaction(SIGUSR1, &oldact, NULL);
#endif	    
	}

    } else
	ret = download(copt, opt, newdir, cfgfile);

    if(ret > 1) {
	if(opt_check(opt, "on-error-execute"))
	    arg = opt_arg(opt, "on-error-execute");
	else if((cpt = cfgopt(copt, "OnErrorExecute"))->enabled)
	    arg = cpt->strarg;

	if(arg)
            execute("OnErrorExecute", arg, opt);
    }

    if (pidfile) {
        unlink(pidfile);
    }

    opt_free(opt);
    freecfg(copt);

#ifdef C_WINDOWS
    WSACleanup();

    if(!pthread_win32_process_detach_np()) {
	mprintf("!Can't stop the win32 pthreads layer\n");
	return 63;
    }
#endif

    return(ret);
}

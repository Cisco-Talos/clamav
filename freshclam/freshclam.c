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

#include "shared/optparser.h"
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

static void writepid(const char *pidfile)
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
    printf("           By The ClamAV Team: http://www.clamav.net/team\n");
    printf("           (C) 2007-2009 Sourcefire, Inc. et al.\n\n");

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
    mprintf("    --submit-stats[=/path/clamd.conf]    only submit detection statistics\n");

    mprintf("\n");
}

static int download(const struct optstruct *opts, const char *datadir, const char *cfgfile)
{
	int ret = 0, try = 0, maxattempts = 0;
	const struct optstruct *opt;


    maxattempts = optget(opts, "MaxAttempts")->numarg;
    logg("*Max retries == %d\n", maxattempts);

    if(!(opt = optget(opts, "DatabaseMirror"))->enabled) {
	logg("^You must specify at least one database mirror in %s\n", cfgfile);
	return 56;
    } else {
	while(opt) {
	    ret = downloadmanager(opts, opt->strarg, datadir, try == maxattempts - 1);
	    alarm(0);

	    if(ret == 52 || ret == 54 || ret == 58 || ret == 59) {
		if(try < maxattempts - 1) {
		    logg("Trying again in 5 secs...\n");
		    try++;
		    sleep(5);
		    continue;
		} else {
		    logg("Giving up on %s...\n", opt->strarg);
		    opt = (struct optstruct *) opt->nextarg;
		    if(!opt) {
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
	const char *dbdir, *cfgfile, *arg = NULL, *pidfile = NULL;
	char *pt;
	struct optstruct *opts;
	const struct optstruct *opt;
#ifndef	C_WINDOWS
	struct sigaction sigact;
	struct sigaction oldact;
#endif
#if !defined(C_OS2) && !defined(C_WINDOWS)
	const char *dbowner;
	struct passwd *user;
#endif
	struct stat statbuf;
	struct mirdat mdat;


    if((opts = optparse(NULL, argc, argv, 1, OPT_FRESHCLAM, 0, NULL)) == NULL) {
	mprintf("!Can't parse command line options\n");
	return 1;
    }

    if(optget(opts, "help")->enabled) {
    	help();
	optfree(opts);
	return 0;
    }

    /* parse the config file */
    cfgfile = optget(opts, "config-file")->strarg;
    pt = strdup(cfgfile);
    if((opts = optparse(cfgfile, 0, NULL, 1, OPT_FRESHCLAM, 0, opts)) == NULL) {
	fprintf(stderr, "ERROR: Can't open/parse the config file %s\n", pt);
	free(pt);
	return 1;
    }
    free(pt);

    dbdir = optget(opts, "DatabaseDirectory")->strarg;

    if(optget(opts, "version")->enabled) {
	print_version(dbdir);
	optfree(opts);
	return 0;
    }

#ifdef C_WINDOWS
    if(!pthread_win32_process_attach_np()) {
	mprintf("!Can't start the win32 pthreads layer\n");
	optfree(opts);
	return 63;
    }
#endif

    if(optget(opts, "HTTPProxyPassword")->enabled) {
	if(stat(cfgfile, &statbuf) == -1) {
	    logg("^Can't stat %s (critical error)\n", cfgfile);
	    optfree(opts);
	    return 56;
	}

#ifndef C_WINDOWS
	if(statbuf.st_mode & (S_IRGRP | S_IWGRP | S_IXGRP | S_IROTH | S_IWOTH | S_IXOTH)) {
	    logg("^Insecure permissions (for HTTPProxyPassword): %s must have no more than 0700 permissions.\n", cfgfile);
	    optfree(opts);
	    return 56;
	}
#endif
    }

#if !defined(C_OS2) && !defined(C_WINDOWS)
    /* freshclam shouldn't work with root privileges */
    dbowner = optget(opts, "DatabaseOwner")->strarg;

    if(!geteuid()) {
	if((user = getpwnam(dbowner)) == NULL) {
	    logg("^Can't get information about user %s.\n", dbowner);
	    optfree(opts);
	    return 60;
	}

	if(optget(opts, "AllowSupplementaryGroups")->enabled) {
#ifdef HAVE_INITGROUPS
	    if(initgroups(dbowner, user->pw_gid)) {
		logg("^initgroups() failed.\n");
		optfree(opts);
		return 61;
	    }
#endif
	} else {
#ifdef HAVE_SETGROUPS
	    if(setgroups(1, &user->pw_gid)) {
		logg("^setgroups() failed.\n");
		optfree(opts);
		return 61;
	    }
#endif
	}

	if(setgid(user->pw_gid)) {
	    logg("^setgid(%d) failed.\n", (int) user->pw_gid);
	    optfree(opts);
	    return 61;
	}

	if(setuid(user->pw_uid)) {
	    logg("^setuid(%d) failed.\n", (int) user->pw_uid);
	    optfree(opts);
	    return 61;
	}
    }
#endif

    /* initialize some important variables */

    if(optget(opts, "Debug")->enabled || optget(opts, "debug")->enabled)
	cl_debug();

    if(optget(opts, "verbose")->enabled)
	mprintf_verbose = 1;

    if(optget(opts, "quiet")->enabled)
	mprintf_quiet = 1;

    if(optget(opts, "no-warnings")->enabled) {
	mprintf_nowarn = 1;
	logg_nowarn = 1;
    }

    if(optget(opts, "stdout")->enabled)
	mprintf_stdout = 1;

    /* initialize logger */
    logg_verbose = mprintf_verbose ? 1 : optget(opts, "LogVerbose")->enabled;
    logg_time = optget(opts, "LogTime")->enabled;
    logg_size = optget(opts, "LogFileMaxSize")->numarg;

    if((opt = optget(opts, "UpdateLogFile"))->enabled) {
	logg_file = opt->strarg; 
	if(logg("#--------------------------------------\n")) {
	    mprintf("!Problem with internal logger (UpdateLogFile = %s).\n", logg_file);
	    optfree(opts);
	    return 62;
	}
    } else
	logg_file = NULL;

#if defined(USE_SYSLOG) && !defined(C_AIX)
    if(optget(opts, "LogSyslog")->enabled) {
	    int fac = LOG_LOCAL6;

	if((opt = optget(opts, "LogFacility"))->enabled) {
	    if((fac = logg_facility(opt->strarg)) == -1) {
		mprintf("!LogFacility: %s: No such facility.\n", opt->strarg);
		optfree(opts);
		return 62;
	    }
	}

	openlog("freshclam", LOG_PID, fac);
	logg_syslog = 1;
    }
#endif

    /* change the current working directory */
    if(chdir(dbdir)) {
	logg("Can't change dir to %s\n", dbdir);
	optfree(opts);
	return 50;
    } else
	logg("*Current working dir is %s\n", dbdir);


    if(optget(opts, "list-mirrors")->enabled) {
	if(mirman_read("mirrors.dat", &mdat, 1) == -1) {
	    printf("Can't read mirrors.dat\n");
	    optfree(opts);
	    return 55;
	}
	mirman_list(&mdat);
	mirman_free(&mdat);
	optfree(opts);
	return 0;
    }

#ifdef	C_WINDOWS
    {
	    WSADATA wsaData;

	if(WSAStartup(MAKEWORD(2,2), &wsaData) != NO_ERROR) {
	    logg("!Error at WSAStartup(): %d\n", WSAGetLastError());
	    optfree(opts);
	    return 1;
	}
    }
#endif

    if(optget(opts, "daemon")->enabled) {
	    int bigsleep, checks;
#ifndef	C_WINDOWS
	    time_t now, wakeup;

	memset(&sigact, 0, sizeof(struct sigaction));
	sigact.sa_handler = daemon_sighandler;
#endif

	checks = optget(opts, "Checks")->numarg;

	if(checks <= 0) {
	    logg("^Number of checks must be a positive integer.\n");
	    optfree(opts);
	    return 41;
	}

	if(!optget(opts, "DNSDatabaseInfo")->enabled || optget(opts, "no-dns")->enabled) {
	    if(checks > 50) {
		logg("^Number of checks must be between 1 and 50.\n");
		optfree(opts);
		return 41;
	    }
	}

	bigsleep = 24 * 3600 / checks;

#if !defined(C_OS2) && !defined(C_WINDOWS)
	if(!optget(opts, "Foreground")->enabled) {
	    if(daemonize() == -1) {
		logg("!daemonize() failed\n");
		optfree(opts);
		return 70; /* FIXME */
	    }
            foreground = 0;
	    mprintf_disabled = 1;
        }
#endif

	if((opt = optget(opts, "PidFile"))->enabled) {
	    pidfile = opt->strarg;
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
	    ret = download(opts, dbdir, cfgfile);

	    if(ret <= 1) {
		if((opt = optget(opts, "SubmitDetectionStats"))->enabled)
		    submitstats(opt->strarg, opts);
            } else  {
		if((opt = optget(opts, "OnErrorExecute"))->enabled)
		    arg = opt->strarg;

		if(arg)
		    execute("OnErrorExecute", arg, opts);

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

    } else {
	if((opt = optget(opts, "submit-stats"))->active) {
	    if(!optget(opts, "no-warnings")->enabled)
		logg(" *** Virus databases are not updated in this mode ***\n");
	    ret = submitstats(opt->strarg, opts);
	} else {
	    ret = download(opts, dbdir, cfgfile);

	    if((opt = optget(opts, "SubmitDetectionStats"))->enabled)
		submitstats(opt->strarg, opts);
	}
    }

    if(ret > 1) {
	if((opt = optget(opts, "OnErrorExecute"))->enabled)
            execute("OnErrorExecute", opt->strarg, opts);
    }

    if (pidfile) {
        unlink(pidfile);
    }

    optfree(opts);

#ifdef C_WINDOWS
    WSACleanup();

    if(!pthread_win32_process_detach_np()) {
	mprintf("!Can't stop the win32 pthreads layer\n");
	return 63;
    }
#endif

    return(ret);
}

/*
 *  Copyright (C) 2002 - 2004 Tomasz Kojm <tkojm@clamav.net>
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
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <pwd.h>
#include <grp.h>
#include <clamav.h>

#if defined(USE_SYSLOG) && !defined(C_AIX)
#include <syslog.h>
#endif

#ifdef C_LINUX
#include <sys/resource.h>
#endif

#include "options.h"
#include "cfgparser.h"
#include "others.h"
/* Fixes gcc warning */
#include "../libclamav/others.h"
#include "tcpserver.h"
#include "localserver.h"
#include "others.h"
#include "defaults.h"
#include "memory.h"
#include "output.h"
#include "shared.h"
#include "target.h"
#include "misc.h"

void help(void);
void daemonize(void);

short debug_mode = 0, logok = 0;

void clamd(struct optstruct *opt)
{
	struct cfgstruct *copt, *cpt;
        struct passwd *user;
	time_t currtime;
	struct cl_node *root = NULL;
	const char *dbdir, *cfgfile;
	int ret, virnum = 0, tcpsock;
#ifdef C_LINUX
	struct stat sb;
#endif

    /* initialize some important variables */

    if(optc(opt, 'V')) {
	print_version();
	exit(0);
    }

    if(optc(opt, 'h')) {
    	help();
    }

    if(optl(opt, "debug")) {
#if defined(C_LINUX)
	    /* njh@bandsman.co.uk: create a dump if needed */
	    struct rlimit rlim;

	rlim.rlim_cur = rlim.rlim_max = RLIM_INFINITY;
	if(setrlimit(RLIMIT_CORE, &rlim) < 0)
	    perror("setrlimit");
#endif
	debug_mode = 1;

    }

    /* parse the config file */
    if(optc(opt, 'c'))
	cfgfile = getargc(opt, 'c');
    else
	cfgfile = CL_DEFAULT_CFG;

    if((copt = parsecfg(cfgfile, 1)) == NULL) {
	fprintf(stderr, "ERROR: Can't open/parse the config file %s\n", cfgfile);
	exit(1);
    }

    umask(0);

    /* initialize logger */

    if(cfgopt(copt, "LogFileUnlock"))
	logg_lock = 0;

    if(cfgopt(copt, "LogTime"))
	logg_time = 1;

    if(cfgopt(copt, "LogClean"))
	logok = 1;

    if((cpt = cfgopt(copt, "LogFileMaxSize")))
	logg_size = cpt->numarg;
    else
	logg_size = CL_DEFAULT_LOGSIZE;

    if(cfgopt(copt, "Debug")) /* enable debug messages in libclamav */
	cl_debug();

    if(cfgopt(copt, "LogVerbose"))
	logg_verbose = 1;
    else
	logg_verbose = 0;

    if((cpt = cfgopt(copt, "LogFile"))) {
	logg_file = cpt->strarg;
	if(logg_file[0] != '/') {
	    fprintf(stderr, "ERROR: LogFile requires full path.\n");
	    exit(1);
	}
	time(&currtime);
	if(logg("+++ Started at %s", ctime(&currtime))) {
	    fprintf(stderr, "ERROR: Problem with internal logger. Please check the permissions on the %s file.\n", logg_file);
	    exit(1);
	}
    } else
	logg_file = NULL;


#if defined(USE_SYSLOG) && !defined(C_AIX)
    if(cfgopt(copt, "LogSyslog")) {
	    int fac = LOG_LOCAL6;

	if((cpt = cfgopt(copt, "LogFacility"))) {
	    if((fac = logg_facility(cpt->strarg)) == -1) {
		fprintf(stderr, "ERROR: LogFacility: %s: No such facility.\n", cpt->strarg);
		exit(1);
	    }
	}

	openlog("clamd", LOG_PID, fac);
	logg_syslog = 1;
	syslog(LOG_INFO, "Daemon started.\n");
    }
#endif

    logg("clamd daemon "VERSION" (OS: "TARGET_OS_TYPE", ARCH: "TARGET_ARCH_TYPE", CPU: "TARGET_CPU_TYPE")\n");

    if(logg_size)
	logg("Log file size limited to %d bytes.\n", logg_size);
    else
	logg("Log file size limit disabled.\n");

    logg("*Verbose logging activated.\n");

#ifdef C_LINUX
    if(stat("/proc", &sb) == -1)
	procdev = 0;
    else
	procdev = sb.st_dev;
#endif

    /* check socket type */

    if(cfgopt(copt, "TCPSocket") && cfgopt(copt, "LocalSocket")) {
	fprintf(stderr, "ERROR: You can select one mode only (local/TCP).\n");
	logg("!Two modes (local & TCP) selected.\n");
	exit(1);
    } else if(cfgopt(copt, "TCPSocket")) {
	tcpsock = 1;
    } else if(cfgopt(copt, "LocalSocket")) {
	tcpsock = 0;
    } else {
	fprintf(stderr, "ERROR: You must select server type (local/tcp).\n");
	logg("!Please select server type (local/TCP).\n");
	exit(1);
    }

    /* drop priviledges */
    if(geteuid() == 0 && (cpt = cfgopt(copt, "User"))) {
	if((user = getpwnam(cpt->strarg)) == NULL) {
	    fprintf(stderr, "ERROR: Can't get information about user %s.\n", cpt->strarg);
	    logg("!Can't get information about user %s.\n", cpt->strarg);
	    exit(1);
	}

	if(cfgopt(copt, "AllowSupplementaryGroups")) {
#ifdef HAVE_INITGROUPS
	    if(initgroups(cpt->strarg, user->pw_gid)) {
		fprintf(stderr, "ERROR: initgroups() failed.\n");
		logg("!initgroups() failed.\n");
		exit(1);
	    }
#else
	    logg("AllowSupplementaryGroups: initgroups() not supported.\n");
#endif
	} else {
#ifdef HAVE_SETGROUPS
	    if(setgroups(1, &user->pw_gid)) {
		fprintf(stderr, "ERROR: setgroups() failed.\n");
		logg("!setgroups() failed.\n");
		exit(1);
	    }
#endif
	}

	if(setgid(user->pw_gid)) {
	    fprintf(stderr, "ERROR: setgid(%d) failed.\n", (int) user->pw_gid);
	    logg("!setgid(%d) failed.\n", (int) user->pw_gid);
	    exit(1);
	}

	if(setuid(user->pw_uid)) {
	    fprintf(stderr, "ERROR: setuid(%d) failed.\n", (int) user->pw_uid);
	    logg("!setuid(%d) failed.\n", (int) user->pw_uid);
	    exit(1);
	}

	logg("Running as user %s (UID %d, GID %d)\n", cpt->strarg, user->pw_uid, user->pw_gid);
    }

    /* set the temporary dir */
    if((cpt = cfgopt(copt, "TemporaryDirectory")))
	cl_settempdir(cpt->strarg, 0);

    if(cfgopt(copt, "LeaveTemporaryFiles"))
	cl_settempdir(NULL, 1);

    /* load the database(s) */
    if((cpt = cfgopt(copt, "DatabaseDirectory")) || (cpt = cfgopt(copt, "DataDirectory")))
	dbdir = cpt->strarg;
    else
	dbdir = cl_retdbdir();

    logg("Reading databases from %s\n", dbdir);

    if((ret = cl_loaddbdir(dbdir, &root, &virnum))) {
	fprintf(stderr, "ERROR: %s\n", cl_strerror(ret));
	logg("!%s\n", cl_strerror(ret));
	exit(1);
    }

    if(!root) {
	fprintf(stderr, "ERROR: Database initialization error.\n");
	logg("!Database initialization error.\n");
	exit(1);
    }

    logg("Protecting against %d viruses.\n", virnum);
    if((ret = cl_build(root)) != 0) {
	fprintf(stderr, "ERROR: Database initialization error: %s\n", cl_strerror(ret));;
	logg("!Database initialization error: %s\n", cl_strerror(ret));;
	exit(1);
    }


    /* fork into background */
    if(!cfgopt(copt, "Foreground"))
	daemonize();


    if(tcpsock)
	ret = tcpserver(opt, copt, root);
    else
	ret = localserver(opt, copt, root);

    printf("server ended; result=%d\n", ret);
    logg_close();
    freecfg(copt);
    printf("free() copt\n");

}

void help(void)
{

    printf("\n");
    printf("                           Clam AntiVirus Daemon "VERSION"\n");
    printf("   (C) 2002 - 2004 Tomasz Kojm <tkojm@clamav.net> and Trog <trog@clamav.net>\n\n");

    printf("    --help                   -h             Show this help.\n");
    printf("    --version                -V             Show version number.\n");
    printf("    --debug                                 Enable debug mode.\n");
    printf("    --config-file=FILE       -c FILE        Read configuration from FILE.\n\n");

    exit(0);
}

void daemonize(void)
{
	int i;


    if((i = open("/dev/null", O_WRONLY)) == -1) {
	logg("!Cannot open /dev/null. Only use Debug if Foreground is enabled.\n");
	for(i = 0; i <= 2; i++)
	    close(i);

    } else {
	close(0);
	dup2(i, 1);
	dup2(i, 2);
    }

    if(!debug_mode)
	chdir("/");

    if(fork())
	exit(0);

    setsid();
}

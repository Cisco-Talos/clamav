/*
 *  Copyright (C) 2002 - 2005 Tomasz Kojm <tkojm@clamav.net>
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
#include <string.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#include <sys/time.h>
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#ifdef C_WINDOWS
#include <direct.h>	/* for chdir */
#else
#include <pwd.h>
#include <grp.h>
#endif

#if defined(USE_SYSLOG) && !defined(C_AIX)
#include <syslog.h>
#endif

#ifdef C_LINUX
#include <sys/resource.h>
#endif

#include "target.h"

#include "libclamav/clamav.h"
#include "libclamav/others.h"
#include "libclamav/matcher-ac.h"
#include "libclamav/readdb.h"

#include "shared/output.h"
#include "shared/options.h"
#include "shared/cfgparser.h"
#include "shared/misc.h"

#include "server.h"
#include "tcpserver.h"
#include "localserver.h"
#include "others.h"
#include "shared.h"

#ifndef C_WINDOWS
#define	closesocket(s)	close(s)
#endif

short debug_mode = 0, logok = 0;
short foreground = 0;

static void help(void)
{
    printf("\n");
    printf("                      Clam AntiVirus Daemon %s\n", get_version());
    printf("    (C) 2002 - 2007 ClamAV Team - http://www.clamav.net/team\n\n");

    printf("    --help                   -h             Show this help.\n");
    printf("    --version                -V             Show version number.\n");
    printf("    --debug                                 Enable debug mode.\n");
    printf("    --config-file=FILE       -c FILE        Read configuration from FILE.\n\n");

}

int main(int argc, char **argv)
{
	struct cfgstruct *copt;
	const struct cfgstruct *cpt;
#ifndef	C_WINDOWS
        struct passwd *user = NULL;
#endif
	time_t currtime;
	struct cl_engine *engine = NULL;
	const char *dbdir, *cfgfile;
	char *pua_cats = NULL;
	int ret, tcpsock = 0, localsock = 0, i;
	unsigned int sigs = 0;
	int lsockets[2], nlsockets = 0;
	unsigned int dboptions = 0;
#ifdef C_LINUX
	struct stat sb;
#endif
	struct optstruct *opt;
	const char *short_options = "hc:V";

	static struct option long_options[] = {
	    {"help", 0, 0, 'h'},
	    {"config-file", 1, 0, 'c'},
	    {"version", 0, 0, 'V'},
	    {"debug", 0, 0, 0},
	    {0, 0, 0, 0}
    	};

#ifdef C_WINDOWS
    if(!pthread_win32_process_attach_np()) {
	mprintf("!Can't start the win32 pthreads layer\n");
        return 1;
    }
#endif

    opt = opt_parse(argc, argv, short_options, long_options, NULL);
    if(!opt) {
	mprintf("!Can't parse the command line\n");
	return 1;
    }

    if(opt_check(opt, "help")) {
    	help();
	opt_free(opt);
	return 0;
    }

    if(opt_check(opt, "debug")) {
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
    if(opt_check(opt, "config-file"))
	cfgfile = opt_arg(opt, "config-file");
    else
	cfgfile = CONFDIR"/clamd.conf";

    if((copt = getcfg(cfgfile, 1)) == NULL) {
	fprintf(stderr, "ERROR: Can't open/parse the config file %s\n", cfgfile);
	opt_free(opt);
	return 1;
    }

    if(opt_check(opt, "version")) {
	print_version(cfgopt(copt, "DatabaseDirectory")->strarg);
	opt_free(opt);
	freecfg(copt);
	return 0;
    }

    opt_free(opt);

    umask(0);

    /* drop privileges */
#if (!defined(C_OS2)) && (!defined(C_WINDOWS))
    if(geteuid() == 0 && (cpt = cfgopt(copt, "User"))->enabled) {
	if((user = getpwnam(cpt->strarg)) == NULL) {
	    fprintf(stderr, "ERROR: Can't get information about user %s.\n", cpt->strarg);
	    freecfg(copt);
	    return 1;
	}

	if(cfgopt(copt, "AllowSupplementaryGroups")->enabled) {
#ifdef HAVE_INITGROUPS
	    if(initgroups(cpt->strarg, user->pw_gid)) {
		fprintf(stderr, "ERROR: initgroups() failed.\n");
		freecfg(copt);
		return 1;
	    }
#else
	    mprintf("!AllowSupplementaryGroups: initgroups() is not available, please disable AllowSupplementaryGroups in %s\n", cfgfile);
	    freecfg(copt);
	    return 1;
#endif
	} else {
#ifdef HAVE_SETGROUPS
	    if(setgroups(1, &user->pw_gid)) {
		fprintf(stderr, "ERROR: setgroups() failed.\n");
		freecfg(copt);
		return 1;
	    }
#endif
	}

	if(setgid(user->pw_gid)) {
	    fprintf(stderr, "ERROR: setgid(%d) failed.\n", (int) user->pw_gid);
	    freecfg(copt);
	    return 1;
	}

	if(setuid(user->pw_uid)) {
	    fprintf(stderr, "ERROR: setuid(%d) failed.\n", (int) user->pw_uid);
	    freecfg(copt);
	    return 1;
	}
    }
#endif

    /* initialize logger */
    logg_lock = cfgopt(copt, "LogFileUnlock")->enabled;
    logg_time = cfgopt(copt, "LogTime")->enabled;
    logok = cfgopt(copt, "LogClean")->enabled;
    logg_size = cfgopt(copt, "LogFileMaxSize")->numarg;
    logg_verbose = mprintf_verbose = cfgopt(copt, "LogVerbose")->enabled;

    if(cfgopt(copt, "Debug")->enabled) /* enable debug messages in libclamav */
	cl_debug();

    if((cpt = cfgopt(copt, "LogFile"))->enabled) {
	char timestr[32];
	logg_file = cpt->strarg;
	if(strlen(logg_file) < 2 || (logg_file[0] != '/' && logg_file[0] != '\\' && logg_file[1] != ':')) {
	    fprintf(stderr, "ERROR: LogFile requires full path.\n");
	    logg_close();
	    freecfg(copt);
	    return 1;
	}
	time(&currtime);
	if(logg("#+++ Started at %s", cli_ctime(&currtime, timestr, sizeof(timestr)))) {
	    fprintf(stderr, "ERROR: Problem with internal logger. Please check the permissions on the %s file.\n", logg_file);
	    logg_close();
	    freecfg(copt);
	    return 1;
	}
    } else
	logg_file = NULL;

#if defined(USE_SYSLOG) && !defined(C_AIX)
    if(cfgopt(copt, "LogSyslog")->enabled) {
	    int fac = LOG_LOCAL6;

	cpt = cfgopt(copt, "LogFacility");
	if((fac = logg_facility(cpt->strarg)) == -1) {
	    logg("!LogFacility: %s: No such facility.\n", cpt->strarg);
	    logg_close();
	    freecfg(copt);
	    return 1;
	}

	openlog("clamd", LOG_PID, fac);
	logg_syslog = 1;
    }
#endif

#ifdef C_LINUX
    procdev = 0;
    if(stat("/proc", &sb) != -1 && !sb.st_size)
	procdev = sb.st_dev;
#endif

    /* check socket type */

    if(cfgopt(copt, "TCPSocket")->enabled)
	tcpsock = 1;

    if(cfgopt(copt, "LocalSocket")->enabled)
	localsock = 1;

    if(!tcpsock && !localsock) {
	logg("!Please define server type (local and/or TCP).\n");
	logg_close();
	freecfg(copt);
	return 1;
    }

    /* set the temporary dir */
    if((cpt = cfgopt(copt, "TemporaryDirectory"))->enabled)
	cl_settempdir(cpt->strarg, 0);

    if(cfgopt(copt, "LeaveTemporaryFiles")->enabled)
	cl_settempdir(NULL, 1);

    logg("#clamd daemon %s (OS: "TARGET_OS_TYPE", ARCH: "TARGET_ARCH_TYPE", CPU: "TARGET_CPU_TYPE")\n", get_version());

#ifndef C_WINDOWS
    if(user)
	logg("#Running as user %s (UID %u, GID %u)\n", user->pw_name, user->pw_uid, user->pw_gid);
#endif

    if(logg_size)
	logg("#Log file size limited to %d bytes.\n", logg_size);
    else
	logg("#Log file size limit disabled.\n");

    /* load the database(s) */
    dbdir = cfgopt(copt, "DatabaseDirectory")->strarg;
    logg("#Reading databases from %s\n", dbdir);

    if(cfgopt(copt, "DetectPUA")->enabled) {
	dboptions |= CL_DB_PUA;

	if((cpt = cfgopt(copt, "ExcludePUA"))->enabled) {
	    dboptions |= CL_DB_PUA_EXCLUDE;
	    i = 0;
	    logg("#Excluded PUA categories:");
	    while(cpt) {
		if(!(pua_cats = realloc(pua_cats, i + strlen(cpt->strarg) + 3))) {
		    logg("!Can't allocate memory for pua_cats\n");
		    logg_close();
		    freecfg(copt);
		    return 1;
		}
		logg("# %s", cpt->strarg);
		sprintf(pua_cats + i, ".%s", cpt->strarg);
		i += strlen(cpt->strarg) + 1;
		pua_cats[i] = 0;
		cpt = cpt->nextarg;
	    }
	    logg("#\n");
	    pua_cats[i] = '.';
	    pua_cats[i + 1] = 0;
	}

	if((cpt = cfgopt(copt, "IncludePUA"))->enabled) {
	    if(pua_cats) {
		logg("!ExcludePUA and IncludePUA cannot be used at the same time\n");
		logg_close();
		freecfg(copt);
		free(pua_cats);
		return 1;
	    }
	    dboptions |= CL_DB_PUA_INCLUDE;
	    i = 0;
	    logg("#Included PUA categories:");
	    while(cpt) {
		if(!(pua_cats = realloc(pua_cats, i + strlen(cpt->strarg) + 3))) {
		    logg("!Can't allocate memory for pua_cats\n");
		    logg_close();
		    freecfg(copt);
		    return 1;
		}
		logg("# %s", cpt->strarg);
		sprintf(pua_cats + i, ".%s", cpt->strarg);
		i += strlen(cpt->strarg) + 1;
		pua_cats[i] = 0;
		cpt = cpt->nextarg;
	    }
	    logg("#\n");
	    pua_cats[i] = '.';
	    pua_cats[i + 1] = 0;
	}

	if(pua_cats) {
	    /* FIXME with the new API */
	    if((ret = cli_initengine(&engine, dboptions))) {
		logg("!cli_initengine() failed: %s\n", cl_strerror(ret));
		logg_close();
		freecfg(copt);
		free(pua_cats);
		return 1;
	    }
	    engine->pua_cats = pua_cats;
	}
    } else {
	logg("#Not loading PUA signatures.\n");
    }

    if(cfgopt(copt, "PhishingSignatures")->enabled)
	dboptions |= CL_DB_PHISHING;
    else
	logg("#Not loading phishing signatures.\n");

    if(cfgopt(copt,"PhishingScanURLs")->enabled)
	dboptions |= CL_DB_PHISHING_URLS;
    else
	logg("#Disabling URL based phishing detection.\n");

    if(cfgopt(copt,"DevACOnly")->enabled) {
	logg("#Only using the A-C matcher.\n");
	dboptions |= CL_DB_ACONLY;
    }

    if((cpt = cfgopt(copt, "DevACDepth"))->enabled) {
	cli_ac_setdepth(AC_DEFAULT_MIN_DEPTH, cpt->numarg);
	logg("#Max A-C depth set to %u\n", cpt->numarg);
    }

    if((ret = cl_load(dbdir, &engine, &sigs, dboptions))) {
	logg("!%s\n", cl_strerror(ret));
	logg_close();
	freecfg(copt);
	return 1;
    }

    if(!engine) {
	logg("!Database initialization error.\n");
	logg_close();
	freecfg(copt);
	return 1;
    }

    logg("#Loaded %u signatures.\n", sigs);
    if((ret = cl_build(engine)) != 0) {
	logg("!Database initialization error: %s\n", cl_strerror(ret));;
	logg_close();
	freecfg(copt);
	return 1;
    }

    if(tcpsock) {
#ifdef C_WINDOWS
	    WSADATA wsaData;

	if(WSAStartup(MAKEWORD(2,2), &wsaData) != NO_ERROR) {
	    logg("!Error at WSAStartup(): %d\n", WSAGetLastError());
	    logg_close();
	    freecfg(copt);
	    return 1;
	}
#endif
	lsockets[nlsockets] = tcpserver(copt);
	if(lsockets[nlsockets] == -1) {
	    logg_close();
	    freecfg(copt);
	    return 1;
	}
	nlsockets++;
    }

    if(localsock) {
	lsockets[nlsockets] = localserver(copt);
	if(lsockets[nlsockets] == -1) {
	    logg_close();
	    freecfg(copt);
	    if(tcpsock)
		closesocket(lsockets[0]);
	    return 1;
	}
	nlsockets++;
    }

    /* fork into background */
    if(!cfgopt(copt, "Foreground")->enabled) {
#ifdef C_BSD	    
	/* workaround for OpenBSD bug, see https://wwws.clamav.net/bugzilla/show_bug.cgi?id=885 */
	for(ret=0;ret<nlsockets;ret++) {
		fcntl(lsockets[ret], F_SETFL, fcntl(lsockets[ret], F_GETFL) | O_NONBLOCK);
	}
#endif
	if(daemonize() == -1) {
	    logg("!daemonize() failed\n");
	    logg_close();
	    freecfg(copt);
	    return 1;
	}
#ifdef C_BSD
	for(ret=0;ret<nlsockets;ret++) {
		fcntl(lsockets[ret], F_SETFL, fcntl(lsockets[ret], F_GETFL) & ~O_NONBLOCK);
	}
#endif
	if(!debug_mode)
	    if(chdir("/") == -1)
		logg("^Can't change current working directory to root\n");

    } else
        foreground = 1;


    ret = acceptloop_th(lsockets, nlsockets, engine, dboptions, copt);

#ifdef C_WINDOWS
    if(tcpsock)
	WSACleanup();

    if(!pthread_win32_process_detach_np()) {
	logg("!Can't stop the win32 pthreads layer\n");
	logg_close();
	freecfg(copt);
	return 1;
    }
#endif

    logg_close();
    freecfg(copt);

    return ret;
}

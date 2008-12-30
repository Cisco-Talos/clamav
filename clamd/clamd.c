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
#include "shared/optparser.h"
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

static struct optstruct *opts;
/* needs to be global, so that valgrind reports it as reachable, and not
 * as definetely/indirectly lost when daemonizing clamd */
static struct cl_engine *engine;
int main(int argc, char **argv)
{
	const struct optstruct *opt;
#ifndef	C_WINDOWS
        struct passwd *user = NULL;
#endif
	time_t currtime;
	const char *dbdir, *cfgfile;
	char *pua_cats = NULL, *pt;
	int ret, tcpsock = 0, localsock = 0, i;
	unsigned int sigs = 0;
	int lsockets[2], nlsockets = 0;
	unsigned int dboptions = 0;
	uint32_t val32;
#ifdef C_LINUX
	struct stat sb;
#endif

#ifdef C_WINDOWS
    if(!pthread_win32_process_attach_np()) {
	mprintf("!Can't start the win32 pthreads layer\n");
        return 1;
    }
#endif

    if((opts = optparse(NULL, argc, argv, 1, OPT_CLAMD, 0, NULL)) == NULL) {
	mprintf("!Can't parse command line options\n");
	return 1;
    }

    if(optget(opts, "help")->enabled) {
    	help();
	optfree(opts);
	return 0;
    }

    if(optget(opts, "debug")->enabled) {
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
    cfgfile = optget(opts, "config-file")->strarg;
    pt = strdup(cfgfile);
    if((opts = optparse(cfgfile, 0, NULL, 1, OPT_CLAMD, 0, opts)) == NULL) {
	fprintf(stderr, "ERROR: Can't open/parse the config file %s\n", pt);
	free(pt);
	return 1;
    }
    free(pt);

    if(optget(opts, "version")->enabled) {
	print_version(optget(opts, "DatabaseDirectory")->strarg);
	optfree(opts);
	return 0;
    }

    umask(0);

    /* drop privileges */
#if (!defined(C_OS2)) && (!defined(C_WINDOWS))
    if(geteuid() == 0 && (opt = optget(opts, "User"))->enabled) {
	if((user = getpwnam(opt->strarg)) == NULL) {
	    fprintf(stderr, "ERROR: Can't get information about user %s.\n", opt->strarg);
	    optfree(opts);
	    return 1;
	}

	if(optget(opts, "AllowSupplementaryGroups")->enabled) {
#ifdef HAVE_INITGROUPS
	    if(initgroups(opt->strarg, user->pw_gid)) {
		fprintf(stderr, "ERROR: initgroups() failed.\n");
		optfree(opts);
		return 1;
	    }
#else
	    mprintf("!AllowSupplementaryGroups: initgroups() is not available, please disable AllowSupplementaryGroups in %s\n", cfgfile);
	    optfree(opts);
	    return 1;
#endif
	} else {
#ifdef HAVE_SETGROUPS
	    if(setgroups(1, &user->pw_gid)) {
		fprintf(stderr, "ERROR: setgroups() failed.\n");
		optfree(opts);
		return 1;
	    }
#endif
	}

	if(setgid(user->pw_gid)) {
	    fprintf(stderr, "ERROR: setgid(%d) failed.\n", (int) user->pw_gid);
	    optfree(opts);
	    return 1;
	}

	if(setuid(user->pw_uid)) {
	    fprintf(stderr, "ERROR: setuid(%d) failed.\n", (int) user->pw_uid);
	    optfree(opts);
	    return 1;
	}
    }
#endif

    /* initialize logger */
    logg_lock = !optget(opts, "LogFileUnlock")->enabled;
    logg_time = optget(opts, "LogTime")->enabled;
    logok = optget(opts, "LogClean")->enabled;
    logg_size = optget(opts, "LogFileMaxSize")->numarg;
    logg_verbose = mprintf_verbose = optget(opts, "LogVerbose")->enabled;

    if((opt = optget(opts, "LogFile"))->enabled) {
	char timestr[32];
	logg_file = opt->strarg;
	if(strlen(logg_file) < 2 || (logg_file[0] != '/' && logg_file[0] != '\\' && logg_file[1] != ':')) {
	    fprintf(stderr, "ERROR: LogFile requires full path.\n");
	    logg_close();
	    optfree(opts);
	    return 1;
	}
	time(&currtime);
	if(logg("#+++ Started at %s", cli_ctime(&currtime, timestr, sizeof(timestr)))) {
	    fprintf(stderr, "ERROR: Can't initialize the internal logger\n");
	    logg_close();
	    optfree(opts);
	    return 1;
	}
    } else
	logg_file = NULL;

    if((ret = cl_init(CL_INIT_DEFAULT))) {
	logg("!Can't initialize libclamav: %s\n", cl_strerror(ret));
	logg_close();
	optfree(opts);
	return 1;
    }

    if(optget(opts, "Debug")->enabled) /* enable debug messages in libclamav */
	cl_debug();

#if defined(USE_SYSLOG) && !defined(C_AIX)
    if(optget(opts, "LogSyslog")->enabled) {
	    int fac = LOG_LOCAL6;

	opt = optget(opts, "LogFacility");
	if((fac = logg_facility(opt->strarg)) == -1) {
	    logg("!LogFacility: %s: No such facility.\n", opt->strarg);
	    logg_close();
	    optfree(opts);
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

    if(optget(opts, "TCPSocket")->enabled)
	tcpsock = 1;

    if(optget(opts, "LocalSocket")->enabled)
	localsock = 1;

    if(!tcpsock && !localsock) {
	logg("!Please define server type (local and/or TCP).\n");
	logg_close();
	optfree(opts);
	return 1;
    }

    logg("#clamd daemon %s (OS: "TARGET_OS_TYPE", ARCH: "TARGET_ARCH_TYPE", CPU: "TARGET_CPU_TYPE")\n", get_version());

#ifndef C_WINDOWS
    if(user)
	logg("#Running as user %s (UID %u, GID %u)\n", user->pw_name, user->pw_uid, user->pw_gid);
#endif

    if(logg_size)
	logg("#Log file size limited to %d bytes.\n", logg_size);
    else
	logg("#Log file size limit disabled.\n");

    if(!(engine = cl_engine_new())) {
	logg("!Can't initialize antivirus engine\n");
	logg_close();
	optfree(opts);
	return 1;
    }

    /* load the database(s) */
    dbdir = optget(opts, "DatabaseDirectory")->strarg;
    logg("#Reading databases from %s\n", dbdir);

    if(optget(opts, "DetectPUA")->enabled) {
	dboptions |= CL_DB_PUA;

	if((opt = optget(opts, "ExcludePUA"))->enabled) {
	    dboptions |= CL_DB_PUA_EXCLUDE;
	    i = 0;
	    logg("#Excluded PUA categories:");
	    while(opt) {
		if(!(pua_cats = realloc(pua_cats, i + strlen(opt->strarg) + 3))) {
		    logg("!Can't allocate memory for pua_cats\n");
		    logg_close();
		    optfree(opts);
		    cl_engine_free(engine);
		    return 1;
		}
		logg("# %s", opt->strarg);
		sprintf(pua_cats + i, ".%s", opt->strarg);
		i += strlen(opt->strarg) + 1;
		pua_cats[i] = 0;
		opt = opt->nextarg;
	    }
	    logg("#\n");
	    pua_cats[i] = '.';
	    pua_cats[i + 1] = 0;
	}

	if((opt = optget(opts, "IncludePUA"))->enabled) {
	    if(pua_cats) {
		logg("!ExcludePUA and IncludePUA cannot be used at the same time\n");
		logg_close();
		optfree(opts);
		free(pua_cats);
		cl_engine_free(engine);
		return 1;
	    }
	    dboptions |= CL_DB_PUA_INCLUDE;
	    i = 0;
	    logg("#Included PUA categories:");
	    while(opt) {
		if(!(pua_cats = realloc(pua_cats, i + strlen(opt->strarg) + 3))) {
		    logg("!Can't allocate memory for pua_cats\n");
		    logg_close();
		    optfree(opts);
		    cl_engine_free(engine);
		    return 1;
		}
		logg("# %s", opt->strarg);
		sprintf(pua_cats + i, ".%s", opt->strarg);
		i += strlen(opt->strarg) + 1;
		pua_cats[i] = 0;
		opt = opt->nextarg;
	    }
	    logg("#\n");
	    pua_cats[i] = '.';
	    pua_cats[i + 1] = 0;
	}

	if(pua_cats) {
	    if((ret = cl_engine_set(engine, CL_ENGINE_PUA_CATEGORIES, pua_cats))) {
		logg("!cli_engine_set(CL_ENGINE_PUA_CATEGORIES) failed: %s\n", cl_strerror(ret));
		logg_close();
		optfree(opts);
		free(pua_cats);
		cl_engine_free(engine);
		return 1;
	    }
	    free(pua_cats);
	}
    } else {
	logg("#Not loading PUA signatures.\n");
    }

    /* set the temporary dir */
    if((opt = optget(opts, "TemporaryDirectory"))->enabled) {
	if((ret = cl_engine_set(engine, CL_ENGINE_TMPDIR, opt->strarg))) {
	    logg("!cli_engine_set(CL_ENGINE_TMPDIR) failed: %s\n", cl_strerror(ret));
	    logg_close();
	    optfree(opts);
	    cl_engine_free(engine);
	    return 1;
	}
    }

    if(optget(opts, "LeaveTemporaryFiles")->enabled) {
	val32 = 1;
	cl_engine_set(engine, CL_ENGINE_KEEPTMP, &val32);
    }

    if(optget(opts, "PhishingSignatures")->enabled)
	dboptions |= CL_DB_PHISHING;
    else
	logg("#Not loading phishing signatures.\n");

    if(optget(opts,"PhishingScanURLs")->enabled)
	dboptions |= CL_DB_PHISHING_URLS;
    else
	logg("#Disabling URL based phishing detection.\n");

    if(optget(opts,"DevACOnly")->enabled) {
	logg("#Only using the A-C matcher.\n");
        val32 = 1;
	cl_engine_set(engine, CL_ENGINE_AC_ONLY, &val32);
    }

    if((opt = optget(opts, "DevACDepth"))->enabled) {
	val32 = opt->numarg;
        cl_engine_set(engine, CL_ENGINE_AC_MAXDEPTH, &val32);
	logg("#Max A-C depth set to %u\n", opt->numarg);
    }

    if((ret = cl_load(dbdir, engine, &sigs, dboptions))) {
	logg("!%s\n", cl_strerror(ret));
	logg_close();
	optfree(opts);
	cl_engine_free(engine);
	return 1;
    }

    logg("#Loaded %u signatures.\n", sigs);
    if((ret = cl_engine_compile(engine)) != 0) {
	logg("!Database initialization error: %s\n", cl_strerror(ret));
	logg_close();
	optfree(opts);
	cl_engine_free(engine);
	return 1;
    }

    if(tcpsock) {
#ifdef C_WINDOWS
	    WSADATA wsaData;

	if(WSAStartup(MAKEWORD(2,2), &wsaData) != NO_ERROR) {
	    logg("!Error at WSAStartup(): %d\n", WSAGetLastError());
	    logg_close();
	    optfree(opts);
	    cl_engine_free(engine);
	    return 1;
	}
#endif
	lsockets[nlsockets] = tcpserver(opts);
	if(lsockets[nlsockets] == -1) {
	    logg_close();
	    optfree(opts);
	    cl_engine_free(engine);
	    return 1;
	}
	nlsockets++;
    }

    if(localsock) {
	lsockets[nlsockets] = localserver(opts);
	if(lsockets[nlsockets] == -1) {
	    logg_close();
	    optfree(opts);
	    if(tcpsock)
		closesocket(lsockets[0]);
	    cl_engine_free(engine);
	    return 1;
	}
	nlsockets++;
    }

    /* fork into background */
    if(!optget(opts, "Foreground")->enabled) {
#ifdef C_BSD	    
	/* workaround for OpenBSD bug, see https://wwws.clamav.net/bugzilla/show_bug.cgi?id=885 */
	for(ret=0;ret<nlsockets;ret++) {
		fcntl(lsockets[ret], F_SETFL, fcntl(lsockets[ret], F_GETFL) | O_NONBLOCK);
	}
#endif
	if(daemonize() == -1) {
	    logg("!daemonize() failed\n");
	    logg_close();
	    optfree(opts);
	    cl_engine_free(engine);
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


    ret = acceptloop_th(lsockets, nlsockets, engine, dboptions, opts);

#ifdef C_WINDOWS
    if(tcpsock)
	WSACleanup();

    if(!pthread_win32_process_detach_np()) {
	logg("!Can't stop the win32 pthreads layer\n");
	logg_close();
	optfree(opts);
	return 1;
    }
#endif

    logg_close();
    optfree(opts);

    return ret;
}

/*
 *  Copyright (C)2008 Sourcefire, Inc.
 *
 *  Author: aCaB <acab@clamav.net>
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
#include <sys/types.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <libmilter/mfapi.h>

#include "clamav.h"

#include "shared/options.h"
#include "shared/output.h"
#include "shared/cfgparser.h"
#include "shared/misc.h"

#include "connpool.h"
#include "netcode.h"
#include "clamfi.h"


struct smfiDesc descr = {
    "ClamAV", 		/* filter name */
    SMFI_VERSION,	/* milter version */
    SMFIF_ADDHDRS|SMFIF_ADDRCPT, /* flags */
    NULL,		/* connection info filter */
    NULL,		/* SMTP HELO command filter */
    NULL,		/* envelope sender filter */
    NULL,		/* envelope recipient filter */
    clamfi_header,	/* header filter */
    NULL,		/* end of header */
    clamfi_body,	/* body block */
    clamfi_eom,		/* end of message */
    NULL,		/* message aborted */
    NULL,		/* connection cleanup */
    NULL,		/* any unrecognized or unimplemented command filter */
    NULL,		/* SMTP DATA command filter */
    NULL		/* negotiation callback */
};

int main(int argc, char **argv) {
    static struct cfgstruct *copt;
    char *my_socket;
    const struct cfgstruct *cpt;
    struct optstruct *opt;
    const char *short_options = "c:hV";
    static struct option long_options[] = {
	{"config-file", required_argument, NULL, 'c'},
	{"help", no_argument, NULL, 'h'},
	{"version", no_argument, NULL, 'V'},
	{NULL, 0, NULL, 0}
    };
    const char *my_conf = CONFDIR "/clamav-milter.conf";
    int ret;

    opt = opt_parse(argc, argv, short_options, long_options, NULL, NULL);	
    if (!opt) {
	mprintf("!Can't parse the command line\n");
	return 1;
    }

    if(opt_check(opt, "help")) {
	printf("Usage: %s [-c <config-file>]\n\n", argv[0]);
	printf("    --help                   -h       Show this help\n");
	printf("    --version                -V       Show version and exit\n");
	printf("    --config-file <file>     -c       Read configuration from file\n\n");
	opt_free(opt);
	return 0;
    }
	
    if(opt->filename)
	mprintf("^Ignoring option %s\n", opt->filename);

    if(opt_check(opt, "version")) {
	printf("clamav-milter %s\n", get_version());
	opt_free(opt);
	return 0;
    }

    if(opt_check(opt, "config-file"))
	my_conf = opt_arg(opt, "config-file");

    if((copt = getcfg(my_conf, 1, OPT_MILTER)) == NULL) {
	printf("%s: cannot parse config file %s\n", argv[0], my_conf);
	opt_free(opt);
	return 1;
    }

    opt_free(opt);

    if(geteuid() == 0 && (cpt = cfgopt(copt, "User"))->enabled) {
        struct passwd *user = NULL;
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
	    mprintf("!AllowSupplementaryGroups: initgroups() is not available, please disable AllowSupplementaryGroups\n");
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

    logg_lock = !cfgopt(copt, "LogFileUnlock")->enabled;
    logg_time = cfgopt(copt, "LogTime")->enabled;
    logg_size = cfgopt(copt, "LogFileMaxSize")->numarg;
    logg_verbose = mprintf_verbose = cfgopt(copt, "LogVerbose")->enabled;

    if((cpt = cfgopt(copt, "LogFile"))->enabled) {
	time_t currtime;
	logg_file = cpt->strarg;
	if(strlen(logg_file) < 2 || logg_file[0] != '/') {
	    fprintf(stderr, "ERROR: LogFile requires full path.\n");
	    logg_close();
	    freecfg(copt);
	    return 1;
	}
	time(&currtime);
	if(logg("#+++ Started at %s", ctime(&currtime))) {
	    fprintf(stderr, "ERROR: Can't initialize the internal logger\n");
	    logg_close();
	    freecfg(copt);
	    return 1;
	}
    } else
	logg_file = NULL;

#if defined(USE_SYSLOG) && !defined(C_AIX)
    if(cfgopt(copt, "LogSyslog")->enabled) {
	int fac;

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

    if(localnets_init(copt)) {
	logg_close();
	freecfg(copt);
	return 1;
    }

    umask(0007);
    if(!(my_socket = cfgopt(copt, "MilterSocket")->strarg)) {
	logg("!Please configure the MilterSocket directive\n");
	logg_close();
	freecfg(copt);
	return 1;
    }
    if(smfi_setconn(my_socket) == MI_FAILURE) {
	logg("!smfi_setconn failed\n");
	logg_close();
	freecfg(copt);
	return 1;
    }
    if(smfi_register(descr) == MI_FAILURE) {
	logg("!smfi_register failed\n");
	logg_close();
	freecfg(copt);
	return 1;
    }
    cpt = cfgopt(copt, "FixStaleSocket");
    if(smfi_opensocket(cpt->enabled) == MI_FAILURE) {
	logg("!Failed to create socket %s\n", my_socket);
	logg_close();
	freecfg(copt);
	return 1;
    }

    maxfilesize = cfgopt(copt, "MaxFileSize")->numarg;
    readtimeout = cfgopt(copt, "ReadTimeout")->numarg;

    cpool_init(copt);
    if (!cp) {
	logg("!Failed to init the socket pool\n");
	logg_close();
	freecfg(copt);
	return 1;
    }	

    if(!cfgopt(copt, "Foreground")->enabled) {
	if(daemonize() == -1) {
	    logg("!daemonize() failed\n");
	    cpool_free();
	    logg_close();
	    return 1;
	}
	if(chdir("/") == -1)
	    logg("^Can't change current working directory to root\n");
    }


    ret = smfi_main();

    freecfg(copt);

    logg_close();
    cpool_free();
    localnets_free();
    return ret;
}
/*
 * Local Variables:
 * mode: c
 * c-basic-offset: 4
 * tab-width: 8
 * End: 
 * vim: set cindent smartindent autoindent softtabstop=4 shiftwidth=4 tabstop=8: 
 */

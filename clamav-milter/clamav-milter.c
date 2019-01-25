/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2008-2013 Sourcefire, Inc.
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
#include <signal.h>
#include <pthread.h>
#ifdef USE_SYSLOG
#include <syslog.h>
#endif
#include <time.h>
#include <libmilter/mfapi.h>

#include "clamav.h"

#include "shared/output.h"
#include "shared/optparser.h"
#include "shared/misc.h"
#include "libclamav/default.h"

#include "connpool.h"
#include "netcode.h"
#include "clamfi.h"
#include "whitelist.h"

struct smfiDesc descr;
struct optstruct *opts;

static void milter_exit(int sig) {
    const struct optstruct *opt;

    logg("*clamav-milter: milter_exit, signal %d\n", sig);

#ifndef _WIN32
    if((opt = optget(opts, "MilterSocket"))) {
        if(unlink(opt->strarg) == -1)
            logg("!Can't unlink the socket file %s\n", opt->strarg);
        else
            logg("Socket file removed.\n");
    }
#endif

    logg("clamav-milter: stopped\n");

    optfree(opts);

    logg_close();
    cpool_free();
    localnets_free();
    whitelist_free();
}

int main(int argc, char **argv) {
    char *my_socket, *pt;
    const struct optstruct *opt;
    time_t currtime;
    mode_t umsk;
    int ret;

    sigset_t sigset;
    struct sigaction act;

    sigfillset(&sigset);
    sigdelset(&sigset, SIGUSR1);
    sigdelset(&sigset, SIGFPE);
    sigdelset(&sigset, SIGILL);
    sigdelset(&sigset, SIGSEGV);
#ifdef SIGBUS
    sigdelset(&sigset, SIGBUS);
#endif
    pthread_sigmask(SIG_SETMASK, &sigset, NULL);
    memset(&act, 0, sizeof(struct sigaction));
    act.sa_handler = milter_exit;
    sigfillset(&(act.sa_mask));
    sigaction(SIGUSR1, &act, NULL);
    sigaction(SIGSEGV, &act, NULL);

    cl_initialize_crypto();

    memset(&descr, 0, sizeof(struct smfiDesc));
    descr.xxfi_name = "ClamAV";			/* filter name */
    descr.xxfi_version = SMFI_VERSION;		/* milter version */
    descr.xxfi_flags = SMFIF_QUARANTINE;	/* flags */
    descr.xxfi_connect = clamfi_connect;	/* connection info filter */
    descr.xxfi_envfrom = clamfi_envfrom;	/* envelope sender filter */
    descr.xxfi_envrcpt = clamfi_envrcpt;	/* envelope recipient filter */
    descr.xxfi_header = clamfi_header;		/* header filter */
    descr.xxfi_body = clamfi_body;		/* body block */
    descr.xxfi_eom = clamfi_eom;		/* end of message */
    descr.xxfi_abort = clamfi_abort;		/* message aborted */

    opts = optparse(NULL, argc, argv, 1, OPT_MILTER, 0, NULL);
    if (!opts) {
	mprintf("!Can't parse command line options\n");
	return 1;
    }

    if(optget(opts, "help")->enabled) {
    printf("\n");
    printf("                       Clam AntiVirus: Milter Mail Scanner %s\n", get_version());
    printf("           By The ClamAV Team: https://www.clamav.net/about.html#credits\n");
    printf("           (C) 2019 Cisco Systems, Inc.\n");
    printf("\n");
	printf("    %s [-c <config-file>]\n\n", argv[0]);
    printf("\n");
	printf("    --help                   -h       Show this help\n");
	printf("    --version                -V       Show version\n");
	printf("    --config-file <file>     -c       Read configuration from file\n");
    printf("\n");
	optfree(opts);
	return 0;
    }

    if(opts->filename) {
	int x;
	for(x = 0; opts->filename[x]; x++)
	    mprintf("^Ignoring option %s\n", opts->filename[x]);
    }

    if(optget(opts, "version")->enabled) {
	printf("clamav-milter %s\n", get_version());
	optfree(opts);
	return 0;
    }

    pt = strdup(optget(opts, "config-file")->strarg);
    if (pt == NULL) {
	printf("Unable to allocate memory for config file\n");
	return 1;
    }
    if((opts = optparse(pt, 0, NULL, 1, OPT_MILTER, 0, opts)) == NULL) {
	printf("%s: cannot parse config file %s\n", argv[0], pt);
	free(pt);
	return 1;
    }
    free(pt);

    if((opt = optget(opts, "Chroot"))->enabled) {
	if(chdir(opt->strarg) != 0) {
	    logg("!Cannot change directory to %s\n", opt->strarg);
	    return 1;
	}
	if(chroot(opt->strarg) != 0) {
	    logg("!chroot to %s failed. Are you root?\n", opt->strarg);
	    return 1;
	}
    }

    pt = optget(opts, "AddHeader")->strarg;
    if (strcasecmp(pt, "No")) {
	char myname[255];

	if (((opt = optget(opts, "ReportHostname"))->enabled &&
	     strncpy(myname, opt->strarg, sizeof(myname))) ||
	    !gethostname(myname, sizeof(myname))) {

	    myname[sizeof(myname)-1] = '\0';
	    snprintf(xvirushdr, sizeof(xvirushdr), "clamav-milter %s at %s",
		     get_version(), myname);
	} else {
	    snprintf(xvirushdr, sizeof(xvirushdr), "clamav-milter %s",
		     get_version());
	}
	xvirushdr[sizeof(xvirushdr)-1] = '\0';

	descr.xxfi_flags |= SMFIF_ADDHDRS;

	if (strcasecmp(pt, "Add")) { /* Replace or Yes */
	    descr.xxfi_flags |= SMFIF_CHGHDRS;
	    addxvirus = 1;
	} else { /* Add */
	    addxvirus = 2;
	}
    }

    if(!(my_socket = optget(opts, "MilterSocket")->strarg)) {
	logg("!Please configure the MilterSocket directive\n");
	logg_close();
	optfree(opts);
	return 1;
    }

    if(smfi_setconn(my_socket) == MI_FAILURE) {
	logg("!smfi_setconn failed\n");
	logg_close();
	optfree(opts);
	return 1;
    }
    if(smfi_register(descr) == MI_FAILURE) {
	logg("!smfi_register failed\n");
	logg_close();
	optfree(opts);
	return 1;
    }
    opt = optget(opts, "FixStaleSocket");
    umsk = umask(0777); /* socket is created with 000 to avoid races */
    if(smfi_opensocket(opt->enabled) == MI_FAILURE) {
	logg("!Failed to create socket %s\n", my_socket);
	logg_close();
	optfree(opts);
	return 1;
    }
    umask(umsk); /* restore umask */
    if(strncmp(my_socket, "inet:", 5) && strncmp(my_socket, "inet6:", 6)) {
	/* set group ownership and perms on the local socket */
	char *sock_name = my_socket;
	mode_t sock_mode;
	if(!strncmp(my_socket, "unix:", 5))
	    sock_name += 5;
	if(!strncmp(my_socket, "local:", 6))
	    sock_name += 6;
	if(*my_socket == ':')
	    sock_name ++;

	if(optget(opts, "MilterSocketGroup")->enabled) {
	    char *gname = optget(opts, "MilterSocketGroup")->strarg, *end;
	    gid_t sock_gid = strtol(gname, &end, 10);
	    if(*end) {
		struct group *pgrp = getgrnam(gname);
		if(!pgrp) {
		    logg("!Unknown group %s\n", gname);
		    logg_close();
		    optfree(opts);
		    return 1;
		}
		sock_gid = pgrp->gr_gid;
	    }
	    if(chown(sock_name, -1, sock_gid)) {
		logg("!Failed to change socket ownership to group %s\n", gname);
		logg_close();
		optfree(opts);
		return 1;
	    }
	}

	if ((opt = optget(opts, "User"))->enabled) {
	    struct passwd *user;
	    if ((user = getpwnam(opt->strarg)) == NULL) {
		logg("ERROR: Can't get information about user %s.\n",
			opt->strarg);
		logg_close();
		optfree(opts);
		return 1;
	    }

	    if(chown(sock_name, user->pw_uid, -1)) {
		logg("!Failed to change socket ownership to user %s\n", user->pw_name);
		optfree(opts);
		logg_close();
		return 1;
	    }
	}

	if(optget(opts, "MilterSocketMode")->enabled) {
	    char *end;
	    sock_mode = strtol(optget(opts, "MilterSocketMode")->strarg, &end, 8);
	    if(*end) {
		logg("!Invalid MilterSocketMode %s\n", optget(opts, "MilterSocketMode")->strarg);
		logg_close();
		optfree(opts);
		return 1;
	    }
	} else
	    sock_mode = 0777 & ~umsk;

	if(chmod(sock_name, sock_mode & 0666)) {
	    logg("!Cannot set milter socket permission to %s\n", optget(opts, "MilterSocketMode")->strarg);
	    logg_close();
	    optfree(opts);
	    return 1;
	}
    }

    if(geteuid() == 0 && (opt = optget(opts, "User"))->enabled) {
        struct passwd *user = NULL;
	if((user = getpwnam(opt->strarg)) == NULL) {
	    fprintf(stderr, "ERROR: Can't get information about user %s.\n", opt->strarg);
	    optfree(opts);
	    return 1;
	}

#ifdef HAVE_INITGROUPS
	if(initgroups(opt->strarg, user->pw_gid)) {
	    fprintf(stderr, "ERROR: initgroups() failed.\n");
	    optfree(opts);
	    return 1;
	}
#elif HAVE_SETGROUPS
	if(setgroups(1, &user->pw_gid)) {
	    fprintf(stderr, "ERROR: setgroups() failed.\n");
	    optfree(opts);
	    return 1;
	}
#endif
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

    logg_lock = !optget(opts, "LogFileUnlock")->enabled;
    logg_time = optget(opts, "LogTime")->enabled;
    logg_size = optget(opts, "LogFileMaxSize")->numarg;
    logg_verbose = mprintf_verbose = optget(opts, "LogVerbose")->enabled;
    if (logg_size)
        logg_rotate = optget(opts, "LogRotate")->enabled;

    if((opt = optget(opts, "LogFile"))->enabled) {
	logg_file = opt->strarg;
	if(!cli_is_abspath(logg_file)) {
	    fprintf(stderr, "ERROR: LogFile requires full path.\n");
	    logg_close();
	    optfree(opts);
	    return 1;
	}
    } else
	logg_file = NULL;

#if defined(USE_SYSLOG) && !defined(C_AIX)
    if(optget(opts, "LogSyslog")->enabled) {
	int fac;

	opt = optget(opts, "LogFacility");
	if((fac = logg_facility(opt->strarg)) == -1) {
	    logg("!LogFacility: %s: No such facility.\n", opt->strarg);
	    logg_close();
	    optfree(opts);
	    return 1;
	}

	openlog("clamav-milter", LOG_PID, fac);
	logg_syslog = 1;
    }
#endif

    time(&currtime);
    if(logg("#+++ Started at %s", ctime(&currtime))) {
	fprintf(stderr, "ERROR: Can't initialize the internal logger\n");
	logg_close();
	optfree(opts);
	return 1;
    }
    if((opt = optget(opts, "TemporaryDirectory"))->enabled)
	tempdir = opt->strarg;

    if(localnets_init(opts) || init_actions(opts)) {
	logg_close();
	optfree(opts);
	return 1;
    }

    if((opt = optget(opts, "Whitelist"))->enabled && whitelist_init(opt->strarg)) {
	localnets_free();
	logg_close();
	optfree(opts);
	return 1;
    }

    if((opt = optget(opts, "SkipAuthenticated"))->enabled && smtpauth_init(opt->strarg)) {
	localnets_free();
	whitelist_free();
	logg_close();
	optfree(opts);
	return 1;
    }

    multircpt = optget(opts, "SupportMultipleRecipients")->enabled;
    
    if(!optget(opts, "Foreground")->enabled) {
	if(daemonize() == -1) {
	    logg("!daemonize() failed\n");
	    localnets_free();
	    whitelist_free();
	    cpool_free();
	    logg_close();
	    optfree(opts);
	    return 1;
	}
	if(chdir("/") == -1)
	    logg("^Can't change current working directory to root\n");
    }

    maxfilesize = optget(opts, "MaxFileSize")->numarg;
    if(!maxfilesize) {
	logg("^Invalid MaxFileSize, using default (%d)\n", CLI_DEFAULT_MAXFILESIZE);
	maxfilesize = CLI_DEFAULT_MAXFILESIZE;
    }
    readtimeout = optget(opts, "ReadTimeout")->numarg;

    cpool_init(opts);
    if (!cp) {
	logg("!Failed to init the socket pool\n");
	localnets_free();
	whitelist_free();
	logg_close();
	optfree(opts);
	return 1;
    }	

    if((opt = optget(opts, "PidFile"))->enabled) {
	FILE *fd;
	mode_t old_umask = umask(0002);

	if((fd = fopen(opt->strarg, "w")) == NULL) {
	    logg("!Can't save PID in file %s\n", opt->strarg);
	} else {
	    if (fprintf(fd, "%u\n", (unsigned int)getpid())<0) {
	    	logg("!Can't save PID in file %s\n", opt->strarg);
	    }
	    fclose(fd);
	}
	umask(old_umask);
    }

    return smfi_main();
}

/*
 * Local Variables:
 * mode: c
 * c-basic-offset: 4
 * tab-width: 8
 * End: 
 * vim: set cindent smartindent autoindent softtabstop=4 shiftwidth=4 tabstop=8: 
 */

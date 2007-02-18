/*
 *  Copyright (C) 2002 - 2004 Tomasz Kojm <tkojm@clamav.net>
 *			      Trog <trog@clamav.net>
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

#include <pthread.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

#include "server.h"
#include "thrmgr.h"
#include "session.h"
#include "defaults.h"
#include "clamuko.h"
#include "others.h"
#include "memory.h"
#include "shared.h"
#include "output.h"

#define BUFFSIZE 1024
#define FALSE (0)
#define TRUE (1)

int progexit = 0;
pthread_mutex_t exit_mutex;
int reload = 0;
time_t reloaded_time = 0;
pthread_mutex_t reload_mutex;
int sighup = 0;

typedef struct client_conn_tag {
    int sd;
    int options;
    const struct cfgstruct *copt;
    struct cl_node *root;
    time_t root_timestamp;
    const struct cl_limits *limits;
    pid_t mainpid;
} client_conn_t;

void scanner_thread(void *arg)
{
	client_conn_t *conn = (client_conn_t *) arg;
	sigset_t sigset;
	int ret, timeout, session=FALSE;
	struct cfgstruct *cpt;


    /* ignore all signals */
    sigfillset(&sigset);
    pthread_sigmask(SIG_SETMASK, &sigset, NULL);

    if((cpt = cfgopt(conn->copt, "ReadTimeout"))) {
	timeout = cpt->numarg;
    } else {
	timeout = CL_DEFAULT_SCANTIMEOUT;
    }

    if(!timeout)
    	timeout = -1;

    do {
    	ret = command(conn->sd, conn->root, conn->limits, conn->options, conn->copt, timeout);
	if (ret < 0) {
		break;
	}

	switch(ret) {
	    case COMMAND_SHUTDOWN:
		pthread_mutex_lock(&exit_mutex);
		progexit = 1;
		kill(conn->mainpid, SIGTERM);
		pthread_mutex_unlock(&exit_mutex);
		break;

	    case COMMAND_RELOAD:
		pthread_mutex_lock(&reload_mutex);
		reload = 1;
		pthread_mutex_unlock(&reload_mutex);
		break;

	    case COMMAND_SESSION:
		session = TRUE;
		break;

	    case COMMAND_END:
		session = FALSE;
		break;
	}
	if (session) {
	    pthread_mutex_lock(&exit_mutex);
	    if(progexit) {
		session = FALSE;
	    }
	    pthread_mutex_unlock(&exit_mutex);
	    pthread_mutex_lock(&reload_mutex);
	    if (conn->root_timestamp != reloaded_time) {
		session = FALSE;
	    }
	    pthread_mutex_unlock(&reload_mutex);
	}
    } while (session);

    close(conn->sd);
    cl_free(conn->root);
    free(conn);
    return;
}

void sighandler_th(int sig)
{
    switch(sig) {
	case SIGINT:
	case SIGTERM:
	    progexit = 1;
	    break;

	case SIGSEGV:
	    logg("Segmentation fault :-( Bye..\n");
	    _exit(11); /* probably not reached at all */
	    break; /* not reached */

	case SIGHUP:
	    sighup = 1;
	    break;

	case SIGUSR2:
	    reload = 1;
	    break;

	default:
	    break; /* Take no action on other signals - e.g. SIGPIPE */
    }
}

static struct cl_node *reload_db(struct cl_node *root, const struct cfgstruct *copt, int do_check)
{
	const char *dbdir;
	int retval;
	unsigned int virnum = 0;
	struct cfgstruct *cpt;
	static struct cl_stat *dbstat=NULL;


    if(do_check) {
	if(dbstat == NULL) {
	    logg("No stats for Database check - forcing reload\n");
	    return root;
	}

	if(cl_statchkdir(dbstat) == 1) {
	    logg("SelfCheck: Database modification detected. Forcing reload.\n");
	    return root;
	} else {
	    logg("SelfCheck: Database status OK.\n");
	    return NULL;
	}
    }

    /* release old structure */
    if(root) {
	cl_free(root);
	root = NULL;
    }

    if((cpt = cfgopt(copt, "DatabaseDirectory")) || (cpt = cfgopt(copt, "DataDirectory"))) {
	dbdir = cpt->strarg;
    } else {
	dbdir = cl_retdbdir();
    }
    logg("Reading databases from %s\n", dbdir);

    if(dbstat == NULL) {
	dbstat = (struct cl_stat *) mmalloc(sizeof(struct cl_stat));
    } else {
	cl_statfree(dbstat);
    }

    memset(dbstat, 0, sizeof(struct cl_stat));
    cl_statinidir(dbdir, dbstat);
    if((retval = cl_loaddbdir(dbdir, &root, &virnum))) {
	logg("!reload db failed: %s\n", cl_strerror(retval));
	exit(-1);
    }

    if(!root) {
	logg("!load db failed: %s\n", cl_strerror(retval));
	exit(-1);
    }

    if((retval = cl_build(root)) != 0) {
	logg("!Database initialization error: can't build engine: %s\n",
	cl_strerror(retval));
	exit(-1);
    }
    logg("Database correctly reloaded (%d viruses)\n", virnum);

    return root;
}

int acceptloop_th(int socketd, struct cl_node *root, const struct cfgstruct *copt)
{
	int new_sd, max_threads, stdopt;
	unsigned int options = 0;
	threadpool_t *thr_pool;
	struct sigaction sigact;
	mode_t old_umask;
	struct cl_limits limits;
	pthread_attr_t thattr;
	sigset_t sigset;
	client_conn_t *client_conn;
	struct cfgstruct *cpt;
#ifdef HAVE_STRERROR_R
	char buff[BUFFSIZE + 1];
#endif
	unsigned int selfchk;
	time_t start_time, current_time;
	pid_t mainpid;
	int idletimeout;

#if defined(C_BIGSTACK) || defined(C_BSD)
        size_t stacksize;
#endif

#ifdef CLAMUKO
	pthread_t clamuko_pid;
	pthread_attr_t clamuko_attr;
	struct thrarg *tharg = NULL; /* shut up gcc */
#endif
	memset(&sigact, 0, sizeof(struct sigaction));

    /* save the PID */
    mainpid = getpid();
    if((cpt = cfgopt(copt, "PidFile"))) {
	    FILE *fd;
	old_umask = umask(0006);
	if((fd = fopen(cpt->strarg, "w")) == NULL) {
	    logg("!Can't save PID in file %s\n", cpt->strarg);
	} else {
	    fprintf(fd, "%d", (int) mainpid);
	    fclose(fd);
	}
	umask(old_umask);
    }

    logg("*Listening daemon: PID: %d\n", getpid());
    if((cpt = cfgopt(copt, "MaxThreads"))) {
	max_threads = cpt->numarg;
    } else {
	max_threads = CL_DEFAULT_MAXTHREADS;
    }

    if(cfgopt(copt, "DisableDefaultScanOptions")) {
	logg("RECOMMENDED OPTIONS DISABLED.\n");
	stdopt = 0;
    } else {
	options |= CL_SCAN_STDOPT;
	stdopt = 1;
    }

    if(stdopt || cfgopt(copt, "ScanArchive") || cfgopt(copt, "ClamukoScanArchive")) {

	/* set up limits */
	memset(&limits, 0, sizeof(struct cl_limits));

	if((cpt = cfgopt(copt, "ArchiveMaxFileSize"))) {
	    if((limits.maxfilesize = cpt->numarg)) {
		logg("Archive: Archived file size limit set to %d bytes.\n", limits.maxfilesize);
	    } else {
		logg("^Archive: File size limit protection disabled.\n");
	    }
	} else {
	    limits.maxfilesize = 10485760;
	    logg("Archive: Archived file size limit set to %d bytes.\n", limits.maxfilesize);
	}

	if((cpt = cfgopt(copt, "ArchiveMaxRecursion"))) {
	    if((limits.maxreclevel = cpt->numarg)) {
		logg("Archive: Recursion level limit set to %d.\n", limits.maxreclevel);
	    } else {
		logg("^Archive: Recursion level limit protection disabled.\n");
	    }
	} else {
	    limits.maxreclevel = 8;
	    logg("Archive: Recursion level limit set to %d.\n", limits.maxreclevel);
	}

	if((cpt = cfgopt(copt, "ArchiveMaxFiles"))) {
	    if((limits.maxfiles = cpt->numarg)) {
		logg("Archive: Files limit set to %d.\n", limits.maxfiles);
	    } else {
		logg("^Archive: Files limit protection disabled.\n");
	    }
	} else {
	    limits.maxfiles = 1000;
	    logg("Archive: Files limit set to %d.\n", limits.maxfiles);
	}

	if((cpt = cfgopt(copt, "ArchiveMaxCompressionRatio"))) {
	    if((limits.maxratio = cpt->numarg)) {
		logg("Archive: Compression ratio limit set to %d.\n", limits.maxratio);
	    } else {
		logg("^Archive: Compression ratio limit disabled.\n");
	    }
	} else {
	    limits.maxratio = 250;
	    logg("Archive: Compression ratio limit set to %d.\n", limits.maxratio);
	}

	if(cfgopt(copt, "ArchiveLimitMemoryUsage")) {
	    limits.archivememlim = 1;
	    logg("Archive: Limited memory usage.\n");
	} else {
	    limits.archivememlim = 0;
	}

    }

    if(stdopt || cfgopt(copt, "ScanArchive")) {
	logg("Archive support enabled.\n");
	options |= CL_SCAN_ARCHIVE;

	if(cfgopt(copt, "ScanRAR")) {
	    logg("Archive: RAR support enabled.\n");
	} else {
	    logg("Archive: RAR support disabled.\n");
	    options |= CL_SCAN_DISABLERAR;
	}

	if(cfgopt(copt, "ArchiveBlockEncrypted")) {
	    logg("Archive: Blocking encrypted archives.\n");
	    options |= CL_SCAN_BLOCKENCRYPTED;
	}

	if(cfgopt(copt, "ArchiveBlockMax")) {
	    logg("Archive: Blocking archives that exceed limits.\n");
	    options |= CL_SCAN_BLOCKMAX;
	}

    } else {
	logg("Archive support disabled.\n");
    }

    if(stdopt || cfgopt(copt, "ScanPE")) {
	logg("Portable Executable support enabled.\n");
	options |= CL_SCAN_PE;

	if(cfgopt(copt, "DetectBrokenExecutables")) {
	    logg("Detection of broken executables enabled.\n");
	    options |= CL_SCAN_BLOCKBROKEN;
	}

    } else {
	logg("Portable Executable support disabled.\n");
    }

    if(stdopt || cfgopt(copt, "ScanMail")) {
	logg("Mail files support enabled.\n");
	options |= CL_SCAN_MAIL;

	if(cfgopt(copt, "MailFollowURLs")) {
	    logg("Mail: URL scanning enabled.\n");
	    options |= CL_SCAN_MAILURL;
	}

    } else {
	logg("Mail files support disabled.\n");
    }

    if(stdopt || cfgopt(copt, "ScanOLE2")) {
	logg("OLE2 support enabled.\n");
	options |= CL_SCAN_OLE2;
    } else {
	logg("OLE2 support disabled.\n");
    }

    if(stdopt || cfgopt(copt, "ScanHTML")) {
	logg("HTML support enabled.\n");
	options |= CL_SCAN_HTML;
    } else {
	logg("HTML support disabled.\n");
    }

    if((cpt = cfgopt(copt, "SelfCheck"))) {
	selfchk = cpt->numarg;
    } else {
	selfchk = CL_DEFAULT_SELFCHECK;
    }

    if(!selfchk) {
	logg("Self checking disabled.\n");
    } else {
	logg("Self checking every %d seconds.\n", selfchk);
    }

    pthread_attr_init(&thattr);
    pthread_attr_setdetachstate(&thattr, PTHREAD_CREATE_DETACHED);

    if(cfgopt(copt, "ClamukoScanOnLine") || cfgopt(copt, "ClamukoScanOnAccess"))
#ifdef CLAMUKO
    {
	pthread_attr_init(&clamuko_attr);
	pthread_attr_setdetachstate(&clamuko_attr, PTHREAD_CREATE_JOINABLE);

	tharg = (struct thrarg *) mmalloc(sizeof(struct thrarg));
	tharg->copt = copt;
	tharg->root = root;
	tharg->limits = &limits;
	tharg->options = options;

	pthread_create(&clamuko_pid, &clamuko_attr, clamukoth, tharg);
    }
#else
	logg("Clamuko is not available.\n");
#endif

    /* set up signal handling */
    sigfillset(&sigset);
    sigdelset(&sigset, SIGINT);
    sigdelset(&sigset, SIGTERM);
    sigdelset(&sigset, SIGSEGV);
    sigdelset(&sigset, SIGHUP);
    sigdelset(&sigset, SIGPIPE);
    sigdelset(&sigset, SIGUSR2);
    sigprocmask(SIG_SETMASK, &sigset, NULL);
 
    /* SIGINT, SIGTERM, SIGSEGV */
    sigact.sa_handler = sighandler_th;
    sigemptyset(&sigact.sa_mask);
    sigaddset(&sigact.sa_mask, SIGINT);
    sigaddset(&sigact.sa_mask, SIGTERM);
    sigaddset(&sigact.sa_mask, SIGHUP);
    sigaddset(&sigact.sa_mask, SIGPIPE);
    sigaddset(&sigact.sa_mask, SIGUSR2);
    sigaction(SIGINT, &sigact, NULL);
    sigaction(SIGTERM, &sigact, NULL);
    sigaction(SIGHUP, &sigact, NULL);
    sigaction(SIGPIPE, &sigact, NULL);
    sigaction(SIGUSR2, &sigact, NULL);

    if(!debug_mode) {
	sigaddset(&sigact.sa_mask, SIGHUP);
	sigaction(SIGSEGV, &sigact, NULL);
    }

#if defined(C_BIGSTACK) || defined(C_BSD)
    /*
     * njh@bandsman.co.uk:
     * libclamav/scanners.c uses a *huge* buffer
     * (128K not BUFSIZ from stdio.h).
     * We need to allow for that.
     */
    pthread_attr_getstacksize(&thattr, &stacksize);
    cli_dbgmsg("set stacksize to %u\n", stacksize + SCANBUFF + 64 * 1024);
    pthread_attr_setstacksize(&thattr, stacksize + SCANBUFF + 64 * 1024);
#endif

    pthread_mutex_init(&exit_mutex, NULL);
    pthread_mutex_init(&reload_mutex, NULL);


    if((cpt = cfgopt(copt, "IdleTimeout")))
	idletimeout = cpt->numarg;
    else
	idletimeout = CL_DEFAULT_IDLETIMEOUT;

    if((thr_pool=thrmgr_new(max_threads, idletimeout, scanner_thread)) == NULL) {
	logg("!thrmgr_new failed\n");
	exit(-1);
    }

    time(&start_time);

    for(;;) {				
	new_sd = accept(socketd, NULL, NULL);
	if((new_sd == -1) && (errno != EINTR)) {
	    /* very bad - need to exit or restart */
#ifdef HAVE_STRERROR_R
	    logg("!accept() failed: %s\n", strerror_r(errno, buff, BUFFSIZE));
#else
	    logg("!accept() failed\n");
#endif
	    continue;
	}

	if (sighup) {
		logg("SIGHUP caught: re-opening log file.\n");
		logg_close();
		sighup = 0;
		if(!logg_file && (cpt = cfgopt(copt, "LogFile")))
		    logg_file = cpt->strarg;
	}

	if (!progexit && new_sd >= 0) {
		client_conn = (client_conn_t *) mmalloc(sizeof(struct client_conn_tag));
		client_conn->sd = new_sd;
		client_conn->options = options;
		client_conn->copt = copt;
		client_conn->root = cl_dup(root);
		client_conn->root_timestamp = reloaded_time;
		client_conn->limits = &limits;
		client_conn->mainpid = mainpid;
		if (!thrmgr_dispatch(thr_pool, client_conn)) {
		    close(client_conn->sd);
		    free(client_conn);
		    logg("!thread dispatch failed\n");
		}
	}

	pthread_mutex_lock(&exit_mutex);
	if(progexit) {
	    if (new_sd >= 0) {
		close(new_sd);
	    }
	    pthread_mutex_unlock(&exit_mutex);
	    break;
	}
	pthread_mutex_unlock(&exit_mutex);

	if(selfchk) {
	    time(&current_time);
	    if((current_time - start_time) > (time_t)selfchk) {
		if(reload_db(root, copt, TRUE)) {
		    pthread_mutex_lock(&reload_mutex);
		    reload = 1;
		    pthread_mutex_unlock(&reload_mutex);
		}
		time(&start_time);
	    }
	}

	pthread_mutex_lock(&reload_mutex);
	if(reload) {
	    pthread_mutex_unlock(&reload_mutex);
	    root = reload_db(root, copt, FALSE);
	    pthread_mutex_lock(&reload_mutex);
	    reload = 0;
	    time(&reloaded_time);
	    pthread_mutex_unlock(&reload_mutex);
#ifdef CLAMUKO
	    if(cfgopt(copt, "ClamukoScanOnLine") || cfgopt(copt, "ClamukoScanOnAccess")) {
		logg("Stopping and restarting Clamuko.\n");
		pthread_kill(clamuko_pid, SIGUSR1);
		pthread_join(clamuko_pid, NULL);
		tharg->root = root;
		pthread_create(&clamuko_pid, &clamuko_attr, clamukoth, tharg);
	    }
#endif
	} else {
	    pthread_mutex_unlock(&reload_mutex);
	}
    }

    /* Destroy the thread manager.
     * This waits for all current tasks to end
     */
    thrmgr_destroy(thr_pool);
#ifdef CLAMUKO
    if(cfgopt(copt, "ClamukoScanOnLine") || cfgopt(copt, "ClamukoScanOnAccess")) {
	logg("Stopping Clamuko.\n");
	pthread_kill(clamuko_pid, SIGUSR1);
	pthread_join(clamuko_pid, NULL);
    }
#endif
    cl_free(root);
    logg("*Shutting down the main socket.\n");
    shutdown(socketd, 2);
    logg("*Closing the main socket.\n");
    close(socketd);

#ifndef C_OS2
    if((cpt = cfgopt(copt, "LocalSocket"))) {
	if(unlink(cpt->strarg) == -1)
	    logg("!Can't unlink the socket file %s\n", cpt->strarg);
	else
	     logg("Socket file removed.\n");
    }
#endif

    if((cpt = cfgopt(copt, "PidFile"))) {
	if(unlink(cpt->strarg) == -1)
	    logg("!Can't unlink the pid file %s\n", cpt->strarg);
	else
	    logg("Pid file removed.\n");
    }

    logg("Exiting (clean)\n");
    time(&current_time);
    logg("--- Stopped at %s", ctime(&current_time));

    return 0;
}

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

#include <pthread.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>

#include "server.h"
#include "thrmgr.h"
#include "session.h"
#include "defaults.h"
#include "clamuko.h"
#include "others.h"

#define BUFFSIZE 1024
#define FALSE (0)
#define TRUE (1)

int progexit = 0;
pthread_mutex_t exit_mutex;
int reload = 0;
pthread_mutex_t reload_mutex;

typedef struct client_conn_tag {
    int sd;
    int options;
    const struct cfgstruct *copt;
    const struct cl_node *root;
    const struct cl_limits *limits;
} client_conn_t;

void scanner_thread(void *arg)
{
	client_conn_t *conn = (client_conn_t *) arg;
	sigset_t sigset;
	int ret;


    /* ignore all signals */
    sigfillset(&sigset);
    pthread_sigmask(SIG_SETMASK, &sigset, NULL);

    ret = command(conn->sd, conn->root, conn->limits, conn->options, conn->copt);

    switch(ret) {
	case COMMAND_QUIT:
	    pthread_mutex_lock(&exit_mutex);
	    progexit = 1;
	    pthread_mutex_unlock(&exit_mutex);
	    break;

	case COMMAND_RELOAD:
	    pthread_mutex_lock(&reload_mutex);
	    reload = 1;
	    pthread_mutex_unlock(&reload_mutex);
	    break;
	}

    close(conn->sd);
    free(conn);
    return;
}

void sighandler_th(int sig)
{
	time_t currtime;
	int maxwait = CL_DEFAULT_MAXWHILEWAIT * 5;
	int i;

    switch(sig) {
	case SIGINT:
	case SIGTERM:
	    progexit = 1;
	    logg("*Signal %d caught -> exiting.\n", sig);
	    time(&currtime);
	    logg("--- Stopped at %s", ctime(&currtime));
	    exit(0);
	    break; /* not reached */

	    case SIGSEGV:
		logg("Segmentation fault :-( Bye..\n");
		exit(11); /* probably not reached at all */
		break; /* not reached */

	    case SIGHUP:
		/* sighup = 1;
		logg("SIGHUP catched: log file re-opened.\n"); */
		break;
    }
}

static struct cl_node *reload_db(struct cl_node *root, const struct cfgstruct *copt, int do_check)
{
	char *dbdir;
	int virnum=0, retval;
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
	cl_freetrie(root);
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

    if((retval = cl_buildtrie(root)) != 0) {
	logg("!Database initialization error: can't build the trie: %s\n",
	cl_strerror(retval));
	exit(-1);
    }
    logg("Database correctly reloaded (%d viruses)\n", virnum);

    return root;
}

int acceptloop_th(int socketd, struct cl_node *root, const struct cfgstruct *copt)
{
	int new_sd, max_threads, options=0;
	thrmgr_t thrmgr;
	struct sigaction sigact;
	mode_t old_umask;
	struct cl_limits limits;
	pthread_attr_t thattr;
	sigset_t sigset;
	client_conn_t *client_conn;
	struct cfgstruct *cpt;
	char *buff[BUFFSIZE+1];
	unsigned int selfchk;
	time_t start_time, current_time;
	
#if defined(C_BIGSTACK) || defined(C_BSD)
        size_t stacksize;
#endif

#ifdef CLAMUKO
	pthread_t clamuko_pid;
	pthread_attr_t clamuko_attr;
	struct thrarg *tharg;
#endif
	memset(&sigact, 0, sizeof(struct sigaction));

    /* save the PID */
    if((cpt = cfgopt(copt, "PidFile"))) {
	    FILE *fd;
	old_umask = umask(0006);
	if((fd = fopen(cpt->strarg, "w")) == NULL) {
	    logg("!Can't save PID in file %s\n", cpt->strarg);
	} else {
	    fprintf(fd, "%d", getpid());
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

    if(cfgopt(copt, "ScanArchive") || cfgopt(copt, "ClamukoScanArchive")) {

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
	    logg("^USING HARDCODED LIMIT: Archive: Archived file size limit set to %d bytes.\n", limits.maxfilesize);
	}

	if((cpt = cfgopt(copt, "ArchiveMaxRecursion"))) {
	    if((limits.maxreclevel = cpt->numarg)) {
		logg("Archive: Recursion level limit set to %d.\n", limits.maxreclevel);
	    } else {
		logg("^Archive: Recursion level limit protection disabled.\n");
	    }
	} else {
	    limits.maxreclevel = 5;
	    logg("^USING HARDCODED LIMIT: Archive: Recursion level set to %d.\n", limits.maxreclevel);
	}

	if((cpt = cfgopt(copt, "ArchiveMaxFiles"))) {
	    if((limits.maxfiles = cpt->numarg)) {
		logg("Archive: Files limit set to %d.\n", limits.maxfiles);
	    } else {
		logg("^Archive: Files limit protection disabled.\n");
	    }
	} else {
	    limits.maxfiles = 1000;
	    logg("^USING HARDCODED LIMIT: Archive: Files limit set to %d.\n", limits.maxfiles);
	}

	if((cpt = cfgopt(copt, "ArchiveMaxCompressionRatio"))) {
	    if((limits.maxratio = cpt->numarg)) {
		logg("Archive: Compression ratio limit set to %d.\n", limits.maxratio);
	    } else {
		logg("^Archive: Compression ratio limit disabled.\n");
	    }
	} else {
	    limits.maxratio = 200;
	    logg("^USING HARDCODED LIMIT: Archive: Compression ratio limit set to %d.\n", limits.maxratio);
	}

	if(cfgopt(copt, "ArchiveLimitMemoryUsage")) {
	    limits.archivememlim = 1;
	    logg("Archive: Limited memory usage.\n");
	} else {
	    limits.archivememlim = 0;
	}
    }

    if(cfgopt(copt, "ScanArchive")) {
	logg("Archive support enabled.\n");
	options |= CL_ARCHIVE;

	if(cfgopt(copt, "ScanRAR")) {
	    logg("RAR support enabled.\n");
	} else {
	    logg("RAR support disabled.\n");
	    options |= CL_DISABLERAR;
	}
    } else {
	logg("Archive support disabled.\n");
    }

    if(cfgopt(copt, "ScanMail")) {
	logg("Mail files support enabled.\n");
	options |= CL_MAIL;
    } else {
	logg("Mail files support disabled.\n");
    }

    if(cfgopt(copt, "ScanOLE2")) {
	logg("OLE2 support enabled.\n");
	options |= CL_OLE2;
    } else {
	logg("OLE2 support disabled.\n");
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

#ifdef CLAMUKO
    pthread_attr_init(&clamuko_attr);
    pthread_attr_setdetachstate(&clamuko_attr, PTHREAD_CREATE_JOINABLE);

    tharg = (struct thrarg *) mmalloc(sizeof(struct thrarg));
    tharg->copt = copt;
    tharg->root = root;
    tharg->limits = &limits;
    tharg->options = options;

    pthread_create(&clamuko_pid, &clamuko_attr, clamukoth, tharg);
#else
    logg("!Clamuko is not available.\n");
#endif

    /* set up signal handling */
    sigfillset(&sigset);
    sigdelset(&sigset, SIGINT);
    sigdelset(&sigset, SIGTERM);
    sigdelset(&sigset, SIGSEGV);
    sigdelset(&sigset, SIGHUP);
    sigprocmask(SIG_SETMASK, &sigset, NULL);
 
    /* SIGINT, SIGTERM, SIGSEGV */
    sigact.sa_handler = sighandler_th;
    sigemptyset(&sigact.sa_mask);
    sigaddset(&sigact.sa_mask, SIGINT);
    sigaddset(&sigact.sa_mask, SIGTERM);
    sigaddset(&sigact.sa_mask, SIGHUP);
    sigaction(SIGINT, &sigact, NULL);
    sigaction(SIGTERM, &sigact, NULL);

    if(!debug_mode)
	sigaction(SIGSEGV, &sigact, NULL);

    sigaction(SIGHUP, &sigact, NULL);

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

    if(thrmgr_init(&thrmgr, max_threads, 1, scanner_thread) != 0) {
	logg("thrmgr_init failed");
	exit(-1);
    }

    time(&start_time);

    for(;;) {				
	new_sd = accept(socketd, NULL, NULL);
	if((new_sd == -1) && (errno != EINTR)) {
	    logg("!accept() failed: %s", strerror_r(errno, buff, BUFFSIZE));
	    /* very bad - need to exit or restart */
	    continue;
	}

	client_conn = (client_conn_t *) mmalloc(sizeof(struct client_conn_tag));
	client_conn->sd = new_sd;
	client_conn->options = options;
	client_conn->copt = copt;
	client_conn->root = root;
	client_conn->limits = &limits;
	thrmgr_add(&thrmgr, client_conn);

	pthread_mutex_lock(&exit_mutex);
	if(progexit) {
	    pthread_mutex_unlock(&exit_mutex);
	    break;
	}
	pthread_mutex_unlock(&exit_mutex);

	if(selfchk) {
	    time(&current_time);
	    if((current_time - start_time) > selfchk) {
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
	    reload = 0;
	    pthread_mutex_unlock(&reload_mutex);
	    /* Destroy the thread manager.
	     * This waits for all current tasks to end
	     */
	    thrmgr_destroy(&thrmgr);
	    root = reload_db(root, copt, FALSE);
	    if(thrmgr_init(&thrmgr, max_threads, 1, scanner_thread) != 0) {
		logg("!thrmgr_init failed");
		pthread_mutex_unlock(&reload_mutex);
		exit(-1);
	    }
#ifdef CLAMUKO
	    logg("Stopping and restarting Clamuko.\n");
	    pthread_kill(clamuko_pid, SIGUSR1);
	    pthread_join(clamuko_pid, NULL);
	    tharg->root = root;
	    pthread_create(&clamuko_pid, &clamuko_attr, clamukoth, tharg);
#endif
	} else {
	    pthread_mutex_unlock(&reload_mutex);
	}
    }

#ifdef CLAMUKO
    logg("Stopping Clamuko.\n");
    pthread_kill(clamuko_pid, SIGUSR1);
    pthread_join(clamuko_pid, NULL);
#endif
    logg("Exiting (clean)\n");
    return 0;
}

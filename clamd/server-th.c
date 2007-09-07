/*
 *  Copyright (C) 2002 - 2005 Tomasz Kojm <tkojm@clamav.net>
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
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA 02110-1301, USA.
 */

#ifdef	_MSC_VER
#include <winsock.h>
#endif

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
#ifndef	C_WINDOWS
#include <sys/socket.h>
#endif
#ifdef	HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "libclamav/clamav.h"

#include "shared/output.h"

#include "server.h"
#include "thrmgr.h"
#include "session.h"
#include "clamuko.h"
#include "others.h"
#include "shared.h"

#ifndef	C_WINDOWS
#define	closesocket(s)	close(s)
#endif

#define BUFFSIZE 1024
#ifndef	FALSE
#define FALSE (0)
#endif
#ifndef	TRUE
#define TRUE (1)
#endif

int progexit = 0;
pthread_mutex_t exit_mutex;
int reload = 0;
time_t reloaded_time = 0;
pthread_mutex_t reload_mutex;
int sighup = 0;
static struct cl_stat *dbstat = NULL;

typedef struct client_conn_tag {
    int sd;
    unsigned int options;
    const struct cfgstruct *copt;
    struct cl_engine *engine;
    time_t engine_timestamp;
    const struct cl_limits *limits;
    int *socketds;
    int nsockets;
} client_conn_t;

static void scanner_thread(void *arg)
{
	client_conn_t *conn = (client_conn_t *) arg;
#ifndef	C_WINDOWS
	sigset_t sigset;
#endif
	int ret, timeout, i, session=FALSE;


#ifndef	C_WINDOWS
    /* ignore all signals */
    sigfillset(&sigset);
    pthread_sigmask(SIG_SETMASK, &sigset, NULL);
#endif

    timeout = cfgopt(conn->copt, "ReadTimeout")->numarg;
    if(!timeout)
    	timeout = -1;

    do {
    	ret = command(conn->sd, conn->engine, conn->limits, conn->options, conn->copt, timeout);
	if (ret < 0) {
		break;
	}

	switch(ret) {
	    case COMMAND_SHUTDOWN:
		pthread_mutex_lock(&exit_mutex);
		progexit = 1;
		for(i = 0; i < conn->nsockets; i++) {
		    shutdown(conn->socketds[i], 2);
		    closesocket(conn->socketds[i]);
		}
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
	    if (conn->engine_timestamp != reloaded_time) {
		session = FALSE;
	    }
	    pthread_mutex_unlock(&reload_mutex);
	}
    } while (session);

    closesocket(conn->sd);
    cl_free(conn->engine);
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

#ifdef	SIGHUP
	case SIGHUP:
	    sighup = 1;
	    break;
#endif

#ifdef	SIGUSR2
	case SIGUSR2:
	    reload = 1;
	    break;
#endif

	default:
	    break; /* Take no action on other signals - e.g. SIGPIPE */
    }
}

static struct cl_engine *reload_db(struct cl_engine *engine, unsigned int dboptions, const struct cfgstruct *copt, int do_check, int *ret)
{
	const char *dbdir;
	int retval;
	unsigned int sigs = 0, try = 1;

    *ret = 0;
    if(do_check) {
	if(dbstat == NULL) {
	    logg("No stats for Database check - forcing reload\n");
	    return engine;
	}

	if(cl_statchkdir(dbstat) == 1) {
	    logg("SelfCheck: Database modification detected. Forcing reload.\n");
	    return engine;
	} else {
	    logg("SelfCheck: Database status OK.\n");
	    return NULL;
	}
    }

    /* release old structure */
    if(engine) {
	cl_free(engine);
	engine = NULL;
    }

    dbdir = cfgopt(copt, "DatabaseDirectory")->strarg;
    logg("Reading databases from %s\n", dbdir);

    if(dbstat == NULL) {
	dbstat = (struct cl_stat *) malloc(sizeof(struct cl_stat));
	if(!dbstat) {
	    logg("!Can't allocate memory for dbstat\n");
	    *ret = 1;
	    return NULL;
	}
    } else {
	cl_statfree(dbstat);
    }

    memset(dbstat, 0, sizeof(struct cl_stat));
    if((retval = cl_statinidir(dbdir, dbstat))) {
	logg("!cl_statinidir() failed: %s\n", cl_strerror(retval));
	*ret = 1;
	return NULL;
    }

    while((retval = cl_load(dbdir, &engine, &sigs, dboptions)) == CL_ELOCKDB) {
	logg("!reload db failed: %s (try %u)\n", cl_strerror(retval), try);
	if(++try > 3)
	    break;
    }

    if(retval) {
	logg("!reload db failed: %s\n", cl_strerror(retval));
	*ret = 1;
	return NULL;
    }

    if(!engine) {
	logg("!reload db failed: %s\n", cl_strerror(retval));
	*ret = 1;
	return NULL;
    }

    if((retval = cl_build(engine)) != 0) {
	logg("!Database initialization error: can't build engine: %s\n", cl_strerror(retval));
	*ret = 1;
	return NULL;
    }
    logg("Database correctly reloaded (%u signatures)\n", sigs);

    return engine;
}

int acceptloop_th(int *socketds, int nsockets, struct cl_engine *engine, unsigned int dboptions, const struct cfgstruct *copt)
{
	int max_threads, i, ret = 0;
	unsigned int options = 0;
	threadpool_t *thr_pool;
#ifndef	C_WINDOWS
	struct sigaction sigact;
#endif
	mode_t old_umask;
	struct cl_limits limits;
#ifndef	C_WINDOWS
	sigset_t sigset;
#endif
	client_conn_t *client_conn;
	const struct cfgstruct *cpt;
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

#ifndef	C_WINDOWS
	memset(&sigact, 0, sizeof(struct sigaction));
#endif

    /* save the PID */
    mainpid = getpid();
    if((cpt = cfgopt(copt, "PidFile"))->enabled) {
	    FILE *fd;
	old_umask = umask(0006);
	if((fd = fopen(cpt->strarg, "w")) == NULL) {
	    logg("!Can't save PID in file %s\n", cpt->strarg);
	} else {
	    fprintf(fd, "%u", (unsigned int) mainpid);
	    fclose(fd);
	}
	umask(old_umask);
    }

    logg("*Listening daemon: PID: %u\n", (unsigned int) mainpid);
    max_threads = cfgopt(copt, "MaxThreads")->numarg;

    if(cfgopt(copt, "ScanArchive")->enabled) {

	/* set up limits */
	memset(&limits, 0, sizeof(struct cl_limits));

	if((limits.maxfilesize = cfgopt(copt, "ArchiveMaxFileSize")->numarg)) {
	    logg("Archive: Archived file size limit set to %lu bytes.\n", limits.maxfilesize);
	} else {
	    logg("^Archive: File size limit protection disabled.\n");
	}

	if((limits.maxreclevel = cfgopt(copt, "ArchiveMaxRecursion")->numarg)) {
	    logg("Archive: Recursion level limit set to %u.\n", limits.maxreclevel);
	} else {
	    logg("^Archive: Recursion level limit protection disabled.\n");
	}

	if((limits.maxfiles = cfgopt(copt, "ArchiveMaxFiles")->numarg)) {
	    logg("Archive: Files limit set to %u.\n", limits.maxfiles);
	} else {
	    logg("^Archive: Files limit protection disabled.\n");
	}

	if((limits.maxratio = cfgopt(copt, "ArchiveMaxCompressionRatio")->numarg)) {
	    logg("Archive: Compression ratio limit set to %u.\n", limits.maxratio);
	} else {
	    logg("^Archive: Compression ratio limit disabled.\n");
	}

	if(cfgopt(copt, "ArchiveLimitMemoryUsage")->enabled) {
	    limits.archivememlim = 1;
	    logg("Archive: Limited memory usage.\n");
	} else {
	    limits.archivememlim = 0;
	}
    }

    if(cfgopt(copt, "ScanArchive")->enabled) {
	logg("Archive support enabled.\n");
	options |= CL_SCAN_ARCHIVE;

	if(cfgopt(copt, "ArchiveBlockEncrypted")->enabled) {
	    logg("Archive: Blocking encrypted archives.\n");
	    options |= CL_SCAN_BLOCKENCRYPTED;
	}

	if(cfgopt(copt, "ArchiveBlockMax")->enabled) {
	    logg("Archive: Blocking archives that exceed limits.\n");
	    options |= CL_SCAN_BLOCKMAX;
	}

    } else {
	logg("Archive support disabled.\n");
    }

    if(cfgopt(copt, "AlgorithmicDetection")->enabled) {
	logg("Algorithmic detection enabled.\n");
	options |= CL_SCAN_ALGORITHMIC;
    } else {
	logg("Algorithmic detection disabled.\n");
    }

    if(cfgopt(copt, "ScanPE")->enabled) {
	logg("Portable Executable support enabled.\n");
	options |= CL_SCAN_PE;
    } else {
	logg("Portable Executable support disabled.\n");
    }

    if(cfgopt(copt, "ScanELF")->enabled) {
	logg("ELF support enabled.\n");
	options |= CL_SCAN_ELF;
    } else {
	logg("ELF support disabled.\n");
    }

    if(cfgopt(copt, "ScanPE")->enabled || cfgopt(copt, "ScanELF")->enabled) {
	if(cfgopt(copt, "DetectBrokenExecutables")->enabled) {
	    logg("Detection of broken executables enabled.\n");
	    options |= CL_SCAN_BLOCKBROKEN;
	}
    }

    if(cfgopt(copt, "ScanMail")->enabled) {
	logg("Mail files support enabled.\n");
	options |= CL_SCAN_MAIL;

	if(cfgopt(copt, "MailFollowURLs")->enabled) {
	    logg("Mail: URL scanning enabled.\n");
	    options |= CL_SCAN_MAILURL;
	}

	if((limits.maxmailrec = cfgopt(copt, "MailMaxRecursion")->numarg)) {
	    logg("Mail: Recursion level limit set to %u.\n", limits.maxmailrec);
	} else {
	    logg("^Mail: Recursion level limit protection disabled.\n");
	}

    } else {
	logg("Mail files support disabled.\n");
    }

    if(cfgopt(copt, "ScanOLE2")->enabled) {
	logg("OLE2 support enabled.\n");
	options |= CL_SCAN_OLE2;
    } else {
	logg("OLE2 support disabled.\n");
    }

    if(cfgopt(copt, "ScanPDF")->enabled) {
	logg("PDF support enabled.\n");
	options |= CL_SCAN_PDF;
    } else {
	logg("PDF support disabled.\n");
    }

    if(cfgopt(copt, "ScanHTML")->enabled) {
	logg("HTML support enabled.\n");
	options |= CL_SCAN_HTML;
    } else {
	logg("HTML support disabled.\n");
    }

    if(cfgopt(copt,"PhishingScanURLs")->enabled) {

	if(cfgopt(copt,"PhishingRestrictedScan")->enabled) {
	    /* we don't scan urls from all domains, just those listed in
	     * .pdb file. This is the safe default
	     */
	    options |= CL_SCAN_PHISHING_DOMAINLIST;
	} else {
	    /* This is a false positive prone option, since newsletters, etc.
	     * often contain links that will be classified as phishing attempts,
	     * even though the site they link to isn't a phish site.
	     */
	    logg("Phishing: Checking all URLs, regardless of domain (FP prone).\n");
	}

	if(cfgopt(copt,"PhishingAlwaysBlockCloak")->enabled) {
	    options |= CL_SCAN_PHISHING_BLOCKCLOAK; 
	    logg("Phishing: Always checking for cloaked urls\n");
	}

	if(cfgopt(copt,"PhishingAlwaysBlockSSLMismatch")->enabled) {
	    options |= CL_SCAN_PHISHING_BLOCKSSL;
	    logg("Phishing: Always checking for ssl mismatches\n");
	}
    }

    selfchk = cfgopt(copt, "SelfCheck")->numarg;
    if(!selfchk) {
	logg("Self checking disabled.\n");
    } else {
	logg("Self checking every %u seconds.\n", selfchk);
    }

    if(cfgopt(copt, "ClamukoScanOnAccess")->enabled)
#ifdef CLAMUKO
    {
	pthread_attr_init(&clamuko_attr);
	pthread_attr_setdetachstate(&clamuko_attr, PTHREAD_CREATE_JOINABLE);

	tharg = (struct thrarg *) malloc(sizeof(struct thrarg));
	tharg->copt = copt;
	tharg->engine = engine;
	tharg->limits = &limits;
	tharg->options = options;

	pthread_create(&clamuko_pid, &clamuko_attr, clamukoth, tharg);
    }
#else
	logg("Clamuko is not available.\n");
#endif

#ifndef	C_WINDOWS
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
#endif

    pthread_mutex_init(&exit_mutex, NULL);
    pthread_mutex_init(&reload_mutex, NULL);

    idletimeout = cfgopt(copt, "IdleTimeout")->numarg;

    if((thr_pool=thrmgr_new(max_threads, idletimeout, scanner_thread)) == NULL) {
	logg("!thrmgr_new failed\n");
	exit(-1);
    }

    time(&start_time);

    for(;;) {				
#if !defined(C_WINDOWS) && !defined(C_BEOS)
	    struct stat st_buf;
#endif
    	int socketd = socketds[0];
	int new_sd = 0;

    	if(nsockets > 1) {
	    int pollret = poll_fds(socketds, nsockets, -1, 1);
    	    if(pollret > 0) {
    		socketd = socketds[pollret - 1];
    	    } else {
		new_sd = -1;
    	    }
    	}
#if !defined(C_WINDOWS) && !defined(C_BEOS)
	if(new_sd != -1 && fstat(socketd, &st_buf) == -1) {
	    logg("!fstat(): socket descriptor gone\n");
	    memmove(socketds, socketds + 1, sizeof(socketds[0]) * nsockets);
	    nsockets--;
	    if(!nsockets) {
		logg("!Main socket gone: fatal\n");
		break;
	    }
	}
#endif
	if (new_sd != -1)
	    new_sd = accept(socketd, NULL, NULL);
	if((new_sd == -1) && (errno != EINTR)) {
	    if(progexit) {
	    	break;
	    }
	    /* very bad - need to exit or restart */
#ifdef HAVE_STRERROR_R
	    strerror_r(errno, buff, BUFFSIZE);
	    logg("!accept() failed: %s\n", buff);
#else
	    logg("!accept() failed\n");
#endif
	    continue;
	}

	if (sighup) {
		logg("SIGHUP caught: re-opening log file.\n");
		logg_close();
		sighup = 0;
		if(!logg_file && (cpt = cfgopt(copt, "LogFile"))->enabled)
		    logg_file = cpt->strarg;
	}

	if (!progexit && new_sd >= 0) {
		client_conn = (client_conn_t *) malloc(sizeof(struct client_conn_tag));
		client_conn->sd = new_sd;
		client_conn->options = options;
		client_conn->copt = copt;
		client_conn->engine = cl_dup(engine);
		client_conn->engine_timestamp = reloaded_time;
		client_conn->limits = &limits;
		client_conn->socketds = socketds;
		client_conn->nsockets = nsockets;
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
		if(reload_db(engine, dboptions, copt, TRUE, &ret)) {
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
	    engine = reload_db(engine, dboptions, copt, FALSE, &ret);
	    if(ret) {
		logg("Terminating because of a fatal error.\n");
		if(new_sd >= 0)
		    close(new_sd);
		break;
	    }
	    pthread_mutex_lock(&reload_mutex);
	    reload = 0;
	    time(&reloaded_time);
	    pthread_mutex_unlock(&reload_mutex);
#ifdef CLAMUKO
	    if(cfgopt(copt, "ClamukoScanOnAccess")->enabled) {
		logg("Stopping and restarting Clamuko.\n");
		pthread_kill(clamuko_pid, SIGUSR1);
		pthread_join(clamuko_pid, NULL);
		tharg->engine = engine;
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
    if(cfgopt(copt, "ClamukoScanOnAccess")->enabled) {
	logg("Stopping Clamuko.\n");
	pthread_kill(clamuko_pid, SIGUSR1);
	pthread_join(clamuko_pid, NULL);
    }
#endif
    if(engine)
	cl_free(engine);

    if(dbstat)
	cl_statfree(dbstat);
    logg("*Shutting down the main socket%s.\n", (nsockets > 1) ? "s" : "");
    for (i = 0; i < nsockets; i++)
	shutdown(socketds[i], 2);
    logg("*Closing the main socket%s.\n", (nsockets > 1) ? "s" : "");
    for (i = 0; i < nsockets; i++)
	closesocket(socketds[i]);
#ifndef C_OS2
    if((cpt = cfgopt(copt, "LocalSocket"))->enabled) {
	if(unlink(cpt->strarg) == -1)
	    logg("!Can't unlink the socket file %s\n", cpt->strarg);
	else
	     logg("Socket file removed.\n");
    }
#endif

    if((cpt = cfgopt(copt, "PidFile"))->enabled) {
	if(unlink(cpt->strarg) == -1)
	    logg("!Can't unlink the pid file %s\n", cpt->strarg);
	else
	    logg("Pid file removed.\n");
    }

    time(&current_time);
    logg("--- Stopped at %s", ctime(&current_time));

    return ret;
}

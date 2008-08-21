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
#include <sys/time.h>
#include <sys/resource.h>
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
#include "libclamav/others.h"
#include "libclamav/readdb.h"

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
pthread_mutex_t exit_mutex = PTHREAD_MUTEX_INITIALIZER;
int reload = 0;
time_t reloaded_time = 0;
pthread_mutex_t reload_mutex = PTHREAD_MUTEX_INITIALIZER;
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
    /* The behavior of a process is undefined after it ignores a 
     * SIGFPE, SIGILL, SIGSEGV, or SIGBUS signal */
    sigdelset(&sigset, SIGFPE);
    sigdelset(&sigset, SIGILL);
    sigdelset(&sigset, SIGSEGV);
#ifdef SIGBUS
    sigdelset(&sigset, SIGBUS);
#endif
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

    shutdown(conn->sd, 2);
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
	unsigned int sigs = 0;
	char *pua_cats = NULL;

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

    /* release old structure */
    if(engine) {
	if(engine->pua_cats)
	    if(!(pua_cats = strdup(engine->pua_cats)))
		logg("^Can't make a copy of pua_cats\n");

	cl_free(engine);
	engine = NULL;
    }

    if(pua_cats) {
	if((retval = cli_initengine(&engine, dboptions))) {
	    logg("!cli_initengine() failed: %s\n", cl_strerror(retval));
	    *ret = 1;
	    free(pua_cats);
	    return NULL;
	}
	engine->pua_cats = pua_cats;
    }

    if((retval = cl_load(dbdir, &engine, &sigs, dboptions))) {
	logg("!reload db failed: %s\n", cl_strerror(retval));
	*ret = 1;
	return NULL;
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
	char timestr[32];
#ifndef	C_WINDOWS
	struct sigaction sigact;
	sigset_t sigset;
	struct rlimit rlim;
#endif
	mode_t old_umask;
	struct cl_limits limits;
	client_conn_t *client_conn;
	const struct cfgstruct *cpt;
#ifdef HAVE_STRERROR_R
	char buff[BUFFSIZE + 1];
#endif
	unsigned int selfchk;
	time_t start_time, current_time;
	pid_t mainpid;
	int idletimeout;

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
	    if (fprintf(fd, "%u", (unsigned int) mainpid)<0) {
	    	logg("!Can't save PID in file %s\n", cpt->strarg);
	    }
	    fclose(fd);
	}
	umask(old_umask);
    }

    logg("*Listening daemon: PID: %u\n", (unsigned int) mainpid);
    max_threads = cfgopt(copt, "MaxThreads")->numarg;


    memset(&limits, 0, sizeof(struct cl_limits));

    if((limits.maxscansize = cfgopt(copt, "MaxScanSize")->numarg)) {
    	logg("Limits: Global size limit set to %lu bytes.\n", limits.maxscansize);
    } else {
    	logg("^Limits: Global size limit protection disabled.\n");
    }

    if((limits.maxfilesize = cfgopt(copt, "MaxFileSize")->numarg)) {
    	logg("Limits: File size limit set to %lu bytes.\n", limits.maxfilesize);
    } else {
	logg("^Limits: File size limit protection disabled.\n");
    }

#ifndef C_WINDOWS
    if(getrlimit(RLIMIT_FSIZE, &rlim) == 0) {
	if((rlim.rlim_max < limits.maxfilesize) || (rlim.rlim_max < limits.maxscansize))
	    logg("^System limit for file size is lower than maxfilesize or maxscansize\n");
    } else {
	logg("^Cannot obtain resource limits for file size\n");
    }
#endif

    if((limits.maxreclevel = cfgopt(copt, "MaxRecursion")->numarg)) {
        logg("Limits: Recursion level limit set to %u.\n", limits.maxreclevel);
    } else {
        logg("^Limits: Recursion level limit protection disabled.\n");
    }

    if((limits.maxfiles = cfgopt(copt, "MaxFiles")->numarg)) {
        logg("Limits: Files limit set to %u.\n", limits.maxfiles);
    } else {
        logg("^Limits: Files limit protection disabled.\n");
    }

    if(cfgopt(copt, "ScanArchive")->enabled) {

	logg("Archive support enabled.\n");
	options |= CL_SCAN_ARCHIVE;

	if(cfgopt(copt, "ArchiveLimitMemoryUsage")->enabled) {
	    limits.archivememlim = 1;
	    logg("Archive: Limited memory usage.\n");
	} else {
	    limits.archivememlim = 0;
	}

	if(cfgopt(copt, "ArchiveBlockEncrypted")->enabled) {
	    logg("Archive: Blocking encrypted archives.\n");
	    options |= CL_SCAN_BLOCKENCRYPTED;
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

	if(cfgopt(copt, "ScanPartialMessages")->enabled) {
	    logg("Mail: RFC1341 handling enabled.\n");
	    options |= CL_SCAN_PARTIAL_MESSAGE;
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

	if(cfgopt(copt,"PhishingAlwaysBlockCloak")->enabled) {
	    options |= CL_SCAN_PHISHING_BLOCKCLOAK; 
	    logg("Phishing: Always checking for cloaked urls\n");
	}

	if(cfgopt(copt,"PhishingAlwaysBlockSSLMismatch")->enabled) {
	    options |= CL_SCAN_PHISHING_BLOCKSSL;
	    logg("Phishing: Always checking for ssl mismatches\n");
	}
    }

    if(cfgopt(copt,"HeuristicScanPrecedence")->enabled) {
	    options |= CL_SCAN_HEURISTIC_PRECEDENCE;
	    logg("Heuristic: precedence enabled\n");
    }

    if(cfgopt(copt, "StructuredDataDetection")->enabled) {
        options |= CL_SCAN_STRUCTURED;

        limits.min_cc_count = cfgopt(copt, "StructuredMinCreditCardCount")->numarg;
        logg("Structured: Minimum Credit Card Number Count set to %u\n", limits.min_cc_count);

        limits.min_ssn_count = cfgopt(copt, "StructuredMinSSNCount")->numarg;
        logg("Structured: Minimum Social Security Number Count set to %u\n", limits.min_ssn_count);

        if(cfgopt(copt, "StructuredSSNFormatNormal")->enabled)
            options |= CL_SCAN_STRUCTURED_SSN_NORMAL;

        if(cfgopt(copt, "StructuredSSNFormatStripped")->enabled)
	    options |= CL_SCAN_STRUCTURED_SSN_STRIPPED;
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
        do {
	    if(!pthread_attr_init(&clamuko_attr)) break;
	    pthread_attr_setdetachstate(&clamuko_attr, PTHREAD_CREATE_JOINABLE);
	    if(!(tharg = (struct thrarg *) malloc(sizeof(struct thrarg)))) break;
	    tharg->copt = copt;
	    tharg->engine = engine;
	    tharg->limits = &limits;
	    tharg->options = options;
	    if(pthread_create(&clamuko_pid, &clamuko_attr, clamukoth, tharg)) break;
	    free(tharg);
	    tharg=NULL;
	} while(0);
	if (!tharg) logg("!Unable to start Clamuko\n");
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
    /* The behavior of a process is undefined after it ignores a 
     * SIGFPE, SIGILL, SIGSEGV, or SIGBUS signal */
    sigdelset(&sigset, SIGFPE);
    sigdelset(&sigset, SIGILL);
    sigdelset(&sigset, SIGSEGV);
#ifdef SIGBUS    
    sigdelset(&sigset, SIGBUS);
#endif
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
	    pthread_mutex_lock(&exit_mutex);
	    if(progexit) {
		pthread_mutex_unlock(&exit_mutex);
	    	break;
	    }
	    pthread_mutex_unlock(&exit_mutex);
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
		if(client_conn) {
		    client_conn->sd = new_sd;
		    client_conn->options = options;
		    client_conn->copt = copt;
		    client_conn->engine = cl_dup(engine);
		    client_conn->engine_timestamp = reloaded_time;
		    client_conn->limits = &limits;
		    client_conn->socketds = socketds;
		    client_conn->nsockets = nsockets;
		    if(!thrmgr_dispatch(thr_pool, client_conn)) {
			closesocket(client_conn->sd);
			free(client_conn);
			logg("!thread dispatch failed\n");
		    }
		} else {
		    logg("!Can't allocate memory for client_conn\n");
		    closesocket(new_sd);
		    if(cfgopt(copt, "ExitOnOOM")->enabled) {
			pthread_mutex_lock(&exit_mutex);
			progexit = 1;
			pthread_mutex_unlock(&exit_mutex);
		    }
		}
	}

	pthread_mutex_lock(&exit_mutex);
	if(progexit) {
#ifdef C_WINDOWS
	    closesocket(new_sd);
#else
  	    if(new_sd >= 0)
		close(new_sd);
#endif
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
#ifdef C_WINDOWS
		closesocket(new_sd);
#else
		if(new_sd >= 0)
		    close(new_sd);
#endif
		break;
	    }

	    pthread_mutex_lock(&reload_mutex);
	    reload = 0;
	    time(&reloaded_time);
	    pthread_mutex_unlock(&reload_mutex);
#ifdef CLAMUKO
	    if(cfgopt(copt, "ClamukoScanOnAccess")->enabled && tharg) {
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
    logg("--- Stopped at %s", cli_ctime(&current_time, timestr, sizeof(timestr)));

    return ret;
}

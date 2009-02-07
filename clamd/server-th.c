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

#include <arpa/inet.h>
#include "libclamav/clamav.h"

#include "shared/output.h"
#include "shared/optparser.h"

#include "server.h"
#include "thrmgr.h"
#include "session.h"
#include "clamuko.h"
#include "others.h"
#include "shared.h"
#include "libclamav/others.h"
#include "libclamav/readdb.h"
#include "libclamav/cltypes.h"

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

static void scanner_thread(void *arg)
{
	client_conn_t *conn = (client_conn_t *) arg;
#ifndef	C_WINDOWS
	sigset_t sigset;
#endif
	int ret, timeout;
	unsigned virus=0, errors = 0;

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

    timeout = optget(conn->opts, "ReadTimeout")->numarg;
    if(!timeout)
	timeout = -1;

    ret = command(conn, &virus);
    if (ret == -1) {
	pthread_mutex_lock(&exit_mutex);
	progexit = 1;
	pthread_mutex_unlock(&exit_mutex);
	errors = 1;
    } else
	errors = ret;

    thrmgr_setactiveengine(NULL);

    if (conn->filename)
	free(conn->filename);
    logg("*SCANTH: finished\n");
    if (thrmgr_group_finished(conn->group, virus ? EXIT_OTHER :
			      errors ? EXIT_ERROR : EXIT_OK)) {
	logg("*SCANTH: connection shut down\n");
	/* close connection if we were last in group */
	shutdown(conn->sd, 2);
	closesocket(conn->sd);
    }
    cl_engine_free(conn->engine);
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

static struct cl_engine *reload_db(struct cl_engine *engine, unsigned int dboptions, const struct optstruct *opts, int do_check, int *ret)
{
	const char *dbdir;
	int retval;
	unsigned int sigs = 0;
	char pua_cats[128];

    pua_cats[0] = 0;
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
	if(dboptions & (CL_DB_PUA_INCLUDE | CL_DB_PUA_EXCLUDE))
	    if(cl_engine_get(engine, CL_ENGINE_PUA_CATEGORIES, pua_cats))
		logg("^Can't make a copy of pua_cats\n");

	thrmgr_setactiveengine(NULL);
	cl_engine_free(engine);
    }

    dbdir = optget(opts, "DatabaseDirectory")->strarg;
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

    if(!(engine = cl_engine_new())) {
	logg("!Can't initialize antivirus engine\n");
	*ret = 1;
	return NULL;
    }

    if(strlen(pua_cats)) {
	if((retval = cl_engine_set(engine, CL_ENGINE_PUA_CATEGORIES, pua_cats))) {
	    logg("!cl_engine_set(CL_ENGINE_PUA_CATEGORIES): %s\n", cl_strerror(retval));
	    cl_engine_free(engine);
	    *ret = 1;
	    return NULL;
	}
    }

    if((retval = cl_load(dbdir, engine, &sigs, dboptions))) {
	logg("!reload db failed: %s\n", cl_strerror(retval));
	cl_engine_free(engine);
	*ret = 1;
	return NULL;
    }

    if((retval = cl_engine_compile(engine)) != 0) {
	logg("!Database initialization error: can't compile engine: %s\n", cl_strerror(retval));
	cl_engine_free(engine);
	*ret = 1;
	return NULL;
    }
    logg("Database correctly reloaded (%u signatures)\n", sigs);

    thrmgr_setactiveengine(engine);
    return engine;
}

static const char *get_cmd(struct fd_buf *buf, size_t off, size_t *len, char *term)
{
    unsigned char *pos;
    if (!buf->off || off >= buf->off) {
	*len = 0;
	return NULL;
    }

    *term = '\n';
    switch (buf->buffer[0]) {
	/* commands terminated by delimiters */
	case 'z':
	    *term = '\0';
	case 'n':
	    pos = memchr(buf->buffer + off, *term, buf->off - off);
	    if (!pos) {
		/* we don't have another full command yet */
		*len = 0;
		return NULL;
	    }
	    *pos = '\0';
	    if (*term) {
		*len = cli_chomp(buf->buffer + off);
	    } else {
		*len = pos - buf->buffer - off;
	    }
	    return buf->buffer + off + 1;
	default:
	    /* one packet = one command */
	    *len = buf->off - off;
	    buf->buffer[buf->off] = '\0';
	    cli_chomp(buf->buffer + off);
	    return buf->buffer + off;
    }
}

struct acceptdata {
    struct fd_data fds;
    struct fd_data recv_fds;
    int syncpipe_wake_recv[2];
    int syncpipe_wake_accept[2];
};

static void *acceptloop_th(void *arg)
{
#ifdef HAVE_STRERROR_R
    char buff[BUFFSIZE + 1];
#endif
    size_t i;
    struct acceptdata *data = (struct acceptdata*)arg;
    struct fd_data *fds = &data->fds;
    struct fd_data *recv_fds = &data->recv_fds;

    pthread_mutex_lock(&fds->buf_mutex);
    for (;;) {
	/* Block waiting for data to become available for reading */
	int new_sd = fds_poll_recv(fds, -1, 0);

	/* TODO: what about sockets that get rm-ed? */
	if (!fds->nfds) {
	    /* no more sockets to poll, all gave an error */
	    logg("!Main socket gone: fatal\n");
	    break;
	}

	if (new_sd == -1 && errno != EINTR) {
	    logg("!Failed to poll sockets, fatal\n");
	    pthread_mutex_lock(&exit_mutex);
	    progexit = 1;
	    pthread_mutex_unlock(&exit_mutex);
	    break;
	}

	/* accept() loop */
	for (i=0;i < fds->nfds && new_sd >= 0; i++) {
	    struct fd_buf *buf = &fds->buf[i];
	    if (!buf->got_newdata)
		continue;
	    if (buf->fd == data->syncpipe_wake_accept[0]) {
		/* dummy sync pipe, just to wake us */
		if (read(buf->fd, buff, sizeof(buff)) < 0) {
		    logg("^Syncpipe read failed\n");
		}
		continue;
	    }
	    if (buf->got_newdata == -1) {
		shutdown(buf->fd, 2);
		closesocket(buf->fd);
		buf->fd = -1;
		continue;
	    }
	    /* listen only socket */
	    new_sd = accept(fds->buf[i].fd, NULL, NULL);
	    if (new_sd >= 0) {
		int ret;
		pthread_mutex_lock(&recv_fds->buf_mutex);
		ret = fds_add(recv_fds, new_sd, 0);
		pthread_mutex_unlock(&recv_fds->buf_mutex);

		if (ret == -1) {
		    logg("!fds_add failed\n");
		    closesocket(new_sd);
		    continue;
		}

		/* notify recvloop */
		if (write(data->syncpipe_wake_recv[1], "", 1) == -1) {
		    logg("!write syncpipe failed\n");
		    continue;
		}
	    } else if (errno != EINTR) {
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
		/* give the poll loop a chance to close disconnected FDs */
		break;
	    }

	}

	/* handle progexit */
	pthread_mutex_lock(&exit_mutex);
	if (progexit) {
	    pthread_mutex_unlock(&exit_mutex);
	    break;
	}
	pthread_mutex_unlock(&exit_mutex);
    }
    pthread_mutex_unlock(&fds->buf_mutex);

    for (i=0;i < fds->nfds; i++) {
	if (fds->buf[i].fd == -1)
	    continue;
	shutdown(fds->buf[i].fd, 2);
	closesocket(fds->buf[i].fd);
    }
    fds_free(fds);

    pthread_mutex_lock(&exit_mutex);
    progexit = 1;
    pthread_mutex_unlock(&exit_mutex);
    if (write(data->syncpipe_wake_recv[1], "", 1) < 0) {
	logg("^Syncpipe write failed\n");
    }

    return NULL;
}

int recvloop_th(int *socketds, unsigned nsockets, struct cl_engine *engine, unsigned int dboptions, const struct optstruct *opts)
{
	int max_threads, ret = 0;
	unsigned int options = 0;
	char timestr[32];
#ifndef	C_WINDOWS
	struct sigaction sigact;
	sigset_t sigset;
	struct rlimit rlim;
#endif
	mode_t old_umask;
	const struct optstruct *opt;
	char buff[BUFFSIZE + 1];
	pid_t mainpid;
	int idletimeout;
	uint32_t val32;
	uint64_t val64;
	size_t i;
	pthread_t accept_th;
	struct acceptdata acceptdata;
	struct fd_data *fds = &acceptdata.recv_fds;
	time_t start_time, current_time;
	unsigned int selfchk;
	threadpool_t *thr_pool;

#ifdef CLAMUKO
	pthread_t clamuko_pid;
	pthread_attr_t clamuko_attr;
	struct thrarg *tharg = NULL; /* shut up gcc */
#endif

#ifndef	C_WINDOWS
	memset(&sigact, 0, sizeof(struct sigaction));
#endif

    /* set up limits */
    if((opt = optget(opts, "MaxScanSize"))->enabled) {
	val64 = opt->numarg;
	if((ret = cl_engine_set(engine, CL_ENGINE_MAX_SCANSIZE, &val64))) {
	    logg("!cli_engine_set(CL_ENGINE_MAX_SCANSIZE) failed: %s\n", cl_strerror(ret));
	    cl_engine_free(engine);
	    return 1;
	}
    }
    cl_engine_get(engine, CL_ENGINE_MAX_SCANSIZE, &val64);
    if(val64)
    	logg("Limits: Global size limit set to %llu bytes.\n", (unsigned long long) val64);
    else
    	logg("^Limits: Global size limit protection disabled.\n");

    if((opt = optget(opts, "MaxFileSize"))->enabled) {
	val64 = opt->numarg;
	if((ret = cl_engine_set(engine, CL_ENGINE_MAX_FILESIZE, &val64))) {
	    logg("!cli_engine_set(CL_ENGINE_MAX_FILESIZE) failed: %s\n", cl_strerror(ret));
	    cl_engine_free(engine);
	    return 1;
	}
    }
    cl_engine_get(engine, CL_ENGINE_MAX_FILESIZE, &val64);
    if(val64)
    	logg("Limits: File size limit set to %llu bytes.\n", (unsigned long long) val64);
    else
    	logg("^Limits: File size limit protection disabled.\n");

#ifndef C_WINDOWS
    if(getrlimit(RLIMIT_FSIZE, &rlim) == 0) {
	cl_engine_get(engine, CL_ENGINE_MAX_FILESIZE, &val64);
	if(rlim.rlim_max < val64)
	    logg("^System limit for file size is lower than engine->maxfilesize\n");
	cl_engine_get(engine, CL_ENGINE_MAX_SCANSIZE, &val64);
	if(rlim.rlim_max < val64)
	    logg("^System limit for file size is lower than engine->maxscansize\n");
    } else {
	logg("^Cannot obtain resource limits for file size\n");
    }
#endif

    if((opt = optget(opts, "MaxRecursion"))->enabled) {
	val32 = opt->numarg;
	if((ret = cl_engine_set(engine, CL_ENGINE_MAX_RECURSION, &val32))) {
	    logg("!cli_engine_set(CL_ENGINE_MAX_RECURSION) failed: %s\n", cl_strerror(ret));
	    cl_engine_free(engine);
	    return 1;
	}
    }
    cl_engine_get(engine, CL_ENGINE_MAX_RECURSION, &val32);
    if(val32)
    	logg("Limits: Recursion level limit set to %u.\n", (unsigned int) val32);
    else
    	logg("^Limits: Recursion level limit protection disabled.\n");

    if((opt = optget(opts, "MaxFiles"))->enabled) {
	val32 = opt->numarg;
	if((ret = cl_engine_set(engine, CL_ENGINE_MAX_FILES, &val32))) {
	    logg("!cli_engine_set(CL_ENGINE_MAX_FILES) failed: %s\n", cl_strerror(ret));
	    cl_engine_free(engine);
	    return 1;
	}
    }
    cl_engine_get(engine, CL_ENGINE_MAX_FILES, &val32);
    if(val32)
    	logg("Limits: Files limit set to %u.\n", (unsigned int) val32);
    else
    	logg("^Limits: Files limit protection disabled.\n");


    if(optget(opts, "ScanArchive")->enabled) {
	logg("Archive support enabled.\n");
	options |= CL_SCAN_ARCHIVE;

	if(optget(opts, "ArchiveBlockEncrypted")->enabled) {
	    logg("Archive: Blocking encrypted archives.\n");
	    options |= CL_SCAN_BLOCKENCRYPTED;
	}

    } else {
	logg("Archive support disabled.\n");
    }

    if(optget(opts, "AlgorithmicDetection")->enabled) {
	logg("Algorithmic detection enabled.\n");
	options |= CL_SCAN_ALGORITHMIC;
    } else {
	logg("Algorithmic detection disabled.\n");
    }

    if(optget(opts, "ScanPE")->enabled) {
	logg("Portable Executable support enabled.\n");
	options |= CL_SCAN_PE;
    } else {
	logg("Portable Executable support disabled.\n");
    }

    if(optget(opts, "ScanELF")->enabled) {
	logg("ELF support enabled.\n");
	options |= CL_SCAN_ELF;
    } else {
	logg("ELF support disabled.\n");
    }

    if(optget(opts, "ScanPE")->enabled || optget(opts, "ScanELF")->enabled) {
	if(optget(opts, "DetectBrokenExecutables")->enabled) {
	    logg("Detection of broken executables enabled.\n");
	    options |= CL_SCAN_BLOCKBROKEN;
	}
    }

    if(optget(opts, "ScanMail")->enabled) {
	logg("Mail files support enabled.\n");
	options |= CL_SCAN_MAIL;

	if(optget(opts, "MailFollowURLs")->enabled) {
	    logg("Mail: URL scanning enabled.\n");
	    options |= CL_SCAN_MAILURL;
	}

	if(optget(opts, "ScanPartialMessages")->enabled) {
	    logg("Mail: RFC1341 handling enabled.\n");
	    options |= CL_SCAN_PARTIAL_MESSAGE;
	}

    } else {
	logg("Mail files support disabled.\n");
    }

    if(optget(opts, "ScanOLE2")->enabled) {
	logg("OLE2 support enabled.\n");
	options |= CL_SCAN_OLE2;
    } else {
	logg("OLE2 support disabled.\n");
    }

    if(optget(opts, "ScanPDF")->enabled) {
	logg("PDF support enabled.\n");
	options |= CL_SCAN_PDF;
    } else {
	logg("PDF support disabled.\n");
    }

    if(optget(opts, "ScanHTML")->enabled) {
	logg("HTML support enabled.\n");
	options |= CL_SCAN_HTML;
    } else {
	logg("HTML support disabled.\n");
    }

    if(optget(opts,"PhishingScanURLs")->enabled) {

	if(optget(opts,"PhishingAlwaysBlockCloak")->enabled) {
	    options |= CL_SCAN_PHISHING_BLOCKCLOAK; 
	    logg("Phishing: Always checking for cloaked urls\n");
	}

	if(optget(opts,"PhishingAlwaysBlockSSLMismatch")->enabled) {
	    options |= CL_SCAN_PHISHING_BLOCKSSL;
	    logg("Phishing: Always checking for ssl mismatches\n");
	}
    }

    if(optget(opts,"HeuristicScanPrecedence")->enabled) {
	    options |= CL_SCAN_HEURISTIC_PRECEDENCE;
	    logg("Heuristic: precedence enabled\n");
    }

    if(optget(opts, "StructuredDataDetection")->enabled) {
        options |= CL_SCAN_STRUCTURED;

	if((opt = optget(opts, "StructuredMinCreditCardCount"))->enabled) {
	    val32 = opt->numarg;
	    if((ret = cl_engine_set(engine, CL_ENGINE_MIN_CC_COUNT, &val32))) {
		logg("!cli_engine_set(CL_ENGINE_MIN_CC_COUNT) failed: %s\n", cl_strerror(ret));
		cl_engine_free(engine);
		return 1;
	    }
	}
	cl_engine_get(engine, CL_ENGINE_MIN_CC_COUNT, &val32);
	logg("Structured: Minimum Credit Card Number Count set to %u\n", (unsigned int) val32);

	if((opt = optget(opts, "StructuredMinSSNCount"))->enabled) {
	    val32 = opt->numarg;
	    if((ret = cl_engine_set(engine, CL_ENGINE_MIN_SSN_COUNT, &val32))) {
		logg("!cli_engine_set(CL_ENGINE_MIN_SSN_COUNT) failed: %s\n", cl_strerror(ret));
		cl_engine_free(engine);
		return 1;
	    }
	}
	cl_engine_get(engine, CL_ENGINE_MIN_SSN_COUNT, &val32);
        logg("Structured: Minimum Social Security Number Count set to %u\n", (unsigned int) val32);

        if(optget(opts, "StructuredSSNFormatNormal")->enabled)
            options |= CL_SCAN_STRUCTURED_SSN_NORMAL;

        if(optget(opts, "StructuredSSNFormatStripped")->enabled)
	    options |= CL_SCAN_STRUCTURED_SSN_STRIPPED;
    }

    selfchk = optget(opts, "SelfCheck")->numarg;
    if(!selfchk) {
	logg("Self checking disabled.\n");
    } else {
	logg("Self checking every %u seconds.\n", selfchk);
    }

    /* save the PID */
    mainpid = getpid();
    if((opt = optget(opts, "PidFile"))->enabled) {
	    FILE *fd;
	old_umask = umask(0006);
	if((fd = fopen(opt->strarg, "w")) == NULL) {
	    logg("!Can't save PID in file %s\n", opt->strarg);
	} else {
	    if (fprintf(fd, "%u", (unsigned int) mainpid)<0) {
	    	logg("!Can't save PID in file %s\n", opt->strarg);
	    }
	    fclose(fd);
	}
	umask(old_umask);
    }

    logg("*Listening daemon: PID: %u\n", (unsigned int) mainpid);
    max_threads = optget(opts, "MaxThreads")->numarg;

    if(optget(opts, "ClamukoScanOnAccess")->enabled)
#ifdef CLAMUKO
    {
        do {
	    if(pthread_attr_init(&clamuko_attr)) break;
	    pthread_attr_setdetachstate(&clamuko_attr, PTHREAD_CREATE_JOINABLE);
	    if(!(tharg = (struct thrarg *) malloc(sizeof(struct thrarg)))) break;
	    tharg->opts = opts;
	    tharg->engine = engine;
	    tharg->options = options;
	    if(!pthread_create(&clamuko_pid, &clamuko_attr, clamukoth, tharg)) break;
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

    idletimeout = optget(opts, "IdleTimeout")->numarg;

    memset(&acceptdata, 0, sizeof(acceptdata));

    for (i=0;i < nsockets;i++)
	if (fds_add(&acceptdata.fds, socketds[i], 1) == -1) {
	    logg("!fds_add failed\n");
	    cl_engine_free(engine);
	    return 1;
	}

    if (pipe(acceptdata.syncpipe_wake_recv) == -1 ||
	(pipe(acceptdata.syncpipe_wake_accept) == -1)) {

	logg("!pipe failed\n");
	exit(-1);
    }

    if (fds_add(fds, acceptdata.syncpipe_wake_recv[0], 1) == -1 ||
	fds_add(&acceptdata.fds, acceptdata.syncpipe_wake_accept[0], 1)) {
	logg("!failed to add pipe fd\n");
	exit(-1);
    }

    if ((thr_pool = thrmgr_new(max_threads, idletimeout, scanner_thread)) == NULL) {
	logg("!thrmgr_new failed\n");
	exit(-1);
    }

    if (pthread_create(&accept_th, NULL, acceptloop_th, &acceptdata)) {
	logg("!pthread_create failed\n");
	exit(-1);
    }

    time(&start_time);
    for(;;) {
	int new_sd;
	/* Block waiting for connection on any of the sockets */
	pthread_mutex_lock(&fds->buf_mutex);
	new_sd = fds_poll_recv(fds, -1, 1);

	if (!fds->nfds) {
	    /* at least the dummy/sync pipe should have remained */
	    logg("!All recv() descriptors gone: fatal\n");
	    pthread_mutex_lock(&exit_mutex);
	    progexit = 1;
	    pthread_mutex_unlock(&exit_mutex);
	    pthread_mutex_unlock(&fds->buf_mutex);
	    break;
	}

	if (new_sd == -1 && errno != EINTR) {
	    logg("!Failed to poll sockets, fatal\n");
	    pthread_mutex_lock(&exit_mutex);
	    progexit = 1;
	    pthread_mutex_unlock(&exit_mutex);
	}

	for (i=0;i < fds->nfds && new_sd >= 0; i++) {
	    size_t pos = 0;
	    int error = 0;
	    struct fd_buf *buf = &fds->buf[i];
	    if (!buf->got_newdata)
		continue;

	    if (buf->fd == acceptdata.syncpipe_wake_recv[0]) {
		/* dummy sync pipe, just to wake us */
		if (read(buf->fd, buff, sizeof(buff)) < 0) {
		    logg("^Syncpipe read failed\n");
		}
		continue;
	    }

	    if (buf->got_newdata == -1) {
		logg("*RECVTH: client read error or EOF on read\n");
		error = 1;
	    }

	    if (buf->mode == MODE_WAITANCILL) {
		buf->mode = MODE_COMMAND;
		logg("*RECVTH: mode -> MODE_COMMAND\n");
	    }
	    while (!error && buf->fd != -1 && buf->buffer && pos < buf->off &&
		   buf->mode != MODE_WAITANCILL) {
		client_conn_t conn;
		const unsigned char *cmd;
		size_t cmdlen = 0;
		char term = '\n';
		int rc;
		/* New data available to read on socket. */

		memset(&conn, 0, sizeof(conn));
		conn.scanfd = buf->recvfd;
		buf->recvfd = -1;
		conn.sd = buf->fd;
		conn.options = options;
		conn.opts = opts;
		conn.thrpool = thr_pool;
		conn.engine = engine;
		conn.group = buf->group;
		conn.id = buf->id;
		conn.quota = buf->quota;
		conn.filename = buf->dumpname;
		conn.mode = buf->mode;
		/* Parse & dispatch commands */
		while ((conn.mode == MODE_COMMAND) &&
		       (cmd = get_cmd(buf, pos, &cmdlen, &term)) != NULL) {
		    const char *argument;
		    int has_more = (buf->buffer + buf->off) > (cmd + cmdlen);
		    enum commands cmdtype = parse_command(cmd, &argument);
		    logg("*RECVTH: got command %s (%u), argument: %s\n",
			 cmd, cmdtype, argument ? argument : "");
		    if (cmdtype == COMMAND_FILDES) {
			if (buf->buffer + buf->off <= cmd + strlen("FILDES\n")) {
			    /* we need the extra byte from recvmsg */
			    conn.mode = MODE_WAITANCILL;
			    buf->mode = MODE_WAITANCILL;
			    cmdlen = 0;
			    logg("*RECVTH: mode -> MODE_WAITANCILL\n");
			    break;
			}
			/* eat extra \0 for controlmsg */
			cmdlen++;
			logg("*RECVTH: FILDES command complete\n");
		    }

		    conn.term = term;

		    if ((rc = execute_or_dispatch_command(&conn, cmdtype, argument)) < 0) {
			logg("!Command dispatch failed\n");
			if(rc == -1 && optget(opts, "ExitOnOOM")->enabled) {
			    pthread_mutex_lock(&exit_mutex);
			    progexit = 1;
			    pthread_mutex_unlock(&exit_mutex);
			}
			error = 1;
		    }
		    if (error || !conn.group || rc) {
			if (rc && thrmgr_group_finished(conn.group, EXIT_OK)) {
			    logg("*RECVTH: closing conn, group finished\n");
			    /* if there are no more active jobs */
			    shutdown(conn.sd, 2);
			    closesocket(conn.sd);
			} else {
			    logg("*RECVTH: mode -> MODE_WAITREPLY\n");
			    /* no more commands are accepted */
			    conn.mode = MODE_WAITREPLY;
			}
			buf->fd = -1;
		    }
		    pos += cmdlen+1;
		    if (conn.mode == MODE_STREAM) {
			/* TODO: this doesn't belong here */
			buf->dumpname = conn.filename;
			buf->dumpfd = conn.scanfd;
			logg("*RECVTH: STREAM: %s fd %u\n", buf->dumpname, buf->dumpfd);
		    }
		    if (conn.mode != MODE_COMMAND) {
			logg("*RECVTH: breaking command loop, mode is no longer MODE_COMMAND\n");
			break;
		    }
		    conn.id++;
		}
		buf->mode = conn.mode;
		buf->id = conn.id;
		buf->group = conn.group;
		buf->quota = conn.quota;
		if (!error) {
		    /* move partial command to beginning of buffer */
		    if (pos < buf->off) {
			memmove (buf->buffer, &buf->buffer[pos], buf->off - pos);
			buf->off -= pos;
		    } else
			buf->off = 0;
		    if (buf->off)
			logg("*RECVTH: moved partial command: %u\n", buf->off);
		    else
			logg("*RECVTH: consumed entire command\n");
		}
		if (!error && buf->mode == MODE_WAITREPLY && buf->off) {
		    /* Client is not supposed to send anything more */
		    logg("^Client sent garbage after last command: %u bytes\n", buf->off);
		    buf->buffer[buf->off] = '\0';
		    logg("*RECVTH: garbage: %s\n", buf->buffer);
		    error = 1;
		}
		if (!error && buf->mode == MODE_STREAM) {
		    logg("*RECVTH: mode == MODE_STREAM\n");
		    if (!buf->chunksize) {
			/* read chunksize */
			if (buf->off >= 4) {
			    uint32_t cs = *(uint32_t*)buf->buffer;
			    buf->chunksize = ntohl(cs);
			    logg("*RECVTH: chunksize: %u\n", buf->chunksize);
			    if (!buf->chunksize) {
				/* chunksize 0 marks end of stream */
				conn.scanfd = buf->dumpfd;
				buf->dumpfd = -1;
				buf->mode = MODE_COMMAND;
				logg("*RECVTH: chunks complete\n");
				if ((rc = execute_or_dispatch_command(&conn, COMMAND_INSTREAMSCAN, NULL)) < 0) {
				    logg("!Command dispatch failed\n");
				    if(rc == -1 && optget(opts, "ExitOnOOM")->enabled) {
					pthread_mutex_lock(&exit_mutex);
					progexit = 1;
					pthread_mutex_unlock(&exit_mutex);
				    }
				    error = 1;
				} else {
				    pos = 4;
				    continue;
				}
			    }
			    if (buf->chunksize > buf->quota) {
				logg("^INSTREAM: Size limit reached, (requested: %lu, max: %lu)\n", buf->chunksize, buf->quota);
				conn_reply_error(&conn, "INSTREAM size limit exceeded. ERROR");
				error = 1;
			    } else {
				buf->quota -= buf->chunksize;
			    }
			    logg("*RECVTH: quota: %lu\n", buf->quota);
			    pos = 4;
			} else
			    continue;
		    } else
			pos = 0;
		    if (pos + buf->chunksize < buf->off)
			cmdlen = buf->chunksize;
		    else
			cmdlen = buf->off - pos;
		    buf->chunksize -= cmdlen;
		    if (cli_writen(buf->dumpfd, buf->buffer + pos, cmdlen) < 0) {
			conn_reply_error(&conn, "Error writing to temporary file");
			logg("!INSTREAM: Can't write to temporary file.\n");
			error = 1;
		    }
		    logg("*RECVTH: processed %lu bytes of chunkdata\n", cmdlen);
		    pos += cmdlen;
		}
		if (error) {
		    conn_reply_error(&conn, "Error processing command.");
		}
	    }
	    if (error) {
		if (thrmgr_group_terminate(buf->group)) {
		    logg("*RECVTH: shutting down socket after error\n");
		    shutdown(buf->fd, 2);
		    closesocket(buf->fd);
		} else
		    logg("*RECVTH: socket not shut down due to active tasks\n");
		buf->fd = -1;
	    }
	}
	pthread_mutex_unlock(&fds->buf_mutex);

	/* handle progexit */
	pthread_mutex_lock(&exit_mutex);
	if (progexit) {
	    pthread_mutex_unlock(&exit_mutex);
	    for (i=0;i < fds->nfds; i++) {
		if (fds->buf[i].fd == -1)
		    continue;
		if (thrmgr_group_terminate(fds->buf[i].group)) {
		    shutdown(fds->buf[i].fd, 2);
		    closesocket(fds->buf[i].fd);
		}
	    }
	    fds->nfds = 0;
	    break;
	}
	pthread_mutex_unlock(&exit_mutex);

	/* SIGHUP */
	if (sighup) {
	    logg("SIGHUP caught: re-opening log file.\n");
	    logg_close();
	    sighup = 0;
	    if(!logg_file && (opt = optget(opts, "LogFile"))->enabled)
		logg_file = opt->strarg;
	}

	/* SelfCheck */
	if(selfchk) {
	    time(&current_time);
	    if((current_time - start_time) > (time_t)selfchk) {
		if(reload_db(engine, dboptions, opts, TRUE, &ret)) {
		    pthread_mutex_lock(&reload_mutex);
		    reload = 1;
		    pthread_mutex_unlock(&reload_mutex);
		}
		time(&start_time);
	    }
	}

	/* DB reload */
	pthread_mutex_lock(&reload_mutex);
	if(reload) {
	    pthread_mutex_unlock(&reload_mutex);
	    engine = reload_db(engine, dboptions, opts, FALSE, &ret);
	    if(ret) {
		logg("Terminating because of a fatal error.\n");
		if(new_sd >= 0)
		    closesocket(new_sd);
		break;
	    }

	    pthread_mutex_lock(&reload_mutex);
	    reload = 0;
	    time(&reloaded_time);
	    pthread_mutex_unlock(&reload_mutex);
#ifdef CLAMUKO
	    if(optget(opts, "ClamukoScanOnAccess")->enabled && tharg) {
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

    fds_free(fds);
    if (write(acceptdata.syncpipe_wake_accept[1], "", 1) < 0) {
	logg("^Write to syncpipe failed\n");
    }
    /* Destroy the thread manager.
     * This waits for all current tasks to end
     */
    logg("*Waiting for all threads to finish\n");
    thrmgr_destroy(thr_pool);
#ifdef CLAMUKO
    if(optget(opts, "ClamukoScanOnAccess")->enabled) {
	logg("Stopping Clamuko.\n");
	pthread_kill(clamuko_pid, SIGUSR1);
	pthread_join(clamuko_pid, NULL);
    }
#endif
    if(engine) {
	thrmgr_setactiveengine(NULL);
	cl_engine_free(engine);
    }

    pthread_join(accept_th, NULL);
    close(acceptdata.syncpipe_wake_accept[1]);
    close(acceptdata.syncpipe_wake_recv[1]);
    if(dbstat)
	cl_statfree(dbstat);
    logg("*Shutting down the main socket%s.\n", (nsockets > 1) ? "s" : "");
    for (i = 0; i < nsockets; i++)
	shutdown(socketds[i], 2);
    logg("*Closing the main socket%s.\n", (nsockets > 1) ? "s" : "");
    for (i = 0; i < nsockets; i++)
	closesocket(socketds[i]);
#ifndef C_OS2
    if((opt = optget(opts, "LocalSocket"))->enabled) {
	if(unlink(opt->strarg) == -1)
	    logg("!Can't unlink the socket file %s\n", opt->strarg);
	else
	     logg("Socket file removed.\n");
    }
#endif

    if((opt = optget(opts, "PidFile"))->enabled) {
	if(unlink(opt->strarg) == -1)
	    logg("!Can't unlink the pid file %s\n", opt->strarg);
	else
	    logg("Pid file removed.\n");
    }

    time(&current_time);
    logg("--- Stopped at %s", cli_ctime(&current_time, timestr, sizeof(timestr)));

    return ret;
}

/*
 *  Copyright (C) 2002, 2003 Tomasz Kojm <zolw@konarski.edu.pl>
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <pthread.h>
#include <time.h>
#include <signal.h>

#include "cfgfile.h"
#include "others.h"
#include "defaults.h"
#include "scanner.h"
#include "server.h"
#include "clamuko.h"
#include "tests.h"

#define CMD1 "SCAN"
#define CMD2 "RAWSCAN"
#define CMD3 "QUIT"
#define CMD4 "RELOAD"
#define CMD5 "PING"
#define CMD6 "CONTSCAN"
#define CMD7 "VERSION"
#define CMD8 "STREAM"

int procscan(const char *name, const struct cl_node *root, const struct cl_limits *limits, int options, const struct cfgstruct *copt, int odesc, short contscan)
{
	int pid;
	struct cfgstruct *cpt;

    switch(pid = fork()) {
	case -1:
	    logg("!Can't fork()\n");
	    return -1;

	case 0:
	    if((cpt = cfgopt(copt, "ThreadTimeout")))
	        alarm(cpt->numarg);
/* 0 should disable the limit
	    else
	        alarm(CL_DEFAULT_SCANTIMEOUT);
*/

	    if(!name)
		scanstream(odesc, NULL, root, limits, options, copt);
	    else
		scan(name, NULL, root, limits, options, copt, odesc, contscan);

	    exit(0);

	default:
	    return pid;
    }

    return -1;
}

int acceptd = -1;

int acceptloop_proc(int socketd, struct cl_node *root, const struct cfgstruct *copt)
{
	int i, j, bread, options = 0, childs, *session, status,
	    virnum, need_wait, ret;
	struct cfgstruct *cpt;
	struct cl_limits limits;
	struct sigaction sigact;
	char buff[1025];
	const char *dbdir;
	sigset_t sigset;
	mode_t old_umask;

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

    if((cpt = cfgopt(copt, "MaxThreads")))
	childs = cpt->numarg;
    else
	childs = CL_DEFAULT_MAXTHREADS;

    logg("Maximal number of childs: %d\n", childs);
    session = (int *) mcalloc(childs, sizeof(int));

    if((cpt = cfgopt(copt, "DatabaseDirectory")) || (cpt = cfgopt(copt, "DataDirectory")))
	dbdir = cpt->strarg;
    else
        dbdir = cl_retdbdir();

    if(cfgopt(copt, "ScanArchive")) {

	/* set up limits */
	memset(&limits, 0, sizeof(struct cl_limits));

	if((cpt = cfgopt(copt, "ArchiveMaxFileSize"))) {
	    if((limits.maxfilesize = cpt->numarg))
		logg("Archive: Archived file size limit set to %d bytes.\n", limits.maxfilesize);
	    else
		logg("^Archive: File size limit protection disabled.\n");
	} else {
	    limits.maxfilesize = 10485760;
	    logg("^USING HARDCODED LIMIT: Archive: Archived file size limit set to %d bytes.\n", limits.maxfilesize);
	}

	if((cpt = cfgopt(copt, "ArchiveMaxRecursion"))) {
	    if((limits.maxreclevel = cpt->numarg))
		logg("Archive: Recursion level limit set to %d.\n", limits.maxreclevel);
	    else
		logg("^Archive: Recursion level limit protection disabled.\n");
	} else {
	    limits.maxreclevel = 5;
	    logg("^USING HARDCODED LIMIT: Archive: Recursion level set to %d.\n", limits.maxreclevel);
	}

	if((cpt = cfgopt(copt, "ArchiveMaxFiles"))) {
	    if((limits.maxfiles = cpt->numarg))
		logg("Archive: Files limit set to %d.\n", limits.maxfiles);
	    else
		logg("^Archive: Files limit protection disabled.\n");
	} else {
	    limits.maxfiles = 1000;
	    logg("^USING HARDCODED LIMIT: Archive: Files limit set to %d.\n", limits.maxfiles);
	}

	if((cpt = cfgopt(copt, "ArchiveMaxCompressionRatio"))) {
	    if((limits.maxratio = cpt->numarg))
		logg("Archive: Compression ratio limit set to %d.\n", limits.maxratio);
	    else
		logg("^Archive: Compression ratio limit disabled.\n");
	} else {
	    limits.maxratio = 200;
	    logg("^USING HARDCODED LIMIT: Archive: Compression ratio limit set to %d.\n", limits.maxratio);
	}

	if(cfgopt(copt, "ArchiveLimitMemoryUsage")) {
	    limits.archivememlim = 1;
	    logg("Archive: Limited memory usage.\n");
	} else
	    limits.archivememlim = 0;

	
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
	logg("Mail support enabled.\n");
	options |= CL_MAIL;
    } else {
	logg("Mail support disabled.\n");
    }

    /* set up signal handling */

    sigfillset(&sigset);
    sigdelset(&sigset, SIGINT);
    sigdelset(&sigset, SIGTERM);
    sigdelset(&sigset, SIGSEGV);
    sigdelset(&sigset, SIGHUP);
    sigprocmask(SIG_SETMASK, &sigset, NULL);

    /* SIGINT, SIGTERM, SIGSEGV */
    sigact.sa_handler = sighandler;
    sigemptyset(&sigact.sa_mask);
    sigaddset(&sigact.sa_mask, SIGINT);
    sigaddset(&sigact.sa_mask, SIGTERM);
    sigaddset(&sigact.sa_mask, SIGHUP);
    sigaction(SIGINT, &sigact, NULL);
    sigaction(SIGTERM, &sigact, NULL);
#ifndef CL_DEBUG
    sigaction(SIGSEGV, &sigact, NULL);
#endif
    sigaction(SIGHUP, &sigact, NULL);


    while(1) {

	for(i = 0; ; i++) { /* find a free session */

	    /* free all finished childs */
	    for(j = 0; j <= childs; j++)
		if(session[j] && waitpid(session[j], &status, WNOHANG))
		    session[j] = 0;

	    if(i == childs) {
		i = 0;
		usleep(50000);
	    }

	    if(!session[i])
		break;
	}

	if((acceptd = accept(socketd, NULL, NULL)) == -1) {
	    logg("!accept() failed.\n");
	    /* exit ? */
	    continue;
	}

	if((bread = read(acceptd, buff, 1024)) == -1) {
	    logg("!read(desc %d) failed.\n", acceptd);
	} else {

	    buff[bread] = 0;
	    chomp(buff);

	    if(!strncmp(buff, CMD1, strlen(CMD1))) { /* SCAN */
		session[i] = procscan(buff + strlen(CMD1) + 1, root, &limits, options, copt, acceptd, 0);

	    } else if(!strncmp(buff, CMD2, strlen(CMD2))) { /* RAWSCAN */
		options &= ~CL_ARCHIVE;
		session[i] = procscan(buff + strlen(CMD2) + 1, root, NULL, options, copt, acceptd, 0);

	    } else if(!strncmp(buff, CMD3, strlen(CMD3))) { /* QUIT */
		kill(0, SIGTERM);

	    } else if(!strncmp(buff, CMD4, strlen(CMD4))) { /* RELOAD */
		mdprintf(acceptd, "RELOADING\n");

		/* wait until all childs are finished */
		do {
		    need_wait = 0;

		    /* free all finished childs */
		    for(i = 0; i <= childs; i++)
			if(session[i] && waitpid(session[i], &status, WNOHANG))
			    session[i] = 0;

		    for(i = 0; i <= childs; i++)
			if(session[i])
			    need_wait = 1;

		    if(need_wait)
			usleep(200000);

		} while(need_wait);

		cl_freetrie(root);
		root = NULL;
		logg("Reading databases from %s\n", dbdir);
		//cl_statfree(&dbstat);
		//cl_statinidir(dbdir, &dbstat);
		virnum = 0;
		if((ret = cl_loaddbdir(dbdir, &root, &virnum))) {
		    logg("!%s\n", cl_strerror(ret));
		    exit(1);
		}

		if(!root) {
		    logg("!Database initialization problem.\n");
		    exit(1);
		} else {
		    if((ret = cl_buildtrie(root)) != 0) {
			logg("!Database initialization error: can't build the trie: %s\n", cl_strerror(i));
			exit(1);
		    }
		    /* check integrity */
		    if(!testsignature(root)) {
			logg("!Unable to detect test signature.\n");
			exit(1);
		    }

		    logg("Database correctly reloaded (%d viruses)\n", virnum);
		    mdprintf(acceptd, "RELOADED\n");
		}

	    } else if(!strncmp(buff, CMD5, strlen(CMD5))) { /* PING */
		mdprintf(acceptd, "PONG\n");

	    } else if(!strncmp(buff, CMD6, strlen(CMD6))) { /* CONTSCAN */
		session[i] = procscan(buff + strlen(CMD6) + 1, root, &limits, options, copt, acceptd, 1);

	    } else if(!strncmp(buff, CMD7, strlen(CMD7))) { /* VERSION */
		mdprintf(acceptd, "clamd / ClamAV version "VERSION"\n");

	    } else if(!strncmp(buff, CMD8, strlen(CMD8))) { /* STREAM */
		session[i] = procscan(NULL, root, &limits, options, copt, acceptd, 0);
	    }
	}

	close(acceptd);
    }
}

void sighandler(int sig)
{
	time_t currtime;

    switch(sig) {
	case SIGINT:
	case SIGTERM:
	    time(&currtime);
	    logg("--- Process %d stopped at %s", getpid(), ctime(&currtime));
	    exit(0);
	    break; /* not reached */

#ifndef CL_DEBUG
	case SIGSEGV:
	    logg("Segmentation fault :-( Bye..\n");
	    exit(11); /* probably not reached at all */
	    break; /* not reached */
#endif
	case SIGHUP:
	    sighup = 1;
	    logg("SIGHUP catched: log file re-opened.\n");
	    break;
	case SIGALRM:
	    if(acceptd > 0)
		mdprintf(acceptd, "Session (PID %d): Time out ERROR\n", getpid());
	    logg("Session (PID %d) stopped due to timeout.\n", getpid());
	    exit(0);
    }
}

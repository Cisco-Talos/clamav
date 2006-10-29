/*
 *  Copyright (C) 2002 - 2005 Tomasz Kojm <tkojm@clamav.net>
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef	HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <sys/types.h>
#ifndef	C_WINDOWS
#include <dirent.h>
#include <sys/socket.h>
#include <sys/time.h>
#endif
#include <pthread.h>
#include <time.h>
#include <signal.h>
#include <errno.h>
#include <stddef.h>

#include "libclamav/clamav.h"
#include "libclamav/str.h"

#include "shared/cfgparser.h"
#include "shared/memory.h"
#include "shared/output.h"
#include "shared/misc.h"

#include "others.h"
#include "scanner.h"
#include "server.h"
#include "clamuko.h"
#include "session.h"
#include "thrmgr.h"
#include "shared.h"

static pthread_mutex_t ctime_mutex = PTHREAD_MUTEX_INITIALIZER;
extern int progexit;

struct multi_tag {
    int sd;
    int options;
    const struct cfgstruct *copt;
    char *fname;
    const struct cl_node *root;
    const struct cl_limits *limits;
};

void multiscanfile(void *arg)
{
	struct multi_tag *tag = (struct multi_tag *) arg;
	const char *virname;
#ifndef	C_WINDOWS
        sigset_t sigset;
#endif
	int ret;


#ifndef	C_WINDOWS
    /* ignore all signals */
    sigfillset(&sigset);
    pthread_sigmask(SIG_SETMASK, &sigset, NULL);
#endif

    ret = cl_scanfile(tag->fname, &virname, NULL, tag->root, tag->limits, tag->options);

    if(ret == CL_VIRUS) {
	mdprintf(tag->sd, "%s: %s FOUND\n", tag->fname, virname);
	logg("%s: %s FOUND\n", tag->fname, virname);
	virusaction(tag->fname, virname, tag->copt);
    } else if(ret != CL_CLEAN) {
	mdprintf(tag->sd, "%s: %s ERROR\n", tag->fname, cl_strerror(ret));
	logg("%s: %s ERROR\n", tag->fname, cl_strerror(ret));
    } else if(logok) {
	logg("%s: OK\n", tag->fname);
    }

    free(tag->fname);
    free(tag);
    return;
}

static int multiscan(const char *dirname, const struct cl_node *root, const struct cl_limits *limits, int options, const struct cfgstruct *copt, int odesc, unsigned int *reclev, threadpool_t *multi_pool)
{
	DIR *dd;
	struct dirent *dent;
#if defined(HAVE_READDIR_R_3) || defined(HAVE_READDIR_R_2)
	union {
	    struct dirent d;
	    char b[offsetof(struct dirent, d_name) + NAME_MAX + 1];
	} result;
#endif
	struct stat statbuf;
	char *fname;
	int scanret = 0;
	unsigned int maxdirrec = 0;
	struct multi_tag *scandata;


    maxdirrec = cfgopt(copt, "MaxDirectoryRecursion")->numarg;
    if(maxdirrec) {
	if(*reclev > maxdirrec) {
	    logg("*multiscan: Directory recursion limit exceeded at %s\n", dirname);
	    return 0;
	}
	(*reclev)++;
    }

    if((dd = opendir(dirname)) != NULL) {
#ifdef HAVE_READDIR_R_3
	while(!readdir_r(dd, &result.d, &dent) && dent) {
#elif defined(HAVE_READDIR_R_2)
	while((dent = (struct dirent *) readdir_r(dd, &result.d))) {
#else
	while((dent = readdir(dd))) {
#endif
	    if (!is_fd_connected(odesc)) {
		logg("multiscan: Client disconnected\n");
		closedir(dd);
		return -1;
	    }

	    if(progexit) {
		closedir(dd);
		return -1;
	    }

#if	(!defined(C_INTERIX)) && (!defined(C_WINDOWS)) && (!defined(C_CYGWIN))
	    if(dent->d_ino)
#endif
	    {
		if(strcmp(dent->d_name, ".") && strcmp(dent->d_name, "..")) {
		    /* build the full name */
		    fname = (char *) mcalloc(strlen(dirname) + strlen(dent->d_name) + 2, sizeof(char));
		    if(!fname) {
			logg("!multiscan: Can't allocate memory for fname\n");
			closedir(dd);
			return -1;
		    }
		    sprintf(fname, "%s/%s", dirname, dent->d_name);

		    /* stat the file */
		    if(lstat(fname, &statbuf) != -1) {
			if((S_ISDIR(statbuf.st_mode) && !S_ISLNK(statbuf.st_mode)) || (S_ISLNK(statbuf.st_mode) && (checksymlink(fname) == 1) && cfgopt(copt, "FollowDirectorySymlinks")->enabled)) {
			    if(multiscan(fname, root, limits, options, copt, odesc, reclev, multi_pool) == -1) {
				free(fname);
				closedir(dd);
				return -1;
			    }
			    free(fname);
			} else {
			    if(S_ISREG(statbuf.st_mode) || (S_ISLNK(statbuf.st_mode) && (checksymlink(fname) == 2) && cfgopt(copt, "FollowFileSymlinks")->enabled)) {

#ifdef C_LINUX
				if(procdev && (statbuf.st_dev == procdev))
				    scanret = CL_CLEAN;
				else
#endif
				{
				    scandata = (struct multi_tag *) mmalloc(sizeof(struct multi_tag));
				    if(!scandata) {
					logg("!multiscan: Can't allocate memory for scandata\n");
					free(fname);
					closedir(dd);
					return -1;
				    }
				    scandata->sd = odesc;
				    scandata->options = options;
				    scandata->copt = copt;
				    scandata->fname = fname;
				    scandata->root = root;
				    scandata->limits = limits;
				    if(!thrmgr_dispatch(multi_pool, scandata)) {
					logg("!multiscan: thread dispatch failed for multi_pool (file %s)\n", fname);
					mdprintf(odesc, "ERROR: Can't scan file %s\n", fname);
					free(fname);
					free(scandata);
					closedir(dd);
					return -1;
				    }

				    while(!multi_pool->thr_idle) /* non-critical */
#ifdef C_WINDOWS
					Sleep(1);
#else
					usleep(200);
#endif
				}
			    }
			}
		    } else {
			free(fname);
		    }
		}
	    }
	}
	closedir(dd);
    } else {
	return -2;
    }

    (*reclev)--;
    return 0;
}

int command(int desc, const struct cl_node *root, const struct cl_limits *limits, int options, const struct cfgstruct *copt, int timeout)
{
	char buff[1025];
	int bread, opt;


    bread = readsock(desc, buff, sizeof(buff)-1, '\n', timeout, 0, 1);
    if(bread == -2) /* timeout */
	return -2;
    if(bread == 0) /* Connection closed */
	return -1;
    if(bread < 0) {
	mdprintf(desc, "ERROR\n");
	logg("!Command: readsock() failed.\n");
	return -1;
    }

    buff[bread] = 0;
    cli_chomp(buff);

    if(!strncmp(buff, CMD1, strlen(CMD1))) { /* SCAN */
	if(scan(buff + strlen(CMD1) + 1, NULL, root, limits, options, copt, desc, 0) == -2)
	    if(cfgopt(copt, "ExitOnOOM")->enabled)
		return COMMAND_SHUTDOWN;

    } else if(!strncmp(buff, CMD2, strlen(CMD2))) { /* RAWSCAN */
	opt = options & ~CL_SCAN_ARCHIVE;
	if(scan(buff + strlen(CMD2) + 1, NULL, root, NULL, opt, copt, desc, 0) == -2)
	    if(cfgopt(copt, "ExitOnOOM")->enabled)
		return COMMAND_SHUTDOWN;

    } else if(!strncmp(buff, CMD3, strlen(CMD3))) { /* QUIT */
	return COMMAND_SHUTDOWN;

    } else if(!strncmp(buff, CMD4, strlen(CMD4))) { /* RELOAD */
	mdprintf(desc, "RELOADING\n");
	return COMMAND_RELOAD;

    } else if(!strncmp(buff, CMD5, strlen(CMD5))) { /* PING */
	mdprintf(desc, "PONG\n");

    } else if(!strncmp(buff, CMD6, strlen(CMD6))) { /* CONTSCAN */
	if(scan(buff + strlen(CMD6) + 1, NULL, root, limits, options, copt, desc, 1) == -2)
	    if(cfgopt(copt, "ExitOnOOM")->enabled)
		return COMMAND_SHUTDOWN;

    } else if(!strncmp(buff, CMD7, strlen(CMD7))) { /* VERSION */
	    const char *dbdir = cfgopt(copt, "DatabaseDirectory")->strarg;
	    char *path;
	    struct cl_cvd *daily;
	    struct stat foo;


	if(!(path = mmalloc(strlen(dbdir) + 30))) {
	    mdprintf(desc, "Memory allocation error - SHUTDOWN forced\n");
	    return COMMAND_SHUTDOWN;
	}

	sprintf(path, "%s/daily.cvd", dbdir);
	if(stat(path, &foo) == -1)
	    sprintf(path, "%s/daily.inc/daily.info", dbdir);

	if((daily = cl_cvdhead(path))) {
		time_t t = (time_t) daily->stime;

	    pthread_mutex_lock(&ctime_mutex);
	    mdprintf(desc, "ClamAV "VERSION"/%d/%s", daily->version, ctime(&t));
	    pthread_mutex_unlock(&ctime_mutex);
	    cl_cvdfree(daily);
	} else {
	    mdprintf(desc, "ClamAV "VERSION"\n");
	}

	free(path);

    } else if(!strncmp(buff, CMD8, strlen(CMD8))) { /* STREAM */
	if(scanstream(desc, NULL, root, limits, options, copt) == CL_EMEM)
	    if(cfgopt(copt, "ExitOnOOM")->enabled)
		return COMMAND_SHUTDOWN;

    } else if(!strncmp(buff, CMD9, strlen(CMD9))) { /* SESSION */
	return COMMAND_SESSION;

    } else if(!strncmp(buff, CMD10, strlen(CMD10))) { /* END */
	return COMMAND_END;

    } else if(!strncmp(buff, CMD11, strlen(CMD11))) { /* SHUTDOWN */
	return COMMAND_SHUTDOWN;

    } else if(!strncmp(buff, CMD12, strlen(CMD12))) { /* FD */
	    int fd = atoi(buff + strlen(CMD12) + 1);

	scanfd(fd, NULL, root, limits, options, copt, desc);
	close(fd); /* FIXME: should we close it here? */

    } else if(!strncmp(buff, CMD13, strlen(CMD13))) { /* MULTISCAN */
	    threadpool_t *multi_pool;
	    int idletimeout = cfgopt(copt, "IdleTimeout")->numarg;
	    int max_threads = cfgopt(copt, "MaxThreads")->numarg;
	    int ret;
	    unsigned int reclev = 0;
	    const char *path = buff + strlen(CMD13) + 1;
	    const char *virname;
	    struct stat sb;

	if(stat(path, &sb) == -1) {
	    mdprintf(desc, "Can't stat file %s\n", path);
	    return -1;
	}

	if(S_ISDIR(sb.st_mode)) {
	    if((multi_pool = thrmgr_new(max_threads, idletimeout, multiscanfile)) == NULL) {
		logg("!thrmgr_new failed for multi_pool\n");
		mdprintf(desc, "ERROR: thrmgr_new failed for multi_pool\n");
		return -1;
	    }

	    ret = multiscan(path, root, limits, options, copt, desc, &reclev, multi_pool);
	    thrmgr_destroy(multi_pool);

	    if(ret < 0)
		return -1;

	} else {
	    ret = cl_scanfile(path, &virname, NULL, root, limits, options);

	    if(ret == CL_VIRUS) {
		mdprintf(desc, "%s: %s FOUND\n", path, virname);
		logg("%s: %s FOUND\n", path, virname);
		virusaction(path, virname, copt);
	    } else if(ret != CL_CLEAN) {
		mdprintf(desc, "%s: %s ERROR\n", path, cl_strerror(ret));
		logg("%s: %s ERROR\n", path, cl_strerror(ret));
	    } else {
		mdprintf(desc, "%s: OK\n", path); 
		if(logok)
		    logg("%s: OK\n", path);
	    }
	}

    } else {
	mdprintf(desc, "UNKNOWN COMMAND\n");
    }

    return 0; /* no error and no 'special' command executed */
}

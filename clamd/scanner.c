/*
 *  Copyright (C) 2002 - 2007 Tomasz Kojm <tkojm@clamav.net>
 *  MULTISCAN code (C) 2006 Sensory Networks, Inc.
 *  Written by Tomasz Kojm
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
#ifdef	HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#ifndef	C_WINDOWS
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/param.h>
#include <signal.h>
#include <dirent.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#endif
#include <pthread.h>

#if defined(HAVE_READDIR_R_3) || defined(HAVE_READDIR_R_2)
#include <limits.h>
#include <stddef.h>
#endif

#include "libclamav/clamav.h"
#include "libclamav/others.h"

#include "shared/cfgparser.h"
#include "shared/output.h"
#include "shared/misc.h"

#include "others.h"
#include "scanner.h"
#include "shared.h"
#include "network.h"
#include "thrmgr.h"

#ifdef C_LINUX
dev_t procdev; /* /proc device */
#endif

extern int progexit;

#ifndef	C_WINDOWS
#define	closesocket(s)	close(s)
#endif

struct multi_tag {
    int sd;
    unsigned int options;
    const struct cfgstruct *copt;
    char *fname;
    const struct cl_engine *engine;
    const struct cl_limits *limits;
};

static int checksymlink(const char *path)
{
	struct stat statbuf;

    if(stat(path, &statbuf) == -1)
	return -1;

    if(S_ISDIR(statbuf.st_mode))
	return 1;

    if(S_ISREG(statbuf.st_mode))
	return 2;

    return 0;
}

static int dirscan(const char *dirname, const char **virname, unsigned long int *scanned, const struct cl_engine *engine, const struct cl_limits *limits, unsigned int options, const struct cfgstruct *copt, int odesc, unsigned int *reclev, unsigned int type, threadpool_t *multi_pool)
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
	int ret = 0, scanret = 0;
	unsigned int maxdirrec = 0;
	struct multi_tag *scandata;
	const struct cfgstruct *cpt;


    if((cpt = cfgopt(copt, "ExcludePath"))->enabled) {
	while(cpt) {
	    if(match_regex(dirname, cpt->strarg) == 1) {
		mdprintf(odesc, "%s: Excluded\n", dirname);
		return 0;
	    }
	    cpt = (struct cfgstruct *) cpt->nextarg;
	}
    }

    maxdirrec = cfgopt(copt, "MaxDirectoryRecursion")->numarg;
    if(maxdirrec) {
	if(*reclev > maxdirrec) {
	    logg("*Directory recursion limit exceeded at %s\n", dirname);
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
		logg("Client disconnected\n");
		closedir(dd);
		return 1;
	    }

            if(progexit) {
		closedir(dd);
		return 1;
	    }

#if	(!defined(C_INTERIX)) && (!defined(C_WINDOWS))
	    if(dent->d_ino)
#endif
	    {
		if(strcmp(dent->d_name, ".") && strcmp(dent->d_name, "..")) {
		    /* build the full name */
		    fname = (char *) malloc(strlen(dirname) + strlen(dent->d_name) + 2);
                    if(!fname) {
			logg("!Can't allocate memory for fname\n");
			closedir(dd);
			return -2;
		    }
		    sprintf(fname, "%s/%s", dirname, dent->d_name);

		    /* stat the file */
		    if(lstat(fname, &statbuf) != -1) {
			if((S_ISDIR(statbuf.st_mode) && !S_ISLNK(statbuf.st_mode)) || (S_ISLNK(statbuf.st_mode) && (checksymlink(fname) == 1) && cfgopt(copt, "FollowDirectorySymlinks")->enabled)) {
			    if(dirscan(fname, virname, scanned, engine, limits, options, copt, odesc, reclev, type, multi_pool) == 1) {
				free(fname);
				closedir(dd);
				return 1;
			    }
			    free(fname);
			} else {
			    if(S_ISREG(statbuf.st_mode) || (S_ISLNK(statbuf.st_mode) && (checksymlink(fname) == 2) && cfgopt(copt, "FollowFileSymlinks")->enabled)) {

#ifdef C_LINUX
				if(procdev && (statbuf.st_dev == procdev))
				    free(fname);
				else
#endif
				{
				    if(type == TYPE_MULTISCAN) {

					scandata = (struct multi_tag *) malloc(sizeof(struct multi_tag));
					if(!scandata) {
					    logg("!Can't allocate memory for scandata\n");
					    free(fname);
					    closedir(dd);
					    return -2;
					}
					scandata->sd = odesc;
					scandata->options = options;
					scandata->copt = copt;
					scandata->fname = fname;
					scandata->engine = engine;
					scandata->limits = limits;
					if(!thrmgr_dispatch(multi_pool, scandata)) {
					    logg("!thread dispatch failed for multi_pool (file %s)\n", fname);
					    mdprintf(odesc, "ERROR: Can't scan file %s\n", fname);
					    free(fname);
					    free(scandata);
					    closedir(dd);
					    return 1;
					}

					pthread_mutex_lock(&multi_pool->pool_mutex);
					while(!multi_pool->thr_idle) /* non-critical */ {
						pthread_cond_wait(&multi_pool->idle_cond, &multi_pool->pool_mutex);
					}
					pthread_mutex_unlock(&multi_pool->pool_mutex);

				    } else { /* CONTSCAN, SCAN */

					scanret = cl_scanfile(fname, virname, scanned, engine, limits, options);

					if(scanret == CL_VIRUS) {

					    mdprintf(odesc, "%s: %s FOUND\n", fname, *virname);
					    logg("~%s: %s FOUND\n", fname, *virname);
					    virusaction(fname, *virname, copt);
					    if(type == TYPE_SCAN) {
						closedir(dd);
						free(fname);
						return 1;
					    } else /* CONTSCAN */
						ret = 2;

					} else if(scanret != CL_CLEAN) {
					    mdprintf(odesc, "%s: %s ERROR\n", fname, cl_strerror(scanret));
					    logg("~%s: %s ERROR\n", fname, cl_strerror(scanret));
					    if(scanret == CL_EMEM) {
						closedir(dd);
						free(fname);
						return -2;
					    }

					} else if(logok) {
					    logg("~%s: OK\n", fname);
					}
					free(fname);
				    }
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
	return -1;
    }

    (*reclev)--;
    return ret;
}

static void multiscanfile(void *arg)
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

    ret = cl_scanfile(tag->fname, &virname, NULL, tag->engine, tag->limits, tag->options);

    if(ret == CL_VIRUS) {
	mdprintf(tag->sd, "%s: %s FOUND\n", tag->fname, virname);
	logg("~%s: %s FOUND\n", tag->fname, virname);
	virusaction(tag->fname, virname, tag->copt);
    } else if(ret != CL_CLEAN) {
	mdprintf(tag->sd, "%s: %s ERROR\n", tag->fname, cl_strerror(ret));
	logg("~%s: %s ERROR\n", tag->fname, cl_strerror(ret));
    } else if(logok) {
	logg("~%s: OK\n", tag->fname);
    }

    free(tag->fname);
    free(tag);
    return;
}

int scan(const char *filename, unsigned long int *scanned, const struct cl_engine *engine, const struct cl_limits *limits, unsigned int options, const struct cfgstruct *copt, int odesc, unsigned int type)
{
	struct stat sb;
	int ret = 0;
	unsigned int reclev = 0;
	const char *virname;
	const struct cfgstruct *cpt;
	threadpool_t *multi_pool = NULL;


    /* stat file */
    if(lstat(filename, &sb) == -1) {
	mdprintf(odesc, "%s: lstat() failed. ERROR\n", filename);
	return -1;
    }

    /* check permissions  */
    if(access(filename, R_OK)) {
	mdprintf(odesc, "%s: Access denied. ERROR\n", filename);
	return -1;
    }

    if((cpt = cfgopt(copt, "ExcludePath"))->enabled) {
	if(match_regex(filename, cpt->strarg) == 1) {
	    mdprintf(odesc, "%s: Excluded\n", filename);
	    return 0;
	}
    }

    switch(sb.st_mode & S_IFMT) {
#ifdef	S_IFLNK
	case S_IFLNK:
	    if(!cfgopt(copt, "FollowFileSymlinks")->enabled)
		break;
	    /* else go to the next case */
#endif
	case S_IFREG: 
	    if(sb.st_size == 0) { /* empty file */
		mdprintf(odesc, "%s: Empty file\n", filename);
		return 0;
	    }
#ifdef C_LINUX
	    if(procdev && (sb.st_dev == procdev))
		ret = CL_CLEAN;
	    else
#endif
		ret = cl_scanfile(filename, &virname, scanned, engine, limits, options);

	    if(ret == CL_VIRUS) {
		mdprintf(odesc, "%s: %s FOUND\n", filename, virname);
		logg("~%s: %s FOUND\n", filename, virname);
		virusaction(filename, virname, copt);
	    } else if(ret != CL_CLEAN) {
		mdprintf(odesc, "%s: %s ERROR\n", filename, cl_strerror(ret));
		logg("~%s: %s ERROR\n", filename, cl_strerror(ret));
		if(ret == CL_EMEM)
		    return -2;
	    } else if (logok) {
		logg("~%s: OK\n", filename);
	    }
	    break;
	case S_IFDIR:
	    if(type == TYPE_MULTISCAN) {
		    int idletimeout = cfgopt(copt, "IdleTimeout")->numarg;
		    int max_threads = cfgopt(copt, "MaxThreads")->numarg;

		if((multi_pool = thrmgr_new(max_threads, idletimeout, multiscanfile)) == NULL) {
		    logg("!thrmgr_new failed for multi_pool\n");
		    mdprintf(odesc, "thrmgr_new failed for multi_pool ERROR\n");
		    return -1;
		}
	    }

	    ret = dirscan(filename, &virname, scanned, engine, limits, options, copt, odesc, &reclev, type, multi_pool);

	    if(multi_pool)
		thrmgr_destroy(multi_pool);

	    break;
	default:
	    mdprintf(odesc, "%s: Not supported file type. ERROR\n", filename);
	    return -1;
    }

    if(!ret)
	mdprintf(odesc, "%s: OK\n", filename);

    /* mdprintf(odesc, "\n"); */ /* Terminate response with a blank line boundary */
    return ret;
}

/*
 * This function was readded by mbalmer@openbsd.org.  That is the reason
 * why it is so nicely formatted.
 */
int scanfd(const int fd, unsigned long int *scanned,
    const struct cl_engine *engine, const struct cl_limits *limits,
    unsigned int options, const struct cfgstruct *copt, int odesc)  
{
	int ret;
	const char *virname;
	struct stat statbuf;
	char fdstr[32];


	if(fstat(fd, &statbuf) == -1)
		return -1;

	if(!S_ISREG(statbuf.st_mode))
		return -1;

	snprintf(fdstr, sizeof(fdstr), "fd[%d]", fd);

	ret = cl_scandesc(fd, &virname, scanned, engine, limits, options);

	if(ret == CL_VIRUS) {
	mdprintf(odesc, "%s: %s FOUND\n", fdstr, virname);
		logg("%s: %s FOUND\n", fdstr, virname);
		virusaction(fdstr, virname, copt);
	} else if(ret != CL_CLEAN) {
		mdprintf(odesc, "%s: %s ERROR\n", fdstr, cl_strerror(ret));
		logg("%s: %s ERROR\n", fdstr, cl_strerror(ret));
	} else {
		mdprintf(odesc, "%s: OK\n", fdstr);
		if(logok)
			logg("%s: OK\n", fdstr);
	}
	return ret;
}

int scanstream(int odesc, unsigned long int *scanned, const struct cl_engine *engine, const struct cl_limits *limits, unsigned int options, const struct cfgstruct *copt)
{
	int ret, sockfd, acceptd;
	int tmpd, bread, retval, timeout, btread;
	unsigned int port = 0, portscan = 1000, min_port, max_port;
	unsigned long int size = 0, maxsize = 0;
	short bound = 0, rnd_port_first = 1;
	const char *virname;
	char buff[FILEBUFF];
	char peer_addr[32];
	struct sockaddr_in server;
	struct sockaddr_in peer;
	socklen_t addrlen;
	struct hostent he;
	const struct cfgstruct *cpt;
	char *tmpname;


    /* get min port */
    min_port = cfgopt(copt, "StreamMinPort")->numarg;
    if(min_port < 1024 || min_port > 65535)
	min_port = 1024;

    /* get max port */
    max_port = cfgopt(copt, "StreamMaxPort")->numarg;
    if(max_port < min_port || max_port > 65535)
	max_port = 65535;

    /* bind to a free port */
    while(!bound && --portscan) {
	if(rnd_port_first) {
	    /* try a random port first */
	    port = min_port + cli_rndnum(max_port - min_port);
	    rnd_port_first = 0;
	} else {
	    /* try the neighbor ports */
	    if(--port < min_port)
		port=max_port;
	}

	memset((char *) &server, 0, sizeof(server));
	server.sin_family = AF_INET;
	server.sin_port = htons(port);

	if((cpt = cfgopt(copt, "TCPAddr"))->enabled) {
	    if(r_gethostbyname(cpt->strarg, &he, buff, sizeof(buff)) == -1) {
		logg("!r_gethostbyname(%s) error: %s\n", cpt->strarg, strerror(errno));
		mdprintf(odesc, "r_gethostbyname(%s) ERROR\n", cpt->strarg);
		return -1;
	    }
	    server.sin_addr = *(struct in_addr *) he.h_addr_list[0];
	} else
	    server.sin_addr.s_addr = INADDR_ANY;

	if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
	    continue;

	if(bind(sockfd, (struct sockaddr *) &server, sizeof(struct sockaddr_in)) == -1)
	    closesocket(sockfd);
	else
	    bound = 1;
    }

    timeout = cfgopt(copt, "ReadTimeout")->numarg;
    if(timeout == 0)
    	timeout = -1;

    if(!bound && !portscan) {
	logg("!ScanStream: Can't find any free port.\n");
	mdprintf(odesc, "Can't find any free port. ERROR\n");
	closesocket(sockfd);
	return -1;
    } else {
	listen(sockfd, 1);
	if(mdprintf(odesc, "PORT %u\n", port) <= 0) {
	    logg("!ScanStream: error transmitting port.\n");
	    closesocket(sockfd);
	    return -1;
	}
    }

    switch(retval = poll_fd(sockfd, timeout, 0)) {
	case 0: /* timeout */
	    mdprintf(odesc, "Accept timeout. ERROR\n");
	    logg("!ScanStream %u: accept timeout.\n", port);
	    closesocket(sockfd);
	    return -1;
	case -1:
	    mdprintf(odesc, "Accept poll. ERROR\n");
	    logg("!ScanStream %u: accept poll failed.\n", port);
	    closesocket(sockfd);
	    return -1;
    }

    addrlen = sizeof(peer);
    if((acceptd = accept(sockfd, (struct sockaddr *) &peer, &addrlen)) == -1) {
	closesocket(sockfd);
	mdprintf(odesc, "accept() ERROR\n");
	logg("!ScanStream %u: accept() failed.\n", port);
	return -1;
    }

    snprintf(peer_addr, sizeof(peer_addr), "%s", inet_ntoa(peer.sin_addr));
    logg("*Accepted connection from %s on port %u, fd %d\n", peer_addr, port, acceptd);

    if(cli_gentempfd(NULL, &tmpname, &tmpd)) {
	shutdown(sockfd, 2);
	closesocket(sockfd);
	closesocket(acceptd);
	mdprintf(odesc, "cli_gentempfd() failed. ERROR\n");
	logg("!ScanStream(%s@%u): Can't create temporary file.\n", peer_addr, port);
	return -1;
    }

    maxsize = cfgopt(copt, "StreamMaxLength")->numarg;

    btread = sizeof(buff);

    while((retval = poll_fd(acceptd, timeout, 0)) == 1) {
	bread = recv(acceptd, buff, btread, 0);
	if(bread <= 0)
	    break;
	size += bread;

	if(writen(tmpd, buff, bread) != bread) {
	    shutdown(sockfd, 2);
	    closesocket(sockfd);
	    closesocket(acceptd);
	    mdprintf(odesc, "Temporary file -> write ERROR\n");
	    logg("!ScanStream(%s@%u): Can't write to temporary file.\n", peer_addr, port);
	    close(tmpd);
	    if(!cfgopt(copt, "LeaveTemporaryFiles")->enabled)
		unlink(tmpname);
	    free(tmpname);
	    return -1;
	}

	if(maxsize && (size + btread >= maxsize)) {
	    btread = (maxsize - size); /* only read up to max */

	    if(btread <= 0) {
		logg("^ScanStream(%s@%u): Size limit reached (max: %lu)\n", peer_addr, port, maxsize);
	    	break; /* Scan what we have */
	    }
	}
    }

    switch(retval) {
	case 0: /* timeout */
	    mdprintf(odesc, "read timeout ERROR\n");
	    logg("!ScanStream(%s@%u): read timeout.\n", peer_addr, port);
	    break;
	case -1:
	    mdprintf(odesc, "read poll ERROR\n");
	    logg("!ScanStream(%s@%u): read poll failed.\n", peer_addr, port);
	    break;
    }

    if(retval == 1) {
	lseek(tmpd, 0, SEEK_SET);
	ret = cl_scandesc(tmpd, &virname, scanned, engine, limits, options);
    } else {
    	ret = -1;
    }
    close(tmpd);
    if(!cfgopt(copt, "LeaveTemporaryFiles")->enabled)
	unlink(tmpname);
    free(tmpname);

    closesocket(acceptd);
    closesocket(sockfd);

    if(ret == CL_VIRUS) {
	mdprintf(odesc, "stream: %s FOUND\n", virname);
	logg("stream(%s@%u): %s FOUND\n", peer_addr, port, virname);
	virusaction("stream", virname, copt);
    } else if(ret != CL_CLEAN) {
    	if(retval == 1) {
	    mdprintf(odesc, "stream: %s ERROR\n", cl_strerror(ret));
	    logg("stream(%s@%u): %s ERROR\n", peer_addr, port, cl_strerror(ret));
	}
    } else {
	mdprintf(odesc, "stream: OK\n");
        if(logok)
	    logg("stream(%s@%u): OK\n", peer_addr, port); 
    }

    return ret;
}

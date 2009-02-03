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

#include "shared/optparser.h"
#include "shared/output.h"
#include "shared/misc.h"

#include "others.h"
#include "scanner.h"
#include "shared.h"
#include "network.h"
#include "thrmgr.h"
#include "server.h"

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
    const struct optstruct *opts;
    char *fname;
    const struct cl_engine *engine;
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

static int dirscan(const char *dirname, const char term, const char **virname, unsigned long int *scanned, const struct cl_engine *engine, unsigned int options, const struct optstruct *opts, int odesc, unsigned int *reclev, unsigned int type, threadpool_t *multi_pool)
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
	const struct optstruct *opt;


    if((opt = optget(opts, "ExcludePath"))->enabled) {
	while(opt) {
	    if(match_regex(dirname, opt->strarg) == 1) {
		mdprintf(odesc, "%s: Excluded%c", dirname, term);
		return 0;
	    }
	    opt = (struct optstruct *) opt->nextarg;
	}
    }

    maxdirrec = optget(opts, "MaxDirectoryRecursion")->numarg;
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
			if((S_ISDIR(statbuf.st_mode) && !S_ISLNK(statbuf.st_mode)) || (S_ISLNK(statbuf.st_mode) && (checksymlink(fname) == 1) && optget(opts, "FollowDirectorySymlinks")->enabled)) {
			    if(dirscan(fname, term, virname, scanned, engine, options, opts, odesc, reclev, type, multi_pool) == 1) {
				free(fname);
				closedir(dd);
				return 1;
			    }
			    free(fname);
			} else {
			    if(S_ISREG(statbuf.st_mode) || (S_ISLNK(statbuf.st_mode) && (checksymlink(fname) == 2) && optget(opts, "FollowFileSymlinks")->enabled)) {

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
					scandata->opts = opts;
					scandata->fname = fname;
					scandata->engine = engine;
					if(!thrmgr_dispatch(multi_pool, scandata)) {
					    logg("!thread dispatch failed for multi_pool (file %s)\n", fname);
					    mdprintf(odesc, "ERROR: Can't scan file %s%c", fname, term);
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
					thrmgr_setactivetask(fname, NULL);
					scanret = cl_scanfile(fname, virname, scanned, engine, options);
					thrmgr_setactivetask(NULL, NULL);

					if(scanret == CL_VIRUS) {

					    mdprintf(odesc, "%s: %s FOUND%c", fname, *virname, term);
					    logg("~%s: %s FOUND\n", fname, *virname);
					    virusaction(fname, *virname, opts);
					    if(type == TYPE_SCAN) {
						closedir(dd);
						free(fname);
						return 1;
					    } else /* CONTSCAN */
						ret = 2;

					} else if(scanret != CL_CLEAN) {
					    mdprintf(odesc, "%s: %s ERROR%c", fname, cl_strerror(scanret), term);
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
			    } else {
				    free(fname);
			    }
			}
		    } else {
			logg("^lstat failed on %s: %s\n", fname, strerror(errno)); 
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

    thrmgr_setactivetask(tag->fname, "MULTISCANFILE");
    ret = cl_scanfile(tag->fname, &virname, NULL, tag->engine, tag->options);
    thrmgr_setactivetask(NULL, NULL);

    if(ret == CL_VIRUS) {
	mdprintf(tag->sd, "%s: %s FOUND\n", tag->fname, virname);
	logg("~%s: %s FOUND\n", tag->fname, virname);
	virusaction(tag->fname, virname, tag->opts);
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

extern time_t reloaded_time;
#define BUFFSIZE 1024
int scan_callback(struct stat *sb, char *filename, const char *msg, enum cli_ftw_reason reason, struct cli_ftw_cbdata *data)
{
    struct scan_cb_data *scandata = data->data;
    const char *virname;
    char buf[BUFFSIZE];
    int ret;
    int type = scandata->type;
    const struct optstruct *opt;

    buf[0] = '\0';
#ifdef HAVE_STRERROR_R
    if (reason == error_mem || reason == error_stat) {
	buf[0]=':';
	buf[1]=' ';
	strerror_r(errno, buf+2, BUFFSIZE-2);
    }
#endif

    switch (reason) {
	case error_mem:
	    logg("!Memory allocation failed during cli_ftw()%s%s\n",
		 msg ? msg : "", buf);
	    scandata->errors++;
	    return CL_EMEM;
	case error_stat:
	    if (type != TYPE_MULTISCAN)
		mdprintf(scandata->odesc, "%s: lstat() failed %s. ERROR%c",
		     msg, buf, scandata->term);
	    scandata->errors++;
	    return CL_SUCCESS;
	case warning_skipped_dir:
	    if (type != TYPE_MULTISCAN)
		logg("^Directory recursion limit reached, skipping %s%s\n",
		     msg, buf);
	    return CL_SUCCESS;
	case warning_skipped_special:
	    if (type != TYPE_MULTISCAN)
		mdprintf(scandata->odesc,
			 "%s: Not supported file type. ERROR%c", msg,
			 scandata->term);
	    return CL_SUCCESS;
	case visit_directory_toplev:
	    return CL_SUCCESS;
	case visit_file:
	    break;
    }

    /* check whether the file is excluded */
#ifdef C_LINUX
    if(procdev && (sb->st_dev == procdev))
	return CL_SUCCESS;
#endif
    if((opt = optget(scandata->opts, "ExcludePath"))->enabled) {
	/* TODO: perhaps multiscan should skip this check? 
	 * This should work unless the user is doing something stupid like
	 * MULTISCAN / */
	if(match_regex(filename, opt->strarg) == 1) {
	    if (type != TYPE_MULTISCAN)
		mdprintf(scandata->odesc, "%s: Excluded%c", filename, scandata->term);
	    return CL_SUCCESS;
	}
    }

    if(sb->st_size == 0) { /* empty file */
	if (type != TYPE_MULTISCAN)
	    mdprintf(scandata->odesc, "%s: Empty file%c", filename, scandata->term);
	return CL_SUCCESS;
    }

    if (type == TYPE_MULTISCAN) {
	client_conn_t *client_conn = (client_conn_t *) malloc(sizeof(struct client_conn_tag));
	if(client_conn) {
	    client_conn->scanfd = -1;
	    client_conn->sd = scandata->odesc;
	    client_conn->fds = NULL;
	    client_conn->filename = filename;
	    client_conn->cmdtype = COMMAND_MULTISCANFILE;
	    client_conn->term = scandata->term;
	    client_conn->options = scandata->options;
	    client_conn->opts = scandata->opts;
	    client_conn->group = scandata->group;
	    if(cl_engine_addref(scandata->engine)) {
		logg("!cl_engine_addref() failed\n");
		return CL_EMEM;
	    } else {
		client_conn->engine = scandata->engine;
		client_conn->engine_timestamp = reloaded_time;
		if(!thrmgr_group_dispatch(scandata->thr_pool, scandata->group, client_conn)) {
		    logg("!thread dispatch failed\n");
		    return CL_EMEM;
		}
	    }
	} else {
	    logg("!Can't allocate memory for client_conn\n");
	    scandata->errors++;
	    return CL_EMEM;
	}
	return CL_SUCCESS;
    }

    if (access(filename, R_OK)) {
	mdprintf(scandata->odesc, "%s: Access denied. ERROR%c",
		 filename, scandata->term);
	scandata->errors++;
	return CL_SUCCESS;
    }

    thrmgr_setactivetask(filename,
			 type == TYPE_MULTISCAN ? "MULTISCANFILE" : NULL);
    ret = cl_scanfile(filename, &virname, &scandata->scanned, scandata->engine, scandata->options);
    thrmgr_setactivetask(NULL, NULL);

    if (ret == CL_VIRUS) {
	scandata->infected++;
	mdprintf(scandata->odesc, "%s: %s FOUND%c", filename, virname, scandata->term);
	logg("~%s: %s FOUND\n", filename, virname);
	virusaction(filename, virname, scandata->opts);
    } else if (ret != CL_CLEAN) {
	mdprintf(scandata->odesc, "%s: %s ERROR%c", filename, cl_strerror(ret), scandata->term);
	logg("~%s: %s ERROR\n", filename, cl_strerror(ret));
	if(ret == CL_EMEM) /* stop scanning */
	    return ret;
    } else if (logok) {
	logg("~%s: OK\n", filename);
    }
    /* TODO: CONTSCAN/SCAN logic of interpreting virus -> break/cont */
    return CL_SUCCESS;
}

int scan(const char *filename, const char term, unsigned long int *scanned, const struct cl_engine *engine, unsigned int options, const struct optstruct *opts, int odesc, unsigned int type)
{
	struct stat sb;
	int ret = 0;
	unsigned int reclev = 0;
	const char *virname;
	const struct optstruct *opt;
	threadpool_t *multi_pool = NULL;


    /* stat file */
    if(lstat(filename, &sb) == -1) {
	mdprintf(odesc, "%s: lstat() failed. ERROR%c", filename, term);
	return -1;
    }

    /* check permissions  */
    if(access(filename, R_OK)) {
	mdprintf(odesc, "%s: Access denied. ERROR%c", filename, term);
	return -1;
    }

    if((opt = optget(opts, "ExcludePath"))->enabled) {
	if(match_regex(filename, opt->strarg) == 1) {
	    mdprintf(odesc, "%s: Excluded%c", filename, term);
	    return 0;
	}
    }

    switch(sb.st_mode & S_IFMT) {
#ifdef	S_IFLNK
	case S_IFLNK:
	    if(!optget(opts, "FollowFileSymlinks")->enabled)
		break;
	    /* else go to the next case */
#endif
	case S_IFREG: 
	    if(sb.st_size == 0) { /* empty file */
		mdprintf(odesc, "%s: Empty file%c", filename, term);
		return 0;
	    }
#ifdef C_LINUX
	    if(procdev && (sb.st_dev == procdev))
		ret = CL_CLEAN;
	    else
#endif
	    {
		thrmgr_setactivetask(filename, NULL);
		ret = cl_scanfile(filename, &virname, scanned, engine, options);
		thrmgr_setactivetask(NULL, NULL);
	    }

	    if(ret == CL_VIRUS) {
		mdprintf(odesc, "%s: %s FOUND%c", filename, virname, term);
		logg("~%s: %s FOUND\n", filename, virname);
		virusaction(filename, virname, opts);
	    } else if(ret != CL_CLEAN) {
		mdprintf(odesc, "%s: %s ERROR%c", filename, cl_strerror(ret), term);
		logg("~%s: %s ERROR\n", filename, cl_strerror(ret));
		if(ret == CL_EMEM)
		    return -2;
	    } else if (logok) {
		logg("~%s: OK\n", filename);
	    }
	    break;
	case S_IFDIR:
	    if(type == TYPE_MULTISCAN) {
		    int idletimeout = optget(opts, "IdleTimeout")->numarg;
		    int max_threads = optget(opts, "MaxThreads")->numarg;

		if((multi_pool = thrmgr_new(max_threads, idletimeout, multiscanfile)) == NULL) {
		    logg("!thrmgr_new failed for multi_pool\n");
		    mdprintf(odesc, "thrmgr_new failed for multi_pool ERROR%c", term);
		    return -1;
		}
	    }

	    ret = dirscan(filename, term, &virname, scanned, engine, options, opts, odesc, &reclev, type, multi_pool);

	    if(multi_pool)
		thrmgr_destroy(multi_pool);

	    break;
	default:
	    mdprintf(odesc, "%s: Not supported file type. ERROR%c", filename, term);
	    return -1;
    }

    if(!ret)
	mdprintf(odesc, "%s: OK%c", filename, term);

    return ret;
}

/*
 * This function was readded by mbalmer@openbsd.org.  That is the reason
 * why it is so nicely formatted.
 */
int scanfd(const int fd, char term, unsigned long int *scanned,
    const struct cl_engine *engine,
    unsigned int options, const struct optstruct *opts, int odesc)
{
	int ret;
	const char *virname;
	struct stat statbuf;
	char fdstr[32];

	snprintf(fdstr, sizeof(fdstr), "fd[%d]", fd);
	if(fstat(fd, &statbuf) == -1 || !S_ISREG(statbuf.st_mode)) {
		mdprintf(odesc, "%s: Not a regular file. ERROR%c", fdstr, term);
		logg("%s: Not a regular file. ERROR\n", fdstr);
		return -1;
	}

	thrmgr_setactivetask(fdstr, NULL);
	ret = cl_scandesc(fd, &virname, scanned, engine, options);
	thrmgr_setactivetask(NULL, NULL);

	if(ret == CL_VIRUS) {
		mdprintf(odesc, "%s: %s FOUND%c", fdstr, virname, term);
		logg("%s: %s FOUND\n", fdstr, virname);
		virusaction(fdstr, virname, opts);
	} else if(ret != CL_CLEAN) {
		mdprintf(odesc, "%s: %s ERROR%c", fdstr, cl_strerror(ret), term);
		logg("%s: %s ERROR\n", fdstr, cl_strerror(ret));
	} else {
		mdprintf(odesc, "%s: OK%c", fdstr, term);
		if(logok)
			logg("%s: OK\n", fdstr);
	}
	return ret;
}

int scanstream(int odesc, unsigned long int *scanned, const struct cl_engine *engine, unsigned int options, const struct optstruct *opts, char term)
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
	const struct optstruct *opt;
	char *tmpname;


    /* get min port */
    min_port = optget(opts, "StreamMinPort")->numarg;
    if(min_port < 1024 || min_port > 65535)
	min_port = 1024;

    /* get max port */
    max_port = optget(opts, "StreamMaxPort")->numarg;
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
	server.sin_addr.s_addr = htonl(INADDR_ANY);

	if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
	    continue;

	if(bind(sockfd, (struct sockaddr *) &server, sizeof(struct sockaddr_in)) == -1)
	    closesocket(sockfd);
	else
	    bound = 1;
    }

    timeout = optget(opts, "ReadTimeout")->numarg;
    if(timeout == 0)
    	timeout = -1;

    if(!bound && !portscan) {
	logg("!ScanStream: Can't find any free port.\n");
	mdprintf(odesc, "Can't find any free port. ERROR%c", term);
	closesocket(sockfd);
	return -1;
    } else {
	listen(sockfd, 1);
	if(mdprintf(odesc, "PORT %u%c", port, term) <= 0) {
	    logg("!ScanStream: error transmitting port.\n");
	    closesocket(sockfd);
	    return -1;
	}
    }

    switch(retval = poll_fd(sockfd, timeout, 0)) {
	case 0: /* timeout */
	    mdprintf(odesc, "Accept timeout. ERROR%c", term);
	    logg("!ScanStream %u: accept timeout.\n", port);
	    closesocket(sockfd);
	    return -1;
	case -1:
	    mdprintf(odesc, "Accept poll. ERROR%c", term);
	    logg("!ScanStream %u: accept poll failed.\n", port);
	    closesocket(sockfd);
	    return -1;
    }

    addrlen = sizeof(peer);
    if((acceptd = accept(sockfd, (struct sockaddr *) &peer, &addrlen)) == -1) {
	closesocket(sockfd);
	mdprintf(odesc, "accept() ERROR%c", term);
	logg("!ScanStream %u: accept() failed.\n", port);
	return -1;
    }

    snprintf(peer_addr, sizeof(peer_addr), "%s", inet_ntoa(peer.sin_addr));
    logg("*Accepted connection from %s on port %u, fd %d\n", peer_addr, port, acceptd);

    if(cli_gentempfd(optget(opts, "TemporaryDirectory")->strarg, &tmpname, &tmpd)) {
	shutdown(sockfd, 2);
	closesocket(sockfd);
	closesocket(acceptd);
	mdprintf(odesc, "cli_gentempfd() failed. ERROR%c", term);
	logg("!ScanStream(%s@%u): Can't create temporary file.\n", peer_addr, port);
	return -1;
    }

    maxsize = optget(opts, "StreamMaxLength")->numarg;

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
	    mdprintf(odesc, "Temporary file -> write ERROR%c", term);
	    logg("!ScanStream(%s@%u): Can't write to temporary file.\n", peer_addr, port);
	    close(tmpd);
	    if(!optget(opts, "LeaveTemporaryFiles")->enabled)
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
	    mdprintf(odesc, "read timeout ERROR%c", term);
	    logg("!ScanStream(%s@%u): read timeout.\n", peer_addr, port);
	    break;
	case -1:
	    mdprintf(odesc, "read poll ERROR%c", term);
	    logg("!ScanStream(%s@%u): read poll failed.\n", peer_addr, port);
	    break;
    }

    if(retval == 1) {
	lseek(tmpd, 0, SEEK_SET);
	thrmgr_setactivetask(peer_addr, NULL);
	ret = cl_scandesc(tmpd, &virname, scanned, engine, options);
	thrmgr_setactivetask(NULL, NULL);
    } else {
    	ret = -1;
    }
    close(tmpd);
    if(!optget(opts, "LeaveTemporaryFiles")->enabled)
	unlink(tmpname);
    free(tmpname);

    closesocket(acceptd);
    closesocket(sockfd);

    if(ret == CL_VIRUS) {
	mdprintf(odesc, "stream: %s FOUND%c", virname, term);
	logg("stream(%s@%u): %s FOUND\n", peer_addr, port, virname);
	virusaction("stream", virname, opts);
    } else if(ret != CL_CLEAN) {
    	if(retval == 1) {
	    mdprintf(odesc, "stream: %s ERROR%c", cl_strerror(ret), term);
	    logg("stream(%s@%u): %s ERROR\n", peer_addr, port, cl_strerror(ret));
	}
    } else {
	mdprintf(odesc, "stream: OK%c", term);
        if(logok)
	    logg("stream(%s@%u): OK\n", peer_addr, port); 
    }

    return ret;
}

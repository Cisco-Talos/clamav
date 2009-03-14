/*
 *  Copyright (C) 2007-2009 Sourcefire, Inc.
 *
 *  Authors: Tomasz Kojm, Török Edvin
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

#ifndef	C_WINDOWS
#define	closesocket(s)	close(s)
#endif

extern int progexit;
extern time_t reloaded_time;
extern pthread_mutex_t reload_mutex;

#define BUFFSIZE 1024
int scan_callback(struct stat *sb, char *filename, const char *msg, enum cli_ftw_reason reason, struct cli_ftw_cbdata *data)
{
    struct scan_cb_data *scandata = data->data;
    const char *virname;
    int ret;
    int type = scandata->type;
    const struct optstruct *opt;

    /* detect disconnected socket, 
     * this should NOT detect half-shutdown sockets (SHUT_WR) */
    if (send(scandata->conn->sd, &ret, 0, 0) == -1 && errno != EINTR) {
	logg("$Client disconnected while command was active!\n");
	thrmgr_group_terminate(scandata->conn->group);
	return CL_BREAK;
    }

    if (thrmgr_group_need_terminate(scandata->conn->group)) {
	logg("^Client disconnected while scanjob was active\n");
	if (reason == visit_file)
	    free(filename);
	return CL_BREAK;
    }
    scandata->total++;
    switch (reason) {
	case error_mem:
	    if (msg)
		logg("!Memory allocation failed during cli_ftw() on %s\n",
		     msg);
	    else
		logg("!Memory allocation failed during cli_ftw()\n");
	    scandata->errors++;
	    return CL_EMEM;
	case error_stat:
	    if (msg == scandata->toplevel_path)
		conn_reply_errno(scandata->conn, msg, "lstat() failed:");
	    logg("^lstat() failed on: %s\n", msg);
	    scandata->errors++;
	    return CL_SUCCESS;
	case warning_skipped_dir:
	    logg("^Directory recursion limit reached, skipping %s\n",
		     msg);
	    return CL_SUCCESS;
	case warning_skipped_link:
	    logg("$Skipping symlink: %s\n", msg);
	    return CL_SUCCESS;
	case warning_skipped_special:
	    if (msg == scandata->toplevel_path)
		conn_reply(scandata->conn, msg, "Not supported file type", "ERROR");
	    logg("*Not supported file type: %s\n", msg);
	    return CL_SUCCESS;
	case visit_directory_toplev:
	    return CL_SUCCESS;
	case visit_file:
	    break;
    }

    /* check whether the file is excluded */
#ifdef C_LINUX
    if(procdev && sb && (sb->st_dev == procdev)) {
	free(filename);
	return CL_SUCCESS;
    }
#endif
    if((opt = optget(scandata->opts, "ExcludePath"))->enabled) {
      while (opt) {
	/* TODO: perhaps multiscan should skip this check? 
	 * This should work unless the user is doing something stupid like
	 * MULTISCAN / */
	if(match_regex(filename, opt->strarg) == 1) {
	    if (type != TYPE_MULTISCAN)
		conn_reply_single(scandata->conn, filename, "Excluded");
	    free(filename);
	    return CL_SUCCESS;
	}
	opt = (const struct optstruct *) opt->nextarg;
      }
    }

    if(sb && sb->st_size == 0) { /* empty file */
	if (msg == scandata->toplevel_path)
	    conn_reply_single(scandata->conn, filename, "Empty file");
	free(filename);
	return CL_SUCCESS;
    }

    if (type == TYPE_MULTISCAN) {
	client_conn_t *client_conn = (client_conn_t *) calloc(1, sizeof(struct client_conn_tag));
	if(client_conn) {
	    client_conn->scanfd = -1;
	    client_conn->sd = scandata->odesc;
	    client_conn->filename = filename;
	    client_conn->cmdtype = COMMAND_MULTISCANFILE;
	    client_conn->term = scandata->conn->term;
	    client_conn->options = scandata->options;
	    client_conn->opts = scandata->opts;
	    client_conn->group = scandata->group;
	    if(cl_engine_addref(scandata->engine)) {
		logg("!cl_engine_addref() failed\n");
		free(filename);
		return CL_EMEM;
	    } else {
		client_conn->engine = scandata->engine;
		pthread_mutex_lock(&reload_mutex);
		client_conn->engine_timestamp = reloaded_time;
		pthread_mutex_unlock(&reload_mutex);
		if(!thrmgr_group_dispatch(scandata->thr_pool, scandata->group, client_conn)) {
		    logg("!thread dispatch failed\n");
		    free(filename);
		    return CL_EMEM;
		}
	    }
	} else {
	    logg("!Can't allocate memory for client_conn\n");
	    scandata->errors++;
	    free(filename);
	    return CL_EMEM;
	}
	return CL_SUCCESS;
    }

    if (access(filename, R_OK)) {
	if (conn_reply(scandata->conn, filename, "Access denied.", "ERROR") == -1)
	    return CL_ETIMEOUT;
	logg("*Access denied: %s\n", filename);
	scandata->errors++;
	free(filename);
	return CL_SUCCESS;
    }

    thrmgr_setactivetask(filename,
			 type == TYPE_MULTISCAN ? "MULTISCANFILE" : NULL);
    ret = cl_scanfile(filename, &virname, &scandata->scanned, scandata->engine, scandata->options);
    thrmgr_setactivetask(NULL, NULL);

    if (thrmgr_group_need_terminate(scandata->conn->group)) {
	logg("*Client disconnected while scanjob was active\n");
	return ret == CL_ETIMEOUT ? ret : CL_BREAK;
    }

    if (ret == CL_VIRUS) {
	scandata->infected++;
	if (conn_reply(scandata->conn, filename, virname, "FOUND") == -1)
	    return CL_ETIMEOUT;
	logg("~%s: %s FOUND\n", filename, virname);
	virusaction(filename, virname, scandata->opts);
    } else if (ret != CL_CLEAN) {
	scandata->errors++;
	if (conn_reply(scandata->conn, filename, cl_strerror(ret), "ERROR") == -1)
	    return CL_ETIMEOUT;
	logg("~%s: %s ERROR\n", filename, cl_strerror(ret));
    } else if (logok) {
	logg("~%s: OK\n", filename);
    }

    free(filename);
    if(ret == CL_EMEM) /* stop scanning */
	return ret;

    if (type == TYPE_SCAN) {
	/* virus -> break */
	return ret;
    }

    /* keep scanning always */
    return CL_SUCCESS;
}

int scanfd(const int fd, const client_conn_t *conn, unsigned long int *scanned,
	   const struct cl_engine *engine,
	   unsigned int options, const struct optstruct *opts, int odesc, int stream)
{
	int ret;
	const char *virname;
	struct stat statbuf;
	char fdstr[32];

	if (stream)
	    strncpy(fdstr, "stream", sizeof(fdstr));
	else
	    snprintf(fdstr, sizeof(fdstr), "fd[%d]", fd);
	if(fstat(fd, &statbuf) == -1 || !S_ISREG(statbuf.st_mode)) {
		logg("%s: Not a regular file. ERROR\n", fdstr);
		if (conn_reply(conn, fdstr, "Not a regular file", "ERROR") == -1)
		    return CL_ETIMEOUT;
		return -1;
	}

	thrmgr_setactivetask(fdstr, NULL);
	ret = cl_scandesc(fd, &virname, scanned, engine, options);
	thrmgr_setactivetask(NULL, NULL);

	if (thrmgr_group_need_terminate(conn->group)) {
	    logg("*Client disconnected while scanjob was active\n");
	    return ret == CL_ETIMEOUT ? ret : CL_BREAK;
	}

	if(ret == CL_VIRUS) {
		if (conn_reply(conn, fdstr, virname, "FOUND") == -1)
		    ret = CL_ETIMEOUT;
		logg("%s: %s FOUND\n", fdstr, virname);
		virusaction(fdstr, virname, opts);
	} else if(ret != CL_CLEAN) {
		if (conn_reply(conn, fdstr, cl_strerror(ret), "ERROR") == -1)
		    ret = CL_ETIMEOUT;
		logg("%s: %s ERROR\n", fdstr, cl_strerror(ret));
	} else {
		if (conn_reply_single(conn, fdstr, "OK") == CL_ETIMEOUT)
		    ret = CL_ETIMEOUT;
		if(logok)
			logg("%s: OK\n", fdstr);
	}
	return ret;
}

int scanstream(int odesc, unsigned long int *scanned, const struct cl_engine *engine, unsigned int options, const struct optstruct *opts, char term)
{
	int ret, sockfd, acceptd;
	int tmpd, bread, retval, firsttimeout, timeout, btread;
	unsigned int port = 0, portscan, min_port, max_port;
	unsigned long int quota = 0, maxsize = 0;
	short bound = 0;
	const char *virname;
	char buff[FILEBUFF];
	char peer_addr[32];
	struct sockaddr_in server;
	struct sockaddr_in peer;
	socklen_t addrlen;
	char *tmpname;


    min_port = optget(opts, "StreamMinPort")->numarg;
    max_port = optget(opts, "StreamMaxPort")->numarg;

    /* search for a free port to bind to */
    port = cli_rndnum(max_port - min_port);
    bound = 0;
    for (portscan = 0; portscan < 1000; portscan++) {
	port = (port - 1) % (max_port - min_port + 1);

	memset((char *) &server, 0, sizeof(server));
	server.sin_family = AF_INET;
	server.sin_port = htons(min_port + port);
	server.sin_addr.s_addr = htonl(INADDR_ANY);

	if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
	    continue;

	if(bind(sockfd, (struct sockaddr *) &server, sizeof(struct sockaddr_in)) == -1)
	    closesocket(sockfd);
	else {
	    bound = 1;
	    break;
	}
    }
    port += min_port;

    timeout = optget(opts, "ReadTimeout")->numarg;
    if(timeout == 0)
	timeout = -1;

    firsttimeout = optget(opts, "CommandReadTimeout")->numarg;
    if (firsttimeout == 0)
	firsttimeout = -1;

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

    retval = poll_fd(sockfd, firsttimeout, 0);
    if (!retval || retval == -1) {
	const char *reason = !retval ? "timeout" : "poll";
	mdprintf(odesc, "Accept %s. ERROR%c", reason, term);
	logg("!ScanStream %u: accept %s.\n", port, reason);
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

    quota = maxsize = optget(opts, "StreamMaxLength")->numarg;

    while((retval = poll_fd(acceptd, timeout, 0)) == 1) {
	/* only read up to max */
	btread = (maxsize && (quota < sizeof(buff))) ? quota : sizeof(buff);
	if (!btread) {
		logg("^ScanStream(%s@%u): Size limit reached (max: %lu)\n", peer_addr, port, maxsize);
		break; /* Scan what we have */
	}
	bread = recv(acceptd, buff, btread, 0);
	if(bread <= 0)
	    break;

	quota -= bread;

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

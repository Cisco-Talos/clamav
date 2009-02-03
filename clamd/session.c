/*
 *  Copyright (C) 2002 - 2007 Tomasz Kojm <tkojm@clamav.net>
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

#if defined HAVE_FD_PASSING && defined FDPASS_NEED_XOPEN
/* to expose BSD 4.4/Unix98 semantics instead of BSD 4.3 semantics */
#define _XOPEN_SOURCE 500
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
#ifdef HAVE_FD_PASSING
#ifdef HAVE_SYS_UIO_H
#include <sys/uio.h>
#endif
#endif

#include <sys/time.h>
#endif
#include <pthread.h>
#include <time.h>
#include <errno.h>
#include <stddef.h>

#include "libclamav/clamav.h"
#include "libclamav/str.h"
#include "libclamav/others.h"

#include "shared/optparser.h"
#include "shared/output.h"
#include "shared/misc.h"

#include "others.h"
#include "scanner.h"
#include "server.h"
#include "session.h"
#include "thrmgr.h"

#ifdef HAVE_FD_PASSING
static int recvfd_and_scan(int desc, const struct cl_engine *engine, unsigned int options, const struct optstruct *opts)
{
	struct msghdr msg;
	struct cmsghdr *cmsg;
	unsigned char buf[CMSG_SPACE(sizeof(int))];
	struct iovec iov[1];
	char dummy;
	int ret=-1;

	memset(&msg, 0, sizeof(msg));
	iov[0].iov_base = &dummy;
	iov[0].iov_len = 1;
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;
	msg.msg_control = buf;
	msg.msg_controllen = sizeof(buf);

	if (recvmsg(desc, &msg, 0) == -1) {
	    logg("recvmsg failed: %s!", strerror(errno));
	    return -1;
	}
	if ((msg.msg_flags & MSG_TRUNC) || (msg.msg_flags & MSG_CTRUNC)) {
	    logg("control message truncated");
	    return -1;
	}
	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL;
	    cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		if (cmsg->cmsg_len == CMSG_LEN(sizeof(int)) &&
		    cmsg->cmsg_level == SOL_SOCKET &&
		    cmsg->cmsg_type == SCM_RIGHTS) {
			int fd = *(int *)CMSG_DATA(cmsg);
			ret = scanfd(fd, '\n', NULL, engine, options, opts, desc);
			close(fd);
		}
	}
	return ret;
}

#else
static int recvfd_and_scan(int desc, const struct cl_engine *engine, unsigned int options, const struct optstruct *opts)
{
	mdprintf(desc, "ERROR: FILDES support not compiled in\n");
	return -1;
}
#endif

enum commands parse_command(const char *cmd, const char **argument)
{
    *argument = NULL;
    if (!strncmp(cmd, CMD1, strlen(CMD1))) { /* SCAN */
	*argument = cmd + strlen(CMD1) + 1;
	return COMMAND_SCAN;
    } else if (!strncmp(cmd, CMD3, strlen(CMD3))) { /* QUIT */
	return COMMAND_SHUTDOWN;
    } else if (!strncmp(cmd, CMD4, strlen(CMD4))) { /* RELOAD */
	return COMMAND_RELOAD;
    } else if (!strncmp(cmd, CMD5, strlen(CMD5))) { /* PING */
	return COMMAND_PING;
    } else if (!strncmp(cmd, CMD6, strlen(CMD6))) { /* CONTSCAN */
	*argument = cmd + strlen(CMD6) + 1;
	return COMMAND_CONTSCAN;
    } else if (!strncmp(cmd, CMD7, strlen(CMD7))) { /* VERSION */
	return COMMAND_VERSION;
    } else if (!strncmp(cmd, CMD8, strlen(CMD8))) { /* STREAM */
	return COMMAND_STREAM;
#if 0
    } else if (!strncmp(cmd, CMD9, strlen(CMD9))) { /* SESSION */
	return COMMAND_SESSION;
#endif
    } else if (!strncmp(cmd, CMD10, strlen(CMD10))) { /* END */
	return COMMAND_END;
    } else if (!strncmp(cmd, CMD11, strlen(CMD11))) { /* SHUTDOWN */
	return COMMAND_SHUTDOWN;
    } else if (!strncmp(cmd, CMD13, strlen(CMD13))) { /* MULTISCAN */
	*argument = cmd + strlen(CMD13) + 1;
	return COMMAND_MULTISCAN;
    } else if (!strncmp(cmd, CMD14, strlen(CMD14))) { /* FILDES */
	return COMMAND_FILDES;
    } else if (!strncmp(cmd, CMD15, strlen(CMD15))) { /* STATS */
	return COMMAND_STATS;
    } else if (!strncmp(cmd, CMD16, strlen(CMD16))) { /* IDSESSION */
	return COMMAND_IDSESSION;
    }
    return COMMAND_UNKNOWN;
}

/* returns
 *  -1 on fatal error (shutdown)
 *  0 on ok, close connection
 *  1 on ok, keep connection open */
int command(client_conn_t *conn)
{
    int desc = conn->sd;
    struct cl_engine *engine = conn->engine;
    unsigned int options = conn->options;
    const struct optstruct *opts = conn->opts;
    const char term = conn->term;
    int type; /* TODO: make this enum */
    int keepopen = conn->group ? 1 : 0;

    struct scan_cb_data scandata;
    struct cli_ftw_cbdata data;
    unsigned ok, error, total;
    jobgroup_t group = JOBGROUP_INITIALIZER;

    thrmgr_setactiveengine(engine);

    data.data = &scandata;
    memset(&scandata, 0, sizeof(scandata));
    scandata.group = conn->group;
    scandata.odesc = desc;
    scandata.term = term;
    scandata.options = options;
    scandata.engine = engine;
    scandata.opts = opts;
    scandata.thr_pool = conn->thrpool;
    scandata.toplevel_path = conn->filename;

    switch (conn->cmdtype) {
	case COMMAND_SCAN:
	    thrmgr_setactivetask(NULL, "SCAN");
	    type = TYPE_SCAN;
	    break;
	case COMMAND_CONTSCAN:
	    thrmgr_setactivetask(NULL, "CONTSCAN");
	    type = TYPE_CONTSCAN;
	    break;
	case COMMAND_MULTISCAN:
	    thrmgr_setactivetask(NULL, "MULTISCAN");
	    type = TYPE_MULTISCAN;
	    scandata.group = &group;
	    keepopen = 0;
	    break;
	case COMMAND_MULTISCANFILE:
	    thrmgr_setactivetask(NULL, "MULTISCANFILE");
	    scandata.group = NULL;
	    scandata.type = TYPE_MULTISCAN;
	    /* TODO: check ret value */
	    scan_callback(NULL, conn->filename, conn->filename, visit_file, &data);
	    keepopen = 1;
	    break;
	case COMMAND_FILDES:
	    thrmgr_setactivetask(NULL, "FILDES");
#ifdef HAVE_FD_PASSING
	    if (conn->scanfd == -1)
		mdprintf(desc, "FILDES: didn't receive file descriptor %c", conn->term);
	    else if (scanfd(conn->scanfd, conn->term, NULL, engine, options, opts, desc) == -2)
		if(optget(opts, "ExitOnOOM")->enabled)
		    return COMMAND_SHUTDOWN;
	    return keepopen;
#else
	    mdprintf(desc, "FILDES support not compiled in. ERROR%c",conn->term);
	    return 0;
#endif
	case COMMAND_STATS:
	    thrmgr_setactivetask(NULL, "STATS");
	    thrmgr_printstats(desc);
	    return keepopen;
	case COMMAND_STREAM:
	    thrmgr_setactivetask(NULL, "STREAM");
	    if(scanstream(desc, NULL, engine, options, opts, conn->term) == CL_EMEM)
		if(optget(opts, "ExitOnOOM")->enabled)
		    return COMMAND_SHUTDOWN;
	    /* STREAM not valid in IDSESSION */
	    return 0;
    }

    scandata.type = type;
    int maxdirrec = optget(opts, "MaxDirectoryRecursion")->numarg;
    // TODO: flags symlink from opt
    if (cli_ftw(conn->filename, CLI_FTW_STD,  maxdirrec ? maxdirrec : INT_MAX, scan_callback, &data) == CL_EMEM) 
	if(optget(opts, "ExitOnOOM")->enabled)
	    return COMMAND_SHUTDOWN;
    if (scandata.group)
	thrmgr_group_waitforall(&group, &ok, &error, &total);
    else {
	error = scandata.errors;
	total = scandata.total;
	ok = total - error - scandata.infected;
    }

    if (ok + error == total && (error != total)) {
	mdprintf(desc, "%s: OK%c", conn->filename, conn->term);
    }
    return keepopen; /* no error and no 'special' command executed */
}

static int dispatch_command(const client_conn_t *conn, enum commands command, const char *argument)
{
    client_conn_t *dup_conn = (client_conn_t *) malloc(sizeof(struct client_conn_tag));
    if(!dup_conn) {
	logg("!Can't allocate memory for client_conn\n");
	return -1;
    }
    memcpy(dup_conn, conn, sizeof(*conn));
    dup_conn->cmdtype = command;
    if(cl_engine_addref(dup_conn->engine)) {
	logg("!cl_engine_addref() failed\n");
	return -1;
    }
    dup_conn->scanfd = -1;
    switch (command) {
	case COMMAND_FILDES:
	    dup_conn->scanfd = conn->scanfd;
	    break;
	case COMMAND_SCAN:
	case COMMAND_CONTSCAN:
	case COMMAND_MULTISCAN:
	    dup_conn->filename = strdup(argument);
	    if (!dup_conn->filename) {
		logg("!Failed to allocate memory for filename\n");
		return -1;
	    }
	    break;
	case COMMAND_STREAM:
	case COMMAND_STATS:
	    /* just dispatch the command */
	    break;
    }
    if(!thrmgr_dispatch(dup_conn->thrpool, dup_conn)) {
	logg("!thread dispatch failed\n");
	return -2;
    }
    return 0;
}

/* returns:
 *  <0 for error
 *     -1 out of memory
 *     -2 other
 *   0 for async dispatched
 *   1 for command completed (connection can be closed)
 */
int execute_or_dispatch_command(client_conn_t *conn, enum commands command, const char *argument)
{
    int desc = conn->sd;
    char term = conn->term;
    const struct cl_engine *engine = conn->engine;
    /* execute commands that can be executed quickly on the recvloop thread,
     * these must:
     *  - not involve any operation that can block for a long time, such as disk
     *  I/O
     *  - send of atomic message is allowed.
     * Dispatch other commands */
    switch (command) {
	case COMMAND_SHUTDOWN:
	    pthread_mutex_lock(&exit_mutex);
	    progexit = 1;
	    pthread_mutex_unlock(&exit_mutex);
	    return 1;
	case COMMAND_RELOAD:
	    pthread_mutex_lock(&reload_mutex);
	    reload = 1;
	    pthread_mutex_unlock(&reload_mutex);
	    mdprintf(desc, "RELOADING%c", term);
	    /* we set reload flag, and we'll reload before closing the
	     * connection */
	    return 1;
	case COMMAND_PING:
	    mdprintf(desc, "PONG%c", term);
	    return 1;
	case COMMAND_VERSION:
	    {
		uint32_t ver;
		cl_engine_get(engine, CL_ENGINE_DB_VERSION, &ver);
		if(ver) {
		    char timestr[32];
		    const char *tstr;
		    time_t t;
		    cl_engine_get(engine, CL_ENGINE_DB_TIME, &t);
		    tstr = cli_ctime(&t, timestr, sizeof(timestr));
		    /* cut trailing \n */
		    timestr[strlen(tstr)-1] = '\0';
		    mdprintf(desc, "ClamAV %s/%u/%s%c", get_version(), (unsigned int) ver, tstr, term);
		} else {
		    mdprintf(desc, "ClamAV %s%c", get_version(), conn->term);
		}
		return 1;
	    }
	case COMMAND_FILDES:
	case COMMAND_SCAN:
	case COMMAND_CONTSCAN:
	case COMMAND_STREAM:
	case COMMAND_MULTISCAN:
	case COMMAND_STATS:
	    return dispatch_command(conn, command, argument);
	case COMMAND_IDSESSION:
	    if (conn->group) {
		/* we are already inside an idsession/multiscan */
		mdprintf(desc, "UNKNOWN COMMAND%c", term);
		return 1;
	    }
	    conn->group = calloc(1, sizeof(*conn->group));
	    if (!conn->group)
		return CL_EMEM;
	    return 0;
	case COMMAND_END:
	    if (!conn->group) {
		/* end without idsession? */
		mdprintf(desc, "UNKNOWN COMMAND%c", term);
		return 1;
	    }
	    return 1;
	/*case COMMAND_UNKNOWN:*/
	default:
	    mdprintf(desc, "UNKNOWN COMMAND%c", term);
	    return 1;
    }
}

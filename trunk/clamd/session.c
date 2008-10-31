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

#include "shared/cfgparser.h"
#include "shared/output.h"
#include "shared/misc.h"

#include "others.h"
#include "scanner.h"
#include "server.h"
#include "session.h"

#ifdef HAVE_FD_PASSING
static int recvfd_and_scan(int desc, const struct cl_engine *engine, const struct cl_limits *limits, unsigned int options, const struct cfgstruct *copt)
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
			ret = scanfd(fd, NULL, engine, limits, options, copt, desc);
			close(fd);
		}
	}
	return ret;
}

#else
static int recvfd_and_scan(int desc, const struct cl_engine *engine, const struct cl_limits *limits, unsigned int options, const struct cfgstruct *copt)
{
	mdprintf(desc, "ERROR: FILDES support not compiled in\n");
	return -1;
}
#endif

int command(int desc, const struct cl_engine *engine, const struct cl_limits *limits, unsigned int options, const struct cfgstruct *copt, int timeout)
{
	char buff[1025];
	int bread;

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
	if(scan(buff + strlen(CMD1) + 1, NULL, engine, limits, options, copt, desc, TYPE_SCAN) == -2)
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
	if(scan(buff + strlen(CMD6) + 1, NULL, engine, limits, options, copt, desc, TYPE_CONTSCAN) == -2)
	    if(cfgopt(copt, "ExitOnOOM")->enabled)
		return COMMAND_SHUTDOWN;

    } else if(!strncmp(buff, CMD7, strlen(CMD7))) { /* VERSION */
	    const char *dbdir = cfgopt(copt, "DatabaseDirectory")->strarg;
	    char *path;
	    struct cl_cvd *daily;


	if(!(path = malloc(strlen(dbdir) + 30))) {
	    mdprintf(desc, "Memory allocation error - SHUTDOWN forced\n");
	    return COMMAND_SHUTDOWN;
	}

	sprintf(path, "%s/daily.cvd", dbdir);
	if(access(path, R_OK))
	    sprintf(path, "%s/daily.cld", dbdir);

	if(!access(path, R_OK) && (daily = cl_cvdhead(path))) {
		char timestr[32];
		time_t t = (time_t) daily->stime;

	    mdprintf(desc, "ClamAV %s/%d/%s", get_version(), daily->version, cli_ctime(&t, timestr, sizeof(timestr)));
	    cl_cvdfree(daily);
	} else {
	    mdprintf(desc, "ClamAV %s\n", get_version());
	}

	free(path);

    } else if(!strncmp(buff, CMD8, strlen(CMD8))) { /* STREAM */
	if(scanstream(desc, NULL, engine, limits, options, copt) == CL_EMEM)
	    if(cfgopt(copt, "ExitOnOOM")->enabled)
		return COMMAND_SHUTDOWN;

    } else if(!strncmp(buff, CMD9, strlen(CMD9))) { /* SESSION */
	return COMMAND_SESSION;

    } else if(!strncmp(buff, CMD10, strlen(CMD10))) { /* END */
	return COMMAND_END;

    } else if(!strncmp(buff, CMD11, strlen(CMD11))) { /* SHUTDOWN */
	return COMMAND_SHUTDOWN;

    } else if(!strncmp(buff, CMD13, strlen(CMD13))) { /* MULTISCAN */
	if(scan(buff + strlen(CMD13) + 1, NULL, engine, limits, options, copt, desc, TYPE_MULTISCAN) == -2)
	    if(cfgopt(copt, "ExitOnOOM")->enabled)
		return COMMAND_SHUTDOWN;

    } else if(!strncmp(buff, CMD14, strlen(CMD14))) { /* FILDES */
	if(recvfd_and_scan(desc, engine, limits, options, copt) == -2)
	    if(cfgopt(copt, "ExitOnOOM")->enabled)
		return COMMAND_SHUTDOWN;
    } else {
	mdprintf(desc, "UNKNOWN COMMAND\n");
    }

    return 0; /* no error and no 'special' command executed */
}

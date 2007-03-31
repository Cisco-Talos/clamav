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
#include <errno.h>
#include <stddef.h>

#include "libclamav/clamav.h"
#include "libclamav/str.h"

#include "shared/cfgparser.h"
#include "shared/output.h"
#include "shared/misc.h"

#include "others.h"
#include "scanner.h"
#include "server.h"
#include "session.h"

static pthread_mutex_t ctime_mutex = PTHREAD_MUTEX_INITIALIZER;

int command(int desc, const struct cl_engine *engine, const struct cl_limits *limits, unsigned int options, const struct cfgstruct *copt, int timeout)
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
	if(scan(buff + strlen(CMD1) + 1, NULL, engine, limits, options, copt, desc, TYPE_SCAN) == -2)
	    if(cfgopt(copt, "ExitOnOOM")->enabled)
		return COMMAND_SHUTDOWN;

    } else if(!strncmp(buff, CMD2, strlen(CMD2))) { /* RAWSCAN */
	opt = options & ~CL_SCAN_ARCHIVE;
	if(scan(buff + strlen(CMD2) + 1, NULL, engine, NULL, opt, copt, desc, TYPE_SCAN) == -2)
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
	    struct stat foo;


	if(!(path = malloc(strlen(dbdir) + 30))) {
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
	if(scanstream(desc, NULL, engine, limits, options, copt) == CL_EMEM)
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

	scanfd(fd, NULL, engine, limits, options, copt, desc);
	close(fd); /* FIXME: should we close it here? */

    } else if(!strncmp(buff, CMD13, strlen(CMD13))) { /* MULTISCAN */
	if(scan(buff + strlen(CMD13) + 1, NULL, engine, limits, options, copt, desc, TYPE_MULTISCAN) == -2)
	    if(cfgopt(copt, "ExitOnOOM")->enabled)
		return COMMAND_SHUTDOWN;

    } else {
	mdprintf(desc, "UNKNOWN COMMAND\n");
    }

    return 0; /* no error and no 'special' command executed */
}

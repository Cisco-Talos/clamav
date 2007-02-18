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
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <pthread.h>
#include <time.h>
#include <signal.h>
#include <errno.h>

#include "cfgparser.h"
#include "others.h"
#include "defaults.h"
#include "scanner.h"
#include "server.h"
#include "clamuko.h"
#include "session.h"
#include "str.h" /* libclamav */
#include "clamav.h"
#include "output.h"
#include "memory.h"

pthread_mutex_t ctime_mutex = PTHREAD_MUTEX_INITIALIZER;

int command(int desc, const struct cl_node *root, const struct cl_limits *limits, int options, const struct cfgstruct *copt, int timeout)
{
	char buff[1025];
	int bread, opt, retval;
	struct cfgstruct *cpt;


    retval = poll_fd(desc, timeout);
    switch (retval) {
    case 0: /* timeout */
	return -2;
    case -1:
	mdprintf(desc, "ERROR\n");
	logg("!Command: poll_fd failed.\n");
	return -1;
    }

    while((bread = readsock(desc, buff, 1024)) == -1 && errno == EINTR);

    if(bread == 0) {
	/* Connection closed */
	return -1;
    }

    if(bread < 0) {
	logg("!Command parser: read() failed.\n");
	/* at least try to display this error message */
	/* mdprintf(desc, "ERROR: Command parser: read() failed.\n"); */
	return -1;
    }

    buff[bread] = 0;
    cli_chomp(buff);

    if(!strncmp(buff, CMD1, strlen(CMD1))) { /* SCAN */
	if(scan(buff + strlen(CMD1) + 1, NULL, root, limits, options, copt, desc, 0) == -2)
	    if(cfgopt(copt, "ExitOnOOM"))
		return COMMAND_SHUTDOWN;

    } else if(!strncmp(buff, CMD2, strlen(CMD2))) { /* RAWSCAN */
	opt = options & ~CL_SCAN_ARCHIVE;
	if(scan(buff + strlen(CMD2) + 1, NULL, root, NULL, opt, copt, desc, 0) == -2)
	    if(cfgopt(copt, "ExitOnOOM"))
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
	    if(cfgopt(copt, "ExitOnOOM"))
		return COMMAND_SHUTDOWN;

    } else if(!strncmp(buff, CMD7, strlen(CMD7))) { /* VERSION */
	    const char *dbdir;
	    char *path;
	    struct cl_cvd *daily;

	if((cpt = cfgopt(copt, "DatabaseDirectory")) || (cpt = cfgopt(copt, "DataDirectory")))
	    dbdir = cpt->strarg;
	else
	    dbdir = cl_retdbdir();

	if(!(path = mmalloc(strlen(dbdir) + 11))) {
	    mdprintf(desc, "Memory allocation error - SHUTDOWN forced\n");
	    return COMMAND_SHUTDOWN;
	}

	sprintf(path, "%s/daily.cvd", dbdir);

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
	    if(cfgopt(copt, "ExitOnOOM"))
		return COMMAND_SHUTDOWN;

    } else if(!strncmp(buff, CMD9, strlen(CMD9))) { /* SESSION */
	return COMMAND_SESSION;

    } else if(!strncmp(buff, CMD10, strlen(CMD10))) { /* END */
	return COMMAND_END;

    } else if(!strncmp(buff, CMD11, strlen(CMD11))) { /* SHUTDOWN */
	return COMMAND_SHUTDOWN;

    } else if(!strncmp(buff, CMD12, strlen(CMD12))) { /* FD */
	    int fd = atoi(buff + strlen(CMD12) + 1);

	scanfd(fd, NULL, root, limits, options, copt, desc, 0);
	close(fd); /* FIXME: should we close it here? */

    } else {
	mdprintf(desc, "UNKNOWN COMMAND\n");
    }

    return 0; /* no error and no 'special' command executed */
}

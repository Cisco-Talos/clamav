/*
 *  Copyright (C) 2002 - 2004 Tomasz Kojm <tkojm@clamav.net>
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
#include "tests.h"
#include "session.h"
#include "str.h" /* libclamav */
#include "output.h"

#define CMD1 "SCAN"
#define CMD2 "RAWSCAN"
#define CMD3 "QUIT" /* deprecated */
#define CMD4 "RELOAD"
#define CMD5 "PING"
#define CMD6 "CONTSCAN"
#define CMD7 "VERSION"
#define CMD8 "STREAM"
#define CMD9 "SESSION"
#define CMD10 "END"
#define CMD11 "SHUTDOWN"


int command(int desc, const struct cl_node *root, const struct cl_limits *limits, int options, const struct cfgstruct *copt)
{
	char buff[1025];
	int bread, opt, ret, retval, timeout;
	struct cfgstruct *cpt;

    if((cpt = cfgopt(copt, "ReadTimeout"))) {
	timeout = cpt->numarg;
    } else {
	timeout = CL_DEFAULT_SCANTIMEOUT;
    }
    if (timeout == 0) {
    	timeout = -1;
    }
       
    retval = poll_fd(desc, timeout);
    switch (retval) {
    case 0: /* timeout */
	mdprintf(desc, "ERROR\n");
	logg("!Command: command timeout.\n");
	return -1;
    case -1:
	mdprintf(desc, "ERROR\n");
	logg("!Command: poll_fd failed.\n");
	return -1;
    }

    if((bread = read(desc, buff, 1024)) == -1) {
	logg("!Command parser: read() failed.\n");
	/* at least try to display this error message */
	mdprintf(desc, "ERROR: Command parser: read() failed.\n");
	return -1;
    }

    buff[bread] = 0;
    cli_chomp(buff);

    if(!strncmp(buff, CMD1, strlen(CMD1))) { /* SCAN */
	scan(buff + strlen(CMD1) + 1, NULL, root, limits, options, copt, desc, 0);

    } else if(!strncmp(buff, CMD2, strlen(CMD2))) { /* RAWSCAN */
	opt = options & ~CL_ARCHIVE;
	scan(buff + strlen(CMD2) + 1, NULL, root, NULL, opt, copt, desc, 0);

    } else if(!strncmp(buff, CMD3, strlen(CMD3))) { /* QUIT */
	return COMMAND_QUIT;

    } else if(!strncmp(buff, CMD4, strlen(CMD4))) { /* RELOAD */
	mdprintf(desc, "RELOADING\n");
	return COMMAND_RELOAD;

    } else if(!strncmp(buff, CMD5, strlen(CMD5))) { /* PING */
	mdprintf(desc, "PONG\n");

    } else if(!strncmp(buff, CMD6, strlen(CMD6))) { /* CONTSCAN */
	scan(buff + strlen(CMD6) + 1, NULL, root, limits, options, copt, desc, 1);

    } else if(!strncmp(buff, CMD7, strlen(CMD7))) { /* VERSION */
	mdprintf(desc, "clamd / ClamAV version "VERSION"\n");

    } else if(!strncmp(buff, CMD8, strlen(CMD8))) { /* STREAM */
	scanstream(desc, NULL, root, limits, options, copt);

    } else if(!strncmp(buff, CMD9, strlen(CMD9))) { /* SESSION */
	do {
	    ret = command(desc, root, limits, options, copt);
	} while(!ret);

	switch(ret) {
	    case COMMAND_QUIT:
		mdprintf(desc, "SESSION TERMINATED (SHUTDOWN)\n");
		break;

	    case COMMAND_RELOAD:
		mdprintf(desc, "SESSION TERMINATED (DATABASE RELOADING)\n");
		break;

	    case COMMAND_END:
		mdprintf(desc, "BYE\n");
		break;

	    default:
		mdprintf(desc, "SESSION TERMINATED (INTERNAL ERROR)\n");
		break;
	}

	return ret;

    } else if(!strncmp(buff, CMD10, strlen(CMD10))) { /* END */
	return COMMAND_END;

    } else if(!strncmp(buff, CMD11, strlen(CMD11))) { /* SHUTDOWN */
	return COMMAND_QUIT;

    } else {
	mdprintf(desc, "UNKNOWN COMMAND\n");
    }

    return 0; /* no error and no 'special' command executed */
}

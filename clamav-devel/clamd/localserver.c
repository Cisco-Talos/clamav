/*
 *  Copyright (C) 2002 Tomasz Kojm <zolw@konarski.edu.pl>
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
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <clamav.h>
#include <errno.h>

#include "options.h"
#include "cfgfile.h"
#include "defaults.h"
#include "others.h"
#include "server.h"

int localserver(const struct optstruct *opt, const struct cfgstruct *copt, struct cl_node *root)
{
	struct sockaddr_un server;
	int sockfd, backlog;
	struct cfgstruct *cpt;
	struct stat foo;
	char *estr;

    memset((char *) &server, 0, sizeof(server));
    server.sun_family = AF_UNIX;
    strncpy(server.sun_path, cfgopt(copt, "LocalSocket")->strarg, sizeof(server.sun_path));

    if((sockfd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
	estr = strerror(errno);
	//fprintf(stderr, "ERROR: socket() error: %s\n", estr);
	logg("!socket() error: %s\n", estr);
	exit(1);
    }

    if(bind(sockfd, (struct sockaddr *) &server, sizeof(struct sockaddr_un)) == -1) {
	if(stat(server.sun_path, &foo) != -1) {
	    //fprintf(stderr, "ERROR: Socket file %s already exists. Please remove it or use another one.\n", server.sun_path);
	    logg("!Socket file %s already exists. Please remove it or use another one.\n", server.sun_path);
	    exit(1);
	}

	estr = strerror(errno);
	//fprintf(stderr, "ERROR: can't bind(): %s\n", estr);
	logg("!bind() error: %s\n", estr);
	exit(1);
    } else
	logg("Unix socket file %s\n", server.sun_path);

    if((cpt = cfgopt(copt, "MaxConnectionQueueLength")))
	backlog = cpt->numarg;
    else
	backlog = CL_DEFAULT_BACKLOG;

    logg("Setting connection queue length to %d\n", backlog);

    if(listen(sockfd, backlog) == -1) {
	estr = strerror(errno);
	//fprintf(stderr, "ERROR: listen() error: %s\n", estr);
	logg("!listen() error: %s\n", estr);
	exit(1);
    }

    acceptloop(sockfd, root, copt);
    return 0;
}

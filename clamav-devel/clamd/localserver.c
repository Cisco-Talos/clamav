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
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <clamav.h>
#include <errno.h>

#include "options.h"
#include "cfgparser.h"
#include "defaults.h"
#include "others.h"
#include "server.h"
#include "output.h"

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
	/* 
	fprintf(stderr, "ERROR: socket() error: %s\n", estr);
	*/
	logg("!Socket allocation error: %s\n", estr);
	exit(1);
    }

    if(bind(sockfd, (struct sockaddr *) &server, sizeof(struct sockaddr_un)) == -1) {
	if(errno == EADDRINUSE) {
	    if(connect(sockfd, (struct sockaddr *) &server, sizeof(struct sockaddr_un)) >= 0) {
		close(sockfd);
		logg("!Socket file %s is in use by another process.\n", server.sun_path);
		exit(1);
	    }
	    if(cfgopt(copt, "FixStaleSocket")) {
		logg("^Socket file %s exists. Unclean shutdown? Removing...\n", server.sun_path);
		if(unlink(server.sun_path) == -1) {
		    estr = strerror(errno);
		    logg("!Socket file %s could not be removed: %s\n", server.sun_path, estr);
		    exit(1);
		}
		if(bind(sockfd, (struct sockaddr *) &server, sizeof(struct sockaddr_un)) == -1) {
		    estr = strerror(errno);
		    logg("!Socket file %s could not be bound: %s (unlink tried)\n", server.sun_path, estr);
		    exit(1);
		}
	    } else if(stat(server.sun_path, &foo) != -1) {
		logg("!Socket file %s exists. Either remove it, or configure a different one.\n", server.sun_path);
		exit(1);
	    }
	} else {
	    estr = strerror(errno);
	    logg("!Socket file %s could not be bound: %s\n", server.sun_path, estr);
	    exit(1);
	}
    }

    logg("Unix socket file %s\n", server.sun_path);

    if((cpt = cfgopt(copt, "MaxConnectionQueueLength")))
	backlog = cpt->numarg;
    else
	backlog = CL_DEFAULT_BACKLOG;

    logg("Setting connection queue length to %d\n", backlog);

    if(listen(sockfd, backlog) == -1) {
	estr = strerror(errno);
	/*
	fprintf(stderr, "ERROR: listen() error: %s\n", estr);
	*/
	logg("!listen() error: %s\n", estr);
	exit(1);
    }

    acceptloop_th(sockfd, root, copt);

    return 0;
}

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

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <clamav.h>
#include <errno.h>
#include <netdb.h>


#include "options.h"
#include "cfgparser.h"
#include "defaults.h"
#include "others.h"
#include "server.h"
#include "output.h"

int tcpserver(const struct optstruct *opt, const struct cfgstruct *copt, struct cl_node *root)
{
	struct sockaddr_in server;
	int sockfd, backlog;
	struct cfgstruct *cpt;
	struct cfgstruct *taddr;
	struct hostent *he;
	char *estr;
	int true = 1;

    memset((char *) &server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port = htons(cfgopt(copt, "TCPSocket")->numarg);


    if((taddr = cfgopt(copt, "TCPAddr"))) {
	if ((he = gethostbyname(taddr->strarg)) == 0) {
	    logg("!gethostbyname(%s) error: %s\n", taddr->strarg, strerror(errno));
	    exit(1);
	}
	server.sin_addr = *(struct in_addr *) he->h_addr_list[0];
    } else
	server.sin_addr.s_addr = INADDR_ANY;


    if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
	estr = strerror(errno);
	/*
	fprintf(stderr, "ERROR: socket() error: %s\n", estr);
	*/
	logg("!socket() error: %s\n", estr);
	exit(1);
    }

    if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (void *) &true, sizeof(true)) == -1) {
	logg("!setsocktopt(SO_REUSEADDR) error: %s\n", strerror(errno));
    }

    if(bind(sockfd, (struct sockaddr *) &server, sizeof(struct sockaddr_in)) == -1) {
	estr = strerror(errno);
	/* 
	fprintf(stderr, "ERROR: can't bind(): %s\n", estr);
	*/
	logg("!bind() error: %s\n", estr);
	exit(1);
    } else {
	if ( taddr != NULL && *taddr->strarg )
	    logg("Bound to address %s on port %d\n", taddr->strarg, cfgopt(copt, "TCPSocket")->numarg);
	else
	    logg("Bound to port %d\n", cfgopt(copt, "TCPSocket")->numarg);
    }

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

    /* if(cfgopt(copt, "UseProcesses"))
	acceptloop_proc(sockfd, root, copt);
    else */
	acceptloop_th(sockfd, root, copt);

    return 0;
}

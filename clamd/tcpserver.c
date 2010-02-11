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

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifndef	_WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#endif
#include <errno.h>

#include "libclamav/clamav.h"

#include "shared/optparser.h"
#include "shared/output.h"
#include "shared/misc.h"

#include "others.h"
#include "server.h"
#include "tcpserver.h"

int tcpserver(const struct optstruct *opts)
{
    struct sockaddr_in server;
    int sockfd, backlog;
    char *estr;
    int true = 1;

    if (cfg_tcpsock(opts, &server, INADDR_ANY) == -1) {
	return -1;
    }

    if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
	estr = strerror(errno);
	logg("!TCP: socket() error: %s\n", estr);
	return -1;
    }

    if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (void *) &true, sizeof(true)) == -1) {
	logg("!TCP: setsocktopt(SO_REUSEADDR) error: %s\n", strerror(errno));
    }

    if(bind(sockfd, (struct sockaddr *) &server, sizeof(struct sockaddr_in)) == -1) {
	estr = strerror(errno);
	logg("!TCP: bind() error: %s\n", estr);
	closesocket(sockfd);
	return -1;
    } else {
	const struct optstruct *taddr = optget(opts, "TCPAddr");
	if(taddr->enabled)
	    logg("#TCP: Bound to address %s on port %u\n", taddr->strarg, (unsigned int) optget(opts, "TCPSocket")->numarg);
	else
	    logg("#TCP: Bound to port %u\n", (unsigned int) optget(opts, "TCPSocket")->numarg);
    }

    backlog = optget(opts, "MaxConnectionQueueLength")->numarg;
    logg("#TCP: Setting connection queue length to %d\n", backlog);

    if(listen(sockfd, backlog) == -1) {
	estr = strerror(errno);
	logg("!TCP: listen() error: %s\n", estr);
	closesocket(sockfd);
	return -1;
    }

    return sockfd;
}

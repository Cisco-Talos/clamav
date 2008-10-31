/*
 *  Copyright (C) 2002 - 2005 Tomasz Kojm <tkojm@clamav.net>
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
#include <string.h>
#include <sys/types.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifndef	C_WINDOWS
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif
#include <errno.h>
#ifndef	C_WINDOWS
#include <netdb.h>
#endif

#include "libclamav/clamav.h"

#include "shared/options.h"
#include "shared/cfgparser.h"
#include "shared/output.h"
#include "shared/network.h"

#include "others.h"
#include "server.h"
#include "tcpserver.h"

#ifndef	C_WINDOWS
#define	closesocket(s)	close(s)
#endif

int tcpserver(const struct cfgstruct *copt)
{
	struct sockaddr_in server;
	int sockfd, backlog;
	const struct cfgstruct *taddr;
	struct hostent he;
	char *estr, buf[1024];
	int true = 1;

    memset((char *) &server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port = htons(cfgopt(copt, "TCPSocket")->numarg);

    if((taddr = cfgopt(copt, "TCPAddr"))->enabled) {
	if(r_gethostbyname(taddr->strarg, &he, buf, sizeof(buf)) == -1) {
	    logg("!TCP: r_gethostbyname(%s) error: %s\n", taddr->strarg, strerror(errno));
	    return -1;
	}
	server.sin_addr = *(struct in_addr *) he.h_addr_list[0];
    } else
	server.sin_addr.s_addr = INADDR_ANY;


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
	if(taddr->enabled)
	    logg("#TCP: Bound to address %s on port %u\n", taddr->strarg, cfgopt(copt, "TCPSocket")->numarg);
	else
	    logg("#TCP: Bound to port %u\n", cfgopt(copt, "TCPSocket")->numarg);
    }

    backlog = cfgopt(copt, "MaxConnectionQueueLength")->numarg;
    logg("#TCP: Setting connection queue length to %d\n", backlog);

    if(listen(sockfd, backlog) == -1) {
	estr = strerror(errno);
	logg("!TCP: listen() error: %s\n", estr);
	closesocket(sockfd);
	return -1;
    }

    return sockfd;
}

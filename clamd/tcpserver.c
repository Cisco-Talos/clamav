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

int tcpserver(int **lsockets, unsigned int *nlsockets, char *ipaddr, const struct optstruct *opts)
{
    struct addrinfo hints, *info, *p;
    int *sockets;
    int sockfd, backlog;
    int *t;
    char *estr, port[10];
    int yes = 1;
    int res;
    unsigned int i=0;

    sockets = *lsockets;

    snprintf(port, sizeof(port), "%lld", optget(opts, "TCPSocket")->numarg);

    memset(&hints, 0x00, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

#if C_LINUX
    if (!(ipaddr)) {
        /*
         * By default, getaddrinfo() will return 0.0.0.0 if NULL is passed in as the first parameter.
         * Binding to 0.0.0.0 will prevent us from also binding IPv6 ::0 (errno = EADDRINUSE). However,
         * if we bind to ::0 (or shorthand, ::), then Linux will bind to both IPv4 and IPv6.
         */
        ipaddr = "::";
    }
#endif

    if ((res = getaddrinfo(ipaddr, port, &hints, &info))) {
        logg("!TCP: getaddrinfo: %s\n", gai_strerror(res));
        return -1;
    }

    for (p = info; p != NULL; p = p->ai_next, i++) {
        t = realloc(sockets, sizeof(int) * (*nlsockets + 1));
        if (!(t)) {
            for (i=0; i < *nlsockets; i++)
                close(sockets[i]);

            return -1;
        }
        sockets = t;

        if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
            estr = strerror(errno);
            logg("!TCP: socket() error: %s\n", estr);
            continue;
        }

        if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (void *) &yes, sizeof(yes)) == -1) {
            logg("!TCP: setsocktopt(SO_REUSEADDR) error: %s\n", strerror(errno));
        }

        if(bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            estr = strerror(errno);
            if (ipaddr || i == 0)
                logg("!TCP: bind() error when trying to listen on [%s]:%s: %s\n", ipaddr, port, estr);
            closesocket(sockfd);

            continue;
        } else {
            if((ipaddr))
                logg("#TCP: Bound to address %s on port %u\n", ipaddr, (unsigned int) optget(opts, "TCPSocket")->numarg);
            else
                logg("#TCP: Bound to port %u\n", (unsigned int) optget(opts, "TCPSocket")->numarg);
        }

        backlog = optget(opts, "MaxConnectionQueueLength")->numarg;
        logg("#TCP: Setting connection queue length to %d\n", backlog);

        if(listen(sockfd, backlog) == -1) {
            estr = strerror(errno);
            logg("!TCP: listen() error: %s\n", estr);
            closesocket(sockfd);

            continue;
        }

        sockets[*nlsockets] = sockfd;
        (*nlsockets)++;
    }

    freeaddrinfo(info);
    *lsockets = sockets;

    return 0;
}

/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
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
    char host[NI_MAXHOST], serv[NI_MAXSERV];
    int *sockets;
    int sockfd = 0, backlog;
    int *t;
    char *estr, port[10];
    int yes = 1;
    int res;
    unsigned int i=0;
	int num_fd;

    sockets = *lsockets;

    num_fd = sd_listen_fds(0);
    if (num_fd > 2)
    {
        logg("!TCP: Received more than two file descriptors from systemd.\n");
        return -1;
    }
    else if (num_fd > 0)
    {
        /* use socket passed by systemd */
        int i;
        for(i = 0; i < num_fd; i += 1)
        {
            sockfd = SD_LISTEN_FDS_START + i;
            if (sd_is_socket(sockfd, AF_INET, SOCK_STREAM, 1) == 1)
            {
                /* correct socket */
                logg("#TCP: Received AF_INET SOCK_STREAM socket from systemd.\n");
                break;
            }
            else if (sd_is_socket(sockfd, AF_INET6, SOCK_STREAM, 1) == 1)
            {
                /* correct socket */
                logg("#TCP: Received AF_INET6 SOCK_STREAM socket from systemd.\n");
                break;
            }
            else
            {
                /* wrong socket */
                sockfd = -2;
            }
        }
        if (sockfd == -2)
        {
            logg("#TCP: No tcp AF_INET/AF_INET6 SOCK_STREAM socket received from systemd.\n");
            return -2;
        }

        t = realloc(sockets, sizeof(int) * (*nlsockets + 1));
        if (!(t)) {
            return -1;
        }
        sockets = t;

        sockets[*nlsockets] = sockfd;
        (*nlsockets)++;
        *lsockets = sockets;
        return 0;
    }

    /* create socket */
    snprintf(port, sizeof(port), "%lld", optget(opts, "TCPSocket")->numarg);

    memset(&hints, 0x00, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

#ifdef AI_ADDRCONFIG
    hints.ai_flags |= AI_ADDRCONFIG;
#endif

    if ((res = getaddrinfo(ipaddr, port, &hints, &info))) {
        logg("!TCP: getaddrinfo failed: %s\n", gai_strerror(res));
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

#ifdef IPV6_V6ONLY
        if (p->ai_family == AF_INET6 &&
            setsockopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY, &yes, sizeof(yes)) == -1) {
            estr = strerror(errno);
            logg("!TCP: setsocktopt(IPV6_V6ONLY) error: %s\n", estr);
        }
#endif /* IPV6_V6ONLY */

#ifdef HAVE_GETNAMEINFO
        if ((res = getnameinfo(p->ai_addr, p->ai_addrlen, host, sizeof(host),
                               serv, sizeof(serv), NI_NUMERICHOST|NI_NUMERICSERV))) {
            logg("!TCP: getnameinfo failed: %s\n", gai_strerror(res));
            host[0] = '\0';
            serv[0] = '\0';
        }
#else
		if (ipaddr) {
			strncpy(host, ipaddr, sizeof(host));
			host[sizeof(host)-1] = '\0';
		} else
			host[0] = '\0';
        snprintf(serv, sizeof(serv), "%u", (unsigned int)(optget(opts, "TCPSocket")->numarg));
#endif
        if(bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            estr = strerror(errno);
            logg("!TCP: Cannot bind to [%s]:%s: %s\n", host, serv, estr);
            closesocket(sockfd);

            continue;
        }
        logg("#TCP: Bound to [%s]:%s\n", host, serv);

        backlog = optget(opts, "MaxConnectionQueueLength")->numarg;
        logg("#TCP: Setting connection queue length to %d\n", backlog);

        if(listen(sockfd, backlog) == -1) {
            estr = strerror(errno);
            logg("!TCP: Cannot listen on [%s]:%s: %s\n", host, serv, estr);
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

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

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#ifndef	C_WINDOWS
#include <sys/socket.h>
#endif
#include <sys/stat.h>
#ifndef	C_WINDOWS
#include <sys/un.h>
#endif
#include <errno.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "libclamav/clamav.h"

#include "shared/options.h"
#include "shared/cfgparser.h"

#include "others.h"
#include "server.h"
#include "output.h"
#include "localserver.h"

#ifdef C_WINDOWS
int localserver(const struct cfgstruct *copt)
{
    logg("!Localserver is not supported on this platform");
    return -1;
}

#else

int localserver(const struct cfgstruct *copt)
{
	struct sockaddr_un server;
	int sockfd, backlog;
	struct stat foo;
	char *estr;

    memset((char *) &server, 0, sizeof(server));
    server.sun_family = AF_UNIX;
    strncpy(server.sun_path, cfgopt(copt, "LocalSocket")->strarg, sizeof(server.sun_path));
    server.sun_path[sizeof(server.sun_path)-1]='\0';

    if((sockfd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
	estr = strerror(errno);
	logg("!LOCAL: Socket allocation error: %s\n", estr);
	return -1;
    }

    if(bind(sockfd, (struct sockaddr *) &server, sizeof(struct sockaddr_un)) == -1) {
	if(errno == EADDRINUSE) {
	    if(connect(sockfd, (struct sockaddr *) &server, sizeof(struct sockaddr_un)) >= 0) {
		logg("!LOCAL: Socket file %s is in use by another process.\n", server.sun_path);
		close(sockfd);
		return -1;
	    }
	    if(cfgopt(copt, "FixStaleSocket")->enabled) {
		logg("#LOCAL: Removing stale socket file %s\n", server.sun_path);
		if(unlink(server.sun_path) == -1) {
		    estr = strerror(errno);
		    logg("!LOCAL: Socket file %s could not be removed: %s\n", server.sun_path, estr);
		    close(sockfd);
		    return -1;
		}
		if(bind(sockfd, (struct sockaddr *) &server, sizeof(struct sockaddr_un)) == -1) {
		    estr = strerror(errno);
		    logg("!LOCAL: Socket file %s could not be bound: %s (unlink tried)\n", server.sun_path, estr);
		    close(sockfd);
		    return -1;
		}
	    } else if(stat(server.sun_path, &foo) != -1) {
		logg("!LOCAL: Socket file %s exists. Either remove it, or configure a different one.\n", server.sun_path);
		close(sockfd);
		return -1;
	    }
	} else {
	    estr = strerror(errno);
	    logg("!LOCAL: Socket file %s could not be bound: %s\n", server.sun_path, estr);
	    close(sockfd);
	    return -1;
	}
    }

    logg("#LOCAL: Unix socket file %s\n", server.sun_path);

    backlog = cfgopt(copt, "MaxConnectionQueueLength")->numarg;
    logg("#LOCAL: Setting connection queue length to %d\n", backlog);

    if(listen(sockfd, backlog) == -1) {
	estr = strerror(errno);
	logg("!LOCAL: listen() error: %s\n", estr);
	close(sockfd);
	return -1;
    }

    return sockfd;
}
#endif /* C_WINDOWS */

/*
 *  Copyright (C) 2002, 2003 Tomasz Kojm <zolw@konarski.edu.pl>
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

#ifdef BUILD_CLAMD

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>

#include "others.h"
#include "cfgfile.h"

int notify(const char *cfgfile)
{
	char buff[20];
	struct sockaddr_un server;
        struct sockaddr_in server2;
	struct hostent *he;
	struct cfgstruct *copt, *cpt;
	int sockd, bread;


    if((copt = parsecfg(cfgfile)) == NULL) {
	mprintf("@Can't parse configuration file.\n");
	return 1;
    }

    if(cfgopt(copt, "TCPSocket") && cfgopt(copt, "LocalSocket")) {
	mprintf("@Clamd is not configured properly. It wasn't notified.\n");
	return 1;
    } else if((cpt = cfgopt(copt, "LocalSocket"))) {

	server.sun_family = AF_UNIX;
	strncpy(server.sun_path, cpt->strarg, sizeof(server.sun_path));

	if((sockd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
	    perror("socket()");
	    mprintf("@Can't create the socket.\n");
	    return 1;
	}

	if(connect(sockd, (struct sockaddr *) &server, sizeof(struct sockaddr_un)) < 0) {
	    close(sockd);
	    perror("connect()");
	    mprintf("@Can't connect to clamd.\n");
	    return 1;
	}

    } else if((cpt = cfgopt(copt, "TCPSocket"))) {

#ifdef PF_INET
	if((sockd = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
#else
	if((sockd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
#endif
	    perror("socket()");
	    mprintf("@Can't create the socket.\n");
	    return 1;
	}

	server2.sin_family = AF_INET;
	server2.sin_port = htons(cpt->numarg);

	if ((cpt = cfgopt(copt, "TCPAddr"))) {
	    if ((he = gethostbyname(cpt->strarg)) == 0) {
		perror("gethostbyname()");
		mprintf("@Can't lookup hostname.\n");
		return 1;
	    }
	    server2.sin_addr = *(struct in_addr *) he->h_addr_list[0];
	} else
	    server2.sin_addr.s_addr = inet_addr("127.0.0.1");


	if(connect(sockd, (struct sockaddr *) &server2, sizeof(struct sockaddr_in)) < 0) {
	    close(sockd);
	    perror("connect()");
	    mprintf("@Can't connect to clamd.\n");
	    return 1;
	}

    } else {
	mprintf("@Clamd is not configured properly. It wasn't notified.\n");
	return 1;
    }

    if(write(sockd, "RELOAD", 6) < 0) {
	mprintf("@Can't write to the socket.\n");
	close(sockd);
	return 1;
    }

    memset(buff, 0, sizeof(buff));
    if((bread = read(sockd, buff, sizeof(buff))) > 0)
	if(!strstr(buff, "RELOADING")) {
	    mprintf("@No answer from clamd.\n");
	    close(sockd);
	    return 1;
	}

    close(sockd);
    mprintf("Clamd successfully notified about the update.\n");
    logg("Clamd successfully notified about the update.\n");
    return 0;
}

#endif

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
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>

#include "others.h"
#include "defaults.h"
#include "shared.h"
#include "options.h"
#include "cfgparser.h"
#include "memory.h"
#include "output.h"

#ifdef PF_INET
# define SOCKET_INET	PF_INET
#else
# define SOCKET_INET	AF_INET
#endif

int client(const struct optstruct *opt)
{
	char buff[4096], cwd[200], *file, *scancmd, *pt;
	struct sockaddr_un server;
        struct sockaddr_in server2;
	struct hostent *he;
	struct cfgstruct *copt, *cpt;
	int sockd, wsockd, loopw = 60, bread, port;
	const char *clamav_conf = getargl(opt, "config-file");
	FILE *fd;

    if(!clamav_conf)
	clamav_conf = DEFAULT_CFG;

    if((copt = parsecfg(clamav_conf)) == NULL) {
	mprintf("@Can't parse configuration file.\n");
	return 2;
    }

    /* Set default address to connect to; needed for scanning a stream and no TCP address specified */
    server2.sin_addr.s_addr = inet_addr("127.0.0.1");    
    if(cfgopt(copt, "ScannerDaemonOutputFormat")) {
	mprintf("clamdscan won't work with the ScannerDaemonOutputFormat option\n");
	mprintf("enabled. Please disable it in %s\n", clamav_conf);
	return 2;
    }

    if(cfgopt(copt, "TCPSocket") && cfgopt(copt, "LocalSocket")) {
	mprintf("@Clamd is not configured properly.\n");
	return 2;
    } else if((cpt = cfgopt(copt, "LocalSocket"))) {

	server.sun_family = AF_UNIX;
	strncpy(server.sun_path, cpt->strarg, sizeof(server.sun_path));

	if((sockd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
	    perror("socket()");
	    mprintf("@Can't create the socket.\n");
	    return 2;
	}

	if(connect(sockd, (struct sockaddr *) &server, sizeof(struct sockaddr_un)) < 0) {
	    close(sockd);
	    perror("connect()");
	    mprintf("@Can't connect to clamd.\n");
	    return 2;
	}

    } else if((cpt = cfgopt(copt, "TCPSocket"))) {

	if((sockd = socket(SOCKET_INET, SOCK_STREAM, 0)) < 0) {
	    perror("socket()");
	    mprintf("@Can't create the socket.\n");
	    return 2;
	}

	server2.sin_family = AF_INET;
	server2.sin_port = htons(cpt->numarg);

	if((cpt = cfgopt(copt, "TCPAddr"))) {
	    if ((he = gethostbyname(cpt->strarg)) == 0) {
		close(sockd);
		perror("gethostbyname()");
		mprintf("@Can't lookup clamd hostname.\n");
		return 2;
	    }
	    server2.sin_addr = *(struct in_addr *) he->h_addr_list[0];

	}

	if(connect(sockd, (struct sockaddr *) &server2, sizeof(struct sockaddr_in)) < 0) {
	    close(sockd);
	    perror("connect()");
	    mprintf("@Can't connect to clamd.\n");
	    return 2;
	}

    } else {
	mprintf("@Clamd is not configured properly.\n");
	return 2;
    }


    if(opt->filename == NULL || strlen(opt->filename) == 0) {
	/* we need the full path to the file */
	if(!getcwd(cwd, 200)) {
	    mprintf("@Can't get the absolute pathname of the current working directory.\n");
	    return 2;
	}
	file = (char *) strdup(cwd);

    } else if(!strcmp(opt->filename, "-")) { /* scan data from stdin */
	if(write(sockd, "STREAM", 6) <= 0) {
	    mprintf("@Can't write to the socket.\n");
	    close(sockd);
	    return 2;
	}

	memset(buff, 0, sizeof(buff));
	while(loopw) {
	    read(sockd, buff, sizeof(buff));
	    if((pt = strstr(buff, "PORT"))) {
		pt += 5;
		sscanf(pt, "%d", &port);
		break;
	    }
	    loopw--;
	}

	if(!loopw) {
	    mprintf("@Daemon not ready for stream scanning.\n");
	    return 2;
	}

	/* connect to clamd */

	if((wsockd = socket(SOCKET_INET, SOCK_STREAM, 0)) < 0) {
	    perror("socket()");
	    mprintf("@Can't create the socket.\n");
	    return 2;
	}

	server2.sin_family = AF_INET;
	server2.sin_port = htons(port);

	if(connect(wsockd, (struct sockaddr *) &server2, sizeof(struct sockaddr_in)) < 0) {
	    close(wsockd);
	    perror("connect()");
	    mprintf("@Can't connect to clamd [port: %d].\n", port);
	    return 2;
	}

	while((bread = read(0, buff, sizeof(buff))) > 0) {
	    if(write(wsockd, buff, bread) <= 0) {
		mprintf("@Can't write to the socket.\n");
		close(wsockd);
		return 2;
	    }
	}
	close(wsockd);


	memset(buff, 0, sizeof(buff)); /* FIXME: ugly, but needed for mprintf */
	while((bread = read(sockd, buff, sizeof(buff))) > 0) {
	    mprintf("%s", buff);
	    if(strstr(buff, "FOUND\n")) {
		claminfo.ifiles++;
		logg("%s", buff);
	    }
	    if (strstr(buff, "ERROR\n")) {
		claminfo.errors++;
		logg("%s", buff);
	    }
	    memset(buff, 0, sizeof(buff));
	}

	return claminfo.ifiles ? 1 : (claminfo.errors ? 2 : 0);

    } else if(opt->filename[0] == '/') {
	file = (char *) strdup(opt->filename);
    } else {
	    struct stat foo;

	if(stat(opt->filename, &foo) == -1) {
	    mprintf("@Can't access file %s\n", opt->filename);
	    perror(opt->filename);
	    return 2;
	} else {
	    file = mcalloc(200 + strlen(opt->filename) + 10, sizeof(char));
#ifdef C_CYGWIN
	    sprintf(file, "%s", opt->filename);
#else
	    /* we need the full path to the file */
	    if(!getcwd(cwd, 200)) {
		mprintf("@Can't get the absolute pathname of the current working directory.\n");
		return 2;
	    }
	    sprintf(file, "%s/%s", cwd, opt->filename);
#endif
	}
    }


    scancmd = mcalloc(strlen(file) + 20, sizeof(char));
    sprintf(scancmd, "CONTSCAN %s", file);
    free(file);

    if(write(sockd, scancmd, strlen(scancmd)) <= 0) {
	mprintf("@Can't write to the socket.\n");
	close(sockd);
	return 2;
    }

    if((fd = fdopen(sockd, "r")) == NULL) {
	mprintf("@Can't open descriptor %d to read.\n", sockd);
	return 2;
    }

    while(fgets(buff, sizeof(buff), fd)) {
	if(strstr(buff, "FOUND\n")) {
	    claminfo.ifiles++;
	    logg("%s", buff);
	}
	if (strstr(buff, "ERROR\n")) {
	    claminfo.errors++;
	    logg("%s", buff);
	}
	mprintf("%s", buff);
    }

    fclose(fd);

    return claminfo.ifiles ? 1 : (claminfo.errors ? 2 : 0);
}

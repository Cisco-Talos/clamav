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
#include "str.h"

#ifdef PF_INET
# define SOCKET_INET	PF_INET
#else
# define SOCKET_INET	AF_INET
#endif


int dsfile(int sockd, const char *filename)
{
	int infected = 0, waserror = 0;
	char buff[4096], *scancmd;
	FILE *fd;


    scancmd = mcalloc(strlen(filename) + 20, sizeof(char));
    sprintf(scancmd, "CONTSCAN %s", filename);

    if(write(sockd, scancmd, strlen(scancmd)) <= 0) {
	mprintf("@Can't write to the socket.\n");
	free(scancmd);
	return -1;
    }

    free(scancmd);

    if((fd = fdopen(dup(sockd), "r")) == NULL) {
	mprintf("@Can't open descriptor for reading.\n");
	return -1;
    }

    while(fgets(buff, sizeof(buff), fd)) {
	if(strstr(buff, "FOUND\n")) {
	    infected++;
	    logg("%s", buff);
	    mprintf("%s", buff);
	}
	if (strstr(buff, "ERROR\n")) {
	    logg("%s", buff);
	    mprintf("%s", buff);
	    waserror = 1;
	}
    }

    fclose(fd);

    if(!infected)
	mprintf("%s: OK\n", filename);

    return infected ? infected : (waserror ? -1 : 0);
}

int dsstream(int sockd)
{
	int wsockd, loopw = 60, bread, port, infected = 0;
	struct sockaddr_in server;
	struct sockaddr_in peer;
	int peer_size;
	char buff[4096], *pt;

    if(write(sockd, "STREAM", 6) <= 0) {
	mprintf("@Can't write to the socket.\n");
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
	return -1;
    }

    /* connect to clamd */

    if((wsockd = socket(SOCKET_INET, SOCK_STREAM, 0)) < 0) {
	perror("socket()");
	mprintf("@Can't create the socket.\n");
	return -1;
    }

    server.sin_family = AF_INET;
    server.sin_port = htons(port);

    peer_size = sizeof(peer);
    if(getpeername(sockd, (struct sockaddr *) &peer, &peer_size) < 0) {
	perror("getpeername()");
	mprintf("@Can't get socket peer name.\n");
	return -1;
    }

    switch (peer.sin_family) {
	case AF_UNIX:
	    server.sin_addr.s_addr = inet_addr("127.0.0.1");
	    break;
	case AF_INET:
	    server.sin_addr.s_addr = peer.sin_addr.s_addr;
	    break;
	default:
	    mprintf("@Unexpected socket type: %d.\n", peer.sin_family);
	    return -1;
    }

    if(connect(wsockd, (struct sockaddr *) &server, sizeof(struct sockaddr_in)) < 0) {
	close(wsockd);
	perror("connect()");
	mprintf("@Can't connect to clamd [port: %d].\n", port);
	return -1;
    }

    while((bread = read(0, buff, sizeof(buff))) > 0) {
	if(write(wsockd, buff, bread) <= 0) {
	    mprintf("@Can't write to the socket.\n");
	    close(wsockd);
	    return -1;
	}
    }
    close(wsockd);

    memset(buff, 0, sizeof(buff));
    while((bread = read(sockd, buff, sizeof(buff))) > 0) {
	mprintf("%s", buff);
	if(strstr(buff, "FOUND\n")) {
	    infected++;
	    logg("%s", buff);
	}
	if(strstr(buff, "ERROR\n")) {
	    logg("%s", buff);
	    return -1;
	}
	memset(buff, 0, sizeof(buff));
    }

    return infected;
}

char *abpath(const char *filename)
{
	struct stat foo;
	char *fullpath, cwd[200];

    if(stat(filename, &foo) == -1) {
	mprintf("@Can't access file %s\n", filename);
	perror(filename);
	return NULL;
    } else {
	fullpath = mcalloc(200 + strlen(filename) + 10, sizeof(char));
#ifdef C_CYGWIN
	sprintf(fullpath, "%s", filename);
#else
	if(!getcwd(cwd, 200)) {
	    mprintf("@Can't get absolute pathname of current working directory.\n");
	    return NULL;
	}
	sprintf(fullpath, "%s/%s", cwd, filename);
#endif
    }

    return fullpath;
}

int dconnect(const struct optstruct *opt)
{
	struct sockaddr_un server;
	struct sockaddr_in server2;
	struct hostent *he;
	struct cfgstruct *copt, *cpt;
	const char *clamav_conf = getargl(opt, "config-file");
	int sockd;


    if(!clamav_conf)
	clamav_conf = DEFAULT_CFG;

    if((copt = parsecfg(clamav_conf, 1)) == NULL) {
	mprintf("@Can't parse the configuration file.\n");
	return -1;
    }

    /* Set default address to connect to */
    server2.sin_addr.s_addr = inet_addr("127.0.0.1");    

    if(cfgopt(copt, "TCPSocket") && cfgopt(copt, "LocalSocket")) {
	mprintf("@Clamd is not configured properly.\n");
	return -1;
    } else if((cpt = cfgopt(copt, "LocalSocket"))) {

	server.sun_family = AF_UNIX;
	strncpy(server.sun_path, cpt->strarg, sizeof(server.sun_path));

	if((sockd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
	    perror("socket()");
	    mprintf("@Can't create the socket.\n");
	    return -1;
	}

	if(connect(sockd, (struct sockaddr *) &server, sizeof(struct sockaddr_un)) < 0) {
	    close(sockd);
	    perror("connect()");
	    mprintf("@Can't connect to clamd.\n");
	    return -1;
	}

    } else if((cpt = cfgopt(copt, "TCPSocket"))) {

	if((sockd = socket(SOCKET_INET, SOCK_STREAM, 0)) < 0) {
	    perror("socket()");
	    mprintf("@Can't create the socket.\n");
	    return -1;
	}

	server2.sin_family = AF_INET;
	server2.sin_port = htons(cpt->numarg);

	if((cpt = cfgopt(copt, "TCPAddr"))) {
	    if ((he = gethostbyname(cpt->strarg)) == 0) {
		close(sockd);
		perror("gethostbyname()");
		mprintf("@Can't lookup clamd hostname.\n");
		return -1;
	    }
	    server2.sin_addr = *(struct in_addr *) he->h_addr_list[0];
	}

	if(connect(sockd, (struct sockaddr *) &server2, sizeof(struct sockaddr_in)) < 0) {
	    close(sockd);
	    perror("connect()");
	    mprintf("@Can't connect to clamd.\n");
	    return -1;
	}

    } else {
	mprintf("@Clamd is not configured properly.\n");
	return -1;
    }

    return sockd;
}

int client(const struct optstruct *opt, int *infected)
{
	char cwd[200], *fullpath;
	int sockd, ret, errors = 0;
	struct stat sb;


    *infected = 0;

    /* parse argument list */

    if(opt->filename == NULL || strlen(opt->filename) == 0) {
	/* scan current directory */
	if(!getcwd(cwd, 200)) {
	    mprintf("@Can't get absolute pathname of current working directory.\n");
	    return 2;
	}

	if((sockd = dconnect(opt)) < 0)
	    return 2;

	if((ret = dsfile(sockd, cwd)) >= 0)
	    *infected += ret;
	else
	    errors++;

	close(sockd);

    } else if(!strcmp(opt->filename, "-")) { /* scan data from stdin */
	if((sockd = dconnect(opt)) < 0)
	    return 2;

	if((ret = dsstream(sockd)) >= 0)
	    *infected += ret;
	else
	    errors++;

	close(sockd);

    } else {
	int x;
	char *thefilename;
	for (x = 0; (thefilename = cli_strtok(opt->filename, x, "\t")) != NULL; x++) {
	    fullpath = thefilename;

	    if(stat(fullpath, &sb) == -1) {
		mprintf("@Can't access file %s\n", fullpath);
		perror(fullpath);
		errors++;
	    } else {
		if(fullpath[0] != '/') {
		    fullpath = abpath(thefilename);
		    free(thefilename);

		    if(!fullpath) {
			mprintf("@Can't determine absolute path.\n");
			return 2;
		    }
		}

		switch(sb.st_mode & S_IFMT) {
		    case S_IFREG:
		    case S_IFDIR:
			if((sockd = dconnect(opt)) < 0)
			    return 2;

			if((ret = dsfile(sockd, fullpath)) >= 0)
			    *infected += ret;
			else
			    errors++;

			close(sockd);
			break;

		    default:
			mprintf("@Not supported file type (%s)\n", fullpath);
			errors++;
		}
	    }

	    free(fullpath);
	}
    }

    return *infected ? 1 : (errors ? 2 : 0);
}

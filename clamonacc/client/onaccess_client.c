/*
 *  Copyright (C) 2015-2018 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2009 Sourcefire, Inc.
 *
 *  Authors: Tomasz Kojm, aCaB, Mickey Sola
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
#include <stdlib.h>
#ifdef	HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#ifdef HAVE_SYS_LIMITS_H
#include <sys/limits.h>
#endif
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <utime.h>
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>

#ifdef HAVE_SYS_UIO_H
#include <sys/uio.h>
#endif

#include "libclamav/clamav.h"
#include "shared/optparser.h"
#include "shared/output.h"
#include "shared/misc.h"
#include "shared/actions.h"
#include "shared/clamdcom.h"

#include "libclamav/str.h"
#include "libclamav/others.h"

#include "onaccess_client.h"
#include "onaccess_proto.h"

#include "../clamonacc.h"

struct sockaddr_un nixsock;

static void print_server_version(struct onas_context **ctx)
{
	if(onas_get_clamd_version(ctx)) {
		/* can't get version from server, fallback */
		printf("ClamAV %s\n", get_version());

	}
}


/* Inits the communication layer
 * Returns 0 if clamd is local, non zero if clamd is remote */
int onas_check_remote(struct onas_context  **ctx) {
    int s, ret;
    const struct optstruct *opt;
    char *ipaddr = NULL;
    char port[10];
    struct addrinfo hints, *info, *p;
    int res;

#ifndef _WIN32
    if((opt = optget((*ctx)->clamdopts, "LocalSocket"))->enabled) {
        memset((void *)&nixsock, 0, sizeof(nixsock));
        nixsock.sun_family = AF_UNIX;
        strncpy(nixsock.sun_path, opt->strarg, sizeof(nixsock.sun_path));
        nixsock.sun_path[sizeof(nixsock.sun_path)-1]='\0';
        return 0;
    }
#endif
    if(!(opt = optget((*ctx)->clamdopts, "TCPSocket"))->enabled)
        return 0;

    snprintf(port, sizeof(port), "%lld", optget((*ctx)->clamdopts, "TCPSocket")->numarg);

    opt = optget((*ctx)->clamdopts, "TCPAddr");
    while (opt) {

        if (opt->strarg)
            ipaddr = (!strcmp(opt->strarg, "any") ? NULL : opt->strarg);

        memset(&hints, 0x00, sizeof(struct addrinfo));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = AI_PASSIVE;

        if ((res = getaddrinfo(ipaddr, port, &hints, &info))) {
            logg("!Can't lookup clamd hostname: %s\n", gai_strerror(res));
            opt = opt->nextarg;
            continue;
        }

        for (p = info; p != NULL; p = p->ai_next) {
            if((s = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) < 0) {
                logg("isremote: socket() returning: %s.\n", strerror(errno));
                continue;
            }

            switch (p->ai_family) {
            case AF_INET:
                ((struct sockaddr_in *)(p->ai_addr))->sin_port = htons(INADDR_ANY);
                break;
            case AF_INET6:
                ((struct sockaddr_in6 *)(p->ai_addr))->sin6_port = htons(INADDR_ANY);
                break;
            default:
                break;
            }

            ret = bind(s, p->ai_addr, p->ai_addrlen);
            if (ret) {
                if (errno == EADDRINUSE) {
                    /*
                     * If we can't bind, then either we're attempting to listen on an IP that isn't
                     * ours or that clamd is already listening on.
                     */
                    closesocket(s);
                    freeaddrinfo(info);
                    return 0;
                }

                closesocket(s);
                freeaddrinfo(info);
                return 1;
            }

            closesocket(s);
        }

        freeaddrinfo(info);

        opt = opt->nextarg;
    }

    return 0;
}

cl_error_t onas_setup_client (struct onas_context **ctx) {

    const struct optstruct *opts;
    const struct optstruct *opt;
    errno = 0;
    int remote;

    opts = (*ctx)->opts;

    if(optget(opts, "verbose")->enabled) {
        mprintf_verbose = 1;
	logg_verbose = 1;
    }

    if(optget(opts, "version")->enabled) {
	print_server_version(ctx);
	return CL_BREAK;
    }

    if(optget(opts, "help")->enabled) {
    	help();
	return CL_BREAK;
    }

    if(optget(opts, "infected")->enabled) {
	(*ctx)->printinfected = 1;
    }

    /* initialize logger */

    if((opt = optget(opts, "log"))->enabled) {
	logg_file = opt->strarg;
	if(logg("--------------------------------------\n")) {
	    logg("!ClamClient: problem with internal logger\n");
            return CL_EARG;
	}
    } else
	logg_file = NULL;

    if(actsetup(opts)) {
	return CL_EARG;
    }

    if (onas_check_remote(ctx)) {
        (*ctx)->isremote = 1;
    } else if (errno == EADDRINUSE) {
        return CL_EARG;
    }

    remote = (*ctx)->isremote | optget(opts, "stream")->enabled;
#ifdef HAVE_FD_PASSING
    if(!remote && optget((*ctx)->clamdopts, "LocalSocket")->enabled && (optget(opts, "fdpass")->enabled)) {
        logg("*ClamClient: client setup to scan via fd passing\n");
        (*ctx)->scantype = FILDES;
        (*ctx)->session = optget(opts, "multiscan")->enabled;
    } else
#endif
        if(remote) {
            logg("*ClamClient: client setup to scan via streaming\n");
            (*ctx)->scantype = STREAM;
            (*ctx)->session = optget(opts, "multiscan")->enabled;
        } else if(optget(opts, "multiscan")->enabled) {
            logg("*ClamClient: client setup to scan in multiscan mode\n");
            (*ctx)->scantype = MULTI;
        } else if(optget(opts, "allmatch")->enabled) {
            logg("*ClamClient: client setup to scan in all-match mode\n");
            (*ctx)->scantype = ALLMATCH;
        } else {
            logg("*ClamClient: client setup for continuous scanning\n");
            (*ctx)->scantype = CONT;
        }

    (*ctx)->maxstream = optget((*ctx)->clamdopts, "StreamMaxLength")->numarg;

    return CL_SUCCESS;
}

/* Turns a relative path into an absolute one
 * Returns a pointer to the path (which must be
 * freed by the caller) or NULL on error */
static char *onas_make_absolute(const char *basepath) {
    int namelen;
    char *ret;

    if(!(ret = malloc(PATH_MAX + 1))) {
	logg("^ClamClient: can't make room for fullpath\n");
	return NULL;
    }
    if(!cli_is_abspath(basepath)) {
	if(!getcwd(ret, PATH_MAX)) {
	    logg("^ClamClient: can't get absolute pathname of current working directory.\n");
	    free(ret);
	    return NULL;
	}
	if(*basepath == '\\') {
	    namelen = 2;
	    basepath++;
	} else {
		namelen = strlen(ret);
	}
	snprintf(&ret[namelen], PATH_MAX - namelen, PATHSEP"%s", basepath);
    } else {
	strncpy(ret, basepath, PATH_MAX);
    }
    ret[PATH_MAX] = '\0';
    return ret;
}

int onas_get_clamd_version(struct onas_context **ctx)
{
    char *buff;
    int len, sockd;
    struct RCVLN rcv;

    onas_check_remote(ctx);
    if((sockd = onas_dconnect(ctx)) < 0) {
        return 2;
    }
    recvlninit(&rcv, sockd);

    if(sendln(sockd, "zVERSION", 9)) {
        closesocket(sockd);
        return 2;
    }

    while((len = recvln(&rcv, &buff, NULL))) {
        if(len == -1) {
            logg("*ClamClient: clamd did not respond with version information\n");
            break;
        }
        printf("%s\n", buff);
    }

    closesocket(sockd);
    return 0;
}

int onas_client_scan(struct onas_context **ctx, const char *fname, STATBUF sb, int *infected, int *err, cl_error_t *ret_code)
{
	int scantype, errors = 0;
	int sockd, ret;

	*infected = 0;

	if((sb.st_mode & S_IFMT) != S_IFREG) {
		scantype = STREAM;
	} else {
		scantype = (*ctx)->scantype;
        }

	/* logg here is noisy even for debug, enable only for dev work if something has gone very wrong. */
        //logg("*ClamClient: connecting to daemon ...\n");
	if((sockd = onas_dconnect(ctx)) >= 0 && (ret = onas_dsresult(ctx, sockd, scantype, fname, &ret, err, ret_code)) >= 0) {
		*infected = ret;
	} else {
		logg("*ClamClient: connection could not be established ... return code %d\n", *ret_code);
		errors = 1;
	}
	if(sockd >= 0) {
		/* logg here is noisy even for debug, enable only for dev work if something has gone very wrong. */
		//logg("*ClamClient: done, closing connection ...\n");
		closesocket(sockd);
	}

	return *infected ? 1 : (errors ? 2 : 0);
}

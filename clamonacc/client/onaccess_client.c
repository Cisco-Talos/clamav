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
#include <curl/curl.h>
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

#include "libclamav/str.h"
#include "libclamav/others.h"


#include "onaccess_com.h"
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
int onas_check_remote(struct onas_context  **ctx, cl_error_t *err) {
	int s, ret;
	const struct optstruct *opt;
	CURL *curl;
	CURLcode curlcode;
	char *ipaddr = NULL;
	char port[10];
	struct addrinfo hints, *info, *p;
	int res;

	*err = CL_SUCCESS;

#ifndef _WIN32
	if((opt = optget((*ctx)->clamdopts, "LocalSocket"))->enabled) {
		return 0;
	}
#endif
	if(!(opt = optget((*ctx)->clamdopts, "TCPSocket"))->enabled) {
		return 0;
	}

	snprintf(port, sizeof(port), "%lld", optget((*ctx)->clamdopts, "TCPSocket")->numarg);

	if ((*ctx)->portstr) {
		free((*ctx)->portstr);
	}

	(*ctx)->portstr = cli_strdup(port);
	if ( NULL == (*ctx)->portstr ) {
		*err = CL_EARG;
		return 0;
	}

	opt = optget((*ctx)->clamdopts, "TCPAddr");
	while (opt) {

		if (opt->strarg) {
			ipaddr = (!strcmp(opt->strarg, "any") ? NULL : opt->strarg);
		}

		if (NULL == ipaddr) {
			logg("!ClamClient: Clamonacc does not support binding to INADDR_ANY, \
					please specify an address with TCPAddr in your clamd.conf config file\n");
			*err = CL_EARG;
			return 1;
		}

		curlcode = onas_curl_init(&curl, ipaddr, port);
		if (CURLE_OK != curlcode) {
			logg("!ClamClient: could not init curl, %s\n", curl_easy_strerror(curlcode));
			*err = CL_EARG;
			return 1;
		}

		curlcode = curl_easy_perform(curl);
		if (CURLE_OK != curlcode) {
			logg("!ClamClient: could not connect to remote clam daemon, %s\n", curl_easy_strerror(curlcode));
			*err = CL_EARG;
			return 1;
		}

		curl_easy_cleanup(curl);

		opt = opt->nextarg;
	}

	if (*err == CL_SUCCESS) {
		return 1;
	} else {
		return 0;
	}
}

CURLcode onas_curl_init(CURL **curl, char *ipaddr, char *port) {

	CURLcode curlcode = CURLE_OK;

	if (!curl || !(*curl) || !ipaddr || !port) {
		logg("!ClamClient: invalid (NULL) args passed to onas_curl_init\n");
		return CURLE_FAILED_INIT;
	}

	*curl = curl_easy_init();

	curlcode = curl_easy_setopt(*curl, CURLOPT_PORT, port);
        if (CURLE_OK != curlcode) {
		logg("!ClamClient: could not setup curl with tcp port, %s\n", curl_easy_strerror(curlcode));
		curl_easy_cleanup(*curl);
		return curlcode;
        }

	curlcode = curl_easy_setopt(*curl, CURLOPT_URL, ipaddr);
        if (CURLE_OK != curlcode) {
		logg("!ClamClient: could not setup curl with tcp address, %s\n", curl_easy_strerror(curlcode));
		curl_easy_cleanup(*curl);
		return curlcode;
        }

	/* we implement our own transfer protocol via send and recv, so we only need to connect */
	curlcode = curl_easy_setopt(curl, CURLOPT_CONNECT_ONLY, 1L);
	if (CURLE_OK != curlcode) {
		logg("!ClamClient: could not setup curl to connect only, %s\n", curl_easy_strerror(curlcode));
		curl_easy_cleanup(*curl);
		return curlcode;
	}

	return curlcode;
}

cl_error_t onas_setup_client (struct onas_context **ctx) {

    const struct optstruct *opts;
    const struct optstruct *opt;
    cl_error_t err;
    int remote;

    errno = 0;

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
    } else {
	logg_file = NULL;
    }

    if(actsetup(opts)) {
	return CL_EARG;
    }

    if (curl_global_init(CURL_GLOBAL_NOTHING)) {
        return CL_EARG;
    }

    (*ctx)->isremote = onas_check_remote(ctx, &err);
    if (err) {
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
    CURL *curl;
    CURLcode curlcode;
    cl_error_t err = CL_SUCCESS;
    int b_remote;
    int len, sockd;
    struct RCVLN rcv;

    b_remote = onas_check_remote(ctx, &err);
    if (CL_SUCCESS != err) {
	    logg("!ClamClient: could not check to see if daemon was remote\n");
	    return 2;
    }

    if (!b_remote) {
	curl = curl_easy_init();
        curlcode = curl_easy_setopt(curl, CURLOPT_UNIX_SOCKET_PATH, optget((*ctx)->clamdopts, "LocalSocket")->strarg);
	if (CURLE_OK != curlcode) {
		logg("!ClamClient: could not setup curl with local unix socket, %s\n", curl_easy_strerror(curlcode));
		curl_easy_cleanup(curl);
		return 2;
	}
    } else {
	curlcode = onas_curl_init(&curl, optget((*ctx)->clamdopts, "TCPAddr")->strarg, (*ctx)->portstr);
	if (CURLE_OK != curlcode) {
		logg("!ClamClient: could not setup curl with tcp address and port, %s\n", curl_easy_strerror(curlcode));
		/* curl cleanup done in ons_curl_init on error */
		return 2;
	}
    }

    onas_recvlninit(&rcv, curl);

    curlcode = curl_easy_perform(curl);
    if (CURLE_OK != curlcode) {
	    logg("!ClamClient: could not connect to clam daemon, %s\n", curl_easy_strerror(curlcode));
	    return 2;
    }


    if(onas_sendln(curl, "zVERSION", 9)) {
        curl_easy_close(curl);
        return 2;
    }

    while((len = onas_recvln(&rcv, &buff, NULL))) {
        if(len == -1) {
            logg("*ClamClient: clamd did not respond with version information\n");
            break;
        }
        printf("%s\n", buff);
    }

    curl_easy_close(curl);
    return 0;
}

int onas_client_scan(struct onas_context **ctx, const char *fname, STATBUF sb, int *infected, int *err, cl_error_t *ret_code)
{
	CURL *curl = NULL;
	CURLcode curlcode = CURLE_OK;
	int scantype, errors = 0;
	int sockd, ret;

	*infected = 0;

	if((sb.st_mode & S_IFMT) != S_IFREG) {
		scantype = STREAM;
	} else {
		scantype = (*ctx)->scantype;
        }

	curlcode = onas_curl_init(&curl, optget((*ctx)->clamdopts, "TCPAddr")->strarg, (*ctx)->portstr);
	if (CURLE_OK != curlcode) {
		logg("!ClamClient: could not setup curl with tcp address and port, %s\n", curl_easy_strerror(curlcode));
		/* curl cleanup done in ons_curl_init on error */
		return 2;
	}

	/* logg here is noisy even for debug, enable only for dev work if something has gone very wrong. */
        //logg("*ClamClient: connecting to daemon ...\n");
	curlcode = curl_easy_perform(curl);
	if (CURLE_OK != curlcode) {
		logg("!ClamClient: could not establish connection, %s\n", curl_easy_strerror(curlcode));
		return 2;
	}


	if((ret = onas_dsresult(ctx, curl, scantype, fname, &ret, err, ret_code)) >= 0) {
		*infected = ret;
	} else {
		logg("*ClamClient: connection could not be established ... return code %d\n", *ret_code);
		errors = 1;
	}
	/* logg here is noisy even for debug, enable only for dev work if something has gone very wrong. */
	//logg("*ClamClient: done, closing connection ...\n");

	curl_easy_cleanup(curl);
	return *infected ? 1 : (errors ? 2 : 0);
}


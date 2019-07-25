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
#ifdef HAVE_UNISTD_H
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

#include "communication.h"
#include "client.h"
#include "protocol.h"

#include "../clamonacc.h"

struct sockaddr_un nixsock;

void onas_print_server_version(struct onas_context **ctx)
{
    if (onas_get_clamd_version(ctx)) {
        /* can't get version from server, fallback */
        printf("ClamAV %s\n", get_version());
    }
}

/* Inits the communication layer
 * Returns 0 if clamd is local, non zero if clamd is remote */
int onas_check_remote(struct onas_context **ctx, cl_error_t *err)
{
    int s, ret;
    const struct optstruct *opt;
    CURL *curl;
    CURLcode curlcode;
    char *ipaddr = NULL;
    struct addrinfo hints, *info, *p;
    int res;
    int64_t timeout;

    timeout = optget((*ctx)->clamdopts, "OnAccessCurlTimeout")->numarg;

    *err = CL_SUCCESS;

#ifndef _WIN32
    if ((opt = optget((*ctx)->clamdopts, "LocalSocket"))->enabled) {
        opt             = optget((*ctx)->clamdopts, "LocalSocket");
        (*ctx)->portnum = 0;
        ret             = 0;
    } else {
        opt             = optget((*ctx)->clamdopts, "TCPAddr");
        (*ctx)->portnum = optget((*ctx)->clamdopts, "TCPSocket")->numarg;
        ret             = 1;
    }
#else
    if (!(opt = optget((*ctx)->clamdopts, "TCPSocket"))->enabled) {
        return 0;
    }
#endif

    while (opt) {

        if (opt->strarg) {
            ipaddr = (!strcmp(opt->strarg, "any") ? NULL : opt->strarg);
        }

        if (NULL == ipaddr) {
            logg("!ClamClient: Clamonacc does not support binding to INADDR_ANY, \
					please specify an address with TCPAddr in your clamd.conf config file\n");
            *err = CL_EARG;
            return ret;
        }

        curlcode = onas_curl_init(&curl, ipaddr, (*ctx)->portnum, timeout);
        if (CURLE_OK != curlcode) {
            logg("!ClamClient: could not init curl, %s\n", curl_easy_strerror(curlcode));
            *err = CL_EARG;
            return ret;
        }

        curlcode = curl_easy_perform(curl);
        if (CURLE_OK != curlcode) {
            logg("!ClamClient: could not connect to remote clam daemon, %s\n", curl_easy_strerror(curlcode));
            *err = CL_EARG;
            return ret;
        }

#ifndef ONAS_DEBUG
        if (onas_sendln(curl, "zPING", 5, timeout)) {
            logg("!ClamClient: could not ping clamd, %s\n", curl_easy_strerror(curlcode));
            *err = CL_EARG;
            curl_easy_cleanup(curl);
            return ret;
        }
#endif

        curl_easy_cleanup(curl);

        opt = opt->nextarg;
    }

    return ret;
}

/**
 * @brief initialises a curl connection for the onaccess client; curl must be initialised globally before use
 *
 * @param curl pointer to the curl object to be used in the connection attempt
 * @param ipaddr string which refers to either the TCPaddress or the local socket to connect to
 * @param port the port to use in case of TCP connection, set to 0 if connecting to a local socket
 * @param timeout time in ms to allow curl before timing out connection attempts
 */
CURLcode onas_curl_init(CURL **curl, const char *ipaddr, int64_t port, int64_t timeout)
{

    CURLcode curlcode = CURLE_OK;

    if (!curl || !ipaddr) {
        logg("!ClamClient: invalid (NULL) args passed to onas_curl_init\n");
        return CURLE_FAILED_INIT;
    }

    /* setup here, but caller needs to cleanup */
    *curl = curl_easy_init();

    if (!port) {

        /* "ipaddr" is actually our unix socket path here */
        curlcode = curl_easy_setopt(*curl, CURLOPT_UNIX_SOCKET_PATH, ipaddr);
        if (CURLE_OK != curlcode) {
            logg("!ClamClient: could not setup curl with local unix socket, %s\n", curl_easy_strerror(curlcode));
            curl_easy_cleanup(*curl);
            return curlcode;
        }

        curlcode = curl_easy_setopt(*curl, CURLOPT_URL, "http://localhost/");
        if (CURLE_OK != curlcode) {
            logg("!ClamClient: could not setup curl with local address, %s\n", curl_easy_strerror(curlcode));
            curl_easy_cleanup(*curl);
            return curlcode;
        }

    } else {

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
    }

    curlcode = curl_easy_setopt(*curl, CURLOPT_NOSIGNAL, 1L);
    if (CURLE_OK != curlcode) {
        logg("!ClamClient: could not setup curl to not use signals, %s\n", curl_easy_strerror(curlcode));
        curl_easy_cleanup(*curl);
        return curlcode;
    }

    curlcode = curl_easy_setopt(*curl, CURLOPT_CONNECTTIMEOUT_MS, (long)timeout);
    if (CURLE_OK != curlcode) {
        logg("!ClamClient: could not setup curl with connect timeout, %s\n", curl_easy_strerror(curlcode));
        curl_easy_cleanup(*curl);
        return curlcode;
    }

    /* we implement our own transfer protocol via send and recv, so we only need to connect */
    curlcode = curl_easy_setopt(*curl, CURLOPT_CONNECT_ONLY, 1L);
    if (CURLE_OK != curlcode) {
        logg("!ClamClient: could not setup curl to connect only, %s\n", curl_easy_strerror(curlcode));
        curl_easy_cleanup(*curl);
        return curlcode;
    }

#ifdef ONAS_DEBUG
    curlcode = curl_easy_setopt(*curl, CURLOPT_VERBOSE, 1L);
    if (CURLE_OK != curlcode) {
        logg("!ClamClient: could not tell curl to be verbose, %s\n", curl_easy_strerror(curlcode));
        curl_easy_cleanup(*curl);
        return curlcode;
    }
#endif

    /* don't care about the body of the return message */
    curlcode = curl_easy_setopt(*curl, CURLOPT_NOBODY, 1L);
    if (CURLE_OK != curlcode) {
        logg("!ClamClient: could not setup curl to send HEAD request, %s\n", curl_easy_strerror(curlcode));
        curl_easy_cleanup(*curl);
        return curlcode;
    }

    curlcode = curl_easy_setopt(*curl, CURLOPT_HEADER, 0L);
    if (CURLE_OK != curlcode) {
        logg("!ClamClient: could not setup curl to not send header, %s\n", curl_easy_strerror(curlcode));
        curl_easy_cleanup(*curl);
        return curlcode;
    }

    return curlcode;
}

cl_error_t onas_setup_client(struct onas_context **ctx)
{

    const struct optstruct *opts;
    const struct optstruct *opt;
    cl_error_t err;
    int remote;

    errno = 0;

    opts = (*ctx)->opts;

    if (optget(opts, "verbose")->enabled) {
        mprintf_verbose = 1;
        logg_verbose    = 1;
    }

    if (optget(opts, "infected")->enabled) {
        (*ctx)->printinfected = 1;
    }

    /* initialize logger */

    if ((opt = optget(opts, "log"))->enabled) {
        logg_file = opt->strarg;
        if (logg("--------------------------------------\n")) {
            logg("!ClamClient: problem with internal logger\n");
            return CL_EARG;
        }
    } else {
        logg_file = NULL;
    }

    if (actsetup(opts)) {
        return CL_EARG;
    }

    (*ctx)->timeout        = optget((*ctx)->clamdopts, "OnAccessCurlTimeout")->numarg;
    (*ctx)->retry_attempts = optget((*ctx)->clamdopts, "OnAccessRetryAttempts")->numarg;
    (*ctx)->retry_attempts ? ((*ctx)->retry_on_error = 1) : ((*ctx)->retry_on_error = 0);
    optget((*ctx)->clamdopts, "OnAccessDenyOnError")->enabled ? ((*ctx)->deny_on_error = 1) : ((*ctx)->deny_on_error = 0);

    (*ctx)->isremote = onas_check_remote(ctx, &err);
    if (err) {
        return CL_EARG;
    }

    remote = (*ctx)->isremote | optget(opts, "stream")->enabled;
#ifdef HAVE_FD_PASSING
    if (!remote && optget((*ctx)->clamdopts, "LocalSocket")->enabled && (optget(opts, "fdpass")->enabled)) {
        logg("*ClamClient: client setup to scan via fd passing\n");
        (*ctx)->scantype = FILDES;
        (*ctx)->session  = optget(opts, "multiscan")->enabled;
    } else
#endif
        if (remote) {
        logg("*ClamClient: client setup to scan via streaming\n");
        (*ctx)->scantype = STREAM;
        (*ctx)->session  = optget(opts, "multiscan")->enabled;
    } else if (optget(opts, "multiscan")->enabled) {
        logg("*ClamClient: client setup to scan in multiscan mode\n");
        (*ctx)->scantype = MULTI;
    } else if (optget(opts, "allmatch")->enabled) {
        logg("*ClamClient: client setup to scan in all-match mode\n");
        (*ctx)->scantype = ALLMATCH;
    } else {
        logg("*ClamClient: client setup for continuous scanning\n");
        (*ctx)->scantype = CONT;
    }

    (*ctx)->maxstream = optget((*ctx)->clamdopts, "StreamMaxLength")->numarg;

    return CL_SUCCESS;
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
    int64_t timeout;

    timeout = optget((*ctx)->clamdopts, "OnAccessCurlTimeout")->numarg;

    b_remote = onas_check_remote(ctx, &err);
    if (CL_SUCCESS != err) {
        logg("!ClamClient: could not check to see if daemon was remote\n");
        return 2;
    }

    if (!b_remote) {
        curlcode = onas_curl_init(&curl, optget((*ctx)->clamdopts, "LocalSocket")->strarg, 0, timeout);
    } else {
        curlcode = onas_curl_init(&curl, optget((*ctx)->clamdopts, "TCPAddr")->strarg, (*ctx)->portnum, timeout);
        if (CURLE_OK != curlcode) {
            logg("!ClamClient: could not setup curl with tcp address and port, %s\n", curl_easy_strerror(curlcode));
            /* curl cleanup done in onas_curl_init on error */
            return 2;
        }
    }

    onas_recvlninit(&rcv, curl);

    curlcode = curl_easy_perform(curl);
    if (CURLE_OK != curlcode) {
        logg("*ClamClient: could not connect to clam daemon, %s\n", curl_easy_strerror(curlcode));
        return 2;
    }

    if (onas_sendln(curl, "zVERSION", 9, timeout)) {
        curl_easy_cleanup(curl);
        return 2;
    }

    while ((len = onas_recvln(&rcv, &buff, NULL, timeout))) {
        if (len == -1) {
            logg("*ClamClient: clamd did not respond with version information\n");
            break;
        }
        printf("%s\n", buff);
    }

    curl_easy_cleanup(curl);
    return 0;
}

/**
 * @brief kick off scanning and return results
 *
 * @param tcpaddr   string string which refers to either the TCPaddress or the local socket to connect to
 * @param portnum   the port to use in case of TCP connection, set to 0 if connecting to a local socket
 * @param scantype  the type of scan to perform, e.g. fdpass, stream
 * @param maxstream the max streamsize (in bytes) allowed across the socket per file
 * @param fname     the name of the file to be scanned
 * @param fd        the file descriptor for the file to be scanned, often (but not always) this is held by fanotify
 * @param timeout   time in ms to allow curl before timing out connection attempts
 * @param sb        variable to store and pass all of our stat info on the file so we don't have to access it multiple times (triggering multiple events)
 * @param infected  return variable indincating whether daemon returned with an infected verdict or not
 * @param err       return variable passed to the daemon protocol interface indicating how many things went wrong in the course of scanning
 * @param ret_code  return variable passed to the daemon protocol interface indicating last known issue or success
 */
int onas_client_scan(const char *tcpaddr, int64_t portnum, int32_t scantype, uint64_t maxstream, const char *fname, int fd, int64_t timeout, STATBUF sb, int *infected, int *err, cl_error_t *ret_code)
{
    CURL *curl        = NULL;
    CURLcode curlcode = CURLE_OK;
    int errors        = 0;
    int sockd, ret;

    *infected = 0;

    if ((sb.st_mode & S_IFMT) != S_IFREG) {
        scantype = STREAM;
    }

    curlcode = onas_curl_init(&curl, tcpaddr, portnum, timeout);
    if (CURLE_OK != curlcode) {
        logg("!ClamClient: could not init curl for scanning, %s\n", curl_easy_strerror(curlcode));
        /* curl cleanup done in onas_curl_init on error */
        return CL_ECREAT;
    }

    curlcode = curl_easy_perform(curl);
    if (CURLE_OK != curlcode) {
        logg("!ClamClient: could not establish connection, %s\n", curl_easy_strerror(curlcode));
        return CL_ECREAT;
    }

    if ((ret = onas_dsresult(curl, scantype, maxstream, fname, fd, timeout, &ret, err, ret_code)) >= 0) {
        *infected = ret;
    } else {
        logg("*ClamClient: connection could not be established ... return code %d\n", *ret_code);
        errors = 1;
    }

    curl_easy_cleanup(curl);
    return *infected ? CL_VIRUS : (errors ? CL_ECREAT : CL_CLEAN);
}

/*
 *  Copyright (C) 2015-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
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

// libclamav
#include "clamav.h"
#include "str.h"
#include "others.h"

// common
#include "optparser.h"
#include "output.h"
#include "misc.h"
#include "actions.h"
#include "clamdcom.h"

#include "communication.h"
#include "client.h"
#include "protocol.h"
#include "socket.h"

#include "../clamonacc.h"

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
    int ret;
    const struct optstruct *opt;
    CURL *curl;
    CURLcode curlcode;
    char *ipaddr = NULL;
    int64_t timeout;
    const char zPING[] = "zPING";

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
            logg(LOGG_ERROR, "ClamClient: Clamonacc does not support binding to INADDR_ANY, \
					please specify an address with TCPAddr in your clamd.conf config file\n");
            *err = CL_EARG;
            return ret;
        }

        curlcode = onas_curl_init(&curl, ipaddr, (*ctx)->portnum, timeout);
        if (CURLE_OK != curlcode) {
            logg(LOGG_ERROR, "ClamClient: could not init curl, %s\n", curl_easy_strerror(curlcode));
            *err = CL_EARG;
            return ret;
        }

        curlcode = curl_easy_perform(curl);
        if (CURLE_OK != curlcode) {
            if (optget((*ctx)->opts, "ping")->enabled || optget((*ctx)->opts, "wait")->enabled) {
                logg(LOGG_INFO, "ClamClient: Initial connection failed, %s. Will try again...\n", curl_easy_strerror(curlcode));
            } else {
                logg(LOGG_ERROR, "ClamClient: Could not connect to clamd, %s\n", curl_easy_strerror(curlcode));
            }
            curl_easy_cleanup(curl);
            *err = CL_EARG;
            return ret;
        }

#ifndef ONAS_DEBUG
        if (onas_sendln(curl, zPING, sizeof(zPING), timeout)) {
            logg(LOGG_ERROR, "ClamClient: could not ping clamd, %s\n", curl_easy_strerror(curlcode));
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

/* pings clamd at the specified interval the number of time specified
 * return 0 on a successful connection, 1 upon timeout, -1 on error */
int16_t onas_ping_clamd(struct onas_context **ctx)
{

    uint64_t attempts           = ONAS_DEFAULT_PING_ATTEMPTS;
    uint64_t interval           = ONAS_DEFAULT_PING_INTERVAL;
    char *attempt_str           = NULL;
    char *interval_str          = NULL;
    char *errchk                = NULL;
    uint64_t i                  = 0;
    const struct optstruct *opt = NULL;
    CURL *curl                  = NULL;
    CURLcode curlcode;
    cl_error_t err = CL_SUCCESS;
    int b_remote   = 0;
    uint16_t ret   = 0;
    int64_t timeout;
    const char zPING[] = "zPING";

    if (ctx == NULL) {
        logg(LOGG_ERROR, "null parameter was passed\n");
        return -1;
    }

    timeout = optget((*ctx)->clamdopts, "OnAccessCurlTimeout")->numarg;

    b_remote = onas_check_remote(ctx, &err);
    if (CL_SUCCESS != err) {
        logg(LOGG_DEBUG, "ClamClient: could not check to see if daemon was remote... PINGing again...\n");
    }

    if (!b_remote) {
        curlcode = onas_curl_init(&curl, optget((*ctx)->clamdopts, "LocalSocket")->strarg, 0, timeout);
    } else {
        curlcode = onas_curl_init(&curl, optget((*ctx)->clamdopts, "TCPAddr")->strarg, (*ctx)->portnum, timeout);
        if (CURLE_OK != curlcode) {
            logg(LOGG_ERROR, "ClamClient: could not setup curl with tcp address and port, %s\n", curl_easy_strerror(curlcode));
            /* curl cleanup done in onas_curl_init on error */
            ret = -1;
            goto done;
        }
    }

    /* ping command takes the form --ping [attempts[:interval]] */
    opt = optget((*ctx)->opts, "ping");

    if (opt->enabled) {
        attempt_str = cli_safer_strdup(opt->strarg);
        if (attempt_str) {
            if (NULL == attempt_str) {
                logg(LOGG_ERROR, "could not allocate memory for string\n");
                ret = -1;
                goto done;
            }
            interval_str = strchr(attempt_str, ':');
            if ((NULL != interval_str) && (interval_str[0] != '\0')) {
                interval_str[0] = '\0';
                interval_str++;
                interval = cli_strntoul(interval_str, strlen(interval_str), &errchk, 10);
                if (interval_str + strlen(interval_str) > errchk) {
                    logg(LOGG_WARNING, "interval_str would go past end of buffer\n");
                    ret = -1;
                    goto done;
                }
            }
            attempts = cli_strntoul(attempt_str, strlen(attempt_str), &errchk, 10);
            if (attempt_str + strlen(attempt_str) > errchk) {
                logg(LOGG_WARNING, "attempt_str would go past end of buffer\n");
                ret = -1;
                goto done;
            }
        }
    }

    do {
        curlcode = curl_easy_perform(curl);
        if (CURLE_OK != curlcode) {
            logg(LOGG_DEBUG, "ClamClient: could not connect to clamd, %s\n", curl_easy_strerror(curlcode));
        } else if (CURLE_OK == onas_sendln(curl, zPING, sizeof(zPING), timeout)) {

            if (!optget((*ctx)->opts, "wait")->enabled) {
                logg(LOGG_INFO, "PONG\n");
            } else {
                logg(LOGG_DEBUG, "ClamClient: Connected.\n");
            }

            ret = 0;
            goto done;
        }

        if (i + 1 < attempts) {
            if (optget((*ctx)->opts, "wait")->enabled) {
                if (interval == 1)
                    logg(LOGG_DEBUG, "Will try again in %lu second\n", interval);
                else
                    logg(LOGG_DEBUG, "Will try again in %lu seconds\n", interval);
            } else {
                if (interval == 1)
                    logg(LOGG_INFO, "PINGing again in %lu second\n", interval);
                else
                    logg(LOGG_INFO, "PINGing again in %lu seconds\n", interval);
            }
            sleep(interval);
        }
        i++;
    } while (i < attempts);

    /* timed out */
    ret = 1;
    if (optget((*ctx)->opts, "wait")->enabled) {
        logg(LOGG_INFO, "Wait timeout exceeded; Could not connect to clamd\n");
    } else {
        logg(LOGG_INFO, "PING timeout exceeded; No response from clamd\n");
    }

done:
    if (curl) {
        curl_easy_cleanup(curl);
    }

    if (attempt_str) {
        free(attempt_str);
    }

    attempt_str  = NULL;
    interval_str = NULL;
    errchk       = NULL;

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
        logg(LOGG_ERROR, "ClamClient: invalid (NULL) args passed to onas_curl_init\n");
        return CURLE_FAILED_INIT;
    }

    /* setup here, but caller needs to cleanup */
    *curl = curl_easy_init();

    if (!port) {

#if ((LIBCURL_VERSION_MAJOR > 7) || (LIBCURL_VERSION_MAJOR == 7 && LIBCURL_VERSION_MINOR >= 40))
        /* "ipaddr" is actually our unix socket path here */
        curlcode = curl_easy_setopt(*curl, CURLOPT_UNIX_SOCKET_PATH, ipaddr);
#endif
        if (CURLE_OK != curlcode) {
            logg(LOGG_ERROR, "ClamClient: could not setup curl with local unix socket, %s\n", curl_easy_strerror(curlcode));
            curl_easy_cleanup(*curl);
            return curlcode;
        }

        curlcode = curl_easy_setopt(*curl, CURLOPT_URL, "http://localhost/");
        if (CURLE_OK != curlcode) {
            logg(LOGG_ERROR, "ClamClient: could not setup curl with local address, %s\n", curl_easy_strerror(curlcode));
            curl_easy_cleanup(*curl);
            return curlcode;
        }

    } else {

        curlcode = curl_easy_setopt(*curl, CURLOPT_PORT, port);
        if (CURLE_OK != curlcode) {
            logg(LOGG_ERROR, "ClamClient: could not setup curl with tcp port, %s\n", curl_easy_strerror(curlcode));
            curl_easy_cleanup(*curl);
            return curlcode;
        }

        curlcode = curl_easy_setopt(*curl, CURLOPT_URL, ipaddr);
        if (CURLE_OK != curlcode) {
            logg(LOGG_ERROR, "ClamClient: could not setup curl with tcp address, %s\n", curl_easy_strerror(curlcode));
            curl_easy_cleanup(*curl);
            return curlcode;
        }
    }

    curlcode = curl_easy_setopt(*curl, CURLOPT_NOSIGNAL, 1L);
    if (CURLE_OK != curlcode) {
        logg(LOGG_ERROR, "ClamClient: could not setup curl to not use signals, %s\n", curl_easy_strerror(curlcode));
        curl_easy_cleanup(*curl);
        return curlcode;
    }

    curlcode = curl_easy_setopt(*curl, CURLOPT_CONNECTTIMEOUT_MS, (long)timeout);
    if (CURLE_OK != curlcode) {
        logg(LOGG_ERROR, "ClamClient: could not setup curl with connect timeout, %s\n", curl_easy_strerror(curlcode));
        curl_easy_cleanup(*curl);
        return curlcode;
    }

    /* we implement our own transfer protocol via send and recv, so we only need to connect */
    curlcode = curl_easy_setopt(*curl, CURLOPT_CONNECT_ONLY, 1L);
    if (CURLE_OK != curlcode) {
        logg(LOGG_ERROR, "ClamClient: could not setup curl to connect only, %s\n", curl_easy_strerror(curlcode));
        curl_easy_cleanup(*curl);
        return curlcode;
    }

#ifdef ONAS_DEBUG
    curlcode = curl_easy_setopt(*curl, CURLOPT_VERBOSE, 1L);
    if (CURLE_OK != curlcode) {
        logg(LOGG_ERROR, "ClamClient: could not tell curl to be verbose, %s\n", curl_easy_strerror(curlcode));
        curl_easy_cleanup(*curl);
        return curlcode;
    }
#endif

    /* don't care about the body of the return message */
    curlcode = curl_easy_setopt(*curl, CURLOPT_NOBODY, 1L);
    if (CURLE_OK != curlcode) {
        logg(LOGG_ERROR, "ClamClient: could not setup curl to send HEAD request, %s\n", curl_easy_strerror(curlcode));
        curl_easy_cleanup(*curl);
        return curlcode;
    }

    curlcode = curl_easy_setopt(*curl, CURLOPT_HEADER, 0L);
    if (CURLE_OK != curlcode) {
        logg(LOGG_ERROR, "ClamClient: could not setup curl to not send header, %s\n", curl_easy_strerror(curlcode));
        curl_easy_cleanup(*curl);
        return curlcode;
    }
    return curlcode;
}

cl_error_t onas_setup_client(struct onas_context **ctx)
{

    const struct optstruct *opts;
    cl_error_t err;
    int remote;

    errno = 0;

    opts = (*ctx)->opts;

    if (optget(opts, "infected")->enabled) {
        (*ctx)->printinfected = 1;
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
        if (onas_set_sock_only_once(*ctx) == CL_EWRITE) {
            return CL_EWRITE;
        }
        logg(LOGG_DEBUG, "ClamClient: client setup to scan via fd passing\n");
        (*ctx)->scantype = FILDES;
        (*ctx)->session  = optget(opts, "multiscan")->enabled;
    } else
#endif
        if (remote) {
        logg(LOGG_DEBUG, "ClamClient: client setup to scan via streaming\n");
        (*ctx)->scantype = STREAM;
        (*ctx)->session  = optget(opts, "multiscan")->enabled;
    } else if (optget(opts, "multiscan")->enabled) {
        logg(LOGG_DEBUG, "ClamClient: client setup to scan in multiscan mode\n");
        (*ctx)->scantype = MULTI;
    } else if (optget(opts, "allmatch")->enabled) {
        logg(LOGG_DEBUG, "ClamClient: client setup to scan in all-match mode\n");
        (*ctx)->scantype = ALLMATCH;
    } else {
        logg(LOGG_DEBUG, "ClamClient: client setup for continuous scanning\n");
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
    int len;
    struct onas_rcvln rcv;
    int64_t timeout;
    const char zVERSION[] = "zVERSION";

    timeout = optget((*ctx)->clamdopts, "OnAccessCurlTimeout")->numarg;

    b_remote = onas_check_remote(ctx, &err);
    if (CL_SUCCESS != err) {
        logg(LOGG_ERROR, "ClamClient: could not check to see if daemon was remote\n");
        return 2;
    }

    if (!b_remote) {
        curlcode = onas_curl_init(&curl, optget((*ctx)->clamdopts, "LocalSocket")->strarg, 0, timeout);
    } else {
        curlcode = onas_curl_init(&curl, optget((*ctx)->clamdopts, "TCPAddr")->strarg, (*ctx)->portnum, timeout);
        if (CURLE_OK != curlcode) {
            logg(LOGG_ERROR, "ClamClient: could not setup curl with tcp address and port, %s\n", curl_easy_strerror(curlcode));
            /* curl cleanup done in onas_curl_init on error */
            return 2;
        }
    }

    onas_recvlninit(&rcv, curl, 0);

    curlcode = curl_easy_perform(curl);
    if (CURLE_OK != curlcode) {
        logg(LOGG_DEBUG, "ClamClient: could not connect to clamd, %s\n", curl_easy_strerror(curlcode));
        curl_easy_cleanup(curl);
        return 2;
    }

    if (onas_sendln(curl, zVERSION, sizeof(zVERSION), timeout)) {
        curl_easy_cleanup(curl);
        return 2;
    }

    while ((len = onas_recvln(&rcv, &buff, NULL, timeout))) {
        if (len == -1) {
            logg(LOGG_DEBUG, "ClamClient: clamd did not respond with version information\n");
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
 * @param infected  return variable indicating whether daemon returned with an infected verdict or not
 * @param err       return variable passed to the daemon protocol interface indicating how many things went wrong in the course of scanning
 * @param ret_code  return variable passed to the daemon protocol interface indicating last known issue or success
 */
int onas_client_scan(const char *tcpaddr, int64_t portnum, int32_t scantype, uint64_t maxstream, const char *fname, int fd, int64_t timeout, STATBUF sb, int *infected, int *err, cl_error_t *ret_code)
{
    CURL *curl        = NULL;
    CURLcode curlcode = CURLE_OK;
    int errors        = 0;
    int ret;
    static bool disconnected = false;

    *infected = 0;

    if ((sb.st_mode & S_IFMT) != S_IFREG) {
        scantype = STREAM;
    }

    curlcode = onas_curl_init(&curl, tcpaddr, portnum, timeout);
    if (CURLE_OK != curlcode) {
        logg(LOGG_ERROR, "ClamClient: could not init curl for scanning, %s\n", curl_easy_strerror(curlcode));
        /* curl cleanup done in onas_curl_init on error */
        return CL_ECREAT;
    }

    curlcode = curl_easy_perform(curl);
    if (CURLE_OK != curlcode) {
        if (!disconnected) {
            logg(LOGG_ERROR, "ClamClient: Connection to clamd failed, %s.\n", curl_easy_strerror(curlcode));
            disconnected = true;
        }
        curl_easy_cleanup(curl);
        return CL_ECREAT;
    }
    if (disconnected) {
        logg(LOGG_INFO, "ClamClient: Connection to clamd re-established.\n");
        disconnected = false;
    }

    if ((ret = onas_dsresult(curl, scantype, maxstream, fname, fd, timeout, &ret, err, ret_code)) >= 0) {
        *infected = ret;
    } else {
        logg(LOGG_DEBUG, "ClamClient: connection could not be established ... return code %d\n", *ret_code);
        errors = 1;
    }

    curl_easy_cleanup(curl);
    return *infected ? CL_VIRUS : (errors ? CL_ECREAT : CL_CLEAN);
}

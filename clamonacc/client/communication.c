/*
 *  Copyright (C) 2015-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2009-2010 Sourcefire, Inc.
 *
 *  Author: aCaB, Mickey Sola
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
#include <sys/stat.h>
#include <curl/curl.h>
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <fcntl.h>
#include <errno.h>

#if !defined(_WIN32)
#include <sys/socket.h>
#endif

// libclamav
#include "clamav.h"

// shared
#include "output.h"

#include "communication.h"

static int onas_socket_wait(curl_socket_t sockfd, int32_t b_recv, uint64_t timeout_ms);

/**
 * Function from curl example code, Copyright (C) 1998 - 2018, Daniel Stenberg, see COPYING.curl for license details
 */
static int onas_socket_wait(curl_socket_t sockfd, int32_t b_recv, uint64_t timeout_ms)
{
    struct timeval tv;
    fd_set infd, outfd, errfd;
    int ret;

    tv.tv_sec  = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    FD_ZERO(&infd);
    FD_ZERO(&outfd);
    FD_ZERO(&errfd);

    FD_SET(sockfd, &errfd); /* always check for error */

    if (b_recv) {
        FD_SET(sockfd, &infd);
    } else {
        FD_SET(sockfd, &outfd);
    }

    /* select() returns the number of signalled sockets or -1 */
    ret = select((int)sockfd + 1, &infd, &outfd, &errfd, &tv);

    return ret;
}

/* Sends bytes over a socket
 * Returns 0 on success */
int onas_sendln(CURL *curl, const void *line, size_t len, int64_t timeout)
{
    size_t sent = 0;
    CURLcode curlcode;
    curl_socket_t sockfd;

#if ((LIBCURL_VERSION_MAJOR > 7) || (LIBCURL_VERSION_MAJOR == 7 && LIBCURL_VERSION_MINOR >= 45))
    /* Use new CURLINFO_ACTIVESOCKET option */
    curlcode = curl_easy_getinfo(curl, CURLINFO_ACTIVESOCKET, &sockfd);
#else
    /* Use deprecated CURLINFO_LASTSOCKET option */
    long long_sockfd;
    curlcode = curl_easy_getinfo(curl, CURLINFO_LASTSOCKET, &long_sockfd);
    sockfd   = (curl_socket_t)long_sockfd;
#endif

    if (CURLE_OK != curlcode) {
        logg(LOGG_ERROR, "ClamCom: could not get curl active socket info %s\n", curl_easy_strerror(curlcode));
        return 1;
    }

    while (len) {

        do {
            curlcode = curl_easy_send(curl, line, len, &sent);
            if (CURLE_AGAIN == curlcode && onas_socket_wait(sockfd, 0, timeout) <= 0) {
                logg(LOGG_ERROR, "ClamCom: TIMEOUT while waiting on socket (send)\n");
                return 1;
            }
        } while (CURLE_AGAIN == curlcode);

        if (sent == 0) {
            if (sent && errno == EINTR) {
                continue;
            } else if (errno == EFAULT) {
                /* Users have reported frequent "bad address" errors when files
                   are created & removed before the file can be sent to be
                   scanned. This isn't a critical error, so we'll log it in
                   verbose-mode only. */
                logg(LOGG_DEBUG, "Can't send to clamd: %s\n", strerror(errno));
            } else {
                logg(LOGG_ERROR, "Can't send to clamd: %s\n", strerror(errno));
            }

            return 1;
        }

        line += sent;
        len -= sent;
    }

    return 0;
}

/* Inits a RECVLN struct before it can be used in recvln() - see below */
void onas_recvlninit(struct onas_rcvln *rcv_data, CURL *curl, int sockd)
{
    rcv_data->curl     = curl;
    rcv_data->curlcode = CURLE_OK;
    rcv_data->lnstart = rcv_data->curr = rcv_data->buf;
    rcv_data->retlen                   = 0;
    rcv_data->sockd                    = sockd;
}

/* Receives a full (terminated with \0) line from a socket
 * Sets ret_bol to the begin of the received line, and optionally
 * ret_eol to the end of line.
 * Should be called repeatedly until all input is consumed
 * Returns:
 * - the length of the line (a positive number) on success
 * - 0 if the connection is closed
 * - -1 on error
 */
int onas_recvln(struct onas_rcvln *rcv_data, char **ret_bol, char **ret_eol, int64_t timeout)
{
    char *eol;
    int ret = 0;
    curl_socket_t sockfd;

#if ((LIBCURL_VERSION_MAJOR > 7) || (LIBCURL_VERSION_MAJOR == 7 && LIBCURL_VERSION_MINOR >= 45))
    /* Use new CURLINFO_ACTIVESOCKET option */
    rcv_data->curlcode = curl_easy_getinfo(rcv_data->curl, CURLINFO_ACTIVESOCKET, &sockfd);
#else
    /* Use deprecated CURLINFO_LASTSOCKET option */
    long long_sockfd;
    rcv_data->curlcode = curl_easy_getinfo(rcv_data->curl, CURLINFO_LASTSOCKET, &long_sockfd);
    sockfd             = (curl_socket_t)long_sockfd;
#endif

    if (CURLE_OK != rcv_data->curlcode) {
        logg(LOGG_ERROR, "ClamCom: could not get curl active socket info %s\n", curl_easy_strerror(rcv_data->curlcode));
        return -1;
    }

    while (1) {
        if (!rcv_data->retlen) {
            do {
                rcv_data->curlcode = curl_easy_recv(rcv_data->curl, rcv_data->curr,
                                                    sizeof(rcv_data->buf) - (rcv_data->curr - rcv_data->buf), &(rcv_data->retlen));

                if (CURLE_AGAIN == rcv_data->curlcode && onas_socket_wait(sockfd, 1, timeout) <= 0) {
                    logg(LOGG_ERROR, "ClamCom: TIMEOUT while waiting on socket (recv)\n");
                    return -1;
                }

            } while (CURLE_AGAIN == rcv_data->curlcode);

            if (rcv_data->retlen <= 0) {
                if (rcv_data->retlen && errno == EINTR) {
                    rcv_data->retlen = 0;
                    continue;
                }

                if (rcv_data->retlen || rcv_data->curr != rcv_data->buf) {
                    *rcv_data->curr = '\0';

                    if (strcmp(rcv_data->buf, "UNKNOWN COMMAND\n")) {
                        logg(LOGG_ERROR, "Communication error, clamd received unknown command\n");
                    } else {
                        logg(LOGG_ERROR, "Command rejected by clamd (wrong clamd version?)\n");
                    }

                    return -1;
                }

                return 0;
            }
        }

        if ((eol = memchr(rcv_data->curr, 0, rcv_data->retlen))) {
            eol++;
            rcv_data->retlen -= eol - rcv_data->curr;

            *ret_bol = rcv_data->lnstart;
            if (ret_eol) {
                *ret_eol = eol;
            }

            ret = eol - rcv_data->lnstart;
            if (rcv_data->retlen) {
                rcv_data->lnstart = rcv_data->curr = eol;
            } else {
                rcv_data->lnstart = rcv_data->curr = rcv_data->buf;
            }

            return ret;
        }

        rcv_data->retlen += rcv_data->curr - rcv_data->lnstart;

        if (!eol && rcv_data->retlen == sizeof(rcv_data->buf)) {
            logg(LOGG_ERROR, "Overlong reply from clamd\n");
            return -1;
        }

        if (!eol) {
            if (rcv_data->buf != rcv_data->lnstart) {
                memmove(rcv_data->buf, rcv_data->lnstart, rcv_data->retlen);
                rcv_data->lnstart = rcv_data->buf;
            }

            rcv_data->curr   = &rcv_data->lnstart[rcv_data->retlen];
            rcv_data->retlen = 0;
        }
    }
}

/* Receives a full (terminated with \0) line from a socket
 * Sets ret_bol to the begin of the received line, and optionally
 * ret_eol to the end of line.
 * Should be called repeatedly until all input is consumed
 * Returns:
 * - the length of the line (a positive number) on success
 * - 0 if the connection is closed
 * - -1 on error
 */
int onas_fd_recvln(struct onas_rcvln *rcv_data, char **ret_bol, char **ret_eol, int64_t timeout_ms)
{
    char *eol;

    UNUSEDPARAM(timeout_ms);

    while (1) {
        if (!rcv_data->retlen) {
            rcv_data->retlen = recv(rcv_data->sockd, rcv_data->curr, sizeof(rcv_data->buf) - (rcv_data->curr - rcv_data->buf), 0);
            if (rcv_data->retlen <= 0) {
                if (rcv_data->retlen && errno == EINTR) {
                    rcv_data->retlen = 0;
                    continue;
                }
                if (rcv_data->retlen || rcv_data->curr != rcv_data->buf) {
                    *rcv_data->curr = '\0';
                    if (strcmp(rcv_data->buf, "UNKNOWN COMMAND\n"))
                        logg(LOGG_ERROR, "Communication error\n");
                    else
                        logg(LOGG_ERROR, "Command rejected by clamd (wrong clamd version?)\n");
                    return -1;
                }
                return 0;
            }
        }
        if ((eol = memchr(rcv_data->curr, 0, rcv_data->retlen))) {
            int ret = 0;
            eol++;
            rcv_data->retlen -= eol - rcv_data->curr;
            *ret_bol = rcv_data->lnstart;
            if (ret_eol) *ret_eol = eol;
            ret = eol - rcv_data->lnstart;
            if (rcv_data->retlen)
                rcv_data->lnstart = rcv_data->curr = eol;
            else
                rcv_data->lnstart = rcv_data->curr = rcv_data->buf;
            return ret;
        }
        rcv_data->retlen += rcv_data->curr - rcv_data->lnstart;
        if (!eol && rcv_data->retlen == sizeof(rcv_data->buf)) {
            logg(LOGG_ERROR, "Overlong reply from clamd\n");
            return -1;
        }
        if (!eol) {
            if (rcv_data->buf != rcv_data->lnstart) { /* old memmove sux */
                memmove(rcv_data->buf, rcv_data->lnstart, rcv_data->retlen);
                rcv_data->lnstart = rcv_data->buf;
            }
            rcv_data->curr   = &rcv_data->lnstart[rcv_data->retlen];
            rcv_data->retlen = 0;
        }
    }
}

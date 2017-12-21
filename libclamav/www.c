/*
 *  Copyright (C) 2014, 2017 Cisco and/or its affiliates. All rights reserved.
 *
 *  Author: Shawn Webb
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
#include <string.h>

#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <ctype.h>

#include <sys/types.h>
#include <fcntl.h>

#include <errno.h>

#if !defined(_WIN32)
#include <sys/socket.h>
#if HAVE_SYS_SELECT_H
#include <sys/select.h>
#else
#include <sys/time.h>
#endif
#include <netinet/in.h>
#include <netdb.h>
#endif

#include "platform.h"

#include "libclamav/others.h"
#include "libclamav/clamav.h"
#include "libclamav/www.h"

int connect_host(const char *host, const char *port, uint32_t timeout, int useAsync)
{
    int sockfd = -1;
    struct addrinfo hints, *servinfo = NULL, *p = NULL;
    int flags = 0, error;
    socklen_t len;
    fd_set read_fds, write_fds;
    struct timeval tv;
#ifdef _WIN32
	int iResult;
	WSADATA wsaData;

	/* Force initialization of Windows sockets, even if it already happened elsewhere */
	iResult = WSAStartup(MAKEWORD(2,2), &wsaData);
	if (iResult != 0)
		return -1;
#endif

    memset(&hints, 0x00, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host, port, &hints, &servinfo))
        return -1;

    for (p = servinfo; p != NULL; p = p->ai_next) {
        sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sockfd < 0)
            continue;

        if (useAsync) {
            flags = fcntl(sockfd, F_GETFL, 0);
            if (fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) < 0) {
                closesocket(sockfd);
                continue;
            }
        }

        if ((error = connect(sockfd, p->ai_addr, p->ai_addrlen))) {
            if (useAsync) {
                if (errno != EINPROGRESS) {
                    closesocket(sockfd);
                    continue;
                }
                errno = 0;

                FD_ZERO(&write_fds);
                FD_ZERO(&read_fds);
                FD_SET(sockfd, &read_fds);
                FD_SET(sockfd, &write_fds);

                /* TODO: Make this timeout configurable */
                tv.tv_sec = timeout;
                tv.tv_usec = 0;
                if (select(sockfd + 1, &read_fds, &write_fds, NULL, &tv) <= 0) {
                    closesocket(sockfd);
                    continue;
                }

                if (FD_ISSET(sockfd, &read_fds) || FD_ISSET(sockfd, &write_fds)) {
                    len = sizeof(error);
                    if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &error, &len) < 0) {
                        closesocket(sockfd);
                        continue;
                    }
                } else {
                    closesocket(sockfd);
                    continue;
                }
            } else {
                closesocket(sockfd);
                continue;
            }
        }


        /* Connected to host */
        break;
    }

    if (!(p)) {
        freeaddrinfo(servinfo);
        if (sockfd >= 0)
            closesocket(sockfd);
        return -1;
    }

    freeaddrinfo(servinfo);

    /* Return to using a synchronous socket to make Linux happy */
    if (useAsync && (sockfd >= 0)) {
        if (fcntl(sockfd, F_SETFL, flags) < 0) {
            closesocket(sockfd);
            return -1;
        }
    }

    return sockfd;
}

size_t encoded_size(const char *postdata)
{
    const char *p;
    size_t len=0;

    for (p = postdata; *p != '\0'; p++)
        len += isalnum(*p) ? 1 : 3;

    return len;
}

char *encode_data(const char *postdata)
{
    char *buf;
    size_t bufsz, i, j;

    bufsz = encoded_size(postdata);
    if (bufsz == 0)
        return NULL;

    buf = cli_calloc(1, bufsz+1);
    if (!(buf))
        return NULL;

    for (i=0, j=0; postdata[i] != '\0'; i++) {
        if (isalnum(postdata[i])) {
            buf[j++] = postdata[i];
        } else {
            sprintf(buf+j, "%%%02x", postdata[i]);
            j += 3;
        }
    }

    return buf;
}

void submit_post(const char *host, const char *port, const char *method, const char *url, const char *postdata, uint32_t timeout)
{
    int sockfd, n;
    unsigned int i;
    char *buf, *encoded=NULL;
    size_t bufsz;
    ssize_t recvsz;
    char chunkedlen[21];
    fd_set readfds;
    struct timeval tv;
    char *acceptable_methods[] = {
        "GET",
        "PUT",
        "POST",
        NULL
    };

    for (i=0; acceptable_methods[i] != NULL; i++)
        if (!strcmp(method, acceptable_methods[i]))
            break;

    if (acceptable_methods[i] == NULL)
        return;

    bufsz = strlen(method);
    bufsz += sizeof("   HTTP/1.1") + 2; /* Yes. Three blank spaces. +1 for the \n */
    bufsz += strlen(url);
    bufsz += sizeof("Host: \r\n");
    bufsz += strlen(host);
    bufsz += sizeof("Connection: Close\r\n");
    bufsz += 4; /* +4 for \r\n\r\n */

    if (!strcmp(method, "POST") || !strcmp(method, "PUT")) {
        encoded = encode_data(postdata);
        if (!(encoded))
            return;
        snprintf(chunkedlen, sizeof(chunkedlen), "%zu", strlen(encoded));
        bufsz += sizeof("Content-Type: application/x-www-form-urlencoded\r\n");
        bufsz += sizeof("Content-Length: \r\n");
        bufsz += strlen(chunkedlen);
        bufsz += strlen(encoded);
    }

    buf = cli_calloc(1, bufsz);
    if (!(buf)) {
        if ((encoded))
            free(encoded);

        return;
    }

    snprintf(buf, bufsz, "%s %s HTTP/1.1\r\n", method, url);
    snprintf(buf+strlen(buf), bufsz-strlen(buf), "Host: %s\r\n", host);
    snprintf(buf+strlen(buf), bufsz-strlen(buf), "Connection: Close\r\n");

    if (!strcmp(method, "POST") || !strcmp(method, "PUT")) {
        snprintf(buf+strlen(buf), bufsz-strlen(buf), "Content-Type: application/x-www-form-urlencoded\r\n");
        snprintf(buf+strlen(buf), bufsz-strlen(buf), "Content-Length: %s\r\n", chunkedlen);
        snprintf(buf+strlen(buf), bufsz-strlen(buf), "\r\n");
        snprintf(buf+strlen(buf), bufsz-strlen(buf), "%s", encoded);
        free(encoded);
    }
#if defined(_WIN32)
	sockfd = connect_host(host, port, timeout, 0);
#else
    sockfd = connect_host(host, port, timeout, 1);
#endif
    if (sockfd < 0) {
        free(buf);
        return;
    }

    cli_dbgmsg("stats - Connected to %s:%s\n", host, port);

    if ((size_t)send(sockfd, buf, strlen(buf), 0) != (size_t)strlen(buf)) {
        closesocket(sockfd);
        free(buf);
        return;
    }

    cli_dbgmsg("stats - Sending %s\n", buf);

    while (1) {
        FD_ZERO(&readfds);
        FD_SET(sockfd, &readfds);

        /*
         * Check to make sure the stats submitted okay (so that we don't kill the HTTP request
         * while it's being processed). Give a ten-second timeout so we don't have a major
         * impact on scanning.
         */
        tv.tv_sec = timeout;
        tv.tv_usec = 0;
        if ((n = select(sockfd+1, &readfds, NULL, NULL, &tv)) <= 0)
            break;

        if (FD_ISSET(sockfd, &readfds)) {
            memset(buf, 0x00, bufsz);
            if ((recvsz = recv(sockfd, buf, bufsz-1, 0) <= 0))
                break;

            buf[bufsz-1] = '\0';

            cli_dbgmsg("stats - received: %s\n", buf);

            if (strstr(buf, "STATOK")) {
                cli_dbgmsg("stats - Data received okay\n");
                break;
            }
        }
    }

    closesocket(sockfd);
    free(buf);
}

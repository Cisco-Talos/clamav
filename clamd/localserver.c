/*
 *  Copyright (C) 2013-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *
 *  Authors: Tomasz Kojm
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
#ifndef _WIN32
#include <sys/socket.h>
#include <sys/un.h>
#endif
#include <sys/stat.h>
#include <errno.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

// libclamav
#include "clamav.h"
#include "str.h"

// common
#include "optparser.h"
#include "output.h"
#include "misc.h"

#include "clamd_others.h"
#include "server.h"
#include "localserver.h"

#ifdef _WIN32
int localserver(const struct optstruct *opts)
{
    logg(LOGG_ERROR, "Localserver is not supported on this platform");
    return -1;
}

#else

int localserver(const struct optstruct *opts)
{
    struct sockaddr_un server;
    int sockfd = 0, backlog;
    STATBUF foo;
    char *estr;
    char *sockdir;
    char *pos;
    struct stat sb;
    int cnt;

    int num_fd = sd_listen_fds(0);
    if (num_fd > 2) {
        logg(LOGG_ERROR, "LOCAL: Received more than two file descriptors from systemd.\n");
        return -1;
    } else if (num_fd > 0) {
        /* use socket passed by systemd */
        int i;
        for (i = 0; i < num_fd; i += 1) {
            sockfd = SD_LISTEN_FDS_START + i;
            if (sd_is_socket(sockfd, AF_UNIX, SOCK_STREAM, 1) == 1) {
                /* correct socket */
                break;
            } else {
                /* wrong socket */
                sockfd = -2;
            }
        }
        if (sockfd == -2) {
            logg(LOGG_INFO_NF, "LOCAL: No local AF_UNIX SOCK_STREAM socket received from systemd.\n");
            return -2;
        }
        logg(LOGG_INFO_NF, "LOCAL: Received AF_UNIX SOCK_STREAM socket from systemd.\n");
        return sockfd;
    }
    /* create socket */
    memset((char *)&server, 0, sizeof(server));
    server.sun_family = AF_UNIX;
    strncpy(server.sun_path, optget(opts, "LocalSocket")->strarg, sizeof(server.sun_path));
    server.sun_path[sizeof(server.sun_path) - 1] = '\0';

    pos = NULL;
    if ((pos = strstr(server.sun_path, "/")) && (pos = strstr(((char *)pos + 1), "/"))) {
        cnt     = 0;
        sockdir = NULL;
        pos     = server.sun_path + strlen(server.sun_path);
        while (pos != server.sun_path) {
            if (*pos == '/') {
                sockdir = CLI_STRNDUP(server.sun_path, strlen(server.sun_path) - cnt);
                break;
            } else {
                pos--;
                cnt++;
            }
        }

        if (stat(sockdir, &sb)) {
            if (errno == ENOENT) {
                mode_t old_umask;
                mode_t sock_mode;
                if (optget(opts, "LocalSocketMode")->enabled) {
                    char *end;
                    sock_mode = strtol(optget(opts, "LocalSocketMode")->strarg, &end, 8);

                    if (*end) {
                        logg(LOGG_ERROR, "Invalid LocalSocketMode %s\n", optget(opts, "LocalSocketMode")->strarg);
                        free(sockdir);
                        return -1;
                    }
                } else {
                    sock_mode = 0777;
                }

                old_umask = umask(0011); /* allow mode 777 for socket directory */
                if (mkdir(sockdir, sock_mode)) {
                    logg(LOGG_ERROR, "LOCAL: Could not create socket directory: %s: %s\n", sockdir, strerror(errno));
                    if (errno == ENOENT) {
                        logg(LOGG_ERROR, "LOCAL: Ensure parent directory exists.\n");
                    }
                } else {
                    logg(LOGG_INFO, "Localserver: Creating socket directory: %s\n", sockdir);
                }
                umask(old_umask); /* restore umask */
            }
        }
        free(sockdir);
    }

    if ((sockfd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        estr = strerror(errno);
        logg(LOGG_ERROR, "LOCAL: Socket allocation error: %s\n", estr);
        return -1;
    }

    if (bind(sockfd, (struct sockaddr *)&server, sizeof(struct sockaddr_un)) == -1) {
        if (errno == EADDRINUSE) {
            if (connect(sockfd, (struct sockaddr *)&server, sizeof(struct sockaddr_un)) >= 0) {
                logg(LOGG_ERROR, "LOCAL: Socket file %s is in use by another process.\n", server.sun_path);
                close(sockfd);
                return -1;
            }
            if (optget(opts, "FixStaleSocket")->enabled) {
                logg(LOGG_INFO_NF, "LOCAL: Removing stale socket file %s\n", server.sun_path);
                if (unlink(server.sun_path) == -1) {
                    estr = strerror(errno);
                    logg(LOGG_ERROR, "LOCAL: Socket file %s could not be removed: %s\n", server.sun_path, estr);
                    close(sockfd);
                    return -1;
                }
                if (bind(sockfd, (struct sockaddr *)&server, sizeof(struct sockaddr_un)) == -1) {
                    estr = strerror(errno);
                    logg(LOGG_ERROR, "LOCAL: Socket file %s could not be bound: %s (unlink tried)\n", server.sun_path, estr);
                    close(sockfd);
                    return -1;
                }
            } else if (CLAMSTAT(server.sun_path, &foo) != -1) {
                logg(LOGG_ERROR, "LOCAL: Socket file %s exists. Either remove it, or configure a different one.\n", server.sun_path);
                close(sockfd);
                return -1;
            }
        } else {
            estr = strerror(errno);
            logg(LOGG_ERROR, "LOCAL: Socket file %s could not be bound: %s\n", server.sun_path, estr);
            close(sockfd);
            return -1;
        }
    }

    logg(LOGG_INFO_NF, "LOCAL: Unix socket file %s\n", server.sun_path);

    backlog = optget(opts, "MaxConnectionQueueLength")->numarg;
    logg(LOGG_INFO_NF, "LOCAL: Setting connection queue length to %d\n", backlog);

    if (listen(sockfd, backlog) == -1) {
        estr = strerror(errno);
        logg(LOGG_ERROR, "LOCAL: listen() error: %s\n", estr);
        close(sockfd);
        return -1;
    }

    return sockfd;
}
#endif

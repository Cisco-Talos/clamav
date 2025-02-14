/*
 *  Copyright (C) 2020-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *
 *  Author: Mickey Sola
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

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "clamav.h"
#include "output.h"

#include "optparser.h"
#include "../clamonacc.h"
#include "socket.h"
#include "platform.h"

#ifdef HAVE_FD_PASSING
struct onas_sock_t onas_sock = {.written = 0};
#endif

/**
 * One time socket setup for unix file descriptor passing
 *
 * @param ctx a point to the onas context struct
 * @return CL_SUCCESS if writing to socket struct was successful, CL_EWRITE if the socket has already been written to
 */
cl_error_t onas_set_sock_only_once(struct onas_context *ctx)
{

    const struct optstruct *opt;

#ifdef HAVE_FD_PASSING
    if (onas_sock.written != 1) {
        if (((opt =
                  optget(ctx->clamdopts, "LocalSocket"))
                 ->enabled) &&
            optget(ctx->opts, "fdpass")->enabled) {
            memset((void *)&onas_sock, 0, sizeof(onas_sock));
            onas_sock.sock.sun_family = AF_UNIX;
            strncpy(onas_sock.sock.sun_path, opt->strarg, sizeof(onas_sock.sock.sun_path));
            onas_sock.sock.sun_path[sizeof(onas_sock.sock.sun_path) - 1] = '\0';
            onas_sock.written                                            = 1;
            return CL_SUCCESS;
        }
    }
#endif

    return CL_EWRITE;
}

/**
 * Retrieves a working socket descriptor for unix fdpassing
 *
 * @return Returns socket descriptor on success, -1 on failure
 */
int onas_get_sockd()
{

#ifdef HAVE_FD_PASSING

    int sockd = 0;
    if (onas_sock.written && (sockd = socket(AF_UNIX, SOCK_STREAM, 0)) >= 0) {
        if (connect(sockd, (struct sockaddr *)&onas_sock.sock, sizeof(onas_sock.sock)) == 0)
            return sockd;
        else {
            logg(LOGG_ERROR, "ClamSock: Could not connect to clamd on LocalSocket \n");
            closesocket(sockd);
        }
    }
#endif
    return -1;
}

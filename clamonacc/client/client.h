/*
 *  Copyright (C) 2015-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2009 Sourcefire, Inc.
 *
 *  Authors: Tomasz Kojm, aCaB
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

#ifndef __ONAS_CLIENT_H
#define __ONAS_CLIENT_H

#include <curl/curl.h>

#include "optparser.h"
#include "../clamonacc.h"

#define ONAS_DEFAULT_PING_INTERVAL 1
#define ONAS_DEFAULT_PING_ATTEMPTS 31

void onas_print_server_version(struct onas_context **ctx);
int onas_client_scan(const char *tcpaddr, int64_t portnum, int32_t scantype, uint64_t maxstream, const char *fname, int fd, int64_t timeout, STATBUF sb, int *infected, int *err, cl_error_t *ret_code);
CURLcode onas_curl_init(CURL **curl, const char *ipaddr, int64_t port, int64_t timeout);
int onas_get_clamd_version(struct onas_context **ctx);
cl_error_t onas_setup_client(struct onas_context **ctx);
int onas_check_remote(struct onas_context **ctx, cl_error_t *err);
int16_t onas_ping_clamd(struct onas_context **ctx);

#endif

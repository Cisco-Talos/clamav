/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *
 *  Authors: Tomasz Kojm, Török Edvin
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

#ifndef __SCANNER_H
#define __SCANNER_H

#include <sys/types.h>

#include "libclamav/others.h"
#include "libclamav/clamav.h"
#include "shared/optparser.h"
#include "thrmgr.h"
#include "session.h"

enum scan_type { TYPE_INIT = -1, TYPE_SCAN = 0, TYPE_CONTSCAN = 1, TYPE_MULTISCAN = 2 };

struct scan_cb_data {
    int scantype;
    int odesc;
    int type;
    int infected;
    int errors;
    int total;
    int id;
    const client_conn_t *conn;
    const char *toplevel_path;
    unsigned long scanned;
    struct cl_scan_options *options;
    struct cl_engine *engine;
    const struct optstruct *opts;
    threadpool_t *thr_pool;
    jobgroup_t *group;
    dev_t dev;
};

struct cb_context {
    const char *filename;
    unsigned long long virsize;
    char virhash[33];
    struct scan_cb_data *scandata;
};

int scanfd(const client_conn_t *conn, unsigned long int *scanned, const struct cl_engine *engine, struct cl_scan_options *options, const struct optstruct *opts, int odesc, int stream);
int scanstream(int odesc, unsigned long int *scanned, const struct cl_engine *engine, struct cl_scan_options *options, const struct optstruct *opts, char term);
int scan_callback(STATBUF *sb, char *filename, const char *msg, enum cli_ftw_reason reason, struct cli_ftw_cbdata *data);
int scan_pathchk(const char *path, struct cli_ftw_cbdata *data);
void hash_callback(int fd, unsigned long long size, const unsigned char *md5, const char *virname, void *ctx);
void msg_callback(enum cl_msg severity, const char *fullmsg, const char *msg, void *ctx);
void clamd_virus_found_cb(int fd, const char *virname, void *context);

#endif

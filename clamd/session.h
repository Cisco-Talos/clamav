/*
 *  Copyright (C) 2013-2024 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
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

#ifndef __SESSION_H
#define __SESSION_H

// libclamav
#include "clamav.h"

// common
#include "optparser.h"

#include "server.h"
#include "clamd_others.h"

enum commands {
    COMMAND_UNKNOWN  = 0,
    COMMAND_SHUTDOWN = 1,
    COMMAND_RELOAD,
    COMMAND_END,
    COMMAND_SCAN,
    COMMAND_PING,
    COMMAND_CONTSCAN,
    COMMAND_VERSION,
    COMMAND_MULTISCAN,
    COMMAND_FILDES,
    COMMAND_STATS,
    /* new proto commands */
    COMMAND_IDSESSION,
    COMMAND_INSTREAM,
    COMMAND_COMMANDS,
    COMMAND_DETSTATSCLEAR,
    COMMAND_DETSTATS,
    /* internal commands */
    COMMAND_MULTISCANFILE,
    COMMAND_INSTREAMSCAN,
    COMMAND_ALLMATCHSCAN,
    COMMAND_OPTSCAN,
};

typedef struct client_conn_tag {
    enum commands cmdtype;
    char *filename;
    int scanfd;
    int sd;
    struct cl_scan_options *options;
    const struct optstruct *opts;
    struct cl_engine *engine;
    time_t engine_timestamp;
    char term;
    threadpool_t *thrpool;
    int id;
    long quota;
    jobgroup_t *group;
    enum mode mode;
} client_conn_t;

int command(client_conn_t *conn, int *virus);
enum commands parse_command(const char *cmd, size_t cmd_len, const char **argument, size_t *argument_len, int oldstyle);
int execute_or_dispatch_command(client_conn_t *conn, enum commands command, const char *argument);

int conn_reply(const client_conn_t *conn, const char *path, const char *msg, const char *status);
int conn_reply_single(const client_conn_t *conn, const char *path, const char *status);
int conn_reply_virus(const client_conn_t *conn, const char *file, const char *virname);
int conn_reply_error(const client_conn_t *conn, const char *msg);
int conn_reply_errno(const client_conn_t *conn, const char *path, const char *msg);
#endif

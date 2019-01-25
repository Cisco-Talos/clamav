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

#ifndef __SESSION_H
#define __SESSION_H


#define CMD1 "SCAN"
/* #define CMD2 "RAWSCAN" */
#define CMD3 "QUIT" /* deprecated */
#define CMD4 "RELOAD"
#define CMD5 "PING"
#define CMD6 "CONTSCAN"
#define CMD7 "VERSION"
#define CMD8 "STREAM"
/*#define CMD9 "SESSION"*/
#define CMD10 "END"
#define CMD11 "SHUTDOWN"
/* #define CMD12 "FD" */
#define CMD13 "MULTISCAN"
#define CMD14 "FILDES"
#define CMD15 "STATS"
#define CMD16 "IDSESSION"
#define CMD17 "INSTREAM"
#define CMD18 "VERSIONCOMMANDS"
#define CMD19 "DETSTATSCLEAR"
#define CMD20 "DETSTATS"

#define CMD21 "ALLMATCHSCAN"

#include "libclamav/clamav.h"
#include "shared/optparser.h"
#include "server.h"
#include "others.h"

enum commands {
    COMMAND_UNKNOWN = 0,
    COMMAND_SHUTDOWN = 1,
    COMMAND_RELOAD,
    COMMAND_END,
    COMMAND_SESSION,
    COMMAND_SCAN,
    COMMAND_PING,
    COMMAND_CONTSCAN,
    COMMAND_VERSION,
    COMMAND_STREAM,
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
    COMMAND_ALLMATCHSCAN
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
enum commands parse_command(const char *cmd, const char **argument, int oldstyle);
int execute_or_dispatch_command(client_conn_t *conn, enum commands command, const char *argument);

int conn_reply(const client_conn_t *conn, const char *path, const char *msg, const char *status);
int conn_reply_single(const client_conn_t *conn, const char *path, const char *status);
int conn_reply_virus(const client_conn_t *conn, const char *file, const char *virname);
int conn_reply_error(const client_conn_t *conn, const char *msg);
int conn_reply_errno(const client_conn_t *conn, const char *path, const char *msg);
#endif

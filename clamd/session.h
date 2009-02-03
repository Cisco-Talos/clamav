/*
 *  Copyright (C) 2002 - 2004 Tomasz Kojm <tkojm@clamav.net>
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

#include "libclamav/clamav.h"
#include "shared/optparser.h"
#include "server.h"

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
    /* internal commands */
    COMMAND_MULTISCANFILE
};

typedef struct client_conn_tag {
    enum commands cmdtype;
    char *filename;
    int scanfd;
    int sd;
    int id;
    struct fd_data *fds;
    unsigned int options;
    const struct optstruct *opts;
    struct cl_engine *engine;
    time_t engine_timestamp;
    char term;
    threadpool_t *thrpool;
    jobgroup_t *group;
} client_conn_t;

int command(client_conn_t *conn);
enum commands parse_command(const char *cmd, const char **argument);
int execute_or_dispatch_command(client_conn_t *conn, enum commands command, const char *argument);

#endif

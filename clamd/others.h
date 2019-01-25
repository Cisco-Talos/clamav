/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *
 *  Authors: Tomasz Kojm, Trog, Török Edvin
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

#ifndef __CLAMD_OTHERS_H
#define __CLAMD_OTHERS_H

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdlib.h>
#include "shared/optparser.h"
#include "thrmgr.h"
#include "clamav-types.h"

enum mode {
    MODE_COMMAND,
    MODE_STREAM,
    MODE_WAITREPLY,
    MODE_WAITANCILL
};

struct fd_buf {
    char *buffer;
    size_t bufsize;
    size_t off;
    int fd;
    char term;
    int got_newdata; /* 0: no, 1: yes, -1: error */
    int recvfd;
    /* TODO: these fields don't belong here, there are identical fields in conn
     * too that don't belong there either. */
    enum mode mode;
    int id;
    int dumpfd;
    uint32_t chunksize;
    long quota;
    char *dumpname;
    time_t timeout_at; /* 0 - no timeout */
    jobgroup_t *group;
};

struct fd_data {
    pthread_mutex_t *buf_mutex; /* protects buf and nfds */
    struct fd_buf *buf;
    size_t nfds;
#ifdef HAVE_POLL
    struct pollfd *poll_data;
    size_t poll_data_nfds;
#endif
};

#ifdef HAVE_POLL
#define FDS_INIT(mutex) { (mutex), NULL, 0, NULL, 0}
#else
#define FDS_INIT(mutex) { (mutex), NULL, 0}
#endif

int poll_fd(int fd, int timeout_sec, int check_signals);
void virusaction(const char *filename, const char *virname, const struct optstruct *opts);
int writen(int fd, void *buff, unsigned int count);
int fds_add(struct fd_data *data, int fd, int listen_only, int timeout);
void fds_remove(struct fd_data *data, int fd);
void fds_cleanup(struct fd_data *data);
int fds_poll_recv(struct fd_data *data, int timeout, int check_signals, void *event);
void fds_free(struct fd_data *data);

#endif

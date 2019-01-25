/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2008-2013 Sourcefire, Inc.
 *
 *  Author: aCaB <acab@clamav.net>
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

#ifndef _NETCODE_H
#define _NETCODE_H

#include <sys/types.h>
#include <sys/socket.h>

#include "shared/optparser.h"
#include "connpool.h"

void nc_ping_entry(struct CP_ENTRY *cpe);
int nc_connect_rand(int *main, int *alt, int *local);
int nc_send(int s, const void *buf, size_t len);
char *nc_recv(int s);
int nc_sendmsg(int s, int fd);
int nc_connect_entry(struct CP_ENTRY *cpe);
int localnets_init(struct optstruct *opts);
void localnets_free(void);
int islocalnet_name(char *name);
int islocalnet_sock(struct sockaddr *sa);

extern long readtimeout;
extern char *tempdir;

#endif

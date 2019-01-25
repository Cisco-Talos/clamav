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

#ifndef _CONNPOOL_H
#define _CONNPOOL_H

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <sys/socket.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <pthread.h>

#include "shared/optparser.h"

struct CP_ENTRY {
    struct sockaddr *server;
    void *gai;
    socklen_t socklen;
    time_t last_poll;
    uint8_t type;
    uint8_t dead;
    uint8_t local;
};

struct CPOOL {
    unsigned int entries;
    unsigned int alive;
    struct CP_ENTRY *local_cpe;
    struct CP_ENTRY *pool;
};

void cpool_init(struct optstruct *copt);
void cpool_free(void);
struct CP_ENTRY *cpool_get_rand(int *s);

extern struct CPOOL *cp;

#endif

/*
 * Local Variables:
 * mode: c
 * c-basic-offset: 4
 * tab-width: 8
 * End: 
 * vim: set cindent smartindent autoindent softtabstop=4 shiftwidth=4 tabstop=8: 
 */

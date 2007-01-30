/*
 *  Copyright (C) 2002, 2003 Tomasz Kojm <tkojm@clamav.net>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
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

#ifndef __SERVER_H
#define __SERVER_H

#include <time.h>
#include <pthread.h>

#include "libclamav/clamav.h"
#include "shared/cfgparser.h"

struct thrarg {
    int sid;
    int options;
    const struct cfgstruct *copt;
    const struct cl_engine *engine;
    const struct cl_limits *limits;
};

struct thrsession {
    pthread_mutex_t mutex;
    short int active;
    pthread_t id;
    time_t start;
    int desc;
} *ths;

/* thread watcher arguments */
struct thrwarg {
    int socketd;
    struct cl_engine **engine;
    const struct cfgstruct *copt;
    const struct cl_limits *limits;
    unsigned int options;
};

int acceptloop_th(int *socketds, int nsockets, struct cl_engine *engine, unsigned int dboptions, const struct cfgstruct *copt);
void sighandler(int sig);
void sighandler_th(int sig);
void daemonize(void);
void sigsegv(int sig);

#endif

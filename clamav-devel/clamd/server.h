/*
 *  Copyright (C) 2002 Tomasz Kojm <zolw@konarski.edu.pl>
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
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifndef __SERVER_H
#define __SERVER_H

#include <time.h>
#include <clamav.h>
#include <pthread.h>

struct thrarg {
    int sid;
    int options; /* archive support 0/1 */
    const struct cfgstruct *copt;
    const struct cl_node *root;
    const struct cl_limits *limits;
};

struct thrsession {
    pthread_mutex_t mutex;
    short int active;
    short int reload;
    pthread_t id;
    time_t start;
    int desc;
} *ths;

/* thread watcher arguments */
struct thrwarg {
    int socketd;
    struct cl_node **root;
    const struct cfgstruct *copt;
};

short int progexit; /* exit steering variable */
int progpid; /* clamd pid */
short int reload, clamuko_reload;

int acceptloop(int socketd, struct cl_node *root, const struct cfgstruct *copt);
void sighandler(int sig);
void daemonize(void);
void sigsegv(int sig);

#endif

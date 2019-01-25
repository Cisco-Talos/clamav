/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *
 *  Authors: Tomasz Kojm, Trog, Török Edvin
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
#include "shared/optparser.h"
#include "thrmgr.h"
#include "session.h"
struct thrarg {
    int sid;
    struct cl_scan_options *options;
    const struct optstruct *opts;
    const struct cl_engine *engine;
};

int recvloop_th(int *socketds, unsigned nsockets, struct cl_engine *engine, unsigned int dboptions, const struct optstruct *opts);
int statinidir_th(const char* dirname);
void sighandler(int sig);
void sighandler_th(int sig);
void sigsegv(int sig);

extern pthread_mutex_t exit_mutex, reload_mutex;
extern int progexit, reload;

#endif

/*
 *  Copyright (C) 2013-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2009-2013 Sourcefire, Inc.
 *
 *  Author: aCaB
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

#ifndef __CLAMDCOM_H
#define __CLAMDCOM_H

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#if HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

#include "misc.h"

enum {
    CONT,
    MULTI,
    STREAM,
    FILDES,
    ALLMATCH,
    MAX_SCANTYPE = ALLMATCH
};

struct RCVLN {
    char buf[PATH_MAX + 1024]; /* FIXME must match that in clamd - bb1349 */
    int sockd;
    int r;
    char *cur;
    char *bol;
};

#ifndef _WIN32
extern struct sockaddr_un nixsock;
#endif

int sendln(int sockd, const char *line, unsigned int len);
void recvlninit(struct RCVLN *s, int sockd);
int recvln(struct RCVLN *s, char **rbol, char **reol);

int chkpath(const char *path, struct optstruct *clamdopts);
#ifdef HAVE_FD_PASSING
int send_fdpass(int sockd, const char *filename);
#endif
int send_stream(int sockd, const char *filename, struct optstruct *clamdopts);
int dconnect(struct optstruct *clamdopts);
int dsresult(int sockd, int scantype, const char *filename, int *printok, int *errors, struct optstruct *clamdopts);
#endif

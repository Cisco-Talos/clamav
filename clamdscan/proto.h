/*
 *  Copyright (C) 2009 Sourcefire, Inc.
 *
 *  Authors: Tomasz Kojm, aCaB
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

#ifndef PROTO_H
#define PROTO_H
#include "shared/misc.h"

struct RCVLN {
    char buf[PATH_MAX+1024]; /* FIXME must match that in clamd - bb1349 */
    int sockd;
    int r;
    char *cur;
    char *bol;
};

int dconnect(void);
int sendln(int sockd, const char *line, unsigned int len);
void recvlninit(struct RCVLN *s, int sockd);
int recvln(struct RCVLN *s, char **rbol, char **reol);
int serial_client_scan(char *file, int scantype, int *infected, int *err, int maxlevel, int flags);
int parallel_client_scan(char *file, int scantype, int *infected, int *err, int maxlevel, int flags);
int dsresult(int sockd, int scantype, const char *filename, int *printok, int *errors);
#endif

/*
 *  Copyright (C) 2002 - 2007 Tomasz Kojm <tkojm@clamav.net>
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

#ifndef __SCANNER_H
#define __SCANNER_H

#define TYPE_SCAN	0
#define TYPE_CONTSCAN	1
#define TYPE_MULTISCAN	2

#include "libclamav/clamav.h"
#include "shared/optparser.h"
#include "thrmgr.h"

struct scan_cb_data {
    int scantype;
    int odesc;
    int type;
    int infected;
    int errors;
    int total;
    char term;
    const char *toplevel_path;
    unsigned long scanned;
    unsigned int options;
    struct cl_engine *engine;
    const struct optstruct *opts;
    threadpool_t *thr_pool;
    jobgroup_t *group;
};

int scanfd(const int fd, char term, unsigned long int *scanned, const struct cl_engine *engine, unsigned int options, const struct optstruct *opts, int odesc);
int scanstream(int odesc, unsigned long int *scanned, const struct cl_engine *engine, unsigned int options, const struct optstruct *opts, char term);
int scan_callback(struct stat *sb, char *filename, const char *msg, enum cli_ftw_reason reason, struct cli_ftw_cbdata *data);

#endif

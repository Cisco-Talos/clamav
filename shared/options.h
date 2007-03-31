/*
 *  Copyright (C) 2002 - 2006 Tomasz Kojm <tkojm@clamav.net>
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

#ifndef __OPTIONS_H
#define __OPTIONS_H

#define _GNU_SOURCE
#include "getopt.h"

struct optnode {
    char optshort;
    char *optlong;
    char *optarg;
    struct optnode *next;
};

struct optstruct {
    struct optnode *optlist;
    char *filename;
};

void opt_free(struct optstruct *opt);

struct optstruct *opt_parse(int argc, char * const *argv, const char *getopt_short, const struct option *options_long, const char * const *accepted_long);

int opt_check(const struct optstruct *opt, const char *optlong);

char *opt_arg(const struct optstruct *opt, const char *optlong);

char *opt_firstarg(const struct optstruct *opt, const char *optlong, const struct optnode **optnode);

char *opt_nextarg(const struct optnode **optnode, const char *optlong);

#endif

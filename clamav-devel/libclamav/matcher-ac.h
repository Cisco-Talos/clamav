/*
 *  Copyright (C) 2002 - 2005 Tomasz Kojm <tkojm@clamav.net>
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

#ifndef __MATCHER_AC_H
#define __MATCHER_AC_H

#include "clamav.h"
#include "matcher.h"
#include "filetypes.h"

#define AC_DEFAULT_DEPTH 2
#define AC_DEFAULT_TRACKLEN 8

struct cli_ac_data {
    unsigned int partsigs;
    unsigned int *partcnt;
    unsigned int **partoff;
    unsigned int *offcnt;
    int *maxshift;
};

int cli_ac_addpatt(struct cli_matcher *root, struct cli_ac_patt *pattern);
int cli_ac_initdata(struct cli_ac_data *data, unsigned int partsigs, unsigned int histlen);
void cli_ac_freedata(struct cli_ac_data *data);
int cli_ac_scanbuff(const unsigned char *buffer, unsigned int length, const char **virname, const struct cli_matcher *root, struct cli_ac_data *mdata, unsigned short otfrec, unsigned long int offset, unsigned short ftype, int fd, struct cli_matched_type **ftoffset);
int cli_ac_buildtrie(struct cli_matcher *root);
void cli_ac_free(struct cli_matcher *root);
void cli_ac_setdepth(unsigned int depth);

#endif

/*
 *  Copyright (C) 2002 - 2004 Tomasz Kojm <tkojm@clamav.net>
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

#ifndef __MATCHER_H
#define __MATCHER_H

#include "clamav.h"

struct nodelist {
    struct cl_node *node;
    struct nodelist *next;
};

int cli_addpatt(struct cl_node *root, struct cli_patt *pattern);
struct nodelist *cli_bfsadd(struct nodelist *bfs, struct cl_node *n);
void cli_failtrans(struct cl_node *root);
void cli_fasttrie(struct cl_node *n, struct cl_node *root);
int cli_findpos(const char *buffer, int offset, int length, const struct cli_patt *pattern);
int cli_scanbuff(const char *buffer, unsigned int length, const char **virname, const struct cl_node *root, int *partcnt);

#endif

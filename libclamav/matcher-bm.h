/*
 *  Copyright (C) 2004 Tomasz Kojm <tkojm@clamav.net>
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

#ifndef __MATCHER_BM_H
#define __MATCHER_BM_H

#include "clamav.h"
#include "matcher.h"

int cli_bm_addpatt(struct cl_node *root, struct cli_bm_patt *pattern);
int cli_bm_init(struct cl_node *root);
int cli_bm_scanbuff(const char *buffer, unsigned int length, const char **virname, const struct cl_node *root, unsigned long int offset, unsigned short ftype, int fd);
void cli_bm_free(struct cl_node *root);

#endif

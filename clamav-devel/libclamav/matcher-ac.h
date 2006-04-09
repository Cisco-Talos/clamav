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

int cli_ac_addpatt(struct cli_matcher *root, struct cli_ac_patt *pattern);
int cli_ac_scanbuff(const char *buffer, unsigned int length, const char **virname, const struct cli_matcher *root, int *partcnt, unsigned short otfrec, unsigned long int offset, unsigned long int *partoff, unsigned short ftype, int fd, struct cli_matched_type **ftoffset);
int cli_ac_buildtrie(struct cli_matcher *root);
void cli_ac_free(struct cli_matcher *root);
void cli_ac_setdepth(unsigned int depth);

#endif

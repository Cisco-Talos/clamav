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

#ifndef __MATCHER_H
#define __MATCHER_H

#include "clamav.h"
#include "filetypes.h"
#include "others.h"

#define CL_TARGET_TABLE_SIZE 7

int cli_scandesc(int desc, cli_ctx *ctx, unsigned short otfrec, unsigned short ftype, struct cli_matched_type **ftoffset);

int cli_scanbuff(const char *buffer, unsigned int length, const char **virname, const struct cl_engine *engine, unsigned short ftype);

int cli_validatesig(unsigned short ftype, const char *offstr, unsigned long int fileoff, int desc, const char *virname);

#endif

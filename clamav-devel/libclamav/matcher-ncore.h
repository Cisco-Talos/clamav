/*
 *  Copyright (C) 2006 Tomasz Kojm <tkojm@clamav.net>
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

#ifndef __MATCHER_NCORE_H
#define __MATCHER_NCORE_H

#include "clamav.h"
#include "md5.h"

int cli_ncore_scanbuff(const char *buffer, unsigned int length, const char **virname, const struct cl_engine *engine, unsigned short ftype, unsigned int *targettab);

int cli_ncore_scandesc(int desc, cli_ctx *ctx, unsigned short ftype, int *cont, unsigned int *targettab, MD5_CTX *md5ctx);

int cli_ncore_load(const char *filename, struct cl_engine **engine, unsigned int *signo, unsigned int options);

void cli_ncore_unload(struct cl_engine *engine);

#endif

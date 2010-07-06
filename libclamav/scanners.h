/*
 *  Copyright (C) 2007-2008 Sourcefire, Inc.
 *
 *  Authors: Tomasz Kojm
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

#ifndef __SCANNERS_H
#define __SCANNERS_H

#include "clamav.h"
#include "others.h"

int cli_magic_scandesc(int desc, cli_ctx *ctx);
int cli_found_possibly_unwanted(cli_ctx* ctx);
int cli_scandesc_stats(int desc, const char **virname, char *virhash, unsigned int *virsize, unsigned long int *scanned, const struct cl_engine *engine, unsigned int scanoptions);
int cli_scanfile_stats(const char *filename, const char **virname, char *virhash, unsigned int *virsize, unsigned long int *scanned, const struct cl_engine *engine, unsigned int scanoptions);

#endif

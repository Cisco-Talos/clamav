/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2010-2013 Sourcefire, Inc.
 *
 *  Authors: aCaB <acab@clamav.net>
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

#ifndef __CACHE_H
#define __CACHE_H

#include "clamav.h"
#include "others.h"

void cache_add(unsigned char *md5, size_t size, cli_ctx *ctx);
/* Removes a hash from the cache */
void cache_remove(unsigned char *md5, size_t size, const struct cl_engine *engine);
int cache_check(unsigned char *hash, cli_ctx *ctx);
int cli_cache_init(struct cl_engine *engine);
void cli_cache_destroy(struct cl_engine *engine);

int cache_get_MD5(unsigned char *hash, cli_ctx *ctx);

#endif

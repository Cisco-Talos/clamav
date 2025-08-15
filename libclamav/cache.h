/*
 *  Copyright (C) 2013-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
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

/**
 * @brief Add a hash of the current layer to the cache of clean files.
 *
 * @param ctx The scanning context.
 */
void clean_cache_add(cli_ctx *ctx);

/**
 * @brief Removes a hash from the clean cache
 *
 * @param sha2_256 The file to remove.
 * @param size     The size of the file.
 * @param ctx      The scanning context.
 */
void clean_cache_remove(uint8_t *sha2_256, size_t size, const struct cl_engine *engine);

/**
 * @brief Hashes a file onto the provided buffer and looks it up the clean cache.
 *
 * @param hash Hash to check
 * @param ctx
 * @return CL_VIRUS if found, CL_CLEAN if not FIXME or a recoverable error.
   @return CL_EREAD if unrecoverable.
 */
cl_error_t clean_cache_check(cli_ctx *ctx);

/**
 * @brief Allocates the trees for the clean cache.
 *
 * @param engine
 * @return int
 */
cl_error_t clean_cache_init(struct cl_engine *engine);

/**
 * @brief Frees the clean cache
 *
 * @param engine
 */
void clean_cache_destroy(struct cl_engine *engine);

#endif

/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
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
#include "filetypes.h"

/**
 * @brief   Scan a tempfile / sub-file of _any_ type, passing in the fd, filepath (if available), and the scanning context.
 * 
 * @param desc      File descriptor
 * @param filepath  (optional) Full file path.
 * @param ctx       Scanning context structure.
 * @return int      CL_SUCCESS, or an error code.
 */
int cli_magic_scandesc(int desc, const char *filepath, cli_ctx *ctx);

/**
 * @brief   Like cli_magic_scandesc(), but where the file type is known to be a partition.
 * 
 * @param desc      File descriptor
 * @param filepath  (optional) Full file path.
 * @param ctx       Scanning context structure.
 * @return int      CL_SUCCESS, or an error code.
 */
int cli_partition_scandesc(int desc, const char *filepath, cli_ctx *ctx);

int cli_magic_scandesc_type(cli_ctx *ctx, cli_file_t type);

/**
 * @brief   Scan an offset/length into a file map.
 * 
 * For map scans that are not forced to disk.
 * 
 * @param map       File map.
 * @param offset    Offset into file map.
 * @param length    Length from offset.
 * @param ctx       Scanning context structure.
 * @param type      CL_TYPE of data to be scanned.
 * @return int      CL_SUCCESS, or an error code.
 */
int cli_map_scandesc(cl_fmap_t *map, off_t offset, size_t length, cli_ctx *ctx, cli_file_t type);

/**
 * @brief   Scan an offset/length into a file map.
 * 
 * Like cli_man_scandesc(), but for map scans that may be forced to disk.
 * 
 * @param map       File map.
 * @param offset    Offset into file map.
 * @param length    Length from offset.
 * @param ctx       Scanning context structure.
 * @param type      CL_TYPE of data to be scanned.
 * @return int      CL_SUCCESS, or an error code.
 */
int cli_map_scan(cl_fmap_t *map, off_t offset, size_t length, cli_ctx *ctx, cli_file_t type);

/**
 * @brief   Convenience wrapper for cli_map_scan().
 * 
 * Creates an fmap and calls cli_map_scan() for you, with type CL_TYPE_ANY.
 * 
 * @param buffer    Pointer to the buffer to be scanned.
 * @param length    Size in bytes of the buffer being scanned.
 * @param ctx       Scanning context structure.
 * @return int      CL_SUCCESS, or an error code.
 */
int cli_mem_scandesc(const void *buffer, size_t length, cli_ctx *ctx);

int cli_found_possibly_unwanted(cli_ctx* ctx);

#endif

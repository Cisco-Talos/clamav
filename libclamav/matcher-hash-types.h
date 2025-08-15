/*
 *  Copyright (C) 2013-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2010-2013 Sourcefire, Inc.
 *
 *  Authors: aCaB
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

#ifndef __MATCHER_HASH_TYPES_H
#define __MATCHER_HASH_TYPES_H

typedef enum cli_hash_type {
    CLI_HASH_MD5 = 0,
    CLI_HASH_SHA1,
    CLI_HASH_SHA2_256,
    CLI_HASH_SHA2_384,
    CLI_HASH_SHA2_512,
} cli_hash_type_t;

#define CLI_HASH_AVAIL_TYPES (CLI_HASH_SHA2_256 + 1)

/**
 * @brief Get the name of the hash type as a string.
 *
 * Note: using the name OpenSSL uses for the hash type.
 *
 * @param type The hash type.
 * @return char* The name of the hash type.
 */
const char* cli_hash_name(cli_hash_type_t type);

/**
 * @brief Get the size of the hash type.
 *
 * @param type The hash type.
 * @return size_t The size of the hash type.
 */
size_t cli_hash_len(cli_hash_type_t type);

#define CLI_HASHLEN_MAX SHA256_HASH_SIZE

#endif

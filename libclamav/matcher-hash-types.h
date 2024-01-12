/*
 *  Copyright (C) 2013-2024 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
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
    CLI_HASH_SHA256,

    /* new hash types go above this line */
    CLI_HASH_AVAIL_TYPES
} cli_hash_type_t;

#define CLI_HASHLEN_MD5 16
#define CLI_HASHLEN_SHA1 20
#define CLI_HASHLEN_SHA256 32
#define CLI_HASHLEN_MAX 32

#endif

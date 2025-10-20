/*
 *  Copyright (C) 2021-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *
 *  Authors: Valerie Snyder
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

#ifndef __OTHER_TYPES_H_LC
#define __OTHER_TYPES_H_LC

#include <stdint.h>

typedef struct image_fuzzy_hash {
    uint8_t hash[8];
} image_fuzzy_hash_t;

typedef void *evidence_t;
typedef void *onedump_t;
typedef void *cvd_t;
typedef void *cli_ctx_t;

#endif /* __OTHER_TYPES_H_LC */

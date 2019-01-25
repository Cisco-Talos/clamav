/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *
 *  Authors: Luciano Giuseppe 'Pnluck', Alberto Wu
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

#ifndef __ASPACK_H
#define __ASPACK_H

#include "clamav-types.h"
#include "execs.h"

#define ASPACK_EP_OFFSET_212    (58+0x70e)
#define ASPACK_EP_OFFSET_OTHER  (58+0x76a)
#define ASPACK_EP_OFFSET_242    (58+0x776)

#define ASPACK_EPBUFF_OFFSET_212    (0x3b9)
#define ASPACK_EPBUFF_OFFSET_OTHER  (0x41f)
#define ASPACK_EPBUFF_OFFSET_242    (0x42B)

typedef enum aspack_version_tag {
    ASPACK_VER_NONE=0,
    ASPACK_VER_212,
    ASPACK_VER_OTHER,
    ASPACK_VER_242
} aspack_version_t;

int unaspack(uint8_t *image, unsigned int size, struct cli_exe_section *sections, uint16_t sectcount, uint32_t ep, uint32_t base, int f, aspack_version_t version);

#endif

/*
 *  Copyright (C) 2013-2026 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *
 *  Authors: Alberto Wu
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

/* a cleaner state interface to LZMA */

#ifndef __LZMA_IFACE_H
#define __LZMA_IFACE_H

#include "clamav-types.h"
#include "others.h"

#define LZMA_PROPS_SIZE 5

struct CLI_LZMA {
    void *rust_state;
    unsigned char *next_in;
    unsigned char *next_out;
    size_t avail_in;
    size_t avail_out;
};

struct stream_state {
    uint32_t avail_in;
    unsigned char *next_in;
    uint32_t avail_out;
    unsigned char *next_out;
};

int cli_LzmaInit(struct CLI_LZMA *, uint64_t);
void cli_LzmaShutdown(struct CLI_LZMA *);
int cli_LzmaDecode(struct CLI_LZMA *);

#define LZMA_STREAM_END 2
#define LZMA_RESULT_OK 0
#define LZMA_RESULT_DATA_ERROR 1
#endif /* __LZMA_IFACE_H */

/*
 *  Copyright (C) 2013-2026 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
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

/* zlib-alike state interface to LZMA */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include "clamav.h"
#include "lzma_iface.h"
#include "clamav_rust.h"

int cli_LzmaInit(struct CLI_LZMA *L, uint64_t size_override)
{
    if (!L)
        return LZMA_RESULT_DATA_ERROR;
    return rust_lzma_init(&L->rust_state, size_override, &L->next_in, &L->avail_in);
}

void cli_LzmaShutdown(struct CLI_LZMA *L)
{
    if (!L)
        return;
    rust_lzma_shutdown(&L->rust_state);
}

int cli_LzmaDecode(struct CLI_LZMA *L)
{
    if (!L)
        return LZMA_RESULT_DATA_ERROR;
    return rust_lzma_decode(&L->rust_state, &L->next_in, &L->avail_in,
                            &L->next_out, &L->avail_out);
}

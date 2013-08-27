/*
 *  Copyright (C) 2013 Sourcefire, Inc.
 *
 *  Authors: David Raynor <draynor@sourcefire.com>
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

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdio.h>
#include <ctype.h>

#include "cltypes.h"
#include "others.h"
#include "dmg.h"
#include "scanners.h"

int cli_scandmg(cli_ctx *ctx)
{
    struct dmg_koly_block hdr;
    int ret, conv;
    size_t maplen;

    char name[513];
    unsigned int file = 0, trailer = 0;
    uint32_t filesize, namesize, hdr_namesize;
    off_t pos = 0;

    if (!ctx || !ctx->fmap) {
        cli_errmsg("cli_scandmg: Invalid context\n");
        return CL_ENULLARG;
    }

    maplen = (*ctx->fmap)->real_len;
    pos = maplen - 512;
    if (pos <= 0) {
        cli_dbgmsg("cli_scandmg: Sizing problem for DMG archive.\n");
        return CL_CLEAN;
    }

    /* Grab koly block */
    if (fmap_readn(*ctx->fmap, &hdr, pos, sizeof(hdr)) != sizeof(hdr)) {
        cli_dbgmsg("cli_scandmg: Invalid DMG trailer block\n");
        return CL_EFORMAT;
    }

    /* Check magic */
    hdr.magic = be32_to_host(hdr.magic);
    if (hdr.magic == 0x6b6f6c79) {
        cli_dbgmsg("cli_scandmg: Found koly block @ %ld\n", (long) pos);
    }
    else {
        cli_dbgmsg("cli_scandmg: No koly magic, %8x\n", hdr.magic);
        return CL_EFORMAT;
    }

    /* TODO: the rest of the unpacking */

    return CL_CLEAN;
}


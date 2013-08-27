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

#include "cltypes.h"
#include "others.h"
#include "xar.h"
#include "fmap.h"
#include "scanners.h"

int cli_scanxar(cli_ctx *ctx)
{
    struct xar_header hdr;
    char name[513];
    unsigned int file = 0, trailer = 0;
    uint32_t filesize, namesize, hdr_namesize;
    int ret, conv;
    off_t pos = 0;

    if (fmap_readn(*ctx->fmap, &hdr, pos, sizeof(hdr)) != sizeof(hdr)) {
        cli_dbgmsg("cli_scanxar: Invalid header, too short.\n");
        return CL_EFORMAT;
    }
    hdr.magic = be32_to_host(hdr.magic);
    if (hdr.magic == 0x78617221) {
        cli_dbgmsg("cli_scanxar: Matched magic\n");
    }
    else {
        cli_dbgmsg("cli_scanxar: Invalid magic\n");
        return CL_EFORMAT;
    }

    /* TODO: First grab the TOC, parse that, and then unpack the rest. */

    return CL_CLEAN;
}


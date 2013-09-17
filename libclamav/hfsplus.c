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
#include "hfsplus.h"
#include "scanners.h"

int cli_scanhfsplus(cli_ctx *ctx)
{
    int ret = CL_CLEAN;

    if (!ctx || !ctx->fmap) {
        cli_errmsg("cli_scanhfsplus: Invalid context\n");
        return CL_ENULLARG;
    }

    cli_dbgmsg("cli_scanhfsplus: starting scan\n");

    return ret;
}

/*
 *  Copyright (C) 2013-2026 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2009-2013 Sourcefire, Inc.
 *
 *  Authors: Tomasz Kojm <tkojm@clamav.net>
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

#include "clamav_rust.h"
#include "clamav.h"
#include "execs.h"
#include "macho.h"

cl_error_t cli_scanmacho(cli_ctx *ctx, struct cli_exe_info *fileinfo)
{
    if (ctx == NULL) {
        cli_errmsg("cli_scanmacho: ctx == NULL\n");
        return CL_ENULLARG;
    }

    if (fileinfo != NULL) {
        return populate_macho_target_info_rust(ctx, fileinfo);
    }

    cli_dbgmsg("cli_scanmacho: using Rust executable parser\n");
    return scan_macho_rust(ctx);
}

cl_error_t cli_machoheader(cli_ctx *ctx, struct cli_exe_info *fileinfo)
{
    return populate_macho_target_info_rust(ctx, fileinfo);
}

cl_error_t cli_scanmacho_unibin(cli_ctx *ctx)
{
    if (ctx == NULL) {
        cli_errmsg("cli_scanmacho_unibin: ctx == NULL\n");
        return CL_ENULLARG;
    }

    cli_dbgmsg("cli_scanmacho_unibin: using Rust executable parser\n");
    return scan_macho_unibin_rust(ctx);
}

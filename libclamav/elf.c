/*
 *  Copyright (C) 2013-2026 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *
 *  Authors: Tomasz Kojm
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

#include "clamav_rust.h"
#include "clamav.h"
#include "elf.h"
#include "execs.h"

cl_error_t cli_scanelf(cli_ctx *ctx)
{
    if (ctx == NULL) {
        cli_errmsg("cli_scanelf: ctx == NULL\n");
        return CL_ENULLARG;
    }

    cli_dbgmsg("cli_scanelf: using Rust executable parser\n");
    return scan_elf_rust(ctx);
}

cl_error_t cli_elfheader(cli_ctx *ctx, struct cli_exe_info *elfinfo)
{
    return populate_elf_target_info_rust(ctx, elfinfo);
}

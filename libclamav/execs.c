/*
 *  Copyright (C) 2018-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *
 *  Authors: Andrew Williams
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

#include "execs.h"
#include <string.h>

void cli_exe_info_init(struct cli_exe_info *exeinfo, uint32_t offset)
{

    if (NULL == exeinfo) {
        return;
    }

    memset(exeinfo, '\0', sizeof(*exeinfo));
    exeinfo->offset = offset;

    // TODO Replace the memset above with the following once we can make
    // certain that this is the only initialization needed (maybe run with
    // MemorySanitizer?)

    ///* Initialize all of the members which are actually used by the matcher
    // * and by the bytecode runtime.  The rest is executable specific and
    // * we'll leave it to be populated by the exe parsing code. */
    // exeinfo->offset = offset;
    // exeinfo->sections = NULL;
    // exeinfo->nsections = 0;
    // exeinfo->ep = 0;
    ///* NOTE: These are PE-specific to an extent, but we should still
    // * initialize them for other exe types because they are used by
    // * the matcher/bytecode runtime. */
    // exeinfo->hdr_size = 0;
    // exeinfo->res_addr = 0;
    // cli_hashset_init_noalloc(&(exeinfo->vinfo));
}

void cli_exe_info_destroy(struct cli_exe_info *exeinfo)
{

    if (NULL == exeinfo) {
        return;
    }

    if (NULL != exeinfo->sections) {
        free(exeinfo->sections);
        exeinfo->sections = NULL;
    }

    cli_hashset_destroy(&(exeinfo->vinfo));
}

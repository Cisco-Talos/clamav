/*
 *  Copyright (C) 2018 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
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
    // TODO the memset below might not be needed.  Instead, replace with:
    // exeinfo->sections = NULL;
    // memset(&exeinfo->vinfo, '\0', sizeof(exeinfo->vinfo));
    memset(exeinfo, '\0', sizeof(*exeinfo));
    exeinfo->offset = offset;
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
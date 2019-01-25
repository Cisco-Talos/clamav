/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2009-2013 Sourcefire, Inc.
 *
 *  Authors: aCaB <acab@clamav.net>
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

#ifndef __PE_ICONS_H
#define __PE_ICONS_H
#include "pe.h"

int cli_scanicon(icon_groupset *set, uint32_t resdir_rva, cli_ctx *ctx, struct cli_exe_section *exe_sections, uint16_t nsections, uint32_t hdr_size);

void cli_icongroupset_add(const char *groupname, icon_groupset *set, unsigned int type, cli_ctx *ctx);
static inline void cli_icongroupset_init(icon_groupset *set) {
    set->v[0][0] = 0;
    set->v[0][1] = 0;
    set->v[0][2] = 0;
    set->v[0][3] = 0;
    set->v[1][0] = 0;
    set->v[1][1] = 0;
    set->v[1][2] = 0;
    set->v[1][3] = 0;
}


#endif

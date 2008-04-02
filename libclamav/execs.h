/*
 *  Copyright (C) 2007-2008 Sourcefire, Inc.
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

#ifndef __EXECS_H
#define __EXECS_H

#include "cltypes.h"
#include <sys/types.h>

struct cli_exe_section {
    uint32_t rva;
    uint32_t vsz;
    uint32_t raw;
    uint32_t rsz;
    uint32_t chr;
    uint32_t urva; /* PE - unaligned VirtualAddress */
    uint32_t uvsz; /* PE - unaligned VirtualSize */
    uint32_t uraw; /* PE - unaligned PointerToRawData */
    uint32_t ursz; /* PE - unaligned SizeOfRawData */
};

struct cli_exe_info {
    struct cli_exe_section *section;
    off_t offset;
    uint32_t ep;
    uint16_t nsections;
};

#endif

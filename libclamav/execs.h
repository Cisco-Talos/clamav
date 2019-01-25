/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
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

#ifndef __EXECS_H
#define __EXECS_H

#include "clamav-types.h"
#include "hashtab.h"
#include "bcfeatures.h"

/** @file */
/** Section of executable file.
  \group_pe
*/
struct cli_exe_section {
    uint32_t rva;/**< Relative VirtualAddress */
    uint32_t vsz;/**< VirtualSize */
    uint32_t raw;/**< Raw offset (in file) */
    uint32_t rsz;/**< Raw size (in file) */
    uint32_t chr;/**< Section characteristics */
    uint32_t urva; /**< PE - unaligned VirtualAddress */
    uint32_t uvsz; /**< PE - unaligned VirtualSize */
    uint32_t uraw; /**< PE - unaligned PointerToRawData */
    uint32_t ursz; /**< PE - unaligned SizeOfRawData */
};

/** Executable file information
  \group_pe
*/
struct cli_exe_info {
    /** Information about all the sections of this file. 
     * This array has \p nsection elements */
    struct cli_exe_section *section;
    /** Offset where this executable start in file (nonzero if embedded) */
    uint32_t offset;
    /** Entrypoint of executable */
    uint32_t ep;
    /** Number of sections*/
    uint16_t nsections;
    void *dummy;/* for compat - preserve offset */
    /** Resources RVA - PE ONLY */
    uint32_t res_addr;
    /** Address size - PE ONLY */
    uint32_t hdr_size;
    /** Hashset for versioninfo matching */
    struct cli_hashset vinfo;
};

#endif

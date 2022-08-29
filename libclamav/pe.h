/*
 *  Copyright (C) 2013-2022 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *
 *  Authors: Alberto Wu, Tomasz Kojm, Andrew Williams
 *
 *  Acknowledgements: The header structures were based upon a PE format
 *                    analysis by B. Luevelsmeyer.
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

#ifndef __PE_H
#define __PE_H

#include "clamav.h"
#include "others.h"
#include "fmap.h"
#include "bcfeatures.h"
#include "pe_structs.h"
#include "execs.h"

/** Data for the bytecode PE hook
 * \group_pe
 *
 *  NOTE: This structure must stay in-sync with the ones defined within the
 *  clamav-bytecode-compiler source at:
 *  - clang/lib/Headers/bytecode_pe.h
 *  - llvm/tools/clang/lib/Headers/bytecode_pe.h
 *  We allocate space for this, populate the values via cli_peheader, and pass
 *  it to the bytecode sig runtime for use.
 *
 *  TODO Next time we are making changes to the clamav-bytecode-compiler
 *  source, update pe_image_optional_hdr32 and pe_image_optional_hdr64 to
 *  remove DataDirectory from both (like with the definitions here).  Then,
 *  remove opt32_dirs and opt64_dirs below.  There's no need to have these
 *  bytes in 3 places!  Also, consider using a union to hold opt32 and opt64,
 *  since you never need more than one at a time.
 */
struct cli_pe_hook_data {
    uint32_t offset;
    uint32_t ep;                          /**< EntryPoint as file offset */
    uint16_t nsections;                   /**< Number of sections */
    uint16_t dummy;                       /* align */
    struct pe_image_file_hdr file_hdr;    /**< Header for this PE file */
    struct pe_image_optional_hdr32 opt32; /**< 32-bit PE optional header */
    /** Our opt32 no longer includes DataDirectory[16], but the one in the
     * bytecode compiler source still does.  Add this here as a placeholder (and
     * it gets used, so we need to populate it also */
    struct pe_image_data_dir opt32_dirs[16];
    uint32_t dummy2;                         /* align */
    struct pe_image_optional_hdr64 opt64;    /**< 64-bit PE optional header */
    struct pe_image_data_dir opt64_dirs[16]; /** See note about opt32_dirs */
    struct pe_image_data_dir dirs[16];       /**< PE data directory header */
    uint32_t e_lfanew;                       /**< address of new exe header */
    uint32_t overlays;                       /**< number of overlays */
    int32_t overlays_sz;                     /**< size of overlays */
    uint32_t hdr_size;                       /**< internally needed by rawaddr */
};

int cli_scanpe(cli_ctx *ctx);

enum {
    CL_GENHASH_PE_CLASS_SECTION,
    CL_GENHASH_PE_CLASS_IMPTBL,
    /* place new class types above this line */
    CL_GENHASH_PE_CLASS_LAST
};

// For info about these, see the cli_peheader definition in pe.c
#define CLI_PEHEADER_OPT_NONE 0x0
#define CLI_PEHEADER_OPT_COLLECT_JSON 0x1
#define CLI_PEHEADER_OPT_DBG_PRINT_INFO 0x2
#define CLI_PEHEADER_OPT_EXTRACT_VINFO 0x4
#define CLI_PEHEADER_OPT_STRICT_ON_PE_ERRORS 0x8
#define CLI_PEHEADER_OPT_REMOVE_MISSING_SECTIONS 0x10

cl_error_t cli_pe_targetinfo(cli_ctx *ctx, struct cli_exe_info *peinfo);
cl_error_t cli_peheader(fmap_t *map, struct cli_exe_info *peinfo, uint32_t opts, cli_ctx *ctx);

cl_error_t cli_check_auth_header(cli_ctx *ctx, struct cli_exe_info *peinfo);
cl_error_t cli_genhash_pe(cli_ctx *ctx, unsigned int class, int type, stats_section_t *hashes);

uint32_t cli_rawaddr(uint32_t, const struct cli_exe_section *, uint16_t, unsigned int *, size_t, uint32_t);
void findres(uint32_t, uint32_t, fmap_t *map, struct cli_exe_info *, int (*)(void *, uint32_t, uint32_t, uint32_t, uint32_t), void *);

#endif

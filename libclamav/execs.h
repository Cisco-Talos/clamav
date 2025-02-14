/*
 *  Copyright (C) 2013-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
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
#include "pe_structs.h"

/** @file */
/** Section of executable file.
 * \group_pe
 *  NOTE: This is used to store PE, MachO, and ELF section information. Not
 *  all members are populated by the respective parsing functions.
 *
 *  NOTE: This header file originates in the clamav-devel source and gets
 *  copied into the clamav-bytecode-compiler source through a script
 *  (sync-clamav.sh). This is done because an array of this structure is
 *  allocated by libclamav and passed to the bytecode sig runtime.
 *
 *  If you need to make changes to this structure, you will need to update
 *  it in both repos.  Also, I'm not sure whether changing this structure
 *  would require a recompile of all previous bytecode sigs.  This should
 *  be investigated before changes are made.
 *
 *  TODO Modify this structure to also include the section name (in both
 *  repos).  Then, populate this field in the libclamav PE/MachO/ELF header
 *  parsing functions.  Choose a length that's reasonable for all platforms
 */
struct cli_exe_section {
    uint32_t rva;  /**< Relative VirtualAddress */
    uint32_t vsz;  /**< VirtualSize */
    uint32_t raw;  /**< Raw offset (in file) */
    uint32_t rsz;  /**< Raw size (in file) */
    uint32_t chr;  /**< Section characteristics */
    uint32_t urva; /**< PE - unaligned VirtualAddress */
    uint32_t uvsz; /**< PE - unaligned VirtualSize */
    uint32_t uraw; /**< PE - unaligned PointerToRawData */
    uint32_t ursz; /**< PE - unaligned SizeOfRawData */
};

/** Executable file information
 *  NOTE: This is used to store PE, MachO, and ELF executable information,
 *  but it predominantly has fields for PE info.  Not all members are
 *  populated by the respective parsing functions.
 *
 *  NOTE: This header file originates in the clamav-devel source and gets
 *  copied into the clamav-bytecode-compiler source through a script
 *  (sync-clamav.sh). This is done because an array of cli_exe_section
 *  structs is allocated by libclamav and passed to the bytecode sig
 *  runtime.
 *
 *  This structure is not used by the bytecode sig runtime, so it can be
 *  modified in the clamav-devel repo without requiring the changes to
 *  be propagated to the clamav-bytecode-compile repo and that code rebuilt.
 *  It'd be nice to keep them in sync if possible, though.
 */
struct cli_exe_info {
    /** Information about all the sections of this file.
     * This array has \p nsection elements */
    struct cli_exe_section *sections;

    /** Offset where this executable starts in file (nonzero if embedded) */
    uint32_t offset;

    /** File offset to the entrypoint of the executable. */
    uint32_t ep;

    /** Number of sections.
     *  NOTE: If a section is determined to be invalid (exists outside of the
     *  file) then it will not be included in this count (at least for PE).
     */
    uint16_t nsections;

    /***************** Begin PE-specific Section *****************/

    /** Resources RVA */
    uint32_t res_addr;

    /** Size of the  header (aligned). This corresponds to
     *  SizeOfHeaders in the optional header
     */
    uint32_t hdr_size;

    /** Hashset for versioninfo matching */
    struct cli_hashset vinfo;

    /** Entry point RVA */
    uint32_t vep;

    /** Number of data directory entries at the end of the optional header.
     *  This also corresponds to the number of entries in dirs that has
     *  been populated with information.
     */
    uint32_t ndatadirs;

    /** Whether this file is a DLL */
    uint32_t is_dll;

    /** Whether this file is a PE32+ exe (64-bit) */
    uint32_t is_pe32plus;

    /**< address of new exe header */
    uint32_t e_lfanew;

    /** The lowest section RVA */
    uint32_t min;

    /** The RVA of the highest byte contained within a section */
    uint32_t max;

    /** Offset of any file overlays, as determined by parsing the PE header */
    uint32_t overlay_start;

    /**< size of overlay */
    uint32_t overlay_size;

    /* Raw data copied in from the EXE directly.
     *
     * NOTE: The data in the members below haven't been converted to host
     * endianness, so all field accesses must account for this to ensure
     * proper functionality on big endian systems (the PE header is always
     * little-endian)
     */

    /** Image File Header for this PE file */
    struct pe_image_file_hdr file_hdr;

    /** PE optional header. Use is_pe32plus to determine whether the 32-bit
     *  or 64-bit union member should be used. */
    union {
        struct pe_image_optional_hdr64 opt64;
        struct pe_image_optional_hdr32 opt32;
    } pe_opt;

    /**< PE data directory header. If ndatadirs is less than 16,
     * the unpopulated entries will be memset'd to zero.
     */
    struct pe_image_data_dir dirs[16];

    /***************** End PE-specific Section *****************/
};

/**
 * Initialize a struct cli_exe_info so that it's ready to be populated
 * by the EXE header parsing functions (cli_peheader, cli_elfheader, and
 * cli_machoheader) and/or cli_exe_info_destroy.
 *
 * @param exeinfo a pointer to the struct cli_exe_info to initialize
 * @param offset the file offset corresponding to the start of the
 *               executable that exeinfo stores information about
 */
void cli_exe_info_init(struct cli_exe_info *exeinfo, uint32_t offset);

/**
 * Free resources associated with a struct cli_exe_info initialized
 * via cli_exe_info_init
 *
 * @param exeinfo a pointer to the struct cli_exe_info to destroy
 */
void cli_exe_info_destroy(struct cli_exe_info *exeinfo);

#endif

/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *
 *  Authors: Tomasz Kojm
 * 
 *  Acknowledgements: The header structures were based upon "ELF: Executable 
 *                    and Linkable Format, Portable Formats Specification, 
 *                    Version 1.1".
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

#ifndef __ELF_H
#define __ELF_H

#include "clamav.h"
#include "execs.h"
#include "others.h"
#include "fmap.h"

/* ELF File Headers */
struct elf_file_hdr32 {
    uint8_t  e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    /* fields after here are NOT aligned the same as 64 */
    uint32_t e_entry;
    uint32_t e_phoff;
    uint32_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
};

struct elf_file_hdr64 {
    uint8_t  e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    /* fields after here are NOT aligned the same as 32 */
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
};

/* ELF File Header Helpers */
#define ELF_HDR_SIZEDIFF 12

/* This part is the same on both headers */
struct elf_file_hdr32plus {
    struct elf_file_hdr32 hdr;
    uint8_t pad[ELF_HDR_SIZEDIFF];
};

union elf_file_hdr {
    struct elf_file_hdr32plus hdr32;
    struct elf_file_hdr64 hdr64;
};

/* ELF Program Headers */
struct elf_program_hdr32 {
    uint32_t p_type;
    uint32_t p_offset;
    uint32_t p_vaddr;
    uint32_t p_paddr;
    uint32_t p_filesz;
    uint32_t p_memsz;
    uint32_t p_flags;
    uint32_t p_align;
};

struct elf_program_hdr64 {
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
};

/* ELF Section Headers */

/* Notable ELF section header flags */
#define ELF_SHF_WRITE (1 << 0)
#define ELF_SHF_ALLOC (1 << 1)
#define ELF_SHF_EXECINSTR  (1 << 2)

/* There are more section header flags, but these are the ones we log */
#define ELF_SHF_MASK (ELF_SHF_WRITE | ELF_SHF_ALLOC | ELF_SHF_EXECINSTR)

struct elf_section_hdr32 {
    uint32_t sh_name;
    uint32_t sh_type;
    uint32_t sh_flags;
    uint32_t sh_addr;
    uint32_t sh_offset;
    uint32_t sh_size;
    uint32_t sh_link;
    uint32_t sh_info;
    uint32_t sh_addralign;
    uint32_t sh_entsize;
};

struct elf_section_hdr64 {
    uint32_t sh_name;
    uint32_t sh_type;
    uint64_t sh_flags;
    uint64_t sh_addr;
    uint64_t sh_offset;
    uint64_t sh_size;
    uint32_t sh_link;
    uint32_t sh_info;
    uint64_t sh_addralign;
    uint64_t sh_entsize;
};

/* Exposed functions */

int cli_scanelf(cli_ctx *ctx);

int cli_elfheader(fmap_t *map, struct cli_exe_info *elfinfo);

#endif

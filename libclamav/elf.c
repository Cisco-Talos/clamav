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

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/stat.h>
#ifdef	HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <time.h>

#include "elf.h"
#include "clamav.h"
#include "execs.h"
#include "matcher.h"

#define EC16(v, conv)   (conv ? cbswap16(v) : v)
#define EC32(v, conv)   (conv ? cbswap32(v) : v)
#define EC64(v, conv)   (conv ? cbswap64(v) : v)

static void cli_elf_sectionlog(uint32_t sh_type, uint32_t sh_flags);

static uint32_t cli_rawaddr32(uint32_t vaddr, struct elf_program_hdr32 *ph, uint16_t phnum, uint8_t conv, uint8_t *err)
{
	uint16_t i, found = 0;

    for(i = 0; i < phnum; i++) {
	if(EC32(ph[i].p_vaddr, conv) <= vaddr && EC32(ph[i].p_vaddr, conv) + EC32(ph[i].p_memsz, conv) > vaddr) {
	    found = 1;
	    break;
	}
    }

    if(!found) {
	*err = 1;
	return 0;
    }

    *err = 0;
    return vaddr - EC32(ph[i].p_vaddr, conv) + EC32(ph[i].p_offset, conv);
}

static uint64_t cli_rawaddr64(uint64_t vaddr, struct elf_program_hdr64 *ph, uint16_t phnum, uint8_t conv, uint8_t *err)
{
	uint16_t i, found = 0;

    for(i = 0; i < phnum; i++) {
	if(EC64(ph[i].p_vaddr, conv) <= vaddr && EC64(ph[i].p_vaddr, conv) + EC64(ph[i].p_memsz, conv) > vaddr) {
	    found = 1;
	    break;
	}
    }

    if(!found) {
	*err = 1;
	return 0;
    }

    *err = 0;
    return vaddr - EC64(ph[i].p_vaddr, conv) + EC64(ph[i].p_offset, conv);
}

/* Return converted endian-fixed header, or error code */
static int cli_elf_fileheader(cli_ctx *ctx, fmap_t *map, union elf_file_hdr *file_hdr,
    uint8_t *do_convert, uint8_t *is64)
{
	uint8_t format64, conv;

    /* Load enough for smaller header first */
    if(fmap_readn(map, file_hdr, 0, sizeof(struct elf_file_hdr32)) != sizeof(struct elf_file_hdr32)) {
	/* Not an ELF file? */
	cli_dbgmsg("ELF: Can't read file header\n");
	return CL_BREAK;
    }

    if(memcmp(file_hdr->hdr64.e_ident, "\x7f\x45\x4c\x46", 4)) {
	cli_dbgmsg("ELF: Not an ELF file\n");
	return CL_BREAK;
    }

    switch(file_hdr->hdr64.e_ident[4]) {
	case 1:
	    cli_dbgmsg("ELF: ELF class 1 (32-bit)\n");
	    format64 = 0;
	    break;
        case 2:
	    cli_dbgmsg("ELF: ELF class 2 (64-bit)\n");
	    format64 = 1;
	    break;
        default:
	    cli_dbgmsg("ELF: Unknown ELF class (%u)\n", file_hdr->hdr64.e_ident[4]);
	    if (ctx)
	      cli_append_virus(ctx, "Heuristics.Broken.Executable");
	    return CL_VIRUS;
    }

    /* Need to know to endian convert */
    if(file_hdr->hdr64.e_ident[5] == 1) {
#if WORDS_BIGENDIAN == 0
	if(ctx)
            cli_dbgmsg("ELF: File is little-endian - conversion not required\n");
	conv = 0;
#else
	if(ctx)
            cli_dbgmsg("ELF: File is little-endian - data conversion enabled\n");
	conv = 1;
#endif
    } else {
#if WORDS_BIGENDIAN == 0
	if(ctx)
            cli_dbgmsg("ELF: File is big-endian - data conversion enabled\n");
	conv = 1;
#else
	if(ctx)
            cli_dbgmsg("ELF: File is big-endian - conversion not required\n");
	conv = 0;
#endif
    }

    *do_convert = conv;
    *is64 = format64;

    /* Solve bit-size and conversion pronto */
    file_hdr->hdr64.e_type = EC16(file_hdr->hdr64.e_type, conv);
    file_hdr->hdr64.e_machine = EC16(file_hdr->hdr64.e_machine, conv);
    file_hdr->hdr64.e_version = EC32(file_hdr->hdr64.e_version, conv);

    if(format64) {
	/* Read rest of 64-bit header */
	if(fmap_readn(map, file_hdr->hdr32.pad, sizeof(struct elf_file_hdr32), ELF_HDR_SIZEDIFF)
                != ELF_HDR_SIZEDIFF) {
	    /* Not an ELF file? */
	    cli_dbgmsg("ELF: Can't read file header\n");
	    return CL_BREAK;
	}
	/* Now endian convert, if needed */
	if(conv) {
	    file_hdr->hdr64.e_entry = EC64(file_hdr->hdr64.e_entry, conv);
            file_hdr->hdr64.e_phoff = EC64(file_hdr->hdr64.e_phoff, conv);
            file_hdr->hdr64.e_shoff = EC64(file_hdr->hdr64.e_shoff, conv);
	    file_hdr->hdr64.e_flags = EC32(file_hdr->hdr64.e_flags, conv);
	    file_hdr->hdr64.e_ehsize = EC16(file_hdr->hdr64.e_ehsize, conv);
	    file_hdr->hdr64.e_phentsize = EC16(file_hdr->hdr64.e_phentsize, conv);
	    file_hdr->hdr64.e_phnum = EC16(file_hdr->hdr64.e_phnum, conv);
	    file_hdr->hdr64.e_shentsize = EC16(file_hdr->hdr64.e_shentsize, conv);
	    file_hdr->hdr64.e_shnum = EC16(file_hdr->hdr64.e_shnum, conv);
	    file_hdr->hdr64.e_shstrndx = EC16(file_hdr->hdr64.e_shstrndx, conv);
	}
    }
    else {
	/* Convert 32-bit structure, if needed */
	if(conv) {
	    file_hdr->hdr32.hdr.e_entry = EC32(file_hdr->hdr32.hdr.e_entry, conv);
            file_hdr->hdr32.hdr.e_phoff = EC32(file_hdr->hdr32.hdr.e_phoff, conv);
            file_hdr->hdr32.hdr.e_shoff = EC32(file_hdr->hdr32.hdr.e_shoff, conv);
	    file_hdr->hdr32.hdr.e_flags = EC32(file_hdr->hdr32.hdr.e_flags, conv);
	    file_hdr->hdr32.hdr.e_ehsize = EC16(file_hdr->hdr32.hdr.e_ehsize, conv);
	    file_hdr->hdr32.hdr.e_phentsize = EC16(file_hdr->hdr32.hdr.e_phentsize, conv);
	    file_hdr->hdr32.hdr.e_phnum = EC16(file_hdr->hdr32.hdr.e_phnum, conv);
	    file_hdr->hdr32.hdr.e_shentsize = EC16(file_hdr->hdr32.hdr.e_shentsize, conv);
	    file_hdr->hdr32.hdr.e_shnum = EC16(file_hdr->hdr32.hdr.e_shnum, conv);
	    file_hdr->hdr32.hdr.e_shstrndx = EC16(file_hdr->hdr32.hdr.e_shstrndx, conv);
        }
        /* Wipe pad for safety */
        memset(file_hdr->hdr32.pad, 0, ELF_HDR_SIZEDIFF);
    }

    return CL_CLEAN;
}

/* Read 32-bit program headers */
static int cli_elf_ph32(cli_ctx *ctx, fmap_t *map, struct cli_exe_info *elfinfo,
    struct elf_file_hdr32 *file_hdr, uint8_t conv)
{
	struct elf_program_hdr32 *program_hdr = NULL;
	uint16_t phnum, phentsize;
	uint32_t entry, fentry = 0, phoff;
	uint32_t i;
	uint8_t err;

    /* Program headers and Entry */
    phnum = file_hdr->e_phnum;
    cli_dbgmsg("ELF: Number of program headers: %d\n", phnum);
    if(phnum > 128) {
        cli_dbgmsg("ELF: Suspicious number of program headers\n");
        if(ctx && SCAN_HEURISTIC_BROKEN) {
            cli_append_virus(ctx, "Heuristics.Broken.Executable");
            return CL_VIRUS;
        }
        return CL_EFORMAT;
    }
    entry = file_hdr->e_entry;

    if(phnum && entry) {
        phentsize = file_hdr->e_phentsize;
        /* Sanity check */
        if(phentsize != sizeof(struct elf_program_hdr32)) {
            cli_dbgmsg("ELF: phentsize != sizeof(struct elf_program_hdr32)\n");
            if(ctx && SCAN_HEURISTIC_BROKEN) {
                cli_append_virus(ctx, "Heuristics.Broken.Executable");
                return CL_VIRUS;
            }
            return CL_EFORMAT;
        }

        phoff = file_hdr->e_phoff;
        if(ctx) {
            cli_dbgmsg("ELF: Program header table offset: %u\n", phoff);
        }

        if(phnum) {
            program_hdr = (struct elf_program_hdr32 *) cli_calloc(phnum, sizeof(struct elf_program_hdr32));
            if(!program_hdr) {
                cli_errmsg("ELF: Can't allocate memory for program headers\n");
                return CL_EMEM;
            }
            if(ctx) {
                cli_dbgmsg("------------------------------------\n");
            }
        }

        for(i = 0; i < phnum; i++) {
            err = 0;
            if(fmap_readn(map, &program_hdr[i], phoff, sizeof(struct elf_program_hdr32)) != sizeof(struct elf_program_hdr32))
                err = 1;
            phoff += sizeof(struct elf_program_hdr32);

            if(err) {
                cli_dbgmsg("ELF: Can't read segment #%d\n", i);
                if(ctx) {
                    cli_dbgmsg("ELF: Possibly broken ELF file\n");
                }
                free(program_hdr);
                if(ctx && SCAN_HEURISTIC_BROKEN) {
                    cli_append_virus(ctx, "Heuristics.Broken.Executable");
                    return CL_VIRUS;
                }
                return CL_BREAK;
            }

            if(ctx) {
                cli_dbgmsg("ELF: Segment #%d\n", i);
                cli_dbgmsg("ELF: Segment type: 0x%x\n", EC32(program_hdr[i].p_type, conv));
                cli_dbgmsg("ELF: Segment offset: 0x%x\n", EC32(program_hdr[i].p_offset, conv));
                cli_dbgmsg("ELF: Segment virtual address: 0x%x\n", EC32(program_hdr[i].p_vaddr, conv));
                cli_dbgmsg("ELF: Segment real size: 0x%x\n", EC32(program_hdr[i].p_filesz, conv));
                cli_dbgmsg("ELF: Segment virtual size: 0x%x\n", EC32(program_hdr[i].p_memsz, conv));
                cli_dbgmsg("------------------------------------\n");
            }
        }

        fentry = cli_rawaddr32(entry, program_hdr, phnum, conv, &err);
        free(program_hdr);
        if(err) {
            cli_dbgmsg("ELF: Can't calculate file offset of entry point\n");
            if(ctx && SCAN_HEURISTIC_BROKEN) {
                cli_append_virus(ctx, "Heuristics.Broken.Executable");
                return CL_VIRUS;
            }
            return CL_EFORMAT;
        }
        if(ctx) {
            cli_dbgmsg("ELF: Entry point address: 0x%.8x\n", entry);
            cli_dbgmsg("ELF: Entry point offset: 0x%.8x (%d)\n", fentry, fentry);
        }
    }

    if(elfinfo) {
        elfinfo->ep = fentry;
    }

    return CL_CLEAN;
}

/* Read 64-bit program headers */
static int cli_elf_ph64(cli_ctx *ctx, fmap_t *map, struct cli_exe_info *elfinfo,
    struct elf_file_hdr64 *file_hdr, uint8_t conv)
{
	struct elf_program_hdr64 *program_hdr = NULL;
	uint16_t phnum, phentsize;
	uint64_t entry, fentry = 0, phoff;
	uint32_t i;
	uint8_t err;

    /* Program headers and Entry */
    phnum = file_hdr->e_phnum;
    cli_dbgmsg("ELF: Number of program headers: %d\n", phnum);
    if(phnum > 128) {
        cli_dbgmsg("ELF: Suspicious number of program headers\n");
        if(ctx && SCAN_HEURISTIC_BROKEN) {
            cli_append_virus(ctx, "Heuristics.Broken.Executable");
            return CL_VIRUS;
        }
        return CL_EFORMAT;
    }
    entry = file_hdr->e_entry;

    if(phnum && entry) {
        phentsize = file_hdr->e_phentsize;
        /* Sanity check */
        if (phentsize != sizeof(struct elf_program_hdr64)) {
            cli_dbgmsg("ELF: phentsize != sizeof(struct elf_program_hdr64)\n");
            if(ctx && SCAN_HEURISTIC_BROKEN) {
                cli_append_virus(ctx, "Heuristics.Broken.Executable");
                return CL_VIRUS;
            }
            return CL_EFORMAT;
        }

        phoff = file_hdr->e_phoff;
        if(ctx) {
            cli_dbgmsg("ELF: Program header table offset: " STDu64 "\n", phoff);
        }

        if(phnum) {
            program_hdr = (struct elf_program_hdr64 *) cli_calloc(phnum, sizeof(struct elf_program_hdr64));
            if(!program_hdr) {
                cli_errmsg("ELF: Can't allocate memory for program headers\n");
                return CL_EMEM;
            }
            if(ctx) {
                cli_dbgmsg("------------------------------------\n");
            }
        }

        for(i = 0; i < phnum; i++) {
            err = 0;
            if(fmap_readn(map, &program_hdr[i], phoff, sizeof(struct elf_program_hdr64)) != sizeof(struct elf_program_hdr64))
                err = 1;
            phoff += sizeof(struct elf_program_hdr64);

            if(err) {
                cli_dbgmsg("ELF: Can't read segment #%d\n", i);
                if(ctx) {
                    cli_dbgmsg("ELF: Possibly broken ELF file\n");
                }
                free(program_hdr);
                if(ctx && SCAN_HEURISTIC_BROKEN) {
                    cli_append_virus(ctx, "Heuristics.Broken.Executable");
                    return CL_VIRUS;
                }
                return CL_BREAK;
            }

            if(ctx) {
                cli_dbgmsg("ELF: Segment #%d\n", i);
                cli_dbgmsg("ELF: Segment type: 0x" STDx32 "\n", (uint32_t) EC32(program_hdr[i].p_type, conv));
                cli_dbgmsg("ELF: Segment offset: 0x" STDx64 "\n", (uint64_t) EC64(program_hdr[i].p_offset, conv));
                cli_dbgmsg("ELF: Segment virtual address: 0x" STDx64 "\n", (uint64_t) EC64(program_hdr[i].p_vaddr, conv));
                cli_dbgmsg("ELF: Segment real size: 0x" STDx64 "\n", (uint64_t) EC64(program_hdr[i].p_filesz, conv));
                cli_dbgmsg("ELF: Segment virtual size: 0x" STDx64 "\n", (uint64_t) EC64(program_hdr[i].p_memsz, conv));
                cli_dbgmsg("------------------------------------\n");
            }
        }

        fentry = cli_rawaddr64(entry, program_hdr, phnum, conv, &err);
        free(program_hdr);
        if(err) {
            cli_dbgmsg("ELF: Can't calculate file offset of entry point\n");
            if(ctx && SCAN_HEURISTIC_BROKEN) {
                cli_append_virus(ctx, "Heuristics.Broken.Executable");
                return CL_VIRUS;
            }
            return CL_EFORMAT;
        }
        if(ctx) {
            cli_dbgmsg("ELF: Entry point address: 0x%.16" PRIx64 "\n", entry);
            cli_dbgmsg("ELF: Entry point offset: 0x%.16" PRIx64 " (" STDi64 ")\n", fentry, fentry);
        }
    }

    if(elfinfo) {
        elfinfo->ep = fentry;
    }

    return CL_CLEAN;
}

/* 32-bit version of section header parsing */
static int cli_elf_sh32(cli_ctx *ctx, fmap_t *map, struct cli_exe_info *elfinfo,
    struct elf_file_hdr32 *file_hdr, uint8_t conv)
{
	struct elf_section_hdr32 *section_hdr = NULL;
	uint16_t shnum, shentsize;
	uint32_t shoff, i;

    shnum = file_hdr->e_shnum;
    cli_dbgmsg("ELF: Number of sections: %d\n", shnum);
    if(ctx && (shnum > 2048)) {
	cli_dbgmsg("ELF: Number of sections > 2048, skipping\n");
	return CL_BREAK;
    }
    else if(elfinfo && (shnum > 256)) {
	cli_dbgmsg("ELF: Suspicious number of sections\n");
	return CL_BREAK;
    }
    if(elfinfo) {
        elfinfo->nsections = shnum;
    }

    shentsize = file_hdr->e_shentsize;
    /* Sanity check */
    if(shentsize != sizeof(struct elf_section_hdr32)) {
	cli_dbgmsg("ELF: shentsize != sizeof(struct elf_section_hdr32)\n");
        if(ctx && SCAN_HEURISTIC_BROKEN) {
	    cli_append_virus(ctx, "Heuristics.Broken.Executable");
	    return CL_VIRUS;
        }
	return CL_EFORMAT;
    }

    if(elfinfo && !shnum) {
        return CL_CLEAN;
    }

    shoff = file_hdr->e_shoff;
    if(ctx)
        cli_dbgmsg("ELF: Section header table offset: %d\n", shoff);

    if(elfinfo) {
        elfinfo->section = (struct cli_exe_section *)cli_calloc(shnum, sizeof(struct cli_exe_section));
        if(!elfinfo->section) {
            cli_dbgmsg("ELF: Can't allocate memory for section headers\n");
            return CL_EMEM;
        }
    }

    if(shnum) {
	section_hdr = (struct elf_section_hdr32 *) cli_calloc(shnum, shentsize);
	if(!section_hdr) {
	    cli_errmsg("ELF: Can't allocate memory for section headers\n");
	    if(elfinfo) {
                free(elfinfo->section);
                elfinfo->section = NULL;
	    }
	    return CL_EMEM;
	}
	if(ctx) {
            cli_dbgmsg("------------------------------------\n");
	}
    }

    /* Loop over section headers */
    for(i = 0; i < shnum; i++) {
        uint32_t sh_type, sh_flags;

	if(fmap_readn(map, &section_hdr[i], shoff, sizeof(struct elf_section_hdr32)) != sizeof(struct elf_section_hdr32)) {
            cli_dbgmsg("ELF: Can't read section header\n");
            if(ctx) {
                cli_dbgmsg("ELF: Possibly broken ELF file\n");
            }
            free(section_hdr);
            if(elfinfo) {
                free(elfinfo->section);
                elfinfo->section = NULL;
	    }
            if(ctx && SCAN_HEURISTIC_BROKEN) {
                cli_append_virus(ctx, "Heuristics.Broken.Executable");
		return CL_VIRUS;
            }
            return CL_BREAK;
        }

	shoff += sizeof(struct elf_section_hdr32);

        if(elfinfo) {
            elfinfo->section[i].rva = EC32(section_hdr[i].sh_addr, conv);
            elfinfo->section[i].raw = EC32(section_hdr[i].sh_offset, conv);
            elfinfo->section[i].rsz = EC32(section_hdr[i].sh_size, conv);
        }
        if(ctx) {
	    cli_dbgmsg("ELF: Section %u\n", i);
	    cli_dbgmsg("ELF: Section offset: %u\n", EC32(section_hdr[i].sh_offset, conv));
	    cli_dbgmsg("ELF: Section size: %u\n", EC32(section_hdr[i].sh_size, conv));

            sh_type = EC32(section_hdr[i].sh_type, conv);
            sh_flags = EC32(section_hdr[i].sh_flags, conv) & ELF_SHF_MASK;
            cli_elf_sectionlog(sh_type, sh_flags);

	    cli_dbgmsg("------------------------------------\n");
        }
    }

    free(section_hdr);
    return CL_CLEAN;
}

/* 64-bit version of section header parsing */
static int cli_elf_sh64(cli_ctx *ctx, fmap_t *map, struct cli_exe_info *elfinfo,
    struct elf_file_hdr64 *file_hdr, uint8_t conv)
{
	struct elf_section_hdr64 *section_hdr = NULL;
	uint16_t shnum, shentsize;
	uint32_t i;
	uint64_t shoff;

    shnum = file_hdr->e_shnum;
    cli_dbgmsg("ELF: Number of sections: %d\n", shnum);
    if(ctx && (shnum > 2048)) {
	cli_dbgmsg("ELF: Number of sections > 2048, skipping\n");
	return CL_BREAK;
    }
    else if(elfinfo && (shnum > 256)) {
	cli_dbgmsg("ELF: Suspicious number of sections\n");
	return CL_BREAK;
    }
    if(elfinfo) {
        elfinfo->nsections = shnum;
    }

    shentsize = file_hdr->e_shentsize;
    /* Sanity check */
    if(shentsize != sizeof(struct elf_section_hdr64)) {
	cli_dbgmsg("ELF: shentsize != sizeof(struct elf_section_hdr64)\n");
        if(ctx && SCAN_HEURISTIC_BROKEN) {
	    cli_append_virus(ctx, "Heuristics.Broken.Executable");
	    return CL_VIRUS;
        }
	return CL_EFORMAT;
    }

    if(elfinfo && !shnum) {
        return CL_CLEAN;
    }

    shoff = file_hdr->e_shoff;
    if(ctx)
        cli_dbgmsg("ELF: Section header table offset: " STDu64 "\n", shoff);

    if(elfinfo) {
        elfinfo->section = (struct cli_exe_section *)cli_calloc(shnum, sizeof(struct cli_exe_section));
        if(!elfinfo->section) {
            cli_dbgmsg("ELF: Can't allocate memory for section headers\n");
            return CL_EMEM;
        }
    }

    if(shnum) {
	section_hdr = (struct elf_section_hdr64 *) cli_calloc(shnum, shentsize);
	if(!section_hdr) {
	    cli_errmsg("ELF: Can't allocate memory for section headers\n");
	    if(elfinfo) {
                free(elfinfo->section);
                elfinfo->section = NULL;
	    }
	    return CL_EMEM;
	}
	if(ctx) {
            cli_dbgmsg("------------------------------------\n");
	}
    }

    /* Loop over section headers */
    for(i = 0; i < shnum; i++) {
        uint32_t sh_type, sh_flags;

	if(fmap_readn(map, &section_hdr[i], shoff, sizeof(struct elf_section_hdr64)) != sizeof(struct elf_section_hdr64)) {
            cli_dbgmsg("ELF: Can't read section header\n");
            if(ctx) {
                cli_dbgmsg("ELF: Possibly broken ELF file\n");
            }
            free(section_hdr);
            if(elfinfo) {
                free(elfinfo->section);
                elfinfo->section = NULL;
	    }
            if(ctx && SCAN_HEURISTIC_BROKEN) {
                cli_append_virus(ctx, "Heuristics.Broken.Executable");
		return CL_VIRUS;
            }
            return CL_BREAK;
        }

	shoff += sizeof(struct elf_section_hdr64);

        if(elfinfo) {
            elfinfo->section[i].rva = EC64(section_hdr[i].sh_addr, conv);
            elfinfo->section[i].raw = EC64(section_hdr[i].sh_offset, conv);
            elfinfo->section[i].rsz = EC64(section_hdr[i].sh_size, conv);
        }
        if(ctx) {
	    cli_dbgmsg("ELF: Section " STDu32 "\n", (uint32_t) i);
	    cli_dbgmsg("ELF: Section offset: " STDu64 "\n", (uint64_t) EC64(section_hdr[i].sh_offset, conv));
	    cli_dbgmsg("ELF: Section size: " STDu64 "\n", (uint64_t) EC64(section_hdr[i].sh_size, conv));

            sh_type = EC32(section_hdr[i].sh_type, conv);
            sh_flags = (uint32_t)(EC64(section_hdr[i].sh_flags, conv) & ELF_SHF_MASK);
            cli_elf_sectionlog(sh_type, sh_flags);

	    cli_dbgmsg("------------------------------------\n");
        }
    }

    free(section_hdr);
    return CL_CLEAN;
}

/* Print section type and selected flags to the log */
static void cli_elf_sectionlog(uint32_t sh_type, uint32_t sh_flags)
{
    switch(sh_type) {
        case 0x6: /* SHT_DYNAMIC */
            cli_dbgmsg("ELF: Section type: Dynamic linking information\n");
            break;
        case 0xb: /* SHT_DYNSYM */
            cli_dbgmsg("ELF: Section type: Symbols for dynamic linking\n");
            break;
        case 0xf: /* SHT_FINI_ARRAY */
            cli_dbgmsg("ELF: Section type: Array of pointers to termination functions\n");
            break;
        case 0x5: /* SHT_HASH */
            cli_dbgmsg("ELF: Section type: Symbol hash table\n");
            break;
        case 0xe: /* SHT_INIT_ARRAY */
            cli_dbgmsg("ELF: Section type: Array of pointers to initialization functions\n");
            break;
        case 0x8: /* SHT_NOBITS */
            cli_dbgmsg("ELF: Section type: Empty section (NOBITS)\n");
            break;
        case 0x7: /* SHT_NOTE */
            cli_dbgmsg("ELF: Section type: Note section\n");
            break;
        case 0x0: /* SHT_NULL */
            cli_dbgmsg("ELF: Section type: Null (no associated section)\n");
            break;
        case 0x10: /* SHT_PREINIT_ARRAY */
            cli_dbgmsg("ELF: Section type: Array of pointers to preinit functions\n");
            break;
        case 0x1: /* SHT_PROGBITS */
            cli_dbgmsg("ELF: Section type: Program information\n");
            break;
        case 0x9: /* SHT_REL */
            cli_dbgmsg("ELF: Section type: Relocation entries w/o explicit addends\n");
            break;
        case 0x4: /* SHT_RELA */
            cli_dbgmsg("ELF: Section type: Relocation entries with explicit addends\n");
            break;
        case 0x3: /* SHT_STRTAB */
            cli_dbgmsg("ELF: Section type: String table\n");
            break;
        case 0x2: /* SHT_SYMTAB */
            cli_dbgmsg("ELF: Section type: Symbol table\n");
            break;
        case 0x6ffffffd: /* SHT_GNU_verdef */
            cli_dbgmsg("ELF: Section type: Provided symbol versions\n");
            break;
        case 0x6ffffffe: /* SHT_GNU_verneed */
            cli_dbgmsg("ELF: Section type: Required symbol versions\n");
            break;
        case 0x6fffffff: /* SHT_GNU_versym */
            cli_dbgmsg("ELF: Section type: Symbol Version Table\n");
            break;
        default :
            cli_dbgmsg("ELF: Section type: Unknown\n");
    }

    if(sh_flags & ELF_SHF_WRITE)
        cli_dbgmsg("ELF: Section contains writable data\n");

    if(sh_flags & ELF_SHF_ALLOC)
        cli_dbgmsg("ELF: Section occupies memory\n");

    if(sh_flags & ELF_SHF_EXECINSTR)
        cli_dbgmsg("ELF: Section contains executable code\n");
}

/* Scan function for ELF */
int cli_scanelf(cli_ctx *ctx)
{
	union elf_file_hdr file_hdr;
	fmap_t *map = *ctx->fmap;
	int ret;
	uint8_t conv = 0, is64 = 0;

    cli_dbgmsg("in cli_scanelf\n");

    /* Load header to determine size and class */
    ret = cli_elf_fileheader(ctx, map, &file_hdr, &conv, &is64);
    if(ret == CL_BREAK) {
	return CL_CLEAN; /* here, break means "exit but report clean" */
    }
    else if(ret != CL_CLEAN) {
	return ret;
    }

    /* Log File type and machine type */
    switch(file_hdr.hdr64.e_type) {
	case 0x0: /* ET_NONE */
	    cli_dbgmsg("ELF: File type: None\n");
	    break;
	case 0x1: /* ET_REL */
	    cli_dbgmsg("ELF: File type: Relocatable\n");
	    break;
	case 0x2: /* ET_EXEC */
	    cli_dbgmsg("ELF: File type: Executable\n");
	    break;
	case 0x3: /* ET_DYN */
	    cli_dbgmsg("ELF: File type: Core\n");
	    break;
	case 0x4: /* ET_CORE */
	    cli_dbgmsg("ELF: File type: Core\n");
	    break;
	default:
	    cli_dbgmsg("ELF: File type: Unknown (%d)\n", file_hdr.hdr64.e_type);
    }

    switch(file_hdr.hdr64.e_machine) {
	/* Due to a huge list, we only include the most popular machines here */
	case 0: /* EM_NONE */
	    cli_dbgmsg("ELF: Machine type: None\n");
	    break;
	case 2: /* EM_SPARC */
	    cli_dbgmsg("ELF: Machine type: SPARC\n");
	    break;
	case 3: /* EM_386 */
	    cli_dbgmsg("ELF: Machine type: Intel 80386\n");
	    break;
	case 4: /* EM_68K */
	    cli_dbgmsg("ELF: Machine type: Motorola 68000\n");
	    break;
	case 8: /* EM_MIPS */
	    cli_dbgmsg("ELF: Machine type: MIPS RS3000\n");
	    break;
	case 9: /* EM_S370 */
	    cli_dbgmsg("ELF: Machine type: IBM System/370\n");
	    break;
	case 15: /* EM_PARISC */
	    cli_dbgmsg("ELF: Machine type: HPPA\n");
	    break;
	case 20: /* EM_PPC */
	    cli_dbgmsg("ELF: Machine type: PowerPC\n");
	    break;
	case 21: /* EM_PPC64 */
	    cli_dbgmsg("ELF: Machine type: PowerPC 64-bit\n");
	    break;
	case 22: /* EM_S390 */
	    cli_dbgmsg("ELF: Machine type: IBM S390\n");
	    break;
	case 40: /* EM_ARM */
	    cli_dbgmsg("ELF: Machine type: ARM\n");
	    break;
	case 41: /* EM_FAKE_ALPHA */
	    cli_dbgmsg("ELF: Machine type: Digital Alpha\n");
	    break;
	case 43: /* EM_SPARCV9 */
	    cli_dbgmsg("ELF: Machine type: SPARC v9 64-bit\n");
	    break;
	case 50: /* EM_IA_64 */
	    cli_dbgmsg("ELF: Machine type: IA64\n");
	    break;
	case 62: /* EM_X86_64 */
	    cli_dbgmsg("ELF: Machine type: AMD x86-64\n");
	    break;
	default:
	    cli_dbgmsg("ELF: Machine type: Unknown (0x%x)\n", file_hdr.hdr64.e_machine);
    }

    /* Program headers and Entry */
    if(is64) {
        ret = cli_elf_ph64(ctx, map, NULL, &(file_hdr.hdr64), conv);
    }
    else {
        ret = cli_elf_ph32(ctx, map, NULL, &(file_hdr.hdr32.hdr), conv);
    }
    if(ret == CL_BREAK) {
	return CL_CLEAN; /* break means "exit but report clean" */
    }
    else if(ret != CL_CLEAN) {
	return ret;
    }

    /* Sections */
    if(is64) {
        ret = cli_elf_sh64(ctx, map, NULL, &(file_hdr.hdr64), conv);
    }
    else {
        ret = cli_elf_sh32(ctx, map, NULL, &(file_hdr.hdr32.hdr), conv);
    }
    if(ret == CL_BREAK) {
	return CL_CLEAN; /* break means "exit but report clean" */
    }
    else if(ret != CL_CLEAN) {
	return ret;
    }

    return CL_CLEAN;
}

/* ELF header parsing only
 * Returns 0 on success, -1 on error
 */
int cli_elfheader(fmap_t *map, struct cli_exe_info *elfinfo)
{
	union elf_file_hdr file_hdr;
	uint8_t conv = 0, is64 = 0;
    int ret;

    cli_dbgmsg("in cli_elfheader\n");

    ret = cli_elf_fileheader(NULL, map, &file_hdr, &conv, &is64);
    if(ret != CL_CLEAN) {
	return -1;
    }

    /* Program headers and Entry */
    if(is64) {
        ret = cli_elf_ph64(NULL, map, elfinfo, &(file_hdr.hdr64), conv);
    }
    else {
        ret = cli_elf_ph32(NULL, map, elfinfo, &(file_hdr.hdr32.hdr), conv);
    }
    if(ret != CL_CLEAN) {
	return -1;
    }

    /* Section Headers */
    if(is64) {
        ret = cli_elf_sh64(NULL, map, elfinfo, &(file_hdr.hdr64), conv);
    }
    else {
        ret = cli_elf_sh32(NULL, map, elfinfo, &(file_hdr.hdr32.hdr), conv);
    }
    if(ret != CL_CLEAN) {
	return -1;
    }

    return 0;
}

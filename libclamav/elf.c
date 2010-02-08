/*
 *  Copyright (C) 2007-2009 Sourcefire, Inc.
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

#include "cltypes.h"
#include "elf.h"
#include "clamav.h"
#include "execs.h"
#include "matcher.h"

#define EC16(v, conv)   (conv ? cbswap16(v) : v)
#define EC32(v, conv)   (conv ? cbswap32(v) : v)

static uint32_t cli_rawaddr(uint32_t vaddr, struct elf_program_hdr32 *ph, uint16_t phnum, uint8_t conv, uint8_t *err)
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

int cli_scanelf(cli_ctx *ctx)
{
	struct elf_file_hdr32 file_hdr;
	struct elf_section_hdr32 *section_hdr;
	struct elf_program_hdr32 *program_hdr;
	uint16_t shnum, phnum, shentsize, phentsize;
	uint32_t entry, fentry, shoff, phoff, i;
	uint8_t conv = 0, err;
	unsigned int format;
	fmap_t *map = *ctx->fmap;


    cli_dbgmsg("in cli_scanelf\n");

    if(fmap_readn(map, &file_hdr, 0, sizeof(file_hdr)) != sizeof(file_hdr)) {
	/* Not an ELF file? */
	cli_dbgmsg("ELF: Can't read file header\n");
	return CL_CLEAN;
    }

    if(memcmp(file_hdr.e_ident, "\x7f\x45\x4c\x46", 4)) {
	cli_dbgmsg("ELF: Not an ELF file\n");
	return CL_CLEAN;
    }

    format = file_hdr.e_ident[4];
    if(format != 1 && format != 2) {
	cli_dbgmsg("ELF: Unknown ELF class (%u)\n", file_hdr.e_ident[4]);
	return CL_EFORMAT;
    }

    if(format == 2) {
	    struct elf_file_hdr64 file_hdr64;
	if(fmap_readn(map, &file_hdr64, 0, sizeof(file_hdr64)) != sizeof(file_hdr64)) {
	    /* Not an ELF file? */
	    cli_dbgmsg("ELF: Can't read file header\n");
	    return CL_CLEAN;
	}
	/* it's enough for us to handle ELF64 as 32 */
	file_hdr.e_entry = file_hdr64.e_entry;
        file_hdr.e_phoff = file_hdr64.e_phoff;
        file_hdr.e_shoff = file_hdr64.e_shoff;
	file_hdr.e_flags = file_hdr64.e_flags;
	file_hdr.e_ehsize = file_hdr64.e_ehsize;
	file_hdr.e_phentsize = file_hdr64.e_phentsize;
	if(file_hdr.e_phentsize == sizeof(struct elf_program_hdr64))
	    file_hdr.e_phentsize = sizeof(struct elf_program_hdr32);
	file_hdr.e_phnum = file_hdr64.e_phnum;
	file_hdr.e_shentsize = file_hdr64.e_shentsize;
	if(file_hdr.e_shentsize == sizeof(struct elf_section_hdr64))
	    file_hdr.e_shentsize = sizeof(struct elf_section_hdr32);
	file_hdr.e_shnum = file_hdr64.e_shnum;
	file_hdr.e_shstrndx = file_hdr64.e_shstrndx;
    }

    if(file_hdr.e_ident[5] == 1) {
#if WORDS_BIGENDIAN == 0
	cli_dbgmsg("ELF: File is little-endian - conversion not required\n");
#else
	cli_dbgmsg("ELF: File is little-endian - data conversion enabled\n");
	conv = 1;
#endif
    } else {
#if WORDS_BIGENDIAN == 0
	cli_dbgmsg("ELF: File is big-endian - data conversion enabled\n");
	conv = 1;
#else
	cli_dbgmsg("ELF: File is big-endian - conversion not required\n");
#endif
    }

    switch(EC16(file_hdr.e_type, conv)) {
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
	    cli_dbgmsg("ELF: File type: Unknown (%d)\n", EC16(file_hdr.e_type, conv));
    }

    switch(EC16(file_hdr.e_machine, conv)) {
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
	    cli_dbgmsg("ELF: Machine type: Unknown (0x%x)\n", EC16(file_hdr.e_machine, conv));
    }

    entry = EC32(file_hdr.e_entry, conv);

    /* Program headers */

    phnum = EC16(file_hdr.e_phnum, conv);
    cli_dbgmsg("ELF: Number of program headers: %d\n", phnum);
    if(phnum > 128) {
	cli_dbgmsg("ELF: Suspicious number of program headers\n");
        if(DETECT_BROKEN) {
	    if(ctx->virname)
		*ctx->virname = "Heuristics.Broken.Executable";
	    return CL_VIRUS;
        }
	return CL_EFORMAT;
    }

    if(phnum && entry) {

	phentsize = EC16(file_hdr.e_phentsize, conv);
	if(phentsize != sizeof(struct elf_program_hdr32)) {
	    cli_dbgmsg("ELF: phentsize != sizeof(struct elf_program_hdr32)\n");
	    if(DETECT_BROKEN) {
		if(ctx->virname)
		    *ctx->virname = "Heuristics.Broken.Executable";
		return CL_VIRUS;
	    }
	    return CL_EFORMAT;
	}

	phoff = EC32(file_hdr.e_phoff, conv);
	cli_dbgmsg("ELF: Program header table offset: %d\n", phoff);

	program_hdr = (struct elf_program_hdr32 *) cli_calloc(phnum, phentsize);
	if(!program_hdr) {
	    cli_errmsg("ELF: Can't allocate memory for program headers\n");
	    return CL_EMEM;
	}

	cli_dbgmsg("------------------------------------\n");

	for(i = 0; i < phnum; i++) {
	    err = 0;
	    if(format == 1) {
		if(fmap_readn(map, &program_hdr[i], phoff, sizeof(struct elf_program_hdr32)) != sizeof(struct elf_program_hdr32))
		    err = 1;
		phoff += sizeof(struct elf_program_hdr32);
	    } else {
		    struct elf_program_hdr64 program_hdr64;

		if(fmap_readn(map, &program_hdr64, phoff, sizeof(program_hdr64)) != sizeof(program_hdr64)) {
		    err = 1;
		} else {
		    program_hdr[i].p_type = program_hdr64.p_type;
		    program_hdr[i].p_offset = program_hdr64.p_offset;
		    program_hdr[i].p_vaddr = program_hdr64.p_vaddr;
		    program_hdr[i].p_paddr = program_hdr64.p_paddr;
		    program_hdr[i].p_filesz = program_hdr64.p_filesz;
		    program_hdr[i].p_memsz = program_hdr64.p_memsz;
		    program_hdr[i].p_flags = program_hdr64.p_flags;
		    program_hdr[i].p_align = program_hdr64.p_align;
		}
		phoff += sizeof(program_hdr64);
	    }

	    if(err) {
		cli_dbgmsg("ELF: Can't read segment #%d\n", i);
		cli_dbgmsg("ELF: Possibly broken ELF file\n");
		free(program_hdr);
		if(DETECT_BROKEN) {
		    if(ctx->virname)
			*ctx->virname = "Heuristics.Broken.Executable";
		    return CL_VIRUS;
		}
		return CL_CLEAN;
	    }

	    cli_dbgmsg("ELF: Segment #%d\n", i);
	    cli_dbgmsg("ELF: Segment type: 0x%x\n", EC32(program_hdr[i].p_type, conv));
	    cli_dbgmsg("ELF: Segment offset: 0x%x\n", EC32(program_hdr[i].p_offset, conv));
	    cli_dbgmsg("ELF: Segment virtual address: 0x%x\n", EC32(program_hdr[i].p_vaddr, conv));
	    cli_dbgmsg("ELF: Segment real size: 0x%x\n", EC32(program_hdr[i].p_filesz, conv));
	    cli_dbgmsg("ELF: Segment virtual size: 0x%x\n", EC32(program_hdr[i].p_memsz, conv));
	    cli_dbgmsg("------------------------------------\n");
	}

	fentry = cli_rawaddr(entry, program_hdr, phnum, conv, &err);
	free(program_hdr);
	if(err) {
	    cli_dbgmsg("ELF: Can't calculate file offset of entry point\n");
	    if(DETECT_BROKEN) {
		if(ctx->virname)
		    *ctx->virname = "Heuristics.Broken.Executable";
		return CL_VIRUS;
	    }
	    return CL_EFORMAT;
	}
	cli_dbgmsg("ELF: Entry point address: 0x%.8x\n", entry);
	cli_dbgmsg("ELF: Entry point offset: 0x%.8x (%d)\n", fentry, fentry);
    }

    /* Sections */

    shnum = EC16(file_hdr.e_shnum, conv);
    cli_dbgmsg("ELF: Number of sections: %d\n", shnum);
    if(shnum > 256) {
	cli_dbgmsg("ELF: Suspicious number of sections\n");
        if(DETECT_BROKEN) {
	    if(ctx->virname)
		*ctx->virname = "Heuristics.Broken.Executable";
	    return CL_VIRUS;
        }
	return CL_EFORMAT;
    }

    shentsize = EC16(file_hdr.e_shentsize, conv);
    if(shentsize != sizeof(struct elf_section_hdr32)) {
	cli_dbgmsg("ELF: shentsize != sizeof(struct elf_section_hdr32)\n");
        if(DETECT_BROKEN) {
	    if(ctx->virname)
		*ctx->virname = "Heuristics.Broken.Executable";
	    return CL_VIRUS;
        }
	return CL_EFORMAT;
    }

    shoff = EC32(file_hdr.e_shoff, conv);
    cli_dbgmsg("ELF: Section header table offset: %d\n", shoff);

    section_hdr = (struct elf_section_hdr32 *) cli_calloc(shnum, shentsize);
    if(!section_hdr) {
	cli_errmsg("ELF: Can't allocate memory for section headers\n");
	return CL_EMEM;
    }

    cli_dbgmsg("------------------------------------\n");

    for(i = 0; i < shnum; i++) {
	err = 0;
	if(format == 1) {
	    if(fmap_readn(map, &section_hdr[i], shoff, sizeof(struct elf_section_hdr32)) != sizeof(struct elf_section_hdr32))
		err = 1;
	    shoff += sizeof(struct elf_section_hdr32);
	} else {
		struct elf_section_hdr64 section_hdr64;

	    if(fmap_readn(map, &section_hdr64, shoff, sizeof(section_hdr64)) != sizeof(section_hdr64)) {
		err = 1;
	    } else {
		section_hdr[i].sh_name = section_hdr64.sh_name;
		section_hdr[i].sh_type = section_hdr64.sh_type;
		section_hdr[i].sh_flags = section_hdr64.sh_flags;
		section_hdr[i].sh_addr = section_hdr64.sh_addr;
		section_hdr[i].sh_offset = section_hdr64.sh_offset;
		section_hdr[i].sh_size = section_hdr64.sh_size;
		section_hdr[i].sh_link = section_hdr64.sh_link;
		section_hdr[i].sh_info = section_hdr64.sh_info;
		section_hdr[i].sh_addralign = section_hdr64.sh_addralign;
		section_hdr[i].sh_entsize = section_hdr64.sh_entsize;
	    }
	    shoff += sizeof(section_hdr64);
	}

	if(err) {
            cli_dbgmsg("ELF: Can't read section header\n");
            cli_dbgmsg("ELF: Possibly broken ELF file\n");
            free(section_hdr);
            if(DETECT_BROKEN) {
                if(ctx->virname)
                    *ctx->virname = "Heuristics.Broken.Executable";
		return CL_VIRUS;
            }
            return CL_CLEAN;
        }

	cli_dbgmsg("ELF: Section %d\n", i);
	cli_dbgmsg("ELF: Section offset: %d\n", EC32(section_hdr[i].sh_offset, conv));
	cli_dbgmsg("ELF: Section size: %d\n", EC32(section_hdr[i].sh_size, conv));

	switch(EC32(section_hdr[i].sh_type, conv)) {
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

	if(EC32(section_hdr[i].sh_flags, conv) & 0x1) /* SHF_WRITE */
	    cli_dbgmsg("ELF: Section contains writable data\n");

	if(EC32(section_hdr[i].sh_flags, conv) & 0x2) /* SHF_ALLOC */
	    cli_dbgmsg("ELF: Section occupies memory\n");

	if(EC32(section_hdr[i].sh_flags, conv) & 0x4) /* SHF_EXECINSTR */
	    cli_dbgmsg("ELF: Section contains executable code\n");

	cli_dbgmsg("------------------------------------\n");
    }

    free(section_hdr);
    return CL_CLEAN;
}

int cli_elfheader(fmap_t *map, struct cli_exe_info *elfinfo)
{
	struct elf_file_hdr32 file_hdr;
	struct elf_section_hdr32 *section_hdr;
	struct elf_program_hdr32 *program_hdr;
	uint16_t shnum, phnum, shentsize, phentsize, i;
	uint32_t entry, fentry = 0, shoff, phoff;
	uint8_t conv = 0, err;
	unsigned int format;

    cli_dbgmsg("in cli_elfheader\n");

    if(fmap_readn(map, &file_hdr, 0, sizeof(file_hdr)) != sizeof(file_hdr)) {
	/* Not an ELF file? */
	cli_dbgmsg("ELF: Can't read file header\n");
	return -1;
    }

    if(memcmp(file_hdr.e_ident, "\x7f\x45\x4c\x46", 4)) {
	cli_dbgmsg("ELF: Not an ELF file\n");
	return -1;
    }

    format = file_hdr.e_ident[4];
    if(format != 1 && format != 2) {
	cli_dbgmsg("ELF: Unknown ELF class (%u)\n", file_hdr.e_ident[4]);
	return -1;
    }

    if(format == 2) {
	    struct elf_file_hdr64 file_hdr64;
	if(!fmap_readn(map, &file_hdr64, 0, sizeof(file_hdr64)) != sizeof(file_hdr64)) {
	    /* Not an ELF file? */
	    cli_dbgmsg("ELF: Can't read file header\n");
	    return -1; 
	}
	/* it's enough for us to handle ELF64 as 32 */
	file_hdr.e_entry = file_hdr64.e_entry;
        file_hdr.e_phoff = file_hdr64.e_phoff;
        file_hdr.e_shoff = file_hdr64.e_shoff;
	file_hdr.e_flags = file_hdr64.e_flags;
	file_hdr.e_ehsize = file_hdr64.e_ehsize;
	file_hdr.e_phentsize = file_hdr64.e_phentsize;
	if(file_hdr.e_phentsize == sizeof(struct elf_program_hdr64))
	    file_hdr.e_phentsize = sizeof(struct elf_program_hdr32);
	file_hdr.e_phnum = file_hdr64.e_phnum;
	file_hdr.e_shentsize = file_hdr64.e_shentsize;
	if(file_hdr.e_shentsize == sizeof(struct elf_section_hdr64))
	    file_hdr.e_shentsize = sizeof(struct elf_section_hdr32);
	file_hdr.e_shnum = file_hdr64.e_shnum;
	file_hdr.e_shstrndx = file_hdr64.e_shstrndx;
    }

    if(file_hdr.e_ident[5] == 1) {
#if WORDS_BIGENDIAN == 1
	conv = 1;
#endif
    } else {
#if WORDS_BIGENDIAN == 0
	conv = 1;
#endif
    }

    phnum = EC16(file_hdr.e_phnum, conv);
    if(phnum > 128) {
	cli_dbgmsg("ELF: Suspicious number of program headers\n");
	return -1;
    }
    entry = EC32(file_hdr.e_entry, conv);

    if(phnum && entry) {
	phentsize = EC16(file_hdr.e_phentsize, conv);
	if(phentsize != sizeof(struct elf_program_hdr32)) {
	    cli_dbgmsg("ELF: phentsize != sizeof(struct elf_program_hdr32)\n");
	    return -1;
	}

	phoff = EC32(file_hdr.e_phoff, conv);

	program_hdr = (struct elf_program_hdr32 *) cli_calloc(phnum, phentsize);
	if(!program_hdr) {
	    cli_errmsg("ELF: Can't allocate memory for program headers\n");
	    return -1;
	}

	for(i = 0; i < phnum; i++) {
	    err = 0;
	    if(format == 1) {
		if(fmap_readn(map, &program_hdr[i], phoff, sizeof(struct elf_program_hdr32)) != sizeof(struct elf_program_hdr32))
		    err = 1;
		phoff += sizeof(struct elf_program_hdr32);
	    } else {
		    struct elf_program_hdr64 program_hdr64;

		if(fmap_readn(map, &program_hdr64, phoff, sizeof(program_hdr64)) != sizeof(program_hdr64)) {
		    err = 1;
		} else {
		    program_hdr[i].p_type = program_hdr64.p_type;
		    program_hdr[i].p_offset = program_hdr64.p_offset;
		    program_hdr[i].p_vaddr = program_hdr64.p_vaddr;
		    program_hdr[i].p_paddr = program_hdr64.p_paddr;
		    program_hdr[i].p_filesz = program_hdr64.p_filesz;
		    program_hdr[i].p_memsz = program_hdr64.p_memsz;
		    program_hdr[i].p_flags = program_hdr64.p_flags;
		    program_hdr[i].p_align = program_hdr64.p_align;
		}
		phoff += sizeof(program_hdr64);
	    }

	    if(err) {
		cli_dbgmsg("ELF: Can't read segment #%d\n", i);
		free(program_hdr);
		return -1;
	    }
	}

	fentry = cli_rawaddr(entry, program_hdr, phnum, conv, &err);
	free(program_hdr);
	if(err) {
	    cli_dbgmsg("ELF: Can't calculate file offset of entry point\n");
	    return -1;
	}
    }

    elfinfo->ep = fentry;

    shnum = EC16(file_hdr.e_shnum, conv);
    if(shnum > 256) {
	cli_dbgmsg("ELF: Suspicious number of sections\n");
	return -1;
    }
    elfinfo->nsections = shnum;

    shentsize = EC16(file_hdr.e_shentsize, conv);
    if(shentsize != sizeof(struct elf_section_hdr32)) {
	cli_dbgmsg("ELF: shentsize != sizeof(struct elf_section_hdr32)\n");
	return -1;
    }

    shoff = EC32(file_hdr.e_shoff, conv);

    elfinfo->section = (struct cli_exe_section *) cli_calloc(elfinfo->nsections, sizeof(struct cli_exe_section));
    if(!elfinfo->section) {
	cli_dbgmsg("ELF: Can't allocate memory for section headers\n");
	return -1;
    }

    section_hdr = (struct elf_section_hdr32 *) cli_calloc(shnum, shentsize);
    if(!section_hdr) {
	cli_errmsg("ELF: Can't allocate memory for section headers\n");
	free(elfinfo->section);
	elfinfo->section = NULL;
	return -1;
    }

    for(i = 0; i < shnum; i++) {
	err = 0;
	if(format == 1) {
	    if(fmap_readn(map, &section_hdr[i], shoff, sizeof(struct elf_section_hdr32)) != sizeof(struct elf_section_hdr32))
		err = 1;
	    shoff += sizeof(struct elf_section_hdr32);
	} else {
		struct elf_section_hdr64 section_hdr64;

	    if(fmap_readn(map, &section_hdr64, shoff, sizeof(section_hdr64)) != sizeof(section_hdr64)) {
		err = 1;
	    } else {
		section_hdr[i].sh_name = section_hdr64.sh_name;
		section_hdr[i].sh_type = section_hdr64.sh_type;
		section_hdr[i].sh_flags = section_hdr64.sh_flags;
		section_hdr[i].sh_addr = section_hdr64.sh_addr;
		section_hdr[i].sh_offset = section_hdr64.sh_offset;
		section_hdr[i].sh_size = section_hdr64.sh_size;
		section_hdr[i].sh_link = section_hdr64.sh_link;
		section_hdr[i].sh_info = section_hdr64.sh_info;
		section_hdr[i].sh_addralign = section_hdr64.sh_addralign;
		section_hdr[i].sh_entsize = section_hdr64.sh_entsize;
	    }
	    shoff += sizeof(section_hdr64);
	}

	if(err) {
            cli_dbgmsg("ELF: Can't read section header\n");
            free(section_hdr);
	    free(elfinfo->section);
	    elfinfo->section = NULL;
            return -1;
        }
	elfinfo->section[i].rva = EC32(section_hdr[i].sh_addr, conv);
	elfinfo->section[i].raw = EC32(section_hdr[i].sh_offset, conv);
	elfinfo->section[i].rsz = EC32(section_hdr[i].sh_size, conv);
    }

    free(section_hdr);
    return 0;
}

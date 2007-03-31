/*
 *  Copyright (C) 2005 - 2006 Tomasz Kojm <tkojm@clamav.net>
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

static inline uint16_t EC16(uint16_t v, uint8_t c)
{
    if(!c)
	return v;
    else
	return ((v >> 8) + (v << 8));
}

static inline uint32_t EC32(uint32_t v, uint8_t c)
{
    if(!c)
	return v;
    else
	return ((v >> 24) | ((v & 0x00FF0000) >> 8) | ((v & 0x0000FF00) << 8) | (v << 24));
}

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

int cli_scanelf(int desc, cli_ctx *ctx)
{
	struct elf_file_hdr32 file_hdr;
	struct elf_section_hdr32 *section_hdr;
	struct elf_program_hdr32 *program_hdr;
	uint16_t shnum, phnum, shentsize, phentsize;
	uint32_t entry, fentry, shoff, phoff, i;
	uint8_t conv = 0, err;


    cli_dbgmsg("in cli_scanelf\n");

    if(read(desc, &file_hdr, sizeof(file_hdr)) != sizeof(file_hdr)) {
	/* Not an ELF file? */
	cli_dbgmsg("ELF: Can't read file header\n");
	return CL_CLEAN;
    }

    if(memcmp(file_hdr.e_ident, "\x7f\x45\x4c\x46", 4)) {
	cli_dbgmsg("ELF: Not an ELF file\n");
	return CL_CLEAN;
    }

    if(file_hdr.e_ident[4] != 1) {
	cli_dbgmsg("ELF: 64-bit binaries are not supported (yet)\n");
	return CL_CLEAN;
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
	case 0x0: /* EM_NONE */
	    cli_dbgmsg("ELF: Machine type: None\n");
	    break;
	case 0x2: /* EM_SPARC */
	    cli_dbgmsg("ELF: Machine type: SPARC\n");
	    break;
	case 0x3: /* EM_386 */
	    cli_dbgmsg("ELF: Machine type: Intel 80386\n");
	    break;
	case 0x4: /* EM_68K */
	    cli_dbgmsg("ELF: Machine type: Motorola 68000\n");
	    break;
	case 0x8: /* EM_MIPS */
	    cli_dbgmsg("ELF: Machine type: MIPS RS3000\n");
	    break;
	case 0x15: /* EM_PARISC */
	    cli_dbgmsg("ELF: Machine type: HPPA\n");
	    break;
	case 0x20: /* EM_PPC */
	    cli_dbgmsg("ELF: Machine type: PowerPC\n");
	    break;
	case 0x21: /* EM_PPC64 */
	    cli_dbgmsg("ELF: Machine type: PowerPC 64-bit\n");
	    break;
	case 0x22: /* EM_S390 */
	    cli_dbgmsg("ELF: Machine type: IBM S390\n");
	    break;
	case 0x40: /* EM_ARM */
	    cli_dbgmsg("ELF: Machine type: ARM\n");
	    break;
	case 0x41: /* EM_FAKE_ALPHA */
	    cli_dbgmsg("ELF: Machine type: Digital Alpha\n");
	    break;
	case 0x43: /* EM_SPARCV9 */
	    cli_dbgmsg("ELF: Machine type: SPARC v9 64-bit\n");
	    break;
	case 0x50: /* EM_IA_64 */
	    cli_dbgmsg("ELF: Machine type: IA64\n");
	    break;
	default:
	    cli_dbgmsg("ELF: Machine type: Unknown (%d)\n", EC16(file_hdr.e_machine, conv));
    }

    entry = EC32(file_hdr.e_entry, conv);

    /* Program headers */

    phnum = EC16(file_hdr.e_phnum, conv);
    cli_dbgmsg("ELF: Number of program headers: %d\n", phnum);
    if(phnum > 128) {
	cli_dbgmsg("ELF: Suspicious number of program headers\n");
        if(DETECT_BROKEN) {
	    if(ctx->virname)
		*ctx->virname = "Broken.Executable";
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
		    *ctx->virname = "Broken.Executable";
		return CL_VIRUS;
	    }
	    return CL_EFORMAT;
	}

	phoff = EC32(file_hdr.e_phoff, conv);
	cli_dbgmsg("ELF: Program header table offset: %d\n", phoff);
	if((uint32_t) lseek(desc, phoff, SEEK_SET) != phoff) {
	    if(DETECT_BROKEN) {
		if(ctx->virname)
		    *ctx->virname = "Broken.Executable";
		return CL_VIRUS;
	    }
	    return CL_CLEAN;
	}

	program_hdr = (struct elf_program_hdr32 *) cli_calloc(phnum, phentsize);
	if(!program_hdr) {
	    cli_errmsg("ELF: Can't allocate memory for program headers\n");
	    return CL_EMEM;
	}

	cli_dbgmsg("------------------------------------\n");

	for(i = 0; i < phnum; i++) {

	    if(read(desc, &program_hdr[i], sizeof(struct elf_program_hdr32)) != sizeof(struct elf_program_hdr32)) {
		cli_dbgmsg("ELF: Can't read segment #%d\n", i);
		cli_dbgmsg("ELF: Possibly broken ELF file\n");
		free(program_hdr);
		if(DETECT_BROKEN) {
		    if(ctx->virname)
			*ctx->virname = "Broken.Executable";
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
		    *ctx->virname = "Broken.Executable";
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
		*ctx->virname = "Broken.Executable";
            return CL_VIRUS;
        }
	return CL_EFORMAT;
    }

    shentsize = EC16(file_hdr.e_shentsize, conv);
    if(shentsize != sizeof(struct elf_section_hdr32)) {
	cli_dbgmsg("ELF: shentsize != sizeof(struct elf_section_hdr32)\n");
        if(DETECT_BROKEN) {
	    if(ctx->virname)
		*ctx->virname = "Broken.Executable";
            return CL_VIRUS;
        }
	return CL_EFORMAT;
    }

    shoff = EC32(file_hdr.e_shoff, conv);
    cli_dbgmsg("ELF: Section header table offset: %d\n", shoff);
    if((uint32_t) lseek(desc, shoff, SEEK_SET) != shoff) {
	/* Possibly broken end of file */
        if(DETECT_BROKEN) {
	    if(ctx->virname)
		*ctx->virname = "Broken.Executable";
            return CL_VIRUS;
        }
	return CL_CLEAN;
    }

    section_hdr = (struct elf_section_hdr32 *) cli_calloc(shnum, shentsize);
    if(!section_hdr) {
	cli_errmsg("ELF: Can't allocate memory for section headers\n");
	return CL_EMEM;
    }

    cli_dbgmsg("------------------------------------\n");

    for(i = 0; i < shnum; i++) {

	if(read(desc, &section_hdr[i], sizeof(struct elf_section_hdr32)) != sizeof(struct elf_section_hdr32)) {
            cli_dbgmsg("ELF: Can't read section header\n");
            cli_dbgmsg("ELF: Possibly broken ELF file\n");
            free(section_hdr);
            if(DETECT_BROKEN) {
                if(ctx->virname)
                    *ctx->virname = "Broken.Executable";
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

int cli_elfheader(int desc, struct cli_exe_info *elfinfo)
{
	struct elf_file_hdr32 file_hdr;
	struct elf_section_hdr32 *section_hdr;
	struct elf_program_hdr32 *program_hdr;
	uint16_t shnum, phnum, shentsize, phentsize, i;
	uint32_t entry, fentry = 0, shoff, phoff;
	uint8_t conv = 0, err;


    cli_dbgmsg("in cli_elfheader\n");

    if(read(desc, &file_hdr, sizeof(file_hdr)) != sizeof(file_hdr)) {
	/* Not an ELF file? */
	cli_dbgmsg("ELF: Can't read file header\n");
	return -1;
    }

    if(memcmp(file_hdr.e_ident, "\x7f\x45\x4c\x46", 4)) {
	cli_dbgmsg("ELF: Not an ELF file\n");
	return -1;
    }

    if(file_hdr.e_ident[4] != 1) {
	cli_dbgmsg("ELF: 64-bit binaries are not supported (yet)\n");
	return -1;
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
	if((uint32_t) lseek(desc, phoff, SEEK_SET) != phoff) {
	    return -1;
	}

	program_hdr = (struct elf_program_hdr32 *) cli_calloc(phnum, phentsize);
	if(!program_hdr) {
	    cli_errmsg("ELF: Can't allocate memory for program headers\n");
	    return -1;
	}

	for(i = 0; i < phnum; i++) {
	    if(read(desc, &program_hdr[i], sizeof(struct elf_program_hdr32)) != sizeof(struct elf_program_hdr32)) {
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
    if((uint32_t) lseek(desc, shoff, SEEK_SET) != shoff) {
	/* Possibly broken end of file */
	return -1;
    }

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

	if(read(desc, &section_hdr[i], sizeof(struct elf_section_hdr32)) != sizeof(struct elf_section_hdr32)) {
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

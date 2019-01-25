/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2009-2013 Sourcefire, Inc.
 *
 *  Authors: Tomasz Kojm <tkojm@clamav.net>
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

#include <stdio.h>
#include <string.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "clamav.h"
#include "others.h"
#include "macho.h"
#include "execs.h"
#include "scanners.h"

#define EC32(v, conv)	(conv ? cbswap32(v) : v)
#define EC64(v, conv)	(conv ? cbswap64(v) : v)

struct macho_hdr
{
    uint32_t magic;
    uint32_t cpu_type;
    uint32_t cpu_subtype;
    uint32_t filetype;
    uint32_t ncmds;
    uint32_t sizeofcmds;
    uint32_t flags;
};

struct macho_load_cmd
{
    uint32_t cmd;
    uint32_t cmdsize;
};

struct macho_segment_cmd
{
    char segname[16];
    uint32_t vmaddr;
    uint32_t vmsize;
    uint32_t fileoff;
    uint32_t filesize;
    uint32_t maxprot;
    uint32_t initprot;
    uint32_t nsects;
    uint32_t flags;
};

struct macho_segment_cmd64
{
    char segname[16];
    uint64_t vmaddr;
    uint64_t vmsize;
    uint64_t fileoff;
    uint64_t filesize;
    uint32_t maxprot;
    uint32_t initprot;
    uint32_t nsects;
    uint32_t flags;
};

struct macho_section
{
    char sectname[16];
    char segname[16];
    uint32_t addr;
    uint32_t size;
    uint32_t offset;
    uint32_t align;
    uint32_t reloff;
    uint32_t nreloc;
    uint32_t flags;
    uint32_t res1;
    uint32_t res2;
};

struct macho_section64
{
    char sectname[16];
    char segname[16];
    uint64_t addr;
    uint64_t size;
    uint32_t offset;
    uint32_t align;
    uint32_t reloff;
    uint32_t nreloc;
    uint32_t flags;
    uint32_t res1;
    uint32_t res2;
};

struct macho_thread_state_ppc
{
    uint32_t srr0; /* PC */
    uint32_t srr1;
    uint32_t reg[32];
    uint32_t cr;
    uint32_t xer;
    uint32_t lr;
    uint32_t ctr;
    uint32_t mq;
    uint32_t vrsave;
};

struct macho_thread_state_ppc64
{
    uint64_t srr0; /* PC */
    uint64_t srr1;
    uint64_t reg[32];
    uint32_t cr;
    uint64_t xer;
    uint64_t lr;
    uint64_t ctr;
    uint32_t vrsave;
};

struct macho_thread_state_x86
{
    uint32_t eax;
    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;
    uint32_t edi;
    uint32_t esi;
    uint32_t ebp;
    uint32_t esp;
    uint32_t ss;
    uint32_t eflags;
    uint32_t eip;
    uint32_t cs;
    uint32_t ds;
    uint32_t es;
    uint32_t fs;
    uint32_t gs;
};

struct macho_fat_header
{
    uint32_t magic;
    uint32_t nfats;
};

struct macho_fat_arch
{
    uint32_t cputype;
    uint32_t cpusubtype;
    uint32_t offset;
    uint32_t size;
    uint32_t align;
};

#define RETURN_BROKEN					    \
    if(matcher)						    \
	return -1;					    \
    if(SCAN_HEURISTIC_BROKEN) {					    \
        if (CL_VIRUS == cli_append_virus(ctx, "Heuristics.Broken.Executable")) \
            return CL_VIRUS;				    \
    }							    \
    return CL_EFORMAT


static uint32_t cli_rawaddr(uint32_t vaddr, struct cli_exe_section *sects, uint16_t nsects, unsigned int *err)
{
	unsigned int i, found = 0;

    for(i = 0; i < nsects; i++) {
	if(sects[i].rva <= vaddr && sects[i].rva + sects[i].vsz > vaddr) {
	    found = 1;
	    break;
	}
    }

    if(!found) {
	*err = 1;
	return 0;
    }

    *err = 0;
    return vaddr - sects[i].rva + sects[i].raw;
}

int cli_scanmacho(cli_ctx *ctx, struct cli_exe_info *fileinfo)
{
	struct macho_hdr hdr;
	struct macho_load_cmd load_cmd;
	struct macho_segment_cmd segment_cmd;
	struct macho_segment_cmd64 segment_cmd64;
	struct macho_section section;
	struct macho_section64 section64;
	unsigned int i, j, sect = 0, conv, m64, nsects, matcher = 0;
	unsigned int arch = 0, ep = 0, err;
	struct cli_exe_section *sections = NULL;
	char name[16];
	fmap_t *map = *ctx->fmap;
	ssize_t at;

    if(fileinfo)
	matcher = 1;

    if(fmap_readn(map, &hdr, 0, sizeof(hdr)) != sizeof(hdr)) {
	cli_dbgmsg("cli_scanmacho: Can't read header\n");
	return matcher ? -1 : CL_EFORMAT;
    }
    at = sizeof(hdr);

    if(hdr.magic == 0xfeedface) {
	conv = 0;
	m64 = 0;
    } else if(hdr.magic == 0xcefaedfe) {
	conv = 1;
	m64 = 0;
    } else if(hdr.magic == 0xfeedfacf) {
	conv = 0;
	m64 = 1;
    } else if(hdr.magic == 0xcffaedfe) {
	conv = 1;
	m64 = 1;
    } else {
	cli_dbgmsg("cli_scanmacho: Incorrect magic\n");
	return matcher ? -1 : CL_EFORMAT;
    }

    switch(EC32(hdr.cpu_type, conv)) {
	case 7:
	    if(!matcher)
		cli_dbgmsg("MACHO: CPU Type: Intel 32-bit\n");
	    arch = 1;
	    break;
	case 7 | 0x1000000:
	    if(!matcher)
		cli_dbgmsg("MACHO: CPU Type: Intel 64-bit\n");
	    break;
	case 12:
	    if(!matcher)
		cli_dbgmsg("MACHO: CPU Type: ARM\n");
	    break;
	case 14:
	    if(!matcher)
		cli_dbgmsg("MACHO: CPU Type: SPARC\n");
	    break;
	case 18:
	    if(!matcher)
		cli_dbgmsg("MACHO: CPU Type: POWERPC 32-bit\n");
	    arch = 2;
	    break;
	case 18 | 0x1000000:
	    if(!matcher)
		cli_dbgmsg("MACHO: CPU Type: POWERPC 64-bit\n");
	    arch = 3;
	    break;
	default:
	    if(!matcher)
		cli_dbgmsg("MACHO: CPU Type: ** UNKNOWN ** (%u)\n", EC32(hdr.cpu_type, conv));
	    break;
    }

    if(!matcher) switch(EC32(hdr.filetype, conv)) {
	case 0x1: /* MH_OBJECT */
	    cli_dbgmsg("MACHO: Filetype: Relocatable object file\n");
	    break;
	case 0x2: /* MH_EXECUTE */
	    cli_dbgmsg("MACHO: Filetype: Executable\n");
	    break;
	case 0x3: /* MH_FVMLIB */
	    cli_dbgmsg("MACHO: Filetype: Fixed VM shared library file\n");
	    break;
	case 0x4: /* MH_CORE */
	    cli_dbgmsg("MACHO: Filetype: Core file\n");
	    break;
	case 0x5: /* MH_PRELOAD */
	    cli_dbgmsg("MACHO: Filetype: Preloaded executable file\n");
	    break;
	case 0x6: /* MH_DYLIB */
	    cli_dbgmsg("MACHO: Filetype: Dynamically bound shared library\n");
	    break;
	case 0x7: /* MH_DYLINKER */
	    cli_dbgmsg("MACHO: Filetype: Dynamic link editor\n");
	    break;
	case 0x8: /* MH_BUNDLE */
	    cli_dbgmsg("MACHO: Filetype: Dynamically bound bundle file\n");
	    break;
	case 0x9: /* MH_DYLIB_STUB */
	    cli_dbgmsg("MACHO: Filetype: Shared library stub for static\n");
	    break;
	default:
	    cli_dbgmsg("MACHO: Filetype: ** UNKNOWN ** (0x%x)\n", EC32(hdr.filetype, conv));
    }

    if(!matcher) {
	cli_dbgmsg("MACHO: Number of load commands: %u\n", EC32(hdr.ncmds, conv));
	cli_dbgmsg("MACHO: Size of load commands: %u\n", EC32(hdr.sizeofcmds, conv));
    }

    if(m64)
	at += 4;

    hdr.ncmds = EC32(hdr.ncmds, conv);
    if(!hdr.ncmds || hdr.ncmds > 1024) {
	cli_dbgmsg("cli_scanmacho: Invalid number of load commands (%u)\n", hdr.ncmds);
	RETURN_BROKEN;
    }

    for(i = 0; i < hdr.ncmds; i++) {
	if(fmap_readn(map, &load_cmd, at, sizeof(load_cmd)) != sizeof(load_cmd)) {
	    cli_dbgmsg("cli_scanmacho: Can't read load command\n");
	    free(sections);
	    RETURN_BROKEN;
	}
	at += sizeof(load_cmd);
	/*
	if((m64 && EC32(load_cmd.cmdsize, conv) % 8) || (!m64 && EC32(load_cmd.cmdsize, conv) % 4)) {
	    cli_dbgmsg("cli_scanmacho: Invalid command size (%u)\n", EC32(load_cmd.cmdsize, conv));
	    free(sections);
	    RETURN_BROKEN;
	}
	*/
	load_cmd.cmd = EC32(load_cmd.cmd, conv);
	if((m64 && load_cmd.cmd == 0x19) || (!m64 && load_cmd.cmd == 0x01)) { /* LC_SEGMENT */
	    if(m64) {
		if(fmap_readn(map, &segment_cmd64, at, sizeof(segment_cmd64)) != sizeof(segment_cmd64)) {
		    cli_dbgmsg("cli_scanmacho: Can't read segment command\n");
		    free(sections);
		    RETURN_BROKEN;
		}
		at += sizeof(segment_cmd64);
		nsects = EC32(segment_cmd64.nsects, conv);
		strncpy(name, segment_cmd64.segname, sizeof(name));
		name[sizeof(name)-1] = '\0';
	    } else {
		if(fmap_readn(map, &segment_cmd, at, sizeof(segment_cmd)) != sizeof(segment_cmd)) {
		    cli_dbgmsg("cli_scanmacho: Can't read segment command\n");
		    free(sections);
		    RETURN_BROKEN;
		}
		at += sizeof(segment_cmd);
		nsects = EC32(segment_cmd.nsects, conv);
		strncpy(name, segment_cmd.segname, sizeof(name));
		name[sizeof(name)-1] = '\0';
	    }
	    if(!matcher) {
		cli_dbgmsg("MACHO: Segment name: %s\n", name);
		cli_dbgmsg("MACHO: Number of sections: %u\n", nsects);
	    }
	    if(nsects > 255) {
		cli_dbgmsg("cli_scanmacho: Invalid number of sections\n");
		free(sections);
		RETURN_BROKEN;
	    }
	    if(!nsects) {
		if(!matcher)
		    cli_dbgmsg("MACHO: ------------------\n");
		continue;
	    }
	    sections = (struct cli_exe_section *) cli_realloc2(sections, (sect + nsects) * sizeof(struct cli_exe_section));
	    if(!sections) {
		cli_errmsg("cli_scanmacho: Can't allocate memory for 'sections'\n");
		return matcher ? -1 : CL_EMEM;
	    }

	    for(j = 0; j < nsects; j++) {
		if(m64) {
		    if(fmap_readn(map, &section64, at, sizeof(section64)) != sizeof(section64)) {
			cli_dbgmsg("cli_scanmacho: Can't read section\n");
			free(sections);
			RETURN_BROKEN;
		    }
		    at += sizeof(section64);
		    sections[sect].rva = EC64(section64.addr, conv);
		    sections[sect].vsz = EC64(section64.size, conv);
		    sections[sect].raw = EC32(section64.offset, conv);
		    section64.align = 1 << EC32(section64.align, conv);
		    sections[sect].rsz = sections[sect].vsz + (section64.align - (sections[sect].vsz % section64.align)) % section64.align; /* most likely we can assume it's the same as .vsz */
		    strncpy(name, section64.sectname, sizeof(name));
		    name[sizeof(name)-1] = '\0';
		} else {
		    if(fmap_readn(map, &section, at, sizeof(section)) != sizeof(section)) {
			cli_dbgmsg("cli_scanmacho: Can't read section\n");
			free(sections);
			RETURN_BROKEN;
		    }
		    at += sizeof(section);
		    sections[sect].rva = EC32(section.addr, conv);
		    sections[sect].vsz = EC32(section.size, conv);
		    sections[sect].raw = EC32(section.offset, conv);
		    section.align = 1 << EC32(section.align, conv);
		    sections[sect].rsz = sections[sect].vsz + (section.align - (sections[sect].vsz % section.align)) % section.align;
		    strncpy(name, section.sectname, sizeof(name));
		    name[sizeof(name)-1] = '\0';
		}
		if(!matcher) {
		    cli_dbgmsg("MACHO: --- Section %u ---\n", sect);
		    cli_dbgmsg("MACHO: Name: %s\n", name);
		    cli_dbgmsg("MACHO: Virtual address: 0x%x\n", (unsigned int) sections[sect].rva);
		    cli_dbgmsg("MACHO: Virtual size: %u\n", (unsigned int) sections[sect].vsz);
		    cli_dbgmsg("MACHO: Raw size: %u\n", (unsigned int) sections[sect].rsz);
		    if(sections[sect].raw)
			cli_dbgmsg("MACHO: File offset: %u\n", (unsigned int) sections[sect].raw);
		}
		sect++;
	    }
	    if(!matcher)
		cli_dbgmsg("MACHO: ------------------\n");

	} else if(arch && (load_cmd.cmd == 0x4 || load_cmd.cmd == 0x5)) { /* LC_(UNIX)THREAD */
	    at += 8;
	    switch(arch) {
		case 1: /* x86 */
		{
			struct macho_thread_state_x86 thread_state_x86;

		    if(fmap_readn(map, &thread_state_x86, at, sizeof(thread_state_x86)) != sizeof(thread_state_x86)) {
			cli_dbgmsg("cli_scanmacho: Can't read thread_state_x86\n");
			free(sections);
			RETURN_BROKEN;
		    }
		    at += sizeof(thread_state_x86);
		    break;
		}

		case 2: /* PPC */
		{
			struct macho_thread_state_ppc thread_state_ppc;

		    if(fmap_readn(map, &thread_state_ppc, at, sizeof(thread_state_ppc)) != sizeof(thread_state_ppc)) {
			cli_dbgmsg("cli_scanmacho: Can't read thread_state_ppc\n");
			free(sections);
			RETURN_BROKEN;
		    }
		    at += sizeof(thread_state_ppc);
		    ep = EC32(thread_state_ppc.srr0, conv);
		    break;
		}

		case 3: /* PPC64 */
		{
			struct macho_thread_state_ppc64 thread_state_ppc64;

		    if(fmap_readn(map, &thread_state_ppc64, at, sizeof(thread_state_ppc64)) != sizeof(thread_state_ppc64)) {
			cli_dbgmsg("cli_scanmacho: Can't read thread_state_ppc64\n");
			free(sections);
			RETURN_BROKEN;
		    }
		    at += sizeof(thread_state_ppc64);
		    ep = EC64(thread_state_ppc64.srr0, conv);
		    break;
		}
		default:
		    cli_errmsg("cli_scanmacho: Invalid arch setting!\n");
		    free(sections);
		    return matcher ? -1 : CL_EARG;
	    }
	} else {
	    if(EC32(load_cmd.cmdsize, conv) > sizeof(load_cmd))
		at += EC32(load_cmd.cmdsize, conv) - sizeof(load_cmd);
	}
    }

    if(ep) {
	if(!matcher)
	    cli_dbgmsg("Entry Point: 0x%x\n", ep);
	if(sections) {
	    ep = cli_rawaddr(ep, sections, sect, &err);
	    if(err) {
		cli_dbgmsg("cli_scanmacho: Can't calculate EP offset\n");
		free(sections);
		return matcher ? -1 : CL_EFORMAT;
	    }
	    if(!matcher)
		cli_dbgmsg("Entry Point file offset: %u\n", ep);
	}
    }

    if(matcher) {
	fileinfo->ep = ep;
	fileinfo->nsections = sect;
	fileinfo->section = sections;
	return 0;
    } else {
	free(sections);
	return CL_SUCCESS;
    }
}

int cli_machoheader(fmap_t *map, struct cli_exe_info *fileinfo)
{
    cli_ctx ctx;
    ctx.fmap = &map;
    return cli_scanmacho(&ctx, fileinfo);
}

int cli_scanmacho_unibin(cli_ctx *ctx)
{
	struct macho_fat_header fat_header;
	struct macho_fat_arch fat_arch;
	unsigned int conv, i, matcher = 0;
	int ret = CL_CLEAN;
	fmap_t *map = *ctx->fmap;
	ssize_t at;

    if(fmap_readn(map, &fat_header, 0, sizeof(fat_header)) != sizeof(fat_header)) {
	cli_dbgmsg("cli_scanmacho_unibin: Can't read fat_header\n");
	return CL_EFORMAT;
    }
    at = sizeof(fat_header);

    if(fat_header.magic == 0xcafebabe) {
	conv = 0;
    } else if(fat_header.magic == 0xbebafeca) {
	conv = 1;
    } else {
	cli_dbgmsg("cli_scanmacho_unibin: Incorrect magic\n");
	return CL_EFORMAT;
    }

    fat_header.nfats = EC32(fat_header.nfats, conv);
    if((fat_header.nfats & 0xffff) >= 39) /* Java Bytecode */
	return CL_CLEAN;

    if(fat_header.nfats > 32) {
	cli_dbgmsg("cli_scanmacho_unibin: Invalid number of architectures\n");
	return CL_EFORMAT;
    }
    cli_dbgmsg("UNIBIN: Number of architectures: %u\n", (unsigned int) fat_header.nfats);
    for(i = 0; i < fat_header.nfats; i++) {
	if(fmap_readn(map, &fat_arch, at, sizeof(fat_arch)) != sizeof(fat_arch)) {
	    cli_dbgmsg("cli_scanmacho_unibin: Can't read fat_arch\n");
	    RETURN_BROKEN;
	}
	at += sizeof(fat_arch);
	fat_arch.offset = EC32(fat_arch.offset, conv);
	fat_arch.size = EC32(fat_arch.size, conv);
	cli_dbgmsg("UNIBIN: Binary %u of %u\n", i + 1, fat_header.nfats);
	cli_dbgmsg("UNIBIN: File offset: %u\n", fat_arch.offset);
	cli_dbgmsg("UNIBIN: File size: %u\n", fat_arch.size);
	ret = cli_map_scan(map, fat_arch.offset, fat_arch.size, ctx, CL_TYPE_ANY);
	if(ret == CL_VIRUS)
	    break;
    }

    return ret; /* result from the last binary */
}

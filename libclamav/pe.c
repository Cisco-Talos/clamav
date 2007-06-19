/*
 *  Copyright (C) 2004 - 2006 Tomasz Kojm <tkojm@clamav.net>
 *			      aCaB <acab@clamav.net>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
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
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <time.h>

#include "cltypes.h"
#include "clamav.h"
#include "others.h"
#include "pe.h"
#include "petite.h"
#include "fsg.h"
#include "spin.h"
#include "upx.h"
#include "yc.h"
#include "aspack.h"
#include "wwunpack.h"
#include "suecrypt.h"
#include "unsp.h"
#include "scanners.h"
#include "str.h"
#include "execs.h"
#include "md5.h"
#include "mew.h"
#include "upack.h"
#include "matcher.h"
#include "matcher-bm.h"

#ifndef	O_BINARY
#define	O_BINARY	0
#endif

#define DCONF ctx->dconf->pe

#define IMAGE_DOS_SIGNATURE	    0x5a4d	    /* MZ */
#define IMAGE_DOS_SIGNATURE_OLD	    0x4d5a          /* ZM */
#define IMAGE_NT_SIGNATURE	    0x00004550
#define PE32_SIGNATURE		    0x010b
#define PE32P_SIGNATURE		    0x020b

#define optional_hdr64 pe_opt.opt64
#define optional_hdr32 pe_opt.opt32

#define UPX_NRV2B "\x11\xdb\x11\xc9\x01\xdb\x75\x07\x8b\x1e\x83\xee\xfc\x11\xdb\x11\xc9\x11\xc9\x75\x20\x41\x01\xdb"
#define UPX_NRV2D "\x83\xf0\xff\x74\x78\xd1\xf8\x89\xc5\xeb\x0b\x01\xdb\x75\x07\x8b\x1e\x83\xee\xfc\x11\xdb\x11\xc9"
#define UPX_NRV2E "\xeb\x52\x31\xc9\x83\xe8\x03\x72\x11\xc1\xe0\x08\x8a\x06\x46\x83\xf0\xff\x74\x75\xd1\xf8\x89\xc5"

#define EC32(x) le32_to_host(x) /* Convert little endian to host */
#define EC16(x) le16_to_host(x)
/* lower and upper bondary alignment (size vs offset) */
#define PEALIGN(o,a) (((a))?(((o)/(a))*(a)):(o))
#define PESALIGN(o,a) (((a))?(((o)/(a)+((o)%(a)!=0))*(a)):(o))

extern short cli_leavetemps_flag;

struct offset_list {
    uint32_t offset;
    struct offset_list *next;
};

static uint32_t cli_rawaddr(uint32_t rva, struct cli_exe_section *shp, uint16_t nos, unsigned int *err,	size_t fsize, uint32_t hdr_size)
{
	int i, found = 0;
	uint32_t ret;

    if (rva<hdr_size) { /* Out of section EP - mapped to imagebase+rva */
        if (rva >= fsize) {
	    *err=1;
	    return 0;
	}
        *err=0;
	return rva;
    }

    for(i = nos-1; i >= 0; i--) {
        if(shp[i].rsz && shp[i].rva <= rva && shp[i].rsz > rva - shp[i].rva) {
	    found = 1;
	    break;
	}
    }

    if(!found) {
	*err = 1;
	return 0;
    }

    ret = rva - shp[i].rva + shp[i].raw;
    *err = 0;
    return ret;
}

static void xckriz(char **opcode, int *len, int checksize, int reg) {
    while(*len>6) {
        if (**opcode>='\x48' && **opcode<='\x4f' && **opcode!='\x4c') {
	    if ((char)(**opcode-reg)=='\x48') break;
	    (*len)--;
	    (*opcode)++;
	    continue;
	}
	if (**opcode>='\xb8' && **opcode<='\xbf' && **opcode!='\xbc') {
	    if (checksize && cli_readint32(*opcode+1)==0x0fd2) break;
	    (*len)-=5;
	    (*opcode)+=5;
	    continue;
	}
	if (**opcode=='\x81') {
	    (*len)-=6;
	    (*opcode)+=6;
	    continue;
	}
	break;
    }
}


/*
static int cli_ddump(int desc, int offset, int size, const char *file)
{
	int pos, ndesc, bread, sum = 0;
	char buff[FILEBUFF];


    cli_dbgmsg("in ddump()\n");

    if((pos = lseek(desc, 0, SEEK_CUR)) == -1) {
	cli_dbgmsg("Invalid descriptor\n");
	return -1;
    }

    if(lseek(desc, offset, SEEK_SET) == -1) {
	cli_dbgmsg("lseek() failed\n");
	lseek(desc, pos, SEEK_SET);
	return -1;
    }

    if((ndesc = open(file, O_WRONLY|O_CREAT|O_TRUNC|O_BINARY, S_IRWXU)) < 0) {
	cli_dbgmsg("Can't create file %s\n", file);
	lseek(desc, pos, SEEK_SET);
	return -1;
    }

    while((bread = cli_readn(desc, buff, FILEBUFF)) > 0) {
	if(sum + bread >= size) {
	    if(write(ndesc, buff, size - sum) == -1) {
		cli_dbgmsg("Can't write to file\n");
		lseek(desc, pos, SEEK_SET);
		close(ndesc);
		unlink(file);
		return -1;
	    }
	    break;
	} else {
	    if(write(ndesc, buff, bread) == -1) {
		cli_dbgmsg("Can't write to file\n");
		lseek(desc, pos, SEEK_SET);
		close(ndesc);
		unlink(file);
		return -1;
	    }
	}
	sum += bread;
    }

    close(ndesc);
    lseek(desc, pos, SEEK_SET);
    return 0;
}
*/

static unsigned int cli_md5sect(int fd, uint32_t offset, uint32_t size, unsigned char *digest)
{
	size_t bread, sum = 0;
	off_t pos;
	char buff[FILEBUFF];
	cli_md5_ctx md5ctx;


    if((pos = lseek(fd, 0, SEEK_CUR)) == -1) {
	cli_dbgmsg("cli_md5sect: Invalid descriptor %d\n", fd);
	return 0;
    }

    if(lseek(fd, offset, SEEK_SET) == -1) {
	cli_dbgmsg("cli_md5sect: lseek() failed\n");
	lseek(fd, pos, SEEK_SET);
	return 0;
    }

    cli_md5_init(&md5ctx);

    while((bread = cli_readn(fd, buff, FILEBUFF)) > 0) {
	if(sum + bread >= size) {
	    cli_md5_update(&md5ctx, buff, size - sum);
	    break;
	} else {
	    cli_md5_update(&md5ctx, buff, bread);
	    sum += bread;
	}
    }

    cli_md5_final(digest, &md5ctx);
    lseek(fd, pos, SEEK_SET);
    return 1;
}

int cli_scanpe(int desc, cli_ctx *ctx)
{
	uint16_t e_magic; /* DOS signature ("MZ") */
	uint16_t nsections;
	uint32_t e_lfanew; /* address of new exe header */
	uint32_t ep, vep; /* entry point (raw, virtual) */
	uint8_t polipos = 0;
	time_t timestamp;
	struct pe_image_file_hdr file_hdr;
	union {
	    struct pe_image_optional_hdr64 opt64;
	    struct pe_image_optional_hdr32 opt32;
	} pe_opt;
	struct pe_image_section_hdr *section_hdr;
	struct stat sb;
	char sname[9], buff[4096], *tempfile;
	unsigned char *ubuff;
	ssize_t bytes;
	unsigned int i, found, upx_success = 0, min = 0, max = 0, err;
	unsigned int ssize = 0, dsize = 0, dll = 0, pe_plus = 0;
	int (*upxfn)(char *, uint32_t, char *, uint32_t *, uint32_t, uint32_t, uint32_t) = NULL;
	char *src = NULL, *dest = NULL;
	int ndesc, ret = CL_CLEAN, upack = 0, native=0;
	size_t fsize;
	uint32_t valign, falign, hdr_size, j;
	struct cli_exe_section *exe_sections;
	struct cli_matcher *md5_sect;


    if(cli_readn(desc, &e_magic, sizeof(e_magic)) != sizeof(e_magic)) {
	cli_dbgmsg("Can't read DOS signature\n");
	return CL_CLEAN;
    }

    if(EC16(e_magic) != IMAGE_DOS_SIGNATURE && EC16(e_magic) != IMAGE_DOS_SIGNATURE_OLD) {
	cli_dbgmsg("Invalid DOS signature\n");
	return CL_CLEAN;
    }

    lseek(desc, 58, SEEK_CUR); /* skip to the end of the DOS header */

    if(cli_readn(desc, &e_lfanew, sizeof(e_lfanew)) != sizeof(e_lfanew)) {
	cli_dbgmsg("Can't read new header address\n");
	/* truncated header? */
	if(DETECT_BROKEN) {
	    if(ctx->virname)
		*ctx->virname = "Broken.Executable";
	    return CL_VIRUS;
	}
	return CL_CLEAN;
    }

    e_lfanew = EC32(e_lfanew);
    cli_dbgmsg("e_lfanew == %d\n", e_lfanew);
    if(!e_lfanew) {
	cli_dbgmsg("Not a PE file\n");
	return CL_CLEAN;
    }

    if(lseek(desc, e_lfanew, SEEK_SET) < 0) {
	/* probably not a PE file */
	cli_dbgmsg("Can't lseek to e_lfanew\n");
	return CL_CLEAN;
    }

    if(cli_readn(desc, &file_hdr, sizeof(struct pe_image_file_hdr)) != sizeof(struct pe_image_file_hdr)) {
	/* bad information in e_lfanew - probably not a PE file */
	cli_dbgmsg("Can't read file header\n");
	return CL_CLEAN;
    }

    if(EC32(file_hdr.Magic) != IMAGE_NT_SIGNATURE) {
	cli_dbgmsg("Invalid PE signature (probably NE file)\n");
	return CL_CLEAN;
    }

    if(EC16(file_hdr.Characteristics) & 0x2000) {
	cli_dbgmsg("File type: DLL\n");
	dll = 1;
    } else if(EC16(file_hdr.Characteristics) & 0x01) {
	cli_dbgmsg("File type: Executable\n");
    }

    switch(EC16(file_hdr.Machine)) {
	case 0x0:
	    cli_dbgmsg("Machine type: Unknown\n");
	case 0x14c:
	    cli_dbgmsg("Machine type: 80386\n");
	    break;
	case 0x14d:
	    cli_dbgmsg("Machine type: 80486\n");
	    break;
	case 0x14e:
	    cli_dbgmsg("Machine type: 80586\n");
	    break;
	case 0x160:
	    cli_dbgmsg("Machine type: R30000 (big-endian)\n");
	    break;
	case 0x162:
	    cli_dbgmsg("Machine type: R3000\n");
	    break;
	case 0x166:
	    cli_dbgmsg("Machine type: R4000\n");
	    break;
	case 0x168:
	    cli_dbgmsg("Machine type: R10000\n");
	    break;
	case 0x184:
	    cli_dbgmsg("Machine type: DEC Alpha AXP\n");
	    break;
	case 0x284:
	    cli_dbgmsg("Machine type: DEC Alpha AXP 64bit\n");
	    break;
	case 0x1f0:
	    cli_dbgmsg("Machine type: PowerPC\n");
	    break;
	case 0x200:
	    cli_dbgmsg("Machine type: IA64\n");
	    break;
	case 0x268:
	    cli_dbgmsg("Machine type: M68k\n");
	    break;
	case 0x266:
	    cli_dbgmsg("Machine type: MIPS16\n");
	    break;
	case 0x366:
	    cli_dbgmsg("Machine type: MIPS+FPU\n");
	    break;
	case 0x466:
	    cli_dbgmsg("Machine type: MIPS16+FPU\n");
	    break;
	case 0x1a2:
	    cli_dbgmsg("Machine type: Hitachi SH3\n");
	    break;
	case 0x1a3:
	    cli_dbgmsg("Machine type: Hitachi SH3-DSP\n");
	    break;
	case 0x1a4:
	    cli_dbgmsg("Machine type: Hitachi SH3-E\n");
	    break;
	case 0x1a6:
	    cli_dbgmsg("Machine type: Hitachi SH4\n");
	    break;
	case 0x1a8:
	    cli_dbgmsg("Machine type: Hitachi SH5\n");
	    break;
	case 0x1c0:
	    cli_dbgmsg("Machine type: ARM\n");
	    break;
	case 0x1c2:
	    cli_dbgmsg("Machine type: THUMB\n");
	    break;
	case 0x1d3:
	    cli_dbgmsg("Machine type: AM33\n");
	    break;
	case 0x520:
	    cli_dbgmsg("Machine type: Infineon TriCore\n");
	    break;
	case 0xcef:
	    cli_dbgmsg("Machine type: CEF\n");
	    break;
	case 0xebc:
	    cli_dbgmsg("Machine type: EFI Byte Code\n");
	    break;
	case 0x9041:
	    cli_dbgmsg("Machine type: M32R\n");
	    break;
	case 0xc0ee:
	    cli_dbgmsg("Machine type: CEE\n");
	    break;
	case 0x8664:
	    cli_dbgmsg("Machine type: AMD64\n");
	    break;
	default:
	    cli_warnmsg("Unknown machine type in PE header (0x%x)\n", EC16(file_hdr.Machine));
    }

    nsections = EC16(file_hdr.NumberOfSections);
    if(nsections < 1 || nsections > 96) {
	if(DETECT_BROKEN) {
	    if(ctx->virname)
		*ctx->virname = "Broken.Executable";
	    return CL_VIRUS;
	}
	if(nsections)
	    cli_warnmsg("PE file contains %d sections\n", nsections);
	else
	    cli_warnmsg("PE file contains no sections\n");
	return CL_CLEAN;
    }
    cli_dbgmsg("NumberOfSections: %d\n", nsections);

    timestamp = (time_t) EC32(file_hdr.TimeDateStamp);
    cli_dbgmsg("TimeDateStamp: %s", ctime(&timestamp));

    cli_dbgmsg("SizeOfOptionalHeader: %x\n", EC16(file_hdr.SizeOfOptionalHeader));

    if (EC16(file_hdr.SizeOfOptionalHeader) < sizeof(struct pe_image_optional_hdr32)) {
        cli_dbgmsg("SizeOfOptionalHeader too small\n");
	if(DETECT_BROKEN) {
	    if(ctx->virname)
	        *ctx->virname = "Broken.Executable";
	    return CL_VIRUS;
	}
	return CL_CLEAN;
    }

    if(cli_readn(desc, &optional_hdr32, sizeof(struct pe_image_optional_hdr32)) != sizeof(struct pe_image_optional_hdr32)) {
        cli_dbgmsg("Can't read optional file header\n");
	if(DETECT_BROKEN) {
	    if(ctx->virname)
	        *ctx->virname = "Broken.Executable";
	    return CL_VIRUS;
	}
	return CL_CLEAN;
    }

    /* This will be a chicken and egg problem until we drop 9x */
    if(EC32(optional_hdr64.Magic)==PE32P_SIGNATURE) {
        if(EC16(file_hdr.SizeOfOptionalHeader)!=sizeof(struct pe_image_optional_hdr64)) {
	    /* FIXME: need to play around a bit more with xp64 */
	    cli_dbgmsg("Incorrect SizeOfOptionalHeader for PE32+\n");
	    if(DETECT_BROKEN) {
	        if(ctx->virname)
		    *ctx->virname = "Broken.Executable";
		return CL_VIRUS;
	    }
	    return CL_CLEAN;
	}
	pe_plus = 1;
    } else {
        /*
	    either it's got a PE32_SIGNATURE or
	    we enable win9x compatibility in that we don't honor magic (see bb#119)
	    either way it's a 32bit thingy
	*/
        if(EC16(optional_hdr32.Magic) != PE32_SIGNATURE) {
	    cli_warnmsg("Incorrect magic number in optional header\n");
	    if(DETECT_BROKEN) {
	        if(ctx->virname)
		    *ctx->virname = "Broken.Executable";
		return CL_VIRUS;
	    }
	    cli_dbgmsg("9x compatibility mode\n");
	}
    }

    if(!pe_plus) { /* PE */
	if (EC16(file_hdr.SizeOfOptionalHeader)!=sizeof(struct pe_image_optional_hdr32)) {
	    /* Seek to the end of the long header */
	    lseek(desc, (EC16(file_hdr.SizeOfOptionalHeader)-sizeof(struct pe_image_optional_hdr32)), SEEK_CUR);
	}

	if(DCONF & PE_CONF_UPACK)
	    upack = (EC16(file_hdr.SizeOfOptionalHeader)==0x148);

	vep = EC32(optional_hdr32.AddressOfEntryPoint);
	hdr_size = EC32(optional_hdr32.SizeOfHeaders);
	cli_dbgmsg("File format: PE\n");

	cli_dbgmsg("MajorLinkerVersion: %d\n", optional_hdr32.MajorLinkerVersion);
	cli_dbgmsg("MinorLinkerVersion: %d\n", optional_hdr32.MinorLinkerVersion);
	cli_dbgmsg("SizeOfCode: 0x%x\n", EC32(optional_hdr32.SizeOfCode));
	cli_dbgmsg("SizeOfInitializedData: 0x%x\n", EC32(optional_hdr32.SizeOfInitializedData));
	cli_dbgmsg("SizeOfUninitializedData: 0x%x\n", EC32(optional_hdr32.SizeOfUninitializedData));
	cli_dbgmsg("AddressOfEntryPoint: 0x%x\n", vep);
	cli_dbgmsg("BaseOfCode: 0x%x\n", EC32(optional_hdr32.BaseOfCode));
	cli_dbgmsg("SectionAlignment: 0x%x\n", EC32(optional_hdr32.SectionAlignment));
	cli_dbgmsg("FileAlignment: 0x%x\n", EC32(optional_hdr32.FileAlignment));
	cli_dbgmsg("MajorSubsystemVersion: %d\n", EC16(optional_hdr32.MajorSubsystemVersion));
	cli_dbgmsg("MinorSubsystemVersion: %d\n", EC16(optional_hdr32.MinorSubsystemVersion));
	cli_dbgmsg("SizeOfImage: 0x%x\n", EC32(optional_hdr32.SizeOfImage));
	cli_dbgmsg("SizeOfHeaders: 0x%x\n", hdr_size);
	cli_dbgmsg("NumberOfRvaAndSizes: %d\n", EC32(optional_hdr32.NumberOfRvaAndSizes));

    } else { /* PE+ */
        /* read the remaining part of the header */
        if(cli_readn(desc, &optional_hdr32 + 1, sizeof(struct pe_image_optional_hdr64) - sizeof(struct pe_image_optional_hdr32)) != sizeof(struct pe_image_optional_hdr64) - sizeof(struct pe_image_optional_hdr32)) {
	    cli_dbgmsg("Can't read optional file header\n");
	    if(DETECT_BROKEN) {
	        if(ctx->virname)
		    *ctx->virname = "Broken.Executable";
		return CL_VIRUS;
	    }
	    return CL_CLEAN;
	}

	vep = EC32(optional_hdr64.AddressOfEntryPoint);
	hdr_size = EC32(optional_hdr64.SizeOfHeaders);
	cli_dbgmsg("File format: PE32+\n");

	cli_dbgmsg("MajorLinkerVersion: %d\n", optional_hdr64.MajorLinkerVersion);
	cli_dbgmsg("MinorLinkerVersion: %d\n", optional_hdr64.MinorLinkerVersion);
	cli_dbgmsg("SizeOfCode: 0x%x\n", EC32(optional_hdr64.SizeOfCode));
	cli_dbgmsg("SizeOfInitializedData: 0x%x\n", EC32(optional_hdr64.SizeOfInitializedData));
	cli_dbgmsg("SizeOfUninitializedData: 0x%x\n", EC32(optional_hdr64.SizeOfUninitializedData));
	cli_dbgmsg("AddressOfEntryPoint: 0x%x\n", vep);
	cli_dbgmsg("BaseOfCode: 0x%x\n", EC32(optional_hdr64.BaseOfCode));
	cli_dbgmsg("SectionAlignment: 0x%x\n", EC32(optional_hdr64.SectionAlignment));
	cli_dbgmsg("FileAlignment: 0x%x\n", EC32(optional_hdr64.FileAlignment));
	cli_dbgmsg("MajorSubsystemVersion: %d\n", EC16(optional_hdr64.MajorSubsystemVersion));
	cli_dbgmsg("MinorSubsystemVersion: %d\n", EC16(optional_hdr64.MinorSubsystemVersion));
	cli_dbgmsg("SizeOfImage: 0x%x\n", EC32(optional_hdr64.SizeOfImage));
	cli_dbgmsg("SizeOfHeaders: 0x%x\n", hdr_size);
	cli_dbgmsg("NumberOfRvaAndSizes: %d\n", EC32(optional_hdr64.NumberOfRvaAndSizes));
    }


    switch(pe_plus ? EC16(optional_hdr64.Subsystem) : EC16(optional_hdr32.Subsystem)) {
	case 0:
	    cli_dbgmsg("Subsystem: Unknown\n");
	    break;
	case 1:
	    cli_dbgmsg("Subsystem: Native (svc)\n");
	    native = 1;
	    break;
	case 2:
	    cli_dbgmsg("Subsystem: Win32 GUI\n");
	    break;
	case 3:
	    cli_dbgmsg("Subsystem: Win32 console\n");
	    break;
	case 5:
	    cli_dbgmsg("Subsystem: OS/2 console\n");
	    break;
	case 7:
	    cli_dbgmsg("Subsystem: POSIX console\n");
	    break;
	case 8:
	    cli_dbgmsg("Subsystem: Native Win9x driver\n");
	    break;
	case 9:
	    cli_dbgmsg("Subsystem: WinCE GUI\n");
	    break;
	case 10:
	    cli_dbgmsg("Subsystem: EFI application\n");
	    break;
	case 11:
	    cli_dbgmsg("Subsystem: EFI driver\n");
	    break;
	case 12:
	    cli_dbgmsg("Subsystem: EFI runtime driver\n");
	    break;
	default:
	    cli_warnmsg("Unknown subsystem in PE header (0x%x)\n", pe_plus ? EC16(optional_hdr64.Subsystem) : EC16(optional_hdr32.Subsystem));
    }

    cli_dbgmsg("------------------------------------\n");

    if (DETECT_BROKEN && !native && (!(pe_plus?EC32(optional_hdr64.SectionAlignment):EC32(optional_hdr32.SectionAlignment)) || (pe_plus?EC32(optional_hdr64.SectionAlignment):EC32(optional_hdr32.SectionAlignment))%0x1000)) {
        cli_dbgmsg("Bad virtual alignemnt\n");
        if(ctx->virname)
	    *ctx->virname = "Broken.Executable";
	return CL_VIRUS;
    }

    if (DETECT_BROKEN && !native && (!(pe_plus?EC32(optional_hdr64.FileAlignment):EC32(optional_hdr32.FileAlignment)) || (pe_plus?EC32(optional_hdr64.FileAlignment):EC32(optional_hdr32.FileAlignment))%0x200)) {
        cli_dbgmsg("Bad file alignemnt\n");
	if(ctx->virname)
	    *ctx->virname = "Broken.Executable";
	return CL_VIRUS;
    }

    if(fstat(desc, &sb) == -1) {
	cli_dbgmsg("fstat failed\n");
	return CL_EIO;
    }

    fsize = sb.st_size;

    section_hdr = (struct pe_image_section_hdr *) cli_calloc(nsections, sizeof(struct pe_image_section_hdr));

    if(!section_hdr) {
	cli_dbgmsg("Can't allocate memory for section headers\n");
	return CL_EMEM;
    }

    exe_sections = (struct cli_exe_section *) cli_calloc(nsections, sizeof(struct cli_exe_section));
    
    if(!exe_sections) {
	cli_dbgmsg("Can't allocate memory for section headers\n");
	free(section_hdr);
	return CL_EMEM;
    }

    valign = (pe_plus)?EC32(optional_hdr64.SectionAlignment):EC32(optional_hdr32.SectionAlignment);
    falign = (pe_plus)?EC32(optional_hdr64.FileAlignment):EC32(optional_hdr32.FileAlignment);

    if(cli_readn(desc, section_hdr, sizeof(struct pe_image_section_hdr)*nsections) != (int)(nsections*sizeof(struct pe_image_section_hdr))) {
        cli_dbgmsg("Can't read section header\n");
	cli_dbgmsg("Possibly broken PE file\n");
	free(section_hdr);
	free(exe_sections);
	if(DETECT_BROKEN) {
	    if(ctx->virname)
		*ctx->virname = "Broken.Executable";
	    return CL_VIRUS;
	}
	return CL_CLEAN;
    }
    
    for(i = 0; falign!=0x200 && i<nsections; i++) {
	/* file alignment fallback mode - blah */
	if (falign && section_hdr[i].SizeOfRawData && EC32(section_hdr[i].PointerToRawData)%falign && !(EC32(section_hdr[i].PointerToRawData)%0x200)) {
	    cli_dbgmsg("Found misaligned section, using 0x200\n");
	    falign = 0x200;
	}
    }

    hdr_size = PESALIGN(hdr_size, valign); /* Aligned headers virtual size */

    for(i = 0; i < nsections; i++) {
	strncpy(sname, (char *) section_hdr[i].Name, 8);
	sname[8] = 0;
	exe_sections[i].rva = PEALIGN(EC32(section_hdr[i].VirtualAddress), valign);
	exe_sections[i].vsz = PESALIGN(EC32(section_hdr[i].VirtualSize), valign);
	exe_sections[i].raw = PEALIGN(EC32(section_hdr[i].PointerToRawData), falign);
	exe_sections[i].rsz = PESALIGN(EC32(section_hdr[i].SizeOfRawData), falign);
	exe_sections[i].chr = EC32(section_hdr[i].Characteristics);
	exe_sections[i].urva = EC32(section_hdr[i].VirtualAddress); /* Just in case */
	exe_sections[i].uvsz = EC32(section_hdr[i].VirtualSize);
	exe_sections[i].uraw = EC32(section_hdr[i].PointerToRawData);
	exe_sections[i].ursz = EC32(section_hdr[i].SizeOfRawData);

	if (!exe_sections[i].vsz && exe_sections[i].rsz)
	    exe_sections[i].vsz=PESALIGN(exe_sections[i].ursz, valign);

	if (exe_sections[i].rsz && fsize>exe_sections[i].raw && !CLI_ISCONTAINED(0, (uint32_t) fsize, exe_sections[i].raw, exe_sections[i].rsz))
	    exe_sections[i].rsz = fsize - exe_sections[i].raw;
	
	cli_dbgmsg("Section %d\n", i);
	cli_dbgmsg("Section name: %s\n", sname);
	cli_dbgmsg("Section data (from headers - in memory)\n");
	cli_dbgmsg("VirtualSize: 0x%x 0x%x\n", exe_sections[i].uvsz, exe_sections[i].vsz);
	cli_dbgmsg("VirtualAddress: 0x%x 0x%x\n", exe_sections[i].urva, exe_sections[i].rva);
	cli_dbgmsg("SizeOfRawData: 0x%x 0x%x\n", exe_sections[i].ursz, exe_sections[i].rsz);
	cli_dbgmsg("PointerToRawData: 0x%x 0x%x\n", exe_sections[i].uraw, exe_sections[i].raw);

	if(exe_sections[i].chr & 0x20) {
	    cli_dbgmsg("Section contains executable code\n");

	    if(exe_sections[i].vsz < exe_sections[i].rsz) {
		cli_dbgmsg("Section contains free space\n");
		/*
		cli_dbgmsg("Dumping %d bytes\n", section_hdr.SizeOfRawData - section_hdr.VirtualSize);
		ddump(desc, section_hdr.PointerToRawData + section_hdr.VirtualSize, section_hdr.SizeOfRawData - section_hdr.VirtualSize, cli_gentemp(NULL));
		*/

	    }
	}

	if(exe_sections[i].chr & 0x20000000)
	    cli_dbgmsg("Section's memory is executable\n");

	if(exe_sections[i].chr & 0x80000000)
	    cli_dbgmsg("Section's memory is writeable\n");

	cli_dbgmsg("------------------------------------\n");

	if (DETECT_BROKEN && (exe_sections[i].urva % valign)) { /* Bad virtual alignment */
	    cli_dbgmsg("VirtualAddress is misaligned\n");
	    if(ctx->virname)
	        *ctx->virname = "Broken.Executable";
	    free(section_hdr);
	    free(exe_sections);
	    return CL_VIRUS;
	}

	if (exe_sections[i].rsz) { /* Don't bother with virtual only sections */
	    unsigned char md5_dig[16];
	    if (exe_sections[i].raw >= fsize) { /* really broken */
	        cli_dbgmsg("Broken PE file - Section %d starts beyond the end of file (Offset@ %d, Total filesize %d)\n", i, exe_sections[i].raw, fsize);
		free(section_hdr);
		free(exe_sections);
		if(DETECT_BROKEN) {
		    if(ctx->virname)
		        *ctx->virname = "Broken.Executable";
		    return CL_VIRUS;
		}
		return CL_CLEAN; /* no ninjas to see here! move along! */
	    }

	    /* check MD5 section sigs */
	    md5_sect = ctx->engine->md5_sect;
	    if((DCONF & PE_CONF_MD5SECT) && md5_sect) {
		found = 0;
		for(j = 0; j < md5_sect->soff_len && md5_sect->soff[j] <= exe_sections[i].rsz; j++) {
		    if(md5_sect->soff[j] == exe_sections[i].rsz) {
			found = 1;
			break;
		    }
		}

		if(found) {
		    if(!cli_md5sect(desc, exe_sections[i].raw, exe_sections[i].rsz, md5_dig)) {
			cli_errmsg("PE: Can't calculate MD5 for section %u\n", i);
		    } else {
			if(cli_bm_scanbuff(md5_dig, 16, ctx->virname, ctx->engine->md5_sect, 0, 0, -1) == CL_VIRUS) {
			    free(section_hdr);
			    free(exe_sections);
			    return CL_VIRUS;
			}
		    }
		}
	    }
	}

	if(!i) {
	    if (DETECT_BROKEN && exe_sections[i].urva!=hdr_size) { /* Bad first section RVA */
	        cli_dbgmsg("First section is in the wrong place\n");
	        if(ctx->virname)
		    *ctx->virname = "Broken.Executable";
		free(section_hdr);
		free(exe_sections);
		return CL_VIRUS;
	    }
	    min = exe_sections[i].rva;
	    max = exe_sections[i].rva + exe_sections[i].rsz;
	} else {
	    if (DETECT_BROKEN && exe_sections[i].urva - exe_sections[i-1].urva != exe_sections[i-1].vsz) { /* No holes, no overlapping, no virtual disorder */
	        cli_dbgmsg("Virtually misplaced section (wrong order, overlapping, non contiguous)\n");
	        if(ctx->virname)
		    *ctx->virname = "Broken.Executable";
		free(section_hdr);
		free(exe_sections);
		return CL_VIRUS;
	    }
	    if(exe_sections[i].rva < min)
	        min = exe_sections[i].rva;

	    if(exe_sections[i].rva + exe_sections[i].rsz > max)
	        max = exe_sections[i].rva + exe_sections[i].rsz;
	}

	if(SCAN_ALGO && (DCONF & PE_CONF_POLIPOS) && !strlen(sname)) {
	    if(exe_sections[i].vsz > 40000 && exe_sections[i].vsz < 70000) {
		if(exe_sections[i].chr == 0xe0000060) {
		    polipos = i;
		}
	    }
	}

    }

    free(section_hdr);

    if(!(ep = cli_rawaddr(vep, exe_sections, nsections, &err, fsize, hdr_size)) && err) {
	cli_dbgmsg("EntryPoint out of file\n");
	free(exe_sections);
	if(DETECT_BROKEN) {
	    if(ctx->virname)
		*ctx->virname = "Broken.Executable";
	    return CL_VIRUS;
	}
	return CL_CLEAN;
    }

    cli_dbgmsg("EntryPoint offset: 0x%x (%d)\n", ep, ep);

    if(pe_plus) { /* Do not continue for PE32+ files */
	free(exe_sections);
	return CL_CLEAN;
    }


    /* Attempt to detect some popular polymorphic viruses */

    /* W32.Parite.B */
    if(SCAN_ALGO && (DCONF & PE_CONF_PARITE) && !dll && ep == exe_sections[nsections - 1].raw) {
	lseek(desc, ep, SEEK_SET);
	if(cli_readn(desc, buff, 4096) == 4096) {
		const char *pt = cli_memstr(buff, 4040, "\x47\x65\x74\x50\x72\x6f\x63\x41\x64\x64\x72\x65\x73\x73\x00", 15);
	    if(pt) {
		    uint32_t dw1, dw2;

		pt += 15;
		if(((dw1 = cli_readint32(pt)) ^ (dw2 = cli_readint32(pt + 4))) == 0x505a4f && ((dw1 = cli_readint32(pt + 8)) ^ (dw2 = cli_readint32(pt + 12))) == 0xffffb && ((dw1 = cli_readint32(pt + 16)) ^ (dw2 = cli_readint32(pt + 20))) == 0xb8) {
		    *ctx->virname = "W32.Parite.B";
		    free(exe_sections);
		    return CL_VIRUS;
		}
	    }
	}
    }

    /* Kriz */
    if(SCAN_ALGO && (DCONF & PE_CONF_KRIZ) && CLI_ISCONTAINED(exe_sections[nsections - 1].raw, exe_sections[nsections - 1].rsz, ep, 0x0fd2)) {
	cli_dbgmsg("in kriz\n");
	lseek(desc, ep, SEEK_SET);
	if(cli_readn(desc, buff, 200) == 200) {
	    while (1) {
		char *krizpos=buff+3;
		char *krizmov, *krizxor;
		int krizleft = 200-3;
		int krizrega,krizregb;

		if (buff[1]!='\x9c' || buff[2]!='\x60') break; /* EP+1 */
		xckriz(&krizpos, &krizleft, 0, 8);
		if (krizleft < 6 || *krizpos!='\xe8' || krizpos[2] || krizpos[3] || krizpos[4]) break; /* call DELTA */
		krizleft-=5+(unsigned char)krizpos[1];
		if (krizleft < 2) break;
		krizpos+=5+(unsigned char)krizpos[1];
		if (*krizpos<'\x58' || *krizpos>'\x5f' || *krizpos=='\x5c') break; /* pop DELTA */
		krizrega=*krizpos-'\x58';
		cli_dbgmsg("kriz: pop delta using %d\n", krizrega);
		krizpos+=1;
		krizleft-=1;
		xckriz(&krizpos, &krizleft, 1, 8);
		if (krizleft <6 || *krizpos<'\xb8' || *krizpos>'\xbf' || *krizpos=='\xbc' || cli_readint32(krizpos+1)!=0x0fd2) break;
		krizregb=*krizpos-'\xb8';
		if (krizrega==krizregb) break;
		cli_dbgmsg("kriz: using %d for size\n", krizregb);
		krizpos+=5;
		krizleft-=5;
		krizmov = krizpos;
		xckriz(&krizpos, &krizleft, 0, 8);
		krizxor=krizpos;
		if (krizleft && *krizpos=='\x3e') {
		    /* strip ds: */
		    krizpos++;
		    krizleft--;
		}
		if (krizleft<8 || *krizpos!='\x80' || (char)(krizpos[1]-krizrega)!='\xb0') {
		    cli_dbgmsg("kriz: bogus opcode or register\n");
		    break;
		}
		krizpos+=7;
		krizleft-=7;
		xckriz(&krizpos, &krizleft, 0, krizrega);
		if (! krizleft || (char)(*krizpos-krizrega)!='\x48') break; /* dec delta */
		krizpos++;
		krizleft--;
		cli_dbgmsg("kriz: dec delta found\n");
		xckriz(&krizpos, &krizleft, 0, krizregb);
		if (krizleft <4 || (char)(*krizpos-krizregb)!='\x48' || krizpos[1]!='\x75') break; /* dec size + jne loop */
		if (krizpos+3+(int)krizpos[2]<krizmov || krizpos+3+(int)krizpos[2]>krizxor) {
		    cli_dbgmsg("kriz: jmp back out of range (%d>%d>%d)\n", krizmov-(krizpos+3), (int)krizpos[2], krizxor-(krizpos+3));
		    break;
		}
		*ctx->virname = "Win32.Kriz";
		free(exe_sections);
		return CL_VIRUS;
	    }
	}
    }

    /* W32.Magistr.A/B */
    if(SCAN_ALGO && (DCONF & PE_CONF_MAGISTR) && !dll && (nsections>1) && (exe_sections[nsections - 1].chr & 0x80000000)) {
	    uint32_t rsize, vsize, dam = 0;

	vsize = exe_sections[nsections - 1].uvsz;
	rsize = exe_sections[nsections - 1].rsz;
	if(rsize < exe_sections[nsections - 1].ursz) {
	    rsize = exe_sections[nsections - 1].ursz;
	    dam = 1;
	}

	if(vsize >= 0x612c && rsize >= 0x612c && ((vsize & 0xff) == 0xec)) {
		int bw = rsize < 0x7000 ? rsize : 0x7000;

	    lseek(desc, exe_sections[nsections - 1].raw + rsize - bw, SEEK_SET);
	    if(cli_readn(desc, buff, 4096) == 4096) {
		if(cli_memstr(buff, 4091, "\xe8\x2c\x61\x00\x00", 5)) {
		    *ctx->virname = dam ? "W32.Magistr.A.dam" : "W32.Magistr.A";
		    free(exe_sections);
		    return CL_VIRUS;
		} 
	    }

	} else if(rsize >= 0x7000 && vsize >= 0x7000 && ((vsize & 0xff) == 0xed)) {
		int bw = rsize < 0x8000 ? rsize : 0x8000;

	    lseek(desc, exe_sections[nsections - 1].raw + rsize - bw, SEEK_SET);
	    if(cli_readn(desc, buff, 4096) == 4096) {
		if(cli_memstr(buff, 4091, "\xe8\x04\x72\x00\x00", 5)) {
		    *ctx->virname = dam ? "W32.Magistr.B.dam" : "W32.Magistr.B";
		    free(exe_sections);
		    return CL_VIRUS;
		} 
	    }
	}
    }

    /* W32.Polipos.A */
   if(polipos && !dll && nsections > 2 && nsections < 13 && e_lfanew <= 0x800 && (EC16(optional_hdr32.Subsystem) == 2 || EC16(optional_hdr32.Subsystem) == 3) && EC16(file_hdr.Machine) == 0x14c && optional_hdr32.SizeOfStackReserve >= 0x80000) {
		uint32_t remaining = exe_sections[0].rsz;
		uint32_t chunk = sizeof(buff);
		uint32_t val, shift, raddr, total = 0;
		const char *jpt;
		struct offset_list *offlist = NULL, *offnode;


	cli_dbgmsg("Detected W32.Polipos.A characteristics\n");

	if(remaining < chunk)
	    chunk = remaining;

	lseek(desc, exe_sections[0].raw, SEEK_SET);
	while((bytes = cli_readn(desc, buff, chunk)) > 0) {
	    shift = 0;
	    while((uint32_t)bytes - 5 > shift) {
		jpt = buff + shift;
		if(*jpt!='\xe9' && *jpt!='\xe8') {
		    shift++;
		    continue;
		}
		val = cli_readint32(jpt + 1);
		val += 5 + exe_sections[0].rva + total + shift;
		raddr = cli_rawaddr(val, exe_sections, nsections, &err, fsize, hdr_size);

		if(!err && (raddr >= exe_sections[polipos].raw && raddr < exe_sections[polipos].raw + exe_sections[polipos].rsz) && (!offlist || (raddr != offlist->offset))) {
		    offnode = (struct offset_list *) cli_malloc(sizeof(struct offset_list));
		    if(!offnode) {
			free(exe_sections);
			while(offlist) {
			    offnode = offlist;
			    offlist = offlist->next;
			    free(offnode);
			}
			return CL_EMEM;
		    }
		    offnode->offset = raddr;
		    offnode->next = offlist;
		    offlist = offnode;
		}

		shift++;
	    }

	    if(remaining < chunk) {
		chunk = remaining;
	    } else {
		remaining -= bytes;
		if(remaining < chunk) {
		    chunk = remaining;
		}
	    }

	    if(!remaining)
		break;

	    total += bytes;
	}

	offnode = offlist;
	while(offnode) {
	    cli_dbgmsg("Polipos: Checking offset 0x%x (%u)", offnode->offset, offnode->offset);
	    lseek(desc, offnode->offset, SEEK_SET);
	    if(cli_readn(desc, buff, 9) == 9) {
		ubuff = (unsigned char *) buff;
		if(ubuff[0] == 0x55 && ubuff[1] == 0x8b && ubuff[2] == 0xec &&
		   ((ubuff[3] == 0x83 && ubuff[4] == 0xec && ubuff[6] == 0x60) ||  ubuff[3] == 0x60 ||
		     (ubuff[3] == 0x81 && ubuff[4] == 0xec && ubuff[7] == 0x00 && ubuff[8] == 0x00))) {
		    ret = CL_VIRUS;
		    *ctx->virname = "W32.Polipos.A";
		    break;
		}
	    }

	    offnode = offnode->next;
	}

	while(offlist) {
	    offnode = offlist;
	    offlist = offlist->next;
	    free(offnode);
	}

	if(ret == CL_VIRUS) {
	    free(exe_sections);
	    return CL_VIRUS;
	}
    }

    /* SUE */
    
    if((DCONF & PE_CONF_SUE) && nsections > 2 && vep == exe_sections[nsections - 1].rva && exe_sections[nsections - 1].rsz > 0x350 && exe_sections[nsections - 1].rsz < 0x292+0x350+1000) {
  
      
      char *sue=buff+0x74;
      uint32_t key = 0;
      
      if(lseek(desc, ep-4, SEEK_SET) == -1) {
	cli_dbgmsg("SUE: lseek() failed\n");
	free(exe_sections);
	return CL_EIO;
      }
      if((unsigned int) cli_readn(desc, buff, exe_sections[nsections - 1].rsz+4) == exe_sections[nsections - 1].rsz+4) {
	found=0;
	while(CLI_ISCONTAINED(buff+4, exe_sections[nsections - 1].rsz, sue, 4*3)) {
	  if((cli_readint32(sue)^cli_readint32(sue+4))==0x5c41090e && (cli_readint32(sue)^cli_readint32(sue+8))==0x021e0145) {
	    found=1;
	    key=(cli_readint32(sue)^0x6e72656b);
	    break;
	  }
	  sue++;
	}
	cli_dbgmsg("SUE: key(%x) found @%x\n", key, sue-buff);
	if (found && CLI_ISCONTAINED(buff, exe_sections[nsections - 1].rsz, sue-0x74, 0xbe) &&
	    (sue=sudecrypt(desc, fsize, exe_sections, nsections-1, sue, key, cli_readint32(buff), e_lfanew))) {
	  if(!(tempfile = cli_gentemp(NULL))) {
	    free(sue);
	    free(exe_sections);
	    return CL_EMEM;
	  }

	  if((ndesc = open(tempfile, O_RDWR|O_CREAT|O_TRUNC|O_BINARY, S_IRWXU)) < 0) {
	    cli_dbgmsg("sue: Can't create file %s\n", tempfile);
	    free(tempfile);
	    free(sue);
	    free(exe_sections);
	    return CL_EIO;
	  }
	  
	  if((unsigned int) cli_writen(ndesc, sue, ep) != ep) {
	    cli_dbgmsg("sue: Can't write %d bytes\n", ep);
	    close(ndesc);
	    free(tempfile);
	    free(sue);
	    free(exe_sections);
	    return CL_EIO;
	  }

	  free(sue);
	  if (cli_leavetemps_flag)
	    cli_dbgmsg("SUE: Decrypted executable saved in %s\n", tempfile);
	  else
	    cli_dbgmsg("SUE: Executable decrypted\n");
	  fsync(ndesc);
	  lseek(ndesc, 0, SEEK_SET);

	  if(cli_magic_scandesc(ndesc, ctx) == CL_VIRUS) {
	    free(exe_sections);
	    close(ndesc);
	    if(!cli_leavetemps_flag)
	      unlink(tempfile);
	    free(tempfile);
	    return CL_VIRUS;
	  }
	  close(ndesc);
	  if(!cli_leavetemps_flag)
	    unlink(tempfile);
	  free(tempfile);
	}
      }

    }

    /* UPX, FSG, MEW support */

    /* try to find the first section with physical size == 0 */
    found = 0;
    if(DCONF & (PE_CONF_UPX | PE_CONF_FSG | PE_CONF_MEW)) {
	for(i = 0; i < (unsigned int) nsections - 1; i++) {
	    if(!exe_sections[i].rsz && exe_sections[i].vsz && exe_sections[i + 1].rsz && exe_sections[i + 1].vsz) {
		found = 1;
		cli_dbgmsg("UPX/FSG/MEW: empty section found - assuming compression\n");
		break;
	    }
	}
    }

    /* MEW support */
    if (found && (DCONF & PE_CONF_MEW)) {
	uint32_t fileoffset;
	/* Check EP for MEW */
	if(lseek(desc, ep, SEEK_SET) == -1) {
	    cli_dbgmsg("MEW: lseek() failed\n");
	    free(exe_sections);
	    return CL_EIO;
	}

        if((bytes = read(desc, buff, 25)) != 25 && bytes < 16) {
	    cli_dbgmsg("MEW: Can't read at least 16 bytes at 0x%x (%d) %d\n", ep, ep, bytes);
	    cli_dbgmsg("MEW: Broken or not compressed file\n");
	    free(exe_sections);
	    return CL_CLEAN;
	}

	fileoffset = (vep + cli_readint32(buff + 1) + 5);
	do {
	    if (found && (buff[0] == '\xe9') && (fileoffset == 0x154 || fileoffset == 0x158))
	    {
		uint32_t offdiff, uselzma;

		cli_dbgmsg ("MEW characteristics found: %08X + %08X + 5 = %08X\n", 
			cli_readint32(buff + 1), vep, cli_readint32(buff + 1) + vep + 5);

		if(lseek(desc, fileoffset, SEEK_SET) == -1) {
		    cli_dbgmsg("MEW: lseek() failed\n");
		    free(exe_sections);
		    return CL_EIO;
		}

		if((bytes = read(desc, buff, 0xb0)) != 0xb0) {
		    cli_dbgmsg("MEW: Can't read 0xb0 bytes at 0x%x (%d) %d\n", fileoffset, fileoffset, bytes);
		    break;
		}

		if (fileoffset == 0x154) 
		    cli_dbgmsg("MEW: Win9x compatibility was set!\n");
		else
		    cli_dbgmsg("MEW: Win9x compatibility was NOT set!\n");

		/* is it always 0x1C and 0x21C or not */
		if((offdiff = cli_readint32(buff+1) - EC32(optional_hdr32.ImageBase)) <= exe_sections[i + 1].rva || offdiff >= exe_sections[i + 1].rva + exe_sections[i + 1].raw - 4)
		{
		    cli_dbgmsg("MEW: ESI is not in proper section\n");
		    break;
		}
		offdiff -= exe_sections[i + 1].rva;

		if(lseek(desc, exe_sections[i + 1].raw, SEEK_SET) == -1) {
		    cli_dbgmsg("MEW: lseek() failed\n"); /* ACAB: lseek won't fail here but checking doesn't hurt even */
		    free(exe_sections);
		    return CL_EIO;
		}
		ssize = exe_sections[i + 1].vsz;
		dsize = exe_sections[i].vsz;

		cli_dbgmsg("MEW: ssize %08x dsize %08x offdiff: %08x\n", ssize, dsize, offdiff);
		if(ctx->limits && ctx->limits->maxfilesize && (ssize + dsize > ctx->limits->maxfilesize || exe_sections[i + 1].rsz > ctx->limits->maxfilesize)) {
		    cli_dbgmsg("MEW: Sizes exceeded (ssize: %u, dsize: %u, max: %lu)\n", ssize, dsize , ctx->limits->maxfilesize);
		    free(exe_sections);
		    if(BLOCKMAX) {
			*ctx->virname = "PE.MEW.ExceededFileSize";
			return CL_VIRUS;
		    } else {
			return CL_CLEAN;
		    }
		}

		/* allocate needed buffer */
		if (!(src = cli_calloc (ssize + dsize, sizeof(char)))) {
		    free(exe_sections);
		    return CL_EMEM;
		}

		if (exe_sections[i + 1].rsz < offdiff + 12 || exe_sections[i + 1].rsz > ssize)
		{
		    cli_dbgmsg("MEW: Size mismatch: %08x\n", exe_sections[i + 1].rsz);
		    free(src);
		    break;
		}

		if((bytes = read(desc, src + dsize, exe_sections[i + 1].rsz)) != exe_sections[i + 1].rsz) {
		    cli_dbgmsg("MEW: Can't read %d bytes [readed: %d]\n", exe_sections[i + 1].rsz, bytes);
		    free(exe_sections);
		    free(src);
		    return CL_EIO;
		}
		cli_dbgmsg("MEW: %d (%08x) bytes read\n", bytes, bytes);
		/* count offset to lzma proc, if lzma used, 0xe8 -> call */
		if (buff[0x7b] == '\xe8')
		{
		    if (!CLI_ISCONTAINED(exe_sections[1].rva, exe_sections[1].vsz, cli_readint32(buff + 0x7c) + fileoffset + 0x80, 4))
		    {
			cli_dbgmsg("MEW: lzma proc out of bounds!\n");
			free(src);
			break; /* to next unpacker in chain */
		    }
		    uselzma = cli_readint32(buff + 0x7c) - (exe_sections[0].rva - fileoffset - 0x80);
		} else
		    uselzma = 0;

		if(!(tempfile = cli_gentemp(NULL))) {
		    free(exe_sections);
		    free(src);
		    return CL_EMEM;
		}
		if((ndesc = open(tempfile, O_RDWR|O_CREAT|O_TRUNC, S_IRWXU)) < 0) {
		    cli_dbgmsg("MEW: Can't create file %s\n", tempfile);
		    free(tempfile);
		    free(exe_sections);
		    free(src);
		    return CL_EIO;
		}
		dest = src;
		switch(unmew11(i, src, offdiff, ssize, dsize, EC32(optional_hdr32.ImageBase), exe_sections[0].rva, uselzma, NULL, NULL, ndesc)) {
		    case 1: /* Everything OK */
			cli_dbgmsg("MEW: Unpacked and rebuilt executable saved in %s\n", tempfile);
			free(src);
			fsync(ndesc);
			lseek(ndesc, 0, SEEK_SET);

			cli_dbgmsg("***** Scanning rebuilt PE file *****\n");
			if(cli_magic_scandesc(ndesc, ctx) == CL_VIRUS) {
			    free(exe_sections);
			    close(ndesc);
			    if(!cli_leavetemps_flag)
				unlink(tempfile);
			    free(tempfile);
			    return CL_VIRUS;
			}
			close(ndesc);
			if(!cli_leavetemps_flag)
			    unlink(tempfile);
			free(tempfile);
			free(exe_sections);
			return CL_CLEAN;
		    default: /* Everything gone wrong */
			cli_dbgmsg("MEW: Unpacking failed\n");
			close(ndesc);
			unlink(tempfile); /* It's empty anyway */
			free(tempfile);
			free(src);
			break;
		}
	    }
	} while (0);
    }

    if(found || upack) {
	/* Check EP for UPX vs. FSG vs. Upack */
	if(lseek(desc, ep, SEEK_SET) == -1) {
	    cli_dbgmsg("UPX/FSG: lseek() failed\n");
	    free(exe_sections);
	    return CL_EIO;
	}

        if(cli_readn(desc, buff, 168) != 168) {
	    cli_dbgmsg("UPX/FSG: Can't read 168 bytes at 0x%x (%d)\n", ep, ep);
	    cli_dbgmsg("UPX/FSG: Broken or not UPX/FSG compressed file\n");
	    free(exe_sections);
	    return CL_CLEAN;
	}

	/* Upack 0.39 produces 2 types of executables
	 * 3 sections:           | 2 sections (one empty, I don't chech found if !upack, since it's in OR above):
	 *   mov esi, value      |   pusha
	 *   lodsd               |   call $+0x9
	 *   push eax            |
	 *
	 * Upack 1.1/1.2 Beta produces [based on 2 samples (sUx) provided by aCaB]:
	 * 2 sections
	 *   mov esi, value
	 *   loads
	 *   mov edi, eax
	 *
	 * Upack unknown [sample 0297729]
	 * 3 sections
	 *   mov esi, value
	 *   push [esi]
	 *   jmp
	 * 
	 */
	/* upack 0.39-3s + sample 0151477*/
 	if(((upack && nsections == 3) && /* 3 sections */
	    (
	     buff[0] == '\xbe' && cli_readint32(buff + 1) - EC32(optional_hdr32.ImageBase) > min && /* mov esi */
	     buff[5] == '\xad' && buff[6] == '\x50' /* lodsd; push eax */
	     )
	    || 
	    /* based on 0297729 sample from aCaB */
	    (buff[0] == '\xbe' && cli_readint32(buff + 1) - EC32(optional_hdr32.ImageBase) > min && /* mov esi */
	     buff[5] == '\xff' && buff[6] == '\x36' /* push [esi] */
	     )
	    ) 
	   ||
	   ((!upack && nsections == 2) && /* 2 sections */
	    ( /* upack 0.39-2s */
	     buff[0] == '\x60' && buff[1] == '\xe8' && cli_readint32(buff+2) == 0x9 /* pusha; call+9 */
	     )
	    ||
	    ( /* upack 1.1/1.2, based on 2 samples */
	     buff[0] == '\xbe' && cli_readint32(buff+1) - EC32(optional_hdr32.ImageBase) < min &&  /* mov esi */
	     cli_readint32(buff + 1) - EC32(optional_hdr32.ImageBase) > 0 &&
	     buff[5] == '\xad' && buff[6] == '\x8b' && buff[7] == '\xf8' /* loads;  mov edi, eax */
	     )
	    )
	   ){ 
		uint32_t vma, off;
		int a,b,c;

		cli_dbgmsg("Upack characteristics found.\n");
		a = exe_sections[0].vsz;
		b = exe_sections[1].vsz;
		if (upack) {
			cli_dbgmsg("Upack: var set\n");
			c = exe_sections[2].vsz;
			ssize = exe_sections[0].ursz + exe_sections[0].uraw;
			off = exe_sections[0].rva;
			vma = EC32(optional_hdr32.ImageBase) + exe_sections[0].rva;
		} else {
			cli_dbgmsg("Upack: var NOT set\n");
			c = exe_sections[1].rva;
			ssize = exe_sections[1].uraw;
			off = 0;
			vma = exe_sections[1].rva - exe_sections[1].uraw;
		}

		dsize = a+b+c;
		if (ctx->limits && ctx->limits->maxfilesize && (dsize > ctx->limits->maxfilesize || ssize > ctx->limits->maxfilesize || exe_sections[1].ursz > ctx->limits->maxfilesize))
		{
		    cli_dbgmsg("Upack: Sizes exceeded (a: %u, b: %u, c: %ux, max: %lu)\n", a, b, c, ctx->limits->maxfilesize);
		    free(exe_sections);
		    if(BLOCKMAX) {
			*ctx->virname = "PE.Upack.ExceededFileSize";
			return CL_VIRUS;
		    } else {
			return CL_CLEAN;
		    }
		}
		/* these are unsigned so if vaddr - off < 0, it should be ok */
		if (exe_sections[1].rva - off > dsize || exe_sections[1].rva - off > dsize - exe_sections[1].ursz || (upack && (exe_sections[2].rva - exe_sections[0].rva > dsize || exe_sections[2].rva - exe_sections[0].rva > dsize - ssize)) || ssize > dsize)
		{
		    cli_dbgmsg("Upack: probably malformed pe-header, skipping to next unpacker\n");
		    goto skip_upack_and_go_to_next_unpacker;
		}
			
		if((dest = (char *) cli_calloc(dsize, sizeof(char))) == NULL) {
		    free(exe_sections);
		    return CL_EMEM;
		}
		src = NULL;
	
		lseek(desc, 0, SEEK_SET);
		if(read(desc, dest, ssize) != ssize) {
		    cli_dbgmsg("Upack: Can't read raw data of section 0\n");
		    free(exe_sections);
		    free(dest);
		    return CL_EIO;
		}

		if (upack)
		    memmove(dest + exe_sections[2].rva - exe_sections[0].rva, dest, ssize);

		lseek(desc, exe_sections[1].uraw, SEEK_SET);

		if(read(desc, dest + exe_sections[1].rva - off, exe_sections[1].ursz) != exe_sections[1].ursz) {
		    cli_dbgmsg("Upack: Can't read raw data of section 1\n");
		    free(exe_sections);
		    free(dest);
		    return CL_EIO;
		}

		if(!(tempfile = cli_gentemp(NULL))) {
		    free(exe_sections);
		    free(dest);
		    return CL_EMEM;
		}

		if((ndesc = open(tempfile, O_RDWR|O_CREAT|O_TRUNC, S_IRWXU)) < 0) {
		    cli_dbgmsg("Upack: Can't create file %s\n", tempfile);
		    free(tempfile);
		    free(exe_sections);
		    free(dest);
		    return CL_EIO;
		}

		switch (unupack(upack, dest, dsize, buff, vma, ep, EC32(optional_hdr32.ImageBase), exe_sections[0].rva, ndesc))
		{
			case 1: /* Everything OK */
				cli_dbgmsg("Upack: Unpacked and rebuilt executable saved in %s\n", tempfile);
				free(dest);
				fsync(ndesc);
				lseek(ndesc, 0, SEEK_SET);

				cli_dbgmsg("***** Scanning rebuilt PE file *****\n");
				if(cli_magic_scandesc(ndesc, ctx) == CL_VIRUS) {
					free(exe_sections);
					close(ndesc);
					if(!cli_leavetemps_flag)
						unlink(tempfile);
					free(tempfile);
					return CL_VIRUS;
				}

				close(ndesc);
				if(!cli_leavetemps_flag)
					unlink(tempfile);
				free(tempfile);
				free(exe_sections);
				return CL_CLEAN;

			default: /* Everything gone wrong */
				cli_dbgmsg("Upack: Unpacking failed\n");
				close(ndesc);
				unlink(tempfile); /* It's empty anyway */
				free(tempfile);
				free(dest);
				break;
		}
	}
skip_upack_and_go_to_next_unpacker:

	if((DCONF & PE_CONF_FSG) && buff[0] == '\x87' && buff[1] == '\x25') {

	    /* FSG v2.0 support - thanks to aCaB ! */

	    ssize = exe_sections[i + 1].rsz;
	    dsize = exe_sections[i].vsz;

	    while(found) {
		    uint32_t newesi, newedi, newebx, newedx;

		if(ctx->limits && ctx->limits->maxfilesize && (ssize > ctx->limits->maxfilesize || dsize > ctx->limits->maxfilesize)) {
		    cli_dbgmsg("FSG: Sizes exceeded (ssize: %u, dsize: %u, max: %lu)\n", ssize, dsize , ctx->limits->maxfilesize);
		    free(exe_sections);
		    if(BLOCKMAX) {
			*ctx->virname = "PE.FSG.ExceededFileSize";
			return CL_VIRUS;
		    } else {
			return CL_CLEAN;
		    }
		}

		if(ssize <= 0x19 || dsize <= ssize) {
		    cli_dbgmsg("FSG: Size mismatch (ssize: %d, dsize: %d)\n", ssize, dsize);
		    free(exe_sections);
		    return CL_CLEAN;
		}

		newedx = cli_readint32(buff + 2) - EC32(optional_hdr32.ImageBase);
		if(!CLI_ISCONTAINED(exe_sections[i + 1].rva, exe_sections[i + 1].rsz, newedx, 4)) {
		    cli_dbgmsg("FSG: xchg out of bounds (%x), giving up\n", newedx);
		    break;
		}

		if((src = (char *) cli_malloc(ssize)) == NULL) {
		    free(exe_sections);
		    return CL_EMEM;
		}

		lseek(desc, exe_sections[i + 1].raw, SEEK_SET);
		if((unsigned int) cli_readn(desc, src, ssize) != ssize) {
		    cli_dbgmsg("Can't read raw data of section %d\n", i + 1);
		    free(exe_sections);
		    free(src);
		    return CL_EIO;
		}

		dest = src + newedx - exe_sections[i + 1].rva;
		if(newedx < exe_sections[i + 1].rva || !CLI_ISCONTAINED(src, ssize, dest, 4)) {
		    cli_dbgmsg("FSG: New ESP out of bounds\n");
		    free(src);
		    break;
		}

		newedx = cli_readint32(dest) - EC32(optional_hdr32.ImageBase);
		if(!CLI_ISCONTAINED(exe_sections[i + 1].rva, exe_sections[i + 1].rsz, newedx, 4)) {
		    cli_dbgmsg("FSG: New ESP (%x) is wrong\n", newedx);
		    free(src);
		    break;
		}
 
		dest = src + newedx - exe_sections[i + 1].rva;
		if(!CLI_ISCONTAINED(src, ssize, dest, 32)) {
		    cli_dbgmsg("FSG: New stack out of bounds\n");
		    free(src);
		    break;
		}

		newedi = cli_readint32(dest) - EC32(optional_hdr32.ImageBase);
		newesi = cli_readint32(dest + 4) - EC32(optional_hdr32.ImageBase);
		newebx = cli_readint32(dest + 16) - EC32(optional_hdr32.ImageBase);
		newedx = cli_readint32(dest + 20);

		if(newedi != exe_sections[i].rva) {
		    cli_dbgmsg("FSG: Bad destination buffer (edi is %x should be %x)\n", newedi, exe_sections[i].rva);
		    free(src);
		    break;
		}

		if(newesi < exe_sections[i + 1].rva || newesi - exe_sections[i + 1].rva >= exe_sections[i + 1].rsz) {
		    cli_dbgmsg("FSG: Source buffer out of section bounds\n");
		    free(src);
		    break;
		}

		if(!CLI_ISCONTAINED(exe_sections[i + 1].rva, exe_sections[i + 1].rsz, newebx, 16)) {
		    cli_dbgmsg("FSG: Array of functions out of bounds\n");
		    free(src);
		    break;
		}

		newedx=cli_readint32(newebx + 12 - exe_sections[i + 1].rva + src) - EC32(optional_hdr32.ImageBase);
		cli_dbgmsg("FSG: found old EP @%x\n",newedx);

		if((dest = (char *) cli_calloc(dsize, sizeof(char))) == NULL) {
		    free(exe_sections);
		    free(src);
		    return CL_EMEM;
		}

		if(!(tempfile = cli_gentemp(NULL))) {
		    free(exe_sections);
		    free(src);
		    free(dest);
		    return CL_EMEM;
		}

		if((ndesc = open(tempfile, O_RDWR|O_CREAT|O_TRUNC|O_BINARY, S_IRWXU)) < 0) {
		    cli_dbgmsg("FSG: Can't create file %s\n", tempfile);
		    free(tempfile);
		    free(exe_sections);
		    free(src);
		    free(dest);
		    return CL_EIO;
		}
		
		switch (unfsg_200(newesi - exe_sections[i + 1].rva + src, dest, ssize + exe_sections[i + 1].rva - newesi, dsize, newedi, EC32(optional_hdr32.ImageBase), newedx, ndesc)) {
		    case 1: /* Everything OK */
			cli_dbgmsg("FSG: Unpacked and rebuilt executable saved in %s\n", tempfile);
			free(src);
			free(dest);
			fsync(ndesc);
			lseek(ndesc, 0, SEEK_SET);

			cli_dbgmsg("***** Scanning rebuilt PE file *****\n");
			if(cli_magic_scandesc(ndesc, ctx) == CL_VIRUS) {
			    free(exe_sections);
			    close(ndesc);
			    if(!cli_leavetemps_flag)
				unlink(tempfile);
			    free(tempfile);
			    return CL_VIRUS;
			}

			close(ndesc);
			if(!cli_leavetemps_flag)
			    unlink(tempfile);
			free(tempfile);
			free(exe_sections);
			return CL_CLEAN;

		    case 0: /* We've got an unpacked buffer, no exe though */
			cli_dbgmsg("FSG: Successfully decompressed\n");
			close(ndesc);
			unlink(tempfile);
			free(tempfile);
			found = 0;
			upx_success = 1;
			break; /* Go and scan the buffer! */

		    default: /* Everything gone wrong */
			cli_dbgmsg("FSG: Unpacking failed\n");
			close(ndesc);
			unlink(tempfile); /* It's empty anyway */
			free(tempfile);
			free(src);
			free(dest);
			break;
		}

		break; /* were done with 2 */
	    }
	}

 	if(found && (DCONF & PE_CONF_FSG) && buff[0] == '\xbe' && cli_readint32(buff + 1) - EC32(optional_hdr32.ImageBase) < min) {

	    /* FSG support - v. 1.33 (thx trog for the many samples) */

	    ssize = exe_sections[i + 1].rsz;
	    dsize = exe_sections[i].vsz;

	    while(found) {
	            int sectcnt = 0;
		    char *support;
		    uint32_t newesi, newedi, newebx, oldep, gp, t;
		    struct cli_exe_section *sections;


		if(ctx->limits && ctx->limits->maxfilesize && (ssize > ctx->limits->maxfilesize || dsize > ctx->limits->maxfilesize)) {
		    cli_dbgmsg("FSG: Sizes exceeded (ssize: %u, dsize: %u, max: %lu)\n", ssize, dsize, ctx->limits->maxfilesize);
		    free(exe_sections);
		    if(BLOCKMAX) {
			*ctx->virname = "PE.FSG.ExceededFileSize";
			return CL_VIRUS;
		    } else {
			return CL_CLEAN;
		    }
		}

		if(ssize <= 0x19 || dsize <= ssize) {
		    cli_dbgmsg("FSG: Size mismatch (ssize: %d, dsize: %d)\n", ssize, dsize);
		    free(exe_sections);
		    return CL_CLEAN;
		}

		if(!(gp = cli_rawaddr(cli_readint32(buff + 1) - EC32(optional_hdr32.ImageBase), NULL, 0 , &err, fsize, hdr_size)) && err ) {
		    cli_dbgmsg("FSG: Support data out of padding area\n");
		    break;
		}

		lseek(desc, gp, SEEK_SET);
		gp = exe_sections[i + 1].raw - gp;

		if(ctx->limits && ctx->limits->maxfilesize && (unsigned int) gp > ctx->limits->maxfilesize) {
		    cli_dbgmsg("FSG: Buffer size exceeded (size: %d, max: %lu)\n", gp, ctx->limits->maxfilesize);
		    free(exe_sections);
		    if(BLOCKMAX) {
			*ctx->virname = "PE.FSG.ExceededFileSize";
			return CL_VIRUS;
		    } else {
			return CL_CLEAN;
		    }
		}

		if((support = (char *) cli_malloc(gp)) == NULL) {
		    free(exe_sections);
		    return CL_EMEM;
		}

		if((int)cli_readn(desc, support, gp) != (int)gp) {
		    cli_dbgmsg("Can't read %d bytes from padding area\n", gp); 
		    free(exe_sections);
		    free(support);
		    return CL_EIO;
		}

		/* newebx = cli_readint32(support) - EC32(optional_hdr32.ImageBase);  Unused */
		newedi = cli_readint32(support + 4) - EC32(optional_hdr32.ImageBase); /* 1st dest */
		newesi = cli_readint32(support + 8) - EC32(optional_hdr32.ImageBase); /* Source */

		if(newesi < exe_sections[i + 1].rva || newesi - exe_sections[i + 1].rva >= exe_sections[i + 1].rsz) {
		    cli_dbgmsg("FSG: Source buffer out of section bounds\n");
		    free(support);
		    break;
		}

		if(newedi != exe_sections[i].rva) {
		    cli_dbgmsg("FSG: Bad destination (is %x should be %x)\n", newedi, exe_sections[i].rva);
		    free(support);
		    break;
		}

		/* Counting original sections */
		for(t = 12; t < gp - 4; t += 4) {
			uint32_t rva = cli_readint32(support+t);

		    if(!rva)
			break;

		    rva -= EC32(optional_hdr32.ImageBase)+1;
		    sectcnt++;

		    if(rva % 0x1000)
			/* FIXME: really need to bother? */
			cli_dbgmsg("FSG: Original section %d is misaligned\n", sectcnt);

		    if(rva < exe_sections[i].rva || rva - exe_sections[i].rva >= exe_sections[i].vsz) {
			cli_dbgmsg("FSG: Original section %d is out of bounds\n", sectcnt);
			break;
		    }
		}

		if(t >= gp - 4 || cli_readint32(support + t)) {
		    free(support);
		    break;
		}

		if((sections = (struct cli_exe_section *) cli_malloc((sectcnt + 1) * sizeof(struct cli_exe_section))) == NULL) {
		    free(exe_sections);
		    free(support);
		    return CL_EMEM;
		}

		sections[0].rva = newedi;
		for(t = 1; t <= (uint32_t)sectcnt; t++)
		    sections[t].rva = cli_readint32(support + 8 + t * 4) - 1 - EC32(optional_hdr32.ImageBase);

		free(support);

		if((src = (char *) cli_malloc(ssize)) == NULL) {
		    free(exe_sections);
		    free(sections);
		    return CL_EMEM;
		}

		lseek(desc, exe_sections[i + 1].raw, SEEK_SET);
		if((unsigned int) cli_readn(desc, src, ssize) != ssize) {
		    cli_dbgmsg("Can't read raw data of section %d\n", i);
		    free(exe_sections);
		    free(sections);
		    free(src);
		    return CL_EIO;
		}

		if((dest = (char *) cli_calloc(dsize, sizeof(char))) == NULL) {
		    free(exe_sections);
		    free(src);
		    free(sections);
		    return CL_EMEM;
		}

		oldep = vep + 161 + 6 + cli_readint32(buff+163);
		cli_dbgmsg("FSG: found old EP @%x\n", oldep);

		if(!(tempfile = cli_gentemp(NULL))) {
		    free(exe_sections);
		    free(src);
		    free(dest);
		    free(sections);
		    return CL_EMEM;
		}

		if((ndesc = open(tempfile, O_RDWR|O_CREAT|O_TRUNC|O_BINARY, S_IRWXU)) < 0) {
		    cli_dbgmsg("FSG: Can't create file %s\n", tempfile);
		    free(tempfile);
		    free(exe_sections);
		    free(src);
		    free(dest);
		    free(sections);
		    return CL_EIO;
		}

		switch(unfsg_133(src + newesi - exe_sections[i + 1].rva, dest, ssize + exe_sections[i + 1].rva - newesi, dsize, sections, sectcnt, EC32(optional_hdr32.ImageBase), oldep, ndesc)) {
		    case 1: /* Everything OK */
			cli_dbgmsg("FSG: Unpacked and rebuilt executable saved in %s\n", tempfile);
			free(src);
			free(dest);
			free(sections);
			fsync(ndesc);
			lseek(ndesc, 0, SEEK_SET);

			cli_dbgmsg("***** Scanning rebuilt PE file *****\n");
			if(cli_magic_scandesc(ndesc, ctx) == CL_VIRUS) {
			    free(exe_sections);
			    close(ndesc);
			    if(!cli_leavetemps_flag)
				unlink(tempfile);
			    free(tempfile);
			    return CL_VIRUS;
			}

			close(ndesc);
			if(!cli_leavetemps_flag)
			    unlink(tempfile);
			free(tempfile);
			free(exe_sections);
			return CL_CLEAN;

		    case 0: /* We've got an unpacked buffer, no exe though */
			cli_dbgmsg("FSG: Successfully decompressed\n");
			close(ndesc);
			unlink(tempfile);
			free(tempfile);
			free(sections);
			found = 0;
			upx_success = 1;
			break; /* Go and scan the buffer! */

		    default: /* Everything gone wrong */
			cli_dbgmsg("FSG: Unpacking failed\n");
			close(ndesc);
			unlink(tempfile); /* It's empty anyway */
			free(tempfile);
			free(src);
			free(dest);
			free(sections);
			break;
		}

		break; /* were done with 1.33 */
	    }
	}

	/* FIXME: easy 2 hack */
 	if(found && (DCONF & PE_CONF_FSG) && buff[0] == '\xbb' && cli_readint32(buff + 1) - EC32(optional_hdr32.ImageBase) < min && buff[5] == '\xbf' && buff[10] == '\xbe' && vep >= exe_sections[i + 1].rva && vep - exe_sections[i + 1].rva > exe_sections[i + 1].rva - 0xe0 ) {

	    /* FSG support - v. 1.31 */

	    ssize = exe_sections[i + 1].rsz;
	    dsize = exe_sections[i].vsz;

	    while(found) {
		    int sectcnt = 0;
		    uint32_t t;
		    uint32_t gp = cli_rawaddr(cli_readint32(buff+1) - EC32(optional_hdr32.ImageBase), NULL, 0 , &err, fsize, hdr_size);
		    char *support;
		    uint32_t newesi = cli_readint32(buff+11) - EC32(optional_hdr32.ImageBase);
		    uint32_t newedi = cli_readint32(buff+6) - EC32(optional_hdr32.ImageBase);
		    uint32_t oldep = vep - exe_sections[i + 1].rva;
		    struct cli_exe_section *sections;

		if(err) {
		    cli_dbgmsg("FSG: Support data out of padding area\n");
		    break;
		}

		if(newesi < exe_sections[i + 1].rva || newesi - exe_sections[i + 1].rva >= exe_sections[i + 1].raw) {
		    cli_dbgmsg("FSG: Source buffer out of section bounds\n");
		    break;
		}

		if(newedi != exe_sections[i].rva) {
		    cli_dbgmsg("FSG: Bad destination (is %x should be %x)\n", newedi, exe_sections[i].rva);
		    break;
		}

		if(ctx->limits && ctx->limits->maxfilesize && (ssize > ctx->limits->maxfilesize || dsize > ctx->limits->maxfilesize)) {
		    cli_dbgmsg("FSG: Sizes exceeded (ssize: %u, dsize: %u, max: %lu)\n", ssize, dsize, ctx->limits->maxfilesize);
		    free(exe_sections);
		    if(BLOCKMAX) {
			*ctx->virname = "PE.FSG.ExceededFileSize";
			return CL_VIRUS;
		    } else {
			return CL_CLEAN;
		    }
		}

		if(ssize <= 0x19 || dsize <= ssize) {
		    cli_dbgmsg("FSG: Size mismatch (ssize: %d, dsize: %d)\n", ssize, dsize);
		    free(exe_sections);
		    return CL_CLEAN;
		}

		lseek(desc, gp, SEEK_SET);
		gp = exe_sections[i + 1].raw - gp;

		if(ctx->limits && ctx->limits->maxfilesize && gp > ctx->limits->maxfilesize) {
		    cli_dbgmsg("FSG: Buffer size exceeded (size: %d, max: %lu)\n", gp, ctx->limits->maxfilesize);
		    free(exe_sections);
		    if(BLOCKMAX) {
			*ctx->virname = "PE.FSG.ExceededFileSize";
			return CL_VIRUS;
		    } else {
			return CL_CLEAN;
		    }
		}

		if((support = (char *) cli_malloc(gp)) == NULL) {
		    free(exe_sections);
		    return CL_EMEM;
		}

		if(cli_readn(desc, support, gp) != (int)gp) {
		    cli_dbgmsg("Can't read %d bytes from padding area\n", gp); 
		    free(exe_sections);
		    free(support);
		    return CL_EIO;
		}

		/* Counting original sections */
		for(t = 0; t < gp - 2; t += 2) {
		  uint32_t rva = support[t]|(support[t+1]<<8);
		  
		  if (rva == 2 || rva == 1)
		    break;

		  rva = ((rva-2)<<12) - EC32(optional_hdr32.ImageBase);
		  sectcnt++;

		  if(rva < exe_sections[i].rva || rva - exe_sections[i].rva >= exe_sections[i].vsz) {
		    cli_dbgmsg("FSG: Original section %d is out of bounds\n", sectcnt);
		    break;
		  }
		}

		if(t >= gp-10 || cli_readint32(support + t + 6) != 2) {
		    free(support);
		    break;
		}

		if((sections = (struct cli_exe_section *) cli_malloc((sectcnt + 1) * sizeof(struct cli_exe_section))) == NULL) {
		    free(exe_sections);
		    free(support);
		    return CL_EMEM;
		}

		sections[0].rva = newedi;
		for(t = 0; t <= (uint32_t)sectcnt - 1; t++) {
		  sections[t+1].rva = (((support[t*2]|(support[t*2+1]<<8))-2)<<12)-EC32(optional_hdr32.ImageBase);
		}

		free(support);

		if((src = (char *) cli_malloc(ssize)) == NULL) {
		    free(exe_sections);
		    free(sections);
		    return CL_EMEM;
		}

		lseek(desc, exe_sections[i + 1].raw, SEEK_SET);
		if((unsigned int) cli_readn(desc, src, ssize) != ssize) {
		    cli_dbgmsg("FSG: Can't read raw data of section %d\n", i);
		    free(exe_sections);
		    free(sections);
		    free(src);
		    return CL_EIO;
		}

		if((dest = (char *) cli_calloc(dsize, sizeof(char))) == NULL) {
		    free(exe_sections);
		    free(src);
		    free(sections);
		    return CL_EMEM;
		}

		/* Better not increasing buff size any further, let's go the hard way */
		gp = 0xda + 6*(buff[16]=='\xe8');
		oldep = vep + gp + 6 + cli_readint32(src+gp+2+oldep);
		cli_dbgmsg("FSG: found old EP @%x\n", oldep);

		if(!(tempfile = cli_gentemp(NULL))) {
		    free(exe_sections);
		    free(src);
		    free(dest);
		    free(sections);
		    return CL_EMEM;
		}

		if((ndesc = open(tempfile, O_RDWR|O_CREAT|O_TRUNC|O_BINARY, S_IRWXU)) < 0) {
		    cli_dbgmsg("FSG: Can't create file %s\n", tempfile);
		    free(tempfile);
		    free(exe_sections);
		    free(src);
		    free(dest);
		    free(sections);
		    return CL_EIO;
		}

		switch(unfsg_133(src + newesi - exe_sections[i + 1].rva, dest, ssize + exe_sections[i + 1].rva - newesi, dsize, sections, sectcnt, EC32(optional_hdr32.ImageBase), oldep, ndesc)) {
		    case 1: /* Everything OK */
			cli_dbgmsg("FSG: Unpacked and rebuilt executable saved in %s\n", tempfile);
			free(src);
			free(dest);
			free(sections);
			fsync(ndesc);
			lseek(ndesc, 0, SEEK_SET);

			cli_dbgmsg("***** Scanning rebuilt PE file *****\n");
			if(cli_magic_scandesc(ndesc, ctx) == CL_VIRUS) {
			    free(exe_sections);
			    close(ndesc);
			    if(!cli_leavetemps_flag)
				unlink(tempfile);
			    free(tempfile);
			    return CL_VIRUS;
			}

			close(ndesc);
			if(!cli_leavetemps_flag)
			    unlink(tempfile);
			free(tempfile);
			free(exe_sections);
			return CL_CLEAN;

		    case 0: /* We've got an unpacked buffer, no exe though */
			cli_dbgmsg("FSG: FSG: Successfully decompressed\n");
			close(ndesc);
			unlink(tempfile);
			free(tempfile);
			free(sections);
			found = 0;
			upx_success = 1;
			break; /* Go and scan the buffer! */

		    default: /* Everything gone wrong */
			cli_dbgmsg("FSG: Unpacking failed\n");
			close(ndesc);
			unlink(tempfile); /* It's empty anyway */
			free(tempfile);
			free(src);
			free(dest);
			free(sections);
			break;
		}

		break; /* were done with 1.31 */
	    }
	}


	if(found && (DCONF & PE_CONF_UPX)) {

	    /* UPX support */

	    /* we assume (i + 1) is UPX1 */
	    ssize = exe_sections[i + 1].rsz;
	    dsize = exe_sections[i].vsz + exe_sections[i + 1].vsz;

	    if(ctx->limits && ctx->limits->maxfilesize && (ssize > ctx->limits->maxfilesize || dsize > ctx->limits->maxfilesize)) {
		cli_dbgmsg("UPX: Sizes exceeded (ssize: %u, dsize: %u, max: %lu)\n", ssize, dsize , ctx->limits->maxfilesize);
		free(exe_sections);
		if(BLOCKMAX) {
		    *ctx->virname = "PE.UPX.ExceededFileSize";
		    return CL_VIRUS;
		} else {
		    return CL_CLEAN;
		}
	    }

	    if(ssize <= 0x19 || dsize <= ssize) { /* FIXME: What are reasonable values? */
		cli_dbgmsg("UPX: Size mismatch (ssize: %d, dsize: %d)\n", ssize, dsize);
		free(exe_sections);
		return CL_CLEAN;
	    }

	    if((src = (char *) cli_malloc(ssize)) == NULL) {
		free(exe_sections);
		return CL_EMEM;
	    }

	    if(dsize > CLI_MAX_ALLOCATION) {
		cli_errmsg("UPX: Too big value of dsize\n");
		free(exe_sections);
		free(src);
		return CL_EMEM;
	    }

	    if((dest = (char *) cli_calloc(dsize + 8192, sizeof(char))) == NULL) {
		free(exe_sections);
		free(src);
		return CL_EMEM;
	    }

	    lseek(desc, exe_sections[i + 1].raw, SEEK_SET);
	    if((unsigned int) cli_readn(desc, src, ssize) != ssize) {
		cli_dbgmsg("UPX: Can't read raw data of section %d\n", i+1);
		free(exe_sections);
		free(src);
		free(dest);
		return CL_EIO;
	    }

	    /* try to detect UPX code */

	    if(lseek(desc, ep, SEEK_SET) == -1) {
		cli_dbgmsg("UPX: lseek() failed\n");
		free(exe_sections);
		free(src);
		free(dest);
		return CL_EIO;
	    }

	    if(cli_readn(desc, buff, 126) != 126) { /* i.e. 0x69 + 13 + 8 */
		cli_dbgmsg("UPX: Can't read 126 bytes at 0x%x (%d)\n", ep, ep);
		cli_dbgmsg("UPX: Broken or not UPX compressed file\n");
		free(exe_sections);
		free(src);
		free(dest);
		return CL_CLEAN;
	    } else {
		if(cli_memstr(UPX_NRV2B, 24, buff + 0x69, 13) || cli_memstr(UPX_NRV2B, 24, buff + 0x69 + 8, 13)) {
		    cli_dbgmsg("UPX: Looks like a NRV2B decompression routine\n");
		    upxfn = upx_inflate2b;
		} else if(cli_memstr(UPX_NRV2D, 24, buff + 0x69, 13) || cli_memstr(UPX_NRV2D, 24, buff + 0x69 + 8, 13)) {
		    cli_dbgmsg("UPX: Looks like a NRV2D decompression routine\n");
		    upxfn = upx_inflate2d;
		} else if(cli_memstr(UPX_NRV2E, 24, buff + 0x69, 13) || cli_memstr(UPX_NRV2E, 24, buff + 0x69 + 8, 13)) {
		    cli_dbgmsg("UPX: Looks like a NRV2E decompression routine\n");
		    upxfn = upx_inflate2e;
		}
	    }

	    if(upxfn) {
		    int skew = cli_readint32(buff + 2) - EC32(optional_hdr32.ImageBase) - exe_sections[i + 1].rva;

		if(buff[1] != '\xbe' || skew <= 0 || skew > 0xfff) { /* FIXME: legit skews?? */
		    skew = 0; 
		    if(upxfn(src, ssize, dest, &dsize, exe_sections[i].rva, exe_sections[i + 1].rva, vep) >= 0)
			upx_success = 1;

		} else {
		    cli_dbgmsg("UPX: UPX1 seems skewed by %d bytes\n", skew);
                    if(upxfn(src + skew, ssize - skew, dest, &dsize, exe_sections[i].rva, exe_sections[i + 1].rva, vep-skew) >= 0 || upxfn(src, ssize, dest, &dsize, exe_sections[i].rva, exe_sections[i + 1].rva, vep) >= 0)
			upx_success = 1;
		}

		if(upx_success)
		    cli_dbgmsg("UPX: Successfully decompressed\n");
		else
		    cli_dbgmsg("UPX: Preferred decompressor failed\n");
	    }

	    if(!upx_success && upxfn != upx_inflate2b) {
		if(upx_inflate2b(src, ssize, dest, &dsize, exe_sections[i].rva, exe_sections[i + 1].rva, vep) == -1 && upx_inflate2b(src + 0x15, ssize - 0x15, dest, &dsize, exe_sections[i].rva, exe_sections[i + 1].rva, vep - 0x15) == -1) {

		    cli_dbgmsg("UPX: NRV2B decompressor failed\n");
		} else {
		    upx_success = 1;
		    cli_dbgmsg("UPX: Successfully decompressed with NRV2B\n");
		}
	    }

	    if(!upx_success && upxfn != upx_inflate2d) {
		if(upx_inflate2d(src, ssize, dest, &dsize, exe_sections[i].rva, exe_sections[i + 1].rva, vep) == -1 && upx_inflate2d(src + 0x15, ssize - 0x15, dest, &dsize, exe_sections[i].rva, exe_sections[i + 1].rva, vep - 0x15) == -1) {

		    cli_dbgmsg("UPX: NRV2D decompressor failed\n");
		} else {
		    upx_success = 1;
		    cli_dbgmsg("UPX: Successfully decompressed with NRV2D\n");
		}
	    }

	    if(!upx_success && upxfn != upx_inflate2e) {
		if(upx_inflate2e(src, ssize, dest, &dsize, exe_sections[i].rva, exe_sections[i + 1].rva, vep) == -1 && upx_inflate2e(src + 0x15, ssize - 0x15, dest, &dsize, exe_sections[i].rva, exe_sections[i + 1].rva, vep - 0x15) == -1) {
		    cli_dbgmsg("UPX: NRV2E decompressor failed\n");
		} else {
		    upx_success = 1;
		    cli_dbgmsg("UPX: Successfully decompressed with NRV2E\n");
		}
	    }

	    if(!upx_success) {
		cli_dbgmsg("UPX: All decompressors failed\n");
		free(src);
		free(dest);
	    }
	}

	if(upx_success) {
	    free(src);
	    free(exe_sections);

	    if(!(tempfile = cli_gentemp(NULL))) {
	        free(dest);
		return CL_EMEM;
	    }

	    if((ndesc = open(tempfile, O_RDWR|O_CREAT|O_TRUNC|O_BINARY, S_IRWXU)) < 0) {
		cli_dbgmsg("UPX/FSG: Can't create file %s\n", tempfile);
		free(tempfile);
		free(dest);
		return CL_EIO;
	    }

	    if((unsigned int) write(ndesc, dest, dsize) != dsize) {
		cli_dbgmsg("UPX/FSG: Can't write %d bytes\n", dsize);
		free(tempfile);
		free(dest);
		close(ndesc);
		return CL_EIO;
	    }

	    free(dest);
	    fsync(ndesc);
	    lseek(ndesc, 0, SEEK_SET);

	    if(cli_leavetemps_flag)
		cli_dbgmsg("UPX/FSG: Decompressed data saved in %s\n", tempfile);

	    cli_dbgmsg("***** Scanning decompressed file *****\n");
	    if((ret = cli_magic_scandesc(ndesc, ctx)) == CL_VIRUS) {
		close(ndesc);
		if(!cli_leavetemps_flag)
		    unlink(tempfile);
		free(tempfile);
		return CL_VIRUS;
	    }

	    close(ndesc);
	    if(!cli_leavetemps_flag)
		unlink(tempfile);
	    free(tempfile);
	    return ret;
	}
    }

    /* Petite */

    found = 2;

    lseek(desc, ep, SEEK_SET);
    memset(buff, 0, sizeof(buff));
    if(cli_readn(desc, buff, 200) == -1) {
	cli_dbgmsg("cli_readn() failed\n");
	free(exe_sections);
	return CL_EIO;
    }

    if(buff[0] != '\xb8' || (uint32_t) cli_readint32(buff + 1) != exe_sections[nsections - 1].rva + EC32(optional_hdr32.ImageBase)) {
	if(nsections < 2 || buff[0] != '\xb8' || (uint32_t) cli_readint32(buff + 1) != exe_sections[nsections - 2].rva + EC32(optional_hdr32.ImageBase))
	    found = 0;
	else
	    found = 1;
    }

    if((DCONF & PE_CONF_PETITE) && found) {
	cli_dbgmsg("Petite: v2.%d compression detected\n", found);

	if(cli_readint32(buff + 0x80) == 0x163c988d) {
	    cli_dbgmsg("Petite: level zero compression is not supported yet\n");
	} else {
	    dsize = max - min;

	    if(ctx->limits && ctx->limits->maxfilesize && dsize > ctx->limits->maxfilesize) {
		cli_dbgmsg("Petite: Size exceeded (dsize: %u, max: %lu)\n", dsize, ctx->limits->maxfilesize);
		free(exe_sections);
		if(BLOCKMAX) {
		    *ctx->virname = "PE.Petite.ExceededFileSize";
		    return CL_VIRUS;
		} else {
		    return CL_CLEAN;
		}
	    }

	    if((dest = (char *) cli_calloc(dsize, sizeof(char))) == NULL) {
		cli_dbgmsg("Petite: Can't allocate %d bytes\n", dsize);
		free(exe_sections);
		return CL_EMEM;
	    }

	    for(i = 0 ; i < nsections; i++) {
		if(exe_sections[i].raw) {
		  uint32_t offset = exe_sections[i].raw;

		  if(lseek(desc, offset, SEEK_SET) == -1 || (unsigned int) cli_readn(desc, dest + exe_sections[i].rva - min, exe_sections[i].ursz) != exe_sections[i].ursz) {
			free(exe_sections);
			free(dest);
			return CL_EIO;
		    }
		}
	    }

	    if(!(tempfile = cli_gentemp(NULL))) {
	      free(dest);
	      free(exe_sections);
	      return CL_EMEM;
	    }

	    if((ndesc = open(tempfile, O_RDWR|O_CREAT|O_TRUNC|O_BINARY, S_IRWXU)) < 0) {
		cli_dbgmsg("Petite: Can't create file %s\n", tempfile);
		free(tempfile);
		free(exe_sections);
		free(dest);
		return CL_EIO;
	    }

	    /* aCaB: Fixed to allow petite v2.1 unpacking (last section is a ghost) */
	    if (!petite_inflate2x_1to9(dest, min, max - min, exe_sections,
		    nsections - (found == 1 ? 1 : 0), EC32(optional_hdr32.ImageBase),
		    vep, ndesc, found, EC32(optional_hdr32.DataDirectory[2].VirtualAddress),
		    EC32(optional_hdr32.DataDirectory[2].Size))) {
	        cli_dbgmsg("Petite: Unpacked and rebuilt executable saved in %s\n", tempfile);
		cli_dbgmsg("***** Scanning rebuilt PE file *****\n");
		free(dest);
		fsync(ndesc);
		lseek(ndesc, 0, SEEK_SET);
		if(cli_magic_scandesc(ndesc, ctx) == CL_VIRUS) {
		    free(exe_sections);
		    close(ndesc);
		    if(!cli_leavetemps_flag) {
		        unlink(tempfile);
		    }
		    free(tempfile);
		    return CL_VIRUS;
		}

	    } else {
	        cli_dbgmsg("Petite: Unpacking failed\n");
		free(dest);
	    }
	    close(ndesc);
	    if(!cli_leavetemps_flag) {
	        unlink(tempfile);
	    }
	    free(tempfile);
	}
    }

    /* PESpin 1.1 */

    if((DCONF & PE_CONF_PESPIN) && nsections > 1 &&
       vep >= exe_sections[nsections - 1].rva &&
       vep < exe_sections[nsections - 1].rva + exe_sections[nsections - 1].rsz - 0x3217 - 4 &&
       memcmp(buff+4, "\xe8\x00\x00\x00\x00\x8b\x1c\x24\x83\xc3", 10) == 0)  {

	    char *spinned;

	if(ctx->limits && ctx->limits->maxfilesize && fsize > ctx->limits->maxfilesize) {
	    cli_dbgmsg("PEspin: Size exceeded (fsize: %u, max: %lu)\n", fsize, ctx->limits->maxfilesize);
	    free(exe_sections);
	    if(BLOCKMAX) {
		*ctx->virname = "PE.Pespin.ExceededFileSize";
		return CL_VIRUS;
	    } else {
		return CL_CLEAN;
	    }
	}

	if((spinned = (char *) cli_malloc(fsize)) == NULL) {
	    free(exe_sections);
	    return CL_EMEM;
	}

	lseek(desc, 0, SEEK_SET);
	if((size_t) cli_readn(desc, spinned, fsize) != fsize) {
	    cli_dbgmsg("PESpin: Can't read %d bytes\n", fsize);
	    free(spinned);
	    free(exe_sections);
	    return CL_EIO;
	}

	if(!(tempfile = cli_gentemp(NULL))) {
	  free(spinned);
	  free(exe_sections);
	  return CL_EMEM;
	}

	if((ndesc = open(tempfile, O_RDWR|O_CREAT|O_TRUNC|O_BINARY, S_IRWXU)) < 0) {
	    cli_dbgmsg("PESpin: Can't create file %s\n", tempfile);
	    free(tempfile);
	    free(spinned);
	    free(exe_sections);
	    return CL_EIO;
	}

	switch(unspin(spinned, fsize, exe_sections, nsections - 1, vep, ndesc, ctx)) {
	case 0:
	    free(spinned);
	    if(cli_leavetemps_flag)
		cli_dbgmsg("PESpin: Unpacked and rebuilt executable saved in %s\n", tempfile);
	    else
		cli_dbgmsg("PESpin: Unpacked and rebuilt executable\n");
	    fsync(ndesc);
	    lseek(ndesc, 0, SEEK_SET);
	    if(cli_magic_scandesc(ndesc, ctx) == CL_VIRUS) {
		close(ndesc);
		if(!cli_leavetemps_flag)
		    unlink(tempfile);
	        free(tempfile);
		free(exe_sections);
		return CL_VIRUS;
	    }
	    close(ndesc);
   	    if(!cli_leavetemps_flag)
		unlink(tempfile);
	    break;
	case 1:
	    free(spinned);
	    close(ndesc);
	    unlink(tempfile);
	    cli_dbgmsg("PESpin: Rebuilding failed\n");
	    break;
	case 2:
	    free(spinned);
	    close(ndesc);
	    unlink(tempfile);
	    cli_dbgmsg("PESpin: Size exceeded\n");
	    if(BLOCKMAX) {
		free(tempfile);
		free(exe_sections);
		*ctx->virname = "PE.Pespin.ExceededFileSize";
		return CL_VIRUS;
	    }
	}
	free(tempfile);
	
    }


    /* yC 1.3 */

    if((DCONF & PE_CONF_YC) && nsections > 1 &&
       EC32(optional_hdr32.AddressOfEntryPoint) == exe_sections[nsections - 1].rva + 0x60 &&
       memcmp(buff, "\x55\x8B\xEC\x53\x56\x57\x60\xE8\x00\x00\x00\x00\x5D\x81\xED\x6C\x28\x40\x00\xB9\x5D\x34\x40\x00\x81\xE9\xC6\x28\x40\x00\x8B\xD5\x81\xC2\xC6\x28\x40\x00\x8D\x3A\x8B\xF7\x33\xC0\xEB\x04\x90\xEB\x01\xC2\xAC", 51) == 0)  {

	    char *spinned;

	if ( fsize >= exe_sections[nsections - 1].raw + 0xC6 + 0xb97 ) { /* size check on yC sect */
	  if((spinned = (char *) cli_malloc(fsize)) == NULL) {
	    free(exe_sections);
	    return CL_EMEM;
	  }

	  lseek(desc, 0, SEEK_SET);
	  if((size_t) cli_readn(desc, spinned, fsize) != fsize) {
	    cli_dbgmsg("yC: Can't read %d bytes\n", fsize);
	    free(spinned);
	    free(exe_sections);
	    return CL_EIO;
	  }

	  if(!(tempfile = cli_gentemp(NULL))) {
	    free(spinned);
	    free(exe_sections);
	    return CL_EMEM;
	  }

	  if((ndesc = open(tempfile, O_RDWR|O_CREAT|O_TRUNC|O_BINARY, S_IRWXU)) < 0) {
	    cli_dbgmsg("yC: Can't create file %s\n", tempfile);
	    free(tempfile);
	    free(spinned);
	    free(exe_sections);
	    return CL_EIO;
	  }

	  if(!yc_decrypt(spinned, fsize, exe_sections, nsections-1, e_lfanew, ndesc)) {
	    free(spinned);
	    cli_dbgmsg("yC: Unpacked and rebuilt executable saved in %s\n", tempfile);
	    fsync(ndesc);
	    lseek(ndesc, 0, SEEK_SET);
	    
	    if(cli_magic_scandesc(ndesc, ctx) == CL_VIRUS) {
	      free(exe_sections);
	      close(ndesc);
	      if(!cli_leavetemps_flag) {
		unlink(tempfile);
		free(tempfile);
	      } else {
		free(tempfile);
	      }
	      return CL_VIRUS;
	    }
	    
	  } else {
	    free(spinned);
	    cli_dbgmsg("yC: Rebuilding failed\n");
	  }
	  
	  close(ndesc);
	  if(!cli_leavetemps_flag) {
	    unlink(tempfile);
	    free(tempfile);
	  } else {
	    free(tempfile);
	  }

	}
    }


    /* WWPack */

    if((DCONF & PE_CONF_WWPACK) && nsections > 1 &&
       exe_sections[nsections-1].raw>0x2b1 &&
       vep == exe_sections[nsections - 1].rva &&
       exe_sections[nsections - 1].rva + exe_sections[nsections - 1].rsz == max &&
       memcmp(buff, "\x53\x55\x8b\xe8\x33\xdb\xeb", 7) == 0 &&
       memcmp(buff+0x68, "\xe8\x00\x00\x00\x00\x58\x2d\x6d\x00\x00\x00\x50\x60\x33\xc9\x50\x58\x50\x50", 19) == 0)  {
      uint32_t headsize=exe_sections[nsections - 1].raw;
      char *dest, *wwp;

      for(i = 0 ; i < (unsigned int)nsections-1; i++)
	if (exe_sections[i].raw<headsize) headsize=exe_sections[i].raw;
      
      dsize = max-min+headsize-exe_sections[nsections - 1].rsz;

      if(ctx->limits && ctx->limits->maxfilesize && dsize > ctx->limits->maxfilesize) {
	cli_dbgmsg("WWPack: Size exceeded (dsize: %u, max: %lu)\n", dsize, ctx->limits->maxfilesize);
	free(exe_sections);
	if(BLOCKMAX) {
	  *ctx->virname = "PE.WWPack.ExceededFileSize";
	  return CL_VIRUS;
	} else {
	  return CL_CLEAN;
	}
      }

      if((dest = (char *) cli_calloc(dsize, sizeof(char))) == NULL) {
	cli_dbgmsg("WWPack: Can't allocate %d bytes\n", dsize);
	free(exe_sections);
	return CL_EMEM;
      }

      lseek(desc, 0, SEEK_SET);
      if((size_t) cli_readn(desc, dest, headsize) != headsize) {
	cli_dbgmsg("WWPack: Can't read %d bytes from headers\n", headsize);
	free(dest);
	free(exe_sections);
	return CL_EIO;
      }

      for(i = 0 ; i < (unsigned int)nsections-1; i++) {
	if(exe_sections[i].rsz) {
	  uint32_t offset = exe_sections[i].raw;
	  
	  if(lseek(desc, offset, SEEK_SET) == -1 || (unsigned int) cli_readn(desc, dest + headsize + exe_sections[i].rva - min, exe_sections[i].rsz) != exe_sections[i].rsz) {
	    free(dest);
	    free(exe_sections);
	    return CL_EIO;
	  }
	}
      }

      if((wwp = (char *) cli_calloc(exe_sections[nsections - 1].rsz, sizeof(char))) == NULL) {
	cli_dbgmsg("WWPack: Can't allocate %d bytes\n", exe_sections[nsections - 1].rsz);
	free(dest);
	free(exe_sections);
	return CL_EMEM;
      }

      lseek(desc, exe_sections[nsections - 1].raw, SEEK_SET);
      if((size_t) cli_readn(desc, wwp, exe_sections[nsections - 1].rsz) != exe_sections[nsections - 1].rsz) {
	cli_dbgmsg("WWPack: Can't read %d bytes from wwpack sect\n", exe_sections[nsections - 1].rsz);
	free(dest);
	free(wwp);
	free(exe_sections);
	return CL_EIO;
      }

      if (!wwunpack(dest, dsize, headsize, min, exe_sections[nsections-1].rva, e_lfanew, wwp, exe_sections[nsections - 1].rsz, nsections-1)) {
	
	free(wwp);

	if(!(tempfile = cli_gentemp(NULL))) {
	  free(dest);
	  free(exe_sections);
	  return CL_EMEM;
	}

	if((ndesc = open(tempfile, O_RDWR|O_CREAT|O_TRUNC|O_BINARY, S_IRWXU)) < 0) {
	  cli_dbgmsg("WWPack: Can't create file %s\n", tempfile);
	  free(tempfile);
	  free(dest);
	  free(exe_sections);
	  return CL_EIO;
	}

	if((unsigned int) write(ndesc, dest, dsize) != dsize) {
	  cli_dbgmsg("WWPack: Can't write %d bytes\n", dsize);
	  close(ndesc);
	  free(tempfile);
	  free(dest);
	  free(exe_sections);
	  return CL_EIO;
	}

	free(dest);
	if (cli_leavetemps_flag)
	  cli_dbgmsg("WWPack: Unpacked and rebuilt executable saved in %s\n", tempfile);
	else
	  cli_dbgmsg("WWPack: Unpacked and rebuilt executable\n");

	fsync(ndesc);
	lseek(ndesc, 0, SEEK_SET);

	if(cli_magic_scandesc(ndesc, ctx) == CL_VIRUS) {
	  free(exe_sections);
	  close(ndesc);
	  if(!cli_leavetemps_flag)
	    unlink(tempfile);
	  free(tempfile);
	  return CL_VIRUS;
	}

	close(ndesc);
	if(!cli_leavetemps_flag)
	  unlink(tempfile);
	free(tempfile);
      } else {
	free(wwp);
	free(dest);
	cli_dbgmsg("WWPpack: Decompression failed\n");
      }
    }

    /* ASPACK support */
    while((DCONF & PE_CONF_ASPACK) && ep+58+0x70e < fsize && !memcmp(buff,"\x60\xe8\x03\x00\x00\x00\xe9\xeb",8)) {
        char nbuff[6];

        if(lseek(desc, ep+0x3b9, SEEK_SET) == -1) break;
        if(cli_readn(desc, nbuff, 6)!=6) break;
        if(memcmp(nbuff, "\x68\x00\x00\x00\x00\xc3",6)) break;
	ssize = 0;
	for(i=0 ; i< nsections ; i++)
	  if(ssize<exe_sections[i].rva+exe_sections[i].vsz)
	    ssize=exe_sections[i].rva+exe_sections[i].vsz;
	if(!ssize) break;
        if(ctx->limits && ctx->limits->maxfilesize && ssize > ctx->limits->maxfilesize) {
            cli_dbgmsg("Pe.Aspack: Size exceeded\n");
            free(exe_sections);
            if(BLOCKMAX) {
                *ctx->virname = "Pe.Aspack.ExceededFileSize";
                return CL_VIRUS;
            } else {
              return CL_CLEAN;
            }
        }
        if(!(src=(char *)cli_calloc(ssize, sizeof(char)))) {
	    free(exe_sections);
	    return CL_EMEM;
	}
        for(i = 0 ; i < (unsigned int)nsections; i++) {
	    if(!exe_sections[i].rsz) continue;
	    if(lseek(desc, exe_sections[i].raw, SEEK_SET) == -1) break;
            if(!CLI_ISCONTAINED(src, ssize, src+exe_sections[i].rva, exe_sections[i].rsz)) break;
            if(cli_readn(desc, src+exe_sections[i].rva, exe_sections[i].rsz)!=exe_sections[i].rsz) break;
        }
        if(i!=nsections) {
            cli_dbgmsg("Aspack: Probably hacked/damaged Aspack file.\n");
            free(src);
            break;
        }
	if(!(tempfile = cli_gentemp(NULL))) {
	  free(exe_sections);
	  free(src);
	  return CL_EMEM;
	}
	if((ndesc = open(tempfile, O_RDWR|O_CREAT|O_TRUNC|O_BINARY, S_IRWXU)) < 0) {
	  cli_dbgmsg("Aspack: Can't create file %s\n", tempfile);
	  free(tempfile);
	  free(exe_sections);
	  free(src);
	  return CL_EIO;
	}
	if (unaspack212((uint8_t *)src, ssize, exe_sections, nsections, vep-1, EC32(optional_hdr32.ImageBase), ndesc)) {
	  free(src);
	  cli_dbgmsg("Aspack: Dumped to %s\n", tempfile);
	  fsync(ndesc);
	  lseek(ndesc, 0, SEEK_SET);
	  if(cli_magic_scandesc(ndesc, ctx) == CL_VIRUS) {
	      free(exe_sections);
	      close(ndesc);
	      if(!cli_leavetemps_flag)
		  unlink(tempfile);
	      free(tempfile);
	      return CL_VIRUS;
	  }
	} else {
	  free(src);
	}

	close(ndesc);
	if(!cli_leavetemps_flag)
	  unlink(tempfile);
	free(tempfile);

	break;
    }

    /* NsPack */

    while (DCONF & PE_CONF_NSPACK) {
      uint32_t eprva = vep;
      uint32_t start_of_stuff, ssize, dsize, rep = ep;
      unsigned int nowinldr;
      char nbuff[24];
      char *src=buff, *dest;

      if (*buff=='\xe9') { /* bitched headers */
	eprva = cli_readint32(buff+1)+vep+5;
	if (!(rep = cli_rawaddr(eprva, exe_sections, nsections, &err, fsize, hdr_size)) && err) break;
	if (lseek(desc, rep, SEEK_SET)==-1) break;
	if (cli_readn(desc, nbuff, 24)!=24) break;
	src = nbuff;
      }

      if (memcmp(src, "\x9c\x60\xe8\x00\x00\x00\x00\x5d\xb8\x07\x00\x00\x00", 13)) break;

      nowinldr = 0x54-cli_readint32(src+17);
      cli_dbgmsg("NsPack: Found *start_of_stuff @delta-%x\n", nowinldr);

      if (lseek(desc, rep-nowinldr, SEEK_SET)==-1) break;
      if (cli_readn(desc, nbuff, 4)!=4) break;
      start_of_stuff=rep+cli_readint32(nbuff);
      if (lseek(desc, start_of_stuff, SEEK_SET)==-1) break;
      if (cli_readn(desc, nbuff, 20)!=20) break;
      src = nbuff;
      if (!cli_readint32(nbuff)) {
	start_of_stuff+=4; /* FIXME: more to do */
	src+=4;
      }

      ssize = cli_readint32(src+5)|0xff;
      dsize = cli_readint32(src+9);

      if(ctx->limits && ctx->limits->maxfilesize && (ssize > ctx->limits->maxfilesize || dsize > ctx->limits->maxfilesize)) {
	cli_dbgmsg("NsPack: Size exceeded\n");
	free(exe_sections);
	if(BLOCKMAX) {
	  *ctx->virname = "PE.NsPack.ExceededFileSize";
	  return CL_VIRUS;
	} else {
	  return CL_CLEAN;
	}
      }

      if ( !ssize || !dsize || dsize != exe_sections[0].vsz) break;
      if (lseek(desc, start_of_stuff, SEEK_SET)==-1) break;
      if (!(dest=cli_malloc(dsize))) break;
      /* memset(dest, 0xfc, dsize); */

      if (!(src=cli_malloc(ssize))) {
	free(dest);
	break;
      }
      /* memset(src, 0x00, ssize); */
      cli_readn(desc, src, ssize);

      eprva+=0x27a;
      if (!(rep = cli_rawaddr(eprva, exe_sections, nsections, &err, fsize, hdr_size)) && err) break;
      if (lseek(desc, rep, SEEK_SET)==-1) break;
      if (cli_readn(desc, nbuff, 5)!=5) break;
      eprva=eprva+5+cli_readint32(nbuff+1);
      cli_dbgmsg("NsPack: OEP = %08x\n", eprva);

      if(!(tempfile = cli_gentemp(NULL))) {
	free(src);
	free(dest);
	free(exe_sections);
	return CL_EMEM;
      }

      if((ndesc = open(tempfile, O_RDWR|O_CREAT|O_TRUNC|O_BINARY, S_IRWXU)) < 0) {
	cli_dbgmsg("NsPack: Can't create file %s\n", tempfile);
	free(tempfile);
	free(src);
	free(dest);
	free(exe_sections);
	return CL_EIO;
      }

      if (!unspack(src, dest, ctx, exe_sections[0].rva, EC32(optional_hdr32.ImageBase), eprva, ndesc)) {
	free(src);
	free(dest);
	if (cli_leavetemps_flag)
	  cli_dbgmsg("NsPack: Unpacked and rebuilt executable saved in %s\n", tempfile);
	else
	  cli_dbgmsg("NsPack: Unpacked and rebuilt executable\n");
	fsync(ndesc);
	lseek(ndesc, 0, SEEK_SET);

	if(cli_magic_scandesc(ndesc, ctx) == CL_VIRUS) {
	  free(exe_sections);
	  close(ndesc);
	  if(!cli_leavetemps_flag) unlink(tempfile);
	  free(tempfile);
	  return CL_VIRUS;
	}
      } else {
	free(src);
	free(dest);
	cli_dbgmsg("NsPack: Unpacking failed\n");
      }
      close(ndesc);
      if(!cli_leavetemps_flag) unlink(tempfile);
      free(tempfile);
      break;
    }

    /* to be continued ... */

    free(exe_sections);
    return CL_CLEAN;
}

int cli_peheader(int desc, struct cli_exe_info *peinfo)
{
	uint16_t e_magic; /* DOS signature ("MZ") */
	uint32_t e_lfanew; /* address of new exe header */
	/* Obsolete - see below
	  uint32_t min = 0, max = 0;
	*/
	struct pe_image_file_hdr file_hdr;
	union {
	    struct pe_image_optional_hdr64 opt64;
	    struct pe_image_optional_hdr32 opt32;
	} pe_opt;
	struct pe_image_section_hdr *section_hdr;
	struct stat sb;
	int i;
	unsigned int err, pe_plus = 0;
	uint32_t valign, falign, hdr_size;
	size_t fsize;

    cli_dbgmsg("in cli_peheader\n");

    if(fstat(desc, &sb) == -1) {
	cli_dbgmsg("fstat failed\n");
	return -1;
    }

    fsize = sb.st_size - peinfo->offset;

    if(cli_readn(desc, &e_magic, sizeof(e_magic)) != sizeof(e_magic)) {
	cli_dbgmsg("Can't read DOS signature\n");
	return -1;
    }

    if(EC16(e_magic) != IMAGE_DOS_SIGNATURE && EC16(e_magic) != IMAGE_DOS_SIGNATURE_OLD) {
	cli_dbgmsg("Invalid DOS signature\n");
	return -1;
    }

    lseek(desc, 58, SEEK_CUR); /* skip to the end of the DOS header */

    if(cli_readn(desc, &e_lfanew, sizeof(e_lfanew)) != sizeof(e_lfanew)) {
	cli_dbgmsg("Can't read new header address\n");
	/* truncated header? */
	return -1;
    }

    e_lfanew = EC32(e_lfanew);
    if(!e_lfanew) {
	cli_dbgmsg("Not a PE file\n");
	return -1;
    }

    if(lseek(desc, peinfo->offset + e_lfanew, SEEK_SET) < 0) {
	/* probably not a PE file */
	cli_dbgmsg("Can't lseek to e_lfanew\n");
	return -1;
    }

    if(cli_readn(desc, &file_hdr, sizeof(struct pe_image_file_hdr)) != sizeof(struct pe_image_file_hdr)) {
	/* bad information in e_lfanew - probably not a PE file */
	cli_dbgmsg("Can't read file header\n");
	return -1;
    }

    if(EC32(file_hdr.Magic) != IMAGE_NT_SIGNATURE) {
	cli_dbgmsg("Invalid PE signature (probably NE file)\n");
	return -1;
    }

    if ( (peinfo->nsections = EC16(file_hdr.NumberOfSections)) < 1 || peinfo->nsections > 96 ) return -1;

    if (EC16(file_hdr.SizeOfOptionalHeader) < sizeof(struct pe_image_optional_hdr32)) {
        cli_dbgmsg("SizeOfOptionalHeader too small\n");
	return -1;
    }

    if(cli_readn(desc, &optional_hdr32, sizeof(struct pe_image_optional_hdr32)) != sizeof(struct pe_image_optional_hdr32)) {
        cli_dbgmsg("Can't read optional file header\n");
	return -1;
    }

    if(EC32(optional_hdr64.Magic)==PE32P_SIGNATURE) { /* PE+ */
        if(EC16(file_hdr.SizeOfOptionalHeader)!=sizeof(struct pe_image_optional_hdr64)) {
	    cli_dbgmsg("Incorrect SizeOfOptionalHeader for PE32+\n");
	    return -1;
	}
        if(cli_readn(desc, &optional_hdr32 + 1, sizeof(struct pe_image_optional_hdr64) - sizeof(struct pe_image_optional_hdr32)) != sizeof(struct pe_image_optional_hdr64) - sizeof(struct pe_image_optional_hdr32)) {
	    cli_dbgmsg("Can't read optional file header\n");
	    return -1;
	}
	hdr_size = EC32(optional_hdr64.SizeOfHeaders);
	pe_plus=1;
    } else { /* PE */
	if (EC16(file_hdr.SizeOfOptionalHeader)!=sizeof(struct pe_image_optional_hdr32)) {
	    /* Seek to the end of the long header */
	    lseek(desc, (EC16(file_hdr.SizeOfOptionalHeader)-sizeof(struct pe_image_optional_hdr32)), SEEK_CUR);
	}
	hdr_size = EC32(optional_hdr32.SizeOfHeaders);
    }

    valign = (pe_plus)?EC32(optional_hdr64.SectionAlignment):EC32(optional_hdr32.SectionAlignment);
    falign = (pe_plus)?EC32(optional_hdr64.FileAlignment):EC32(optional_hdr32.FileAlignment);

    hdr_size = PESALIGN(hdr_size, valign);

    peinfo->section = (struct cli_exe_section *) cli_calloc(peinfo->nsections, sizeof(struct cli_exe_section));

    if(!peinfo->section) {
	cli_dbgmsg("Can't allocate memory for section headers\n");
	return -1;
    }

    section_hdr = (struct pe_image_section_hdr *) cli_calloc(peinfo->nsections, sizeof(struct pe_image_section_hdr));

    if(!section_hdr) {
	cli_dbgmsg("Can't allocate memory for section headers\n");
	free(peinfo->section);
	peinfo->section = NULL;
	return -1;
    }

    if(cli_readn(desc, section_hdr, peinfo->nsections * sizeof(struct pe_image_section_hdr)) != peinfo->nsections * sizeof(struct pe_image_section_hdr)) {
        cli_dbgmsg("Can't read section header\n");
	cli_dbgmsg("Possibly broken PE file\n");
	free(section_hdr);
	free(peinfo->section);
	peinfo->section = NULL;
	return -1;
    }

    for(i = 0; falign!=0x200 && i<peinfo->nsections; i++) {
	/* file alignment fallback mode - blah */
	if (falign && section_hdr[i].SizeOfRawData && EC32(section_hdr[i].PointerToRawData)%falign && !(EC32(section_hdr[i].PointerToRawData)%0x200)) {
	    falign = 0x200;
	}
    }

    for(i = 0; i < peinfo->nsections; i++) {
        peinfo->section[i].rva = PEALIGN(EC32(section_hdr[i].VirtualAddress), valign);
	peinfo->section[i].vsz = PESALIGN(EC32(section_hdr[i].VirtualSize), valign);
	peinfo->section[i].raw = PEALIGN(EC32(section_hdr[i].PointerToRawData), falign);
	peinfo->section[i].rsz = PESALIGN(EC32(section_hdr[i].SizeOfRawData), falign);

	if (!peinfo->section[i].vsz && peinfo->section[i].rsz)
	    peinfo->section[i].vsz=PESALIGN(EC32(section_hdr[i].SizeOfRawData), valign);

	if (peinfo->section[i].rsz && !CLI_ISCONTAINED(0, (uint32_t) fsize, peinfo->section[i].raw, peinfo->section[i].rsz))
	    peinfo->section[i].rsz = (fsize - peinfo->section[i].raw)*(fsize>peinfo->section[i].raw);
    }

    if(pe_plus)
	peinfo->ep = EC32(optional_hdr64.AddressOfEntryPoint);
    else
	peinfo->ep = EC32(optional_hdr32.AddressOfEntryPoint);

    if(!(peinfo->ep = cli_rawaddr(peinfo->ep, peinfo->section, peinfo->nsections, &err, fsize, hdr_size)) && err) {
	cli_dbgmsg("Broken PE file\n");
	free(section_hdr);
	free(peinfo->section);
	peinfo->section = NULL;
	return -1;
    }

    free(section_hdr);
    return 0;
}

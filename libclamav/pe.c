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
#include "wwunpack.h"
#include "suecrypt.h"
#include "unsp.h"
#include "scanners.h"
#include "rebuildpe.h"
#include "str.h"
#include "execs.h"
#include "md5.h"

#ifndef	O_BINARY
#define	O_BINARY	0
#endif

#define IMAGE_DOS_SIGNATURE	    0x5a4d	    /* MZ */
#define IMAGE_DOS_SIGNATURE_OLD	    0x4d5a          /* ZM */
#define IMAGE_NT_SIGNATURE	    0x00004550
#define PE32_SIGNATURE		    0x010b
#define PE32P_SIGNATURE		    0x020b

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

static uint32_t cli_rawaddr(uint32_t rva, struct pe_image_section_hdr *shp, uint16_t nos, unsigned int *err, uint32_t valign, uint32_t falign)
{
	int i, found = 0;


    for(i = 0; i < nos; i++) {
      if(PEALIGN(EC32(shp[i].VirtualAddress), valign) <= rva && PEALIGN(EC32(shp[i].VirtualAddress), valign) + PESALIGN(EC32(shp[i].SizeOfRawData), falign) > rva) {
	    found = 1;
	    break;
	}
    }

    if(!found) {
	*err = 1;
	return 0;
    }

    *err = 0;
    return rva - PEALIGN(EC32(shp[i].VirtualAddress), valign) + PEALIGN(EC32(shp[i].PointerToRawData), falign);
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

static unsigned char *cli_md5sect(int fd, uint32_t offset, uint32_t size)
{
	size_t bread, sum = 0;
	off_t pos;
	char buff[FILEBUFF];
	unsigned char *digest;
	MD5_CTX md5ctx;


    if((pos = lseek(fd, 0, SEEK_CUR)) == -1) {
	cli_dbgmsg("cli_md5sect: Invalid descriptor %d\n", fd);
	return NULL;
    }

    if(lseek(fd, offset, SEEK_SET) == -1) {
	cli_dbgmsg("cli_md5sect: lseek() failed\n");
	lseek(fd, pos, SEEK_SET);
	return NULL;
    }

    digest = cli_calloc(16, sizeof(char));
    if(!digest) {
	cli_errmsg("cli_md5sect: Can't allocate memory for digest\n");
	return NULL;
    }

    MD5_Init(&md5ctx);

    while((bread = cli_readn(fd, buff, FILEBUFF)) > 0) {
	if(sum + bread >= size) {
	    MD5_Update(&md5ctx, buff, size - sum);
	    break;
	} else {
	    MD5_Update(&md5ctx, buff, bread);
	    sum += bread;
	}
    }

    MD5_Final(digest, &md5ctx);
    lseek(fd, pos, SEEK_SET);
    return digest;
}

int cli_scanpe(int desc, cli_ctx *ctx)
{
	uint16_t e_magic; /* DOS signature ("MZ") */
	uint16_t nsections;
	uint32_t e_lfanew; /* address of new exe header */
	uint32_t ep; /* entry point (raw) */
	uint8_t polipos = 0;
	time_t timestamp;
	struct pe_image_file_hdr file_hdr;
	struct pe_image_optional_hdr32 optional_hdr32;
	struct pe_image_optional_hdr64 optional_hdr64;
	struct pe_image_section_hdr *section_hdr;
	struct cli_md5_node *md5_sect;
	struct stat sb;
	char sname[9], buff[4096], *tempfile;
	unsigned char *ubuff, *md5_dig;
	ssize_t bytes;
	unsigned int i, found, upx_success = 0, min = 0, max = 0, err, broken = 0;
	unsigned int ssize = 0, dsize = 0, dll = 0, pe_plus = 0;
	int (*upxfn)(char *, uint32_t, char *, uint32_t *, uint32_t, uint32_t, uint32_t) = NULL;
	char *src = NULL, *dest = NULL;
	int ndesc, ret = CL_CLEAN;
	size_t fsize;


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
    if(nsections < 1 || nsections > 99) {
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

    if(EC16(file_hdr.SizeOfOptionalHeader) != sizeof(struct pe_image_optional_hdr32) && EC16(file_hdr.SizeOfOptionalHeader)!=0x148) {
	if(EC16(file_hdr.SizeOfOptionalHeader) == sizeof(struct pe_image_optional_hdr64)) {
	    pe_plus = 1;
	} else {
	    cli_dbgmsg("Incorrect value of SizeOfOptionalHeader\n");
	    if(DETECT_BROKEN) {
		if(ctx->virname)
		    *ctx->virname = "Broken.Executable";
		return CL_VIRUS;
	    }
	    return CL_CLEAN;
	}
    }

    if(!pe_plus) { /* PE */

	if(cli_readn(desc, &optional_hdr32, sizeof(struct pe_image_optional_hdr32)) != sizeof(struct pe_image_optional_hdr32)) {
	    cli_dbgmsg("Can't read optional file header\n");
	    if(DETECT_BROKEN) {
		if(ctx->virname)
		    *ctx->virname = "Broken.Executable";
		return CL_VIRUS;
	    }
	    return CL_CLEAN;
	}
	if (EC16(file_hdr.SizeOfOptionalHeader)==0x148) {
	  cli_dbgmsg("Found long header\n");
	  lseek(desc, (0x148-0xe0), SEEK_CUR); /* Seek to the end of the long header */
	}

	if(EC16(optional_hdr32.Magic) != PE32_SIGNATURE) {
	    cli_warnmsg("Incorrect magic number in optional header\n");
	    if(DETECT_BROKEN) {
		if(ctx->virname)
		    *ctx->virname = "Broken.Executable";
		return CL_VIRUS;
	    }
	}
	cli_dbgmsg("File format: PE\n");

	cli_dbgmsg("MajorLinkerVersion: %d\n", optional_hdr32.MajorLinkerVersion);
	cli_dbgmsg("MinorLinkerVersion: %d\n", optional_hdr32.MinorLinkerVersion);
	cli_dbgmsg("SizeOfCode: %d\n", EC32(optional_hdr32.SizeOfCode));
	cli_dbgmsg("SizeOfInitializedData: %d\n", EC32(optional_hdr32.SizeOfInitializedData));
	cli_dbgmsg("SizeOfUninitializedData: %d\n", EC32(optional_hdr32.SizeOfUninitializedData));
	cli_dbgmsg("AddressOfEntryPoint: 0x%x\n", EC32(optional_hdr32.AddressOfEntryPoint));
	cli_dbgmsg("BaseOfCode: 0x%x\n", EC32(optional_hdr32.BaseOfCode));
	cli_dbgmsg("SectionAlignment: %d\n", EC32(optional_hdr32.SectionAlignment));
	cli_dbgmsg("FileAlignment: %d\n", EC32(optional_hdr32.FileAlignment));
	cli_dbgmsg("MajorSubsystemVersion: %d\n", EC16(optional_hdr32.MajorSubsystemVersion));
	cli_dbgmsg("MinorSubsystemVersion: %d\n", EC16(optional_hdr32.MinorSubsystemVersion));
	cli_dbgmsg("SizeOfImage: %d\n", EC32(optional_hdr32.SizeOfImage));
	cli_dbgmsg("SizeOfHeaders: %d\n", EC32(optional_hdr32.SizeOfHeaders));
	cli_dbgmsg("NumberOfRvaAndSizes: %d\n", EC32(optional_hdr32.NumberOfRvaAndSizes));

    } else { /* PE+ */

	if(cli_readn(desc, &optional_hdr64, sizeof(struct pe_image_optional_hdr64)) != sizeof(struct pe_image_optional_hdr64)) {
	    cli_dbgmsg("Can't optional file header\n");
	    if(DETECT_BROKEN) {
		if(ctx->virname)
		    *ctx->virname = "Broken.Executable";
		return CL_VIRUS;
	    }
	    return CL_CLEAN;
	}

	if(EC16(optional_hdr64.Magic) != PE32P_SIGNATURE) {
	    cli_warnmsg("Incorrect magic number in optional header\n");
	    if(DETECT_BROKEN) {
		if(ctx->virname)
		    *ctx->virname = "Broken.Executable";
		return CL_VIRUS;
	    }
	}
	cli_dbgmsg("File format: PE32+\n");

	cli_dbgmsg("MajorLinkerVersion: %d\n", optional_hdr64.MajorLinkerVersion);
	cli_dbgmsg("MinorLinkerVersion: %d\n", optional_hdr64.MinorLinkerVersion);
	cli_dbgmsg("SizeOfCode: %d\n", EC32(optional_hdr64.SizeOfCode));
	cli_dbgmsg("SizeOfInitializedData: %d\n", EC32(optional_hdr64.SizeOfInitializedData));
	cli_dbgmsg("SizeOfUninitializedData: %d\n", EC32(optional_hdr64.SizeOfUninitializedData));
	cli_dbgmsg("AddressOfEntryPoint: 0x%x\n", EC32(optional_hdr64.AddressOfEntryPoint));
	cli_dbgmsg("BaseOfCode: 0x%x\n", EC32(optional_hdr64.BaseOfCode));
	cli_dbgmsg("SectionAlignment: %d\n", EC32(optional_hdr64.SectionAlignment));
	cli_dbgmsg("FileAlignment: %d\n", EC32(optional_hdr64.FileAlignment));
	cli_dbgmsg("MajorSubsystemVersion: %d\n", EC16(optional_hdr64.MajorSubsystemVersion));
	cli_dbgmsg("MinorSubsystemVersion: %d\n", EC16(optional_hdr64.MinorSubsystemVersion));
	cli_dbgmsg("SizeOfImage: %d\n", EC32(optional_hdr64.SizeOfImage));
	cli_dbgmsg("SizeOfHeaders: %d\n", EC32(optional_hdr64.SizeOfHeaders));
	cli_dbgmsg("NumberOfRvaAndSizes: %d\n", EC32(optional_hdr64.NumberOfRvaAndSizes));
    }

    if (DETECT_BROKEN && (!(pe_plus?EC32(optional_hdr64.SectionAlignment):EC32(optional_hdr32.SectionAlignment)) || (pe_plus?EC32(optional_hdr64.SectionAlignment):EC32(optional_hdr32.SectionAlignment))%0x1000)) {
      cli_dbgmsg("Bad virtual alignemnt\n");
      if(ctx->virname)
	*ctx->virname = "Broken.Executable";
      return CL_VIRUS;
    }

    if (DETECT_BROKEN && (!(pe_plus?EC32(optional_hdr64.FileAlignment):EC32(optional_hdr32.FileAlignment)) || (pe_plus?EC32(optional_hdr64.FileAlignment):EC32(optional_hdr32.FileAlignment))%0x200)) {
      cli_dbgmsg("Bad file alignemnt\n");
      if(ctx->virname)
	*ctx->virname = "Broken.Executable";
      return CL_VIRUS;
    }

    switch(pe_plus ? EC16(optional_hdr64.Subsystem) : EC16(optional_hdr32.Subsystem)) {
	case 0:
	    cli_dbgmsg("Subsystem: Unknown\n");
	    break;
	case 1:
	    cli_dbgmsg("Subsystem: Native (a driver ?)\n");
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

    for(i = 0; i < nsections; i++) {

	if(cli_readn(desc, &section_hdr[i], sizeof(struct pe_image_section_hdr)) != sizeof(struct pe_image_section_hdr)) {
	    cli_dbgmsg("Can't read section header\n");
	    cli_dbgmsg("Possibly broken PE file\n");
	    free(section_hdr);
	    if(DETECT_BROKEN) {
		if(ctx->virname)
		    *ctx->virname = "Broken.Executable";
		return CL_VIRUS;
	    }
	    return CL_CLEAN;
	}

	strncpy(sname, (char *) section_hdr[i].Name, 8);
	sname[8] = 0;
	cli_dbgmsg("Section %d\n", i);
	cli_dbgmsg("Section name: %s\n", sname);
	cli_dbgmsg("VirtualSize: %d\n", EC32(section_hdr[i].VirtualSize));
	cli_dbgmsg("VirtualAddress: 0x%x\n", EC32(section_hdr[i].VirtualAddress));
	cli_dbgmsg("SizeOfRawData: %d\n", EC32(section_hdr[i].SizeOfRawData));
	cli_dbgmsg("PointerToRawData: 0x%x (%d)\n", EC32(section_hdr[i].PointerToRawData), EC32(section_hdr[i].PointerToRawData));

	if(EC32(section_hdr[i].Characteristics) & 0x20) {
	    cli_dbgmsg("Section contains executable code\n");

	    if(EC32(section_hdr[i].VirtualSize) < EC32(section_hdr[i].SizeOfRawData)) {
		cli_dbgmsg("Section contains free space\n");
		/*
		cli_dbgmsg("Dumping %d bytes\n", section_hdr.SizeOfRawData - section_hdr.VirtualSize);
		ddump(desc, section_hdr.PointerToRawData + section_hdr.VirtualSize, section_hdr.SizeOfRawData - section_hdr.VirtualSize, cli_gentemp(NULL));
		*/

	    }
	}

	if(EC32(section_hdr[i].Characteristics) & 0x20000000)
	    cli_dbgmsg("Section's memory is executable\n");

	if(EC32(section_hdr[i].Characteristics) & 0x80000000)
	    cli_dbgmsg("Section's memory is writeable\n");

	cli_dbgmsg("------------------------------------\n");

	if (DETECT_BROKEN && EC32(section_hdr[i].VirtualAddress)%((pe_plus)?EC32(optional_hdr64.SectionAlignment):EC32(optional_hdr32.SectionAlignment))) { /* Bad virtual alignment */
	    cli_dbgmsg("VirtualAddress is misaligned\n");
	    if(ctx->virname)
	        *ctx->virname = "Broken.Executable";
	    free(section_hdr);
	    return CL_VIRUS;
	}

	if (EC32(section_hdr[i].SizeOfRawData)) { /* Don't bother with virtual only sections */
	    if(!CLI_ISCONTAINED2(0, (uint32_t) fsize, EC32(section_hdr[i].PointerToRawData), EC32(section_hdr[i].SizeOfRawData)) || EC32(section_hdr[i].PointerToRawData) > fsize) {
	        cli_dbgmsg("Possibly broken PE file - Section %d out of file (Offset@ %d, Rsize %d, Total filesize %d)\n", i, EC32(section_hdr[i].PointerToRawData), EC32(section_hdr[i].SizeOfRawData), fsize);
		  if(DETECT_BROKEN) {
		      if(ctx->virname)
			  *ctx->virname = "Broken.Executable";
		      free(section_hdr);
		      return CL_VIRUS;
		  }
		  broken = 1;

	    } else {
	        /* check MD5 section sigs */
	        md5_sect = ctx->engine->md5_sect;
		while(md5_sect && md5_sect->size < EC32(section_hdr[i].SizeOfRawData))
		    md5_sect = md5_sect->next;

		if(md5_sect && md5_sect->size == EC32(section_hdr[i].SizeOfRawData)) {
		    md5_dig = cli_md5sect(desc, EC32(section_hdr[i].PointerToRawData), EC32(section_hdr[i].SizeOfRawData));
		    if(!md5_dig) {
		        cli_errmsg("PE: Can't calculate MD5 for section %d\n", i);
		    } else {
		        while(md5_sect && md5_sect->size == EC32(section_hdr[i].SizeOfRawData)) {
			    if(!memcmp(md5_dig, md5_sect->md5, 16)) {
			        if(ctx->virname)
				    *ctx->virname = md5_sect->virname;
				free(md5_dig);
				free(section_hdr);
				return CL_VIRUS;
			    }
			    md5_sect = md5_sect->next;
			}
			free(md5_dig);
		    }
		}
	    }
	}

	if(!i) {
	    if (DETECT_BROKEN && EC32(section_hdr[i].VirtualAddress)!=((pe_plus)?EC32(optional_hdr64.SectionAlignment):EC32(optional_hdr32.SectionAlignment))) { /* Bad first section RVA */
	        cli_dbgmsg("First section is in the wrong place\n");
	        if(ctx->virname)
		    *ctx->virname = md5_sect->virname;
		free(section_hdr);
		return CL_VIRUS;
	    }
	    min = EC32(section_hdr[i].VirtualAddress);
	    max = EC32(section_hdr[i].VirtualAddress) + EC32(section_hdr[i].SizeOfRawData);
	} else {
	    if (DETECT_BROKEN && EC32(section_hdr[i].VirtualAddress)-EC32(section_hdr[i-1].VirtualAddress)!=PESALIGN(EC32(section_hdr[i-1].VirtualSize), ((pe_plus)?EC32(optional_hdr64.SectionAlignment):EC32(optional_hdr32.SectionAlignment)))) { /* No holes, no overlapping, no virtual disorder */
	        cli_dbgmsg("Virtually misplaced section (wrong order, overlapping, non contiguous)\n");
	        if(ctx->virname)
		    *ctx->virname = md5_sect->virname;
		free(section_hdr);
		return CL_VIRUS;
	    }
	    if(EC32(section_hdr[i].VirtualAddress) < min)
		min = EC32(section_hdr[i].VirtualAddress);

	    if(EC32(section_hdr[i].VirtualAddress) + EC32(section_hdr[i].SizeOfRawData) > max)
		max = EC32(section_hdr[i].VirtualAddress) + EC32(section_hdr[i].SizeOfRawData);
	}

	if(SCAN_ALGO && !strlen(sname)) {
	    if(EC32(section_hdr[i].VirtualSize) > 40000 && EC32(section_hdr[i].VirtualSize) < 70000) {
		if(EC32(section_hdr[i].Characteristics) == 0xe0000060) {
		    polipos = i;
		}
	    }
	}

    }



    if(pe_plus)
	ep = EC32(optional_hdr64.AddressOfEntryPoint);
    else
	ep = EC32(optional_hdr32.AddressOfEntryPoint);

    if(ep >= min && !(ep = cli_rawaddr(ep, section_hdr, nsections, &err, 0, 0)) && err) {
	cli_dbgmsg("Possibly broken PE file\n");
	free(section_hdr);
	if(DETECT_BROKEN) {
	    if(ctx->virname)
		*ctx->virname = "Broken.Executable";
	    return CL_VIRUS;
	}
	return CL_CLEAN;
    }

    cli_dbgmsg("EntryPoint offset: 0x%x (%d)\n", ep, ep);

    if(pe_plus) { /* Do not continue for PE32+ files */
	free(section_hdr);
	return CL_CLEAN;
    }

    /* Attempt to detect some popular polymorphic viruses */

    /* W32.Parite.B */
    if(SCAN_ALGO && !dll && ep == EC32(section_hdr[nsections - 1].PointerToRawData)) {
	lseek(desc, ep, SEEK_SET);
	if(cli_readn(desc, buff, 4096) == 4096) {
		const char *pt = cli_memstr(buff, 4040, "\x47\x65\x74\x50\x72\x6f\x63\x41\x64\x64\x72\x65\x73\x73\x00", 15);
	    if(pt) {
		    uint32_t dw1, dw2;

		pt += 15;
		if(((dw1 = cli_readint32(pt)) ^ (dw2 = cli_readint32(pt + 4))) == 0x505a4f && ((dw1 = cli_readint32(pt + 8)) ^ (dw2 = cli_readint32(pt + 12))) == 0xffffb && ((dw1 = cli_readint32(pt + 16)) ^ (dw2 = cli_readint32(pt + 20))) == 0xb8) {
		    *ctx->virname = "W32.Parite.B";
		    free(section_hdr);
		    return CL_VIRUS;
		}
	    }
	}
    }

    /* Kriz */
    if(SCAN_ALGO && CLI_ISCONTAINED(EC32(section_hdr[nsections - 1].PointerToRawData), EC32(section_hdr[nsections - 1].SizeOfRawData), ep, 0x0fd2)) {
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
			free(section_hdr);
			return CL_VIRUS;
		}
	}
    }

    /* W32.Magistr.A/B */
    if(SCAN_ALGO && !dll && (EC32(section_hdr[nsections - 1].Characteristics) & 0x80000000)) {
	    uint32_t rsize, vsize;

	rsize = EC32(section_hdr[nsections - 1].SizeOfRawData);
	vsize = EC32(section_hdr[nsections - 1].VirtualSize);

	if(rsize >= 0x612c && vsize >= 0x612c && ((vsize & 0xff) == 0xec)) {
		int bw = rsize < 0x7000 ? rsize : 0x7000;

	    lseek(desc, EC32(section_hdr[nsections - 1].PointerToRawData) + rsize - bw, SEEK_SET);
	    if(cli_readn(desc, buff, 4096) == 4096) {
		if(cli_memstr(buff, 4091, "\xe8\x2c\x61\x00\x00", 5)) {
		    *ctx->virname = "W32.Magistr.A";
		    free(section_hdr);
		    return CL_VIRUS;
		} 
	    }

	} else if(rsize >= 0x7000 && vsize >= 0x7000 && ((vsize & 0xff) == 0xed)) {
		int bw = rsize < 0x8000 ? rsize : 0x8000;

	    lseek(desc, EC32(section_hdr[nsections - 1].PointerToRawData) + rsize - bw, SEEK_SET);
	    if(cli_readn(desc, buff, 4096) == 4096) {
		if(cli_memstr(buff, 4091, "\xe8\x04\x72\x00\x00", 5)) {
		    *ctx->virname = "W32.Magistr.B";
		    free(section_hdr);
		    return CL_VIRUS;
		} 
	    }
	}
    }

    /* W32.Polipos.A */
   if(polipos && !dll && nsections > 2 && nsections < 13 && e_lfanew <= 0x800 && (EC16(optional_hdr32.Subsystem) == 2 || EC16(optional_hdr32.Subsystem) == 3) && EC16(file_hdr.Machine) == 0x14c && optional_hdr32.SizeOfStackReserve >= 0x80000) {
		uint32_t remaining = EC32(section_hdr[0].SizeOfRawData);
		uint32_t chunk = sizeof(buff);
		uint32_t val, shift, raddr, total = 0;
		const char *jpt;
		struct offset_list *offlist = NULL, *offnode;


	cli_dbgmsg("Detected W32.Polipos.A characteristics\n");

	if(remaining < chunk)
	    chunk = remaining;

	lseek(desc, EC32(section_hdr[0].PointerToRawData), SEEK_SET);
	while((bytes = cli_readn(desc, buff, chunk)) > 0) {
	    shift = 0;
	    while(bytes - 5 > shift) {
		jpt = buff + shift;
		if(*jpt!='\xe9' && *jpt!='\xe8') {
		    shift++;
		    continue;
		}
		val = cli_readint32(jpt + 1);
		val += 5 + EC32(section_hdr[0].VirtualAddress) + total + shift;
		raddr = cli_rawaddr(val, section_hdr, nsections, &err, 0, 0);

		if(!err && (raddr >= EC32(section_hdr[polipos].PointerToRawData) && raddr < EC32(section_hdr[polipos].PointerToRawData) + EC32(section_hdr[polipos].SizeOfRawData)) && (!offlist || (raddr != offlist->offset))) {
		    offnode = (struct offset_list *) cli_malloc(sizeof(struct offset_list));
		    if(!offnode) {
			free(section_hdr);
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
	    free(section_hdr);
	    return CL_VIRUS;
	}
    }


    if(broken) {
	free(section_hdr);
	return CL_CLEAN;
    }

#ifdef CL_EXPERIMENTAL
    /* SUE */
    
    if(nsections > 2 && EC32(optional_hdr32.AddressOfEntryPoint) == EC32(section_hdr[nsections - 1].VirtualAddress) && EC32(section_hdr[nsections - 1].SizeOfRawData) > 0x350 && EC32(section_hdr[nsections - 1].SizeOfRawData) < 0x292+0x350+1000) {
  
      
      char *sue=buff+0x74;
      uint32_t key;
      
      if(lseek(desc, ep-4, SEEK_SET) == -1) {
	cli_dbgmsg("SUE: lseek() failed - EP out of file\n");
	free(section_hdr);
	return CL_EIO;
      }
      if((unsigned int) cli_readn(desc, buff, EC32(section_hdr[nsections - 1].SizeOfRawData)+4) == EC32(section_hdr[nsections - 1].SizeOfRawData)+4) {
	found=0;
	while(CLI_ISCONTAINED(buff+4, EC32(section_hdr[nsections - 1].SizeOfRawData), sue, 4*3)) {
	  if((cli_readint32(sue)^cli_readint32(sue+4))==0x5c41090e && (cli_readint32(sue)^cli_readint32(sue+8))==0x021e0145) {
	    found=1;
	    key=(cli_readint32(sue)^0x6e72656b);
	    break;
	  }
	  sue++;
	}
	cli_dbgmsg("SUE: key(%x) found @%x\n", key, sue-buff);
	if (found && CLI_ISCONTAINED(buff, EC32(section_hdr[nsections - 1].SizeOfRawData), sue-0x74, 0xbe) &&
	    (sue=sudecrypt(desc, fsize, section_hdr, nsections-1, sue, key, cli_readint32(buff), e_lfanew))) {
	  if(!(tempfile = cli_gentemp(NULL))) {
	    free(sue);
	    free(section_hdr);
	    return CL_EMEM;
	  }
	  
	  if((ndesc = open(tempfile, O_RDWR|O_CREAT|O_TRUNC|O_BINARY, S_IRWXU)) < 0) {
	    cli_dbgmsg("sue: Can't create file %s\n", tempfile);
	    free(tempfile);
	    free(sue);
	    free(section_hdr);
	    return CL_EIO;
	  }
	  
	  if((unsigned int) write(ndesc, sue, ep) != ep) {
	    cli_dbgmsg("sue: Can't write %d bytes\n", ep);
	    close(ndesc);
	    free(tempfile);
	    free(sue);
	    free(section_hdr);
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
	    free(section_hdr);
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
#endif

    /* UPX & FSG support */

    /* try to find the first section with physical size == 0 */
    found = 0;
    for(i = 0; i < (unsigned int) nsections - 1; i++) {
	if(!section_hdr[i].SizeOfRawData && section_hdr[i].VirtualSize && section_hdr[i + 1].SizeOfRawData && section_hdr[i + 1].VirtualSize) {
	    found = 1;
	    cli_dbgmsg("UPX/FSG: empty section found - assuming compression\n");
	    break;
	}
    }

    if(found) {

	/* Check EP for UPX vs. FSG */
	if(lseek(desc, ep, SEEK_SET) == -1) {
	    cli_dbgmsg("UPX/FSG: lseek() failed\n");
	    free(section_hdr);
	    return CL_EIO;
	}

        if(cli_readn(desc, buff, 168) != 168) {
	    cli_dbgmsg("UPX/FSG: Can't read 168 bytes at 0x%x (%d)\n", ep, ep);
	    cli_dbgmsg("UPX/FSG: Broken or not UPX/FSG compressed file\n");
            free(section_hdr);
	    return CL_CLEAN;
	}

	if(buff[0] == '\x87' && buff[1] == '\x25') {

	    /* FSG v2.0 support - thanks to aCaB ! */

	    ssize = EC32(section_hdr[i + 1].SizeOfRawData);
	    dsize = EC32(section_hdr[i].VirtualSize);

	    while(found) {
		    uint32_t newesi, newedi, newebx, newedx;

		if(ctx->limits && ctx->limits->maxfilesize && (ssize > ctx->limits->maxfilesize || dsize > ctx->limits->maxfilesize)) {
		    cli_dbgmsg("FSG: Sizes exceeded (ssize: %u, dsize: %u, max: %lu)\n", ssize, dsize , ctx->limits->maxfilesize);
		    free(section_hdr);
		    if(BLOCKMAX) {
			*ctx->virname = "PE.FSG.ExceededFileSize";
			return CL_VIRUS;
		    } else {
			return CL_CLEAN;
		    }
		}

		if(ssize <= 0x19 || dsize <= ssize) {
		    cli_dbgmsg("FSG: Size mismatch (ssize: %d, dsize: %d)\n", ssize, dsize);
		    free(section_hdr);
		    return CL_CLEAN;
		}

		if((newedx = cli_readint32(buff + 2) - EC32(optional_hdr32.ImageBase)) < EC32(section_hdr[i + 1].VirtualAddress) || newedx >= EC32(section_hdr[i + 1].VirtualAddress) + EC32(section_hdr[i + 1].SizeOfRawData) - 4) {
		    cli_dbgmsg("FSG: xchg out of bounds (%x), giving up\n", newedx);
		    break;
		}

		if((src = (char *) cli_malloc(ssize)) == NULL) {
		    free(section_hdr);
		    return CL_EMEM;
		}

		lseek(desc, EC32(section_hdr[i + 1].PointerToRawData), SEEK_SET);
		if((unsigned int) cli_readn(desc, src, ssize) != ssize) {
		    cli_dbgmsg("Can't read raw data of section %d\n", i);
		    free(section_hdr);
		    free(src);
		    return CL_EIO;
		}

		if(newedx < EC32(section_hdr[i + 1].VirtualAddress) || ((dest = src + newedx - EC32(section_hdr[i + 1].VirtualAddress)) < src && dest >= src + EC32(section_hdr[i + 1].VirtualAddress) + EC32(section_hdr[i + 1].SizeOfRawData) - 4)) {
		    cli_dbgmsg("FSG: New ESP out of bounds\n");
		    free(src);
		    break;
		}

		if((newedx = cli_readint32(dest) - EC32(optional_hdr32.ImageBase)) <= EC32(section_hdr[i + 1].VirtualAddress) || newedx >= EC32(section_hdr[i + 1].VirtualAddress) + EC32(section_hdr[i + 1].SizeOfRawData) - 4) {
		    cli_dbgmsg("FSG: New ESP (%x) is wrong\n", newedx);
		    free(src);
		    break;
		}
 
		if((dest = src + newedx - EC32(section_hdr[i + 1].VirtualAddress)) < src || dest >= src + EC32(section_hdr[i + 1].VirtualAddress) + EC32(section_hdr[i + 1].SizeOfRawData) - 32) {
		    cli_dbgmsg("FSG: New stack out of bounds\n");
		    free(src);
		    break;
		}

		newedi = cli_readint32(dest) - EC32(optional_hdr32.ImageBase);
		newesi = cli_readint32(dest + 4) - EC32(optional_hdr32.ImageBase);
		newebx = cli_readint32(dest + 16) - EC32(optional_hdr32.ImageBase);
		newedx = cli_readint32(dest + 20);

		if(newedi != EC32(section_hdr[i].VirtualAddress)) {
		    cli_dbgmsg("FSG: Bad destination buffer (edi is %x should be %x)\n", newedi, EC32(section_hdr[i].VirtualAddress));
		    free(src);
		    break;
		}

		if(newesi < EC32(section_hdr[i + 1].VirtualAddress) || newesi >= EC32(section_hdr[i + 1].VirtualAddress) + EC32(section_hdr[i + 1].SizeOfRawData)) {
		    cli_dbgmsg("FSG: Source buffer out of section bounds\n");
		    free(src);
		    break;
		}

		if(newebx < EC32(section_hdr[i + 1].VirtualAddress) || newebx >= EC32(section_hdr[i + 1].VirtualAddress) + EC32(section_hdr[i + 1].SizeOfRawData) - 16) {
		    cli_dbgmsg("FSG: Array of functions out of bounds\n");
		    free(src);
		    break;
		}

		newedx=cli_readint32(newebx + 12 - EC32(section_hdr[i + 1].VirtualAddress) + src) - EC32(optional_hdr32.ImageBase);
		cli_dbgmsg("FSG: found old EP @%x\n",newedx);

		if((dest = (char *) cli_calloc(dsize, sizeof(char))) == NULL) {
		    free(section_hdr);
		    free(src);
		    return CL_EMEM;
		}

		if(!(tempfile = cli_gentemp(NULL))) {
		    free(section_hdr);
		    free(src);
		    return CL_EMEM;
		}

		if((ndesc = open(tempfile, O_RDWR|O_CREAT|O_TRUNC|O_BINARY, S_IRWXU)) < 0) {
		    cli_dbgmsg("FSG: Can't create file %s\n", tempfile);
		    free(tempfile);
		    free(section_hdr);
		    free(src);
		    free(dest);
		    return CL_EIO;
		}
		
		switch (unfsg_200(newesi - EC32(section_hdr[i + 1].VirtualAddress) + src, dest, ssize + EC32(section_hdr[i + 1].VirtualAddress) - newesi, dsize, newedi, EC32(optional_hdr32.ImageBase), newedx, ndesc)) {
		    case 1: /* Everything OK */
			cli_dbgmsg("FSG: Unpacked and rebuilt executable saved in %s\n", tempfile);
			free(src);
			free(dest);
			fsync(ndesc);
			lseek(ndesc, 0, SEEK_SET);

			cli_dbgmsg("***** Scanning rebuilt PE file *****\n");
			if(cli_magic_scandesc(ndesc, ctx) == CL_VIRUS) {
			    free(section_hdr);
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
			free(section_hdr);
			return CL_CLEAN;

		    case 0: /* We've got an unpacked buffer, no exe though */
			cli_dbgmsg("FSG: FSG: Successfully decompressed\n");
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

 	if(found && buff[0] == '\xbe' && cli_readint32(buff + 1) - EC32(optional_hdr32.ImageBase) < min) {

	    /* FSG support - v. 1.33 (thx trog for the many samples) */

	    ssize = EC32(section_hdr[i + 1].SizeOfRawData);
	    dsize = EC32(section_hdr[i].VirtualSize);

	    while(found) {
	            int gp, t, sectcnt = 0;
		    char *support;
		    uint32_t newesi, newedi, newebx, oldep;
		    struct SECTION *sections;


		if(ctx->limits && ctx->limits->maxfilesize && (ssize > ctx->limits->maxfilesize || dsize > ctx->limits->maxfilesize)) {
		    cli_dbgmsg("FSG: Sizes exceeded (ssize: %u, dsize: %u, max: %lu)\n", ssize, dsize, ctx->limits->maxfilesize);
		    free(section_hdr);
		    if(BLOCKMAX) {
			*ctx->virname = "PE.FSG.ExceededFileSize";
			return CL_VIRUS;
		    } else {
			return CL_CLEAN;
		    }
		}

		if(ssize <= 0x19 || dsize <= ssize) {
		    cli_dbgmsg("FSG: Size mismatch (ssize: %d, dsize: %d)\n", ssize, dsize);
		    free(section_hdr);
		    return CL_CLEAN;
		}

		if((gp = cli_readint32(buff + 1) - EC32(optional_hdr32.ImageBase)) >= (int) EC32(section_hdr[i + 1].PointerToRawData) || gp < 0) {
		    cli_dbgmsg("FSG: Support data out of padding area (vaddr: %d)\n", EC32(section_hdr[i].VirtualAddress));
		    break;
		}

		lseek(desc, gp, SEEK_SET);
		gp = EC32(section_hdr[i + 1].PointerToRawData) - gp;

		if(ctx->limits && ctx->limits->maxfilesize && (unsigned int) gp > ctx->limits->maxfilesize) {
		    cli_dbgmsg("FSG: Buffer size exceeded (size: %d, max: %lu)\n", gp, ctx->limits->maxfilesize);
		    free(section_hdr);
		    if(BLOCKMAX) {
			*ctx->virname = "PE.FSG.ExceededFileSize";
			return CL_VIRUS;
		    } else {
			return CL_CLEAN;
		    }
		}

		if((support = (char *) cli_malloc(gp)) == NULL) {
		    free(section_hdr);
		    return CL_EMEM;
		}

		if(cli_readn(desc, support, gp) != gp) {
		    cli_dbgmsg("Can't read %d bytes from padding area\n", gp); 
		    free(section_hdr);
		    free(support);
		    return CL_EIO;
		}

		newebx = cli_readint32(support) - EC32(optional_hdr32.ImageBase); /* Unused */
		newedi = cli_readint32(support + 4) - EC32(optional_hdr32.ImageBase); /* 1st dest */
		newesi = cli_readint32(support + 8) - EC32(optional_hdr32.ImageBase); /* Source */

		if(newesi < EC32(section_hdr[i + 1].VirtualAddress) || newesi >= EC32(section_hdr[i + 1].VirtualAddress) + EC32(section_hdr[i + 1].SizeOfRawData)) {
		    cli_dbgmsg("FSG: Source buffer out of section bounds\n");
		    free(support);
		    break;
		}

		if(newedi != EC32(section_hdr[i].VirtualAddress)) {
		    cli_dbgmsg("FSG: Bad destination (is %x should be %x)\n", newedi, EC32(section_hdr[i].VirtualAddress));
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

		    if(rva < EC32(section_hdr[i].VirtualAddress) || rva >= EC32(section_hdr[i].VirtualAddress)+EC32(section_hdr[i].VirtualSize)) {
			cli_dbgmsg("FSG: Original section %d is out of bounds\n", sectcnt);
			break;
		    }
		}

		if(t >= gp - 4 || cli_readint32(support + t)) {
		    free(support);
		    break;
		}

		if((sections = (struct SECTION *) cli_malloc((sectcnt + 1) * sizeof(struct SECTION))) == NULL) {
		    free(section_hdr);
		    free(support);
		    return CL_EMEM;
		}

		sections[0].rva = newedi;
		for(t = 1; t <= sectcnt; t++)
		    sections[t].rva = cli_readint32(support + 8 + t * 4) - 1 -EC32(optional_hdr32.ImageBase);

		free(support);

		if((src = (char *) cli_malloc(ssize)) == NULL) {
		    free(section_hdr);
		    free(sections);
		    return CL_EMEM;
		}

		lseek(desc, EC32(section_hdr[i + 1].PointerToRawData), SEEK_SET);
		if((unsigned int) cli_readn(desc, src, ssize) != ssize) {
		    cli_dbgmsg("Can't read raw data of section %d\n", i);
		    free(section_hdr);
		    free(sections);
		    free(src);
		    return CL_EIO;
		}

		if((dest = (char *) cli_calloc(dsize, sizeof(char))) == NULL) {
		    free(section_hdr);
		    free(src);
		    free(sections);
		    return CL_EMEM;
		}

		oldep = EC32(optional_hdr32.AddressOfEntryPoint) + 161 + 6 + cli_readint32(buff+163);
		cli_dbgmsg("FSG: found old EP @%x\n", oldep);

		if(!(tempfile = cli_gentemp(NULL))) {
		    free(section_hdr);
		    free(src);
		    free(dest);
		    free(sections);
		    return CL_EMEM;
		}

		if((ndesc = open(tempfile, O_RDWR|O_CREAT|O_TRUNC|O_BINARY, S_IRWXU)) < 0) {
		    cli_dbgmsg("FSG: Can't create file %s\n", tempfile);
		    free(tempfile);
		    free(section_hdr);
		    free(src);
		    free(dest);
		    free(sections);
		    return CL_EIO;
		}

		switch(unfsg_133(src + newesi - EC32(section_hdr[i + 1].VirtualAddress), dest, ssize + EC32(section_hdr[i + 1].VirtualAddress) - newesi, dsize, sections, sectcnt, EC32(optional_hdr32.ImageBase), oldep, ndesc)) {
		    case 1: /* Everything OK */
			cli_dbgmsg("FSG: Unpacked and rebuilt executable saved in %s\n", tempfile);
			free(src);
			free(dest);
			free(sections);
			fsync(ndesc);
			lseek(ndesc, 0, SEEK_SET);

			cli_dbgmsg("***** Scanning rebuilt PE file *****\n");
			if(cli_magic_scandesc(ndesc, ctx) == CL_VIRUS) {
			    free(section_hdr);
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
			free(section_hdr);
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

		break; /* were done with 1.33 */
	    }
	}

	/* FIXME: easy 2 hack */
 	if(found && buff[0] == '\xbb' && cli_readint32(buff + 1) - EC32(optional_hdr32.ImageBase) < min && buff[5] == '\xbf' && buff[10] == '\xbe') {

	    /* FSG support - v. 1.31 */

	    ssize = EC32(section_hdr[i + 1].SizeOfRawData);
	    dsize = EC32(section_hdr[i].VirtualSize);

	    while(found) {
		    int gp = cli_readint32(buff+1) - EC32(optional_hdr32.ImageBase), t, sectcnt = 0;
		    char *support;
		    uint32_t newesi = cli_readint32(buff+11) - EC32(optional_hdr32.ImageBase);
		    uint32_t newedi = cli_readint32(buff+6) - EC32(optional_hdr32.ImageBase);
		    uint32_t oldep = EC32(optional_hdr32.AddressOfEntryPoint);
		    struct SECTION *sections;

	        if (oldep <= EC32(section_hdr[i + 1].VirtualAddress) || oldep > EC32(section_hdr[i + 1].VirtualAddress)+EC32(section_hdr[i + 1].SizeOfRawData) - 0xe0) {
		  cli_dbgmsg("FSG: EP not in section %d\n", i+1);
		  break;
		}
		oldep -= EC32(section_hdr[i + 1].VirtualAddress);

		if(newesi < EC32(section_hdr[i + 1].VirtualAddress) || newesi >= EC32(section_hdr[i + 1].VirtualAddress) + EC32(section_hdr[i + 1].SizeOfRawData)) {
		    cli_dbgmsg("FSG: Source buffer out of section bounds\n");
		    break;
		}

		if(newedi != EC32(section_hdr[i].VirtualAddress)) {
		    cli_dbgmsg("FSG: Bad destination (is %x should be %x)\n", newedi, EC32(section_hdr[i].VirtualAddress));
		    break;
		}

		if(ctx->limits && ctx->limits->maxfilesize && (ssize > ctx->limits->maxfilesize || dsize > ctx->limits->maxfilesize)) {
		    cli_dbgmsg("FSG: Sizes exceeded (ssize: %u, dsize: %u, max: %lu)\n", ssize, dsize, ctx->limits->maxfilesize);
		    free(section_hdr);
		    if(BLOCKMAX) {
			*ctx->virname = "PE.FSG.ExceededFileSize";
			return CL_VIRUS;
		    } else {
			return CL_CLEAN;
		    }
		}

		if(ssize <= 0x19 || dsize <= ssize) {
		    cli_dbgmsg("FSG: Size mismatch (ssize: %d, dsize: %d)\n", ssize, dsize);
		    free(section_hdr);
		    return CL_CLEAN;
		}

		if(gp >= (int) EC32(section_hdr[i + 1].PointerToRawData) || gp < 0) {
		    cli_dbgmsg("FSG: Support data out of padding area (newedi: %d, vaddr: %d)\n", newedi, EC32(section_hdr[i].VirtualAddress));
		    break;
		}

		lseek(desc, gp, SEEK_SET);
		gp = EC32(section_hdr[i + 1].PointerToRawData) - gp;

		if(ctx->limits && ctx->limits->maxfilesize && (unsigned int) gp > ctx->limits->maxfilesize) {
		    cli_dbgmsg("FSG: Buffer size exceeded (size: %d, max: %lu)\n", gp, ctx->limits->maxfilesize);
		    free(section_hdr);
		    if(BLOCKMAX) {
			*ctx->virname = "PE.FSG.ExceededFileSize";
			return CL_VIRUS;
		    } else {
			return CL_CLEAN;
		    }
		}

		if((support = (char *) cli_malloc(gp)) == NULL) {
		    free(section_hdr);
		    return CL_EMEM;
		}

		if(cli_readn(desc, support, gp) != gp) {
		    cli_dbgmsg("Can't read %d bytes from padding area\n", gp); 
		    free(section_hdr);
		    free(support);
		    return CL_EIO;
		}

		/* Counting original sections */
		for(t = 0; t < gp - 2; t += 2) {
		  uint32_t rva = support[t]+256*support[t+1];
		  
		  if (rva == 2 || rva == 1)
		    break;

		  rva = ((rva-2)<<12) - EC32(optional_hdr32.ImageBase);
		  sectcnt++;

		  if(rva < EC32(section_hdr[i].VirtualAddress) || rva >= EC32(section_hdr[i].VirtualAddress)+EC32(section_hdr[i].VirtualSize)) {
		    cli_dbgmsg("FSG: Original section %d is out of bounds\n", sectcnt);
		    break;
		  }
		}

		if(t >= gp-10 || cli_readint32(support + t + 6) != 2) {
		    free(support);
		    break;
		}

		if((sections = (struct SECTION *) cli_malloc((sectcnt + 1) * sizeof(struct SECTION))) == NULL) {
		    free(section_hdr);
		    free(support);
		    return CL_EMEM;
		}

		sections[0].rva = newedi;
		for(t = 0; t <= sectcnt - 1; t++) {
		  sections[t+1].rva = (((support[t*2]+256*support[t*2+1])-2)<<12)-EC32(optional_hdr32.ImageBase);
		}

		free(support);

		if((src = (char *) cli_malloc(ssize)) == NULL) {
		    free(section_hdr);
		    free(sections);
		    return CL_EMEM;
		}

		lseek(desc, EC32(section_hdr[i + 1].PointerToRawData), SEEK_SET);
		if((unsigned int) cli_readn(desc, src, ssize) != ssize) {
		    cli_dbgmsg("Can't read raw data of section %d\n", i);
		    free(section_hdr);
		    free(sections);
		    free(src);
		    return CL_EIO;
		}

		if((dest = (char *) cli_calloc(dsize, sizeof(char))) == NULL) {
		    free(section_hdr);
		    free(src);
		    free(sections);
		    return CL_EMEM;
		}

		/* Better not increasing buff size any further, let's go the hard way */
		gp = 0xda + 6*(buff[16]=='\xe8');
		oldep = EC32(optional_hdr32.AddressOfEntryPoint) + gp + 6 + cli_readint32(src+gp+2+oldep);
		cli_dbgmsg("FSG: found old EP @%x\n", oldep);

		if(!(tempfile = cli_gentemp(NULL))) {
		    free(section_hdr);
		    free(src);
		    free(dest);
		    free(sections);
		    return CL_EMEM;
		}

		if((ndesc = open(tempfile, O_RDWR|O_CREAT|O_TRUNC|O_BINARY, S_IRWXU)) < 0) {
		    cli_dbgmsg("FSG: Can't create file %s\n", tempfile);
		    free(tempfile);
		    free(section_hdr);
		    free(src);
		    free(dest);
		    free(sections);
		    return CL_EIO;
		}

		switch(unfsg_133(src + newesi - EC32(section_hdr[i + 1].VirtualAddress), dest, ssize + EC32(section_hdr[i + 1].VirtualAddress) - newesi, dsize, sections, sectcnt, EC32(optional_hdr32.ImageBase), oldep, ndesc)) {
		    case 1: /* Everything OK */
			cli_dbgmsg("FSG: Unpacked and rebuilt executable saved in %s\n", tempfile);
			free(src);
			free(dest);
			free(sections);
			fsync(ndesc);
			lseek(ndesc, 0, SEEK_SET);

			cli_dbgmsg("***** Scanning rebuilt PE file *****\n");
			if(cli_magic_scandesc(ndesc, ctx) == CL_VIRUS) {
			    free(section_hdr);
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
			free(section_hdr);
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


	if(found) {

	    /* UPX support */

	    strncpy(sname, (char *) section_hdr[i].Name, 8);
	    sname[8] = 0;
	    cli_dbgmsg("UPX: Section %d name: %s\n", i, sname);
	    strncpy(sname, (char *) section_hdr[i + 1].Name, 8);
	    sname[8] = 0;
	    cli_dbgmsg("UPX: Section %d name: %s\n", i + 1, sname);

	    if(strncmp((char *) section_hdr[i].Name, "UPX0", 4) || strncmp((char *) section_hdr[i + 1].Name, "UPX1", 4))
		cli_dbgmsg("UPX: Possibly hacked UPX section headers\n");

	    /* we assume (i + 1) is UPX1 */
	    ssize = EC32(section_hdr[i + 1].SizeOfRawData);
	    dsize = EC32(section_hdr[i].VirtualSize) + EC32(section_hdr[i + 1].VirtualSize);

	    if(ctx->limits && ctx->limits->maxfilesize && (ssize > ctx->limits->maxfilesize || dsize > ctx->limits->maxfilesize)) {
		cli_dbgmsg("UPX: Sizes exceeded (ssize: %u, dsize: %u, max: %lu)\n", ssize, dsize , ctx->limits->maxfilesize);
		free(section_hdr);
		if(BLOCKMAX) {
		    *ctx->virname = "PE.UPX.ExceededFileSize";
		    return CL_VIRUS;
		} else {
		    return CL_CLEAN;
		}
	    }

	    if(ssize <= 0x19 || dsize <= ssize) { /* FIXME: What are reasonable values? */
		cli_dbgmsg("UPX: Size mismatch (ssize: %d, dsize: %d)\n", ssize, dsize);
		free(section_hdr);
		return CL_CLEAN;
	    }

	    /* FIXME: use file operations in case of big files */
	    if((src = (char *) cli_malloc(ssize)) == NULL) {
		free(section_hdr);
		return CL_EMEM;
	    }

	    if(dsize > CLI_MAX_ALLOCATION) {
		cli_errmsg("UPX: Too big value of dsize\n");
		free(section_hdr);
		free(src);
		return CL_EMEM;
	    }

	    if((dest = (char *) cli_calloc(dsize + 1024 + nsections * 40, sizeof(char))) == NULL) {
		free(section_hdr);
		free(src);
		return CL_EMEM;
	    }

	    lseek(desc, EC32(section_hdr[i + 1].PointerToRawData), SEEK_SET);
	    if((unsigned int) cli_readn(desc, src, ssize) != ssize) {
		cli_dbgmsg("Can't read raw data of section %d\n", i);
		free(section_hdr);
		free(src);
		free(dest);
		return CL_EIO;
	    }

	    /* try to detect UPX code */

	    if(lseek(desc, ep, SEEK_SET) == -1) {
		cli_dbgmsg("lseek() failed\n");
		free(section_hdr);
		free(src);
		free(dest);
		return CL_EIO;
	    }

	    if(cli_readn(desc, buff, 126) != 126) { /* i.e. 0x69 + 13 + 8 */
		cli_dbgmsg("UPX: Can't read 126 bytes at 0x%x (%d)\n", ep, ep);
		cli_dbgmsg("UPX/FSG: Broken or not UPX/FSG compressed file\n");
		free(section_hdr);
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
		    int skew = cli_readint32(buff + 2) - EC32(optional_hdr32.ImageBase) - EC32(section_hdr[i + 1].VirtualAddress);

		if(buff[1] != '\xbe' || skew <= 0 || skew > 0xfff) { /* FIXME: legit skews?? */
		    skew = 0; 
		    if(upxfn(src, ssize, dest, &dsize, EC32(section_hdr[i].VirtualAddress), EC32(section_hdr[i + 1].VirtualAddress), EC32(optional_hdr32.AddressOfEntryPoint)) >= 0)
			upx_success = 1;

		} else {
		    cli_dbgmsg("UPX: UPX1 seems skewed by %d bytes\n", skew);
                    if(upxfn(src + skew, ssize - skew, dest, &dsize, EC32(section_hdr[i].VirtualAddress), EC32(section_hdr[i + 1].VirtualAddress), EC32(optional_hdr32.AddressOfEntryPoint)-skew) >= 0 || upxfn(src, ssize, dest, &dsize, EC32(section_hdr[i].VirtualAddress), EC32(section_hdr[i + 1].VirtualAddress), EC32(optional_hdr32.AddressOfEntryPoint)) >= 0)
			upx_success = 1;
		}

		if(upx_success)
		    cli_dbgmsg("UPX: Successfully decompressed\n");
		else
		    cli_dbgmsg("UPX: Prefered decompressor failed\n");
	    }

	    if(!upx_success && upxfn != upx_inflate2b) {
		if(upx_inflate2b(src, ssize, dest, &dsize, EC32(section_hdr[i].VirtualAddress), EC32(section_hdr[i + 1].VirtualAddress), EC32(optional_hdr32.AddressOfEntryPoint)) == -1 && upx_inflate2b(src + 0x15, ssize - 0x15, dest, &dsize, EC32(section_hdr[i].VirtualAddress), EC32(section_hdr[i + 1].VirtualAddress), EC32(optional_hdr32.AddressOfEntryPoint) - 0x15) == -1) {

		    cli_dbgmsg("UPX: NRV2B decompressor failed\n");
		} else {
		    upx_success = 1;
		    cli_dbgmsg("UPX: Successfully decompressed with NRV2B\n");
		}
	    }

	    if(!upx_success && upxfn != upx_inflate2d) {
		if(upx_inflate2d(src, ssize, dest, &dsize, EC32(section_hdr[i].VirtualAddress), EC32(section_hdr[i + 1].VirtualAddress), EC32(optional_hdr32.AddressOfEntryPoint)) == -1 && upx_inflate2d(src + 0x15, ssize - 0x15, dest, &dsize, EC32(section_hdr[i].VirtualAddress), EC32(section_hdr[i + 1].VirtualAddress), EC32(optional_hdr32.AddressOfEntryPoint) - 0x15) == -1) {

		    cli_dbgmsg("UPX: NRV2D decompressor failed\n");
		} else {
		    upx_success = 1;
		    cli_dbgmsg("UPX: Successfully decompressed with NRV2D\n");
		}
	    }

	    if(!upx_success && upxfn != upx_inflate2e) {
		if(upx_inflate2e(src, ssize, dest, &dsize, EC32(section_hdr[i].VirtualAddress), EC32(section_hdr[i + 1].VirtualAddress), EC32(optional_hdr32.AddressOfEntryPoint)) == -1 && upx_inflate2e(src + 0x15, ssize - 0x15, dest, &dsize, EC32(section_hdr[i].VirtualAddress), EC32(section_hdr[i + 1].VirtualAddress), EC32(optional_hdr32.AddressOfEntryPoint) - 0x15) == -1) {
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
	    free(section_hdr);

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
	free(section_hdr);
	return CL_EIO;
    }

    if(buff[0] != '\xb8' || (uint32_t) cli_readint32(buff + 1) != EC32(section_hdr[nsections - 1].VirtualAddress) + EC32(optional_hdr32.ImageBase)) {
	if(nsections < 2 || buff[0] != '\xb8' || (uint32_t) cli_readint32(buff + 1) != EC32(section_hdr[nsections - 2].VirtualAddress) + EC32(optional_hdr32.ImageBase))
	    found = 0;
	else
	    found = 1;
    }

    if(found) {
	cli_dbgmsg("Petite: v2.%d compression detected\n", found);

	if(cli_readint32(buff + 0x80) == 0x163c988d) {
	    cli_dbgmsg("Petite: level zero compression is not supported yet\n");
	} else {
	    dsize = max - min;

	    if(ctx->limits && ctx->limits->maxfilesize && dsize > ctx->limits->maxfilesize) {
		cli_dbgmsg("Petite: Size exceeded (dsize: %u, max: %lu)\n", dsize, ctx->limits->maxfilesize);
		free(section_hdr);
		if(BLOCKMAX) {
		    *ctx->virname = "PE.Petite.ExceededFileSize";
		    return CL_VIRUS;
		} else {
		    return CL_CLEAN;
		}
	    }

	    if((dest = (char *) cli_calloc(dsize, sizeof(char))) == NULL) {
		cli_dbgmsg("Petite: Can't allocate %d bytes\n", dsize);
		free(section_hdr);
		return CL_EMEM;
	    }

	    for(i = 0 ; i < nsections; i++) {
		if(section_hdr[i].SizeOfRawData) {
		  uint32_t offset = cli_rawaddr(EC32(section_hdr[i].VirtualAddress), section_hdr, nsections, &err, 0, 0);

		    if(err || lseek(desc, offset, SEEK_SET) == -1 || (unsigned int) cli_readn(desc, dest + EC32(section_hdr[i].VirtualAddress) - min, EC32(section_hdr[i].SizeOfRawData)) != EC32(section_hdr[i].SizeOfRawData)) {
			free(section_hdr);
			free(dest);
			return CL_EIO;
		    }
		}
	    }

	    if(!(tempfile = cli_gentemp(NULL))) {
	      free(dest);
	      free(section_hdr);
	      return CL_EMEM;
	    }

	    if((ndesc = open(tempfile, O_RDWR|O_CREAT|O_TRUNC|O_BINARY, S_IRWXU)) < 0) {
		cli_dbgmsg("Petite: Can't create file %s\n", tempfile);
		free(tempfile);
		free(section_hdr);
		free(dest);
		return CL_EIO;
	    }

	    /* aCaB: Fixed to allow petite v2.1 unpacking (last section is a ghost) */
	    switch(petite_inflate2x_1to9(dest, min, max - min, section_hdr,
		    nsections - (found == 1 ? 1 : 0), EC32(optional_hdr32.ImageBase),
		    EC32(optional_hdr32.AddressOfEntryPoint), ndesc,
		    found, EC32(optional_hdr32.DataDirectory[2].VirtualAddress),
		    EC32(optional_hdr32.DataDirectory[2].Size))) {
		case 1:
		    cli_dbgmsg("Petite: Unpacked and rebuilt executable saved in %s\n", tempfile);
		    cli_dbgmsg("***** Scanning rebuilt PE file *****\n");
		    break;

		case 0:
		    cli_dbgmsg("Petite: Unpacked data saved in %s\n", tempfile);
		    break;

		default:
		    cli_dbgmsg("Petite: Unpacking failed\n");
	    }

	    free(dest);
	    fsync(ndesc);
	    lseek(ndesc, 0, SEEK_SET);

	    if(cli_magic_scandesc(ndesc, ctx) == CL_VIRUS) {
		free(section_hdr);
		close(ndesc);
		if(!cli_leavetemps_flag) {
		    unlink(tempfile);
		    free(tempfile);
		} else {
		    free(tempfile);
		}
		return CL_VIRUS;
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

    /* PESpin 1.1 */

    if(nsections > 1 &&
       EC32(optional_hdr32.AddressOfEntryPoint) >= EC32(section_hdr[nsections - 1].VirtualAddress) &&
       EC32(optional_hdr32.AddressOfEntryPoint) < EC32(section_hdr[nsections - 1].VirtualAddress) + EC32(section_hdr[nsections - 1].SizeOfRawData) - 0x3217 - 4 &&
       memcmp(buff+4, "\xe8\x00\x00\x00\x00\x8b\x1c\x24\x83\xc3", 10) == 0)  {

	    char *spinned;

	if(ctx->limits && ctx->limits->maxfilesize && fsize > ctx->limits->maxfilesize) {
	    cli_dbgmsg("PEspin: Size exceeded (fsize: %u, max: %lu)\n", fsize, ctx->limits->maxfilesize);
            free(section_hdr);
	    if(BLOCKMAX) {
		*ctx->virname = "PE.Pespin.ExceededFileSize";
		return CL_VIRUS;
	    } else {
		return CL_CLEAN;
	    }
	}

	if((spinned = (char *) cli_malloc(fsize)) == NULL) {
	    free(section_hdr);
	    return CL_EMEM;
	}

	lseek(desc, 0, SEEK_SET);
	if((size_t) cli_readn(desc, spinned, fsize) != fsize) {
	    cli_dbgmsg("PESpin: Can't read %d bytes\n", fsize);
	    free(spinned);
	    free(section_hdr);
	    return CL_EIO;
	}

	if(!(tempfile = cli_gentemp(NULL))) {
	  free(spinned);
	  free(section_hdr);
	  return CL_EMEM;
	}

	if((ndesc = open(tempfile, O_RDWR|O_CREAT|O_TRUNC|O_BINARY, S_IRWXU)) < 0) {
	    cli_dbgmsg("PESpin: Can't create file %s\n", tempfile);
	    free(tempfile);
	    free(spinned);
	    free(section_hdr);
	    return CL_EIO;
	}

	switch(unspin(spinned, fsize, section_hdr, nsections - 1, EC32(optional_hdr32.AddressOfEntryPoint), ndesc, ctx)) {
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
		free(section_hdr);
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
		free(section_hdr);
		*ctx->virname = "PE.Pespin.ExceededFileSize";
		return CL_VIRUS;
	    }
	}
	free(tempfile);
	
    }


    /* yC 1.3 */

    if(nsections > 1 &&
       EC32(optional_hdr32.AddressOfEntryPoint) == EC32(section_hdr[nsections - 1].VirtualAddress) + 0x60 &&
       memcmp(buff, "\x55\x8B\xEC\x53\x56\x57\x60\xE8\x00\x00\x00\x00\x5D\x81\xED\x6C\x28\x40\x00\xB9\x5D\x34\x40\x00\x81\xE9\xC6\x28\x40\x00\x8B\xD5\x81\xC2\xC6\x28\x40\x00\x8D\x3A\x8B\xF7\x33\xC0\xEB\x04\x90\xEB\x01\xC2\xAC", 51) == 0)  {

	    char *spinned;

	if ( fsize >= EC32(section_hdr[nsections - 1].PointerToRawData) + 0xC6 + 0xb97 ) { /* size check on yC sect */
	  if((spinned = (char *) cli_malloc(fsize)) == NULL) {
	    free(section_hdr);
	    return CL_EMEM;
	  }

	  lseek(desc, 0, SEEK_SET);
	  if((size_t) cli_readn(desc, spinned, fsize) != fsize) {
	    cli_dbgmsg("yC: Can't read %d bytes\n", fsize);
	    free(spinned);
	    free(section_hdr);
	    return CL_EIO;
	  }

	  if(!(tempfile = cli_gentemp(NULL))) {
	    free(spinned);
	    free(section_hdr);
	    return CL_EMEM;
	  }

	  if((ndesc = open(tempfile, O_RDWR|O_CREAT|O_TRUNC|O_BINARY, S_IRWXU)) < 0) {
	    cli_dbgmsg("yC: Can't create file %s\n", tempfile);
	    free(tempfile);
	    free(spinned);
	    free(section_hdr);
	    return CL_EIO;
	  }

	  if(!yc_decrypt(spinned, fsize, section_hdr, nsections-1, e_lfanew, ndesc)) {
	    free(spinned);
	    cli_dbgmsg("yC: Unpacked and rebuilt executable saved in %s\n", tempfile);
	    fsync(ndesc);
	    lseek(ndesc, 0, SEEK_SET);
	    
	    if(cli_magic_scandesc(ndesc, ctx) == CL_VIRUS) {
	      free(section_hdr);
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

    if(nsections > 1 &&
       EC32(section_hdr[nsections-1].SizeOfRawData)>0x2b1 &&
       EC32(optional_hdr32.AddressOfEntryPoint) == EC32(section_hdr[nsections - 1].VirtualAddress) &&
       EC32(section_hdr[nsections - 1].VirtualAddress)+EC32(section_hdr[nsections - 1].SizeOfRawData) == max &&
       memcmp(buff, "\x53\x55\x8b\xe8\x33\xdb\xeb", 7) == 0 &&
       memcmp(buff+0x68, "\xe8\x00\x00\x00\x00\x58\x2d\x6d\x00\x00\x00\x50\x60\x33\xc9\x50\x58\x50\x50", 19) == 0)  {
      uint32_t headsize=EC32(section_hdr[nsections - 1].PointerToRawData);
      char *dest, *wwp;

      for(i = 0 ; i < (unsigned int)nsections-1; i++) {
	uint32_t offset = cli_rawaddr(EC32(section_hdr[i].VirtualAddress), section_hdr, nsections, &err, 0, 0);
	if (!err && offset<headsize) headsize=offset;
      }
      
      dsize = max-min+headsize-EC32(section_hdr[nsections - 1].SizeOfRawData);

      if(ctx->limits && ctx->limits->maxfilesize && dsize > ctx->limits->maxfilesize) {
	cli_dbgmsg("WWPack: Size exceeded (dsize: %u, max: %lu)\n", dsize, ctx->limits->maxfilesize);
	free(section_hdr);
	if(BLOCKMAX) {
	  *ctx->virname = "PE.WWPack.ExceededFileSize";
	  return CL_VIRUS;
	} else {
	  return CL_CLEAN;
	}
      }

      if((dest = (char *) cli_calloc(dsize, sizeof(char))) == NULL) {
	cli_dbgmsg("WWPack: Can't allocate %d bytes\n", dsize);
	free(section_hdr);
	return CL_EMEM;
      }
      memset(dest, 0, dsize);

      lseek(desc, 0, SEEK_SET);
      if((size_t) cli_readn(desc, dest, headsize) != headsize) {
	cli_dbgmsg("WWPack: Can't read %d bytes from headers\n", headsize);
	free(dest);
	free(section_hdr);
	return CL_EIO;
      }

      for(i = 0 ; i < (unsigned int)nsections-1; i++) {
	if(section_hdr[i].SizeOfRawData) {
	  uint32_t offset = cli_rawaddr(EC32(section_hdr[i].VirtualAddress), section_hdr, nsections, &err, 0, 0);
	  
	  if(err || lseek(desc, offset, SEEK_SET) == -1 || (unsigned int) cli_readn(desc, dest + headsize + EC32(section_hdr[i].VirtualAddress) - min, EC32(section_hdr[i].SizeOfRawData)) != EC32(section_hdr[i].SizeOfRawData)) {
	    free(dest);
	    free(section_hdr);
	    return CL_EIO;
	  }
	}
      }

      if((wwp = (char *) cli_calloc(EC32(section_hdr[nsections - 1].SizeOfRawData), sizeof(char))) == NULL) {
	cli_dbgmsg("WWPack: Can't allocate %d bytes\n", EC32(section_hdr[nsections - 1].SizeOfRawData));
	free(dest);
	free(section_hdr);
	return CL_EMEM;
      }

      lseek(desc, EC32(section_hdr[nsections - 1].PointerToRawData), SEEK_SET);      
      if((size_t) cli_readn(desc, wwp, EC32(section_hdr[nsections - 1].SizeOfRawData)) != EC32(section_hdr[nsections - 1].SizeOfRawData)) {
	cli_dbgmsg("WWPack: Can't read %d bytes from wwpack sect\n", EC32(section_hdr[nsections - 1].SizeOfRawData));
	free(dest);
	free(wwp);
	free(section_hdr);
	return CL_EIO;
      }

      if (!wwunpack(dest, dsize, headsize, min, EC32(section_hdr[nsections-1].VirtualAddress),  e_lfanew, wwp, EC32(section_hdr[nsections - 1].SizeOfRawData), nsections-1)) {
	
	free(wwp);

	if(!(tempfile = cli_gentemp(NULL))) {
	  free(dest);
	  free(section_hdr);
	  return CL_EMEM;
	}

	if((ndesc = open(tempfile, O_RDWR|O_CREAT|O_TRUNC|O_BINARY, S_IRWXU)) < 0) {
	  cli_dbgmsg("WWPack: Can't create file %s\n", tempfile);
	  free(tempfile);
	  free(dest);
	  free(section_hdr);
	  return CL_EIO;
	}

	if((unsigned int) write(ndesc, dest, dsize) != dsize) {
	  cli_dbgmsg("WWPack: Can't write %d bytes\n", dsize);
	  close(ndesc);
	  free(tempfile);
	  free(dest);
	  free(section_hdr);
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
	  free(section_hdr);
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

#ifdef CL_EXPERIMENTAL
    /* NsPack */

    /* WATCH OUT: ep && buff destroyed!!! */
    while (1) {
      uint32_t eprva = EC32(optional_hdr32.AddressOfEntryPoint);
      uint32_t start_of_stuff, ssize, dsize;
      unsigned int nowinldr;
      char *src, *dest;
      FILE *asd;

      ep = cli_rawaddr(eprva , section_hdr, nsections, &err, EC32(optional_hdr32.SectionAlignment), EC32(optional_hdr32.FileAlignment));
      if (lseek(desc, ep, SEEK_SET)==-1) break;
      if (cli_readn(desc, buff, 13)!=13) break;
      if (*buff=='\xe9') { /* bitched headers */
	eprva = cli_readint32(buff+1)+EC32(optional_hdr32.AddressOfEntryPoint)+5;
	ep = cli_rawaddr(eprva, section_hdr, nsections, &err, EC32(optional_hdr32.SectionAlignment), EC32(optional_hdr32.FileAlignment));
	if (lseek(desc, ep, SEEK_SET)==-1) break;
	if (cli_readn(desc, buff, 24)!=24) break;
      }

      if (memcmp(buff, "\x9c\x60\xe8\x00\x00\x00\x00\x5d\xb8\x07\x00\x00\x00", 13)) break;

      nowinldr = 0x54-cli_readint32(buff+17);
      cli_dbgmsg("NsPack: Found *start_of_stuff @delta-%x\n", nowinldr);

      if (lseek(desc, ep-nowinldr, SEEK_SET)==-1) break;
      if (cli_readn(desc, buff, 4)!=4) break;
      start_of_stuff=ep+cli_readint32(buff);
      if (lseek(desc, start_of_stuff, SEEK_SET)==-1) break;
      if (cli_readn(desc, buff, 20)!=20) break;
      src = buff;
      if (!cli_readint32(buff)) {
	start_of_stuff+=4; /* FIXME: more to do */
	src+=4;
      }

      ssize = cli_readint32(src+5)|0xff;
      dsize = cli_readint32(src+9);

      if(ctx->limits && ctx->limits->maxfilesize && (ssize > ctx->limits->maxfilesize || dsize > ctx->limits->maxfilesize)) {
	cli_dbgmsg("NsPack: Size exceeded\n");
	free(section_hdr);
	if(BLOCKMAX) {
	  *ctx->virname = "PE.NsPack.ExceededFileSize";
	  return CL_VIRUS;
	} else {
	  return CL_CLEAN;
	}
      }

      if ( !ssize || !dsize || dsize != (uint32_t)PESALIGN(EC32(section_hdr[0].VirtualSize), EC32(optional_hdr32.SectionAlignment))) break;
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
      ep = cli_rawaddr(eprva, section_hdr, nsections, &err, EC32(optional_hdr32.SectionAlignment), EC32(optional_hdr32.FileAlignment));
      if (lseek(desc, ep, SEEK_SET)==-1) break;
      if (cli_readn(desc, buff, 5)!=5) break;
      eprva=eprva+5+cli_readint32(buff+1);
      cli_dbgmsg("NsPack: OEP = %08x\n", eprva);

      if(!(tempfile = cli_gentemp(NULL))) {
	free(src);
	free(dest);
	free(section_hdr);
	return CL_EMEM;
      }

      if((ndesc = open(tempfile, O_RDWR|O_CREAT|O_TRUNC|O_BINARY, S_IRWXU)) < 0) {
	cli_dbgmsg("NsPack: Can't create file %s\n", tempfile);
	free(tempfile);
	free(src);
	free(dest);
	free(section_hdr);
	return CL_EIO;
      }

      if (!unspack(src, dest, ctx, EC32(section_hdr[0].VirtualAddress), EC32(optional_hdr32.ImageBase), eprva, ndesc)) {
	free(src);
	free(dest);
	if (cli_leavetemps_flag)
	  cli_dbgmsg("NsPack: Unpacked and rebuilt executable saved in %s\n", tempfile);
	else
	  cli_dbgmsg("NsPack: Unpacked and rebuilt executable\n");
	fsync(ndesc);
	lseek(ndesc, 0, SEEK_SET);

	if(cli_magic_scandesc(ndesc, ctx) == CL_VIRUS) {
	  free(section_hdr);
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
#endif /* CL_EXPERIMENTAL - NsPack */

    /* to be continued ... */

    free(section_hdr);
    return CL_CLEAN;
}

int cli_peheader(int desc, struct cli_exe_info *peinfo)
{
	uint16_t e_magic; /* DOS signature ("MZ") */
	uint32_t e_lfanew; /* address of new exe header */
	uint32_t min = 0, max = 0;
	struct pe_image_file_hdr file_hdr;
	struct pe_image_optional_hdr32 optional_hdr32;
	struct pe_image_optional_hdr64 optional_hdr64;
	struct pe_image_section_hdr *section_hdr;
	struct stat sb;
	int i;
	unsigned int err, pe_plus = 0;


    cli_dbgmsg("in cli_peheader\n");

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

    if(lseek(desc, e_lfanew, SEEK_SET) < 0) {
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

    peinfo->nsections = EC16(file_hdr.NumberOfSections);

    if(EC16(file_hdr.SizeOfOptionalHeader) != sizeof(struct pe_image_optional_hdr32)) {
	if(EC16(file_hdr.SizeOfOptionalHeader) == sizeof(struct pe_image_optional_hdr64)) {
	    pe_plus = 1;
	} else {
	    cli_dbgmsg("Incorrect value of SizeOfOptionalHeader\n");
	    return -1;
	}
    }

    if(!pe_plus) { /* PE */
	cli_dbgmsg("File format: PE\n");

	if(cli_readn(desc, &optional_hdr32, sizeof(struct pe_image_optional_hdr32)) != sizeof(struct pe_image_optional_hdr32)) {
	    cli_dbgmsg("Can't optional file header\n");
	    return -1;
	}

    } else { /* PE+ */
	cli_dbgmsg("File format: PE32+\n");

	if(cli_readn(desc, &optional_hdr64, sizeof(struct pe_image_optional_hdr64)) != sizeof(struct pe_image_optional_hdr64)) {
	    cli_dbgmsg("Can't optional file header\n");
	    return -1;
	}
    }

    peinfo->section = (struct cli_exe_section *) cli_calloc(peinfo->nsections, sizeof(struct cli_exe_section));

    if(!peinfo->section) {
	cli_dbgmsg("Can't allocate memory for section headers\n");
	return -1;
    }

    if(fstat(desc, &sb) == -1) {
	cli_dbgmsg("fstat failed\n");
	free(peinfo->section);
	return -1;
    }

    section_hdr = (struct pe_image_section_hdr *) cli_calloc(peinfo->nsections, sizeof(struct pe_image_section_hdr));

    if(!section_hdr) {
	cli_dbgmsg("Can't allocate memory for section headers\n");
	free(peinfo->section);
	return -1;
    }

    for(i = 0; i < peinfo->nsections; i++) {

	if(cli_readn(desc, &section_hdr[i], sizeof(struct pe_image_section_hdr)) != sizeof(struct pe_image_section_hdr)) {
	    cli_dbgmsg("Can't read section header\n");
	    cli_dbgmsg("Possibly broken PE file\n");
	    free(section_hdr);
	    free(peinfo->section);
	    return -1;
	}

	peinfo->section[i].rva = EC32(section_hdr[i].VirtualAddress);
	peinfo->section[i].vsz = EC32(section_hdr[i].VirtualSize);
	peinfo->section[i].raw = EC32(section_hdr[i].PointerToRawData);
	peinfo->section[i].rsz = EC32(section_hdr[i].SizeOfRawData);

	if(!i) {
	    min = EC32(section_hdr[i].VirtualAddress);
	    max = EC32(section_hdr[i].VirtualAddress) + EC32(section_hdr[i].SizeOfRawData);
	} else {
	    if(EC32(section_hdr[i].VirtualAddress) < min)
		min = EC32(section_hdr[i].VirtualAddress);

	    if(EC32(section_hdr[i].VirtualAddress) + EC32(section_hdr[i].SizeOfRawData) > max)
		max = EC32(section_hdr[i].VirtualAddress) + EC32(section_hdr[i].SizeOfRawData);
	}
    }

    if(pe_plus)
	peinfo->ep = EC32(optional_hdr64.AddressOfEntryPoint);
    else
	peinfo->ep = EC32(optional_hdr32.AddressOfEntryPoint);

	if(peinfo->ep >= min && !(peinfo->ep = cli_rawaddr(peinfo->ep, section_hdr, peinfo->nsections, &err, 0, 0)) && err) {
	cli_dbgmsg("Possibly broken PE file\n");
	free(section_hdr);
	free(peinfo->section);
	return -1;
    }

    free(section_hdr);
    return 0;
}

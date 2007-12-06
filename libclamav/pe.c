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
#include <stdarg.h>

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

#define CLI_UNPSIZELIMITS(NAME,CHK) \
if(ctx->limits && ctx->limits->maxfilesize && (CHK) > ctx->limits->maxfilesize) { \
    cli_dbgmsg(NAME": Sizes exceeded (%lu > %lu)\n", (CHK), ctx->limits->maxfilesize); \
    free(exe_sections); \
    if(BLOCKMAX) { \
        *ctx->virname = "PE."NAME".ExceededFileSize"; \
        return CL_VIRUS; \
    } else { \
        return CL_CLEAN; \
    } \
}

#define CLI_UNPTEMP(NAME,FREEME) \
if(!(tempfile = cli_gentemp(NULL))) { \
    cli_multifree FREEME; \
    return CL_EMEM; \
} \
if((ndesc = open(tempfile, O_RDWR|O_CREAT|O_TRUNC|O_BINARY, S_IRWXU)) < 0) { \
    cli_dbgmsg(NAME": Can't create file %s\n", tempfile); \
    free(tempfile); \
    cli_multifree FREEME; \
    return CL_EIO; \
}

#define CLI_TMPUNLK() if(!cli_leavetemps_flag) unlink(tempfile)

#define FSGCASE(NAME,FREESEC) \
    case 0: /* Unpacked and NOT rebuilt */ \
	cli_dbgmsg(NAME": Successfully decompressed\n"); \
	close(ndesc); \
	unlink(tempfile); \
	free(tempfile); \
	FREESEC; \
	found = 0; \
	upx_success = 1; \
	break; /* FSG ONLY! - scan raw data after upx block */

#define SPINCASE() \
    case 2: \
	free(spinned); \
	close(ndesc); \
	unlink(tempfile); \
	cli_dbgmsg("PESpin: Size exceeded\n"); \
	if(BLOCKMAX) { \
	    free(tempfile); \
	    free(exe_sections); \
	    *ctx->virname = "PE.Pespin.ExceededFileSize"; \
	    return CL_VIRUS; \
	} \
	free(tempfile); \
	break; \

#define CLI_UNPRESULTS_(NAME,FSGSTUFF,EXPR,GOOD,FREEME) \
    switch(EXPR) { \
    case GOOD: /* Unpacked and rebuilt */ \
	if(cli_leavetemps_flag) \
	    cli_dbgmsg(NAME": Unpacked and rebuilt executable saved in %s\n", tempfile); \
	else \
	    cli_dbgmsg(NAME": Unpacked and rebuilt executable\n"); \
	cli_multifree FREEME; \
        free(exe_sections); \
	fsync(ndesc); \
	lseek(ndesc, 0, SEEK_SET); \
	cli_dbgmsg("***** Scanning rebuilt PE file *****\n"); \
	if(cli_magic_scandesc(ndesc, ctx) == CL_VIRUS) { \
	    close(ndesc); \
	    CLI_TMPUNLK(); \
	    free(tempfile); \
	    return CL_VIRUS; \
	} \
	close(ndesc); \
	CLI_TMPUNLK(); \
	free(tempfile); \
	return CL_CLEAN; \
\
FSGSTUFF; \
\
    default: \
	cli_dbgmsg(NAME": Unpacking failed\n"); \
	close(ndesc); \
	unlink(tempfile); \
	cli_multifree FREEME; \
        free(tempfile); \
    }


#define CLI_UNPRESULTS(NAME,EXPR,GOOD,FREEME) CLI_UNPRESULTS_(NAME,NULL,EXPR,GOOD,FREEME)
#define CLI_UNPRESULTSFSG1(NAME,EXPR,GOOD,FREEME) CLI_UNPRESULTS_(NAME,FSGCASE(NAME,free(sections)),EXPR,GOOD,FREEME)
#define CLI_UNPRESULTSFSG2(NAME,EXPR,GOOD,FREEME) CLI_UNPRESULTS_(NAME,FSGCASE(NAME,NULL),EXPR,GOOD,FREEME)

struct offset_list {
    uint32_t offset;
    struct offset_list *next;
};

static void cli_multifree(void *f, ...) {
    void *ff;
    va_list ap;
    free(f);
    va_start(ap, f);
    while((ff=va_arg(ap, void*))) free(ff);
    va_end(ap);
}

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


/*
static int cli_ddump(int desc, int offset, int size, const char *file) {
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

static off_t cli_seeksect(int fd, struct cli_exe_section *s) {
    off_t ret;

    if(!s->rsz) return 0;
    if((ret=lseek(fd, s->raw, SEEK_SET)) == -1)
	cli_dbgmsg("cli_seeksect: lseek() failed\n");
    return ret+1;
}

static unsigned int cli_md5sect(int fd, struct cli_exe_section *s, unsigned char *digest) {
    void *hashme;
    cli_md5_ctx md5;

    if (s->rsz > CLI_MAX_ALLOCATION) {
	cli_dbgmsg("cli_md5sect: skipping md5 calculation for too big section\n");
	return 0;
    }

    if(!cli_seeksect(fd, s)) return 0;

    if(!(hashme=cli_malloc(s->rsz))) {
	cli_dbgmsg("cli_md5sect: out of memory\n");
	return 0;
    }

    if(cli_readn(fd, hashme, s->rsz)!=s->rsz) {
	cli_dbgmsg("cli_md5sect: unable to read section data\n");
	return 0;
    }

    cli_md5_init(&md5);
    cli_md5_update(&md5, hashme, s->rsz);
    free(hashme);
    cli_md5_final(digest, &md5);
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
	char sname[9], buff[4096], epbuff[4096], *tempfile;
	uint32_t epsize;
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


    if(!ctx) {
	cli_errmsg("cli_scanpe: ctx == NULL\n");
	return CL_ENULLARG;
    }

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
	    break;
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

	    if(SCAN_ALGO && (DCONF & PE_CONF_POLIPOS) && !*sname && exe_sections[i].vsz > 40000 && exe_sections[i].vsz < 70000 && exe_sections[i].chr == 0xe0000060) polipos = i;

	    /* check MD5 section sigs */
	    md5_sect = ctx->engine->md5_sect;
	    if((DCONF & PE_CONF_MD5SECT) && md5_sect) {
		found = 0;
		for(j = 0; j < md5_sect->soff_len && md5_sect->soff[j] <= exe_sections[i].rsz; j++) {
		    if(md5_sect->soff[j] == exe_sections[i].rsz) {
			unsigned char md5_dig[16];
			if(cli_md5sect(desc, &exe_sections[i], md5_dig) && cli_bm_scanbuff(md5_dig, 16, ctx->virname, ctx->engine->md5_sect, 0, 0, -1) == CL_VIRUS) {
				free(section_hdr);
				free(exe_sections);
				return CL_VIRUS;
			}
			break;
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

    lseek(desc, ep, SEEK_SET);
    epsize = cli_readn(desc, epbuff, 4096);

    /* Attempt to detect some popular polymorphic viruses */

    /* W32.Parite.B */
    if(SCAN_ALGO && (DCONF & PE_CONF_PARITE) && !dll && epsize == 4096 && ep == exe_sections[nsections - 1].raw) {
        const char *pt = cli_memstr(epbuff, 4040, "\x47\x65\x74\x50\x72\x6f\x63\x41\x64\x64\x72\x65\x73\x73\x00", 15);
	if(pt) {
	    pt += 15;
	    if((((uint32_t)cli_readint32(pt) ^ (uint32_t)cli_readint32(pt + 4)) == 0x505a4f) && (((uint32_t)cli_readint32(pt + 8) ^ (uint32_t)cli_readint32(pt + 12)) == 0xffffb) && (((uint32_t)cli_readint32(pt + 16) ^ (uint32_t)cli_readint32(pt + 20)) == 0xb8)) {
	        *ctx->virname = "W32.Parite.B";
		free(exe_sections);
		return CL_VIRUS;
	    }
	}
    }

    /* Kriz */
    if(SCAN_ALGO && (DCONF & PE_CONF_KRIZ) && epsize >= 200 && CLI_ISCONTAINED(exe_sections[nsections - 1].raw, exe_sections[nsections - 1].rsz, ep, 0x0fd2) && epbuff[1]=='\x9c' && epbuff[2]=='\x60') {
	enum {KZSTRASH,KZSCDELTA,KZSPDELTA,KZSGETSIZE,KZSXORPRFX,KZSXOR,KZSDDELTA,KZSLOOP,KZSTOP};
	uint8_t kzs[] = {KZSTRASH,KZSCDELTA,KZSPDELTA,KZSGETSIZE,KZSTRASH,KZSXORPRFX,KZSXOR,KZSTRASH,KZSDDELTA,KZSTRASH,KZSLOOP,KZSTOP};
	uint8_t *kzstate = kzs;
	uint8_t *kzcode = (uint8_t *)epbuff + 3;
	uint8_t kzdptr=0xff, kzdsize=0xff;
	int kzlen = 197, kzinitlen=0xffff, kzxorlen=-1;
	cli_dbgmsg("in kriz\n");

	while(*kzstate!=KZSTOP) {
	    uint8_t op;
	    if(kzlen<=6) break;
	    op = *kzcode++;
	    kzlen--;
	    switch (*kzstate) {
	    case KZSTRASH: case KZSGETSIZE: {
		int opsz=0;
		switch(op) {
		case 0x81:
		    kzcode+=5;
		    kzlen-=5;
		    break;
		case 0xb8: case 0xb9: case 0xba: case 0xbb: case 0xbd: case 0xbe: case 0xbf:
		    if(*kzstate==KZSGETSIZE && cli_readint32(kzcode)==0x0fd2) {
			kzinitlen = kzlen-5;
			kzdsize=op-0xb8;
			kzstate++;
			op=4; /* fake the register to avoid breaking out */
			cli_dbgmsg("kriz: using #%d as size counter\n", kzdsize);
		    }
		    opsz=4;
		case 0x48: case 0x49: case 0x4a: case 0x4b: case 0x4d: case 0x4e: case 0x4f:
		    op&=7;
		    if(op!=kzdptr && op!=kzdsize) {
			kzcode+=opsz;
			kzlen-=opsz;
			break;
		    }
		default:
		    kzcode--;
		    kzlen++;
		    kzstate++;
		}
		break;
	    }
	    case KZSCDELTA:
		if(op==0xe8 && (uint32_t)cli_readint32(kzcode) < 0xff) {
		    kzlen-=*kzcode+4;
		    kzcode+=*kzcode+4;
		    kzstate++;
		} else *kzstate=KZSTOP;
		break;
	    case KZSPDELTA:
		if((op&0xf8)==0x58 && (kzdptr=op-0x58)!=4) {
		    kzstate++;
		    cli_dbgmsg("kriz: using #%d as pointer\n", kzdptr);
		} else *kzstate=KZSTOP;
		break;
	    case KZSXORPRFX:
		kzstate++;
		if(op==0x3e) break;
	    case KZSXOR:
		if (op==0x80 && *kzcode==kzdptr+0xb0) {
		    kzxorlen=kzlen;
		    kzcode+=+6;
		    kzlen-=+6;
		    kzstate++;
		} else *kzstate=KZSTOP;
		break;
	    case KZSDDELTA:
		if (op==kzdptr+0x48) kzstate++;
		else *kzstate=KZSTOP;
		break;
	    case KZSLOOP:
		if (op==kzdsize+0x48 && *kzcode==0x75 && kzlen-(int8_t)kzcode[1]-3<=kzinitlen && kzlen-(int8_t)kzcode[1]>=kzxorlen) {
		    *ctx->virname = "W32.Kriz";
		    free(exe_sections);
		    return CL_VIRUS;
		}
		cli_dbgmsg("kriz: loop out of bounds, corrupted sample?\n");
		kzstate++;
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
    while(polipos && !dll && nsections > 2 && nsections < 13 && e_lfanew <= 0x800 && (EC16(optional_hdr32.Subsystem) == 2 || EC16(optional_hdr32.Subsystem) == 3) && EC16(file_hdr.Machine) == 0x14c && optional_hdr32.SizeOfStackReserve >= 0x80000) {
	uint32_t jump, jold, *jumps = NULL;
	uint8_t *code;
	unsigned int xsjs = 0;

	if(exe_sections[0].rsz > CLI_MAX_ALLOCATION) break;
	if(!cli_seeksect(desc, &exe_sections[0])) break;
	if(!(code=cli_malloc(exe_sections[0].rsz))) {
	    free(exe_sections);
	    return CL_EMEM;
	}
	if(cli_readn(desc, code, exe_sections[0].rsz)!=exe_sections[0].rsz) {
	    free(exe_sections);
	    return CL_EIO;
	}
	for(i=0; i<exe_sections[0].rsz - 5; i++) {
	    if((uint8_t)(code[i]-0xe8) > 1) continue;
	    jump = cli_rawaddr(exe_sections[0].rva+i+5+cli_readint32(&code[i+1]), exe_sections, nsections, &err, fsize, hdr_size);
	    if(err || !CLI_ISCONTAINED(exe_sections[polipos].raw, exe_sections[polipos].rsz, jump, 9)) continue;
	    if(xsjs % 128 == 0) {
		if(xsjs == 1280) break;
		if(!(jumps=(uint32_t *)cli_realloc2(jumps, (xsjs+128)*sizeof(uint32_t)))) {
		    free(code);
		    free(exe_sections);
		    return CL_EMEM;
		}
	    }
	    j=0;
	    for(; j<xsjs; j++) {
		if(jumps[j]<jump) continue;
		if(jumps[j]==jump) {
		    xsjs--;
		    break;
		}
		jold=jumps[j];
		jumps[j]=jump;
		jump=jold;
	    }
	    jumps[j]=jump;
	    xsjs++;
	}
	free(code);
	if(!xsjs) break;
	cli_dbgmsg("Polipos: Checking %d xsect jump(s)\n", xsjs);
	for(i=0;i<xsjs;i++) {
	    lseek(desc, jumps[i], SEEK_SET);
	    if(cli_readn(desc, buff, 9) != 9) continue;
	    if((jump=cli_readint32(buff))==0x60ec8b55 || (buff[4]=='\xec' && ((jump==0x83ec8b55 && buff[6]=='\x60') || (jump==0x81ec8b55 && !buff[7] && !buff[8])))) {
		*ctx->virname = "W32.Polipos.A";
		free(jumps);
		free(exe_sections);
		return CL_VIRUS;
	    }
	}
	free(jumps);
	break;
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
    if (found && (DCONF & PE_CONF_MEW) && epsize>=16 && epbuff[0]=='\xe9') {
	uint32_t fileoffset;

	fileoffset = (vep + cli_readint32(epbuff + 1) + 5);
	while (fileoffset == 0x154 || fileoffset == 0x158) {
	    uint32_t offdiff, uselzma;

	    cli_dbgmsg ("MEW: found MEW characteristics %08X + %08X + 5 = %08X\n", 
			cli_readint32(epbuff + 1), vep, cli_readint32(epbuff + 1) + vep + 5);

	    if(lseek(desc, fileoffset, SEEK_SET) == -1) {
	        cli_dbgmsg("MEW: lseek() failed\n");
		free(exe_sections);
		return CL_EIO;
	    }

	    if((bytes = read(desc, buff, 0xb0)) != 0xb0) {
	        cli_dbgmsg("MEW: Can't read 0xb0 bytes at 0x%x (%d) %d\n", fileoffset, fileoffset, bytes);
		break;
	    }

	    if (fileoffset == 0x154) cli_dbgmsg("MEW: Win9x compatibility was set!\n");
	    else cli_dbgmsg("MEW: Win9x compatibility was NOT set!\n");

	    if((offdiff = cli_readint32(buff+1) - EC32(optional_hdr32.ImageBase)) <= exe_sections[i + 1].rva || offdiff >= exe_sections[i + 1].rva + exe_sections[i + 1].raw - 4) {
	        cli_dbgmsg("MEW: ESI is not in proper section\n");
		break;
	    }
	    offdiff -= exe_sections[i + 1].rva;

	    if(!cli_seeksect(desc, &exe_sections[i + 1])) {
		free(exe_sections);
		return CL_EIO;
	    }
	    ssize = exe_sections[i + 1].vsz;
	    dsize = exe_sections[i].vsz;

	    cli_dbgmsg("MEW: ssize %08x dsize %08x offdiff: %08x\n", ssize, dsize, offdiff);

	    CLI_UNPSIZELIMITS("MEW", MAX(ssize, dsize));
	    CLI_UNPSIZELIMITS("MEW", MAX(ssize + dsize, exe_sections[i + 1].rsz));

	    /* allocate needed buffer */
	    if (!(src = cli_calloc (ssize + dsize, sizeof(char)))) {
	        free(exe_sections);
		return CL_EMEM;
	    }

	    if (exe_sections[i + 1].rsz < offdiff + 12 || exe_sections[i + 1].rsz > ssize) {
	        cli_dbgmsg("MEW: Size mismatch: %08x\n", exe_sections[i + 1].rsz);
		free(src);
		break;
	    }

	    if((bytes = read(desc, src + dsize, exe_sections[i + 1].rsz)) != exe_sections[i + 1].rsz) {
	        cli_dbgmsg("MEW: Can't read %d bytes [read: %d]\n", exe_sections[i + 1].rsz, bytes);
		free(exe_sections);
		free(src);
		return CL_EIO;
	    }
	    cli_dbgmsg("MEW: %d (%08x) bytes read\n", bytes, bytes);

	    /* count offset to lzma proc, if lzma used, 0xe8 -> call */
	    if (buff[0x7b] == '\xe8') {
	        if (!CLI_ISCONTAINED(exe_sections[1].rva, exe_sections[1].vsz, cli_readint32(buff + 0x7c) + fileoffset + 0x80, 4)) {
		    cli_dbgmsg("MEW: lzma proc out of bounds!\n");
		    free(src);
		    break; /* to next unpacker in chain */
		}
		uselzma = cli_readint32(buff + 0x7c) - (exe_sections[0].rva - fileoffset - 0x80);
	    } else {
	        uselzma = 0;
	    }

	    CLI_UNPTEMP("MEW",(src,exe_sections,0));
	    CLI_UNPRESULTS("MEW",(unmew11(i, src, offdiff, ssize, dsize, EC32(optional_hdr32.ImageBase), exe_sections[0].rva, uselzma, NULL, NULL, ndesc)),1,(src,0));
	    break;
	}
    }

    if(epsize<168) {
	free(exe_sections);
	return CL_CLEAN;
    }

    if (found || upack) {
	/* Check EP for UPX vs. FSG vs. Upack */

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
 	while(((upack && nsections == 3) && /* 3 sections */
	    ((
	     epbuff[0] == '\xbe' && cli_readint32(epbuff + 1) - EC32(optional_hdr32.ImageBase) > min && /* mov esi */
	     epbuff[5] == '\xad' && epbuff[6] == '\x50' /* lodsd; push eax */
	     )
	    || 
	    /* based on 0297729 sample from aCaB */
	    (epbuff[0] == '\xbe' && cli_readint32(epbuff + 1) - EC32(optional_hdr32.ImageBase) > min && /* mov esi */
	     epbuff[5] == '\xff' && epbuff[6] == '\x36' /* push [esi] */
	     )
	   )) 
	   ||
	   ((!upack && nsections == 2) && /* 2 sections */
	    (( /* upack 0.39-2s */
	     epbuff[0] == '\x60' && epbuff[1] == '\xe8' && cli_readint32(epbuff+2) == 0x9 /* pusha; call+9 */
	     )
	    ||
	    ( /* upack 1.1/1.2, based on 2 samples */
	     epbuff[0] == '\xbe' && cli_readint32(epbuff+1) - EC32(optional_hdr32.ImageBase) < min &&  /* mov esi */
	     cli_readint32(epbuff + 1) - EC32(optional_hdr32.ImageBase) > 0 &&
	     epbuff[5] == '\xad' && epbuff[6] == '\x8b' && epbuff[7] == '\xf8' /* loads;  mov edi, eax */
	     )
	   ))
	   ) { 
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

	    CLI_UNPSIZELIMITS("Upack", MAX(MAX(dsize, ssize), exe_sections[1].ursz));

	    if (exe_sections[1].rva - off > dsize || exe_sections[1].rva - off > dsize - exe_sections[1].ursz || (upack && (exe_sections[2].rva - exe_sections[0].rva > dsize || exe_sections[2].rva - exe_sections[0].rva > dsize - ssize)) || ssize > dsize) {
	        cli_dbgmsg("Upack: probably malformed pe-header, skipping to next unpacker\n");
		break;
	    }
			
	    if((dest = (char *) cli_calloc(dsize, sizeof(char))) == NULL) {
	        free(exe_sections);
		return CL_EMEM;
	    }

	    lseek(desc, 0, SEEK_SET);
	    if(read(desc, dest, ssize) != ssize) {
	        cli_dbgmsg("Upack: Can't read raw data of section 0\n");
		free(exe_sections);
		free(dest);
		return CL_EIO;
	    }

	    if(upack) memmove(dest + exe_sections[2].rva - exe_sections[0].rva, dest, ssize);

	    lseek(desc, exe_sections[1].uraw, SEEK_SET);

	    if(read(desc, dest + exe_sections[1].rva - off, exe_sections[1].ursz) != exe_sections[1].ursz) {
		cli_dbgmsg("Upack: Can't read raw data of section 1\n");
		free(exe_sections);
		free(dest);
		return CL_EIO;
	    }

	    CLI_UNPTEMP("Upack",(dest,exe_sections,0));
	    CLI_UNPRESULTS("Upack",(unupack(upack, dest, dsize, epbuff, vma, ep, EC32(optional_hdr32.ImageBase), exe_sections[0].rva, ndesc)),1,(dest,0));
	    break;
	}
    }

    
    while(found && (DCONF & PE_CONF_FSG) && epbuff[0] == '\x87' && epbuff[1] == '\x25') {

	/* FSG v2.0 support - thanks to aCaB ! */

	uint32_t newesi, newedi, newebx, newedx;
	
	ssize = exe_sections[i + 1].rsz;
	dsize = exe_sections[i].vsz;

	CLI_UNPSIZELIMITS("FSG", MAX(dsize, ssize));

	if(ssize <= 0x19 || dsize <= ssize) {
	    cli_dbgmsg("FSG: Size mismatch (ssize: %d, dsize: %d)\n", ssize, dsize);
	    free(exe_sections);
	    return CL_CLEAN;
	}
	
	newedx = cli_readint32(epbuff + 2) - EC32(optional_hdr32.ImageBase);
	if(!CLI_ISCONTAINED(exe_sections[i + 1].rva, exe_sections[i + 1].rsz, newedx, 4)) {
	    cli_dbgmsg("FSG: xchg out of bounds (%x), giving up\n", newedx);
	    break;
	}
	
	if((src = (char *) cli_malloc(ssize)) == NULL) {
	    free(exe_sections);
	    return CL_EMEM;
	}

	if(!cli_seeksect(desc, &exe_sections[i + 1]) || (unsigned int) cli_readn(desc, src, ssize) != ssize) {
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

	CLI_UNPTEMP("FSG",(src,dest,exe_sections,0));
	CLI_UNPRESULTSFSG2("FSG",(unfsg_200(newesi - exe_sections[i + 1].rva + src, dest, ssize + exe_sections[i + 1].rva - newesi, dsize, newedi, EC32(optional_hdr32.ImageBase), newedx, ndesc)),1,(src,dest,0));
	break;
    }


    while(found && (DCONF & PE_CONF_FSG) && epbuff[0] == '\xbe' && cli_readint32(epbuff + 1) - EC32(optional_hdr32.ImageBase) < min) {

	/* FSG support - v. 1.33 (thx trog for the many samples) */

	int sectcnt = 0;
	char *support;
	uint32_t newesi, newedi, oldep, gp, t;
	struct cli_exe_section *sections;

	ssize = exe_sections[i + 1].rsz;
	dsize = exe_sections[i].vsz;

	CLI_UNPSIZELIMITS("FSG", MAX(dsize, ssize));

	if(ssize <= 0x19 || dsize <= ssize) {
	    cli_dbgmsg("FSG: Size mismatch (ssize: %d, dsize: %d)\n", ssize, dsize);
	    free(exe_sections);
	    return CL_CLEAN;
	}

	if(!(gp = cli_rawaddr(cli_readint32(epbuff + 1) - EC32(optional_hdr32.ImageBase), NULL, 0 , &err, fsize, hdr_size)) && err ) {
	    cli_dbgmsg("FSG: Support data out of padding area\n");
	    break;
	}

	lseek(desc, gp, SEEK_SET);
	gp = exe_sections[i + 1].raw - gp;

	CLI_UNPSIZELIMITS("FSG", gp)

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

	    if(rva % 0x1000) cli_dbgmsg("FSG: Original section %d is misaligned\n", sectcnt);

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

	if(!cli_seeksect(desc, &exe_sections[i + 1]) || (unsigned int) cli_readn(desc, src, ssize) != ssize) {
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

	oldep = vep + 161 + 6 + cli_readint32(epbuff+163);
	cli_dbgmsg("FSG: found old EP @%x\n", oldep);

	CLI_UNPTEMP("FSG",(src,dest,sections,exe_sections,0));
	CLI_UNPRESULTSFSG1("FSG",(unfsg_133(src + newesi - exe_sections[i + 1].rva, dest, ssize + exe_sections[i + 1].rva - newesi, dsize, sections, sectcnt, EC32(optional_hdr32.ImageBase), oldep, ndesc)),1,(src,dest,sections,0));
	break; /* were done with 1.33 */
    }


    while(found && (DCONF & PE_CONF_FSG) && epbuff[0] == '\xbb' && cli_readint32(epbuff + 1) - EC32(optional_hdr32.ImageBase) < min && epbuff[5] == '\xbf' && epbuff[10] == '\xbe' && vep >= exe_sections[i + 1].rva && vep - exe_sections[i + 1].rva > exe_sections[i + 1].rva - 0xe0 ) {

	/* FSG support - v. 1.31 */

	int sectcnt = 0;
	uint32_t t;
	uint32_t gp = cli_rawaddr(cli_readint32(epbuff+1) - EC32(optional_hdr32.ImageBase), NULL, 0 , &err, fsize, hdr_size);
	char *support;
	uint32_t newesi = cli_readint32(epbuff+11) - EC32(optional_hdr32.ImageBase);
	uint32_t newedi = cli_readint32(epbuff+6) - EC32(optional_hdr32.ImageBase);
	uint32_t oldep = vep - exe_sections[i + 1].rva;
	struct cli_exe_section *sections;

	ssize = exe_sections[i + 1].rsz;
	dsize = exe_sections[i].vsz;


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

	CLI_UNPSIZELIMITS("FSG", MAX(dsize, ssize));

	if(ssize <= 0x19 || dsize <= ssize) {
	    cli_dbgmsg("FSG: Size mismatch (ssize: %d, dsize: %d)\n", ssize, dsize);
	    free(exe_sections);
	    return CL_CLEAN;
	}

	lseek(desc, gp, SEEK_SET);
	gp = exe_sections[i + 1].raw - gp;

	CLI_UNPSIZELIMITS("FSG", gp)

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

	if(!cli_seeksect(desc, &exe_sections[i + 1]) || (unsigned int) cli_readn(desc, src, ssize) != ssize) {
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

	gp = 0xda + 6*(epbuff[16]=='\xe8');
	oldep = vep + gp + 6 + cli_readint32(src+gp+2+oldep);
	cli_dbgmsg("FSG: found old EP @%x\n", oldep);

	CLI_UNPTEMP("FSG",(src,dest,sections,exe_sections,0));
	CLI_UNPRESULTSFSG1("FSG",(unfsg_133(src + newesi - exe_sections[i + 1].rva, dest, ssize + exe_sections[i + 1].rva - newesi, dsize, sections, sectcnt, EC32(optional_hdr32.ImageBase), oldep, ndesc)),1,(src,dest,sections,0));
	break; /* were done with 1.31 */
    }


    if(found && (DCONF & PE_CONF_UPX)) {

	/* UPX support */

	/* we assume (i + 1) is UPX1 */
	ssize = exe_sections[i + 1].rsz;
	dsize = exe_sections[i].vsz + exe_sections[i + 1].vsz;

	CLI_UNPSIZELIMITS("UPX", MAX(dsize, ssize));

	if(ssize <= 0x19 || dsize <= ssize || dsize > CLI_MAX_ALLOCATION ) {
	    cli_dbgmsg("UPX: Size mismatch or dsize too big (ssize: %d, dsize: %d)\n", ssize, dsize);
	    free(exe_sections);
	    return CL_CLEAN;
	}

	if((src = (char *) cli_malloc(ssize)) == NULL) {
	    free(exe_sections);
	    return CL_EMEM;
	}

	if((dest = (char *) cli_calloc(dsize + 8192, sizeof(char))) == NULL) {
	    free(exe_sections);
	    free(src);
	    return CL_EMEM;
	}

	if(!cli_seeksect(desc, &exe_sections[i + 1]) || (unsigned int) cli_readn(desc, src, ssize) != ssize) {
	    cli_dbgmsg("UPX: Can't read raw data of section %d\n", i+1);
	    free(exe_sections);
	    free(src);
	    free(dest);
	    return CL_EIO;
	}

	/* try to detect UPX code */
	if(cli_memstr(UPX_NRV2B, 24, epbuff + 0x69, 13) || cli_memstr(UPX_NRV2B, 24, epbuff + 0x69 + 8, 13)) {
	    cli_dbgmsg("UPX: Looks like a NRV2B decompression routine\n");
	    upxfn = upx_inflate2b;
	} else if(cli_memstr(UPX_NRV2D, 24, epbuff + 0x69, 13) || cli_memstr(UPX_NRV2D, 24, epbuff + 0x69 + 8, 13)) {
	    cli_dbgmsg("UPX: Looks like a NRV2D decompression routine\n");
	    upxfn = upx_inflate2d;
	} else if(cli_memstr(UPX_NRV2E, 24, epbuff + 0x69, 13) || cli_memstr(UPX_NRV2E, 24, epbuff + 0x69 + 8, 13)) {
	    cli_dbgmsg("UPX: Looks like a NRV2E decompression routine\n");
	    upxfn = upx_inflate2e;
	}

	if(upxfn) {
	    int skew = cli_readint32(epbuff + 2) - EC32(optional_hdr32.ImageBase) - exe_sections[i + 1].rva;

	    if(epbuff[1] != '\xbe' || skew <= 0 || skew > 0xfff) { /* FIXME: legit skews?? */
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

	CLI_UNPTEMP("UPX/FSG",(dest,0));

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
	    CLI_TMPUNLK();
	    free(tempfile);
	    return CL_VIRUS;
	}

	close(ndesc);
	CLI_TMPUNLK();
	free(tempfile);
	return ret;
    }


    /* Petite */

    if(epsize<200) {
	free(exe_sections);
	return CL_CLEAN;
    }

    found = 2;

    if(epbuff[0] != '\xb8' || (uint32_t) cli_readint32(epbuff + 1) != exe_sections[nsections - 1].rva + EC32(optional_hdr32.ImageBase)) {
	if(nsections < 2 || epbuff[0] != '\xb8' || (uint32_t) cli_readint32(epbuff + 1) != exe_sections[nsections - 2].rva + EC32(optional_hdr32.ImageBase))
	    found = 0;
	else
	    found = 1;
    }

    if(found && (DCONF & PE_CONF_PETITE)) {
	cli_dbgmsg("Petite: v2.%d compression detected\n", found);

	if(cli_readint32(epbuff + 0x80) == 0x163c988d) {
	    cli_dbgmsg("Petite: level zero compression is not supported yet\n");
	} else {
	    dsize = max - min;

	    CLI_UNPSIZELIMITS("Petite", dsize);

	    if((dest = (char *) cli_calloc(dsize, sizeof(char))) == NULL) {
		cli_dbgmsg("Petite: Can't allocate %d bytes\n", dsize);
		free(exe_sections);
		return CL_EMEM;
	    }

	    for(i = 0 ; i < nsections; i++) {
		if(exe_sections[i].raw) {
		    if(!cli_seeksect(desc, &exe_sections[i]) || (unsigned int) cli_readn(desc, dest + exe_sections[i].rva - min, exe_sections[i].ursz) != exe_sections[i].ursz) {
			free(exe_sections);
			free(dest);
			return CL_EIO;
		    }
		}
	    }

	    CLI_UNPTEMP("Petite",(dest,exe_sections,0));
	    CLI_UNPRESULTS("Petite",(petite_inflate2x_1to9(dest, min, max - min, exe_sections, nsections - (found == 1 ? 1 : 0), EC32(optional_hdr32.ImageBase),vep, ndesc, found, EC32(optional_hdr32.DataDirectory[2].VirtualAddress),EC32(optional_hdr32.DataDirectory[2].Size))),0,(dest,0));
	}
    }

    /* PESpin 1.1 */

    if((DCONF & PE_CONF_PESPIN) && nsections > 1 &&
       vep >= exe_sections[nsections - 1].rva &&
       vep < exe_sections[nsections - 1].rva + exe_sections[nsections - 1].rsz - 0x3217 - 4 &&
       memcmp(epbuff+4, "\xe8\x00\x00\x00\x00\x8b\x1c\x24\x83\xc3", 10) == 0)  {

	char *spinned;

	CLI_UNPSIZELIMITS("PEspin", fsize);

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

	CLI_UNPTEMP("PESpin",(spinned,exe_sections,0));
	CLI_UNPRESULTS_("PEspin",SPINCASE(),(unspin(spinned, fsize, exe_sections, nsections - 1, vep, ndesc, ctx)),0,(spinned,0));
    }


    /* yC 1.3 */

    if((DCONF & PE_CONF_YC) && nsections > 1 &&
       EC32(optional_hdr32.AddressOfEntryPoint) == exe_sections[nsections - 1].rva + 0x60 &&
       memcmp(epbuff, "\x55\x8B\xEC\x53\x56\x57\x60\xE8\x00\x00\x00\x00\x5D\x81\xED\x6C\x28\x40\x00\xB9\x5D\x34\x40\x00\x81\xE9\xC6\x28\x40\x00\x8B\xD5\x81\xC2\xC6\x28\x40\x00\x8D\x3A\x8B\xF7\x33\xC0\xEB\x04\x90\xEB\x01\xC2\xAC", 51) == 0 && fsize >= exe_sections[nsections - 1].raw + 0xC6 + 0xb97)  {

	char *spinned;

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

	CLI_UNPTEMP("yC",(spinned,exe_sections,0));
	CLI_UNPRESULTS("yC",(yc_decrypt(spinned, fsize, exe_sections, nsections-1, e_lfanew, ndesc)),0,(spinned,0));
    }


    /* WWPack */

    if((DCONF & PE_CONF_WWPACK) && nsections > 1 &&
       exe_sections[nsections-1].raw>0x2b1 &&
       vep == exe_sections[nsections - 1].rva &&
       exe_sections[nsections - 1].rva + exe_sections[nsections - 1].rsz == max &&
       memcmp(epbuff, "\x53\x55\x8b\xe8\x33\xdb\xeb", 7) == 0 &&
       memcmp(epbuff+0x68, "\xe8\x00\x00\x00\x00\x58\x2d\x6d\x00\x00\x00\x50\x60\x33\xc9\x50\x58\x50\x50", 19) == 0)  {
	uint32_t headsize=exe_sections[nsections - 1].raw;
	char *dest, *wwp;

	for(i = 0 ; i < (unsigned int)nsections-1; i++)
	    if (exe_sections[i].raw<headsize) headsize=exe_sections[i].raw;
      
	dsize = max-min+headsize-exe_sections[nsections - 1].rsz;

	CLI_UNPSIZELIMITS("WWPack", dsize);

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
		if(!cli_seeksect(desc, &exe_sections[i]) || (unsigned int) cli_readn(desc, dest + headsize + exe_sections[i].rva - min, exe_sections[i].rsz) != exe_sections[i].rsz) {
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

	if(!cli_seeksect(desc, &exe_sections[nsections - 1]) || (size_t) cli_readn(desc, wwp, exe_sections[nsections - 1].rsz) != exe_sections[nsections - 1].rsz) {
	    cli_dbgmsg("WWPack: Can't read %d bytes from wwpack sect\n", exe_sections[nsections - 1].rsz);
	    free(dest);
	    free(wwp);
	    free(exe_sections);
	    return CL_EIO;
	}

	if (!wwunpack(dest, dsize, headsize, min, exe_sections[nsections-1].rva, e_lfanew, wwp, exe_sections[nsections - 1].rsz, nsections-1)) {
	
	    free(wwp);

	    CLI_UNPTEMP("WWPack",(dest,exe_sections,0));

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
    while((DCONF & PE_CONF_ASPACK) && ep+58+0x70e < fsize && !memcmp(epbuff,"\x60\xe8\x03\x00\x00\x00\xe9\xeb",8)) {

        if(epsize<0x3bf || memcmp(epbuff+0x3b9, "\x68\x00\x00\x00\x00\xc3",6)) break;
	ssize = 0;
	for(i=0 ; i< nsections ; i++)
	    if(ssize<exe_sections[i].rva+exe_sections[i].vsz)
		ssize=exe_sections[i].rva+exe_sections[i].vsz;
	if(!ssize) break;

	CLI_UNPSIZELIMITS("Aspack", ssize);

        if(!(src=(char *)cli_calloc(ssize, sizeof(char)))) {
	    free(exe_sections);
	    return CL_EMEM;
	}
        for(i = 0 ; i < (unsigned int)nsections; i++) {
	    if(!exe_sections[i].rsz) continue;
	    if(!cli_seeksect(desc, &exe_sections[i])) break;
            if(!CLI_ISCONTAINED(src, ssize, src+exe_sections[i].rva, exe_sections[i].rsz)) break;
            if(cli_readn(desc, src+exe_sections[i].rva, exe_sections[i].rsz)!=exe_sections[i].rsz) break;
        }
        if(i!=nsections) {
            cli_dbgmsg("Aspack: Probably hacked/damaged Aspack file.\n");
            free(src);
            break;
        }

	CLI_UNPTEMP("Aspack",(src,exe_sections,0));
	CLI_UNPRESULTS("Aspack",(unaspack212((uint8_t *)src, ssize, exe_sections, nsections, vep-1, EC32(optional_hdr32.ImageBase), ndesc)),1,(src,0));
	break;
    }

    /* NsPack */

    while (DCONF & PE_CONF_NSPACK) {
	uint32_t eprva = vep;
	uint32_t start_of_stuff, ssize, dsize, rep = ep;
	unsigned int nowinldr;
	char nbuff[24];
	char *src=epbuff, *dest;

	if (*epbuff=='\xe9') { /* bitched headers */
	    eprva = cli_readint32(epbuff+1)+vep+5;
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

	CLI_UNPSIZELIMITS("NsPack", MAX(ssize,dsize));

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
	if (!(rep = cli_rawaddr(eprva, exe_sections, nsections, &err, fsize, hdr_size)) && err) {
	  free(dest);
	  free(src);
	  break;
	}
	if (lseek(desc, rep, SEEK_SET)==-1) {
	  free(dest);
	  free(src);
	  break;
	}
	if (cli_readn(desc, nbuff, 5)!=5) {
	  free(dest);
	  free(src);
	  break;
	}
	eprva=eprva+5+cli_readint32(nbuff+1);
	cli_dbgmsg("NsPack: OEP = %08x\n", eprva);

	CLI_UNPTEMP("NsPack",(src,dest,exe_sections,0));
	CLI_UNPRESULTS("NsPack",(unspack(src, dest, ctx, exe_sections[0].rva, EC32(optional_hdr32.ImageBase), eprva, ndesc)),0,(src,dest,0));
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

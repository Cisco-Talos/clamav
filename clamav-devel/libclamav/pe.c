/*
 *  Copyright (C) 2004 Tomasz Kojm <tkojm@clamav.net>
 *
 *  With additions from aCaB <acab@clamav.net>
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
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
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
#include <unistd.h>
#include <time.h>

#include "cltypes.h"
#include "clamav.h"
#include "others.h"
#include "pe.h"
#include "upx.h"
#include "petite.h"
#include "fsg.h"
#include "scanners.h"
#include "rebuildpe.h"

#define IMAGE_DOS_SIGNATURE	    0x5a4d	    /* MZ */
#define IMAGE_DOS_SIGNATURE_OLD	    0x4d5a          /* ZM */
#define IMAGE_NT_SIGNATURE	    0x00004550
#define IMAGE_OPTIONAL_SIGNATURE    0x010b

#define DETECT_BROKEN		    (options & CL_SCAN_BLOCKBROKEN)

#define UPX_NRV2B "\x11\xdb\x11\xc9\x01\xdb\x75\x07\x8b\x1e\x83\xee\xfc\x11\xdb\x11\xc9\x11\xc9\x75\x20\x41\x01\xdb"
#define UPX_NRV2D "\x83\xf0\xff\x74\x78\xd1\xf8\x89\xc5\xeb\x0b\x01\xdb\x75\x07\x8b\x1e\x83\xee\xfc\x11\xdb\x11\xc9"
#define UPX_NRV2E "\xeb\x52\x31\xc9\x83\xe8\x03\x72\x11\xc1\xe0\x08\x8a\x06\x46\x83\xf0\xff\x74\x75\xd1\xf8\x89\xc5"

#if WORDS_BIGENDIAN == 0
#define EC16(v)	(v)
#define EC32(v) (v)
#else
static inline uint16_t EC16(uint16_t v)
{
    return ((v >> 8) + (v << 8));
}

static inline uint32_t EC32(uint32_t v)
{
    return ((v >> 24) | ((v & 0x00FF0000) >> 8) | ((v & 0x0000FF00) << 8) | (v << 24));
}
#endif

extern short cli_leavetemps_flag;

static uint32_t cli_rawaddr(uint32_t rva, struct pe_image_section_hdr *shp, uint16_t nos)
{
	int i, found = 0;


    for(i = 0; i < nos; i++) {
	if(EC32(shp[i].VirtualAddress) <= rva && EC32(shp[i].VirtualAddress) + EC32(shp[i].SizeOfRawData) > rva) {
	    found = 1;
	    break;
	}
    }

    if(!found) {
	cli_dbgmsg("Can't calculate raw address from RVA 0x%x\n", rva);
	return -1;
    }

    return rva - EC32(shp[i].VirtualAddress) + EC32(shp[i].PointerToRawData);
}

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

    if((ndesc = open(file, O_WRONLY|O_CREAT|O_TRUNC, S_IRWXU)) < 0) {
	cli_dbgmsg("Can't create file %s\n", file);
	lseek(desc, pos, SEEK_SET);
	return -1;
    }

    while((bread = read(desc, buff, FILEBUFF)) > 0) {
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

int cli_scanpe(int desc, const char **virname, long int *scanned, const struct cl_node *root, const struct cl_limits *limits, unsigned int options, int *arec, int *mrec)
{
	uint16_t e_magic; /* DOS signature ("MZ") */
	uint16_t nsections;
	uint32_t e_lfanew; /* address of new exe header */
	uint32_t ep; /* entry point (raw) */
	time_t timestamp;
	struct pe_image_file_hdr file_hdr;
	struct pe_image_optional_hdr optional_hdr;
	struct pe_image_section_hdr *section_hdr;
	struct stat sb;
	char sname[9], buff[256], *tempfile;
	int i, found, upx_success = 0, min = 0, max = 0, ret;
	int (*upxfn)(char *, int , char *, int) = NULL;
	char *src = NULL, *dest = NULL;
	int ssize = -1, dsize = -1, ndesc;


    if(read(desc, &e_magic, sizeof(e_magic)) != sizeof(e_magic)) {
	cli_dbgmsg("Can't read DOS signature\n");
	return CL_CLEAN;
    }

    if(EC16(e_magic) != IMAGE_DOS_SIGNATURE && EC16(e_magic) != IMAGE_DOS_SIGNATURE_OLD) {
	cli_dbgmsg("Invalid DOS signature\n");
	return CL_CLEAN;
    }

    lseek(desc, 58, SEEK_CUR); /* skip to the end of the DOS header */

    if(read(desc, &e_lfanew, sizeof(e_lfanew)) != sizeof(e_lfanew)) {
	cli_dbgmsg("Can't read new header address\n");
	/* truncated header? */
	if(DETECT_BROKEN) {
	    if(virname)
		*virname = "Broken.Executable";
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

    if(read(desc, &file_hdr, sizeof(struct pe_image_file_hdr)) != sizeof(struct pe_image_file_hdr)) {
	/* bad information in e_lfanew - probably not a PE file */
	cli_dbgmsg("Can't read file header\n");
	return CL_CLEAN;
    }

    if(EC32(file_hdr.Magic) != IMAGE_NT_SIGNATURE) {
	cli_dbgmsg("Invalid PE signature (probably NE file)\n");
	return CL_CLEAN;
    }

    switch(EC16(file_hdr.Machine)) {
	case 0x14c:
	    cli_dbgmsg("Machine type: 80386\n");
	    break;
	case 0x014d:
	    cli_dbgmsg("Machine type: 80486\n");
	    break;
	case 0x014e:
	    cli_dbgmsg("Machine type: 80586\n");
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
	case 0x1f0:
	    cli_dbgmsg("Machine type: PowerPC\n");
	    break;
	default:
	    cli_warnmsg("Unknown machine type in PE header\n");
    }

    nsections = EC16(file_hdr.NumberOfSections);
    cli_dbgmsg("NumberOfSections: %d\n", nsections);

    timestamp = (time_t) EC32(file_hdr.TimeDateStamp);
    cli_dbgmsg("TimeDateStamp: %s", ctime(&timestamp));

    cli_dbgmsg("SizeOfOptionalHeader: %d\n", EC16(file_hdr.SizeOfOptionalHeader));

    if(EC16(file_hdr.SizeOfOptionalHeader) != sizeof(struct pe_image_optional_hdr)) {
	cli_warnmsg("Broken PE header detected.\n");
	if(DETECT_BROKEN) {
	    if(virname)
		*virname = "Broken.Executable";
	    return CL_VIRUS;
	}
	return CL_CLEAN;
    }

    if(read(desc, &optional_hdr, sizeof(struct pe_image_optional_hdr)) != sizeof(struct pe_image_optional_hdr)) {
	cli_dbgmsg("Can't optional file header\n");
	if(DETECT_BROKEN) {
	    if(virname)
		*virname = "Broken.Executable";
	    return CL_VIRUS;
	}
	return CL_CLEAN;
    }

    cli_dbgmsg("MajorLinkerVersion: %d\n", optional_hdr.MajorLinkerVersion);
    cli_dbgmsg("MinorLinkerVersion: %d\n", optional_hdr.MinorLinkerVersion);
    cli_dbgmsg("SizeOfCode: %d\n", EC32(optional_hdr.SizeOfCode));
    cli_dbgmsg("SizeOfInitializedData: %d\n", EC32(optional_hdr.SizeOfInitializedData));
    cli_dbgmsg("SizeOfUninitializedData: %d\n", EC32(optional_hdr.SizeOfUninitializedData));
    cli_dbgmsg("AddressOfEntryPoint: 0x%x\n", EC32(optional_hdr.AddressOfEntryPoint));
    cli_dbgmsg("SectionAlignment: %d\n", EC32(optional_hdr.SectionAlignment));
    cli_dbgmsg("FileAlignment: %d\n", EC32(optional_hdr.FileAlignment));
    cli_dbgmsg("MajorSubsystemVersion: %d\n", EC16(optional_hdr.MajorSubsystemVersion));
    cli_dbgmsg("MinorSubsystemVersion: %d\n", EC16(optional_hdr.MinorSubsystemVersion));
    cli_dbgmsg("SizeOfImage: %d\n", EC32(optional_hdr.SizeOfImage));
    cli_dbgmsg("SizeOfHeaders: %d\n", EC32(optional_hdr.SizeOfHeaders));

    switch(EC16(optional_hdr.Subsystem)) {
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
	default:
	    cli_warnmsg("Unknown subsystem in PE header\n");
    }

    cli_dbgmsg("NumberOfRvaAndSizes: %d\n", EC32(optional_hdr.NumberOfRvaAndSizes));
    cli_dbgmsg("------------------------------------\n");

    if(fstat(desc, &sb) == -1) {
	cli_dbgmsg("fstat failed\n");
	return CL_EIO;
    }

    section_hdr = (struct pe_image_section_hdr *) cli_calloc(nsections, sizeof(struct pe_image_section_hdr));

    if(!section_hdr) {
	cli_dbgmsg("Can't allocate memory for section headers\n");
	return CL_EMEM;
    }

    for(i = 0; i < nsections; i++) {

	if(read(desc, &section_hdr[i], sizeof(struct pe_image_section_hdr)) != sizeof(struct pe_image_section_hdr)) {
	    cli_dbgmsg("Can't read section header\n");
	    cli_dbgmsg("Possibly broken PE file\n");
	    free(section_hdr);
	    if(DETECT_BROKEN) {
		if(virname)
		    *virname = "Broken.Executable";
		return CL_VIRUS;
	    }
	    return CL_CLEAN;
	}

	strncpy(sname, section_hdr[i].Name, 8);
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
	cli_dbgmsg("------------------------------------\n");

	if(EC32(section_hdr[i].PointerToRawData) + EC32(section_hdr[i].SizeOfRawData) > sb.st_size) {
	    cli_dbgmsg("Possibly broken PE file - Section %d out of file (Offset@ %d, Rsize %d, Total filesize %d)\n", i, EC32(section_hdr[i].PointerToRawData), EC32(section_hdr[i].SizeOfRawData), sb.st_size);
	    free(section_hdr);
	    if(DETECT_BROKEN) {
		if(virname)
		    *virname = "Broken.Executable";
		return CL_VIRUS;
	    }
	    return CL_CLEAN;
	}

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

    if((ep = EC32(optional_hdr.AddressOfEntryPoint)) >= min && (ep = cli_rawaddr(EC32(optional_hdr.AddressOfEntryPoint), section_hdr, nsections)) == -1) {
	cli_dbgmsg("Possibly broken PE file\n");
	free(section_hdr);
	if(DETECT_BROKEN) {
	    if(virname)
		*virname = "Broken.Executable";
	    return CL_VIRUS;
	}
	return CL_CLEAN;
    }

    cli_dbgmsg("EntryPoint offset: 0x%x (%d)\n", ep, ep);

    /* UPX & FSG support */

    /* try to find the first section with physical size == 0 */
    found = 0;
    for(i = 0; i < nsections - 1; i++) {
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

        if(read(desc, buff, 168) != 168) {
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

		if(limits && limits->maxfilesize && (ssize > limits->maxfilesize || dsize > limits->maxfilesize)) {
		    cli_dbgmsg("FSG: Sizes exceeded (ssize: %d, dsize: %d, max: %lu)\n", ssize, dsize , limits->maxfilesize);
		    free(section_hdr);
		    return CL_CLEAN;
		}

		if(ssize <= 0x19 || dsize <= ssize) {
		    cli_dbgmsg("FSG: Size mismatch (ssize: %d, dsize: %d)\n", ssize, dsize);
		    free(section_hdr);
		    return CL_CLEAN;
		}

		if((newedx = cli_readint32(buff + 2) - EC32(optional_hdr.ImageBase)) < EC32(section_hdr[i + 1].VirtualAddress) || newedx >= EC32(section_hdr[i + 1].VirtualAddress) + EC32(section_hdr[i + 1].SizeOfRawData) - 4) {
		    cli_dbgmsg("FSG: xchg out of bounds (%x), giving up\n", newedx);
		    break;
		}

		if((src = (char *) cli_malloc(ssize)) == NULL) {
		    free(section_hdr);
		    return CL_EMEM;
		}

		lseek(desc, EC32(section_hdr[i + 1].PointerToRawData), SEEK_SET);
		if(read(desc, src, ssize) != ssize) {
		    cli_dbgmsg("Can't read raw data of section %d\n", i);
		    free(section_hdr);
		    free(src);
		    return CL_EIO;
		}

		if((newedx - EC32(section_hdr[i + 1].VirtualAddress)) < 0 || ((dest = src + newedx - EC32(section_hdr[i + 1].VirtualAddress)) < src && dest >= src + EC32(section_hdr[i + 1].VirtualAddress) + EC32(section_hdr[i + 1].SizeOfRawData) - 4)) {
		    cli_dbgmsg("FSG: New ESP out of bounds\n");
		    free(src);
		    break;
		}

		if((newedx = cli_readint32(dest) - EC32(optional_hdr.ImageBase)) <= EC32(section_hdr[i + 1].VirtualAddress) || newedx >= EC32(section_hdr[i + 1].VirtualAddress) + EC32(section_hdr[i + 1].SizeOfRawData) - 4) {
		    cli_dbgmsg("FSG: New ESP (%x) is wrong\n", newedx);
		    free(src);
		    break;
		}
 
		if((dest = src + newedx - EC32(section_hdr[i + 1].VirtualAddress)) < src || dest >= src + EC32(section_hdr[i + 1].VirtualAddress) + EC32(section_hdr[i + 1].SizeOfRawData) - 32) {
		    cli_dbgmsg("FSG: New stack out of bounds\n");
		    free(src);
		    break;
		}

		newedi = cli_readint32(dest) - EC32(optional_hdr.ImageBase);
		newesi = cli_readint32(dest + 4) - EC32(optional_hdr.ImageBase);
		newebx = cli_readint32(dest + 16) - EC32(optional_hdr.ImageBase);
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

		/* FIXME: unused atm, needed for pe rebuilding */
		cli_dbgmsg("FSG: found old EP @%x\n", cli_readint32(newebx + 12 - EC32(section_hdr[i + 1].VirtualAddress) + src) - EC32(optional_hdr.ImageBase));

		if((dest = (char *) cli_calloc(dsize, sizeof(char))) == NULL) {
		    free(section_hdr);
		    free(src);
		    return CL_EMEM;
		}

		if(unfsg_200(newesi - EC32(section_hdr[i + 1].VirtualAddress) + src, dest, ssize + EC32(section_hdr[i + 1].VirtualAddress) - newesi, dsize) == -1) {
		    cli_dbgmsg("FSG: Unpacking failed\n");
		    free(src);
		    free(dest);
		    break;
		}

		found = 0;
		upx_success = 1;
		cli_dbgmsg("FSG: Successfully decompressed\n");
	    }
	}

 	if(found && buff[0] == '\xbe' && cli_readint32(buff + 1) - EC32(optional_hdr.ImageBase) < min) {

	    /* FSG support - v. 1.33 (thx trog for the many samples) */

	    ssize = EC32(section_hdr[i + 1].SizeOfRawData);
	    dsize = EC32(section_hdr[i].VirtualSize);

	    while(found) {
	            int gp, t, sectcnt = 0;
		    char *support;
		    uint32_t newesi, newedi, newebx, oldep;
		    struct SECTION *sections;


		if(limits && limits->maxfilesize && (ssize > limits->maxfilesize || dsize > limits->maxfilesize)) {
		    cli_dbgmsg("FSG: Sizes exceeded (ssize: %d, dsize: %d, max: %lu)\n", ssize, dsize, limits->maxfilesize);
		    free(section_hdr);
		    return CL_CLEAN;
		}

		if(ssize <= 0x19 || dsize <= ssize) {
		    cli_dbgmsg("FSG: Size mismatch (ssize: %d, dsize: %d)\n", ssize, dsize);
		    free(section_hdr);
		    return CL_CLEAN;
		}

		if((gp = cli_readint32(buff + 1) - EC32(optional_hdr.ImageBase)) >= EC32(section_hdr[i + 1].PointerToRawData) || gp < 0) {
		    cli_dbgmsg("FSG: Support data out of padding area (vaddr: %d)\n", EC32(section_hdr[i].VirtualAddress));
		    break;
		}

		lseek(desc, gp, SEEK_SET);
		gp = EC32(section_hdr[i + 1].PointerToRawData) - gp;

		if(limits && limits->maxfilesize && gp > limits->maxfilesize) {
		    cli_dbgmsg("FSG: Buffer size exceeded (size: %d, max: %lu)\n", gp, limits->maxfilesize);
		    free(section_hdr);
		    return CL_CLEAN;
		}

		if((support = (char *) cli_malloc(gp)) == NULL) {
		    free(section_hdr);
		    return CL_EMEM;
		}

		if(read(desc, support, gp) != gp) {
		    cli_dbgmsg("Can't read %d bytes from padding area\n", gp); 
		    free(section_hdr);
		    free(support);
		    return CL_EIO;
		}

		newebx = cli_readint32(support) - EC32(optional_hdr.ImageBase); /* Unused */
		newedi = cli_readint32(support + 4) - EC32(optional_hdr.ImageBase); /* 1st dest */
		newesi = cli_readint32(support + 8) - EC32(optional_hdr.ImageBase); /* Source */

		if(newesi < EC32(section_hdr[i + 1].VirtualAddress || newesi >= EC32(section_hdr[i + 1].VirtualAddress) + EC32(section_hdr[i + 1].SizeOfRawData))) {
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

		    rva -= EC32(optional_hdr.ImageBase)+1;
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
		    sections[t].rva = cli_readint32(support + 8 + t * 4) - 1 -EC32(optional_hdr.ImageBase);

		free(support);

		if((src = (char *) cli_malloc(ssize)) == NULL) {
		    free(section_hdr);
		    free(sections);
		    return CL_EMEM;
		}

		lseek(desc, EC32(section_hdr[i + 1].PointerToRawData), SEEK_SET);
		if(read(desc, src, ssize) != ssize) {
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

		oldep = EC32(optional_hdr.AddressOfEntryPoint) + 161 + 6 + cli_readint32(buff+163);
		cli_dbgmsg("FSG: found old EP @%x\n", oldep);

		tempfile = cli_gentemp(NULL);
		if((ndesc = open(tempfile, O_RDWR|O_CREAT|O_TRUNC, S_IRWXU)) < 0) {
		    cli_dbgmsg("FSG: Can't create file %s\n", tempfile);
		    free(tempfile);
		    free(section_hdr);
		    free(src);
		    free(dest);
		    free(sections);
		    return CL_EIO;
		}

		switch(unfsg_133(src + newesi - EC32(section_hdr[i + 1].VirtualAddress), dest, ssize + EC32(section_hdr[i + 1].VirtualAddress) - newesi, dsize, sections, sectcnt, EC32(optional_hdr.ImageBase), oldep, ndesc)) {
		    case 1: /* Everything OK */
			cli_dbgmsg("FSG: Unpacked and rebuilt executable saved in %s\n", tempfile);
			free(src);
			free(dest);
			free(sections);
			fsync(ndesc);
			lseek(ndesc, 0, SEEK_SET);

			if(cli_magic_scandesc(ndesc, virname, scanned, root, limits, options, arec, mrec) == CL_VIRUS) {
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
			unlink(tempfile); // It's empty anyway
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
 	if(found && buff[0] == '\xbb' && cli_readint32(buff + 1) - EC32(optional_hdr.ImageBase) < min && buff[5] == '\xbf' && buff[10] == '\xbe') {

	    /* FSG support - v. 1.31 */

	    ssize = EC32(section_hdr[i + 1].SizeOfRawData);
	    dsize = EC32(section_hdr[i].VirtualSize);

	    while(found) {
		    int gp = cli_readint32(buff+1) - EC32(optional_hdr.ImageBase), t, sectcnt = 0;
		    char *support;
		    uint32_t newesi = cli_readint32(buff+11) - EC32(optional_hdr.ImageBase);
		    uint32_t newedi = cli_readint32(buff+6) - EC32(optional_hdr.ImageBase);
		    uint32_t oldep = EC32(optional_hdr.AddressOfEntryPoint);
		    struct SECTION *sections;

	        if (oldep <= EC32(section_hdr[i + 1].VirtualAddress) || oldep > EC32(section_hdr[i + 1].VirtualAddress)+EC32(section_hdr[i + 1].SizeOfRawData) - 0xe0) {
		  cli_dbgmsg("FSG: EP not in section %d\n", i+1);
		  break;
		}
		oldep -= EC32(section_hdr[i + 1].VirtualAddress);

		if(newesi < EC32(section_hdr[i + 1].VirtualAddress || newesi >= EC32(section_hdr[i + 1].VirtualAddress) + EC32(section_hdr[i + 1].SizeOfRawData))) {
		    cli_dbgmsg("FSG: Source buffer out of section bounds\n");
		    break;
		}

		if(newedi != EC32(section_hdr[i].VirtualAddress)) {
		    cli_dbgmsg("FSG: Bad destination (is %x should be %x)\n", newedi, EC32(section_hdr[i].VirtualAddress));
		    break;
		}

		if(limits && limits->maxfilesize && (ssize > limits->maxfilesize || dsize > limits->maxfilesize)) {
		    cli_dbgmsg("FSG: Sizes exceeded (ssize: %d, dsize: %d, max: %lu)\n", ssize, dsize, limits->maxfilesize);
		    free(section_hdr);
		    return CL_CLEAN;
		}

		if(ssize <= 0x19 || dsize <= ssize) {
		    cli_dbgmsg("FSG: Size mismatch (ssize: %d, dsize: %d)\n", ssize, dsize);
		    free(section_hdr);
		    return CL_CLEAN;
		}

		if( gp >= EC32(section_hdr[i + 1].PointerToRawData) || gp < 0) {
		    cli_dbgmsg("FSG: Support data out of padding area (newedi: %d, vaddr: %d)\n", newedi, EC32(section_hdr[i].VirtualAddress));
		    break;
		}

		lseek(desc, gp, SEEK_SET);
		gp = EC32(section_hdr[i + 1].PointerToRawData) - gp;

		if(limits && limits->maxfilesize && gp > limits->maxfilesize) {
		    cli_dbgmsg("FSG: Buffer size exceeded (size: %d, max: %lu)\n", gp, limits->maxfilesize);
		    free(section_hdr);
		    return CL_CLEAN;
		}

		if((support = (char *) cli_malloc(gp)) == NULL) {
		    free(section_hdr);
		    return CL_EMEM;
		}

		if(read(desc, support, gp) != gp) {
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

		  rva = ((rva-2)<<12) - EC32(optional_hdr.ImageBase);
		  sectcnt++;

		  if(rva < EC32(section_hdr[i].VirtualAddress) || rva >= EC32(section_hdr[i].VirtualAddress)+EC32(section_hdr[i].VirtualSize)) {
		    cli_dbgmsg("FSG: Original section %d is out of bounds\n", sectcnt);
		    break;
		  }
		}

		if( t >= gp-10 || cli_readint32(support + t + 6) != 2 ) {
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
		  sections[t+1].rva = (((support[t*2]+256*support[t*2+1])-2)<<12)-EC32(optional_hdr.ImageBase);
		}

		free(support);

		if((src = (char *) cli_malloc(ssize)) == NULL) {
		    free(section_hdr);
		    free(sections);
		    return CL_EMEM;
		}

		lseek(desc, EC32(section_hdr[i + 1].PointerToRawData), SEEK_SET);
		if(read(desc, src, ssize) != ssize) {
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
		oldep = EC32(optional_hdr.AddressOfEntryPoint) + gp + 6 + cli_readint32(src+gp+2+oldep);
		cli_dbgmsg("FSG: found old EP @%x\n", oldep);

		tempfile = cli_gentemp(NULL);
		if((ndesc = open(tempfile, O_RDWR|O_CREAT|O_TRUNC, S_IRWXU)) < 0) {
		    cli_dbgmsg("FSG: Can't create file %s\n", tempfile);
		    free(tempfile);
		    free(section_hdr);
		    free(src);
		    free(dest);
		    free(sections);
		    return CL_EIO;
		}

		switch(unfsg_133(src + newesi - EC32(section_hdr[i + 1].VirtualAddress), dest, ssize + EC32(section_hdr[i + 1].VirtualAddress) - newesi, dsize, sections, sectcnt, EC32(optional_hdr.ImageBase), oldep, ndesc)) {
		    case 1: /* Everything OK */
			cli_dbgmsg("FSG: Unpacked and rebuilt executable saved in %s\n", tempfile);
			free(src);
			free(dest);
			free(sections);
			fsync(ndesc);
			lseek(ndesc, 0, SEEK_SET);

			if(cli_magic_scandesc(ndesc, virname, scanned, root, limits, options, arec, mrec) == CL_VIRUS) {
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
			unlink(tempfile); // It's empty anyway
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

	    strncpy(sname, section_hdr[i].Name, 8);
	    sname[8] = 0;
	    cli_dbgmsg("UPX: Section %d name: %s\n", i, sname);
	    strncpy(sname, section_hdr[i + 1].Name, 8);
	    sname[8] = 0;
	    cli_dbgmsg("UPX: Section %d name: %s\n", i + 1, sname);

	    if(strncmp(section_hdr[i].Name, "UPX0", 4) || strncmp(section_hdr[i + 1].Name, "UPX1", 4))
		cli_dbgmsg("UPX: Possibly hacked UPX section headers\n");

	    /* we assume (i + 1) is UPX1 */
	    ssize = EC32(section_hdr[i + 1].SizeOfRawData);
	    dsize = EC32(section_hdr[i].VirtualSize) + EC32(section_hdr[i + 1].VirtualSize);

	    if(limits && limits->maxfilesize && (ssize > limits->maxfilesize || dsize > limits->maxfilesize)) {
		cli_dbgmsg("UPX: Sizes exceeded (ssize: %d, dsize: %d, max: %lu)\n", ssize, dsize , limits->maxfilesize);
		free(section_hdr);
		return CL_CLEAN;
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

	    if((dest = (char *) cli_calloc(dsize, sizeof(char))) == NULL) {
		free(section_hdr);
		free(src);
		return CL_EMEM;
	    }

	    lseek(desc, EC32(section_hdr[i + 1].PointerToRawData), SEEK_SET);
	    if(read(desc, src, ssize) != ssize) {
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

	    if(read(desc, buff, 126) != 126) { /* i.e. 0x69 + 13 + 8 */
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
		    int skew = cli_readint32(buff + 2) - EC32(optional_hdr.ImageBase) - EC32(section_hdr[i + 1].VirtualAddress);

		if(buff[1] != '\xbe' || skew <= 0 || skew > 0xfff ) { /* FIXME: legit skews?? */
		    skew = 0; 
		    if(!upxfn(src, ssize, dest, dsize))
			upx_success = 1;

		} else {
		    cli_dbgmsg("UPX: UPX1 seems skewed by %d bytes\n", skew);
		    if(!upxfn(src + skew, ssize - skew, dest, dsize) || !upxfn(src, ssize, dest, dsize))
			upx_success = 1;
		}

		if(upx_success)
		    cli_dbgmsg("UPX: Successfully decompressed\n");
		else
		    cli_dbgmsg("UPX: Prefered decompressor failed\n");
	    }

	    if(!upx_success && upxfn != upx_inflate2b) {
		if(upx_inflate2b(src, ssize, dest, dsize) && upx_inflate2b(src + 0x15, ssize - 0x15, dest, dsize) ) {
		    cli_dbgmsg("UPX: NRV2B decompressor failed\n");
		} else {
		    upx_success = 1;
		    cli_dbgmsg("UPX: Successfully decompressed with NRV2B\n");
		}
	    }

	    if(!upx_success && upxfn != upx_inflate2d) {
		if(upx_inflate2d(src, ssize, dest, dsize) && upx_inflate2d(src + 0x15, ssize - 0x15, dest, dsize) ) {
		    cli_dbgmsg("UPX: NRV2D decompressor failed\n");
		} else {
		    upx_success = 1;
		    cli_dbgmsg("UPX: Successfully decompressed with NRV2D\n");
		}
	    }

	    if(!upx_success && upxfn != upx_inflate2e) {
		if(upx_inflate2e(src, ssize, dest, dsize) && upx_inflate2e(src + 0x15, ssize - 0x15, dest, dsize) ) {
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
		int ndesc;

	    if(cli_leavetemps_flag) {
		tempfile = cli_gentemp(NULL);
		if((ndesc = open(tempfile, O_WRONLY|O_CREAT|O_TRUNC, S_IRWXU)) < 0) {
		    cli_dbgmsg("UPX/FSG: Can't create file %s\n", tempfile);
		    free(tempfile);
		    free(section_hdr);
		    free(src);
		    free(dest);
		    return CL_EIO;
		}

		if(write(ndesc, dest, dsize) != dsize) {
		    cli_dbgmsg("UPX/FSG: Can't write %d bytes\n", dsize);
		    free(tempfile);
		    free(section_hdr);
		    free(src);
		    free(dest);
		    return CL_EIO;
		}

		close(ndesc);
		cli_dbgmsg("UPX/FSG: Decompressed data saved in %s\n", tempfile);
		free(tempfile);
	    }

	    if(scanned)
		*scanned += dsize / CL_COUNT_PRECISION;

	    ret = cl_scanbuff(dest, dsize, virname, root);
	    free(section_hdr);
	    free(src);
	    free(dest);
	    return ret;
	}
    }

    /* Petite */

    found = 2;

    lseek(desc, ep, SEEK_SET);
    if(read(desc, buff, 200) != 200) {
	cli_dbgmsg("Can't read 200 bytes\n");
	free(section_hdr);
	return CL_EIO;
    }

    if(buff[0] != '\xb8' || cli_readint32(buff + 1) != EC32(section_hdr[nsections - 1].VirtualAddress) + EC32(optional_hdr.ImageBase)) {
	if(buff[0] != '\xb8' || cli_readint32(buff + 1) != EC32(section_hdr[nsections - 2].VirtualAddress) + EC32(optional_hdr.ImageBase))
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

	    if(limits && limits->maxfilesize && dsize > limits->maxfilesize) {
		cli_dbgmsg("Petite: Size exceeded (dsize: %d, max: %lu)\n", dsize, limits->maxfilesize);
		free(section_hdr);
		return CL_CLEAN;
	    }

	    if((dest = (char *) cli_calloc(dsize, sizeof(char))) == NULL) {
		cli_dbgmsg("Petite: Can't allocate %d bytes\n", dsize);
		free(section_hdr);
		return CL_EMEM;
	    }

	    for(i = 0 ; i < nsections; i++) {
		if(section_hdr[i].SizeOfRawData) {
			uint32_t offset = cli_rawaddr(EC32(section_hdr[i].VirtualAddress), section_hdr, nsections);

		    if(offset == -1 || lseek(desc, offset, SEEK_SET) == -1 || read(desc, dest + EC32(section_hdr[i].VirtualAddress) - min, EC32(section_hdr[i].SizeOfRawData)) != EC32(section_hdr[i].SizeOfRawData)) {
			free(section_hdr);
			free(dest);
			return CL_EIO;
		    }
		}
	    }

	    tempfile = cli_gentemp(NULL);
	    if((ndesc = open(tempfile, O_RDWR|O_CREAT|O_TRUNC, S_IRWXU)) < 0) {
		cli_dbgmsg("Petite: Can't create file %s\n", tempfile);
		free(tempfile);
		free(section_hdr);
		free(dest);
		return CL_EIO;
	    }

	    /* aCaB: Fixed to allow petite v2.1 unpacking (last section is a ghost) */
	    switch(petite_inflate2x_1to9(dest, min, max - min, section_hdr,
		    nsections - (found == 1 ? 1 : 0), EC32(optional_hdr.ImageBase),
		    EC32(optional_hdr.AddressOfEntryPoint), ndesc,
		    found, EC32(optional_hdr.DataDirectory[2].VirtualAddress),
		    EC32(optional_hdr.DataDirectory[2].Size))) {
		case 1:
		    cli_dbgmsg("Petite: Unpacked and rebuilt executable saved in %s\n", tempfile);
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

	    if(cli_magic_scandesc(ndesc, virname, scanned, root, limits, options, arec, mrec) == CL_VIRUS) {
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

    /* to be continued ... */

    free(section_hdr);
    return CL_CLEAN;
}

int cli_peheader(int desc, struct cli_pe_info *peinfo)
{
	uint16_t e_magic; /* DOS signature ("MZ") */
	uint32_t e_lfanew; /* address of new exe header */
	struct pe_image_file_hdr file_hdr;
	struct pe_image_optional_hdr optional_hdr;
	struct pe_image_section_hdr *section_hdr;
	struct stat sb;
	int i;


    cli_dbgmsg("in cli_peheader\n");

    if(read(desc, &e_magic, sizeof(e_magic)) != sizeof(e_magic)) {
	cli_dbgmsg("Can't read DOS signature\n");
	return -1;
    }

    if(EC16(e_magic) != IMAGE_DOS_SIGNATURE && EC16(e_magic) != IMAGE_DOS_SIGNATURE_OLD) {
	cli_dbgmsg("Invalid DOS signature\n");
	return -1;
    }

    lseek(desc, 58, SEEK_CUR); /* skip to the end of the DOS header */

    if(read(desc, &e_lfanew, sizeof(e_lfanew)) != sizeof(e_lfanew)) {
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

    if(read(desc, &file_hdr, sizeof(struct pe_image_file_hdr)) != sizeof(struct pe_image_file_hdr)) {
	/* bad information in e_lfanew - probably not a PE file */
	cli_dbgmsg("Can't read file header\n");
	return -1;
    }

    if(EC32(file_hdr.Magic) != IMAGE_NT_SIGNATURE) {
	cli_dbgmsg("Invalid PE signature (probably NE file)\n");
	return -1;
    }

    if(EC16(file_hdr.SizeOfOptionalHeader) != sizeof(struct pe_image_optional_hdr)) {
	cli_warnmsg("Broken PE header detected.\n");
	return -1;
    }

    peinfo->nsections = EC16(file_hdr.NumberOfSections);

    if(read(desc, &optional_hdr, sizeof(struct pe_image_optional_hdr)) != sizeof(struct pe_image_optional_hdr)) {
	cli_dbgmsg("Can't optional file header\n");
	return -1;
    }

    peinfo->section = (struct SECTION *) cli_calloc(peinfo->nsections, sizeof(struct SECTION));

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

	if(read(desc, &section_hdr[i], sizeof(struct pe_image_section_hdr)) != sizeof(struct pe_image_section_hdr)) {
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
    }

    if((peinfo->ep = cli_rawaddr(EC32(optional_hdr.AddressOfEntryPoint), section_hdr, peinfo->nsections)) == -1) {
	cli_dbgmsg("Possibly broken PE file\n");
	free(section_hdr);
	free(peinfo->section);
	return -1;
    }

    free(section_hdr);
    return 0;
}

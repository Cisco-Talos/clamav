/*
 *  Copyright (C) 2004 Tomasz Kojm <tkojm@clamav.net>
 *
 *  Implementation (header structures) based on the PE format description
 *  by B. Luevelsmeyer
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

#define IMAGE_DOS_SIGNATURE	    0x5a4d	    /* MZ */
#define IMAGE_NT_SIGNATURE	    0x00004550
#define IMAGE_OPTIONAL_SIGNATURE    0x010b

struct pe_image_file_hdr {
    uint32_t Magic;
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;		    /* unreliable */
    uint32_t PointerToSymbolTable;	    /* debug */
    uint32_t NumberOfSymbols;		    /* debug */
    uint16_t SizeOfOptionalHeader;	    /* == 224 */
    uint16_t Characteristics;
};

struct pe_image_data_dir {
    uint32_t VirtualAddress;
    uint32_t Size;
};

struct pe_image_optional_hdr {
    uint16_t Magic;
    uint8_t  MajorLinkerVersion;		    /* unreliable */
    uint8_t  MinorLinkerVersion;		    /* unreliable */
    uint32_t SizeOfCode;			    /* unreliable */
    uint32_t SizeOfInitializedData;		    /* unreliable */
    uint32_t SizeOfUninitializedData;		    /* unreliable */
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint32_t BaseOfData;
    uint32_t ImageBase;				    /* multiple of 64 KB */
    uint32_t SectionAlignment;			    /* usually 32 or 4096 */
    uint32_t FileAlignment;			    /* usually 32 or 512 */
    uint16_t MajorOperatingSystemVersion;	    /* not used */
    uint16_t MinorOperatingSystemVersion;	    /* not used */
    uint16_t MajorImageVersion;			    /* unreliable */
    uint16_t MinorImageVersion;			    /* unreliable */
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;			    /* ? */
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;				    /* NT drivers only */
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint32_t SizeOfStackReserve;
    uint32_t SizeOfStackCommit;
    uint32_t SizeOfHeapReserve;
    uint32_t SizeOfHeapCommit;
    uint32_t LoaderFlags;			    /* ? */
    uint32_t NumberOfRvaAndSizes;		    /* unreliable */
    struct pe_image_data_dir DataDirectory[16];
};

struct pe_image_section_hdr {
    uint8_t Name[8];			    /* may not end with NULL */
    /*
    union {
	uint32_t PhysicalAddress;
	uint32_t VirtualSize;
    } AddrSize;
    */
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;		    /* multiple of FileAlignment */
    uint32_t PointerToRawData;		    /* offset to the section's data */
    uint32_t PointerToRelocations;	    /* object files only */
    uint32_t PointerToLinenumbers;	    /* object files only */
    uint16_t NumberOfRelocations;	    /* object files only */
    uint16_t NumberOfLinenumbers;	    /* object files only */
    uint32_t Characteristics;
};

int cli_scanpe(int desc, const char **virname, long int *scanned, const struct cl_node *root, const struct cl_limits *limits, int options, int *reclev)
{
	uint16_t e_magic; /* DOS signature ("MZ") */
	uint32_t e_lfanew; /* address of new exe header */
	struct pe_image_file_hdr file_hdr;
	struct pe_image_optional_hdr optional_hdr;
	struct pe_image_section_hdr section_hdr;
	struct stat sb;
	char sname[9];
	int i;


    if(read(desc, &e_magic, sizeof(e_magic)) != sizeof(e_magic)) {
	cli_dbgmsg("Can't read DOS signature.\n");
	return -1;
    }

    if(e_magic != IMAGE_DOS_SIGNATURE) {
	cli_dbgmsg("Invalid DOS signature\n");
	return -1;
    }

    lseek(desc, 58, SEEK_CUR); /* skip to the end of the DOS header */

    if(read(desc, &e_lfanew, sizeof(e_lfanew)) != sizeof(e_lfanew)) {
	cli_dbgmsg("Can't read new header address.\n");
	return -1;
    }

    cli_dbgmsg("e_lfanew == %d\n", e_lfanew);
    if(!e_lfanew) {
	cli_dbgmsg("Not a PE file\n");
	return -2;
    }

    lseek(desc, e_lfanew, SEEK_SET);

    if(read(desc, &file_hdr, sizeof(struct pe_image_file_hdr)) != sizeof(struct pe_image_file_hdr)) {
	cli_dbgmsg("Can't read file header\n");
	return -1;
    }

    if(file_hdr.Magic != IMAGE_NT_SIGNATURE) {
	cli_dbgmsg("Invalid PE signature\n");
	return -2;
    }

    cli_dbgmsg("Machine type: ");
    switch(file_hdr.Machine) {
	case 0x14c:
	    cli_dbgmsg("80386\n");
	    break;
	case 0x014d:
	    cli_dbgmsg("80486\n");
	    break;
	case 0x014e:
	    cli_dbgmsg("80586\n");
	    break;
	case 0x162:
	    cli_dbgmsg("R3000\n");
	    break;
	case 0x166:
	    cli_dbgmsg("R4000\n");
	    break;
	case 0x168:
	    cli_dbgmsg("R10000\n");
	    break;
	case 0x184:
	    cli_dbgmsg("DEC Alpha AXP\n");
	    break;
	case 0x1f0:
	    cli_dbgmsg("PowerPC\n");
	    break;
	default:
	    cli_dbgmsg("Unknown\n");
    }

    cli_dbgmsg("NumberOfSections: %d\n", file_hdr.NumberOfSections);
    cli_dbgmsg("TimeDateStamp: %s", ctime((time_t *) &file_hdr.TimeDateStamp));

    cli_dbgmsg("SizeOfOptionalHeader: %d\n", file_hdr.SizeOfOptionalHeader);

    if(file_hdr.SizeOfOptionalHeader != sizeof(struct pe_image_optional_hdr)) {
	cli_warnmsg("Broken PE header detected.\n");
	return -1;
    }

    if(read(desc, &optional_hdr, sizeof(struct pe_image_optional_hdr)) != sizeof(struct pe_image_optional_hdr)) {
	cli_dbgmsg("Can't optional file header\n");
	return -1;
    }

    cli_dbgmsg("MajorLinkerVersion: %d\n", optional_hdr.MajorLinkerVersion);
    cli_dbgmsg("MinorLinkerVersion: %d\n", optional_hdr.MinorLinkerVersion);
    cli_dbgmsg("SizeOfCode: %d\n", optional_hdr.SizeOfCode);
    cli_dbgmsg("SizeOfInitializedData: %d\n", optional_hdr.SizeOfInitializedData);
    cli_dbgmsg("SizeOfUninitializedData: %d\n", optional_hdr.SizeOfUninitializedData);
    cli_dbgmsg("AddressOfEntryPoint: 0x%x\n", optional_hdr.AddressOfEntryPoint);
    cli_dbgmsg("SectionAlignment: %d\n", optional_hdr.SectionAlignment);
    cli_dbgmsg("FileAlignment: %d\n", optional_hdr.FileAlignment);
    cli_dbgmsg("MajorSubsystemVersion: %d\n", optional_hdr.MajorSubsystemVersion);
    cli_dbgmsg("MinorSubsystemVersion: %d\n", optional_hdr.MinorSubsystemVersion);
    cli_dbgmsg("SizeOfImage: %d\n", optional_hdr.SizeOfImage);
    cli_dbgmsg("SizeOfHeaders: %d\n", optional_hdr.SizeOfHeaders);

    cli_dbgmsg("Subsystem: ");
    switch(optional_hdr.Subsystem) {
	case 1:
	    cli_dbgmsg("Native (a driver ?)\n");
	    break;
	case 2:
	    cli_dbgmsg("Win32 GUI\n");
	    break;
	case 3:
	    cli_dbgmsg("Win32 console\n");
	    break;
	case 5:
	    cli_dbgmsg("OS/2 console\n");
	    break;
	case 7:
	    cli_dbgmsg("POSIX console\n");
	    break;
	default:
	    cli_dbgmsg("Unknown\n");
    }

    cli_dbgmsg("NumberOfRvaAndSizes: %d\n", optional_hdr.NumberOfRvaAndSizes);

    for(i = 0; i < file_hdr.NumberOfSections; i++) {

	if(read(desc, &section_hdr, sizeof(struct pe_image_section_hdr)) != sizeof(struct pe_image_section_hdr)) {
	    cli_dbgmsg("Can't read section header\n");
	    return -1;
	}

	strncpy(sname, section_hdr.Name, 8);
	sname[8] = 0;
	cli_dbgmsg("------------------------------------\n");
	cli_dbgmsg("Section name: %s\n", sname);
	cli_dbgmsg("VirtualSize: %d\n", section_hdr.VirtualSize);
	cli_dbgmsg("VirtualAddress: 0x%x\n", section_hdr.VirtualAddress);
	cli_dbgmsg("Section size: %d\n", section_hdr.SizeOfRawData);
	cli_dbgmsg("PointerToRawData: 0x%x (%d)\n", section_hdr.PointerToRawData, section_hdr.PointerToRawData);

	if(section_hdr.Characteristics & 0x20)
	    cli_dbgmsg("Section contains executable code.\n");

	if(section_hdr.Characteristics & 0x20000000)
	    cli_dbgmsg("Section's memory is executable.\n");
    }

    if(fstat(desc, &sb) == -1) {
	cli_dbgmsg("stat failed\n");
	return -1;
    }

    if(section_hdr.PointerToRawData + section_hdr.SizeOfRawData > sb.st_size) {
	cli_warnmsg("Possibly broken PE file\n");
	return -1;
    }

    /* to be continued ... */

    return 0;
}

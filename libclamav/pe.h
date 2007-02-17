/*
 *  Copyright (C) 2004 - 2005 Tomasz Kojm <tkojm@clamav.net>
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
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA 02110-1301, USA.
 */

#ifndef __PE_H
#define __PE_H

#include "clamav.h"
#include "execs.h"
#include "others.h"
#include "cltypes.h"

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

struct pe_image_optional_hdr32 {
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

struct pe_image_optional_hdr64 {
    uint16_t Magic;
    uint8_t  MajorLinkerVersion;		    /* unreliable */
    uint8_t  MinorLinkerVersion;		    /* unreliable */
    uint32_t SizeOfCode;			    /* unreliable */
    uint32_t SizeOfInitializedData;		    /* unreliable */
    uint32_t SizeOfUninitializedData;		    /* unreliable */
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint64_t ImageBase;				    /* multiple of 64 KB */
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
    uint64_t SizeOfStackReserve;
    uint64_t SizeOfStackCommit;
    uint64_t SizeOfHeapReserve;
    uint64_t SizeOfHeapCommit;
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

int cli_scanpe(int desc, cli_ctx *ctx);

int cli_peheader(int desc, struct cli_exe_info *peinfo);

#endif

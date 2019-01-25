/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *
 *  Authors: Alberto Wu
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

/*
** rebuildpe.c
** 
** 28/07/2k4 - Moved out of petitep.c
** 08/08/2k4 - Fixed typo for sects characteristics
**
*/

/*
** Rebuilds a fully parsable / *not runnable* PE file including
** a fake MZ header, a piece of informational 16bit code,
** lookalike PE & Optional headers, an array of structures and
** of course the real content.
** Sections characteristics will have all the bits set.
*/

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <string.h>

#include "clamav.h"
#include "rebuildpe.h"
#include "others.h"

#define EC32(x) le32_to_host(x) /* Convert little endian to host */
#define EC16(x) le16_to_host(x) /* Convert little endian to host */
#define PEALIGN(o,a) (((a))?(((o)/(a))*(a)):(o))
#define PESALIGN(o,a) (((a))?(((o)/(a)+((o)%(a)!=0))*(a)):(o))


struct IMAGE_PE_HEADER {
    uint32_t Signature;
    /* FILE HEADER */
    uint16_t    Machine;
    uint16_t    NumberOfSections;
    uint32_t   TimeDateStamp;
    uint32_t   PointerToSymbolTable;
    uint32_t   NumberOfSymbols;
    uint16_t    SizeOfOptionalHeader;
    uint16_t    Characteristics;
    /* OPTIONAL HEADER */
    uint16_t    Magic;
    uint8_t    MajorLinkerVersion;
    uint8_t    MinorLinkerVersion;
    uint32_t   SizeOfCode;
    uint32_t   SizeOfInitializedData;
    uint32_t   SizeOfUninitializedData;
    uint32_t   AddressOfEntryPoint;
    uint32_t   BaseOfCode;
    uint32_t   BaseOfData;
    /* NT additional fields. */
    uint32_t   ImageBase;
    uint32_t   SectionAlignment;
    uint32_t   FileAlignment;
    uint16_t    MajorOperatingSystemVersion;
    uint16_t    MinorOperatingSystemVersion;
    uint16_t    MajorImageVersion;
    uint16_t    MinorImageVersion;
    uint16_t    MajorSubsystemVersion;
    uint16_t    MinorSubsystemVersion;
    uint32_t   Win32VersionValue;
    uint32_t   SizeOfImage;
    uint32_t   SizeOfHeaders;
    uint32_t   CheckSum;
    uint16_t    Subsystem;
    uint16_t    DllCharacteristics;
    uint32_t   SizeOfStackReserve;
    uint32_t   SizeOfStackCommit;
    uint32_t   SizeOfHeapReserve;
    uint32_t   SizeOfHeapCommit;
    uint32_t   LoaderFlags;
    uint32_t   NumberOfRvaAndSizes;
    /* IMAGE_DATA_DIRECTORY follows.... */
};

#define HEADERS "\
\x4D\x5A\x90\x00\x02\x00\x00\x00\x04\x00\x0F\x00\xFF\xFF\x00\x00\
\xB0\x00\x00\x00\x00\x00\x00\x00\x40\x00\x1A\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xD0\x00\x00\x00\
\x0E\x1F\xB4\x09\xBA\x0D\x00\xCD\x21\xB4\x4C\xCD\x21\x54\x68\x69\
\x73\x20\x66\x69\x6C\x65\x20\x77\x61\x73\x20\x63\x72\x65\x61\x74\
\x65\x64\x20\x62\x79\x20\x43\x6C\x61\x6D\x41\x56\x20\x66\x6F\x72\
\x20\x69\x6E\x74\x65\x72\x6E\x61\x6C\x20\x75\x73\x65\x20\x61\x6E\
\x64\x20\x73\x68\x6F\x75\x6C\x64\x20\x6E\x6F\x74\x20\x62\x65\x20\
\x72\x75\x6E\x2E\x0D\x0A\x43\x6C\x61\x6D\x41\x56\x20\x2D\x20\x41\
\x20\x47\x50\x4C\x20\x76\x69\x72\x75\x73\x20\x73\x63\x61\x6E\x6E\
\x65\x72\x20\x2D\x20\x68\x74\x74\x70\x3A\x2F\x2F\x77\x77\x77\x2E\
\x63\x6C\x61\x6D\x61\x76\x2E\x6E\x65\x74\x0D\x0A\x24\x00\x00\x00\
\x50\x45\x00\x00\x4C\x01\xFF\xFF\x43\x4C\x41\x4D\x00\x00\x00\x00\
\x00\x00\x00\x00\xE0\x00\x83\x8F\x0B\x01\x00\x00\x00\x10\x00\x00\
\x00\x10\x00\x00\x00\x00\x00\x00\xFF\xFF\xFF\xFF\x00\x10\x00\x00\
\x00\x10\x00\x00\xFF\xFF\xFF\xFF\x00\x10\x00\x00\x00\x02\x00\x00\
\x01\x00\x00\x00\x00\x00\x00\x00\x03\x00\x0A\x00\x00\x00\x00\x00\
\x00\x10\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\
\x00\x00\x10\x00\x00\x10\x00\x00\x00\x00\x10\x00\x00\x10\x00\x00\
\x00\x00\x00\x00\x10\x00\x00\x00\
"

int cli_rebuildpe(char *buffer, struct cli_exe_section *sections, int sects, uint32_t base, uint32_t ep, uint32_t ResRva, uint32_t ResSize, int file)
{
  return cli_rebuildpe_align(buffer, sections, sects, base, ep, ResRva, ResSize, file, 0);
}

int cli_rebuildpe_align(char *buffer, struct cli_exe_section *sections, int sects, uint32_t base, uint32_t ep, uint32_t ResRva, uint32_t ResSize, int file, uint32_t align)
{
  uint32_t datasize=0, rawbase=PESALIGN(0x148+0x80+0x28*sects, 0x200);
  char *pefile=NULL, *curpe;
  struct IMAGE_PE_HEADER *fakepe;
  int i, gotghost=(sections[0].rva > PESALIGN(rawbase, 0x1000));

  if (gotghost) rawbase=PESALIGN(0x148+0x80+0x28*(sects+1), 0x200);

  if(sects+gotghost > 96)
    return 0;

  if (!align)
    for (i=0; i < sects; i++)
      datasize+=PESALIGN(sections[i].rsz, 0x200);
  else
    for (i=0; i < sects; i++)
      datasize+=PESALIGN(PESALIGN(sections[i].rsz, align), 0x200);

  if(datasize > CLI_MAX_ALLOCATION)
    return 0;

  pefile = (char *) cli_calloc(rawbase+datasize, 1);
  if(!pefile)
      return 0;

  memcpy(pefile, HEADERS, 0x148);

  datasize = PESALIGN(rawbase, 0x1000);

  fakepe = (struct IMAGE_PE_HEADER *)(pefile+0xd0);
  fakepe->NumberOfSections = EC16(sects+gotghost);
  fakepe->AddressOfEntryPoint = EC32(ep);
  fakepe->ImageBase = EC32(base);
  fakepe->SizeOfHeaders = EC32(rawbase);
  memset(pefile+0x148, 0, 0x80);
  cli_writeint32(pefile+0x148+0x10, ResRva);
  cli_writeint32(pefile+0x148+0x14, ResSize);
  curpe = pefile+0x148+0x80;

  if (gotghost) {
      snprintf(curpe, 8, "empty");
      cli_writeint32(curpe+8, sections[0].rva-datasize); /* vsize */
      cli_writeint32(curpe+12, datasize); /* rva */
      cli_writeint32(curpe+0x24, 0xffffffff);
      curpe+=40;
      datasize+=PESALIGN(sections[0].rva-datasize, 0x1000);
  }

  for (i=0; i < sects; i++) {
      snprintf(curpe, 8, ".clam%.2d", i+1);
      if (!align) {
          cli_writeint32(curpe+8, sections[i].vsz);
          cli_writeint32(curpe+12, sections[i].rva);
          cli_writeint32(curpe+16, sections[i].rsz);
          cli_writeint32(curpe+20, rawbase);
      } else {
          cli_writeint32(curpe+8, PESALIGN(sections[i].vsz, align));
          cli_writeint32(curpe+12, PESALIGN(sections[i].rva, align));
          cli_writeint32(curpe+16, PESALIGN(sections[i].rsz, align));
          cli_writeint32(curpe+20, rawbase);
      }
      /* already zeroed
         cli_writeint32(curpe+24, 0);
         cli_writeint32(curpe+28, 0);
         cli_writeint32(curpe+32, 0);
      */
      cli_writeint32(curpe+0x24, 0xffffffff);
      memcpy(pefile+rawbase, buffer+sections[i].raw, sections[i].rsz);
      curpe+=40;
      if (!align) {
          rawbase+=PESALIGN(sections[i].rsz, 0x200);
          datasize+=PESALIGN(sections[i].vsz, 0x1000);
      } else {
          rawbase+=PESALIGN(PESALIGN(sections[i].rsz, align), 0x200);
          datasize+=PESALIGN(PESALIGN(sections[i].vsz, align), 0x1000);
      }
  }
  fakepe->SizeOfImage = EC32(datasize);

  i = (cli_writen(file, pefile, rawbase)!=-1);
  free(pefile);
  return i;
}

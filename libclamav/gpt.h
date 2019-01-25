/*
 *  Copyright (C) 2014-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *
 *  Authors: Kevin Lin <klin@sourcefire.com>
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

#ifndef __GPT_H
#define __GPT_H

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include "clamav-types.h"
#include "others.h"

/* GPT sector size is normally 512 bytes be can be set to much larger 
 * values. Sector size for GPT can be found by the offset the GPT header
 * signature is located (marking the beginning of the second sector.
*/
#define GPT_SIGNATURE 0x4546492050415254ULL
#define GPT_SIGNATURE_STR "EFI PART"
#define GPT_PRIMARY_HDR_LBA 1
#define GPT_HDR_RESERVED 0

#ifndef HAVE_ATTRIB_PACKED
#define __attribute__(x)
#endif

#ifdef HAVE_PRAGMA_PACK
#pragma pack(1)
#endif

#ifdef HAVE_PRAGMA_PACK_HPPA
#pragma pack 1
#endif

/* 92-byte gpt_header, these are little endian */
struct gpt_header {
    uint64_t signature  __attribute__ ((packed));
    uint32_t revision  __attribute__ ((packed));
    uint32_t headerSize  __attribute__ ((packed)); /* should be 92 bytes */
    uint32_t headerCRC32  __attribute__ ((packed));
    uint32_t reserved  __attribute__ ((packed)); /* this MUST be zero */

    /* LBA values should be 1 and the last sector index */
    uint64_t currentLBA  __attribute__ ((packed));
    uint64_t backupLBA  __attribute__ ((packed));

    /* data not including the gpt_header and partition table */
    uint64_t firstUsableLBA  __attribute__ ((packed));
    uint64_t lastUsableLBA  __attribute__ ((packed));

    uint8_t DiskGUID[16];

    /* partition table information */
    uint64_t tableStartLBA  __attribute__ ((packed));
    uint32_t tableNumEntries  __attribute__ ((packed));
    uint32_t tableEntrySize  __attribute__ ((packed));
    uint32_t tableCRC32  __attribute__ ((packed));
    /* zeroes fill remainder of sector (420 bytes in 512 sector size) */
};

/* 128-byte partition entry, part of an array of 128+ entries, in little_endian */
struct gpt_partition_entry {
    uint8_t typeGUID[16];
    uint8_t uniqueGUID[16];
    uint64_t firstLBA  __attribute__ ((packed));
    uint64_t lastLBA  __attribute__ ((packed));
    uint64_t attributes  __attribute__ ((packed));
    uint16_t name[36] __attribute__ ((packed));
};

#ifdef HAVE_PRAGMA_PACK
#pragma pack()
#endif

#ifdef HAVE_PRAGMA_PACK_HPPA
#pragma pack
#endif

size_t gpt_detect_size(fmap_t *map);
int cli_scangpt(cli_ctx *ctx, size_t sectorsize);

#endif

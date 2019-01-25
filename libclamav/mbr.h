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

#ifndef __MBR_H
#define __MBR_H

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include "clamav-types.h"
#include "others.h"

#define MBR_SECTOR_SIZE 512
#define MBR_MAX_PARTITION_ENTRIES 4
#define CL_MAX_LOGICAL_PARTITIONS 50

#define MBR_SIGNATURE 0x55aa
#define MBR_SECTOR 0

/* MBR Status */
#define MBR_STATUS_INACTIVE 0x00
/* other values are invalid status */
#define MBR_STATUS_ACTIVE   0x80
/* End MBR Status */

/* MBR Partition Types */
#define MBR_EMPTY      0x00
#define MBR_EXTENDED   0x05
#define MBR_HYBRID     0xed
#define MBR_PROTECTIVE 0xee
/* End Partition Types */

#ifndef HAVE_ATTRIB_PACKED
#define __attribute__(x)
#endif

#ifdef HAVE_PRAGMA_PACK
#pragma pack(1)
#endif

#ifdef HAVE_PRAGMA_PACK_HPPA
#pragma pack 1
#endif

/* 16-byte MBR partition entry, little-endian */
struct mbr_partition_entry {
    uint8_t status; /* 0x80 = active, 0x00 = inactive */
    uint8_t firstCHS[3];
    uint8_t type;
    uint8_t lastCHS[3];
    uint32_t firstLBA  __attribute__ ((packed));
    uint32_t numLBA  __attribute__ ((packed));
};

struct mbr_boot_record {
    /* 446 bytes of reserved, implementation-based data */
    struct mbr_partition_entry entries[4];
    uint16_t signature  __attribute__ ((packed));
};

#ifdef HAVE_PRAGMA_PACK
#pragma pack()
#endif

#ifdef HAVE_PRAGMA_PACK_HPPA
#pragma pack
#endif

int cli_mbr_check(const unsigned char *buff, size_t len, size_t maplen);
int cli_mbr_check2(cli_ctx *ctx, size_t sectorsize);
int cli_scanmbr(cli_ctx *ctx, size_t sectorsize);
void mbr_convert_to_host(struct mbr_boot_record *record);

#endif

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

#ifndef __APM_H
#define __APM_H

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include "clamav-types.h"
#include "others.h"

#define APM_FALLBACK_SECTOR_SIZE 512

#define APM_PTABLE_BLOCK 1
#define APM_STRUCT_SIZE 512

#define DDM_SIGNATURE 0x4552 /* driver description signature ('ER') */
#define APM_SIGNATURE 0x504D /* partition map signature ('PM') */

/* partition flags */
#define VALID          0x00000001
#define ALLOCATED      0x00000002
#define IN_USE         0x00000004
#define BOOTABLE       0x00000008
#define READABLE       0x00000010
#define WRITEABLE      0x00000020
#define POSINDEPENDENT 0x00000040
/* end of partition flags */

#ifndef HAVE_ATTRIB_PACKED
#define __attribute__(x)
#endif

#ifdef HAVE_PRAGMA_PACK
#pragma pack(1)
#endif

#ifdef HAVE_PRAGMA_PACK_HPPA
#pragma pack 1
#endif

/* 8-byte driver description entry for ddmap, big endian */
struct apm_driver_desc_entry {
    uint32_t block  __attribute__ ((packed));
    uint16_t size  __attribute__ ((packed));
    uint16_t type  __attribute__ ((packed));
}; //NOTE may need to be renamed

/* 512(82)-byte driver descriptor map (Block0), big endian */
struct apm_driver_desc_map {
    uint16_t signature  __attribute__ ((packed));
    uint16_t blockSize  __attribute__ ((packed));
    uint32_t blockCount  __attribute__ ((packed));
    uint16_t deviceType  __attribute__ ((packed));
    uint16_t deviceID  __attribute__ ((packed));
    uint32_t driverData  __attribute__ ((packed));
    uint16_t driverCount  __attribute__ ((packed));
    struct apm_driver_desc_entry driverTable[8];
    /* zeroes fill remainder of sector (430 bytes in 512 sector size) */
};

/* 512(136)-byte partition info, big endian;
 * both the partition table and the individual partitions use this 
 * struct to describe their details
 */
struct apm_partition_info {
    uint16_t signature  __attribute__ ((packed));
    uint16_t reserved  __attribute__ ((packed));
    uint32_t numPartitions  __attribute__ ((packed));
    uint32_t pBlockStart  __attribute__ ((packed));
    uint32_t pBlockCount  __attribute__ ((packed));
    uint8_t name[32];
    uint8_t type[32];
    uint32_t lBlockStart  __attribute__ ((packed));
    uint32_t lBlockCount  __attribute__ ((packed));
    uint32_t flags  __attribute__ ((packed));
    uint32_t bootBlockStart  __attribute__ ((packed));
    uint32_t bootSize  __attribute__ ((packed));
    uint32_t bootAddr  __attribute__ ((packed));
    uint32_t bootAddr2  __attribute__ ((packed));
    uint32_t bootEntry  __attribute__ ((packed));
    uint32_t bootEntry2  __attribute__ ((packed));
    uint32_t bootChecksum  __attribute__ ((packed));
    uint8_t processor[16];
    /* zeroes fill remainder of sector (376 bytes in 512 sector size) */
};

#ifdef HAVE_PRAGMA_PACK
#pragma pack()
#endif

#ifdef HAVE_PRAGMA_PACK_HPPA
#pragma pack
#endif

int cli_scanapm(cli_ctx *ctx);

#endif

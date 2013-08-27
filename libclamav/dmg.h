/*
 *  Copyright (C) 2013 Sourcefire, Inc.
 *
 *  Authors: David Raynor <draynor@sourcefire.com>
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

#ifndef __DMG_H
#define __DMG_H

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include "cltypes.h"
#include "others.h"

#ifndef HAVE_ATTRIB_PACKED
#define __attribute__(x)
#endif

#ifdef HAVE_PRAGMA_PACK
#pragma pack(1)
#endif

#ifdef HAVE_PRAGMA_PACK_HPPA
#pragma pack 1
#endif

/* 512-byte block, remember these are big-endian! */
struct dmg_koly_block {
    uint32_t magic  __attribute__ ((packed));
    uint32_t version __attribute__ ((packed));
    uint32_t headerLength __attribute__ ((packed));
    uint32_t flags __attribute__ ((packed));
    uint64_t runningOffset __attribute__ ((packed));
    uint64_t dataForkOffset __attribute__ ((packed));
    uint64_t dataForkLength __attribute__ ((packed));
    uint64_t resourceForkOffset __attribute__ ((packed));
    uint64_t resourceForkLength __attribute__ ((packed));
    uint32_t segment __attribute__ ((packed));
    uint32_t segmentCount __attribute__ ((packed));
    /* technically uuid */
    uint8_t  segmentID[16];

    uint32_t dataChecksumFields[34] __attribute__ ((packed));

    uint64_t xmlOffset __attribute__ ((packed));
    uint64_t xmlLength __attribute__ ((packed));
    uint8_t  padding[120];

    uint32_t masterChecksumFields[34] __attribute__ ((packed));

    uint32_t imageVariant __attribute__ ((packed));
    uint64_t sectorCount __attribute__ ((packed));

    uint32_t reserved[3] __attribute__ ((packed));
};

/* 204-byte block, still big-endian */
struct dmg_mish_block {
    uint32_t magic;
    uint32_t version;

    uint64_t startSector;
    uint64_t sectorCount;
    uint64_t dataOffset;
    uint32_t bufferCount;
    uint32_t descriptorBlocks;

    uint8_t  reserved[24];

    uint32_t checksum[34];
    uint64_t blockDescriptorCount;
};

#ifdef HAVE_PRAGMA_PACK
#pragma pack()
#endif

#ifdef HAVE_PRAGMA_PACK_HPPA
#pragma pack
#endif

int cli_scandmg(cli_ctx *ctx);

#endif

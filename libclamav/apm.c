/*
 *  Copyright (C) 2014-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *
 *  Authors: Kevin Lin <kevlin2@cisco.com>
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

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdio.h>
#include <errno.h>
#if HAVE_STRING_H
#include <string.h>
#endif
#include <ctype.h>
#include <fcntl.h>

#include "clamav-types.h"
#include "others.h"
#include "apm.h"
#include "prtn_intxn.h"
#include "scanners.h"
#include "dconf.h"

//#define DEBUG_APM_PARSE

#ifdef DEBUG_APM_PARSE
#  define apm_parsemsg(...) cli_dbgmsg( __VA_ARGS__)
#else
#  define apm_parsemsg(...) ;
#endif

static int apm_prtn_intxn(cli_ctx *ctx, struct apm_partition_info *aptable, size_t sectorsize, int old_school);

int cli_scanapm(cli_ctx *ctx)
{
    struct apm_driver_desc_map ddm;
    struct apm_partition_info aptable, apentry;
    int ret = CL_CLEAN, detection = CL_CLEAN, old_school = 0;
    size_t sectorsize, maplen, partsize;
    off_t pos = 0, partoff = 0;
    unsigned i;
    uint32_t max_prtns = 0;

    if (!ctx || !ctx->fmap) {
        cli_errmsg("cli_scanapm: Invalid context\n");
        return CL_ENULLARG;
    }

    /* read driver description map at sector 0  */
    if (fmap_readn(*ctx->fmap, &ddm, pos, sizeof(ddm)) != sizeof(ddm)) {
        cli_dbgmsg("cli_scanapm: Invalid Apple driver description map\n");
        return CL_EFORMAT;
    }

    /* convert driver description map big-endian to host */
    ddm.signature = be16_to_host(ddm.signature);
    ddm.blockSize = be16_to_host(ddm.blockSize);
    ddm.blockCount = be32_to_host(ddm.blockCount);

    /* check DDM signature */
    if (ddm.signature != DDM_SIGNATURE) {
        cli_dbgmsg("cli_scanapm: Apple driver description map signature mismatch\n");
        return CL_EFORMAT;
    }

    /* sector size is determined by the ddm */
    sectorsize = ddm.blockSize;

    /* size of total file must be described by the ddm */
    maplen = (*ctx->fmap)->real_len;
    if ((ddm.blockSize * ddm.blockCount) != maplen) {
        cli_dbgmsg("cli_scanapm: File described %u size does not match %lu actual size\n",
                   (ddm.blockSize * ddm.blockCount), (unsigned long)maplen);
        return CL_EFORMAT;
    }

    /* check for old-school partition map */
    if (sectorsize == 2048) {
        if (fmap_readn(*ctx->fmap, &aptable, APM_FALLBACK_SECTOR_SIZE, sizeof(aptable)) != sizeof(aptable)) {
            cli_dbgmsg("cli_scanapm: Invalid Apple partition entry\n");
            return CL_EFORMAT;
        }

        aptable.signature = be16_to_host(aptable.signature);
        if (aptable.signature == APM_SIGNATURE) {
            sectorsize = APM_FALLBACK_SECTOR_SIZE;
            old_school = 1;
        }
    }

    /* read partition table at sector 1 (or after the ddm if old-school) */
    pos = APM_PTABLE_BLOCK * sectorsize;

    if (fmap_readn(*ctx->fmap, &aptable, pos, sizeof(aptable)) != sizeof(aptable)) {
        cli_dbgmsg("cli_scanapm: Invalid Apple partition table\n");
        return CL_EFORMAT;
    }

    /* convert partition table big endian to host */
    aptable.signature = be16_to_host(aptable.signature);
    aptable.numPartitions = be32_to_host(aptable.numPartitions);
    aptable.pBlockStart = be32_to_host(aptable.pBlockStart);
    aptable.pBlockCount = be32_to_host(aptable.pBlockCount);

    /* check the partition entry signature */
    if (aptable.signature != APM_SIGNATURE) {
        cli_dbgmsg("cli_scanapm: Apple partition table signature mismatch\n");
        return CL_EFORMAT;
    }

    /* check if partition table partition */
    if (strncmp((char*)aptable.type, "Apple_Partition_Map", 32) &&
        strncmp((char*)aptable.type, "Apple_partition_map", 32) &&
        strncmp((char*)aptable.type, "Apple_patition_map", 32)){
        cli_dbgmsg("cli_scanapm: Initial Apple Partition Map partition is not detected\n");
        return CL_EFORMAT;
    }

    /* check that the partition table fits in the space specified - HEURISTICS */
    if (SCAN_HEURISTIC_PARTITION_INTXN && (ctx->dconf->other & OTHER_CONF_PRTNINTXN)) {
        ret = apm_prtn_intxn(ctx, &aptable, sectorsize, old_school);
        if (ret != CL_CLEAN) {
            if (SCAN_ALLMATCHES && (ret == CL_VIRUS))
                detection = CL_VIRUS;
            else
                return ret;
        }
    }

    /* print debugging info on partition tables */
    cli_dbgmsg("APM Partition Table:\n");
    cli_dbgmsg("Name: %s\n", (char*)aptable.name);
    cli_dbgmsg("Type: %s\n", (char*)aptable.type);
    cli_dbgmsg("Signature: %x\n", aptable.signature);
    cli_dbgmsg("Partition Count: %u\n", aptable.numPartitions);
    cli_dbgmsg("Blocks: [%u, +%u), ([%lu, +%lu))\n",
               aptable.pBlockStart, aptable.pBlockCount,
               (unsigned long)(aptable.pBlockStart * sectorsize),
               (unsigned long)(aptable.pBlockCount * sectorsize));

    /* check engine maxpartitions limit */
    if (aptable.numPartitions < ctx->engine->maxpartitions) {
        max_prtns = aptable.numPartitions;
    }
    else {
        max_prtns = ctx->engine->maxpartitions;
    }

    /* partition table is a partition [at index 1], so skip it */
    for (i = 2; i <= max_prtns; ++i) {
        /* read partition table entry */
        pos = i * sectorsize;
        if (fmap_readn(*ctx->fmap, &apentry, pos, sizeof(apentry)) != sizeof(apentry)) {
            cli_dbgmsg("cli_scanapm: Invalid Apple partition entry\n");
            return CL_EFORMAT;
        }

        /* convert partition entry big endian to host */
        apentry.signature = be16_to_host(apentry.signature);
        apentry.reserved = be16_to_host(apentry.reserved);
        apentry.numPartitions = be32_to_host(apentry.numPartitions);
        apentry.pBlockStart = be32_to_host(apentry.pBlockStart);
        apentry.pBlockCount = be32_to_host(apentry.pBlockCount);

        /* check the partition entry signature */
        if (aptable.signature != APM_SIGNATURE) {
            cli_dbgmsg("cli_scanapm: Apple partition entry signature mismatch\n");
            return CL_EFORMAT;
        }

        /* check if a out-of-order partition map */
        if (!strncmp((char*)apentry.type, "Apple_Partition_Map", 32) ||
            !strncmp((char*)apentry.type, "Apple_partition_map", 32) ||
            !strncmp((char*)apentry.type, "Apple_patition_map", 32)) {

            cli_dbgmsg("cli_scanapm: Out of order Apple Partition Map partition\n");
            continue;
        }

        partoff = apentry.pBlockStart * sectorsize;
        partsize = apentry.pBlockCount * sectorsize;
        /* re-calculate if old_school and aligned [512 * 4 => 2048] */
        if (old_school && ((i % 4) == 0)) {
            if (!strncmp((char*)apentry.type, "Apple_Driver",       32) ||
                !strncmp((char*)apentry.type, "Apple_Driver43",     32) ||
                !strncmp((char*)apentry.type, "Apple_Driver43_CD",  32) ||
                !strncmp((char*)apentry.type, "Apple_Driver_ATA",   32) ||
                !strncmp((char*)apentry.type, "Apple_Driver_ATAPI", 32) ||
                !strncmp((char*)apentry.type, "Apple_Patches",      32)) {

                partsize = apentry.pBlockCount * 2048;;
            }
        }

        /* check if invalid partition */
        if ((partoff == 0) || (partoff+partsize > maplen)) {
            cli_dbgmsg("cli_scanapm: Detected invalid Apple partition entry\n");
            continue;
        }

        /* print debugging info on partition */
        cli_dbgmsg("APM Partition Entry %u:\n", i);
        cli_dbgmsg("Name: %s\n", (char*)apentry.name);
        cli_dbgmsg("Type: %s\n", (char*)apentry.type);
        cli_dbgmsg("Signature: %x\n", apentry.signature);
        cli_dbgmsg("Partition Count: %u\n", apentry.numPartitions);
        cli_dbgmsg("Blocks: [%u, +%u), ([%lu, +%lu))\n",
                   apentry.pBlockStart, apentry.pBlockCount, (long unsigned)partoff, (long unsigned)partsize);

        /* send the partition to cli_map_scan */
        ret = cli_map_scan(*ctx->fmap, partoff, partsize, ctx, CL_TYPE_PART_ANY);
        if (ret != CL_CLEAN) {
            if (SCAN_ALLMATCHES && (ret == CL_VIRUS))
                detection = CL_VIRUS;
            else
                return ret;
        }
    } 

    if (i >= ctx->engine->maxpartitions) {
        cli_dbgmsg("cli_scanapm: max partitions reached\n");
    }

    return detection;
}

static int apm_prtn_intxn(cli_ctx *ctx, struct apm_partition_info *aptable, size_t sectorsize, int old_school)
{
    prtn_intxn_list_t prtncheck;
    struct apm_partition_info apentry;
    unsigned i, pitxn;
    int ret = CL_CLEAN, tmp = CL_CLEAN;
    off_t pos;
    uint32_t max_prtns = 0;
    int virus_found = 0;

    prtn_intxn_list_init(&prtncheck);

    /* check engine maxpartitions limit */
    if (aptable->numPartitions < ctx->engine->maxpartitions) {
        max_prtns = aptable->numPartitions;
    }
    else {
        max_prtns = ctx->engine->maxpartitions;
    }

    for (i = 1; i <= max_prtns; ++i) {
        /* read partition table entry */
        pos = i * sectorsize;
        if (fmap_readn(*ctx->fmap, &apentry, pos, sizeof(apentry)) != sizeof(apentry)) {
            cli_dbgmsg("cli_scanapm: Invalid Apple partition entry\n");
            prtn_intxn_list_free(&prtncheck);
            return CL_EFORMAT;
        }

        /* convert necessary info big endian to host */
        apentry.pBlockStart = be32_to_host(apentry.pBlockStart);
        apentry.pBlockCount = be32_to_host(apentry.pBlockCount);
        /* re-calculate if old_school and aligned [512 * 4 => 2048] */
        if (old_school && ((i % 4) == 0)) {
            if (!strncmp((char*)apentry.type, "Apple_Driver",       32) ||
                !strncmp((char*)apentry.type, "Apple_Driver43",     32) ||
                !strncmp((char*)apentry.type, "Apple_Driver43_CD",  32) ||
                !strncmp((char*)apentry.type, "Apple_Driver_ATA",   32) ||
                !strncmp((char*)apentry.type, "Apple_Driver_ATAPI", 32) ||
                !strncmp((char*)apentry.type, "Apple_Patches",      32)) {

                apentry.pBlockCount = apentry.pBlockCount * 4;;
            }
        }

        tmp = prtn_intxn_list_check(&prtncheck, &pitxn, apentry.pBlockStart, apentry.pBlockCount);
        if (tmp != CL_CLEAN) {
            if (tmp == CL_VIRUS) {
                apm_parsemsg("Name: %s\n", (char*)aptable.name);
                apm_parsemsg("Type: %s\n", (char*)aptable.type);

                cli_dbgmsg("cli_scanapm: detected intersection with partitions "
                           "[%u, %u]\n", pitxn, i);
                ret = cli_append_virus(ctx, PRTN_INTXN_DETECTION);
                if (ret == CL_VIRUS)
                    virus_found = 1;
                if (SCAN_ALLMATCHES || ret == CL_CLEAN)
                    tmp = 0;
                else
                    goto leave;
            } else {
                ret = tmp;
                goto leave;
            }
        }
        pos += sectorsize;
    }

 leave:
    prtn_intxn_list_free(&prtncheck);
    if (virus_found)
        return CL_VIRUS;
    return ret;
}

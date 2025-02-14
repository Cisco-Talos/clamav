/*
 *  Copyright (C) 2014-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
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
#include "partition_intersection.h"
#include "scanners.h"
#include "dconf.h"

// #define DEBUG_APM_PARSE

#ifdef DEBUG_APM_PARSE
#define apm_parsemsg(...) cli_dbgmsg(__VA_ARGS__)
#else
#define apm_parsemsg(...) ;
#endif

static cl_error_t apm_partition_intersection(cli_ctx *ctx, struct apm_partition_info *aptable, size_t sectorsize, bool old_school);

cl_error_t cli_scanapm(cli_ctx *ctx)
{
    cl_error_t status = CL_SUCCESS;
    struct apm_driver_desc_map ddm;
    struct apm_partition_info aptable, apentry;
    bool old_school = false;
    size_t sectorsize, maplen, partsize;
    size_t pos = 0, partoff = 0;
    unsigned i;
    uint32_t max_prtns = 0;

    if (!ctx || !ctx->fmap) {
        cli_errmsg("cli_scanapm: Invalid context\n");
        status = CL_ENULLARG;
        goto done;
    }

    /* read driver description map at sector 0  */
    if (fmap_readn(ctx->fmap, &ddm, pos, sizeof(ddm)) != sizeof(ddm)) {
        cli_dbgmsg("cli_scanapm: Invalid Apple driver description map\n");
        status = CL_EFORMAT;
        goto done;
    }

    /* convert driver description map big-endian to host */
    ddm.signature  = be16_to_host(ddm.signature);
    ddm.blockSize  = be16_to_host(ddm.blockSize);
    ddm.blockCount = be32_to_host(ddm.blockCount);

    /* check DDM signature */
    if (ddm.signature != DDM_SIGNATURE) {
        cli_dbgmsg("cli_scanapm: Apple driver description map signature mismatch\n");
        status = CL_EFORMAT;
        goto done;
    }

    /* sector size is determined by the ddm */
    sectorsize = ddm.blockSize;

    /* size of total file must be described by the ddm */
    maplen = ctx->fmap->len;
    if ((ddm.blockSize * ddm.blockCount) != maplen) {
        cli_dbgmsg("cli_scanapm: File described %u size does not match %lu actual size\n",
                   (ddm.blockSize * ddm.blockCount), (unsigned long)maplen);
        status = CL_EFORMAT;
        goto done;
    }

    /* check for old-school partition map */
    if (sectorsize == 2048) {
        if (fmap_readn(ctx->fmap, &aptable, APM_FALLBACK_SECTOR_SIZE, sizeof(aptable)) != sizeof(aptable)) {
            cli_dbgmsg("cli_scanapm: Invalid Apple partition entry\n");
            status = CL_EFORMAT;
            goto done;
        }

        aptable.signature = be16_to_host(aptable.signature);
        if (aptable.signature == APM_SIGNATURE) {
            sectorsize = APM_FALLBACK_SECTOR_SIZE;
            old_school = true;
        }
    }

    /* read partition table at sector 1 (or after the ddm if old-school) */
    pos = APM_PTABLE_BLOCK * sectorsize;

    if (fmap_readn(ctx->fmap, &aptable, pos, sizeof(aptable)) != sizeof(aptable)) {
        cli_dbgmsg("cli_scanapm: Invalid Apple partition table\n");
        status = CL_EFORMAT;
        goto done;
    }

    /* convert partition table big endian to host */
    aptable.signature     = be16_to_host(aptable.signature);
    aptable.numPartitions = be32_to_host(aptable.numPartitions);
    aptable.pBlockStart   = be32_to_host(aptable.pBlockStart);
    aptable.pBlockCount   = be32_to_host(aptable.pBlockCount);

    /* check the partition entry signature */
    if (aptable.signature != APM_SIGNATURE) {
        cli_dbgmsg("cli_scanapm: Apple partition table signature mismatch\n");
        status = CL_EFORMAT;
        goto done;
    }

    /* check if partition table partition */
    if (strncmp((char *)aptable.type, "Apple_Partition_Map", 32) &&
        strncmp((char *)aptable.type, "Apple_partition_map", 32) &&
        strncmp((char *)aptable.type, "Apple_patition_map", 32)) {
        cli_dbgmsg("cli_scanapm: Initial Apple Partition Map partition is not detected\n");
        status = CL_EFORMAT;
        goto done;
    }

    /* check that the partition table fits in the space specified - HEURISTICS */
    if (SCAN_HEURISTIC_PARTITION_INTXN && (ctx->dconf->other & OTHER_CONF_PRTNINTXN)) {
        status = apm_partition_intersection(ctx, &aptable, sectorsize, old_school);
        if (status != CL_SUCCESS) {
            goto done;
        }
    }

    /* print debugging info on partition tables */
    cli_dbgmsg("APM Partition Table:\n");
    cli_dbgmsg("Name: %s\n", (char *)aptable.name);
    cli_dbgmsg("Type: %s\n", (char *)aptable.type);
    cli_dbgmsg("Signature: %x\n", aptable.signature);
    cli_dbgmsg("Partition Count: %u\n", aptable.numPartitions);
    cli_dbgmsg("Blocks: [%u, +%u), ([%lu, +%lu))\n",
               aptable.pBlockStart, aptable.pBlockCount,
               (unsigned long)(aptable.pBlockStart * sectorsize),
               (unsigned long)(aptable.pBlockCount * sectorsize));

    /* check engine maxpartitions limit */
    if (aptable.numPartitions < ctx->engine->maxpartitions) {
        max_prtns = aptable.numPartitions;
    } else {
        max_prtns = ctx->engine->maxpartitions;
    }

    /* partition table is a partition [at index 1], so skip it */
    for (i = 2; i <= max_prtns; ++i) {
        /* read partition table entry */
        pos = i * sectorsize;
        if (fmap_readn(ctx->fmap, &apentry, pos, sizeof(apentry)) != sizeof(apentry)) {
            cli_dbgmsg("cli_scanapm: Invalid Apple partition entry\n");
            status = CL_EFORMAT;
            goto done;
        }

        /* convert partition entry big endian to host */
        apentry.signature     = be16_to_host(apentry.signature);
        apentry.reserved      = be16_to_host(apentry.reserved);
        apentry.numPartitions = be32_to_host(apentry.numPartitions);
        apentry.pBlockStart   = be32_to_host(apentry.pBlockStart);
        apentry.pBlockCount   = be32_to_host(apentry.pBlockCount);

        /* check the partition entry signature */
        if (aptable.signature != APM_SIGNATURE) {
            cli_dbgmsg("cli_scanapm: Apple partition entry signature mismatch\n");
            status = CL_EFORMAT;
            goto done;
        }

        /* check if an out-of-order partition map */
        if (!strncmp((char *)apentry.type, "Apple_Partition_Map", 32) ||
            !strncmp((char *)apentry.type, "Apple_partition_map", 32) ||
            !strncmp((char *)apentry.type, "Apple_patition_map", 32)) {

            cli_dbgmsg("cli_scanapm: Out of order Apple Partition Map partition\n");
            continue;
        }

        partoff  = apentry.pBlockStart * sectorsize;
        partsize = apentry.pBlockCount * sectorsize;
        /* re-calculate if old_school and aligned [512 * 4 => 2048] */
        if (old_school && ((i % 4) == 0)) {
            if (!strncmp((char *)apentry.type, "Apple_Driver", 32) ||
                !strncmp((char *)apentry.type, "Apple_Driver43", 32) ||
                !strncmp((char *)apentry.type, "Apple_Driver43_CD", 32) ||
                !strncmp((char *)apentry.type, "Apple_Driver_ATA", 32) ||
                !strncmp((char *)apentry.type, "Apple_Driver_ATAPI", 32) ||
                !strncmp((char *)apentry.type, "Apple_Patches", 32)) {

                partsize = apentry.pBlockCount * 2048;
            }
        }

        /* check if invalid partition */
        if ((partoff == 0) || (partoff + partsize > maplen)) {
            cli_dbgmsg("cli_scanapm: Detected invalid Apple partition entry\n");
            continue;
        }

        /* print debugging info on partition */
        cli_dbgmsg("APM Partition Entry %u:\n", i);
        cli_dbgmsg("Name: %s\n", (char *)apentry.name);
        cli_dbgmsg("Type: %s\n", (char *)apentry.type);
        cli_dbgmsg("Signature: %x\n", apentry.signature);
        cli_dbgmsg("Partition Count: %u\n", apentry.numPartitions);
        cli_dbgmsg("Blocks: [%u, +%u), ([%zu, +%zu))\n",
                   apentry.pBlockStart, apentry.pBlockCount, partoff, partsize);

        /* send the partition to cli_magic_scan_nested_fmap_type */
        status = cli_magic_scan_nested_fmap_type(ctx->fmap, partoff, partsize, ctx, CL_TYPE_PART_ANY, (const char *)apentry.name, LAYER_ATTRIBUTES_NONE);
        if (status != CL_SUCCESS) {
            goto done;
        }
    }

    if (i >= ctx->engine->maxpartitions) {
        cli_dbgmsg("cli_scanapm: max partitions reached\n");
    }

done:

    return status;
}

static cl_error_t apm_partition_intersection(cli_ctx *ctx, struct apm_partition_info *aptable, size_t sectorsize, bool old_school)
{
    cl_error_t status = CL_SUCCESS;
    cl_error_t ret;
    partition_intersection_list_t prtncheck;
    struct apm_partition_info apentry;
    unsigned i, pitxn;
    size_t pos;
    uint32_t max_prtns = 0;

    partition_intersection_list_init(&prtncheck);

    /* check engine maxpartitions limit */
    if (aptable->numPartitions < ctx->engine->maxpartitions) {
        max_prtns = aptable->numPartitions;
    } else {
        max_prtns = ctx->engine->maxpartitions;
    }

    for (i = 1; i <= max_prtns; ++i) {
        /* read partition table entry */
        pos = i * sectorsize;
        if (fmap_readn(ctx->fmap, &apentry, pos, sizeof(apentry)) != sizeof(apentry)) {
            cli_dbgmsg("cli_scanapm: Invalid Apple partition entry\n");
            partition_intersection_list_free(&prtncheck);
            status = CL_EFORMAT;
            goto done;
        }

        /* convert necessary info big endian to host */
        apentry.pBlockStart = be32_to_host(apentry.pBlockStart);
        apentry.pBlockCount = be32_to_host(apentry.pBlockCount);
        /* re-calculate if old_school and aligned [512 * 4 => 2048] */
        if (old_school && ((i % 4) == 0)) {
            if (!strncmp((char *)apentry.type, "Apple_Driver", 32) ||
                !strncmp((char *)apentry.type, "Apple_Driver43", 32) ||
                !strncmp((char *)apentry.type, "Apple_Driver43_CD", 32) ||
                !strncmp((char *)apentry.type, "Apple_Driver_ATA", 32) ||
                !strncmp((char *)apentry.type, "Apple_Driver_ATAPI", 32) ||
                !strncmp((char *)apentry.type, "Apple_Patches", 32)) {

                apentry.pBlockCount = apentry.pBlockCount * 4;
            }
        }

        ret = partition_intersection_list_check(&prtncheck, &pitxn, apentry.pBlockStart, apentry.pBlockCount);
        if (ret != CL_CLEAN) {
            if (ret == CL_VIRUS) {
                apm_parsemsg("Name: %s\n", (char *)aptable.name);
                apm_parsemsg("Type: %s\n", (char *)aptable.type);

                cli_dbgmsg("cli_scanapm: detected intersection with partitions "
                           "[%u, %u]\n",
                           pitxn, i);
                status = cli_append_potentially_unwanted(ctx, "Heuristics.APMPartitionIntersection");
                if (status != CL_SUCCESS) {
                    goto done;
                }
            } else {
                status = ret;
                goto done;
            }
        }

        /* increment the offsets to next partition entry */
        pos += sectorsize;
    }

done:
    partition_intersection_list_free(&prtncheck);

    return status;
}

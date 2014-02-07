/*
 *  Copyright (C) 2014 Sourcefire, Inc.
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
#include <zlib.h>

#include "cltypes.h"
#include "others.h"
#include "mbr.h"
#include "prtn_intxn.h"
#include "scanners.h"

//#define DEBUG_MBR_PARSE
//#define DEBUG_EBR_PARSE

#ifdef DEBUG_MBR_PARSE
#  define mbr_parsemsg(...) cli_dbgmsg( __VA_ARGS__)
#else
#  define mbr_parsemsg(...) ;
#endif

#ifdef DEBUG_EBR_PARSE
#  define ebr_parsemsg(...) cli_dbgmsg( __VA_ARGS__)
#else
#  define ebr_parsemsg(...) ;
#endif

enum MBR_STATE {
    SEEN_NOTHING,
    SEEN_PARTITION,
    SEEN_EXTENDED,
    SEEN_EMPTY
};

static int mbr_scanebr(cli_ctx *ctx, off_t *exloff, off_t exoff, size_t sectorsize);
static void mbr_printbr(struct mbr_boot_record *record);
static void mbr_convert_to_host(struct mbr_boot_record *record);
static int mbr_check_mbr(struct mbr_boot_record *record, size_t maplen);
static int mbr_check_ebr(struct mbr_boot_record *record);
static int mbr_primary_prtn_intxn(cli_ctx *ctx, struct mbr_boot_record mbr, size_t sectorsize);
static int mbr_extended_prtn_intxn(cli_ctx *ctx, struct mbr_boot_record mbr, size_t sectorsize);


int cli_mbr_check(const unsigned char *buff, size_t len, size_t maplen) {
    struct mbr_boot_record mbr;

    if (len < 512) {
        return CL_EFORMAT;
    }

    memcpy(&mbr, buff+MBR_BASE_OFFSET, sizeof(mbr));
    mbr_convert_to_host(&mbr);

    //mbr_printbr(&mbr);

    return mbr_check_mbr(&mbr, maplen);
}

int cli_scanmbr(cli_ctx *ctx)
{
    struct mbr_boot_record mbr;
    enum MBR_STATE state = SEEN_NOTHING;
    int ret = 0;
    size_t sectorsize, maplen, partsize;
    off_t pos = 0, partoff = 0;
    off_t exoff, exloff, exlcheck[CL_MAX_LOGICAL_PARTITIONS];
    unsigned i, j, k, prtncount;

    mbr_parsemsg("The start of something magnificant: MBR parsing\n");

    if (!ctx || !ctx->fmap) {
        cli_errmsg("cli_scanmbr: Invalid context\n");
        return CL_ENULLARG;
    }

    /* sector size calculation */
    sectorsize = MBR_SECTOR_SIZE;

    /* size of total file must be a multiple of the sector size */
    maplen = (*ctx->fmap)->real_len;
    if ((maplen % sectorsize) != 0) {
        cli_dbgmsg("cli_scanmbr: File sized %u is not a multiple of sector size %u\n",
                   maplen, sectorsize);
        return CL_EFORMAT;
    }

    /* sector 0 (first sector) is the master boot record */
    pos = (MBR_SECTOR * sectorsize) + MBR_BASE_OFFSET;

    /* read the master boot record */
    if (fmap_readn(*ctx->fmap, &mbr, pos, sizeof(mbr)) != sizeof(mbr)) {
        cli_dbgmsg("cli_scanmbr: Invalid master boot record\n");
        return CL_EFORMAT;
    }

    /* convert the little endian to host, include the internal  */
    mbr_convert_to_host(&mbr);

    /* MBR checks */
    ret = mbr_check_mbr(&mbr, maplen);
    if (ret != CL_CLEAN) {
        return ret;
    }

    /* check that the partition table has no intersections - HEURISTICS */
    if (ctx->options & CL_SCAN_PARTITION_INTXN) {
        ret = mbr_primary_prtn_intxn(ctx, mbr, sectorsize);
        if ((ret != CL_CLEAN) &&
            !((ctx->options & CL_SCAN_ALLMATCHES) && (ret == CL_VIRUS))) {
        
            return ret;
        }
        ret = mbr_extended_prtn_intxn(ctx, mbr, sectorsize);
        if ((ret != CL_CLEAN) &&
            !((ctx->options & CL_SCAN_ALLMATCHES) && (ret == CL_VIRUS))) {
        
            return ret;
        }
    }

    /* MBR is valid, examine partitions */
    prtncount = 0;
    cli_dbgmsg("MBR Signature: %x\n", mbr.signature);
    for (i = 0; i < MBR_MAX_PARTITION_ENTRIES; ++i) {
        cli_dbgmsg("MBR Partition Entry %u:\n", i);
        cli_dbgmsg("Status: %u\n", mbr.entries[i].status);
        cli_dbgmsg("Type: %x\n", mbr.entries[i].type);
        cli_dbgmsg("Blocks: [%u, +%u), ([%u, +%u))\n",
                   mbr.entries[i].firstLBA, mbr.entries[i].numSectors,
                   (mbr.entries[i].firstLBA * sectorsize),
                   (mbr.entries[i].numSectors * sectorsize));

        /* Handle MBR entry based on type */
        if (mbr.entries[i].type == MBR_EMPTY) {
            /* empty partiton entry */
            prtncount++;
        }
        else if (mbr.entries[i].type == MBR_EXTENDED) {
            if (state == SEEN_EXTENDED) {
                cli_dbgmsg("cli_scanmbr: detected a master boot record "
                           "with multiple extended partitions\n");
            }
            state = SEEN_EXTENDED; /* used only to detect mutiple extended partitions */

            exoff = mbr.entries[i].firstLBA;
            exloff = 0; j = 0;
            do {
                prtncount++;
                /* check if a logical partition has been seen before */
                for (k = 0; k < j; ++k) {
                    if (exloff == exlcheck[k]) {
                        cli_dbgmsg("cli_scanmbr: found a logical partition "
                                   "that was previously seen!\n");
                        /* do things! */
                        return CL_EFORMAT;
                    }
                }
                exlcheck[j] = exloff;

                cli_dbgmsg("EBR Partition Entry %u:\n", j);
                ret = mbr_scanebr(ctx, &exloff, exoff, sectorsize);
                if ((ret != CL_CLEAN) &&
                    !((ctx->options & CL_SCAN_ALLMATCHES) && (ret == CL_VIRUS))) {
                        return ret;
                }

                ++j;
            } while (exloff != 0 && prtncount < ctx->engine->maxpartitions);

            cli_dbgmsg("cli_scanmbr: examined %u logical partitions\n", j);
        }
        else {
            prtncount++;

            partoff = mbr.entries[i].firstLBA * sectorsize;
            partsize = mbr.entries[i].numSectors * sectorsize;
            mbr_parsemsg("cli_map_scan: [%u, +%u)\n", partoff, partsize);
            ret = cli_map_scan(*ctx->fmap, partoff, partsize, ctx, CL_TYPE_PART_ANY);
            if ((ret != CL_CLEAN) &&
                !((ctx->options & CL_SCAN_ALLMATCHES) && (ret == CL_VIRUS))) {
                    return ret;
            }
        }

        if (prtncount >= ctx->engine->maxpartitions) {
            cli_dbgmsg("cli_scanmbr: maximum partitions reached\n");
            break;
        }
    }

    return ret;
}

int mbr_scanebr(cli_ctx *ctx, off_t *exloff, off_t exoff, size_t sectorsize) {
    struct mbr_boot_record ebr;
    enum MBR_STATE state = SEEN_NOTHING;
    int ret = 0;
    off_t pos = 0, partoff = 0;
    size_t partsize;
    unsigned i;

    ebr_parsemsg("The start of something excellent: EBR parsing\n");

    pos = exoff * sectorsize; /* start of extended partition */
    partoff = (exoff + *exloff) * sectorsize; /* start of logical partition */

    /* read the extended boot record */
    pos += (*exloff * sectorsize) + MBR_BASE_OFFSET;
    if (fmap_readn(*ctx->fmap, &ebr, pos, sizeof(ebr)) != sizeof(ebr)) {
        cli_dbgmsg("cli_scanebr: Invalid extended boot record\n");
        return CL_EFORMAT;
    }

    /* convert the little endian to host */
    mbr_convert_to_host(&ebr);

    /* EBR checks */
    ret = mbr_check_ebr(&ebr);
    if (ret != CL_CLEAN) {
        return ret;
    }

    /* EBR is valid, examine partitions */
    cli_dbgmsg("EBR Signature: %x\n", ebr.signature);
    for (i = 0; i < MBR_MAX_PARTITION_ENTRIES; ++i) {
        if (i < 2) {
            cli_dbgmsg("Logical Partition Entry %u:\n", i);
            cli_dbgmsg("Status: %u\n", ebr.entries[i].status);
            cli_dbgmsg("Type: %x\n", ebr.entries[i].type);
            cli_dbgmsg("Blocks: [%u, +%u), ([%u, +%u))\n",
                       ebr.entries[i].firstLBA, ebr.entries[i].numSectors,
                       (ebr.entries[i].firstLBA * sectorsize),
                       (ebr.entries[i].numSectors * sectorsize));

            if (ebr.entries[i].type == MBR_EMPTY) {
                /* empty partiton entry */
                switch(state) {
                case SEEN_NOTHING:
                    state = SEEN_EMPTY;
                    break;
                case SEEN_PARTITION:
                    *exloff = 0;
                    break;
                case SEEN_EMPTY:
                    *exloff = 0;
                    /* fall-through */
                case SEEN_EXTENDED:
                    cli_dbgmsg("cli_scanebr: detected a logical boot record "
                               "without a partition record\n");
                    break;
                default:
                    cli_dbgmsg("cli_scanebr: undefined state for EBR parsing\n");
                    return CL_EPARSE;
                }
            }
            else if (ebr.entries[i].type == MBR_EXTENDED) {
                switch(state) {
                case SEEN_NOTHING:
                    state = SEEN_EXTENDED;
                    break;
                case SEEN_PARTITION:
                    break;
                case SEEN_EMPTY:
                    cli_dbgmsg("cli_scanebr: detected a logical boot record "
                               "without a partition record\n");
                    break;
                case SEEN_EXTENDED:
                    cli_dbgmsg("cli_scanebr: detected a logical boot record "
                               "with multiple extended partition records\n");
                    return CL_EFORMAT;
                default:
                    cli_dbgmsg("cli_scanebr: undefined state for EBR parsing\n");
                    return CL_EPARSE;
                }

                *exloff = ebr.entries[i].firstLBA;
            }
            else {
                switch(state) {
                case SEEN_NOTHING:
                    state = SEEN_PARTITION;
                    break;
                case SEEN_PARTITION:
                    cli_dbgmsg("cli_scanebr: detected a logical boot record "
                               "with multiple partition records\n");
                    *exloff = 0; /* no extended partitions are possible */
                    break;
                case SEEN_EXTENDED:
                    cli_dbgmsg("cli_scanebr: detected a logical boot record "
                               "with extended partition record first\n");
                    break;
                case SEEN_EMPTY:
                    cli_dbgmsg("cli_scanebr: detected a logical boot record "
                               "with empty partition record first\n");
                    *exloff = 0; /* no extended partitions are possible */
                    break;
                default:
                    cli_dbgmsg("cli_scanebr: undefined state for EBR parsing\n");
                    return CL_EPARSE;
                }

                partoff += (ebr.entries[i].firstLBA * sectorsize);
                partsize = ebr.entries[i].numSectors * sectorsize;
                ret = cli_map_scan(*ctx->fmap, partoff, partsize, ctx, CL_TYPE_PART_ANY);
                if ((ret != CL_CLEAN) &&
                    !((ctx->options & CL_SCAN_ALLMATCHES) && (ret == CL_VIRUS))) {
                        return ret;
                }
            }
        }
        else {
            /* check the last two entries to be empty */
            if (ebr.entries[i].type != MBR_EMPTY) {
                cli_dbgmsg("cli_scanebr: detected a logical boot record "
                           "with an entry at index %u\n", i);
                /* should we attepmt to use these entries? */
                return CL_EFORMAT;
            }
        }
    }

    return ret;
}

static void mbr_printbr(struct mbr_boot_record *record)
{
    unsigned i;

    cli_dbgmsg("signature: %x\n", record->signature);
    for (i = 0; i < MBR_MAX_PARTITION_ENTRIES; ++i) {
        cli_dbgmsg("entry %u:\n", i);
        cli_dbgmsg("\tstatus: %x\n", record->entries[i].status);
        cli_dbgmsg("\tfirstCHS: [%u, %u, %u]\n", record->entries[i].firstCHS[0],
                   record->entries[i].firstCHS[1], record->entries[i].firstCHS[2]);
        cli_dbgmsg("\ttype: %x\n", record->entries[i].type);
        cli_dbgmsg("\tlastCHS: [%u, %u, %u]\n", record->entries[i].lastCHS[0],
                   record->entries[i].lastCHS[1], record->entries[i].lastCHS[2]);
        cli_dbgmsg("\tfirstLBA: %u\n", record->entries[i].firstLBA);
        cli_dbgmsg("\tnumSectors: %u\n", record->entries[i].numSectors);
    }
}

static void mbr_convert_to_host(struct mbr_boot_record *record)
{
    struct mbr_partition_entry *entry;
    unsigned i;
 
    for (i = 0; i < MBR_MAX_PARTITION_ENTRIES; ++i) {
        entry = &record->entries[i];
 
        entry->firstLBA = le32_to_host(entry->firstLBA);
        entry->numSectors = le32_to_host(entry->numSectors);
    }
    record->signature = be16_to_host(record->signature);
}

static int mbr_check_mbr(struct mbr_boot_record *record, size_t maplen)
{
    unsigned i = 0;
    off_t partoff = 0;
    size_t partsize = 0, sectorsize = MBR_SECTOR_SIZE;

    for (i = 0; i < MBR_MAX_PARTITION_ENTRIES; ++i) {
        /* check status */
        if ((record->entries[i].status != MBR_STATUS_INACTIVE) && 
            (record->entries[i].status != MBR_STATUS_ACTIVE)) {
            cli_dbgmsg("cli_scanmbr: Invalid boot record status\n");
            return CL_EFORMAT;
        }

        partoff = record->entries[i].firstLBA * sectorsize;
        partsize = record->entries[i].numSectors * sectorsize;
        if (partoff + partsize > maplen) {
            cli_dbgmsg("cli_scanmbr: Invalid partition entry\n");
            return CL_EFORMAT;
        }
    }

    /* check the signature */
    if (record->signature != MBR_SIGNATURE) {
        cli_dbgmsg("cli_scanmbr: Invalid boot record signature\n");
        return CL_EFORMAT;
    }

    return CL_CLEAN;
}

static int mbr_check_ebr(struct mbr_boot_record *record)
{
    unsigned i = 0;

    for (i = 0; i < MBR_MAX_PARTITION_ENTRIES; ++i) {
        /* check status */
        if ((record->entries[i].status != MBR_STATUS_INACTIVE) && 
            (record->entries[i].status != MBR_STATUS_ACTIVE)) {
            cli_dbgmsg("cli_scanmbr: Invalid boot record status\n");
            return CL_EFORMAT;
        }
    }

    /* check the signature */
    if (record->signature != MBR_SIGNATURE) {
        cli_dbgmsg("cli_scanmbr: Invalid boot record signature\n");
        return CL_EFORMAT;
    }

    return CL_CLEAN;
}

/* this includes the overall bounds of extended partitions */
static int mbr_primary_prtn_intxn(cli_ctx *ctx, struct mbr_boot_record mbr, size_t sectorsize)
{
    prtn_intxn_list_t prtncheck;
    unsigned i, pitxn;
    int ret = 0, tmp = 0;

    prtn_intxn_list_init(&prtncheck);

    for (i = 0; i < MBR_MAX_PARTITION_ENTRIES; ++i) {
        if (mbr.entries[i].type != MBR_EMPTY) {
            tmp = prtn_intxn_list_check(&prtncheck, &pitxn, mbr.entries[i].firstLBA, 
                                        mbr.entries[i].numSectors);
            if (tmp != CL_CLEAN) {
                if ((ctx->options & CL_SCAN_ALLMATCHES) && (tmp == CL_VIRUS)) {
                    cli_dbgmsg("cli_scanmbr: detected intersection with partitions "
                               "[%u, %u]\n", pitxn, i);
                    cli_append_virus(ctx, "Heuristic.PartitionIntersection");
                    ret = tmp;
                    tmp = 0;
                }
                else if (tmp == CL_VIRUS) {
                    cli_dbgmsg("cli_scanmbr: detected intersection with partitions "
                               "[%u, %u]\n", pitxn, i);
                    cli_append_virus(ctx, "Heuristic.PartitionIntersection");
                    prtn_intxn_list_free(&prtncheck);
                    return CL_VIRUS;
                }
                else {
                    prtn_intxn_list_free(&prtncheck);
                    return tmp;
                }
            }
        }
    }

    prtn_intxn_list_free(&prtncheck);
    return ret;
}

/* checks internal logical partitions */
static int mbr_extended_prtn_intxn(cli_ctx *ctx, struct mbr_boot_record mbr, size_t sectorsize)
{
    struct mbr_boot_record ebr;
    prtn_intxn_list_t prtncheck;
    unsigned i, j, pitxn;
    int ret = 0, tmp = 0;
    off_t pos = 0, exoff = 0, exloff = 0;

    for (i = 0; i < MBR_MAX_PARTITION_ENTRIES; ++i) {
        if (mbr.entries[i].type == MBR_EXTENDED) {

            prtn_intxn_list_init(&prtncheck);

            exoff = mbr.entries[i].firstLBA;
            exloff = 0; j = 0;
            do {
                pos = exoff * sectorsize; /* start of extended partition */

                /* read the extended boot record */
                pos += (exloff * sectorsize) + MBR_BASE_OFFSET;
                if (fmap_readn(*ctx->fmap, &ebr, pos, sizeof(ebr)) != sizeof(ebr)) {
                    cli_dbgmsg("cli_scanebr: Invalid extended boot record\n");
                    prtn_intxn_list_free(&prtncheck);
                    return CL_EFORMAT;
                }

                /* convert the little endian to host */
                mbr_convert_to_host(&ebr);

                /* assume that logical record is first and extended is second */
                tmp = prtn_intxn_list_check(&prtncheck, &pitxn, exloff, ebr.entries[0].numSectors);
                if (tmp != CL_CLEAN) {
                    if ((ctx->options & CL_SCAN_ALLMATCHES) && (tmp == CL_VIRUS)) {
                        cli_dbgmsg("cli_scanebr: detected intersection with partitions "
                                   "[%u, %u]\n", pitxn, i);
                        cli_append_virus(ctx, "Heuristic.PartitionIntersection");
                        ret = tmp;
                        tmp = 0;
                    }
                    else if (tmp == CL_VIRUS) {
                        cli_dbgmsg("cli_scanebr: detected intersection with partitions "
                                   "[%u, %u]\n", pitxn, i);
                        cli_append_virus(ctx, "Heuristic.PartitionIntersection");
                        prtn_intxn_list_free(&prtncheck);
                        return CL_VIRUS;
                    }
                    else {
                        prtn_intxn_list_free(&prtncheck);
                        return tmp;
                    }
                }

                /* assume extended is second entry */
                if (ebr.entries[1].type != MBR_EXTENDED) {
                    cli_dbgmsg("cli_scanebr: second entry for EBR is not an extended partition\n");
                    break;
                }

                exloff = ebr.entries[1].firstLBA;

                ++j;
            } while (exloff != 0 && j < CL_MAX_LOGICAL_PARTITIONS);

            if (j == CL_MAX_LOGICAL_PARTITIONS) {
                cli_dbgmsg("cli_scanebr: reached maximum number of scanned logical partitions\n");
            }

            prtn_intxn_list_free(&prtncheck);    
        }
    }


    return ret;

}

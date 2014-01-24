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
#include "gpt.h"
#include "scanners.h"

//#define DEBUG_GPT_PARSE
//#define DEBUG_GPT_PRINT

#ifdef DEBUG_GPT_PARSE
#  define gpt_parsemsg(...) cli_dbgmsg( __VA_ARGS__)
#else
#  define gpt_parsemsg(...) ;
#endif

#ifdef DEBUG_GPT_PRINT
#  define gpt_printmsg(...) cli_dbgmsg( __VA_ARGS__)
#else
#  define gpt_printmsg(...) ;
#endif

static void gpt_printSectors(cli_ctx *ctx, size_t sectorsize)
{
#ifdef DEBUG_GPT_PARSE
    struct gpt_header phdr, shdr;
    off_t ppos = 0, spos = 0;
    size_t pptable_len, sptable_len, maplen;
    uint64_t ptableLastLBA, stableLastLBA;

    /* sector size may need to be calculated */
    sectorsize = GPT_SECTOR_SIZE;

    maplen = (*ctx->fmap)->real_len;

    ppos = 1 * sectorsize; /* sector 1 (second sector) is the primary gpt header */
    spos = maplen - sectorsize; /* last sector is the secondary gpt header */

    /* read in the primary and secondary gpt headers */
    if (fmap_readn(*ctx->fmap, &phdr, ppos, sizeof(phdr)) != sizeof(phdr)) {
        cli_dbgmsg("cli_scangpt: Invalid primary GPT header\n");
        return;
    }
    if (fmap_readn(*ctx->fmap, &shdr, spos, sizeof(shdr)) != sizeof(shdr)) {
        cli_dbgmsg("cli_scangpt: Invalid secondary GPT header\n");
        return;
    }

    pptable_len = phdr.tableNumEntries * phdr.tableEntrySize;
    sptable_len = shdr.tableNumEntries * shdr.tableEntrySize;
    ptableLastLBA = (phdr.tableStartLBA + (pptable_len / sectorsize)) - 1;
    stableLastLBA = (shdr.tableStartLBA + (sptable_len / sectorsize)) - 1;

    gpt_parsemsg("0: MBR\n");
    gpt_parsemsg("%llu: Primary GPT Header\n", phdr.currentLBA);
    gpt_parsemsg("%llu-%llu: Primary GPT Partition Table\n", phdr.tableStartLBA, ptableLastLBA);
    gpt_parsemsg("%llu-%llu: Usuable LBAs\n", phdr.firstUsableLBA, phdr.lastUsableLBA);
    gpt_parsemsg("%llu-%llu: Secondary GPT Partition Table\n", shdr.tableStartLBA, stableLastLBA);
    gpt_parsemsg("%llu: Secondary GPT Header\n", phdr.backupLBA);
#else
    return;
#endif
}

static void gpt_printGUID(uint8_t GUID[], const char* msg)
{
    unsigned i;
    char hexstr[64], tmpstr[64];

    hexstr[0] = '\0';
    tmpstr[0] = '\0';
    for (i = 0; i < 16; ++i) {
        gpt_printmsg("%x\n", GUID[i]);
        if (i == 3 || i == 5 || i == 7 || i == 9) {
            snprintf(hexstr, 64, "%s%02x-", tmpstr, GUID[i]);
            gpt_printmsg("%s\n", hexstr);
        }
        else {
            snprintf(hexstr, 64, "%s%02x", tmpstr, GUID[i]);
            gpt_printmsg("%s\n", hexstr);
        }
        strncpy(tmpstr, hexstr, 64);
    }
    cli_dbgmsg("%s: %s\n", msg, hexstr);
}

static int gpt_validate_header(cli_ctx *ctx, struct gpt_header hdr, size_t sectorsize)
{
    uint32_t crc32_calc, crc32_ref;
    uint64_t tableLastLBA, lastLBA;
    size_t maplen, ptable_start, ptable_len;
    unsigned char *ptable;

    maplen = (*ctx->fmap)->real_len;

    /* checking header crc32 checksum */
    crc32_ref = hdr.headerCRC32;
    hdr.headerCRC32 = 0; /* checksum is calculated with field = 0 */
    crc32_calc = crc32(0, (unsigned char*)&hdr, sizeof(hdr));
    if (crc32_calc != crc32_ref) {
        cli_dbgmsg("cli_scangpt: GPT header checksum mismatch\n");
        gpt_parsemsg("%x != %x\n", crc32_calc, crc32_ref);
        return -1;
    }

    /* convert endian to host to check partition table */
    hdr.signature = be64_to_host(hdr.signature);
    hdr.revision = be32_to_host(hdr.revision);
    hdr.headerSize = le32_to_host(hdr.headerSize);
    hdr.headerCRC32 = le32_to_host(hdr.headerCRC32);
    hdr.reserved = le32_to_host(hdr.reserved);
    hdr.currentLBA = le64_to_host(hdr.currentLBA);
    hdr.backupLBA = le64_to_host(hdr.backupLBA);
    hdr.firstUsableLBA = le64_to_host(hdr.firstUsableLBA);
    hdr.lastUsableLBA = le64_to_host(hdr.lastUsableLBA);
    hdr.tableStartLBA = le64_to_host(hdr.tableStartLBA);
    hdr.tableNumEntries = le32_to_host(hdr.tableNumEntries);
    hdr.tableEntrySize = le32_to_host(hdr.tableEntrySize);
    hdr.tableCRC32 = le32_to_host(hdr.tableCRC32);

    ptable_start = hdr.tableStartLBA * sectorsize;
    ptable_len = hdr.tableNumEntries * hdr.tableEntrySize;
    tableLastLBA = (hdr.tableStartLBA + (ptable_len / sectorsize)) - 1;
    lastLBA = (maplen / sectorsize) - 1;

    /** HEADER CHECKS **/
    gpt_printSectors(ctx, sectorsize);

    /* check signature */
    if (hdr.signature != GPT_SIGNATURE) {
        cli_dbgmsg("cli_scangpt: Invalid GPT header signature %llx\n",
                   hdr.signature);
        return -1;
    }

    /* check header size */
    if (hdr.headerSize != sizeof(hdr)) {
        cli_dbgmsg("cli_scangpt: GPT header size does not match stated size\n");
        return -1;
    }

    /* check reserved value == 0 */
    if (hdr.reserved != GPT_HDR_RESERVED) {
        cli_dbgmsg("cli_scangpt: GPT header reserved is not expected value\n");
        return -1;
    }

    /* check that sectors are in a valid configuration */
    if (!((hdr.currentLBA == GPT_PRIMARY_HDR_LBA && hdr.backupLBA == lastLBA) ||
          (hdr.currentLBA == lastLBA && hdr.backupLBA == GPT_PRIMARY_HDR_LBA))) {
        cli_dbgmsg("cli_scangpt: GPT secondary header is not last LBA\n");
        return -1;
    }
    if (hdr.firstUsableLBA > hdr.lastUsableLBA) {
        cli_dbgmsg("cli_scangpt: GPT first usable sectors is after last usable sector\n");
        return -1;
    }
    if (hdr.firstUsableLBA <= GPT_PRIMARY_HDR_LBA || hdr.lastUsableLBA >= lastLBA) {
        cli_dbgmsg("cli_scangpt: GPT usable sectors intersects header sector\n");
        return -1;
    }
    if ((hdr.tableStartLBA <= hdr.firstUsableLBA && tableLastLBA >= hdr.firstUsableLBA) ||
        (hdr.tableStartLBA >= hdr.firstUsableLBA && hdr.tableStartLBA <= hdr.lastUsableLBA)) {
        cli_dbgmsg("cli_scangpt: GPT usable sectors intersects partition table\n");
        return -1;
    }
    if (hdr.tableStartLBA <= GPT_PRIMARY_HDR_LBA || tableLastLBA >= lastLBA) {
        cli_dbgmsg("cli_scangpt: GPT partition table intersects header sector\n");
        return -1;
    }

    /* check valid table */
    if ((ptable_start + ptable_len) > maplen) {
        cli_dbgmsg("cli_scangpt: GPT partition table extends over fmap limit\n");
        return -1;
    }

    /** END HEADER CHECKS **/

    /* checking partition table crc32 checksum */
    ptable = (unsigned char*)fmap_need_off_once((*ctx->fmap), ptable_start, ptable_len);
    crc32_calc = crc32(0, ptable, ptable_len);
    if (crc32_calc != hdr.tableCRC32) {
        cli_dbgmsg("cli_scangpt: GPT partition table checksum mismatch\n");
        gpt_parsemsg("%x != %x\n", crc32_calc, hdr.tableCRC32);
        return -1;
    }

    return 0;
}

int cli_scangpt(cli_ctx *ctx)
{
    struct gpt_header hdr;
    struct gpt_partition_entry gpe;
    int ret = 0, func_ret = 0;
    size_t sectorsize, maplen, part_size;
    off_t pos = 0, part_off = 0;
    unsigned i = 0;

    gpt_parsemsg("The beginning of something big: GPT parsing\n");

    if (!ctx || !ctx->fmap) {
        cli_errmsg("cli_scangpt: Invalid context\n");
        return CL_ENULLARG;
    }

    /* sector size may need to be calculated */
    sectorsize = GPT_SECTOR_SIZE;

    /* size of total file must be a multiple of the sector size */
    maplen = (*ctx->fmap)->real_len;
    if ((maplen % sectorsize) != 0) {
        cli_dbgmsg("cli_scangpt: File sized %u is not a multiple of sector size %u\n",
                   maplen, sectorsize);
        return CL_EFORMAT;
    }

    pos = GPT_PRIMARY_HDR_LBA * sectorsize; /* sector 1 (second sector) is the primary gpt header */
  
    /* read primary gpt header */
    cli_dbgmsg("cli_scangpt: Using primary GPT header\n");
    if (fmap_readn(*ctx->fmap, &hdr, pos, sizeof(hdr)) != sizeof(hdr)) {
        cli_dbgmsg("cli_scangpt: Invalid primary GPT header\n");
        return CL_EFORMAT;
    }

    if (gpt_validate_header(ctx, hdr, sectorsize)) {
        cli_dbgmsg("cli_scangpt: Primary GPT header is invalid\n");
        cli_dbgmsg("cli_scangpt: Using secondary GPT header\n");

        pos = maplen - sectorsize; /* last sector is the secondary gpt header */

        /* read secondary gpt header */
        if (fmap_readn(*ctx->fmap, &hdr, pos, sizeof(hdr)) != sizeof(hdr)) {
            cli_dbgmsg("cli_scangpt: Invalid secondary GPT header\n");
            return CL_EFORMAT;
        }

        if (gpt_validate_header(ctx, hdr, sectorsize)) {
            cli_dbgmsg("cli_scangpt: Secondary GPT header is invalid\n");
            cli_dbgmsg("cli_scangpt: Disk is unusable\n");
            return CL_EFORMAT;
        }
    }

    /* convert endian to host */
    hdr.signature = be64_to_host(hdr.signature);
    hdr.revision = be32_to_host(hdr.revision);
    hdr.headerSize = le32_to_host(hdr.headerSize);
    hdr.headerCRC32 = le32_to_host(hdr.headerCRC32);
    hdr.reserved = le32_to_host(hdr.reserved);
    hdr.currentLBA = le64_to_host(hdr.currentLBA);
    hdr.backupLBA = le64_to_host(hdr.backupLBA);
    hdr.firstUsableLBA = le64_to_host(hdr.firstUsableLBA);
    hdr.lastUsableLBA = le64_to_host(hdr.lastUsableLBA);
    hdr.tableStartLBA = le64_to_host(hdr.tableStartLBA);
    hdr.tableNumEntries = le32_to_host(hdr.tableNumEntries);
    hdr.tableEntrySize = le32_to_host(hdr.tableEntrySize);
    hdr.tableCRC32 = le32_to_host(hdr.tableCRC32);

    /* print header info for the debug */
    cli_dbgmsg("GPT Header:\n");
    cli_dbgmsg("Signature: 0x%llx\n", hdr.signature);
    cli_dbgmsg("Revision: %x\n", hdr.revision);
    gpt_printGUID(hdr.DiskGUID, "DISK GUID");
    cli_dbgmsg("Partition Entry Count: %u\n", hdr.tableNumEntries);
    cli_dbgmsg("Partition Entry Size: %u\n", hdr.tableEntrySize);

    /* check that all partition table parameters are expected values */
    if (hdr.tableEntrySize != GPT_PARTITION_ENTRY_SIZE) {
        cli_dbgmsg("cli_scangpt: cannot parse gpt with partition entry sized %u\n",
                   hdr.tableEntrySize);
        return CL_EFORMAT;
    }

    /* use the partition tables to pass partitions to cli_map_scan */
    pos = hdr.tableStartLBA * sectorsize;
    for (i = 0; i < hdr.tableNumEntries; ++i) {
        /* read in partition entry */
        if (fmap_readn(*ctx->fmap, &gpe, pos, sizeof(gpe)) != sizeof(gpe)) {
            cli_dbgmsg("cli_scangpt: Invalid secondary GPT partition entry\n");
            return CL_EFORMAT;
        }

        /* convert the endian to host */
        gpe.firstLBA = le64_to_host(gpe.firstLBA);
        gpe.lastLBA = le64_to_host(gpe.lastLBA);
        gpe.attributes = le64_to_host(gpe.attributes);

        /* check that partition is not empty and within a valid location */
        if (gpe.firstLBA == 0) {
            /* empty partition, valid */
        }
        else if ((gpe.firstLBA > gpe.lastLBA) ||
                 (gpe.firstLBA < hdr.firstUsableLBA) || (gpe.lastLBA > hdr.lastUsableLBA)) {
            /* partition exists outside bounds specified by header or invalid */
            /* see what a mac does in this situation */
            cli_dbgmsg("cli_scangpt: GPT partition exists outside specified bounds\n");
            gpt_parsemsg("%llu < %llu, %llu > %llu\n", gpe.firstLBA, hdr.firstUsableLBA,
                         gpe.lastLBA, hdr.lastUsableLBA);
            return CL_EFORMAT;
        }
        else {
            /* print partition entry data for debug */
            cli_dbgmsg("GPT Partition Entry %u:\n", i);
            gpt_printGUID(gpe.typeGUID, "Type GUID");
            gpt_printGUID(gpe.uniqueGUID, "Unique GUID");
            cli_dbgmsg("Attributes: %llx\n", gpe.attributes);
            /* printing this name is worrisome, disabling */
            //cli_dbgmsg("Name: %s\n", (char*)gpe.name);

            /* send the partition to cli_map_scan */
            part_off = gpe.firstLBA * sectorsize;
            part_size = (gpe.lastLBA - gpe.firstLBA) * sectorsize;
            ret = cli_map_scan(*ctx->fmap, part_off, part_size, ctx, CL_TYPE_PART_ANY);
            if (ret != CL_CLEAN) {
                if ((ctx->options & CL_SCAN_ALLMATCHES) && (ret == CL_VIRUS)) {
                    func_ret = ret;
                }
                else {
                    return ret;
                }
            }
        }

        /* increment the offsets to next partition entry */
        pos += hdr.tableEntrySize;
    }

    return func_ret;
}

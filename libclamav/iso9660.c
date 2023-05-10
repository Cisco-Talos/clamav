/*
 *  Copyright (C) 2013-2023 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2011-2013 Sourcefire, Inc.
 *
 *  Authors: aCaB <acab@clamav.net>
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

#include <string.h>

#include "clamav.h"
#include "scanners.h"
#include "iso9660.h"
#include "fmap.h"
#include "str.h"
#include "entconv.h"
#include "hashtab.h"

typedef struct {
    cli_ctx *ctx;
    size_t base_offset;
    unsigned int blocksz;
    unsigned int sectsz;
    unsigned int fileno;
    unsigned int joliet;
    char buf[260];
    struct cli_hashset dir_blocks;
} iso9660_t;

static const void *needblock(const iso9660_t *iso, unsigned int block, int temp)
{
    cli_ctx *ctx = iso->ctx;
    size_t loff;
    unsigned int blocks_per_sect = (2048 / iso->blocksz);
    if (block > ((ctx->fmap->len - iso->base_offset) / iso->sectsz) * blocks_per_sect)
        return NULL;                                  /* Block is out of file */
    loff = (block / blocks_per_sect) * iso->sectsz;   /* logical sector */
    loff += (block % blocks_per_sect) * iso->blocksz; /* logical block within the sector */
    if (temp)
        return fmap_need_off_once(ctx->fmap, iso->base_offset + loff, iso->blocksz);
    return fmap_need_off(ctx->fmap, iso->base_offset + loff, iso->blocksz);
}

static cl_error_t iso_scan_file(const iso9660_t *iso, unsigned int block, unsigned int len)
{
    char *tmpf;
    int fd         = -1;
    cl_error_t ret = CL_SUCCESS;

    if (cli_gentempfd(iso->ctx->sub_tmpdir, &tmpf, &fd) != CL_SUCCESS) {
        return CL_ETMPFILE;
    }

    cli_dbgmsg("iso_scan_file: dumping to %s\n", tmpf);
    while (len) {
        const void *buf   = needblock(iso, block, 1);
        unsigned int todo = MIN(len, iso->blocksz);
        if (!buf) {
            /* Block outside file */
            cli_dbgmsg("iso_scan_file: cannot dump block outside file, ISO may be truncated\n");
            ret = CL_EFORMAT;
            break;
        }
        if (cli_writen(fd, buf, todo) != todo) {
            cli_warnmsg("iso_scan_file: Can't write to file %s\n", tmpf);
            ret = CL_EWRITE;
            break;
        }
        len -= todo;
        block++;
    }

    if (!len) {
        ret = cli_magic_scan_desc(fd, tmpf, iso->ctx, iso->buf, LAYER_ATTRIBUTES_NONE);
    }

    close(fd);
    if (!iso->ctx->engine->keeptmp) {
        if (cli_unlink(tmpf)) {
            ret = CL_EUNLINK;
        }
    }

    free(tmpf);
    return ret;
}

static char *iso_string(iso9660_t *iso, const void *src, unsigned int len)
{
    if (iso->joliet) {
        char *utf8;
        const char *uutf8;
        if (len > (sizeof(iso->buf) - 2))
            len = sizeof(iso->buf) - 2;
        memcpy(iso->buf, src, len);
        iso->buf[len]     = '\0';
        iso->buf[len + 1] = '\0';
        utf8              = cli_utf16_to_utf8(iso->buf, len, E_UTF16_BE);
        uutf8             = utf8 ? utf8 : "";
        strncpy(iso->buf, uutf8, sizeof(iso->buf));
        iso->buf[sizeof(iso->buf) - 1] = '\0';
        free(utf8);
    } else {
        memcpy(iso->buf, src, len);
        iso->buf[len] = '\0';
    }
    return iso->buf;
}

static cl_error_t iso_parse_dir(iso9660_t *iso, unsigned int block, unsigned int len)
{
    cli_ctx *ctx   = iso->ctx;
    cl_error_t ret = CL_SUCCESS;

    if (len < 34) {
        cli_dbgmsg("iso_parse_dir: Directory too small, skipping\n");
        return CL_SUCCESS;
    }

    for (; len && ret == CL_SUCCESS; block++, len -= MIN(len, iso->blocksz)) {
        const uint8_t *dir, *dir_orig;
        unsigned int dirsz;

        if (iso->dir_blocks.count > 1024) {
            cli_dbgmsg("iso_parse_dir: Breaking out due to too many dir records\n");
            return CL_BREAK;
        }

        if (cli_hashset_contains(&iso->dir_blocks, block)) {
            continue;
        }

        if (CL_SUCCESS != (ret = cli_hashset_addkey(&iso->dir_blocks, block))) {
            return ret;
        }

        dir = dir_orig = needblock(iso, block, 0);
        if (!dir) {
            return CL_SUCCESS;
        }

        for (dirsz = MIN(iso->blocksz, len);;) {
            unsigned int entrysz = *dir, fileoff, filesz;
            char *sep;

            if (!dirsz || !entrysz) /* continuing on next block, if any */
                break;
            if (entrysz > dirsz) { /* record size overlaps onto the next sector, no point in looking in there */
                cli_dbgmsg("iso_parse_dir: Directory entry overflow, breaking out %u %u\n", entrysz, dirsz);
                len = 0;
                break;
            }
            if (entrysz < 34) { /* this shouldn't happen really*/
                cli_dbgmsg("iso_parse_dir: Too short directory entry, attempting to skip\n");
                dirsz -= entrysz;
                dir += entrysz;
                continue;
            }
            filesz = dir[32];
            if (filesz == 1 && (dir[33] == 0 || dir[33] == 1)) { /* skip "." and ".." */
                dirsz -= entrysz;
                dir += entrysz;
                continue;
            }

            if (filesz + 33 > dirsz) {
                cli_dbgmsg("iso_parse_dir: Directory entry name overflow, clamping\n");
                filesz = dirsz - 33;
            }
            iso_string(iso, &dir[33], filesz);
            sep = memchr(iso->buf, ';', filesz);
            if (sep)
                *sep = '\0';
            else
                iso->buf[filesz] = '\0';
            fileoff = cli_readint32(dir + 2);
            fileoff += dir[1];
            filesz = cli_readint32(dir + 10);

            cli_dbgmsg("iso_parse_dir: %s '%s': off %x - size %x - flags %x - unit size %x - gap size %x - volume %u\n", (dir[25] & 2) ? "Directory" : "File", iso->buf, fileoff, filesz, dir[25], dir[26], dir[27], cli_readint32(&dir[28]) & 0xffff);
            ret = cli_matchmeta(ctx, iso->buf, filesz, filesz, 0, 0, 0, NULL);
            if (ret != CL_SUCCESS) {
                break;
            }

            if (dir[26] || dir[27])
                cli_dbgmsg("iso_parse_dir: Skipping interleaved file\n");
            else {
                /* TODO Handle multi-extent ? */
                if (dir[25] & 2) {
                    ret = iso_parse_dir(iso, fileoff, filesz);
                } else {
                    if (CL_SUCCESS != cli_checklimits("ISO9660", ctx, filesz, 0, 0)) {
                        cli_dbgmsg("iso_parse_dir: Skipping overlimit file\n");
                    } else {
                        ret = iso_scan_file(iso, fileoff, filesz);
                    }
                }
                if (ret != CL_SUCCESS) {
                    break;
                }
            }
            dirsz -= entrysz;
            dir += entrysz;
        }

        fmap_unneed_ptr(ctx->fmap, dir_orig, iso->blocksz);
    }

    return ret;
}

static uint16_t getDescriptorTagId(const uint8_t *const buffer)
{
    return le16_to_host(((DescriptorTag *)buffer)->tagId);
}

static bool isDirectory(FileIdentifierDescriptor *fid)
{
    return (fid->characteristics & 2);
}

static cl_error_t writeWholeFile(cli_ctx *ctx, const char *const fileName, const uint8_t *const data, const size_t dataLen)
{

    int fd;
    char *tmpf = NULL;

    cl_error_t ret = CL_ETMPFILE;

    if (0 == dataLen || NULL == data) {
        cli_warnmsg("writeWholeFile: Invalid arguments\n");
        ret = CL_EARG;
        goto done;
    }

    /*Not sure if I care about the name that is actually created.*/
    if (cli_gentempfd_with_prefix(ctx->sub_tmpdir, fileName, &tmpf, &fd) != CL_SUCCESS) {
        cli_warnmsg("writeWholeFile: Can't create temp file\n");
        return CL_ETMPFILE;
    }

    if (cli_writen(fd, data, dataLen) != dataLen) {
        cli_warnmsg("iso_scan_file: Can't write to file %s\n", tmpf);
        ret = CL_EWRITE;
        goto done;
    }

    ret = cli_magic_scan_desc(fd, tmpf, ctx, fileName, LAYER_ATTRIBUTES_NONE);

    close(fd);
    if (!ctx->engine->keeptmp) {
        if (cli_unlink(tmpf)) {
            ret = CL_EUNLINK;
            goto done;
        }
    }

done:
    FREE(tmpf);

    return ret;
}

static cl_error_t extractFile(cli_ctx *ctx, PartitionDescriptor *pPartitionDescriptor, LogicalVolumeDescriptor *pLogicalVolumeDescriptor, void *address, uint16_t icbFlags, FileIdentifierDescriptor *fileIdentifierDescriptor)
{

    cl_error_t ret    = CL_SUCCESS;
    uint32_t offset   = 0;
    uint32_t length   = 0;
    uint8_t *contents = NULL;

    if (isDirectory(fileIdentifierDescriptor)) {
        goto done;
    }

    switch (icbFlags & 3) {
        case 0: {
            short_ad *shortDesc = (short_ad *)address;

            offset = pPartitionDescriptor->partitionStartingLocation * pLogicalVolumeDescriptor->logicalBlockSize;
            offset += shortDesc->position * pLogicalVolumeDescriptor->logicalBlockSize;

            length = shortDesc->length;

        } break;
        case 1: {
            long_ad *longDesc = (long_ad *)address;
            offset            = pPartitionDescriptor->partitionStartingLocation * pLogicalVolumeDescriptor->logicalBlockSize;
            length            = longDesc->length;

            if (longDesc->extentLocation.partitionReferenceNumber != pPartitionDescriptor->partitionNumber) {
                cli_warnmsg("extractFile: Unable to extract the files because the Partition Descriptor Reference Numbers don't match\n");
                goto done;
            }
            offset += longDesc->extentLocation.blockNumber * pLogicalVolumeDescriptor->logicalBlockSize;
            offset += pPartitionDescriptor->partitionStartingLocation;

        } break;
        case 2:

        {
            ext_ad *extDesc = (ext_ad *)address;
            offset          = pPartitionDescriptor->partitionStartingLocation * pLogicalVolumeDescriptor->logicalBlockSize;
            length          = extDesc->recordedLen;

            if (extDesc->extentLocation.partitionReferenceNumber != pPartitionDescriptor->partitionNumber) {
                cli_warnmsg("extractFile: Unable to extract the files because the Partition Descriptor Reference Numbers don't match\n");
                goto done;
            }
            offset += extDesc->extentLocation.blockNumber * pLogicalVolumeDescriptor->logicalBlockSize;
            offset += pPartitionDescriptor->partitionStartingLocation;

        }

        break;
        default:
            //impossible unless the file is malformed.
            cli_warnmsg("extractFile: Unknown descriptor type found.\n");
            goto done;
    }

    contents = (uint8_t *)fmap_need_off(ctx->fmap, offset, length);
    if (NULL == contents) {
        cli_warnmsg("extractFile: Unable to get offset referenced in the file.\n");
        goto done;
    }

    ret = writeWholeFile(ctx, "Test", contents, length);

    fmap_unneed_off(ctx->fmap, offset, length);

done:

    return ret;
}

static int parseFileEntryDescriptor(cli_ctx *ctx, const uint8_t *const data, PartitionDescriptor *pPartitionDescriptor, LogicalVolumeDescriptor *pLogicalVolumeDescriptor, FileIdentifierDescriptor *fileIdentifierDescriptor)
{

    FileEntryDescriptor *fed = (FileEntryDescriptor *)data;
    int ret                  = -1;

    if (261 != fed->tag.tagId) {
        cli_warnmsg("parseFileEntryDescriptor: Tag ID of 0x%x does not match File Entry Descriptor.\n", fed->tag.tagId);
        goto done;
    }

    if (257 != fileIdentifierDescriptor->tag.tagId) {
        cli_warnmsg("parseFileEntryDescriptor: Tag ID of 0x%x does not match File Identifier Descriptor.\n", fed->tag.tagId);
        goto done;
    }

    extractFile(ctx, pPartitionDescriptor, pLogicalVolumeDescriptor,
                (void *)&(data[getFileEntryDescriptorSize(fed) - fed->allocationDescLen]),
                fed->icbTag.flags, fileIdentifierDescriptor);

    ret = 0;
done:
    return ret;
}

void dumpTag(DescriptorTag *dt)
{
    fprintf(stderr, "TagId = %d (0x%x)\n", dt->tagId, dt->tagId);
    fprintf(stderr, "Version = %d (0x%x)\n", dt->descriptorVersion, dt->descriptorVersion);
    fprintf(stderr, "Checksum = %d (0x%x)\n", dt->checksum, dt->checksum);
    fprintf(stderr, "Serial Number = %d (0x%x)\n", dt->serialNumber, dt->serialNumber);

    fprintf(stderr, "Descriptor CRC = %d (0x%x)\n", dt->descriptorCRC, dt->descriptorCRC);
    fprintf(stderr, "Descriptor CRC Length = %d (0x%x)\n", dt->descriptorCRCLength, dt->descriptorCRCLength);
    fprintf(stderr, "Tag Location = %d (0x%x)\n", dt->tagLocation, dt->tagLocation);
}

typedef struct {
    uint8_t structType;
    char standardIdentifier[5];
    uint8_t structVersion;
    uint8_t rest[2041];
} GenericVolumeStructureDescriptor;
#define NUM_GENERIC_VOLUME_DESCRIPTORS 3

/*If this function fails, idx will not be updated*/
int skipEmptyDescriptors(cli_ctx *ctx, size_t *idxp, size_t *lastOffsetp)
{
    int ret         = -1;
    uint8_t *buffer = NULL;
    size_t idx      = *idxp;
    bool allzeros   = true;
    size_t i;

    while (1) {

        buffer = (uint8_t *)fmap_need_off(ctx->fmap, idx, VOLUME_DESCRIPTOR_SIZE);
        if (NULL == buffer) {
            goto done;
        }

        allzeros = true;
        for (i = 0; i < VOLUME_DESCRIPTOR_SIZE; i++) {
            if (0 != buffer[i]) {
                allzeros = false;
                break;
            }
        }
        if (!allzeros) {
            break;
        }
        idx += VOLUME_DESCRIPTOR_SIZE;
    }

    ret = 0;
done:

    *idxp        = idx;
    *lastOffsetp = idx;

    return ret;
}

typedef enum {
    PRIMARY_VOLUME_DESCRIPTOR                   = 1,
    IMPLEMENTATION_USE_VOLUME_DESCRIPTOR        = 4,
    LOGICAL_VOLUME_DESCRIPTOR                   = 6,
    PARTITION_DESCRIPTOR                        = 5,
    UNALLOCATED_SPACE_DESCRIPTOR                = 7,
    TERMINATING_DESCRIPTOR                      = 8,
    LOGICAL_VOLUME_INTEGRITY_DESCRIPTOR         = 9,
    ANCHOR_VOLUME_DESCRIPTOR_DESCRIPTOR_POINTER = 2,
    FILE_SET_DESCRIPTOR                         = 256
} VOLUME_DESCRIPTOR_TAG;

static PrimaryVolumeDescriptor *getPrimaryVolumeDescriptor(cli_ctx *ctx, size_t *idxp, size_t *lastOffsetp)
{
    uint8_t *buffer               = NULL;
    PrimaryVolumeDescriptor *test = NULL;
    PrimaryVolumeDescriptor *ret  = NULL;
    size_t idx                    = *idxp;
    size_t lastOffset             = *lastOffsetp;

    if (skipEmptyDescriptors(ctx, idxp, lastOffsetp)) {
        goto done;
    }

    idx        = *idxp;
    lastOffset = *lastOffsetp;

    buffer = (uint8_t *)fmap_need_off(ctx->fmap, idx, VOLUME_DESCRIPTOR_SIZE);
    if (NULL == buffer) {
        goto done;
    }
    lastOffset = idx;

    test = (PrimaryVolumeDescriptor *)buffer;
    if (PRIMARY_VOLUME_DESCRIPTOR != test->tag.tagId) {
        goto done;
    }

    idx += VOLUME_DESCRIPTOR_SIZE;
    ret = test;

done:
    *idxp        = idx;
    *lastOffsetp = lastOffset;

    return ret;
}

static ImplementationUseVolumeDescriptor *getImplementationUseVolumeDescriptor(cli_ctx *ctx, size_t *idxp, size_t *lastOffsetp)
{
    uint8_t *buffer                         = NULL;
    ImplementationUseVolumeDescriptor *test = NULL;
    ImplementationUseVolumeDescriptor *ret  = NULL;
    size_t idx                              = *idxp;
    size_t lastOffset                       = *lastOffsetp;

    if (skipEmptyDescriptors(ctx, idxp, lastOffsetp)) {
        goto done;
    }

    idx        = *idxp;
    lastOffset = *lastOffsetp;

    buffer = (uint8_t *)fmap_need_off(ctx->fmap, idx, VOLUME_DESCRIPTOR_SIZE);
    if (NULL == buffer) {
        goto done;
    }
    lastOffset = idx;

    test = (ImplementationUseVolumeDescriptor *)buffer;
    if (IMPLEMENTATION_USE_VOLUME_DESCRIPTOR != test->tag.tagId) {
        goto done;
    }

    ret = test;
    idx += VOLUME_DESCRIPTOR_SIZE;

done:
    *idxp        = idx;
    *lastOffsetp = lastOffset;

    return ret;
}

static LogicalVolumeDescriptor *getLogicalVolumeDescriptor(cli_ctx *ctx, size_t *idxp, size_t *lastOffsetp)
{
    uint8_t *buffer               = NULL;
    LogicalVolumeDescriptor *ret  = NULL;
    LogicalVolumeDescriptor *test = NULL;
    size_t idx                    = *idxp;
    size_t lastOffset             = *lastOffsetp;

    if (skipEmptyDescriptors(ctx, idxp, lastOffsetp)) {
        goto done;
    }

    idx        = *idxp;
    lastOffset = *lastOffsetp;

    buffer = (uint8_t *)fmap_need_off(ctx->fmap, idx, VOLUME_DESCRIPTOR_SIZE);
    if (NULL == buffer) {
        goto done;
    }
    lastOffset = idx;

    test = (LogicalVolumeDescriptor *)buffer;
    if (LOGICAL_VOLUME_DESCRIPTOR != test->tag.tagId) {
        goto done;
    }

    idx += VOLUME_DESCRIPTOR_SIZE;
    ret = test;

done:
    *idxp        = idx;
    *lastOffsetp = lastOffset;

    return ret;
}

static PartitionDescriptor *getPartitionDescriptor(cli_ctx *ctx, size_t *idxp, size_t *lastOffsetp)
{
    uint8_t *buffer           = NULL;
    PartitionDescriptor *ret  = NULL;
    PartitionDescriptor *test = NULL;
    size_t idx                = *idxp;
    size_t lastOffset         = *lastOffsetp;

    if (skipEmptyDescriptors(ctx, idxp, lastOffsetp)) {
        goto done;
    }

    idx        = *idxp;
    lastOffset = *lastOffsetp;

    buffer = (uint8_t *)fmap_need_off(ctx->fmap, idx, VOLUME_DESCRIPTOR_SIZE);
    if (NULL == buffer) {
        goto done;
    }
    lastOffset = idx;

    test = (PartitionDescriptor *)buffer;
    if (PARTITION_DESCRIPTOR != test->tag.tagId) {
        goto done;
    }

    ret = test;
    idx += VOLUME_DESCRIPTOR_SIZE;

done:
    *idxp        = idx;
    *lastOffsetp = lastOffset;

    return ret;
}

static UnallocatedSpaceDescriptor *getUnallocatedSpaceDescriptor(cli_ctx *ctx, size_t *idxp, size_t *lastOffsetp)
{
    uint8_t *buffer                  = NULL;
    UnallocatedSpaceDescriptor *ret  = NULL;
    UnallocatedSpaceDescriptor *test = NULL;
    size_t idx                       = *idxp;
    size_t lastOffset                = *lastOffsetp;

    if (skipEmptyDescriptors(ctx, idxp, lastOffsetp)) {
        goto done;
    }

    idx        = *idxp;
    lastOffset = *lastOffsetp;

    buffer = (uint8_t *)fmap_need_off(ctx->fmap, idx, VOLUME_DESCRIPTOR_SIZE);
    if (NULL == buffer) {
        goto done;
    }
    lastOffset = idx;

    test = (UnallocatedSpaceDescriptor *)buffer;
    if (UNALLOCATED_SPACE_DESCRIPTOR != test->tag.tagId) {
        goto done;
    }

    ret = test;
    idx += VOLUME_DESCRIPTOR_SIZE;

done:
    *idxp        = idx;
    *lastOffsetp = lastOffset;

    return ret;
}

static TerminatingDescriptor *getTerminatingDescriptor(cli_ctx *ctx, size_t *idxp, size_t *lastOffsetp)
{
    uint8_t *buffer             = NULL;
    TerminatingDescriptor *ret  = NULL;
    TerminatingDescriptor *test = NULL;
    size_t idx                  = *idxp;
    size_t lastOffset           = *lastOffsetp;

    if (skipEmptyDescriptors(ctx, idxp, lastOffsetp)) {
        goto done;
    }

    idx        = *idxp;
    lastOffset = *lastOffsetp;

    buffer = (uint8_t *)fmap_need_off(ctx->fmap, idx, VOLUME_DESCRIPTOR_SIZE);
    if (NULL == buffer) {
        goto done;
    }
    lastOffset = idx;

    test = (TerminatingDescriptor *)buffer;
    if (TERMINATING_DESCRIPTOR != test->tag.tagId) {
        goto done;
    }

    ret = test;
    idx += VOLUME_DESCRIPTOR_SIZE;

done:
    *idxp        = idx;
    *lastOffsetp = lastOffset;

    return ret;
}

static LogicalVolumeIntegrityDescriptor *getLogicalVolumeIntegrityDescriptor(cli_ctx *ctx, size_t *idxp, size_t *lastOffsetp)
{
    uint8_t *buffer                        = NULL;
    LogicalVolumeIntegrityDescriptor *ret  = NULL;
    LogicalVolumeIntegrityDescriptor *test = NULL;
    size_t idx                             = *idxp;
    size_t lastOffset                      = *lastOffsetp;

    if (skipEmptyDescriptors(ctx, idxp, lastOffsetp)) {
        goto done;
    }

    idx        = *idxp;
    lastOffset = *lastOffsetp;

    buffer = (uint8_t *)fmap_need_off(ctx->fmap, idx, VOLUME_DESCRIPTOR_SIZE);
    if (NULL == buffer) {
        goto done;
    }
    lastOffset = idx;

    test = (LogicalVolumeIntegrityDescriptor *)buffer;
    if (LOGICAL_VOLUME_INTEGRITY_DESCRIPTOR != test->tag.tagId) {
        goto done;
    }

    ret = test;
    idx += VOLUME_DESCRIPTOR_SIZE;

done:
    *idxp        = idx;
    *lastOffsetp = lastOffset;

    return ret;
}

static AnchorVolumeDescriptorPointer *getAnchorVolumeDescriptorPointer(cli_ctx *ctx, size_t *idxp, size_t *lastOffsetp)
{
    uint8_t *buffer                     = NULL;
    AnchorVolumeDescriptorPointer *ret  = NULL;
    AnchorVolumeDescriptorPointer *test = NULL;
    size_t idx                          = *idxp;
    size_t lastOffset                   = *lastOffsetp;

    if (skipEmptyDescriptors(ctx, idxp, lastOffsetp)) {
        goto done;
    }

    idx        = *idxp;
    lastOffset = *lastOffsetp;

    buffer = (uint8_t *)fmap_need_off(ctx->fmap, idx, VOLUME_DESCRIPTOR_SIZE);
    if (NULL == buffer) {
        goto done;
    }
    lastOffset = idx;

    test = (AnchorVolumeDescriptorPointer *)buffer;
    if (ANCHOR_VOLUME_DESCRIPTOR_DESCRIPTOR_POINTER != test->tag.tagId) {
        goto done;
    }

    ret = test;

    idx += VOLUME_DESCRIPTOR_SIZE;

done:
    *idxp        = idx;
    *lastOffsetp = lastOffset;

    return ret;
}

static FileSetDescriptor *getFileSetDescriptor(cli_ctx *ctx, size_t *idxp, size_t *lastOffsetp)
{
    uint8_t *buffer         = NULL;
    FileSetDescriptor *ret  = NULL;
    FileSetDescriptor *test = NULL;
    size_t idx              = *idxp;
    size_t lastOffset       = *lastOffsetp;

    if (skipEmptyDescriptors(ctx, idxp, lastOffsetp)) {
        goto done;
    }

    idx        = *idxp;
    lastOffset = *lastOffsetp;

    buffer = (uint8_t *)fmap_need_off(ctx->fmap, idx, VOLUME_DESCRIPTOR_SIZE);
    if (NULL == buffer) {
        goto done;
    }
    lastOffset = idx;

    test = (FileSetDescriptor *)buffer;
    if (FILE_SET_DESCRIPTOR != test->tag.tagId) {
        goto done;
    }

    ret = test;
    idx += VOLUME_DESCRIPTOR_SIZE;

done:
    *idxp        = idx;
    *lastOffsetp = lastOffset;

    return ret;
}

typedef struct {

    const uint8_t **idxs;

    uint32_t cnt;

    uint32_t capacity;

} PointerList;
#define POINTER_LIST_INCREMENT 1024

static void freePointerList(PointerList *pl)
{
    FREE(pl->idxs);
    memset(pl, 0, sizeof(PointerList));
}

static cl_error_t initPointerList(PointerList *pl)
{
    cl_error_t ret    = CL_SUCCESS;
    uint32_t capacity = POINTER_LIST_INCREMENT;

    freePointerList(pl);
    CLI_CALLOC(pl->idxs, capacity, sizeof(uint8_t *),
               cli_errmsg("initPointerList: Can't allocate memory\n");
               ret = CL_EMEM);

    pl->capacity = capacity;
done:
    return ret;
}

static cl_error_t insertPointer(PointerList *pl, const uint8_t *pointer)
{
    cl_error_t ret = CL_SUCCESS;

    if (pl->cnt == (pl->capacity - 1)) {
        uint32_t newCapacity = pl->capacity + POINTER_LIST_INCREMENT;
        CLI_REALLOC(pl->idxs, newCapacity * sizeof(uint8_t *),
                    cli_errmsg("insertPointer: Can't allocate memory\n");
                    ret = CL_EMEM);

        pl->capacity = newCapacity;
    }

    pl->idxs[pl->cnt++] = pointer;

done:
    return ret;
}

static cl_error_t findFileIdentifiers(const uint8_t *const input, PointerList *pfil)
{

    cl_error_t ret        = CL_SUCCESS;
    const uint8_t *buffer = input;
    uint16_t tagId        = getDescriptorTagId(buffer);

    while (257 == tagId) {
        if (CL_SUCCESS != (ret = insertPointer(pfil, buffer))) {
            goto done;
        }

        buffer = buffer + getFileIdentifierDescriptorSize((FileIdentifierDescriptor *)buffer);
        tagId  = getDescriptorTagId(buffer);
    }

done:
    return ret;
}

static cl_error_t findFileEntries(const uint8_t *const input, PointerList *pfil)
{

    cl_error_t ret        = CL_SUCCESS;
    const uint8_t *buffer = input;
    uint16_t tagId        = getDescriptorTagId(buffer);

    while (261 == tagId) {
        if (CL_SUCCESS != (ret = insertPointer(pfil, buffer))) {
            goto done;
        }

        buffer = buffer + getFileEntryDescriptorSize((FileEntryDescriptor *)buffer);
        tagId  = getDescriptorTagId(buffer);
    }

done:
    return ret;
}

cl_error_t parseBEA01(cli_ctx *ctx, const size_t offset)
{
    cl_error_t ret                          = CL_SUCCESS;
    size_t idx                              = offset;
    size_t lastOffset                       = 0;
    size_t i                                = 0;
    uint8_t *buffer                         = NULL;
    PrimaryVolumeDescriptor *pvd            = NULL;
    GenericVolumeStructureDescriptor *gvsd  = NULL;
    ImplementationUseVolumeDescriptor *iuvd = NULL;
    LogicalVolumeDescriptor *lvd            = NULL;
    PartitionDescriptor *pd                 = NULL;
    UnallocatedSpaceDescriptor *usd         = NULL;
    TerminatingDescriptor *td               = NULL;
    LogicalVolumeIntegrityDescriptor *lvid  = NULL;
    AnchorVolumeDescriptorPointer *avdp     = NULL;

    bool isInitialized = false;
    PointerList fileIdentifierList;
    PointerList fileEntryList;

    if (offset < 32768) {
        return CL_SUCCESS; /* Need 16 sectors at least 2048 bytes long */
    }

    buffer = (uint8_t *)fmap_need_off(ctx->fmap, idx, NUM_GENERIC_VOLUME_DESCRIPTORS * VOLUME_DESCRIPTOR_SIZE);
    if (NULL == buffer) {
        ret = CL_SUCCESS;
        goto done;
    }

    /*There seem to always be 3 of these.
     * TODO: Maybe still just keep going until 
     *
     * The format matters depending on the standard identifier.
     */
    for (i = 0; i < NUM_GENERIC_VOLUME_DESCRIPTORS; i++) {
        gvsd       = (GenericVolumeStructureDescriptor *)fmap_need_off(ctx->fmap, idx, VOLUME_DESCRIPTOR_SIZE);
        lastOffset = idx;

        if (strncmp("BEA01", gvsd->standardIdentifier, 5)) {
        } else if (strncmp("BOOT2", gvsd->standardIdentifier, 5)) {
        } else if (strncmp("CD001", gvsd->standardIdentifier, 5)) {
        } else if (strncmp("CDW02", gvsd->standardIdentifier, 5)) {
        } else if (strncmp("NSR02", gvsd->standardIdentifier, 5)) {
        } else if (strncmp("NSR03", gvsd->standardIdentifier, 5)) {
        } else if (strncmp("TEA01", gvsd->standardIdentifier, 5)) {
        } else {
            cli_warnmsg("Unknown Standard Identifier '%s'\n", gvsd->standardIdentifier);
            break;
        }

        idx += VOLUME_DESCRIPTOR_SIZE;
    }

    memset(&fileIdentifierList, 0, sizeof(PointerList));
    memset(&fileEntryList, 0, sizeof(PointerList));

    while (1) {

        if (!isInitialized) {

            if (CL_SUCCESS != (ret = initPointerList(&fileIdentifierList))) {
                goto done;
            }

            if (CL_SUCCESS != (ret = initPointerList(&fileEntryList))) {
                goto done;
            }

            if (NULL == (pvd = getPrimaryVolumeDescriptor(ctx, &idx, &lastOffset))) {
                goto done;
            }

            if (NULL == (iuvd = getImplementationUseVolumeDescriptor(ctx, &idx, &lastOffset))) {
                goto done;
            }

            if (NULL == (lvd = getLogicalVolumeDescriptor(ctx, &idx, &lastOffset))) {
                goto done;
            }

            if (NULL == (pd = getPartitionDescriptor(ctx, &idx, &lastOffset))) {
                goto done;
            }

            if (NULL == (usd = getUnallocatedSpaceDescriptor(ctx, &idx, &lastOffset))) {
                goto done;
            }

            if (NULL == (td = getTerminatingDescriptor(ctx, &idx, &lastOffset))) {
                goto done;
            }

            /*May not be every file, need to verify.*/
            if (NULL == (lvid = getLogicalVolumeIntegrityDescriptor(ctx, &idx, &lastOffset))) {
                goto done;
            }

            if (NULL == (td = getTerminatingDescriptor(ctx, &idx, &lastOffset))) {
                goto done;
            }

            if (NULL == (avdp = getAnchorVolumeDescriptorPointer(ctx, &idx, &lastOffset))) {
                goto done;
            }

            if (NULL == getFileSetDescriptor(ctx, &idx, &lastOffset)) {
                goto done;
            }

            isInitialized = true;
        }

        buffer = (uint8_t *)fmap_need_off(ctx->fmap, idx, VOLUME_DESCRIPTOR_SIZE);
        if (NULL == buffer) {
            goto done;
        }
        lastOffset = idx;

        uint16_t tagId = getDescriptorTagId(buffer);
        if (tagId) {
            switch (tagId) {
                case 257:

                    findFileIdentifiers(buffer, &fileIdentifierList);
                    break;

                case 261:

                    findFileEntries(buffer, &fileEntryList);
                    break;
                case 8:
                    break;

                default: {
                    /*Dump all the files here.*/
                    size_t i;
                    size_t cnt = fileIdentifierList.cnt;

                    /*The number of file entries should match the number of file identifiers, but in the 
                         * case that the file is malformed, we are going to do the best we can to extract as much as we can.
                         */
                    if (fileEntryList.cnt < cnt) {
                        cnt = fileEntryList.cnt;
                    }

                    for (i = 0; i < cnt; i++) {
                        if (parseFileEntryDescriptor(ctx,
                                                     (const uint8_t *const)fileEntryList.idxs[i],
                                                     pd, lvd, (FileIdentifierDescriptor *)fileIdentifierList.idxs[i])) {
                            goto done;
                        }
                    }

                    /* Start looking for the next volume */
                    isInitialized = false;
                    break;
                }
            }
        }

        idx += VOLUME_DESCRIPTOR_SIZE;
    }

done:
    freePointerList(&fileIdentifierList);
    freePointerList(&fileEntryList);

    for (idx = offset; idx <= lastOffset; idx += VOLUME_DESCRIPTOR_SIZE) {
        fmap_unneed_off(ctx->fmap, idx, VOLUME_DESCRIPTOR_SIZE);
    }

    return ret;
}

#if 0
/*Used for debugging.*/
static void dumpAllTags(cli_ctx *ctx, size_t offset){
    uint8_t * buffer;
    size_t lastOffset, startoffset = offset;
    size_t i;

    while (1){
        buffer = (uint8_t*) fmap_need_off(ctx->fmap, offset, VOLUME_DESCRIPTOR_SIZE);
        if (NULL == buffer){
            break;
        }
        lastOffset = offset;

        uint16_t tagId = getDescriptorTagId(buffer);
        if (tagId){

            fprintf(stderr, "%s::%d::%lx::tagId = %d (0x%x)\n", __FUNCTION__, __LINE__, offset, tagId, tagId);
        }

        offset += VOLUME_DESCRIPTOR_SIZE;
    }

    for (i = startoffset; i <= lastOffset; i+= VOLUME_DESCRIPTOR_SIZE){
        fmap_unneed_off(ctx->fmap, i, VOLUME_DESCRIPTOR_SIZE);
    }
}
#endif

cl_error_t cli_scaniso(cli_ctx *ctx, size_t offset)
{
    const uint8_t *privol, *next;
    iso9660_t iso;
    int i;

    if (offset < 32768)
        return CL_SUCCESS; /* Need 16 sectors at least 2048 bytes long */

    privol = fmap_need_off(ctx->fmap, offset, 2448 + 6);
    if (!privol)
        return CL_SUCCESS;

    next = (uint8_t *)cli_memstr((char *)privol + 2049, 2448 + 6 - 2049, "CD001", 5);
    if (!next) {
        return parseBEA01(ctx, offset);
    }

    iso.sectsz = (next - privol) - 1;
    if (iso.sectsz * 16 > offset)
        return CL_SUCCESS; /* Need room for 16 system sectors */

    iso.blocksz = cli_readint32(privol + 128) & 0xffff;
    if (iso.blocksz != 512 && iso.blocksz != 1024 && iso.blocksz != 2048)
        return CL_SUCCESS; /* Likely not a cdrom image */

    iso.base_offset = offset - iso.sectsz * 16;
    iso.joliet      = 0;

    for (i = 16; i < 32; i++) { /* scan for a joliet secondary volume descriptor */
        next = fmap_need_off_once(ctx->fmap, iso.base_offset + i * iso.sectsz, 2048);
        if (!next)
            break; /* Out of disk */
        if (*next == 0xff || memcmp(next + 1, "CD001", 5))
            break; /* Not a volume descriptor */
        if (*next != 2)
            continue; /* Not a secondary volume descriptor */
        if (next[88] != 0x25 || next[89] != 0x2f)
            continue; /* Not a joliet descriptor */
        if (next[156 + 26] || next[156 + 27])
            continue; /* Root is interleaved so we fallback to the primary descriptor */
        switch (next[90]) {
            case 0x40: /* Level 1 */
                iso.joliet = 1;
                break;
            case 0x43: /* Level 2 */
                iso.joliet = 2;
                break;
            case 0x45: /* Level 3 */
                iso.joliet = 3;
                break;
            default: /* Not Joliet */
                continue;
        }
        break;
    }

    /* TODO rr, el torito, udf ? */

    /* NOTE: freeing sector now. it is still safe to access as we don't alloc anymore */
    fmap_unneed_off(ctx->fmap, offset, 2448);
    if (iso.joliet)
        privol = next;

    cli_dbgmsg("in cli_scaniso\n");
    if (cli_debug_flag) {
        cli_dbgmsg("cli_scaniso: Raw sector size: %u\n", iso.sectsz);
        cli_dbgmsg("cli_scaniso: Block size: %u\n", iso.blocksz);

        cli_dbgmsg("cli_scaniso: Volume descriptor version: %u\n", privol[6]);

#define ISOSTRING(src, len) iso_string(&iso, (src), (len))
        cli_dbgmsg("cli_scaniso: System: %s\n", ISOSTRING(privol + 8, 32));
        cli_dbgmsg("cli_scaniso: Volume: %s\n", ISOSTRING(privol + 40, 32));

        cli_dbgmsg("cli_scaniso: Volume space size: 0x%x blocks\n", cli_readint32(&privol[80]));
        cli_dbgmsg("cli_scaniso: Volume %u of %u\n", cli_readint32(privol + 124) & 0xffff, cli_readint32(privol + 120) & 0xffff);

        cli_dbgmsg("cli_scaniso: Volume Set: %s\n", ISOSTRING(privol + 190, 128));
        cli_dbgmsg("cli_scaniso: Publisher: %s\n", ISOSTRING(privol + 318, 128));
        cli_dbgmsg("cli_scaniso: Data Preparer: %s\n", ISOSTRING(privol + 446, 128));
        cli_dbgmsg("cli_scaniso: Application: %s\n", ISOSTRING(privol + 574, 128));

#define ISOTIME(s, n) cli_dbgmsg("cli_scaniso: "s                         \
                                 ": %c%c%c%c-%c%c-%c%c %c%c:%c%c:%c%c\n", \
                                 privol[n], privol[n + 1], privol[n + 2], privol[n + 3], privol[n + 4], privol[n + 5], privol[n + 6], privol[n + 7], privol[n + 8], privol[n + 9], privol[n + 10], privol[n + 11], privol[n + 12], privol[n + 13])
        ISOTIME("Volume creation time", 813);
        ISOTIME("Volume modification time", 830);
        ISOTIME("Volume expiration time", 847);
        ISOTIME("Volume effective time", 864);

        cli_dbgmsg("cli_scaniso: Path table size: 0x%x\n", cli_readint32(privol + 132) & 0xffff);
        cli_dbgmsg("cli_scaniso: LSB Path Table: 0x%x\n", cli_readint32(privol + 140));
        cli_dbgmsg("cli_scaniso: Opt LSB Path Table: 0x%x\n", cli_readint32(privol + 144));
        cli_dbgmsg("cli_scaniso: MSB Path Table: 0x%x\n", cbswap32(cli_readint32(privol + 148)));
        cli_dbgmsg("cli_scaniso: Opt MSB Path Table: 0x%x\n", cbswap32(cli_readint32(privol + 152)));
        cli_dbgmsg("cli_scaniso: File Structure Version: %u\n", privol[881]);

        if (iso.joliet)
            cli_dbgmsg("cli_scaniso: Joliet level %u\n", iso.joliet);
    }

    if (privol[156 + 26] || privol[156 + 27]) {
        cli_dbgmsg("cli_scaniso: Interleaved root directory is not supported\n");
        return CL_SUCCESS;
    }

    iso.ctx = ctx;
    i       = cli_hashset_init(&iso.dir_blocks, 1024, 80);
    if (i != CL_SUCCESS)
        return i;
    i = iso_parse_dir(&iso, cli_readint32(privol + 156 + 2) + privol[156 + 1], cli_readint32(privol + 156 + 10));
    cli_hashset_destroy(&iso.dir_blocks);
    if (i == CL_BREAK)
        return CL_SUCCESS;
    return i;
}

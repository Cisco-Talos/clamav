/*
 *  Copyright (C) 2023-2024 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *
 *  Author: Andy Ragusa
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
#include "udf.h"
#include "fmap.h"
#include "str.h"
#include "entconv.h"
#include "hashtab.h"

typedef enum {
    PRIMARY_VOLUME_DESCRIPTOR                   = 1,
    IMPLEMENTATION_USE_VOLUME_DESCRIPTOR        = 4,
    LOGICAL_VOLUME_DESCRIPTOR                   = 6,
    PARTITION_DESCRIPTOR                        = 5,
    UNALLOCATED_SPACE_DESCRIPTOR                = 7,
    TERMINATING_DESCRIPTOR                      = 8,
    LOGICAL_VOLUME_INTEGRITY_DESCRIPTOR         = 9,
    ANCHOR_VOLUME_DESCRIPTOR_DESCRIPTOR_POINTER = 2

    ,
    FILE_SET_DESCRIPTOR        = 256,
    FILE_IDENTIFIER_DESCRIPTOR = 257,
    FILE_ENTRY_DESCRIPTOR      = 261
} VOLUME_DESCRIPTOR_TAG;

static uint16_t getDescriptorTagId(const uint8_t *const buffer)
{
    return le16_to_host(((DescriptorTag *)buffer)->tagId);
}

static bool isDirectory(FileIdentifierDescriptor *fid)
{
    return (0 != (fid->characteristics & 2));
}

static cl_error_t writeWholeFile(cli_ctx *ctx, const char *const fileName, const uint8_t *const data, const size_t dataLen)
{

    int fd     = -1;
    char *tmpf = NULL;

    cl_error_t status = CL_ETMPFILE;

    if (0 == dataLen || NULL == data) {
        cli_warnmsg("writeWholeFile: Invalid arguments\n");
        status = CL_EARG;
        goto done;
    }

    /* Not sure if I care about the name that is actually created. */
    if (cli_gentempfd_with_prefix(ctx->sub_tmpdir, fileName, &tmpf, &fd) != CL_SUCCESS) {
        cli_warnmsg("writeWholeFile: Can't create temp file\n");
        status = CL_ETMPFILE;
        goto done;
    }

    if (cli_writen(fd, data, dataLen) != dataLen) {
        cli_warnmsg("writeWholeFile: Can't write to file %s\n", tmpf);
        status = CL_EWRITE;
        goto done;
    }

    status = cli_magic_scan_desc(fd, tmpf, ctx, fileName, LAYER_ATTRIBUTES_NONE);

done:
    if (-1 != fd) {
        close(fd);
        fd = -1;
    }
    if (!ctx->engine->keeptmp) {
        if (NULL != tmpf) {
            if (cli_unlink(tmpf)) {
                /* If status is already set to virus or something, that should take priority of the
                 * error unlinking the file. */
                if (CL_CLEAN == status) {
                    status = CL_EUNLINK;
                }
            }
        }
    }

    CLI_FREE_AND_SET_NULL(tmpf);

    return status;
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
            // impossible unless the file is malformed.
            cli_warnmsg("extractFile: Unknown descriptor type found.\n");
            goto done;
    }

    contents = (uint8_t *)fmap_need_off(ctx->fmap, offset, length);
    if (NULL == contents) {
        cli_warnmsg("extractFile: Unable to get offset referenced in the file.\n");
        goto done;
    }

    ret = writeWholeFile(ctx, "", contents, length);

    fmap_unneed_off(ctx->fmap, offset, length);

done:

    return ret;
}

static bool parseFileEntryDescriptor(cli_ctx *ctx, const uint8_t *const data, PartitionDescriptor *pPartitionDescriptor, LogicalVolumeDescriptor *pLogicalVolumeDescriptor, FileIdentifierDescriptor *fileIdentifierDescriptor)
{

    FileEntryDescriptor *fed = (FileEntryDescriptor *)data;
    bool ret                 = false;

    if (FILE_ENTRY_DESCRIPTOR != fed->tag.tagId) {
        cli_warnmsg("parseFileEntryDescriptor: Tag ID of 0x%x does not match File Entry Descriptor.\n", fed->tag.tagId);
        goto done;
    }

    if (FILE_IDENTIFIER_DESCRIPTOR != fileIdentifierDescriptor->tag.tagId) {
        cli_warnmsg("parseFileEntryDescriptor: Tag ID of 0x%x does not match File Identifier Descriptor.\n", fed->tag.tagId);
        goto done;
    }

    if (CL_SUCCESS != extractFile(ctx, pPartitionDescriptor, pLogicalVolumeDescriptor,
                                  (void *)&(data[getFileEntryDescriptorSize(fed) - fed->allocationDescLen]),
                                  fed->icbTag.flags, fileIdentifierDescriptor)) {
        ret = false;
        goto done;
    }

    ret = true;
done:
    return ret;
}

/*
// Uncomment for debugging.
static void dumpTag (DescriptorTag *dt)
{
    fprintf(stderr, "TagId = %d (0x%x)\n", dt->tagId, dt->tagId);
    fprintf(stderr, "Version = %d (0x%x)\n", dt->descriptorVersion, dt->descriptorVersion);
    fprintf(stderr, "Checksum = %d (0x%x)\n", dt->checksum, dt->checksum);
    fprintf(stderr, "Serial Number = %d (0x%x)\n", dt->serialNumber, dt->serialNumber);

    fprintf(stderr, "Descriptor CRC = %d (0x%x)\n", dt->descriptorCRC, dt->descriptorCRC);
    fprintf(stderr, "Descriptor CRC Length = %d (0x%x)\n", dt->descriptorCRCLength, dt->descriptorCRCLength);
    fprintf(stderr, "Tag Location = %d (0x%x)\n", dt->tagLocation, dt->tagLocation);
}
*/

typedef struct {
    uint8_t structType;
    char standardIdentifier[5];
    uint8_t structVersion;
    uint8_t rest[2041];
} GenericVolumeStructureDescriptor;
#define NUM_GENERIC_VOLUME_DESCRIPTORS 3

/* If this function fails, idx will not be updated */
static bool skipEmptyDescriptors(cli_ctx *ctx, size_t *idxp, size_t *lastOffsetp)
{
    bool ret        = false;
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

    ret = true;
done:

    *idxp        = idx;
    *lastOffsetp = idx;

    return ret;
}

/* Skip past all the empty descriptors and find the PrimaryVolumeDescriptor.
 * Return error if the next non-empty descriptor is not a PrimaryVolumeDescriptor. */
static PrimaryVolumeDescriptor *getPrimaryVolumeDescriptor(cli_ctx *ctx, size_t *idxp, size_t *lastOffsetp)
{
    uint8_t *buffer               = NULL;
    PrimaryVolumeDescriptor *test = NULL;
    PrimaryVolumeDescriptor *ret  = NULL;
    size_t idx                    = *idxp;
    size_t lastOffset             = *lastOffsetp;

    if (!skipEmptyDescriptors(ctx, idxp, lastOffsetp)) {
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

/* Skip past all the empty descriptors and find the ImplementationUseVolumeDescriptor.
 * Return error if the next non-empty descriptor is not an ImplementationUseVolumeDescriptor. */
static ImplementationUseVolumeDescriptor *getImplementationUseVolumeDescriptor(cli_ctx *ctx, size_t *idxp, size_t *lastOffsetp)
{
    uint8_t *buffer                         = NULL;
    ImplementationUseVolumeDescriptor *test = NULL;
    ImplementationUseVolumeDescriptor *ret  = NULL;
    size_t idx                              = *idxp;
    size_t lastOffset                       = *lastOffsetp;

    if (!skipEmptyDescriptors(ctx, idxp, lastOffsetp)) {
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

/* Skip past all the empty descriptors and find the LogicalVolumeDescriptor.
 * Return error if the next non-empty descriptor is not a LogicalVolumeDescriptor. */
static LogicalVolumeDescriptor *getLogicalVolumeDescriptor(cli_ctx *ctx, size_t *idxp, size_t *lastOffsetp)
{
    uint8_t *buffer               = NULL;
    LogicalVolumeDescriptor *ret  = NULL;
    LogicalVolumeDescriptor *test = NULL;
    size_t idx                    = *idxp;
    size_t lastOffset             = *lastOffsetp;

    if (!skipEmptyDescriptors(ctx, idxp, lastOffsetp)) {
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

/* Skip past all the empty descriptors and find the PartitionDescriptor.
 * Return error if the next non-empty descriptor is not a PartitionDescriptor. */
static PartitionDescriptor *getPartitionDescriptor(cli_ctx *ctx, size_t *idxp, size_t *lastOffsetp)
{
    uint8_t *buffer           = NULL;
    PartitionDescriptor *ret  = NULL;
    PartitionDescriptor *test = NULL;
    size_t idx                = *idxp;
    size_t lastOffset         = *lastOffsetp;

    if (!skipEmptyDescriptors(ctx, idxp, lastOffsetp)) {
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

/* Skip past all the empty descriptors and find the UnallocatedSpaceDescriptor.
 * Return error if the next non-empty descriptor is not a UnallocatedSpaceDescriptor. */
static UnallocatedSpaceDescriptor *getUnallocatedSpaceDescriptor(cli_ctx *ctx, size_t *idxp, size_t *lastOffsetp)
{
    uint8_t *buffer                  = NULL;
    UnallocatedSpaceDescriptor *ret  = NULL;
    UnallocatedSpaceDescriptor *test = NULL;
    size_t idx                       = *idxp;
    size_t lastOffset                = *lastOffsetp;

    if (!skipEmptyDescriptors(ctx, idxp, lastOffsetp)) {
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

/* Skip past all the empty descriptors and find the TerminatingDescriptor.
 * Return error if the next non-empty descriptor is not a TerminatingDescriptor. */
static TerminatingDescriptor *getTerminatingDescriptor(cli_ctx *ctx, size_t *idxp, size_t *lastOffsetp)
{
    uint8_t *buffer             = NULL;
    TerminatingDescriptor *ret  = NULL;
    TerminatingDescriptor *test = NULL;
    size_t idx                  = *idxp;
    size_t lastOffset           = *lastOffsetp;

    if (!skipEmptyDescriptors(ctx, idxp, lastOffsetp)) {
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

/* Skip past all the empty descriptors and find the LogicalVolumeIntegrityDescriptor.
 * Return error if the next non-empty descriptor is not a LogicalVolumeIntegrityDescriptor. */
static LogicalVolumeIntegrityDescriptor *getLogicalVolumeIntegrityDescriptor(cli_ctx *ctx, size_t *idxp, size_t *lastOffsetp)
{
    uint8_t *buffer                        = NULL;
    LogicalVolumeIntegrityDescriptor *ret  = NULL;
    LogicalVolumeIntegrityDescriptor *test = NULL;
    size_t idx                             = *idxp;
    size_t lastOffset                      = *lastOffsetp;

    if (!skipEmptyDescriptors(ctx, idxp, lastOffsetp)) {
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

/* Skip past all the empty descriptors and find the AnchorVolumeDescriptor.
 * Return error if the next non-empty descriptor is not an AnchorVolumeDescriptor. */
static AnchorVolumeDescriptorPointer *getAnchorVolumeDescriptorPointer(cli_ctx *ctx, size_t *idxp, size_t *lastOffsetp)
{
    uint8_t *buffer                     = NULL;
    AnchorVolumeDescriptorPointer *ret  = NULL;
    AnchorVolumeDescriptorPointer *test = NULL;
    size_t idx                          = *idxp;
    size_t lastOffset                   = *lastOffsetp;

    if (!skipEmptyDescriptors(ctx, idxp, lastOffsetp)) {
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

/* Skip past all the empty descriptors and find the FileSetDescriptor.
 * Return error if the next non-empty descriptor is not a FileSetDescriptor. */
static FileSetDescriptor *getFileSetDescriptor(cli_ctx *ctx, size_t *idxp, size_t *lastOffsetp)
{
    uint8_t *buffer         = NULL;
    FileSetDescriptor *ret  = NULL;
    FileSetDescriptor *test = NULL;
    size_t idx              = *idxp;
    size_t lastOffset       = *lastOffsetp;

    if (!skipEmptyDescriptors(ctx, idxp, lastOffsetp)) {
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
    CLI_FREE_AND_SET_NULL(pl->idxs);
    memset(pl, 0, sizeof(PointerList));
}

static cl_error_t initPointerList(PointerList *pl)
{
    cl_error_t ret    = CL_SUCCESS;
    uint32_t capacity = POINTER_LIST_INCREMENT;

    freePointerList(pl);
    CLI_CALLOC_OR_GOTO_DONE(pl->idxs, capacity, sizeof(uint8_t *),
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
        CLI_SAFER_REALLOC_OR_GOTO_DONE(pl->idxs, newCapacity * sizeof(uint8_t *),
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

    while (FILE_IDENTIFIER_DESCRIPTOR == tagId) {
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

    while (FILE_ENTRY_DESCRIPTOR == tagId) {
        if (CL_SUCCESS != (ret = insertPointer(pfil, buffer))) {
            goto done;
        }

        buffer = buffer + getFileEntryDescriptorSize((FileEntryDescriptor *)buffer);
        tagId  = getDescriptorTagId(buffer);
    }

done:
    return ret;
}

cl_error_t cli_scanudf(cli_ctx *ctx, const size_t offset)
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

    bool isInitialized             = false;
    PointerList fileIdentifierList = {0};
    PointerList fileEntryList      = {0};

    if (offset < 32768) {
        return CL_SUCCESS; /* Need 16 sectors at least 2048 bytes long */
    }

    buffer = (uint8_t *)fmap_need_off(ctx->fmap, idx, NUM_GENERIC_VOLUME_DESCRIPTORS * VOLUME_DESCRIPTOR_SIZE);
    if (NULL == buffer) {
        ret = CL_SUCCESS;
        goto done;
    }

    for (i = 0; i < NUM_GENERIC_VOLUME_DESCRIPTORS; i++) {
        gvsd       = (GenericVolumeStructureDescriptor *)fmap_need_off(ctx->fmap, idx, VOLUME_DESCRIPTOR_SIZE);
        lastOffset = idx;

        if (strncmp("BEA01", gvsd->standardIdentifier, 5)) {
            cli_dbgmsg("Found Standard Identifier '%s'\n", "BEA01");
        } else if (strncmp("BOOT2", gvsd->standardIdentifier, 5)) {
            cli_dbgmsg("Found Standard Identifier '%s'\n", "BOOT2");
        } else if (strncmp("CD001", gvsd->standardIdentifier, 5)) {
            cli_dbgmsg("Found Standard Identifier '%s'\n", "CD001");
        } else if (strncmp("CDW02", gvsd->standardIdentifier, 5)) {
            cli_dbgmsg("Found Standard Identifier '%s'\n", "CDW02");
        } else if (strncmp("NSR02", gvsd->standardIdentifier, 5)) {
            cli_dbgmsg("Found Standard Identifier '%s'\n", "NSR02");
        } else if (strncmp("NSR03", gvsd->standardIdentifier, 5)) {
            cli_dbgmsg("Found Standard Identifier '%s'\n", "NSR03");
        } else if (strncmp("TEA01", gvsd->standardIdentifier, 5)) {
            cli_dbgmsg("Found Standard Identifier '%s'\n", "TEA01");
        } else {
            cli_dbgmsg("Unknown Standard Identifier '%s'\n", gvsd->standardIdentifier);
            break;
        }

        idx += VOLUME_DESCRIPTOR_SIZE;
    }

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

            /* May not be every file, need to verify. */
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
                /*We don't actually use the FileSetDescriptor, but verify it is there because
                 * that is part of a properly formatted udf file.*/
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
                case FILE_IDENTIFIER_DESCRIPTOR: {
                    cl_error_t temp = findFileIdentifiers(buffer, &fileIdentifierList);
                    if (CL_SUCCESS != temp) {
                        ret = temp;
                        goto done;
                    }
                    break;
                }

                case FILE_ENTRY_DESCRIPTOR: {
                    cl_error_t temp = findFileEntries(buffer, &fileEntryList);
                    if (CL_SUCCESS != temp) {
                        ret = temp;
                        goto done;
                    }
                    break;
                }

                case TERMINATING_DESCRIPTOR:
                    break;

                default: {
                    /* Dump all the files here. */
                    size_t i;
                    size_t cnt = fileIdentifierList.cnt;

                    /* The number of file entries should match the number of file identifiers, but in the
                     * case that the file is malformed, we are going to do the best we can to extract as much as we can.
                     */
                    if (fileEntryList.cnt < cnt) {
                        cnt = fileEntryList.cnt;
                    }

                    for (i = 0; i < cnt; i++) {
                        if (!parseFileEntryDescriptor(ctx,
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

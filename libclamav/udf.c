/*
 *  Copyright (C) 2023-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
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
    INVALID_DESCRIPTOR                          = 0,
    PRIMARY_VOLUME_DESCRIPTOR                   = 1,
    IMPLEMENTATION_USE_VOLUME_DESCRIPTOR        = 4,
    LOGICAL_VOLUME_DESCRIPTOR                   = 6,
    PARTITION_DESCRIPTOR                        = 5,
    UNALLOCATED_SPACE_DESCRIPTOR                = 7,
    TERMINATING_DESCRIPTOR                      = 8,
    LOGICAL_VOLUME_INTEGRITY_DESCRIPTOR         = 9,
    ANCHOR_VOLUME_DESCRIPTOR_DESCRIPTOR_POINTER = 2,
    FILE_SET_DESCRIPTOR                         = 256,
    FILE_IDENTIFIER_DESCRIPTOR                  = 257,
    FILE_ENTRY_DESCRIPTOR                       = 261,
    EXTENDED_FILE_ENTRY_DESCRIPTOR              = 266
} tag_identifier;

static tag_identifier getDescriptorTagId(DescriptorTag *tag)
{
    return le16_to_host(tag->tagId);
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
    if (cli_gentempfd_with_prefix(ctx->this_layer_tmpdir, fileName, &tmpf, &fd) != CL_SUCCESS) {
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

static cl_error_t extractFile(cli_ctx *ctx, PartitionDescriptor *pPartitionDescriptor, LogicalVolumeDescriptor *pLogicalVolumeDescriptor,
                              void *allocation_descriptor,
                              size_t allocation_descriptor_len,
                              uint16_t icbFlags, FileIdentifierDescriptor *fileIdentifierDescriptor)
{
    cl_error_t ret                     = CL_EPARSE;
    uint32_t offset                    = 0;
    uint32_t length                    = 0;
    uint8_t *contents                  = NULL;
    uint32_t partitionStartingLocation = le32_to_host(pPartitionDescriptor->partitionStartingLocation);
    uint32_t logicalBlockSize          = le32_to_host(pLogicalVolumeDescriptor->logicalBlockSize);

    if (isDirectory(fileIdentifierDescriptor)) {
        cli_dbgmsg("extractFile: Skipping directory\n");
        ret = CL_SUCCESS;
        goto done;
    }

    switch (icbFlags & 3) {
        case 0: {
            if (sizeof(short_ad) != allocation_descriptor_len) {
                cli_warnmsg("extractFile: Short Allocation Descriptor length is incorrect.\n");
                goto done;
            }

            short_ad *shortDesc = (short_ad *)allocation_descriptor;

            offset = partitionStartingLocation * logicalBlockSize;
            offset += le32_to_host(shortDesc->position) * logicalBlockSize;

            length = le32_to_host(shortDesc->length);

        } break;
        case 1: {
            if (sizeof(long_ad) != allocation_descriptor_len) {
                cli_warnmsg("extractFile: Long Allocation Descriptor length is incorrect.\n");
                goto done;
            }

            long_ad *longDesc = (long_ad *)allocation_descriptor;

            offset = partitionStartingLocation * logicalBlockSize;
            length = le32_to_host(longDesc->length);

            if (le16_to_host(longDesc->extentLocation.partitionReferenceNumber) != le16_to_host(pPartitionDescriptor->partitionNumber)) {
                cli_warnmsg("extractFile: Unable to extract the files because the Partition Descriptor Reference Numbers don't match\n");
                goto done;
            }
            offset += le32_to_host(longDesc->extentLocation.blockNumber) * logicalBlockSize;
            offset += partitionStartingLocation;

        } break;
        case 2: {
            if (sizeof(ext_ad) != allocation_descriptor_len) {
                cli_warnmsg("extractFile: Extended Allocation Descriptor length is incorrect.\n");
                goto done;
            }

            ext_ad *extDesc = (ext_ad *)allocation_descriptor;

            offset = partitionStartingLocation * logicalBlockSize;
            length = le32_to_host(extDesc->recordedLen);

            if (le16_to_host(extDesc->extentLocation.partitionReferenceNumber) != le16_to_host(pPartitionDescriptor->partitionNumber)) {
                cli_warnmsg("extractFile: Unable to extract the files because the Partition Descriptor Reference Numbers don't match\n");
                goto done;
            }
            offset += le32_to_host(extDesc->extentLocation.blockNumber) * logicalBlockSize;
            offset += partitionStartingLocation;
        } break;
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

static bool parseFileEntryDescriptor(cli_ctx *ctx, FileEntryDescriptor *fed, PartitionDescriptor *pPartitionDescriptor, LogicalVolumeDescriptor *pLogicalVolumeDescriptor, FileIdentifierDescriptor *fileIdentifierDescriptor)
{
    bool ret                    = false;
    uint16_t tagId              = getDescriptorTagId(&fed->tag);
    void *allocation_descriptor = NULL;

    size_t file_entry_descriptor_size;
    size_t allocation_descriptor_len;

    if (FILE_ENTRY_DESCRIPTOR != tagId) {
        cli_warnmsg("parseFileEntryDescriptor: Tag ID of 0x%x does not match File Entry Descriptor.\n", tagId);
        goto done;
    }

    tagId = getDescriptorTagId(&fileIdentifierDescriptor->tag);
    if (FILE_IDENTIFIER_DESCRIPTOR != tagId) {
        cli_warnmsg("parseFileEntryDescriptor: Tag ID of 0x%x does not match File Identifier Descriptor.\n", tagId);
        goto done;
    }

    // Calculate pointer for the allocation descriptor.
    // The allocation descriptors are the last bytes of the Extended File Entry.
    // See Section 14.17 in https://www.ecma-international.org/wp-content/uploads/ECMA-167_3rd_edition_june_1997.pdf
    file_entry_descriptor_size = getFileEntryDescriptorSize(fed);
    allocation_descriptor_len  = le32_to_host(fed->allocationDescLen);

    if (allocation_descriptor_len > file_entry_descriptor_size) {
        cli_dbgmsg("parseFileEntryDescriptor: Allocation Descriptor Length is greater than the File Entry Descriptor Size.\n");
        goto done;
    }
    allocation_descriptor = (void *)((uint8_t *)fed + (file_entry_descriptor_size - allocation_descriptor_len));

    // The Allocation Descriptor was taken from the end of the  File Entry Descriptor.
    // We already verified that the File Entry Descriptor is within the fmap,
    // so it's safe to say the Allocation Descriptor is also within the fmap.
    // No need to use an `fmap_need...()` function here.

    // Extract the file.
    if (CL_SUCCESS != extractFile(ctx, pPartitionDescriptor, pLogicalVolumeDescriptor,
                                  allocation_descriptor,
                                  allocation_descriptor_len,
                                  le16_to_host(fed->icbTag.flags), fileIdentifierDescriptor)) {
        cli_dbgmsg("parseFileEntryDescriptor: Failed to extract file.\n");
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
    PrimaryVolumeDescriptor *test = NULL;
    PrimaryVolumeDescriptor *ret  = NULL;
    size_t idx                    = *idxp;
    size_t lastOffset             = *lastOffsetp;

    if (!skipEmptyDescriptors(ctx, idxp, lastOffsetp)) {
        goto done;
    }

    idx        = *idxp;
    lastOffset = *lastOffsetp;

    test = (PrimaryVolumeDescriptor *)fmap_need_off(ctx->fmap, idx, VOLUME_DESCRIPTOR_SIZE);
    if (NULL == test) {
        goto done;
    }
    lastOffset = idx;

    if (PRIMARY_VOLUME_DESCRIPTOR != getDescriptorTagId(&test->tag)) {
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
    ImplementationUseVolumeDescriptor *test = NULL;
    ImplementationUseVolumeDescriptor *ret  = NULL;
    size_t idx                              = *idxp;
    size_t lastOffset                       = *lastOffsetp;

    if (!skipEmptyDescriptors(ctx, idxp, lastOffsetp)) {
        goto done;
    }

    idx        = *idxp;
    lastOffset = *lastOffsetp;

    test = (ImplementationUseVolumeDescriptor *)fmap_need_off(ctx->fmap, idx, VOLUME_DESCRIPTOR_SIZE);
    if (NULL == test) {
        goto done;
    }
    lastOffset = idx;

    if (IMPLEMENTATION_USE_VOLUME_DESCRIPTOR != getDescriptorTagId(&test->tag)) {
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
    LogicalVolumeDescriptor *ret  = NULL;
    LogicalVolumeDescriptor *test = NULL;
    size_t idx                    = *idxp;
    size_t lastOffset             = *lastOffsetp;

    if (!skipEmptyDescriptors(ctx, idxp, lastOffsetp)) {
        goto done;
    }

    idx        = *idxp;
    lastOffset = *lastOffsetp;

    test = (LogicalVolumeDescriptor *)fmap_need_off(ctx->fmap, idx, VOLUME_DESCRIPTOR_SIZE);
    if (NULL == test) {
        goto done;
    }
    lastOffset = idx;

    if (LOGICAL_VOLUME_DESCRIPTOR != getDescriptorTagId(&test->tag)) {
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
    PartitionDescriptor *ret  = NULL;
    PartitionDescriptor *test = NULL;
    size_t idx                = *idxp;
    size_t lastOffset         = *lastOffsetp;

    if (!skipEmptyDescriptors(ctx, idxp, lastOffsetp)) {
        goto done;
    }

    idx        = *idxp;
    lastOffset = *lastOffsetp;

    test = (PartitionDescriptor *)fmap_need_off(ctx->fmap, idx, VOLUME_DESCRIPTOR_SIZE);
    if (NULL == test) {
        goto done;
    }
    lastOffset = idx;

    if (PARTITION_DESCRIPTOR != getDescriptorTagId(&test->tag)) {
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
    UnallocatedSpaceDescriptor *ret  = NULL;
    UnallocatedSpaceDescriptor *test = NULL;
    size_t idx                       = *idxp;
    size_t lastOffset                = *lastOffsetp;

    if (!skipEmptyDescriptors(ctx, idxp, lastOffsetp)) {
        goto done;
    }

    idx        = *idxp;
    lastOffset = *lastOffsetp;

    test = (UnallocatedSpaceDescriptor *)fmap_need_off(ctx->fmap, idx, VOLUME_DESCRIPTOR_SIZE);
    if (NULL == test) {
        goto done;
    }
    lastOffset = idx;

    if (UNALLOCATED_SPACE_DESCRIPTOR != getDescriptorTagId(&test->tag)) {
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
    TerminatingDescriptor *ret  = NULL;
    TerminatingDescriptor *test = NULL;
    size_t idx                  = *idxp;
    size_t lastOffset           = *lastOffsetp;

    if (!skipEmptyDescriptors(ctx, idxp, lastOffsetp)) {
        goto done;
    }

    idx        = *idxp;
    lastOffset = *lastOffsetp;

    test = (TerminatingDescriptor *)fmap_need_off(ctx->fmap, idx, VOLUME_DESCRIPTOR_SIZE);
    if (NULL == test) {
        goto done;
    }
    lastOffset = idx;

    if (TERMINATING_DESCRIPTOR != getDescriptorTagId(&test->tag)) {
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
    LogicalVolumeIntegrityDescriptor *ret  = NULL;
    LogicalVolumeIntegrityDescriptor *test = NULL;
    size_t idx                             = *idxp;
    size_t lastOffset                      = *lastOffsetp;

    if (!skipEmptyDescriptors(ctx, idxp, lastOffsetp)) {
        goto done;
    }

    idx        = *idxp;
    lastOffset = *lastOffsetp;

    test = (LogicalVolumeIntegrityDescriptor *)fmap_need_off(ctx->fmap, idx, VOLUME_DESCRIPTOR_SIZE);
    if (NULL == test) {
        goto done;
    }
    lastOffset = idx;

    if (LOGICAL_VOLUME_INTEGRITY_DESCRIPTOR != getDescriptorTagId(&test->tag)) {
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
    AnchorVolumeDescriptorPointer *ret  = NULL;
    AnchorVolumeDescriptorPointer *test = NULL;
    size_t idx                          = *idxp;
    size_t lastOffset                   = *lastOffsetp;

    if (!skipEmptyDescriptors(ctx, idxp, lastOffsetp)) {
        goto done;
    }

    idx        = *idxp;
    lastOffset = *lastOffsetp;

    test = (AnchorVolumeDescriptorPointer *)fmap_need_off(ctx->fmap, idx, VOLUME_DESCRIPTOR_SIZE);
    if (NULL == test) {
        goto done;
    }
    lastOffset = idx;

    if (ANCHOR_VOLUME_DESCRIPTOR_DESCRIPTOR_POINTER != getDescriptorTagId(&test->tag)) {
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
    FileSetDescriptor *ret  = NULL;
    FileSetDescriptor *test = NULL;
    size_t idx              = *idxp;
    size_t lastOffset       = *lastOffsetp;

    if (!skipEmptyDescriptors(ctx, idxp, lastOffsetp)) {
        goto done;
    }

    idx        = *idxp;
    lastOffset = *lastOffsetp;

    test = (FileSetDescriptor *)fmap_need_off(ctx->fmap, idx, VOLUME_DESCRIPTOR_SIZE);
    if (NULL == test) {
        goto done;
    }
    lastOffset = idx;

    if (FILE_SET_DESCRIPTOR != getDescriptorTagId(&test->tag)) {
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
                            cli_errmsg("initPointerList: Can't allocate memory\n"),
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
    uint16_t tagId        = getDescriptorTagId((DescriptorTag *)buffer);
    size_t bufUsed;
    size_t fidDescSize;

    while (FILE_IDENTIFIER_DESCRIPTOR == tagId) {
        /* This is how far into the Volume we already are. */
        bufUsed     = buffer - input;
        fidDescSize = getFileIdentifierDescriptorSize((FileIdentifierDescriptor *)buffer);

        /* Check that it's safe to save the file identifier pointer for later use */
        if (VOLUME_DESCRIPTOR_SIZE < (fidDescSize + bufUsed)) {
            break;
        }

        /* Add the buffer to the list of file identifier pointers */
        if (CL_SUCCESS != (ret = insertPointer(pfil, buffer))) {
            goto done;
        }

        /* Check that it's safe to read the TagID from the header of the next FileIdentifierDescriptor (if one exists) */
        if (VOLUME_DESCRIPTOR_SIZE < (fidDescSize + bufUsed + FILE_IDENTIFIER_DESCRIPTOR_SIZE_KNOWN)) {
            break;
        }

        buffer = buffer + fidDescSize;
        tagId  = getDescriptorTagId((DescriptorTag *)buffer);
    }

done:
    return ret;
}

static cl_error_t findFileEntries(const uint8_t *const input, PointerList *pfil)
{
    cl_error_t ret        = CL_SUCCESS;
    const uint8_t *buffer = input;
    uint16_t tagId        = getDescriptorTagId((DescriptorTag *)buffer);
    size_t bufUsed;
    size_t fedDescSize;

    while (FILE_ENTRY_DESCRIPTOR == tagId) {
        /* This is how far into the Volume we already are. */
        bufUsed     = buffer - input;
        fedDescSize = getFileEntryDescriptorSize((FileEntryDescriptor *)buffer);

        /* Check that it's safe to save the file identifier pointer for later use */
        if (VOLUME_DESCRIPTOR_SIZE < (fedDescSize + bufUsed)) {
            break;
        }

        /* Add the buffer to the list of file entry pointers */
        if (CL_SUCCESS != (ret = insertPointer(pfil, buffer))) {
            goto done;
        }

        /* Check that it's safe to read the TagID from the header of the next FileEntryDescriptor (if one exists) */
        if (VOLUME_DESCRIPTOR_SIZE < (fedDescSize + bufUsed + FILE_ENTRY_DESCRIPTOR_SIZE_KNOWN)) {
            break;
        }

        buffer = buffer + fedDescSize;
        tagId  = getDescriptorTagId((DescriptorTag *)buffer);
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
    PrimaryVolumeDescriptor *pvd            = NULL;
    GenericVolumeStructureDescriptor *gvsd  = NULL;
    ImplementationUseVolumeDescriptor *iuvd = NULL;
    LogicalVolumeDescriptor *lvd            = NULL;
    PartitionDescriptor *pd                 = NULL;
    UnallocatedSpaceDescriptor *usd         = NULL;
    TerminatingDescriptor *td               = NULL;
    LogicalVolumeIntegrityDescriptor *lvid  = NULL;
    AnchorVolumeDescriptorPointer *avdp     = NULL;
    FileSetDescriptor *fsd                  = NULL;
    DescriptorTag *file_volume_tag          = NULL;

    bool isInitialized             = false;
    PointerList fileIdentifierList = {0};
    PointerList fileEntryList      = {0};

    if (offset < 32768) {
        return CL_SUCCESS; /* Need 16 sectors at least 2048 bytes long */
    }

    cli_dbgmsg("Scanning UDF file\n");

    for (i = 0; i < NUM_GENERIC_VOLUME_DESCRIPTORS; i++) {
        gvsd = (GenericVolumeStructureDescriptor *)fmap_need_off(ctx->fmap, idx, sizeof(GenericVolumeStructureDescriptor));
        if (NULL == gvsd) {
            // File isn't long enough to store the required generic volume structure descriptors at the given offset.
            ret = CL_SUCCESS;
            goto done;
        }

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

        fmap_unneed_ptr(ctx->fmap, gvsd, sizeof(GenericVolumeStructureDescriptor));

        idx += sizeof(GenericVolumeStructureDescriptor);
    }

    while (1) {

        if (!isInitialized) {
            /* We don't use most of these descriptors, but verify they all exist because
             * they are part of a properly formatted udf file. */

            if (CL_SUCCESS != (ret = initPointerList(&fileIdentifierList))) {
                cli_dbgmsg("Failed to initialize fileIdentifierList\n");
                goto done;
            }

            if (CL_SUCCESS != (ret = initPointerList(&fileEntryList))) {
                cli_dbgmsg("Failed to initialize fileEntryList\n");
                goto done;
            }

            if (NULL == (pvd = getPrimaryVolumeDescriptor(ctx, &idx, &lastOffset))) {
                cli_dbgmsg("Failed to get Primary Volume Descriptor\n");
                goto done;
            }
            fmap_unneed_ptr(ctx->fmap, pvd, VOLUME_DESCRIPTOR_SIZE);

            if (NULL == (iuvd = getImplementationUseVolumeDescriptor(ctx, &idx, &lastOffset))) {
                cli_dbgmsg("Failed to get Implementation Use Volume Descriptor\n");
                goto done;
            }
            // Hold on to this pointer, we'll use it later.
            // We'll release it after `done`.

            if (NULL == (lvd = getLogicalVolumeDescriptor(ctx, &idx, &lastOffset))) {
                cli_dbgmsg("Failed to get Logical Volume Descriptor\n");
                goto done;
            }
            // Hold on to this pointer, we'll use it later.
            // We'll release it after `done`.

            if (NULL == (pd = getPartitionDescriptor(ctx, &idx, &lastOffset))) {
                cli_dbgmsg("Failed to get Partition Descriptor\n");
                goto done;
            }
            fmap_unneed_ptr(ctx->fmap, pd, VOLUME_DESCRIPTOR_SIZE);

            if (NULL == (usd = getUnallocatedSpaceDescriptor(ctx, &idx, &lastOffset))) {
                cli_dbgmsg("Failed to get Unallocated Space Descriptor\n");
                goto done;
            }
            fmap_unneed_ptr(ctx->fmap, usd, VOLUME_DESCRIPTOR_SIZE);

            if (NULL == (td = getTerminatingDescriptor(ctx, &idx, &lastOffset))) {
                cli_dbgmsg("Failed to get Terminating Descriptor\n");
                goto done;
            }
            fmap_unneed_ptr(ctx->fmap, td, VOLUME_DESCRIPTOR_SIZE);

            if (NULL == (lvid = getLogicalVolumeIntegrityDescriptor(ctx, &idx, &lastOffset))) {
                cli_dbgmsg("Failed to get Logical Volume Integrity Descriptor\n");
                goto done;
            }
            fmap_unneed_ptr(ctx->fmap, lvid, VOLUME_DESCRIPTOR_SIZE);

            if (NULL == (td = getTerminatingDescriptor(ctx, &idx, &lastOffset))) {
                cli_dbgmsg("Failed to get Terminating Descriptor\n");
                goto done;
            }
            fmap_unneed_ptr(ctx->fmap, td, VOLUME_DESCRIPTOR_SIZE);

            if (NULL == (avdp = getAnchorVolumeDescriptorPointer(ctx, &idx, &lastOffset))) {
                cli_dbgmsg("Failed to get Anchor Volume Descriptor Pointer\n");
                goto done;
            }
            fmap_unneed_ptr(ctx->fmap, avdp, VOLUME_DESCRIPTOR_SIZE);

            if (NULL == (fsd = getFileSetDescriptor(ctx, &idx, &lastOffset))) {
                cli_dbgmsg("Failed to get File Set Descriptor\n");

                // The file set descriptor may come after an extended file entry descriptor.
                idx = lastOffset;
            } else {
                fmap_unneed_ptr(ctx->fmap, fsd, VOLUME_DESCRIPTOR_SIZE);
            }

            isInitialized = true;
        }

        /*
         * Find all of the file identifier descriptors and file entry descriptors.
         */

        // Need the entire volume descriptor. We'll un-need it at the end.
        file_volume_tag = (DescriptorTag *)fmap_need_off(ctx->fmap, idx, VOLUME_DESCRIPTOR_SIZE);
        if (NULL == file_volume_tag) {
            cli_dbgmsg("Failed to get File Volume Tag\n");
            goto done;
        }
        lastOffset = idx;

        tag_identifier tagId = getDescriptorTagId(file_volume_tag);

        cli_dbgmsg("UDF Descriptor Tag ID: %d\n", tagId);

        switch (tagId) {
            case FILE_IDENTIFIER_DESCRIPTOR: {
                cl_error_t temp = findFileIdentifiers((const uint8_t *)file_volume_tag, &fileIdentifierList);
                if (CL_SUCCESS != temp) {
                    ret = temp;
                    goto done;
                }
                break;
            }

            case FILE_ENTRY_DESCRIPTOR: {
                cl_error_t temp = findFileEntries((const uint8_t *)file_volume_tag, &fileEntryList);
                if (CL_SUCCESS != temp) {
                    ret = temp;
                    goto done;
                }
                break;
            }

            case EXTENDED_FILE_ENTRY_DESCRIPTOR: {
                // Not supported yet. Skip.
                break;
            }

            case TERMINATING_DESCRIPTOR: {
                // Skip.
                break;
            }

            case INVALID_DESCRIPTOR: {
                // Skip.
                break;
            }

            default: {
                // TODO: Something feels wrong about doing this in `default:`.
                // Is there a specific value we can look for to be certain we found them all?
                // Right now this code appears to work by running into an invalid tagId when
                // actually is out of descriptors and starts indexing into file data.
                // Ideally we would end the loop when we know we've found all the descriptors,
                // and then do this after the loop.

                cli_dbgmsg("cli_scanudf: Parsing %d file entries.\n", fileEntryList.cnt);

                /* Dump all the files here. */
                size_t cnt = fileIdentifierList.cnt;

                /* The number of file entries should match the number of file identifiers, but in the
                 * case that the file is malformed, we are going to do the best we can to extract as much as we can.
                 */
                if (fileEntryList.cnt < cnt) {
                    cnt = fileEntryList.cnt;
                }

                for (i = 0; i < cnt; i++) {
                    if (!parseFileEntryDescriptor(ctx,
                                                  (FileEntryDescriptor *)fileEntryList.idxs[i],
                                                  pd, lvd, (FileIdentifierDescriptor *)fileIdentifierList.idxs[i])) {
                        cli_dbgmsg("cli_scanudf: Failed to extract file %zu\n", i);
                        goto done;
                    }
                }

                /*
                 * We're done with this volume. Release our pointers and free up our pointer lists.
                 * Start looking for the next volume.
                 */
                fmap_unneed_ptr(ctx->fmap, iuvd, VOLUME_DESCRIPTOR_SIZE);
                iuvd = NULL;
                fmap_unneed_ptr(ctx->fmap, lvd, VOLUME_DESCRIPTOR_SIZE);
                lvd = NULL;
                fmap_unneed_ptr(ctx->fmap, file_volume_tag, VOLUME_DESCRIPTOR_SIZE);
                file_volume_tag = NULL;

                isInitialized = false;
                break;
            }
        }

        idx += VOLUME_DESCRIPTOR_SIZE;
    }

done:
    freePointerList(&fileIdentifierList);
    freePointerList(&fileEntryList);

    if (NULL != iuvd) {
        fmap_unneed_ptr(ctx->fmap, iuvd, VOLUME_DESCRIPTOR_SIZE);
    }
    if (NULL != lvd) {
        fmap_unneed_ptr(ctx->fmap, lvd, VOLUME_DESCRIPTOR_SIZE);
    }
    if (NULL != file_volume_tag) {
        fmap_unneed_ptr(ctx->fmap, file_volume_tag, VOLUME_DESCRIPTOR_SIZE);
    }

    return ret;
}

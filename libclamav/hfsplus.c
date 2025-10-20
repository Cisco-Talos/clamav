/*
 *  Copyright (C) 2013-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
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
/**
 * Documentation:
 * - https://digital-forensics.sans.org/media/FOR518-Reference-Sheet.pdf
 * - https://github.com/sleuthkit/sleuthkit/blob/develop/tsk/fs/tsk_hfs.h
 * - https://github.com/unsound/hfsexplorer/tree/master/src/java/org/catacombae/hfs
 */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <fcntl.h>

#include "clamav.h"
#include "others.h"
#include "hfsplus.h"
#include "scanners.h"
#include "entconv.h"

#define DECMPFS_HEADER_MAGIC 0x636d7066
#define DECMPFS_HEADER_MAGIC_LE 0x66706d63

static void headerrecord_to_host(hfsHeaderRecord *);
static void headerrecord_print(const char *, hfsHeaderRecord *);
static void nodedescriptor_to_host(hfsNodeDescriptor *);
static void nodedescriptor_print(const char *, hfsNodeDescriptor *);
static void forkdata_to_host(hfsPlusForkData *);
static void forkdata_print(const char *, hfsPlusForkData *);

static cl_error_t hfsplus_volumeheader(cli_ctx *, hfsPlusVolumeHeader **);
static cl_error_t hfsplus_readheader(cli_ctx *, hfsPlusVolumeHeader *, hfsNodeDescriptor *,
                                     hfsHeaderRecord *, int, const char *);
static cl_error_t hfsplus_scanfile(cli_ctx *, hfsPlusVolumeHeader *, hfsHeaderRecord *,
                                   hfsPlusForkData *, const char *, char **, char *);
static cl_error_t hfsplus_validate_catalog(cli_ctx *, hfsPlusVolumeHeader *, hfsHeaderRecord *);
static cl_error_t hfsplus_fetch_node(cli_ctx *, hfsPlusVolumeHeader *, hfsHeaderRecord *,
                                     hfsHeaderRecord *, hfsPlusForkData *, uint32_t, uint8_t *,
                                     size_t);
static cl_error_t hfsplus_walk_catalog(cli_ctx *, hfsPlusVolumeHeader *, hfsHeaderRecord *,
                                       hfsHeaderRecord *, hfsHeaderRecord *, const char *);

/* Header Record : fix endianness for useful fields */
static void headerrecord_to_host(hfsHeaderRecord *hdr)
{
    hdr->treeDepth     = be16_to_host(hdr->treeDepth);
    hdr->rootNode      = be32_to_host(hdr->rootNode);
    hdr->leafRecords   = be32_to_host(hdr->leafRecords);
    hdr->firstLeafNode = be32_to_host(hdr->firstLeafNode);
    hdr->lastLeafNode  = be32_to_host(hdr->lastLeafNode);
    hdr->nodeSize      = be16_to_host(hdr->nodeSize);
    hdr->maxKeyLength  = be16_to_host(hdr->maxKeyLength);
    hdr->totalNodes    = be32_to_host(hdr->totalNodes);
    hdr->freeNodes     = be32_to_host(hdr->freeNodes);
    hdr->attributes    = be32_to_host(hdr->attributes); /* not too useful */
}

/* Header Record : print details in debug mode */
static void headerrecord_print(const char *pfx, hfsHeaderRecord *hdr)
{
    cli_dbgmsg("%s Header: depth %hu root %u leafRecords %u firstLeaf %u lastLeaf %u nodeSize %hu\n",
               pfx, hdr->treeDepth, hdr->rootNode, hdr->leafRecords, hdr->firstLeafNode,
               hdr->lastLeafNode, hdr->nodeSize);
    cli_dbgmsg("%s Header: maxKeyLength %hu totalNodes %u freeNodes %u btreeType %hhu attributes %x\n",
               pfx, hdr->maxKeyLength, hdr->totalNodes, hdr->freeNodes,
               hdr->btreeType, hdr->attributes);
}

/* Node Descriptor : fix endianness for useful fields */
static void nodedescriptor_to_host(hfsNodeDescriptor *node)
{
    node->fLink      = be32_to_host(node->fLink);
    node->bLink      = be32_to_host(node->bLink);
    node->numRecords = be16_to_host(node->numRecords);
}

/* Node Descriptor : print details in debug mode */
static void nodedescriptor_print(const char *pfx, hfsNodeDescriptor *node)
{
    cli_dbgmsg("%s Desc: fLink %u bLink %u kind %d height %u numRecords %u\n",
               pfx, node->fLink, node->bLink, node->kind, node->height, node->numRecords);
}

/* ForkData : fix endianness */
static void forkdata_to_host(hfsPlusForkData *fork)
{
    int i;

    fork->logicalSize = be64_to_host(fork->logicalSize);
    fork->clumpSize   = be32_to_host(fork->clumpSize); /* does this matter for read-only? */
    fork->totalBlocks = be32_to_host(fork->totalBlocks);
    for (i = 0; i < 8; i++) {
        fork->extents[i].startBlock = be32_to_host(fork->extents[i].startBlock);
        fork->extents[i].blockCount = be32_to_host(fork->extents[i].blockCount);
    }
}

/* ForkData : print details in debug mode */
static void forkdata_print(const char *pfx, hfsPlusForkData *fork)
{
    int i;
    cli_dbgmsg("%s logicalSize " STDu64 " clumpSize " STDu32 " totalBlocks " STDu32 "\n", pfx,
               fork->logicalSize, fork->clumpSize, fork->totalBlocks);
    for (i = 0; i < 8; i++) {
        if (fork->extents[i].startBlock == 0)
            break;
        cli_dbgmsg("%s extent[%d] startBlock " STDu32 " blockCount " STDu32 "\n", pfx, i,
                   fork->extents[i].startBlock, fork->extents[i].blockCount);
    }
}

/* Read and convert the HFS+ volume header */
static cl_error_t hfsplus_volumeheader(cli_ctx *ctx, hfsPlusVolumeHeader **header)
{
    hfsPlusVolumeHeader *volHeader;
    const uint8_t *mPtr;

    if (!header) {
        return CL_ENULLARG;
    }

    /* Start with volume header, 512 bytes at offset 1024 */
    if (ctx->fmap->len < 1536) {
        cli_dbgmsg("hfsplus_volumeheader: too short for HFS+\n");
        return CL_EFORMAT;
    }
    mPtr = fmap_need_off_once(ctx->fmap, 1024, 512);
    if (!mPtr) {
        cli_errmsg("hfsplus_volumeheader: cannot read header from map\n");
        return CL_EMAP;
    }

    volHeader = malloc(sizeof(hfsPlusVolumeHeader));
    if (!volHeader) {
        cli_errmsg("hfsplus_volumeheader: header malloc failed\n");
        return CL_EMEM;
    }
    *header = volHeader;
    memcpy(volHeader, mPtr, 512);

    volHeader->signature = be16_to_host(volHeader->signature);
    volHeader->version   = be16_to_host(volHeader->version);
    if ((volHeader->signature == 0x482B) && (volHeader->version == 4)) {
        cli_dbgmsg("hfsplus_volumeheader: HFS+ signature matched\n");
    } else if ((volHeader->signature == 0x4858) && (volHeader->version == 5)) {
        cli_dbgmsg("hfsplus_volumeheader: HFSX v5 signature matched\n");
    } else {
        cli_dbgmsg("hfsplus_volumeheader: no matching signature\n");
        return CL_EFORMAT;
    }
    /* skip fields that will definitely be ignored */
    volHeader->attributes  = be32_to_host(volHeader->attributes);
    volHeader->fileCount   = be32_to_host(volHeader->fileCount);
    volHeader->folderCount = be32_to_host(volHeader->folderCount);
    volHeader->blockSize   = be32_to_host(volHeader->blockSize);
    volHeader->totalBlocks = be32_to_host(volHeader->totalBlocks);

    cli_dbgmsg("HFS+ Header:\n");
    cli_dbgmsg("Signature: %x\n", volHeader->signature);
    cli_dbgmsg("Attributes: %x\n", volHeader->attributes);
    cli_dbgmsg("File Count: " STDu32 "\n", volHeader->fileCount);
    cli_dbgmsg("Folder Count: " STDu32 "\n", volHeader->folderCount);
    cli_dbgmsg("Block Size: " STDu32 "\n", volHeader->blockSize);
    cli_dbgmsg("Total Blocks: " STDu32 "\n", volHeader->totalBlocks);

    /* Block Size must be power of 2 between 512 and 1 MB */
    if ((volHeader->blockSize < 512) || (volHeader->blockSize > (1 << 20))) {
        cli_dbgmsg("hfsplus_volumeheader: Invalid blocksize\n");
        return CL_EFORMAT;
    }
    if (volHeader->blockSize & (volHeader->blockSize - 1)) {
        cli_dbgmsg("hfsplus_volumeheader: Invalid blocksize\n");
        return CL_EFORMAT;
    }

    forkdata_to_host(&(volHeader->allocationFile));
    forkdata_to_host(&(volHeader->extentsFile));
    forkdata_to_host(&(volHeader->catalogFile));
    forkdata_to_host(&(volHeader->attributesFile));
    forkdata_to_host(&(volHeader->startupFile));

    if (cli_debug_flag) {
        forkdata_print("allocationFile", &(volHeader->allocationFile));
        forkdata_print("extentsFile", &(volHeader->extentsFile));
        forkdata_print("catalogFile", &(volHeader->catalogFile));
        forkdata_print("attributesFile", &(volHeader->attributesFile));
        forkdata_print("startupFile", &(volHeader->startupFile));
    }

    return CL_CLEAN;
}

/* Read and convert the header node */
static cl_error_t hfsplus_readheader(cli_ctx *ctx, hfsPlusVolumeHeader *volHeader, hfsNodeDescriptor *nodeDesc,
                                     hfsHeaderRecord *headerRec, int headerType, const char *name)
{
    const uint8_t *mPtr = NULL;
    off_t offset;
    uint32_t minSize, maxSize;

    /* From TN1150: Node Size must be power of 2 between 512 and 32768 */
    /* Node Size for Catalog or Attributes must be at least 4096 */
    maxSize = 32768; /* Doesn't seem to vary */
    switch (headerType) {
        case HFS_FILETREE_ALLOCATION:
            offset  = volHeader->allocationFile.extents[0].startBlock * volHeader->blockSize;
            minSize = 512;
            break;
        case HFS_FILETREE_EXTENTS:
            offset  = volHeader->extentsFile.extents[0].startBlock * volHeader->blockSize;
            minSize = 512;
            break;
        case HFS_FILETREE_CATALOG:
            offset  = volHeader->catalogFile.extents[0].startBlock * volHeader->blockSize;
            minSize = 4096;
            break;
        case HFS_FILETREE_ATTRIBUTES:
            offset  = volHeader->attributesFile.extents[0].startBlock * volHeader->blockSize;
            minSize = 4096;
            break;
        case HFS_FILETREE_STARTUP:
            offset  = volHeader->startupFile.extents[0].startBlock * volHeader->blockSize;
            minSize = 512;
            break;
        default:
            cli_errmsg("hfsplus_readheader: %s: invalid headerType %d\n", name, headerType);
            return CL_EARG;
    }
    mPtr = fmap_need_off_once(ctx->fmap, offset, volHeader->blockSize);
    if (!mPtr) {
        cli_dbgmsg("hfsplus_readheader: %s: headerNode is out-of-range\n", name);
        return CL_EFORMAT;
    }

    /* Node descriptor first */
    memcpy(nodeDesc, mPtr, sizeof(hfsNodeDescriptor));
    nodedescriptor_to_host(nodeDesc);
    nodedescriptor_print(name, nodeDesc);
    if (nodeDesc->kind != HFS_NODEKIND_HEADER) {
        cli_dbgmsg("hfsplus_readheader: %s: headerNode not header kind\n", name);
        return CL_EFORMAT;
    }
    if ((nodeDesc->bLink != 0) || (nodeDesc->height != 0) || (nodeDesc->numRecords != 3)) {
        cli_dbgmsg("hfsplus_readheader: %s: Invalid headerNode\n", name);
        return CL_EFORMAT;
    }

    /* Then header record */
    memcpy(headerRec, mPtr + sizeof(hfsNodeDescriptor), sizeof(hfsHeaderRecord));
    headerrecord_to_host(headerRec);
    headerrecord_print(name, headerRec);

    if ((headerRec->nodeSize < minSize) || (headerRec->nodeSize > maxSize)) {
        cli_dbgmsg("hfsplus_readheader: %s: Invalid nodesize\n", name);
        return CL_EFORMAT;
    }
    if (headerRec->nodeSize & (headerRec->nodeSize - 1)) {
        cli_dbgmsg("hfsplus_readheader: %s: Invalid nodesize\n", name);
        return CL_EFORMAT;
    }
    /* KeyLength must be between 6 and 516 for catalog */
    if (headerType == HFS_FILETREE_CATALOG) {
        if ((headerRec->maxKeyLength < 6) || (headerRec->maxKeyLength > 516)) {
            cli_dbgmsg("hfsplus_readheader: %s: Invalid cat maxKeyLength\n", name);
            return CL_EFORMAT;
        }
        if (headerRec->maxKeyLength > (headerRec->nodeSize / 2)) {
            cli_dbgmsg("hfsplus_readheader: %s: Invalid cat maxKeyLength based on nodeSize\n", name);
            return CL_EFORMAT;
        }
    } else if (headerType == HFS_FILETREE_EXTENTS) {
        if (headerRec->maxKeyLength != 10) {
            cli_dbgmsg("hfsplus_readheader: %s: Invalid ext maxKeyLength\n", name);
            return CL_EFORMAT;
        }
    }

    /* hdr->treeDepth = rootnode->height */
    return CL_CLEAN;
}

/**
 * @brief Read and dump a file for scanning.
 *
 * If the filename pointer is provided, the file name will be set and the
 * resulting file will __NOT__ be scanned. The returned pointer must be freed
 * by the caller. If the pointer is NULL, the file will be scanned and,
 * depending on the --leave-temps value, deleted or not.
 *
 * @param ctx           The current scan context
 * @param volHeader     Volume header
 * @param extHeader     Extent overflow file header
 * @param fork          Fork Data
 * @param dirname       Temp directory name
 * @param[out] filename (optional) temp file name
 * @param orig_filename (optional) Original filename
 * @return cl_error_t
 */
static cl_error_t hfsplus_scanfile(cli_ctx *ctx, hfsPlusVolumeHeader *volHeader, hfsHeaderRecord *extHeader,
                                   hfsPlusForkData *fork, const char *dirname, char **filename, char *orig_filename)
{
    cl_error_t status = CL_SUCCESS;
    hfsPlusExtentDescriptor *currExt;
    const uint8_t *mPtr = NULL;
    char *tmpname       = NULL;
    int ofd             = -1;
    uint64_t targetSize;
    uint32_t outputBlocks = 0;
    uint8_t ext;

    UNUSEDPARAM(extHeader);

    /* bad record checks */
    if (!fork || (fork->logicalSize == 0) || (fork->totalBlocks == 0)) {
        cli_dbgmsg("hfsplus_scanfile: Empty file.\n");
        goto done;
    }

    /* check limits */
    targetSize = fork->logicalSize;
#if SIZEOF_LONG < 8
    if (targetSize > ULONG_MAX) {
        cli_dbgmsg("hfsplus_scanfile: File too large for limit check.\n");
        status = CL_EFORMAT;
        goto done;
    }
#endif
    status = cli_checklimits("hfsplus_scanfile", ctx, targetSize, 0, 0);
    if (status != CL_SUCCESS) {
        goto done;
    }

    /* open file */
    status = cli_gentempfd(dirname, &tmpname, &ofd);
    if (status != CL_SUCCESS) {
        cli_dbgmsg("hfsplus_scanfile: Cannot generate temporary file.\n");
        goto done;
    }
    cli_dbgmsg("hfsplus_scanfile: Extracting to %s\n", tmpname);

    ext = 0;
    /* Dump file, extent by extent */
    do {
        uint32_t currBlock, endBlock;
        if (targetSize == 0) {
            cli_dbgmsg("hfsplus_scanfile: output complete\n");
            break;
        }
        if (outputBlocks >= fork->totalBlocks) {
            cli_dbgmsg("hfsplus_scanfile: output all blocks, remaining size " STDu64 "\n", targetSize);
            break;
        }

        /* Prepare extent */
        if (ext < 8) {
            currExt = &(fork->extents[ext]);
            cli_dbgmsg("hfsplus_scanfile: extent %u\n", ext);
        } else {
            cli_dbgmsg("hfsplus_scanfile: need next extent from ExtentOverflow\n");
            /* Not implemented yet */
            status = CL_EFORMAT;
            goto done;
        }

        /* have extent, so validate and get block range */
        if ((currExt->startBlock == 0) || (currExt->blockCount == 0)) {
            cli_dbgmsg("hfsplus_scanfile: next extent empty, done\n");
            break;
        }

        if ((currExt->startBlock & 0x10000000) && (currExt->blockCount & 0x10000000)) {
            cli_dbgmsg("hfsplus_scanfile: next extent illegal!\n");
            status = CL_EFORMAT;
            goto done;
        }

        currBlock = currExt->startBlock;
        endBlock  = currExt->startBlock + currExt->blockCount - 1;
        if ((currBlock > volHeader->totalBlocks) || (endBlock > volHeader->totalBlocks) || (currExt->blockCount > volHeader->totalBlocks)) {
            cli_dbgmsg("hfsplus_scanfile: bad extent!\n");
            status = CL_EFORMAT;
            goto done;
        }

        /* Write the blocks, walking the map */
        while (currBlock <= endBlock) {
            size_t to_write = MIN(targetSize, volHeader->blockSize);
            size_t written;
            off_t offset = currBlock * volHeader->blockSize;

            /* move map to next block */
            mPtr = fmap_need_off_once(ctx->fmap, offset, volHeader->blockSize);
            if (!mPtr) {
                cli_errmsg("hfsplus_scanfile: map error\n");
                status = CL_EMAP;
                goto done;
            }

            written = cli_writen(ofd, mPtr, to_write);
            if (written != to_write) {
                cli_errmsg("hfsplus_scanfile: write error\n");
                status = CL_EWRITE;
                goto done;
            }

            targetSize -= to_write;
            currBlock++;

            if (targetSize == 0) {
                cli_dbgmsg("hfsplus_scanfile: all data written\n");
                break;
            }

            if (outputBlocks >= fork->totalBlocks) {
                cli_dbgmsg("hfsplus_scanfile: output all blocks, remaining size " STDu64 "\n", targetSize);
                break;
            }
        }

        /* Finished the extent, move to next */
        ext++;
    } while (status == CL_SUCCESS);

    /* Now that we're done, ...
     *  A) if filename output param is provided, just pass back the filename.
     *  B) otherwise scan the file.
     */
    if (filename) {
        *filename = tmpname;

    } else {
        status = cli_magic_scan_desc(ofd, tmpname, ctx, orig_filename, LAYER_ATTRIBUTES_NONE);
        if (status != CL_SUCCESS) {
            goto done;
        }

        /* TODO: Scan overlay if outputBlocks >= fork->totalBlocks ? */
    }

done:

    if (ofd >= 0) {
        close(ofd);
    }
    if ((NULL == filename) ||     // output param not provided, which means we should clean up the temp file,
        (status != CL_SUCCESS)) { // or we failed, so we should clean up the temp file.

        if (tmpname) {
            if (!ctx->engine->keeptmp) {
                (void)cli_unlink(tmpname);
            }
            free(tmpname);
        }
    }

    return status;
}

/* Calculate true node limit for catalogFile */
static cl_error_t hfsplus_validate_catalog(cli_ctx *ctx, hfsPlusVolumeHeader *volHeader, hfsHeaderRecord *catHeader)
{
    hfsPlusForkData *catFork;

    UNUSEDPARAM(ctx);

    catFork = &(volHeader->catalogFile);
    if (catFork->totalBlocks >= volHeader->totalBlocks) {
        cli_dbgmsg("hfsplus_validate_catalog: catFork totalBlocks too large!\n");
        return CL_EFORMAT;
    }
    if (catFork->logicalSize > (catFork->totalBlocks * volHeader->blockSize)) {
        cli_dbgmsg("hfsplus_validate_catalog: catFork logicalSize too large!\n");
        return CL_EFORMAT;
    }
    if (catFork->logicalSize < (catHeader->totalNodes * catHeader->nodeSize)) {
        cli_dbgmsg("hfsplus_validate_catalog: too many nodes for catFile\n");
        return CL_EFORMAT;
    }

    return CL_CLEAN;
}

/* Check if an attribute is present in the attribute map */
static cl_error_t hfsplus_check_attribute(cli_ctx *ctx, hfsPlusVolumeHeader *volHeader, hfsHeaderRecord *attrHeader, uint32_t expectedCnid, const uint8_t name[], uint32_t nameLen, int *found, uint8_t record[], size_t *recordSize)
{
    cl_error_t status = CL_SUCCESS;
    uint16_t nodeSize, recordNum, topOfOffsets;
    uint16_t recordStart, nextDist, nextStart;
    uint8_t *nodeBuf = NULL;
    uint32_t thisNode, nodeLimit, nodesScanned = 0;
    bool foundAttr = false;

    if (found) {
        *found = 0;
    }

    if (!attrHeader) {
        return CL_EARG;
    }

    nodeLimit = MIN(attrHeader->totalNodes, HFSPLUS_NODE_LIMIT);
    thisNode  = attrHeader->firstLeafNode;
    nodeSize  = attrHeader->nodeSize;

    /* Need to buffer current node, map will keep moving */
    nodeBuf = cli_max_malloc(nodeSize);
    if (!nodeBuf) {
        cli_dbgmsg("hfsplus_check_attribute: failed to acquire node buffer, "
                   "size " STDu32 "\n",
                   nodeSize);
        status = CL_EMEM;
        goto done;
    }

    /* Walk catalog leaf nodes, and scan contents of each */
    /* Because we want to scan them all, the index nodes add no value */
    while (status == CL_SUCCESS && !foundAttr) {
        hfsNodeDescriptor nodeDesc;

        if (thisNode == 0) {
            cli_dbgmsg("hfsplus_check_attribute: reached end of leaf nodes.\n");
            break;
        }
        if (nodesScanned++ > nodeLimit) {
            cli_dbgmsg("hfsplus_check_attribute: node scan limit reached.\n");
            break;
        }

        /* fetch node into buffer */
        status = hfsplus_fetch_node(ctx, volHeader, attrHeader, NULL, &(volHeader->attributesFile), thisNode, nodeBuf, nodeSize);
        if (status != CL_SUCCESS) {
            cli_dbgmsg("hfsplus_check_attribute: node fetch failed.\n");
            goto done;
        }
        memcpy(&nodeDesc, nodeBuf, 14);

        /* convert and validate node */
        nodedescriptor_to_host(&nodeDesc);
        nodedescriptor_print("leaf attribute node", &nodeDesc);
        if ((nodeDesc.kind != HFS_NODEKIND_LEAF) || (nodeDesc.height != 1)) {
            cli_dbgmsg("hfsplus_check_attribute: invalid leaf node!\n");
            status = CL_EFORMAT;
            goto done;
        }
        if ((nodeSize / 4) < nodeDesc.numRecords) {
            cli_dbgmsg("hfsplus_check_attribute: too many leaf records for one node!\n");
            status = CL_EFORMAT;
            goto done;
        }

        /* Walk this node's records and scan */
        recordStart = 14; /* 1st record can be after end of node descriptor */
        /* offsets take 1 u16 per at the end of the node, along with an empty space offset */
        topOfOffsets = nodeSize - (nodeDesc.numRecords * 2) - 2;
        for (recordNum = 0; recordNum < nodeDesc.numRecords; recordNum++) {
            uint16_t keylen;
            hfsPlusAttributeKey attrKey;
            hfsPlusAttributeRecord attrRec;

            /* Locate next record */
            nextDist  = nodeSize - (recordNum * 2) - 2;
            nextStart = nodeBuf[nextDist] * 0x100 + nodeBuf[nextDist + 1];
            /* Check record location */
            if ((nextStart > topOfOffsets - 1) || (nextStart < recordStart)) {
                cli_dbgmsg("hfsplus_check_attribute: bad record location %x for %u!\n", nextStart, recordNum);
                status = CL_EFORMAT;
                goto done;
            }
            recordStart = nextStart;
            if (recordStart + sizeof(attrKey) >= topOfOffsets) {
                cli_dbgmsg("hfsplus_check_attribute: Not enough data for an attribute key at location %x for %u!\n",
                           nextStart, recordNum);
                status = CL_EFORMAT;
                goto done;
            }

            memcpy(&attrKey, &nodeBuf[recordStart], sizeof(attrKey));
            attrKey.keyLength  = be16_to_host(attrKey.keyLength);
            attrKey.cnid       = be32_to_host(attrKey.cnid);
            attrKey.startBlock = be32_to_host(attrKey.startBlock);
            attrKey.nameLength = be16_to_host(attrKey.nameLength);

            /* Get record key length */
            keylen = nodeBuf[recordStart] * 0x100 + nodeBuf[recordStart + 1];
            keylen += keylen % 2; /* pad 1 byte if required to make 2-byte align */
            /* Validate keylen */
            if (recordStart + attrKey.keyLength + 4 >= topOfOffsets) {
                cli_dbgmsg("hfsplus_check_attribute: key too long for location %x for %u!\n",
                           nextStart, recordNum);
                status = CL_EFORMAT;
                goto done;
            }

            if (recordStart + sizeof(hfsPlusAttributeKey) + attrKey.nameLength >= topOfOffsets) {
                cli_dbgmsg("hfsplus_check_attribute: Attribute name is longer than expected: %u\n", attrKey.nameLength);
                status = CL_EFORMAT;
                goto done;
            }

            if (attrKey.cnid == expectedCnid && attrKey.nameLength * 2 == nameLen && memcmp(&nodeBuf[recordStart + 14], name, nameLen) == 0) {
                memcpy(&attrRec, &(nodeBuf[recordStart + sizeof(hfsPlusAttributeKey) + attrKey.nameLength * 2]), sizeof(attrRec));
                attrRec.recordType    = be32_to_host(attrRec.recordType);
                attrRec.attributeSize = be32_to_host(attrRec.attributeSize);

                if (attrRec.recordType != HFSPLUS_RECTYPE_INLINE_DATA_ATTRIBUTE) {
                    cli_dbgmsg("hfsplus_check_attribute: Unexpected attribute record type 0x%x\n", attrRec.recordType);
                    continue;
                }

                if (attrRec.attributeSize > *recordSize) {
                    status = CL_EFORMAT;
                    goto done;
                }

                memcpy(record, &(nodeBuf[recordStart + sizeof(hfsPlusAttributeKey) + attrKey.nameLength * 2 + sizeof(attrRec)]), attrRec.attributeSize);
                *recordSize = attrRec.attributeSize;

                if (found) {
                    *found = 1;
                }

                foundAttr = true;
                break;
            }
        }
    }

done:

    if (nodeBuf != NULL) {
        free(nodeBuf);
        nodeBuf = NULL;
    }

    return status;
}

/* Fetch a node's contents into the buffer */
static cl_error_t hfsplus_fetch_node(cli_ctx *ctx, hfsPlusVolumeHeader *volHeader, hfsHeaderRecord *catHeader,
                                     hfsHeaderRecord *extHeader, hfsPlusForkData *catFork, uint32_t node, uint8_t *buff,
                                     size_t buffSize)
{
    bool foundBlock = false;
    uint64_t catalogOffset;
    uint32_t startBlock, startOffset;
    uint32_t endBlock, endSize;
    uint32_t curBlock;
    uint32_t extentNum = 0, realFileBlock;
    uint32_t readSize;
    size_t fileOffset = 0;
    uint32_t searchBlock;
    uint32_t buffOffset = 0;

    UNUSEDPARAM(extHeader);

    /* Make sure node is in range */
    if (node >= catHeader->totalNodes) {
        cli_dbgmsg("hfsplus_fetch_node: invalid node number " STDu32 "\n", node);
        return CL_EFORMAT;
    }

    /* Need one block */
    /* First, calculate the node's offset within the catalog */
    catalogOffset = (uint64_t)node * catHeader->nodeSize;
    /* Determine which block of the catalog we need */
    startBlock  = (uint32_t)(catalogOffset / volHeader->blockSize);
    startOffset = (uint32_t)(catalogOffset % volHeader->blockSize);
    endBlock    = (uint32_t)((catalogOffset + catHeader->nodeSize - 1) / volHeader->blockSize);
    endSize     = (uint32_t)(((catalogOffset + catHeader->nodeSize - 1) % volHeader->blockSize) + 1);
    cli_dbgmsg("hfsplus_fetch_node: need catalog block " STDu32 "\n", startBlock);
    if (startBlock >= catFork->totalBlocks || endBlock >= catFork->totalBlocks) {
        cli_dbgmsg("hfsplus_fetch_node: block number invalid!\n");
        return CL_EFORMAT;
    }

    for (curBlock = startBlock; curBlock <= endBlock; ++curBlock) {

        foundBlock  = false;
        searchBlock = curBlock;
        /* Find which extent has that block */
        for (extentNum = 0; extentNum < 8; extentNum++) {
            hfsPlusExtentDescriptor *currExt = &(catFork->extents[extentNum]);

            /* Beware empty extent */
            if ((currExt->startBlock == 0) || (currExt->blockCount == 0)) {
                cli_dbgmsg("hfsplus_fetch_node: extent " STDu32 " empty!\n", extentNum);
                return CL_EFORMAT;
            }
            /* Beware too long extent */
            if ((currExt->startBlock & 0x10000000) && (currExt->blockCount & 0x10000000)) {
                cli_dbgmsg("hfsplus_fetch_node: extent " STDu32 " illegal!\n", extentNum);
                return CL_EFORMAT;
            }
            /* Check if block found in current extent */
            if (searchBlock < currExt->blockCount) {
                cli_dbgmsg("hfsplus_fetch_node: found block in extent " STDu32 "\n", extentNum);
                realFileBlock = currExt->startBlock + searchBlock;
                foundBlock    = true;
                break;
            } else {
                cli_dbgmsg("hfsplus_fetch_node: not in extent " STDu32 "\n", extentNum);
                searchBlock -= currExt->blockCount;
            }
        }

        if (foundBlock == false) {
            cli_dbgmsg("hfsplus_fetch_node: not in first 8 extents\n");
            cli_dbgmsg("hfsplus_fetch_node: finding this node requires extent overflow support\n");
            return CL_EFORMAT;
        }

        /* Block found */
        if (realFileBlock >= volHeader->totalBlocks) {
            cli_dbgmsg("hfsplus_fetch_node: block past end of volume\n");
            return CL_EFORMAT;
        }
        fileOffset = realFileBlock * volHeader->blockSize;
        readSize   = volHeader->blockSize;

        if (curBlock == startBlock) {
            fileOffset += startOffset;
        } else if (curBlock == endBlock) {
            readSize = endSize;
        }

        if ((buffOffset + readSize) > buffSize) {
            cli_dbgmsg("hfsplus_fetch_node: Not enough space for read\n");
            return CL_EFORMAT;
        }

        if (fmap_readn(ctx->fmap, buff + buffOffset, fileOffset, readSize) != readSize) {
            cli_dbgmsg("hfsplus_fetch_node: not all bytes read\n");
            return CL_EFORMAT;
        }
        buffOffset += readSize;
    }

    return CL_CLEAN;
}

static cl_error_t hfsplus_seek_to_cmpf_resource(int fd, size_t *size)
{
    cl_error_t status = CL_SUCCESS;
    hfsPlusResourceHeader resourceHeader;
    hfsPlusResourceMap resourceMap;
    hfsPlusResourceType resourceType;
    hfsPlusReferenceEntry entry;
    int i;
    int cmpfInstanceIdx = -1;
    int curInstanceIdx  = 0;
    size_t dataOffset;
    uint32_t dataLength;

    if (!size) {
        status = CL_ENULLARG;
        goto done;
    }

    if (cli_readn(fd, &resourceHeader, sizeof(resourceHeader)) != sizeof(resourceHeader)) {
        cli_dbgmsg("hfsplus_seek_to_cmpf_resource: Failed to read resource header from temporary file\n");
        status = CL_EREAD;
        goto done;
    }

    resourceHeader.dataOffset = be32_to_host(resourceHeader.dataOffset);
    resourceHeader.mapOffset  = be32_to_host(resourceHeader.mapOffset);
    resourceHeader.dataLength = be32_to_host(resourceHeader.dataLength);
    resourceHeader.mapLength  = be32_to_host(resourceHeader.mapLength);

    // TODO: Need to get offset of cmpf resource in data stream

    if (lseek(fd, resourceHeader.mapOffset, SEEK_SET) != resourceHeader.mapOffset) {
        cli_dbgmsg("hfsplus_seek_to_cmpf_resource: Failed to seek to map in temporary file\n");
        status = CL_ESEEK;
        goto done;
    }

    if (cli_readn(fd, &resourceMap, sizeof(resourceMap)) != sizeof(resourceMap)) {
        cli_dbgmsg("hfsplus_seek_to_cmpf_resource: Failed to read resource map from temporary file\n");
        status = CL_EREAD;
        goto done;
    }

    resourceMap.resourceForkAttributes = be16_to_host(resourceMap.resourceForkAttributes);
    resourceMap.typeListOffset         = be16_to_host(resourceMap.typeListOffset);
    resourceMap.nameListOffset         = be16_to_host(resourceMap.nameListOffset);
    resourceMap.typeCount              = be16_to_host(resourceMap.typeCount);

    for (i = 0; i < resourceMap.typeCount + 1; ++i) {
        if (cli_readn(fd, &resourceType, sizeof(resourceType)) != sizeof(resourceType)) {
            cli_dbgmsg("hfsplus_seek_to_cmpf_resource: Failed to read resource type from temporary file\n");
            status = CL_EREAD;
            goto done;
        }
        resourceType.instanceCount       = be16_to_host(resourceType.instanceCount);
        resourceType.referenceListOffset = be16_to_host(resourceType.referenceListOffset);

        if (memcmp(resourceType.type, "cmpf", 4) == 0) {
            if (cmpfInstanceIdx != -1) {
                cli_dbgmsg("hfsplus_seek_to_cmpf_resource: There are several cmpf resource types in the file\n");
                status = CL_EFORMAT;
                goto done;
            }

            cmpfInstanceIdx = curInstanceIdx;
            cli_dbgmsg("Found compressed resource type!\n");
        }

        curInstanceIdx += resourceType.instanceCount + 1;
    }

    if (cmpfInstanceIdx < 0) {
        cli_dbgmsg("hfsplus_seek_to_cmpf_resource: Didn't find cmpf resource type\n");
        status = CL_EFORMAT;
        goto done;
    }

    if (lseek(fd, cmpfInstanceIdx * sizeof(hfsPlusReferenceEntry), SEEK_CUR) < 0) {
        cli_dbgmsg("hfsplus_seek_to_cmpf_resource: Failed to seek to instance index\n");
        status = CL_ESEEK;
        goto done;
    }

    if (cli_readn(fd, &entry, sizeof(entry)) != sizeof(entry)) {
        cli_dbgmsg("hfsplus_seek_to_cmpf_resource: Failed to read resource entry from temporary file\n");
        status = CL_EREAD;
        goto done;
    }

    dataOffset = (entry.resourceDataOffset[0] << 16) | (entry.resourceDataOffset[1] << 8) | entry.resourceDataOffset[2];

    if (lseek(fd, resourceHeader.dataOffset + dataOffset, SEEK_SET) < 0) {
        cli_dbgmsg("hfsplus_seek_to_cmpf_resource: Failed to seek to data offset\n");
        status = CL_ESEEK;
        goto done;
    }

    if (cli_readn(fd, &dataLength, sizeof(dataLength)) != sizeof(dataLength)) {
        cli_dbgmsg("hfsplus_seek_to_cmpf_resource: Failed to read data length from temporary file\n");
        status = CL_EREAD;
        goto done;
    }

    *size = be32_to_host(dataLength);

done:
    return status;
}

/**
 * @brief Read the table from the provided file.
 *
 * The caller is responsible for freeing the table.
 *
 * @param fd                File descriptor of the file to read from.
 * @param [out] numBlocks   Number of blocks in the table, as determined from reading the file.
 * @param [out] table       Will be allocated and populated with table data.
 * @return cl_error_t  CL_SUCCESS on success, CL_E* on failure.
 */
static cl_error_t hfsplus_read_block_table(int fd, uint32_t *numBlocks, hfsPlusResourceBlockTable **table)
{
    cl_error_t status = CL_SUCCESS;
    uint32_t i;

    if (!table || !numBlocks) {
        status = CL_ENULLARG;
        goto done;
    }

    if (cli_readn(fd, numBlocks, sizeof(*numBlocks)) != sizeof(*numBlocks)) {
        cli_dbgmsg("hfsplus_read_block_table: Failed to read block count\n");
        status = CL_EREAD;
        goto done;
    }

    *numBlocks = le32_to_host(*numBlocks); // Let's do a little little endian just for fun, shall we?
    *table     = cli_max_malloc(sizeof(hfsPlusResourceBlockTable) * *numBlocks);
    if (!*table) {
        cli_dbgmsg("hfsplus_read_block_table: Failed to allocate memory for block table\n");
        status = CL_EMEM;
        goto done;
    }

    if (cli_readn(fd, *table, *numBlocks * sizeof(hfsPlusResourceBlockTable)) != *numBlocks * sizeof(hfsPlusResourceBlockTable)) {
        cli_dbgmsg("hfsplus_read_block_table: Failed to read table\n");
        status = CL_EREAD;
        goto done;
    }

    for (i = 0; i < *numBlocks; ++i) {
        (*table)[i].offset = le32_to_host((*table)[i].offset);
        (*table)[i].length = le32_to_host((*table)[i].length);
    }

done:
    if (CL_SUCCESS != status) {
        if (NULL != table) {
            free(*table);
            *table = NULL;
        }
    }
    return status;
}

/* Given the catalog and other details, scan all the volume contents */
static cl_error_t hfsplus_walk_catalog(cli_ctx *ctx, hfsPlusVolumeHeader *volHeader, hfsHeaderRecord *catHeader,
                                       hfsHeaderRecord *extHeader, hfsHeaderRecord *attrHeader, const char *dirname)
{
    cl_error_t status = CL_SUCCESS;
    uint32_t thisNode, nodeLimit, nodesScanned = 0;
    uint16_t nodeSize, recordNum, topOfOffsets;
    uint16_t recordStart, nextDist, nextStart;
    uint8_t *nodeBuf                = NULL;
    const uint8_t COMPRESSED_ATTR[] = {0, 'c', 0, 'o', 0, 'm', 0, '.', 0, 'a', 0, 'p', 0, 'p', 0, 'l', 0, 'e', 0, '.', 0, 'd', 0, 'e', 0, 'c', 0, 'm', 0, 'p', 0, 'f', 0, 's'};
    char *tmpname                   = NULL;
    uint8_t *uncompressed           = NULL;
    char *resourceFile              = NULL;
    int ifd                         = -1;
    int ofd                         = -1;
    char *name_utf8                 = NULL;
    size_t name_utf8_size           = 0;
    bool extracted_file             = false;

    hfsPlusResourceBlockTable *table = NULL;

    nodeLimit = MIN(catHeader->totalNodes, HFSPLUS_NODE_LIMIT);
    thisNode  = catHeader->firstLeafNode;
    nodeSize  = catHeader->nodeSize;

    /* Need to buffer current node, map will keep moving */
    nodeBuf = cli_max_malloc(nodeSize);
    if (!nodeBuf) {
        cli_dbgmsg("hfsplus_walk_catalog: failed to acquire node buffer, "
                   "size " STDu32 "\n",
                   nodeSize);
        return CL_EMEM;
    }

    /* Walk catalog leaf nodes, and scan contents of each */
    /* Because we want to scan them all, the index nodes add no value */
    while (status == CL_SUCCESS) {
        hfsNodeDescriptor nodeDesc;

        if (thisNode == 0) {
            cli_dbgmsg("hfsplus_walk_catalog: reached end of leaf nodes.\n");
            goto done;
        }
        if (nodesScanned++ > nodeLimit) {
            cli_dbgmsg("hfsplus_walk_catalog: node scan limit reached.\n");
            goto done;
        }

        /* fetch node into buffer */
        status = hfsplus_fetch_node(ctx, volHeader, catHeader, extHeader, &(volHeader->catalogFile), thisNode, nodeBuf, nodeSize);
        if (status != CL_SUCCESS) {
            cli_dbgmsg("hfsplus_walk_catalog: node fetch failed.\n");
            goto done;
        }
        memcpy(&nodeDesc, nodeBuf, 14);

        /* convert and validate node */
        nodedescriptor_to_host(&nodeDesc);
        nodedescriptor_print("leaf node", &nodeDesc);
        if ((nodeDesc.kind != HFS_NODEKIND_LEAF) || (nodeDesc.height != 1)) {
            cli_dbgmsg("hfsplus_walk_catalog: invalid leaf node!\n");
            status = CL_EFORMAT;
            goto done;
        }
        if ((nodeSize / 4) < nodeDesc.numRecords) {
            cli_dbgmsg("hfsplus_walk_catalog: too many leaf records for one node!\n");
            status = CL_EFORMAT;
            goto done;
        }

        /* Walk this node's records and scan */
        recordStart = 14; /* 1st record can be after end of node descriptor */
        /* offsets take 1 u16 per at the end of the node, along with an empty space offset */
        topOfOffsets = nodeSize - (nodeDesc.numRecords * 2) - 2;
        for (recordNum = 0; recordNum < nodeDesc.numRecords; recordNum++) {
            uint16_t keylen;
            int16_t rectype;
            hfsPlusCatalogFile fileRec;
            name_utf8 = NULL;

            /* Locate next record */
            nextDist  = nodeSize - (recordNum * 2) - 2;
            nextStart = nodeBuf[nextDist] * 0x100 + nodeBuf[nextDist + 1];
            /* Check record location */
            if ((nextStart > topOfOffsets - 1) || (nextStart < recordStart)) {
                cli_dbgmsg("hfsplus_walk_catalog: bad record location %x for %u!\n", nextStart, recordNum);
                status = CL_EFORMAT;
                goto done;
            }
            recordStart = nextStart;
            /* Get record key length */
            keylen = nodeBuf[recordStart] * 0x100 + nodeBuf[recordStart + 1];
            keylen += keylen % 2; /* pad 1 byte if required to make 2-byte align */
            /* Validate keylen */
            if (recordStart + keylen + 4 >= topOfOffsets) {
                cli_dbgmsg("hfsplus_walk_catalog: key too long for location %x for %u!\n",
                           nextStart, recordNum);
                status = CL_EFORMAT;
                goto done;
            }
            /* Collect filename  */
            if (keylen >= 6) {
                uint16_t name_length = (nodeBuf[recordStart + 2 + 4] << 8) | nodeBuf[recordStart + 2 + 4 + 1];
                char *index          = (char *)&nodeBuf[recordStart + 2 + 4 + 2];
                if ((name_length > 0) && (name_length * 2 <= keylen - 2 - 4)) {
                    /*
                     * The name is contained in nodeBuf[recordStart + 2 + 4 + 2 : recordStart + 2 + 4 + 2 + name_length * 2] encoded as UTF-16BE.
                     */
                    if (CL_SUCCESS != cli_codepage_to_utf8((char *)index, name_length * 2, CODEPAGE_UTF16_BE, &name_utf8, &name_utf8_size)) {
                        cli_errmsg("hfsplus_walk_catalog: failed to convert UTF-16BE to UTF-8\n");
                        name_utf8 = NULL;
                    }
                    cli_dbgmsg("hfsplus_walk_catalog: Extracting file %s\n", name_utf8);
                }
            }
            /* Copy type (after key, which is after keylength field) */
            memcpy(&rectype, &(nodeBuf[recordStart + keylen + 2]), 2);
            rectype = be16_to_host(rectype);
            cli_dbgmsg("hfsplus_walk_catalog: record %u nextStart %x keylen %u type %d\n",
                       recordNum, nextStart, keylen, rectype);
            /* Non-file records are not needed */
            if (rectype != HFSPLUS_RECTYPE_FILE) {
                if (NULL != name_utf8) {
                    free(name_utf8);
                    name_utf8 = NULL;
                }
                continue;
            }
            /* Check file record location */
            if (recordStart + keylen + 2 + sizeof(hfsPlusCatalogFile) >= topOfOffsets) {
                cli_dbgmsg("hfsplus_walk_catalog: not enough bytes for file record!\n");
                status = CL_EFORMAT;
                goto done;
            }
            memcpy(&fileRec, &(nodeBuf[recordStart + keylen + 2]), sizeof(hfsPlusCatalogFile));

            /* Only scan files */
            fileRec.fileID               = be32_to_host(fileRec.fileID);
            fileRec.permissions.fileMode = be16_to_host(fileRec.permissions.fileMode);
            if ((fileRec.permissions.fileMode & HFS_MODE_TYPEMASK) == HFS_MODE_FILE) {
                int compressed = 0;
                uint8_t attribute[8192];
                size_t attributeSize = sizeof(attribute);

                /* Convert forks and scan */
                forkdata_to_host(&(fileRec.dataFork));
                forkdata_print("data fork:", &(fileRec.dataFork));
                forkdata_to_host(&(fileRec.resourceFork));
                forkdata_print("resource fork:", &(fileRec.resourceFork));

                if (hfsplus_check_attribute(ctx, volHeader, attrHeader, fileRec.fileID, COMPRESSED_ATTR, sizeof(COMPRESSED_ATTR), &compressed, attribute, &attributeSize) != CL_SUCCESS) {
                    cli_dbgmsg("hfsplus_walk_catalog: Failed to check compressed attribute, assuming no compression\n");
                }

                if (compressed) {
                    hfsPlusCompressionHeader header;
                    cli_dbgmsg("hfsplus_walk_catalog: File is compressed\n");

                    if (attributeSize < sizeof(header)) {
                        cli_warnmsg("hfsplus_walk_catalog: Error: Compression attribute size is less than the compression header\n");
                        status = CL_EFORMAT;
                        goto done;
                    }

                    memcpy(&header, attribute, sizeof(header));
                    // In the sample I had (12de189078b1e260d669a2b325d688a3a39cb5b9697e00fb1777e1ecc64f4e91), this was stored in little endian.
                    // According to the doc, it should be in big endian.

                    if (header.magic == DECMPFS_HEADER_MAGIC_LE) {
                        header.magic           = cbswap32(header.magic);
                        header.compressionType = cbswap32(header.compressionType);
                        header.fileSize        = cbswap64(header.fileSize);
                    }

                    if (header.magic != DECMPFS_HEADER_MAGIC) {
                        cli_dbgmsg("hfsplus_walk_catalog: Unexpected magic value for compression header: 0x%08x\n", header.magic);
                        status = CL_EFORMAT;
                        goto done;
                    }

                    /* open file */
                    status = cli_gentempfd(dirname, &tmpname, &ofd);
                    if (status != CL_SUCCESS) {
                        cli_dbgmsg("hfsplus_walk_catalog: Cannot generate temporary file.\n");
                        goto done;
                    }

                    cli_dbgmsg("Found compressed file type %u size %" PRIu64 "\n", header.compressionType, header.fileSize);
                    switch (header.compressionType) {
                        case HFSPLUS_COMPRESSION_INLINE: {
                            size_t written;
                            if (attributeSize < sizeof(header) + 1) {
                                cli_dbgmsg("hfsplus_walk_catalog: Unexpected end of stream, no compression flag\n");
                                status = CL_EFORMAT;
                                goto done;
                            }

                            if ((attribute[sizeof(header)] & 0x0f) == 0x0f) { // Data is stored uncompressed
                                if (attributeSize - sizeof(header) - 1 != header.fileSize) {
                                    cli_dbgmsg("hfsplus_walk_catalog: Expected file size different from size of data available\n");
                                    status = CL_EFORMAT;
                                    goto done;
                                }

                                written = cli_writen(ofd, &attribute[sizeof(header) + 1], header.fileSize);
                            } else {
                                z_stream stream;
                                int z_ret;

                                if (header.fileSize > 65536) {
                                    cli_dbgmsg("hfsplus_walk_catalog: Uncompressed file seems too big, something is probably wrong\n");
                                    status = CL_EFORMAT;
                                    goto done;
                                }

                                uncompressed = malloc(header.fileSize);
                                if (!uncompressed) {
                                    cli_dbgmsg("hfsplus_walk_catalog: Failed to allocate memory for the uncompressed file contents\n");
                                    status = CL_EMEM;
                                    goto done;
                                }

                                stream.zalloc    = Z_NULL;
                                stream.zfree     = Z_NULL;
                                stream.opaque    = Z_NULL;
                                stream.avail_in  = attributeSize - sizeof(header);
                                stream.next_in   = &attribute[sizeof(header)];
                                stream.avail_out = header.fileSize;
                                stream.next_out  = uncompressed;

                                z_ret = inflateInit2(&stream, 15 /* maximum windowBits size */);
                                if (z_ret != Z_OK) {
                                    switch (z_ret) {
                                        case Z_MEM_ERROR:
                                            cli_dbgmsg("hfsplus_walk_catalog: inflateInit2: out of memory!\n");
                                            break;
                                        case Z_VERSION_ERROR:
                                            cli_dbgmsg("hfsplus_walk_catalog: inflateinit2: zlib version error!\n");
                                            break;
                                        case Z_STREAM_ERROR:
                                            cli_dbgmsg("hfsplus_walk_catalog: inflateinit2: zlib stream error!\n");
                                            break;
                                        default:
                                            cli_dbgmsg("hfsplus_walk_catalog: inflateInit2: unknown error %d\n", z_ret);
                                            break;
                                    }

                                    status = CL_EFORMAT;
                                    goto done;
                                }

                                z_ret = inflate(&stream, Z_NO_FLUSH);
                                if (z_ret != Z_OK && z_ret != Z_STREAM_END) {
                                    cli_dbgmsg("hfsplus_walk_catalog: inflateSync failed to extract compressed stream (%d)\n", z_ret);
                                    status = CL_EFORMAT;
                                    goto done;
                                }

                                z_ret = inflateEnd(&stream);
                                if (z_ret == Z_STREAM_ERROR) {
                                    cli_dbgmsg("hfsplus_walk_catalog: inflateEnd failed (%d)\n", z_ret);
                                }

                                written = cli_writen(ofd, uncompressed, header.fileSize);

                                extracted_file = true;

                                free(uncompressed);
                                uncompressed = NULL;
                            }
                            if (written != header.fileSize) {
                                cli_errmsg("hfsplus_walk_catalog: write error\n");
                                status = CL_EWRITE;
                                goto done;
                            }

                            break;
                        }
                        case HFSPLUS_COMPRESSION_RESOURCE: {
                            // FIXME: This is hackish. We're assuming (which is
                            // correct according to the spec) that there's only
                            // one resource, and that it's the compressed data.
                            // Ideally we should check that there is only one
                            // resource, that its type is correct, and that its
                            // name is cmpf.
                            size_t written = 0;

                            // 4096 is an approximative value, there should be
                            // at least 16 (resource header) + 30 (map header) +
                            // 4096 bytes (data that doesn't fit in an
                            // attribute)
                            if (fileRec.resourceFork.logicalSize < 4096) {
                                cli_dbgmsg("hfsplus_walk_catalog: Error: Expected more data in the compressed resource fork\n");
                                status = CL_EFORMAT;
                                goto done;
                            }

                            if ((status = hfsplus_scanfile(ctx, volHeader, extHeader, &(fileRec.resourceFork), dirname, &resourceFile, name_utf8)) != CL_SUCCESS) {
                                cli_dbgmsg("hfsplus_walk_catalog: Error while extracting the resource fork\n");
                                goto done;
                            }

                            if (NULL == resourceFile) {
                                cli_dbgmsg("hfsplus_walk_catalog: Error: hfsplus_scanfile returned no resource file\n");
                                status = CL_EFORMAT;
                                goto done;
                            }

                            if (-1 == (ifd = safe_open(resourceFile, O_RDONLY | O_BINARY))) {
                                cli_dbgmsg("hfsplus_walk_catalog: Failed to open temporary file %s\n", resourceFile);
                                status = CL_EOPEN;
                                goto done;
                            } else {
                                size_t resourceLen;
                                if (CL_SUCCESS != (status = hfsplus_seek_to_cmpf_resource(ifd, &resourceLen))) {
                                    cli_dbgmsg("hfsplus_walk_catalog: Failed to find cmpf resource in resource fork\n");
                                } else {
                                    uint32_t numBlocks;
                                    uint32_t dataOffset = lseek(ifd, 0, SEEK_CUR);

                                    if (CL_SUCCESS != (status = hfsplus_read_block_table(ifd, &numBlocks, &table))) {
                                        cli_dbgmsg("hfsplus_walk_catalog: Failed to read block table\n");
                                    } else {
                                        uint8_t block[4096];
                                        uint8_t uncompressed_block[4096];
                                        unsigned curBlock;

                                        for (curBlock = 0; status == CL_SUCCESS && curBlock < numBlocks; ++curBlock) {
                                            int z_ret;
                                            off_t blockOffset = dataOffset + table[curBlock].offset;
                                            size_t curOffset;
                                            size_t readLen;
                                            z_stream stream;
                                            int streamBeginning  = 1;
                                            int streamCompressed = 0;

                                            cli_dbgmsg("Handling block %u of %" PRIu32 " at offset %" PRIi64 " (size %u)\n", curBlock, numBlocks, (int64_t)blockOffset, table[curBlock].length);

                                            if (lseek(ifd, blockOffset, SEEK_SET) != blockOffset) {
                                                cli_dbgmsg("hfsplus_walk_catalog: Failed to seek to beginning of block\n");
                                                status = CL_ESEEK;
                                                goto done;
                                            }

                                            for (curOffset = 0; curOffset < table[curBlock].length;) {
                                                readLen = table[curBlock].length - curOffset;
                                                if (readLen > sizeof(block)) {
                                                    readLen = sizeof(block);
                                                }

                                                if (cli_readn(ifd, block, readLen) != readLen) {
                                                    cli_dbgmsg("hfsplus_walk_catalog: Failed to read block from temporary file\n");
                                                    status = CL_EREAD;
                                                    goto done;
                                                }

                                                if (streamBeginning) {
                                                    streamCompressed = (block[0] & 0x0f) != 0x0f;

                                                    if (streamCompressed) {
                                                        cli_dbgmsg("Current stream is compressed\n");
                                                        stream.zalloc    = Z_NULL;
                                                        stream.zfree     = Z_NULL;
                                                        stream.opaque    = Z_NULL;
                                                        stream.avail_in  = readLen;
                                                        stream.next_in   = block;
                                                        stream.avail_out = sizeof(uncompressed_block);
                                                        stream.next_out  = uncompressed_block;

                                                        if (Z_OK != (z_ret = inflateInit2(&stream, 15))) {
                                                            cli_dbgmsg("hfsplus_walk_catalog: inflateInit2 failed (%d)\n", z_ret);
                                                            status = CL_EFORMAT;
                                                            goto done;
                                                        }
                                                    }
                                                }

                                                if (streamCompressed) {
                                                    stream.avail_in  = readLen;
                                                    stream.next_in   = block;
                                                    stream.avail_out = sizeof(uncompressed_block);
                                                    stream.next_out  = uncompressed_block;

                                                    while (stream.avail_in > 0) {
                                                        z_ret = inflate(&stream, Z_NO_FLUSH);
                                                        if (z_ret != Z_OK && z_ret != Z_STREAM_END) {
                                                            cli_dbgmsg("hfsplus_walk_catalog: Failed to extract (%d)\n", z_ret);
                                                            status = CL_EFORMAT;
                                                            goto done;
                                                        }

                                                        if (cli_writen(ofd, &uncompressed_block, sizeof(uncompressed_block) - stream.avail_out) != sizeof(uncompressed_block) - stream.avail_out) {
                                                            cli_dbgmsg("hfsplus_walk_catalog: Failed to write to temporary file\n");
                                                            status = CL_EWRITE;
                                                            goto done;
                                                        }
                                                        written += sizeof(uncompressed_block) - stream.avail_out;
                                                        stream.avail_out = sizeof(uncompressed_block);
                                                        stream.next_out  = uncompressed_block;

                                                        extracted_file = true;

                                                        if (stream.avail_in > 0 && Z_STREAM_END == z_ret) {
                                                            cli_dbgmsg("hfsplus_walk_catalog: Reached end of stream even though there's still some available bytes left!\n");
                                                            break;
                                                        }
                                                    }
                                                } else {
                                                    if (cli_writen(ofd, &block[streamBeginning ? 1 : 0], readLen - (streamBeginning ? 1 : 0)) != readLen - (streamBeginning ? 1 : 0)) {
                                                        cli_dbgmsg("hfsplus_walk_catalog: Failed to write to temporary file\n");
                                                        status = CL_EWRITE;
                                                        goto done;
                                                    }
                                                    written += readLen - (streamBeginning ? 1 : 0);

                                                    extracted_file = true;
                                                }

                                                curOffset += readLen;
                                                streamBeginning = 0;
                                            }

                                            if (Z_OK != (z_ret = inflateEnd(&stream))) {
                                                cli_dbgmsg("hfsplus_walk_catalog: inflateEnd failed (%d)\n", z_ret);
                                                status = CL_EFORMAT;
                                                goto done;
                                            }
                                        }

                                        cli_dbgmsg("hfsplus_walk_catalog: Extracted compressed file from resource fork to %s (size %zu)\n", tmpname, written);

                                        if (table) {
                                            free(table);
                                            table = NULL;
                                        }
                                    }
                                }
                            }

                            if (!ctx->engine->keeptmp) {
                                if (cli_unlink(resourceFile)) {
                                    status = CL_EUNLINK;
                                    goto done;
                                }
                            }
                            free(resourceFile);
                            resourceFile = NULL;

                            cli_dbgmsg("hfsplus_walk_catalog: Resource compression not implemented\n");
                            break;
                        }
                        default:
                            cli_dbgmsg("hfsplus_walk_catalog: Unknown compression type %u\n", header.compressionType);
                            break;
                    }

                    if (tmpname) {
                        if (extracted_file) {
                            cli_dbgmsg("hfsplus_walk_catalog: Extracted to %s\n", tmpname);

                            /* Scan the extracted file */
                            status = cli_magic_scan_desc(ofd, tmpname, ctx, name_utf8, LAYER_ATTRIBUTES_NONE);
                            if (status != CL_SUCCESS) {
                                goto done;
                            }
                        }

                        if (!ctx->engine->keeptmp) {
                            if (cli_unlink(tmpname)) {
                                status = CL_EUNLINK;
                                goto done;
                            }
                        }

                        free(tmpname);
                        tmpname = NULL;
                    }

                    if (ofd >= 0) {
                        close(ofd);
                        ofd = -1;
                    }
                }

                /* Scan data fork */
                if (fileRec.dataFork.logicalSize) {
                    status = hfsplus_scanfile(ctx, volHeader, extHeader, &(fileRec.dataFork), dirname, NULL, name_utf8);
                    if (status != CL_SUCCESS) {
                        cli_dbgmsg("hfsplus_walk_catalog: data fork retcode %d\n", status);
                        goto done;
                    }
                }
                /* Scan resource fork */
                if (fileRec.resourceFork.logicalSize) {
                    status = hfsplus_scanfile(ctx, volHeader, extHeader, &(fileRec.resourceFork), dirname, NULL, name_utf8);
                    if (status != CL_SUCCESS) {
                        cli_dbgmsg("hfsplus_walk_catalog: resource fork retcode %d", status);
                        goto done;
                    }
                }
            } else {
                cli_dbgmsg("hfsplus_walk_catalog: record mode %o is not File\n", fileRec.permissions.fileMode);
            }

            if (NULL != name_utf8) {
                free(name_utf8);
                name_utf8 = NULL;
            }
        }

        /* After that, proceed to next node */
        if (thisNode == nodeDesc.fLink) {
            /* TODO: Add heuristic alert? */
            cli_warnmsg("hfsplus_walk_catalog: simple cycle detected!\n");
            status = CL_EFORMAT;
            goto done;
        } else {
            thisNode = nodeDesc.fLink;
        }
    }

done:
    if (table) {
        free(table);
    }
    if (-1 != ifd) {
        close(ifd);
    }
    if (-1 != ofd) {
        close(ofd);
    }
    if (NULL != resourceFile) {
        if (!ctx->engine->keeptmp) {
            (void)cli_unlink(resourceFile);
        }
        free(resourceFile);
    }
    if (NULL != tmpname) {
        if (!ctx->engine->keeptmp) {
            if (cli_unlink(tmpname)) {
                status = CL_EUNLINK;
                goto done;
            }
        }
        free(tmpname);
    }
    if (NULL != nodeBuf) {
        free(nodeBuf);
    }
    if (NULL != name_utf8) {
        free(name_utf8);
    }
    if (NULL != uncompressed) {
        free(uncompressed);
    }

    return status;
}

/* Base scan function for scanning HFS+ or HFSX partitions */
cl_error_t cli_scanhfsplus(cli_ctx *ctx)
{
    cl_error_t status = CL_SUCCESS;
    cl_error_t ret;
    char *targetdir                = NULL;
    hfsPlusVolumeHeader *volHeader = NULL;
    hfsNodeDescriptor catFileDesc;
    hfsHeaderRecord catFileHeader;
    hfsNodeDescriptor extentFileDesc;
    hfsHeaderRecord extentFileHeader;
    hfsNodeDescriptor attributesFileDesc;
    hfsHeaderRecord attributesFileHeader;
    int hasAttributesFileHeader = 0;

    if (!ctx || !ctx->fmap) {
        cli_errmsg("cli_scanhfsplus: Invalid context\n");
        status = CL_ENULLARG;
        goto done;
    }

    cli_dbgmsg("cli_scanhfsplus: scanning partition content\n");
    /* first, read volume header contents */
    status = hfsplus_volumeheader(ctx, &volHeader);
    if (status != CL_SUCCESS) {
        goto done;
    }

    /*
cli_dbgmsg("sizeof(hfsUniStr255) is %lu\n", sizeof(hfsUniStr255));
cli_dbgmsg("sizeof(hfsPlusBSDInfo) is %lu\n", sizeof(hfsPlusBSDInfo));
cli_dbgmsg("sizeof(hfsPlusExtentDescriptor) is %lu\n", sizeof(hfsPlusExtentDescriptor));
cli_dbgmsg("sizeof(hfsPlusExtentRecord) is %lu\n", sizeof(hfsPlusExtentRecord));
cli_dbgmsg("sizeof(hfsPlusForkData) is %lu\n", sizeof(hfsPlusForkData));
cli_dbgmsg("sizeof(hfsPlusVolumeHeader) is %lu\n", sizeof(hfsPlusVolumeHeader));
cli_dbgmsg("sizeof(hfsNodeDescriptor) is %lu\n", sizeof(hfsNodeDescriptor));
 */

    /* Get root node (header node) of extent overflow file */
    status = hfsplus_readheader(ctx, volHeader, &extentFileDesc, &extentFileHeader, HFS_FILETREE_EXTENTS, "extentFile");
    if (status != CL_SUCCESS) {
        goto done;
    }
    /* Get root node (header node) of catalog file */
    status = hfsplus_readheader(ctx, volHeader, &catFileDesc, &catFileHeader, HFS_FILETREE_CATALOG, "catalogFile");
    if (status != CL_SUCCESS) {
        goto done;
    }

    /* Get root node (header node) of attributes file */
    ret = hfsplus_readheader(ctx, volHeader, &attributesFileDesc, &attributesFileHeader, HFS_FILETREE_ATTRIBUTES, "attributesFile");
    if (ret == CL_SUCCESS) {
        hasAttributesFileHeader = 1;
    } else {
        hasAttributesFileHeader = 0;
    }

    /* Create temp folder for contents */
    if (!(targetdir = cli_gentemp_with_prefix(ctx->this_layer_tmpdir, "hfsplus-tmp"))) {
        cli_errmsg("cli_scanhfsplus: cli_gentemp failed\n");
        status = CL_ETMPDIR;
        goto done;
    }
    if (mkdir(targetdir, 0700)) {
        cli_errmsg("cli_scanhfsplus: Cannot create temporary directory %s\n", targetdir);
        status = CL_ETMPDIR;
        goto done;
    }
    cli_dbgmsg("cli_scanhfsplus: Extracting into %s\n", targetdir);

    /* Can build and scan catalog file if we want ***
    ret = hfsplus_scanfile(ctx, volHeader, &extentFileHeader, &(volHeader->catalogFile), targetdir);
     */

    status = hfsplus_validate_catalog(ctx, volHeader, &catFileHeader);
    if (status == CL_SUCCESS) {
        cli_dbgmsg("cli_scanhfsplus: validation successful\n");
    } else {
        cli_dbgmsg("cli_scanhfsplus: validation returned %d : %s\n", status, cl_strerror(status));
        goto done;
    }

    /* Walk through catalog to identify files to scan */
    status = hfsplus_walk_catalog(ctx, volHeader, &catFileHeader, &extentFileHeader, hasAttributesFileHeader ? &attributesFileHeader : NULL, targetdir);
    if (status != CL_SUCCESS) {
        goto done;
    }

done:
    if (NULL != targetdir) {
        /* Clean up extracted content, if needed */
        if (!ctx->engine->keeptmp) {
            (void)cli_rmdirs(targetdir);
        }
        free(targetdir);
    }
    if (NULL != volHeader) {
        free(volHeader);
    }

    return status;
}

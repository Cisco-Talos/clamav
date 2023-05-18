/*
 *  Copyright (C) 2013-2022 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
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

static int hfsplus_volumeheader(cli_ctx *, hfsPlusVolumeHeader **);
static int hfsplus_readheader(cli_ctx *, hfsPlusVolumeHeader *, hfsNodeDescriptor *,
                              hfsHeaderRecord *, int, const char *);
static cl_error_t hfsplus_scanfile(cli_ctx *, hfsPlusVolumeHeader *, hfsHeaderRecord *,
                                   hfsPlusForkData *, const char *, char **, char *);
static int hfsplus_validate_catalog(cli_ctx *, hfsPlusVolumeHeader *, hfsHeaderRecord *);
static int hfsplus_fetch_node(cli_ctx *, hfsPlusVolumeHeader *, hfsHeaderRecord *,
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
static int hfsplus_volumeheader(cli_ctx *ctx, hfsPlusVolumeHeader **header)
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

    volHeader = cli_malloc(sizeof(hfsPlusVolumeHeader));
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
static int hfsplus_readheader(cli_ctx *ctx, hfsPlusVolumeHeader *volHeader, hfsNodeDescriptor *nodeDesc,
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
 * @param filename      [out] (optional) temp file name
 * @param orig_filename (optiopnal) Original filename
 * @return cl_error_t
 */
static cl_error_t hfsplus_scanfile(cli_ctx *ctx, hfsPlusVolumeHeader *volHeader, hfsHeaderRecord *extHeader,
                                   hfsPlusForkData *fork, const char *dirname, char **filename, char *orig_filename)
{
    hfsPlusExtentDescriptor *currExt;
    const uint8_t *mPtr = NULL;
    char *tmpname       = NULL;
    int ofd;
    cl_error_t ret = CL_CLEAN;
    uint64_t targetSize;
    uint32_t outputBlocks = 0;
    uint8_t ext;

    UNUSEDPARAM(extHeader);

    /* bad record checks */
    if (!fork || (fork->logicalSize == 0) || (fork->totalBlocks == 0)) {
        cli_dbgmsg("hfsplus_scanfile: Empty file.\n");
        return CL_CLEAN;
    }

    /* check limits */
    targetSize = fork->logicalSize;
#if SIZEOF_LONG < 8
    if (targetSize > ULONG_MAX) {
        cli_dbgmsg("hfsplus_scanfile: File too large for limit check.\n");
        return CL_EFORMAT;
    }
#endif
    ret = cli_checklimits("hfsplus_scanfile", ctx, (unsigned long)targetSize, 0, 0);
    if (ret != CL_CLEAN) {
        return ret;
    }

    /* open file */
    ret = cli_gentempfd(dirname, &tmpname, &ofd);
    if (ret != CL_CLEAN) {
        cli_dbgmsg("hfsplus_scanfile: Cannot generate temporary file.\n");
        return ret;
    }
    cli_dbgmsg("hfsplus_scanfile: Extracting to %s\n", tmpname);

    ext = 0;
    /* Dump file, extent by extent */
    do {
        uint32_t currBlock, endBlock, outputSize = 0;
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
            ret = CL_EFORMAT;
            break;
        }
        /* have extent, so validate and get block range */
        if ((currExt->startBlock == 0) || (currExt->blockCount == 0)) {
            cli_dbgmsg("hfsplus_scanfile: next extent empty, done\n");
            break;
        }
        if ((currExt->startBlock & 0x10000000) && (currExt->blockCount & 0x10000000)) {
            cli_dbgmsg("hfsplus_scanfile: next extent illegal!\n");
            ret = CL_EFORMAT;
            break;
        }
        currBlock = currExt->startBlock;
        endBlock  = currExt->startBlock + currExt->blockCount - 1;
        if ((currBlock > volHeader->totalBlocks) || (endBlock > volHeader->totalBlocks) || (currExt->blockCount > volHeader->totalBlocks)) {
            cli_dbgmsg("hfsplus_scanfile: bad extent!\n");
            ret = CL_EFORMAT;
            break;
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
                ret = CL_EMAP;
                break;
            }
            written = cli_writen(ofd, mPtr, to_write);
            if (written != to_write) {
                cli_errmsg("hfsplus_scanfile: write error\n");
                ret = CL_EWRITE;
                break;
            }
            targetSize -= to_write;
            outputSize += to_write;
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
    } while (ret == CL_CLEAN);

    /* if successful so far, scan the output */
    if (filename) {
        *filename = tmpname;
    } else {
        if (ret == CL_CLEAN) {
            ret = cli_magic_scan_desc(ofd, tmpname, ctx, orig_filename);
        }

        if (!ctx->engine->keeptmp) {
            if (cli_unlink(tmpname)) {
                ret = CL_EUNLINK;
            }
        }
        free(tmpname);
    }

    if (ofd >= 0) {
        close(ofd);
    }

    return ret;
}

/* Calculate true node limit for catalogFile */
static int hfsplus_validate_catalog(cli_ctx *ctx, hfsPlusVolumeHeader *volHeader, hfsHeaderRecord *catHeader)
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
static cl_error_t hfsplus_check_attribute(cli_ctx *ctx, hfsPlusVolumeHeader *volHeader, hfsHeaderRecord *attrHeader, uint32_t expectedCnid, const uint8_t name[], uint32_t nameLen, int *found, uint8_t record[], unsigned *recordSize)
{
    uint16_t nodeSize, recordNum, topOfOffsets;
    uint16_t recordStart, nextDist, nextStart;
    uint8_t *nodeBuf = NULL;
    uint32_t thisNode, nodeLimit, nodesScanned = 0;
    cl_error_t ret = CL_SUCCESS;
    int foundAttr  = 0;

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
    nodeBuf = cli_malloc(nodeSize);
    if (!nodeBuf) {
        cli_dbgmsg("hfsplus_check_attribute: failed to acquire node buffer, "
                   "size " STDu32 "\n",
                   nodeSize);
        return CL_EMEM;
    }

    /* Walk catalog leaf nodes, and scan contents of each */
    /* Because we want to scan them all, the index nodes add no value */
    while (ret == CL_CLEAN && !foundAttr) {
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
        ret = hfsplus_fetch_node(ctx, volHeader, attrHeader, NULL, &(volHeader->attributesFile), thisNode, nodeBuf, nodeSize);
        if (ret != CL_CLEAN) {
            cli_dbgmsg("hfsplus_check_attribute: node fetch failed.\n");
            break;
        }
        memcpy(&nodeDesc, nodeBuf, 14);

        /* convert and validate node */
        nodedescriptor_to_host(&nodeDesc);
        nodedescriptor_print("leaf attribute node", &nodeDesc);
        if ((nodeDesc.kind != HFS_NODEKIND_LEAF) || (nodeDesc.height != 1)) {
            cli_dbgmsg("hfsplus_check_attribute: invalid leaf node!\n");
            ret = CL_EFORMAT;
            break;
        }
        if ((nodeSize / 4) < nodeDesc.numRecords) {
            cli_dbgmsg("hfsplus_check_attribute: too many leaf records for one node!\n");
            ret = CL_EFORMAT;
            break;
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
                ret = CL_EFORMAT;
                break;
            }
            recordStart = nextStart;
            if (recordStart + sizeof(attrKey) >= topOfOffsets) {
                cli_dbgmsg("hfsplus_check_attribute: Not enough data for an attribute key at location %x for %u!\n",
                           nextStart, recordNum);
                ret = CL_EFORMAT;
                break;
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
                ret = CL_EFORMAT;
                break;
            }

            if (recordStart + sizeof(hfsPlusAttributeKey) + attrKey.nameLength >= topOfOffsets) {
                cli_dbgmsg("hfsplus_check_attribute: Attribute name is longer than expected: %u\n", attrKey.nameLength);
                ret = CL_EFORMAT;
                break;
            }

            if (attrKey.cnid == expectedCnid && attrKey.nameLength * 2 == nameLen && memcmp(&nodeBuf[recordStart + 14], name, nameLen) == 0) {
                memcpy(&attrRec, &(nodeBuf[recordStart + sizeof(hfsPlusAttributeKey) + attrKey.nameLength * 2]), sizeof(attrRec));
                attrRec.recordType    = be32_to_host(attrRec.recordType);
                attrRec.attributeSize = be32_to_host(attrRec.attributeSize);

                if (attrRec.recordType != HFSPLUS_RECTYPE_INLINE_DATA_ATTRIBUTE) {
                    cli_dbgmsg("hfsplus_check_attribute: Unexpected attribute record type 0x%x\n", attrRec.recordType);
                    continue;
                }

                if (found) {
                    *found = 1;
                }

                if (attrRec.attributeSize > *recordSize) {
                    ret = CL_EMAXSIZE;
                    break;
                }

                memcpy(record, &(nodeBuf[recordStart + sizeof(hfsPlusAttributeKey) + attrKey.nameLength * 2 + sizeof(attrRec)]), attrRec.attributeSize);
                *recordSize = attrRec.attributeSize;

                ret       = CL_SUCCESS;
                foundAttr = 1;
                break;
            }
        }
    }

    if (nodeBuf != NULL) {
        free(nodeBuf);
        nodeBuf = NULL;
    }
    return ret;
}

/* Fetch a node's contents into the buffer */
static int hfsplus_fetch_node(cli_ctx *ctx, hfsPlusVolumeHeader *volHeader, hfsHeaderRecord *catHeader,
                              hfsHeaderRecord *extHeader, hfsPlusForkData *catFork, uint32_t node, uint8_t *buff,
                              size_t buffSize)
{
    int foundBlock = 0;
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

        foundBlock  = 0;
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
                foundBlock    = 1;
                break;
            } else {
                cli_dbgmsg("hfsplus_fetch_node: not in extent " STDu32 "\n", extentNum);
                searchBlock -= currExt->blockCount;
            }
        }

        if (foundBlock == 0) {
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
    hfsPlusResourceHeader resourceHeader;
    hfsPlusResourceMap resourceMap;
    hfsPlusResourceType resourceType;
    hfsPlusReferenceEntry entry;
    int i;
    int cmpfInstanceIdx = -1;
    int curInstanceIdx  = 0;
    size_t dataOffset;
    uint32_t dataLength;
    cl_error_t ret = CL_SUCCESS;

    if (!size) {
        ret = CL_ENULLARG;
        goto done;
    }

    if (cli_readn(fd, &resourceHeader, sizeof(resourceHeader)) != sizeof(resourceHeader)) {
        cli_dbgmsg("hfsplus_seek_to_cmpf_resource: Failed to read resource header from temporary file\n");
        ret = CL_EREAD;
        goto done;
    }

    resourceHeader.dataOffset = be32_to_host(resourceHeader.dataOffset);
    resourceHeader.mapOffset  = be32_to_host(resourceHeader.mapOffset);
    resourceHeader.dataLength = be32_to_host(resourceHeader.dataLength);
    resourceHeader.mapLength  = be32_to_host(resourceHeader.mapLength);

    //TODO: Need to get offset of cmpf resource in data stream

    if (lseek(fd, resourceHeader.mapOffset, SEEK_SET) != resourceHeader.mapOffset) {
        cli_dbgmsg("hfsplus_seek_to_cmpf_resource: Failed to seek to map in temporary file\n");
        ret = CL_ESEEK;
        goto done;
    }

    if (cli_readn(fd, &resourceMap, sizeof(resourceMap)) != sizeof(resourceMap)) {
        cli_dbgmsg("hfsplus_seek_to_cmpf_resource: Failed to read resource map from temporary file\n");
        ret = CL_EREAD;
        goto done;
    }

    resourceMap.resourceForkAttributes = be16_to_host(resourceMap.resourceForkAttributes);
    resourceMap.typeListOffset         = be16_to_host(resourceMap.typeListOffset);
    resourceMap.nameListOffset         = be16_to_host(resourceMap.nameListOffset);
    resourceMap.typeCount              = be16_to_host(resourceMap.typeCount);

    for (i = 0; i < resourceMap.typeCount + 1; ++i) {
        if (cli_readn(fd, &resourceType, sizeof(resourceType)) != sizeof(resourceType)) {
            cli_dbgmsg("hfsplus_seek_to_cmpf_resource: Failed to read resource type from temporary file\n");
            ret = CL_EREAD;
            goto done;
        }
        resourceType.instanceCount       = be16_to_host(resourceType.instanceCount);
        resourceType.referenceListOffset = be16_to_host(resourceType.referenceListOffset);

        if (memcmp(resourceType.type, "cmpf", 4) == 0) {
            if (cmpfInstanceIdx != -1) {
                cli_dbgmsg("hfsplus_seek_to_cmpf_resource: There are several cmpf resource types in the file\n");
                ret = CL_EFORMAT;
                goto done;
            }

            cmpfInstanceIdx = curInstanceIdx;
            cli_dbgmsg("Found compressed resource type!\n");
        }

        curInstanceIdx += resourceType.instanceCount + 1;
    }

    if (cmpfInstanceIdx < 0) {
        cli_dbgmsg("hfsplus_seek_to_cmpf_resource: Didn't find cmpf resource type\n");
        ret = CL_EFORMAT;
        goto done;
    }

    if (lseek(fd, cmpfInstanceIdx * sizeof(hfsPlusReferenceEntry), SEEK_CUR) < 0) {
        cli_dbgmsg("hfsplus_seek_to_cmpf_resource: Failed to seek to instance index\n");
        ret = CL_ESEEK;
        goto done;
    }

    if (cli_readn(fd, &entry, sizeof(entry)) != sizeof(entry)) {
        cli_dbgmsg("hfsplus_seek_to_cmpf_resource: Failed to read resource entry from temporary file\n");
        ret = CL_EREAD;
        goto done;
    }

    dataOffset = (entry.resourceDataOffset[0] << 16) | (entry.resourceDataOffset[1] << 8) | entry.resourceDataOffset[2];

    if (lseek(fd, resourceHeader.dataOffset + dataOffset, SEEK_SET) < 0) {
        cli_dbgmsg("hfsplus_seek_to_cmpf_resource: Failed to seek to data offset\n");
        ret = CL_ESEEK;
        goto done;
    }

    if (cli_readn(fd, &dataLength, sizeof(dataLength)) != sizeof(dataLength)) {
        cli_dbgmsg("hfsplus_seek_to_cmpf_resource: Failed to read data length from temporary file\n");
        ret = CL_EREAD;
        goto done;
    }

    *size = be32_to_host(dataLength);
done:
    return ret;
}

static int hfsplus_read_block_table(int fd, uint32_t *numBlocks, hfsPlusResourceBlockTable **table)
{
    uint32_t i;

    if (!table || !numBlocks) {
        return CL_ENULLARG;
    }

    if (cli_readn(fd, numBlocks, sizeof(*numBlocks)) != sizeof(*numBlocks)) {
        cli_dbgmsg("hfsplus_read_block_table: Failed to read block count\n");
        return CL_EREAD;
    }

    *numBlocks = le32_to_host(*numBlocks); //Let's do a little little endian just for fun, shall we?
    *table     = cli_malloc(sizeof(hfsPlusResourceBlockTable) * *numBlocks);
    if (!*table) {
        cli_dbgmsg("hfsplus_read_block_table: Failed to allocate memory for block table\n");
        return CL_EMEM;
    }

    if (cli_readn(fd, *table, *numBlocks * sizeof(hfsPlusResourceBlockTable)) != *numBlocks * sizeof(hfsPlusResourceBlockTable)) {
        cli_dbgmsg("hfsplus_read_block_table: Failed to read table\n");
        free(*table);
        return CL_EREAD;
    }

    for (i = 0; i < *numBlocks; ++i) {
        (*table)[i].offset = le32_to_host((*table)[i].offset);
        (*table)[i].length = le32_to_host((*table)[i].length);
    }

    return CL_SUCCESS;
}

/* Given the catalog and other details, scan all the volume contents */
static cl_error_t hfsplus_walk_catalog(cli_ctx *ctx, hfsPlusVolumeHeader *volHeader, hfsHeaderRecord *catHeader,
                                       hfsHeaderRecord *extHeader, hfsHeaderRecord *attrHeader, const char *dirname)
{
    cl_error_t ret          = CL_SUCCESS;
    unsigned int has_alerts = 0;
    uint32_t thisNode, nodeLimit, nodesScanned = 0;
    uint16_t nodeSize, recordNum, topOfOffsets;
    uint16_t recordStart, nextDist, nextStart;
    uint8_t *nodeBuf                = NULL;
    const uint8_t COMPRESSED_ATTR[] = {0, 'c', 0, 'o', 0, 'm', 0, '.', 0, 'a', 0, 'p', 0, 'p', 0, 'l', 0, 'e', 0, '.', 0, 'd', 0, 'e', 0, 'c', 0, 'm', 0, 'p', 0, 'f', 0, 's'};
    char *tmpname                   = NULL;
    uint8_t *uncompressed           = NULL;
    int ofd                         = -1;
    char *name_utf8                 = NULL;
    size_t name_utf8_size           = 0;

    nodeLimit = MIN(catHeader->totalNodes, HFSPLUS_NODE_LIMIT);
    thisNode  = catHeader->firstLeafNode;
    nodeSize  = catHeader->nodeSize;

    /* Need to buffer current node, map will keep moving */
    nodeBuf = cli_malloc(nodeSize);
    if (!nodeBuf) {
        cli_dbgmsg("hfsplus_walk_catalog: failed to acquire node buffer, "
                   "size " STDu32 "\n",
                   nodeSize);
        return CL_EMEM;
    }

    /* Walk catalog leaf nodes, and scan contents of each */
    /* Because we want to scan them all, the index nodes add no value */
    while (ret == CL_SUCCESS) {
        hfsNodeDescriptor nodeDesc;

        if (thisNode == 0) {
            cli_dbgmsg("hfsplus_walk_catalog: reached end of leaf nodes.\n");
            break;
        }
        if (nodesScanned++ > nodeLimit) {
            cli_dbgmsg("hfsplus_walk_catalog: node scan limit reached.\n");
            break;
        }

        /* fetch node into buffer */
        ret = hfsplus_fetch_node(ctx, volHeader, catHeader, extHeader, &(volHeader->catalogFile), thisNode, nodeBuf, nodeSize);
        if (ret != CL_SUCCESS) {
            cli_dbgmsg("hfsplus_walk_catalog: node fetch failed.\n");
            break;
        }
        memcpy(&nodeDesc, nodeBuf, 14);

        /* convert and validate node */
        nodedescriptor_to_host(&nodeDesc);
        nodedescriptor_print("leaf node", &nodeDesc);
        if ((nodeDesc.kind != HFS_NODEKIND_LEAF) || (nodeDesc.height != 1)) {
            cli_dbgmsg("hfsplus_walk_catalog: invalid leaf node!\n");
            ret = CL_EFORMAT;
            break;
        }
        if ((nodeSize / 4) < nodeDesc.numRecords) {
            cli_dbgmsg("hfsplus_walk_catalog: too many leaf records for one node!\n");
            ret = CL_EFORMAT;
            break;
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
                ret = CL_EFORMAT;
                break;
            }
            recordStart = nextStart;
            /* Get record key length */
            keylen = nodeBuf[recordStart] * 0x100 + nodeBuf[recordStart + 1];
            keylen += keylen % 2; /* pad 1 byte if required to make 2-byte align */
            /* Validate keylen */
            if (recordStart + keylen + 4 >= topOfOffsets) {
                cli_dbgmsg("hfsplus_walk_catalog: key too long for location %x for %u!\n",
                           nextStart, recordNum);
                ret = CL_EFORMAT;
                break;
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
                ret = CL_EFORMAT;
                break;
            }
            memcpy(&fileRec, &(nodeBuf[recordStart + keylen + 2]), sizeof(hfsPlusCatalogFile));

            /* Only scan files */
            fileRec.fileID               = be32_to_host(fileRec.fileID);
            fileRec.permissions.fileMode = be16_to_host(fileRec.permissions.fileMode);
            if ((fileRec.permissions.fileMode & HFS_MODE_TYPEMASK) == HFS_MODE_FILE) {
                int compressed = 0;
                uint8_t attribute[8192];
                unsigned attributeSize = sizeof(attribute);

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
                        ret = CL_EFORMAT;
                        break;
                    }

                    memcpy(&header, attribute, sizeof(header));
                    //In the sample I had (12de189078b1e260d669a2b325d688a3a39cb5b9697e00fb1777e1ecc64f4e91), this was stored in little endian.
                    //According to the doc, it should be in big endian.

                    if (header.magic == DECMPFS_HEADER_MAGIC_LE) {
                        header.magic           = cbswap32(header.magic);
                        header.compressionType = cbswap32(header.compressionType);
                        header.fileSize        = cbswap64(header.fileSize);
                    }

                    if (header.magic != DECMPFS_HEADER_MAGIC) {
                        cli_dbgmsg("hfsplus_walk_catalog: Unexpected magic value for compression header: 0x%08x\n", header.magic);
                        ret = CL_EFORMAT;
                        break;
                    }

                    /* open file */
                    ret = cli_gentempfd(dirname, &tmpname, &ofd);
                    if (ret != CL_SUCCESS) {
                        cli_dbgmsg("hfsplus_walk_catalog: Cannot generate temporary file.\n");
                        break;
                    }

                    cli_dbgmsg("Found compressed file type %u size %" PRIu64 "\n", header.compressionType, header.fileSize);
                    switch (header.compressionType) {
                        case HFSPLUS_COMPRESSION_INLINE: {
                            size_t written;
                            if (attributeSize < sizeof(header) + 1) {
                                cli_dbgmsg("hfsplus_walk_catalog: Unexpected end of stream, no compression flag\n");
                                ret = CL_EFORMAT;
                                break;
                            }

                            if ((attribute[sizeof(header)] & 0x0f) == 0x0f) { //Data is stored uncompressed
                                if (attributeSize - sizeof(header) - 1 != header.fileSize) {
                                    cli_dbgmsg("hfsplus_walk_catalog: Expected file size different from size of data available\n");
                                    free(tmpname);
                                    ret = CL_EFORMAT;
                                    break;
                                }

                                written = cli_writen(ofd, &attribute[sizeof(header) + 1], header.fileSize);
                            } else {
                                z_stream stream;
                                int z_ret;

                                if (header.fileSize > 65536) {
                                    cli_dbgmsg("hfsplus_walk_catalog: Uncompressed file seems too big, something is probably wrong\n");
                                    ret = CL_EFORMAT;
                                    break;
                                }

                                uncompressed = malloc(header.fileSize);
                                if (!uncompressed) {
                                    cli_dbgmsg("hfsplus_walk_catalog: Failed to allocate memory for the uncompressed file contents\n");
                                    ret = CL_EMEM;
                                    break;
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
                                            cli_dbgmsg("hfsplus_walk_catalog: inflateInit2: unknown error %d\n", ret);
                                            break;
                                    }

                                    ret = CL_EFORMAT;
                                    break;
                                }

                                z_ret = inflate(&stream, Z_NO_FLUSH);
                                if (z_ret != Z_OK && z_ret != Z_STREAM_END) {
                                    cli_dbgmsg("hfsplus_walk_catalog: inflateSync failed to extract compressed stream (%d)\n", ret);
                                    ret = CL_EFORMAT;
                                    break;
                                }

                                z_ret = inflateEnd(&stream);
                                if (z_ret == Z_STREAM_ERROR) {
                                    cli_dbgmsg("hfsplus_walk_catalog: inflateEnd failed (%d)\n", ret);
                                }

                                written = cli_writen(ofd, uncompressed, header.fileSize);
                                free(uncompressed);
                                uncompressed = NULL;
                            }
                            if (written != header.fileSize) {
                                cli_errmsg("hfsplus_walk_catalog: write error\n");
                                ret = CL_EWRITE;
                                break;
                            }

                            ret = CL_SUCCESS;
                            break;
                        }
                        case HFSPLUS_COMPRESSION_RESOURCE: {
                            //FIXME: This is hackish. We're assuming (which is
                            //correct according to the spec) that there's only
                            //one resource, and that it's the compressed data.
                            //Ideally we should check that there is only one
                            //resource, that its type is correct, and that its
                            //name is cmpf.
                            char *resourceFile = NULL;
                            int ifd            = -1;
                            size_t written     = 0;

                            //4096 is an approximative value, there should be
                            //at least 16 (resource header) + 30 (map header) +
                            //4096 bytes (data that doesn't fit in an
                            //attribute)
                            if (fileRec.resourceFork.logicalSize < 4096) {
                                cli_dbgmsg("hfsplus_walk_catalog: Error: Expected more data in the compressed resource fork\n");
                                ret = CL_EFORMAT;
                                break;
                            }

                            if ((ret = hfsplus_scanfile(ctx, volHeader, extHeader, &(fileRec.resourceFork), dirname, &resourceFile, name_utf8)) != CL_SUCCESS) {
                                cli_dbgmsg("hfsplus_walk_catalog: Error while extracting the resource fork\n");
                                if (resourceFile) {
                                    free(resourceFile);
                                }
                                break;
                            }

                            if (NULL == resourceFile) {
                                cli_dbgmsg("hfsplus_walk_catalog: Error: hfsplus_scanfile returned no resource file\n");
                                ret = CL_EFORMAT;
                                break;
                            }

                            if ((ifd = safe_open(resourceFile, O_RDONLY | O_BINARY)) == -1) {
                                cli_dbgmsg("hfsplus_walk_catalog: Failed to open temporary file %s\n", resourceFile);
                                ret = CL_EOPEN;
                            } else {
                                size_t resourceLen;
                                if ((ret = hfsplus_seek_to_cmpf_resource(ifd, &resourceLen)) != CL_SUCCESS) {
                                    cli_dbgmsg("hfsplus_walk_catalog: Failed to find cmpf resource in resource fork\n");
                                } else {
                                    hfsPlusResourceBlockTable *table = NULL;
                                    uint32_t numBlocks;
                                    uint32_t dataOffset = lseek(ifd, 0, SEEK_CUR);

                                    if ((ret = hfsplus_read_block_table(ifd, &numBlocks, &table)) != CL_SUCCESS) {
                                        cli_dbgmsg("hfsplus_walk_catalog: Failed to read block table\n");
                                    } else {
                                        uint8_t block[4096];
                                        uint8_t uncompressed[4096];
                                        unsigned curBlock;

                                        for (curBlock = 0; ret == CL_SUCCESS && curBlock < numBlocks; ++curBlock) {
                                            off_t blockOffset = dataOffset + table[curBlock].offset;
                                            size_t curOffset;
                                            size_t readLen;
                                            z_stream stream;
                                            int streamBeginning  = 1;
                                            int streamCompressed = 0;

                                            cli_dbgmsg("Handling block %u of %" PRIu32 " at offset %" PRIi64 " (size %u)\n", curBlock, numBlocks, (int64_t)blockOffset, table[curBlock].length);

                                            if (lseek(ifd, blockOffset, SEEK_SET) != blockOffset) {
                                                cli_dbgmsg("hfsplus_walk_catalog: Failed to seek to beginning of block\n");
                                                ret = CL_ESEEK;
                                                break;
                                            }

                                            for (curOffset = 0; curOffset < table[curBlock].length;) {
                                                readLen = table[curBlock].length - curOffset;
                                                if (readLen > sizeof(block)) {
                                                    readLen = sizeof(block);
                                                }

                                                if (cli_readn(ifd, block, readLen) != readLen) {
                                                    cli_dbgmsg("hfsplus_walk_catalog: Failed to read block from temporary file\n");
                                                    ret = CL_EREAD;
                                                    break;
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
                                                        stream.avail_out = sizeof(uncompressed);
                                                        stream.next_out  = uncompressed;

                                                        if ((ret = inflateInit2(&stream, 15)) != Z_OK) {
                                                            cli_dbgmsg("hfsplus_walk_catalog: inflateInit2 failed (%d)\n", ret);
                                                            ret = CL_EFORMAT;
                                                            break;
                                                        }
                                                    }
                                                }

                                                if (streamCompressed) {
                                                    stream.avail_in  = readLen;
                                                    stream.next_in   = block;
                                                    stream.avail_out = sizeof(uncompressed);
                                                    stream.next_out  = uncompressed;

                                                    while (stream.avail_in > 0) {
                                                        int z_ret = inflate(&stream, Z_NO_FLUSH);
                                                        if (z_ret != Z_OK && z_ret != Z_STREAM_END) {
                                                            cli_dbgmsg("hfsplus_walk_catalog: Failed to extract (%d)\n", z_ret);
                                                            ret = CL_EFORMAT;
                                                            break;
                                                        }
                                                        ret = CL_SUCCESS;
                                                        if (cli_writen(ofd, &uncompressed, sizeof(uncompressed) - stream.avail_out) != sizeof(uncompressed) - stream.avail_out) {
                                                            cli_dbgmsg("hfsplus_walk_catalog: Failed to write to temporary file\n");
                                                            ret = CL_EWRITE;
                                                            break;
                                                        }
                                                        written += sizeof(uncompressed) - stream.avail_out;
                                                        stream.avail_out = sizeof(uncompressed);
                                                        stream.next_out  = uncompressed;

                                                        if (stream.avail_in > 0 && Z_STREAM_END == z_ret) {
                                                            cli_dbgmsg("hfsplus_walk_catalog: Reached end of stream even though there's still some available bytes left!\n");
                                                            break;
                                                        }
                                                    }
                                                } else {
                                                    if (cli_writen(ofd, &block[streamBeginning ? 1 : 0], readLen - (streamBeginning ? 1 : 0)) != readLen - (streamBeginning ? 1 : 0)) {
                                                        cli_dbgmsg("hfsplus_walk_catalog: Failed to write to temporary file\n");
                                                        ret = CL_EWRITE;
                                                        break;
                                                    }
                                                    written += readLen - (streamBeginning ? 1 : 0);
                                                }

                                                curOffset += readLen;
                                                streamBeginning = 0;
                                            }

                                            if (ret == CL_SUCCESS) {
                                                if ((ret = inflateEnd(&stream)) != Z_OK) {
                                                    cli_dbgmsg("hfsplus_walk_catalog: inflateEnd failed (%d)\n", ret);
                                                    ret = CL_EFORMAT;
                                                } else {
                                                    ret = CL_SUCCESS;
                                                }
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
                                    ret = CL_EUNLINK;
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
                        if (ret == CL_SUCCESS) {
                            cli_dbgmsg("hfsplus_walk_catalog: Extracted to %s\n", tmpname);

                            /* if successful so far, scan the output */
                            ret = cli_magic_scan_desc(ofd, tmpname, ctx, name_utf8);

                            if (ret == CL_VIRUS) {
                                has_alerts = 1;
                                if (SCAN_ALLMATCHES) {
                                    /* Continue scanning in SCAN_ALLMATCHES mode */
                                    cli_dbgmsg("hfsplus_walk_catalog: Compressed file alert, continuing");
                                    ret = CL_SUCCESS;
                                }
                            }
                        }

                        if (!ctx->engine->keeptmp) {
                            if (cli_unlink(tmpname)) {
                                ret = CL_EUNLINK;
                            }
                        }

                        free(tmpname);
                        tmpname = NULL;
                    }
                    if (ofd >= 0) {
                        close(ofd);
                        ofd = -1;
                    }

                    if (ret != CL_SUCCESS) {
                        break;
                    }
                }

                if (fileRec.dataFork.logicalSize) {
                    ret = hfsplus_scanfile(ctx, volHeader, extHeader, &(fileRec.dataFork), dirname, NULL, name_utf8);
                }
                /* Check return code */
                if (ret == CL_VIRUS) {
                    has_alerts = 1;
                    if (SCAN_ALLMATCHES) {
                        /* Continue scanning in SCAN_ALLMATCHES mode */
                        cli_dbgmsg("hfsplus_walk_catalog: data fork alert, continuing");
                        ret = CL_CLEAN;
                    }
                }
                if (ret != CL_SUCCESS) {
                    cli_dbgmsg("hfsplus_walk_catalog: data fork retcode %d\n", ret);
                    break;
                }
                /* Scan resource fork */
                if (fileRec.resourceFork.logicalSize) {
                    ret = hfsplus_scanfile(ctx, volHeader, extHeader, &(fileRec.resourceFork), dirname, NULL, name_utf8);
                }
                /* Check return code */
                if (ret == CL_VIRUS) {
                    has_alerts = 1;
                    if (SCAN_ALLMATCHES) {
                        /* Continue scanning in SCAN_ALLMATCHES mode */
                        cli_dbgmsg("hfsplus_walk_catalog: resource fork alert, continuing");
                        ret = CL_CLEAN;
                    }
                }
                if (ret != CL_SUCCESS) {
                    cli_dbgmsg("hfsplus_walk_catalog: resource fork retcode %d", ret);
                    break;
                }
            } else {
                cli_dbgmsg("hfsplus_walk_catalog: record mode %o is not File\n", fileRec.permissions.fileMode);
            }

            if (NULL != name_utf8) {
                free(name_utf8);
                name_utf8 = NULL;
            }
        }
        /* if return code, exit loop, message already logged */
        if (ret != CL_SUCCESS) {
            break;
        }

        /* After that, proceed to next node */
        if (thisNode == nodeDesc.fLink) {
            /* Future heuristic */
            cli_warnmsg("hfsplus_walk_catalog: simple cycle detected!\n");
            ret = CL_EFORMAT;
            break;
        } else {
            thisNode = nodeDesc.fLink;
        }
    }

    free(nodeBuf);
    if (NULL != name_utf8) {
        free(name_utf8);
    }

    if (has_alerts) {
        ret = CL_VIRUS;
    }
    return ret;
}

/* Base scan function for scanning HFS+ or HFSX partitions */
cl_error_t cli_scanhfsplus(cli_ctx *ctx)
{
    char *targetdir                = NULL;
    cl_error_t ret                 = CL_SUCCESS;
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
        return CL_ENULLARG;
    }

    cli_dbgmsg("cli_scanhfsplus: scanning partition content\n");
    /* first, read volume header contents */
    ret = hfsplus_volumeheader(ctx, &volHeader);
    if (ret != CL_SUCCESS) {
        goto freeHeader;
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
    ret = hfsplus_readheader(ctx, volHeader, &extentFileDesc, &extentFileHeader, HFS_FILETREE_EXTENTS, "extentFile");
    if (ret != CL_SUCCESS) {
        goto freeHeader;
    }
    /* Get root node (header node) of catalog file */
    ret = hfsplus_readheader(ctx, volHeader, &catFileDesc, &catFileHeader, HFS_FILETREE_CATALOG, "catalogFile");
    if (ret != CL_SUCCESS) {
        goto freeHeader;
    }

    /* Get root node (header node) of attributes file */
    ret = hfsplus_readheader(ctx, volHeader, &attributesFileDesc, &attributesFileHeader, HFS_FILETREE_ATTRIBUTES, "attributesFile");
    if (ret == CL_SUCCESS) {
        hasAttributesFileHeader = 1;
    } else {
        hasAttributesFileHeader = 0;
        ret                     = CL_SUCCESS;
    }

    /* Create temp folder for contents */
    if (!(targetdir = cli_gentemp_with_prefix(ctx->sub_tmpdir, "hfsplus-tmp"))) {
        cli_errmsg("cli_scanhfsplus: cli_gentemp failed\n");
        ret = CL_ETMPDIR;
        goto freeHeader;
    }
    if (mkdir(targetdir, 0700)) {
        cli_errmsg("cli_scanhfsplus: Cannot create temporary directory %s\n", targetdir);
        ret = CL_ETMPDIR;
        goto freeDirname;
    }
    cli_dbgmsg("cli_scanhfsplus: Extracting into %s\n", targetdir);

    /* Can build and scan catalog file if we want ***
    ret = hfsplus_scanfile(ctx, volHeader, &extentFileHeader, &(volHeader->catalogFile), targetdir);
     */
    if (ret == CL_SUCCESS) {
        ret = hfsplus_validate_catalog(ctx, volHeader, &catFileHeader);
        if (ret == CL_SUCCESS) {
            cli_dbgmsg("cli_scanhfsplus: validation successful\n");
        } else {
            cli_dbgmsg("cli_scanhfsplus: validation returned %d : %s\n", ret, cl_strerror(ret));
        }
    }

    /* Walk through catalog to identify files to scan */
    if (ret == CL_SUCCESS) {
        ret = hfsplus_walk_catalog(ctx, volHeader, &catFileHeader, &extentFileHeader, hasAttributesFileHeader ? &attributesFileHeader : NULL, targetdir);
        cli_dbgmsg("cli_scanhfsplus: walk catalog finished\n");
    }

    /* Clean up extracted content, if needed */
    if (!ctx->engine->keeptmp) {
        cli_rmdirs(targetdir);
    }

freeDirname:
    free(targetdir);
freeHeader:
    free(volHeader);
    return ret;
}

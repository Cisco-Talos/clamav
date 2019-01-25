/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
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

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include "clamav.h"
#include "others.h"
#include "hfsplus.h"
#include "scanners.h"

static void headerrecord_to_host(hfsHeaderRecord *);
static void headerrecord_print(const char *, hfsHeaderRecord *);
static void nodedescriptor_to_host(hfsNodeDescriptor *);
static void nodedescriptor_print(const char *, hfsNodeDescriptor *);
static void forkdata_to_host(hfsPlusForkData *);
static void forkdata_print(const char *, hfsPlusForkData *);

static int hfsplus_volumeheader(cli_ctx *, hfsPlusVolumeHeader **);
static int hfsplus_readheader(cli_ctx *, hfsPlusVolumeHeader *, hfsNodeDescriptor *,
    hfsHeaderRecord *, int, const char *);
static int hfsplus_scanfile(cli_ctx *, hfsPlusVolumeHeader *, hfsHeaderRecord *,
    hfsPlusForkData *, const char *);
static int hfsplus_validate_catalog(cli_ctx *, hfsPlusVolumeHeader *, hfsHeaderRecord *);
static int hfsplus_fetch_node (cli_ctx *, hfsPlusVolumeHeader *, hfsHeaderRecord *,
    hfsHeaderRecord *, uint32_t, uint8_t *);
static int hfsplus_walk_catalog(cli_ctx *, hfsPlusVolumeHeader *, hfsHeaderRecord *,
    hfsHeaderRecord *, const char *);

/* Header Record : fix endianness for useful fields */
static void headerrecord_to_host(hfsHeaderRecord *hdr)
{
    hdr->treeDepth = be16_to_host(hdr->treeDepth);
    hdr->rootNode = be32_to_host(hdr->rootNode);
    hdr->leafRecords = be32_to_host(hdr->leafRecords);
    hdr->firstLeafNode = be32_to_host(hdr->firstLeafNode);
    hdr->lastLeafNode = be32_to_host(hdr->lastLeafNode);
    hdr->nodeSize = be16_to_host(hdr->nodeSize);
    hdr->maxKeyLength = be16_to_host(hdr->maxKeyLength);
    hdr->totalNodes = be32_to_host(hdr->totalNodes);
    hdr->freeNodes = be32_to_host(hdr->freeNodes);
    hdr->attributes = be32_to_host(hdr->attributes); /* not too useful */
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
    node->fLink = be32_to_host(node->fLink);
    node->bLink = be32_to_host(node->bLink);
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
    fork->clumpSize = be32_to_host(fork->clumpSize); /* does this matter for read-only? */
    fork->totalBlocks = be32_to_host(fork->totalBlocks);
    for (i=0; i < 8; i++) {
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
    for (i=0; i < 8; i++) {
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
    if ((*ctx->fmap)->len < 1536) {
        cli_dbgmsg("cli_scanhfsplus: too short for HFS+\n");
        return CL_EFORMAT;
    }
    mPtr = fmap_need_off_once(*ctx->fmap, 1024, 512);
    if (!mPtr) {
       cli_errmsg("cli_scanhfsplus: cannot read header from map\n");
       return CL_EMAP;
    }

    volHeader = cli_malloc(sizeof(hfsPlusVolumeHeader));
    if (!volHeader) {
       cli_errmsg("cli_scanhfsplus: header malloc failed\n");
       return CL_EMEM;
    }
    *header = volHeader;
    memcpy(volHeader, mPtr, 512);

    volHeader->signature = be16_to_host(volHeader->signature);
    volHeader->version = be16_to_host(volHeader->version);
    if ((volHeader->signature == 0x482B) && (volHeader->version == 4)) {
        cli_dbgmsg("cli_scanhfsplus: HFS+ signature matched\n");
    }
    else if ((volHeader->signature == 0x4858) && (volHeader->version == 5)) {
        cli_dbgmsg("cli_scanhfsplus: HFSX v5 signature matched\n");
    }
    else {
        cli_dbgmsg("cli_scanhfsplus: no matching signature\n");
        return CL_EFORMAT;
    }
    /* skip fields that will definitely be ignored */
    volHeader->attributes = be32_to_host(volHeader->attributes);
    volHeader->fileCount = be32_to_host(volHeader->fileCount);
    volHeader->folderCount = be32_to_host(volHeader->folderCount);
    volHeader->blockSize = be32_to_host(volHeader->blockSize);
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
        cli_dbgmsg("cli_scanhfsplus: Invalid blocksize\n");
        return CL_EFORMAT;
    }
    if (volHeader->blockSize & (volHeader->blockSize - 1)) {
        cli_dbgmsg("cli_scanhfsplus: Invalid blocksize\n");
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
            offset = volHeader->allocationFile.extents[0].startBlock * volHeader->blockSize;
            minSize = 512;
            break;
        case HFS_FILETREE_EXTENTS:
            offset = volHeader->extentsFile.extents[0].startBlock * volHeader->blockSize;
            minSize = 512;
            break;
        case HFS_FILETREE_CATALOG:
            offset = volHeader->catalogFile.extents[0].startBlock * volHeader->blockSize;
            minSize = 4096;
            break;
        case HFS_FILETREE_ATTRIBUTES:
            offset = volHeader->attributesFile.extents[0].startBlock * volHeader->blockSize;
            minSize = 4096;
            break;
        case HFS_FILETREE_STARTUP:
            offset = volHeader->startupFile.extents[0].startBlock * volHeader->blockSize;
            minSize = 512;
            break;
        default:
            cli_errmsg("hfsplus_readheader: %s: invalid headerType %d\n", name, headerType);
            return CL_EARG;
    }
    mPtr = fmap_need_off_once(*ctx->fmap, offset, volHeader->blockSize);
    if (!mPtr) {
        cli_dbgmsg("hfsplus_header: %s: headerNode is out-of-range\n", name);
        return CL_EFORMAT;
    }

    /* Node descriptor first */
    memcpy(nodeDesc, mPtr, sizeof(hfsNodeDescriptor));
    nodedescriptor_to_host(nodeDesc);
    nodedescriptor_print(name, nodeDesc);
    if (nodeDesc->kind != HFS_NODEKIND_HEADER) {
        cli_dbgmsg("hfsplus_header: %s: headerNode not header kind\n", name);
        return CL_EFORMAT;
    }
    if ((nodeDesc->bLink != 0) || (nodeDesc->height != 0) || (nodeDesc->numRecords != 3)) {
        cli_dbgmsg("hfsplus_header: %s: Invalid headerNode\n", name);
        return CL_EFORMAT;
    }

    /* Then header record */
    memcpy(headerRec, mPtr + sizeof(hfsNodeDescriptor), sizeof(hfsHeaderRecord));
    headerrecord_to_host(headerRec);
    headerrecord_print(name, headerRec);

    if ((headerRec->nodeSize < minSize) || (headerRec->nodeSize > maxSize)) {
        cli_dbgmsg("hfsplus_header: %s: Invalid nodesize\n", name);
        return CL_EFORMAT;
    }
    if (headerRec->nodeSize & (headerRec->nodeSize - 1)) {
        cli_dbgmsg("hfsplus_header: %s: Invalid nodesize\n", name);
        return CL_EFORMAT;
    }
    /* KeyLength must be between 6 and 516 for catalog */
    if (headerType == HFS_FILETREE_CATALOG) {
        if ((headerRec->maxKeyLength < 6) || (headerRec->maxKeyLength > 516)) {
            cli_dbgmsg("hfsplus_header: %s: Invalid cat maxKeyLength\n", name);
            return CL_EFORMAT;
        }
        if (headerRec->maxKeyLength > (headerRec->nodeSize / 2)) {
            cli_dbgmsg("hfsplus_header: %s: Invalid cat maxKeyLength based on nodeSize\n", name);
            return CL_EFORMAT;
        }
    }
    else if (headerType == HFS_FILETREE_EXTENTS) {
        if (headerRec->maxKeyLength != 10) {
            cli_dbgmsg("hfsplus_header: %s: Invalid ext maxKeyLength\n", name);
            return CL_EFORMAT;
        }
    }

    /* hdr->treeDepth = rootnode->height */
    return CL_CLEAN;
}

/* Read and dump a file for scanning */
static int hfsplus_scanfile(cli_ctx *ctx, hfsPlusVolumeHeader *volHeader, hfsHeaderRecord *extHeader,
    hfsPlusForkData *fork, const char *dirname)
{
    hfsPlusExtentDescriptor *currExt;
    const uint8_t *mPtr = NULL;
    char *tmpname = NULL;
    int ofd, ret = CL_CLEAN;
    uint64_t targetSize;
    uint32_t outputBlocks = 0;
    uint8_t ext;

    UNUSEDPARAM(extHeader);

    /* bad record checks */
    if (!fork || (fork->logicalSize == 0) || (fork->totalBlocks == 0)) {
        cli_dbgmsg("hfsplus_dumpfile: Empty file.\n");
        return CL_CLEAN;
    }

    /* check limits */
    targetSize = fork->logicalSize;
#if SIZEOF_LONG < 8
    if (targetSize > ULONG_MAX) {
        cli_dbgmsg("hfsplus_dumpfile: File too large for limit check.\n");
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
        cli_dbgmsg("hfsplus_dumpfile: Cannot generate temporary file.\n");
        return ret;
    }
    cli_dbgmsg("hfsplus_dumpfile: Extracting to %s\n", tmpname);

    ext = 0;
    /* Dump file, extent by extent */
    do {
        uint32_t currBlock, endBlock, outputSize = 0;
        if (targetSize == 0) {
            cli_dbgmsg("hfsplus_dumpfile: output complete\n");
            break;
        }
        if (outputBlocks >= fork->totalBlocks) {
            cli_dbgmsg("hfsplus_dumpfile: output all blocks, remaining size " STDu64 "\n", targetSize);
            break;
        }
        /* Prepare extent */
        if (ext < 8) {
            currExt = &(fork->extents[ext]);
            cli_dbgmsg("hfsplus_dumpfile: extent %u\n", ext);
        }
        else {
            cli_dbgmsg("hfsplus_dumpfile: need next extent from ExtentOverflow\n");
            /* Not implemented yet */
            ret = CL_EFORMAT;
            break;
        }
        /* have extent, so validate and get block range */
        if ((currExt->startBlock == 0) || (currExt->blockCount == 0)) {
            cli_dbgmsg("hfsplus_dumpfile: next extent empty, done\n");
            break;
        }
        if ((currExt->startBlock & 0x10000000) && (currExt->blockCount & 0x10000000)) {
            cli_dbgmsg("hfsplus_dumpfile: next extent illegal!\n");
            ret = CL_EFORMAT;
            break;
        }
        currBlock = currExt->startBlock;
        endBlock = currExt->startBlock + currExt->blockCount - 1;
        if ((currBlock > volHeader->totalBlocks) || (endBlock > volHeader->totalBlocks)
                || (currExt->blockCount > volHeader->totalBlocks)) {
            cli_dbgmsg("hfsplus_dumpfile: bad extent!\n");
            ret = CL_EFORMAT;
            break;
        }
        /* Write the blocks, walking the map */
        while (currBlock <= endBlock) {
            size_t to_write = MIN(targetSize, volHeader->blockSize);
            ssize_t written;
            off_t offset = currBlock * volHeader->blockSize;
            /* move map to next block */
            mPtr = fmap_need_off_once(*ctx->fmap, offset, volHeader->blockSize);
            if (!mPtr) {
                cli_errmsg("hfsplus_dumpfile: map error\n");
                ret = CL_EMAP;
                break;
            }
            written = cli_writen(ofd, mPtr, to_write);
            if ((size_t)written != to_write) {
                cli_errmsg("hfsplus_dumpfile: write error\n");
                ret = CL_EWRITE;
                break;
            }
            targetSize -= to_write;
            outputSize += to_write;
            currBlock++;
            if (targetSize == 0) {
                cli_dbgmsg("hfsplus_dumpfile: all data written\n");
                break;
            }
            if (outputBlocks >= fork->totalBlocks) {
                cli_dbgmsg("hfsplus_dumpfile: output all blocks, remaining size " STDu64 "\n", targetSize);
                break;
            }
        }
        /* Finished the extent, move to next */
        ext++;
    } while (ret == CL_CLEAN);

    /* if successful so far, scan the output */
    if (ret == CL_CLEAN) {
        ret = cli_magic_scandesc(ofd, tmpname, ctx);
    }

    if (ofd >= 0) {
        close(ofd);
    }
    if (!ctx->engine->keeptmp) {
        if (cli_unlink(tmpname)) {
            ret = CL_EUNLINK;
        }
    }
    free(tmpname);

    return ret;
}

/* Calculate true node limit for catalogFile */
static int hfsplus_validate_catalog(cli_ctx *ctx, hfsPlusVolumeHeader *volHeader, hfsHeaderRecord *catHeader)
{
    hfsPlusForkData *catFork;

    UNUSEDPARAM(ctx);

    catFork = &(volHeader->catalogFile);
    if (catFork->totalBlocks >= volHeader->totalBlocks) {
        cli_dbgmsg("hfsplus_getnodelimit: catFork totalBlocks too large!\n");
        return CL_EFORMAT;
    }
    if (catFork->logicalSize > (catFork->totalBlocks * volHeader->blockSize)) {
        cli_dbgmsg("hfsplus_getnodelimit: catFork logicalSize too large!\n");
        return CL_EFORMAT;
    }
    if (catFork->logicalSize < (catHeader->totalNodes * catHeader->nodeSize)) {
        cli_dbgmsg("hfsplus_getnodelimit: too many nodes for catFile\n");
        return CL_EFORMAT;
    }

    return CL_CLEAN;
}

/* Fetch a node's contents into the buffer */
static int hfsplus_fetch_node (cli_ctx *ctx, hfsPlusVolumeHeader *volHeader, hfsHeaderRecord *catHeader,
    hfsHeaderRecord *extHeader, uint32_t node, uint8_t *buff)
{
    int foundBlock = 0;
    uint64_t catalogOffset;
    uint32_t fetchBlock, fetchStart;
    uint32_t extentNum = 0, realFileBlock;
    size_t fileOffset = 0;
    hfsPlusForkData *catFork;

    UNUSEDPARAM(extHeader);

    /* Make sure node is in range */
    if (node >= catHeader->totalNodes) {
        cli_dbgmsg("hfsplus_fetch_node: invalid node number " STDu32 "\n", node);
        return CL_EFORMAT;
    }

    catFork = &(volHeader->catalogFile);
    /* Do we need one block or more? */
    if (catHeader->nodeSize <= volHeader->blockSize) {
        /* Need one block */
        /* First, calculate the node's offset within the catalog */
        catalogOffset = (uint64_t)node * catHeader->nodeSize;
        /* Determine which block of the catalog we need */
        fetchBlock = (uint32_t) (catalogOffset / volHeader->blockSize);
        fetchStart = (uint32_t) (catalogOffset % volHeader->blockSize);
        cli_dbgmsg("hfsplus_fetch_node: need catalog block " STDu32 "\n", fetchBlock);
        if (fetchBlock >= catFork->totalBlocks) {
            cli_dbgmsg("hfsplus_fetch_node: block number invalid!\n");
            return CL_EFORMAT;
        }

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
            if (fetchBlock < currExt->blockCount) {
                cli_dbgmsg("hfsplus_fetch_node: found block in extent " STDu32 "\n", extentNum);
                realFileBlock = currExt->startBlock + fetchBlock;
                foundBlock = 1;
                break;
            }
            else {
                cli_dbgmsg("hfsplus_fetch_node: not in extent " STDu32 "\n", extentNum);
                fetchBlock -= currExt->blockCount;
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
    }
    else {
        /* Need more than one block for this node */
        cli_dbgmsg("hfsplus_fetch_node: nodesize bigger than blocksize, is this allowed?\n");
        return CL_EFORMAT;
    }

    if (fileOffset) {
        if (fmap_readn(*ctx->fmap, buff, fileOffset, catHeader->nodeSize) != catHeader->nodeSize) {
            cli_dbgmsg("hfsplus_fetch_node: not all bytes read\n");
            return CL_EFORMAT;
        }
    }
    else {
        cli_dbgmsg("hfsplus_fetch_node: nodesize bigger than blocksize, is this allowed?\n");
        return CL_EFORMAT;
    }

    return CL_CLEAN;
}

/* Given the catalog and other details, scan all the volume contents */
static int hfsplus_walk_catalog(cli_ctx *ctx, hfsPlusVolumeHeader *volHeader, hfsHeaderRecord *catHeader,
    hfsHeaderRecord *extHeader, const char *dirname)
{
    int ret = CL_CLEAN;
    unsigned int has_alerts = 0;
    uint32_t thisNode, nodeLimit, nodesScanned = 0;
    uint16_t nodeSize, recordNum, topOfOffsets;
    uint16_t distance, recordStart, nextDist, nextStart;
    uint8_t *nodeBuf = NULL;
    hfsPlusForkData *catFork;

    catFork = &(volHeader->catalogFile);
    nodeLimit = MIN(catHeader->totalNodes, HFSPLUS_NODE_LIMIT);
    thisNode = catHeader->firstLeafNode;
    nodeSize = catHeader->nodeSize;

    /* Need to buffer current node, map will keep moving */
    nodeBuf = cli_malloc(nodeSize);
    if (!nodeBuf) {
        cli_dbgmsg("hfsplus_walk_catalog: failed to acquire node buffer, "
            "size " STDu32 "\n", nodeSize);
        return CL_EMEM;
    }

    /* Walk catalog leaf nodes, and scan contents of each */
    /* Because we want to scan them all, the index nodes add no value */
    while (ret == CL_CLEAN) {
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
        ret = hfsplus_fetch_node(ctx, volHeader, catHeader, extHeader, thisNode, nodeBuf);
        if (ret != CL_CLEAN) {
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
        distance = nodeSize;
        recordStart = 14; /* 1st record can be after end of node descriptor */
        /* offsets take 1 u16 per at the end of the node, along with an empty space offset */
        topOfOffsets = nodeSize - (nodeDesc.numRecords * 2) - 2;
        for (recordNum = 0; recordNum < nodeDesc.numRecords; recordNum++) {
            uint16_t keylen;
            int16_t rectype;
            hfsPlusCatalogFile fileRec;

            /* Locate next record */
            nextDist = nodeSize - (recordNum * 2) - 2;
            nextStart = nodeBuf[nextDist] * 0x100 + nodeBuf[nextDist+1];
            /* Check record location */
            if ((nextStart > topOfOffsets-1) || (nextStart < recordStart)) {
                cli_dbgmsg("hfsplus_walk_catalog: bad record location %x for %u!\n", nextStart, recordNum);
                ret = CL_EFORMAT;
                break;
            }
            distance = nextDist;
            recordStart = nextStart;
            /* Get record key length */
            keylen = nodeBuf[recordStart] * 0x100 + nodeBuf[recordStart+1];
            keylen += keylen % 2; /* pad 1 byte if required to make 2-byte align */
            /* Validate keylen */
            if (recordStart + keylen + 4 >= topOfOffsets) {
                cli_dbgmsg("hfsplus_walk_catalog: key too long for location %x for %u!\n",
                    nextStart, recordNum);
                ret = CL_EFORMAT;
                break;
            }
            /* Copy type (after key, which is after keylength field) */
            memcpy(&rectype, &(nodeBuf[recordStart+keylen+2]), 2);
            rectype = be16_to_host(rectype);
            cli_dbgmsg("hfsplus_walk_catalog: record %u nextStart %x keylen %u type %d\n",
                recordNum, nextStart, keylen, rectype);
            /* Non-file records are not needed */
            if (rectype != HFSPLUS_RECTYPE_FILE) {
                continue;
            }
            /* Check file record location */
            if (recordStart+keylen+2+sizeof(hfsPlusCatalogFile) >= topOfOffsets) {
                cli_dbgmsg("hfsplus_walk_catalog: not enough bytes for file record!\n");
                ret = CL_EFORMAT;
                break;
            }
            memcpy(&fileRec, &(nodeBuf[recordStart+keylen+2]), sizeof(hfsPlusCatalogFile));

            /* Only scan files */
            fileRec.permissions.fileMode = be16_to_host(fileRec.permissions.fileMode);
            if ((fileRec.permissions.fileMode & HFS_MODE_TYPEMASK) == HFS_MODE_FILE) {
                /* Convert forks and scan */
                forkdata_to_host(&(fileRec.dataFork));
                forkdata_print("data fork:", &(fileRec.dataFork));
                if (fileRec.dataFork.logicalSize) {
                    ret = hfsplus_scanfile(ctx, volHeader, extHeader, &(fileRec.dataFork), dirname);
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
                if (ret != CL_CLEAN) {
                    cli_dbgmsg("hfsplus_walk_catalog: data fork retcode %d\n", ret);
                    break;
                }
                /* Scan resource fork */
                forkdata_to_host(&(fileRec.resourceFork));
                forkdata_print("resource fork:", &(fileRec.resourceFork));
                if (fileRec.resourceFork.logicalSize) {
                    ret = hfsplus_scanfile(ctx, volHeader, extHeader, &(fileRec.resourceFork), dirname);
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
                if (ret != CL_CLEAN) {
                    cli_dbgmsg("hfsplus_walk_catalog: resource fork retcode %d", ret);
                    break;
                }
            }
            else {
                cli_dbgmsg("hfsplus_walk_catalog: record mode %o is not File\n", fileRec.permissions.fileMode);
            }
        }
        /* if return code, exit loop, message already logged */
        if (ret != CL_CLEAN) {
            break;
        }

        /* After that, proceed to next node */
        if (thisNode == nodeDesc.fLink) {
            /* Future heuristic */
            cli_warnmsg("hfsplus_walk_catalog: simple cycle detected!\n");
            ret = CL_EFORMAT;
            break;
        }
        else {
            thisNode = nodeDesc.fLink;
        }
    }

    free(nodeBuf);
    if (has_alerts) {
        ret = CL_VIRUS;
    }
    return ret;
}

/* Base scan function for scanning HFS+ or HFSX partitions */
int cli_scanhfsplus(cli_ctx *ctx)
{
    char *targetdir = NULL;
    int ret = CL_CLEAN;
    hfsPlusVolumeHeader *volHeader = NULL;
    hfsNodeDescriptor catFileDesc;
    hfsHeaderRecord catFileHeader;
    hfsNodeDescriptor extentFileDesc;
    hfsHeaderRecord extentFileHeader;

    if (!ctx || !ctx->fmap) {
        cli_errmsg("cli_scanhfsplus: Invalid context\n");
        return CL_ENULLARG;
    }

    cli_dbgmsg("cli_scanhfsplus: scanning partition content\n");
    /* first, read volume header contents */
    ret = hfsplus_volumeheader(ctx, &volHeader);
    if (ret != CL_CLEAN) {
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
    if (ret != CL_CLEAN) {
        goto freeHeader;
    }
    /* Get root node (header node) of catalog file */
    ret = hfsplus_readheader(ctx, volHeader, &catFileDesc, &catFileHeader, HFS_FILETREE_CATALOG, "catalogFile");
    if (ret != CL_CLEAN) {
        goto freeHeader;
    }

    /* Create temp folder for contents */
    if (!(targetdir = cli_gentemp(ctx->engine->tmpdir))) {
        cli_errmsg("cli_scandmg: cli_gentemp failed\n");
        ret = CL_ETMPDIR;
        goto freeHeader;
    }
    if (mkdir(targetdir, 0700)) {
        cli_errmsg("cli_scandmg: Cannot create temporary directory %s\n", targetdir);
        ret = CL_ETMPDIR;
        goto freeDirname;
    }
    cli_dbgmsg("cli_scandmg: Extracting into %s\n", targetdir);

    /* Can build and scan catalog file if we want ***
    ret = hfsplus_scanfile(ctx, volHeader, &extentFileHeader, &(volHeader->catalogFile), targetdir);
     */
    if (ret == CL_CLEAN) {
        ret = hfsplus_validate_catalog(ctx, volHeader, &catFileHeader);
        if (ret == CL_CLEAN) {
            cli_dbgmsg("cli_scandmg: validation successful\n");
        }
        else {
            cli_dbgmsg("cli_scandmg: validation returned %d : %s\n", ret, cl_strerror(ret));
        }
    }

    /* Walk through catalog to identify files to scan */
    if (ret == CL_CLEAN) {
        ret = hfsplus_walk_catalog(ctx, volHeader, &catFileHeader, &extentFileHeader, targetdir);
        cli_dbgmsg("cli_scandmg: walk catalog finished\n");
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

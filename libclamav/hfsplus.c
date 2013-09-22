/*
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

#include "cltypes.h"
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

static void headerrecord_print(const char *pfx, hfsHeaderRecord *hdr)
{
    cli_dbgmsg("%s Header: depth %hu root %u leafRecords %u firstLeaf %u lastLeaf %u nodeSize %hu\n",
        pfx, hdr->treeDepth, hdr->rootNode, hdr->leafRecords, hdr->firstLeafNode,
        hdr->lastLeafNode, hdr->nodeSize);
    cli_dbgmsg("%s Header: maxKeyLength %hu totalNodes %u freeNodes %u btreeType %hu attributes %x\n",
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

static void forkdata_print(const char *pfx, hfsPlusForkData *fork)
{
    int i;
    cli_dbgmsg("%s logicalSize %lu clumpSize %lu totalBlocks %lu\n", pfx,
        fork->logicalSize, fork->clumpSize, fork->totalBlocks);
    for (i=0; i < 8; i++) {
        if (fork->extents[i].startBlock == 0)
            break;
        cli_dbgmsg("%s extent[%d] startBlock %lu blockCount %lu\n", pfx, i,
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
        return CL_EFORMAT;
    }
    if ((volHeader->signature == 0x4858) && (volHeader->version == 5)) {
        cli_dbgmsg("cli_scanhfsplus: HFSX v5 signature matched\n");
        return CL_EFORMAT;
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
    cli_dbgmsg("File Count: %lu\n", volHeader->fileCount);
    cli_dbgmsg("Folder Count: %lu\n", volHeader->folderCount);
    cli_dbgmsg("Block Size: %lu\n", volHeader->blockSize);
    cli_dbgmsg("Total Blocks: %lu\n", volHeader->totalBlocks);

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
    uint32_t minSize;

    /* Node Size must be power of 2 between 512 and 32768 */
    /* Node Size for Catalog or Attributes must be at least 4096 */
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

    if ((headerRec->nodeSize < minSize) || (volHeader->blockSize > 32768)) {
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

    /* bad record checks */
    if (!fork || (fork->logicalSize == 0) || (fork->totalBlocks == 0)) {
        cli_dbgmsg("hfsplus_dumpfile: Empty file.\n");
        return CL_CLEAN;
    }

    /* check limits */
    targetSize = fork->logicalSize;
    if (targetSize > ULONG_MAX) {
        cli_dbgmsg("hfsplus_dumpfile: File too large for limit check.\n");
        return CL_EFORMAT;
    }
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
        uint32_t currBlock, endBlock, outputSize;
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
            if (written != to_write) {
                cli_errmsg("hfsplus_dumpfile: write error\n");
                ret = CL_EWRITE;
                break;
            }
            targetSize -= to_write;
            outputSize += to_write;
            currBlock++;
            if (targetSize == 0) {
                cli_dbgmsg("hfsplus_dumpfile: output complete\n");
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
        ret = cli_magic_scandesc(ofd, ctx);
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

    /* Get root node (header node) of catalog file */
    ret = hfsplus_readheader(ctx, volHeader, &extentFileDesc, &extentFileHeader, HFS_FILETREE_EXTENTS, "extentFile");
    if (ret != CL_CLEAN) {
        goto freeHeader;
    }
    ret = hfsplus_readheader(ctx, volHeader, &catFileDesc, &catFileHeader, HFS_FILETREE_CATALOG, "catalogFile");
    if (ret != CL_CLEAN) {
        goto freeHeader;
    }

    /* Create temp folder for contents */
    if (!(targetdir = cli_gentemp(ctx->engine->tmpdir))) {
        ret = CL_ETMPDIR;
        goto freeHeader;
    }
    if (mkdir(targetdir, 0700)) {
        cli_errmsg("cli_scandmg: Cannot create temporary directory %s\n", targetdir);
        ret = CL_ETMPDIR;
        goto freeDirname;
    }
    cli_dbgmsg("cli_scandmg: Extracting into %s\n", targetdir);

    ret = hfsplus_scanfile(ctx, volHeader, &extentFileHeader, &(volHeader->catalogFile), targetdir);

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

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

#ifndef __HFSPLUS_H
#define __HFSPLUS_H

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include "clamav-types.h"

/* Structures based on Apple Technote 1150 */

/* volume attributes that may affect reading */
enum hfsVolAttributes {
    /* hfsVolumeHardwareLockBit       =  7, */
    hfsVolumeUnmountedBit          =  8,
    hfsVolumeSparedBlocksBit       =  9,
    /* hfsVolumeNoCacheRequiredBit    = 10, */
    hfsBootVolumeInconsistentBit   = 11,
    hfsCatalogNodeIDsReusedBit     = 12,
    hfsVolumeJournaledBit          = 13
    /* hfsVolumeSoftwareLockBit       = 15 */
};

/* reserved CatalogNodeID values */
enum {
    hfsRootParentID            = 1,
    hfsRootFolderID            = 2,
    hfsExtentsFileID           = 3,
    hfsCatalogFileID           = 4,
    hfsBadBlockFileID          = 5,
    hfsAllocationFileID        = 6,
    hfsStartupFileID           = 7,
    hfsAttributesFileID        = 8,
    hfsRepairCatalogFileID     = 14,
    hfsBogusExtentFileID       = 15,
    hfsFirstUserCatalogNodeID  = 16
};

#ifndef HAVE_ATTRIB_PACKED
#define __attribute__(x)
#endif

#ifdef HAVE_PRAGMA_PACK
#pragma pack(2)
#endif

#ifdef HAVE_PRAGMA_PACK_HPPA
#pragma pack 2
#endif

/* Basic HFS+ structures */
struct hfsUniStr255 {
    uint16_t	length;
    uint16_t	unicode[255];
} __attribute__((__packed__));
typedef struct hfsUniStr255 hfsUniStr255;

struct hfsPlusExtentDescriptor {
    uint32_t	startBlock;
    uint32_t	blockCount;
} __attribute__((__packed__));
typedef struct hfsPlusExtentDescriptor hfsPlusExtentDescriptor;
typedef hfsPlusExtentDescriptor hfsPlusExtentRecord[8];

struct hfsPlusForkData {
    uint64_t	logicalSize;
    uint32_t	clumpSize;
    uint32_t	totalBlocks;
    hfsPlusExtentRecord	extents;
} __attribute__((__packed__));
typedef struct hfsPlusForkData hfsPlusForkData;

/* HFS+ Volume Header (512 bytes) */
struct hfsPlusVolumeHeader {
    uint16_t	signature; /* H+ for HFS+, HX for HFSX */
    uint16_t	version;
    uint32_t	attributes;
    uint32_t	lastMountedVersion;
    uint32_t	journalInfoBlock;

    uint32_t	createDate;
    uint32_t	modifyDate;
    uint32_t	backupDate;
    uint32_t	checkedDate;

    uint32_t	fileCount;
    uint32_t	folderCount;

    uint32_t	blockSize;
    uint32_t	totalBlocks;
    uint32_t	freeBlocks;

    uint32_t	nextAllocation;
    uint32_t	rsrcClumpSize;
    uint32_t	dataClumpSize;
    uint32_t	nextCatalogID; /* Next unused catalog ID */

    uint32_t	writeCount;
    uint64_t	encodingsBitmap;

    uint32_t	finderInfo[8]; /* for Finder */

    hfsPlusForkData	allocationFile;
    hfsPlusForkData	extentsFile;
    hfsPlusForkData	catalogFile;
    hfsPlusForkData	attributesFile;
    hfsPlusForkData	startupFile;
} __attribute__((__packed__));
typedef struct hfsPlusVolumeHeader hfsPlusVolumeHeader;

#define HFS_FILETREE_ALLOCATION 1 
#define HFS_FILETREE_EXTENTS 2
#define HFS_FILETREE_CATALOG 3
#define HFS_FILETREE_ATTRIBUTES 4
#define HFS_FILETREE_STARTUP 5

/* BSD object info (16 bytes) */
/* important parts for scanning are fileMode and the special part */
struct hfsPlusBSDInfo {
    uint32_t ownerID;
    uint32_t groupID;
    uint8_t	adminFlags;
    uint8_t	ownerFlags;
    uint16_t	fileMode;
    union {
        uint32_t	iNodeNum;
        uint32_t	linkCount;
        uint32_t	rawDevice;
    } special;
} __attribute__((__packed__));
typedef struct hfsPlusBSDInfo hfsPlusBSDInfo;

#define HFS_MODE_TYPEMASK	0170000
#define HFS_MODE_DIRECTORY	0040000
#define HFS_MODE_FILE		0100000
#define HFS_MODE_SOFTLINK	0120000

/******************************/
/* Node and tree structures   */
/******************************/

/* B-tree node descriptor (14 bytes) */
struct hfsNodeDescriptor {
    uint32_t	fLink;
    uint32_t	bLink;
    int8_t	kind;
    uint8_t	height;
    uint16_t	numRecords;
    uint16_t	reserved;
} __attribute__((__packed__));
typedef struct hfsNodeDescriptor hfsNodeDescriptor;

/* Node kinds are int8_t */
#define HFS_NODEKIND_LEAF	-1
#define HFS_NODEKIND_INDEX	0
#define HFS_NODEKIND_HEADER	1
#define HFS_NODEKIND_MAP	2

/* B-tree header record (106 bytes) */
struct hfsHeaderRecord {
    uint16_t	treeDepth;
    uint32_t	rootNode;
    uint32_t	leafRecords;
    uint32_t	firstLeafNode;
    uint32_t	lastLeafNode;
    uint16_t	nodeSize;
    uint16_t	maxKeyLength;
    uint32_t	totalNodes;
    uint32_t	freeNodes;
    uint16_t	reserved1;
    uint32_t	clumpSize;
    uint8_t	btreeType;
    uint8_t	keyCompareType;
    uint32_t	attributes;
    uint32_t	reserved3[16];
} __attribute__((__packed__));
typedef struct hfsHeaderRecord hfsHeaderRecord;

#define HFS_HEADERATTR_MASK	0x00000006
#define HFS_HEADERATTR_BIGKEYS	0x00000002
#define HFS_HEADERATTR_VARKEYS	0x00000004

struct hfsPlusCatalogKey {
    uint16_t	keyLength;
    uint32_t	parentID; /* CNID */
    hfsUniStr255	nodeName;
} __attribute__((__packed__));
typedef struct hfsPlusCatalogKey hfsPlusCatalogKey;

struct hfsPlusCatalogFolder {
    int16_t	recordType;
    uint16_t	flags;
    uint32_t	valence;
    uint32_t	folderID; /* CNID */
    uint32_t	dates[5];
    hfsPlusBSDInfo	permissions;
    uint16_t	userInfo[8]; /* FolderInfo */
    uint16_t	finderInfo[8]; /* ExtendedFolderInfo */
    uint32_t	textEncoding;
    uint32_t	reserved;
} __attribute__((__packed__));
typedef struct hfsPlusCatalogFolder hfsPlusCatalogFolder;

struct hfsPlusCatalogFile {
    int16_t	recordType;
    uint16_t	flags;
    uint32_t	reserved1;
    uint32_t	fileID; /* CNID */
    uint32_t	dates[5];
    hfsPlusBSDInfo	permissions;
    uint16_t	userInfo[8]; /* FileInfo */
    uint16_t	finderInfo[8]; /* ExtendedFileInfo */
    uint32_t	textEncoding;
    uint32_t	reserved2;
    hfsPlusForkData	dataFork;
    hfsPlusForkData	resourceFork;
};
typedef struct hfsPlusCatalogFile hfsPlusCatalogFile;

struct hfsPlusCatalogThread {
    int16_t	recordType;
    int16_t	reserved;
    uint32_t	parentID; /* CNID */
    hfsUniStr255	nodeName;
} __attribute__((__packed__));
typedef struct hfsPlusCatalogThread hfsPlusCatalogThread;

#define HFSPLUS_RECTYPE_FOLDER       0x0001
#define HFSPLUS_RECTYPE_FILE         0x0002
#define HFSPLUS_RECTYPE_FOLDERTHREAD 0x0003
#define HFSPLUS_RECTYPE_FILETHREAD   0x0004
/* HFS types are similar 
#define HFS_RECTYPE_FOLDER       0x0100
#define HFS_RECTYPE_FILE         0x0200
#define HFS_RECTYPE_FOLDERTHREAD 0x0300
#define HFS_RECTYPE_FILETHREAD   0x0400
 */

#define HFS_HARD_LINK_FILE_TYPE 0x686C6E6B /* hlnk */

/* Extents structures */
struct hfsPlusExtentKey {
    uint16_t	keyLength;
    uint8_t	forkType;
    uint8_t	pad;
    uint32_t	fileID; /* CNID */
    uint32_t	startBlock;
} __attribute__((__packed__));
typedef struct hfsPlusExtentKey hfsPlusExtentKey;

#define HFSPLUS_FORKTYPE_DATA 0x00
#define HFSPLUS_FORKTYPE_RSRC 0xFF

#ifdef HAVE_PRAGMA_PACK
#pragma pack()
#endif

#ifdef HAVE_PRAGMA_PACK_HPPA
#pragma pack
#endif

#define HFS_VOL_INCONSISTENT(hdr)	\
    ((hdr->attributes & (1 << hfsBootVolumeInconsistentBit))	\
    || !(hdr->attributes & (1 << hfsVolumeUnmountedBit)))

/* Maximum number of catalog leaf nodes to scan for records */
#define HFSPLUS_NODE_LIMIT 1000

int cli_scanhfsplus(cli_ctx *ctx);

#endif

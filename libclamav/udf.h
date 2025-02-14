/*
 *  Copyright (C) 2023-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *
 *  Authors: Cisco
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

#ifndef _UDF_H_
#define _UDF_H_

#include "others.h"

#define UDF_EMPTY_LEN 32768

// All Volume Descriptors are the same size.
#define VOLUME_DESCRIPTOR_SIZE 0x800

#ifndef HAVE_ATTRIB_PACKED
#define __attribute__(x)
#endif

#ifdef HAVE_PRAGMA_PACK
#pragma pack(1)
#endif

#ifdef HAVE_PRAGMA_PACK_HPPA
#pragma pack 1
#endif

typedef struct __attribute__((packed)) {
    uint16_t typeTimeZone; /*
                              0     Coordinated UTC
                              1     Local Time
                              2     Up to agreement between originator and recipient
                              3 - 15    Reserved
                              */
    uint16_t year;
    uint8_t month;
    uint8_t day;
    uint8_t hour;
    uint8_t minute;
    uint8_t second;
    uint8_t centiseconds;
    uint8_t hundredsMicroSeconds;
    uint8_t microseconds;
} timestamp;

typedef struct __attribute__((packed)) {

    uint32_t blockNumber;

    uint16_t partitionReferenceNumber;

} lb_addr;

// Long allocation descriptor
typedef struct __attribute__((packed)) {
    uint32_t length; // 4/14.14.1.1
    /*30 least significant bits are length in bytes.
     *
     * 2 most significant bits are described in figure 4/42
     *
     * 0 extent recorded and allocated
     * 1 extent NOT recorded but allocated
     * 2 extent NOT recorded and NOT allocated
     * 3 the extent is the next extent of allocation descriptors.
     * */

    lb_addr extentLocation; // logical block number.  (CAN be zero)

    uint8_t implementationUse[6];

} long_ad;

/*
 * https://www.ecma-international.org/wp-content/uploads/ECMA-167_3rd_edition_june_1997.pdf
 * section 3/7.2 */
typedef struct __attribute__((packed)) {
    uint16_t tagId;
    uint16_t descriptorVersion;
    uint8_t checksum;
    uint8_t reserved;
    uint16_t serialNumber;
    uint16_t descriptorCRC;
    uint16_t descriptorCRCLength;
    uint32_t tagLocation;
} DescriptorTag;

typedef struct __attribute__((packed)) {
    uint8_t flags;
    /*
     * 1/7.4
     * characteristics
     * bit 0    dirty: If regid has been modified and might not be valid, set to * 1.  Otherwise, 0
     * bit 1    protected: If 1, this regid cannot be modified
     * bit 2-7  reserved
     */
    uint8_t identifier[23];
    /*
     * If first byte is 0x2b, then this is covered by ECMA-168 (this spec)
     * If first byte is 0x2d, then this is not registered
     */
    uint8_t identifierSuffix[8];
} regid;

typedef struct __attribute__((packed)) {
    DescriptorTag tag;
    uint32_t volumeDescriptorSequenceNumber;
    uint32_t primaryVolumeDescriptorNumber;
    uint8_t volumeIdentifier[32];
    uint16_t volumeSequenceNumber;
    uint16_t interchangeLevel;
    uint16_t maxInterchangeLevel;
    uint32_t charSetList;
    uint8_t volumeSetIdentifier[128];
    uint8_t descriptorCharSet[64];
    uint8_t explanatoryCharSet[64];
    uint64_t volumeAbstract;
    uint64_t volumeCopyrightNotice;
    uint8_t applicationIdentifier[32];
    uint8_t recordingDateTime[12];
    uint8_t implementationIdentifier[32];
    uint8_t implementationUse[64];
    uint32_t predVolumeDescSequenceLocation;
    uint16_t flags;
    uint8_t reserved[22];

} PrimaryVolumeDescriptor;

typedef struct __attribute__((packed)) {
    DescriptorTag tag;
    uint32_t volumeDescriptorSequenceNumber;

    regid implementationIdentifier;
    uint8_t implementationUse[460];

} ImplementationUseVolumeDescriptor;

/* https://www.ecma-international.org/wp-content/uploads/ECMA-167_3rd_edition_june_1997.pdf */
/* 4/3 */
typedef struct __attribute__((packed)) {
    uint32_t logicalBlockNumber;

    uint16_t partitionReferenceNumber;
} LBAddr;

// https://www.ecma-international.org/wp-content/uploads/ECMA-167_3rd_edition_june_1997.pdf
// section 4/23
typedef struct __attribute__((packed)) {
    uint32_t priorRecordedNumberOfDirectEntries;
    uint16_t strategyType;
    uint8_t strategyParameter[2]; /*described as 'bytes' in docs, so don't want to worry about byte order.*/
    uint16_t maxEntries;
    uint8_t reserved_must_be_zero;

    uint8_t fileType;

    LBAddr parentICBLocation;

    uint16_t flags;
} ICBTag;

typedef struct __attribute__((packed)) {

    DescriptorTag tag;

    uint16_t versionNumber;

    uint8_t characteristics;

    uint8_t fileIdentifierLength;

    long_ad icb;

    /*L_IU specified in 1/7.1.3 */
    uint16_t implementationLength;

    uint8_t rest[1];

} FileIdentifierDescriptor;

#define FILE_IDENTIFIER_DESCRIPTOR_SIZE_KNOWN (sizeof(FileIdentifierDescriptor) - 1)

/*Section 14.4.9 of https:... */
static uint32_t getFileIdentifierDescriptorPaddingLength(const FileIdentifierDescriptor* const fid)
{
    uint32_t ret = 0;
    uint32_t tmp = le16_to_host(fid->implementationLength) + fid->fileIdentifierLength + 38;
    ret          = tmp + 3;
    ret          = ret / 4;

    ret = ret * 4;
    ret = ret - tmp;

    return ret;
}

static inline size_t getFileIdentifierDescriptorSize(const FileIdentifierDescriptor* fid)
{
    return FILE_IDENTIFIER_DESCRIPTOR_SIZE_KNOWN + le16_to_host(fid->implementationLength) + fid->fileIdentifierLength + getFileIdentifierDescriptorPaddingLength(fid);
}

typedef struct __attribute__((packed)) {
    DescriptorTag tag;

    ICBTag icbTag;

    uint32_t uid;

    uint32_t gid;

    uint32_t permissions;

    uint16_t fileLinkCnt;

    uint8_t recordFormat;
    uint8_t recordDisplayAttributes;

    uint32_t recordLength;

    uint64_t infoLength;

    uint64_t logicalBlocksRecorded;

    timestamp accessDateTime;

    timestamp modificationDateTime;

    timestamp attributeDateTime;

    uint32_t checkpoint;

    long_ad extendedAttrICB;

    regid implementationId;

    uint64_t uniqueId;

    uint32_t extendedAttrLen;

    uint32_t allocationDescLen;

    /* Variable length stuff here, need to handle;
     */
    uint8_t rest[1];

} FileEntryDescriptor;

#define FILE_ENTRY_DESCRIPTOR_SIZE_KNOWN (sizeof(FileEntryDescriptor) - 1)
static inline size_t getFileEntryDescriptorSize(const FileEntryDescriptor* fed)
{
    return FILE_ENTRY_DESCRIPTOR_SIZE_KNOWN + le32_to_host(fed->extendedAttrLen) + le32_to_host(fed->allocationDescLen);
}

typedef struct __attribute__((packed)) {
    DescriptorTag tag;

    ICBTag icbTag;

    uint32_t uid;

    uint32_t gid;

    uint32_t permissions;

    uint16_t fileLinkCnt;

    uint8_t recordFormat;

    uint8_t recordDisplayAttributes;

    uint32_t recordLength;

    uint64_t infoLength;

    uint64_t objectSize; // different

    uint64_t logicalBlocksRecorded;

    timestamp accessDateTime;

    timestamp modificationDateTime;

    timestamp creationDateTime; // different

    timestamp attributeDateTime;

    uint32_t checkpoint;

    uint32_t reserved; // different

    long_ad extendedAttrICB;

    long_ad streamDirectoryICB; // different

    regid implementationId;

    uint64_t uniqueId;

    uint32_t extendedAttrLen;

    uint32_t allocationDescLen;

    /* Variable length stuff here, need to handle;
     */

} ExtendedFileEntryDescriptor;

// Short allocation descriptor
typedef struct __attribute__((packed)) {

    uint32_t length;

    uint32_t position;

} short_ad;

typedef struct __attribute__((packed)) {
    uint32_t extentLen;
    uint32_t recordedLen;

    uint32_t infoLen;

    lb_addr extentLocation;

    uint8_t implementationUse[2];
} ext_ad;

typedef struct __attribute__((packed)) {
    uint32_t extentLength;

    uint32_t extentLocation;

} extent_ad;

typedef struct __attribute__((packed)) {

    DescriptorTag tag;

    uint32_t volumeDescriptorSequenceNumber;

    uint16_t partitionFlags;

    uint16_t partitionNumber;

    regid partitionContents;

    uint8_t partitionContentsUse[128];

    uint32_t accessType;

    uint32_t partitionStartingLocation;

    uint32_t partitionLength;

    regid implementationIdentifier;

    uint8_t implementationUse[128];

    uint8_t reserved[156];

} PartitionDescriptor;

typedef struct __attribute__((packed)) {
    DescriptorTag tag;

    uint32_t volumeDescriptorSequenceNumber;

    uint32_t numAllocationDescriptors;

    uint8_t rest[1]; /*reset is 'numAllocationDescriptors' * sizeof (extent_ad),
    and padded out to VOLUME_DESCRIPTOR_SIZE with zeros. */

} UnallocatedSpaceDescriptor;

typedef struct __attribute__((packed)) {
    DescriptorTag tag;

    uint8_t padding[496];
} TerminatingDescriptor;

typedef struct __attribute__((packed)) {
    DescriptorTag tag;

    timestamp recordingDateTime;

    uint32_t integrityType;

    extent_ad nextIntegrityExtent;

    uint8_t logicalVolumeContents[32];

    uint32_t numPartitions;

    uint32_t lenImplementationUse;

    uint32_t freeSpaceTable;

    uint32_t sizeTable;

    uint8_t rest[1];

} LogicalVolumeIntegrityDescriptor;

typedef struct __attribute__((packed)) {
    DescriptorTag tag;

    extent_ad mainVolumeDescriptorSequence;

    extent_ad reserveVolumeDescriptorSequence;

    uint8_t reserved[480];

} AnchorVolumeDescriptorPointer;

typedef struct __attribute__((packed)) {
    DescriptorTag tag;

    uint32_t volumeDescriptorSequenceNumber;

    extent_ad nextVolumeDescriptorSequence;

    uint8_t reserved[484];

} VolumeDescriptorPointer;

/*
 * charsetType can be
 0 The CS0 coded character set (1/7.2.2).
 1 The CS1 coded character set (1/7.2.3).
 2 The CS2 coded character set (1/7.2.4).
 3 The CS3 coded character set (1/7.2.5).
 4 The CS4 coded character set (1/7.2.6).
 5 The CS5 coded character set (1/7.2.7).
 6 The CS6 coded character set (1/7.2.8).
 7 The CS7 coded character set (1/7.2.9).
 8 The CS8 coded character set (1/7.2.10).
 9-255 Reserved for future standardisation.
 *
 */
typedef struct __attribute__((packed)) {
    uint8_t charSetType;

    uint8_t charSetInfo[63];
} charspec;

typedef struct __attribute__((packed)) {

    DescriptorTag tag;

    uint32_t volumeDescriptorSequenceNumber;

    charspec descriptorCharSet;

    uint8_t logicalVolumeIdentifier[128]; // TODO: handle dstring

    uint32_t logicalBlockSize;

    regid domainIdentifier;

    uint8_t logicalVolumeContentsUse[16];

    uint32_t mapTableLength;

    uint32_t numPartitionMaps;

    regid implementationIdentifier;

    uint8_t implementationUse[128];

    ext_ad integritySequenceExtent;

    uint8_t partitionMaps[1]; // actual length of mapTableLength above;

} LogicalVolumeDescriptor;

typedef struct __attribute__((packed)) {
    DescriptorTag tag;
    timestamp recordingDateTime;

    uint16_t interchangeLevel;

    uint16_t maxInterchangeLevel;
    uint32_t characterSetList;
    uint32_t maxCharacterSetList;

    uint32_t fileSetNumber;
    uint32_t fileSetDescriptorNumber;

    charspec logicalVolumeIdentifierCharSet;
    uint8_t logicalVolumeIdentifier[128];
    charspec fileSetCharSet;
    uint8_t fileSetIdentifier[32];

    uint8_t copyrightIdentifier[32];
    uint8_t abstractIdentifier[32];
    long_ad rootDirectoryICB;

    regid domainIdentifier;

    long_ad nextExtent;
    long_ad systemStreamDirectoryICB;
    uint8_t reserved[32];

} FileSetDescriptor;

typedef struct __attribute__((packed)) {
    uint8_t structType;
    char standardIdentifier[5];
    uint8_t structVersion;
    uint8_t rest[2041];
} GenericVolumeStructureDescriptor;

#ifdef HAVE_PRAGMA_PACK
#pragma pack()
#endif

#ifdef HAVE_PRAGMA_PACK_HPPA
#pragma pack
#endif

cl_error_t cli_scanudf(cli_ctx* ctx, size_t offset);

#endif /* _UDF_H_ */

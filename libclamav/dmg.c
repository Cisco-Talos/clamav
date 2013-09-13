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

#include <stdio.h>
#include <errno.h>
#if HAVE_STRING_H
#include <string.h>
#endif
#include <ctype.h>
#include <fcntl.h>
#if HAVE_SYS_PARAM_H
#include <sys/param.h>  /* for NAME_MAX */
#endif

#if HAVE_LIBZ
#include <zlib.h>
#endif
#if HAVE_BZLIB_H
#include <bzlib.h>
#ifdef NOBZ2PREFIX
#define BZ2_bzDecompress bzDecompress
#define BZ2_bzDecompressEnd bzDecompressEnd
#define BZ2_bzDecompressInit bzDecompressInit
#endif
#endif

#if HAVE_LIBXML2
#include <libxml/xmlreader.h>
#endif

#include "cltypes.h"
#include "others.h"
#include "dmg.h"
#include "scanners.h"
#include "sf_base64decode.h"

// #define DEBUG_DMG_PARSE

#ifdef DEBUG_DMG_PARSE
#  define dmg_parsemsg(...) cli_dbgmsg( __VA_ARGS__)
#else
#  define dmg_parsemsg(...) ;
#endif

enum dmgReadState {
    DMG_FIND_BASE_PLIST = 0,
    DMG_FIND_BASE_DICT = 1,
    DMG_FIND_KEY_RESOURCE_FORK = 2,
    DMG_FIND_DICT_RESOURCE_FORK = 3,
    DMG_FIND_KEY_BLKX = 4,
    DMG_FIND_BLKX_CONTAINER = 5,
    DMG_FIND_KEY_DATA = 6,
    DMG_FIND_DATA_MISH = 7,
    DMG_MAX_STATE = 8
};

static int dmg_extract_xml(cli_ctx *, char *, struct dmg_koly_block *);
#if HAVE_LIBXML2
static int dmg_decode_mish(cli_ctx *, unsigned int *, xmlChar *, struct dmg_mish_with_stripes *);
#endif
static int cmp_mish_stripes(const void * stripe_a, const void * stripe_b);
static int dmg_track_sectors(uint64_t *, uint8_t *, uint32_t, uint32_t, uint64_t);
static int dmg_handle_mish(cli_ctx *, unsigned int, char *, uint64_t, struct dmg_mish_with_stripes *);

int cli_scandmg(cli_ctx *ctx)
{
    struct dmg_koly_block hdr;
    int ret, namelen, ofd;
    size_t maplen, nread;
    off_t pos = 0;
    char *dirname, *tmpfile;
    const char *outdata;
    unsigned int file = 0;

    unsigned int trailer = 0;
    uint32_t filesize, namesize, hdr_namesize;

    if (!ctx || !ctx->fmap) {
        cli_errmsg("cli_scandmg: Invalid context\n");
        return CL_ENULLARG;
    }

    maplen = (*ctx->fmap)->real_len;
    pos = maplen - 512;
    if (pos <= 0) {
        cli_dbgmsg("cli_scandmg: Sizing problem for DMG archive.\n");
        return CL_CLEAN;
    }

    /* Grab koly block */
    if (fmap_readn(*ctx->fmap, &hdr, pos, sizeof(hdr)) != sizeof(hdr)) {
        cli_dbgmsg("cli_scandmg: Invalid DMG trailer block\n");
        return CL_EFORMAT;
    }

    /* Check magic */
    hdr.magic = be32_to_host(hdr.magic);
    if (hdr.magic == 0x6b6f6c79) {
        cli_dbgmsg("cli_scandmg: Found koly block @ %ld\n", (long) pos);
    }
    else {
        cli_dbgmsg("cli_scandmg: No koly magic, %8x\n", hdr.magic);
        return CL_EFORMAT;
    }

    hdr.xmlOffset = be64_to_host(hdr.xmlOffset);
    hdr.xmlLength = be64_to_host(hdr.xmlLength);
    if (hdr.xmlLength > (uint64_t)INT_MAX) {
        cli_dbgmsg("cli_scandmg: The embedded XML is way larger than necessary, and probably corrupt or tampered with.\n");
        return CL_EFORMAT;
    }
    if ((hdr.xmlOffset > (uint64_t)maplen) || (hdr.xmlLength > (uint64_t)maplen)
        || (hdr.xmlOffset + hdr.xmlLength) > (uint64_t)maplen) {
        cli_dbgmsg("cli_scandmg: XML out of range for this file\n");
        return CL_EFORMAT;
    }
    cli_dbgmsg("cli_scandmg: XML offset %lu len %d\n", (unsigned long)hdr.xmlOffset, (int)hdr.xmlLength);

    /* Create temp folder for contents */
    if (!(dirname = cli_gentemp(ctx->engine->tmpdir))) {
        return CL_ETMPDIR;
    }
    if (mkdir(dirname, 0700)) {
        cli_errmsg("cli_scandmg: Cannot create temporary directory %s\n", dirname);
        free(dirname);
        return CL_ETMPDIR;
    }
    cli_dbgmsg("cli_scandmg: Extracting into %s\n", dirname);

    /* Dump XML to tempfile, if needed */
    if (ctx->engine->keeptmp) {
        int xret;
        xret = dmg_extract_xml(ctx, dirname, &hdr);

        if (xret != CL_SUCCESS) {
            /* Printed err detail inside dmg_extract_xml */
            free(dirname);
            return xret;
        }
    }

    /* scan XML with cli_map_scandesc */
    ret = cli_map_scandesc(*ctx->fmap, (off_t)hdr.xmlOffset, (size_t)hdr.xmlLength, ctx);
    if (ret != CL_CLEAN) {
        cli_dbgmsg("cli_scandmg: retcode from scanning TOC xml: %s\n", cl_strerror(ret));
        if (!ctx->engine->keeptmp)
            cli_rmdirs(dirname);
        free(dirname);
        return ret;
    }

    /* page data from map */
    outdata = fmap_need_off_once_len(*ctx->fmap, hdr.xmlOffset, hdr.xmlLength, &nread);
    if (!outdata || (nread != hdr.xmlLength)) {
        cli_errmsg("cli_scandmg: Failed getting XML from map, len %d\n", (int)hdr.xmlLength);
        if (!ctx->engine->keeptmp)
            cli_rmdirs(dirname);
        free(dirname);
        return CL_EMAP;
    }

    /* time to walk the tree */
    /* plist -> dict -> (key:resource_fork) dict -> (key:blkx) array -> dict */
    /* each of those bottom level dict should have 4 parts */
    /* [ Attributes, Data, ID, Name ], where Data is Base64 mish block */

/* This is the block where we require libxml2 */
#if HAVE_LIBXML2

/* XML_PARSE_NOENT | XML_PARSE_NONET | XML_PARSE_COMPACT */
#define DMG_XML_PARSE_OPTS (1 << 1 | 1 << 11 | 1 << 16)

    xmlTextReaderPtr reader = xmlReaderForMemory(outdata, (int)hdr.xmlLength, "toc.xml", NULL, DMG_XML_PARSE_OPTS);
    if (!reader) {
        cli_dbgmsg("cli_scandmg: Failed parsing XML!\n");
        if (!ctx->engine->keeptmp)
            cli_rmdirs(dirname);
        free(dirname);
        return CL_EFORMAT;
    }

    enum dmgReadState state = DMG_FIND_BASE_PLIST;
    int stateDepth[DMG_MAX_STATE];
    stateDepth[DMG_FIND_BASE_PLIST] = -1;

    // May need to check for (xmlTextReaderIsEmptyElement(reader) == 0)

    /* Break loop if have return code or reader can't read any more */
    while ((ret == CL_CLEAN) && (xmlTextReaderRead(reader) == 1)) {
        xmlReaderTypes nodeType;
        nodeType = xmlTextReaderNodeType(reader);

        if (nodeType == XML_READER_TYPE_ELEMENT) {
            // New element, do name check
            xmlChar *nodeName;
            int depth;

            depth = xmlTextReaderDepth(reader);
            if (depth < 0) {
                break;
            }
            if ((depth > 50) && SCAN_ALGO) {
                // Possible heuristic, should limit runaway
                cli_dbgmsg("cli_scandmg: Excessive nesting in DMG TOC.\n");
                break;
            }
            nodeName = xmlTextReaderLocalName(reader);
            if (!nodeName)
                continue;
            dmg_parsemsg("read: name %s depth %d\n", nodeName, depth);

            if ((state == DMG_FIND_DATA_MISH)
                    && (depth == stateDepth[state-1])) {
                xmlChar * textValue;
                struct dmg_mish_with_stripes mish_set;
                /* Reset state early, for continue cases */
                stateDepth[DMG_FIND_KEY_DATA] = -1;
                state--;
                if (xmlStrcmp(nodeName, "data") != 0) {
                    cli_dbgmsg("cli_scandmg: Not blkx data element\n");
                    xmlFree(nodeName);
                    continue;
                }
                dmg_parsemsg("read: Found blkx data element\n");
                /* Pull out data content from text */
                if (xmlTextReaderIsEmptyElement(reader)) {
                    cli_dbgmsg("cli_scandmg: blkx data element is empty\n");
                    xmlFree(nodeName);
                    continue;
                }
                if (xmlTextReaderRead(reader) != 1) {
                    xmlFree(nodeName);
                    break;
                }   
                if (xmlTextReaderNodeType(reader) != XML_READER_TYPE_TEXT) {
                    cli_dbgmsg("cli_scandmg: Next node not text\n");
                    xmlFree(nodeName);
                    continue;
                }
                textValue = xmlTextReaderValue(reader);
                if (textValue == NULL) {
                    xmlFree(nodeName);
                    continue;
                }
                /* Have encoded mish block */
                ret = dmg_decode_mish(ctx, &file, textValue, &mish_set);
                xmlFree(textValue);
                if (ret == CL_EFORMAT) {
                    /* Didn't decode, or not a mish block */
                    ret = CL_CLEAN;
                    xmlFree(nodeName);
                    continue;
                }
                else if (ret != CL_CLEAN) {
                    xmlFree(nodeName);
                    continue;
                }
                /* Handle & scan mish block */
                ret = dmg_handle_mish(ctx, file, dirname, hdr.xmlOffset, &mish_set);
                free(mish_set.mish);
            }
            if ((state == DMG_FIND_KEY_DATA)
                    && (depth > stateDepth[state-1])
                    && (xmlStrcmp(nodeName, "key") == 0)) {
                xmlChar * textValue;
                dmg_parsemsg("read: Found key - checking for Data\n");
                if (xmlTextReaderRead(reader) != 1) {
                    xmlFree(nodeName);
                    break;
                }   
                if (xmlTextReaderNodeType(reader) != XML_READER_TYPE_TEXT) {
                    cli_dbgmsg("cli_scandmg: Key node no text\n");
                    xmlFree(nodeName);
                    continue;
                }
                textValue = xmlTextReaderValue(reader);
                if (textValue == NULL) {
                    cli_dbgmsg("cli_scandmg: no value from xmlTextReaderValue\n");
                    xmlFree(nodeName);
                    continue;
                }
                if (xmlStrcmp(textValue, "Data") == 0) {
                    dmg_parsemsg("read: Matched data\n");
                    stateDepth[DMG_FIND_KEY_DATA] = depth;
                    state++;
                }
                else {
                    dmg_parsemsg("read: text value is %s\n", textValue);
                }
                xmlFree(textValue);
            }
            if ((state == DMG_FIND_BLKX_CONTAINER)
                    && (depth == stateDepth[state-1])) {
                if (xmlStrcmp(nodeName, "array") == 0) {
                    dmg_parsemsg("read: Found array blkx\n");
                    stateDepth[DMG_FIND_BLKX_CONTAINER] = depth;
                    state++;
                }
                else if (xmlStrcmp(nodeName, "dict") == 0) {
                    dmg_parsemsg("read: Found dict blkx\n");
                    stateDepth[DMG_FIND_BLKX_CONTAINER] = depth;
                    state++;
                }
                else {
                    cli_dbgmsg("cli_scandmg: Bad blkx, not container\n");
                    stateDepth[DMG_FIND_KEY_BLKX] = -1;
                    state--;
                }
            }
            if ((state == DMG_FIND_KEY_BLKX)
                    && (depth == stateDepth[state-1] + 1)
                    && (xmlStrcmp(nodeName, "key") == 0)) {
                xmlChar * textValue;
                dmg_parsemsg("read: Found key - checking for blkx\n");
                if (xmlTextReaderRead(reader) != 1) {
                    xmlFree(nodeName);
                    break;
                }   
                if (xmlTextReaderNodeType(reader) != XML_READER_TYPE_TEXT) {
                    cli_dbgmsg("cli_scandmg: Key node no text\n");
                    xmlFree(nodeName);
                    continue;
                }
                textValue = xmlTextReaderValue(reader);
                if (textValue == NULL) {
                    cli_dbgmsg("cli_scandmg: no value from xmlTextReaderValue\n");
                    xmlFree(nodeName);
                    continue;
                }
                if (xmlStrcmp(textValue, "blkx") == 0) {
                    cli_dbgmsg("cli_scandmg: Matched blkx\n");
                    stateDepth[DMG_FIND_KEY_BLKX] = depth;
                    state++;
                }
                else {
                    cli_dbgmsg("cli_scandmg: wanted blkx, text value is %s\n", textValue);
                }
                xmlFree(textValue);
            }
            if ((state == DMG_FIND_DICT_RESOURCE_FORK)
                    && (depth == stateDepth[state-1])) {
                if (xmlStrcmp(nodeName, "dict") == 0) {
                    dmg_parsemsg("read: Found resource-fork dict\n");
                    stateDepth[DMG_FIND_DICT_RESOURCE_FORK] = depth;
                    state++;
                }
                else {
                    dmg_parsemsg("read: Not resource-fork dict\n");
                    stateDepth[DMG_FIND_KEY_RESOURCE_FORK] = -1;
                    state--;
                }
            }
            if ((state == DMG_FIND_KEY_RESOURCE_FORK)
                    && (depth == stateDepth[state-1] + 1)
                    && (xmlStrcmp(nodeName, "key") == 0)) {
                dmg_parsemsg("read: Found resource-fork key\n");
                stateDepth[DMG_FIND_KEY_RESOURCE_FORK] = depth;
                state++;
            }
            if ((state == DMG_FIND_BASE_DICT)
                    && (depth == stateDepth[state-1] + 1)
                    && (xmlStrcmp(nodeName, "dict") == 0)) {
                dmg_parsemsg("read: Found dict start\n");
                stateDepth[DMG_FIND_BASE_DICT] = depth;
                state++;
            }
            if ((state == DMG_FIND_BASE_PLIST) && (xmlStrcmp(nodeName, "plist") == 0)) {
                dmg_parsemsg("read: Found plist start\n");
                stateDepth[DMG_FIND_BASE_PLIST] = depth;
                state++;
            }
            xmlFree(nodeName);
        }
        else if ((nodeType == XML_READER_TYPE_END_ELEMENT) && (state > DMG_FIND_BASE_PLIST)) {
            int significantEnd = 0;
            int depth = xmlTextReaderDepth(reader);
            if (depth < 0) {
                break;
            }
            else if (depth < stateDepth[state-1]) {
                significantEnd = 1;
            }
            else if ((depth == stateDepth[state-1])
                    && (state-1 == DMG_FIND_BLKX_CONTAINER)) {
                /* Special case, ending blkx container */
                significantEnd = 1;
            }
            if (significantEnd) {
                dmg_parsemsg("read: significant end tag, state %d\n", state);
                stateDepth[state-1] = -1;
                state--;
                if ((state-1 == DMG_FIND_KEY_RESOURCE_FORK)
                        || (state-1 == DMG_FIND_KEY_BLKX)) {
                    /* Keys end their own tag (validly) and the next state depends on the following tag */
                    // cli_dbgmsg("read: significant end tag ending prior key state\n");
                    stateDepth[state-1] = -1;
                    state--;
                }
            }
            else {
                dmg_parsemsg("read: not significant end tag, state %d depth %d prior depth %d\n", state, depth, stateDepth[state-1]);
            }
        }
    }

#else

    cli_dbgmsg("cli_scandmg: libxml2 support is compiled out. It is required for full DMG support.\n");

#endif

    /* Cleanup */
    if (!ctx->engine->keeptmp)
        cli_rmdirs(dirname);
    free(dirname);
    return ret;
}

#if HAVE_LIBXML2
/* Transform the base64-encoded string into the binary structure
 * After this, the base64 string (from xml) can be released
 * If mish_set->mish is set by this function, it must be freed by the caller */
static int dmg_decode_mish(cli_ctx *ctx, unsigned int *mishblocknum, xmlChar *mish_base64,
        struct dmg_mish_with_stripes *mish_set)
{
    int ret = CL_CLEAN;
    size_t base64_len, buff_size, decoded_len;
    uint8_t *decoded;
    const uint8_t mish_magic[4] = { 0x6d, 0x69, 0x73, 0x68 };

    (*mishblocknum)++;
    base64_len = strlen(mish_base64);
    cli_dbgmsg("dmg_decode_mish: len of encoded block %u is %lu\n", *mishblocknum, base64_len);

    /* speed vs memory, could walk the encoded data and skip whitespace in calculation */
    buff_size = 3 * base64_len / 4 + 4;
    cli_dbgmsg("dmg_decode_mish: buffer for mish block %u is %lu\n", *mishblocknum, (unsigned long)buff_size);
    decoded = cli_malloc(buff_size);
    if (!decoded)
        return CL_EMEM;

    if (sf_base64decode((uint8_t *)mish_base64, base64_len, decoded, buff_size - 1, &decoded_len)) {
        cli_dbgmsg("dmg_decode_mish: failed base64 decoding on mish block %u\n", *mishblocknum);
        free(decoded);
        return CL_EFORMAT;
    }
    cli_dbgmsg("dmg_decode_mish: len of decoded mish block %u is %lu\n", *mishblocknum, (unsigned long)decoded_len);
    
    if (decoded_len < sizeof(struct dmg_mish_block)) {
        cli_dbgmsg("dmg_decode_mish: block %u too short for valid mish block\n", *mishblocknum);
        free(decoded);
        return CL_EFORMAT;
    }
    /* mish check: magic is mish, have to check after conversion from base64
     * mish base64 is bWlzaA [but last character can change last two bytes]
     * won't see that in practice much (affects value of version field) */
    if (memcmp(decoded, mish_magic, 4)) {
        cli_dbgmsg("dmg_decode_mish: block %u does not have mish magic\n", *mishblocknum);
        free(decoded);
        return CL_EFORMAT;
    }

    mish_set->mish = (struct dmg_mish_block *)decoded;
    mish_set->mish->startSector = be64_to_host(mish_set->mish->startSector);
    mish_set->mish->sectorCount = be64_to_host(mish_set->mish->sectorCount);
    mish_set->mish->dataOffset = be64_to_host(mish_set->mish->dataOffset);
    // mish_set->mish->bufferCount = be32_to_host(mish_set->mish->bufferCount);
    mish_set->mish->blockDataCount = be32_to_host(mish_set->mish->blockDataCount);

    cli_dbgmsg("dmg_decode_mish: startSector = %lu\n", mish_set->mish->startSector);
    cli_dbgmsg("dmg_decode_mish: sectorCount = %lu\n", mish_set->mish->sectorCount);
    cli_dbgmsg("dmg_decode_mish: dataOffset = %lu\n", mish_set->mish->dataOffset);
    // cli_dbgmsg("dmg_decode_mish: bufferCount = %lu\n", mish_set->mish->bufferCount);
    cli_dbgmsg("dmg_decode_mish: blockDataCount = %lu\n", mish_set->mish->blockDataCount);

    /* decoded length should be mish block + blockDataCount * 40 */
    if (decoded_len < (sizeof(struct dmg_mish_block)
         + mish_set->mish->blockDataCount * sizeof(struct dmg_block_data))) {
        cli_dbgmsg("dmg_decode_mish: mish block %u too small\n", *mishblocknum);
        free(decoded);
        mish_set->mish = NULL;
        return CL_EFORMAT;
    }
    else if (decoded_len > (sizeof(struct dmg_mish_block)
         + mish_set->mish->blockDataCount * sizeof(struct dmg_block_data))) {
        cli_dbgmsg("dmg_decode_mish: mish block %u bigger than needed, continuing\n", *mishblocknum);
    }

    mish_set->stripes = (struct dmg_block_data *)(decoded + sizeof(struct dmg_mish_block));
    return CL_CLEAN;
}
#endif

/* Comparator for stripe sorting */
static int cmp_mish_stripes(const void * stripe_a, const void * stripe_b)
{
    const struct dmg_block_data *a = stripe_a, *b = stripe_b;
    return a->startSector - b->startSector;
}

/* Safely track sector sizes for output estimate */
static int dmg_track_sectors(uint64_t *total, uint8_t *data_to_write,
    uint32_t stripeNum, uint32_t stripeType, uint64_t stripeCount)
{
    int ret = CL_CLEAN, usable = 0;

    switch (stripeType) {
        case DMG_STRIPE_STORED:
            *data_to_write = 1;
            usable = 1;
            break;
        case DMG_STRIPE_ADC:
            *data_to_write = 1;
            usable = 1;
            break;
        case DMG_STRIPE_DEFLATE:
#if HAVE_LIBZ
            *data_to_write = 1;
            usable = 1;
#else
            cli_warnmsg("dmg_track_sectors: Need zlib decompression to properly scan this file.\n");
            return CL_EFORMAT;
#endif
            break;
        case DMG_STRIPE_BZ:
#if HAVE_BZLIB_H
            *data_to_write = 1;
            usable = 1;
#else
            cli_warnmsg("dmg_track_sectors: Need bzip2 decompression to properly scan this file.\n");
            return CL_EFORMAT;
#endif
            break;
        case DMG_STRIPE_EMPTY:
        case DMG_STRIPE_ZEROES:
            /* Usable, but only zeroes is not worth scanning on its own */
            usable = 1;
            break;
        case DMG_STRIPE_SKIP:
        case DMG_STRIPE_END:
            /* These should be sectorCount 0 */
            break;
        default:
            if (stripeCount) {
                /* Continue for now */
                cli_dbgmsg("dmg_track_sectors: unknown type on stripe %lu, will skip\n", stripeNum);
            }
            else {
                /* Continue, no sectors missed  */
                cli_dbgmsg("dmg_track_sectors: unknown type on empty stripe %lu\n", stripeNum);
            }
            break;
    }

    if (usable) {
        /* Check for wrap */
        if (*total < (*total + stripeCount)) {
            *total = *total + stripeCount;
        }
        else if (stripeCount) {
            cli_dbgmsg("dmg_track_sectors: *total would wrap uint64, suspicious\n");
            ret = CL_EFORMAT;
        }
        else {
            /* Can continue */
            cli_dbgmsg("dmg_track_sectors: unexpected zero sectorCount on stripe %lu\n", stripeNum);
        }
    }

    return ret;
}

/* Given mish data, reconstruct the partition details */
static int dmg_handle_mish(cli_ctx *ctx, unsigned int mishblocknum, char *dir,
        uint64_t xmlOffset, struct dmg_mish_with_stripes *mish_set)
{
    struct dmg_block_data *blocklist = mish_set->stripes;
    uint64_t totalSectors = 0;
    uint32_t i;
    unsigned long projected_size;
    int ret = CL_CLEAN, ofd;
    uint8_t sorted = 1, writeable_data = 0;
    char outfile[NAME_MAX + 1];

    /* First loop, fix endian-ness and check if already sorted */
    for (i = 0; i < mish_set->mish->blockDataCount; i++) {
        blocklist[i].type = be32_to_host(blocklist[i].type);
        // blocklist[i].reserved = be32_to_host(blocklist[i].reserved);
        blocklist[i].startSector = be64_to_host(blocklist[i].startSector);
        blocklist[i].sectorCount = be64_to_host(blocklist[i].sectorCount);
        blocklist[i].dataOffset = be64_to_host(blocklist[i].dataOffset);
        blocklist[i].dataLength = be64_to_host(blocklist[i].dataLength);
        cli_dbgmsg("mish %lu block %u type %lx start %lu count %lu source %lu length %lu\n", mishblocknum, i,
            blocklist[i].type, blocklist[i].startSector, blocklist[i].sectorCount,
            blocklist[i].dataOffset, blocklist[i].dataLength);
        if ((blocklist[i].dataOffset > xmlOffset) || 
               (blocklist[i].dataOffset + blocklist[i].dataLength > xmlOffset)) {
            cli_dbgmsg("dmg_handle_mish: invalid stripe offset and/or length\n");
            return CL_EFORMAT;
        }
        if ((i > 0) && sorted && (blocklist[i].startSector < blocklist[i-1].startSector)) {
            cli_dbgmsg("dmg_handle_mish: stripes not in order, will have to sort\n");
            sorted = 0;
        }
        if (dmg_track_sectors(&totalSectors, &writeable_data, i, blocklist[i].type, blocklist[i].sectorCount)) {
            /* reason was logged from dmg_track_sector_count */
            return CL_EFORMAT;
        }
    }

    if (!sorted) {
        cli_qsort(blocklist, mish_set->mish->blockDataCount, sizeof(struct dmg_block_data), cmp_mish_stripes);
    }
    cli_dbgmsg("dmg_handle_mish: stripes in order!\n");

    /* Size checks */
    if ((writeable_data == 0) || (totalSectors == 0)) {
        cli_dbgmsg("dmg_handle_mish: no data to output\n");
        return CL_CLEAN;
    }
    else if (totalSectors > (ULONG_MAX / DMG_SECTOR_SIZE)) {
        /* cli_checklimits only takes unsigned long for now */
        cli_warnmsg("dmg_handle_mish: mish block %u too big to handle (for now)", mishblocknum);
        return CL_CLEAN;
    }
    projected_size = (unsigned long)(totalSectors * DMG_SECTOR_SIZE);
    ret = cli_checklimits("cli_scandmg", ctx, projected_size, 0, 0);
    if (ret != CL_CLEAN) {
        /* limits exceeded */
        cli_dbgmsg("dmg_handle_mish: skipping block %u, limits exceeded\n", mishblocknum);
        return ret;
    }

    /* Prepare for file */
    snprintf(outfile, sizeof(outfile)-1, "%s"PATHSEP"dmg%02u", dir, mishblocknum);
    outfile[sizeof(outfile)-1] = '\0';
    ofd = open(outfile, O_RDWR|O_CREAT|O_EXCL|O_TRUNC|O_BINARY, 0600);
    if (ofd < 0) {
        char err[128];
        cli_errmsg("cli_scandmg: Can't create temporary file %s: %s\n", 
            outfile, cli_strerror(errno, err, sizeof(err)));
        return CL_ETMPFILE;
    }
    cli_dbgmsg("dmg_handle_mish: extracting block %u to %s\n", mishblocknum, outfile);

    /* Push data, stripe by stripe */
    for(i=0; i < mish_set->mish->blockDataCount && ret == CL_CLEAN; i++) {
        switch (blocklist[i].type) {
            case DMG_STRIPE_EMPTY:
            case DMG_STRIPE_ZEROES:
                cli_dbgmsg("dmg_handle_mish: stripe %lu, zero block\n", (unsigned long)i);
                break;
            case DMG_STRIPE_STORED:
                cli_dbgmsg("dmg_handle_mish: stripe %lu, stored data block\n", (unsigned long)i);
                break;
            case DMG_STRIPE_ADC:
                cli_dbgmsg("dmg_handle_mish: stripe %lu, ADC data block\n", (unsigned long)i);
                break;
            case DMG_STRIPE_DEFLATE:
                cli_dbgmsg("dmg_handle_mish: stripe %lu, zlib block\n", (unsigned long)i);
                break;
            case DMG_STRIPE_BZ:
                cli_dbgmsg("dmg_handle_mish: stripe %lu, bzip block\n", (unsigned long)i);
                break;
            case DMG_STRIPE_SKIP:
            case DMG_STRIPE_END:
            default:
                cli_dbgmsg("dmg_handle_mish: stripe %lu, skipped\n", (unsigned long)i);
                break;
        }
    }

    // ret = cli_magic_scandesc(ofd, ctx);
    close(ofd);
    if (!ctx->engine->keeptmp)
        if (cli_unlink(outfile)) return CL_EUNLINK;
    
    return ret;
}

static int dmg_extract_xml(cli_ctx *ctx, char *dir, struct dmg_koly_block *hdr)
{
    char * xmlfile;
    const char *outdata;
    size_t namelen, nread;
    int ofd;

    /* Prep TOC XML for output */
    outdata = fmap_need_off_once_len(*ctx->fmap, hdr->xmlOffset, hdr->xmlLength, &nread);
    if (!outdata || (nread != hdr->xmlLength)) {
        cli_errmsg("cli_scandmg: Failed getting XML from map, len %ld\n", hdr->xmlLength);
        return CL_EMAP;
    }

    namelen = strlen(dir) + 1 + 7 + 1;
    if (!(xmlfile = cli_malloc(namelen))) {
        return CL_EMEM;
    }
    snprintf(xmlfile, namelen, "%s"PATHSEP"toc.xml", dir);
    cli_dbgmsg("cli_scandmg: Extracting XML as %s\n", xmlfile);

    /* Write out TOC XML */
    if ((ofd = open(xmlfile, O_CREAT|O_RDWR|O_EXCL|O_TRUNC|O_BINARY, S_IRWXU)) < 0) {
        return CL_ETMPFILE;
    }

    if (cli_writen(ofd, outdata, hdr->xmlLength) != hdr->xmlLength) {
        cli_errmsg("cli_scandmg: Not all bytes written!\n");
        close(ofd);
        free(xmlfile);
        return CL_EWRITE;
    }

    close(ofd);
    free(xmlfile);
    return CL_SUCCESS;
}


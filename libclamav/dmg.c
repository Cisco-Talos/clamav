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

#include "clamav.h"
#include "others.h"
#include "dmg.h"
#include "scanners.h"
#include "sf_base64decode.h"
#include "adc.h"

/* #define DEBUG_DMG_PARSE */
/* #define DEBUG_DMG_BZIP */

#ifdef DEBUG_DMG_PARSE
#  define dmg_parsemsg(...) cli_dbgmsg( __VA_ARGS__)
#else
#  define dmg_parsemsg(...) ;
#endif

#ifdef DEBUG_DMG_BZIP
#  define dmg_bzipmsg(...) cli_dbgmsg( __VA_ARGS__)
#else
#  define dmg_bzipmsg(...) ;
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
    int ret;
    size_t maplen, nread;
    off_t pos = 0;
    char *dirname;
    const char *outdata;
    unsigned int file = 0;
    struct dmg_mish_with_stripes *mish_list = NULL, *mish_list_tail = NULL;
    enum dmgReadState state = DMG_FIND_BASE_PLIST;
    int stateDepth[DMG_MAX_STATE];
#if HAVE_LIBXML2
    xmlTextReaderPtr reader;
#endif

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

    hdr.dataForkOffset = be64_to_host(hdr.dataForkOffset);
    hdr.dataForkLength = be64_to_host(hdr.dataForkLength);
    cli_dbgmsg("cli_scandmg: data offset %lu len %d\n", (unsigned long)hdr.dataForkOffset, (int)hdr.dataForkLength);

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
    if (hdr.xmlLength == 0) {
        cli_dbgmsg("cli_scandmg: Embedded XML length is zero.\n");
        return CL_EFORMAT;
    }

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
    if (ctx->engine->keeptmp && !(ctx->engine->engine_options & ENGINE_OPTIONS_FORCE_TO_DISK)) {
        int xret;
        xret = dmg_extract_xml(ctx, dirname, &hdr);

        if (xret != CL_SUCCESS) {
            /* Printed err detail inside dmg_extract_xml */
            free(dirname);
            return xret;
        }
    }

    /* scan XML with cli_map_scandesc */
    ret = cli_map_scan(*ctx->fmap, (off_t)hdr.xmlOffset, (size_t)hdr.xmlLength, ctx, CL_TYPE_ANY);
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
#define DMG_XML_PARSE_OPTS ((1 << 1 | 1 << 11 | 1 << 16) | CLAMAV_MIN_XMLREADER_FLAGS)

    reader = xmlReaderForMemory(outdata, (int)hdr.xmlLength, "toc.xml", NULL, DMG_XML_PARSE_OPTS);
    if (!reader) {
        cli_dbgmsg("cli_scandmg: Failed parsing XML!\n");
        if (!ctx->engine->keeptmp)
            cli_rmdirs(dirname);
        free(dirname);
        return CL_EFORMAT;
    }

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
            if ((depth > 50) && SCAN_HEURISTICS) {
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
                struct dmg_mish_with_stripes *mish_set;
                /* Reset state early, for continue cases */
                stateDepth[DMG_FIND_KEY_DATA] = -1;
                state--;
                if (xmlStrcmp(nodeName, (const xmlChar *)"data") != 0) {
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
                mish_set = cli_malloc(sizeof(struct dmg_mish_with_stripes));
                if (mish_set == NULL) {
                    ret = CL_EMEM;
                    xmlFree(textValue);
                    xmlFree(nodeName);
                    break;
                }
                ret = dmg_decode_mish(ctx, &file, textValue, mish_set);
                xmlFree(textValue);
                if (ret == CL_EFORMAT) {
                    /* Didn't decode, or not a mish block */
                    ret = CL_CLEAN;
                    free(mish_set);
                    xmlFree(nodeName);
                    continue;
                }
                else if (ret != CL_CLEAN) {
                    xmlFree(nodeName);
                    free(mish_set);
                    continue;
                }
                /* Add mish block to list */
                if (mish_list_tail != NULL) {
                    mish_list_tail->next = mish_set;
                    mish_list_tail = mish_set;
                }
                else {
                    mish_list = mish_set;
                    mish_list_tail = mish_set;
                }
                mish_list_tail->next = NULL;
            }
            if ((state == DMG_FIND_KEY_DATA)
                    && (depth > stateDepth[state-1])
                    && (xmlStrcmp(nodeName, (const xmlChar *)"key") == 0)) {
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
                if (xmlStrcmp(textValue, (const xmlChar *)"Data") == 0) {
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
                if (xmlStrcmp(nodeName, (const xmlChar *)"array") == 0) {
                    dmg_parsemsg("read: Found array blkx\n");
                    stateDepth[DMG_FIND_BLKX_CONTAINER] = depth;
                    state++;
                }
                else if (xmlStrcmp(nodeName, (const xmlChar *)"dict") == 0) {
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
                    && (xmlStrcmp(nodeName, (const xmlChar *)"key") == 0)) {
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
                if (xmlStrcmp(textValue, (const xmlChar *)"blkx") == 0) {
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
                if (xmlStrcmp(nodeName, (const xmlChar *)"dict") == 0) {
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
                    && (xmlStrcmp(nodeName, (const xmlChar *)"key") == 0)) {
                dmg_parsemsg("read: Found resource-fork key\n");
                stateDepth[DMG_FIND_KEY_RESOURCE_FORK] = depth;
                state++;
            }
            if ((state == DMG_FIND_BASE_DICT)
                    && (depth == stateDepth[state-1] + 1)
                    && (xmlStrcmp(nodeName, (const xmlChar *)"dict") == 0)) {
                dmg_parsemsg("read: Found dict start\n");
                stateDepth[DMG_FIND_BASE_DICT] = depth;
                state++;
            }
            if ((state == DMG_FIND_BASE_PLIST) && (xmlStrcmp(nodeName, (const xmlChar *)"plist") == 0)) {
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

    xmlFreeTextReader(reader);

#else

    cli_dbgmsg("cli_scandmg: libxml2 support is compiled out. It is required for full DMG support.\n");

#endif

    /* Loop over mish array */
    file = 0;
    while ((ret == CL_CLEAN) && (mish_list != NULL)) {
        /* Handle & scan mish block */
        ret = dmg_handle_mish(ctx, file++, dirname, hdr.xmlOffset, mish_list);
        free(mish_list->mish);
        mish_list_tail = mish_list;
        mish_list = mish_list->next;
        free(mish_list_tail);
    }

    /* Cleanup */
    /* If error occurred, need to free mish items and mish blocks */
    while (mish_list != NULL) {
        free(mish_list->mish);
        mish_list_tail = mish_list;
        mish_list = mish_list->next;
        free(mish_list_tail);
    }
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
    size_t base64_len, buff_size, decoded_len;
    uint8_t *decoded;
    const uint8_t mish_magic[4] = { 0x6d, 0x69, 0x73, 0x68 };

    UNUSEDPARAM(ctx);

    (*mishblocknum)++;
    base64_len = strlen((const char *)mish_base64);
    dmg_parsemsg("dmg_decode_mish: len of encoded block %u is %lu\n", *mishblocknum, base64_len);

    /* speed vs memory, could walk the encoded data and skip whitespace in calculation */
    buff_size = 3 * base64_len / 4 + 4;
    dmg_parsemsg("dmg_decode_mish: buffer for mish block %u is %lu\n", *mishblocknum, (unsigned long)buff_size);
    decoded = cli_malloc(buff_size);
    if (!decoded)
        return CL_EMEM;

    if (sf_base64decode((uint8_t *)mish_base64, base64_len, decoded, buff_size - 1, &decoded_len)) {
        cli_dbgmsg("dmg_decode_mish: failed base64 decoding on mish block %u\n", *mishblocknum);
        free(decoded);
        return CL_EFORMAT;
    }
    dmg_parsemsg("dmg_decode_mish: len of decoded mish block %u is %lu\n", *mishblocknum, (unsigned long)decoded_len);
    
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

    cli_dbgmsg("dmg_decode_mish: startSector = " STDu64 " sectorCount = " STDu64
        " dataOffset = " STDu64 " stripeCount = " STDu32 "\n",
        mish_set->mish->startSector, mish_set->mish->sectorCount,
        mish_set->mish->dataOffset, mish_set->mish->blockDataCount);

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
                cli_dbgmsg("dmg_track_sectors: unknown type on stripe " STDu32 ", will skip\n", stripeNum);
            }
            else {
                /* Continue, no sectors missed  */
                cli_dbgmsg("dmg_track_sectors: unknown type on empty stripe " STDu32 "\n", stripeNum);
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
            cli_dbgmsg("dmg_track_sectors: unexpected zero sectorCount on stripe " STDu32 "\n", stripeNum);
        }
    }

    return ret;
}

/* Stripe handling: zero block (type 0x0 or 0x2) */
static int dmg_stripe_zeroes(cli_ctx *ctx, int fd, uint32_t index, struct dmg_mish_with_stripes *mish_set)
{
    int ret = CL_CLEAN;
    size_t len = mish_set->stripes[index].sectorCount * DMG_SECTOR_SIZE;
    ssize_t written;
    uint8_t obuf[BUFSIZ];

    UNUSEDPARAM(ctx);

    cli_dbgmsg("dmg_stripe_zeroes: stripe " STDu32 "\n", index);
    if (len == 0)
        return CL_CLEAN;

    memset(obuf, 0, sizeof(obuf));
    while (len > sizeof(obuf)) {
        written = cli_writen(fd, obuf, sizeof(obuf));
        if ((size_t)written != sizeof(obuf)) {
            ret = CL_EWRITE;
            break;
        }
        len -= sizeof(obuf);
    }

    if ((ret == CL_CLEAN) && (len > 0)) {
        written = cli_writen(fd, obuf, len);
        if ((size_t)written != len) {
            ret = CL_EWRITE;
        }
    }

    if (ret != CL_CLEAN) {
        cli_errmsg("dmg_stripe_zeroes: error writing bytes to file (out of disk space?)\n");
        return CL_EWRITE;
    }
    return CL_CLEAN;
}

/* Stripe handling: stored block (type 0x1) */
static int dmg_stripe_store(cli_ctx *ctx, int fd, uint32_t index, struct dmg_mish_with_stripes *mish_set)
{
    const void *obuf;
    size_t off = mish_set->stripes[index].dataOffset;
    size_t len = mish_set->stripes[index].dataLength;
    ssize_t written;

    cli_dbgmsg("dmg_stripe_store: stripe " STDu32 "\n", index);
    if (len == 0)
        return CL_CLEAN;

    obuf = (void *)fmap_need_off_once(*ctx->fmap, off, len);
    if (!obuf) {
        cli_warnmsg("dmg_stripe_store: fmap need failed on stripe " STDu32 "\n", index);
        return CL_EMAP;
    }
    written = cli_writen(fd, obuf, len);
    if (written < 0) {
        cli_errmsg("dmg_stripe_store: error writing bytes to file (out of disk space?)\n");
        return CL_EWRITE;
    }
    else if ((size_t)written != len) {
        cli_errmsg("dmg_stripe_store: error writing bytes to file (out of disk space?)\n");
        return CL_EWRITE;
    }
    return CL_CLEAN;
}

/* Stripe handling: ADC block (type 0x80000004) */
static int dmg_stripe_adc(cli_ctx *ctx, int fd, uint32_t index, struct dmg_mish_with_stripes *mish_set)
{
    int adcret;
    adc_stream strm;
    size_t off = mish_set->stripes[index].dataOffset;
    size_t len = mish_set->stripes[index].dataLength;
    uint64_t size_so_far = 0;
    uint64_t expected_len = mish_set->stripes[index].sectorCount * DMG_SECTOR_SIZE;
    uint8_t obuf[BUFSIZ];

    cli_dbgmsg("dmg_stripe_adc: stripe " STDu32 " initial len " STDu64 " expected len " STDu64 "\n",
            index, (uint64_t)len, (uint64_t)expected_len);
    if (len == 0)
        return CL_CLEAN;

    memset(&strm, 0, sizeof(strm));
    strm.next_in = (uint8_t *)fmap_need_off_once(*ctx->fmap, off, len);
    if (!strm.next_in) {
        cli_warnmsg("dmg_stripe_adc: fmap need failed on stripe " STDu32 "\n", index);
        return CL_EMAP;
    }
    strm.avail_in = len;
    strm.next_out = obuf;
    strm.avail_out = sizeof(obuf);

    adcret = adc_decompressInit(&strm);
    if(adcret != ADC_OK) {
        cli_warnmsg("dmg_stripe_adc: adc_decompressInit failed\n");
        return CL_EMEM;
    }

    while(adcret == ADC_OK) {
        int written;
        if (size_so_far > expected_len) {
            cli_warnmsg("dmg_stripe_adc: expected size exceeded!\n");
            adc_decompressEnd(&strm);
            return CL_EFORMAT;
        }
        adcret = adc_decompress(&strm);
        switch(adcret) {
            case ADC_OK:
                if(strm.avail_out == 0) {
                    if ((written=cli_writen(fd, obuf, sizeof(obuf)))!=sizeof(obuf)) {
                        cli_errmsg("dmg_stripe_adc: failed write to output file\n");
                        adc_decompressEnd(&strm);
                        return CL_EWRITE;
                    }
                    size_so_far += written;
                    strm.next_out = obuf;
                    strm.avail_out = sizeof(obuf);
                }
                continue;
            case ADC_STREAM_END:
            default:
                written = sizeof(obuf) - strm.avail_out;
                if (written) {
                    if ((cli_writen(fd, obuf, written))!=written) {
                        cli_errmsg("dmg_stripe_adc: failed write to output file\n");
                        adc_decompressEnd(&strm);
                        return CL_EWRITE;
                    }
                    size_so_far += written;
                    strm.next_out = obuf;
                    strm.avail_out = sizeof(obuf);
                }
                if (adcret == ADC_STREAM_END)
                    break;
                cli_dbgmsg("dmg_stripe_adc: after writing " STDu64 " bytes, "
                           "got error %d decompressing stripe " STDu32 "\n",
                           size_so_far, adcret, index);
                adc_decompressEnd(&strm);
                return CL_EFORMAT;
        }
        break;
    }

    adc_decompressEnd(&strm);
    cli_dbgmsg("dmg_stripe_adc: stripe " STDu32 " actual len " STDu64 " expected len " STDu64 "\n",
            index, size_so_far, expected_len);
    return CL_CLEAN;
}

/* Stripe handling: deflate block (type 0x80000005) */
static int dmg_stripe_inflate(cli_ctx *ctx, int fd, uint32_t index, struct dmg_mish_with_stripes *mish_set)
{
    int zstat;
    z_stream strm;
    size_t off = mish_set->stripes[index].dataOffset;
    size_t len = mish_set->stripes[index].dataLength;
    uint64_t size_so_far = 0;
    uint64_t expected_len = mish_set->stripes[index].sectorCount * DMG_SECTOR_SIZE;
    uint8_t obuf[BUFSIZ];

    cli_dbgmsg("dmg_stripe_inflate: stripe " STDu32 "\n", index);
    if (len == 0)
        return CL_CLEAN;

    memset(&strm, 0, sizeof(strm));
    strm.next_in = (void*)fmap_need_off_once(*ctx->fmap, off, len);
    if (!strm.next_in) {
        cli_warnmsg("dmg_stripe_inflate: fmap need failed on stripe " STDu32 "\n", index);
        return CL_EMAP;
    }
    strm.avail_in = len;
    strm.next_out = obuf;
    strm.avail_out = sizeof(obuf);

    zstat = inflateInit(&strm);
    if(zstat != Z_OK) {
        cli_warnmsg("dmg_stripe_inflate: inflateInit failed\n");
        return CL_EMEM;
    }

    while(strm.avail_in) {
        int written;
        if (size_so_far > expected_len) {
            cli_warnmsg("dmg_stripe_inflate: expected size exceeded!\n");
            inflateEnd(&strm);
            return CL_EFORMAT;
        }
        zstat = inflate(&strm, Z_NO_FLUSH);   /* zlib */
        switch(zstat) {
            case Z_OK:
                if(strm.avail_out == 0) {
                    if ((written=cli_writen(fd, obuf, sizeof(obuf)))!=sizeof(obuf)) {
                        cli_errmsg("dmg_stripe_inflate: failed write to output file\n");
                        inflateEnd(&strm);
                        return CL_EWRITE;
                    }
                    size_so_far += written;
                    strm.next_out = (Bytef *)obuf;
                    strm.avail_out = sizeof(obuf);
                }
                continue;
            case Z_STREAM_END:
            default:
                written = sizeof(obuf) - strm.avail_out;
                if (written) {
                    if ((cli_writen(fd, obuf, written))!=written) {
                        cli_errmsg("dmg_stripe_inflate: failed write to output file\n");
                        inflateEnd(&strm);
                        return CL_EWRITE;
                    }
                    size_so_far += written;
                    strm.next_out = (Bytef *)obuf;
                    strm.avail_out = sizeof(obuf);
                    if (zstat == Z_STREAM_END)
                        break;
                }
                if(strm.msg)
                    cli_dbgmsg("dmg_stripe_inflate: after writing " STDu64 " bytes, "
                               "got error \"%s\" inflating stripe " STDu32 "\n",
                               size_so_far, strm.msg, index);
                else
                    cli_dbgmsg("dmg_stripe_inflate: after writing " STDu64 " bytes, "
                               "got error %d inflating stripe " STDu32 "\n",
                               size_so_far, zstat, index);
                inflateEnd(&strm);
                return CL_EFORMAT;
        }
        break;
    }

    if(strm.avail_out != sizeof(obuf)) {
        if(cli_writen(fd, obuf, sizeof(obuf) - strm.avail_out) < 0) {
            cli_errmsg("dmg_stripe_inflate: failed write to output file\n");
            inflateEnd(&strm);
            return CL_EWRITE;
        }
    }

    inflateEnd(&strm);
    return CL_CLEAN;
}

/* Stripe handling: bzip block (type 0x80000006) */
static int dmg_stripe_bzip(cli_ctx *ctx, int fd, uint32_t index, struct dmg_mish_with_stripes *mish_set)
{
    int ret = CL_CLEAN;
    size_t off = mish_set->stripes[index].dataOffset;
    size_t len = mish_set->stripes[index].dataLength;
    uint64_t size_so_far = 0;
    uint64_t expected_len = mish_set->stripes[index].sectorCount * DMG_SECTOR_SIZE;
#if HAVE_BZLIB_H
    int rc;
    bz_stream strm;
    uint8_t obuf[BUFSIZ];
#endif

    cli_dbgmsg("dmg_stripe_bzip: stripe " STDu32 " initial len " STDu64 " expected len " STDu64 "\n",
            index, (uint64_t)len, (uint64_t)expected_len);

#if HAVE_BZLIB_H
    memset(&strm, 0, sizeof(strm));
    strm.next_out = (char *)obuf;
    strm.avail_out = sizeof(obuf);
    if (BZ2_bzDecompressInit(&strm, 0, 0) != BZ_OK) {
        cli_dbgmsg("dmg_stripe_bzip: bzDecompressInit failed\n");
        return CL_EOPEN;
    }

    do {
        if (size_so_far > expected_len) {
            cli_warnmsg("dmg_stripe_bzip: expected size exceeded!\n");
            ret = CL_EFORMAT;
            break;
        }
        if (strm.avail_in == 0) {
            size_t next_len = (len > sizeof(obuf)) ? sizeof(obuf) : len;
            dmg_bzipmsg("dmg_stripe_bzip: off %lu len %lu next_len %lu\n", off, len, next_len);
            strm.next_in = (void*)fmap_need_off_once(*ctx->fmap, off, next_len);
            if (strm.next_in == NULL) {
                cli_dbgmsg("dmg_stripe_bzip: expected more stream\n");
                ret = CL_EMAP;
                break;
            }
            strm.avail_in = next_len;
            len -= next_len;
            off += next_len;
        }

        dmg_bzipmsg("dmg_stripe_bzip: before = strm.avail_in %lu strm.avail_out: %lu\n", strm.avail_in, strm.avail_out);
        rc = BZ2_bzDecompress(&strm);
        if ((rc != BZ_OK) && (rc != BZ_STREAM_END)) {
            cli_dbgmsg("dmg_stripe_bzip: decompress error: %d\n", rc);
            ret = CL_EFORMAT;
            break;
        }

        dmg_bzipmsg("dmg_stripe_bzip: after = strm.avail_in %lu strm.avail_out: %lu rc: %d %d\n",
                strm.avail_in, strm.avail_out, rc, BZ_STREAM_END);
        /* Drain output buffer */
        if (!strm.avail_out) {
            size_t next_write = sizeof(obuf);
            do {
                size_so_far += next_write;
                dmg_bzipmsg("dmg_stripe_bzip: size_so_far: " STDu64 " next_write: %lu\n", size_so_far, next_write);
                if (size_so_far > expected_len) {
                    cli_warnmsg("dmg_stripe_bzip: expected size exceeded!\n");
                    ret = CL_EFORMAT;
                    rc = BZ_DATA_ERROR; /* prevent stream end block */
                    break;
                }

                ret = cli_checklimits("dmg_stripe_bzip", ctx, (unsigned long)(size_so_far + sizeof(obuf)), 0, 0);
                if (ret != CL_CLEAN) {
                    break;
                }

                if ((size_t)cli_writen(fd, obuf, next_write) != next_write) {
                    cli_dbgmsg("dmg_stripe_bzip: error writing to tmpfile\n");
                    ret = CL_EWRITE;
                    break;
                }

                strm.next_out = (char *)obuf;
                strm.avail_out = sizeof(obuf);

                if (rc == BZ_OK)
                    rc = BZ2_bzDecompress(&strm);
                if ((rc != BZ_OK) && (rc != BZ_STREAM_END)) {
                    cli_dbgmsg("dmg_stripe_bzip: decompress error: %d\n", rc);
                    ret = CL_EFORMAT;
                    break;
                }
            } while (!strm.avail_out);
        }
        /* Stream end, so write data if any remains in buffer */
        if (rc == BZ_STREAM_END) {
            size_t next_write = sizeof(obuf) - strm.avail_out;
            size_so_far += next_write;
            dmg_bzipmsg("dmg_stripe_bzip: size_so_far: " STDu64 " next_write: %lu\n", size_so_far, next_write);

            ret = cli_checklimits("dmg_stripe_bzip", ctx, (unsigned long)(size_so_far + sizeof(obuf)), 0, 0);
            if (ret != CL_CLEAN) {
                break;
            }

            if ((size_t)cli_writen(fd, obuf, next_write) != next_write) {
                cli_dbgmsg("dmg_stripe_bzip: error writing to tmpfile\n");
                ret = CL_EWRITE;
                break;
            }

            strm.next_out = (char *)obuf;
            strm.avail_out = sizeof(obuf);
        }
    } while ((rc == BZ_OK) && (len > 0));

    BZ2_bzDecompressEnd(&strm);
#endif

    if (ret == CL_CLEAN) {
        if (size_so_far != expected_len) {
            cli_dbgmsg("dmg_stripe_bzip: output does not match expected size!\n");
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
        cli_dbgmsg("mish %u stripe " STDu32 " type " STDx32 " start " STDu64
            " count " STDu64 " source " STDu64 " length " STDu64 "\n",
            mishblocknum, i, blocklist[i].type, blocklist[i].startSector, blocklist[i].sectorCount,
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
                ret = dmg_stripe_zeroes(ctx, ofd, i, mish_set);
                break;
            case DMG_STRIPE_STORED:
                ret = dmg_stripe_store(ctx, ofd, i, mish_set);
                break;
            case DMG_STRIPE_ADC:
                ret = dmg_stripe_adc(ctx, ofd, i, mish_set);
                break;
            case DMG_STRIPE_DEFLATE:
                ret = dmg_stripe_inflate(ctx, ofd, i, mish_set);
                break;
            case DMG_STRIPE_BZ:
                ret = dmg_stripe_bzip(ctx, ofd, i, mish_set);
                break;
            case DMG_STRIPE_SKIP:
            case DMG_STRIPE_END:
            default:
                cli_dbgmsg("dmg_handle_mish: stripe " STDu32 ", skipped\n", i);
                break;
        }
    }

    /* If okay so far, scan rebuilt partition */
    if (ret == CL_CLEAN) {
        ret = cli_partition_scandesc(ofd, outfile, ctx);
    }

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
        cli_errmsg("cli_scandmg: Failed getting XML from map, len " STDu64 "\n", hdr->xmlLength);
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
        char err[128];
        cli_errmsg("cli_scandmg: Can't create temporary file %s: %s\n",
            xmlfile, cli_strerror(errno, err, sizeof(err)));
        free(xmlfile);
        return CL_ETMPFILE;
    }

    if ((uint64_t)cli_writen(ofd, outdata, hdr->xmlLength) != hdr->xmlLength) {
        cli_errmsg("cli_scandmg: Not all bytes written!\n");
        close(ofd);
        free(xmlfile);
        return CL_EWRITE;
    }

    close(ofd);
    free(xmlfile);
    return CL_SUCCESS;
}


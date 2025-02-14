/*
 *  Copyright (C) 2013-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2011-2013 Sourcefire, Inc.
 *
 *  Authors: Tomasz Kojm <tkojm@clamav.net>
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
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/stat.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdbool.h>
#include <time.h>

#include "jpeg.h"
#include "clamav.h"
#include "scanners.h"

// clang-format off
/*
 * JPEG format highlights
 * ----------------------
 *
 * Links:
 * - https://en.wikipedia.org/wiki/JPEG#Syntax_and_structure
 * - https://en.wikipedia.org/wiki/JPEG_File_Interchange_Format
 * - https://en.wikipedia.org/wiki/Exif
 *
 * A JPEG image is a sequence of segments.
 *
 * Each segment starts with a two-byte marker. The first byte is 0xff and is
 * followed by one of the following to identify the segment.

 * Some segments are simply the 2-byte marker, while others have a payload.
 * Realistically it appears that just the start-of-image and end-of-image lack
 * the 2-byte size field, the rest have it, even the 4-byte DRI segment.
 *
 * All variable-byte payloads have 2-bytes indicating the size which includes
 * the 2-bytes (but not the marker itself).
 *
 * Within entropy-encoded (compressed) data, any 0xff will have an 0x00
 * inserted after it to indicate that it's just and 0xff and _NOT_ a segment
 * marker. Decoders skip the 0x00 byte.
 * This only applies to entropy-encoded data, not to marker payload data.
 * We don't really worry about this though because this parser stops when it
 * reaches the image data.
 */

/*
 * JPEG Segment & Entropy Markers.
 */
typedef enum {
    /* Start of Image
     * No payload
     */
    JPEG_MARKER_SEGMENT_SOI_START_OF_IMAGE = 0xD8,

    /* Start of Frame for a Baseline DCT-based JPEG (S0F0)
     * Variable size payload.
     * Baseline DCT-based JPEG, and specifies the width, height, number of
     * components, and component subsampling
     */
    JPEG_MARKER_SEGMENT_S0F0_START_OF_FRAME_BASELINE_DCT = 0xC0,

    /* Start of Frame for an extended sequential DCT-based JPEG (S0F1)
     * Variable size payload.
     */
    JPEG_MARKER_SEGMENT_S0F1_START_OF_FRAME_EXT_SEQ_DCT = 0xC1,

    /* Start of Frame for a progressive DCT-based JPEG (S0F2)
     * Variable size payload.
     * Progressive DCT-based JPEG, and specifies the width, height, number of
     * components, and component subsampling
     */
    JPEG_MARKER_SEGMENT_S0F2_START_OF_FRAME_PROG_DCT = 0xC2,

    /* Start of Frame for a lossless sequential DCT-based JPEG (S0F3)
     * Variable size payload.
     */
    JPEG_MARKER_SEGMENT_S0F3_START_OF_FRAME_DIFF_SEQ_DCT = 0xC3,

    /* Start of Frame for a differential sequential DCT-based JPEG (S0F5)
     * Variable size payload.
     */
    JPEG_MARKER_SEGMENT_S0F5_START_OF_FRAME_DIFF_SEQ_DCT = 0xC5,

    /* Start of Frame for a differential progressive DCT-based JPEG (S0F6)
     * Variable size payload.
     */
    JPEG_MARKER_SEGMENT_S0F6_START_OF_FRAME_DIFF_PROG_DCT = 0xC6,

    /* Start of Frame for a differential lossless DCT-based JPEG (S0F7)
     * Variable size payload.
     */
    JPEG_MARKER_SEGMENT_S0F7_START_OF_FRAME_DIFF_LOSSLESS_DCT = 0xC7,

    /* Start of Frame for a differential sequential arithmetic-based JPEG (S0F5)
     * Variable size payload.
     */
    JPEG_MARKER_SEGMENT_S0F9_START_OF_FRAME_DIFF_SEQ_ARITH = 0xC9,

    /* Start of Frame for a differential progressive arithmetic-based JPEG (S0F6)
     * Variable size payload.
     */
    JPEG_MARKER_SEGMENT_S0F10_START_OF_FRAME_DIFF_PROG_ARITH = 0xCA,

    /* Start of Frame for a differential lossless arithmetic-based JPEG (S0F7)
     * Variable size payload.
     */
    JPEG_MARKER_SEGMENT_S0F11_START_OF_FRAME_DIFF_LOSSLESS_ARITH = 0xCB,

    /* Define Huffman Tables (DHT)
     * Variable size payload.
     * Defines one or more Huffman tables.
     */
    JPEG_MARKER_SEGMENT_DHT_DEFINE_HUFFMAN_TABLES = 0xC4,

    /* Define Arithmetic Coding Conditioning (DAC)
     * Variable size payload.
     */
    JPEG_MARKER_SEGMENT_DHT_DEFINE_ARITH_CODING = 0xCC,

    /* Define Quantization Tables (DTQ)
     * Variable size payload.
     * Defines one or more quantization tables.
     */
    JPEG_MARKER_SEGMENT_DQT_DEFINE_QUANTIZATION_TABLES = 0xDB,

    /* Define Restart Interval (DRI)
     * 4-byte payload.
     * Specifies the interval between RSTn markers, in Minimum Coded Units (MCUs).
     * This marker is followed by two bytes indicating the fixed size so it can be
     * treated like any other variable size segment.
     */
    JPEG_MARKER_SEGMENT_DRI_DEFINE_RESTART_INTERVAL = 0xDD,

    /* Start of Scan (SOS)
     * Variable size payload
     * This is the start of the JPEG image data, so we'll actually stop parsing
     * when we reach this.
     */
    JPEG_MARKER_SEGMENT_SOS_START_OF_SCAN = 0xDA,

    /*
     * App-specific markers E0 - EF
     * Variable size payload.
     * Since several vendors might use the *same* APPn marker type, application-
     * specific markers often begin with a standard or vendor name (e.g., "Exif" or
     * "Adobe") or some other identifying string.
     *
     * Some known app specific markers include:
     *   0xE0:
     *     - JFIF
     *   0xE1:
     *     - Exif
     *     - XMP data, starts with http://ns.adobe.com/xap/1.0/\0
     *   0xE2:
     *     - ICC Profile Chunk. There could be multiple of these to fit the entire profile, see http://www.color.org/icc_specs2.xalter and http://www.color.org/specification/ICC1v43_2010-12.pdf Section B.4
     *   0xE8:
     *     - SPIFF. Not a common format, see http://fileformats.archiveteam.org/wiki/SPIFF
     *   0xED:
     *     - IPTC / IMM metadata (a type of comment)
     *     - Photoshop data
     *   0xEE:
     *     - AdobeRGB (as opposed to sRGB)
     */
    JPEG_MARKER_SEGMENT_APP0 = 0xE0,
    JPEG_MARKER_SEGMENT_APP1 = 0xE1,
    JPEG_MARKER_SEGMENT_APP2 = 0xE2,
    JPEG_MARKER_SEGMENT_APP3 = 0xE3,
    JPEG_MARKER_SEGMENT_APP4 = 0xE4,
    JPEG_MARKER_SEGMENT_APP5 = 0xE5,
    JPEG_MARKER_SEGMENT_APP6 = 0xE6,
    JPEG_MARKER_SEGMENT_APP7 = 0xE7,
    JPEG_MARKER_SEGMENT_APP8 = 0xE8,
    JPEG_MARKER_SEGMENT_APP9 = 0xE9,
    JPEG_MARKER_SEGMENT_APP10 = 0xEA,
    JPEG_MARKER_SEGMENT_APP11 = 0xEB,
    JPEG_MARKER_SEGMENT_APP12 = 0xEC,
    JPEG_MARKER_SEGMENT_APP13 = 0xED,
    JPEG_MARKER_SEGMENT_APP14 = 0xEE,
    JPEG_MARKER_SEGMENT_APP15 = 0xEF,

    /* DTI (?)
     *
     */
    JPEG_MARKER_SEGMENT_DTI = 0xF1,

    /* DTT (?)
     *
     */
    JPEG_MARKER_SEGMENT_DTT = 0xF2,

    /* JPG7
     * Variable size payload (?)
     */
    JPEG_MARKER_SEGMENT_JPG7 = 0xF7,

    /* Comment (COM)
     * Variable size payload.
     */
    JPEG_MARKER_SEGMENT_COM_COMMENT = 0xFE,

    /* End of Image
     * No payload
     */
    JPEG_MARKER_SEGMENT_EOI_END_OF_IMAGE = 0xD9,

    /* Entropy-encoded (aka compressed) data markers.
     *
     * These aren't referenced since we don't parse the image data.
     */
    JPEG_MARKER_NOT_A_MARKER_0x00 = 0x00,
    JPEG_MARKER_NOT_A_MARKER_0xFF = 0xFF,

    /* Reset entropy-markers are inserted every r macroblocks, where r is the restart interval set by a DRI marker.
     * Not used if there was no DRI segment-marker.
     * The low three bits of the marker code cycle in value from 0 to 7 (i.e. D0 - D7).
     */
    JPEG_MARKER_ENTROPY_RST0_RESET = 0xD0,
    JPEG_MARKER_ENTROPY_RST1_RESET = 0xD1,
    JPEG_MARKER_ENTROPY_RST2_RESET = 0xD2,
    JPEG_MARKER_ENTROPY_RST3_RESET = 0xD3,
    JPEG_MARKER_ENTROPY_RST4_RESET = 0xD4,
    JPEG_MARKER_ENTROPY_RST5_RESET = 0xD5,
    JPEG_MARKER_ENTROPY_RST6_RESET = 0xD6,
    JPEG_MARKER_ENTROPY_RST7_RESET = 0xD7,
} jpeg_marker_t;

// clang-format on

static cl_error_t jpeg_check_photoshop_8bim(cli_ctx *ctx, size_t *off)
{
    cl_error_t retval;
    const unsigned char *buf;
    uint16_t ntmp;
    uint8_t nlength, id[2];
    uint32_t size;
    size_t offset = *off;
    fmap_t *map   = ctx->fmap;

    if (!(buf = fmap_need_off_once(map, offset, 4 + 2 + 1))) {
        cli_dbgmsg("read bim failed\n");
        return CL_BREAK;
    }
    if (memcmp(buf, "8BIM", 4) != 0) {
        cli_dbgmsg("missed 8bim\n");
        return CL_BREAK;
    }

    id[0] = (uint8_t)buf[4];
    id[1] = (uint8_t)buf[5];
    cli_dbgmsg("ID: 0x%.2x%.2x\n", id[0], id[1]);
    nlength = buf[6];
    ntmp    = nlength + ((((uint16_t)nlength) + 1) & 0x01);
    offset += 4 + 2 + 1 + ntmp;

    if (fmap_readn(map, &size, offset, 4) != 4) {
        return CL_BREAK;
    }
    size = be32_to_host(size);
    if (size == 0) {
        return CL_BREAK;
    }
    if ((size & 0x01) == 1) {
        size++;
    }

    *off = offset + 4 + size;
    /* Is it a thumbnail image: 0x0409 or 0x040c */
    if ((id[0] == 0x04) && ((id[1] == 0x09) || (id[1] == 0x0c))) {
        /* Yes */
        cli_dbgmsg("found thumbnail\n");
    } else {
        /* No - Seek past record */
        return CL_CLEAN;
    }

    /* Jump past header */
    offset += 4 + 28;

    /* Scan the thumbnail JPEG */
    retval = cli_magic_scan_nested_fmap_type(map, offset, 0, ctx, CL_TYPE_JPEG,
                                             "photoshop-thumbnail", LAYER_ATTRIBUTES_NONE);

    return retval;
}

cl_error_t cli_parsejpeg(cli_ctx *ctx)
{
    cl_error_t status = CL_SUCCESS;

    fmap_t *map          = NULL;
    jpeg_marker_t marker = JPEG_MARKER_NOT_A_MARKER_0x00, prev_marker, prev_segment = JPEG_MARKER_NOT_A_MARKER_0x00;
    uint8_t buff[50]; /* 50 should be sufficient for now */
    uint16_t len_u16;
    unsigned int offset = 0, i, len, segment = 0;
    bool found_comment = false;
    bool found_app     = false;

    uint32_t num_JFIF  = 0;
    uint32_t num_Exif  = 0;
    uint32_t num_SPIFF = 0;

    cli_dbgmsg("in cli_parsejpeg()\n");

    if (NULL == ctx) {
        cli_dbgmsg("passed context was NULL\n");
        status = CL_EARG;
        goto done;
    }
    map = ctx->fmap;

    if (fmap_readn(map, buff, offset, 4) != 4) {
        goto done; /* Ignore */
    }

    if (!memcmp(buff, "\xff\xd8\xff", 3)) {
        offset = 2;
    } else if (!memcmp(buff, "\xff\xd9\xff\xd8", 4)) {
        offset = 4;
    } else {
        goto done; /* Not a JPEG file */
    }

    while (1) {
        segment++;
        prev_marker = JPEG_MARKER_NOT_A_MARKER_0x00;
        for (i = 0; offset < map->len && i < 16; i++) {
            uint8_t marker_u8;
            if (fmap_readn(map, &marker_u8, offset, sizeof(marker_u8)) == sizeof(marker_u8)) {
                offset += sizeof(marker_u8);
            } else {
                if (SCAN_HEURISTIC_BROKEN_MEDIA) {
                    cli_errmsg("JPEG: Failed to read marker, file corrupted?\n");
                    status = cli_append_potentially_unwanted(ctx, "Heuristics.Broken.Media.JPEG.CantReadMarker");
                } else {
                    cli_dbgmsg("Failed to read marker, file corrupted?\n");
                }
                goto done;
            }
            marker = (jpeg_marker_t)marker_u8;

            if (prev_marker == JPEG_MARKER_NOT_A_MARKER_0xFF && marker != JPEG_MARKER_NOT_A_MARKER_0xFF)
                break;
            prev_marker = marker;
        }
        if (i == 16) {
            if (SCAN_HEURISTIC_BROKEN_MEDIA) {
                cli_warnmsg("JPEG: Spurious bytes before segment %u\n", segment);
                status = cli_append_potentially_unwanted(ctx, "Heuristics.Broken.Media.JPEG.SpuriousBytesBeforeSegment");
            } else {
                cli_dbgmsg("Spurious bytes before segment %u\n", segment);
            }
            goto done;
        }

        /*
         * Check for MS04-028 exploit (See: https://docs.microsoft.com/en-us/security-updates/securitybulletins/2004/ms04-028)
         * You can reproduce to test with https://www.exploit-db.com/exploits/474
         * Checking here because the exploit PoC will fail our length check, below.
         */
        if (JPEG_MARKER_SEGMENT_COM_COMMENT == marker) {
            if (fmap_readn(map, buff, offset, 2) == 2) {
                if (buff[0] == 0x00) {
                    if ((buff[1] == 0x00) || (buff[1] == 0x01)) {
                        /* Found exploit */
                        status = cli_append_potentially_unwanted(ctx, "Heuristics.Exploit.W32.MS04-028");
                        goto done;
                    }
                }
            }
        }

        if (fmap_readn(map, &len_u16, offset, sizeof(len_u16)) != sizeof(len_u16)) {
            if (SCAN_HEURISTIC_BROKEN_MEDIA) {
                cli_errmsg("JPEG: Failed to read the segment size, file corrupted?\n");
                status = cli_append_potentially_unwanted(ctx, "Heuristics.Broken.Media.JPEG.CantReadSegmentSize");
            } else {
                cli_dbgmsg("Failed to read the segment size, file corrupted?\n");
            }
            goto done;
        }
        len = (unsigned int)be16_to_host(len_u16);
        cli_dbgmsg("segment[%d] = 0x%02x, Length %u\n", segment, marker, len);

        if (len < 2) {
            if (SCAN_HEURISTIC_BROKEN_MEDIA) {
                cli_warnmsg("JPEG: Invalid segment size\n");
                status = cli_append_potentially_unwanted(ctx, "Heuristics.Broken.Media.JPEG.InvalidSegmentSize");
            } else {
                cli_dbgmsg("Invalid segment size\n");
            }
            goto done;
        }
        if (len >= map->len - offset + sizeof(len_u16)) {
            if (SCAN_HEURISTIC_BROKEN_MEDIA) {
                cli_warnmsg("JPEG: Segment data out of file\n");
                status = cli_append_potentially_unwanted(ctx, "Heuristics.Broken.Media.JPEG.SegmentDataOutOfFile");
            } else {
                cli_dbgmsg("Segment data out of file\n");
            }
            goto done;
        }
        offset += len;

        switch (marker) {
            case JPEG_MARKER_SEGMENT_APP0:
                /*
                 * JFIF, maybe
                 */
                if ((fmap_readn(map, buff, offset - len + sizeof(len_u16), strlen("JFIF") + 1) == strlen("JFIF") + 1) &&
                    (0 == memcmp(buff, "JFIF\0", strlen("JFIF") + 1))) {
                    /* Found a JFIF marker */
                    cli_dbgmsg(" JFIF application marker\n");

                    if (SCAN_HEURISTIC_BROKEN_MEDIA) {
                        if (found_app && num_JFIF > 0) {
                            cli_warnmsg("JPEG: Duplicate Application Marker found (JFIF)\n");
                            cli_warnmsg("JPEG: Already observed JFIF: %d, Exif: %d, SPIFF: %d\n", num_JFIF, num_Exif, num_SPIFF);
                            status = cli_append_potentially_unwanted(ctx, "Heuristics.Broken.Media.JPEG.JFIFdupAppMarker");
                            goto done;
                        }
                        if (!(segment == 1 ||
                              (segment == 2 && found_comment) ||
                              (segment == 2 && num_Exif > 0) ||
                              (segment == 3 && found_comment && num_Exif > 0))) {
                            /* The JFIF segment is technically required to appear first, though it has been observed
                             * appearing in segment 2 in functional images when segment 1 is a comment or an Exif segment.
                             * If segment 1 wasn't a comment or Exif, then the file structure is unusual. */
                            cli_warnmsg("JPEG: JFIF marker at wrong position, found in segment # %d\n", segment);
                            cli_warnmsg("JPEG: Already observed JFIF: %d, Exif: %d, SPIFF: %d\n", num_JFIF, num_Exif, num_SPIFF);
                            status = cli_append_potentially_unwanted(ctx, "Heuristics.Broken.Media.JPEG.JFIFmarkerBadPosition");
                            goto done;
                        }
                        if (len < 16) {
                            cli_warnmsg("JPEG: JFIF header too short\n");
                            status = cli_append_potentially_unwanted(ctx, "Heuristics.Broken.Media.JPEG.JFIFheaderTooShort");
                            goto done;
                        }
                    }
                    found_app = true;
                    num_JFIF += 1;
                } else {
                    /* Found something else. Eg could be an Ocad Revision # (eg "Ocad$Rev: 14797 $"), for example.
                       Whatever it is, we don't really care for now */
                    cli_dbgmsg(" Unfamiliar use of application marker: 0x%02x\n", marker);
                }
                break;

            case JPEG_MARKER_SEGMENT_APP1:
                /*
                 * Exif, or maybe XMP data
                 */
                if ((fmap_readn(map, buff, offset - len + sizeof(len_u16), strlen("Exif") + 2) == strlen("Exif") + 2) &&
                    (0 == memcmp(buff, "Exif\0\0", strlen("Exif") + 2))) {
                    /* Found an Exif marker */
                    cli_dbgmsg(" Exif application marker\n");

                    if (SCAN_HEURISTIC_BROKEN_MEDIA) {
                        if (found_app && (num_Exif > 0 || num_SPIFF > 0)) {
                            cli_warnmsg("JPEG: Duplicate Application Marker found (Exif)\n");
                            cli_warnmsg("JPEG: Already observed JFIF: %d, Exif: %d, SPIFF: %d\n", num_JFIF, num_Exif, num_SPIFF);
                            status = cli_append_potentially_unwanted(ctx, "Heuristics.Broken.Media.JPEG.ExifDupAppMarker");
                            goto done;
                        }
                        if (segment > 3 && !found_comment && num_JFIF > 0) {
                            /* If Exif was found after segment 3 and previous segments weren't a comment or JFIF, something is unusual. */
                            cli_warnmsg("JPEG: Exif marker at wrong position\n");
                            status = cli_append_potentially_unwanted(ctx, "Heuristics.Broken.Media.JPEG.ExifHeaderBadPosition");
                            goto done;
                        }
                        if (len < 16) {
                            cli_warnmsg("JPEG: Exif header too short\n");
                            status = cli_append_potentially_unwanted(ctx, "Heuristics.Broken.Media.JPEG.ExifHeaderTooShort");
                            goto done;
                        }
                    }
                    found_app = true;
                    num_Exif += 1;
                } else if ((fmap_readn(map, buff, offset - len + sizeof(len_u16), strlen("http://")) == strlen("http://")) &&
                           (0 == memcmp(buff, "http://", strlen("http://")))) {
                    cli_dbgmsg(" XMP metadata\n");
                    found_comment = true;
                } else {
                    cli_dbgmsg(" Unfamiliar use of application marker: 0x%02x\n", marker);
                }
                break;

            case JPEG_MARKER_SEGMENT_APP2:
                /*
                 * ICC Profile
                 */
                if ((fmap_readn(map, buff, offset - len + sizeof(len_u16), strlen("ICC_PROFILE") + 2) == strlen("ICC_PROFILE") + 2) &&
                    (0 == memcmp(buff, "ICC_PROFILE\0", strlen("ICC_PROFILE") + 1))) {
                    /* Found ICC Profile Chunk. Let's print out the chunk #, which follows "ICC_PROFILE\0"... */
                    uint8_t chunk_no = buff[strlen("ICC_PROFILE") + 1];
                    cli_dbgmsg(" ICC Profile, chunk # %d\n", chunk_no);
                } else {
                    cli_dbgmsg(" Unfamiliar use of application marker: 0x%02x\n", marker);
                }
                break;

            case JPEG_MARKER_SEGMENT_APP8:
                /*
                 * SPIFF
                 */
                if ((fmap_readn(map, buff, offset - len + sizeof(len_u16), strlen("SPIFF") + 1) == strlen("SPIFF") + 1) &&
                    (0 == memcmp(buff, "SPIFF\0", strlen("SPIFF") + 1))) {
                    /* Found SPIFF application marker */
                    cli_dbgmsg(" SPIFF application marker\n");

                    if (SCAN_HEURISTIC_BROKEN_MEDIA) {
                        if (found_app) {
                            cli_warnmsg("JPEG: Duplicate Application Marker found (SPIFF)\n");
                            cli_warnmsg("JPEG: Already observed JFIF: %d, Exif: %d, SPIFF: %d\n", num_JFIF, num_Exif, num_SPIFF);
                            status = cli_append_potentially_unwanted(ctx, "Heuristics.Broken.Media.JPEG.SPIFFdupAppMarker");
                            goto done;
                        }
                        if (segment != 1 && (segment != 2 || !found_comment)) {
                            cli_warnmsg("JPEG: SPIFF marker at wrong position\n");
                            status = cli_append_potentially_unwanted(ctx, "Heuristics.Broken.Media.JPEG.SPIFFmarkerBadPosition");
                            goto done;
                        }
                        if (len < 16) {
                            cli_warnmsg("JPEG: SPIFF header too short\n");
                            status = cli_append_potentially_unwanted(ctx, "Heuristics.Broken.Media.JPEG.SPIFFheaderTooShort");
                            goto done;
                        }
                    }
                    found_app = true;
                    num_SPIFF += 1;
                } else {
                    cli_dbgmsg(" Unfamiliar use of application marker: 0x%02x\n", marker);
                }
                break;

            case JPEG_MARKER_SEGMENT_APP13:
                /*
                 * Check for Photoshop information
                 * Example file to test with: 2c5883a964917aa54c8b3e2c70dabf0a7b06ba8c21bcbaf6f1c19501be9d9196
                 */
                if ((fmap_readn(map, buff, offset - len + sizeof(len_u16), strlen("Photoshop 3.0") + 1) == strlen("Photoshop 3.0") + 1) &&
                    (0 == memcmp(buff, "Photoshop 3.0\0", strlen("Photoshop 3.0") + 1))) {
                    /* Found a Photoshop file */
                    size_t photoshop_data_offset = offset - len + sizeof(len_u16) + strlen("Photoshop 3.0") + 1;
                    size_t old_offset;

                    cli_dbgmsg("Found Photoshop segment\n");
                    do {
                        old_offset = photoshop_data_offset;
                        status     = jpeg_check_photoshop_8bim(ctx, &photoshop_data_offset);
                        if (photoshop_data_offset <= old_offset)
                            break;
                    } while (status == CL_CLEAN);

                    if (status == CL_BREAK) {
                        status = CL_CLEAN;
                    }
                } else {
                    cli_dbgmsg(" Unfamiliar use of application marker: 0x%02x\n", marker);
                }
                found_comment = true;
                break;

            case JPEG_MARKER_SEGMENT_APP14:
                /*
                 * Adobe RGB, probably
                 */
                if ((fmap_readn(map, buff, offset - len + sizeof(len_u16), strlen("Adobe") + 1) == strlen("Adobe") + 1) &&
                    (0 == memcmp(buff, "Adobe\0", strlen("Adobe") + 1))) {
                    cli_dbgmsg(" AdobeRGB application marker\n");
                } else {
                    /* Not Adobe, dunno what this is. */
                    cli_dbgmsg(" Unfamiliar use of application marker: 0x%02x\n", marker);
                }
                break;

            case JPEG_MARKER_SEGMENT_APP3:
            case JPEG_MARKER_SEGMENT_APP4:
            case JPEG_MARKER_SEGMENT_APP5:
            case JPEG_MARKER_SEGMENT_APP6:
            case JPEG_MARKER_SEGMENT_APP7:
            case JPEG_MARKER_SEGMENT_APP9:
            case JPEG_MARKER_SEGMENT_APP10:
            case JPEG_MARKER_SEGMENT_APP11:
            case JPEG_MARKER_SEGMENT_APP12:
            case JPEG_MARKER_SEGMENT_APP15:
                /*
                 * Unknown
                 */
                cli_dbgmsg(" Unfamiliar application marker: 0x%02x\n", marker);
                break;

            case JPEG_MARKER_SEGMENT_S0F0_START_OF_FRAME_BASELINE_DCT:
            case JPEG_MARKER_SEGMENT_S0F1_START_OF_FRAME_EXT_SEQ_DCT:
            case JPEG_MARKER_SEGMENT_S0F2_START_OF_FRAME_PROG_DCT:
            case JPEG_MARKER_SEGMENT_S0F3_START_OF_FRAME_DIFF_SEQ_DCT:
            case JPEG_MARKER_SEGMENT_S0F5_START_OF_FRAME_DIFF_SEQ_DCT:
            case JPEG_MARKER_SEGMENT_S0F6_START_OF_FRAME_DIFF_PROG_DCT:
            case JPEG_MARKER_SEGMENT_S0F7_START_OF_FRAME_DIFF_LOSSLESS_DCT:
            case JPEG_MARKER_SEGMENT_S0F9_START_OF_FRAME_DIFF_SEQ_ARITH:
            case JPEG_MARKER_SEGMENT_S0F10_START_OF_FRAME_DIFF_PROG_ARITH:
            case JPEG_MARKER_SEGMENT_S0F11_START_OF_FRAME_DIFF_LOSSLESS_ARITH:
                cli_dbgmsg(" Start of Frame (S0F) %02x\n", (uint8_t)marker);
                break;

            case JPEG_MARKER_SEGMENT_DHT_DEFINE_HUFFMAN_TABLES:
                cli_dbgmsg(" Huffman Tables definitions (DHT)\n");
                break;

            case JPEG_MARKER_SEGMENT_DQT_DEFINE_QUANTIZATION_TABLES:
                cli_dbgmsg(" Quantization Tables definitions (DQT)\n");
                break;

            case JPEG_MARKER_SEGMENT_DRI_DEFINE_RESTART_INTERVAL:
                cli_dbgmsg(" Restart Interval definition (DRI)\n");
                break;

            case JPEG_MARKER_SEGMENT_JPG7: /* JPG7 */
                cli_dbgmsg(" JPG7 segment marker\n");
                if (found_app) {
                    if (SCAN_HEURISTIC_BROKEN_MEDIA) {
                        cli_warnmsg("JPEG: Application Marker before JPG7\n");
                        status = cli_append_potentially_unwanted(ctx, "Heuristics.Broken.Media.JPEG.AppMarkerBeforeJPG7");
                        goto done;
                    }
                }
                goto done;

            case JPEG_MARKER_SEGMENT_SOS_START_OF_SCAN: /* SOS */
                cli_dbgmsg(" Start of Scan (SOS) segment marker\n");
                if (!found_app) {
                    cli_dbgmsg(" Found the Start-of-Scan segment without identifying the JPEG application type.\n");
                }
                /* What follows would be scan data (compressed image data),
                 * parsing is not presently required for validation purposes
                 * so we'll just call it quits. */
                goto done;

            case JPEG_MARKER_SEGMENT_EOI_END_OF_IMAGE: /* EOI (End of Image) */
                cli_dbgmsg(" End of Image (EOI) segment marker\n");
                /*
                 * We shouldn't reach this marker because we exit out when we hit the Start of Scan marker.
                 */
                if (SCAN_HEURISTIC_BROKEN_MEDIA) {
                    cli_warnmsg("JPEG: No image in jpeg\n");
                    status = cli_append_potentially_unwanted(ctx, "Heuristics.Broken.Media.JPEG.NoImages");
                }
                goto done;

            case JPEG_MARKER_SEGMENT_COM_COMMENT: /* COM (comment) */
                cli_dbgmsg(" Comment (COM) segment marker\n");
                found_comment = true;
                break;

            case JPEG_MARKER_SEGMENT_DTI: /* DTI */
                cli_dbgmsg(" DTI segment marker\n");
                break;

            case JPEG_MARKER_SEGMENT_DTT: /* DTT */
                cli_dbgmsg(" DTT segment marker\n");
                if (SCAN_HEURISTIC_BROKEN_MEDIA) {
                    if (prev_segment != JPEG_MARKER_SEGMENT_DTI) {
                        cli_warnmsg("JPEG: No DTI segment before DTT\n");
                        status = cli_append_potentially_unwanted(ctx, "Heuristics.Broken.Media.JPEG.DTTMissingDTISegment");
                        goto done;
                    }
                }
                break;

            default:
                /* Some unknown marker we don't presently handle, don't worry about it. */
                break;
        }

        prev_segment = marker;
    }

done:
    return status;
}

/*
 *   Copyright (C) 2013-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *   Copyright (C) 2011-2013 Sourcefire, Inc.
 *   Copyright (C) 1995-2007 by Alexander Lehmann <lehmann@usa.net>,
 *                              Andreas Dilger <adilger@enel.ucalgary.ca>,
 *                              Glenn Randers-Pehrson <randeg@alum.rpi.edu>,
 *                              Greg Roelofs <newt@pobox.com>,
 *                              John Bowler <jbowler@acm.org>,
 *                              Tom Lane <tgl@sss.pgh.pa.us>
 *
 *   Initial work derived from pngcheck: http://www.libpng.org/pub/png/apps/pngcheck.html
 *
 *   Permission to use, copy, modify, and distribute this software and its
 *   documentation for any purpose and without fee is hereby granted, provided
 *   that the above copyright notice appear in all copies and that both that
 *   copyright notice and this permission notice appear in supporting
 *   documentation.  This software is provided "as is" without express or
 *   implied warranty.
 *
 */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <fcntl.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <zlib.h>

#include "clamav.h"
#include "others.h"
#include "png.h"
#include "scanners.h"

#define PNG_CHUNK_LENGTH_SIZE (4)
#define PNG_CHUNK_TYPE_SIZE (4)
#define PNG_CHUNK_CRC_SIZE (4)
/* Header Size does not include chunk data size */
#define PNG_CHUNK_HEADER_SIZE (PNG_CHUNK_LENGTH_SIZE + \
                               PNG_CHUNK_TYPE_SIZE +   \
                               PNG_CHUNK_CRC_SIZE)

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
    uint8_t red;
    uint8_t green;
    uint8_t blue;
} png_palette_entry;

#ifdef HAVE_PRAGMA_PACK
#pragma pack()
#endif

#ifdef HAVE_PRAGMA_PACK_HPPA
#pragma pack
#endif

cl_error_t cli_parsepng(cli_ctx *ctx)
{
    cl_error_t status = CL_SUCCESS;

    uint64_t chunk_data_length = 0;
    char chunk_type[5]         = {'\0', '\0', '\0', '\0', '\0'};
    uint32_t chunk_crc;
    uint32_t chunk_data_length_u32 = 0;
    bool have_IEND                 = false;
    bool have_PLTE                 = false;

    uint64_t width  = 0;
    uint64_t height = 0;

    uint32_t sample_depth = 0, bit_depth = 0, interlace_method = 0;
    uint64_t num_palette_entries = 0;
    uint32_t color_type          = 1;
    uint32_t compression_method  = 0;
    uint32_t filter_method       = 0;
    uint8_t *ptr                 = NULL;
    uint64_t offset              = 8;
    fmap_t *map                  = NULL;

    cli_dbgmsg("in cli_parsepng()\n");

    if (NULL == ctx) {
        cli_dbgmsg("PNG: passed context was NULL\n");
        status = CL_EARG;
        goto done;
    }
    map = ctx->fmap;

    while (fmap_readn(map, (void *)&chunk_data_length_u32, offset, PNG_CHUNK_LENGTH_SIZE) == PNG_CHUNK_LENGTH_SIZE) {
        chunk_data_length = be32_to_host(chunk_data_length_u32);
        offset += PNG_CHUNK_LENGTH_SIZE;

        if (chunk_data_length > (uint64_t)0x7fffffff) {
            cli_dbgmsg("PNG: invalid chunk length (too large): 0x" STDx64 "\n", chunk_data_length);
            if (SCAN_HEURISTIC_BROKEN_MEDIA) {
                status = cli_append_potentially_unwanted(ctx, "Heuristics.Broken.Media.PNG.InvalidChunkLength");
            }
            goto scan_overlay;
        }

        if (fmap_readn(map, chunk_type, offset, PNG_CHUNK_TYPE_SIZE) != PNG_CHUNK_TYPE_SIZE) {
            cli_dbgmsg("PNG: EOF while reading chunk type\n");
            if (SCAN_HEURISTIC_BROKEN_MEDIA) {
                status = cli_append_potentially_unwanted(ctx, "Heuristics.Broken.Media.PNG.EOFReadingChunkType");
            }
            goto scan_overlay;
        }
        offset += PNG_CHUNK_TYPE_SIZE;

        /* GRR:  add 4-character EBCDIC conversion here (chunk_type) */

        chunk_type[4] = '\0';

        cli_dbgmsg("Chunk Type: %s, Data Length: " STDu64 " bytes\n", chunk_type, chunk_data_length);

        if (chunk_data_length > 0) {
            ptr = (uint8_t *)fmap_need_off_once(map, offset, chunk_data_length);
            if (NULL == ptr) {
                cli_dbgmsg("PNG: Unexpected early end-of-file.\n");
                if (SCAN_HEURISTIC_BROKEN_MEDIA) {
                    status = cli_append_potentially_unwanted(ctx, "Heuristics.Broken.Media.PNG.EOFReadingChunk");
                }
                goto scan_overlay;
            }
            offset += chunk_data_length;
        }

        if (strcmp(chunk_type, "IHDR") == 0) {
            /*------*
             | IHDR |
             *------*/
            if (chunk_data_length != 13) {
                cli_dbgmsg("PNG: invalid IHDR length: " STDu64 "\n", chunk_data_length);
                break;
            } else {
                width  = be32_to_host(*(uint32_t *)ptr);
                height = be32_to_host(*(uint32_t *)(ptr + 4));
                if (width == 0 || height == 0 || width > (uint64_t)0x7fffffff || height > (uint64_t)0x7fffffff) {
                    cli_dbgmsg("PNG: invalid image dimensions: width = " STDu64 ", height = " STDu64 "\n", width, height);
                    break;
                }
                sample_depth = bit_depth = (uint32_t)ptr[8];
                color_type               = (uint32_t)ptr[9];
                compression_method       = (uint32_t)ptr[10];
                filter_method            = (uint32_t)ptr[11];
                interlace_method         = (uint32_t)ptr[12];

                if (compression_method != 0) {
                    cli_dbgmsg("PNG: invalid compression method (%u)\n", compression_method);
                }
                if (filter_method != 0) {
                    cli_dbgmsg("PNG: invalid filter method (%u)\n", filter_method);
                }
                switch (bit_depth) {
                    case 1:
                    case 2:
                    case 4:
                        if (color_type == 2 || color_type == 4 || color_type == 6) { /* RGB or GA or RGBA */
                            cli_dbgmsg("PNG: invalid sample depth (%u)\n", bit_depth);
                            break;
                        }
                        break;
                    case 8:
                        break;
                    case 16:
                        if (color_type == 3) { /* palette */
                            cli_dbgmsg("PNG: invalid sample depth (%u)\n", bit_depth);
                            break;
                        }
                        break;
                    default:
                        cli_dbgmsg("PNG: invalid sample depth (%u)\n", bit_depth);
                        break;
                }
                switch (color_type) {
                    case 2:
                        sample_depth = bit_depth * 3; /* RGB */
                        break;
                    case 4:
                        sample_depth = bit_depth * 2; /* gray+alpha */
                        break;
                    case 6:
                        sample_depth = bit_depth * 4; /* RGBA */
                        break;
                }
                cli_dbgmsg("  Width:                 " STDu64 "\n", width);
                cli_dbgmsg("  Height:                " STDu64 "\n", height);
                cli_dbgmsg("  Bit Depth:             " STDu32 " (Sample Depth: " STDu32 ")\n", bit_depth, sample_depth);
                cli_dbgmsg("  Color Type:            " STDu32 "\n", color_type);
                cli_dbgmsg("  Compression Method:    " STDu32 "\n", compression_method);
                cli_dbgmsg("  Filter Method:         " STDu32 "\n", filter_method);
                cli_dbgmsg("  Interlace Method:      " STDu32 "\n", interlace_method);
            }
        } else if (strcmp(chunk_type, "PLTE") == 0) {
            /*------*
             | PLTE |
             *------*/
            if (have_PLTE) {
                cli_dbgmsg("PNG: More than one PTLE chunk found in a PNG file, which is not valid\n");
            }

            if (!(chunk_data_length > sizeof(png_palette_entry) * 256 || chunk_data_length % 3 != 0)) {
                num_palette_entries = chunk_data_length / 3;
            }
            if (color_type == 1) /* for MNG and tRNS */ {
                color_type = 3;
            }

            if (color_type == 0 || color_type == 4) {
                cli_dbgmsg("PNG: PTLE chunk found in a PNG file with color type set to (%u), which is not valid\n", color_type);
            }
            have_PLTE = true;

            cli_dbgmsg("  # palette entries: " STDu64 "\n", num_palette_entries);
        } else if (interlace_method == 0 && strcmp(chunk_type, "IDAT") == 0) {
            /*------*
             | IDAT |
             *------*/
            cli_dbgmsg("  IDAT chunk: image data decompression no longer performed in PNG CVE checker.\n");
        } else if (strcmp(chunk_type, "IEND") == 0) {
            /*------*
             | IEND |
             *------*/

            have_IEND = true;
        } else if (strcmp(chunk_type, "pHYs") == 0) {
            /*------*
             | pHYs |
             *------*/

            if (chunk_data_length != 9) {
                // Could it be CVE-2007-2365?
                cli_dbgmsg("PNG: invalid pHYs length\n");
            }
        } else if (strcmp(chunk_type, "tRNS") == 0) {
            /*------*
             | tRNS |
             *------*/
        }

        if (fmap_readn(map, &chunk_crc, offset, PNG_CHUNK_CRC_SIZE) != PNG_CHUNK_CRC_SIZE) {
            cli_dbgmsg("PNG: EOF while reading chunk crc\n");
            if (SCAN_HEURISTIC_BROKEN_MEDIA) {
                status = cli_append_potentially_unwanted(ctx, "Heuristics.Broken.Media.PNG.EOFReadingChunkCRC");
            }
            goto scan_overlay;
        }
        chunk_crc = be32_to_host(chunk_crc);
        cli_dbgmsg("  Chunk CRC:             0x" STDx32 "\n", chunk_crc);
        offset += PNG_CHUNK_CRC_SIZE;

        if (have_IEND) {
            /*
             * That's all, folks!
             */
            break;
        }
    }

    if (!have_IEND) {
        cli_dbgmsg("PNG: EOF before IEND chunk!\n");
    }

scan_overlay:

    if (CL_SUCCESS == status) {
        /* Check if there's an overlay, and scan it if one exists. */
        if (map->len > offset) {
            cli_dbgmsg("PNG: Found " STDu64 " additional data after end of PNG! Scanning as a nested file.\n", map->len - offset);
            status = cli_magic_scan_nested_fmap_type(map, (size_t)offset, map->len - offset, ctx, CL_TYPE_ANY, NULL, LAYER_ATTRIBUTES_NONE);
            goto done;
        }
    }

done:

    return status;
}

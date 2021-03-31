/*
 *   Copyright (C) 2013-2021 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
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

#define BUFFER_SIZE 128000 /* size of read block  */

typedef enum {
    PNG_IDAT_NOT_FOUND_YET,
    PNG_IDAT_DECOMPRESSION_IN_PROGRESS,
    PNG_IDAT_DECOMPRESSION_COMPLETE,
    PNG_IDAT_DECOMPRESSION_FAILED,
} png_idat_state;

cl_error_t cli_parsepng(cli_ctx *ctx)
{
    cl_error_t status = CL_ERROR;

    uint64_t chunk_data_length = 0;
    char chunk_type[5]         = {'\0', '\0', '\0', '\0', '\0'};
    uint32_t chunk_crc;
    uint32_t chunk_data_length_u32 = 0;
    bool have_IEND                 = false;
    bool have_PLTE                 = false;
    uint64_t zhead                 = 1; /* 0x10000 indicates both zlib header bytes read */

    int64_t num_chunks = 0;
    uint64_t width     = 0;
    uint64_t height    = 0;

    uint32_t sample_depth = 0, bit_depth = 0, interlace_method = 0;
    uint64_t num_palette_entries = 0;
    uint32_t color_type          = 1;
    uint32_t compression_method  = 0;
    uint32_t filter_method       = 0;
    uint8_t *ptr                 = NULL;
    uint64_t offset              = 8;
    fmap_t *map                  = NULL;

    uint64_t image_size = 0;

    int err                    = Z_OK;
    uint8_t *decompressed_data = NULL;

    bool zstrm_initialized = false;
    z_stream zstrm;
    size_t decompressed_data_len = 0;

    png_idat_state idat_state = PNG_IDAT_NOT_FOUND_YET;

    cli_dbgmsg("in cli_parsepng()\n");

    if (NULL == ctx) {
        cli_dbgmsg("PNG: passed context was NULL\n");
        status = CL_EARG;
        goto done;
    }
    map = *ctx->fmap;

    while (fmap_readn(map, (void *)&chunk_data_length_u32, offset, PNG_CHUNK_LENGTH_SIZE) == PNG_CHUNK_LENGTH_SIZE) {
        chunk_data_length = be32_to_host(chunk_data_length_u32);
        offset += PNG_CHUNK_LENGTH_SIZE;

        if (chunk_data_length > (uint64_t)0x7fffffff) {
            cli_dbgmsg("PNG: invalid chunk length (too large): 0x" STDx64 "\n", chunk_data_length);
            if (SCAN_HEURISTIC_BROKEN_MEDIA) {
                cli_append_possibly_unwanted(ctx, "Heuristics.Broken.Media.PNG.InvalidChunkLength");
                status = CL_EPARSE;
            }
            goto scan_overlay;
        }

        if (fmap_readn(map, chunk_type, offset, PNG_CHUNK_TYPE_SIZE) != PNG_CHUNK_TYPE_SIZE) {
            cli_dbgmsg("PNG: EOF while reading chunk type\n");
            if (SCAN_HEURISTIC_BROKEN_MEDIA) {
                cli_append_possibly_unwanted(ctx, "Heuristics.Broken.Media.PNG.EOFReadingChunkType");
                status = CL_EPARSE;
            }
            goto scan_overlay;
        }
        offset += PNG_CHUNK_TYPE_SIZE;

        /* GRR:  add 4-character EBCDIC conversion here (chunk_type) */

        chunk_type[4] = '\0';
        ++num_chunks;

        cli_dbgmsg("Chunk Type: %s, Data Length: " STDu64 " bytes\n", chunk_type, chunk_data_length);

        if (chunk_data_length > 0) {
            ptr = (uint8_t *)fmap_need_off_once(map, offset, chunk_data_length);
            if (NULL == ptr) {
                cli_warnmsg("PNG: Unexpected early end-of-file.\n");
                if (SCAN_HEURISTIC_BROKEN_MEDIA) {
                    cli_append_possibly_unwanted(ctx, "Heuristics.Broken.Media.PNG.EOFReadingChunk");
                    status = CL_EPARSE;
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

            /*
             * Note from pngcheck:
             *   GRR 20000304:  data dump not yet compatible with interlaced images.
             */

            if (idat_state == PNG_IDAT_NOT_FOUND_YET) {
                unsigned zlib_windowbits = 15;

                /* Dump the zlib header from the first two bytes. */
                if (zhead < 0x10000 && chunk_data_length > 0) {
                    zhead = (zhead << 8) + ptr[0];
                    if (chunk_data_length > 1 && zhead < 0x10000)
                        zhead = (zhead << 8) + ptr[1];
                    if (zhead >= 0x10000) {
                        unsigned int CINFO = (zhead & 0xf000) >> 12;
                        zlib_windowbits    = CINFO + 8;
                    }
                }

                decompressed_data = (uint8_t *)malloc(BUFFER_SIZE);
                if (NULL == decompressed_data) {
                    cli_errmsg("Failed to allocation memory for decompressed PNG data.\n");
                    goto done;
                }

                /* initialize zlib and bit/byte/line variables if not already done */
                zstrm.zalloc = (alloc_func)Z_NULL;
                zstrm.zfree  = (free_func)Z_NULL;
                zstrm.opaque = (voidpf)Z_NULL;
                if ((err = inflateInit2(&zstrm, zlib_windowbits)) != Z_OK) {
                    cli_dbgmsg("PNG: zlib: can't initialize (error = %d)\n", err);

                    idat_state = PNG_IDAT_DECOMPRESSION_FAILED;
                } else {
                    zstrm_initialized = true;
                    uint64_t cur_width, cur_linebytes;
                    int64_t cur_xoff  = 0;
                    int64_t cur_xskip = interlace_method ? 8 : 1;
                    cur_width         = (width - cur_xoff + cur_xskip - 1) / cur_xskip; /* round up */
                    cur_linebytes     = ((cur_width * sample_depth + 7) >> 3) + 1;      /* round, fltr */
                    image_size        = cur_linebytes * height;
                    cli_dbgmsg("  Image Size:            " STDu64 "\n", image_size);

                    idat_state = PNG_IDAT_DECOMPRESSION_IN_PROGRESS;
                }
            }

            /* skip scans of image data > max scan size. */
            if (image_size > ctx->engine->maxscansize) {
                idat_state = PNG_IDAT_DECOMPRESSION_COMPLETE;
            }

            if (idat_state == PNG_IDAT_DECOMPRESSION_IN_PROGRESS) {
                /*
                 * We'll decompress the image data, but we don't _actually_ scan it.
                 * We just want to know how much data comes out, so we can alert on the file
                 * if it exceeds the image size calculated above (CVE-2010-1205).
                 * Therefore, we'll use a static buffer and won't preserve the decompressed data.
                 * This will prevent realloc errors from exceeding CLI_MAX_ALLOCATION,
                 * will reduce RAM usage, and should be a wee bit faster.
                 */
                zstrm.next_in  = ptr;
                zstrm.avail_in = chunk_data_length;

                while (err != Z_STREAM_END) {
                    if (zstrm.avail_in == 0) {
                        // Ran out of data before zstream ended... Additional IDAT chunks expected.
                        idat_state = PNG_IDAT_DECOMPRESSION_IN_PROGRESS;
                        break;
                    }

                    /* Just keep overwriting our buffer, we don't need to save the PNG image data. */
                    zstrm.next_out  = decompressed_data;
                    zstrm.avail_out = BUFFER_SIZE;

                    /* inflate! */
                    err = inflate(&zstrm, Z_NO_FLUSH);
                    decompressed_data_len += BUFFER_SIZE - zstrm.avail_out;
                    if (err != Z_OK && err != Z_STREAM_END) {
                        cli_dbgmsg("PNG: zlib: inflate error: %d, Image decompression failed!\n", err);
                        inflateEnd(&zstrm);
                        zstrm_initialized = false;
                        idat_state = PNG_IDAT_DECOMPRESSION_FAILED;
                        break;
                    }
                }

                if (err == Z_STREAM_END) {
                    cli_dbgmsg("  TOTAL decompressed:    %zu\n", decompressed_data_len);
                    inflateEnd(&zstrm);
                    zstrm_initialized = false;
                    idat_state = PNG_IDAT_DECOMPRESSION_COMPLETE;

                    if (decompressed_data_len > image_size) {
                        status = cli_append_virus(ctx, "Heuristics.PNG.CVE-2010-1205");
                        goto done;
                    }
                } else {
                    cli_dbgmsg("  Decompressed so far:   %zu  (Additional IDAT chunks expected)\n", decompressed_data_len);
                }
            }
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

            if (color_type == 3) {
                if ((chunk_data_length > 256 || chunk_data_length > num_palette_entries) && !have_PLTE) {
                    status = cli_append_virus(ctx, "Heuristics.PNG.CVE-2004-0597");
                    goto done;
                }
            }
        }

        if (fmap_readn(map, &chunk_crc, offset, PNG_CHUNK_CRC_SIZE) != PNG_CHUNK_CRC_SIZE) {
            cli_dbgmsg("PNG: EOF while reading chunk crc\n");
            if (SCAN_HEURISTIC_BROKEN_MEDIA) {
                cli_append_possibly_unwanted(ctx, "Heuristics.Broken.Media.PNG.EOFReadingChunkCRC");
                status = CL_EPARSE;
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

    if (idat_state == PNG_IDAT_DECOMPRESSION_IN_PROGRESS) {
        cli_dbgmsg("PNG: EOF before Image data decompression completed, truncated or malformed file?\n");
    }

scan_overlay:
    if (status == CL_EPARSE) {
        /* We added with cli_append_possibly_unwanted so it will alert at the end if nothing else matches. */
        status = CL_CLEAN;
    }

    /* Check if there's an overlay, and scan it if one exists. */
    if (map->len > offset) {
        cli_dbgmsg("PNG: Found " STDu64 " additional data after end of PNG! Scanning as a nested file.\n", map->len - offset);
        status = cli_magic_scan_nested_fmap_type(map, (size_t)offset, map->len - offset, ctx, CL_TYPE_ANY, NULL);
        goto done;
    }

    status = CL_CLEAN;

done:
    if (NULL != decompressed_data) {
        free(decompressed_data);
    }
    if (zstrm_initialized) {
        inflateEnd(&zstrm);
    }

    return status;
}

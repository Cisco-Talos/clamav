/*
 *  Copyright (C) 2013-2020 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
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
#include <time.h>

#include "jpeg.h"
#include "clamav.h"

cl_error_t cli_parsejpeg(cli_ctx *ctx)
{
    cl_error_t status = CL_CLEAN;

    fmap_t *map = NULL;
    unsigned char marker, prev_marker, prev_segment = 0, buff[8];
    uint16_t len_u16;
    unsigned int offset = 0, i, len, comment = 0, segment = 0, app = 0;

    cli_dbgmsg("in cli_parsejpeg()\n");

    if (NULL == ctx) {
        cli_dbgmsg("JPEG: passed context was NULL\n");
        status = CL_EARG;
        goto done;
    }
    map = *ctx->fmap;

    if (fmap_readn(map, buff, offset, 4) != 4)
        goto done; /* Ignore */

    if (!memcmp(buff, "\xff\xd8\xff", 3))
        offset = 2;
    else if (!memcmp(buff, "\xff\xd9\xff\xd8", 4))
        offset = 4;
    else
        goto done; /* Not a JPEG file */

    while (1) {
        segment++;
        prev_marker = 0;
        for (i = 0; offset < map->len && i < 16; i++) {
            if (fmap_readn(map, &marker, offset, sizeof(marker)) == sizeof(marker)) {
                offset += sizeof(marker);
            } else {
                cli_errmsg("JPEG: Failed to read marker, file corrupted?\n");
                cli_append_possibly_unwanted(ctx, "Heuristics.Broken.Media.JPEG.CantReadMarker");
                goto done;
            }

            if (prev_marker == 0xff && marker != 0xff)
                break;
            prev_marker = marker;
        }
        if (i == 16) {
            cli_warnmsg("JPEG: Spurious bytes before segment %u\n", segment);
            cli_append_possibly_unwanted(ctx, "Heuristics.Broken.Media.JPEG.SpuriousBytesBeforeSegment");
            status = CL_EPARSE;
            goto done;
        }

        if (fmap_readn(map, &len_u16, offset, sizeof(len_u16)) != sizeof(len_u16)) {
            cli_errmsg("JPEG: Failed to read the segment size, file corrupted?\n");
            cli_append_possibly_unwanted(ctx, "Heuristics.Broken.Media.JPEG.CantReadSegmentSize");
            goto done;
        }
        len = (unsigned int)be16_to_host(len_u16);
        cli_dbgmsg("JPEG: Marker %02x, length %u\n", marker, len);

        if (len < 2) {
            cli_warnmsg("JPEG: Invalid segment size\n");
            cli_append_possibly_unwanted(ctx, "Heuristics.Broken.Media.JPEG.InvalidSegmentSize");
            status = CL_EPARSE;
            goto done;
        }
        if (len >= map->len - offset + sizeof(len_u16)) {
            cli_warnmsg("JPEG: Segment data out of file\n");
            cli_append_possibly_unwanted(ctx, "Heuristics.Broken.Media.JPEG.SegmentDataOutOfFile");
            status = CL_EPARSE;
            goto done;
        }
        offset += len;

        switch (marker) {
            case 0xe0: /* JFIF */
                if (app) {
                    cli_warnmsg("JPEG: Duplicate Application Marker\n");
                    cli_append_possibly_unwanted(ctx, "Heuristics.Broken.Media.JPEG.JFIFdupAppMarker");
                    status = CL_EPARSE;
                    goto done;
                }
                if (segment != 1 && (segment != 2 || !comment)) {
                    cli_warnmsg("JPEG: JFIF marker at wrong position\n");
                    cli_append_possibly_unwanted(ctx, "Heuristics.Broken.Media.JPEG.JFIFmarkerBadPosition");
                    status = CL_EPARSE;
                    goto done;
                }
                if (fmap_readn(map, buff, offset - len + sizeof(len_u16), 5) != 5 || memcmp(buff, "JFIF\0", 5)) {
                    cli_warnmsg("JPEG: No JFIF marker\n");
                    cli_append_possibly_unwanted(ctx, "Heuristics.Broken.Media.JPEG.NoJFIFmarker");
                    status = CL_EPARSE;
                    goto done;
                }
                if (len < 16) {
                    cli_warnmsg("JPEG: JFIF header too short\n");
                    cli_append_possibly_unwanted(ctx, "Heuristics.Broken.Media.JPEG.JFIFheaderTooShort");
                    status = CL_EPARSE;
                    goto done;
                }
                app = 0xe0;
                break;

            case 0xe1: /* EXIF */
                if (fmap_readn(map, buff, offset - len + sizeof(len_u16), 7) != 7) {
                    cli_warnmsg("JPEG: Can't read Exif header\n");
                    cli_append_possibly_unwanted(ctx, "Heuristics.Broken.Media.JPEG.CantReadExifHeader");
                    status = CL_EPARSE;
                    goto done;
                }
                if (!memcmp(buff, "Exif\0\0", 6)) {
                    if (app && app != 0xe0) {
                        cli_warnmsg("JPEG: Duplicate Application Marker\n");
                        cli_append_possibly_unwanted(ctx, "Heuristics.Broken.Media.JPEG.ExifDupAppMarker");
                        status = CL_EPARSE;
                        goto done;
                    }
                    if (segment > 3 && !comment && app != 0xe0) {
                        cli_warnmsg("JPEG: Exif marker at wrong position\n");
                        cli_append_possibly_unwanted(ctx, "Heuristics.Broken.Media.JPEG.ExifHeaderBadPosition");
                        status = CL_EPARSE;
                        goto done;
                    }
                } else if (!memcmp(buff, "http://", 7)) {
                    cli_dbgmsg("JPEG: XMP data in segment %u\n", segment);
                } else {
                    cli_warnmsg("JPEG: Invalid Exif header\n");
                    cli_append_possibly_unwanted(ctx, "Heuristics.Broken.Media.JPEG.InvalidExifHeader");
                    status = CL_EPARSE;
                    goto done;
                }
                if (len < 16) {
                    cli_warnmsg("JPEG: Exif header too short\n");
                    cli_append_possibly_unwanted(ctx, "Heuristics.Broken.Media.JPEG.ExifHeaderTooShort");
                    status = CL_EPARSE;
                    goto done;
                }
                app = 0xe1;
                break;

            case 0xe8: /* SPIFF */
                if (app) {
                    cli_warnmsg("JPEG: Duplicate Application Marker\n");
                    cli_append_possibly_unwanted(ctx, "Heuristics.Broken.Media.JPEG.SPIFFdupAppMarker");
                    status = CL_EPARSE;
                    goto done;
                }
                if (segment != 1 && (segment != 2 || !comment)) {
                    cli_warnmsg("JPEG: SPIFF marker at wrong position\n");
                    cli_append_possibly_unwanted(ctx, "Heuristics.Broken.Media.JPEG.SPIFFmarkerBadPosition");
                    status = CL_EPARSE;
                    goto done;
                }
                if (fmap_readn(map, buff, offset - len + sizeof(len_u16), 6) != 6 || memcmp(buff, "SPIFF\0", 6)) {
                    cli_warnmsg("JPEG: No SPIFF marker\n");
                    cli_append_possibly_unwanted(ctx, "Heuristics.Broken.Media.JPEG.NoSPIFFmarker");
                    status = CL_EPARSE;
                    goto done;
                }
                if (len < 16) {
                    cli_warnmsg("JPEG: SPIFF header too short\n");
                    cli_append_possibly_unwanted(ctx, "Heuristics.Broken.Media.JPEG.SPIFFheaderTooShort");
                    status = CL_EPARSE;
                    goto done;
                }
                app = 0xe8;
                break;

            case 0xf7: /* JPG7 */
                if (app) {
                    cli_warnmsg("JPEG: Application Marker before JPG7\n");
                    cli_append_possibly_unwanted(ctx, "Heuristics.Broken.Media.JPEG.AppMarkerBeforeJPG7");
                    status = CL_EPARSE;
                    goto done;
                }
                goto done;

            case 0xda: /* SOS */
                if (!app) {
                    cli_warnmsg("JPEG: Invalid file structure\n");
                    cli_append_possibly_unwanted(ctx, "Heuristics.Broken.Media.JPEG.InvalidStructure");
                    status = CL_EPARSE;
                    goto done;
                }
                goto done;

            case 0xd9: /* EOI */
                cli_warnmsg("JPEG: No image in jpeg\n");
                cli_append_possibly_unwanted(ctx, "Heuristics.Broken.Media.JPEG.NoImages");
                status = CL_EPARSE;
                goto done;

            case 0xfe: /* COM */
                comment = 1;
                break;

            case 0xed: /* IPTC */
                comment = 1;
                break;

            case 0xf2: /* DTT */
                if (prev_segment != 0xf1) {
                    cli_warnmsg("JPEG: No DTI segment before DTT\n");
                    cli_append_possibly_unwanted(ctx, "Heuristics.Broken.Media.JPEG.DTTMissingDTISegment");
                    status = CL_EPARSE;
                    goto done;
                }
                break;

            default:
                break;
        }
        prev_segment = marker;
    }

done:
    if (status == CL_EPARSE) {
        /* We added with cli_append_possibly_unwanted so it will alert at the end if nothing else matches. */
        status = CL_CLEAN;
    }

    return status;
}

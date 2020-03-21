/*
 *   Copyright (C) 2013-2020 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *   Copyright (C) 2011-2013 Sourcefire, Inc.
 *   Copyright (C) 1995-2007 by Alexander Lehmann <lehmann@usa.net>,
 *                              Andreas Dilger <adilger@enel.ucalgary.ca>,
 *                              Glenn Randers-Pehrson <randeg@alum.rpi.edu>,
 *                              Greg Roelofs <newt@pobox.com>,
 *                              John Bowler <jbowler@acm.org>,
 *                              Tom Lane <tgl@sss.pgh.pa.us>\
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

#define BUFFER_SIZE 128000 /* size of read block  */

cl_error_t cli_parsepng(cli_ctx *ctx)
{
    uint64_t sz     = 0;
    char chunkid[5] = {'\0', '\0', '\0', '\0', '\0'};
    size_t toread = 0, toread_check = 0;
    int32_t c         = 0;
    int32_t have_IEND = 0, have_PLTE = 0;
    uint64_t zhead     = 1; /* 0x10000 indicates both zlib header bytes read */
    int64_t num_chunks = 0L;
    int64_t w = 0L, h = 0L;
    int32_t bitdepth = 0, sampledepth = 0, lace = 0;
    uint64_t nplte = 0;
    uint32_t ityp  = 1;
    uint32_t buffer[BUFFER_SIZE];
    uint64_t offset = 8;
    fmap_t *map     = NULL;

    int64_t cur_xoff, cur_xskip;
    uint64_t cur_width, cur_linebytes, cur_imagesize;
    int32_t err      = Z_OK;
    uint32_t *outbuf = NULL;
    z_stream zstrm;
    uint64_t offadjust    = 0;
    size_t left_comp_read = 0, uncomp_data = 0;

    cli_dbgmsg("in cli_parsepng()\n");

    if (NULL == ctx) {
        cli_dbgmsg("PNG: passed context was NULL\n");
        return CL_EARG;
    }
    map = *ctx->fmap;

    while (fmap_readn(map, &c, offset, sizeof(c)) == sizeof(c)) {

        int j = 0;
        for (j = 0; j < 4; ++j) {
            unsigned char c;
            if (fmap_readn(map, &c, offset, sizeof(c)) != sizeof(c)) {
                cli_dbgmsg("PNG: EOF(?) while reading %s\n", "chunk length");
                return CL_CLEAN;
            }
            offset++;
            sz <<= 8;
            sz |= c & 0xff;
        }

        if (sz > 0x7fffffff) {
            cli_dbgmsg("PNG: invalid chunk length (too large)\n");
            return CL_EPARSE;
        }

        if (fmap_readn(map, chunkid, offset, 4) != 4) {
            cli_dbgmsg("PNG: EOF while reading chunk type\n");
            return CL_EPARSE;
        }
        offset += 4;

        /* GRR:  add 4-character EBCDIC conversion here (chunkid) */

        chunkid[4] = '\0';
        ++num_chunks;

        toread       = (sz > BUFFER_SIZE) ? BUFFER_SIZE : sz;
        toread_check = fmap_readn(map, buffer, offset, toread);
        if ((size_t)-1 == toread_check) {
            cli_dbgmsg("PNG: Failed to read from map.\n");
            return CL_EPARSE;
        }
        if (toread > toread_check) {
            cli_dbgmsg("PNG: EOF while reading data\n");
            return CL_EPARSE;
        }
        toread = toread_check;

        offset += toread;

        /*------*
         | IHDR |
         *------*/
        if (strcmp(chunkid, "IHDR") == 0) {
            if (sz != 13) {
                cli_dbgmsg("PNG: invalid IHDR length\n");
                break;
            } else {
                w = be32_to_host(*buffer);
                h = be32_to_host(*(buffer + 4));
                if (w <= 0 || h <= 0 || w > 2147483647 || h > 2147483647) {
                    cli_dbgmsg("PNG: invalid image dimensions\n");
                    break;
                }
                bitdepth = sampledepth = (uint32_t)buffer[8];
                ityp                   = (uint32_t)buffer[9];
                lace                   = (uint32_t)buffer[12];
                switch (sampledepth) {
                    case 1:
                    case 2:
                    case 4:
                        if (ityp == 2 || ityp == 4 || ityp == 6) { /* RGB or GA or RGBA */
                            cli_dbgmsg("PNG: invalid sample depth (%d)\n", sampledepth);
                            break;
                        }
                        break;
                    case 8:
                        break;
                    case 16:
                        if (ityp == 3) { /* palette */
                            cli_dbgmsg("PNG: invalid sample depth (%d)\n", sampledepth);
                            break;
                        }
                        break;
                    default:
                        cli_dbgmsg("PNG: invalid sample depth (%d)\n", sampledepth);
                        break;
                }
                switch (ityp) {
                    case 2:
                        bitdepth = sampledepth * 3; /* RGB */
                        break;
                    case 4:
                        bitdepth = sampledepth * 2; /* gray+alpha */
                        break;
                    case 6:
                        bitdepth = sampledepth * 4; /* RGBA */
                        break;
                }
            }

            /* GRR 20000304:  data dump not yet compatible with interlaced images: */
            /*================================================*
            * PNG chunks (with the exception of IHDR, above) *
            *================================================*/

        }
        /*------*
         | PLTE |
         *------*/
        else if (strcmp(chunkid, "PLTE") == 0) {
            if (!(sz > 768 || sz % 3 != 0)) {
                nplte = sz / 3;
            }
            if (ityp == 1) /* for MNG and tRNS */
                ityp = 3;
            have_PLTE = 1;

        }
        /*------*
         | IDAT |
         *------*/
        else if (lace == 0 && strcmp(chunkid, "IDAT") == 0) {
            unsigned zlib_windowbits = 15;

            /* Dump the zlib header from the first two bytes. */
            if (zhead < 0x10000 && sz > 0) {
                zhead = (zhead << 8) + buffer[0];
                if (sz > 1 && zhead < 0x10000)
                    zhead = (zhead << 8) + buffer[1];
                if (zhead >= 0x10000) {
                    unsigned int CINFO = (zhead & 0xf000) >> 12;
                    zlib_windowbits    = CINFO + 8;
                }
            }

            outbuf         = (uint32_t *)malloc(BUFFER_SIZE);
            offadjust      = offset + sz - 8;
            left_comp_read = MIN(map->len - offset + sz - 8, sz);

            zstrm.next_in  = (uint8_t *) buffer;
            zstrm.avail_in = MIN(toread, left_comp_read);
            left_comp_read -= zstrm.avail_in;

            /* initialize zlib and bit/byte/line variables if not already done */
            zstrm.zalloc = (alloc_func)Z_NULL;
            zstrm.zfree  = (free_func)Z_NULL;
            zstrm.opaque = (voidpf)Z_NULL;
            if ((err = inflateInit2(&zstrm, zlib_windowbits)) != Z_OK) {
                cli_dbgmsg("PNG: zlib: can't initialize (error = %d)\n", err);
                if (outbuf) {
                    free(outbuf);
                    outbuf = NULL;
                }
            } else {
                cur_xoff      = 0;
                cur_xskip     = lace ? 8 : 1;
                cur_width     = (w - cur_xoff + cur_xskip - 1) / cur_xskip; /* round up */
                cur_linebytes = ((cur_width * bitdepth + 7) >> 3) + 1;      /* round, fltr */
                cur_imagesize = cur_linebytes * h;

                while (err != Z_STREAM_END) {
                    if (zstrm.avail_in == 0) {
                        // The zlib stream is over. Quit the while loop
                        if (left_comp_read == 0)
                            break;

                        toread       = MIN(sizeof(buffer), left_comp_read);
                        toread_check = fmap_readn(map, buffer, offset, toread);
                        if ((size_t)-1 == toread_check) {
                            cli_dbgmsg("PNG: Failed to read from map.\n");
                            if (outbuf) {
                                free(outbuf);
                                outbuf = NULL;
                            }
                            return CL_EPARSE;
                        }
                        if (toread > toread_check) {
                            cli_dbgmsg("PNG: EOF while reading data\n");
                            if (outbuf) {
                                free(outbuf);
                                outbuf = NULL;
                            }
                            return CL_EPARSE;
                        }
                        toread = toread_check;
                        offset += toread;
                        zstrm.next_in  = (uint8_t *) buffer;
                        zstrm.avail_in = toread;
                        left_comp_read -= toread;
                    }

                    zstrm.next_out  = (uint8_t *) outbuf;
                    zstrm.avail_out = BUFFER_SIZE;
                    err             = inflate(&zstrm, Z_NO_FLUSH);
                    uncomp_data += (BUFFER_SIZE - zstrm.avail_out);
                    if (err != Z_OK && err != Z_STREAM_END) {
                        cli_dbgmsg("PNG: zlib: inflate error\n");
                        break;
                    }
                }
                inflateEnd(&zstrm);
                if (outbuf) {
                    free(outbuf);
                    outbuf = NULL;
                }

                if (uncomp_data > cur_imagesize && err == Z_STREAM_END) {
                    cli_append_virus(ctx, "Heuristics.PNG.CVE-2010-1205");
                    return CL_VIRUS;
                }
            }

        }
        /*------*
         | IEND |
         *------*/
        else if (strcmp(chunkid, "IEND") == 0) {

            have_IEND = 1;
            break;

        }
        /*------*
         | pHYs |
         *------*/
        else if (strcmp(chunkid, "pHYs") == 0) {

            if (sz != 9) {
                // Could it be CVE-2007-2365?
                cli_dbgmsg("PNG: invalid pHYS length\n");
            }
        }
        /*------*
         | tRNS |
         *------*/
        else if (strcmp(chunkid, "tRNS") == 0) {

            if (ityp == 3) {
                if ((sz > 256 || sz > nplte) && !have_PLTE) {
                    cli_append_virus(ctx, "Heuristics.PNG.CVE-2004-0597");
                    return CL_VIRUS;
                }

                offset += (sz - toread) + 4;
            }

            // Is there an overlay?
            if (have_IEND && (map->len - (offset + 4) > 0))
                return cli_magic_scan_nested_fmap_type(map, offset + 4, map->len - (offset + 4), ctx, CL_TYPE_ANY, NULL);

            return CL_SUCCESS;
        }
    }
    return CL_SUCCESS;
}

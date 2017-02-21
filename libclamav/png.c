/*
 *   Copyright 1995-2007 by Alexander Lehmann <lehmann@usa.net>,
 *                          Andreas Dilger <adilger@enel.ucalgary.ca>,
 *                          Glenn Randers-Pehrson <randeg@alum.rpi.edu>,
 *                          Greg Roelofs <newt@pobox.com>,
 *                          John Bowler <jbowler@acm.org>,
 *                          Tom Lane <tgl@sss.pgh.pa.us>
 *   Copyright (C) 2015 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *   Copyright (C) 2011 Sourcefire, Inc.
 *   Maintainer: Tomasz Kojm <tkojm@clamav.net>
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
#ifdef  HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <zlib.h>

#include "clamav.h"
#include "others.h"
#include "png.h"
#include "scanners.h"

#define BS 32768 /* size of read block  */

/* Mark's macros to extract big-endian short and long ints: */
#define SH(p) ((unsigned short)(unsigned char)((p)[1]) | ((unsigned short)(unsigned char)((p)[0]) << 8))
#define LG(p) ((unsigned long)(SH((p)+2)) | ((unsigned long)(SH(p)) << 16))

static unsigned long getlong(fmap_t *map, unsigned int *offset, const char *where)
{
  unsigned long res = 0;
  int j;

  for (j = 0; j < 4; ++j) {
    unsigned char c;
    if(fmap_readn(map, &c, *offset, sizeof(c)) != sizeof(c)) {
      cli_dbgmsg("PNG: EOF(?) while reading %s\n", where);
      return 0;
    }
    (*offset)++;
    res <<= 8;
    res |= c & 0xff;
  }

  return res;
}

int cli_parsepng(cli_ctx *ctx)
{
  long sz;
  char chunkid[5] = {'\0', '\0', '\0', '\0', '\0'};
  int toread;
  int c;
  int have_IEND = 0, have_PLTE = 0;
  unsigned long zhead = 1;   /* 0x10000 indicates both zlib header bytes read */
  long num_chunks = 0L;
  long w = 0L, h = 0L;
  int bitdepth = 0, sampledepth = 0, lace = 0, nplte = 0;
  unsigned int ityp = 1;
  unsigned char buffer[BS];
  unsigned int offset = 8;
  fmap_t *map = *ctx->fmap;

  cli_dbgmsg("in cli_parsepng()\n");

  while(fmap_readn(map, &c, offset, sizeof(c)) == sizeof(c)) {

    sz = getlong(map, &offset, "chunk length");
    if (sz < 0 || sz > 0x7fffffff) {   /* FIXME:  convert to ulg, lose "< 0" */
      cli_dbgmsg("PNG: invalid chunk length (too large)\n");
      return CL_EPARSE;
    }

    if(fmap_readn(map, chunkid, offset, 4) != 4) {
      cli_dbgmsg("PNG: EOF while reading chunk type\n");
      return CL_EPARSE;
    }
    offset += 4;

    /* GRR:  add 4-character EBCDIC conversion here (chunkid) */

    chunkid[4] = '\0';
    ++num_chunks;

    toread = (sz > BS)? BS:sz;
    toread = fmap_readn(map, buffer, offset, toread);
    offset += toread;

    /*------*
     | IHDR |
     *------*/
    if (strcmp(chunkid, "IHDR") == 0) {
      if (sz != 13) {
        cli_dbgmsg("PNG: invalid IHDR length\n");
        break;
      } else {
        w = LG(buffer);
        h = LG(buffer+4);
        if (w <= 0 || h <= 0 || w > 2147483647 || h > 2147483647) {
          cli_dbgmsg("PNG: invalid image dimensions\n");
          break;
        }
        bitdepth = sampledepth = (unsigned char)buffer[8];
        ityp = (unsigned char)buffer[9];
        lace = (unsigned char)buffer[12];
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
            bitdepth = sampledepth * 3;   /* RGB */
            break;
          case 4:
            bitdepth = sampledepth * 2;   /* gray+alpha */
            break;
          case 6:
            bitdepth = sampledepth * 4;   /* RGBA */
            break;
        }
      }
      /* GRR 20000304:  data dump not yet compatible with interlaced images: */
    /*================================================*
     * PNG chunks (with the exception of IHDR, above) *
     *================================================*/

    /*------*
     | PLTE |
     *------*/
    } else if (strcmp(chunkid, "PLTE") == 0) {
      if (!(sz > 768 || sz % 3 != 0)) {
        nplte = sz / 3;
      }
        if (ityp == 1)   /* for MNG and tRNS */
          ityp = 3;
      have_PLTE = 1;

    /*------*
     | IDAT |
     *------*/
    } else if (lace == 0 && strcmp(chunkid, "IDAT") == 0) {
      unsigned zlib_windowbits = 15;

      /* Dump the zlib header from the first two bytes. */
      if (zhead < 0x10000 && sz > 0) {
        zhead = (zhead << 8) + buffer[0];
        if (sz > 1 && zhead < 0x10000)
          zhead = (zhead << 8) + buffer[1];
        if (zhead >= 0x10000) {
          unsigned int CINFO = (zhead & 0xf000) >> 12;
	  zlib_windowbits = CINFO + 8;
        }
      }

      {
        int cur_xoff, cur_xskip;
        unsigned long cur_width, cur_linebytes, cur_imagesize;
        int err = Z_OK;
        unsigned char* outbuf = (unsigned char *)malloc(BS);
        z_stream zstrm;
        size_t left_comp_read = MIN(map->len - offset + sz - 8, sz), uncomp_data = 0;

        zstrm.next_in = buffer;
        zstrm.avail_in = MIN(toread, left_comp_read);
        left_comp_read -= zstrm.avail_in;

        /* initialize zlib and bit/byte/line variables if not already done */
        zstrm.zalloc = (alloc_func)Z_NULL;
        zstrm.zfree = (free_func)Z_NULL;
        zstrm.opaque = (voidpf)Z_NULL;
        if ((err = inflateInit2(&zstrm, zlib_windowbits)) != Z_OK) {
          cli_dbgmsg("PNG: zlib: can't initialize (error = %d)\n", err);
        }
        else
        {
          cur_xoff = 0;
          cur_xskip = lace ? 8 : 1;
          cur_width = (w - cur_xoff + cur_xskip - 1) / cur_xskip; /* round up */
          cur_linebytes = ((cur_width*bitdepth + 7) >> 3) + 1; /* round, fltr */
          cur_imagesize = cur_linebytes * h;

          while (err != Z_STREAM_END) {
            if (zstrm.avail_in == 0)
            {
              // The zlib stream is over. Quit the while loop
              if (left_comp_read == 0)
                break;
              
              toread = MIN(sizeof(buffer), left_comp_read);
              toread = fmap_readn(map, buffer, offset, toread);
              offset += toread;
              zstrm.next_in = buffer;
              zstrm.avail_in = toread;
              left_comp_read -= toread;
            }

            zstrm.next_out = outbuf;
            zstrm.avail_out = BS;
            err = inflate(&zstrm, Z_NO_FLUSH);
            uncomp_data += (BS - zstrm.avail_out);
            if (err != Z_OK && err != Z_STREAM_END) {
              cli_dbgmsg("PNG: zlib: inflate error\n");
              break;
            }
          }
          inflateEnd(&zstrm);
          free(outbuf);

          if (uncomp_data > cur_imagesize && err == Z_STREAM_END)
          {
            cli_append_virus(ctx, "Heuristics.CVE-2010-1205");
            return CL_VIRUS;
          }
        }
      }

    /*------*
     | IEND |
     *------*/
    } else if (strcmp(chunkid, "IEND") == 0) {
      have_IEND = 1;
      break;

    /*------*
     | pHYs |
     *------*/
    } else if (strcmp(chunkid, "pHYs") == 0) {
      if (sz != 9) {
        // Could it be CVE-2007-2365?
        cli_dbgmsg("PNG: invalid pHYS length\n");
      }

    /*------*
     | tRNS |
     *------*/
    } else if (strcmp(chunkid, "tRNS") == 0) {
      if (ityp == 3)
      {
        if ((sz > 256 || sz > nplte) && !have_PLTE)
        {
          cli_append_virus(ctx, "Heuristics.CVE-2004-0597");
          return CL_VIRUS;
        }
      }
    }

    offset += (sz - toread) + 4;
  }

  // Is there an overlay?
  if (have_IEND && (map->len - (offset + 4) > 0))
    return cli_map_scan(map, offset + 4, map->len - (offset + 4), ctx, CL_TYPE_ANY);

  return CL_SUCCESS;
}

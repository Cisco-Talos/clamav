/*
 *   Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
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
#ifdef  HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <zlib.h>

#include "clamav.h"
#include "others.h"
#include "png.h"

typedef unsigned char  uch;
typedef unsigned short ush;
typedef unsigned long  ulg;

#define BS 32000 /* size of read block for CRC calculation (and zlib) */

/* Mark's macros to extract big-endian short and long ints: */
#define SH(p) ((ush)(uch)((p)[1]) | ((ush)(uch)((p)[0]) << 8))
#define LG(p) ((ulg)(SH((p)+2)) | ((ulg)(SH(p)) << 16))

#define isASCIIalpha(x)     (ascii_alpha_table[x] & 0x1)

#define ANCILLARY(chunkID)  ((chunkID)[0] & 0x20)
#define PRIVATE(chunkID)    ((chunkID)[1] & 0x20)
#define RESERVED(chunkID)   ((chunkID)[2] & 0x20)
#define SAFECOPY(chunkID)   ((chunkID)[3] & 0x20)
#define CRITICAL(chunkID)   (!ANCILLARY(chunkID))
#define PUBLIC(chunkID)     (!PRIVATE(chunkID))

/* GRR FIXME:  could merge all three of these into single table (bit fields) */

/* GRR 20061203:  for "isalpha()" that works even on EBCDIC machines */
static const uch ascii_alpha_table[256] = {
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0,0,0,0,0,
  0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 
};

/* GRR 20070707:  list of forbidden characters in various keywords */
static const uch latin1_keyword_forbidden[256] = {
  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,
  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
  1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 
};

/* GRR 20070707:  list of discouraged (control) characters in tEXt/zTXt text */
static const uch latin1_text_discouraged[256] = {
  1,1,1,1,1,1,1,1,1,1,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,
  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 
};

/* PNG stuff */

static const char *png_type[] = {		/* IHDR, tRNS, BASI, summary */
  "grayscale",
  "INVALID",
  "RGB",
  "palette",
  "grayscale+alpha",
  "INVALID",
  "RGB+alpha"
};

#define CRCCOMPL(c) c
#define CRCINIT (0)
#define update_crc crc32

static ulg getlong(fmap_t *map, unsigned int *offset, const char *where)
{
  ulg res = 0;
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

static int keywordlen(uch *buf, int maxsize)
{
  int j = 0;

  while (j < maxsize && buf[j])
    ++j;

  return j;
}

static const char *getmonth(int m)
{
  static const char *month[] = {
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
  };

  return (m < 1 || m > 12)? "INVALID" : month[m-1];
}

/* GRR 20061203:  now EBCDIC-safe */
static int check_chunk_name(char *chunk_name)
{
  if (isASCIIalpha((int)chunk_name[0]) && isASCIIalpha((int)chunk_name[1]) &&
      isASCIIalpha((int)chunk_name[2]) && isASCIIalpha((int)chunk_name[3]))
    return 0;

  cli_dbgmsg("PNG: invalid chunk name\n");
  return CL_EPARSE;  /* usually means we've "jumped the tracks": bail! */
}

/* GRR 20050724 */
/* caller must do return CL_EPARSE based on return value (0 == OK) */
/* keyword_name is "keyword" for most chunks, but it can instead be "name" or
 * "identifier" or whatever makes sense for the chunk in question */
static int check_keyword(uch *buffer, int maxsize, int *pKeylen)
{
  int j, prev_space = 0;
  int keylen = keywordlen(buffer, maxsize);

  if (pKeylen)
    *pKeylen = keylen;

  if (keylen == 0) {
    cli_dbgmsg("PNG: zero length keyword\n");
    return 1;
  }

  if (keylen > 79) {
    cli_dbgmsg("PNG: keyword is longer than 79 characters\n");
    return 2;
  }

  if (buffer[0] == ' ') {
    cli_dbgmsg("PNG: keyword has leading space(s)\n");
    return 3;
  }

  if (buffer[keylen - 1] == ' ') {
    cli_dbgmsg("PNG: keyword has trailing space(s)\n");
    return 4;
  }

  for (j = 0; j < keylen; ++j) {
    if (buffer[j] == ' ') {
      if (prev_space) {
        cli_dbgmsg("PNG: keyword has consecutive spaces\n");
        return 5;
      }
      prev_space = 1;
    } else {
      prev_space = 0;
    }
  }

  for (j = 0; j < keylen; ++j) {
    if (latin1_keyword_forbidden[buffer[j]]) {   /* [0,31] || [127,160] */
      cli_dbgmsg("PNG: keyword has control character(s)\n");
      return 6;
    }
  }
  return 0;
}

/* GRR 20070707 */
/* caller must do return CL_EPARSE based on return value (0 == OK) */
static int check_text(uch *buffer, int maxsize)
{
  int j;

  for (j = 0; j < maxsize; ++j) {
    if (buffer[j] == 0) {
      cli_dbgmsg("PNG: text contains NULL character(s)\n");
      return 1;
    } else if (latin1_text_discouraged[buffer[j]]) {
      cli_dbgmsg("PNG: text has control character(s)\n");
      return 1;
    }
  }
  return 0;
}

/* GRR 20061203 (used only for sCAL) */
static int check_ascii_float(uch *buffer, int len)
{
  uch *qq = buffer, *bufEnd = buffer + len;
  int have_sign = 0, have_integer = 0, have_dot = 0, have_fraction = 0;
  int have_E = 0, have_Esign = 0, have_exponent = 0, in_digits = 0;
  int have_nonzero = 0;
  int rc = 0;

  for (qq = buffer;  qq < bufEnd && !rc;  ++qq) {
    switch (*qq) {
      case '+':
      case '-':
        if (qq == buffer) {
          have_sign = 1;
          in_digits = 0;
        } else if (have_E && !have_Esign) {
          have_Esign = 1;
          in_digits = 0;
        } else {
          cli_dbgmsg("PNG: invalid sign character\n");
          rc = 1;
        }
        break;

      case '.':
        if (!have_dot && !have_E) {
          have_dot = 1;
          in_digits = 0;
        } else {
          cli_dbgmsg("PNG: invalid decimal point\n");
          rc = 2;
        }
        break;

      case 'e':
      case 'E':
        if (have_integer || have_fraction) {
          have_E = 1;
          in_digits = 0;
        } else {
          cli_dbgmsg("PNG: invalid exponent before mantissa\n");
          rc = 3;
        }
        break;

      default:
        if (*qq < '0' || *qq > '9') {
          cli_dbgmsg("PNG: invalid character\n");
          rc = 4;
        } else if (in_digits) {
          /* still in digits:  do nothing except check for non-zero digits */
          if (!have_exponent && *qq != '0')
            have_nonzero = 1;
        } else if (!have_integer && !have_dot) {
          have_integer = 1;
          in_digits = 1;
          if (*qq != '0')
            have_nonzero = 1;
        } else if (have_dot && !have_fraction) {
          have_fraction = 1;
          in_digits = 1;
          if (*qq != '0')
            have_nonzero = 1;
        } else if (have_E && !have_exponent) {
          have_exponent = 1;
          in_digits = 1;
        } else {
          /* is this case possible? */
          cli_dbgmsg("PNG: invalid digits\n");
          rc = 5;
        }
        break;
    }
  }

  /* must have either integer part or fractional part; all else is optional */
  if (rc == 0 && !have_integer && !have_fraction) {
    cli_dbgmsg("PNG: missing mantissa\n");
    rc = 6;
  }

  /* non-exponent part must be non-zero (=> must have seen a non-zero digit) */
  if (rc == 0 && !have_nonzero) {
    cli_dbgmsg("PNG: invalid zero value(s)\n");
    rc = 7;
  }

  return rc;
}

int cli_parsepng(cli_ctx *ctx)
{
  long sz;
  uch magic[8];
  char chunkid[5] = {'\0', '\0', '\0', '\0', '\0'};
  int toread;
  int c;
  int have_IHDR = 0, have_IEND = 0;
  int have_PLTE = 0;
  int have_IDAT = 0, have_JDAT = 0, last_is_IDAT = 0, last_is_JDAT = 0;
  int have_bKGD = 0, have_cHRM = 0, have_gAMA = 0, have_hIST = 0, have_iCCP = 0;
  int have_oFFs = 0, have_pCAL = 0, have_pHYs = 0, have_sBIT = 0, have_sCAL = 0;
  int have_sRGB = 0, have_sTER = 0, have_tIME = 0, have_tRNS = 0;
  ulg zhead = 1;   /* 0x10000 indicates both zlib header bytes read */
  ulg crc, filecrc;
  long num_chunks = 0L;
  long w = 0L, h = 0L;
  int bitdepth = 0, sampledepth = 0, lace = 0, nplte = 0;
  unsigned int ityp = 1;
  uch buffer[BS];
  int first_idat = 1;           /* flag:  is this the first IDAT chunk? */
  int zlib_error = 0;           /* reset in IHDR section; used for IDAT */
  int check_zlib = 1;           /* validate zlib stream (just IDATs for now) */
  unsigned zlib_windowbits = 15;
  uch outbuf[BS];
  z_stream zstrm;
  unsigned int offset = 0;
  fmap_t *map = *ctx->fmap;

  cli_dbgmsg("in cli_parsepng()\n");

  if(fmap_readn(map, magic, offset, 8) != 8)
    return CL_SUCCESS; /* Ignore */

  if(memcmp(magic, "\x89\x50\x4e\x47\x0d\x0a\x1a\x0a", 8))
    return CL_SUCCESS; /* Not a PNG file */

  offset += 8;

  /*-------------------- BEGINNING OF IMMENSE WHILE-LOOP --------------------*/


  while(fmap_readn(map, &c, offset, sizeof(c)) == sizeof(c)) {

    if (have_IEND) {
      cli_dbgmsg("PNG: additional data after END chunk\n");
      return CL_EPARSE;
    }

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

    if (check_chunk_name(chunkid) != 0)
      return CL_EPARSE;

    if (!have_IHDR && strcmp(chunkid,"IHDR")!=0)
    {
      cli_dbgmsg("PNG: first chunk must be IHDR\n");
      return CL_EPARSE;
    }

    crc = update_crc(CRCINIT, (uch *)chunkid, 4);
    toread = (sz > BS)? BS:sz;
    if(toread && fmap_readn(map, buffer, offset, toread) != toread) {
      cli_dbgmsg("PNG: EOF while reading data\n");
      return CL_EPARSE;
    }
    offset += toread;

    crc = update_crc(crc, (uch *)buffer, toread);

    /*------*
     | IHDR |
     *------*/
    if (strcmp(chunkid, "IHDR") == 0) {
      if (have_IHDR) {
        cli_dbgmsg("PNG: multiple IHDR not allowed\n");
	return CL_EPARSE;
      } else if (sz != 13) {
        cli_dbgmsg("PNG: invalid IHDR length\n");
	return CL_EPARSE;
      } else {
        int compr, filt;

        w = LG(buffer);
        h = LG(buffer+4);
        if (w <= 0 || h <= 0 || w > 2147483647 || h > 2147483647) {
          cli_dbgmsg("PNG: invalid image dimensions\n");
	  return CL_EPARSE;
        }
        bitdepth = sampledepth = (uch)buffer[8];
        ityp = (uch)buffer[9];
        if (ityp == 1 || ityp == 5 || ityp > sizeof(png_type)/sizeof(char*)) {
          cli_dbgmsg("PNG: invalid image type (%d)\n", ityp);
	  return CL_EPARSE;
        }
        switch (sampledepth) {
          case 1:
          case 2:
          case 4:
            if (ityp == 2 || ityp == 4 || ityp == 6) { /* RGB or GA or RGBA */
              cli_dbgmsg("PNG: invalid sample depth (%d)\n", sampledepth);
	      return CL_EPARSE;
            }
            break;
          case 8:
            break;
          case 16:
            if (ityp == 3) { /* palette */
              cli_dbgmsg("PNG: invalid sample depth (%d)\n", sampledepth);
              return CL_EPARSE;
            }
            break;
          default:
              cli_dbgmsg("PNG: invalid sample depth (%d)\n", sampledepth);
	      return CL_EPARSE;
        }
        compr = (uch)buffer[10];
        if (compr > 127) {
          cli_dbgmsg("PNG: private (invalid?) compression method (%d)\n", compr);
          return CL_EPARSE;
        } else if (compr > 0) {
          cli_dbgmsg("PNG: invalid compression method (%d)\n", compr);
          return CL_EPARSE;
        }
        filt = (uch)buffer[11];
        if (filt > 127) {
          cli_dbgmsg("PNG: private (invalid?) filter method (%d)\n", filt);
          return CL_EPARSE;
        } else if (filt > 0)
        {
          cli_dbgmsg("PNG: invalid filter method (%d)\n", filt);
          return CL_EPARSE;
        }
        lace = (uch)buffer[12];
        if (lace > 127) {
          cli_dbgmsg("PNG: private (invalid?) interlace method (%d)\n", lace);
          return CL_EPARSE;
        } else if (lace > 1) {
          cli_dbgmsg("PNG: invalid interlace method (%d)\n", lace);
          return CL_EPARSE;
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
      have_IHDR = 1;
      last_is_IDAT = last_is_JDAT = 0;
      first_idat = 1;  /* flag:  next IDAT will be the first in this subimage */
      zlib_error = 0;  /* flag:  no zlib errors yet in this file */
      /* GRR 20000304:  data dump not yet compatible with interlaced images: */
    /*================================================*
     * PNG chunks (with the exception of IHDR, above) *
     *================================================*/

    /*------*
     | PLTE |
     *------*/
    } else if (strcmp(chunkid, "PLTE") == 0) {
      if (have_PLTE) {
        cli_dbgmsg("PNG: multiple PLTE not allowed\n");
        return CL_EPARSE;
      } else if (ityp != 3 && ityp != 2 && ityp != 6) {
        cli_dbgmsg("PNG: PLTE not allowed in %s image\n", png_type[ityp]);
        return CL_EPARSE;
      } else if (have_IDAT) {
        cli_dbgmsg("PNG: PLTE must precede IDAT\n");
        return CL_EPARSE;
      } else if (have_bKGD) {
        cli_dbgmsg("PNG: PLTE must precede bKGD\n");
        return CL_EPARSE;
      } else if (sz > 768 || sz % 3 != 0) {
        cli_dbgmsg("PNG: invalid number of PLTE entries (%g)\n", (double)sz / 3);
        return CL_EPARSE;
      } else {
        nplte = sz / 3;
        if (((bitdepth == 1 && nplte > 2) ||
            (bitdepth == 2 && nplte > 4) || (bitdepth == 4 && nplte > 16)))
        {
          cli_dbgmsg("PNG: invalid number of PLTE entries (%d) for %d-bit image\n", nplte, bitdepth);
          return CL_EPARSE;
        }
      }
        if (ityp == 1)   /* for MNG and tRNS */
          ityp = 3;
      have_PLTE = 1;
      last_is_IDAT = last_is_JDAT = 0;

    } else if (strcmp(chunkid, "IDAT") == 0) {
      /* GRR FIXME:  need to check for consecutive IDATs within MNG segments */
      if (have_IDAT && !last_is_IDAT) {
          cli_dbgmsg("PNG: IDAT chunks must be consecutive\n");
          return CL_EPARSE;
      } else if (ityp == 3 && !have_PLTE) {
        cli_dbgmsg("PNG: IDAT must follow PLTE in %s image\n", png_type[ityp]);
        return CL_EPARSE;
      }

      /* We just want to check that we have read at least the minimum (10)
       * IDAT bytes possible, but avoid any overflow for short ints.  We
       * must also take into account that 0-length IDAT chunks are legal.
       */
      if (have_IDAT <= 0)
        have_IDAT = (sz > 0)? sz : -1;  /* -1 as marker for IDAT(s), no data */
      else if (have_IDAT < 10)
        have_IDAT += (sz > 10)? 10 : sz;  /* FIXME? could cap at 10 always */

      /* Dump the zlib header from the first two bytes. */
      if (zhead < 0x10000 && sz > 0) {
        zhead = (zhead << 8) + buffer[0];
        if (sz > 1 && zhead < 0x10000)
          zhead = (zhead << 8) + buffer[1];
        if (zhead >= 0x10000) {
          /* formerly print_zlibheader(zhead & 0xffff); */
          /* See the code in zlib deflate.c that writes out the header when
             s->status is INIT_STATE.  In fact this code is based on the zlib
             specification in RFC 1950 (ftp://ds.internic.net/rfc/rfc1950.txt),
             with the implicit assumption that the zlib header *is* written (it
             always should be inside a valid PNG file).  The variable names are
             taken, verbatim, from the RFC. */
          unsigned int CINFO = (zhead & 0xf000) >> 12;
          unsigned int CM = (zhead & 0xf00) >> 8;
	  zlib_windowbits = CINFO + 8;
          if((zhead & 0xffff) % 31) {
            cli_dbgmsg("PNG: compression header fails checksum\n");
            return CL_EPARSE;
          } else if (CM != 8) {
            cli_dbgmsg("PNG: non-deflate compression method (%d)\n", CM);
	    return CL_EPARSE;
	  }
        }
      }

      if (check_zlib && !zlib_error) {
        static uch *p;   /* always points to next filter byte */
        static int cur_y, cur_pass, cur_xoff, cur_yoff, cur_xskip, cur_yskip;
        static long cur_width, cur_linebytes;
        static long numfilt, numfilt_this_block, numfilt_total, numfilt_pass[7];
        uch *eod;
        int err=Z_OK;

        zstrm.next_in = buffer;
        zstrm.avail_in = toread;

        /* initialize zlib and bit/byte/line variables if not already done */
        if (first_idat) {
          zstrm.next_out = p = outbuf;
          zstrm.avail_out = BS;
          zstrm.zalloc = (alloc_func)Z_NULL;
          zstrm.zfree = (free_func)Z_NULL;
          zstrm.opaque = (voidpf)Z_NULL;
          if ((err = inflateInit2(&zstrm, zlib_windowbits)) != Z_OK) {
            cli_dbgmsg("PNG: zlib: can't initialize (error = %d)\n", err);
	    return CL_EUNPACK;
          }
          cur_y = 0;
          cur_pass = 1;     /* interlace pass:  1 through 7 */
          cur_xoff = cur_yoff = 0;
          cur_xskip = cur_yskip = lace? 8 : 1;
          cur_width = (w - cur_xoff + cur_xskip - 1) / cur_xskip; /* round up */
          cur_linebytes = ((cur_width*bitdepth + 7) >> 3) + 1; /* round, fltr */
          numfilt = 0L;
          first_idat = 0;
          if (lace) {   /* loop through passes to calculate total filters */
            int passm1, yskip=0, yoff=0, xoff=0;

            for (passm1 = 0;  passm1 < 7;  ++passm1) {
              switch (passm1) {  /* (see table below for full summary) */
                case 0:  yskip = 8; yoff = 0; xoff = 0; break;
                case 1:  yskip = 8; yoff = 0; xoff = 4; break;
                case 2:  yskip = 8; yoff = 4; xoff = 0; break;
                case 3:  yskip = 4; yoff = 0; xoff = 2; break;
                case 4:  yskip = 4; yoff = 2; xoff = 0; break;
                case 5:  yskip = 2; yoff = 0; xoff = 1; break;
                case 6:  yskip = 2; yoff = 1; xoff = 0; break;
              }
              /* effective height is reduced if odd pass:  subtract yoff (but
               * if effective width of pass is 0 => no rows and no filters) */
              numfilt_pass[passm1] =
                (w <= xoff)? 0 : (h - yoff + yskip - 1) / yskip;
              if (passm1 > 0)  /* now make it cumulative */
                numfilt_pass[passm1] += numfilt_pass[passm1 - 1];
            }
          } else {
            numfilt_pass[0] = h;   /* if non-interlaced */
            numfilt_pass[1] = numfilt_pass[2] = numfilt_pass[3] = h;
            numfilt_pass[4] = numfilt_pass[5] = numfilt_pass[6] = h;
          }
          numfilt_total = numfilt_pass[6];
        }
        numfilt_this_block = 0L;

        while (err != Z_STREAM_END && zstrm.avail_in > 0) {
          /* know zstrm.avail_out > 0:  get some image/filter data */
          err = inflate(&zstrm, Z_SYNC_FLUSH);
          if (err != Z_OK && err != Z_STREAM_END) {
            cli_dbgmsg("PNG: zlib: inflate error\n");
	    inflateEnd(&zstrm);
	    return CL_EPARSE;
          }

          /* now have uncompressed, filtered image data in outbuf */
          eod = outbuf + BS - zstrm.avail_out;
          while (p < eod) {

            if (cur_linebytes) {	/* GRP 20000727:  bugfix */
              int filttype = p[0];
              if (filttype > 127) {
                if (lace > 1)
                  break;  /* assume it's due to unknown interlace method */
                if (numfilt_this_block == 0) {
                  /* warn only on first one per block; don't break */
                  cli_dbgmsg("PNG: private (invalid?) row-filter type (%d)\n", filttype);
		  inflateEnd(&zstrm);
                  return CL_EPARSE;
                }
              } else if (filttype > 4) {
                if (lace <= 1) {
                  cli_dbgmsg("PNG: invalid row-filter type (%d)\n", filttype);
		  inflateEnd(&zstrm);
                  return CL_EPARSE;
                } /* else assume it's due to unknown interlace method */
                break;
              }
              ++numfilt;
              p += cur_linebytes;
            }
            cur_y += cur_yskip;

            if (lace) {
              while (cur_y >= h) {	/* may loop if very short image */
                /*
                    pass  xskip yskip  xoff yoff
                      1     8     8      0    0
                      2     8     8      4    0
                      3     4     8      0    4
                      4     4     4      2    0
                      5     2     4      0    2
                      6     2     2      1    0
                      7     1     2      0    1
                 */
                ++cur_pass;
                if (cur_pass & 1) {	/* beginning an odd pass */
                  cur_yoff = cur_xoff;
                  cur_xoff = 0;
                  cur_xskip >>= 1;
                } else {		/* beginning an even pass */
                  if (cur_pass == 2)
                    cur_xoff = 4;
                  else {
                    cur_xoff = cur_yoff >> 1;
                    cur_yskip >>= 1;
                  }
                  cur_yoff = 0;
                }
                cur_y = cur_yoff;
                /* effective width is reduced if even pass: subtract cur_xoff */
                cur_width = (w - cur_xoff + cur_xskip - 1) / cur_xskip;
                cur_linebytes = ((cur_width*bitdepth + 7) >> 3) + 1;
                if (cur_linebytes == 1)	/* just the filter byte?  no can do */
                    cur_linebytes = 0;	/* GRP 20000727:  added fix */
              }
            } else if (cur_y >= h) {
                inflateEnd(&zstrm);
		if(eod - p > 0) {
		    cli_dbgmsg("PNG:  %u bytes remaining in buffer before inflateEnd()", (unsigned int)(eod - p));
		    return CL_EPARSE;
		}
		err = Z_STREAM_END;
		zlib_error = 1;
            }
          }
          p -= (eod - outbuf);		/* wrap p back into outbuf region */
          zstrm.next_out = outbuf;
          zstrm.avail_out = BS;

          /* get more input (waiting until buffer empties is not necessary best
           * zlib strategy, but simpler than shifting leftover data around) */
          if (zstrm.avail_in == 0 && sz > toread) {
            int data_read;

            sz -= toread;
            toread = (sz > BS)? BS:sz;
	    if((data_read = fmap_readn(map, buffer, offset, toread)) != toread) {
              cli_dbgmsg("PNG: EOF while reading %s data\n", chunkid);
              return CL_EPARSE;
            }
	    offset += toread;
            crc = update_crc(crc, buffer, toread);
            zstrm.next_in = buffer;
            zstrm.avail_in = toread;
          }
        }
      }
      last_is_IDAT = 1;
      last_is_JDAT = 0;

    /*------*
     | IEND |
     *------*/
    } else if (strcmp(chunkid, "IEND") == 0) {
      if (have_IEND) {
        cli_dbgmsg("PNG: multiple IEND not allowed\n");
        return CL_EPARSE;
      } else if (sz != 0) {
        cli_dbgmsg("PNG: invalid IEND length\n");
        return CL_EPARSE;
      } else if (have_IDAT <= 0) {
        cli_dbgmsg("PNG: no IDAT chunks\n");
        return CL_EPARSE;
      } else if (have_IDAT < 10) {
        cli_dbgmsg("PNG: not enough IDAT data\n");
        return CL_EPARSE;
      }
      have_IEND = 1;
      last_is_IDAT = last_is_JDAT = 0;

    /*------*
     | bKGD |
     *------*/
    } else if (strcmp(chunkid, "bKGD") == 0) {
      if (have_bKGD) {
        cli_dbgmsg("PNG: multiple bKGD not allowed\n");
        return CL_EPARSE;
      } else if ((have_IDAT || have_JDAT)) {
        cli_dbgmsg("PNG: bKGD must precede IDAT\n");
        return CL_EPARSE;
      }
      switch (ityp) {
        case 0:
        case 4:
          if (sz != 2) {
            cli_dbgmsg("PNG: invalid bKGD length\n");
            return CL_EPARSE;
          }
          break;
        case 1: /* MNG top-level chunk (default values):  "as if 16-bit RGBA" */
        case 2:
        case 6:
          if (sz != 6) {
            cli_dbgmsg("PNG: invalid bKGD length\n");
            return CL_EPARSE;
          }
          break;
        case 3:
          if (sz != 1) {
            cli_dbgmsg("PNG: invalid bKGD length\n");
            return CL_EPARSE;
          } else if (buffer[0] >= nplte) {
            cli_dbgmsg("PNG: bKGD index falls outside PLTE\n");
            return CL_EPARSE;
          }
          break;
      }
      have_bKGD = 1;
      last_is_IDAT = last_is_JDAT = 0;

    /*------*
     | cHRM |
     *------*/
    } else if (strcmp(chunkid, "cHRM") == 0) {
      if (have_cHRM) {
        cli_dbgmsg("PNG: multiple cHRM not allowed\n");
        return CL_EPARSE;
      } else if (have_PLTE) {
        cli_dbgmsg("PNG: cHRM must precede PLTE\n");
        return CL_EPARSE;
      } else if ((have_IDAT || have_JDAT)) {
        cli_dbgmsg("PNG: cHRM must precede IDAT\n");
        return CL_EPARSE;
      } else if (sz != 32) {
        cli_dbgmsg("PNG: invalid cHRM length\n");
        return CL_EPARSE;
      } else {
        double wx, wy, rx, ry, gx, gy, bx, by;

        wx = (double)LG(buffer)/100000;
        wy = (double)LG(buffer+4)/100000;
        rx = (double)LG(buffer+8)/100000;
        ry = (double)LG(buffer+12)/100000;
        gx = (double)LG(buffer+16)/100000;
        gy = (double)LG(buffer+20)/100000;
        bx = (double)LG(buffer+24)/100000;
        by = (double)LG(buffer+28)/100000;

        if (wx < 0 || wx > 0.8 || wy < 0 || wy > 0.8 || wx + wy > 1.0) {
          cli_dbgmsg("PNG: invalid cHRM white point\n");
          return CL_EPARSE;
        } else if (rx < 0 || rx > 0.8 || ry < 0 || ry > 0.8 || rx + ry > 1.0) {
          cli_dbgmsg("PNG: invalid cHRM red point\n");
          return CL_EPARSE;
        } else if (gx < 0 || gx > 0.8 || gy < 0 || gy > 0.8 || gx + gy > 1.0) {
          cli_dbgmsg("PNG: invalid cHRM green point\n");
          return CL_EPARSE;
        } else if (bx < 0 || bx > 0.8 || by < 0 || by > 0.8 || bx + by > 1.0) {
          cli_dbgmsg("PNG: invalid cHRM blue point\n");
          return CL_EPARSE;
        }
      }
      have_cHRM = 1;
      last_is_IDAT = last_is_JDAT = 0;

    /*------*
     | fRAc |
     *------*/
    } else if (strcmp(chunkid, "fRAc") == 0) {
      last_is_IDAT = last_is_JDAT = 0;

    /*------*
     | gAMA |
     *------*/
    } else if (strcmp(chunkid, "gAMA") == 0) {
      if (have_gAMA) {
        cli_dbgmsg("PNG: multiple gAMA not allowed\n");
        return CL_EPARSE;
      } else if (have_IDAT || have_JDAT) {
        cli_dbgmsg("PNG: gAMA must precede IDAT\n");
        return CL_EPARSE;
      } else if (have_PLTE) {
        cli_dbgmsg("PNG: gAMA must precede PLTE\n");
        return CL_EPARSE;
      } else if (sz != 4) {
        cli_dbgmsg("PNG: invalid gAMA length\n");
        return CL_EPARSE;
      } else if (LG(buffer) == 0) {
        cli_dbgmsg("PNG: invalid gAMA value (0.0000)\n");
        return CL_EPARSE;
      }
      have_gAMA = 1;
      last_is_IDAT = last_is_JDAT = 0;

    /*------*
     | gIFg |
     *------*/
    } else if (strcmp(chunkid, "gIFg") == 0) {
      if (sz != 4) {
        cli_dbgmsg("PNG: invalid gIFg length\n");
        return CL_EPARSE;
      }
      last_is_IDAT = last_is_JDAT = 0;

    /*------*
     | gIFt |
     *------*/
    } else if (strcmp(chunkid, "gIFt") == 0) {
      if (sz < 24) {
        cli_dbgmsg("PNG: invalid gIFt length\n");
        return CL_EPARSE;
      }
      last_is_IDAT = last_is_JDAT = 0;

    /*------*
     | gIFx |
     *------*/
    } else if (strcmp(chunkid, "gIFx") == 0) {
      if (sz < 11) {
        cli_dbgmsg("PNG: invalid gIFx length\n");
        return CL_EPARSE;
      }
      last_is_IDAT = last_is_JDAT = 0;

    /*------*
     | hIST |
     *------*/
    } else if (strcmp(chunkid, "hIST") == 0) {
      if (have_hIST) {
        cli_dbgmsg("PNG: multiple hIST not allowed\n");
        return CL_EPARSE;
      } else if (!have_PLTE) {
        cli_dbgmsg("PNG: hIST must follow PLTE\n");
        return CL_EPARSE;
      } else if (have_IDAT) {
        cli_dbgmsg("PNG: hIST must precede IDAT\n");
        return CL_EPARSE;
      } else if (sz != nplte * 2) {
        cli_dbgmsg("PNG: invalid number of hIST entries (%g)\n", (double)sz / 2);
        return CL_EPARSE;
      }
      have_hIST = 1;
      last_is_IDAT = last_is_JDAT = 0;

    /*------*
     | iCCP |
     *------*/
    } else if (strcmp(chunkid, "iCCP") == 0) {
      int name_len;

      if (have_iCCP) {
        cli_dbgmsg("PNG: multiple iCCP not allowed\n");
        return CL_EPARSE;
      } else if (have_sRGB) {
        cli_dbgmsg("PNG: iCCP not allowed with sRGB\n");
        return CL_EPARSE;
      } else if (have_PLTE) {
        cli_dbgmsg("PNG: iCCP must precede PLTE\n");
        return CL_EPARSE;
      } else if (have_IDAT || have_JDAT) {
        cli_dbgmsg("PNG: iCCP must precede IDAT\n");
        return CL_EPARSE;
      } else if (check_keyword(buffer, toread, &name_len)) {
        return CL_EPARSE;
      } else {
        int remainder = toread - name_len - 3;
        uch compr = buffer[name_len+1];

        if (remainder < 0) {
          cli_dbgmsg("PNG: invalid iCCP length\n");
          return CL_EPARSE;
        } else if (buffer[name_len] != 0) {
          cli_dbgmsg("PNG: missing NULL after iCCP profile name\n");
          return CL_EPARSE;
        } else if (compr > 0 && compr < 128) {
          cli_dbgmsg("PNG: invalid iCCP compression method (%d)\n", compr);
          return CL_EPARSE;
        } else if (compr >= 128) {
          return CL_EPARSE;
        }
      }
      have_iCCP = 1;
      last_is_IDAT = last_is_JDAT = 0;

    /*------*
     | iTXt |
     *------*/
    } else if (strcmp(chunkid, "iTXt") == 0) {
      int keylen;

      if (check_keyword(buffer, toread, &keylen))
        return CL_EPARSE;
      else {
        int compressed = 0, compr = 0;

	if(keylen + 1 >= BS)
	    return CL_EPARSE;
        compressed = buffer[keylen+1];
        if (compressed < 0 || compressed > 1) {
          cli_dbgmsg("PNG: invalid iTXt compression flag (%d)\n", compressed);
          return CL_EPARSE;
        } else if ((compr = (uch)buffer[keylen+2]) > 127) {
          cli_dbgmsg("PNG: private (invalid?) iTXt compression method (%d)\n", compr);
          return CL_EPARSE;
        } else if (compr > 0) {
          cli_dbgmsg("PNG: invalid iTXt compression method (%d)\n", compr);
          return CL_EPARSE;
        }
      }
      last_is_IDAT = last_is_JDAT = 0;

    /*------*
     | oFFs |
     *------*/
    } else if (strcmp(chunkid, "oFFs") == 0) {
      if (have_oFFs) {
        cli_dbgmsg("PNG: multiple oFFs not allowed\n");
        return CL_EPARSE;
      } else if (have_IDAT || have_JDAT) {
        cli_dbgmsg("PNG: oFFs must precede IDAT\n");
        return CL_EPARSE;
      } else if (sz != 9) {
        cli_dbgmsg("PNG: invalid oFFs length\n");
        return CL_EPARSE;
      } else if (buffer[8] > 1) {
        cli_dbgmsg("PNG: invalid oFFs unit specifier (%u)\n", buffer[8]);
        return CL_EPARSE;
      }
      have_oFFs = 1;
      last_is_IDAT = last_is_JDAT = 0;

    /*------*
     | pCAL |
     *------*/
    } else if (strcmp(chunkid, "pCAL") == 0) {
      if (have_pCAL) {
        cli_dbgmsg("PNG: multiple pCAL not allowed\n");
        return CL_EPARSE;
      } else if (have_IDAT) {
        cli_dbgmsg("PNG: pCAL must precede IDAT\n");
        return CL_EPARSE;
      }
      have_pCAL = 1;
      last_is_IDAT = last_is_JDAT = 0;

    /*------*
     | pHYs |
     *------*/
    } else if (strcmp(chunkid, "pHYs") == 0) {
      if (have_pHYs) {
        cli_dbgmsg("PNG: multiple pHYs not allowed\n");
        return CL_EPARSE;
      } else if (have_IDAT || have_JDAT) {
        cli_dbgmsg("PNG: pHYS must precede DAT\n");
        return CL_EPARSE;
      } else if (sz != 9) {
        cli_dbgmsg("PNG: invalid pHYS length\n");
        return CL_EPARSE;
      } else if (buffer[8] > 1) {
        cli_dbgmsg("PNG: invalid pHYs unit specifier (%u)\n", buffer[8]);
        return CL_EPARSE;
      }
      have_pHYs = 1;
      last_is_IDAT = last_is_JDAT = 0;

    /*------*
     | sBIT |
     *------*/
    } else if (strcmp(chunkid, "sBIT") == 0) {
      int maxbits = (ityp == 3)? 8 : sampledepth;

      if (have_sBIT) {
        cli_dbgmsg("PNG: multiple sBIT not allowed\n");
        return CL_EPARSE;
      } else if (have_PLTE) {
        cli_dbgmsg("PNG: sBIT must precede PLTE\n");
        return CL_EPARSE;
      } else if (have_IDAT) {
        cli_dbgmsg("PNG: sBIT must precede IDAT\n");
        return CL_EPARSE;
      }
      switch (ityp) {
        case 0:
          if (sz != 1) {
            cli_dbgmsg("PNG: invalid sBIT length\n");
            return CL_EPARSE;
          } else if (buffer[0] == 0 || buffer[0] > maxbits) {
            cli_dbgmsg("PNG: sBIT grey bits invalid for sample image\n");
            return CL_EPARSE;
          } 
          break;
        case 2:
        case 3:
          if (sz != 3) {
            cli_dbgmsg("PNG: invalid sBIT length\n");
            return CL_EPARSE;
          } else if (buffer[0] == 0 || buffer[0] > maxbits) {
            cli_dbgmsg("PNG: sBIT red bits invalid for sample image\n");
            return CL_EPARSE;
          } else if (buffer[1] == 0 || buffer[1] > maxbits) {
            cli_dbgmsg("PNG: sBIT green bits invalid for sample image\n");
            return CL_EPARSE;
          } else if (buffer[2] == 0 || buffer[2] > maxbits) {
            cli_dbgmsg("PNG: sBIT blue bits invalid for sample image\n");
            return CL_EPARSE;
          }
          break;
        case 4:
          if (sz != 2) {
            cli_dbgmsg("PNG: invalid length\n");
            return CL_EPARSE;
          } else if (buffer[0] == 0 || buffer[0] > maxbits) {
            cli_dbgmsg("PNG: grey bits invalid for sample image\n");
            return CL_EPARSE;
          } else if (buffer[1] == 0 || buffer[1] > maxbits) {
            cli_dbgmsg("PNG: alpha bits invalid for sample image\n");
            return CL_EPARSE;
          }
          break;
        case 6:
          if (sz != 4) {
            cli_dbgmsg("PNG: invalid sBIT length\n");
            return CL_EPARSE;
          } else if (buffer[0] == 0 || buffer[0] > maxbits) {
            cli_dbgmsg("PNG: red bits invalid for sample image\n");
            return CL_EPARSE;
          } else if (buffer[1] == 0 || buffer[1] > maxbits) {
            cli_dbgmsg("PNG: green bits invalid for sample image\n");
            return CL_EPARSE;
          } else if (buffer[2] == 0 || buffer[2] > maxbits) {
            cli_dbgmsg("PNG: blue bits invalid for sample image\n");
            return CL_EPARSE;
          } else if (buffer[3] == 0 || buffer[3] > maxbits) {
            cli_dbgmsg("PNG: alpha bits invalid for sample image\n");
            return CL_EPARSE;
          }
          break;
      }
      have_sBIT = 1;
      last_is_IDAT = last_is_JDAT = 0;

    /*------*
     | sCAL |
     *------*/
    } else if (strcmp(chunkid, "sCAL") == 0) {
      int unittype = buffer[0];
      uch *pPixwidth = buffer+1, *pPixheight=NULL;

      if (have_sCAL) {
        cli_dbgmsg("PNG: multiple sCAL not allowed\n");
        return CL_EPARSE;
      } else if (have_IDAT || have_JDAT) {
        cli_dbgmsg("PNG: sCAL must precede IDAT\n");
        return CL_EPARSE;
      } else if (sz < 4) {
        cli_dbgmsg("PNG: invalid sCAL length\n");
        return CL_EPARSE;
      } else if (unittype < 1 || unittype > 2) {
        cli_dbgmsg("PNG: invalid sCAL unit specifier (%d)\n", unittype);
        return CL_EPARSE;
      } else {
        uch *qq;
        for (qq = pPixwidth;  qq < buffer+sz;  ++qq) {
          if (*qq == 0)
            break;
        }
        if (qq == buffer+sz) {
          cli_dbgmsg("PNG: missing sCAL null separator\n");
          return CL_EPARSE;
        } else {
          pPixheight = qq + 1;
          if (pPixheight == buffer+sz || *pPixheight == 0) {
            cli_dbgmsg("PNG: missing sCAL pixel height\n");
            return CL_EPARSE;
          }
        }
          for (qq = pPixheight;  qq < buffer+sz;  ++qq) {
            if (*qq == 0)
              break;
          }
          if (qq != buffer+sz) {
            cli_dbgmsg("PNG: extra sCAL null separator\n");
            return CL_EPARSE;
          }
          if (*pPixwidth == '-' || *pPixheight == '-') {
            cli_dbgmsg("PNG: invalid negative sCAL value(s)\n");
            return CL_EPARSE;
          } else if (check_ascii_float(pPixwidth, pPixheight-pPixwidth-1) ||
                     check_ascii_float(pPixheight, buffer+sz-pPixheight))
          {
            return CL_EPARSE;
          }
      }
      have_sCAL = 1;
      last_is_IDAT = last_is_JDAT = 0;

    /*------*
     | sPLT |
     *------*/
    } else if (strcmp(chunkid, "sPLT") == 0) {
      int name_len;

      if (have_IDAT) {
        cli_dbgmsg("PNG: sPLT must precede IDAT\n");
        return CL_EPARSE;
      } else if (check_keyword(buffer, toread, &name_len)) {
        return CL_EPARSE;
      } else {
        uch bps = buffer[name_len+1];
        int remainder = toread - name_len - 2;
        int bytes = (bps >> 3);
        int entry_sz = 4*bytes + 2;

        if (remainder < 0) {
          cli_dbgmsg("PNG: invalid sPLT length\n");
          return CL_EPARSE;
        } else if (buffer[name_len] != 0) {
          cli_dbgmsg("PNG: missing NULL after sPLT palette name\n");
          return CL_EPARSE;
        } else if (bps != 8 && bps != 16) {
          cli_dbgmsg("PNG: invalid sPLT sample depth\n");
          return CL_EPARSE;
        } else if (remainder % entry_sz != 0) {
          cli_dbgmsg("PNG: invalid number of sPLT entries\n");
          return CL_EPARSE;
        }
      }
      last_is_IDAT = last_is_JDAT = 0;

    /*------*
     | sRGB |
     *------*/
    } else if (strcmp(chunkid, "sRGB") == 0) {
      if (have_sRGB) {
        cli_dbgmsg("PNG: multiple sRGB not allowed\n");
        return CL_EPARSE;
      } else if (have_iCCP) {
        cli_dbgmsg("PNG: sRGB not allowed with iCCP\n");
        return CL_EPARSE;
      } else if (have_PLTE) {
        cli_dbgmsg("PNG: sRGB must precede PLTE\n");
        return CL_EPARSE;
      } else if (have_IDAT || have_JDAT) {
        cli_dbgmsg("PNG: sRGB must precede IDAT\n");
        return CL_EPARSE;
      } else if (sz != 1) {
        cli_dbgmsg("PNG: invalid sRGB length\n");
        return CL_EPARSE;
      } else if (buffer[0] > 3) {
        cli_dbgmsg("PNG: sRGB invalid rendering intent\n");
        return CL_EPARSE;
      }
      have_sRGB = 1;
      last_is_IDAT = last_is_JDAT = 0;

    /*------*
     | sTER |
     *------*/
    } else if (strcmp(chunkid, "sTER") == 0) {
      if (have_sTER) {
        cli_dbgmsg("PNG: multiple sTER not allowed\n");
        return CL_EPARSE;
      } else if (have_IDAT || have_JDAT) {
        cli_dbgmsg("PNG: sTER must precede IDAT\n");
        return CL_EPARSE;
      } else if (sz != 1) {
        cli_dbgmsg("PNG: invalid sTER length\n");
        return CL_EPARSE;
      } else if (buffer[0] > 1) {
        cli_dbgmsg("PNG: invalid sTER layout mode\n");
        return CL_EPARSE;
      }
      have_sTER = 1;
      last_is_IDAT = last_is_JDAT = 0;

    /*------*  *------*
     | tEXt |  | zTXt |
     *------*  *------*/
    } else if (strcmp(chunkid, "tEXt") == 0 || strcmp(chunkid, "zTXt") == 0) {
      int ztxt = (chunkid[0] == 'z');
      int keylen;

      if (check_keyword(buffer, toread, &keylen))
        return CL_EPARSE;
      else if (ztxt) {
        int compr = (uch)buffer[keylen+1];
        if (compr > 127) {
          cli_dbgmsg("PNG: private (possibly invalid) compression method\n");
          return CL_EPARSE;
        } else if (compr > 0) {
          cli_dbgmsg("PNG: invalid compression method\n");
          return CL_EPARSE;
        }
      }
      else if (check_text(buffer + keylen + 1, toread - keylen - 1)) {
        return CL_EPARSE;
      }
      last_is_IDAT = last_is_JDAT = 0;

    /*------*
     | tIME |
     *------*/
    } else if (strcmp(chunkid, "tIME") == 0) {
      if (have_tIME) {
        cli_dbgmsg("PNG: multiple tIME not allowed\n");
        return CL_EPARSE;
      } else if (sz != 7) {
        cli_dbgmsg("PNG: invalid tIME length\n");
        return CL_EPARSE;
      } else {
        int yr = SH(buffer);
        int mo = buffer[2];
        int dy = buffer[3];
        int hh = buffer[4];
        int mm = buffer[5];
        int ss = buffer[6];

        if (yr < 1995) {
          /* conversion to PNG format counts as modification... */
          /* FIXME:  also test for future dates? (may allow current year + 1) */
          cli_dbgmsg("PNG: invalid year\n");
          return CL_EPARSE;
        } else if (mo < 1 || mo > 12) {
          cli_dbgmsg("PNG: invalid month\n");
          return CL_EPARSE;
        } else if (dy < 1 || dy > 31) {
          /* FIXME:  also validate day given specified month? */
          cli_dbgmsg("PNG: invalid day\n");
          return CL_EPARSE;
        } else if (hh < 0 || hh > 23) {
          cli_dbgmsg("PNG: invalid hour\n");
          return CL_EPARSE;
        } else if (mm < 0 || mm > 59) {
          cli_dbgmsg("PNG: invalid minute\n");
          return CL_EPARSE;
        } else if (ss < 0 || ss > 60) {
          cli_dbgmsg("PNG: invalid second\n");
          return CL_EPARSE;
        }
        cli_dbgmsg("PNG: Time: %2d %s %4d %02d:%02d:%02d UTC\n", dy, getmonth(mo), yr, hh, mm, ss);
      }
      have_tIME = 1;
      last_is_IDAT = last_is_JDAT = 0;

    /*------*
     | tRNS |
     *------*/
    } else if (strcmp(chunkid, "tRNS") == 0) {
      if (have_tRNS) {
        cli_dbgmsg("PNG: multiple tRNS not allowed\n");
        return CL_EPARSE;
      } else if (ityp == 3 && !have_PLTE) {
        cli_dbgmsg("PNG: tRNS must follow PLTE\n");
        return CL_EPARSE;
      } else if (have_IDAT) {
        cli_dbgmsg("PNG: tRNS must precede IDAT\n");
        return CL_EPARSE;
      } else {
        switch (ityp) {
          case 0:
            if (sz != 2) {
              cli_dbgmsg("PNG: invalid tRNS length for %s image\n", png_type[ityp]);
              return CL_EPARSE;
            }
            break;
          case 2:
            if (sz != 6) {
              cli_dbgmsg("PNG: invalid tRNS length for %s image\n", png_type[ityp]);
              return CL_EPARSE;
            }
            break;
          case 3:
            if (sz > nplte) {
              cli_dbgmsg("PNG: invalid tRNS length for %s image\n", png_type[ityp]);
              return CL_EPARSE;
            }
            break;
          default:
            cli_dbgmsg("PNG: tRNS not allowed in %s image\n", png_type[ityp]);
            return CL_EPARSE;
            break;
        }
      }
      have_tRNS = 1;
      last_is_IDAT = last_is_JDAT = 0;

    /*===============*
     * unknown chunk *
     *===============*/

    } else {
      if (CRITICAL(chunkid) && SAFECOPY(chunkid)) {
        /* a critical, safe-to-copy chunk is an error */
        cli_dbgmsg("PNG: illegal critical, safe-to-copy chunk\n");
        return CL_EPARSE;
      } else if (RESERVED(chunkid)) {
        /* a chunk with the reserved bit set is an error (or spec updated) */
        cli_dbgmsg("PNG: illegal reserved-bit-set chunk\n");
        return CL_EPARSE;
      } else if (PUBLIC(chunkid)) {
        /* GRR 20050725:  all registered (public) PNG/MNG/JNG chunks are now
         *  known to pngcheck, so any unknown public ones are invalid (or have
         *  been proposed and approved since the last release of pngcheck) */
        cli_dbgmsg("PNG: illegal (unless recently approved) unknown, public\n");
        return CL_EPARSE;
      } else if (/* !PUBLIC(chunkid) && */ CRITICAL(chunkid)) {
        cli_dbgmsg("PNG: private, critical chunk (warning)\n");
        return CL_EPARSE;  /* not an error if used only internally */
      }
      last_is_IDAT = last_is_JDAT = 0;
    }

      while (sz > toread) {
        int data_read;
        sz -= toread;
        toread = (sz > BS)? BS:sz;

	data_read = fmap_readn(map, buffer, offset, toread);
        if (data_read != toread) {
          cli_dbgmsg("PNG: EOF while reading final data\n");
          return CL_EPARSE;
        }
	offset += toread;
        crc = update_crc(crc, (uch *)buffer, toread);
      }

      filecrc = getlong(map, &offset, "CRC value");

      if (filecrc != CRCCOMPL(crc)) {
        cli_dbgmsg("PNG: CRC error in chunk %s (computed %08lx, expected %08lx)\n",
               chunkid, CRCCOMPL(crc), filecrc);
        return CL_EPARSE;
      }
  }

  /*----------------------- END OF IMMENSE WHILE-LOOP -----------------------*/

  if (!have_IEND) {
    cli_dbgmsg("PNG: file doesn't end with a IEND chunk\n");
    return CL_EPARSE;
  }

  return CL_SUCCESS;
}

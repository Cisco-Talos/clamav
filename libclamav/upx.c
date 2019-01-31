/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *
 *  Authors: Alberto Wu
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

/*
** upxdec.c
**
** 05/05/2k4 - 1st attempt
** 08/05/2k4 - Now works as a charm :D
** 09/05/2k4 - Moved code outta main(), got rid of globals for thread safety, added bound checking, minor cleaning
** 04/06/2k4 - Now we handle 2B, 2D and 2E :D
** 28/08/2k4 - PE rebuild for nested packers
** 12/12/2k4 - Improved PE rebuild code and added some debug info on failure
** 23/03/2k7 - New approach for rebuilding:
               o Get imports via magic
               o Get imports via leascan
               o if (!pe) pe=scan4pe();
	       o if (!pe) forgepe();
*/

/*
** This code unpacks a dumped UPX1 section to a file.
** It was written reversing the loader found on some Win32 UPX compressed trojans; while porting
** it to C i've kinda followed the asm flow so it will probably be a bit hard to read.
** This code DOES NOT revert the uncompressed section to its original state as no E8/E9 fixup and
** of cause no IAT rebuild are performed.
**
** The Win32 asm unpacker is really a little programming jewel, pretty damn rare in these days of
** bloatness. My gratitude to whoever wrote it.
*/

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdlib.h>
#include <string.h>

#include "clamav.h"
#include "others.h"
#include "upx.h"
#include "str.h"
#include "lzma_iface.h"

#define PEALIGN(o,a) (((a))?(((o)/(a))*(a)):(o))
#define PESALIGN(o,a) (((a))?(((o)/(a)+((o)%(a)!=0))*(a)):(o))

#define HEADERS "\
\x4D\x5A\x90\x00\x02\x00\x00\x00\x04\x00\x0F\x00\xFF\xFF\x00\x00\
\xB0\x00\x00\x00\x00\x00\x00\x00\x40\x00\x1A\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xD0\x00\x00\x00\
\x0E\x1F\xB4\x09\xBA\x0D\x00\xCD\x21\xB4\x4C\xCD\x21\x54\x68\x69\
\x73\x20\x66\x69\x6C\x65\x20\x77\x61\x73\x20\x63\x72\x65\x61\x74\
\x65\x64\x20\x62\x79\x20\x43\x6C\x61\x6D\x41\x56\x20\x66\x6F\x72\
\x20\x69\x6E\x74\x65\x72\x6E\x61\x6C\x20\x75\x73\x65\x20\x61\x6E\
\x64\x20\x73\x68\x6F\x75\x6C\x64\x20\x6E\x6F\x74\x20\x62\x65\x20\
\x72\x75\x6E\x2E\x0D\x0A\x43\x6C\x61\x6D\x41\x56\x20\x2D\x20\x41\
\x20\x47\x50\x4C\x20\x76\x69\x72\x75\x73\x20\x73\x63\x61\x6E\x6E\
\x65\x72\x20\x2D\x20\x68\x74\x74\x70\x3A\x2F\x2F\x77\x77\x77\x2E\
\x63\x6C\x61\x6D\x61\x76\x2E\x6E\x65\x74\x0D\x0A\x24\x00\x00\x00\
"
#define FAKEPE "\
\x50\x45\x00\x00\x4C\x01\x01\x00\x43\x4C\x41\x4D\x00\x00\x00\x00\
\x00\x00\x00\x00\xE0\x00\x83\x8F\x0B\x01\x00\x00\x00\x10\x00\x00\
\x00\x10\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x10\x00\x00\
\x00\x10\x00\x00\x00\x00\x40\x00\x00\x10\x00\x00\x00\x02\x00\x00\
\x01\x00\x00\x00\x00\x00\x00\x00\x03\x00\x0A\x00\x00\x00\x00\x00\
\xFF\xFF\xFF\xFF\x00\x02\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\
\x00\x00\x10\x00\x00\x10\x00\x00\x00\x00\x10\x00\x00\x10\x00\x00\
\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x2e\x63\x6c\x61\x6d\x30\x31\x00\
\xFF\xFF\xFF\xFF\x00\x10\x00\x00\xFF\xFF\xFF\xFF\x00\x02\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\
"

static char *checkpe(char *dst, uint32_t dsize, char *pehdr, uint32_t *valign, unsigned int *sectcnt)
{
  char *sections;
  if (!CLI_ISCONTAINED(dst, dsize,  pehdr, 0xf8)) return NULL;

  if (cli_readint32(pehdr) != 0x4550 ) return NULL;

  if (!(*valign=cli_readint32(pehdr+0x38))) return NULL;

  sections = pehdr+0xf8;
  if (!(*sectcnt = (unsigned char)pehdr[6] + (unsigned char)pehdr[7]*256)) return NULL;

  if (!CLI_ISCONTAINED(dst, dsize, sections, *sectcnt*0x28)) return NULL;

  return sections;
}

/* PE from UPX */

static int pefromupx (const char *src, uint32_t ssize, char *dst, uint32_t *dsize, uint32_t ep, uint32_t upx0, uint32_t upx1, uint32_t *magic, uint32_t dend)
{
  char *imports, *sections=NULL, *pehdr=NULL, *newbuf;
  unsigned int sectcnt=0, upd=1;
  uint32_t realstuffsz=0, valign=0;
  uint32_t foffset=0xd0+0xf8;

  if((dst == NULL) || (src == NULL))
    return 0;

  while ((valign=magic[sectcnt++])) {
    if (CLI_ISCONTAINED(src, ssize - 5, src + ep - upx1 + valign - 2, 2) &&
	 src[ep - upx1 + valign - 2] == '\x8d' && /* lea edi, ...                  */
	 src[ep - upx1 + valign - 1] == '\xbe' )  /* ... [esi + offset]          */
      break;
  }

  if (!valign && CLI_ISCONTAINED(src, ssize - 8, src + ep - upx1 + 0x80, 8)) {
    const char *pt = &src[ep - upx1 + 0x80];
    cli_dbgmsg("UPX: bad magic - scanning for imports\n");

    while ((pt=cli_memstr(pt, ssize - (pt-src) - 8, "\x8d\xbe", 2))) {
      if (pt[6] == '\x8b' && pt[7] == '\x07') { /* lea edi, [esi+imports] / mov eax, [edi] */
	valign=pt-src+2-ep+upx1;
	break;
      }
      pt++;
    }
  }

  if (valign && CLI_ISCONTAINED(src, ssize, src + ep - upx1 + valign, 4)) {
    imports = dst + cli_readint32(src + ep - upx1 + valign);

    realstuffsz = imports-dst;

    if (realstuffsz >= *dsize ) {
      cli_dbgmsg("UPX: wrong realstuff size\n");
      /* fallback and eventually craft */
    } else {
      pehdr = imports;
      while (CLI_ISCONTAINED(dst, *dsize,  pehdr, 8) && cli_readint32(pehdr)) {
	pehdr+=8;
	while(CLI_ISCONTAINED(dst, *dsize,  pehdr, 2) && *pehdr) {
	  pehdr++;
	  while (CLI_ISCONTAINED(dst, *dsize,  pehdr, 2) && *pehdr)
	    pehdr++;
	  pehdr++;
	}
	pehdr++;
      }

      pehdr+=4;
      if (!(sections=checkpe(dst, *dsize, pehdr, &valign, &sectcnt))) pehdr=NULL;
    }
  }

  if (!pehdr && dend>0xf8+0x28) {
    cli_dbgmsg("UPX: no luck - scanning for PE\n");
    pehdr = &dst[dend-0xf8-0x28];
    while (pehdr>dst) {
      if ((sections=checkpe(dst, *dsize, pehdr, &valign, &sectcnt)))
	break;
      pehdr--;
    }
    if (!(realstuffsz = pehdr-dst)) pehdr=NULL;
  }

  if (!pehdr) {
    uint32_t rebsz = PESALIGN(dend, 0x1000);
    cli_dbgmsg("UPX: no luck - brutally crafting a reasonable PE\n");
    if (!(newbuf = (char *)cli_calloc(rebsz+0x200, sizeof(char)))) {
      cli_dbgmsg("UPX: malloc failed - giving up rebuild\n");
      return 0;
    }
    memcpy(newbuf, HEADERS, 0xd0);
    memcpy(newbuf+0xd0, FAKEPE, 0x120);
    memcpy(newbuf+0x200, dst, dend);
    memcpy(dst, newbuf, dend+0x200);
    free(newbuf);
    cli_writeint32(dst+0xd0+0x50, rebsz+0x1000);
    cli_writeint32(dst+0xd0+0x100, rebsz);
    cli_writeint32(dst+0xd0+0x108, rebsz);
    *dsize=rebsz+0x200;
    cli_dbgmsg("UPX: PE structure added to uncompressed data\n");
    return 1;
  }

  if (!sections)
    sectcnt = 0;
  foffset = PESALIGN(foffset+0x28*sectcnt, valign);

  for (upd = 0; upd <sectcnt ; upd++) {
    uint32_t vsize=PESALIGN((uint32_t)cli_readint32(sections+8), valign);
    uint32_t urva=PEALIGN((uint32_t)cli_readint32(sections+12), valign);

    /* Within bounds ? */
    if (!CLI_ISCONTAINED(upx0, realstuffsz, urva, vsize)) {
      cli_dbgmsg("UPX: Sect %d out of bounds - giving up rebuild\n", upd);
      return 0;
    }

    cli_writeint32(sections+8, vsize);
    cli_writeint32(sections+12, urva);
    cli_writeint32(sections+16, vsize);
    cli_writeint32(sections+20, foffset);
    if (foffset + vsize < foffset) {
        /* Integer overflow */
        return 0;
    }
    foffset+=vsize;

    sections+=0x28;
  }

  cli_writeint32(pehdr+8, 0x4d414c43);
  cli_writeint32(pehdr+0x3c, valign);

  if (!(newbuf = (char *) cli_calloc(foffset, sizeof(char)))) {
    cli_dbgmsg("UPX: malloc failed - giving up rebuild\n");
    return 0;
  }

  memcpy(newbuf, HEADERS, 0xd0);
  memcpy(newbuf+0xd0, pehdr,0xf8+0x28*sectcnt);
  sections = pehdr+0xf8;
  for (upd = 0; upd <sectcnt ; upd++) {
      uint32_t offset1, offset2, offset3;
      offset1 = (uint32_t)cli_readint32(sections+20);
      offset2 = (uint32_t)cli_readint32(sections+16);
      if (offset1 > foffset || offset2 > foffset || offset1 + offset2 > foffset) {
          free(newbuf);
          return 1;
      }

      offset3 = (uint32_t)cli_readint32(sections+12);
      if (offset3-upx0 > *dsize) {
          free(newbuf);
          return 1;
      }
    memcpy(newbuf+offset1, dst+offset3-upx0, offset2);
    sections+=0x28;
  }

  /* CBA restoring the imports they'll look different from the originals anyway... */
  /* ...and yeap i miss the icon too :P */

  if (foffset > *dsize + 8192) {
    cli_dbgmsg("UPX: wrong raw size - giving up rebuild\n");
    free(newbuf);
    return 0;
  }
  memcpy(dst, newbuf, foffset);
  *dsize = foffset;
  free(newbuf);

  cli_dbgmsg("UPX: PE structure rebuilt from compressed file\n");
  return 1;
}


/* [doubleebx] */

static int doubleebx(const char *src, uint32_t *myebx, uint32_t *scur, uint32_t ssize)
{
  uint32_t oldebx = *myebx;

  *myebx*=2;
  if ( !(oldebx & 0x7fffffff)) {
    if (! CLI_ISCONTAINED(src, ssize, src+*scur, 4))
      return -1;
    oldebx = cli_readint32(src+*scur);
    *myebx = oldebx*2+1;
    *scur+=4;
  }
  return (oldebx>>31);
}

/* [inflate] */

int upx_inflate2b(const char *src, uint32_t ssize, char *dst, uint32_t *dsize, uint32_t upx0, uint32_t upx1, uint32_t ep)
{
  int32_t backbytes, unp_offset = -1;
  uint32_t backsize, myebx = 0, scur=0, dcur=0, i, magic[]={0x108,0x110,0xd5,0};
  int oob;

  while (1) {
    while ((oob = doubleebx(src, &myebx, &scur, ssize)) == 1) {
      if (scur>=ssize || dcur>=*dsize)
	return -1;
      dst[dcur++] = src[scur++];
    }

    if ( oob == -1 )
      return -1;

    backbytes = 1;

    while (1) {
      if ( (oob = doubleebx(src, &myebx, &scur, ssize)) == -1 )
        return -1;
      if (((int64_t) backbytes + oob ) > INT32_MAX / 2)
        return -1;
      backbytes = backbytes*2+oob;
      if ( (oob = doubleebx(src, &myebx, &scur, ssize)) == -1 )
	return -1;
      if (oob)
        break;
    }

    backbytes-=3;

    if ( backbytes >= 0 ) {

      if (scur>=ssize)
	return -1;
            if (backbytes & 0xff000000)
                return -1;
      backbytes<<=8;
      backbytes+=(unsigned char)(src[scur++]);
      backbytes^=0xffffffff;

      if (!backbytes)
	break;
      unp_offset = backbytes;
    }

    if ( (backsize = (uint32_t)doubleebx(src, &myebx, &scur, ssize)) == 0xffffffff)
      return -1;
    if ( (oob = doubleebx(src, &myebx, &scur, ssize)) == -1)
      return -1;
        if (backsize + oob > UINT32_MAX / 2)
            return -1;
    backsize = backsize*2 + oob;
    if (!backsize) {
      backsize++;
      do {
        if ( (oob = doubleebx(src, &myebx, &scur, ssize)) == -1)
          return -1;
                if (backsize + oob > UINT32_MAX / 2)
                    return -1;
	backsize = backsize*2 + oob;
      } while ((oob = doubleebx(src, &myebx, &scur, ssize)) == 0);
      if ( oob == -1 )
        return -1;
            if (backsize + 2 > UINT32_MAX)
                return -1;
      backsize+=2;
    }

    if ( (uint32_t)unp_offset < 0xfffff300 )
      backsize++;

    backsize++;

    if (!CLI_ISCONTAINED(dst, *dsize, dst+dcur+unp_offset, backsize) || !CLI_ISCONTAINED(dst, *dsize, dst+dcur, backsize) || unp_offset >=0)
      return -1;
    for (i = 0; i < backsize; i++)
      dst[dcur + i] = dst[dcur + unp_offset + i];
    dcur+=backsize;
  }

  return pefromupx (src, ssize, dst, dsize, ep, upx0, upx1, magic, dcur);
}

int upx_inflate2d(const char *src, uint32_t ssize, char *dst, uint32_t *dsize, uint32_t upx0, uint32_t upx1, uint32_t ep)
{
  int32_t backbytes, unp_offset = -1;
  uint32_t backsize, myebx = 0, scur=0, dcur=0, i, magic[]={0x11c,0x124,0};
  int oob;

  while (1) {
    while ( (oob = doubleebx(src, &myebx, &scur, ssize)) == 1) {
      if (scur>=ssize || dcur>=*dsize)
	return -1;
      dst[dcur++] = src[scur++];
    }

    if ( oob == -1 )
      return -1;

    backbytes = 1;

    while (1) {
      if ( (oob = doubleebx(src, &myebx, &scur, ssize)) == -1 )
        return -1;
      if (((int64_t) backbytes + oob ) > INT32_MAX / 2)
        return -1;
      backbytes = backbytes*2+oob;
      if ( (oob = doubleebx(src, &myebx, &scur, ssize)) == -1 )
        return -1;
      if (oob)
	break;
      backbytes--;
      if ( (oob = doubleebx(src, &myebx, &scur, ssize)) == -1 )
        return -1;
      if (((int64_t) backbytes + oob ) > INT32_MAX / 2)
        return -1;
      backbytes=backbytes*2+oob;
    }

    backsize = 0;
    backbytes-=3;

    if ( backbytes >= 0 ) {

      if (scur>=ssize)
	return -1;
            if (backbytes & 0xff000000)
                return -1;
      backbytes<<=8;
      backbytes+=(unsigned char)(src[scur++]);
      backbytes^=0xffffffff;

      if (!backbytes)
	break;
      backsize = backbytes & 1;
      CLI_SAR(backbytes,1);
      unp_offset = backbytes;
    } else {
      if ( (backsize = (uint32_t)doubleebx(src, &myebx, &scur, ssize)) == 0xffffffff )
        return -1;
    }

    if ( (oob = doubleebx(src, &myebx, &scur, ssize)) == -1 )
      return -1;
        if (backsize + oob > UINT32_MAX / 2)
            return -1;
    backsize = backsize*2 + oob;
    if (!backsize) {
      backsize++;
      do {
        if ( (oob = doubleebx(src, &myebx, &scur, ssize)) == -1 )
          return -1;
                if (backsize + oob > UINT32_MAX / 2)
                    return -1;
	backsize = backsize*2 + oob;
      } while ( (oob = doubleebx(src, &myebx, &scur, ssize)) == 0);
      if ( oob == -1 )
        return -1;
            if (backsize + 2 > UINT32_MAX)
                return -1;
      backsize+=2;
    }

    if ( (uint32_t)unp_offset < 0xfffffb00 )
      backsize++;

    backsize++;
    if (!CLI_ISCONTAINED(dst, *dsize, dst+dcur+unp_offset, backsize) || !CLI_ISCONTAINED(dst, *dsize, dst+dcur, backsize) || unp_offset >=0 )
      return -1;
    for (i = 0; i < backsize; i++)
      dst[dcur + i] = dst[dcur + unp_offset + i];
    dcur+=backsize;
  }

  return pefromupx (src, ssize, dst, dsize, ep, upx0, upx1, magic, dcur);
}

int upx_inflate2e(const char *src, uint32_t ssize, char *dst, uint32_t *dsize, uint32_t upx0, uint32_t upx1, uint32_t ep)
{
  int32_t backbytes, unp_offset = -1;
  uint32_t backsize, myebx = 0, scur=0, dcur=0, i, magic[]={0x128,0x130,0};
  int oob;

  for(;;) {
    while ( (oob = doubleebx(src, &myebx, &scur, ssize)) ) {
      if (oob == -1)
        return -1;
      if (scur>=ssize || dcur>=*dsize)
	return -1;
      dst[dcur++] = src[scur++];
    }

    backbytes = 1;

    for(;;) {
      if ( (oob = doubleebx(src, &myebx, &scur, ssize)) == -1 )
        return -1;
      if (((int64_t) backbytes + oob ) > INT32_MAX / 2)
        return -1;
      backbytes = backbytes*2+oob;
      if ( (oob = doubleebx(src, &myebx, &scur, ssize)) == -1 )
        return -1;
      if ( oob )
	break;
      backbytes--;
      if ( (oob = doubleebx(src, &myebx, &scur, ssize)) == -1 )
        return -1;
      if (((int64_t) backbytes + oob ) > INT32_MAX / 2)
        return -1;
      backbytes=backbytes*2+oob;
    }

    backbytes-=3;

    if ( backbytes >= 0 ) {

      if (scur>=ssize)
	return -1;
            if (backbytes & 0xff000000)
                return -1;
      backbytes<<=8;
      backbytes+=(unsigned char)(src[scur++]);
      backbytes^=0xffffffff;

      if (!backbytes)
	break;
      backsize = backbytes & 1; /* Using backsize to carry on the shifted out bit (UPX uses CF) */
      CLI_SAR(backbytes,1);
      unp_offset = backbytes;
    } else {
      if ( (backsize = (uint32_t)doubleebx(src, &myebx, &scur, ssize)) == 0xffffffff )
        return -1;
    } /* Using backsize to carry on the doubleebx result (UPX uses CF) */

    if (backsize) { /* i.e. IF ( last sar shifted out 1 bit || last doubleebx()==1 ) */
      if ( (backsize = (uint32_t)doubleebx(src, &myebx, &scur, ssize)) == 0xffffffff )
        return -1;
    } else {
      backsize = 1;
      if ((oob = doubleebx(src, &myebx, &scur, ssize)) == -1)
        return -1;
      if (oob) {
	if ((oob = doubleebx(src, &myebx, &scur, ssize)) == -1)
	  return -1;
                if (backsize + oob > UINT32_MAX / 2)
                    return -1;
	  backsize = 2 + oob;
	} else {
	  do {
	    if ((oob = doubleebx(src, &myebx, &scur, ssize)) == -1)
	      return -1;
                    if (backsize + oob > UINT32_MAX / 2)
                        return -1;
	    backsize = backsize * 2 + oob;
	  } while ((oob = doubleebx(src, &myebx, &scur, ssize)) == 0);
	  if (oob == -1)
	    return -1;
                if (backsize + 2 > UINT32_MAX)
                    return -1;
	  backsize+=2;
	}
    }

    if ( (uint32_t)unp_offset < 0xfffffb00 )
      backsize++;

        if (backsize + 2 > UINT32_MAX)
            return -1;
    backsize+=2;

    if (!CLI_ISCONTAINED(dst, *dsize, dst+dcur+unp_offset, backsize) || !CLI_ISCONTAINED(dst, *dsize, dst+dcur, backsize) || unp_offset >=0 )
      return -1;
    for (i = 0; i < backsize; i++)
      dst[dcur + i] = dst[dcur + unp_offset + i];
    dcur+=backsize;
  }

  return pefromupx (src, ssize, dst, dsize, ep, upx0, upx1, magic, dcur);
}

int upx_inflatelzma(const char *src, uint32_t ssize, char *dst, uint32_t *dsize, uint32_t upx0, uint32_t upx1, uint32_t ep, uint32_t properties) {
  struct CLI_LZMA l;
  uint32_t magic[]={0xb16,0xb1e,0};
  unsigned char fake_lzmahdr[5];

  memset(&l, 0, sizeof(l));
  cli_writeint32(fake_lzmahdr + 1, *dsize);
  uint8_t lc = properties & 0xff;
  uint8_t lp = (properties >> 8) & 0xff;
  uint8_t pb = (properties >> 16) & 0xff;
  if (lc >= 9 || lp >= 5 || pb >= 5)
      return -1;

  *fake_lzmahdr = lc + 9* ( 5* pb + lp);
  l.next_in = fake_lzmahdr;
  l.avail_in = 5;
  if(cli_LzmaInit(&l, *dsize) != LZMA_RESULT_OK)
      return 0;
  l.avail_in = ssize;
  l.avail_out = *dsize;
  l.next_in = (unsigned char*)src+2;
  l.next_out = (unsigned char*)dst;

  if(cli_LzmaDecode(&l)==LZMA_RESULT_DATA_ERROR) {
/*     __asm__ __volatile__("int3"); */
    cli_LzmaShutdown(&l);
    return -1;
  }
  cli_LzmaShutdown(&l);

  return pefromupx (src, ssize, dst, dsize, ep, upx0, upx1, magic, *dsize);
}

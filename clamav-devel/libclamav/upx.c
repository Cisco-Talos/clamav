/*
 *  Copyright (C) 2004 aCaB <acab@clamav.net>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

/*
** upxdec.c
**
** 05/05/2k4 - 1st attempt
** 08/05/2k4 - Now works as a charm :D
** 09/05/2k4 - Moved code outta main(), got rid of globals for thread safety, added bound checking, minor cleaning
** 04/06/2k4 - Now we handle 2B, 2D and 2E :D
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

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>

#include "cltypes.h"

/* [doubleebx] */

static int doubleebx(char *src, int32_t *myebx, int *scur, int ssize)
{
  int32_t oldebx = *myebx;
#if WORDS_BIGENDIAN == 1
  char *pt;
  int32_t shift, i = 0;
#endif

  *myebx*=2;
  if ( !(oldebx & 0x7fffffff)) {
    if (*scur<0 || ssize-*scur<4)
      return -1;
#if WORDS_BIGENDIAN == 0
    oldebx = *(int*)(src+*scur);
#else
    oldebx = 0;
    pt = src + *scur;
    for(shift = 0; shift < 32; shift += 8) {
      oldebx |= (pt[i] & 0xff ) << shift;
      i++;
    }
#endif

    *myebx = oldebx*2+1;
    *scur+=4;
  }
  return (oldebx>>31)&1;
}

/* [inflate] */

int upx_inflate2b(char *src, int ssize, char *dst, int dsize)
{
  int32_t backbytes, unp_offset = -1, myebx = 0;
  int scur=0, dcur=0, i, backsize,oob;

  while (1) {
    while ((oob = doubleebx(src, &myebx, &scur, ssize)) == 1) {
      if (scur<0 || scur>=ssize || dcur<0 || dcur>=dsize)
	return -1;
      dst[dcur++] = src[scur++];
    }

    if ( oob == -1 )
      return -1;
    
    backbytes = 1;

    while (1) {
      if ( (oob = doubleebx(src, &myebx, &scur, ssize)) == -1 )
        return -1;
      backbytes = backbytes*2+oob;
      if ( (oob = doubleebx(src, &myebx, &scur, ssize)) == -1 )
	return -1;
      if (oob)
        break;
    }

    backsize = 0;	
    backbytes-=3;
  
    if ( backbytes >= 0 ) {

      if (scur<0 || scur>=ssize)
	return -1;
      backbytes<<=8;
      backbytes+=(unsigned char)(src[scur++]);
      backbytes^=0xffffffff;

      if (!backbytes)
	break;
      unp_offset = backbytes;
    }

    if ( (oob = doubleebx(src, &myebx, &scur, ssize)) == -1)
      return -1;
    backsize = oob;
    if ( (oob = doubleebx(src, &myebx, &scur, ssize)) == -1)
      return -1;
    backsize = backsize*2 + oob;
    if (!backsize) {
      backsize++;
      do {
        if ( (oob = doubleebx(src, &myebx, &scur, ssize)) == -1)
          return -1;
	backsize = backsize*2 + oob;
      } while ((oob = doubleebx(src, &myebx, &scur, ssize)) == 0);
      if ( oob == -1 )
        return -1;
      backsize+=2;
    }

    if ( (unsigned int)unp_offset < 0xfffff300 )
      backsize++;

    backsize++;

    for (i = 0; i < backsize; i++) {
      if (dcur+i<0 || dcur+i>=dsize || dcur+unp_offset+i<0 || dcur+unp_offset+i>=dsize)
	return -1;
      dst[dcur + i] = dst[dcur + unp_offset + i];
    }
    dcur+=backsize;
  }
  return 0;
}

int upx_inflate2d(char *src, int ssize, char *dst, int dsize)
{
  int32_t backbytes, unp_offset = -1, myebx = 0;
  int scur=0, dcur=0, i, backsize, oob;

  while (1) {
    while ( (oob = doubleebx(src, &myebx, &scur, ssize)) == 1) {
      if (scur<0 || scur>=ssize || dcur<0 || dcur>=dsize)
	return -1;
      dst[dcur++] = src[scur++];
    }

    if ( oob == -1 )
      return -1;

    backbytes = 1;

    while (1) {
      if ( (oob = doubleebx(src, &myebx, &scur, ssize)) == -1 )
        return -1;
      backbytes = backbytes*2+oob;
      if ( (oob = doubleebx(src, &myebx, &scur, ssize)) == -1 )
        return -1;
      if (oob)
	break;
      backbytes--;
      if ( (oob = doubleebx(src, &myebx, &scur, ssize)) == -1 )
        return -1;
      backbytes=backbytes*2+oob;
    }

    backsize = 0;
    backbytes-=3;
  
    if ( backbytes >= 0 ) {

      if (scur<0 || scur>=ssize)
	return -1;
      backbytes<<=8;
      backbytes+=(unsigned char)(src[scur++]);
      backbytes^=0xffffffff;

      if (!backbytes)
	break;
      backsize = backbytes & 1;
      backbytes>>=1;
      unp_offset = backbytes;
    }
    else {
      if ( (backsize = doubleebx(src, &myebx, &scur, ssize)) == -1 )
        return -1;
    }
 
    if ( (oob = doubleebx(src, &myebx, &scur, ssize)) == -1 )
      return -1;
    backsize = backsize*2 + oob;
    if (!backsize) {
      backsize++;
      do {
        if ( (oob = doubleebx(src, &myebx, &scur, ssize)) == -1 )
          return -1;
	backsize = backsize*2 + oob;
      } while ( (oob = doubleebx(src, &myebx, &scur, ssize)) == 0);
      if ( oob == -1 )
        return -1;
      backsize+=2;
    }

    if ( (unsigned int)unp_offset < 0xfffffb00 ) 
      backsize++;

    backsize++;
    for (i = 0; i < backsize; i++) {
      if (dcur+i<0 || dcur+i>=dsize || dcur+unp_offset+i<0 || dcur+unp_offset+i>=dsize)
	return -1;
      dst[dcur + i] = dst[dcur + unp_offset + i];
    }
    dcur+=backsize;
  }
  return 0;
}

int upx_inflate2e(char *src, int ssize, char *dst, int dsize)
{
  int32_t backbytes, unp_offset = -1, myebx = 0;
  int scur=0, dcur=0, i, backsize, oob;

  while (1) {
    while ( (oob = doubleebx(src, &myebx, &scur, ssize)) ) {
      if (oob == -1)
        return -1;
      if (scur<0 || scur>=ssize || dcur<0 || dcur>=dsize)
	return -1;
      dst[dcur++] = src[scur++];
    }

    backbytes = 1;

    while (1) {
      if ( (oob = doubleebx(src, &myebx, &scur, ssize)) == -1 )
        return -1;
      backbytes = backbytes*2+oob;
      if ( (oob = doubleebx(src, &myebx, &scur, ssize)) == -1 )
        return -1;
      if ( oob )
	break;
      backbytes--;
      if ( (oob = doubleebx(src, &myebx, &scur, ssize)) == -1 )
        return -1;
      backbytes=backbytes*2+oob;
    }

    backsize = 0;
    backbytes-=3;
  
    if ( backbytes >= 0 ) {

      if (scur<0 || scur>=ssize)
	return -1;
      backbytes<<=8;
      backbytes+=(unsigned char)(src[scur++]);
      backbytes^=0xffffffff;

      if (!backbytes)
	break;
      backsize = backbytes & 1; /* Using backsize to carry on the shifted out bit (UPX uses CF) */
      backbytes>>=1;
      unp_offset = backbytes;
    }
    else {
      if ( (backsize = doubleebx(src, &myebx, &scur, ssize)) == -1 )
        return -1;
    } /* Using backsize to carry on the doubleebx result (UPX uses CF) */

    if (backsize) { /* i.e. IF ( last sar shifted out 1 bit || last doubleebx()==1 ) */
      if ( (backsize = doubleebx(src, &myebx, &scur, ssize)) == -1 )
        return -1;
    }
    else {
      backsize = 1;
      if ((oob = doubleebx(src, &myebx, &scur, ssize)) == -1)
        return -1;
      if (oob) {
	if ((oob = doubleebx(src, &myebx, &scur, ssize)) == -1)
	  return -1;
	  backsize = 2 + oob;
	}
      else {
	do {
          if ((oob = doubleebx(src, &myebx, &scur, ssize)) == -1)
          return -1;
	  backsize = backsize * 2 + oob;
	} while ((oob = doubleebx(src, &myebx, &scur, ssize)) == 0);
	if (oob == -1)
          return -1;
	backsize+=2;
      }
    }
 
    if ( (unsigned int)unp_offset < 0xfffffb00 ) 
      backsize++;

    backsize+=2;
    for (i = 0; i < backsize; i++) {
      if (dcur+i<0 || dcur+i>=dsize || dcur+unp_offset+i<0 || dcur+unp_offset+i>=dsize)
	return -1;
      dst[dcur + i] = dst[dcur + unp_offset + i];
    }
    dcur+=backsize;
  }
  return 0;
}


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
** defsg.c
** 
** 02/08/2k4 - Dumped and reversed
** 02/08/2k4 - Done coding
** 03/08/2k4 - Cleaning and securing
** 04/08/2k4 - Done porting
** 07/08/2k4 - Started adding support for 1.33
*/

/*
** Unpacks an FSG compressed section.
**
** Czesc bart, good asm, nice piece of code ;)
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
#include "pe.h"
#include "rebuildpe.h"
#include "others.h"

#if WORDS_BIGENDIAN == 0
#define EC16(v)	(v)
#define EC32(v) (v)
#else
static inline uint16_t EC16(uint16_t v)
{
    return ((v >> 8) + (v << 8));
}

static inline uint32_t EC32(uint32_t v)
{
    return ((v >> 24) | ((v & 0x00FF0000) >> 8) | ((v & 0x0000FF00) << 8) | (v << 24));
}
#endif

static int doubledl(char **scur, uint8_t *mydlptr, char *buffer, int buffersize)
{
  unsigned char mydl = *mydlptr;
  unsigned char olddl = mydl;

  mydl*=2;
  if ( !(olddl & 0x7f)) {
    if ( *scur < buffer || *scur >= buffer+buffersize-1 )
      return -1;
    olddl = **scur;
    mydl = olddl*2+1;
    *scur=*scur + 1;
  }
  *mydlptr = mydl;
  return (olddl>>7)&1;
}

static int unfsg(char *source, char *dest, int ssize, int dsize, char **endsrc, char **enddst) {
  uint8_t mydl=0x80;
  uint32_t backbytes, backsize, oldback;
  char *csrc = source, *cdst = dest;
  int oob, lostbit = 1;

  /* I assume buffers size is >0 - No checking! */
  *cdst++=*csrc++;

  while ( 1 ) {
    if ((oob=doubledl(&csrc, &mydl, source, ssize))) {
      if (oob == -1)
	return -1;
      /* 164 */
      backsize = 0;
      if ((oob=doubledl(&csrc, &mydl, source, ssize))) {
	if (oob == -1)
	  return -1;
	/* 16a */
	backbytes = 0;
	if ((oob=doubledl(&csrc, &mydl, source, ssize))) {
	  if (oob == -1)
	    return -1;
	  /* 170 */
	  lostbit = 1;
	  backsize++;
	  backbytes = 0x10;
	  while ( backbytes < 0x100 ) {
	    if ((oob=doubledl(&csrc, &mydl, source, ssize)) == -1)
	      return -1;
	    backbytes = backbytes*2+oob;
	  }
	  backbytes &= 0xff;
	  if ( ! backbytes ) {
	    if (cdst >= dest+dsize)
	      return -1;
	    *cdst++=0x00;
	    continue;
	  } else {
	    /* repne movsb - FIXME dont remove for now */
	  }
	} else {
	  /* 18f */
	  if (csrc >= source+ssize)
	    return -1;
	  backbytes = *(unsigned char*)csrc;
	  backsize = backsize * 2 + (backbytes & 1);
	  backbytes = (backbytes & 0xff)>>1;
	  csrc++;
	  if (! backbytes)
	    break;
	  backsize+=2;
	  oldback = backbytes;
	  lostbit = 0;
	}
      } else {
	/* 180 */
	backsize = 1;
	do {
	  if ((oob=doubledl(&csrc, &mydl, source, ssize)) == -1)
	    return -1;
	  backsize = backsize*2+oob;
	  if ((oob=doubledl(&csrc, &mydl, source, ssize)) == -1)
	    return -1;
	} while (oob);

	backsize = backsize - 1 - lostbit;
	if (! backsize) {
	  /* 18a */
	  backsize = 1;
	  do {
	    if ((oob=doubledl(&csrc, &mydl, source, ssize)) == -1)
	      return -1;
	    backsize = backsize*2+oob;
	    if ((oob=doubledl(&csrc, &mydl, source, ssize)) == -1)
	      return -1;
	  } while (oob);

	  backbytes = oldback;
	} else {
	  /* 198 */
	  if (csrc >= source+ssize)
	    return -1;
	  backbytes = *(unsigned char*)csrc;
	  backbytes += (backsize-1)<<8;
	  backsize = 1;
	  csrc++;
	  do {
	    if ((oob=doubledl(&csrc, &mydl, source, ssize)) == -1)
	      return -1;
	    backsize = backsize*2+oob;
	    if ((oob=doubledl(&csrc, &mydl, source, ssize)) == -1)
	      return -1;
	  } while (oob);

          if (backbytes >= 0x7d00)
            backsize++;
          if (backbytes >= 0x500)
            backsize++;
          if (backbytes <= 0x7f)
            backsize += 2;

	  oldback = backbytes;
	}
	lostbit = 0;
      }
      if (cdst-backbytes < dest || cdst+backsize >= dest+dsize)
	return -1;
      while(backsize--) {
	*cdst=*(cdst-backbytes);
	cdst++;
      }

    } else {
      /* 15d */
      if (cdst < dest || cdst >= dest+dsize || csrc < source || csrc >= source+ssize)
	return -1;
      *cdst++=*csrc++;
      lostbit=1;
    }
  }

  *endsrc = csrc;
  *enddst = cdst;
  return 0;
}

int unfsg_200(char *source, char *dest, int ssize, int dsize) {
  char *fake;

  return unfsg(source, dest, ssize, dsize, &fake, &fake);
}

int unfsg_133(char *source, char *dest, int ssize, int dsize, struct SECTION *sections, int sectcount, uint32_t base, uint32_t ep, int file) {
  char *tsrc=source, *tdst=dest;
  int i, upd=1, offs=0, lastsz=dsize;

  for (i = 0 ; i <= sectcount ; i++) {
    char *startd=tdst;
    if ( unfsg(tsrc, tdst, tsrc - source + ssize, tdst - dest + dsize, &tsrc, &tdst) == -1 )
      return -1;

    /* RVA has been filled already in pe.c */
    sections[i].raw=offs;
    sections[i].rsz=tdst-startd;
    /*    cli_dbgmsg("Unpacked section %d @%x size %x Vsize =%x \n", i, offs, tdst-startd, dsize - (startd - dest)); */
    offs+=tdst-startd;
  }

  /* Sort out the sections */
  while ( upd ) {
    upd = 0;
    for (i = 0; i < sectcount  ; i++) {
      uint32_t trva,trsz,traw;
      
      if ( sections[i].rva < sections[i+1].rva )
	continue;
      trva = sections[i].rva;
      traw = sections[i].raw;
      trsz = sections[i].rsz;
      sections[i].rva = sections[i+1].rva;
      sections[i].rsz = sections[i+1].rsz;
      sections[i].raw = sections[i+1].raw;
      sections[i+1].rva = trva;
      sections[i+1].raw = traw;
      sections[i+1].rsz = trsz;
      upd = 1;
    }
  }

  /* Cure Vsizes and debugspam */
  for (i = 0; i <= sectcount ; i++) {
    if ( i != sectcount ) {
      sections[i].vsz = sections[i+1].rva - sections[i].rva;
      lastsz-= sections[i+1].rva - sections[i].rva;
    }
    else 
      sections[i].vsz = lastsz;

    cli_dbgmsg("FSG: .SECT%d RVA:%x VSize:%x ROffset: %x, RSize:% x\n", i, sections[i].rva, sections[i].vsz, sections[i].raw, sections[i].rsz);
  }

  if ( (tsrc = rebuildpe(dest, sections, sectcount+1, base, ep, 0, 0)) ) {
    write(file, tsrc, 0x148+0x80+0x28*(sectcount+1)+offs);
    free(tsrc);
  } else {
    free(tsrc);
    cli_dbgmsg("FSG: Rebuilding failed\n");
    return 0;
  }

  return 1;
}

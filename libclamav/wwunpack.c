/*
 *  Copyright (C) 2006 Sensory Networks, Inc.
 *             Written by aCaB <acab@clamav.net>
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
** wwunpack.c
**
** 09/07/2k6 - Campioni del mondo!!!
** 14/07/2k6 - RCE'ed + standalone sect unpacker
** 15/07/2k6 - Merge started
** 17/07/2k6 - Rebuild
** 18/07/2k6 - Secured (well, hopefully...)
**
*/

/*
** Unpacks+rebuilds WWPack32 1.20
**
** Just boooooring stuff, blah.
**
*/


/*
** TODO:
**
** review
** check eax vs al
** (check for dll's)
** (have a look at older versions)
**
*/


#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdlib.h>
#include <string.h>

#include "cltypes.h"
#include "others.h"
#include "wwunpack.h"

#define VAALIGN(s) (((s)/0x1000+((s)%0x1000!=0))*0x1000)
#define FIXVS(v, r) (VAALIGN((r>v)?r:v))


static int getbitmap(uint32_t *bitmap, char **src, uint8_t *bits, char *buf, unsigned int size) {
  if (! CLI_ISCONTAINED(buf, size, *src, 4)) return 1;
  *bitmap=cli_readint32(*src);
  *src+=4;
  *bits=32;
  return 0;
}

static int getbits(uint8_t X, uint32_t *eax, uint32_t *bitmap, uint8_t *bits, char **src, char *buf, unsigned int size) {
  *eax=*bitmap>>(32-X);
  if (*bits>X) {
    *bitmap<<=X;
    *bits-=X;
  } else if (*bits<X) {
    X-=*bits;
    *eax>>=X;
    if (getbitmap(bitmap, src, bits, buf, size)) return 1;
    *eax<<=X;
    *eax|=*bitmap>>(32-X);
    *bitmap<<=X;
    *bits-=X;
  } else {
    if (getbitmap(bitmap, src, bits, buf, size)) return 1;
  }
  return 0;
}

static int wunpsect(char *packed, char *unpacked, unsigned int psize, unsigned int usize) {
  char *src=packed, *dst=unpacked;
  uint32_t bitmap, eax;
  uint8_t bits;
  unsigned int lostbit, getmorestuff;
  uint16_t backbytes;
  uint16_t backsize;
  uint8_t oal;

  if (getbitmap(&bitmap, &src, &bits, packed, psize)) return 1;
  eax=bitmap;

  while (1) {
    lostbit=bitmap>>31;
    bitmap<<=1;
    bits--;
    if (!lostbit && bits) {
      if (!(CLI_ISCONTAINED(packed, psize, src, 1) && CLI_ISCONTAINED(unpacked, usize, dst, 1))) return 1;
      *dst++=*src++;
      continue;
    }
    
    if (!bits) {
      if (getbitmap(&bitmap, &src, &bits, packed, psize)) return 1;
      eax=bitmap;
      if (!lostbit) {
	if (!(CLI_ISCONTAINED(packed, psize, src, 1) && CLI_ISCONTAINED(unpacked, usize, dst, 1))) return 1;
	*dst++=*src++;
	continue;
      }
    }
    
    if (getbits(2, &eax, &bitmap, &bits, &src, packed, psize)) return 1;
    
    if ((eax&0xff)>=3) {
      /* 50ff - two_bytes */
      uint8_t fetchbits;
      
      if (getbits(2, &eax, &bitmap, &bits, &src, packed, psize)) return 1;
      fetchbits=(eax&0xff)+5;
      eax--;
      if ((int16_t)(eax&0xffff)<=0) {
	/* 5113 */
	backbytes=1<<fetchbits;
	backbytes=(backbytes&0xff00)|((backbytes-31)&0xff);
      } else {
	/* 511b */
	fetchbits++;
	backbytes=1<<fetchbits;
	backbytes-=0x9f;
      }
      /* 5125 */
      if (getbits(fetchbits, &eax, &bitmap, &bits, &src, packed, psize)) return 1;
      if ((eax&0xffff)==0x1ff) break;
      eax&=0xffff;
      backbytes+=eax;
      if (!(CLI_ISCONTAINED(unpacked, usize, dst-backbytes, 2) && CLI_ISCONTAINED(unpacked, usize, dst, 2))) return 1;
      *dst=*(dst-backbytes);
      dst++;
      *dst=*(dst-backbytes);
      dst++;
      continue;
    }

    /* 5143 - more_backbytes */      
    oal=eax&0xff;
    getmorestuff=1;

    
    if (getbits(3, &eax, &bitmap, &bits, &src, packed, psize)) return 1;
    if ((eax&0xff)<=3) {
      lostbit=0;
      if ((eax&0xff)==3) {
	/* next_bit_or_reseed */
	lostbit=bitmap>>31;
	bitmap<<=1;
	bits--;
	if (!bits) {
	  if (getbitmap(&bitmap, &src, &bits, packed, psize)) return 1; 
	}
      }
      eax=eax+lostbit+5;
      /* jmp more_bb_commondock */
    } else { /* >3 */
      /* 5160 - more_bb_morethan3 */
      if ((eax&0xff)==4) {
	/* next_bit_or_reseed */
	lostbit=bitmap>>31;
	bitmap<<=1;
	bits--;
	if (!bits) {
	  if (getbitmap(&bitmap, &src, &bits, packed, psize)) return 1;  
	}
	eax=eax+lostbit+6;
	/* jmp more_bb_commondock */
      } else { /* !=4 */
	eax+=7;
	if ((eax&0xff)>=0x0d) {
	  getmorestuff=0; /* jmp more_bb_PASTcommondock */
	  if ((eax&0xff)==0x0d) {
	    /* 5179  */
	    if (getbits(0x0e, &eax, &bitmap, &bits, &src, packed, psize)) return 1;
	    eax+=0x1fe1;
	  } else {
	    /* 516c */
	    if (getbits(0x0f, &eax, &bitmap, &bits, &src, packed, psize)) return 1;
	    eax+=0x5fe1;
	  }
	  /* jmp more_bb_PASTcommondock */
	} /* al >= 0d */
      } /* al != 4 */
    } /* >3 */
    
    if (getmorestuff) {
      /* 5192 - more_bb_commondock */
      uint16_t bk=(1<<(eax&0xff))-0x1f;
      if (getbits((eax&0xff), &eax, &bitmap, &bits, &src, packed, psize)) return 1;
      eax+=bk;
    }
    
    /* 51a7 - more_bb_pastcommondock */
    eax&=0xffff;
    backbytes=eax;
    backsize=3+(oal!=1);
    
    if (oal<1) { /* overrides backsize */
      /* 51bb - more_bb_again */
      
      /* next_bit_or_reseed */
      lostbit=bitmap>>31;
      bitmap<<=1;
      bits--;
      if (!bits) {
	if (getbitmap(&bitmap, &src, &bits, packed, psize)) return 1;  
      }
      if (!lostbit) {
	/* 51c2 */
	/* next_bit_or_reseed */
	lostbit=bitmap>>31;
	bitmap<<=1;
	bits--;
	if (!bits) {
	  if (getbitmap(&bitmap, &src, &bits, packed, psize)) return 1;   
	}
	eax=5+lostbit;
	/* jmp setsize_and_backcopy */
      } else {
	/* 51ce - more_bb_again_and_again */
	if (getbits(3, &eax, &bitmap, &bits, &src, packed, psize)) return 1;
	if (eax&0xff) {
	  /* 51e6 */
	  eax+=6;
	  /* jmp setsize_and_backcopy */
	} else {
	  if (getbits(4, &eax, &bitmap, &bits, &src, packed, psize)) return 1;
	  if (eax&0xff) {
	    /* 51e4 */
	    eax+=7+6;
	    /* jmp setsize_and_backcopy */
	  } else {
	    /* 51ea - OMGWTF */
	    uint8_t c=4;
	    uint16_t d=0x0d;
	    
	    while ( 1 ) {
	      if (c!=7){
		d+=2;
		d<<=1;
		d--;
		
		/* next_bit_or_reseed */
		lostbit=bitmap>>31;
		bitmap<<=1;
		bits--;
		if (!bits) {
		  if (getbitmap(&bitmap, &src, &bits, packed, psize)) return 1;    
		}
		c++;
		if (!lostbit) continue;
		if (getbits(c, &eax, &bitmap, &bits, &src, packed, psize)) return 1;
		d+=eax&0xff;
		eax&=0xffffff00;
		eax|=d&0xff;
	      } else {
		if (getbits(14, &eax, &bitmap, &bits, &src, packed, psize)) return 1;
	      }
	      break;
	    } /* while */
	  } /* OMGWTF */
	} /* eax&0xff */
      } /* lostbit */
	/* 521b - setsize_and_backcopy */
      backsize=eax&0xffff;
    }

    /* 521e - backcopy */
    if (!(CLI_ISCONTAINED(unpacked, usize, dst-backbytes, backsize) && CLI_ISCONTAINED(unpacked, usize, dst, backsize))) return 1;
    while(backsize--){
      *dst=*(dst-backbytes);
      dst++;
    }

  } /* while true */

  return 0;
}

int wwunpack(char *exe, uint32_t exesz, uint32_t headsize, uint32_t min, uint32_t wwprva, uint32_t e_lfanew, char *wwp, uint32_t wwpsz, uint16_t sects) {
  char *stuff=wwp+0x2a1, *packed, *unpacked;
  uint32_t rva, csize;

  cli_dbgmsg("in wwunpack\n");


  while(1) {
    if (!CLI_ISCONTAINED(wwp, wwpsz, stuff, 17)) {
      cli_dbgmsg("WWPack: next chunk out ouf file, giving up.\n");
      return 1;
    }
    if ((csize=cli_readint32(stuff+8)*4)!=(uint32_t)cli_readint32(stuff+12)+4) {
      cli_dbgmsg("WWPack: inconsistent/hacked data, go figure!\n");
      return 1;
    }
    rva = wwprva-cli_readint32(stuff);
    if((packed = (char *) cli_calloc(csize, sizeof(char))) == NULL) {
      cli_dbgmsg("WWPack: Can't allocate %d bytes\n", csize);
      return 1;
    }
    unpacked=exe+headsize+rva-min;
    if (!CLI_ISCONTAINED(exe, exesz, unpacked, csize)) {
      free(packed);
      cli_dbgmsg("WWPack: packed data out of bounds, giving up.\n");
      return 1;
    }
    memcpy(packed, unpacked, csize);
    if (wunpsect(packed, unpacked, csize, exesz-(unpacked-exe))) {
      free(packed);
      cli_dbgmsg("WWPack: unpacking failed.\n");
      return 1;
    }
    free(packed);
    if (!stuff[16]) break;
    stuff+=17;
  }

  stuff=exe+e_lfanew;
  stuff[6]=sects&0xff;
  stuff[7]=sects>>8;

  csize=cli_readint32(wwp+0x295)+wwprva+0x299;
  cli_dbgmsg("WWPack: found OEP @%x\n", csize);
  cli_writeint32(stuff+0x28, csize);

  csize=cli_readint32(stuff+0x50)-VAALIGN(wwpsz);
  cli_writeint32(stuff+0x50, csize);


  stuff+=0x18+(cli_readint32(stuff+0x14)&0xffff);
  while (sects--) {
    uint32_t v=cli_readint32(stuff+8);
    uint32_t r=cli_readint32(stuff+16);
    csize=FIXVS(v, r);
    cli_writeint32(stuff+8, csize);
    cli_writeint32(stuff+16, csize);
    cli_writeint32(stuff+20, cli_readint32(stuff+12)-min+headsize);
    stuff+=0x28;
  }
  memset(stuff, 0, 0x28);

  return 0;
}

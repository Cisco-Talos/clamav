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

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include "clamav.h"
#include "others.h"
#include "execs.h"
#include "wwunpack.h"

#if HAVE_STRING_H
#include <string.h>
#endif

#define RESEED \
if (CLI_ISCONTAINED(compd, szd, ccur, 4)) { \
  bt = cli_readint32(ccur); \
  ccur+=4; \
} else { \
  cli_dbgmsg("WWPack: Out of bits\n"); \
  error=1; \
} \
bc = 32;


#define BIT \
bits = bt>>31; \
bt<<=1; \
if(!--bc) { \
  RESEED; \
}

#define BITS(N) \
bits = bt>>(32-(N)); \
if (bc>=(N)) { \
  bc -= (N); \
  bt<<=(N); \
  if (!bc) { \
    RESEED; \
  } \
} else { \
  if (CLI_ISCONTAINED(compd, szd, ccur, 4)) { \
    bt = cli_readint32(ccur); \
    ccur+=4; \
    bc += 32 - (N); \
    bits |= bt>>(bc); \
    bt <<= (32-bc); \
  } else { \
    cli_dbgmsg("WWPack: Out of bits\n"); \
    error=1; \
  } \
}

int wwunpack(uint8_t *exe, uint32_t exesz, uint8_t *wwsect, struct cli_exe_section *sects, uint16_t scount, uint32_t pe, int desc) {
  uint8_t *structs = wwsect + 0x2a1, *compd, *ccur, *unpd, *ucur, bc;
  uint32_t src, srcend, szd, bt, bits;
  int error=0, i;

  cli_dbgmsg("in wwunpack\n");
  while (1) {
    if (!CLI_ISCONTAINED(wwsect, sects[scount].rsz, structs, 17)) {
      cli_dbgmsg("WWPack: Array of structs out of section\n");
      break;
    }
    src = sects[scount].rva - cli_readint32(structs); /* src delta / dst delta - not used / dwords / end of src */
    structs+=8;
    szd = cli_readint32(structs) * 4;
    structs+=4;
    srcend = cli_readint32(structs);
    structs+=4;

    unpd = ucur = exe+src+srcend+4-szd;
    if (!szd || !CLI_ISCONTAINED(exe, exesz, unpd, szd)) {
      cli_dbgmsg("WWPack: Compressed data out of file\n");
      break;
    }
    cli_dbgmsg("WWP: src: %x, szd: %x, srcend: %x - %x\n", src, szd, srcend, srcend+4-szd);
    if (!(compd = cli_malloc(szd))) {
        cli_dbgmsg("WWPack: Unable to allocate memory for compd\n");
        break;
    }
    memcpy(compd, unpd, szd);
    memset(unpd, -1, szd); /*FIXME*/
    ccur=compd;
    
    RESEED;
    while(!error) {
      uint32_t backbytes, backsize;
      uint8_t saved;

      BIT;
      if (!bits) { /* BYTE copy */
	if(ccur-compd>=szd || !CLI_ISCONTAINED(exe, exesz, ucur, 1))
	  error=1;
	else
	  *ucur++=*ccur++;
	continue;
      }

      BITS(2);
      if(bits==3) { /* WORD backcopy */
	uint8_t shifted, subbed = 31;
	BITS(2);
	shifted = bits + 5;
	if(bits>=2) {
	  shifted++;
	  subbed += 0x80;
	}
	backbytes = (1<<shifted)-subbed; /* 1h, 21h, 61h, 161h */
	BITS(shifted); /* 5, 6, 8, 9 */
	if(error || bits == 0x1ff) break;
	backbytes+=bits;
	if(!CLI_ISCONTAINED(exe, exesz, ucur, 2) || !CLI_ISCONTAINED(exe, exesz, ucur-backbytes, 2)) {
	  error=1;
	} else {
	  ucur[0]=*(ucur-backbytes);
	  ucur[1]=*(ucur-backbytes+1);
	  ucur+=2;
	}
	continue;
      }

      /* BLOCK backcopy */
      saved = bits; /* cmp al, 1 / pushf */

      BITS(3);
      if (bits<6) {
	backbytes = bits;
	switch(bits) {
	case 4: /* 10,11 */
	  backbytes++;
	case 3: /* 8,9 */
	  BIT;
	  backbytes+=bits;
	case 0:	case 1:	case 2: /* 5,6,7 */
	  backbytes+=5;
	  break;
	case 5: /* 12 */
	  backbytes=12;
	  break;
	}
	BITS(backbytes);
	bits+=(1<<backbytes)-31;
      } else if(bits==6) {
	BITS(0x0e);
	bits+=0x1fe1;
      } else {
	BITS(0x0f);
	bits+=0x5fe1;
      }

      backbytes = bits;

      /* popf / jb */
      if (!saved) {
	BIT;
	if(!bits) {
	  BIT;
	  bits+=5;
	} else {
	  BITS(3);
	  if(bits) {
	    bits+=6;
	  } else {
	    BITS(4);
	    if(bits) {
	      bits+=13;
	    } else {
	      uint8_t cnt = 4;
	      uint16_t shifted = 0x0d;
	      
	      do {
		if(cnt==7) { cnt = 0x0e; shifted = 0; break; }
		shifted=((shifted+2)<<1)-1;
		BIT;
		cnt++;
	      } while(!bits);
	      BITS(cnt);
	      bits+=shifted;
	    }
	  }
	}
	backsize = bits;
      } else {
	backsize = saved+2;
      }

      if(!CLI_ISCONTAINED(exe, exesz, ucur, backsize) || !CLI_ISCONTAINED(exe, exesz, ucur-backbytes, backsize)) error=1;
      else while(backsize--) {
	*ucur=*(ucur-backbytes);
	ucur++;
      }
    }
    free(compd);
    if(error) {
      cli_dbgmsg("WWPack: decompression error\n");
      break;
    }
    if (error || !*structs++) break;
  }

  if(!error) {
    if (pe+6 > exesz || pe+7 > exesz || pe+0x28 > exesz ||
		pe+0x50 > exesz || pe+0x14 > exesz) 
	return CL_EFORMAT;
    exe[pe+6]=(uint8_t)scount;
    exe[pe+7]=(uint8_t)(scount>>8);
    if (!CLI_ISCONTAINED(wwsect, sects[scount].rsz, wwsect+0x295, 4))
        cli_dbgmsg("WWPack: unpack memory address out of bounds.\n");
    else
        cli_writeint32(&exe[pe+0x28], cli_readint32(wwsect+0x295)+sects[scount].rva+0x299);
    cli_writeint32(&exe[pe+0x50], cli_readint32(&exe[pe+0x50])-sects[scount].vsz);

    structs = &exe[(0xffff&cli_readint32(&exe[pe+0x14]))+pe+0x18];
    for(i=0 ; i<scount ; i++) {
	  if (!CLI_ISCONTAINED(exe, exesz, structs, 0x28)) {
	    cli_dbgmsg("WWPack: structs pointer out of bounds\n");
	    return CL_EFORMAT;
	  }

      cli_writeint32(structs+8, sects[i].vsz);
      cli_writeint32(structs+12, sects[i].rva);
      cli_writeint32(structs+16, sects[i].vsz);
      cli_writeint32(structs+20, sects[i].rva);
      structs+=0x28;
    }
	if (!CLI_ISCONTAINED(exe, exesz, structs, 0x28)) {
	  cli_dbgmsg("WWPack: structs pointer out of bounds\n");
	  return CL_EFORMAT;
	}

    memset(structs, 0, 0x28);
    error = (uint32_t)cli_writen(desc, exe, exesz)!=exesz;
  }
  return error;
}

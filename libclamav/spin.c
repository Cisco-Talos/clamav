/*
 *  Copyright (C) 2005 aCaB <acab@clamav.net>
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
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA 02110-1301, USA.
 */

/*
** spin.c
** 
** 19/07/2k5 - Finally started coding something
** 21/07/2k5 - Works, started clearing the mess
** 31/07/2k5 - Porting to libclamav
*/

/*
** Unpacks pespin v1.1
**
** Funny thing to reverse
**
** [ A big fat thank to christoph for not letting me give up ]
*/


/*
** TODO ( a fat one ):
**
** OEP restore and unhijacking
** code redir handling (at least near OEP)
** passwd protection (didn't really look at it)
**
** All this stuff really needs a way better emu and a hell of unlaming
** ATM not worth the effort... and pespin v1.3 is out :@
**
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
#include "spin.h"

#define EC32(x) le32_to_host(x) /* Convert little endian to host */

static char exec86(uint8_t aelle, uint8_t cielle, char *curremu) {
  int len = 0;
  while (len <0x24) {
    uint8_t opcode = curremu[len], support;
    len++;
    switch (opcode) {
      case 0xeb:
        len++;
      case 0x0a:
        len++;
      case 0x90:
      case 0xf8:
      case 0xf9:
        break;

      case 0x02: /* add al, cl */
        aelle+=cielle;
	len++;
        break;
      case 0x2a: /* sub al, cl */
        aelle-=cielle;
	len++;
        break;
      case 0x04: /* add al, ?? */
        aelle+=curremu[len];
	len++;
        break;
      case 0x2c: /* sub al, ?? */
        aelle-=curremu[len];
	len++;
        break;
      case 0x32: /* xor al, cl */
        aelle^=cielle;
	len++;
        break;
      case 0x34: /* xor al, ?? */
        aelle^=curremu[len];
	len++;
        break;

      case 0xfe: /* inc/dec al */
        if ( curremu[len] == '\xc0' ) aelle++;
	else aelle--;
        len++;
        break;

      case 0xc0: /* ror/rol al, ?? */
	support = curremu[len];
        len++;
        if ( support == 0xc0 ) ROL(aelle, curremu[len]);
        else ROR(aelle, curremu[len]);
        len++;
        break;

      default:
        cli_dbgmsg("Bogus opcode %x\n", opcode);
    }
  }
  if ( len!=0x24 || curremu[len]!='\xaa' )
    cli_dbgmsg("spin: bad emucode\n"); /* FIXME: I should really give up here */
  return aelle;
}


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


static int unfsg(char *source, char *dest, int ssize, int dsize) {
  uint8_t mydl=0x80;
  uint32_t backbytes, backsize, oldback = 0;
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
      if ((backsize > (uint32_t)(dest + dsize - cdst)) || (backbytes > (uint32_t)(cdst - dest)))
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

  return 0;
}


static uint32_t summit (char *src, int size) 
{
  uint32_t eax=0xffffffff, ebx=0xffffffff;
  int i;

  while(size) {
    eax ^= *src++<<8 & 0xff00;
    eax = eax>>3 & 0x1fffffff;
    for (i=0; i<4; i++) {
      uint32_t swap;
      eax ^= ebx>>8 & 0xff;
      eax += 0x7801a108;
      eax ^= ebx;
      ROR(eax, ebx&0xff);
      swap = eax;
      eax = ebx;
      ebx = swap;
    }
    size--; 
  }
  return ebx;
}


int unspin(char *src, int ssize, struct pe_image_section_hdr *sections, int sectcnt, uint32_t nep, int desc) {
  char *curr, *emu, *ep, *spinned;
  char **sects;
  int blobsz=0, j;
  uint32_t key32, bitmap, bitman;
  uint32_t len;
  uint8_t key8;

  cli_dbgmsg("in unspin\n");

  if ( (spinned = (char *) cli_malloc(EC32(sections[sectcnt].SizeOfRawData))) == NULL )
    return 1;

  memcpy(spinned, src + EC32(sections[sectcnt].PointerToRawData), EC32(sections[sectcnt].SizeOfRawData)); 
  ep = spinned + nep - sections[sectcnt].VirtualAddress;

  curr = ep+0xdb; /* HELP: as a general rule, can i do char* math or should use monsters like "&ep[0xdb]" instead? */
  if ( *curr != '\xbb' ) {
    free(spinned);
    cli_dbgmsg("spin: Not spinned or bad version\n");
    return 1;
  }
  
  key8 = (uint8_t)*++curr;
  curr+=4;
  if ( *curr != '\xb9' ) {
    free(spinned);
    cli_dbgmsg("spin: Not spinned or bad version\n");
    return 1;
  }

  if ( (len = cli_readint32(curr+1)) != 0x11fe ) {
    free(spinned);
    cli_dbgmsg("spin: Not spinned or bad version\n");
    return 1;
  }

  cli_dbgmsg("spin: Key8 is %x, Len is %x\n", key8, len);

  if ( (uint32_t)(ep - spinned) >= EC32(sections[sectcnt].SizeOfRawData) - len - 0x1fe5 ) {
    free(spinned);
    cli_dbgmsg("spin: len out of bounds, giving up\n");
    return 1; /* Outta bounds - HELP: i suppose i should check for wraps.. not sure though */
  }


  if ( ep[0x1e0]!='\xb8' )
    cli_dbgmsg("spin: prolly not spinned, expect failure\n");
  
  if ( (cli_readint32(ep+0x1e1) & 0x00200000) )
    cli_dbgmsg("spin: password protected, expect failure\n");


  curr = ep+0x1fe5+len-1;
  while ( len-- ) {
    *curr=(*curr)^(key8--);
    curr--;
  }

  curr = ep+0x26eb;
  key32 = cli_readint32(curr);
  if ( (len = cli_readint32(curr+5)) != 0x5a0) {
    free(spinned);
    cli_dbgmsg("spin: Not spinned or bad version\n");
    return 1;
  }

  curr = ep+0x2d5; /* 0x2d5+5a0 < 0x3217 - still within bounds (checked by caller) */
  cli_dbgmsg("spin: Key is %x, Len is %x\n", key32, len);

  while ( len-- ) {
    if ( key32 & 1 ) {
      key32 = key32>>1&0x7fffffff;
      key32 ^= 0x8c328834;
    } else {
      key32 = key32>>1 & 0x7fffffff;
    }
    *curr = *curr ^ (key32 & 0xff);
    curr++;
  }

  len = ssize - cli_readint32(ep+0x429); /* sub size, value */
  if ( len >= (uint32_t)ssize ) {
    free(spinned);
    cli_dbgmsg("spin: crc out of bounds, giving up\n");
    return 1; /* We wrapped */
  }
  key32 = cli_readint32(ep+0x3217) - summit(src,len);

  memcpy(src + EC32(sections[sectcnt].PointerToRawData), spinned, EC32(sections[sectcnt].SizeOfRawData)); 
  free(spinned); /* done CRC'ing - can have a dirty buffer now */
  ep = src + nep + sections[sectcnt].PointerToRawData - sections[sectcnt].VirtualAddress; /* Fix the helper */

  bitmap = cli_readint32(ep+0x3207);
  cli_dbgmsg("spin: Key32 is %x - XORbitmap is %x\n", key32, bitmap);
  
  cli_dbgmsg("spin: Decrypting sects (xor)\n");
  for (j=0; j<sectcnt; j++) {

    if (bitmap&1) {
      uint32_t size = EC32(sections[j].SizeOfRawData);
      char *ptr = src + EC32(sections[j].PointerToRawData);
      uint32_t keydup = key32;
      
      if ( EC32(sections[j].PointerToRawData) + size >=  (uint32_t)ssize ) {
	cli_dbgmsg("spin: sect %d out of file, giving up\n", j);
	return 1; /* sect outta bounds - HELP: i suppose i should check for wraps.. not sure though */
      }

      while (size--) {
	if (! (keydup & 1)) {
	  keydup = keydup>>1&0x7fffffff; /* HELP: clear sign bit for unsigned values too? */
	  keydup ^= 0xed43af31;
	} else {
	  keydup = keydup>>1 & 0x7fffffff; /* HELP: clear sign bit for unsigned values too? */
	}
	*ptr = *ptr ^ (keydup & 0xff);
	ptr++;
      }
    } 
    bitmap = bitmap >>1 & 0x7fffffff; /* HELP: clear sign bit for unsigned values too? */
  }
  
  cli_dbgmsg("spin: done\n");

  
  curr = ep+0x644; /* 0x28d3+0x180 < 0x3217 - still within bounds (checked by caller) */
  if ( (len = cli_readint32(curr)) != 0x180) {
    cli_dbgmsg("spin: Not spinned or bad version\n");
    return 1;
  }

  key32 = cli_readint32(curr+0x0c);
  cli_dbgmsg("spin: Key is %x, Len is %x\n", key32, len);
  curr = ep+0x28d3;

  while ( len-- ) {
    if ( key32 & 1 ) {
      key32 = key32>>1&0x7fffffff;
      key32 ^= 0xed43af32;
    } else {
      key32 = key32>>1 & 0x7fffffff;
    }
    *curr = *curr ^ (key32 & 0xff);
    curr++;
  }


  curr = ep+0x28dd;
  if ( (len = cli_readint32(curr)) != 0x1a1 ) {
    cli_dbgmsg("spin: Not spinned or bad version\n");
    return 1;
  }

  cli_dbgmsg("spin: POLY1 len is %x\n", len);
  curr+=0xf; /* POLY1 */
  emu = ep+0x6d4; /* Still within bounds */

  while (len) {
    *emu=exec86(*emu, len-- & 0xff, curr); /* unlame POLY1 */
    emu++;
  }


  bitmap = cli_readint32(ep+0x6f1);
  cli_dbgmsg("spin: POLYbitmap is %x - decrypting sects (poly)\n", bitmap);
  curr = ep+0x755;

  for (j=0; j<sectcnt; j++) {
    if (bitmap&1) {
      uint32_t notthesamelen = EC32(sections[j].SizeOfRawData);

      emu = src + EC32(sections[j].PointerToRawData);

      if ( emu < src || EC32(sections[j].PointerToRawData) + notthesamelen >= (uint32_t)ssize) { /* HELP: Is this enough for me to be within bounds? */
	cli_dbgmsg("spin: code to exec is out of file?\n");
	return 1;
      }

      while (notthesamelen) {
        *emu=exec86(*emu, notthesamelen-- & 0xff, curr);
        emu++;
      }
    }
      bitmap = bitmap >>1 & 0x7fffffff;
  }
  
  cli_dbgmsg("spin: done\n");

  bitmap = cli_readint32(ep+0x3061);
  bitman = bitmap;
  cli_dbgmsg("spin: Compression bitmap is %x\n", bitmap);
  if ( (sects= (char **) cli_malloc(sectcnt*sizeof(char *))) == NULL )
    return 1;

  len = 0;
  for (j=0; j<sectcnt; j++) {
    if (bitmap&1) {
       if ( (sects[j] = (char *) cli_malloc(EC32(sections[j].VirtualSize)) ) == NULL ) { /* FIXME: use "static" maxmalloc @4380b6 instead??? */
	 cli_dbgmsg("spin: malloc(%d) failed\n", EC32(sections[j].VirtualSize));
	 len = 1;
	 break;
       }
       blobsz+=EC32(sections[j].VirtualSize);
       memset(sects[j], 0, EC32(sections[j].VirtualSize));
       cli_dbgmsg("spin: Growing sect%d: was %x will be %x\n", j, EC32(sections[j].SizeOfRawData), EC32(sections[j].VirtualSize));
       if ( unfsg(src + EC32(sections[j].PointerToRawData), sects[j], EC32(sections[j].SizeOfRawData), EC32(sections[j].VirtualSize)) == -1 ) {
	 len++;
         cli_dbgmsg("spin: Unpack failure\n");
       }
       /* sections[j].rsz = sections[j].vsz; FIXME: can't hack the caller, gotta find a better way! */
    } else {
      blobsz+=EC32(sections[j].SizeOfRawData);
      sects[j] = src + EC32(sections[j].PointerToRawData);
      cli_dbgmsg("spin: Not growing sect%d\n", j);
    }
    bitmap = bitmap >>1 & 0x7fffffff;
  }
  
  cli_dbgmsg("spin: decompression complete\n");
 
  if ( len ) {
    int t;
    for (t=0 ; t<j ; t++) {
      if (bitman&1)
	free(sects[t]);
      bitman = bitman >>1 & 0x7fffffff;
    }
    free(sects);
    return 1;
  }


  key32 = cli_readint32(ep+0x2fee);
  if (key32) {
    /*    len = cli_readint32(ep+0x2fc8); -- Using vsizes instead */

    for (j=0; j<sectcnt; j++) {
      if (EC32(sections[j].VirtualAddress) <= key32 && EC32(sections[j].VirtualAddress)+EC32(sections[j].SizeOfRawData) > key32) /* HELP: wraps? */
	break;
    }

    if (j!=sectcnt && ((bitman & (1<<j)) == 0)) { /* FIXME: not really sure either the res sect is lamed or just compressed, but this'll save some major headakes */
      cli_dbgmsg("spin: Resources (sect%d) appear to be compressed\n\tuncompressed offset %x, len %x\n\tcompressed offset %x, len %x\n", j, EC32(sections[j].VirtualAddress), key32 - EC32(sections[j].VirtualAddress), key32, EC32(sections[j].VirtualSize) - (key32 - EC32(sections[j].VirtualAddress)));

      if ( (curr=(char *)cli_malloc(EC32(sections[j].VirtualSize))) != NULL ) {
	memcpy(curr, src + EC32(sections[j].PointerToRawData), key32 - EC32(sections[j].VirtualAddress)); /* Uncompressed part */
	memset(curr + key32 - EC32(sections[j].VirtualAddress), 0, EC32(sections[j].VirtualSize) - (key32 - EC32(sections[j].VirtualAddress))); /* bzero */
	if ( unfsg(src + EC32(sections[j].PointerToRawData) + key32 - EC32(sections[j].VirtualAddress), curr + key32 - EC32(sections[j].VirtualAddress), EC32(sections[j].SizeOfRawData) - (key32 - EC32(sections[j].VirtualAddress)), EC32(sections[j].VirtualSize) - (key32 - EC32(sections[j].VirtualAddress))) ) { /* HELP: i can't read my own line - hope's ok :( */
      
	  free(curr);
	  cli_dbgmsg("spin: Failed to grow resources, continuing anyway\n");
	  blobsz+=EC32(sections[j].SizeOfRawData);
	} else {
	  sects[j]=curr; /* FIXME: bitman check above should save me from leaks */
	  bitman|=1<<j;
	  cli_dbgmsg("spin: Resources grown\n");
	  blobsz+=EC32(sections[j].VirtualSize);
	}
      } else {
	/* HELP: malloc failed but i'm too deep into this crap to worry... what to do next? */
	blobsz+=EC32(sections[j].SizeOfRawData);
      }
    } else {
      cli_dbgmsg("spin: No res?!\n");
    }
  }
  

  bitmap=bitman; /* save as a free() bitmap */

  if ( (ep = (char *) cli_malloc(blobsz)) != NULL ) {
    struct SECTION *rebhlp;
    if ( (rebhlp = (struct SECTION *) cli_malloc(sizeof(struct SECTION)*(sectcnt))) != NULL ) {
      char *to = ep;
      int retval = 0;

      for (j = 0; j < sectcnt; j++) {
	rebhlp[j].raw = (j>0)*(rebhlp[j-1].raw + rebhlp[j-1].rsz);
	rebhlp[j].rsz = (bitmap &1) ? EC32(sections[j].VirtualSize) : EC32(sections[j].SizeOfRawData);
	rebhlp[j].rva = EC32(sections[j].VirtualAddress);
	rebhlp[j].vsz = EC32(sections[j].VirtualSize);

	memcpy(to, sects[j], rebhlp[j].rsz);
	to+=rebhlp[j].rsz;
	if ( bitmap & 1 ) free(sects[j]);
	bitmap = bitmap >>1 & 0x7fffffff;
      }

      if ( (to = rebuildpe(ep, rebhlp, sectcnt, 0x400000, 0x1000, 0, 0))) { /* HELP: should i bother fixing those values? the rebuilt exe is completely broken anyway. */
	if (cli_writen(desc, to, 0x148+0x80+0x28*j+rebhlp[j-1].raw+rebhlp[j-1].rsz)==-1) {
	  cli_dbgmsg("spin: Cannot write unpacked file\n");
	  retval = 1;
	}
	free(to);
      } else {
	cli_dbgmsg("spin: Cannot write unpacked file\n");
	retval = 1;
      }
      free(rebhlp);
      free(ep);
      free(sects);
      return retval;
    }
    free(ep);
  }

  cli_dbgmsg ("spin: free bitmap is %x\n", bitman);
  for (j=0; j<sectcnt; j++) {
    if (bitmap&1) free(sects[j]);
    bitman = bitman >>1 & 0x7fffffff;
  }
  free(sects);
  return 1; /* :( */
}

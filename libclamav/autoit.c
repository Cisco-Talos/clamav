/*
 *  Copyright (C) 2007 Sourcefire Inc.
 *  Author: aCaB <acab@clamav.net>
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

#ifndef I_AM_A_FOOL
#error only a fool would use this stuff
#endif

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>

#include <stdlib.h>
#include <unistd.h>

/*********************
   MT realted stuff 
*********************/

struct MT {
  uint32_t mt[624];
  uint32_t items;
  uint32_t *next;
};

static uint8_t MT_getnext(struct MT *MT) {
  uint32_t r;

  if (!--MT->items) {
    uint32_t *mt = MT->mt;
    unsigned int i;

    MT->items = 624;
    MT->next = mt;

    for (i=0; i<227; i++)
      mt[i] = ((((mt[i] ^ mt[i+1])&0x7ffffffe)^mt[i])>>1)^((0-(mt[i+1]&1))&0x9908b0df)^mt[i+397];
    for (; i<623; i++)
      mt[i] = ((((mt[i] ^ mt[i+1])&0x7ffffffe)^mt[i])>>1)^((0-(mt[i+1]&1))&0x9908b0df)^mt[i-227];
    mt[623] = ((((mt[623] ^ mt[0])&0x7ffffffe)^mt[623])>>1)^((0-(mt[0]&1))&0x9908b0df)^mt[i-227];
  }

  r = *(MT->next++);
  r ^= (r >> 11);
  r ^= ((r & 0xff3a58ad) << 7);
  r ^= ((r & 0xffffdf8c) << 15);
  r ^= (r >> 18);
  return (uint8_t)(r >> 1);
}

static void MT_decrypt(uint8_t *buf, unsigned int size, uint32_t seed) {
  struct MT MT;
  unsigned int i;
  uint32_t *mt = MT.mt;

  *mt=seed;
  for(i=1; i<624; i++)
    mt[i] = i+0x6c078965*((mt[i-1]>>30)^mt[i-1]);
  MT.items = 1;

  while(size--)
    *buf++ ^= MT_getnext(&MT);
}


/*********************
     inflate stuff 
*********************/

struct UNP {
  uint8_t *outputbuf;
  uint8_t *inputbuf;
  uint32_t cur_output;
  uint32_t cur_input;
  uint32_t unc_size_again;
  uint8_t *alloc1_20k;
  uint32_t unc_current;
  uint32_t alloc1_cur;
  union {
    uint32_t full;
    struct {
#if WORDS_BIGENDIAN != 0
      uint16_t h; /* BE */
      uint16_t l;
#else
      uint16_t l; /* LE */
      uint16_t h;
#endif
    } half;
  } bitmap;
  uint32_t bits_avail;
};


static uint32_t getbits(struct UNP *UNP, uint32_t size) {
  UNP->bitmap.half.h = 0;
  while (size) {
    if (!UNP->bits_avail) {
      UNP->bitmap.half.l |= UNP->inputbuf[UNP->cur_input++]<<8;
      UNP->bitmap.half.l |= UNP->inputbuf[UNP->cur_input++];
      UNP->bits_avail = 16;
    }
    UNP->bitmap.full<<=1;
    UNP->bits_avail--;
    size--;
  }
  return (uint32_t)UNP->bitmap.half.h;
}


/*********************
   autoit3 handler 
*********************/

int main(int argc, char **argv) {
  uint8_t b[20000];
  uint8_t *buf = b, *out, *alloc1_20k;
  uint32_t s, cs, us, m4sum=0;
  uint8_t comp;
  int i; 
  struct UNP UNP;

  if (argc!=3) {
    printf("usage: %s <file> <offset>\n", argv[0]);
    return -1;
  }
  i = open(argv[1], O_RDONLY);
  lseek(i, strtol(argv[2], NULL, 0), SEEK_SET);
  read(i, buf, 20000);
  close(i);

  if(memcmp(buf, "\xa3\x48\x4b\xbe\x98\x6c\x4a\xa9\x99\x4c\x53\x0a\x86\xd6\x48\x7d\x41\x55\x33\x21\x45\x41\x30\x35", 8+8+4+4)) return -1;
  buf+=8+8+4+4;
  printf("found\n");

  for (i=0; i<16; i++) m4sum += *buf++;
  
  MT_decrypt(buf,4,0x16fa);
  if(memcmp(buf, "FILE", 4)) return -1;
  buf+=4;
  printf("Got FILE\n");
  s = *(uint32_t *)buf;
  buf+=4;
  s ^= 0x29bc;
  printf("Magic size: %x vs %x\n", s, 0x17);
  MT_decrypt(buf,s,s+0xa25e);
  printf("%s\n", buf);
  buf+=s;

  s = *(uint32_t *)buf;
  buf+=4;
  s ^= 0x29ac;
  printf("Original filename size: %x\n", s);
  MT_decrypt(buf,s,s+0xf25e);
  printf("%s\n", buf);
  buf+=s;

  comp = *buf++;
  
  cs = *(uint32_t *)buf;
  buf+=4;
  cs ^= 0x45aa;
  printf("Compressed size: %x\n", cs);

  us = *(uint32_t *)buf;
  buf+=4;
  us ^= 0x45aa;
  printf("Uncompressed size: %x\n", us);
  out = malloc(us);

  s = *(uint32_t *)buf;
  buf+=20;
  s ^= 0xc3d2;
  printf("Ref chksum: %x\n", s);

  MT_decrypt(buf,cs,0x22af+m4sum);
  /* verify_checksum() */

  /* struct_init */
  UNP.outputbuf = out;
  UNP.inputbuf = buf;
  UNP.cur_output = 0;
  UNP.cur_input = 8;

  /* in real_decode() */
  UNP.unc_current = 0;
  UNP.alloc1_cur = 0;
  UNP.bitmap.full = 0;
  UNP.bits_avail = 0;
  
  /* in check_packed_header() */
  if (*(uint32_t *)buf!=0x35304145) return -1;
  UNP.unc_size_again = ntohl(*(uint32_t *)(buf+4));
  printf("Uncompressed size again: %x\n", UNP.unc_size_again);
  /* in check_packed_header */

  /* in alloc123() */
  UNP.alloc1_20k = malloc(0x20000);
  /* out alloc123() */

  /* in the_real_thing() */
  while (UNP.unc_current < UNP.unc_size_again) {
    if (getbits(&UNP, 1)) {
      uint32_t bb, bs, addme=0;
      bb = getbits(&UNP, 15);
      
      /* in getback() */
      if ((bs = getbits(&UNP, 2))==3) {
	addme = 3;
	if((bs = getbits(&UNP, 3))==7) {
	  addme = 10;
	  if((bs = getbits(&UNP, 5))==31) {
	    addme = 41;
	    if((bs = getbits(&UNP, 8))==255) {
	      addme = 296;
	      while((bs = getbits(&UNP, 8))==255) {
		addme+=255;
	      }
	    }
	  }
	}
      }
      bs += 3+addme;
      /* out getback() */

      while(bs--) {
	UNP.alloc1_20k[UNP.unc_current & 0x1ffff]=UNP.alloc1_20k[(UNP.unc_current - bb) & 0x1ffff];
	UNP.unc_current++;
      }
    } else {
      UNP.alloc1_20k[UNP.unc_current & 0x1ffff] = (uint8_t)getbits(&UNP, 8);
      UNP.unc_current++;
    }
    while (UNP.alloc1_cur<UNP.unc_current) { /* flush_output - FIXME: get rid of this crap */
      UNP.outputbuf[UNP.cur_output] = UNP.alloc1_20k[UNP.alloc1_cur & 0x1fff];
      UNP.alloc1_cur++;
      UNP.cur_output++;
    }
  }

  printf("Unpacked %d out of %d bytes\n", UNP.unc_current, UNP.unc_size_again);
  i = open("script.txt", O_WRONLY|O_CREAT|O_TRUNC, S_IWUSR|S_IRUSR);
  write(i, UNP.outputbuf, UNP.unc_size_again);
  close(i);
  return 0;
}

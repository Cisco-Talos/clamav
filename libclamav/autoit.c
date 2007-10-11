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

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <arpa/inet.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "others.h"

/* STUFF TO BE REMOVED */
#include <string.h>
#define HERE printf("HERE!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
#define cli_debug_flag 1
#define cli_dbgmsg(...) printf(__VA_ARGS__)


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
  uint32_t usize;
  uint32_t csize;
  uint32_t bits_avail;
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
  uint32_t error;
};


static uint32_t getbits(struct UNP *UNP, uint32_t size) {
  UNP->bitmap.half.h = 0;
  if (size > UNP->bits_avail && ((size - UNP->bits_avail - 1)/16+1)*2 > UNP->csize - UNP->cur_input) {
    cli_dbgmsg("autoit: getbits() - not enough bits available");
    UNP->error = 1;
    return 0; /* won't infloop nor spam */
  }
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


int cli_scanautoit(int desc, cli_ctx *ctx, off_t offset) {
  uint8_t b[24];
  uint8_t *buf = b;
  uint32_t s, us, m4sum=0;
  uint8_t comp;
  int i;
  struct UNP UNP;

  lseek(desc, offset, SEEK_SET);
  if (cli_readn(desc, buf, 24)!=24)
    return CL_CLEAN;

  for (i=0; i<16; i++)
    m4sum += *buf++;
  
  MT_decrypt(buf,4,0x16fa);
  if(cli_readint32(buf) != 0x454c4946) {
    cli_dbgmsg("autoit: no FILE magic found, giving up\n");
    return CL_CLEAN;
  }

  buf+=4;
  s = cli_readint32(buf) ^ 0x29bc;
  buf=b;
  if (s > 23) {
    cli_dbgmsg("autoit: magic string too long, giving up\n");
    return CL_CLEAN;
  }
  if(cli_debug_flag) {
    cli_dbgmsg("autoit: magic string size %d (expected values 23 or 15)\n", s);
    if (cli_readn(desc, buf, s)!=(int)s)
      return CL_CLEAN;
    buf[s]='\0';
    MT_decrypt(buf,s,s+0xa25e);
    cli_dbgmsg("autoit: magic string '%s'\n", buf);
  } else {
    lseek(desc, s, SEEK_CUR);
  }

  if (cli_readn(desc, buf, 4)!=4)
    return CL_CLEAN;
  s = cli_readint32(buf) ^ 0x29ac;
  if(cli_debug_flag && s<300) {
    uint8_t *n;
    if (!(n = cli_malloc(s+1)))
      return CL_EMEM;
    if (cli_readn(desc, n, s)!=(int)s) {
      free(n);
      return CL_CLEAN;
    }
    MT_decrypt(n,s,s+0xf25e);
    n[s]='\0';
    cli_dbgmsg("autoit: original filename '%s'\n", n);
    free(n);
  } else {
    lseek(desc, s, SEEK_CUR);
  }

  if (cli_readn(desc, buf, 13)!=13)
    return CL_CLEAN;
  comp = *buf; /* FIXME: TODO - nocomp */
  UNP.csize = cli_readint32(buf+1) ^ 0x45aa;
  cli_dbgmsg("autoit: compressed size: %x\n", UNP.csize);
  us = cli_readint32(buf+5) ^ 0x45aa;
  cli_dbgmsg("autoit: advertised uncompressed size %x\n", us);
  s = cli_readint32(buf+9) ^ 0xc3d2;
  cli_dbgmsg("autoit: ref chksum: %x\n", s);

  if(ctx->limits && ctx->limits->maxfilesize && UNP.csize > ctx->limits->maxfilesize) {
    cli_dbgmsg("autoit: sizes exceeded (%lu > %lu)\n", (unsigned long int)UNP.csize, ctx->limits->maxfilesize);
    return CL_CLEAN;
  }

  lseek(desc, 16, SEEK_CUR);
  if (!(buf = cli_malloc(UNP.csize)))
    return CL_EMEM;
  if (cli_readn(desc, buf, UNP.csize)!=(int)UNP.csize) {
    cli_dbgmsg("autoit: failed to read compressed stream. broken/truncated file?\n");
    free(buf);
    return CL_CLEAN;
  }
  MT_decrypt(buf,UNP.csize,0x22af+m4sum);

  if (cli_readint32(buf)!=0x35304145) {
    cli_dbgmsg("autoit: bad magic or unsupported version\n");
    return CL_EFORMAT;
  }

  UNP.usize = ntohl(*(uint32_t *)(buf+4)); /* FIXME: portable? */
  if (!(UNP.outputbuf = cli_malloc(UNP.usize))) {
    free(buf);
    return CL_EMEM;
  }
  cli_dbgmsg("autoit: uncompressed size again: %x\n", UNP.usize);

  UNP.inputbuf = buf;
  UNP.cur_output = 0;
  UNP.cur_input = 8;
  UNP.bitmap.full = 0;
  UNP.bits_avail = 0;
  UNP.error = 0;
  
  while (!UNP.error && UNP.cur_output < UNP.usize) {
    if (getbits(&UNP, 1)) {
      uint32_t bb, bs, addme=0;
      bb = getbits(&UNP, 15);
      
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

      if(!CLI_ISCONTAINED(UNP.outputbuf, UNP.usize, &UNP.outputbuf[UNP.cur_output], bs) ||
	 !CLI_ISCONTAINED(UNP.outputbuf, UNP.usize, &UNP.outputbuf[UNP.cur_output-bb], bs)) {
	UNP.error = 1;
	break;
      }
      while(bs--) {
	UNP.outputbuf[UNP.cur_output]=UNP.outputbuf[UNP.cur_output-bb];
	UNP.cur_output++;
      }
    } else {
      UNP.outputbuf[UNP.cur_output] = (uint8_t)getbits(&UNP, 8);
      UNP.cur_output++;
    }
  }

  free(buf);
  if (UNP.error) {
    cli_dbgmsg("autoit: decompression error\n");
    free(UNP.outputbuf);
    return CL_CLEAN;
  }
  cli_dbgmsg("autoit: estracted script to FIXME...\n");
  i = open("script.txt", O_WRONLY|O_CREAT|O_TRUNC, S_IWUSR|S_IRUSR);
  write(i, UNP.outputbuf, UNP.usize);
  /* FIXME: TODO send to text notmalization and call scandesc */
  close(i);
  free(UNP.outputbuf);
  return CL_CLEAN;
}

int main(int argc, char **argv) {
  int i, j;
  char magic[24];
  cli_ctx ctx;
  ctx.limits = NULL;
  if (argc!=3) {
    printf("usage: %s <file> <offset>\n", argv[0]);
    return -1;
  }
  i = open(argv[1], O_RDONLY);
  j = strtol(argv[2], NULL, 0);
  lseek(i, j, SEEK_SET);
  read(i, magic, 24);
  if(memcmp(magic, "\xa3\x48\x4b\xbe\x98\x6c\x4a\xa9\x99\x4c\x53\x0a\x86\xd6\x48\x7d\x41\x55\x33\x21\x45\x41\x30\x35", 24)) {
    printf("Bad file or offset\n");
    return 0;
  }

  return cli_scanautoit(i, &ctx, j+24);
}

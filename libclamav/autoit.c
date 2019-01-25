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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>

#if HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "clamav.h"
#include "others.h"
#include "scanners.h"
#include "autoit.h"
#include "fmap.h"
#include "fpu.h"

static int fpu_words = FPU_ENDIAN_INITME;

/* FIXME: use unicode detection and normalization from edwin */
static unsigned int u2a(uint8_t *dest, unsigned int len) {
  uint8_t *src = dest;
  unsigned int i,j;

  if (len<2)
    return len;

  if (len>4 && src[0]==0xff && src[1]==0xfe && src[2]) {
    len-=2;
    src+=2;
  } else {
    unsigned int cnt=0;
    j = (len > 20) ? 20 : (len&~1);
      
    for (i=0; i<j; i+=2)
      cnt+=(src[i]!=0 && src[i+1]==0);

    if (cnt*4 < j)
      return len;
  }

  j=len;
  len>>=1;
  for (i=0; i<j; i+=2)
    *dest++ = src[i];

  return len;
}


/*********************
   MT realted stuff 
*********************/

struct MT {
  uint32_t *next;
  uint32_t items;
  uint32_t mt[624];
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
  MT.next = MT.mt;

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
    cli_dbgmsg("autoit: getbits() - not enough bits available\n");
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
 autoit3 EA05 handler 
*********************/


static int ea05(cli_ctx *ctx, const uint8_t *base, char *tmpd) {
  uint8_t b[300], comp;
  uint32_t s, m4sum=0;
  int i, ret, det = 0;
  unsigned int files=0;
  char tempfile[1024];
  struct UNP UNP;
  fmap_t *map = *ctx->fmap;

  if(!fmap_need_ptr_once(map, base, 16))
    return CL_CLEAN;

  for (i=0; i<16; i++)
    m4sum += *base++;

  while((ret=cli_checklimits("autoit", ctx, 0, 0, 0))==CL_CLEAN) {
    if(!fmap_need_ptr_once(map, base, 8))
      return (det ? CL_VIRUS : CL_CLEAN);

    /*     MT_decrypt(buf,4,0x16fa);  waste of time */
    if((uint32_t)cli_readint32(base) != 0xceb06dff) {
      cli_dbgmsg("autoit: no FILE magic found, extraction complete\n");
      return (det ? CL_VIRUS : CL_CLEAN);
    }

    s = cli_readint32(base+4) ^ 0x29bc;
    if ((int32_t)s<0)
      return (det ? CL_VIRUS : CL_CLEAN); /* the original code wouldn't seek back here */
    base += 8;
    if(cli_debug_flag && s<sizeof(b)) {
      if (!fmap_need_ptr_once(map, base, s))
	return (det ? CL_VIRUS : CL_CLEAN);
      memcpy(b, base, s);
      MT_decrypt(b,s,s+0xa25e);
      b[s]='\0';
      cli_dbgmsg("autoit: magic string '%s'\n", b);
    }
    base += s;

    if (!fmap_need_ptr_once(map, base, 4))
      return (det ? CL_VIRUS : CL_CLEAN);
    s = cli_readint32(base) ^ 0x29ac;
    if ((int32_t)s<0)
      return (det ? CL_VIRUS : CL_CLEAN); /* the original code wouldn't seek back here */
    base += 4;
    if (cli_debug_flag && s<sizeof(b)) {
      if (!fmap_need_ptr_once(map, base, s))
	return (det ? CL_VIRUS : CL_CLEAN);
      memcpy(b, base, s);
      MT_decrypt(b,s,s+0xf25e);
      b[s]='\0';
      cli_dbgmsg("autoit: original filename '%s'\n", b);
    }
    base += s;

    if (!fmap_need_ptr_once(map, base, 13))
      return (det ? CL_VIRUS : CL_CLEAN);
    comp = *base;
    UNP.csize = cli_readint32(base+1) ^ 0x45aa;
    if ((int32_t)UNP.csize<0) {
      cli_dbgmsg("autoit: bad file size - giving up\n");
      return (det ? CL_VIRUS : CL_CLEAN);
    }

    if(!UNP.csize) {
      cli_dbgmsg("autoit: skipping empty file\n");
      base += 13 + 16;
      continue;
    }
    cli_dbgmsg("autoit: compressed size: %x\n", UNP.csize);
    cli_dbgmsg("autoit: advertised uncompressed size %x\n", cli_readint32(base+5) ^ 0x45aa);
    cli_dbgmsg("autoit: ref chksum: %x\n", cli_readint32(base+9) ^ 0xc3d2);

    base += 13 + 16;

    if(cli_checklimits("autoit", ctx, UNP.csize, 0, 0)!=CL_CLEAN) {
      base += UNP.csize;
      continue;
    }

    if (comp == 1 && UNP.csize < sizeof(union unaligned_32)) {
      cli_dbgmsg("autoit: compressed size too small, skipping\n");
      continue;
    }

    if (!(UNP.inputbuf = cli_malloc(UNP.csize)))
      return CL_EMEM;
    if (!fmap_need_ptr_once(map, base, UNP.csize)) {
      cli_dbgmsg("autoit: failed to read compressed stream. broken/truncated file?\n");
      free(UNP.inputbuf);
      return (det ? CL_VIRUS : CL_CLEAN);
    }
    memcpy(UNP.inputbuf, base, UNP.csize);
    base += UNP.csize;
    MT_decrypt(UNP.inputbuf,UNP.csize,0x22af+m4sum);

    if (comp == 1) {
      cli_dbgmsg("autoit: file is compressed\n");
      if (cli_readint32(UNP.inputbuf)!=0x35304145) {
	cli_dbgmsg("autoit: bad magic or unsupported version\n");
	free(UNP.inputbuf);
	continue;
      }

      if(!(UNP.usize = be32_to_host(*(uint32_t *)(UNP.inputbuf+4))))
	UNP.usize = UNP.csize; /* only a specifically crafted or badly corrupted sample should land here */
      if(cli_checklimits("autoit", ctx, UNP.usize, 0, 0)!=CL_CLEAN) {
	free(UNP.inputbuf);
	continue;
      }

      if (!(UNP.outputbuf = cli_malloc(UNP.usize))) {
	free(UNP.inputbuf);
	return CL_EMEM;
      }
      cli_dbgmsg("autoit: uncompressed size again: %x\n", UNP.usize);

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

      free(UNP.inputbuf);
      /* Sometimes the autoit exe is in turn packed/lamed with a runtime compressor and similar shit.
       * However, since the autoit script doesn't compress a second time very well, chances are we're
       * still able to match the headers and unpack something (see sample 0811129)
       * I'd rather unpack something (although possibly highly corrupted) than nothing at all
       *
       * - Fortuna audaces iuvat -
       */
      if (UNP.error) {
	cli_dbgmsg("autoit: decompression error after %u bytes  - partial file may exist\n", UNP.cur_output);
	UNP.usize = UNP.cur_output;
      }
    } else {
      cli_dbgmsg("autoit: file is not compressed\n");
      UNP.outputbuf = UNP.inputbuf;
      UNP.usize = UNP.csize;
    }

    if (UNP.usize<4) {
      cli_dbgmsg("autoit: file is too short\n");
      free(UNP.outputbuf);
      continue;
    }

    files++;

    /* FIXME: REGRESSION NEEDED! */
    /* UNP.usize = u2a(UNP.outputbuf, UNP.usize); */

    snprintf(tempfile, 1023, "%s"PATHSEP"autoit.%.3u", tmpd, files);
    tempfile[1023]='\0';
    if((i = open(tempfile, O_RDWR|O_CREAT|O_TRUNC|O_BINARY, S_IRWXU)) < 0) {
      cli_dbgmsg("autoit: Can't create file %s\n", tempfile);
      free(UNP.outputbuf);
      return CL_ECREAT;
    }
    if(cli_writen(i, UNP.outputbuf, UNP.usize) != (int32_t)UNP.usize) {
      cli_dbgmsg("autoit: cannot write %d bytes\n", UNP.usize);
      close(i);
      free(UNP.outputbuf);
      return CL_EWRITE;
    }
    free(UNP.outputbuf);
    if(ctx->engine->keeptmp)
      cli_dbgmsg("autoit: file extracted to %s\n", tempfile);
    else 
      cli_dbgmsg("autoit: file successfully extracted\n");
    if (lseek(i, 0, SEEK_SET) == -1) {
        cli_dbgmsg("autoit: call to lseek() has failed\n");
        close(i);
        return CL_ESEEK;
    }
    if(cli_magic_scandesc(i, tempfile, ctx) == CL_VIRUS) {
      if (!SCAN_ALLMATCHES) {
	close(i);
	if(!ctx->engine->keeptmp)
	  if(cli_unlink(tempfile)) return CL_EUNLINK;
	return CL_VIRUS;
      }
      det = 1;
    }
    close(i);
    if(!ctx->engine->keeptmp)
      if (cli_unlink(tempfile)) return CL_EUNLINK;
  }
  return (det ? CL_VIRUS : ret);
}


/*********************
  LAME realted stuff 
*********************/

#define ROFL(a,b) (( a << (b % (sizeof(a)<<3) ))  |  (a >> (  (sizeof(a)<<3)  -  (b % (sizeof(a)<<3 )) ) ))

struct LAME {
  uint32_t c0;
  uint32_t c1;
  uint32_t grp1[17];
};


static double LAME_fpusht(struct LAME *l) {
  union {
    double as_double;
    struct {
      uint32_t lo;
      uint32_t hi;
    } as_uint;
  } ret;

  uint32_t rolled = ROFL(l->grp1[l->c0],9) +  ROFL(l->grp1[l->c1],13);

  l->grp1[l->c0] = rolled;

  if (!l->c0--) l->c0 = 16;
  if (!l->c1--) l->c1 = 16;

/*   if (l->grp1[l->c0] == l->grp2[0]) { */
/*     if (!memcmp(l->grp1, (uint32_t *)l + 0x24 - l->c0, 0x44)) */
/*       return 0.0; */
/*   } */

  if (fpu_words == FPU_ENDIAN_LITTLE) {
      ret.as_uint.lo = rolled << 0x14;
      ret.as_uint.hi = 0x3ff00000 | (rolled >> 0xc);
  } else {
      ret.as_uint.hi = rolled << 0x14;
      ret.as_uint.lo = 0x3ff00000 | (rolled >> 0xc);
  }
  return ret.as_double - 1.0;
}


static void LAME_srand(struct LAME *l, uint32_t seed) {
  unsigned int i;

  for (i=0; i<17; i++) {
    seed *= 0x53A9B4FB; /*1403630843*/
    seed = 1 - seed;
    l->grp1[i] = seed;
  }

  l->c0 = 0;
  l->c1 = 10;

  for (i = 0; i < 9; i++)
    LAME_fpusht(l);
}

static uint8_t LAME_getnext(struct LAME *l) {
  double x;
  uint8_t ret;

  LAME_fpusht(l);
  x = LAME_fpusht(l) * 256.0;
  if ((int32_t)x < 256) ret = (uint8_t)x;
  else ret=0xff;
  return ret;
}

static void LAME_decrypt (uint8_t *cypher, uint32_t size, uint16_t seed) {
  struct LAME lame;
  /* mt_srand_timewrap(struct srand_struc bufDC); */

  LAME_srand(&lame, (uint32_t)seed);
  while(size--)
    *cypher++^=LAME_getnext(&lame);
}


/*********************
 autoit3 EA06 handler 
*********************/

static int ea06(cli_ctx *ctx, const uint8_t *base, char *tmpd) {
  uint8_t b[600], comp, script, *buf;
  uint32_t s;
  int i, ret, det = 0;
  unsigned int files=0;
  char tempfile[1024];
  const char prefixes[] = { '\0', '\0', '@', '$', '\0', '.', '"', '#' };
  const char *opers[] = { ",", "=", ">", "<", "<>", ">=", "<=", "(", ")", "+", "-", "/", "*", "&", "[", "]", "==", "^", "+=", "-=", "/=", "*=", "&=" };
  struct UNP UNP;
  fmap_t *map = *ctx->fmap;


  /* Useless due to a bug in CRC calculation - LMAO!!1 */
  /*   if (cli_readn(desc, buf, 24)!=24) */
  /*     return CL_CLEAN; */
  /*   LAME_decrypt(buf, 0x10, 0x99f2); */
  /*   buf+=0x10; */
  base += 16;   /* for now we just skip the garbage */

  while((ret=cli_checklimits("cli_autoit", ctx, 0, 0, 0))==CL_CLEAN) {
    if(!fmap_need_ptr_once(map, base, 8))
      return (det ? CL_VIRUS : CL_CLEAN);
    /*     LAME_decrypt(buf, 4, 0x18ee); waste of time */
    if(cli_readint32(base) != 0x52ca436b) {
      cli_dbgmsg("autoit: no FILE magic found, giving up\n");
      return (det ? CL_VIRUS : CL_CLEAN);
    }

    script = 0;

    s = cli_readint32(base+4) ^ 0xadbc;
    if ((int32_t)(s*2)<0)
      return (det ? CL_VIRUS : CL_CLEAN); /* the original code wouldn't seek back here */
    base += 8;
    if(s < sizeof(b) / 2) {
      if(!fmap_need_ptr_once(map, base, s*2))
	return (det ? CL_VIRUS : CL_CLEAN);
      memcpy(b, base, s*2);
      LAME_decrypt(b,s*2,s+0xb33f);
      u2a(b,s*2);
      cli_dbgmsg("autoit: magic string '%s'\n", b);
      if (s==19 && !memcmp(">>>AUTOIT SCRIPT<<<", b, 19))
	script = 1;
    } else {
      cli_dbgmsg("autoit: magic string too long to print\n");
    }
    base += s*2;

    if (!fmap_need_ptr_once(map, base, 4))
      return (det ? CL_VIRUS : CL_CLEAN);
    s = cli_readint32(base) ^ 0xf820;
    if ((int32_t)(s*2)<0)
      return (det ? CL_VIRUS : CL_CLEAN); /* the original code wouldn't seek back here */
    base += 4;
    if(cli_debug_flag && s<sizeof(b) / 2) {
      if(!fmap_need_ptr_once(map, base, s*2))
	return (det ? CL_VIRUS : CL_CLEAN);
      memcpy(b, base, s*2);
      LAME_decrypt(b,s*2,s+0xf479);
      b[s*2]='\0'; b[s*2+1]='\0';
      u2a(b,s*2);
      cli_dbgmsg("autoit: original filename '%s'\n", b);
    }
    base += s*2;

    if(!fmap_need_ptr_once(map, base, 13))
      return (det ? CL_VIRUS : CL_CLEAN);
    comp = *base;
    UNP.csize = cli_readint32(base+1) ^ 0x87bc;
    if ((int32_t)UNP.csize<0) {
      cli_dbgmsg("autoit: bad file size - giving up\n");
      return (det ? CL_VIRUS : CL_CLEAN);
    }

    if(!UNP.csize) {
      cli_dbgmsg("autoit: skipping empty file\n");
      base += 13 + 16;
      continue;
    }
    cli_dbgmsg("autoit: compressed size: %x\n", UNP.csize);
    cli_dbgmsg("autoit: advertised uncompressed size %x\n", cli_readint32(base+5) ^ 0x87bc);
    cli_dbgmsg("autoit: ref chksum: %x\n", cli_readint32(base+9) ^ 0xa685);

    base += 13 + 16;

    if(cli_checklimits("autoit", ctx, UNP.csize, 0, 0)!=CL_CLEAN) {
      base += UNP.csize;
      continue;
    }

    if (comp == 1 && UNP.csize < sizeof(union unaligned_32)) {
      cli_dbgmsg("autoit: compressed size too small, skipping\n");
      continue;
    }

    files++;
    if (!(UNP.inputbuf = cli_malloc(UNP.csize)))
      return CL_EMEM;
    if (!fmap_need_ptr_once(map, base, UNP.csize)) {
      cli_dbgmsg("autoit: failed to read compressed stream. broken/truncated file?\n");
      free(UNP.inputbuf);
      return (det ? CL_VIRUS : CL_CLEAN);
    }
    memcpy(UNP.inputbuf, base, UNP.csize);
    base += UNP.csize;
    LAME_decrypt(UNP.inputbuf,UNP.csize,0x2477 /* + m4sum (broken by design) */ );

    if (comp == 1) {
      cli_dbgmsg("autoit: file is compressed\n");
      if (cli_readint32(UNP.inputbuf)!=0x36304145) {
          cli_dbgmsg("autoit: bad magic or unsupported version\n");
          free(UNP.inputbuf);
          continue;
      }

      if(!(UNP.usize = be32_to_host(*(uint32_t *)(UNP.inputbuf+4))))
	UNP.usize = UNP.csize; /* only a specifically crafted or badly corrupted sample should land here */
      if(cli_checklimits("autoit", ctx, UNP.usize, 0, 0)!=CL_CLEAN) {
	free(UNP.inputbuf);
	continue;
      }
      if (!(UNP.outputbuf = cli_malloc(UNP.usize))) {
	free(UNP.inputbuf);
	return CL_EMEM;
      }
      cli_dbgmsg("autoit: uncompressed size again: %x\n", UNP.usize);

      UNP.cur_output = 0;
      UNP.cur_input = 8;
      UNP.bitmap.full = 0;
      UNP.bits_avail = 0;
      UNP.error = 0;

      while (!UNP.error && UNP.cur_output < UNP.usize) {
	if (!getbits(&UNP, 1)) {
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

      free(UNP.inputbuf);
      if (UNP.error) {
	cli_dbgmsg("autoit: decompression error after %u bytes - partial file may exist\n", UNP.cur_output);
	UNP.usize = UNP.cur_output;
      }
    } else {
      cli_dbgmsg("autoit: file is not compressed\n");
      UNP.outputbuf = UNP.inputbuf;
      UNP.usize = UNP.csize;
    }

    if (UNP.usize<4) {
      cli_dbgmsg("autoit: file is too short\n");
      free(UNP.outputbuf);
      continue;
    }

    if (script) {
      UNP.csize = UNP.usize;
      if (!(buf = cli_malloc(UNP.csize))) {
	free(UNP.outputbuf);
	return CL_EMEM;
      }
      UNP.cur_output = 0;
      UNP.cur_input = 4;
      UNP.bits_avail = cli_readint32((char *)UNP.outputbuf);
      UNP.error = 0;
      cli_dbgmsg("autoit: script has got %u lines\n", UNP.bits_avail);

      while (!UNP.error && UNP.bits_avail && UNP.cur_input < UNP.usize) {
	uint8_t op;

	switch((op = UNP.outputbuf[UNP.cur_input++])) {
	case 5: /* <INT> */
	  if (UNP.cur_input >= UNP.usize-4) {
	    UNP.error = 1;
	    cli_dbgmsg("autoit: not enough space for an int\n");
	    break;
	  }
	  if (UNP.cur_output+12 >= UNP.csize) {
	    uint8_t *newout;
	    UNP.csize += 512;
	    if (!(newout = cli_realloc(buf, UNP.csize))) {
	      UNP.error = 1;
	      break;
	    }
	    buf = newout;
	  }
	  snprintf((char *)&buf[UNP.cur_output], 12, "0x%08x ", cli_readint32((char *)&UNP.outputbuf[UNP.cur_input]));
	  UNP.cur_output += 11;
	  UNP.cur_input += 4;
	  break;

	case 0x10: /* <INT64> */
	  {
	    uint64_t val;
	    if (UNP.usize < 8 || UNP.cur_input >= UNP.usize-8) {
	      UNP.error = 1;
	      cli_dbgmsg("autoit: not enough space for an int64\n");
	      break;
	    }
	    if (UNP.cur_output+20 >= UNP.csize) {
	      uint8_t *newout;
	      UNP.csize += 512;
	      if (!(newout = cli_realloc(buf, UNP.csize))) {
	      UNP.error = 1;
	      break;
	      }
	      buf = newout;
	    }
	    val = (uint64_t)cli_readint32((char *)&UNP.outputbuf[UNP.cur_input+4]);
	    val <<=32;
	    val += (uint64_t)cli_readint32((char *)&UNP.outputbuf[UNP.cur_input]);
	    snprintf((char *)&buf[UNP.cur_output], 20, "0x%016lx ", (unsigned long int) val);
	    UNP.cur_output += 19;
	    UNP.cur_input += 8;
	    break;
	  }

	case 0x20: /* <DOUBLE> */
	  if (UNP.usize < 8 || UNP.cur_input >= UNP.usize-8) {
	    UNP.error = 1;
	    cli_dbgmsg("autoit: not enough space for a double\n");
	    break;
	  }
	  if (UNP.cur_output+40 >= UNP.csize) {
	    uint8_t *newout;
	    UNP.csize += 512;
	    if (!(newout = cli_realloc(buf, UNP.csize))) {
	      UNP.error = 1;
	      break;
	    }
	    buf = newout;
	  }
          if (fpu_words == FPU_ENDIAN_LITTLE)
              snprintf((char *)&buf[UNP.cur_output], 39, "%g ", *(double *)&UNP.outputbuf[UNP.cur_input]);
          else
              do {
                  double x;
                  uint8_t *j = (uint8_t *)&x;
                  unsigned int i;
                  
                  for(i=0; i<8; i++)
                      j[7-i]=UNP.outputbuf[UNP.cur_input+i];
                  snprintf((char *)&buf[UNP.cur_output], 39, "%g ", x); /* FIXME: check */
              } while(0);
	  buf[UNP.cur_output+38]=' ';
	  buf[UNP.cur_output+39]='\0';
	  UNP.cur_output += strlen((char *)&buf[UNP.cur_output]);
	  UNP.cur_input += 8;
	  break;

	case 0x30: /* COSTRUCT */
	case 0x31: /* COMMAND */
	case 0x32: /* MACRO */
	case 0x33: /* VAR */
	case 0x34: /* FUNC */
	case 0x35: /* OBJECT */
	case 0x36: /* STRING */
	case 0x37: /* DIRECTIVE */
	  {
	    uint32_t chars, dchars, i;

	    if (UNP.cur_input >= UNP.usize-4) {
	      UNP.error = 1;
	      cli_dbgmsg("autoit: not enough space for size\n");
	      break;
	    }
	    chars = cli_readint32((char *)&UNP.outputbuf[UNP.cur_input]);
	    dchars = chars*2;
	    UNP.cur_input+=4;

	    if (UNP.usize < dchars || UNP.cur_input >= UNP.usize-dchars) {
	      UNP.error = 1;
	      cli_dbgmsg("autoit: size too big - needed %d, total %d, avail %d\n", dchars, UNP.usize, UNP.usize - UNP.cur_input);
	      break;
	    }
	    if (UNP.cur_output+chars+3 >= UNP.csize) {
	      uint8_t *newout;
	      UNP.csize += chars + 512;
	      if (!(newout = cli_realloc(buf, UNP.csize))) {
		UNP.error = 1;
		break;
	      }
	      buf = newout;
	    }

	    if(prefixes[op-0x30])
	      buf[UNP.cur_output++] = prefixes[op-0x30];

	    if (chars) {
	      for (i = 0; i<dchars; i+=2) {
		UNP.outputbuf[UNP.cur_input+i] ^= (uint8_t)chars;
		UNP.outputbuf[UNP.cur_input+i+1] ^= (uint8_t)(chars>>8);
	      }
	      u2a(&UNP.outputbuf[UNP.cur_input], dchars);
	      memcpy(&buf[UNP.cur_output], &UNP.outputbuf[UNP.cur_input], chars);
	      UNP.cur_output += chars;
	      UNP.cur_input += dchars;
	    }
	    if (op==0x36)
	      buf[UNP.cur_output++] = '"';
	    if (op!=0x34)
	      buf[UNP.cur_output++] = ' ';
	  }
	  break;

	case 0x40: /* , */
	case 0x41: /* = */
	case 0x42: /* > */
	case 0x43: /* < */
	case 0x44: /* <> */
	case 0x45: /* >= */
	case 0x46: /* <= */
	case 0x47: /* ( */
	case 0x48: /* ) */
	case 0x49: /* + */
	case 0x4a: /* - */
	case 0x4b: /* / */
	case 0x4c: /* * */
	case 0x4d: /* & */
	case 0x4e: /* [ */
	case 0x4f: /* ] */
	case 0x50: /* == */
	case 0x51: /* ^ */
	case 0x52: /* += */
	case 0x53: /* -= */
	case 0x54: /* /= */
	case 0x55: /* *= */
	case 0x56: /* &= */
	  if (UNP.cur_output+4 >= UNP.csize) {
	    uint8_t *newout;
	    UNP.csize += 512;
	    if (!(newout = cli_realloc(buf, UNP.csize))) {
	      UNP.error = 1;
	      break;
	    }
	    buf = newout;
	  }
	  UNP.cur_output += snprintf((char *)&buf[UNP.cur_output], 4, "%s ", opers[op-0x40]);
	  break;

	case 0x7f:
	  UNP.bits_avail--;
	  if (UNP.cur_output+1 >= UNP.csize) {
	    uint8_t *newout;
	    UNP.csize += 512;
	    if (!(newout = cli_realloc(buf, UNP.csize))) {
	      UNP.error = 1;
	      break;
	    }
	    buf = newout;
	  }
	  buf[UNP.cur_output++]='\n';
	  break;

	default:
	  cli_dbgmsg("autoit: found unknown op (%x)\n", op);
	  UNP.error = 1;
	}
      }

      if (UNP.error)
	cli_dbgmsg("autoit: decompilation aborted - partial script may exist\n");

      free(UNP.outputbuf);
    } else {
      buf = UNP.outputbuf;
      UNP.cur_output = UNP.usize ;
    }

    snprintf(tempfile, 1023, "%s"PATHSEP"autoit.%.3u", tmpd, files);
    tempfile[1023]='\0';
    if((i = open(tempfile, O_RDWR|O_CREAT|O_TRUNC|O_BINARY, S_IRWXU)) < 0) {
      cli_dbgmsg("autoit: Can't create file %s\n", tempfile);
      free(buf);
      return CL_ECREAT;
    }
    if(cli_writen(i, buf, UNP.cur_output) != (int32_t)UNP.cur_output) {
      cli_dbgmsg("autoit: cannot write %d bytes\n", UNP.usize);
      close(i);
      free(buf);
      return CL_EWRITE;
    }
    free(buf);
    if(ctx->engine->keeptmp)
      cli_dbgmsg("autoit: %s extracted to %s\n", (script)?"script":"file", tempfile);
    else 
      cli_dbgmsg("autoit: %s successfully extracted\n", (script)?"script":"file");
    if (lseek(i, 0, SEEK_SET) == -1) {
        cli_dbgmsg("autoit: call to lseek() has failed\n");
        close(i);
        return CL_ESEEK;
    }
    if(cli_magic_scandesc(i, tempfile, ctx) == CL_VIRUS) {
      if (!SCAN_ALLMATCHES) {
	close(i);
	if(!ctx->engine->keeptmp)
	  if (cli_unlink(tempfile)) return CL_EUNLINK;
	return CL_VIRUS;
      }
      det = 1;
    }
    close(i);
    if(!ctx->engine->keeptmp)
      if (cli_unlink(tempfile)) return CL_EUNLINK;
  }
  return (det ? CL_VIRUS : ret);
}

/*********************
   autoit3 wrapper 
*********************/

int cli_scanautoit(cli_ctx *ctx, off_t offset) {
  const uint8_t *version;
  int r;
  char *tmpd;
  fmap_t *map = *ctx->fmap;

  cli_dbgmsg("in scanautoit()\n");

  if(!(version = fmap_need_off_once(map, offset, sizeof(*version))))
    return CL_EREAD;

  if (!(tmpd = cli_gentemp(ctx->engine->tmpdir)))    
    return CL_ETMPDIR;
  if (mkdir(tmpd, 0700)) {
    cli_dbgmsg("autoit: Can't create temporary directory %s\n", tmpd);
    free(tmpd);
    return CL_ETMPDIR;
  }
  if (ctx->engine->keeptmp)
    cli_dbgmsg("autoit: Extracting files to %s\n", tmpd);

  switch(*version) {
  case 0x35:
    r = ea05(ctx, version + 1, tmpd);
    break;
  case 0x36:
      if (fpu_words == FPU_ENDIAN_INITME)
          fpu_words = get_fpu_endian();
      if (fpu_words == FPU_ENDIAN_UNKNOWN) {
          cli_dbgmsg("autoit: EA06 support not available"
                     "(cannot extract ea06 doubles, unknown floating double representation).\n");
          r = CL_CLEAN;
      }
      else
          r = ea06(ctx, version + 1, tmpd);
      break;
  default:
    /* NOT REACHED */
    cli_dbgmsg("autoit: unknown method\n");
    r = CL_CLEAN;
  }

  if (!ctx->engine->keeptmp)
    cli_rmdirs(tmpd);

  free(tmpd);
  return r;
}

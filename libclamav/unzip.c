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

/* FIXME: get a clue about masked stuff */
/* FIXME: is unz() infloop safe ? */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#if HAVE_MMAP

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#endif
#include <sys/mman.h>
#include <stdio.h>

#include <zlib.h>
#include <bzlib.h>
#include "inflate64.h"

#include "others.h"
#include "clamav.h"
#include "scanners.h"

#ifndef O_BINARY
#define O_BINARY 0
#endif

#define F_ENCR  (1<<0)
#define F_ALGO1 (1<<1)
#define F_ALGO2 (1<<2)
#define F_USEDD (1<<3)
#define F_RSVD1 (1<<4)
#define F_PATCH (1<<5)
#define F_STRNG (1<<6)
#define F_UNUS1 (1<<7)
#define F_UNUS2 (1<<8)
#define F_UNUS3 (1<<9)
#define F_UNUS4 (1<<10)
#define F_UTF8  (1<<11)
#define F_RSVD2 (1<<12)
#define F_MSKED (1<<13)
#define F_RSVD3 (1<<14)
#define F_RSVD4 (1<<15)

enum ALGO {
  ALG_STORED,
  ALG_SHRUNK,
  ALG_REDUCE1,
  ALG_REDUCE2,
  ALG_REDUCE3,
  ALG_REDUCE4,
  ALG_IMPLODE,
  ALG_TOKENZD,
  ALG_DEFLATE,
  ALG_DEFLATE64,
  ALG_OLDTERSE,
  ALG_RSVD1,
  ALG_BZIP2,
  ALG_RSVD2,
  ALG_LZMA,
  ALG_RSVD3,
  ALG_RSVD4,
  ALG_RSVD5,
  ALG_NEWTERSE,
  ALG_LZ77,
  ALG_WAVPACK = 97,
  ALG_PPMD
};


/* struct LH { */
/*   uint32_t magic; */
/*   uint16_t version; */
/*   uint16_t flags; */
/*   uint16_t method; */
/*   uint32_t mtime; */
/*   uint32_t crc32; */
/*   uint32_t csize; */
/*   uint32_t usize; */
/*   uint16_t flen; */
/*   uint16_t elen; */
/*   char fname[flen] */
/*   char extra[elen] */
/* } __attribute__((packed)); */

#define LH_magic	((uint32_t)cli_readint32((uint8_t *)(lh)+0))
#define LH_version	((uint16_t)cli_readint16((uint8_t *)(lh)+4))
#define LH_flags	((uint16_t)cli_readint16((uint8_t *)(lh)+6))
#define LH_method	((uint16_t)cli_readint16((uint8_t *)(lh)+8))
#define LH_mtime	((uint32_t)cli_readint32((uint8_t *)(lh)+10))
#define LH_crc32	((uint32_t)cli_readint32((uint8_t *)(lh)+14))
#define LH_csize	((uint32_t)cli_readint32((uint8_t *)(lh)+18))
#define LH_usize	((uint32_t)cli_readint32((uint8_t *)(lh)+22))
#define LH_flen 	((uint16_t)cli_readint16((uint8_t *)(lh)+26))
#define LH_elen 	((uint16_t)cli_readint16((uint8_t *)(lh)+28))
#define SIZEOF_LH 30

/* struct CH { */
/*   uint32_t magic; */
/*   uint16_t vermade; */
/*   uint16_t verneed; */
/*   uint16_t flags; */
/*   uint16_t method; */
/*   uint32_t mtime; */
/*   uint32_t crc32; */
/*   uint32_t csize; */
/*   uint32_t usize; */
/*   uint16_t flen; */
/*   uint16_t elen; */
/*   uint16_t clen; */
/*   uint16_t dsk; */
/*   uint16_t iattrib; */
/*   uint32_t eattrib; */
/*   uint32_t off; */
/*   char fname[flen] */
/*   char extra[elen] */
/*   char comment[clen] */
/* } __attribute__((packed)); */

#define CH_magic	((uint32_t)cli_readint32((uint8_t *)(ch)+0))
#define CH_vermade	((uint16_t)cli_readint16((uint8_t *)(ch)+4))
#define CH_verneed	((uint16_t)cli_readint16((uint8_t *)(ch)+6))
#define CH_flags	((uint16_t)cli_readint16((uint8_t *)(ch)+8))
#define CH_method	((uint16_t)cli_readint16((uint8_t *)(ch)+10))
#define CH_mtime	((uint32_t)cli_readint32((uint8_t *)(ch)+12))
#define CH_crc32	((uint32_t)cli_readint32((uint8_t *)(ch)+16))
#define CH_csize	((uint32_t)cli_readint32((uint8_t *)(ch)+20))
#define CH_usize	((uint32_t)cli_readint32((uint8_t *)(ch)+24))
#define CH_flen 	((uint16_t)cli_readint16((uint8_t *)(ch)+28))
#define CH_elen 	((uint16_t)cli_readint16((uint8_t *)(ch)+30))
#define CH_clen 	((uint16_t)cli_readint16((uint8_t *)(ch)+32))
#define CH_dsk  	((uint16_t)cli_readint16((uint8_t *)(ch)+34))
#define CH_iattrib	((uint16_t)cli_readint16((uint8_t *)(ch)+36))
#define CH_eattrib	((uint32_t)cli_readint32((uint8_t *)(ch)+38))
#define CH_off  	((uint32_t)cli_readint32((uint8_t *)(ch)+42))
#define SIZEOF_CH 46

static int wrap_inflateinit2(void *a, int b) {
  return inflateInit2(a, b);
}

static int unz(uint8_t *src, uint32_t csize, uint32_t usize, uint16_t method, unsigned int *fu, cli_ctx *ctx, char *tmpd) {
  char name[1024];
  char obuf[BUFSIZ];
  int of, ret=CL_CLEAN;
  unsigned int res=1;

  snprintf(name, sizeof(name), "%s/zip.%03u", tmpd, *fu);
  name[sizeof(name)-1]='\0';
  if((of = open(name, O_RDWR|O_CREAT|O_TRUNC|O_BINARY, S_IRUSR|S_IWUSR))==-1) {
    cli_warnmsg("cli_unzip: failed to create temporary file %s\n", name);
    return CL_EIO;
  }
  switch (method) {
  case ALG_STORED:
    if(csize<usize) {
      unsigned int fake = *fu + 1;
      cli_dbgmsg("cli_unzip: attempting to inflate stored file with inconsistent size\n");
      if ((ret=unz(src, csize, usize, ALG_DEFLATE, &fake, ctx, tmpd))==CL_CLEAN) {
	(*fu)++;
	res=fake-(*fu);
      }
      else break;
    }
    if(res==1) {
      if(cli_writen(of, src, csize)!=(int)csize) ret = CL_EIO;
      else res=0;
    }
    break;

  case ALG_DEFLATE:
  case ALG_DEFLATE64: {
    union {
      z_stream64 strm64;
      z_stream strm;
    } strm;
    typedef int (*unz_init_) (void *, int);
    typedef int (*unz_unz_) (void *, int);
    typedef int (*unz_end_) (void *);
    unz_init_ unz_init;
    unz_unz_ unz_unz;
    unz_end_ unz_end;
    int wbits;
    void **next_in;
    void **next_out;
    unsigned int *avail_in;
    unsigned int *avail_out;

    if(method == ALG_DEFLATE64) {
      unz_init = (unz_init_)inflate64Init2;
      unz_unz = (unz_unz_)inflate64;
      unz_end = (unz_end_)inflate64End;
      next_in = (void *)&strm.strm64.next_in;
      next_out = (void *)&strm.strm64.next_out;
      avail_in = &strm.strm64.avail_in;
      avail_out = &strm.strm64.avail_out;
      wbits=MAX_WBITS64;
    } else {
      unz_init = (unz_init_)wrap_inflateinit2;
      unz_unz = (unz_unz_)inflate;
      unz_end = (unz_end_)inflateEnd;
      next_in = (void *)&strm.strm.next_in;
      next_out = (void *)&strm.strm.next_out;
      avail_in = &strm.strm.avail_in;
      avail_out = &strm.strm.avail_out;
      wbits=MAX_WBITS;
    }

    memset(&strm, 0, sizeof(strm));

    *next_in = src;
    *next_out = obuf;
    *avail_in = csize;
    *avail_out = sizeof(obuf);
    if (unz_init(&strm, -wbits)!=Z_OK) {
      cli_dbgmsg("cli_unzip: zinit failed\n");
      break;
    }
    while(1) {
      while((res = unz_unz(&strm, Z_NO_FLUSH))==Z_OK) {};
      if(*avail_out!=sizeof(obuf)) {
	if(cli_writen(of, obuf, sizeof(obuf)-(*avail_out)) != (int)(sizeof(obuf)-(*avail_out))) {
	  cli_warnmsg("cli_unzip: falied to write %lu inflated bytes\n", sizeof(obuf)-(*avail_out));
	  ret = CL_EIO;
	  res=1;
	}
	*next_out = obuf;
	*avail_out = sizeof(obuf);
	continue;
      }
      break;
    }
    unz_end(&strm);
    if (res == Z_STREAM_END) res=0;
    break;
  }

  case ALG_BZIP2: {
    bz_stream strm;
    memset(&strm, 0, sizeof(strm));
    strm.next_in = (char *)src;
    strm.next_out = obuf;
    strm.avail_in = csize;
    strm.avail_out = sizeof(obuf);
    if (BZ2_bzDecompressInit(&strm, 0, 0)!=BZ_OK) {
      cli_dbgmsg("cli_unzip: bzinit failed\n");
      break;
    }
    while((res = BZ2_bzDecompress(&strm))==BZ_OK || res==BZ_STREAM_END) {
      if(strm.avail_out!=sizeof(obuf)) {
	if(cli_writen(of, obuf, sizeof(obuf)-strm.avail_out) != (int)(sizeof(obuf)-strm.avail_out)) {
	  cli_warnmsg("cli_unzip: falied to write %lu bunzipped bytes\n", sizeof(obuf)-strm.avail_out);
	  ret = CL_EIO;
	  res=1;
	}
	strm.next_out = obuf;
	strm.avail_out = sizeof(obuf);
      }
      break;
    }
    BZ2_bzDecompressEnd(&strm);
    if (res == BZ_STREAM_END) {
      res=0;
    }
    break;
  }

  case ALG_LZMA:
    /* easy but there's not a single sample in the zoo */

  case ALG_SHRUNK:
  case ALG_REDUCE1:
  case ALG_REDUCE2:
  case ALG_REDUCE3:
  case ALG_REDUCE4:
  case ALG_IMPLODE:
  case ALG_TOKENZD:
  case ALG_OLDTERSE:
  case ALG_RSVD1:
  case ALG_RSVD2:
  case ALG_RSVD3:
  case ALG_RSVD4:
  case ALG_RSVD5:
  case ALG_NEWTERSE:
  case ALG_LZ77:
  case ALG_WAVPACK:
  case ALG_PPMD:
    cli_dbgmsg("cli_unzip: unsupported method (%d)\n", method);
    break;
  default:
    cli_dbgmsg("cli_unzip: unknown method (%d)\n", method);
    break;
  }

  if(!res) {
    (*fu)++;
    cli_dbgmsg("cli_unzip: extracted to %s\n", name);
    lseek(of, 0, SEEK_SET);
    ret = cli_magic_scandesc(of, ctx);
    close(of);
    if(!cli_leavetemps_flag) unlink(name);
    return ret;
  }

  close(of);
  if(!cli_leavetemps_flag) unlink(name);
  cli_dbgmsg("cli_unzip: extraction failed\n");
  return ret;
}

static unsigned int lhdr(uint8_t *zip, uint32_t zsize, unsigned int *fu, uint8_t *ch, int *ret, cli_ctx *ctx, char *tmpd) {
  uint8_t *lh = zip;
  char name[256];
  uint32_t csize;

  if(zsize<=SIZEOF_LH) {
    cli_dbgmsg("cli_unzip: lh - out of file\n");
    return 0;
  }
  if(LH_magic != 0x04034b50) {
    if (!ch) cli_dbgmsg("cli_unzip: lh - wrkcomplete\n");
    else cli_dbgmsg("cli_unzip: lh - bad magic\n");
    return 0;
  }

  zip+=SIZEOF_LH;
  zsize-=SIZEOF_LH;

  cli_dbgmsg("cli_unzip: lh - flags %x - method %x - csize %x - usize %x - flen %x - elen %x\n", LH_flags, LH_method, LH_csize, LH_usize, LH_flen, LH_elen);

  if(LH_flags & F_MSKED) {
    cli_dbgmsg("cli_unzip: lh - header has got unusable masked data\n");
    /* FIXME: need to find/craft a sample */
    return 0;
  }

  if(LH_flags & F_USEDD) {
    cli_dbgmsg("cli_unzip: lh - has data desc\n");
    if(!ch) return 0;
    else csize = CH_csize;
  } else csize = LH_csize;

  if(zsize<=LH_flen) {
    cli_dbgmsg("cli_unzip: lh - fname out of file\n");
    return 0;
  }
  if(cli_debug_flag) {
    uint32_t nsize = (LH_flen>=sizeof(name))?sizeof(name)-1:LH_flen;
    memcpy(name, zip, nsize);
    name[nsize]='\0';
    cli_dbgmsg("cli_unzip: lh - fname: %s\n", name);
  }
  zip+=LH_flen;
  zsize-=LH_flen;

  if(zsize<=LH_elen) {
    cli_dbgmsg("cli_unzip: lh - extra out of file\n");
    return 0;
  }
  zip+=LH_elen;
  zsize-=LH_elen;

  if (!csize) { /* FIXME: what's used for method0 files? csize or usize? Nothing in the specs, needs testing */
    cli_dbgmsg("cli_unzip: lh - skipping empty file\n");
  } else {
    if(zsize<csize) {
      cli_dbgmsg("cli_unzip: lh - stream out of file\n");
      return 0;
    } 
    if(LH_flags & F_ENCR) {
      cli_dbgmsg("cli_unzip: lh - skipping encrypted file\n");
    } else {
      *ret = unz(zip, csize, LH_usize, LH_method, fu, ctx, tmpd);
    }
    zip+=csize;
    zsize-=csize;
  }

  if(LH_flags & F_USEDD) {
    if(zsize<20) {
      cli_dbgmsg("cli_unzip: lh - data desc out of file\n");
      return 0;
    }
    zsize-=20;
    if(cli_readint32(zip)==0x08074b50) {
      if(zsize<4) {
	cli_dbgmsg("cli_unzip: lh - data desc out of file\n");
	return 0;
      }
      zip+=4;
    }
    zip+=12;
  }
  return zip-lh;
}


static unsigned int chdr(uint8_t *zip, uint32_t coff, uint32_t zsize, unsigned int *fu, int *ret, cli_ctx *ctx, char *tmpd) {
  uint8_t *ch = &zip[coff];
  char name[256];
  int last = 0;

  if(zsize-coff<=SIZEOF_CH || CH_magic != 0x02014b50) {
    cli_dbgmsg("cli_unzip: ch - wrkcomplete\n");
    return 0;
  }
  coff+=SIZEOF_CH;

  cli_dbgmsg("cli_unzip: ch - flags %x - method %x - csize %x - usize %x - flen %x - elen %x - clen %x - disk %x - off %x\n", CH_flags, CH_method, CH_csize, CH_usize, CH_flen, CH_elen, CH_clen, CH_dsk, CH_off);

  if(zsize-coff<=CH_flen) {
    cli_dbgmsg("cli_unzip: ch - fname out of file\n");
    last=1;
  }
  if(cli_debug_flag && !last) {
    unsigned int size = (CH_flen>=sizeof(name))?sizeof(name)-1:CH_flen;
    memcpy(name, &zip[coff], size);
    name[size]='\0';
    cli_dbgmsg("cli_unzip: ch - fname: %s\n", name);
  }
  coff+=CH_flen;

  if(zsize-coff<=CH_elen && !last) {
    cli_dbgmsg("cli_unzip: ch - extra out of file\n");
    last=1;
  }
  coff+=CH_elen;

  if(zsize-coff<CH_clen && !last) {
    cli_dbgmsg("cli_unzip: ch - comment out of file\n");
    last = 1;
  }
  coff+=CH_clen;

  if(CH_off<zsize-SIZEOF_LH) {
    lhdr(&zip[CH_off], zsize-CH_off, fu, ch, ret, ctx, tmpd);
  } else cli_dbgmsg("cli_unzip: ch - local hdr out of file\n");
  return last?0:coff;
}


int cli_unzip(int f, cli_ctx *ctx, off_t zoffl) {
  unsigned int fc=0, fu=0;
  int ret=CL_CLEAN;
  uint32_t fsize, zoff = (uint32_t)zoffl, coff = (uint32_t)zoffl;
  struct stat st;
  uint8_t *map;
  char *tmpd;

  cli_dbgmsg("in cli_unzip\n");
  fstat(f, &st);
  fsize = (uint32_t)st.st_size;
  if(sizeof(off_t)!=sizeof(uint32_t) && ((off_t)zoff!=zoffl || (off_t)fsize!=st.st_size)) {
    cli_dbgmsg("cli_unzip: file too big\n");
    return CL_CLEAN;
  }
  if (zoff>=fsize || fsize-zoff < SIZEOF_CH) {
    cli_dbgmsg("cli_unzip: file too short\n");
    return CL_CLEAN;
  }
  if ((map = mmap(NULL, fsize, PROT_READ, MAP_PRIVATE, f, 0))==MAP_FAILED) {
    cli_dbgmsg("cli_unzip: mmap failed\n");
    return CL_EMEM;
  }

  if (!(tmpd = cli_gentemp(NULL)))    
    return CL_ETMPDIR;
  if (mkdir(tmpd, 0700)) {
    cli_dbgmsg("cli_unzip: Can't create temporary directory %s\n", tmpd);
    free(tmpd);
    return CL_ETMPDIR;
  }

  for(coff=fsize-22 ; coff>zoff ; coff--) { /* sizeof(EOC)==22 */
    if(cli_readint32(&map[coff])==0x06054b50) {
      uint32_t chptr = cli_readint32(&map[coff+16]);
      if(!CLI_ISCONTAINED(map+zoff, fsize-zoff, map+chptr+zoff, SIZEOF_CH)) continue;
      coff=chptr+zoff;
      break;
    }
  }

  if(coff!=zoff) {
    cli_dbgmsg("cli_unzip: central @%x\n", coff);
    /* FIXME: fu vs maxfiles */
    while(ret==CL_CLEAN && coff<fsize && (coff=chdr(&map[zoff], coff-zoff, fsize-zoff, &fu, &ret, ctx, tmpd))) {
      fc++;
      coff+=zoff;
    }
  } else cli_dbgmsg("cli_unzip: central not found, using localhdrs\n");
  if(fu<(fc/4)) { /* FIXME: make up a sane ratio or remove the whole logic */
    /* FIXME: fu vs maxfiles */
    while (ret==CL_CLEAN && zoff<fsize && (coff=lhdr(&map[zoff], fsize-zoff, &fu, NULL, &ret, ctx, tmpd))) {
      fc++;
      zoff+=coff;
    }
  }

  munmap(map, fsize);
  if (!cli_leavetemps_flag) cli_rmdirs(tmpd);
  free(tmpd);

  return ret;
}

#else /* HAVE_MMAP */

#include "others.h"
#include "clamav.h"
int cli_unzip(int f, cli_ctx *ctx, off_t zoffl) {
  cli_warnmsg("cli_unzip: unzip support not compiled in\n");
  return CL_CLEAN;
}

#endif /* HAVE_MMAP */

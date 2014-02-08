/*
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

/* FIXME: get a clue about masked stuff */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#endif
#include <stdlib.h>
#include <stdio.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include "libclamav/crypto.h"

#include <zlib.h>
#include "inflate64.h"
#if HAVE_BZLIB_H
#include <bzlib.h>
#endif

#include "explode.h"
#include "others.h"
#include "clamav.h"
#include "scanners.h"
#include "matcher.h"
#include "fmap.h"

#define UNZIP_PRIVATE
#include "unzip.h"

static int wrap_inflateinit2(void *a, int b) {
  return inflateInit2(a, b);
}

static int unz(const uint8_t *src, uint32_t csize, uint32_t usize, uint16_t method, uint16_t flags, unsigned int *fu, cli_ctx *ctx, char *tmpd) {
  char name[1024], obuf[BUFSIZ];
  char *tempfile = name;
  int of, ret=CL_CLEAN;
  unsigned int res=1, written=0;

  if(tmpd) {
    snprintf(name, sizeof(name), "%s"PATHSEP"zip.%03u", tmpd, *fu);
    name[sizeof(name)-1]='\0';
  } else {
    if(!(tempfile = cli_gentemp(ctx->engine->tmpdir))) return CL_EMEM;
  }
  if((of = open(tempfile, O_RDWR|O_CREAT|O_TRUNC|O_BINARY, S_IRUSR|S_IWUSR))==-1) {
    cli_warnmsg("cli_unzip: failed to create temporary file %s\n", tempfile);
    if(!tmpd) free(tempfile);
    return CL_ECREAT;
  }
  switch (method) {
  case ALG_STORED:
    if(csize<usize) {
      unsigned int fake = *fu + 1;
      cli_dbgmsg("cli_unzip: attempting to inflate stored file with inconsistent size\n");
      if ((ret=unz(src, csize, usize, ALG_DEFLATE, 0, &fake, ctx, tmpd))==CL_CLEAN) {
	(*fu)++;
	res=fake-(*fu);
      }
      else break;
    }
    if(res==1) {
      if(ctx->engine->maxfilesize && csize > ctx->engine->maxfilesize) {
	cli_dbgmsg("cli_unzip: trimming output size to maxfilesize (%lu)\n", (long unsigned int) ctx->engine->maxfilesize);
	csize = ctx->engine->maxfilesize;
      }
      if(cli_writen(of, src, csize)!=(int)csize) ret = CL_EWRITE;
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

    *next_in = (void*) src;
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
	written+=sizeof(obuf)-(*avail_out);
	if(ctx->engine->maxfilesize && written > ctx->engine->maxfilesize) {
	  cli_dbgmsg("cli_unzip: trimming output size to maxfilesize (%lu)\n", (long unsigned int) ctx->engine->maxfilesize);
	  res = Z_STREAM_END;
	  break;
	}
	if(cli_writen(of, obuf, sizeof(obuf)-(*avail_out)) != (int)(sizeof(obuf)-(*avail_out))) {
	  cli_warnmsg("cli_unzip: falied to write %lu inflated bytes\n", sizeof(obuf)-(*avail_out));
	  ret = CL_EWRITE;
	  res = 100;
	  break;
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


#if HAVE_BZLIB_H
#ifdef NOBZ2PREFIX
#define BZ2_bzDecompress bzDecompress
#define BZ2_bzDecompressEnd bzDecompressEnd
#define BZ2_bzDecompressInit bzDecompressInit
#endif

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
	written+=sizeof(obuf)-strm.avail_out;
	if(ctx->engine->maxfilesize && written > ctx->engine->maxfilesize) {
	  cli_dbgmsg("cli_unzip: trimming output size to maxfilesize (%lu)\n", (unsigned long int) ctx->engine->maxfilesize);
	  res = BZ_STREAM_END;
	  break;
	}
	if(cli_writen(of, obuf, sizeof(obuf)-strm.avail_out) != (int)(sizeof(obuf)-strm.avail_out)) {
	  cli_warnmsg("cli_unzip: falied to write %lu bunzipped bytes\n", sizeof(obuf)-strm.avail_out);
	  ret = CL_EWRITE;
	  res = 100;
	  break;
	}
	strm.next_out = obuf;
	strm.avail_out = sizeof(obuf);
	if (res == BZ_OK) continue; /* after returning BZ_STREAM_END once, decompress returns an error */
      }
      break;
    }
    BZ2_bzDecompressEnd(&strm);
    if (res == BZ_STREAM_END) res=0;
    break;
  }
#endif /* HAVE_BZLIB_H */


  case ALG_IMPLODE: {
    struct xplstate strm;
    strm.next_in = (void*)src;
    strm.next_out = (uint8_t *)obuf;
    strm.avail_in = csize;
    strm.avail_out = sizeof(obuf);
    if (explode_init(&strm, flags)!=EXPLODE_OK) {
      cli_dbgmsg("cli_unzip: explode_init() failed\n");
      break;
    }
    while((res = explode(&strm))==EXPLODE_OK) {
      if(strm.avail_out!=sizeof(obuf)) {
	written+=sizeof(obuf)-strm.avail_out;
	if(ctx->engine->maxfilesize && written > ctx->engine->maxfilesize) {
	  cli_dbgmsg("cli_unzip: trimming output size to maxfilesize (%lu)\n", (unsigned long int) ctx->engine->maxfilesize);
	  res = 0;
	  break;
	}
	if(cli_writen(of, obuf, sizeof(obuf)-strm.avail_out) != (int)(sizeof(obuf)-strm.avail_out)) {
	  cli_warnmsg("cli_unzip: falied to write %lu exploded bytes\n", sizeof(obuf)-strm.avail_out);
	  ret = CL_EWRITE;
	  res = 100;
	  break;
	}
	strm.next_out = (uint8_t *)obuf;
	strm.avail_out = sizeof(obuf);
	continue;
      }
      break;
    }
    break;
  }


  case ALG_LZMA:
    /* easy but there's not a single sample in the zoo */

#if !HAVE_BZLIB_H
  case ALG_BZIP2:
#endif
  case ALG_SHRUNK:
  case ALG_REDUCE1:
  case ALG_REDUCE2:
  case ALG_REDUCE3:
  case ALG_REDUCE4:
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
    cli_dbgmsg("cli_unzip: extracted to %s\n", tempfile);
    if (lseek(of, 0, SEEK_SET) == -1) {
        cli_dbgmsg("cli_unzip: call to lseek() failed\n");
        if (!(tmpd))
            free(tempfile);
        close(of);
        return CL_ESEEK;
    }
    ret = cli_magic_scandesc(of, ctx);
    close(of);
    if(!ctx->engine->keeptmp)
      if(cli_unlink(tempfile)) ret = CL_EUNLINK;
    if(!tmpd) free(tempfile);
    return ret;
  }

  close(of);
  if(!ctx->engine->keeptmp)
    if(cli_unlink(tempfile)) ret = CL_EUNLINK;
  if(!tmpd) free(tempfile);
  cli_dbgmsg("cli_unzip: extraction failed\n");
  return ret;
}

static unsigned int lhdr(fmap_t *map, uint32_t loff,uint32_t zsize, unsigned int *fu, unsigned int fc, const uint8_t *ch, int *ret, cli_ctx *ctx, char *tmpd, int detect_encrypted) {
  const uint8_t *lh, *zip;
  char name[256];
  uint32_t csize, usize;

  if(!(lh = fmap_need_off(map, loff, SIZEOF_LH))) {
      cli_dbgmsg("cli_unzip: lh - out of file\n");
      return 0;
  }
  if(LH_magic != 0x04034b50) {
    if (!ch) cli_dbgmsg("cli_unzip: lh - wrkcomplete\n");
    else cli_dbgmsg("cli_unzip: lh - bad magic\n");
    fmap_unneed_off(map, loff, SIZEOF_LH);
    return 0;
  }

  zip = lh + SIZEOF_LH;
  zsize-=SIZEOF_LH;

  if(zsize<=LH_flen) {
    cli_dbgmsg("cli_unzip: lh - fname out of file\n");
    fmap_unneed_off(map, loff, SIZEOF_LH);
    return 0;
  }
  if(ctx->engine->cdb || cli_debug_flag) {
      uint32_t nsize = (LH_flen>=sizeof(name))?sizeof(name)-1:LH_flen;
      const char *src;
      if(nsize && (src = fmap_need_ptr_once(map, zip, nsize))) {
	  memcpy(name, zip, nsize);
	  name[nsize]='\0';
      } else
	  name[0] = '\0';
  }
  zip+=LH_flen;
  zsize-=LH_flen;

  cli_dbgmsg("cli_unzip: lh - ZMDNAME:%d:%s:%u:%u:%x:%u:%u:%u\n", ((LH_flags & F_ENCR)!=0), name, LH_usize, LH_csize, LH_crc32, LH_method, fc, ctx->recursion);
  /* ZMDfmt virname:encrypted(0-1):filename(exact|*):usize(exact|*):csize(exact|*):crc32(exact|*):method(exact|*):fileno(exact|*):maxdepth(exact|*) */

  if(cli_matchmeta(ctx, name, LH_csize, LH_usize, (LH_flags & F_ENCR)!=0, fc, LH_crc32, NULL) == CL_VIRUS) {
    *ret = CL_VIRUS;
    return 0;
  }

  if(LH_flags & F_MSKED) {
    cli_dbgmsg("cli_unzip: lh - header has got unusable masked data\n");
    /* FIXME: need to find/craft a sample */
    fmap_unneed_off(map, loff, SIZEOF_LH);
    return 0;
  }

  if(detect_encrypted && (LH_flags & F_ENCR) && DETECT_ENCRYPTED) {
    cli_dbgmsg("cli_unzip: Encrypted files found in archive.\n");
    cli_append_virus(ctx, "Heuristics.Encrypted.Zip");
    *ret = CL_VIRUS;
    fmap_unneed_off(map, loff, SIZEOF_LH);
    return 0;
  }
 
  if(LH_flags & F_USEDD) {
    cli_dbgmsg("cli_unzip: lh - has data desc\n");
    if(!ch) {
	fmap_unneed_off(map, loff, SIZEOF_LH);
	return 0;
    }
    else { usize = CH_usize; csize = CH_csize; }
  } else { usize = LH_usize; csize = LH_csize; }

  if(zsize<=LH_elen) {
    cli_dbgmsg("cli_unzip: lh - extra out of file\n");
    fmap_unneed_off(map, loff, SIZEOF_LH);
    return 0;
  }
  zip+=LH_elen;
  zsize-=LH_elen;

  if (!csize) { /* FIXME: what's used for method0 files? csize or usize? Nothing in the specs, needs testing */
      cli_dbgmsg("cli_unzip: lh - skipping empty file\n");
  } else {
      if(zsize<csize) {
	  cli_dbgmsg("cli_unzip: lh - stream out of file\n");
	  fmap_unneed_off(map, loff, SIZEOF_LH);
	  return 0;
      }
      if(LH_flags & F_ENCR) {
	  cli_dbgmsg("cli_unzip: lh - skipping encrypted file\n");
      } else {
	  if(fmap_need_ptr_once(map, zip, csize))
	      *ret = unz(zip, csize, usize, LH_method, LH_flags, fu, ctx, tmpd);
      }
      zip+=csize;
      zsize-=csize;
  }

  fmap_unneed_off(map, loff, SIZEOF_LH); /* unneed now. block is guaranteed to exists till the next need */
  if(LH_flags & F_USEDD) {
      if(zsize<12) {
	  cli_dbgmsg("cli_unzip: lh - data desc out of file\n");
	  return 0;
      }
      zsize-=12;
      if(fmap_need_ptr_once(map, zip, 4)) {
	  if(cli_readint32(zip)==0x08074b50) {
	      if(zsize<4) {
		  cli_dbgmsg("cli_unzip: lh - data desc out of file\n");
		  return 0;
	      }
	      zip+=4;
	  }
      }
      zip+=12;
  }
  return zip-lh;
}


static unsigned int chdr(fmap_t *map, uint32_t coff, uint32_t zsize, unsigned int *fu, unsigned int fc, int *ret, cli_ctx *ctx, char *tmpd) {
  char name[256];
  int last = 0;
  const uint8_t *ch;

  if(!(ch = fmap_need_off(map, coff, SIZEOF_CH)) || CH_magic != 0x02014b50) {
      if(ch) fmap_unneed_ptr(map, ch, SIZEOF_CH);
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
      const char *src = fmap_need_off_once(map, coff, size);
      if(src) {
	  memcpy(name, src, size);
	  name[size]='\0';
	  cli_dbgmsg("cli_unzip: ch - fname: %s\n", name);
      }
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
      lhdr(map, CH_off, zsize-CH_off, fu, fc, ch, ret, ctx, tmpd, 1);
  } else cli_dbgmsg("cli_unzip: ch - local hdr out of file\n");
  fmap_unneed_ptr(map, ch, SIZEOF_CH);
  return last?0:coff;
}


int cli_unzip(cli_ctx *ctx) {
  unsigned int fc=0, fu=0;
  int ret=CL_CLEAN;
  uint32_t fsize, lhoff = 0, coff = 0;
  fmap_t *map = *ctx->fmap;
  char *tmpd;
  const char *ptr;

  cli_dbgmsg("in cli_unzip\n");
  fsize = (uint32_t)map->len;
  if(sizeof(off_t)!=sizeof(uint32_t) && (off_t)fsize!=map->len) {
    cli_dbgmsg("cli_unzip: file too big\n");
    return CL_CLEAN;
  }
  if (fsize < SIZEOF_CH) {
    cli_dbgmsg("cli_unzip: file too short\n");
    return CL_CLEAN;
  }
  if (!(tmpd = cli_gentemp(ctx->engine->tmpdir))) {
    return CL_ETMPDIR;
  }
  if (mkdir(tmpd, 0700)) {
    cli_dbgmsg("cli_unzip: Can't create temporary directory %s\n", tmpd);
    free(tmpd);
    return CL_ETMPDIR;
  }

  for(coff=fsize-22 ; coff>0 ; coff--) { /* sizeof(EOC)==22 */
      if(!(ptr = fmap_need_off_once(map, coff, 20)))
	  continue;
      if(cli_readint32(ptr)==0x06054b50) {
	  uint32_t chptr = cli_readint32(&ptr[16]);
	  if(!CLI_ISCONTAINED(0, fsize, chptr, SIZEOF_CH)) continue;
	  coff=chptr;
	  break;
      }
  }

  if(coff) {
      cli_dbgmsg("cli_unzip: central @%x\n", coff);
      while(ret==CL_CLEAN && (coff=chdr(map, coff, fsize, &fu, fc+1, &ret, ctx, tmpd))) {
	  fc++;
	  if (ctx->engine->maxfiles && fu>=ctx->engine->maxfiles) {
	      cli_dbgmsg("cli_unzip: Files limit reached (max: %u)\n", ctx->engine->maxfiles);
	      ret=CL_EMAXFILES;
	  }
      }
  } else cli_dbgmsg("cli_unzip: central not found, using localhdrs\n");
  if(fu<=(fc/4)) { /* FIXME: make up a sane ratio or remove the whole logic */
    fc = 0;
    while (ret==CL_CLEAN && lhoff<fsize && (coff=lhdr(map, lhoff, fsize-lhoff, &fu, fc+1, NULL, &ret, ctx, tmpd, 1))) {
      fc++;
      lhoff+=coff;
      if (ctx->engine->maxfiles && fu>=ctx->engine->maxfiles) {
	cli_dbgmsg("cli_unzip: Files limit reached (max: %u)\n", ctx->engine->maxfiles);
	ret=CL_EMAXFILES;
      }
    }
  }

  if (!ctx->engine->keeptmp) cli_rmdirs(tmpd);
  free(tmpd);

  return ret;
}

int cli_unzip_single(cli_ctx *ctx, off_t lhoffl) {
  int ret=CL_CLEAN;
  unsigned int fu=0;
  uint32_t fsize;
  fmap_t *map = *ctx->fmap;

  cli_dbgmsg("in cli_unzip_single\n");
  fsize = (uint32_t)(map->len - lhoffl);
  if (lhoffl<0 || lhoffl>map->len || (sizeof(off_t)!=sizeof(uint32_t) && (off_t)fsize!=map->len - lhoffl)) {
    cli_dbgmsg("cli_unzip: bad offset\n");
    return CL_CLEAN;
  }
  if (fsize < SIZEOF_LH) {
    cli_dbgmsg("cli_unzip: file too short\n");
    return CL_CLEAN;
  }

  lhdr(map, lhoffl, fsize, &fu, 0, NULL, &ret, ctx, NULL, 0);

  return ret;
}

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
#include "json_api.h"

#define UNZIP_PRIVATE
#include "unzip.h"

#define ZIP_MAX_NUM_OVERLAPPING_FILES 5

#define ZIP_CRC32(r,c,b,l)			\
    do {					\
	r = crc32(~c,b,l);			\
	r = ~r;					\
    } while(0)


static int wrap_inflateinit2(void *a, int b) {
  return inflateInit2(a, b);
}

static int unz(const uint8_t *src, uint32_t csize, uint32_t usize, uint16_t method, uint16_t flags, unsigned int *fu, cli_ctx *ctx, char *tmpd, zip_cb zcb) {
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
    return CL_ETMPFILE;
  }
  switch (method) {
  case ALG_STORED:
    if(csize<usize) {
      unsigned int fake = *fu + 1;
      cli_dbgmsg("cli_unzip: attempting to inflate stored file with inconsistent size\n");
      if ((ret=unz(src, csize, usize, ALG_DEFLATE, 0, &fake, ctx, tmpd, zcb))==CL_CLEAN) {
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
            cli_warnmsg("cli_unzip: falied to write %lu inflated bytes\n", (unsigned long int)sizeof(obuf)-(*avail_out));
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
    if ((res == Z_STREAM_END) | (res == Z_BUF_ERROR)) res=0;
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
            cli_warnmsg("cli_unzip: falied to write %lu bunzipped bytes\n", (long unsigned int)sizeof(obuf)-strm.avail_out);
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
            cli_warnmsg("cli_unzip: falied to write %lu exploded bytes\n", (unsigned long int) sizeof(obuf)-strm.avail_out);
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
    ret = zcb(of, tempfile, ctx);
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

/* zip update keys, taken from zip specification */
static inline void zupdatekey(uint32_t key[3], unsigned char input)
{
    unsigned char tmp[1];
    unsigned long crctmp;

    tmp[0] = input;
    ZIP_CRC32(key[0], key[0], tmp, 1);

    key[1] = key[1] + (key[0] & 0xff);
    key[1] = key[1] * 134775813 + 1;

    tmp[0] = key[1] >> 24;
    ZIP_CRC32(key[2], key[2], tmp, 1);
}

/* zip init keys */
static inline void zinitkey(uint32_t key[3], struct cli_pwdb *password)
{
    int i;

    /* initialize keys, these are specified but the zip specification */
    key[0] = 305419896L;
    key[1] = 591751049L;
    key[2] = 878082192L;

    /* update keys with password  */
    for (i = 0; i < password->length; i++)
	zupdatekey(key, password->passwd[i]);
}

/* zip decrypt byte */
static inline unsigned char zdecryptbyte(uint32_t key[3])
{
    unsigned short temp;
    temp = key[2] | 2;
    return ((temp * (temp ^ 1)) >> 8);
}

/* zip decrypt, CL_EPARSE = could not apply a password, csize includes the decryption header */
/* TODO - search for strong encryption header (0x0017) and handle them */
static inline int zdecrypt(const uint8_t *src, uint32_t csize, uint32_t usize, const uint8_t *lh, unsigned int *fu, cli_ctx *ctx, char *tmpd, zip_cb zcb)
{
    int i, ret, v = 0;
    uint32_t key[3];
    uint8_t eh[12]; /* encryption header buffer */
    struct cli_pwdb *password, *pass_any, *pass_zip;

    if (!ctx || !ctx->engine)
	return CL_ENULLARG;

    /* dconf */
    if (ctx->dconf && !(ctx->dconf->archive & ARCH_CONF_PASSWD)) {
	cli_dbgmsg("cli_unzip: decrypt - skipping encrypted file\n");
	return CL_SUCCESS;
    }

    pass_any = ctx->engine->pwdbs[CLI_PWDB_ANY];
    pass_zip = ctx->engine->pwdbs[CLI_PWDB_ZIP];

    while (pass_any || pass_zip) {
	password = pass_zip ? pass_zip : pass_any;

	zinitkey(key, password);

	/* decrypting the encryption header */
	memcpy(eh, src, SIZEOF_EH);

	for (i = 0; i < SIZEOF_EH; i++) {
	    eh[i] ^= zdecryptbyte(key);
	    zupdatekey(key, eh[i]);
	}

	/* verify that the password is correct */
	if (LH_version > 20) { /* higher than 2.0 */
	    uint16_t a = eh[SIZEOF_EH-1];

	    if (LH_flags & F_USEDD) {
		cli_dbgmsg("cli_unzip: decrypt - (v%u) >> 0x%02x 0x%x (moddate)\n", LH_version, a, LH_mtime);
		if (a == ((LH_mtime >> 8) & 0xff))
		    v = 1;
	    } else {
		cli_dbgmsg("cli_unzip: decrypt - (v%u) >> 0x%02x 0x%x (crc32)\n", LH_version, a, LH_crc32);
		if (a == ((LH_crc32 >> 24) & 0xff))
		    v = 1;
	    }
	} else {
	    uint16_t a = eh[SIZEOF_EH-1], b = eh[SIZEOF_EH-2];

	    if (LH_flags & F_USEDD) {
		cli_dbgmsg("cli_unzip: decrypt - (v%u) >> 0x0000%02x%02x 0x%x (moddate)\n", LH_version, a, b, LH_mtime);
		if ((b | (a << 8)) == (LH_mtime & 0xffff))
		    v = 1;
	    } else {
		cli_dbgmsg("cli_unzip: decrypt - (v%u) >> 0x0000%02x%02x 0x%x (crc32)\n", LH_version, eh[SIZEOF_EH-1], eh[SIZEOF_EH-2], LH_crc32);
		if ((b | (a << 8)) == ((LH_crc32 >> 16) & 0xffff))
		    v = 1;
	    }
	}

	if (v) {
	    char name[1024], obuf[BUFSIZ];
	    char *tempfile = name;
	    unsigned int written = 0, total = 0;
	    fmap_t *dcypt_map;
	    const uint8_t *dcypt_zip;
	    int of;

	    cli_dbgmsg("cli_unzip: decrypt - password [%s] matches\n", password->name);

	    /* output decrypted data to tempfile */
	    if(tmpd) {
		snprintf(name, sizeof(name), "%s"PATHSEP"zip.decrypt.%03u", tmpd, *fu);
		name[sizeof(name)-1]='\0';
	    } else {
		if(!(tempfile = cli_gentemp(ctx->engine->tmpdir))) return CL_EMEM;
	    }
	    if((of = open(tempfile, O_RDWR|O_CREAT|O_TRUNC|O_BINARY, S_IRUSR|S_IWUSR))==-1) {
		cli_warnmsg("cli_unzip: decrypt - failed to create temporary file %s\n", tempfile);
		if(!tmpd) free(tempfile);
		return CL_ETMPFILE;
	    }

	    for (i = 12; i < csize; i++) {
		obuf[written] = src[i] ^ zdecryptbyte(key);
		zupdatekey(key, obuf[written]);

		written++;
		if (written >= BUFSIZ) {
		    if (cli_writen(of, obuf, written)!=(int)written) {
			ret = CL_EWRITE;
			goto zd_clean;
		    }
		    total += written;
		    written = 0;
		}
	    }
	    if (written) {
		if (cli_writen(of, obuf, written)!=(int)written) {
		    ret = CL_EWRITE;
		    goto zd_clean;
		}
		total += written;
		written = 0;
	    }

	    cli_dbgmsg("cli_unzip: decrypt - decrypted %u bytes to %s\n", total, tempfile);

	    /* decrypt data to new fmap -> buffer */
	    if (!(dcypt_map = fmap(of, 0, total))) {
		cli_warnmsg("cli_unzip: decrypt - failed to create fmap on decrypted file %s\n", tempfile);
		ret = CL_EMAP;
		goto zd_clean;
	    }

	    if (!(dcypt_zip = fmap_need_off_once(dcypt_map, 0, total))) {
		cli_warnmsg("cli_unzip: decrypt - failed to acquire buffer on decrypted file %s\n", tempfile);
		funmap(dcypt_map);
		ret = CL_EREAD;
		goto zd_clean;
	    }

	    /* call unz on decrypted output */
	    ret = unz(dcypt_zip, csize - SIZEOF_EH, usize, LH_method, LH_flags, fu, ctx, tmpd, zcb);

	    /* clean-up and return */
	    funmap(dcypt_map);
	zd_clean:
	    close(of);
	    if (!ctx->engine->keeptmp)
                if (cli_unlink(tempfile)) {
		    if (!tmpd) free(tempfile);
		    return CL_EUNLINK;
		}
            if (!tmpd) free(tempfile);
	    return ret;
	}

	if (pass_zip)
	    pass_zip = pass_zip->next;
	else
	    pass_any = pass_any->next;
    }

    cli_dbgmsg("cli_unzip: decrypt - skipping encrypted file, no valid passwords\n");
    return CL_SUCCESS;
}

static unsigned int lhdr(fmap_t *map, uint32_t loff,uint32_t zsize, unsigned int *fu, unsigned int fc, const uint8_t *ch, int *ret, cli_ctx *ctx, char *tmpd, int detect_encrypted, zip_cb zcb, uint32_t *file_local_header_size, uint32_t* file_local_data_size) {
  const uint8_t *lh, *zip;
  char name[256];
  uint32_t csize, usize;
  int virus_found = 0;

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
      if (!SCAN_ALLMATCHES)
          return 0;
      virus_found = 1;
  }

  if(LH_flags & F_MSKED) {
    cli_dbgmsg("cli_unzip: lh - header has got unusable masked data\n");
    /* FIXME: need to find/craft a sample */
    fmap_unneed_off(map, loff, SIZEOF_LH);
    return 0;
  }

  if(detect_encrypted && (LH_flags & F_ENCR) && SCAN_HEURISTIC_ENCRYPTED_ARCHIVE) {
    cli_dbgmsg("cli_unzip: Encrypted files found in archive.\n");
    *ret = cli_append_virus(ctx, "Heuristics.Encrypted.Zip");
    if ((*ret == CL_VIRUS && !SCAN_ALLMATCHES) || *ret != CL_CLEAN) {
        fmap_unneed_off(map, loff, SIZEOF_LH);
        return 0;
    }
    virus_found = 1;
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

  if (NULL != file_local_header_size)
      *file_local_header_size = zip - lh;
  if (NULL != file_local_data_size)
      *file_local_data_size = csize;

  if (!csize) { /* FIXME: what's used for method0 files? csize or usize? Nothing in the specs, needs testing */
      cli_dbgmsg("cli_unzip: lh - skipping empty file\n");
  } else {
      if(zsize<csize) {
	  cli_dbgmsg("cli_unzip: lh - stream out of file\n");
	  fmap_unneed_off(map, loff, SIZEOF_LH);
	  return 0;
      }

      if(LH_flags & F_ENCR) {
	  if(fmap_need_ptr_once(map, zip, csize))
	      *ret = zdecrypt(zip, csize, usize, lh, fu, ctx, tmpd, zcb);
      } else {
	  if(fmap_need_ptr_once(map, zip, csize))
	      *ret = unz(zip, csize, usize, LH_method, LH_flags, fu, ctx, tmpd, zcb);
      }
      zip+=csize;
      zsize-=csize;
  }

  if (virus_found != 0)
      *ret = CL_VIRUS;

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

static unsigned int chdr(fmap_t *map, uint32_t coff, uint32_t zsize, unsigned int *fu, unsigned int fc, int *ret, cli_ctx *ctx, char *tmpd, struct zip_requests *requests, uint32_t *file_local_offset, uint32_t *file_local_header_size, uint32_t *file_local_data_size) {
  char name[256];
  int last = 0;
  const uint8_t *ch;
  int virus_found = 0;

  if (NULL != file_local_offset)
      *file_local_offset = 0;
  if (NULL != file_local_header_size)
      *file_local_header_size = 0;
  if (NULL != file_local_data_size)
      *file_local_data_size = 0;

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

  name[0]='\0';
  if(!last) {
      unsigned int size = (CH_flen>=sizeof(name))?sizeof(name)-1:CH_flen;
      const char *src = fmap_need_off_once(map, coff, size);
      if(src) {
	  memcpy(name, src, size);
	  name[size]='\0';
	  cli_dbgmsg("cli_unzip: ch - fname: %s\n", name);
      }
  }
  coff+=CH_flen;

  /* requests do not supply a ctx; also prevent multiple scans */
  if(ctx && cli_matchmeta(ctx, name, CH_csize, CH_usize, (CH_flags & F_ENCR)!=0, fc, CH_crc32, NULL) == CL_VIRUS)
    virus_found = 1;

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

  if (!requests) {
      if(CH_off<zsize-SIZEOF_LH) {
          if (NULL != file_local_offset)
              *file_local_offset = CH_off;
          lhdr(map, CH_off, zsize-CH_off, fu, fc, ch, ret, ctx, tmpd, 1, zip_scan_cb, file_local_header_size, file_local_data_size);
      } else cli_dbgmsg("cli_unzip: ch - local hdr out of file\n");
  }
  else {
      int i;
      size_t len;

      if (!last) {
          for (i = 0; i < requests->namecnt; ++i) {
              cli_dbgmsg("checking for %i: %s\n", i, requests->names[i]);

              len = MIN(sizeof(name)-1, requests->namelens[i]);
              if (!strncmp(requests->names[i], name, len)) {
                  requests->match = 1;
                  requests->found = i;
                  requests->loff = CH_off;
              }
          }
      }
  }

  if (virus_found == 1)
      *ret = CL_VIRUS;
  fmap_unneed_ptr(map, ch, SIZEOF_CH);
  return (last?0:coff);
}

int cli_unzip(cli_ctx *ctx) {
  unsigned int fc=0, fu=0;
  int ret=CL_CLEAN;
  uint32_t fsize, lhoff = 0, coff = 0;
  fmap_t *map = *ctx->fmap;
  char *tmpd;
  const char *ptr;
  int virus_found = 0;
#if HAVE_JSON
  int toval = 0;
#endif
  int bZipBombDetected                 = 0;
  uint32_t cur_file_local_offset       = 0;
  uint32_t cur_file_local_header_size  = 0;
  uint32_t cur_file_local_data_size    = 0;
  uint32_t prev_file_local_offset      = 0;
  uint32_t prev_file_local_header_size = 0;
  uint32_t prev_file_local_data_size   = 0;

  cli_dbgmsg("in cli_unzip\n");
  fsize = (uint32_t)map->len;
  if(sizeof(off_t)!=sizeof(uint32_t) && (size_t)fsize!=map->len) {
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
      uint32_t nOverlappingFiles = 0;

      cli_dbgmsg("cli_unzip: central @%x\n", coff);
      while((coff=chdr(map, coff, fsize, &fu, fc+1, &ret, ctx, tmpd, NULL, &cur_file_local_offset, &cur_file_local_header_size, &cur_file_local_data_size))) {
	  fc++;
	  if (ctx->engine->maxfiles && fu>=ctx->engine->maxfiles) {
	      cli_dbgmsg("cli_unzip: Files limit reached (max: %u)\n", ctx->engine->maxfiles);
	      ret=CL_EMAXFILES;
	  }

    if (cli_checktimelimit(ctx) != CL_SUCCESS) {
        cli_dbgmsg("cli_unzip: Time limit reached (max: %u)\n", ctx->engine->maxscantime);
        ret = CL_ETIMEOUT;
    }
    /*
     * Detect overlapping files and zip bombs.
     */
    if ((((cur_file_local_offset > prev_file_local_offset) && (cur_file_local_offset < prev_file_local_offset + prev_file_local_header_size + prev_file_local_data_size)) ||
         ((prev_file_local_offset > cur_file_local_offset) && (prev_file_local_offset < cur_file_local_offset + cur_file_local_header_size + cur_file_local_data_size))) &&
        (cur_file_local_header_size + cur_file_local_data_size > 0)) {
        /* Overlapping file detected */
        nOverlappingFiles++;

        cli_dbgmsg("cli_unzip: Overlapping files detected.\n");
        cli_dbgmsg("    previous file end:  %u\n", prev_file_local_offset + prev_file_local_header_size + prev_file_local_data_size);
        cli_dbgmsg("    current file start: %u\n", cur_file_local_offset);
        if (ZIP_MAX_NUM_OVERLAPPING_FILES < nOverlappingFiles) {
          if (SCAN_HEURISTICS) {
              ret         = cli_append_virus(ctx, "Heuristics.Zip.OverlappingFiles");
              virus_found = 1;
          } else {
              ret = CL_EFORMAT;
          }
          bZipBombDetected = 1;
        }
    }
    prev_file_local_offset      = cur_file_local_offset;
    prev_file_local_header_size = cur_file_local_header_size;
    prev_file_local_data_size   = cur_file_local_data_size;

#if HAVE_JSON
          if (cli_json_timeout_cycle_check(ctx, &toval) != CL_SUCCESS) {
              ret=CL_ETIMEOUT;
          }
#endif
          if (ret != CL_CLEAN) {
              if (ret == CL_VIRUS && SCAN_ALLMATCHES && !bZipBombDetected) {
                  ret = CL_CLEAN;
                  virus_found = 1;
              } else
                  break;
          }
      }
  } else cli_dbgmsg("cli_unzip: central not found, using localhdrs\n");
  if (virus_found == 1)
      ret = CL_VIRUS;
  if(fu<=(fc/4)) { /* FIXME: make up a sane ratio or remove the whole logic */
    fc = 0;
    while (ret==CL_CLEAN && lhoff<fsize && (coff=lhdr(map, lhoff, fsize-lhoff, &fu, fc+1, NULL, &ret, ctx, tmpd, 1, zip_scan_cb, NULL, NULL))) {
      fc++;
      lhoff+=coff;
      if (SCAN_ALLMATCHES && ret == CL_VIRUS) {
          ret = CL_CLEAN;
          virus_found = 1;
      }
      if (ctx->engine->maxfiles && fu>=ctx->engine->maxfiles) {
	cli_dbgmsg("cli_unzip: Files limit reached (max: %u)\n", ctx->engine->maxfiles);
	ret=CL_EMAXFILES;
      }
#if HAVE_JSON
      if (cli_json_timeout_cycle_check(ctx, &toval) != CL_SUCCESS) {
          ret=CL_ETIMEOUT;
      }
#endif

    }
  }

  if (!ctx->engine->keeptmp) cli_rmdirs(tmpd);
  free(tmpd);

  if (ret == CL_CLEAN && virus_found)
    ret = CL_VIRUS;

  return ret;
}

int unzip_single_internal(cli_ctx *ctx, off_t lhoffl, zip_cb zcb)
{
  int ret=CL_CLEAN;
  unsigned int fu=0;
  uint32_t fsize;
  fmap_t *map = *ctx->fmap;

  cli_dbgmsg("in cli_unzip_single\n");
  fsize = (uint32_t)(map->len - lhoffl);
  if (lhoffl<0 || (size_t)lhoffl>map->len || (sizeof(off_t)!=sizeof(uint32_t) && (size_t)fsize!=map->len - lhoffl)) {
    cli_dbgmsg("cli_unzip: bad offset\n");
    return CL_CLEAN;
  }
  if (fsize < SIZEOF_LH) {
    cli_dbgmsg("cli_unzip: file too short\n");
    return CL_CLEAN;
  }

  lhdr(map, lhoffl, fsize, &fu, 0, NULL, &ret, ctx, NULL, 0, zcb, NULL, NULL);

  return ret;
}

int cli_unzip_single(cli_ctx *ctx, off_t lhoffl) {
    return unzip_single_internal(ctx, lhoffl, zip_scan_cb);
}

int unzip_search_add(struct zip_requests *requests, const char *name, size_t nlen)
{
    cli_dbgmsg("in unzip_search_add\n");

    if (requests->namecnt >= MAX_ZIP_REQUESTS) {
        cli_dbgmsg("DEBUGGING MESSAGE GOES HERE!\n");
        return CL_BREAK;
    }

    cli_dbgmsg("unzip_search_add: adding %s (len %llu)\n", name, (long long unsigned)nlen);

    requests->names[requests->namecnt] = name;
    requests->namelens[requests->namecnt] = nlen;
    requests->namecnt++;

    return CL_SUCCESS;
}

int unzip_search(cli_ctx *ctx, fmap_t *map, struct zip_requests *requests)
{
    unsigned int fc = 0;
    fmap_t *zmap = map;
    size_t fsize;
    uint32_t coff = 0;
    const char *ptr;
    int ret = CL_CLEAN;
#if HAVE_JSON
    uint32_t toval = 0;
#endif
    cli_dbgmsg("in unzip_search\n");

    if ((!ctx && !map) || !requests) {
        return CL_ENULLARG;
    }

    /* get priority to given map over *ctx->fmap */
    if (ctx && !map)
        zmap = *ctx->fmap;
    fsize = zmap->len;
    if(sizeof(off_t)!=sizeof(uint32_t) && fsize!=zmap->len) {
        cli_dbgmsg("unzip_search: file too big\n");
        return CL_CLEAN;
    }
    if (fsize < SIZEOF_CH) {
        cli_dbgmsg("unzip_search: file too short\n");
        return CL_CLEAN;
    }

    for(coff=fsize-22 ; coff>0 ; coff--) { /* sizeof(EOC)==22 */
        if(!(ptr = fmap_need_off_once(zmap, coff, 20)))
            continue;
        if(cli_readint32(ptr)==0x06054b50) {
            uint32_t chptr = cli_readint32(&ptr[16]);
            if(!CLI_ISCONTAINED(0, fsize, chptr, SIZEOF_CH)) continue;
            coff=chptr;
            break;
        }
    }

    if(coff) {
        cli_dbgmsg("unzip_search: central @%x\n", coff);
        while(ret==CL_CLEAN && (coff=chdr(zmap, coff, fsize, NULL, fc+1, &ret, ctx, NULL, requests, NULL, NULL, NULL))) {
            if (requests->match) {
                ret=CL_VIRUS;
            }

            fc++;
            if (ctx && ctx->engine->maxfiles && fc >= ctx->engine->maxfiles) {
                cli_dbgmsg("cli_unzip: Files limit reached (max: %u)\n", ctx->engine->maxfiles);
                ret=CL_EMAXFILES;
            }
#if HAVE_JSON
            if (ctx && cli_json_timeout_cycle_check(ctx, (int *)(&toval)) != CL_SUCCESS) {
                ret=CL_ETIMEOUT;
            }
#endif
        }
    } else {
        cli_dbgmsg("unzip_search: cannot locate central directory\n");
    }

    return ret;
}

int unzip_search_single(cli_ctx *ctx, const char *name, size_t nlen, uint32_t *loff)
{
    struct zip_requests requests;
    int ret;

    cli_dbgmsg("in unzip_search_single\n");
    if (!ctx) {
        return CL_ENULLARG;
    }

    memset(&requests, 0, sizeof(struct zip_requests));

    if ((ret = unzip_search_add(&requests, name, nlen)) != CL_SUCCESS) {
        return ret;
    }

    if ((ret = unzip_search(ctx, NULL, &requests)) == CL_VIRUS) {
        *loff = requests.loff;
    }

    return ret;
}


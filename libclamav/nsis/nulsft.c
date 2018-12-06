/*
 *  Copyright (C) 2007-2008 Sourcefire Inc.
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

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "clamav.h"
#include "others.h"
#include "nsis_bzlib.h"
/* #include "zlib.h" */
#include "nsis_zlib.h"
#include "lzma_iface.h"
#include "matcher.h"
#include "scanners.h"
#include "nulsft.h" /* SHUT UP GCC -Wextra */
#include "fmap.h"

#define EC32(x) le32_to_host(x)

enum {
  COMP_NOT_DETECTED,
  COMP_BZIP2,
  COMP_LZMA,
  COMP_ZLIB,
  COMP_NOCOMP
};

struct nsis_st {
  size_t curpos;
  int ofd;
  int opened;
  off_t off;
  off_t fullsz;
  char *dir;
  uint32_t asz;
  uint32_t hsz;
  uint32_t fno;
  uint8_t comp;
  uint8_t solid;
  uint8_t freecomp;
  uint8_t eof;
  struct stream_state nsis;
  nsis_bzstream bz;
  struct CLI_LZMA lz;
/*   z_stream z; */
  nsis_z_stream z;
  const unsigned char *freeme;
  fmap_t *map;
  char ofn[1024];
};


#define LINESTR(x) #x
#define LINESTR2(x) LINESTR(x)
#define __AT__  " at "__FILE__":"LINESTR2(__LINE__)

static int nsis_init(struct nsis_st *n) {
  switch(n->comp) {
  case COMP_BZIP2:
    memset(&n->bz, 0, sizeof(nsis_bzstream));
    if (nsis_BZ2_bzDecompressInit(&n->bz, 0, 0)!=BZ_OK)
      return CL_EUNPACK;
    n->freecomp=1;
    break;
  case COMP_LZMA:
    memset(&n->lz, 0, sizeof(struct CLI_LZMA));
    if(cli_LzmaInit(&n->lz, 0xffffffffffffffffULL)!=LZMA_RESULT_OK)
      return CL_EUNPACK;
    n->freecomp=1;
    break;
  case COMP_ZLIB:
    memset(&n->z, 0, sizeof(z_stream));
/*     inflateInit2(&n->z, -MAX_WBITS); */
/*     n->freecomp=1; */
    nsis_inflateInit(&n->z);
    n->freecomp=0;
  }
  return CL_SUCCESS;
}

static void nsis_shutdown(struct nsis_st *n) {
  if(!n->freecomp)
    return;

  switch(n->comp) {
  case COMP_BZIP2:
    nsis_BZ2_bzDecompressEnd(&n->bz);
    break;
  case COMP_LZMA:
    cli_LzmaShutdown(&n->lz);
    break;
  case COMP_ZLIB:
/*     inflateEnd(&n->z); */
    break;
  }

  n->freecomp=0;
}

static int nsis_decomp(struct nsis_st *n) {
  int ret = CL_EFORMAT;
  switch(n->comp) {
  case COMP_BZIP2:
    n->bz.avail_in = n->nsis.avail_in;
    n->bz.next_in = n->nsis.next_in;
    n->bz.avail_out = n->nsis.avail_out;
    n->bz.next_out = n->nsis.next_out;
    switch (nsis_BZ2_bzDecompress(&n->bz)) {
    case BZ_OK:
      ret = CL_SUCCESS;
      break;
    case BZ_STREAM_END:
      ret = CL_BREAK;
    }
    n->nsis.avail_in = n->bz.avail_in;
    n->nsis.next_in = n->bz.next_in;
    n->nsis.avail_out = n->bz.avail_out;
    n->nsis.next_out = n->bz.next_out;
    break;
  case COMP_LZMA:
    n->lz.avail_in = n->nsis.avail_in;
    n->lz.next_in = n->nsis.next_in;
    n->lz.avail_out = n->nsis.avail_out;
    n->lz.next_out = n->nsis.next_out;
    switch (cli_LzmaDecode(&n->lz)) {
    case LZMA_RESULT_OK:
      ret = CL_SUCCESS;
      break;
    case LZMA_STREAM_END:
      ret = CL_BREAK;
    }
    n->nsis.avail_in = n->lz.avail_in;
    n->nsis.next_in = n->lz.next_in;
    n->nsis.avail_out = n->lz.avail_out;
    n->nsis.next_out = n->lz.next_out;
    break;
  case COMP_ZLIB:
    n->z.avail_in = n->nsis.avail_in;
    n->z.next_in = n->nsis.next_in;
    n->z.avail_out = n->nsis.avail_out;
    n->z.next_out = n->nsis.next_out;
/*  switch (inflate(&n->z, Z_NO_FLUSH)) { */
    switch (nsis_inflate(&n->z)) {
    case Z_OK:
      ret = CL_SUCCESS;
      break;
    case Z_STREAM_END:
      ret = CL_BREAK;
    }
    n->nsis.avail_in = n->z.avail_in;
    n->nsis.next_in = n->z.next_in;
    n->nsis.avail_out = n->z.avail_out;
    n->nsis.next_out = n->z.next_out;
    break;
  }
  return ret;
}

static int nsis_unpack_next(struct nsis_st *n, cli_ctx *ctx) {
  const unsigned char *ibuf;
  uint32_t size, loops;
  int ret, gotsome=0;
  unsigned char obuf[BUFSIZ];

  if (n->eof) {
    cli_dbgmsg("NSIS: extraction complete\n");
    return CL_BREAK;
  }
  
  if ((ret=cli_checklimits("NSIS", ctx, 0, 0, 0))!=CL_CLEAN)
    return ret;

  if (n->fno)
    snprintf(n->ofn, 1023, "%s"PATHSEP"content.%.3u", n->dir, n->fno);
  else
    snprintf(n->ofn, 1023, "%s"PATHSEP"headers", n->dir);

  n->fno++;
  n->opened = 0;

  if (!n->solid) {
    if (fmap_readn(n->map, &size, n->curpos, 4)!=4) {
      cli_dbgmsg("NSIS: reached EOF - extraction complete\n");
      return CL_BREAK;
    }
    n->curpos += 4;
    if (n->asz==4) {
      cli_dbgmsg("NSIS: reached CRC - extraction complete\n");
      return CL_BREAK;
    }
    loops = EC32(size);
    if (!(size = (loops&~0x80000000))) {
      cli_dbgmsg("NSIS: empty file found\n");
      return CL_SUCCESS;
    }
    if (n->asz <4 || size > n->asz-4) {
      cli_dbgmsg("NSIS: next file is outside the archive\n");
      return CL_BREAK;
    }

    n->asz -= size+4;

    if ((ret=cli_checklimits("NSIS", ctx, size, 0, 0))!=CL_CLEAN) {
      n->curpos += size;
      return ret;
    }
    if (!(ibuf = fmap_need_off_once(n->map, n->curpos, size))) {
      cli_dbgmsg("NSIS: cannot read %u bytes"__AT__"\n", size);
      return CL_EREAD;
    }
  if ((n->ofd=open(n->ofn, O_RDWR|O_CREAT|O_TRUNC|O_BINARY, 0600))==-1) {
    cli_errmsg("NSIS: unable to create output file %s - aborting.", n->ofn);
    return CL_ECREAT;
  }
  n->opened = 1;
    n->curpos += size;
    if (loops==size) {

      if (cli_writen(n->ofd, ibuf, size) != (ssize_t) size) {
	cli_dbgmsg("NSIS: cannot write output file"__AT__"\n");
	close(n->ofd);
	return CL_EWRITE;
      }
    } else {
      if ((ret=nsis_init(n))!=CL_SUCCESS) {
	cli_dbgmsg("NSIS: decompressor init failed"__AT__"\n");
	close(n->ofd);
	return ret;
      }
      
      n->nsis.avail_in = size;
      n->nsis.next_in = (void*)ibuf;
      n->nsis.next_out = obuf;
      n->nsis.avail_out = BUFSIZ;
      loops=0;

      while ((ret=nsis_decomp(n))==CL_SUCCESS) {
	if ((size = n->nsis.next_out - obuf)) {
	  gotsome=1;
	  if (cli_writen(n->ofd, obuf, size) != (ssize_t) size) {
	    cli_dbgmsg("NSIS: cannot write output file"__AT__"\n");
	    close(n->ofd);
	    nsis_shutdown(n);
	    return CL_EWRITE;
	  }
	  n->nsis.next_out = obuf;
	  n->nsis.avail_out = BUFSIZ;
	  loops=0;
	  if ((ret=cli_checklimits("NSIS", ctx, size, 0, 0))!=CL_CLEAN) {
	    close(n->ofd);
	    nsis_shutdown(n);
	    return ret;
	  }
	} else if (++loops > 20) {
	  cli_dbgmsg("NSIS: xs looping, breaking out"__AT__"\n");
	  ret = CL_EFORMAT;
	  break;
	}
      }

      nsis_shutdown(n);

      if (n->nsis.next_out - obuf) {
	gotsome=1;
	if (cli_writen(n->ofd, obuf, n->nsis.next_out - obuf) != n->nsis.next_out - obuf) {
	  cli_dbgmsg("NSIS: cannot write output file"__AT__"\n");
	  close(n->ofd);
	  return CL_EWRITE;
	}
      }

      if (ret != CL_SUCCESS && ret != CL_BREAK) {
	cli_dbgmsg("NSIS: bad stream"__AT__"\n");
	if (gotsome) {
	  ret = CL_SUCCESS;
	} else {
	  ret = CL_EMAXSIZE;
	  close(n->ofd);
	}
	return ret;
      }

    }

    return CL_SUCCESS;

  } else {
    if (!n->freeme) {
      if ((ret=nsis_init(n))!=CL_SUCCESS) {
	cli_dbgmsg("NSIS: decompressor init failed\n");
	return ret;
      }
      if(!(n->freeme = fmap_need_off_once(n->map, n->curpos, n->asz))) {
	cli_dbgmsg("NSIS: cannot read %u bytes"__AT__"\n", n->asz);
	return CL_EREAD;
      }
      n->nsis.next_in = (void*)n->freeme;
      n->nsis.avail_in = n->asz;
    }

    if (n->nsis.avail_in<=4) {
      cli_dbgmsg("NSIS: extraction complete\n");
      return CL_BREAK;
    }
    n->nsis.next_out = obuf;
    n->nsis.avail_out = 4;
    loops = 0;

    while ((ret=nsis_decomp(n))==CL_SUCCESS) {
      if (n->nsis.next_out - obuf == 4) break;
      if (++loops > 20) {
	cli_dbgmsg("NSIS: xs looping, breaking out"__AT__"\n");
	ret = CL_BREAK;
	break;
      }
    }

    if (ret != CL_SUCCESS) {
      cli_dbgmsg("NSIS: bad stream"__AT__"\n");
      return CL_EFORMAT;
    }

    size=cli_readint32(obuf);
    if ((ret=cli_checklimits("NSIS", ctx, size, 0, 0))!=CL_CLEAN) {
      return ret;
    }

    if (size == 0) {
        cli_dbgmsg("NSIS: Empty file found.\n");
        return CL_SUCCESS;
    }

    n->nsis.next_out = obuf;
    n->nsis.avail_out = MIN(BUFSIZ,size);
    loops = 0;

      if ((n->ofd=open(n->ofn, O_RDWR|O_CREAT|O_TRUNC|O_BINARY, 0600))==-1) {
        cli_errmsg("NSIS: unable to create output file %s - aborting.", n->ofn);
        return CL_ECREAT;
      }
      n->opened = 1;

    while (size && (ret=nsis_decomp(n))==CL_SUCCESS) {
      unsigned int wsz;
      if ((wsz = n->nsis.next_out - obuf)) {
	gotsome=1;
	if (cli_writen(n->ofd, obuf, wsz) != (ssize_t) wsz) {
	  cli_dbgmsg("NSIS: cannot write output file"__AT__"\n");
	  close(n->ofd);
	  return CL_EWRITE;
	}
	size-=wsz;
	loops=0;
	n->nsis.next_out = obuf;
	n->nsis.avail_out = MIN(size,BUFSIZ);
      } else if ( ++loops > 20 ) {
	cli_dbgmsg("NSIS: xs looping, breaking out"__AT__"\n");
	ret = CL_EFORMAT;
	break;
      }
    }

    if (n->nsis.next_out - obuf) {
      gotsome=1;
      if (cli_writen(n->ofd, obuf, n->nsis.next_out - obuf) != n->nsis.next_out - obuf) {
	cli_dbgmsg("NSIS: cannot write output file"__AT__"\n");
	close(n->ofd);
	return CL_EWRITE;
      }
    }

    if (ret == CL_EFORMAT) {
      cli_dbgmsg("NSIS: bad stream"__AT__"\n");
      if (!gotsome) {
	close(n->ofd);
	return CL_EMAXSIZE;
      } 
    }

    if (ret == CL_EFORMAT || ret == CL_BREAK) {
      n->eof=1;
    } else if (ret != CL_SUCCESS) {
      cli_dbgmsg("NSIS: bad stream"__AT__"\n");
      close(n->ofd);
      return CL_EFORMAT;
    }
    return CL_SUCCESS;
  }

}

static uint8_t nsis_detcomp(const char *b) {
  if (*b=='1') return COMP_BZIP2;
  if ((cli_readint32(b)&~0x80000000)==0x5d) return COMP_LZMA;
  return COMP_ZLIB;
}

static int nsis_headers(struct nsis_st *n, cli_ctx *ctx) {
  const char *buf;
  uint32_t pos;
  int i;
  uint8_t comps[] = {0, 0, 0, 0}, trunc = 0;
  
  if (!(buf = fmap_need_off_once(n->map, n->off, 0x1c)))
    return CL_EREAD;

  n->hsz = (uint32_t)cli_readint32(buf+0x14);
  n->asz = (uint32_t)cli_readint32(buf+0x18);
  n->fullsz = n->map->len;

  cli_dbgmsg("NSIS: Header info - Flags=%x, Header size=%x, Archive size=%x\n", cli_readint32(buf), n->hsz, n->asz);

  if (n->fullsz - n->off < (off_t) n->asz) {
    cli_dbgmsg("NSIS: Possibly truncated file\n");
    n->asz = n->fullsz - n->off;
    trunc++;
  } else if (n->fullsz - n->off != (off_t) n->asz) {
    cli_dbgmsg("NSIS: Overlays found\n");
  }

  n->asz -= 0x1c;
  buf += 0x1c;

  /* Guess if solid */
  for (i=0, pos=0;pos < n->asz-4;i++) {
    int32_t nextsz;
    if (!(buf = fmap_need_ptr_once(n->map, (void *)buf, 4))) return CL_EREAD;
    nextsz=cli_readint32(buf);
    if (!i) n->comp = nsis_detcomp(buf);
    buf += 4;
    if (nextsz&0x80000000) {
      nextsz&=~0x80000000;
      if (!(buf = fmap_need_ptr_once(n->map, (void *)buf, 4))) return CL_EREAD;
      comps[nsis_detcomp(buf)]++;
      nextsz-=4;
      pos+=4;
      buf+=4;
    }
    if ((pos+=4+nextsz) > n->asz) {
      n->solid = 1;
      break;
    }

    buf += nextsz;
  }
  
  if (trunc && i>=2) n->solid=0;

  cli_dbgmsg("NSIS: solid compression%s detected\n", (n->solid)?"":" not");

  /* Guess the compression method */
  if (!n->solid) {
    cli_dbgmsg("NSIS: bzip2 %u - lzma %u - zlib %u\n", comps[1], comps[2], comps[3]);
    n->comp = (comps[1]<comps[2]) ? (comps[2]<comps[3] ? COMP_ZLIB : COMP_LZMA) : (comps[1]<comps[3] ? COMP_ZLIB : COMP_BZIP2);
  }

  n->curpos = n->off+0x1c;
  return nsis_unpack_next(n, ctx);
}



static int cli_nsis_unpack(struct nsis_st *n, cli_ctx *ctx) {
  return (n->fno) ? nsis_unpack_next(n, ctx) : nsis_headers(n, ctx);
}


int cli_scannulsft(cli_ctx *ctx, off_t offset) {
        int ret;
	struct nsis_st nsist;

    cli_dbgmsg("in scannulsft()\n");

    memset(&nsist, 0, sizeof(struct nsis_st));

    nsist.off = offset;
    if (!(nsist.dir = cli_gentemp(ctx->engine->tmpdir)))
        return CL_ETMPDIR;
    if(mkdir(nsist.dir, 0700)) {
	cli_dbgmsg("NSIS: Can't create temporary directory %s\n", nsist.dir);
	free(nsist.dir);
	return CL_ETMPDIR;
    }
    
    nsist.map = *ctx->fmap;
    if(ctx->engine->keeptmp) cli_dbgmsg("NSIS: Extracting files to %s\n", nsist.dir);

    do {
        ret = cli_nsis_unpack(&nsist, ctx);
        if (ret == CL_SUCCESS && nsist.opened == 0) {
            /* Don't scan a non-existent file */
            continue;
        }
	if (ret == CL_SUCCESS) {
	  cli_dbgmsg("NSIS: Successully extracted file #%u\n", nsist.fno);
	  if (lseek(nsist.ofd, 0, SEEK_SET) == -1) {
          cli_dbgmsg("NSIS: call to lseek() failed\n");
          free(nsist.dir);
        return CL_ESEEK;
      }
	  if(nsist.fno == 1)
	    ret=cli_scandesc(nsist.ofd, ctx, 0, 0, NULL, AC_SCAN_VIR, NULL);
	  else
	    ret=cli_magic_scandesc(nsist.ofd, nsist.ofn, ctx);
	  close(nsist.ofd);
	  if(!ctx->engine->keeptmp)
	    if(cli_unlink(nsist.ofn)) ret = CL_EUNLINK;
	} else if(ret == CL_EMAXSIZE) {
	    ret = nsist.solid ? CL_BREAK : CL_SUCCESS;
	}
    } while(ret == CL_SUCCESS);

    if(ret == CL_BREAK || ret == CL_EMAXFILES)
	ret = CL_CLEAN;

    nsis_shutdown(&nsist);

    if(!ctx->engine->keeptmp)
        cli_rmdirs(nsist.dir);

    free(nsist.dir);

    return ret;
}


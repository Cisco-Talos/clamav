/*
 *  Copyright (C) 2007 aCaB <acab@clamav.net>
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

#include "others.h"
#include "cltypes.h"
#include "nsis_bzlib.h"
#include "LZMADecode.h"
#include "nsis_zlib.h"
#include "matcher.h"
#include "scanners.h"
#include "nulsft.h" /* SHUT UP GCC -Wextra */

#ifndef O_BINARY
#define O_BINARY 0
#endif

#define EC32(x) le32_to_host(x)

enum {
  COMP_NOT_DETECTED,
  COMP_BZIP2,
  COMP_LZMA,
  COMP_ZLIB,
  COMP_NOCOMP
};

struct nsis_st {
  int ifd;
  int ofd;
  off_t off;
  char *dir;
  uint32_t asz;
  uint32_t hsz;
  uint32_t fno;
  struct {
    uint32_t avail_in;
    unsigned char *next_in;
    uint32_t avail_out;
    unsigned char *next_out;
  } nsis;
  nsis_bzstream bz;
  lzma_stream lz;
  nsis_z_stream z;
  unsigned char *freeme;
  uint8_t comp;
  uint8_t solid;
  uint8_t freecomp;
  uint8_t eof;
  char ofn[1024];
};


#define LINESTR(x) #x
#define LINESTR2(x) LINESTR(x)
#define __AT__  " at "__FILE__":"LINESTR2(__LINE__)

static int nsis_init(struct nsis_st *n) {
  switch(n->comp) {
  case COMP_BZIP2:
    if (nsis_BZ2_bzDecompressInit(&n->bz, 0, 0)!=BZ_OK)
      return CL_EBZIP;
    n->freecomp=1;
    break;
  case COMP_LZMA:
    lzmaInit(&n->lz);
    n->freecomp=1;
    break;
  case COMP_ZLIB:
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
    lzmaShutdown(&n->lz);
  case COMP_ZLIB:
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
    switch (lzmaDecode(&n->lz)) {
    case LZMA_OK:
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
  unsigned char *ibuf;
  uint32_t size, loops;
  int ret;
  unsigned char obuf[BUFSIZ];

  if (n->eof) {
    cli_dbgmsg("NSIS: extraction complete\n");
    return CL_BREAK;
  }
  if (ctx->limits && ctx->limits->maxfiles && n->fno >= ctx->limits->maxfiles) {
    cli_dbgmsg("NSIS: Files limit reached (max: %u)\n", ctx->limits->maxfiles);
    return CL_EMAXFILES;
  }

  if (n->fno)
    snprintf(n->ofn, 1023, "%s/content.%.3u", n->dir, n->fno);
  else
    snprintf(n->ofn, 1023, "%s/headers", n->dir);

  n->fno++;

  if ((n->ofd=open(n->ofn, O_RDWR|O_CREAT|O_TRUNC|O_BINARY, 0600))==-1) {
    cli_errmsg("NSIS: unable to create output file %s - aborting.", n->ofn);
    return CL_EIO;
  }

  if (!n->solid) {
    if (cli_readn(n->ifd, &size, 4)!=4) {
      cli_dbgmsg("NSIS: reached EOF - extraction complete\n");
      close(n->ofd);
      return CL_BREAK;
    }
    if (n->asz==4) {
      cli_dbgmsg("NSIS: reached CRC - extraction complete\n");
      close(n->ofd);
      return CL_BREAK;
    }
    loops = EC32(size);
    if (!(size = (loops&~0x80000000))) {
      cli_dbgmsg("NSIS: empty file found\n");
      return CL_SUCCESS;
    }
    if (n->asz <4 || size > n->asz-4) {
      cli_dbgmsg("NSIS: next file is outside the archive\n");
      close(n->ofd);
      return CL_BREAK;
    }

    n->asz -= size+4;

    if (ctx->limits && ctx->limits->maxfilesize && size > ctx->limits->maxfilesize) {
      cli_dbgmsg("NSIS: Skipping file due to size limit (%u, max: %lu)\n", size, ctx->limits->maxfilesize);
      close(n->ofd);
      if (lseek(n->ifd, size, SEEK_CUR)==-1) return CL_EIO;
      return CL_EMAXSIZE;
    }
    if (!(ibuf= (unsigned char *) cli_malloc(size))) {
      	cli_dbgmsg("NSIS: out of memory"__AT__"\n");
      close(n->ofd);
      return CL_EMEM;
    }
    if (cli_readn(n->ifd, ibuf, size) != (ssize_t) size) {
      cli_dbgmsg("NSIS: cannot read %u bytes"__AT__"\n", size);
      free(ibuf);
      close(n->ofd);
      return CL_EIO;
    }
    if (loops==size) {
      if (cli_writen(n->ofd, ibuf, size) != (ssize_t) size) {
	cli_dbgmsg("NSIS: cannot write output file"__AT__"\n");
	free(ibuf);
	close(n->ofd);
	return CL_EIO;
      }
    } else {
      if ((ret=nsis_init(n))!=CL_SUCCESS) {
	cli_dbgmsg("NSIS: decompressor init failed"__AT__"\n");
	free(ibuf);
	close(n->ofd);
	return ret;
      }
      
      n->nsis.avail_in = size;
      n->nsis.next_in = ibuf;
      n->nsis.next_out = obuf;
      n->nsis.avail_out = BUFSIZ;
      loops=0;

      while ((ret=nsis_decomp(n))==CL_SUCCESS) {
	if ((size = n->nsis.next_out - obuf)) {
	  if (cli_writen(n->ofd, obuf, size) != (ssize_t) size) {
	    cli_dbgmsg("NSIS: cannot write output file"__AT__"\n");
	    free(ibuf);
	    close(n->ofd);
	    return CL_EIO;
	  }
	  n->nsis.next_out = obuf;
	  n->nsis.avail_out = BUFSIZ;
	  loops=0;
	  if (ctx->limits && ctx->limits->maxfilesize && size > ctx->limits->maxfilesize) {
	    cli_dbgmsg("NSIS: Skipping file due to size limit (%u, max: %lu)\n", size, ctx->limits->maxfilesize);
	    free(ibuf);
	    close(n->ofd);
	    nsis_shutdown(n);
	    return CL_EMAXSIZE;
	  }
	} else if (++loops > 10) {
	  cli_dbgmsg("NSIS: xs looping, breaking out"__AT__"\n");
	  ret = CL_BREAK;
	  break;
	}
      }

      if (ret != CL_BREAK) {
	cli_dbgmsg("NSIS: bad stream"__AT__"\n");
	free(ibuf);
	close(n->ofd);
	return CL_EFORMAT;
      }

      if (cli_writen(n->ofd, obuf, n->nsis.next_out - obuf) != n->nsis.next_out - obuf) {
	cli_dbgmsg("NSIS: cannot write output file"__AT__"\n");
	free(ibuf);
	close(n->ofd);
	return CL_EIO;
      }
      nsis_shutdown(n);
    }

    free(ibuf);
    return CL_SUCCESS;

  } else {
    if (!n->freeme) {
      if ((ret=nsis_init(n))!=CL_SUCCESS) {
	cli_dbgmsg("NSIS: decompressor init failed\n");
	close(n->ofd);
	return ret;
      }
      if (!(n->freeme= (unsigned char *) cli_malloc(n->asz))) {
	cli_dbgmsg("NSIS: out of memory\n");
	close(n->ofd);
	return CL_EMEM;
      }
      if (cli_readn(n->ifd, n->freeme, n->asz) != (ssize_t) n->asz) {
	cli_dbgmsg("NSIS: cannot read %u bytes"__AT__"\n", n->asz);
	close(n->ofd);
	return CL_EIO;
      }
      n->nsis.next_in = n->freeme;
      n->nsis.avail_in = n->asz;
    }

    if (n->nsis.avail_in<=4) {
      cli_dbgmsg("NSIS: extraction complete\n");
      close(n->ofd);
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
      close(n->ofd);
      return CL_EFORMAT;
    }

    size=cli_readint32(obuf);
    if (ctx->limits && ctx->limits->maxfilesize && size > ctx->limits->maxfilesize) {
      cli_dbgmsg("NSIS: Breaking out due to filesize limit (%u, max: %lu) in solid archive\n", size, ctx->limits->maxfilesize);
      close(n->ofd);
      return CL_EFORMAT;
    }

    n->nsis.next_out = obuf;
    n->nsis.avail_out = MIN(BUFSIZ,size);
    loops = 0;

    while (size && (ret=nsis_decomp(n))==CL_SUCCESS) {
      unsigned int wsz;
      if ((wsz = n->nsis.next_out - obuf)) {
	if (cli_writen(n->ofd, obuf, wsz) != (ssize_t) wsz) {
	  close(n->ofd);
	  return CL_EIO;
	}
	size-=wsz;
	n->nsis.next_out = obuf;
	n->nsis.avail_out = MIN(size,BUFSIZ);
      } else if ( ++loops > 20 ) {
	cli_dbgmsg("NSIS: xs looping, breaking out"__AT__"\n");
	ret = CL_BREAK;
	break;
      }
    }

    if (ret == CL_BREAK) {
      if (cli_writen(n->ofd, obuf, n->nsis.next_out - obuf) != n->nsis.next_out - obuf) {
	close(n->ofd);
	return CL_EIO;
      }
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
  char buf[28];
  struct stat st;
  uint32_t pos;
  int i;
  uint8_t comps[] = {0, 0, 0, 0}, trunc = 0;
  
  if (fstat(n->ifd, &st)==-1 ||
      lseek(n->ifd, n->off, SEEK_SET)==-1 ||
      cli_readn(n->ifd, buf, 28) != 28)
    return CL_EIO;

  n->hsz = (uint32_t)cli_readint32(buf+0x14);
  n->asz = (uint32_t)cli_readint32(buf+0x18);

  cli_dbgmsg("NSIS: Header info - Flags=%x, Header size=%x, Archive size=%x\n", cli_readint32(buf), n->hsz, n->asz);

  if (st.st_size - n->off < (off_t) n->asz) {
    cli_dbgmsg("NSIS: Possibly truncated file\n");
    n->asz = st.st_size - n->off;
    trunc++;
  } else if (st.st_size - n->off != (off_t) n->asz) {
    cli_dbgmsg("NSIS: Overlays found\n");
  }

  n->asz -= 0x1c;

  /* Guess if solid */
  for (i=0, pos=0;pos < n->asz-4;i++) {
    int32_t nextsz;
    if (cli_readn(n->ifd, buf+4, 4)!=4) return CL_EIO;
    nextsz=cli_readint32(buf+4);
    if (!i) n->comp = nsis_detcomp(buf+4);
    if (nextsz&0x80000000) {
      nextsz&=~0x80000000;
      if (cli_readn(n->ifd, buf+4, 4)!=4) return CL_EIO;
      comps[nsis_detcomp(buf+4)]++;
      nextsz-=4;
      pos+=4;
    }
    if ((pos+=4+nextsz) > n->asz) {
      n->solid = 1;
      break;
    }

    if (lseek(n->ifd, nextsz, SEEK_CUR)==-1) return CL_EIO;
  }
  
  if (trunc && i>=2) n->solid=0;

  cli_dbgmsg("NSIS: solid compression%s detected\n", (n->solid)?"":" not");

  /* Guess the compression method */
  if (!n->solid) {
    cli_dbgmsg("NSIS: bzip2 %u - lzma %u - zlib %u\n", comps[1], comps[2], comps[3]);
    n->comp = (comps[1]<comps[2]) ? (comps[2]<comps[3] ? COMP_ZLIB : COMP_LZMA) : (comps[1]<comps[3] ? COMP_ZLIB : COMP_BZIP2);
  }

  if (lseek(n->ifd, n->off+0x1c, SEEK_SET)==-1) return CL_EIO;

  return nsis_unpack_next(n, ctx);
}



static int cli_nsis_unpack(struct nsis_st *n, cli_ctx *ctx) {
  return (n->fno) ? nsis_unpack_next(n, ctx) : nsis_headers(n, ctx);
}

static void cli_nsis_free(struct nsis_st *n) {
  nsis_shutdown(n);
  if (n->solid && n->freeme) free(n->freeme);
}

int cli_scannulsft(int desc, cli_ctx *ctx, off_t offset) {
        int ret;
	struct nsis_st nsist;

    cli_dbgmsg("in scannulsft()\n");
    if(ctx->limits && ctx->limits->maxreclevel && ctx->arec >= ctx->limits->maxreclevel) {
        cli_dbgmsg("Archive recursion limit exceeded (arec == %u).\n", ctx->arec+1);
	return CL_EMAXREC;
    }

    memset(&nsist, 0, sizeof(struct nsis_st));

    nsist.ifd = desc;
    nsist.off = offset;
    if (!(nsist.dir = cli_gentemp(NULL)))
        return CL_ETMPDIR;
    if(mkdir(nsist.dir, 0700)) {
	cli_dbgmsg("NSIS: Can't create temporary directory %s\n", nsist.dir);
	free(nsist.dir);
	return CL_ETMPDIR;
    }

    if(cli_leavetemps_flag) cli_dbgmsg("NSIS: Extracting files to %s\n", nsist.dir);

    ctx->arec++;

    do {
        ret = cli_nsis_unpack(&nsist, ctx);
	if(ret != CL_SUCCESS) {
	    if(ret == CL_EMAXSIZE) {
	        if(BLOCKMAX) {
		    *ctx->virname = "NSIS.ExceededFileSize";
		    ret=CL_VIRUS;
		} else {
		    ret = nsist.solid ? CL_BREAK : CL_SUCCESS;
		}
	    }
	} else {
	    cli_dbgmsg("NSIS: Successully extracted file #%u\n", nsist.fno);
	    lseek(nsist.ofd, 0, SEEK_SET);
	    if(nsist.fno == 1)
	        ret=cli_scandesc(nsist.ofd, ctx, 0, 0, 0, NULL);
	    else
	        ret=cli_magic_scandesc(nsist.ofd, ctx);
	    close(nsist.ofd);
	    if(!cli_leavetemps_flag)
	        unlink(nsist.ofn);
	}
    } while(ret == CL_SUCCESS);

    if(ret == CL_BREAK)
	ret = CL_CLEAN;

    cli_nsis_free(&nsist);

    if(!cli_leavetemps_flag)
        cli_rmdirs(nsist.dir);

    free(nsist.dir);

    ctx->arec--;    
    return ret;
}


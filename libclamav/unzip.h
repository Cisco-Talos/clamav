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

#ifndef __UNZIP_H
#define __UNZIP_H

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include "others.h"

typedef int (*zip_cb)(int fd, const char *filepath, cli_ctx *ctx);
#define zip_scan_cb cli_magic_scandesc

#define MAX_ZIP_REQUESTS 10
struct zip_requests {
    const char *names[MAX_ZIP_REQUESTS];
    size_t namelens[MAX_ZIP_REQUESTS];
    int namecnt;

    uint32_t loff;
    int found, match;
};

int cli_unzip(cli_ctx *);
int cli_unzip_single_internal(cli_ctx *, off_t, zip_cb);
int unzip_single_internal(cli_ctx *, off_t, zip_cb);
int cli_unzip_single(cli_ctx *, off_t);

int unzip_search_add(struct zip_requests *, const char *, size_t);
int unzip_search(cli_ctx *, fmap_t *, struct zip_requests *);
int unzip_search_single(cli_ctx *, const char *, size_t, uint32_t *);


#ifdef UNZIP_PRIVATE
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

#define SIZEOF_EH 12
#endif /* UNZIP_PRIVATE */

#endif /* __UNZIP_H */

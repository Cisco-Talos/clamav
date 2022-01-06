/*
 *  Copyright (C) 2013-2022 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
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

typedef cl_error_t (*zip_cb)(int fd, const char *filepath, cli_ctx *ctx, const char *name);
#define zip_scan_cb cli_magic_scan_desc

#define MAX_ZIP_REQUESTS 10
struct zip_requests {
    const char *names[MAX_ZIP_REQUESTS];
    size_t namelens[MAX_ZIP_REQUESTS];
    int namecnt;

    uint32_t loff;
    int found, match;
};

cl_error_t cli_unzip(cli_ctx *);
cl_error_t unzip_single_internal(cli_ctx *, off_t, zip_cb);
cl_error_t cli_unzip_single(cli_ctx *, off_t);

cl_error_t unzip_search_add(struct zip_requests *, const char *, size_t);
cl_error_t unzip_search(cli_ctx *, fmap_t *, struct zip_requests *);
cl_error_t unzip_search_single(cli_ctx *, const char *, size_t, uint32_t *);

// clang-format off
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
// clang-format on

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

/*
 * Local File Header format:
 */
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

/*
 * Local File Header convenience macros:
 */
// clang-format off
#define LOCAL_HEADER_magic   ((uint32_t)cli_readint32((uint8_t *)(local_header)+0))
#define LOCAL_HEADER_version ((uint16_t)cli_readint16((uint8_t *)(local_header)+4))
#define LOCAL_HEADER_flags   ((uint16_t)cli_readint16((uint8_t *)(local_header)+6))
#define LOCAL_HEADER_method  ((uint16_t)cli_readint16((uint8_t *)(local_header)+8))
#define LOCAL_HEADER_mtime   ((uint32_t)cli_readint32((uint8_t *)(local_header)+10))
#define LOCAL_HEADER_crc32   ((uint32_t)cli_readint32((uint8_t *)(local_header)+14))
#define LOCAL_HEADER_csize   ((uint32_t)cli_readint32((uint8_t *)(local_header)+18))
#define LOCAL_HEADER_usize   ((uint32_t)cli_readint32((uint8_t *)(local_header)+22))
#define LOCAL_HEADER_flen    ((uint16_t)cli_readint16((uint8_t *)(local_header)+26))
#define LOCAL_HEADER_elen    ((uint16_t)cli_readint16((uint8_t *)(local_header)+28))
#define SIZEOF_LOCAL_HEADER 30
// clang-format on

/*
 * Central Directory File Header format:
 */
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

/*
 * Central Directory File Header convenience macro's:
 */
// clang-format off
#define CENTRAL_HEADER_magic        ((uint32_t)cli_readint32((uint8_t *)(central_header)+0))
#define CENTRAL_HEADER_vermade      ((uint16_t)cli_readint16((uint8_t *)(central_header)+4))
#define CENTRAL_HEADER_verneed      ((uint16_t)cli_readint16((uint8_t *)(central_header)+6))
#define CENTRAL_HEADER_flags        ((uint16_t)cli_readint16((uint8_t *)(central_header)+8))
#define CENTRAL_HEADER_method       ((uint16_t)cli_readint16((uint8_t *)(central_header)+10))
#define CENTRAL_HEADER_mtime        ((uint32_t)cli_readint32((uint8_t *)(central_header)+12))
#define CENTRAL_HEADER_crc32        ((uint32_t)cli_readint32((uint8_t *)(central_header)+16))
#define CENTRAL_HEADER_csize        ((uint32_t)cli_readint32((uint8_t *)(central_header)+20))
#define CENTRAL_HEADER_usize        ((uint32_t)cli_readint32((uint8_t *)(central_header)+24))
#define CENTRAL_HEADER_flen         ((uint16_t)cli_readint16((uint8_t *)(central_header)+28))
#define CENTRAL_HEADER_extra_len    ((uint16_t)cli_readint16((uint8_t *)(central_header)+30))
#define CENTRAL_HEADER_comment_len  ((uint16_t)cli_readint16((uint8_t *)(central_header)+32))
#define CENTRAL_HEADER_disk_num     ((uint16_t)cli_readint16((uint8_t *)(central_header)+34))
#define CENTRAL_HEADER_iattrib      ((uint16_t)cli_readint16((uint8_t *)(central_header)+36))
#define CENTRAL_HEADER_eattrib      ((uint32_t)cli_readint32((uint8_t *)(central_header)+38))
#define CENTRAL_HEADER_off          ((uint32_t)cli_readint32((uint8_t *)(central_header)+42))
// clang-format on

#define SIZEOF_CENTRAL_HEADER 46
#define SIZEOF_ENCRYPTION_HEADER 12
#endif /* UNZIP_PRIVATE */

#endif /* __UNZIP_H */

/*
 *  Copyright (C) 2013-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
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

/*
 * General Structure for PKZIP files:
 * +---------------------------------------------------------------+
 * | Local file header 1                                           |
 * +---------------------------------------------------------------+
 * | File data 1                                                   |
 * +---------------------------------------------------------------+
 * | Data descriptor 1 (optional)                                  |
 * +---------------------------------------------------------------+
 * | Local file header 2                                           |
 * +---------------------------------------------------------------+
 * | File data 2                                                   |
 * +---------------------------------------------------------------+
 * | Data descriptor 2 (optional)                                  |
 * +---------------------------------------------------------------+
 * | ...                                                           |
 * +---------------------------------------------------------------+
 * | Local file header N                                           |
 * +---------------------------------------------------------------+
 * | File data N                                                   |
 * +---------------------------------------------------------------+
 * | Data descriptor N (optional)                                  |
 * +---------------------------------------------------------------+
 * | Archive Decryption Header (optional, v6.2+)                   |
 * +---------------------------------------------------------------+
 * | Archive Extra Data Record (optional, v6.2+)                   |
 * +---------------------------------------------------------------+
 * | Central directory                                             |
 * +---------------------------------------------------------------+
 *
 * This and additional diagrams from courtesy of:
 * https://users.cs.jmu.edu/buchhofp/forensics/formats/pkzip.html
 *
 * See also:
 * https://www.pkware.com/documents/casestudies/APPNOTE.TXT
 *
 * And see also: unzip.h
 *
 * Note the diagrams and current implemementation do not implement all features.
 */

#ifndef __UNZIP_H
#define __UNZIP_H

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include "others.h"

/**
 * @brief Callback function type for handling extracted files.
 *
 * The `unzip_single_internal` function lets you specify a callback function to handle the extracted file.
 * Other functions like `cli_unzip` and `cli_unzip_single` use `zip_scan_cb` as the default callback and
 * thus just scan the file.
 *
 * Note: The callback function must match the signature of `cli_magic_scan_desc`.
 */
typedef cl_error_t (*zip_cb)(int fd, const char *filepath, cli_ctx *ctx, const char *name, uint32_t attributes);
#define zip_scan_cb cli_magic_scan_desc

#define MAX_ZIP_REQUESTS 10

/**
 * @brief Structure to hold zip file search requests.
 *
 * This structure is used to hold multiple file names that we want to search for in a zip archive.
 * It is used by the `unzip_search` function.
 */
struct zip_requests {
    const char *names[MAX_ZIP_REQUESTS];
    size_t namelens[MAX_ZIP_REQUESTS];
    int namecnt;

    uint32_t loff;
    int found, match;
};

/**
 * @brief Unzip a zip file.
 *
 * Scan each extracted file.
 *
 * @param ctx                   The scan context containing the file map and other scan parameters.
 * @return cl_error_t           Returns CL_SUCCESS on success, or an error code on failure.
 */
cl_error_t cli_unzip(cli_ctx *ctx);

/**
 * @brief Unzip a single file from a zip archive.
 *
 * Scan the file after extracting it.
 *
 * @param ctx                   The scan context containing the file map and other scan parameters.
 * @param local_header_offset   The offset of the local file header in the zip archive.
 * @return cl_error_t           Returns CL_SUCCESS on success, or an error code on failure.
 */
cl_error_t cli_unzip_single(cli_ctx *ctx, size_t local_header_offset);

/**
 * @brief Verify a single local file header.
 *
 * Does not extract or scan the file.
 *
 * @param[in,out] ctx           Scan context
 * @param offset                Offset of the local file header
 * @param[out] size             Will be set to the size of the file header + file data.
 * @return cl_error_t           CL_SUCCESS on success, or an error code on failure.
 */
cl_error_t cli_unzip_single_header_check(cli_ctx *ctx, uint32_t offset, size_t *size);

/**
 * @brief Unzip a single file from a zip archive.
 *
 * Different from `cli_unzip_single`, this function allows for a custom callback to be used after extraction.
 * In other words, it can be used to extract a file without scanning it immediately.
 * This is useful for cases where you want to handle the file differently.
 *
 * @param ctx                   The scan context containing the file map and other scan parameters.
 * @param local_header_offset   The offset of the local file header in the zip archive.
 * @param zcb                   The callback function to invoke after extraction. See `zip_scan_cb`.
 * @return cl_error_t           Returns CL_SUCCESS on success, or an error code on failure.
 */
cl_error_t unzip_single_internal(cli_ctx *ctx, size_t local_header_offset, zip_cb zcb);

/**
 * @brief Add a file a bundle of files to search for in a zip archive.
 *
 * @param requests              The `zip_requests` structure to modify.
 * @param name                  The name of the file to add.
 * @param nlen                  The length of the file name.
 * @return cl_error_t           Returns CL_SUCCESS on success, or an error code on failure.
 */
cl_error_t unzip_search_add(struct zip_requests *requests, const char *name, size_t nlen);

/**
 * @brief Search for files in a zip archive.
 *
 * This function searches for one or more files in a zip archive and scans them.
 *
 * Disclaimer: As compared with `cli_unzip`, this function depends on the central directory header.
 *             It will not work correctly if the zip archive does not have a central directory header
 *             or the file you're looking for is not listed in the central directory.
 *
 * @param ctx                   The scan context containing the file map and other scan parameters.
 * @param requests              The `zip_requests` structure containing the files to search for.
 * @return cl_error_t           Returns CL_SUCCESS if nothing was found.
 *                              Returns CL_VIRUS if a match was found.
 *                              Returns a CL_E* error code on failure.
 */
cl_error_t unzip_search(cli_ctx *ctx, struct zip_requests *requests);

/**
 * @brief Search for a single file in a zip archive.
 *
 * This function searches for a single file in a zip archive.
 *
 * Disclaimer: As compared with `cli_unzip`, this function depends on the central directory header.
 *             It will not work correctly if the zip archive does not have a central directory header
 *             or the file you're looking for is not listed in the central directory.
 *
 * @param ctx                   The scan context containing the file map and other scan parameters.
 * @param name                  The name of the file to search for.
 * @param nlen                  The length of the file name.
 * @param loff                  The offset of the file in the zip archive.
 * @return cl_error_t           Returns CL_SUCCESS if nothing was found.
 *                              Returns CL_VIRUS if a match was found.
 *                              Returns a CL_E* error code on failure.
 */
cl_error_t unzip_search_single(cli_ctx *ctx, const char *name, size_t nlen, uint32_t *loff);

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
 * Local File Header Structure:
 *
 *  0x0 0x1 0x2 0x3 0x4 0x5 0x6 0x7 0x8 0x9 0xa 0xb 0xc 0xd 0xe 0xf
 * +---------------+-------+-------+-------+-------+-------+-------+
 * | P K 0x03 0x04 | Vers  | Flags | Compr |Mod Tm |Mod Dt | CRC 32|
 * +-------+-------+-------+-------+-------+-------+-------+-------+
 * | CRC 32| Compr Size    | Uncompr Size  |FName L|Extra L|       |
 * +-------+---------------+---------------+-------+-------+       +
 * | File Name (variable)                                          |
 * +---------------------------------------------------------------+
 * | Extra field (variable)                                        |
 * +---------------------------------------------------------------+
 */

// struct LH {
//   uint32_t magic;
//   uint16_t version;
//   uint16_t flags;
//   uint16_t method;
//   uint32_t mtime;
//   uint32_t crc32;
//   uint32_t csize;
//   uint32_t usize;
//   uint16_t flen;
//   uint16_t elen;
//   char fname[flen]
//   char extra[elen]
// } __attribute__((packed));

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
 * Central Directory Structure:
 *
 * +---------------------------------------------------------------+
 * | Central directory file header 1                               |
 * +---------------------------------------------------------------+
 * | Central directory file header 2                               |
 * +---------------------------------------------------------------+
 * | ...                                                           |
 * +---------------------------------------------------------------+
 * | Central directory file header N                               |
 * +---------------------------------------------------------------+
 * | Digital Signature                                             |
 * +---------------------------------------------------------------+
 * | Data descriptor N (optional)                                  |
 * +---------------------------------------------------------------+
 * | Zip64 end of central directory Record                         |
 * +---------------------------------------------------------------+
 * | Zip64 end of central directory locator                        |
 * +---------------------------------------------------------------+
 * | End of central directory record                               |
 * +---------------------------------------------------------------+
 *
 * Central Directory File Header structure:
 *
 *  0x0 0x1 0x2 0x3 0x4 0x5 0x6 0x7 0x8 0x9 0xa 0xb 0xc 0xd 0xe 0xf
 * +---------------+-------+-------+-------+-------+-------+-------+
 * | P K 0x01 0x02 | Vers  |Vers Nd| Flags | Compr |Mod Tm |Mod Dt |
 * +---------------+-------+-------+-------+-------+-------+-------+
 * | CRC 32        | Compr Size    | Uncompr Size  |FName L|Extra L|
 * +---------------+-------+-------+-------+-------+-------+-------+
 * |F Com L|D #strt|IntAttr|Ext Attributes |Offset L Header|       |
 * +---------------+-----------------------+---------------+       +
 * | File Name (variable)                                          |
 * +---------------------------------------------------------------+
 * | Extra field (variable)                                        |
 * +---------------------------------------------------------------+
 * | File comment (variable)                                       |
 * +---------------------------------------------------------------+
 *
 * End of central directory record structure:
 *
 *  0x0 0x1 0x2 0x3 0x4 0x5 0x6 0x7 0x8 0x9 0xa 0xb 0xc 0xd 0xe 0xf
 * +---------------+-------+-------+-------+-------+---------------+
 * | P K 0x05 0x06 |Disk # |Dsk#cd |DskEnts|T.Entrs|Central Dir Sz |
 * +---------------+-------+-------+-------+-------+---------------+
 * | Offset of CD  |CommLen| ZIP file comment (variable)           |
 * +---------------+-------+-------+-------+-------+-------+-------+
 */

// struct CH {
//   uint32_t magic;
//   uint16_t vermade;
//   uint16_t verneed;
//   uint16_t flags;
//   uint16_t method;
//   uint32_t mtime;
//   uint32_t crc32;
//   uint32_t csize;
//   uint32_t usize;
//   uint16_t flen;
//   uint16_t elen;
//   uint16_t clen;
//   uint16_t dsk;
//   uint16_t iattrib;
//   uint32_t eattrib;
//   uint32_t off;
//   char fname[flen]
//   char extra[elen]
//   char comment[clen]
// } __attribute__((packed));

/*
 * Central Directory File Header convenience macro's.
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

#define SIZEOF_CENTRAL_HEADER 46    // Excluding variable size fields
#define SIZEOF_ENCRYPTION_HEADER 12 // Excluding variable size fields
#define SIZEOF_END_OF_CENTRAL 22    // Excluding variable size fields

#endif /* UNZIP_PRIVATE */

#endif /* __UNZIP_H */

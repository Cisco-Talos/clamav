/*
 *  Copyright (C) 2013-2021 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
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
#include "str.h"

#define UNZIP_PRIVATE
#include "unzip.h"

// clang-format off
#define ZIP_MAGIC_CENTRAL_DIRECTORY_RECORD_BEGIN    (0x02014b50)
#define ZIP_MAGIC_CENTRAL_DIRECTORY_RECORD_END      (0x06054b50)
#define ZIP_MAGIC_LOCAL_FILE_HEADER                 (0x04034b50)
#define ZIP_MAGIC_FILE_BEGIN_SPLIT_OR_SPANNED       (0x08074b50)
// clang-format on

#define ZIP_MAX_NUM_OVERLAPPING_FILES 5

#define ZIP_CRC32(r, c, b, l) \
    do {                      \
        r = crc32(~c, b, l);  \
        r = ~r;               \
    } while (0)

#define ZIP_RECORDS_CHECK_BLOCKSIZE 100
struct zip_record {
    uint32_t local_header_offset;
    uint32_t local_header_size;
    uint32_t compressed_size;
    uint32_t uncompressed_size;
    uint16_t method;
    uint16_t flags;
    int encrypted;
    char *original_filename;
};

static int wrap_inflateinit2(void *a, int b)
{
    return inflateInit2(a, b);
}

/**
 * @brief uncompress file from zip
 *
 * @param src                           pointer to compressed data
 * @param csize                         size of compressed data
 * @param usize                         expected size of uncompressed data
 * @param method                        compression method
 * @param flags                         local header flags
 * @param[in,out] num_files_unzipped    current number of files that have been unzipped
 * @param[in,out] ctx                   scan context
 * @param tmpd                          temp directory path name
 * @param zcb                           callback function to invoke after extraction (default: scan)
 * @return cl_error_t                   CL_EPARSE = could not apply a password
 */
static cl_error_t unz(
    const uint8_t *src,
    uint32_t csize,
    uint32_t usize,
    uint16_t method,
    uint16_t flags,
    unsigned int *num_files_unzipped,
    cli_ctx *ctx,
    char *tmpd,
    zip_cb zcb,
    const char *original_filename)
{
    char obuf[BUFSIZ];
    char *tempfile = NULL;
    int out_file, ret = CL_CLEAN;
    int res        = 1;
    size_t written = 0;

    if (tmpd) {
        if (ctx->engine->keeptmp && (NULL != original_filename)) {
            if (!(tempfile = cli_gentemp_with_prefix(tmpd, original_filename))) return CL_EMEM;
        } else {
            if (!(tempfile = cli_gentemp(tmpd))) return CL_EMEM;
        }
    } else {
        if (ctx->engine->keeptmp && (NULL != original_filename)) {
            if (!(tempfile = cli_gentemp_with_prefix(ctx->sub_tmpdir, original_filename))) return CL_EMEM;
        } else {
            if (!(tempfile = cli_gentemp(ctx->sub_tmpdir))) return CL_EMEM;
        }
    }
    if ((out_file = open(tempfile, O_RDWR | O_CREAT | O_TRUNC | O_BINARY, S_IRUSR | S_IWUSR)) == -1) {
        cli_warnmsg("cli_unzip: failed to create temporary file %s\n", tempfile);
        free(tempfile);
        return CL_ETMPFILE;
    }
    switch (method) {
        case ALG_STORED:
            if (csize < usize) {
                unsigned int fake = *num_files_unzipped + 1;
                cli_dbgmsg("cli_unzip: attempting to inflate stored file with inconsistent size\n");
                if ((ret = unz(src, csize, usize, ALG_DEFLATE, 0, &fake, ctx, tmpd, zcb, original_filename)) == CL_CLEAN) {
                    (*num_files_unzipped)++;
                    res = fake - (*num_files_unzipped);
                } else
                    break;
            }
            if (res == 1) {
                if (ctx->engine->maxfilesize && csize > ctx->engine->maxfilesize) {
                    cli_dbgmsg("cli_unzip: trimming output size to maxfilesize (%lu)\n", (long unsigned int)ctx->engine->maxfilesize);
                    csize = ctx->engine->maxfilesize;
                }
                if (cli_writen(out_file, src, csize) != csize)
                    ret = CL_EWRITE;
                else
                    res = 0;
            }
            break;

        case ALG_DEFLATE:
        case ALG_DEFLATE64: {
            union {
                z_stream64 strm64;
                z_stream strm;
            } strm;
            typedef int (*unz_init_)(void *, int);
            typedef int (*unz_unz_)(void *, int);
            typedef int (*unz_end_)(void *);
            unz_init_ unz_init;
            unz_unz_ unz_unz;
            unz_end_ unz_end;
            int wbits;
            void **next_in;
            void **next_out;
            unsigned int *avail_in;
            unsigned int *avail_out;

            if (method == ALG_DEFLATE64) {
                unz_init  = (unz_init_)inflate64Init2;
                unz_unz   = (unz_unz_)inflate64;
                unz_end   = (unz_end_)inflate64End;
                next_in   = (void *)&strm.strm64.next_in;
                next_out  = (void *)&strm.strm64.next_out;
                avail_in  = &strm.strm64.avail_in;
                avail_out = &strm.strm64.avail_out;
                wbits     = MAX_WBITS64;
            } else {
                unz_init  = (unz_init_)wrap_inflateinit2;
                unz_unz   = (unz_unz_)inflate;
                unz_end   = (unz_end_)inflateEnd;
                next_in   = (void *)&strm.strm.next_in;
                next_out  = (void *)&strm.strm.next_out;
                avail_in  = &strm.strm.avail_in;
                avail_out = &strm.strm.avail_out;
                wbits     = MAX_WBITS;
            }

            memset(&strm, 0, sizeof(strm));

            *next_in   = (void *)src;
            *next_out  = obuf;
            *avail_in  = csize;
            *avail_out = sizeof(obuf);
            if (unz_init(&strm, -wbits) != Z_OK) {
                cli_dbgmsg("cli_unzip: zinit failed\n");
                break;
            }
            while (1) {
                while ((res = unz_unz(&strm, Z_NO_FLUSH)) == Z_OK) {
                };
                if (*avail_out != sizeof(obuf)) {
                    written += sizeof(obuf) - (*avail_out);
                    if (ctx->engine->maxfilesize && written > ctx->engine->maxfilesize) {
                        cli_dbgmsg("cli_unzip: trimming output size to maxfilesize (%lu)\n", (long unsigned int)ctx->engine->maxfilesize);
                        res = Z_STREAM_END;
                        break;
                    }
                    if (cli_writen(out_file, obuf, sizeof(obuf) - (*avail_out)) != (size_t)(sizeof(obuf) - (*avail_out))) {
                        cli_warnmsg("cli_unzip: falied to write %lu inflated bytes\n", (unsigned long int)sizeof(obuf) - (*avail_out));
                        ret = CL_EWRITE;
                        res = 100;
                        break;
                    }
                    *next_out  = obuf;
                    *avail_out = sizeof(obuf);
                    continue;
                }
                break;
            }
            unz_end(&strm);
            if ((res == Z_STREAM_END) | (res == Z_BUF_ERROR)) res = 0;
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
            strm.next_in   = (char *)src;
            strm.next_out  = obuf;
            strm.avail_in  = csize;
            strm.avail_out = sizeof(obuf);
            if (BZ2_bzDecompressInit(&strm, 0, 0) != BZ_OK) {
                cli_dbgmsg("cli_unzip: bzinit failed\n");
                break;
            }
            while ((res = BZ2_bzDecompress(&strm)) == BZ_OK || res == BZ_STREAM_END) {
                if (strm.avail_out != sizeof(obuf)) {
                    written += sizeof(obuf) - strm.avail_out;
                    if (ctx->engine->maxfilesize && written > ctx->engine->maxfilesize) {
                        cli_dbgmsg("cli_unzip: trimming output size to maxfilesize (%lu)\n", (unsigned long int)ctx->engine->maxfilesize);
                        res = BZ_STREAM_END;
                        break;
                    }
                    if (cli_writen(out_file, obuf, sizeof(obuf) - strm.avail_out) != (size_t)(sizeof(obuf) - strm.avail_out)) {
                        cli_warnmsg("cli_unzip: falied to write %lu bunzipped bytes\n", (long unsigned int)sizeof(obuf) - strm.avail_out);
                        ret = CL_EWRITE;
                        res = 100;
                        break;
                    }
                    strm.next_out  = obuf;
                    strm.avail_out = sizeof(obuf);
                    if (res == BZ_OK) continue; /* after returning BZ_STREAM_END once, decompress returns an error */
                }
                break;
            }
            BZ2_bzDecompressEnd(&strm);
            if (res == BZ_STREAM_END) res = 0;
            break;
        }
#endif /* HAVE_BZLIB_H */

        case ALG_IMPLODE: {
            struct xplstate strm;
            strm.next_in   = (void *)src;
            strm.next_out  = (uint8_t *)obuf;
            strm.avail_in  = csize;
            strm.avail_out = sizeof(obuf);
            if (explode_init(&strm, flags) != EXPLODE_OK) {
                cli_dbgmsg("cli_unzip: explode_init() failed\n");
                break;
            }
            while ((res = explode(&strm)) == EXPLODE_OK) {
                if (strm.avail_out != sizeof(obuf)) {
                    written += sizeof(obuf) - strm.avail_out;
                    if (ctx->engine->maxfilesize && written > ctx->engine->maxfilesize) {
                        cli_dbgmsg("cli_unzip: trimming output size to maxfilesize (%lu)\n", (unsigned long int)ctx->engine->maxfilesize);
                        res = 0;
                        break;
                    }
                    if (cli_writen(out_file, obuf, sizeof(obuf) - strm.avail_out) != (size_t)(sizeof(obuf) - strm.avail_out)) {
                        cli_warnmsg("cli_unzip: falied to write %lu exploded bytes\n", (unsigned long int)sizeof(obuf) - strm.avail_out);
                        ret = CL_EWRITE;
                        res = 100;
                        break;
                    }
                    strm.next_out  = (uint8_t *)obuf;
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

    if (!res) {
        (*num_files_unzipped)++;
        cli_dbgmsg("cli_unzip: extracted to %s\n", tempfile);
        if (lseek(out_file, 0, SEEK_SET) == -1) {
            cli_dbgmsg("cli_unzip: call to lseek() failed\n");
            free(tempfile);
            close(out_file);
            return CL_ESEEK;
        }
        ret = zcb(out_file, tempfile, ctx, original_filename);
        close(out_file);
        if (!ctx->engine->keeptmp)
            if (cli_unlink(tempfile)) ret = CL_EUNLINK;
        free(tempfile);
        return ret;
    }

    close(out_file);
    if (!ctx->engine->keeptmp)
        if (cli_unlink(tempfile)) ret = CL_EUNLINK;
    free(tempfile);
    cli_dbgmsg("cli_unzip: extraction failed\n");
    return ret;
}

/* zip update keys, taken from zip specification */
static inline void zupdatekey(uint32_t key[3], unsigned char input)
{
    unsigned char tmp[1];

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

/**
 * @brief zip decrypt.
 *
 * TODO - search for strong encryption header (0x0017) and handle them
 *
 * @param src
 * @param csize                         size of compressed data; includes the decryption header
 * @param usize                         expected size of uncompressed data
 * @param local_header
 * @param[in,out] num_files_unzipped    current number of files that have been unzipped
 * @param[in,out] ctx                   scan context
 * @param tmpd                          temp directory path name
 * @param zcb                           callback function to invoke after extraction (default: scan)
 * @return cl_error_t                   CL_EPARSE = could not apply a password
 */
static inline cl_error_t zdecrypt(
    const uint8_t *src,
    uint32_t csize,
    uint32_t usize,
    const uint8_t *local_header,
    unsigned int *num_files_unzipped,
    cli_ctx *ctx,
    char *tmpd,
    zip_cb zcb,
    const char *original_filename)
{
    cl_error_t ret;
    int v = 0;
    uint32_t i;
    uint32_t key[3];
    uint8_t encryption_header[12]; /* encryption header buffer */
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
        memcpy(encryption_header, src, SIZEOF_ENCRYPTION_HEADER);

        for (i = 0; i < SIZEOF_ENCRYPTION_HEADER; i++) {
            encryption_header[i] ^= zdecryptbyte(key);
            zupdatekey(key, encryption_header[i]);
        }

        /* verify that the password is correct */
        if (LOCAL_HEADER_version > 20) { /* higher than 2.0 */
            uint16_t a = encryption_header[SIZEOF_ENCRYPTION_HEADER - 1];

            if (LOCAL_HEADER_flags & F_USEDD) {
                cli_dbgmsg("cli_unzip: decrypt - (v%u) >> 0x%02x 0x%x (moddate)\n", LOCAL_HEADER_version, a, LOCAL_HEADER_mtime);
                if (a == ((LOCAL_HEADER_mtime >> 8) & 0xff))
                    v = 1;
            } else {
                cli_dbgmsg("cli_unzip: decrypt - (v%u) >> 0x%02x 0x%x (crc32)\n", LOCAL_HEADER_version, a, LOCAL_HEADER_crc32);
                if (a == ((LOCAL_HEADER_crc32 >> 24) & 0xff))
                    v = 1;
            }
        } else {
            uint16_t a = encryption_header[SIZEOF_ENCRYPTION_HEADER - 1], b = encryption_header[SIZEOF_ENCRYPTION_HEADER - 2];

            if (LOCAL_HEADER_flags & F_USEDD) {
                cli_dbgmsg("cli_unzip: decrypt - (v%u) >> 0x0000%02x%02x 0x%x (moddate)\n", LOCAL_HEADER_version, a, b, LOCAL_HEADER_mtime);
                if ((uint32_t)(b | (a << 8)) == (LOCAL_HEADER_mtime & 0xffff))
                    v = 1;
            } else {
                cli_dbgmsg("cli_unzip: decrypt - (v%u) >> 0x0000%02x%02x 0x%x (crc32)\n", LOCAL_HEADER_version, encryption_header[SIZEOF_ENCRYPTION_HEADER - 1], encryption_header[SIZEOF_ENCRYPTION_HEADER - 2], LOCAL_HEADER_crc32);
                if ((uint32_t)(b | (a << 8)) == ((LOCAL_HEADER_crc32 >> 16) & 0xffff))
                    v = 1;
            }
        }

        if (v) {
            char name[1024], obuf[BUFSIZ];
            char *tempfile = name;
            size_t written = 0, total = 0;
            fmap_t *dcypt_map;
            const uint8_t *dcypt_zip;
            int out_file;

            cli_dbgmsg("cli_unzip: decrypt - password [%s] matches\n", password->name);

            /* output decrypted data to tempfile */
            if (tmpd) {
                snprintf(name, sizeof(name), "%s" PATHSEP "zip.decrypt.%03u", tmpd, *num_files_unzipped);
                name[sizeof(name) - 1] = '\0';
            } else {
                if (!(tempfile = cli_gentemp_with_prefix(ctx->sub_tmpdir, "zip-decrypt"))) return CL_EMEM;
            }
            if ((out_file = open(tempfile, O_RDWR | O_CREAT | O_TRUNC | O_BINARY, S_IRUSR | S_IWUSR)) == -1) {
                cli_warnmsg("cli_unzip: decrypt - failed to create temporary file %s\n", tempfile);
                if (!tmpd) free(tempfile);
                return CL_ETMPFILE;
            }

            for (i = 12; i < csize; i++) {
                obuf[written] = src[i] ^ zdecryptbyte(key);
                zupdatekey(key, obuf[written]);

                written++;
                if (written >= BUFSIZ) {
                    if (cli_writen(out_file, obuf, written) != written) {
                        ret = CL_EWRITE;
                        goto zd_clean;
                    }
                    total += written;
                    written = 0;
                }
            }
            if (written) {
                if (cli_writen(out_file, obuf, written) != written) {
                    ret = CL_EWRITE;
                    goto zd_clean;
                }
                total += written;
                written = 0;
            }

            cli_dbgmsg("cli_unzip: decrypt - decrypted %zu bytes to %s\n", total, tempfile);

            /* decrypt data to new fmap -> buffer */
            if (!(dcypt_map = fmap(out_file, 0, total, NULL))) {
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
            ret = unz(dcypt_zip, csize - SIZEOF_ENCRYPTION_HEADER, usize, LOCAL_HEADER_method, LOCAL_HEADER_flags, num_files_unzipped, ctx, tmpd, zcb, original_filename);

            /* clean-up and return */
            funmap(dcypt_map);
        zd_clean:
            close(out_file);
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

/**
 * @brief Parse, extract, and scan a file using the local file header.
 *
 * Usage of the `record` parameter will alter behavior so it only collect file record metadata and does not extract or scan any files.
 *
 * @param map                           fmap for the file
 * @param loff                          offset of the local file header
 * @param zsize                         size of the zip file
 * @param[in,out] num_files_unzipped    current number of files that have been unzipped
 * @param file_count                    current number of files that have been discovered
 * @param central_header                offset of central directory header
 * @param[out] ret                      The status code
 * @param[in,out] ctx                   scan context
 * @param tmpd                          temp directory path name
 * @param detect_encrypted              bool: if encrypted files should raise heuristic alert
 * @param zcb                           callback function to invoke after extraction (default: scan)
 * @param record                        (optional) a pointer to a struct to store file record information.
 * @return unsigned int                 returns the size of the file header + file data, so zip file can be indexed without the central directory
 */
static unsigned int parse_local_file_header(
    fmap_t *map,
    uint32_t loff,
    uint32_t zsize,
    unsigned int *num_files_unzipped,
    unsigned int file_count,
    const uint8_t *central_header, /* pointer to central header. */
    cl_error_t *ret,
    cli_ctx *ctx,
    char *tmpd,
    int detect_encrypted,
    zip_cb zcb,
    struct zip_record *record)
{
    const uint8_t *local_header, *zip;
    char name[256];
    char *original_filename = NULL;
    uint32_t csize, usize;
    int virus_found                          = 0;
    unsigned int size_of_fileheader_and_data = 0;

    if (!(local_header = fmap_need_off(map, loff, SIZEOF_LOCAL_HEADER))) {
        cli_dbgmsg("cli_unzip: local header - out of file\n");
        goto done;
    }
    if (LOCAL_HEADER_magic != ZIP_MAGIC_LOCAL_FILE_HEADER) {
        if (!central_header)
            cli_dbgmsg("cli_unzip: local header - wrkcomplete\n");
        else
            cli_dbgmsg("cli_unzip: local header - bad magic\n");
        fmap_unneed_off(map, loff, SIZEOF_LOCAL_HEADER);
        goto done;
    }

    zip = local_header + SIZEOF_LOCAL_HEADER;
    zsize -= SIZEOF_LOCAL_HEADER;

    if (zsize <= LOCAL_HEADER_flen) {
        cli_dbgmsg("cli_unzip: local header - fname out of file\n");
        fmap_unneed_off(map, loff, SIZEOF_LOCAL_HEADER);
        goto done;
    }
    if (ctx->engine->cdb || cli_debug_flag || ctx->engine->keeptmp || ctx->options->general & CL_SCAN_GENERAL_COLLECT_METADATA) {
        uint32_t nsize = (LOCAL_HEADER_flen >= sizeof(name)) ? sizeof(name) - 1 : LOCAL_HEADER_flen;
        const char *src;
        if (nsize && (src = fmap_need_ptr_once(map, zip, nsize))) {
            memcpy(name, zip, nsize);
            name[nsize] = '\0';
            if (CL_SUCCESS != cli_basename(name, nsize, &original_filename)) {
                original_filename = NULL;
            }
        } else
            name[0] = '\0';
    }
    zip += LOCAL_HEADER_flen;
    zsize -= LOCAL_HEADER_flen;

    cli_dbgmsg("cli_unzip: local header - ZMDNAME:%d:%s:%u:%u:%x:%u:%u:%u\n",
               ((LOCAL_HEADER_flags & F_ENCR) != 0), name, LOCAL_HEADER_usize, LOCAL_HEADER_csize, LOCAL_HEADER_crc32, LOCAL_HEADER_method, file_count, ctx->recursion_level);
    /* ZMDfmt virname:encrypted(0-1):filename(exact|*):usize(exact|*):csize(exact|*):crc32(exact|*):method(exact|*):fileno(exact|*):maxdepth(exact|*) */

    /* Scan file header metadata. */
    if (cli_matchmeta(ctx, name, LOCAL_HEADER_csize, LOCAL_HEADER_usize, (LOCAL_HEADER_flags & F_ENCR) != 0, file_count, LOCAL_HEADER_crc32, NULL) == CL_VIRUS) {
        *ret = CL_VIRUS;
        if (!SCAN_ALLMATCHES)
            goto done;
        virus_found = 1;
    }

    if (LOCAL_HEADER_flags & F_MSKED) {
        cli_dbgmsg("cli_unzip: local header - header has got unusable masked data\n");
        /* FIXME: need to find/craft a sample */
        fmap_unneed_off(map, loff, SIZEOF_LOCAL_HEADER);
        goto done;
    }

    if (detect_encrypted && (LOCAL_HEADER_flags & F_ENCR) && SCAN_HEURISTIC_ENCRYPTED_ARCHIVE) {
        cli_dbgmsg("cli_unzip: Encrypted files found in archive.\n");
        *ret = cli_append_virus(ctx, "Heuristics.Encrypted.Zip");
        if ((*ret == CL_VIRUS && !SCAN_ALLMATCHES) || *ret != CL_CLEAN) {
            fmap_unneed_off(map, loff, SIZEOF_LOCAL_HEADER);
            goto done;
        }
        virus_found = 1;
    }

    if (LOCAL_HEADER_flags & F_USEDD) {
        cli_dbgmsg("cli_unzip: local header - has data desc\n");
        if (!central_header) {
            fmap_unneed_off(map, loff, SIZEOF_LOCAL_HEADER);
            goto done;
        } else {
            usize = CENTRAL_HEADER_usize;
            csize = CENTRAL_HEADER_csize;
        }
    } else {
        usize = LOCAL_HEADER_usize;
        csize = LOCAL_HEADER_csize;
    }

    if (zsize <= LOCAL_HEADER_elen) {
        cli_dbgmsg("cli_unzip: local header - extra out of file\n");
        fmap_unneed_off(map, loff, SIZEOF_LOCAL_HEADER);
        goto done;
    }
    zip += LOCAL_HEADER_elen;
    zsize -= LOCAL_HEADER_elen;

    if (!csize) { /* FIXME: what's used for method0 files? csize or usize? Nothing in the specs, needs testing */
        cli_dbgmsg("cli_unzip: local header - skipping empty file\n");
    } else {
        if (zsize < csize) {
            cli_dbgmsg("cli_unzip: local header - stream out of file\n");
            fmap_unneed_off(map, loff, SIZEOF_LOCAL_HEADER);
            goto done;
        }

        /* Don't actually unzip if we're just collecting the file record information (offset, sizes) */
        if (NULL == record) {
            if (LOCAL_HEADER_flags & F_ENCR) {
                if (fmap_need_ptr_once(map, zip, csize))
                    *ret = zdecrypt(zip, csize, usize, local_header, num_files_unzipped, ctx, tmpd, zcb, original_filename);
            } else {
                if (fmap_need_ptr_once(map, zip, csize))
                    *ret = unz(zip, csize, usize, LOCAL_HEADER_method, LOCAL_HEADER_flags, num_files_unzipped, ctx, tmpd, zcb, original_filename);
            }
        } else {
            if ((NULL == original_filename) ||
                (CL_SUCCESS != cli_basename(original_filename, strlen(original_filename), &record->original_filename))) {
                record->original_filename = NULL;
            }
            record->local_header_offset = loff;
            record->local_header_size   = zip - local_header;
            record->compressed_size     = csize;
            record->uncompressed_size   = usize;
            record->method              = LOCAL_HEADER_method;
            record->flags               = LOCAL_HEADER_flags;
            record->encrypted           = (LOCAL_HEADER_flags & F_ENCR) ? 1 : 0;
        }

        zip += csize;
        zsize -= csize;
    }

    fmap_unneed_off(map, loff, SIZEOF_LOCAL_HEADER); /* unneed now. block is guaranteed to exists till the next need */
    if (LOCAL_HEADER_flags & F_USEDD) {
        if (zsize < 12) {
            cli_dbgmsg("cli_unzip: local header - data desc out of file\n");
            goto done;
        }
        zsize -= 12;
        if (fmap_need_ptr_once(map, zip, 4)) {
            if (cli_readint32(zip) == ZIP_MAGIC_FILE_BEGIN_SPLIT_OR_SPANNED) {
                if (zsize < 4) {
                    cli_dbgmsg("cli_unzip: local header - data desc out of file\n");
                    goto done;
                }
                zip += 4;
            }
        }
        zip += 12;
    }

    /* Success */
    size_of_fileheader_and_data = zip - local_header;

done:
    if (NULL != original_filename) {
        free(original_filename);
    }

    if ((NULL != ret) && (0 != virus_found))
        *ret = CL_VIRUS;

    return size_of_fileheader_and_data;
}

/**
 * @brief Parse, extract, and scan a file by iterating the central directory.
 *
 * Usage of the `record` parameter will alter behavior so it only collect file record metadata and does not extract or scan any files.
 *
 * @param map                           fmap for the file
 * @param coff                          offset of the file header in the central directory
 * @param zsize                         size of the zip file
 * @param[in,out] num_files_unzipped    current number of files that have been unzipped
 * @param file_count                    current number of files that have been discovered
 * @param[out] ret                      The status code
 * @param[in,out] ctx                   scan context
 * @param tmpd                          temp directory path name
 * @param requests                      (optional) structure use to search the zip for files by name
 * @param record                        (optional) a pointer to a struct to store file record information.
 * @return unsigned int                 returns the size of the file header in the central directory, or 0 if no more files
 */
static unsigned int
parse_central_directory_file_header(
    fmap_t *map,
    uint32_t coff,
    uint32_t zsize,
    unsigned int *num_files_unzipped,
    unsigned int file_count,
    cl_error_t *ret,
    cli_ctx *ctx,
    char *tmpd,
    struct zip_requests *requests,
    struct zip_record *record)
{
    char name[256];
    int last                      = 0;
    const uint8_t *central_header = NULL;
    int virus_found               = 0;

    if (!(central_header = fmap_need_off(map, coff, SIZEOF_CENTRAL_HEADER)) || CENTRAL_HEADER_magic != ZIP_MAGIC_CENTRAL_DIRECTORY_RECORD_BEGIN) {
        if (central_header) {
            fmap_unneed_ptr(map, central_header, SIZEOF_CENTRAL_HEADER);
            central_header = NULL;
        }
        cli_dbgmsg("cli_unzip: central header - wrkcomplete\n");
        last = 1;
        goto done;
    }
    coff += SIZEOF_CENTRAL_HEADER;

    cli_dbgmsg("cli_unzip: central header - flags %x - method %x - csize %x - usize %x - flen %x - elen %x - clen %x - disk %x - off %x\n",
               CENTRAL_HEADER_flags, CENTRAL_HEADER_method, CENTRAL_HEADER_csize, CENTRAL_HEADER_usize, CENTRAL_HEADER_flen, CENTRAL_HEADER_extra_len, CENTRAL_HEADER_comment_len, CENTRAL_HEADER_disk_num, CENTRAL_HEADER_off);

    if (zsize - coff <= CENTRAL_HEADER_flen) {
        cli_dbgmsg("cli_unzip: central header - fname out of file\n");
        last = 1;
        goto done;
    }

    name[0] = '\0';
    if (!last) {
        unsigned int size = (CENTRAL_HEADER_flen >= sizeof(name)) ? sizeof(name) - 1 : CENTRAL_HEADER_flen;
        const char *src   = fmap_need_off_once(map, coff, size);
        if (src) {
            memcpy(name, src, size);
            name[size] = '\0';
            cli_dbgmsg("cli_unzip: central header - fname: %s\n", name);
        }
    }
    coff += CENTRAL_HEADER_flen;

    /* requests do not supply a ctx; also prevent multiple scans */
    if (ctx && (CL_VIRUS == cli_matchmeta(ctx, name, CENTRAL_HEADER_csize, CENTRAL_HEADER_usize, (CENTRAL_HEADER_flags & F_ENCR) != 0, file_count, CENTRAL_HEADER_crc32, NULL))) {
        virus_found = 1;

        if (!SCAN_ALLMATCHES) {
            last = 1;
            goto done;
        }
    }

    if (zsize - coff <= CENTRAL_HEADER_extra_len && !last) {
        cli_dbgmsg("cli_unzip: central header - extra out of file\n");
        last = 1;
    }
    coff += CENTRAL_HEADER_extra_len;

    if (zsize - coff < CENTRAL_HEADER_comment_len && !last) {
        cli_dbgmsg("cli_unzip: central header - comment out of file\n");
        last = 1;
    }
    coff += CENTRAL_HEADER_comment_len;

    if (!requests) {
        if (CENTRAL_HEADER_off < zsize - SIZEOF_LOCAL_HEADER) {
            parse_local_file_header(map,
                                    CENTRAL_HEADER_off,
                                    zsize - CENTRAL_HEADER_off,
                                    num_files_unzipped,
                                    file_count,
                                    central_header,
                                    ret,
                                    ctx,
                                    tmpd,
                                    1,
                                    zip_scan_cb,
                                    record);
        } else {
            cli_dbgmsg("cli_unzip: central header - local hdr out of file\n");
        }
    } else {
        int i;
        size_t len;

        if (!last) {
            for (i = 0; i < requests->namecnt; ++i) {
                cli_dbgmsg("cli_unzip: central header - checking for %i: %s\n", i, requests->names[i]);

                len = MIN(sizeof(name) - 1, requests->namelens[i]);
                if (!strncmp(requests->names[i], name, len)) {
                    requests->match = 1;
                    requests->found = i;
                    requests->loff  = CENTRAL_HEADER_off;
                }
            }
        }
    }

done:
    if (virus_found == 1)
        *ret = CL_VIRUS;

    if (NULL != central_header) {
        fmap_unneed_ptr(map, central_header, SIZEOF_CENTRAL_HEADER);
    }

    return (last ? 0 : coff);
}

/**
 * @brief Sort zip_record structures based on local file offset.
 *
 * @param first
 * @param second
 * @return int 1 if first record's offset is higher than second's.
 * @return int 0 if first and second record offsets are equal.
 * @return int -1 if first record's offset is less than second's.
 */
static int sort_by_file_offset(const void *first, const void *second)
{
    const struct zip_record *a = (const struct zip_record *)first;
    const struct zip_record *b = (const struct zip_record *)second;

    /* Avoid return x - y, which can cause undefined behaviour
       because of signed integer overflow. */
    if (a->local_header_offset < b->local_header_offset)
        return -1;
    else if (a->local_header_offset > b->local_header_offset)
        return 1;

    return 0;
}

/**
 * @brief Create a catalogue of the central directory.
 *
 * This function indexes every file in the central directory.
 * It creates a zip record catalogue and sorts them by file entry offset.
 * Then it iterates the sorted file records looking for overlapping files.
 *
 * The caller is responsible for freeing the catalogue.
 * The catalogue may contain duplicate items, which should be skipped.
 *
 * @param ctx               The scanning context
 * @param map               The file map
 * @param fsize             The file size
 * @param coff              The central directory offset
 * @param[out] catalogue    A catalogue of zip_records found in the central directory.
 * @param[out] num_records  The number of records in the catalogue.
 * @return cl_error_t  CL_CLEAN if no overlapping files
 * @return cl_error_t  CL_VIRUS if overlapping files and heuristic alerts are enabled
 * @return cl_error_t  CL_EFORMAT if overlapping files and heuristic alerts are disabled
 * @return cl_error_t  CL_ETIMEOUT if the scan time limit is exceeded.
 * @return cl_error_t  CL_EMEM for memory allocation errors.
 */
cl_error_t index_the_central_directory(
    cli_ctx *ctx,
    fmap_t *map,
    uint32_t fsize,
    uint32_t coff,
    struct zip_record **catalogue,
    size_t *num_records)
{
    cl_error_t status = CL_CLEAN;
    cl_error_t ret    = CL_CLEAN;

    size_t num_record_blocks = 0;
    size_t index             = 0;

    struct zip_record *zip_catalogue = NULL;
    size_t records_count             = 0;
    struct zip_record *curr_record   = NULL;
    struct zip_record *prev_record   = NULL;
    uint32_t num_overlapping_files   = 0;
    int virus_found                  = 0;
    bool exceeded_max_files          = false;

    if (NULL == catalogue || NULL == num_records) {
        cli_errmsg("index_the_central_directory: Invalid NULL arguments\n");
        goto done;
    }

    *catalogue   = NULL;
    *num_records = 0;

    zip_catalogue = (struct zip_record *)cli_malloc(sizeof(struct zip_record) * ZIP_RECORDS_CHECK_BLOCKSIZE);
    if (NULL == zip_catalogue) {
        status = CL_EMEM;
        goto done;
    }
    num_record_blocks = 1;
    memset(zip_catalogue, 0, sizeof(struct zip_record) * ZIP_RECORDS_CHECK_BLOCKSIZE);

    cli_dbgmsg("cli_unzip: checking for non-recursive zip bombs...\n");

    while (0 != (coff = parse_central_directory_file_header(map,
                                                            coff,
                                                            fsize,
                                                            NULL, // num_files_unziped not required
                                                            index + 1,
                                                            &ret,
                                                            ctx,
                                                            NULL, // tmpd not required
                                                            NULL,
                                                            &(zip_catalogue[records_count])))) {
        if (ret == CL_VIRUS) {
            if (SCAN_ALLMATCHES)
                virus_found = 1;
            else {
                status = CL_VIRUS;
                goto done;
            }
        }

        index++;

        if (cli_checktimelimit(ctx) != CL_SUCCESS) {
            cli_dbgmsg("cli_unzip: Time limit reached (max: %u)\n", ctx->engine->maxscantime);
            status = CL_ETIMEOUT;
            goto done;
        }

        /* stop checking file entries if we'll exceed maxfiles */
        if (ctx->engine->maxfiles && records_count >= ctx->engine->maxfiles) {
            cli_dbgmsg("cli_unzip: Files limit reached (max: %u)\n", ctx->engine->maxfiles);
            cli_append_virus_if_heur_exceedsmax(ctx, "Heuristics.Limits.Exceeded.MaxFiles");
            exceeded_max_files = true; // Set a bool so we can return the correct status code later.
                                       // We still need to scan the files we found while reviewing the file records up to this limit.
            break;
        }
        records_count++;

        if (records_count % ZIP_RECORDS_CHECK_BLOCKSIZE == 0) {
            cli_dbgmsg("   cli_unzip: Exceeded zip record block size, allocating more space...\n");

            /* allocate more space for zip records */
            if (sizeof(struct zip_record) * ZIP_RECORDS_CHECK_BLOCKSIZE * (num_record_blocks + 1) <
                sizeof(struct zip_record) * ZIP_RECORDS_CHECK_BLOCKSIZE * (num_record_blocks)) {
                cli_errmsg("cli_unzip: Number of file records in zip will exceed the max for current architecture (integer overflow)\n");
                status = CL_EFORMAT;
                goto done;
            }

            zip_catalogue = cli_realloc2(zip_catalogue, sizeof(struct zip_record) * ZIP_RECORDS_CHECK_BLOCKSIZE * (num_record_blocks + 1));
            if (NULL == zip_catalogue) {
                status = CL_EMEM;
                goto done;
            }
            num_record_blocks++;
            /* zero out the memory for the new records */
            memset(&(zip_catalogue[records_count]), 0, sizeof(struct zip_record) * (ZIP_RECORDS_CHECK_BLOCKSIZE * num_record_blocks - records_count));
        }
    }

    if (ret == CL_VIRUS) {
        if (SCAN_ALLMATCHES)
            virus_found = 1;
        else {
            status = CL_VIRUS;
            goto done;
        }
    }

    if (records_count > 1) {
        /*
         * Sort the records by local file offset
         */
        cli_qsort(zip_catalogue, records_count, sizeof(struct zip_record), sort_by_file_offset);

        /*
         * Detect overlapping files.
         */
        for (index = 1; index < records_count; index++) {
            prev_record = &(zip_catalogue[index - 1]);
            curr_record = &(zip_catalogue[index]);

            /* Check for integer overflow in 32bit size & offset values */
            if ((UINT32_MAX - (prev_record->local_header_size + prev_record->compressed_size) < prev_record->local_header_offset) ||
                (UINT32_MAX - (curr_record->local_header_size + curr_record->compressed_size) < curr_record->local_header_offset)) {
                cli_dbgmsg("cli_unzip: Integer overflow detected; invalid data sizes in zip file headers.\n");
                status = CL_EFORMAT;
                goto done;
            }

            if (((curr_record->local_header_offset >= prev_record->local_header_offset) && (curr_record->local_header_offset < prev_record->local_header_offset + prev_record->local_header_size + prev_record->compressed_size)) ||
                ((prev_record->local_header_offset >= curr_record->local_header_offset) && (prev_record->local_header_offset < curr_record->local_header_offset + curr_record->local_header_size + curr_record->compressed_size))) {
                /* Overlapping file detected */
                num_overlapping_files++;

                if ((curr_record->local_header_offset == prev_record->local_header_offset) &&
                    (curr_record->local_header_size == prev_record->local_header_size) &&
                    (curr_record->compressed_size == prev_record->compressed_size)) {
                    cli_dbgmsg("cli_unzip: Ignoring duplicate file entry @ 0x%x.\n", curr_record->local_header_offset);
                } else {
                    cli_dbgmsg("cli_unzip: Overlapping files detected.\n");
                    cli_dbgmsg("    previous file end:  %u\n", prev_record->local_header_offset + prev_record->local_header_size + prev_record->compressed_size);
                    cli_dbgmsg("    current file start: %u\n", curr_record->local_header_offset);

                    if (ZIP_MAX_NUM_OVERLAPPING_FILES < num_overlapping_files) {
                        if (SCAN_HEURISTICS) {
                            status = cli_append_virus(ctx, "Heuristics.Zip.OverlappingFiles");
                        } else {
                            status = CL_EFORMAT;
                        }
                        goto done;
                    }
                }
            }

            if (cli_checktimelimit(ctx) != CL_SUCCESS) {
                cli_dbgmsg("cli_unzip: Time limit reached (max: %u)\n", ctx->engine->maxscantime);
                status = CL_ETIMEOUT;
                goto done;
            }
        }
    }

    *catalogue   = zip_catalogue;
    *num_records = records_count;
    status       = CL_SUCCESS;

done:

    if (CL_SUCCESS != status) {
        if (NULL != zip_catalogue) {
            free(zip_catalogue);
            zip_catalogue = NULL;
        }
    }

    if (virus_found)
        status = CL_VIRUS;
    else if (exceeded_max_files)
        status = CL_EMAXFILES;

    return status;
}

cl_error_t cli_unzip(cli_ctx *ctx)
{
    unsigned int file_count = 0, num_files_unzipped = 0;
    cl_error_t ret = CL_CLEAN;
    uint32_t fsize, lhoff = 0, coff = 0;
    fmap_t *map = ctx->fmap;
    char *tmpd  = NULL;
    const char *ptr;
    int virus_found = 0;
#if HAVE_JSON
    int toval = 0;
#endif
    struct zip_record *zip_catalogue = NULL;
    size_t records_count             = 0;
    size_t i;

    cli_dbgmsg("in cli_unzip\n");
    fsize = (uint32_t)map->len;
    if (sizeof(off_t) != sizeof(uint32_t) && (size_t)fsize != map->len) {
        cli_dbgmsg("cli_unzip: file too big\n");
        ret = CL_CLEAN;
        goto done;
    }
    if (fsize < SIZEOF_CENTRAL_HEADER) {
        cli_dbgmsg("cli_unzip: file too short\n");
        ret = CL_CLEAN;
        goto done;
    }

    for (coff = fsize - 22; coff > 0; coff--) { /* sizeof(EOC)==22 */
        if (!(ptr = fmap_need_off_once(map, coff, 20)))
            continue;
        if (cli_readint32(ptr) == ZIP_MAGIC_CENTRAL_DIRECTORY_RECORD_END) {
            uint32_t chptr = cli_readint32(&ptr[16]);
            if (!CLI_ISCONTAINED_0_TO(fsize, chptr, SIZEOF_CENTRAL_HEADER)) continue;
            coff = chptr;
            break;
        }
    }

    if (coff) {
        cli_dbgmsg("cli_unzip: central directory header offset: @%x\n", coff);

        /*
         * Index the central directory first.
         */
        ret = index_the_central_directory(
            ctx,
            map,
            fsize,
            coff,
            &zip_catalogue,
            &records_count);
        if (CL_SUCCESS != ret) {
            if (CL_VIRUS == ret && SCAN_ALLMATCHES)
                virus_found = 1;
            else {
                goto done;
            }
        }

        /*
         * Then decrypt/unzip & scan each unique file entry.
         */
        for (i = 0; i < records_count; i++) {
            const uint8_t *compressed_data = NULL;

            if ((i > 0) &&
                (zip_catalogue[i].local_header_offset == zip_catalogue[i - 1].local_header_offset) &&
                (zip_catalogue[i].local_header_size == zip_catalogue[i - 1].local_header_size) &&
                (zip_catalogue[i].compressed_size == zip_catalogue[i - 1].compressed_size)) {

                /* Duplicate file entry, skip. */
                cli_dbgmsg("cli_unzip: Skipping unzipping of duplicate file entry: @ 0x%x\n", zip_catalogue[i].local_header_offset);
                continue;
            }

            compressed_data = fmap_need_off(map, zip_catalogue[i].local_header_offset + zip_catalogue[i].local_header_size, SIZEOF_LOCAL_HEADER);

            if (zip_catalogue[i].encrypted) {
                if (fmap_need_ptr_once(map, compressed_data, zip_catalogue[i].compressed_size))
                    ret = zdecrypt(
                        compressed_data,
                        zip_catalogue[i].compressed_size,
                        zip_catalogue[i].uncompressed_size,
                        fmap_need_off(map, zip_catalogue[i].local_header_offset, SIZEOF_LOCAL_HEADER),
                        &num_files_unzipped,
                        ctx,
                        tmpd,
                        zip_scan_cb,
                        zip_catalogue[i].original_filename);
            } else {
                if (fmap_need_ptr_once(map, compressed_data, zip_catalogue[i].compressed_size))
                    ret = unz(
                        compressed_data,
                        zip_catalogue[i].compressed_size,
                        zip_catalogue[i].uncompressed_size,
                        zip_catalogue[i].method,
                        zip_catalogue[i].flags,
                        &num_files_unzipped,
                        ctx,
                        tmpd,
                        zip_scan_cb,
                        zip_catalogue[i].original_filename);
            }

            file_count++;

            if (ctx->engine->maxfiles && num_files_unzipped >= ctx->engine->maxfiles) {
                // Note: this check piggybacks on the MaxFiles setting, but is not actually
                //   scanning these files or incrementing the ctx->scannedfiles count
                // This check is also redundant. zip_scan_cb == cli_magic_scan_desc,
                //   so we will also check and update the limits for the actual number of scanned
                //   files inside cli_magic_scan()
                cli_dbgmsg("cli_unzip: Files limit reached (max: %u)\n", ctx->engine->maxfiles);
                cli_append_virus_if_heur_exceedsmax(ctx, "Heuristics.Limits.Exceeded.MaxFiles");
                ret = CL_EMAXFILES;
            }

            if (cli_checktimelimit(ctx) != CL_SUCCESS) {
                cli_dbgmsg("cli_unzip: Time limit reached (max: %u)\n", ctx->engine->maxscantime);
                ret = CL_ETIMEOUT;
            }

#if HAVE_JSON
            if (cli_json_timeout_cycle_check(ctx, &toval) != CL_SUCCESS) {
                ret = CL_ETIMEOUT;
            }
#endif
            if (ret != CL_CLEAN) {
                if (ret == CL_VIRUS && SCAN_ALLMATCHES) {
                    ret         = CL_CLEAN;
                    virus_found = 1;
                } else {
                    break;
                }
            }
        }
    } else {
        cli_dbgmsg("cli_unzip: central not found, using localhdrs\n");
    }

    if (virus_found == 1) {
        ret = CL_VIRUS;
    }
    if (0 < num_files_unzipped && num_files_unzipped <= (file_count / 4)) { /* FIXME: make up a sane ratio or remove the whole logic */
        file_count = 0;
        while ((ret == CL_CLEAN) &&
               (lhoff < fsize) &&
               (0 != (coff = parse_local_file_header(map,
                                                     lhoff,
                                                     fsize - lhoff,
                                                     &num_files_unzipped,
                                                     file_count + 1,
                                                     NULL,
                                                     &ret,
                                                     ctx,
                                                     tmpd,
                                                     1,
                                                     zip_scan_cb,
                                                     NULL)))) {
            file_count++;
            lhoff += coff;
            if (SCAN_ALLMATCHES && ret == CL_VIRUS) {
                ret         = CL_CLEAN;
                virus_found = 1;
            }
            if (ctx->engine->maxfiles && num_files_unzipped >= ctx->engine->maxfiles) {
                // Note: this check piggybacks on the MaxFiles setting, but is not actually
                //   scanning these files or incrementing the ctx->scannedfiles count
                // This check is also redundant. zip_scan_cb == cli_magic_scan_desc,
                //   so we will also check and update the limits for the actual number of scanned
                //   files inside cli_magic_scan()
                cli_dbgmsg("cli_unzip: Files limit reached (max: %u)\n", ctx->engine->maxfiles);
                cli_append_virus_if_heur_exceedsmax(ctx, "Heuristics.Limits.Exceeded.MaxFiles");
                ret = CL_EMAXFILES;
            }
#if HAVE_JSON
            if (cli_json_timeout_cycle_check(ctx, &toval) != CL_SUCCESS) {
                ret = CL_ETIMEOUT;
            }
#endif
        }
    }

done:

    if (NULL != zip_catalogue) {
        /* Clean up zip record resources */
        for (i = 0; i < records_count; i++) {
            if (NULL != zip_catalogue[i].original_filename) {
                free(zip_catalogue[i].original_filename);
                zip_catalogue[i].original_filename = NULL;
            }
        }
        free(zip_catalogue);
        zip_catalogue = NULL;
    }

    if (NULL != tmpd) {
        if (!ctx->engine->keeptmp) {
            cli_rmdirs(tmpd);
        }
        free(tmpd);
    }

    if (ret == CL_CLEAN && virus_found)
        ret = CL_VIRUS;

    return ret;
}

cl_error_t unzip_single_internal(cli_ctx *ctx, off_t local_header_offset, zip_cb zcb)
{
    cl_error_t ret = CL_CLEAN;

    unsigned int num_files_unzipped = 0;
    uint32_t fsize;
    fmap_t *map = ctx->fmap;

    cli_dbgmsg("in cli_unzip_single\n");
    fsize = (uint32_t)(map->len - local_header_offset);
    if ((local_header_offset < 0) ||
        ((size_t)local_header_offset > map->len) ||
        ((sizeof(off_t) != sizeof(uint32_t)) && ((size_t)fsize != map->len - local_header_offset))) {

        cli_dbgmsg("cli_unzip: bad offset\n");
        return CL_CLEAN;
    }
    if (fsize < SIZEOF_LOCAL_HEADER) {
        cli_dbgmsg("cli_unzip: file too short\n");
        return CL_CLEAN;
    }

    parse_local_file_header(map,
                            local_header_offset,
                            fsize,
                            &num_files_unzipped,
                            0,
                            NULL,
                            &ret,
                            ctx,
                            NULL,
                            0,
                            zcb,
                            NULL);

    return ret;
}

cl_error_t cli_unzip_single(cli_ctx *ctx, off_t local_header_offset)
{
    return unzip_single_internal(ctx, local_header_offset, zip_scan_cb);
}

cl_error_t unzip_search_add(struct zip_requests *requests, const char *name, size_t nlen)
{
    cli_dbgmsg("in unzip_search_add\n");

    if (requests->namecnt >= MAX_ZIP_REQUESTS) {
        cli_dbgmsg("DEBUGGING MESSAGE GOES HERE!\n");
        return CL_BREAK;
    }

    cli_dbgmsg("unzip_search_add: adding %s (len %llu)\n", name, (long long unsigned)nlen);

    requests->names[requests->namecnt]    = name;
    requests->namelens[requests->namecnt] = nlen;
    requests->namecnt++;

    return CL_SUCCESS;
}

cl_error_t unzip_search(cli_ctx *ctx, fmap_t *map, struct zip_requests *requests)
{
    unsigned int file_count = 0;
    fmap_t *zmap            = map;
    size_t fsize;
    uint32_t coff = 0;
    const char *ptr;
    cl_error_t ret = CL_CLEAN;
#if HAVE_JSON
    uint32_t toval = 0;
#endif
    cli_dbgmsg("in unzip_search\n");

    if ((!ctx && !map) || !requests) {
        return CL_ENULLARG;
    }

    /* get priority to given map over ctx->fmap */
    if (ctx && !map)
        zmap = ctx->fmap;
    fsize = zmap->len;
    if (sizeof(off_t) != sizeof(uint32_t) && fsize != zmap->len) {
        cli_dbgmsg("unzip_search: file too big\n");
        return CL_CLEAN;
    }
    if (fsize < SIZEOF_CENTRAL_HEADER) {
        cli_dbgmsg("unzip_search: file too short\n");
        return CL_CLEAN;
    }

    for (coff = fsize - 22; coff > 0; coff--) { /* sizeof(EOC)==22 */
        if (!(ptr = fmap_need_off_once(zmap, coff, 20)))
            continue;
        if (cli_readint32(ptr) == ZIP_MAGIC_CENTRAL_DIRECTORY_RECORD_END) {
            uint32_t chptr = cli_readint32(&ptr[16]);
            if (!CLI_ISCONTAINED_0_TO(fsize, chptr, SIZEOF_CENTRAL_HEADER)) continue;
            coff = chptr;
            break;
        }
    }

    if (coff) {
        cli_dbgmsg("unzip_search: central directory header offset: @%x\n", coff);
        while (ret == CL_CLEAN && (coff = parse_central_directory_file_header(zmap,
                                                                              coff,
                                                                              fsize,
                                                                              NULL,
                                                                              file_count + 1,
                                                                              &ret,
                                                                              ctx,
                                                                              NULL,
                                                                              requests,
                                                                              NULL))) {
            if (requests->match) {
                ret = CL_VIRUS;
            }

            file_count++;
            if (ctx && ctx->engine->maxfiles && file_count >= ctx->engine->maxfiles) {
                // Note: this check piggybacks on the MaxFiles setting, but is not actually
                //   scanning these files or incrementing the ctx->scannedfiles count
                cli_dbgmsg("cli_unzip: Files limit reached (max: %u)\n", ctx->engine->maxfiles);
                cli_append_virus_if_heur_exceedsmax(ctx, "Heuristics.Limits.Exceeded.MaxFiles");
                ret = CL_EMAXFILES;
            }
#if HAVE_JSON
            if (ctx && cli_json_timeout_cycle_check(ctx, (int *)(&toval)) != CL_SUCCESS) {
                ret = CL_ETIMEOUT;
            }
#endif
        }
    } else {
        cli_dbgmsg("unzip_search: cannot locate central directory\n");
    }

    return ret;
}

cl_error_t unzip_search_single(cli_ctx *ctx, const char *name, size_t nlen, uint32_t *loff)
{
    struct zip_requests requests;
    cl_error_t ret;

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

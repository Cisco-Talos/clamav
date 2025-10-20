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

#include <bzlib.h>

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

// Non-malicious zips in enterprise critical JAR-ZIPs have been observed with a 1-byte overlap.
// The goal with overlap detection is to alert on non-recursive zip bombs, so this tiny overlap isn't a concern.
// We'll allow a 2-byte overlap so we don't alert on such zips.
#define ZIP_RECORD_OVERLAP_FUDGE_FACTOR 2
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
    uint64_t csize,
    uint64_t usize,
    uint16_t method,
    uint16_t flags,
    size_t *num_files_unzipped,
    cli_ctx *ctx,
    char *tmpd,
    zip_cb zcb,
    const char *original_filename,
    bool decrypted)
{
    char obuf[BUFSIZ] = {0};
    char *tempfile    = NULL;
    int out_file, ret = CL_SUCCESS;
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
            if (!(tempfile = cli_gentemp_with_prefix(ctx->this_layer_tmpdir, original_filename))) return CL_EMEM;
        } else {
            if (!(tempfile = cli_gentemp(ctx->this_layer_tmpdir))) return CL_EMEM;
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
                size_t fake = *num_files_unzipped + 1;
                cli_dbgmsg("cli_unzip: attempting to inflate stored file with inconsistent size\n");
                if (CL_SUCCESS == (ret = unz(src, csize, usize, ALG_DEFLATE, 0, &fake, ctx,
                                             tmpd, zcb, original_filename, decrypted))) {
                    (*num_files_unzipped)++;
                    res = fake - (*num_files_unzipped);
                } else
                    break;
            }
            if (res == 1) {
                if (ctx->engine->maxfilesize && csize > ctx->engine->maxfilesize) {
                    cli_dbgmsg("cli_unzip: trimming output size to maxfilesize (" STDu64 ")\n",
                               ctx->engine->maxfilesize);
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
                        cli_dbgmsg("cli_unzip: trimming output size to maxfilesize (" STDu64 ")\n",
                                   ctx->engine->maxfilesize);
                        res = Z_STREAM_END;
                        break;
                    }
                    if (cli_writen(out_file, obuf, sizeof(obuf) - *avail_out) != sizeof(obuf) - *avail_out) {
                        cli_warnmsg("cli_unzip: failed to write %zu inflated bytes\n",
                                    sizeof(obuf) - *avail_out);
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
                        cli_dbgmsg("cli_unzip: trimming output size to maxfilesize (" STDu64 ")\n", ctx->engine->maxfilesize);
                        res = BZ_STREAM_END;
                        break;
                    }
                    if (cli_writen(out_file, obuf, sizeof(obuf) - strm.avail_out) != sizeof(obuf) - strm.avail_out) {
                        cli_warnmsg("cli_unzip: failed to write %zu bunzipped bytes\n", sizeof(obuf) - strm.avail_out);
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
                        cli_dbgmsg("cli_unzip: trimming output size to maxfilesize (" STDu64 ")\n", ctx->engine->maxfilesize);
                        res = 0;
                        break;
                    }
                    if (cli_writen(out_file, obuf, sizeof(obuf) - strm.avail_out) != sizeof(obuf) - strm.avail_out) {
                        cli_warnmsg("cli_unzip: failed to write %zu exploded bytes\n", sizeof(obuf) - strm.avail_out);
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
        ret = zcb(out_file, tempfile, ctx, original_filename, decrypted);
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
    size_t *num_files_unzipped,
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
                snprintf(name, sizeof(name), "%s" PATHSEP "zip.decrypt.%03zu", tmpd, *num_files_unzipped);
                name[sizeof(name) - 1] = '\0';
            } else {
                if (!(tempfile = cli_gentemp_with_prefix(ctx->this_layer_tmpdir, "zip-decrypt"))) return CL_EMEM;
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
            if (!(dcypt_map = fmap_new(out_file, 0, total, NULL, tempfile))) {
                cli_warnmsg("cli_unzip: decrypt - failed to create fmap on decrypted file %s\n", tempfile);
                ret = CL_EMAP;
                goto zd_clean;
            }

            if (!(dcypt_zip = fmap_need_off_once(dcypt_map, 0, total))) {
                cli_warnmsg("cli_unzip: decrypt - failed to acquire buffer on decrypted file %s\n", tempfile);
                fmap_free(dcypt_map);
                ret = CL_EREAD;
                goto zd_clean;
            }

            /* call unz on decrypted output */
            ret = unz(dcypt_zip, csize - SIZEOF_ENCRYPTION_HEADER, usize, LOCAL_HEADER_method, LOCAL_HEADER_flags,
                      num_files_unzipped, ctx, tmpd, zcb, original_filename, true);

            /* clean-up and return */
            fmap_free(dcypt_map);
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

    cli_dbgmsg("cli_unzip: decrypt failed - will attempt to unzip as if it were not encrypted\n");

    ret = unz(src, csize, usize, LOCAL_HEADER_method, LOCAL_HEADER_flags,
              num_files_unzipped, ctx, tmpd, zcb, original_filename, false);

    return CL_SUCCESS;
}

/**
 * @brief Parse, extract, and scan a file using the local file header.
 *
 * Usage of the `record` parameter will alter behavior so it only collect file record metadata and does not extract or scan any files.
 *
 * @param[in,out] ctx                   scan context
 * @param loff                          offset of the local file header
 * @param[in,out] num_files_unzipped    current number of files that have been unzipped
 * @param file_count                    current number of files that have been discovered
 * @param central_header                pointer to central directory header
 * @param tmpd                          temp directory path name
 * @param detect_encrypted              bool: if encrypted files should raise heuristic alert
 * @param zcb                           callback function to invoke after extraction (default: scan)
 * @param record                        (optional) a pointer to a struct to store file record information.
 * @param[out] file_record_size         (optional) if not NULL, will be set to the size of the file header + file data.
 * @return cl_error_t                   CL_SUCCESS on success, or an error code on failure.
 */
static cl_error_t parse_local_file_header(
    cli_ctx *ctx,
    uint32_t loff,
    size_t *num_files_unzipped,
    size_t file_count,
    const uint8_t *central_header,
    char *tmpd,
    int detect_encrypted,
    zip_cb zcb,
    struct zip_record *record,
    size_t *file_record_size)
{
    cl_error_t status = CL_ERROR;
    cl_error_t ret;
    const uint8_t *local_header = NULL;
    char name[256]              = {0};
    char *original_filename     = NULL;
    uint32_t csize = 0, usize = 0;

    uint32_t name_size = 0;
    const char *src    = NULL;

    const uint8_t *zip     = NULL;
    size_t bytes_remaining = 0;

    if (NULL != file_record_size) {
        *file_record_size = 0;
    }

    local_header = fmap_need_off(ctx->fmap, loff, SIZEOF_LOCAL_HEADER);
    if (NULL == local_header) {
        cli_dbgmsg("cli_unzip: local header - out of file or work complete\n");
        status = CL_EPARSE;
        goto done;
    }
    if (LOCAL_HEADER_magic != ZIP_MAGIC_LOCAL_FILE_HEADER) {
        cli_dbgmsg("cli_unzip: local header - bad magic\n");
        status = CL_EFORMAT;
        goto done;
    }
    bytes_remaining = ctx->fmap->len - loff;

    zip = local_header + SIZEOF_LOCAL_HEADER;
    bytes_remaining -= SIZEOF_LOCAL_HEADER;

    if (bytes_remaining <= LOCAL_HEADER_flen) {
        cli_dbgmsg("cli_unzip: local header - fname out of file\n");
        status = CL_EPARSE;
        goto done;
    }

    name_size = LOCAL_HEADER_flen >= (sizeof(name) - 1) ? sizeof(name) - 1 : LOCAL_HEADER_flen;
    cli_dbgmsg("cli_unzip: name_size %u\n", name_size);
    src = fmap_need_ptr_once(ctx->fmap, zip, name_size);
    if (name_size && (NULL != src)) {
        memcpy(name, zip, name_size);
        if (CL_SUCCESS != cli_basename(name, name_size, &original_filename, true /* posix_support_backslash_pathsep */)) {
            original_filename = NULL;
        }
    }

    zip += LOCAL_HEADER_flen;
    bytes_remaining -= LOCAL_HEADER_flen;

    /* Print ZMD container metadata signature and try matching the metadata AFTER we have all the metadata. */
    cli_dbgmsg("cli_unzip: local header - ZMDNAME:%d:%s:%u:%u:%x:%u:%zu:%u\n",
               ((LOCAL_HEADER_flags & F_ENCR) != 0), name, LOCAL_HEADER_usize, LOCAL_HEADER_csize, LOCAL_HEADER_crc32, LOCAL_HEADER_method, file_count, ctx->recursion_level);
    /* ZMDfmt virname:encrypted(0-1):filename(exact|*):usize(exact|*):csize(exact|*):crc32(exact|*):method(exact|*):fileno(exact|*):maxdepth(exact|*) */

    /* Scan file header metadata. */
    ret = cli_matchmeta(ctx, name, LOCAL_HEADER_csize, LOCAL_HEADER_usize, (LOCAL_HEADER_flags & F_ENCR) != 0, file_count, LOCAL_HEADER_crc32);
    if (ret != CL_SUCCESS) {
        status = ret;
        goto done;
    }

    if (LOCAL_HEADER_flags & F_MSKED) {
        cli_dbgmsg("cli_unzip: local header - header has got unusable masked data\n");
        /* FIXME: need to find/craft a sample */
        status = CL_EPARSE;
        goto done;
    }

    if (detect_encrypted && (LOCAL_HEADER_flags & F_ENCR) && SCAN_HEURISTIC_ENCRYPTED_ARCHIVE) {
        cli_dbgmsg("cli_unzip: Encrypted files found in archive.\n");
        ret = cli_append_potentially_unwanted(ctx, "Heuristics.Encrypted.Zip");
        if (ret != CL_SUCCESS) {
            status = ret;
            goto done;
        }
    }

    if (LOCAL_HEADER_flags & F_USEDD) {
        cli_dbgmsg("cli_unzip: local header - has data desc\n");
        if (!central_header) {
            status = CL_EPARSE;
            goto done;
        }

        usize = CENTRAL_HEADER_usize;
        csize = CENTRAL_HEADER_csize;
    } else {
        usize = LOCAL_HEADER_usize;
        csize = LOCAL_HEADER_csize;
    }

    if (bytes_remaining <= LOCAL_HEADER_elen) {
        cli_dbgmsg("cli_unzip: local header - extra out of file\n");
        status = CL_EPARSE;
        goto done;
    }

    zip += LOCAL_HEADER_elen;
    bytes_remaining -= LOCAL_HEADER_elen;

    if (bytes_remaining < csize) {
        cli_dbgmsg("cli_unzip: local header - stream out of file\n");
        status = CL_EPARSE;
        goto done;
    }

    if (NULL != record) {
        /* Don't actually unzip if we're just collecting the file record information (offset, sizes) */
        if (NULL == original_filename) {
            record->original_filename = NULL;
        } else {
            record->original_filename = CLI_STRNDUP(original_filename, strlen(original_filename));
        }
        record->local_header_offset = loff;
        record->local_header_size   = zip - local_header;
        record->compressed_size     = csize;
        record->uncompressed_size   = usize;
        record->method              = LOCAL_HEADER_method;
        record->flags               = LOCAL_HEADER_flags;
        record->encrypted           = (LOCAL_HEADER_flags & F_ENCR) ? 1 : 0;

        status = CL_SUCCESS;
    } else {
        /*
         * Unzip or decompress & then unzip.
         */
        if (!csize) { /* FIXME: what's used for method0 files? csize or usize? Nothing in the specs, needs testing */
            cli_dbgmsg("cli_unzip: local header - skipping empty file\n");
        } else {
            zip = fmap_need_ptr_once(ctx->fmap, zip, csize);
            if (NULL == zip) {
                cli_dbgmsg("cli_unzip: local header - data out of file\n");
                status = CL_EPARSE;
                goto done;
            }

            if (LOCAL_HEADER_flags & F_ENCR) {
                ret = zdecrypt(zip, csize, usize, local_header, num_files_unzipped, ctx, tmpd, zcb, original_filename);
                if (ret != CL_SUCCESS) {
                    cli_dbgmsg("cli_unzip: local header - zdecrypt failed with %d\n", ret);
                    status = ret;
                    goto done;
                }
            } else {
                ret = unz(zip, csize, usize, LOCAL_HEADER_method, LOCAL_HEADER_flags, num_files_unzipped,
                          ctx, tmpd, zcb, original_filename, false);
                if (ret != CL_SUCCESS) {
                    cli_dbgmsg("cli_unzip: local header - unz failed with %d\n", ret);
                    status = ret;
                    goto done;
                }
            }
        }
    }

    zip += csize;
    bytes_remaining -= csize;

    if (LOCAL_HEADER_flags & F_USEDD) {
        if (bytes_remaining < 12) {
            cli_dbgmsg("cli_unzip: local header - data desc out of file\n");
            status = CL_EPARSE;
            goto done;
        }
        bytes_remaining -= 12;

        /*
         * Get the next 4 bytes to check if ZIP is split or spanned.
         *
         * 8.5.3 Spanned/Split archives created using PKZIP for Windows
         * (V2.50 or greater), PKZIP Command Line (V2.50 or greater),
         * or PKZIP Explorer will include a special spanning
         * signature as the first 4 bytes of the first segment of
         * the archive.  This signature (0x08074b50) will be
         * followed immediately by the local header signature for
         * the first file in the archive.
         */
        zip = fmap_need_ptr_once(ctx->fmap, zip, 4);
        if (NULL == zip) {
            cli_dbgmsg("cli_unzip: local header - data desc out of file\n");
            status = CL_EPARSE;
            goto done;
        }

        if (cli_readint32(zip) == ZIP_MAGIC_FILE_BEGIN_SPLIT_OR_SPANNED) {
            cli_dbgmsg("cli_unzip: local header - split/spanned archive detected\n");
            /* skip the split/spanned signature */
            zip += 4;
            bytes_remaining -= 4;
        }
        zip += 12;
    }

    /* Success */
    if (file_record_size) {
        *file_record_size = zip - local_header;
    }
    status = CL_SUCCESS;

done:
    if (NULL != local_header) {
        fmap_unneed_off(ctx->fmap, loff, SIZEOF_LOCAL_HEADER);
    }

    if (NULL != original_filename) {
        free(original_filename);
    }

    return status;
}

cl_error_t cli_unzip_single_header_check(
    cli_ctx *ctx,
    uint32_t offset,
    size_t *size)
{
    cl_error_t status             = CL_ERROR;
    struct zip_record file_record = {0};
    cl_error_t ret;

    ret = parse_local_file_header(
        ctx,
        offset,
        NULL,  /* num_files_unzipped */
        0,     /* file_count */
        NULL,  /* central_header */
        NULL,  /* tmpd */
        false, /* detect_encrypted */
        NULL,  /* zcb */
        &file_record,
        size);
    if (ret != CL_SUCCESS) {
        cli_dbgmsg("cli_unzip: single header check - failed to parse local file header: %s (%d)\n", cl_strerror(ret), ret);
        status = ret;
        goto done;
    }

    if (file_record.compressed_size == 0 || file_record.uncompressed_size == 0) {
        cli_dbgmsg("cli_unzip: single header check - empty file\n");
        status = CL_EFORMAT;
        goto done;
    }

    status = CL_SUCCESS;

done:
    if (file_record.original_filename) {
        free(file_record.original_filename);
    }

    return status;
}

/**
 * @brief Parse, extract, and scan a file by iterating the central directory.
 *
 * Usage of the `record` parameter will alter behavior so it only collect file record metadata and does not extract or scan any files.
 *
 * @param[in,out] ctx                   scan context
 * @param central_file_header_offset    offset of the file header in the central directory
 * @param[in,out] num_files_unzipped    current number of files that have been unzipped
 * @param file_count                    current number of files that have been discovered
 * @param tmpd                          temp directory path name
 * @param requests                      (optional) structure use to search the zip for files by name
 * @param record                        (optional) a pointer to a struct to store file record information.
 * @param[out] file_record_size         A pointer to a variable to store the size of the file record.
 * @return cl_error_t                   CL_SUCCESS on success, or an error code on failure.
 */
static cl_error_t parse_central_directory_file_header(
    cli_ctx *ctx,
    size_t central_file_header_offset,
    size_t *num_files_unzipped,
    size_t file_count,
    char *tmpd,
    struct zip_requests *requests,
    struct zip_record *record,
    size_t *file_record_size)
{
    cl_error_t status = CL_ERROR;
    cl_error_t ret;

    char name[256] = {0};

    const uint8_t *central_header = NULL;
    size_t index;

    *file_record_size = 0;

    if (cli_checktimelimit(ctx) != CL_SUCCESS) {
        cli_dbgmsg("cli_unzip: central header - Time limit reached (max: %u)\n", ctx->engine->maxscantime);
        status = CL_ETIMEOUT;
        goto done;
    }

    central_header = fmap_need_off(ctx->fmap, central_file_header_offset, SIZEOF_CENTRAL_HEADER);
    if (NULL == central_header) {
        cli_dbgmsg("cli_unzip: central header - reached end of central directory.\n");
        status = CL_BREAK;
        goto done;
    }

    if (CENTRAL_HEADER_magic != ZIP_MAGIC_CENTRAL_DIRECTORY_RECORD_BEGIN) {
        cli_dbgmsg("cli_unzip: central header - file header offset has wrong magic\n");
        status = CL_EPARSE;
        goto done;
    }
    index = central_file_header_offset + SIZEOF_CENTRAL_HEADER;

    cli_dbgmsg("cli_unzip: central header - flags %x - method %x - csize %x - usize %x - flen %x - elen %x - clen %x - disk %x - off %x\n",
               CENTRAL_HEADER_flags, CENTRAL_HEADER_method, CENTRAL_HEADER_csize, CENTRAL_HEADER_usize, CENTRAL_HEADER_flen, CENTRAL_HEADER_extra_len, CENTRAL_HEADER_comment_len, CENTRAL_HEADER_disk_num, CENTRAL_HEADER_off);

    if (ctx->fmap->len <= index + CENTRAL_HEADER_flen) {
        cli_dbgmsg("cli_unzip: central header - fname out of file\n");
        status = CL_EPARSE;
        goto done;
    }

    size_t size     = (CENTRAL_HEADER_flen >= sizeof(name)) ? sizeof(name) - 1 : CENTRAL_HEADER_flen;
    const char *src = fmap_need_off_once(ctx->fmap, index, size);
    if (src) {
        memcpy(name, src, size);
        name[size] = '\0';
        cli_dbgmsg("cli_unzip: central header - fname: %s\n", name);
    }
    index += CENTRAL_HEADER_flen;

    /* requests do not supply a ctx; also prevent multiple scans */
    ret = cli_matchmeta(ctx, name, CENTRAL_HEADER_csize, CENTRAL_HEADER_usize, (CENTRAL_HEADER_flags & F_ENCR) != 0, file_count, CENTRAL_HEADER_crc32);
    if (CL_VIRUS == ret) {
        // Set file record size to 0 to indicate this is the last file record
        status = CL_VIRUS;
        goto done;
    }

    if (ctx->fmap->len <= index + CENTRAL_HEADER_extra_len) {
        cli_dbgmsg("cli_unzip: central header - extra out of file\n");
        status = CL_EPARSE;
        goto done;
    }
    index += CENTRAL_HEADER_extra_len;

    if (ctx->fmap->len < index + CENTRAL_HEADER_comment_len) {
        cli_dbgmsg("cli_unzip: central header - comment out of file\n");
        status = CL_EPARSE;
        goto done;
    }
    index += CENTRAL_HEADER_comment_len;

    *file_record_size = index - central_file_header_offset;

    if (!requests) {
        // Parse the local file header.
        // We'll verify enough bytes available for a local file header when we parse it.

        status = parse_local_file_header(
            ctx,
            CENTRAL_HEADER_off,
            num_files_unzipped,
            file_count,
            central_header,
            tmpd,
            1, /* detect_encrypted */
            zip_scan_cb,
            record,
            NULL); /* file_record_size */
    } else {
        int i;
        size_t len;

        for (i = 0; i < requests->namecnt; ++i) {
            cli_dbgmsg("cli_unzip: central header - checking for %i: %s\n", i, requests->names[i]);

            len = MIN(sizeof(name) - 1, requests->namelens[i]);
            if (!strncmp(requests->names[i], name, len)) {
                requests->match = 1;
                requests->found = i;
                requests->loff  = CENTRAL_HEADER_off;
            }
        }

        status = CL_SUCCESS;
    }

done:
    if (NULL != central_header) {
        fmap_unneed_ptr(ctx->fmap, central_header, SIZEOF_CENTRAL_HEADER);
    }

    return status;
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
 * @param coff              The central directory offset
 * @param[out] catalogue    A catalogue of zip_records found in the central directory.
 * @param[out] num_records  The number of records in the catalogue.
 * @return cl_error_t  CL_SUCCESS if no overlapping files
 * @return cl_error_t  CL_VIRUS if overlapping files and heuristic alerts are enabled
 * @return cl_error_t  CL_EFORMAT if overlapping files and heuristic alerts are disabled
 * @return cl_error_t  CL_ETIMEOUT if the scan time limit is exceeded.
 * @return cl_error_t  CL_EMEM for memory allocation errors.
 */
cl_error_t index_the_central_directory(
    cli_ctx *ctx,
    uint32_t coff,
    struct zip_record **catalogue,
    size_t *num_records)
{
    cl_error_t status = CL_ERROR;
    cl_error_t ret;

    size_t num_record_blocks = 0;
    size_t index             = 0;

    struct zip_record *zip_catalogue = NULL;
    size_t records_count             = 0;
    struct zip_record *curr_record   = NULL;
    struct zip_record *prev_record   = NULL;
    uint32_t num_overlapping_files   = 0;
    bool exceeded_max_files          = false;

    size_t record_size   = 0;
    size_t record_offset = coff;

    if (NULL == catalogue || NULL == num_records) {
        cli_errmsg("index_the_central_directory: Invalid NULL arguments\n");
        goto done;
    }

    *catalogue   = NULL;
    *num_records = 0;

    CLI_CALLOC_OR_GOTO_DONE(
        zip_catalogue,
        1,
        sizeof(struct zip_record) * ZIP_RECORDS_CHECK_BLOCKSIZE,
        status = CL_EMEM);

    num_record_blocks = 1;

    cli_dbgmsg("cli_unzip: checking for non-recursive zip bombs...\n");

    do {
        ret = parse_central_directory_file_header(
            ctx,
            record_offset,
            NULL, // num_files_unzipped not required
            records_count + 1,
            NULL, // tmpd not required
            NULL,
            &(zip_catalogue[records_count]),
            &record_size);

        if (ret == CL_VIRUS) {
            // Aborting scan due to a detection (not in all match mode).
            status = CL_VIRUS;
            goto done;
        }

        if (record_size == 0) {
            // No more files (previous was last).
            break;
        }

        // Found a record.
        records_count++;

        // Increment the record offset by the size of the record for the next iteration.
        record_offset += record_size;

        if (cli_checktimelimit(ctx) != CL_SUCCESS) {
            cli_dbgmsg("cli_unzip: Time limit reached (max: %u)\n", ctx->engine->maxscantime);
            status = CL_ETIMEOUT;
            goto done;
        }

        /* stop checking file entries if we'll exceed maxfiles */
        if (ctx->engine->maxfiles && records_count >= ctx->engine->maxfiles) {
            cli_dbgmsg("cli_unzip: Files limit reached (max: %u)\n", ctx->engine->maxfiles);
            cli_append_potentially_unwanted_if_heur_exceedsmax(ctx, "Heuristics.Limits.Exceeded.MaxFiles");
            exceeded_max_files = true; // Set a bool so we can return the correct status code later.
                                       // We still need to scan the files we found while reviewing the file records up to this limit.
            break;
        }

        if (num_record_blocks * ZIP_RECORDS_CHECK_BLOCKSIZE == records_count + 1) {
            cli_dbgmsg("cli_unzip: Filled a block of zip records. Allocating an additional block for more zip records...\n");

            CLI_MAX_REALLOC_OR_GOTO_DONE(
                zip_catalogue,
                sizeof(struct zip_record) * ZIP_RECORDS_CHECK_BLOCKSIZE * (num_record_blocks + 1),
                status = CL_EMEM);

            num_record_blocks++;
            /* zero out the memory for the new records */
            memset(&(zip_catalogue[records_count]), 0,
                   sizeof(struct zip_record) * (ZIP_RECORDS_CHECK_BLOCKSIZE * num_record_blocks - records_count));
        }
    } while (1);

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

            uint32_t prev_record_size = prev_record->local_header_size + prev_record->compressed_size;
            uint32_t curr_record_size = curr_record->local_header_size + curr_record->compressed_size;
            uint32_t prev_record_end;
            uint32_t curr_record_end;

            /* Check for integer overflow in 32bit size & offset values */
            if ((UINT32_MAX - prev_record_size < prev_record->local_header_offset) ||
                (UINT32_MAX - curr_record_size < curr_record->local_header_offset)) {
                cli_dbgmsg("cli_unzip: Integer overflow detected; invalid data sizes in zip file headers.\n");
                status = CL_EFORMAT;
                goto done;
            }

            prev_record_end = prev_record->local_header_offset + prev_record_size;
            curr_record_end = curr_record->local_header_offset + curr_record_size;

            if (((curr_record->local_header_offset >= prev_record->local_header_offset) && (curr_record->local_header_offset + ZIP_RECORD_OVERLAP_FUDGE_FACTOR < prev_record_end)) ||
                ((prev_record->local_header_offset >= curr_record->local_header_offset) && (prev_record->local_header_offset + ZIP_RECORD_OVERLAP_FUDGE_FACTOR < curr_record_end))) {
                /* Overlapping file detected */
                num_overlapping_files++;

                if ((curr_record->local_header_offset == prev_record->local_header_offset) &&
                    (curr_record->local_header_size == prev_record->local_header_size) &&
                    (curr_record->compressed_size == prev_record->compressed_size)) {
                    cli_dbgmsg("cli_unzip: Ignoring duplicate file entry at offset: 0x%x.\n", curr_record->local_header_offset);
                } else {
                    cli_dbgmsg("cli_unzip: Overlapping files detected.\n");
                    cli_dbgmsg("    previous file end:  %u\n", prev_record_end);
                    cli_dbgmsg("    current file start: %u\n", curr_record->local_header_offset);

                    if (ZIP_MAX_NUM_OVERLAPPING_FILES < num_overlapping_files) {
                        status = CL_EFORMAT;

                        if (SCAN_HEURISTICS) {
                            ret = cli_append_potentially_unwanted(ctx, "Heuristics.Zip.OverlappingFiles");
                            if (CL_SUCCESS != ret) {
                                status = ret;
                            }
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
            size_t i;
            for (i = 0; i < records_count; i++) {
                if (NULL != zip_catalogue[i].original_filename) {
                    free(zip_catalogue[i].original_filename);
                    zip_catalogue[i].original_filename = NULL;
                }
            }
            free(zip_catalogue);
            zip_catalogue = NULL;
        }

        if (exceeded_max_files) {
            status = CL_EMAXFILES;
        }
    }

    return status;
}

/**
 * @brief Index local file headers between two file offsets
 *
 * This function indexes every file within certain file offsets in a zip file.
 * It places the indexed local file headers into a catalogue. If there are
 * already elements in the catalogue, it appends the found files to the
 * catalogue.
 *
 * The caller is responsible for freeing the catalogue.
 * The catalogue may contain duplicate items, which should be skipped.
 *
 * @param ctx               The scanning context
 * @param map               The file map
 * @param fsize             The file size
 * @param start_offset      The start file offset
 * @param end_offset        The end file offset
 * @param file_count        The number of files extracted from the zip file thus far
 * @param[out] temp_catalogue    A catalogue of zip_records. Found files between the two offset bounds will be appended to this list.
 * @param[out] num_records  The number of records in the catalogue.
 * @return cl_error_t  CL_SUCCESS if no overlapping files
 * @return cl_error_t  CL_VIRUS if overlapping files and heuristic alerts are enabled
 * @return cl_error_t  CL_EFORMAT if overlapping files and heuristic alerts are disabled
 * @return cl_error_t  CL_ETIMEOUT if the scan time limit is exceeded.
 * @return cl_error_t  CL_EMEM for memory allocation errors.
 */
cl_error_t index_local_file_headers_within_bounds(
    cli_ctx *ctx,
    fmap_t *map,
    uint32_t fsize,
    uint32_t start_offset,
    uint32_t end_offset,
    uint32_t file_count,
    struct zip_record **temp_catalogue,
    size_t *num_records)
{
    cl_error_t status = CL_ERROR;
    cl_error_t ret;

    size_t num_record_blocks = 0;
    size_t index             = 0;

    uint32_t search_offset           = 0;
    uint32_t total_file_count        = file_count;
    struct zip_record *zip_catalogue = NULL;
    bool exceeded_max_files          = false;

    if (NULL == temp_catalogue || NULL == num_records) {
        cli_errmsg("index_local_file_headers_within_bounds: Invalid NULL arguments\n");
        goto done;
    }

    zip_catalogue = *temp_catalogue;

    /*
     * Allocate zip_record if it is empty. If not empty, we will append file headers to the list
     */
    if (NULL == zip_catalogue) {
        CLI_CALLOC_OR_GOTO_DONE(
            zip_catalogue,
            1,
            sizeof(struct zip_record) * ZIP_RECORDS_CHECK_BLOCKSIZE,
            status = CL_EMEM);

        *num_records = 0;
    }

    num_record_blocks = (*num_records / ZIP_RECORDS_CHECK_BLOCKSIZE) + 1;
    index             = *num_records;

    if (start_offset > fsize || end_offset > fsize || start_offset > end_offset) {
        cli_errmsg("index_local_file_headers_within_bounds: Invalid offset arguments: start_offset=%u, end_offset=%u, fsize=%u\n",
                   start_offset, end_offset, fsize);
        status = CL_EPARSE;
        goto done;
    }

    /*
     * Search for local file headers between the start and end offsets. Append found file headers to zip_catalogue
     */
    for (search_offset = start_offset; search_offset < end_offset; search_offset++) {
        const char *local_file_header = fmap_need_off_once(map, search_offset, SIZEOF_LOCAL_HEADER);
        if (NULL == local_file_header) {
            break; // Reached the end of the file.
        }

        if (cli_readint32(local_file_header) == ZIP_MAGIC_LOCAL_FILE_HEADER) {
            uint32_t local_file_header_offset = search_offset;
            size_t file_record_size           = 0;

            ret = parse_local_file_header(
                ctx,
                local_file_header_offset,
                NULL,                    /* num_files_unzipped */
                total_file_count + 1,    /* file_count */
                NULL,                    /* central_header */
                NULL,                    /* tmpd */
                1,                       /* detect_encrypted */
                NULL,                    /* zcb */
                &(zip_catalogue[index]), /* record */
                &file_record_size);      /* file_record_size */

            if (file_record_size != 0 && CL_EPARSE != ret) {
                // Found a record.
                cli_dbgmsg("cli_unzip: Found a record\n");
                index++;
                total_file_count++;

                // increment search_offset by the size of the found local file header + file data
                // but decrement by 1 to account for the increment at the end of the loop
                search_offset += file_record_size - 1;
            }

            if (ret == CL_VIRUS) {
                status = CL_VIRUS;
                goto done;
            }

            if (cli_checktimelimit(ctx) != CL_SUCCESS) {
                cli_dbgmsg("cli_unzip: Time limit reached (max: %u)\n", ctx->engine->maxscantime);
                status = CL_ETIMEOUT;
                goto done;
            }

            /* stop checking file entries if we'll exceed maxfiles */
            if (ctx->engine->maxfiles && total_file_count >= ctx->engine->maxfiles) {
                cli_dbgmsg("cli_unzip: Files limit reached (max: %u)\n", ctx->engine->maxfiles);
                cli_append_potentially_unwanted_if_heur_exceedsmax(ctx, "Heuristics.Limits.Exceeded.MaxFiles");
                exceeded_max_files = true; // Set a bool so we can return the correct status code later.
                                           // We still need to scan the files we found while reviewing the file records up to this limit.
                break;
            }

            if (num_record_blocks * ZIP_RECORDS_CHECK_BLOCKSIZE == index + 1) {
                // Filled up the current block of zip records, need to allocate more space to fit additional records.
                cli_dbgmsg("cli_unzip: Filled a zip record block. Allocating an additional block for more zip records...\n");

                CLI_MAX_REALLOC_OR_GOTO_DONE(
                    zip_catalogue,
                    sizeof(struct zip_record) * ZIP_RECORDS_CHECK_BLOCKSIZE * (num_record_blocks + 1),
                    status = CL_EMEM);

                num_record_blocks++;
                /* zero out the memory for the new records */
                memset(&(zip_catalogue[index]), 0,
                       sizeof(struct zip_record) * (ZIP_RECORDS_CHECK_BLOCKSIZE * num_record_blocks - index));
            }
        }
    }

    *temp_catalogue = zip_catalogue;
    *num_records    = index;
    status          = CL_SUCCESS;

done:
    if (CL_SUCCESS != status) {
        if (NULL != zip_catalogue) {
            size_t i;
            for (i = 0; i < index; i++) {
                if (NULL != zip_catalogue[i].original_filename) {
                    free(zip_catalogue[i].original_filename);
                    zip_catalogue[i].original_filename = NULL;
                }
            }
            free(zip_catalogue);
            zip_catalogue   = NULL;
            *temp_catalogue = NULL; // zip_catalogue and *temp_catalogue have the same value. Set temp_catalogue to NULL to ensure no use after free
        }

        if (exceeded_max_files) {
            status = CL_EMAXFILES;
        }
    }

    return status;
}

/**
 * @brief Add files not present in the central directory to the catalogue
 *
 * This function indexes every file not present in the central directory.
 * It searches through all the local file headers in the zip file and
 * adds any that are found that were not already in the catalogue.
 *
 * The caller is responsible for freeing the catalogue.
 * The catalogue may contain duplicate items, which should be skipped.
 *
 * @param ctx               The scanning context
 * @param map               The file map
 * @param fsize             The file size
 * @param[in, out] catalogue    A catalogue of zip_records found in the central directory.
 * @param[in, out] num_records  The number of records in the catalogue.
 * @return cl_error_t  CL_SUCCESS if no overlapping files
 * @return cl_error_t  CL_VIRUS if overlapping files and heuristic alerts are enabled
 * @return cl_error_t  CL_EFORMAT if overlapping files and heuristic alerts are disabled
 * @return cl_error_t  CL_ETIMEOUT if the scan time limit is exceeded.
 * @return cl_error_t  CL_EMEM for memory allocation errors.
 */
cl_error_t index_local_file_headers(
    cli_ctx *ctx,
    fmap_t *map,
    uint32_t fsize,
    struct zip_record **catalogue,
    size_t *num_records)
{
    cl_error_t status = CL_ERROR;
    cl_error_t ret;

    uint32_t i               = 0;
    uint32_t start_offset    = 0;
    uint32_t end_offset      = 0;
    size_t total_files_found = 0;

    struct zip_record *temp_catalogue     = NULL;
    struct zip_record *combined_catalogue = NULL;
    struct zip_record *curr_record        = NULL;
    struct zip_record *next_record        = NULL;
    struct zip_record *prev_record        = NULL;
    size_t local_file_headers_count       = 0;
    uint32_t num_overlapping_files        = 0;

    if (NULL == catalogue || NULL == num_records || NULL == *catalogue) {
        cli_dbgmsg("index_local_file_headers: Invalid NULL arguments\n");
        goto done;
    }

    total_files_found = *num_records;

    /*
     * Generate a list of zip records found before, between, and after the zip records already in catalogue
     * First, scan between the start of the file and the first zip_record offset (or the end of the file if no zip_records have been found)
     */
    if (*num_records == 0) {
        end_offset = fsize;
    } else {
        end_offset = (*catalogue)[0].local_header_offset;
    }

    ret = index_local_file_headers_within_bounds(
        ctx,
        map,
        fsize,
        start_offset,
        end_offset,
        total_files_found,
        &temp_catalogue,
        &local_file_headers_count);
    if (CL_SUCCESS != ret) {
        goto done;
    }

    total_files_found += local_file_headers_count;

    /*
     * Search for zip records between the zip records already in the catalogue
     */
    for (i = 0; i < *num_records; i++) {
        // Before searching for more files, check if number of found files exceeds maxfiles
        if (ctx->engine->maxfiles && total_files_found >= ctx->engine->maxfiles) {
            cli_dbgmsg("cli_unzip: Files limit reached (max: %u)\n", ctx->engine->maxfiles);
            cli_append_potentially_unwanted_if_heur_exceedsmax(ctx, "Heuristics.Limits.Exceeded.MaxFiles");
            break;
        }

        curr_record  = &((*catalogue)[i]);
        start_offset = curr_record->local_header_offset + curr_record->local_header_size + curr_record->compressed_size;
        if (i + 1 == *num_records) {
            end_offset = fsize;
        } else {
            next_record = &((*catalogue)[i + 1]);
            end_offset  = next_record->local_header_offset;
        }

        ret = index_local_file_headers_within_bounds(
            ctx,
            map,
            fsize,
            start_offset,
            end_offset,
            total_files_found,
            &temp_catalogue,
            &local_file_headers_count);
        if (CL_SUCCESS != ret) {
            status = ret;
            goto done;
        }

        total_files_found = *num_records + local_file_headers_count;

        if (cli_checktimelimit(ctx) != CL_SUCCESS) {
            cli_dbgmsg("cli_unzip: Time limit reached (max: %u)\n", ctx->engine->maxscantime);
            status = CL_ETIMEOUT;
            goto done;
        }
    }

    /*
     * Combine the zip records already in the catalogue with the recently found zip records
     * Only do this if new zip records were found
     */
    if (local_file_headers_count > 0) {
        CLI_CALLOC_OR_GOTO_DONE(
            combined_catalogue,
            1,
            sizeof(struct zip_record) * ZIP_RECORDS_CHECK_BLOCKSIZE * (total_files_found + 1),
            status = CL_EMEM);

        // *num_records is the number of already found files
        // local_file_headers_count is the number of new files found
        // total_files_found is the sum of both of the above
        uint32_t temp_catalogue_offset = 0;
        uint32_t catalogue_offset      = 0;

        for (i = 0; i < total_files_found; i++) {
            // Conditions in which we add from temp_catalogue: it is the only one left OR
            if (catalogue_offset >= *num_records ||
                (temp_catalogue_offset < local_file_headers_count &&
                 temp_catalogue[temp_catalogue_offset].local_header_offset < (*catalogue)[catalogue_offset].local_header_offset)) {
                // add entry from temp_catalogue into the list
                combined_catalogue[i] = temp_catalogue[temp_catalogue_offset];
                temp_catalogue_offset++;
            } else {
                // add entry from the catalogue into the list
                combined_catalogue[i] = (*catalogue)[catalogue_offset];
                catalogue_offset++;
            }

            /*
             * Detect overlapping files.
             */
            if (i > 0) {
                prev_record = &(combined_catalogue[i - 1]);
                curr_record = &(combined_catalogue[i]);

                uint32_t prev_record_size = prev_record->local_header_size + prev_record->compressed_size;
                uint32_t curr_record_size = curr_record->local_header_size + curr_record->compressed_size;
                uint32_t prev_record_end;
                uint32_t curr_record_end;

                /* Check for integer overflow in 32bit size & offset values */
                if ((UINT32_MAX - prev_record_size < prev_record->local_header_offset) ||
                    (UINT32_MAX - curr_record_size < curr_record->local_header_offset)) {
                    cli_dbgmsg("cli_unzip: Integer overflow detected; invalid data sizes in zip file headers.\n");
                    status = CL_EFORMAT;
                    goto done;
                }

                prev_record_end = prev_record->local_header_offset + prev_record_size;
                curr_record_end = curr_record->local_header_offset + curr_record_size;

                if (((curr_record->local_header_offset >= prev_record->local_header_offset) && (curr_record->local_header_offset + ZIP_RECORD_OVERLAP_FUDGE_FACTOR < prev_record_end)) ||
                    ((prev_record->local_header_offset >= curr_record->local_header_offset) && (prev_record->local_header_offset + ZIP_RECORD_OVERLAP_FUDGE_FACTOR < curr_record_end))) {
                    /* Overlapping file detected */
                    num_overlapping_files++;

                    if ((curr_record->local_header_offset == prev_record->local_header_offset) &&
                        (curr_record->local_header_size == prev_record->local_header_size) &&
                        (curr_record->compressed_size == prev_record->compressed_size)) {
                        cli_dbgmsg("cli_unzip: Ignoring duplicate file entry at offset: 0x%x.\n", curr_record->local_header_offset);
                    } else {
                        cli_dbgmsg("cli_unzip: Overlapping files detected.\n");
                        cli_dbgmsg("    previous file end:  %u\n", prev_record_end);
                        cli_dbgmsg("    current file start: %u\n", curr_record->local_header_offset);

                        if (ZIP_MAX_NUM_OVERLAPPING_FILES < num_overlapping_files) {
                            status = CL_EFORMAT;
                            if (SCAN_HEURISTICS) {
                                ret = cli_append_potentially_unwanted(ctx, "Heuristics.Zip.OverlappingFiles");
                                if (CL_SUCCESS != ret) {
                                    status = ret;
                                }
                            }
                            goto done;
                        }
                    }
                }
            }

            if (cli_checktimelimit(ctx) != CL_SUCCESS) {
                cli_dbgmsg("cli_unzip: Time limit reached (max: %u)\n", ctx->engine->maxscantime);
                status = CL_ETIMEOUT;
                goto done;
            }
        }

        free(temp_catalogue);
        temp_catalogue = NULL;

        free(*catalogue);
        *catalogue         = combined_catalogue;
        combined_catalogue = NULL;

        *num_records = total_files_found;
    } else {
        free(temp_catalogue);
        temp_catalogue = NULL;
    }

    status = CL_SUCCESS;

done:
    if (CL_SUCCESS != status) {
        if (NULL != *catalogue) {
            size_t i;
            for (i = 0; i < (total_files_found - local_file_headers_count); i++) {
                if (NULL != (*catalogue)[i].original_filename) {
                    free((*catalogue)[i].original_filename);
                    (*catalogue)[i].original_filename = NULL;
                }
            }
            free(*catalogue);
            *catalogue = NULL;
        }
    }

    if (NULL != temp_catalogue) {
        size_t i;
        for (i = 0; i < local_file_headers_count; i++) {
            if (NULL != temp_catalogue[i].original_filename) {
                free(temp_catalogue[i].original_filename);
                temp_catalogue[i].original_filename = NULL;
            }
        }
        free(temp_catalogue);
        temp_catalogue = NULL;
    }

    if (NULL != combined_catalogue) {
        size_t i;
        for (i = 0; i < total_files_found; i++) {
            if (NULL != combined_catalogue[i].original_filename) {
                free(combined_catalogue[i].original_filename);
                combined_catalogue[i].original_filename = NULL;
            }
        }
        free(combined_catalogue);
        combined_catalogue = NULL;
    }

    return status;
}

/**
 * @brief Find the central directory header in a zip file.
 *
 * Find the central directory header, first by finding the End Of Central Directory header.
 *
 * The End Of Central Directory header is located at the end of the zip file and contains the offset of the central
 * directory and ends with a variable length comment.
 * We'll start searching for the magic bytes SIZEOF_END_OF_CENTRAL bytes from the end of the file, and work our way
 * backwards until we find the End Of Central Directory header magic bytes.
 *
 * @param map          The file map
 * @param fsize        The file size
 * @param[out] coff    The central directory offset
 * @return cl_error_t
 */
static cl_error_t find_central_directory_header(
    fmap_t *map,
    uint32_t fsize,
    uint32_t *coff)
{
    cl_error_t status = CL_ERROR;
    uint32_t eocoff   = 0;

    cli_dbgmsg("find_central_directory_header: Searching for End Of Central Directory header...\n");

    /*
     * Find the End Of Central Directory header.
     */
    for (eocoff = fsize - SIZEOF_END_OF_CENTRAL; eocoff > 0; eocoff--) {
        const char *eocptr = fmap_need_off_once(
            map,
            eocoff,
            SIZEOF_END_OF_CENTRAL - 2 /* -2 because don't need to read the comment length */);
        if (!eocptr) {
            // Failed to get a pointer within the file at that offset and size.
            continue;
        }

        if (cli_readint32(eocptr) == ZIP_MAGIC_CENTRAL_DIRECTORY_RECORD_END) {
            // Found the End Of Central Directory header.
            // Use it to find the central directory offset.
            cli_dbgmsg("find_central_directory_header: Found End Of Central Directory header at offset: 0x%x. "
                       "Searching for Central Directory header...\n",
                       eocoff);

            // The offset for the Central Directory header is stored at offset 16 in the End Of Central Directory header.
            uint32_t maybe_coff = cli_readint32(&eocptr[16]);

            if (!CLI_ISCONTAINED_0_TO(fsize, maybe_coff, SIZEOF_CENTRAL_HEADER)) {
                // The alleged central directory offset + size of the header is not within the file size.
                continue;
            }

            // Found it.
            cli_dbgmsg("find_central_directory_header: Found Central Directory header at offset: 0x%x\n", maybe_coff);
            *coff  = maybe_coff;
            status = CL_SUCCESS;
            break;
        }
    }

    if (CL_SUCCESS != status) {
        cli_dbgmsg("find_central_directory_header: Central directory header not found.\n");
        status = CL_EPARSE;
    }

    return status;
}

cl_error_t cli_unzip(cli_ctx *ctx)
{
    cl_error_t status = CL_ERROR;
    cl_error_t ret;

    size_t num_files_unzipped = 0;
    uint32_t fsize;
    uint32_t coff = 0;

    fmap_t *map = ctx->fmap;

    char *tmpd = NULL;

    int toval                        = 0;
    struct zip_record *zip_catalogue = NULL;
    size_t records_count             = 0;
    size_t i;

    cli_dbgmsg("in cli_unzip\n");
    fsize = (uint32_t)map->len;
    if (sizeof(off_t) != sizeof(uint32_t) && (size_t)fsize != map->len) {
        cli_dbgmsg("cli_unzip: file too big\n");
        status = CL_SUCCESS;
        goto done;
    }
    if (fsize < SIZEOF_CENTRAL_HEADER) {
        cli_dbgmsg("cli_unzip: file too short\n");
        status = CL_SUCCESS;
        goto done;
    }

    /*
     * Find the central directory header
     */
    ret = find_central_directory_header(
        map,
        fsize,
        &coff);
    if (CL_SUCCESS == ret) {
        cli_dbgmsg("cli_unzip: central directory header offset: 0x%x\n", coff);

        /*
         * Index the central directory.
         */
        ret = index_the_central_directory(
            ctx,
            coff,
            &zip_catalogue,
            &records_count);
        if (CL_SUCCESS != ret) {
            cli_dbgmsg("index_central_dir_failed, must rely purely on local file headers\n");

            CLI_CALLOC_OR_GOTO_DONE(
                zip_catalogue,
                1,
                sizeof(struct zip_record) * ZIP_RECORDS_CHECK_BLOCKSIZE,
                status = CL_EMEM);

            records_count = 0;
        }
    } else {
        cli_dbgmsg("cli_unzip: central directory header not found, must rely purely on local file headers\n");

        CLI_CALLOC_OR_GOTO_DONE(
            zip_catalogue,
            1,
            sizeof(struct zip_record) * ZIP_RECORDS_CHECK_BLOCKSIZE,
            status = CL_EMEM);

        records_count = 0;
    }

    /*
     * Add local file headers not referenced by the central directory.
     */
    ret = index_local_file_headers(
        ctx,
        map,
        fsize,
        &zip_catalogue,
        &records_count);
    if (CL_SUCCESS != ret) {
        cli_dbgmsg("index_local_file_headers_failed\n");
        status = ret;
        goto done;
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
            cli_dbgmsg("cli_unzip: Skipping unzipping of duplicate file entry at offset: 0x%x\n", zip_catalogue[i].local_header_offset);
            continue;
        }

        // Get a pointer to the compressed data, is just after the local header.
        compressed_data = fmap_need_off(
            map,
            zip_catalogue[i].local_header_offset + zip_catalogue[i].local_header_size,
            zip_catalogue[i].compressed_size);

        if (zip_catalogue[i].encrypted) {
            if (fmap_need_ptr_once(map, compressed_data, zip_catalogue[i].compressed_size)) {
                status = zdecrypt(
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
                // If we cannot get a pointer to the compressed data, we cannot decrypt it.
                // Skip this file.
                cli_dbgmsg("cli_unzip: Skipping decryption of file entry at offset: 0x%x, size: %u, compressed data not available\n",
                           zip_catalogue[i].local_header_offset,
                           zip_catalogue[i].compressed_size);
            }
        } else {
            if (fmap_need_ptr_once(map, compressed_data, zip_catalogue[i].compressed_size)) {
                status = unz(
                    compressed_data,
                    zip_catalogue[i].compressed_size,
                    zip_catalogue[i].uncompressed_size,
                    zip_catalogue[i].method,
                    zip_catalogue[i].flags,
                    &num_files_unzipped,
                    ctx,
                    tmpd,
                    zip_scan_cb,
                    zip_catalogue[i].original_filename,
                    false);
            } else {
                // If we cannot get a pointer to the compressed data, we cannot decompress it.
                // Skip this file.
                cli_dbgmsg("cli_unzip: Skipping decompression of file entry at offset: 0x%x, size: %u, compressed data not available\n",
                           zip_catalogue[i].local_header_offset,
                           zip_catalogue[i].compressed_size);
            }
        }

        if (ctx->engine->maxfiles && num_files_unzipped >= ctx->engine->maxfiles) {
            // Note: this check piggybacks on the MaxFiles setting, but is not actually
            //   scanning these files or incrementing the ctx->scannedfiles count
            // This check is also redundant. zip_scan_cb == cli_magic_scan_desc,
            //   so we will also check and update the limits for the actual number of scanned
            //   files inside cli_magic_scan()
            cli_dbgmsg("cli_unzip: Files limit reached (max: %u)\n", ctx->engine->maxfiles);
            cli_append_potentially_unwanted_if_heur_exceedsmax(ctx, "Heuristics.Limits.Exceeded.MaxFiles");
            status = CL_EMAXFILES;
            goto done;
        }

        if (cli_checktimelimit(ctx) != CL_SUCCESS) {
            cli_dbgmsg("cli_unzip: Time limit reached (max: %u)\n", ctx->engine->maxscantime);
            status = CL_ETIMEOUT;
            goto done;
        }

        if (cli_json_timeout_cycle_check(ctx, &toval) != CL_SUCCESS) {
            status = CL_ETIMEOUT;
            goto done;
        }

        if (ctx->abort_scan) {
            // The scan was aborted, stop processing files.
            // This also takes into account CL_VIRUS status (to abort on detection when not in allmatch mode).
            break;
        }

        // Continue to the next file entry even if the current one failed.
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

    return status;
}

cl_error_t unzip_single_internal(cli_ctx *ctx, size_t local_header_offset, zip_cb zcb)
{
    cl_error_t ret = CL_SUCCESS;

    size_t num_files_unzipped = 0;

    cli_dbgmsg("in cli_unzip_single\n");

    if (NULL == ctx || NULL == ctx->fmap) {
        cli_dbgmsg("cli_unzip_single: Invalid NULL arguments\n");
        return CL_ENULLARG;
    }

    if (local_header_offset + SIZEOF_LOCAL_HEADER > ctx->fmap->len) {
        cli_dbgmsg("cli_unzip: file too short\n");
        return CL_SUCCESS;
    }

    ret = parse_local_file_header(
        ctx,
        local_header_offset,
        &num_files_unzipped,
        0,    /* file_count */
        NULL, /* central_header*/
        NULL, /* tmpd */
        0,    /* detect_encrypted */
        zcb,
        NULL,  /* record */
        NULL); /* file_record_size */

    return ret;
}

cl_error_t cli_unzip_single(cli_ctx *ctx, size_t local_header_offset)
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

cl_error_t unzip_search(cli_ctx *ctx, struct zip_requests *requests)
{
    cl_error_t status = CL_ERROR;
    cl_error_t ret;
    size_t file_count = 0;
    uint32_t coff     = 0;
    uint32_t toval    = 0;

    size_t file_record_size = 0;

    cli_dbgmsg("in unzip_search\n");

    if (NULL == ctx || NULL == ctx->fmap) {
        return CL_ENULLARG;
    }

    if (ctx->fmap->len < SIZEOF_CENTRAL_HEADER) {
        cli_dbgmsg("unzip_search: file too short\n");
        status = CL_SUCCESS;
        goto done;
    }

    /*
     * Find the central directory header
     */
    ret = find_central_directory_header(
        ctx->fmap,
        ctx->fmap->len,
        &coff);
    if (CL_SUCCESS == ret) {
        uint32_t central_file_header_offset = coff;
        cli_dbgmsg("unzip_search: central directory header offset: 0x%x\n", central_file_header_offset);
        do {
            ret = parse_central_directory_file_header(
                ctx,
                central_file_header_offset,
                NULL, /* num_files_unzipped */
                file_count + 1,
                NULL, /* tmpd */
                requests,
                NULL, /* record */
                &file_record_size);

            if (requests->match) {
                // Found a match.
                status = CL_VIRUS;
                goto done;
            }

            file_count++;
            if (ctx && ctx->engine->maxfiles && file_count >= ctx->engine->maxfiles) {
                // Note: this check piggybacks on the MaxFiles setting, but is not actually
                //   scanning these files or incrementing the ctx->scannedfiles count
                cli_dbgmsg("cli_unzip: Files limit reached (max: %u)\n", ctx->engine->maxfiles);
                cli_append_potentially_unwanted_if_heur_exceedsmax(ctx, "Heuristics.Limits.Exceeded.MaxFiles");
                status = CL_EMAXFILES;
                goto done;
            }

            if (ctx && cli_json_timeout_cycle_check(ctx, (int *)(&toval)) != CL_SUCCESS) {
                status = CL_ETIMEOUT;
                goto done;
            }

            // Increment to the next central file header.
            central_file_header_offset += file_record_size;
        } while ((ret == CL_SUCCESS) && (file_record_size > 0));
    } else {
        cli_dbgmsg("unzip_search: Cannot locate central directory. unzip_search failed.\n");
        status = CL_EPARSE;
        goto done;
    }

done:
    return status;
}

cl_error_t unzip_search_single(cli_ctx *ctx, const char *name, size_t nlen, uint32_t *loff)
{
    cl_error_t status            = CL_ERROR;
    struct zip_requests requests = {0};

    cli_dbgmsg("in unzip_search_single\n");
    if (!ctx) {
        status = CL_ENULLARG;
        goto done;
    }

    // Add the file name to the requests.
    status = unzip_search_add(&requests, name, nlen);
    if (CL_SUCCESS != status) {
        cli_dbgmsg("unzip_search_single: Failed to add file name to requests\n");
        goto done;
    }

    // Search for the zip file entry in the current layer.
    status = unzip_search(ctx, &requests);
    if (CL_VIRUS == status) {
        *loff = requests.loff;
    }

done:
    return status;
}

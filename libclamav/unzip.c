/*
 *  Copyright (C) 2013-2026 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
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

// How far back from the end of central directory record we're willing to search for the ZIP64
// end of central directory record when the ZIP64 locator isn't where the spec says it should be.
// The locator is 20 bytes and the extensible data sector is normally empty, so this is generous.
#define ZIP64_END_OF_CENTRAL_SEARCH_RANGE 4096

#define ZIP_CRC32(r, c, b, l) \
    do {                      \
        r = crc32(~c, b, l);  \
        r = ~r;               \
    } while (0)

#define ZIP_RECORDS_CHECK_BLOCKSIZE 100
/**
 * @brief The central directory file header values needed when parsing a local file header.
 *
 * A file entry written with a data descriptor (F_USEDD) does not have usable sizes in its
 * local file header, so they have to come from the central directory file header instead.
 *
 * These values have already had any ZIP64 extra field applied, so that the ZIP64
 * placeholders are resolved in exactly one place.
 */
struct zip_central_record {
    uint64_t csize;
    uint64_t usize;

    /* true if the central directory file header carried a ZIP64 extra field. */
    bool is_zip64;
};

struct zip_record {
    uint64_t local_header_offset;
    uint64_t local_header_size;
    uint64_t compressed_size;
    uint64_t uncompressed_size;
    uint16_t method;
    uint16_t flags;
    int encrypted;
    char *original_filename;
};

/**
 * @brief Move a zip record and its owned resources to another record.
 */
static void zip_record_move(struct zip_record *dst, struct zip_record *src)
{
    *dst = *src;
    src->original_filename = NULL;
}

/**
 * @brief Check that a 64-bit value from a ZIP header can be used as a size_t.
 *
 * ZIP64 headers carry 64-bit sizes and offsets but the fmap API works in size_t.
 * On a 32-bit host an implicit conversion would silently truncate, so check before
 * converting rather than trusting the cast.
 */
static inline bool zip_u64_fits_size_t(uint64_t value)
{
#if SIZE_MAX < UINT64_MAX
    return value <= (uint64_t)SIZE_MAX;
#else
    (void)value;
    return true;
#endif
}

static int wrap_inflateinit2(void *a, int b)
{
    return inflateInit2(a, b);
}

/**
 * @brief Clamp the amount of compressed data handed to zlib/bzip2 per call.
 *
 * zlib's (and bzip2's) avail_in is a 32-bit type, but a ZIP64 member can have a 64-bit
 * csize. The inflate loop tops up avail_in with another chunk whenever it runs dry.
 */
static inline uint32_t zip_inflate_chunk(uint64_t remaining)
{
    return (remaining > UINT32_MAX) ? UINT32_MAX : (uint32_t)remaining;
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
                    cli_append_potentially_unwanted_if_heur_exceedsmax(ctx, "Heuristics.Limits.Exceeded.MaxFileSize");
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

            uint64_t in_remaining = csize;

            *next_in   = (void *)src;
            *next_out  = obuf;
            *avail_in  = zip_inflate_chunk(in_remaining);
            in_remaining -= *avail_in;
            *avail_out = sizeof(obuf);
            if (unz_init(&strm, -wbits) != Z_OK) {
                cli_dbgmsg("cli_unzip: zinit failed\n");
                break;
            }
            while (1) {
                if ((0 == *avail_in) && (in_remaining > 0)) {
                    /* zlib's avail_in is 32-bit; top it up for ZIP64 members with csize > 4 GiB. */
                    *avail_in = zip_inflate_chunk(in_remaining);
                    in_remaining -= *avail_in;
                }
                while ((res = unz_unz(&strm, Z_NO_FLUSH)) == Z_OK) {
                };
                if (*avail_out != sizeof(obuf)) {
                    written += sizeof(obuf) - (*avail_out);
                    if (ctx->engine->maxfilesize && written > ctx->engine->maxfilesize) {
                        cli_dbgmsg("cli_unzip: trimming output size to maxfilesize (" STDu64 ")\n",
                                   ctx->engine->maxfilesize);
                        cli_append_potentially_unwanted_if_heur_exceedsmax(ctx, "Heuristics.Limits.Exceeded.MaxFileSize");
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
            if (in_remaining > 0) {
                /* The stream ended (or hit maxfilesize) before consuming all of the input. */
                cli_dbgmsg("cli_unzip: inflate finished with %" PRIu64 " bytes of input unconsumed\n",
                           in_remaining);
            }
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
                        cli_append_potentially_unwanted_if_heur_exceedsmax(ctx, "Heuristics.Limits.Exceeded.MaxFileSize");
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
                        cli_append_potentially_unwanted_if_heur_exceedsmax(ctx, "Heuristics.Limits.Exceeded.MaxFileSize");
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
    uint64_t csize,
    uint64_t usize,
    const uint8_t *local_header,
    size_t *num_files_unzipped,
    cli_ctx *ctx,
    char *tmpd,
    zip_cb zcb,
    const char *original_filename)
{
    cl_error_t ret;
    int v = 0;
    uint64_t i;
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

cl_error_t cli_zip_parse_zip64_extra_field(
    const uint8_t *extra_field,
    size_t extra_field_len,
    bool is_central_directory,
    uint32_t csize32,
    uint32_t usize32,
    uint32_t local_header_offset32,
    uint16_t disk_num16,
    struct zip64_extra_info *zip64_info)
{
    cl_error_t status = CL_ERROR;
    size_t offset     = 0;

    if (NULL == zip64_info) {
        cli_errmsg("cli_zip_parse_zip64_extra_field: Invalid NULL arguments\n");
        status = CL_ENULLARG;
        goto done;
    }

    memset(zip64_info, 0, sizeof(*zip64_info));

    if (0 == extra_field_len) {
        // No extra field. Not an error, there is simply no ZIP64 information to be had.
        status = CL_SUCCESS;
        goto done;
    }

    if (NULL == extra_field) {
        cli_errmsg("cli_zip_parse_zip64_extra_field: Invalid NULL extra field with non-zero length\n");
        status = CL_ENULLARG;
        goto done;
    }

    /*
     * The extra field is a sequence of records, each introduced by a 2-byte header ID and a
     * 2-byte data size. Walk the sequence looking for the ZIP64 record.
     *
     * Note: every iteration advances by at least SIZEOF_EXTRA_FIELD_HEADER bytes, so a record
     * with a zero data size cannot cause an infinite loop.
     */
    while (extra_field_len - offset >= SIZEOF_EXTRA_FIELD_HEADER) {
        uint16_t header_id    = (uint16_t)cli_readint16(extra_field + offset);
        uint16_t data_size    = (uint16_t)cli_readint16(extra_field + offset + 2);
        const uint8_t *data   = extra_field + offset + SIZEOF_EXTRA_FIELD_HEADER;
        size_t data_available = extra_field_len - offset - SIZEOF_EXTRA_FIELD_HEADER;
        size_t data_remaining;

        if ((size_t)data_size > data_available) {
            /*
             * This record claims more data than the extra field has left.
             * Stop walking rather than failing the header outright; anything already
             * collected is still usable, and the caller can fall back on the 32-bit fields.
             */
            cli_dbgmsg("cli_zip_parse_zip64_extra_field: extra field record 0x%04x claims %u bytes but only %zu remain\n",
                       header_id, data_size, data_available);
            break;
        }

        if (ZIP_EXTRA_FIELD_ID_ZIP64 != header_id) {
            // Some other extra field record (timestamps, unix uid/gid, ...). Skip it.
            offset += SIZEOF_EXTRA_FIELD_HEADER + (size_t)data_size;
            continue;
        }

        data_remaining = data_size;

        if (!is_central_directory) {
            /*
             * 4.5.3: in a local file header the uncompressed and compressed sizes are both
             * mandatory and always present, in that order, so the record is at least 16 bytes.
             */
            if (data_remaining < 16) {
                cli_dbgmsg("cli_zip_parse_zip64_extra_field: local file header ZIP64 record is too short: %u bytes\n",
                           data_size);
                status = CL_EFORMAT;
                goto done;
            }

            zip64_info->usize      = (uint64_t)cli_readint64(data);
            zip64_info->have_usize = true;
            zip64_info->csize      = (uint64_t)cli_readint64(data + 8);
            zip64_info->have_csize = true;

            status = CL_SUCCESS;
            goto done;
        }

        /*
         * 4.5.3: in a central directory file header the fields appear in this fixed order, but
         * only those whose original header field holds the "all ones" placeholder are stored.
         * That is why the caller has to hand us the original 32-bit (and 16-bit) values.
         */
        if (ZIP64_PLACEHOLDER_32 == usize32) {
            if (data_remaining < 8) {
                cli_dbgmsg("cli_zip_parse_zip64_extra_field: central directory ZIP64 record is missing the uncompressed size\n");
                status = CL_EFORMAT;
                goto done;
            }
            zip64_info->usize      = (uint64_t)cli_readint64(data);
            zip64_info->have_usize = true;
            data += 8;
            data_remaining -= 8;
        }

        if (ZIP64_PLACEHOLDER_32 == csize32) {
            if (data_remaining < 8) {
                cli_dbgmsg("cli_zip_parse_zip64_extra_field: central directory ZIP64 record is missing the compressed size\n");
                status = CL_EFORMAT;
                goto done;
            }
            zip64_info->csize      = (uint64_t)cli_readint64(data);
            zip64_info->have_csize = true;
            data += 8;
            data_remaining -= 8;
        }

        if (ZIP64_PLACEHOLDER_32 == local_header_offset32) {
            if (data_remaining < 8) {
                cli_dbgmsg("cli_zip_parse_zip64_extra_field: central directory ZIP64 record is missing the local header offset\n");
                status = CL_EFORMAT;
                goto done;
            }
            zip64_info->local_header_offset      = (uint64_t)cli_readint64(data);
            zip64_info->have_local_header_offset = true;
            data += 8;
            data_remaining -= 8;
        }

        if (ZIP64_PLACEHOLDER_16 == disk_num16) {
            if (data_remaining < 4) {
                cli_dbgmsg("cli_zip_parse_zip64_extra_field: central directory ZIP64 record is missing the disk number\n");
                status = CL_EFORMAT;
                goto done;
            }
            zip64_info->disk_num      = (uint32_t)cli_readint32(data);
            zip64_info->have_disk_num = true;
            // This is the last field, so `data` and `data_remaining` are not advanced.
        }

        status = CL_SUCCESS;
        goto done;
    }

    // Walked the whole extra field without finding a usable ZIP64 record. That is fine.
    status = CL_SUCCESS;

done:
    if (CL_SUCCESS != status && NULL != zip64_info) {
        // Don't hand back a half-filled struct.
        memset(zip64_info, 0, sizeof(*zip64_info));
    }

    return status;
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
 * @param central_record                (optional) the ZIP64-resolved sizes from the matching central directory file header
 * @param tmpd                          temp directory path name
 * @param detect_encrypted              bool: if encrypted files should raise heuristic alert
 * @param zcb                           callback function to invoke after extraction (default: scan)
 * @param record                        (optional) a pointer to a struct to store file record information.
 * @param[out] file_record_size         (optional) if not NULL, will be set to the size of the file header + file data.
 * @return cl_error_t                   CL_SUCCESS on success, or an error code on failure.
 */
static cl_error_t parse_local_file_header(
    cli_ctx *ctx,
    size_t loff,
    size_t *num_files_unzipped,
    size_t file_count,
    const struct zip_central_record *central_record,
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
    uint64_t csize = 0, usize = 0;

    uint32_t name_size = 0;
    const char *src    = NULL;

    const uint8_t *zip     = NULL;
    size_t bytes_remaining = 0;

    struct zip64_extra_info zip64_info = {0};
    bool is_zip64                      = false;

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

    /*
     * Parse the extra field before anything else looks at the sizes.
     *
     * In a ZIP64 archive the 32-bit size fields hold the 0xFFFFFFFF placeholder and the real
     * 64-bit sizes live in the Zip64 Extended Information Extra Field. We need those resolved
     * before matching metadata or bounds checking the file data.
     * See the ZIP64 notes in unzip.h.
     */
    if (bytes_remaining <= LOCAL_HEADER_elen) {
        cli_dbgmsg("cli_unzip: local header - extra out of file\n");
        status = CL_EPARSE;
        goto done;
    }

    if (0 != LOCAL_HEADER_elen) {
        const uint8_t *extra_field = fmap_need_ptr_once(ctx->fmap, zip, LOCAL_HEADER_elen);
        if (NULL == extra_field) {
            cli_dbgmsg("cli_unzip: local header - extra field not available\n");
        } else {
            ret = cli_zip_parse_zip64_extra_field(
                extra_field,
                LOCAL_HEADER_elen,
                false, /* is_central_directory */
                LOCAL_HEADER_csize,
                LOCAL_HEADER_usize,
                0, /* local_header_offset32: central directory only */
                0, /* disk_num16: central directory only */
                &zip64_info);
            if (CL_SUCCESS != ret) {
                // Malformed ZIP64 record. Fall back on the 32-bit fields.
                cli_dbgmsg("cli_unzip: local header - failed to parse the ZIP64 extra field: %s (%d)\n",
                           cl_strerror(ret), ret);
            } else if (zip64_info.have_csize || zip64_info.have_usize) {
                is_zip64 = true;
                cli_dbgmsg("cli_unzip: local header - ZIP64 extra field - csize %" PRIu64 " - usize %" PRIu64 "\n",
                           zip64_info.csize, zip64_info.usize);
            }
        }
    }

    zip += LOCAL_HEADER_elen;
    bytes_remaining -= LOCAL_HEADER_elen;

    /*
     * Resolve the compressed and uncompressed sizes.
     */
    if (LOCAL_HEADER_flags & F_USEDD) {
        cli_dbgmsg("cli_unzip: local header - has data desc\n");
        if (NULL == central_record) {
            // The local file header sizes aren't usable and we have no central directory
            // file header to get them from.
            status = CL_EPARSE;
            goto done;
        }

        // The central directory values already have any ZIP64 extra field applied.
        usize = central_record->usize;
        csize = central_record->csize;

        if (central_record->is_zip64) {
            // The data descriptor sizes are 8 bytes wide for a ZIP64 entry.
            is_zip64 = true;
        }
    } else {
        usize = zip64_info.have_usize ? zip64_info.usize : (uint64_t)LOCAL_HEADER_usize;
        csize = zip64_info.have_csize ? zip64_info.csize : (uint64_t)LOCAL_HEADER_csize;
    }

    /* Print ZMD container metadata signature and try matching the metadata AFTER we have all the metadata. */
    cli_dbgmsg("cli_unzip: local header - ZMDNAME:%d:%s:%" PRIu64 ":%" PRIu64 ":%x:%u:%zu:%u\n",
               ((LOCAL_HEADER_flags & F_ENCR) != 0), name, usize, csize, LOCAL_HEADER_crc32, LOCAL_HEADER_method, file_count, ctx->recursion_level);
    /* ZMDfmt virname:encrypted(0-1):filename(exact|*):usize(exact|*):csize(exact|*):crc32(exact|*):method(exact|*):fileno(exact|*):maxdepth(exact|*) */

    /* Scan file header metadata. */
    ret = cli_matchmeta(ctx, name, csize, usize, (LOCAL_HEADER_flags & F_ENCR) != 0, file_count, LOCAL_HEADER_crc32);
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
            // csize is bounded by bytes_remaining above, so it is known to fit in a size_t.
            zip = fmap_need_ptr_once(ctx->fmap, zip, (size_t)csize);
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
        /*
         * The data descriptor holds the crc-32 followed by the compressed and uncompressed
         * sizes. For a ZIP64 entry (4.3.9.2) those two sizes are 8 bytes wide instead of 4,
         * making the descriptor 20 bytes rather than 12.
         */
        size_t data_descriptor_size = is_zip64 ? 20 : 12;

        if (bytes_remaining < data_descriptor_size) {
            cli_dbgmsg("cli_unzip: local header - data desc out of file\n");
            status = CL_EPARSE;
            goto done;
        }

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
        if (NULL == fmap_need_ptr_once(ctx->fmap, zip, 4)) {
            cli_dbgmsg("cli_unzip: local header - data desc out of file\n");
            status = CL_EPARSE;
            goto done;
        }

        if (cli_readint32(zip) == ZIP_MAGIC_FILE_BEGIN_SPLIT_OR_SPANNED) {
            cli_dbgmsg("cli_unzip: local header - split/spanned archive detected\n");

            // Re-check the bounds now that we know the optional signature is also present.
            if (bytes_remaining - data_descriptor_size < 4) {
                cli_dbgmsg("cli_unzip: local header - data desc out of file\n");
                status = CL_EPARSE;
                goto done;
            }

            /* skip the split/spanned signature */
            zip += 4;
            bytes_remaining -= 4;
        }

        zip += data_descriptor_size;
        bytes_remaining -= data_descriptor_size;
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
    size_t offset,
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
        NULL,  /* central_record */
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

    struct zip64_extra_info zip64_info       = {0};
    struct zip_central_record central_record = {0};
    uint64_t local_header_offset             = 0;

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

    // `index` is now at the start of the extra field.

    /*
     * Parse the extra field before using any of the sizes or the local header offset.
     *
     * In a ZIP64 archive the 32-bit size and offset fields hold the 0xFFFFFFFF placeholder
     * and the real 64-bit values live in the Zip64 Extended Information Extra Field.
     * Unlike the local file header, only the fields whose 32-bit counterpart holds the
     * placeholder are actually stored. See the ZIP64 notes in unzip.h.
     */
    if (0 != CENTRAL_HEADER_extra_len) {
        const uint8_t *extra_field = fmap_need_off_once(ctx->fmap, index, CENTRAL_HEADER_extra_len);
        if (NULL == extra_field) {
            cli_dbgmsg("cli_unzip: central header - extra field not available\n");
        } else {
            ret = cli_zip_parse_zip64_extra_field(
                extra_field,
                CENTRAL_HEADER_extra_len,
                true, /* is_central_directory */
                CENTRAL_HEADER_csize,
                CENTRAL_HEADER_usize,
                CENTRAL_HEADER_off,
                CENTRAL_HEADER_disk_num,
                &zip64_info);
            if (CL_SUCCESS != ret) {
                // Malformed ZIP64 record. Fall back on the 32-bit fields.
                cli_dbgmsg("cli_unzip: central header - failed to parse the ZIP64 extra field: %s (%d)\n",
                           cl_strerror(ret), ret);
            }
        }
    }

    central_record.csize    = zip64_info.have_csize ? zip64_info.csize : (uint64_t)CENTRAL_HEADER_csize;
    central_record.usize    = zip64_info.have_usize ? zip64_info.usize : (uint64_t)CENTRAL_HEADER_usize;
    central_record.is_zip64 = zip64_info.have_csize || zip64_info.have_usize ||
                              zip64_info.have_local_header_offset || zip64_info.have_disk_num;

    local_header_offset = zip64_info.have_local_header_offset ? zip64_info.local_header_offset
                                                             : (uint64_t)CENTRAL_HEADER_off;

    if (central_record.is_zip64) {
        cli_dbgmsg("cli_unzip: central header - ZIP64 extra field - csize %" PRIu64 " - usize %" PRIu64 " - off %" PRIu64 "\n",
                   central_record.csize, central_record.usize, local_header_offset);
    }

    /* requests do not supply a ctx; also prevent multiple scans */
    ret = cli_matchmeta(ctx, name, central_record.csize, central_record.usize, (CENTRAL_HEADER_flags & F_ENCR) != 0, file_count, CENTRAL_HEADER_crc32);
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

    if (!zip_u64_fits_size_t(local_header_offset)) {
        cli_dbgmsg("cli_unzip: central header - local header offset exceeds the addressable range\n");
        status = CL_EFORMAT;
        goto done;
    }

    if (!requests) {
        // Parse the local file header.
        // We'll verify enough bytes available for a local file header when we parse it.

        status = parse_local_file_header(
            ctx,
            (size_t)local_header_offset,
            num_files_unzipped,
            file_count,
            &central_record,
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
                requests->loff  = (size_t)local_header_offset;
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
    size_t coff,
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

            uint64_t prev_record_size = prev_record->local_header_size + prev_record->compressed_size;
            uint64_t curr_record_size = curr_record->local_header_size + curr_record->compressed_size;
            uint64_t prev_record_end;
            uint64_t curr_record_end;

            /* Check for integer overflow in the 64bit size & offset values */
            if ((UINT64_MAX - prev_record_size < prev_record->local_header_offset) ||
                (UINT64_MAX - curr_record_size < curr_record->local_header_offset)) {
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
                    cli_dbgmsg("cli_unzip: Ignoring duplicate file entry at offset: 0x%" PRIx64 ".\n", curr_record->local_header_offset);
                } else {
                    cli_dbgmsg("cli_unzip: Overlapping files detected.\n");
                    cli_dbgmsg("    previous file end:  %" PRIu64 "\n", prev_record_end);
                    cli_dbgmsg("    current file start: %" PRIu64 "\n", curr_record->local_header_offset);

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
 * @param[out] temp_catalogue     A catalogue of zip_records. Found files between the two offset bounds will be appended to this list.
 * @param[in, out] num_records       The number of records in the catalogue.
 * @param[in, out] num_record_blocks The number of allocated ZIP_RECORDS_CHECK_BLOCKSIZE blocks in the catalogue.
 * @return cl_error_t  CL_SUCCESS if no overlapping files
 * @return cl_error_t  CL_VIRUS if overlapping files and heuristic alerts are enabled
 * @return cl_error_t  CL_EFORMAT if overlapping files and heuristic alerts are disabled
 * @return cl_error_t  CL_ETIMEOUT if the scan time limit is exceeded.
 * @return cl_error_t  CL_EMEM for memory allocation errors.
 */
cl_error_t index_local_file_headers_within_bounds(
    cli_ctx *ctx,
    fmap_t *map,
    size_t fsize,
    size_t start_offset,
    size_t end_offset,
    size_t file_count,
    struct zip_record **temp_catalogue,
    size_t *num_records,
    size_t *num_record_blocks)
{
    cl_error_t status = CL_ERROR;
    cl_error_t ret;

    size_t index = 0;

    size_t search_offset             = 0;
    size_t total_file_count          = file_count;
    struct zip_record *zip_catalogue = NULL;
    bool exceeded_max_files          = false;

    if (NULL == temp_catalogue || NULL == num_records || NULL == num_record_blocks) {
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

        *num_records       = 0;
        *num_record_blocks = 1;
    } else if (0 == *num_record_blocks) {
        cli_errmsg("index_local_file_headers_within_bounds: Invalid zero catalogue capacity\n");
        status = CL_EARG;
        goto done;
    }

    index = *num_records;

    if (start_offset > fsize || end_offset > fsize || start_offset > end_offset) {
        cli_errmsg("index_local_file_headers_within_bounds: Invalid offset arguments: start_offset=%zu, end_offset=%zu, fsize=%zu\n",
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
            size_t local_file_header_offset = search_offset;
            size_t file_record_size         = 0;
            size_t record_capacity          = *num_record_blocks * ZIP_RECORDS_CHECK_BLOCKSIZE;

            if (record_capacity <= index) {
                size_t new_record_blocks = (index / ZIP_RECORDS_CHECK_BLOCKSIZE) + 1;

                // Filled the available zip record blocks. Allocate more space before writing the next record.
                cli_dbgmsg("cli_unzip: Filled zip record blocks. Allocating more space for zip records...\n");

                CLI_MAX_REALLOC_OR_GOTO_DONE(
                    zip_catalogue,
                    sizeof(struct zip_record) * ZIP_RECORDS_CHECK_BLOCKSIZE * new_record_blocks,
                    status = CL_EMEM);

                /* zero out the memory for the new records */
                memset(&(zip_catalogue[record_capacity]), 0,
                       sizeof(struct zip_record) * (ZIP_RECORDS_CHECK_BLOCKSIZE * new_record_blocks - record_capacity));
                *num_record_blocks = new_record_blocks;
            }

            ret = parse_local_file_header(
                ctx,
                local_file_header_offset,
                NULL,                    /* num_files_unzipped */
                total_file_count + 1,    /* file_count */
                NULL,                    /* central_record */
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
            *num_record_blocks = 0;
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
    size_t fsize,
    struct zip_record **catalogue,
    size_t *num_records)
{
    cl_error_t status = CL_ERROR;
    cl_error_t ret;

    size_t i                 = 0;
    size_t start_offset      = 0;
    size_t end_offset        = 0;
    size_t total_files_found = 0;

    struct zip_record *temp_catalogue     = NULL;
    struct zip_record *combined_catalogue = NULL;
    struct zip_record *curr_record        = NULL;
    struct zip_record *next_record        = NULL;
    struct zip_record *prev_record        = NULL;
    size_t local_file_headers_count       = 0;
    size_t local_file_headers_blocks      = 0;
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
        // Catalogue offsets are 64-bit (ZIP64) but are always within the map, so narrowing to
        // a size_t search bound here is safe. index_local_file_headers_within_bounds() still
        // validates the bounds against the file size.
        end_offset = (size_t)(*catalogue)[0].local_header_offset;
    }

    ret = index_local_file_headers_within_bounds(
        ctx,
        map,
        fsize,
        start_offset,
        end_offset,
        total_files_found,
        &temp_catalogue,
        &local_file_headers_count,
        &local_file_headers_blocks);
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
        start_offset = (size_t)(curr_record->local_header_offset + curr_record->local_header_size + curr_record->compressed_size);
        if (i + 1 == *num_records) {
            end_offset = fsize;
        } else {
            next_record = &((*catalogue)[i + 1]);
            end_offset  = (size_t)next_record->local_header_offset;
        }

        ret = index_local_file_headers_within_bounds(
            ctx,
            map,
            fsize,
            start_offset,
            end_offset,
            total_files_found,
            &temp_catalogue,
            &local_file_headers_count,
            &local_file_headers_blocks);
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
        size_t temp_catalogue_offset = 0;
        size_t catalogue_offset      = 0;

        for (i = 0; i < total_files_found; i++) {
            // Conditions in which we add from temp_catalogue: it is the only one left OR
            if (catalogue_offset >= *num_records ||
                (temp_catalogue_offset < local_file_headers_count &&
                 temp_catalogue[temp_catalogue_offset].local_header_offset < (*catalogue)[catalogue_offset].local_header_offset)) {
                // add entry from temp_catalogue into the list
                zip_record_move(
                    &combined_catalogue[i],
                    &temp_catalogue[temp_catalogue_offset]);
                temp_catalogue_offset++;
            } else {
                // add entry from the catalogue into the list
                zip_record_move(
                    &combined_catalogue[i],
                    &((*catalogue)[catalogue_offset]));
                catalogue_offset++;
            }

            /*
             * Detect overlapping files.
             */
            if (i > 0) {
                prev_record = &(combined_catalogue[i - 1]);
                curr_record = &(combined_catalogue[i]);

                uint64_t prev_record_size = prev_record->local_header_size + prev_record->compressed_size;
                uint64_t curr_record_size = curr_record->local_header_size + curr_record->compressed_size;
                uint64_t prev_record_end;
                uint64_t curr_record_end;

                /* Check for integer overflow in the 64bit size & offset values */
                if ((UINT64_MAX - prev_record_size < prev_record->local_header_offset) ||
                    (UINT64_MAX - curr_record_size < curr_record->local_header_offset)) {
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
                        cli_dbgmsg("cli_unzip: Ignoring duplicate file entry at offset: 0x%" PRIx64 ".\n", curr_record->local_header_offset);
                    } else {
                        cli_dbgmsg("cli_unzip: Overlapping files detected.\n");
                        cli_dbgmsg("    previous file end:  %" PRIu64 "\n", prev_record_end);
                        cli_dbgmsg("    current file start: %" PRIu64 "\n", curr_record->local_header_offset);

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
static cl_error_t find_zip64_central_directory_offset(
    fmap_t *map,
    size_t fsize,
    size_t eocoff,
    bool *record_search_allowed,
    size_t *coff)
{
    cl_error_t status            = CL_EPARSE;
    const uint8_t *zip64_eocd    = NULL;
    const uint8_t *zip64_locator = NULL;
    uint64_t zip64_eocd_offset   = 0;
    uint64_t maybe_coff          = 0;
    bool have_eocd_offset        = false;

    /*
     * 4.3.15: the locator sits immediately before the end of central directory record.
     */
    if (eocoff >= SIZEOF_ZIP64_END_OF_CENTRAL_LOCATOR) {
        size_t locator_offset = eocoff - SIZEOF_ZIP64_END_OF_CENTRAL_LOCATOR;

        zip64_locator = fmap_need_off_once(map, locator_offset, SIZEOF_ZIP64_END_OF_CENTRAL_LOCATOR);
        if (NULL != zip64_locator &&
            ZIP64_END_OF_CENTRAL_LOCATOR_magic == ZIP_MAGIC_ZIP64_END_OF_CENTRAL_LOCATOR) {

            zip64_eocd_offset = ZIP64_END_OF_CENTRAL_LOCATOR_eocd_offset;
            have_eocd_offset  = true;

            cli_dbgmsg("find_central_directory_header: Found ZIP64 End Of Central Directory locator at offset: 0x%zx, "
                       "pointing at 0x%" PRIx64 "\n",
                       locator_offset, zip64_eocd_offset);
        }
    }

    if (have_eocd_offset) {
        if (!zip_u64_fits_size_t(zip64_eocd_offset) ||
            !CLI_ISCONTAINED_0_TO(fsize, (size_t)zip64_eocd_offset, SIZEOF_ZIP64_END_OF_CENTRAL)) {
            cli_dbgmsg("find_central_directory_header: ZIP64 End Of Central Directory offset 0x%" PRIx64 " is not within the file.\n",
                       zip64_eocd_offset);
        } else {
            zip64_eocd = fmap_need_off_once(map, (size_t)zip64_eocd_offset, SIZEOF_ZIP64_END_OF_CENTRAL);
            if (NULL != zip64_eocd && ZIP64_END_OF_CENTRAL_magic != ZIP_MAGIC_ZIP64_END_OF_CENTRAL_RECORD) {
                cli_dbgmsg("find_central_directory_header: No ZIP64 End Of Central Directory record at 0x%" PRIx64 ".\n",
                           zip64_eocd_offset);
                zip64_eocd = NULL;
            }
        }
    }

    if (NULL == zip64_eocd) {
        /*
         * The locator didn't pan out. Scan backwards a bounded distance for the ZIP64 record
         * itself. This covers self-extracting archives, where the offset recorded in the
         * locator is shifted by the size of the prepended executable stub.
         *
         * The caller is walking every end of central directory candidate in the file, so only
         * do this search for the first candidate that needs it. Otherwise a file full of
         * end of central directory records would make this quadratic.
         */
        if (!*record_search_allowed) {
            cli_dbgmsg("find_central_directory_header: Not searching for the ZIP64 End Of Central Directory record again.\n");
            goto done;
        }
        *record_search_allowed = false;

        size_t search_len = (eocoff < ZIP64_END_OF_CENTRAL_SEARCH_RANGE)
                                ? eocoff
                                : (size_t)ZIP64_END_OF_CENTRAL_SEARCH_RANGE;

        if (search_len >= SIZEOF_ZIP64_END_OF_CENTRAL) {
            size_t search_start   = eocoff - search_len;
            const uint8_t *window = fmap_need_off_once(map, search_start, search_len);

            if (NULL != window) {
                // Walk backwards through the window so the record nearest the end wins.
                size_t i;
                for (i = search_len - SIZEOF_ZIP64_END_OF_CENTRAL + 1; i > 0; i--) {
                    const uint8_t *candidate = window + (i - 1);

                    if (ZIP_MAGIC_ZIP64_END_OF_CENTRAL_RECORD == (uint32_t)cli_readint32(candidate)) {
                        zip64_eocd = candidate;
                        cli_dbgmsg("find_central_directory_header: Found ZIP64 End Of Central Directory record at offset: 0x%zx\n",
                                   search_start + (i - 1));
                        break;
                    }
                }
            }
        }
    }

    if (NULL == zip64_eocd) {
        cli_dbgmsg("find_central_directory_header: No ZIP64 End Of Central Directory record found.\n");
        goto done;
    }

    maybe_coff = ZIP64_END_OF_CENTRAL_cd_offset;

    if (!zip_u64_fits_size_t(maybe_coff) ||
        !CLI_ISCONTAINED_0_TO(fsize, (size_t)maybe_coff, SIZEOF_CENTRAL_HEADER)) {
        // The alleged central directory offset + size of the header is not within the file size.
        cli_dbgmsg("find_central_directory_header: ZIP64 central directory offset 0x%" PRIx64 " is not within the file.\n",
                   maybe_coff);
        goto done;
    }

    /*
     * The whole central directory that the record describes must be within the file, and must
     * start with a central directory file header.
     *
     * The backwards record scan (and even the locator) can land on a fake record planted in,
     * say, the end of central directory comment. Requiring a plausible central directory
     * keeps such a record from outranking a legitimate central directory offset.
     */
    if (!CLI_ISCONTAINED_0_TO(fsize, (size_t)maybe_coff, (size_t)ZIP64_END_OF_CENTRAL_cd_size)) {
        cli_dbgmsg("find_central_directory_header: ZIP64 central directory size 0x%" PRIx64 " is not within the file.\n",
                   ZIP64_END_OF_CENTRAL_cd_size);
        goto done;
    }

    {
        const uint8_t *cd = fmap_need_off_once(map, (size_t)maybe_coff, 4);
        if (NULL == cd || ZIP_MAGIC_CENTRAL_DIRECTORY_RECORD_BEGIN != (uint32_t)cli_readint32(cd)) {
            cli_dbgmsg("find_central_directory_header: No central directory file header at the ZIP64 central directory offset 0x%" PRIx64 ".\n",
                       maybe_coff);
            goto done;
        }
    }

    cli_dbgmsg("find_central_directory_header: Found Central Directory header at offset: 0x%" PRIx64 " (via ZIP64)\n",
               maybe_coff);
    *coff  = (size_t)maybe_coff;
    status = CL_SUCCESS;

done:
    return status;
}

static cl_error_t find_central_directory_header(
    fmap_t *map,
    size_t fsize,
    size_t *coff)
{
    cl_error_t status = CL_ERROR;
    size_t eocoff     = 0;

    // The ZIP64 record search is a bounded backwards scan, so only allow it for the first
    // end of central directory candidate that needs it.
    bool record_search_allowed = true;

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
            cli_dbgmsg("find_central_directory_header: Found End Of Central Directory header at offset: 0x%zx. "
                       "Searching for Central Directory header...\n",
                       eocoff);

            // The offset for the Central Directory header is stored at offset 16 in the End Of Central Directory header.
            uint32_t maybe_coff = (uint32_t)cli_readint32(&eocptr[16]);

            // The alleged central directory offset + size of the header must be within the file size.
            bool coff_is_usable = (ZIP64_PLACEHOLDER_32 != maybe_coff) &&
                                  CLI_ISCONTAINED_0_TO(fsize, maybe_coff, SIZEOF_CENTRAL_HEADER);

            /*
             * In a ZIP64 archive the 32-bit central directory offset holds the 0xFFFFFFFF
             * placeholder and the real 64-bit offset lives in the ZIP64 end of central
             * directory record. Only consult the ZIP64 records when the 32-bit offset is
             * unusable - a placeholder entry count alone does not mean the offset is wrong
             * (a plain archive may legitimately hold up to 0xFFFF entries), and a fallback
             * search for ZIP64 records must not be able to outrank a working 32-bit offset.
             * See the ZIP64 notes in unzip.h.
             */
            if (ZIP64_PLACEHOLDER_32 == maybe_coff || !coff_is_usable) {
                if (CL_SUCCESS == find_zip64_central_directory_offset(map, fsize, eocoff, &record_search_allowed, coff)) {
                    status = CL_SUCCESS;
                    break;
                }
            }

            if (!coff_is_usable) {
                // Neither the 32-bit offset nor the ZIP64 records gave us a usable central
                // directory offset. Keep looking for another end of central directory record.
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
    size_t fsize;
    size_t coff = 0;

    fmap_t *map = ctx->fmap;

    char *tmpd = NULL;

    int toval                        = 0;
    struct zip_record *zip_catalogue = NULL;
    size_t records_count             = 0;
    size_t i;

    cli_dbgmsg("in cli_unzip\n");

    // Note: offsets and sizes are tracked with 64-bit (or size_t) types throughout so that
    // ZIP64 archives larger than 4 GiB can be parsed. See the ZIP64 notes in unzip.h.
    fsize = map->len;
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
        cli_dbgmsg("cli_unzip: central directory header offset: 0x%zx\n", coff);

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
        const uint8_t *compressed_data  = NULL;
        uint64_t compressed_data_offset = 0;

        if ((i > 0) &&
            (zip_catalogue[i].local_header_offset == zip_catalogue[i - 1].local_header_offset) &&
            (zip_catalogue[i].local_header_size == zip_catalogue[i - 1].local_header_size) &&
            (zip_catalogue[i].compressed_size == zip_catalogue[i - 1].compressed_size)) {

            /* Duplicate file entry, skip. */
            cli_dbgmsg("cli_unzip: Skipping unzipping of duplicate file entry at offset: 0x%" PRIx64 "\n", zip_catalogue[i].local_header_offset);
            continue;
        }

        /*
         * ZIP64 records carry 64-bit offsets and sizes. Verify this record is addressable
         * before converting to size_t for the fmap API, instead of truncating it.
         */
        if (UINT64_MAX - zip_catalogue[i].local_header_size < zip_catalogue[i].local_header_offset) {
            cli_dbgmsg("cli_unzip: Skipping file entry with out of range local header offset and size\n");
            continue;
        }
        compressed_data_offset = zip_catalogue[i].local_header_offset + zip_catalogue[i].local_header_size;

        if (!zip_u64_fits_size_t(compressed_data_offset) ||
            !zip_u64_fits_size_t(zip_catalogue[i].compressed_size)) {
            cli_dbgmsg("cli_unzip: Skipping file entry at offset: 0x%" PRIx64 ", offset or size exceeds the addressable range\n",
                       zip_catalogue[i].local_header_offset);
            continue;
        }

        // Get a pointer to the compressed data, is just after the local header.
        compressed_data = fmap_need_off(
            map,
            (size_t)compressed_data_offset,
            (size_t)zip_catalogue[i].compressed_size);

        if (zip_catalogue[i].encrypted) {
            if (fmap_need_ptr_once(map, compressed_data, (size_t)zip_catalogue[i].compressed_size)) {
                status = zdecrypt(
                    compressed_data,
                    zip_catalogue[i].compressed_size,
                    zip_catalogue[i].uncompressed_size,
                    fmap_need_off(map, (size_t)zip_catalogue[i].local_header_offset, SIZEOF_LOCAL_HEADER),
                    &num_files_unzipped,
                    ctx,
                    tmpd,
                    zip_scan_cb,
                    zip_catalogue[i].original_filename);
            } else {
                // If we cannot get a pointer to the compressed data, we cannot decrypt it.
                // Skip this file.
                cli_dbgmsg("cli_unzip: Skipping decryption of file entry at offset: 0x%" PRIx64 ", size: %" PRIu64 ", compressed data not available\n",
                           zip_catalogue[i].local_header_offset,
                           zip_catalogue[i].compressed_size);
            }
        } else {
            if (fmap_need_ptr_once(map, compressed_data, (size_t)zip_catalogue[i].compressed_size)) {
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
                cli_dbgmsg("cli_unzip: Skipping decompression of file entry at offset: 0x%" PRIx64 ", size: %" PRIu64 ", compressed data not available\n",
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
        NULL, /* central_record */
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
    size_t coff       = 0;
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
        size_t central_file_header_offset = coff;
        cli_dbgmsg("unzip_search: central directory header offset: 0x%zx\n", central_file_header_offset);
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

cl_error_t unzip_search_single(cli_ctx *ctx, const char *name, size_t nlen, size_t *loff)
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

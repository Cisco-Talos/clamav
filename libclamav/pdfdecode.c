/*
 *  Copyright (C) 2016-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *
 *  Author: Kevin Lin
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
 *
 *  In addition, as a special exception, the copyright holders give
 *  permission to link the code of portions of this program with the
 *  OpenSSL library under certain conditions as described in each
 *  individual source file, and distribute linked combinations
 *  including the two.
 *
 *  You must obey the GNU General Public License in all respects
 *  for all of the code used other than OpenSSL.  If you modify
 *  file(s) with this exception, you may extend this exception to your
 *  version of the file(s), but you are not obligated to do so.  If you
 *  do not wish to do so, delete this exception statement from your
 *  version.  If you delete this exception statement from all source
 *  files in the program, then also delete it here.
 */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdio.h>
#include <stddef.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <ctype.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <errno.h>
#ifdef HAVE_LIMITS_H
#include <limits.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <zlib.h>

#if HAVE_ICONV
#include <iconv.h>
#endif

#include "clamav.h"
#include "others.h"
#include "pdf.h"
#include "pdfdecode.h"
#include "str.h"
#include "bytecode.h"
#include "bytecode_api.h"
#include "lzw/lzwdec.h"

#define PDFTOKEN_FLAG_XREF 0x1

#define INFLATE_CHUNK_SIZE (1024 * 256)

struct pdf_token {
    uint32_t flags;   /* tracking flags */
    uint32_t success; /* successfully decoded filters */
    size_t length;    /* length of current content; TODO: transition to size_t */
    uint8_t *content; /* content stream */
};

static size_t pdf_decodestream_internal(struct pdf_struct *pdf, struct pdf_obj *obj, struct pdf_dict *params, struct pdf_token *token, int fout, cl_error_t *status, struct objstm_struct *objstm);

static cl_error_t filter_ascii85decode(struct pdf_struct *pdf, struct pdf_obj *obj, struct pdf_token *token);
static cl_error_t filter_rldecode(struct pdf_struct *pdf, struct pdf_obj *obj, struct pdf_token *token);
static cl_error_t filter_flatedecode(struct pdf_struct *pdf, struct pdf_obj *obj, struct pdf_dict *params, struct pdf_token *token);
static cl_error_t filter_asciihexdecode(struct pdf_struct *pdf, struct pdf_obj *obj, struct pdf_token *token);
static cl_error_t filter_decrypt(struct pdf_struct *pdf, struct pdf_obj *obj, struct pdf_dict *params, struct pdf_token *token, int mode);
static cl_error_t filter_lzwdecode(struct pdf_struct *pdf, struct pdf_obj *obj, struct pdf_dict *params, struct pdf_token *token);

/**
 * @brief       Wrapper function for pdf_decodestream_internal.
 *
 * Allocate a token object to store decoded filter data.
 * Parse/decode the filter data and scan it.
 *
 * @param pdf       Pdf context structure.
 * @param obj       The object we found the filter content in.
 * @param params    (optional) Dictionary parameters describing the filter data.
 * @param stream    Filter stream buffer pointer.
 * @param streamlen Length of filter stream buffer.
 * @param xref      Indicates if the stream is an /XRef stream.  Do not apply forced decryption on /XRef streams.
 * @param fout      File descriptor to write to be scanned.
 * @param[out] rc   Return code ()
 * @param objstm    (optional) Object stream context structure.
 * @return size_t   The number of bytes written to 'fout' to be scanned.
 */
size_t pdf_decodestream(
    struct pdf_struct *pdf, struct pdf_obj *obj, struct pdf_dict *params,
    const char *stream, uint32_t streamlen, int xref, int fout, cl_error_t *status,
    struct objstm_struct *objstm)
{
    struct pdf_token *token = NULL;
    size_t bytes_scanned    = 0;

    if (!status) {
        /* invalid args, and no way to pass back the status code */
        return 0;
    }

    if (!pdf || !obj) {
        /* Invalid args */
        *status = CL_EARG;
        goto done;
    }

    if (!stream || !streamlen || fout < 0) {
        cli_dbgmsg("pdf_decodestream: no filters or stream on obj %u %u\n", obj->id >> 8, obj->id & 0xff);
        *status = CL_ENULLARG;
        goto done;
    }

    *status = CL_SUCCESS;

#if 0
    if (params)
        pdf_print_dict(params, 0);
#endif

    CLI_CALLOC_OR_GOTO_DONE(
        token, 1, sizeof(struct pdf_token),
        *status = CL_EMEM);

    token->flags = 0;
    if (xref)
        token->flags |= PDFTOKEN_FLAG_XREF;

    token->success = 0;

    CLI_MAX_CALLOC_OR_GOTO_DONE(
        token->content, 1, streamlen,
        *status = CL_EMEM);

    memcpy(token->content, stream, streamlen);
    token->length = streamlen;

    cli_dbgmsg("pdf_decodestream: detected %lu applied filters\n", (long unsigned)(obj->numfilters));

    bytes_scanned = pdf_decodestream_internal(pdf, obj, params, token, fout, status, objstm);
    if (CL_VIRUS == *status) {
        goto done;
    }

    if (0 == token->success) {
        /*
         * Either:
         *  a) it failed to decode any filters, or
         *  b) there were no filters.
         *
         * Write out the raw stream to be scanned.
         *
         * Nota bene: If it did decode any filters, the internal() function would
         *            have written out the decoded stream to be scanned.
         */
        if (!cli_checklimits("pdf", pdf->ctx, streamlen, 0, 0)) {
            cli_dbgmsg("pdf_decodestream: no non-forced filters decoded, returning raw stream\n");

            if (cli_writen(fout, stream, streamlen) != streamlen) {
                cli_errmsg("pdf_decodestream: failed to write raw stream to output file\n");
            } else {
                bytes_scanned = streamlen;
            }
        }
    }

done:
    /*
     * Free up the token, and token content, if any.
     */
    if (NULL != token) {
        if (NULL != token->content) {
            free(token->content);
            token->content = NULL;
            token->length  = 0;
        }
        free(token);
        token = NULL;
    }

    return bytes_scanned;
}

/**
 * @brief       Decode filter buffer data.
 *
 * Attempt to decompress, decrypt or otherwise parse it.
 *
 * @param pdf           Pdf context structure.
 * @param obj           The object we found the filter content in.
 * @param params        (optional) Dictionary parameters describing the filter data.
 * @param token         Pointer to and length of filter data.
 * @param fout          File handle to write data to be scanned.
 * @param[out] status   CL_CLEAN/CL_SUCCESS or CL_VIRUS/CL_E<error>
 * @param objstm        (optional) Object stream context structure.
 * @return ptrdiff_t    The number of bytes we wrote to 'fout'. -1 if failed out.
 */
static size_t pdf_decodestream_internal(
    struct pdf_struct *pdf, struct pdf_obj *obj, struct pdf_dict *params,
    struct pdf_token *token, int fout, cl_error_t *status, struct objstm_struct *objstm)
{
    cl_error_t retval    = CL_SUCCESS;
    size_t bytes_scanned = 0;
    const char *filter   = NULL;
    uint32_t i;

    if (!status) {
        /* invalid args, and no way to pass back the status code */
        return 0;
    }

    if (!pdf || !obj || !token) {
        /* Invalid args */
        *status = CL_EARG;
        goto done;
    }

    *status = CL_SUCCESS;

    /*
     * if pdf is decryptable, scan for CRYPT filter
     * if none, force a DECRYPT filter application
     */
    if ((pdf->flags & (1 << DECRYPTABLE_PDF)) && !(obj->flags & (1 << OBJ_FILTER_CRYPT))) {
        if (token->flags & PDFTOKEN_FLAG_XREF) /* TODO: is this on all crypt filters or only the assumed one? */
            cli_dbgmsg("pdf_decodestream_internal: skipping decoding => non-filter CRYPT (reason: xref)\n");
        else {
            cli_dbgmsg("pdf_decodestream_internal: decoding => non-filter CRYPT\n");
            retval = filter_decrypt(pdf, obj, params, token, 1);
            if (retval != CL_SUCCESS) {
                *status = CL_EPARSE;
                goto done;
            }
        }
    }

    for (i = 0; i < obj->numfilters; i++) {
        switch (obj->filterlist[i]) {
            case OBJ_FILTER_A85:
                cli_dbgmsg("pdf_decodestream_internal: decoding [%u] => ASCII85DECODE\n", obj->filterlist[i]);
                retval = filter_ascii85decode(pdf, obj, token);
                break;

            case OBJ_FILTER_RL:
                cli_dbgmsg("pdf_decodestream_internal: decoding [%u] => RLDECODE\n", obj->filterlist[i]);
                retval = filter_rldecode(pdf, obj, token);
                break;

            case OBJ_FILTER_FLATE:
                cli_dbgmsg("pdf_decodestream_internal: decoding [%u] => FLATEDECODE\n", obj->filterlist[i]);
                retval = filter_flatedecode(pdf, obj, params, token);
                break;

            case OBJ_FILTER_AH:
                cli_dbgmsg("pdf_decodestream_internal: decoding [%u] => ASCIIHEXDECODE\n", obj->filterlist[i]);
                retval = filter_asciihexdecode(pdf, obj, token);
                break;

            case OBJ_FILTER_CRYPT:
                cli_dbgmsg("pdf_decodestream_internal: decoding [%u] => CRYPT\n", obj->filterlist[i]);
                retval = filter_decrypt(pdf, obj, params, token, 0);
                break;

            case OBJ_FILTER_LZW:
                cli_dbgmsg("pdf_decodestream_internal: decoding [%u] => LZWDECODE\n", obj->filterlist[i]);
                retval = filter_lzwdecode(pdf, obj, params, token);
                break;

            case OBJ_FILTER_JPX:
                if (!filter) filter = "JPXDECODE";
                /*fallthrough*/
            case OBJ_FILTER_DCT:
                if (!filter) filter = "DCTDECODE";
                /*fallthrough*/
            case OBJ_FILTER_FAX:
                if (!filter) filter = "FAXDECODE";
                /*fallthrough*/
            case OBJ_FILTER_JBIG2:
                if (!filter) filter = "JBIG2DECODE";

                cli_dbgmsg("pdf_decodestream_internal: unimplemented filter type [%u] => %s\n", obj->filterlist[i], filter);
                filter = NULL;
                retval = CL_BREAK;
                break;

            default:
                cli_dbgmsg("pdf_decodestream_internal: unknown filter type [%u]\n", obj->filterlist[i]);
                retval = CL_BREAK;
                break;
        }

        if (!(token->content) || !(token->length)) {
            cli_dbgmsg("pdf_decodestream_internal: empty content, breaking after %u (of %u) filters\n", i, obj->numfilters);
            break;
        }

        if (retval != CL_SUCCESS) {
            const char *reason;

            switch (retval) {
                case CL_VIRUS:
                    *status = CL_VIRUS;
                    reason  = "detection";
                    break;
                case CL_BREAK:
                    *status = CL_SUCCESS;
                    reason  = "decoding break";
                    break;
                default:
                    *status = CL_EPARSE;
                    reason  = "decoding error";
                    break;
            }

            cli_dbgmsg("pdf_decodestream_internal: stopping after %d (of %u) filters (reason: %s)\n", i, obj->numfilters, reason);
            break;
        }
        token->success++;
    }

    if ((token->success > 0) && (NULL != token->content)) {
        /*
         * Looks like we successfully decoded some or all of the stream filters,
         * so lets write it out to a file descriptor we scan.
         *
         * In the event that we didn't decode any filters (or maybe there
         * weren't any filters), the calling function will do the same with
         * the raw stream.
         */
        if (CL_SUCCESS == cli_checklimits("pdf", pdf->ctx, token->length, 0, 0)) {
            if (cli_writen(fout, token->content, token->length) != token->length) {
                cli_errmsg("pdf_decodestream_internal: failed to write decoded stream content to output file\n");
            } else {
                bytes_scanned = token->length;
            }
        }
    }

    if ((NULL != objstm) &&
        (CL_SUCCESS == *status)) {
        unsigned int objs_found = pdf->nobjs;

        /*
         * The caller indicated that the decoded data is an object stream.
         * Perform experimental object stream parsing to extract objects from the stream.
         */
        objstm->streambuf     = (char *)token->content;
        objstm->streambuf_len = (size_t)token->length;

        /* Take ownership of the malloc'd buffer */
        token->content = NULL;
        token->length  = 0;

        /* Don't store the result. It's ok if some or all objects failed to parse.
           It would be far worse to add objects from a stream to the list, and then free
           the stream buffer due to an "error". */
        if (CL_SUCCESS != pdf_find_and_parse_objs_in_objstm(pdf, objstm)) {
            cli_dbgmsg("pdf_decodestream_internal: pdf_find_and_parse_objs_in_objstm failed!\n");
        }

        if (pdf->nobjs <= objs_found) {
            cli_dbgmsg("pdf_decodestream_internal: pdf_find_and_parse_objs_in_objstm did not find any new objects!\n");
        } else {
            cli_dbgmsg("pdf_decodestream_internal: pdf_find_and_parse_objs_in_objstm found %u new objects.\n", pdf->nobjs - objs_found);
        }
    }

done:

    return bytes_scanned;
}

/*
 * ascii85 inflation
 * See http://www.piclist.com/techref/method/encode.htm (look for base85)
 */
static cl_error_t filter_ascii85decode(struct pdf_struct *pdf, struct pdf_obj *obj, struct pdf_token *token)
{
    uint8_t *decoded, *dptr;
    uint32_t declen = 0;

    const uint8_t *ptr = (uint8_t *)token->content;
    size_t remaining   = token->length;
    int quintet = 0, rc = CL_SUCCESS;
    uint64_t sum = 0;

    /* Check for overflow */
    if (remaining > (SIZE_MAX / 4)) {
        cli_dbgmsg("cli_pdf: ascii85decode: overflow detected\n");
        return CL_EFORMAT;
    }

    /* 5:4 decoding ratio, with 1:4 expansion sequences => (4*length)+1 */
    if (!(dptr = decoded = (uint8_t *)cli_max_malloc((4 * remaining) + 1))) {
        cli_errmsg("cli_pdf: cannot allocate memory for decoded output\n");
        return CL_EMEM;
    }

    if (cli_memstr((const char *)ptr, remaining, "~>", 2) == NULL)
        cli_dbgmsg("cli_pdf: no EOF marker found\n");

    while (remaining > 0) {
        int byte = (remaining--) ? (int)*ptr++ : EOF;

        if ((byte == '~') && (remaining > 0) && (*ptr == '>'))
            byte = EOF;

        if (byte >= '!' && byte <= 'u') {
            sum = (sum * 85) + ((uint32_t)byte - '!');
            if (++quintet == 5) {
                *dptr++ = (unsigned char)(sum >> 24);
                *dptr++ = (unsigned char)((sum >> 16) & 0xFF);
                *dptr++ = (unsigned char)((sum >> 8) & 0xFF);
                *dptr++ = (unsigned char)(sum & 0xFF);

                declen += 4;
                quintet = 0;
                sum     = 0;
            }
        } else if (byte == 'z') {
            if (quintet) {
                cli_dbgmsg("cli_pdf: unexpected 'z'\n");
                rc = CL_EFORMAT;
                break;
            }

            *dptr++ = '\0';
            *dptr++ = '\0';
            *dptr++ = '\0';
            *dptr++ = '\0';

            declen += 4;
        } else if (byte == EOF) {
            cli_dbgmsg("cli_pdf: last quintet contains %d bytes\n", quintet);
            if (quintet) {
                int i;

                if (quintet == 1) {
                    cli_dbgmsg("cli_pdf: invalid last quintet (only 1 byte)\n");
                    rc = CL_EFORMAT;
                    break;
                }

                for (i = quintet; i < 5; i++)
                    sum *= 85;

                if (quintet > 1)
                    sum += (0xFFFFFF >> ((quintet - 2) * 8));

                for (i = 0; i < quintet - 1; i++)
                    *dptr++ = (uint8_t)((sum >> (24 - 8 * i)) & 0xFF);
                declen += quintet - 1;
            }

            break;
        } else if (!isspace(byte)) {
            cli_dbgmsg("cli_pdf: invalid character 0x%x @ %zu\n",
                       byte & 0xFF, token->length - remaining);

            rc = CL_EFORMAT;
            break;
        }
    }

    if (rc == CL_SUCCESS) {
        free(token->content);

        cli_dbgmsg("cli_pdf: deflated " STDu32 " bytes from %zu total bytes\n",
                   declen, token->length);

        token->content = decoded;
        token->length  = declen;
    } else {
        if (!(obj->flags & ((1 << OBJ_IMAGE) | (1 << OBJ_TRUNCATED))))
            pdfobj_flag(pdf, obj, BAD_ASCIIDECODE);

        cli_dbgmsg("cli_pdf: error occurred parsing byte %zu of %zu\n",
                   token->length - remaining, token->length);
        free(decoded);
    }
    return rc;
}

/* imported from razorback */
static cl_error_t filter_rldecode(struct pdf_struct *pdf, struct pdf_obj *obj, struct pdf_token *token)
{
    uint8_t *decoded, *temp;
    uint32_t declen = 0, capacity = 0;

    uint8_t *content = (uint8_t *)token->content;
    uint32_t length  = token->length;
    uint32_t offset  = 0;
    int rc           = CL_SUCCESS;

    UNUSEDPARAM(obj);

    capacity = INFLATE_CHUNK_SIZE;

    if (!(decoded = (uint8_t *)malloc(capacity))) {
        cli_errmsg("cli_pdf: cannot allocate memory for decoded output\n");
        return CL_EMEM;
    }

    while (offset < length) {
        uint8_t srclen = content[offset++];
        if (srclen < 128) {
            /* direct copy of (srclen + 1) bytes */
            if (offset + srclen + 1 > length) {
                cli_dbgmsg("cli_pdf: required source length (%lu) exceeds remaining length (%lu)\n",
                           (long unsigned)(offset + srclen + 1), (long unsigned)(length - offset));
                rc = CL_EFORMAT;
                break;
            }
            if (declen + srclen + 1 > capacity) {

                if ((rc = cli_checklimits("pdf", pdf->ctx, capacity + INFLATE_CHUNK_SIZE, 0, 0)) != CL_SUCCESS)
                    break;

                if (!(temp = cli_max_realloc(decoded, capacity + INFLATE_CHUNK_SIZE))) {
                    cli_errmsg("cli_pdf: cannot reallocate memory for decoded output\n");
                    rc = CL_EMEM;
                    break;
                }
                decoded = temp;
                capacity += INFLATE_CHUNK_SIZE;
            }

            memcpy(decoded + declen, content + offset, srclen + 1);
            offset += srclen + 1;
            declen += srclen + 1;
        } else if (srclen > 128) {
            /* copy the next byte (257 - srclen) times */
            if (offset + 1 > length) {
                cli_dbgmsg("cli_pdf: required source length (%lu) exceeds remaining length (%lu)\n",
                           (long unsigned)(offset + srclen + 1), (long unsigned)(length - offset));
                rc = CL_EFORMAT;
                break;
            }
            if (declen + (257 - srclen) + 1 > capacity) {
                if ((rc = cli_checklimits("pdf", pdf->ctx, capacity + INFLATE_CHUNK_SIZE, 0, 0)) != CL_SUCCESS) {
                    cli_dbgmsg("cli_pdf: required buffer size to inflate compressed filter exceeds maximum: %u\n", capacity + INFLATE_CHUNK_SIZE);
                    break;
                }

                if (!(temp = cli_max_realloc(decoded, capacity + INFLATE_CHUNK_SIZE))) {
                    cli_errmsg("cli_pdf: cannot reallocate memory for decoded output\n");
                    rc = CL_EMEM;
                    break;
                }
                decoded = temp;
                capacity += INFLATE_CHUNK_SIZE;
            }

            memset(decoded + declen, content[offset], 257 - srclen);
            offset++;
            declen += 257 - srclen;
        } else { /* srclen == 128 */
            /* end of data */
            cli_dbgmsg("cli_pdf: end-of-stream marker @ offset " STDu32 " (%zu bytes remaining)\n",
                       offset, token->length - offset);
            break;
        }
    }

    if (rc == CL_SUCCESS) {
        if (declen == 0) {
            cli_dbgmsg("cli_pdf: empty stream after inflation completed.\n");
            rc = CL_BREAK;
        } else if (!(temp = cli_max_realloc(decoded, declen))) {
            /* Shrink output buffer to final the decoded data length to minimize RAM usage */
            cli_errmsg("cli_pdf: cannot reallocate memory for decoded output\n");
            rc = CL_EMEM;
        } else {
            decoded = temp;
        }
    }

    if (rc == CL_SUCCESS || rc == CL_BREAK) {
        free(token->content);

        cli_dbgmsg("cli_pdf: decoded " STDu32 " bytes from %zu total bytes\n",
                   declen, token->length);

        token->content = decoded;
        token->length  = declen;
    } else {
        cli_dbgmsg("cli_pdf: error occurred parsing byte " STDu32 " of %zu\n",
                   offset, token->length);
        free(decoded);
    }
    return rc;
}

static uint8_t *decode_nextlinestart(uint8_t *content, uint32_t length)
{
    uint8_t *pt = content;
    uint32_t r;
    int toggle = 0;

    for (r = 0; r < length; r++, pt++) {
        if (*pt == '\n' || *pt == '\r')
            toggle = 1;
        else if (toggle)
            break;
    }

    return pt;
}

static cl_error_t filter_flatedecode(struct pdf_struct *pdf, struct pdf_obj *obj, struct pdf_dict *params, struct pdf_token *token)
{
    uint8_t *decoded, *temp;
    uint32_t declen = 0, capacity = 0;

    uint8_t *content = (uint8_t *)token->content;
    uint32_t length  = token->length;
    z_stream stream;
    int zstat, rc = CL_SUCCESS;

    UNUSEDPARAM(params);

    if (*content == '\r') {
        content++;
        length--;
        pdfobj_flag(pdf, obj, BAD_STREAMSTART);
        /* PDF spec says stream is followed by \r\n or \n, but not \r alone.
         * Sample 0015315109, it has \r followed by zlib header.
         * Flag pdf as suspicious, and attempt to extract by skipping the \r.
         */
        if (!length)
            return CL_SUCCESS;
    }

    capacity = INFLATE_CHUNK_SIZE;

    if (!(decoded = (uint8_t *)malloc(capacity))) {
        cli_errmsg("cli_pdf: cannot allocate memory for decoded output\n");
        return CL_EMEM;
    }

    memset(&stream, 0, sizeof(stream));
    stream.next_in   = (Bytef *)content;
    stream.avail_in  = length;
    stream.next_out  = (Bytef *)decoded;
    stream.avail_out = INFLATE_CHUNK_SIZE;

    zstat = inflateInit(&stream);
    if (zstat != Z_OK) {
        cli_warnmsg("cli_pdf: inflateInit failed\n");
        free(decoded);
        return CL_EMEM;
    }

    /* initial inflate */
    zstat = inflate(&stream, Z_NO_FLUSH);
    /* check if nothing written whatsoever */
    if ((zstat != Z_OK) && (stream.avail_out == INFLATE_CHUNK_SIZE)) {
        /* skip till EOL, and try inflating from there, sometimes
         * PDFs contain extra whitespace */
        uint8_t *q = decode_nextlinestart(content, length);
        if (q) {
            (void)inflateEnd(&stream);
            length -= q - content;
            content = q;

            stream.next_in   = (Bytef *)content;
            stream.avail_in  = length;
            stream.next_out  = (Bytef *)decoded;
            stream.avail_out = capacity;

            zstat = inflateInit(&stream);
            if (zstat != Z_OK) {
                cli_warnmsg("cli_pdf: inflateInit failed\n");
                free(decoded);
                return CL_EMEM;
            }

            pdfobj_flag(pdf, obj, BAD_FLATESTART);
        }

        zstat = inflate(&stream, Z_NO_FLUSH);
    }

    while (zstat == Z_OK && stream.avail_in) {
        /* extend output capacity if needed,*/
        if (stream.avail_out == 0) {
            if ((rc = cli_checklimits("pdf", pdf->ctx, capacity + INFLATE_CHUNK_SIZE, 0, 0)) != CL_SUCCESS) {
                cli_dbgmsg("cli_pdf: required buffer size to inflate compressed filter exceeds maximum: %u\n", capacity + INFLATE_CHUNK_SIZE);
                break;
            }

            if (!(temp = cli_max_realloc(decoded, capacity + INFLATE_CHUNK_SIZE))) {
                cli_errmsg("cli_pdf: cannot reallocate memory for decoded output\n");
                rc = CL_EMEM;
                break;
            }
            decoded          = temp;
            stream.next_out  = decoded + capacity;
            stream.avail_out = INFLATE_CHUNK_SIZE;
            declen += INFLATE_CHUNK_SIZE;
            capacity += INFLATE_CHUNK_SIZE;
        }

        /* continue inflation */
        zstat = inflate(&stream, Z_NO_FLUSH);
    }

    /* add stream end fragment to decoded length */
    declen += (INFLATE_CHUNK_SIZE - stream.avail_out);

    /* error handling */
    switch (zstat) {
        case Z_OK:
            cli_dbgmsg("cli_pdf: Z_OK on stream inflation completion\n");
            /* intentional fall-through */
        case Z_STREAM_END:
            cli_dbgmsg("cli_pdf: inflated " STDu32 " bytes from %zu total bytes (%u bytes remaining)\n",
                       declen, token->length, stream.avail_in);
            break;

        /* potentially fatal - *mostly* ignored as per older version */
        case Z_STREAM_ERROR:
        case Z_NEED_DICT:
        case Z_DATA_ERROR:
        case Z_MEM_ERROR:
        default:
            if (stream.msg)
                cli_dbgmsg("cli_pdf: after writing " STDu32 " bytes, got error \"%s\" inflating PDF stream in %u %u obj\n",
                           declen, stream.msg, obj->id >> 8, obj->id & 0xff);
            else
                cli_dbgmsg("cli_pdf: after writing " STDu32 " bytes, got error %d inflating PDF stream in %u %u obj\n",
                           declen, zstat, obj->id >> 8, obj->id & 0xff);

            if (declen == 0) {
                pdfobj_flag(pdf, obj, BAD_FLATESTART);
                cli_dbgmsg("cli_pdf: no bytes were inflated.\n");

                rc = CL_EFORMAT;
            } else {
                pdfobj_flag(pdf, obj, BAD_FLATE);
            }
            break;
    }

    (void)inflateEnd(&stream);

    if (rc == CL_SUCCESS) {
        if (declen == 0) {
            cli_dbgmsg("cli_pdf: empty stream after inflation completed.\n");
            rc = CL_BREAK;
        } else if (!(temp = cli_max_realloc(decoded, declen))) {
            /* Shrink output buffer to final the decoded data length to minimize RAM usage */
            cli_errmsg("cli_pdf: cannot reallocate memory for decoded output\n");
            rc = CL_EMEM;
        } else {
            decoded = temp;
        }
    }

    if (rc == CL_SUCCESS || rc == CL_BREAK) {
        free(token->content);

        token->content = decoded;
        token->length  = declen;
    } else {
        cli_dbgmsg("cli_pdf: error occurred parsing byte %zu of %zu\n",
                   (size_t)length - stream.avail_in, token->length);
        free(decoded);
    }

    return rc;
}

static cl_error_t filter_asciihexdecode(struct pdf_struct *pdf, struct pdf_obj *obj, struct pdf_token *token)
{
    uint8_t *decoded;

    const uint8_t *content = (uint8_t *)token->content;
    size_t length          = token->length;
    size_t i, j;
    cl_error_t rc = CL_SUCCESS;

    if (!(decoded = (uint8_t *)cli_max_calloc(length / 2 + 1, sizeof(uint8_t)))) {
        cli_errmsg("cli_pdf: cannot allocate memory for decoded output\n");
        return CL_EMEM;
    }

    for (i = 0, j = 0; i + 1 < length; i++) {
        if (content[i] == ' ')
            continue;

        if (content[i] == '>')
            break;

        if (cli_hex2str_to((const char *)content + i, (char *)decoded + j, 2) == -1) {
            if (length - i < 4)
                continue;

            rc = CL_EFORMAT;
            break;
        }

        i++;
        j++;
    }

    if (rc == CL_SUCCESS) {
        free(token->content);

        cli_dbgmsg("cli_pdf: deflated %zu bytes from %zu total bytes\n",
                   j, token->length);

        token->content = decoded;
        token->length  = j;
    } else {
        if (!(obj->flags & ((1 << OBJ_IMAGE) | (1 << OBJ_TRUNCATED))))
            pdfobj_flag(pdf, obj, BAD_ASCIIDECODE);

        cli_dbgmsg("cli_pdf: error occurred parsing byte %zu of %zu\n",
                   i, token->length);
        free(decoded);
    }
    return rc;
}

/* modes: 0 = use default/DecodeParms, 1 = use document setting */
static cl_error_t filter_decrypt(struct pdf_struct *pdf, struct pdf_obj *obj, struct pdf_dict *params, struct pdf_token *token, int mode)
{
    char *decrypted;
    size_t length       = (size_t)token->length;
    enum enc_method enc = ENC_IDENTITY;

    if (mode)
        enc = get_enc_method(pdf, obj);
    else if (params) {
        struct pdf_dict_node *node = params->nodes;

        while (node) {
            if (node->type == PDF_DICT_STRING) {
                if (!strncmp(node->key, "/Type", 6)) { /* optional field - Type */
                    /* MUST be "CryptFilterDecodeParms" */
                    if (node->value)
                        cli_dbgmsg("cli_pdf: Type: %s\n", (char *)(node->value));
                } else if (!strncmp(node->key, "/Name", 6)) { /* optional field - Name */
                    /* overrides document and default encryption method */
                    if (node->value)
                        cli_dbgmsg("cli_pdf: Name: %s\n", (char *)(node->value));
                    enc = parse_enc_method(pdf->CF, pdf->CF_n, (char *)(node->value), enc);
                }
            }
            node = node->next;
        }
    }

    decrypted = decrypt_any(pdf, obj->id, (const char *)token->content, &length, enc);
    if (!decrypted) {
        cli_dbgmsg("cli_pdf: failed to decrypt stream\n");
        return CL_EPARSE; /* TODO: what should this value be? CL_SUCCESS would mirror previous behavior */
    }

    cli_dbgmsg("cli_pdf: decrypted %zu bytes from %zu total bytes\n",
               length, token->length);

    free(token->content);
    token->content = (uint8_t *)decrypted;
    token->length  = length;
    return CL_SUCCESS;
}

static cl_error_t filter_lzwdecode(struct pdf_struct *pdf, struct pdf_obj *obj, struct pdf_dict *params, struct pdf_token *token)
{
    uint8_t *decoded = NULL;
    uint8_t *temp    = NULL;
    size_t declen = 0, capacity = 0;

    uint8_t *content = (uint8_t *)token->content;
    uint32_t length  = token->length;
    lzw_stream stream;
    bool stream_initialized = false;
    int echg = 1, lzwstat, rc = CL_SUCCESS;

    if (pdf->ctx && !(pdf->ctx->dconf->other & OTHER_CONF_LZW)) {
        rc = CL_BREAK;
        goto done;
    }

    if (params) {
        struct pdf_dict_node *node = params->nodes;

        while (node) {
            if (node->type == PDF_DICT_STRING) {
                if (!strncmp(node->key, "/EarlyChange", 13)) { /* optional field - lzw flag */
                    char *end, *value = (char *)node->value;
                    long set;

                    if (value) {
                        cli_dbgmsg("cli_pdf: EarlyChange: %s\n", value);
                        set = strtol(value, &end, 10);
                        if (end != value)
                            echg = (int)set;
                    }
                }
            }
            node = node->next;
        }
    }

    if (*content == '\r') {
        content++;
        length--;
        pdfobj_flag(pdf, obj, BAD_STREAMSTART);
        /* PDF spec says stream is followed by \r\n or \n, but not \r alone.
         * Sample 0015315109, it has \r followed by zlib header.
         * Flag pdf as suspicious, and attempt to extract by skipping the \r.
         */
        if (!length) {
            rc = CL_SUCCESS;
            goto done;
        }
    }

    capacity = INFLATE_CHUNK_SIZE;

    if (!(decoded = (uint8_t *)malloc(capacity))) {
        cli_errmsg("cli_pdf: cannot allocate memory for decoded output\n");
        rc = CL_EMEM;
        goto done;
    }
    stream_initialized = true;

    memset(&stream, 0, sizeof(stream));
    stream.next_in   = content;
    stream.avail_in  = length;
    stream.next_out  = decoded;
    stream.avail_out = INFLATE_CHUNK_SIZE;
    if (echg)
        stream.flags |= LZW_FLAG_EARLYCHG;

    lzwstat = lzwInit(&stream);
    if (lzwstat != Z_OK) {
        cli_warnmsg("cli_pdf: lzwInit failed\n");
        rc = CL_EMEM;
        goto done;
    }

    /* initial inflate */
    lzwstat = lzwInflate(&stream);
    /* check if nothing written whatsoever */
    if ((lzwstat != Z_OK) && (stream.avail_out == INFLATE_CHUNK_SIZE)) {
        /* skip till EOL, and try inflating from there, sometimes
         * PDFs contain extra whitespace */
        uint8_t *q = decode_nextlinestart(content, length);
        if (q) {
            (void)lzwInflateEnd(&stream);
            length -= q - content;
            content = q;

            stream.next_in   = content;
            stream.avail_in  = length;
            stream.next_out  = decoded;
            stream.avail_out = INFLATE_CHUNK_SIZE;

            lzwstat = lzwInit(&stream);
            if (lzwstat != Z_OK) {
                cli_warnmsg("cli_pdf: lzwInit failed\n");
                rc = CL_EMEM;
                goto done;
            }

            pdfobj_flag(pdf, obj, BAD_FLATESTART);
        }

        lzwstat = lzwInflate(&stream);
    }

    while (lzwstat == Z_OK && stream.avail_in) {
        /* extend output capacity if needed,*/
        if (stream.avail_out == 0) {
            if ((rc = cli_checklimits("pdf", pdf->ctx, capacity + INFLATE_CHUNK_SIZE, 0, 0)) != CL_SUCCESS) {
                cli_dbgmsg("cli_pdf: required buffer size to inflate compressed filter exceeds maximum: %zu\n", capacity + INFLATE_CHUNK_SIZE);
                break;
            }

            if (!(temp = cli_max_realloc(decoded, capacity + INFLATE_CHUNK_SIZE))) {
                cli_errmsg("cli_pdf: cannot reallocate memory for decoded output\n");
                rc = CL_EMEM;
                break;
            }
            decoded          = temp;
            stream.next_out  = decoded + capacity;
            stream.avail_out = INFLATE_CHUNK_SIZE;
            if (declen > (SIZE_MAX - INFLATE_CHUNK_SIZE)) {
                cli_dbgmsg("cli_pdf: lzwdecode: overflow detected\n");
                rc = CL_EFORMAT;
                goto done;
            }
            declen += INFLATE_CHUNK_SIZE;
            if (capacity > (SIZE_MAX - INFLATE_CHUNK_SIZE)) {
                cli_dbgmsg("cli_pdf: lzwdecode: overflow detected\n");
                rc = CL_EFORMAT;
                goto done;
            }
            capacity += INFLATE_CHUNK_SIZE;
        }

        /* continue inflation */
        lzwstat = lzwInflate(&stream);
    }

    if (declen > (UINT32_MAX - (INFLATE_CHUNK_SIZE - stream.avail_out))) {
        cli_dbgmsg("cli_pdf: lzwdecode: overflow detected\n");
        rc = CL_EFORMAT;
        goto done;
    }

    /* add stream end fragment to decoded length */
    declen += (INFLATE_CHUNK_SIZE - stream.avail_out);

    /* error handling */
    switch (lzwstat) {
        case LZW_OK:
            cli_dbgmsg("cli_pdf: LZW_OK on stream inflation completion\n");
            /* intentional fall-through */
        case LZW_STREAM_END:
            cli_dbgmsg("cli_pdf: inflated %zu bytes from %zu total bytes (%u bytes remaining)\n",
                       declen, token->length, stream.avail_in);
            break;

        /* potentially fatal - *mostly* ignored as per older version */
        case LZW_STREAM_ERROR:
        case LZW_DATA_ERROR:
        case LZW_MEM_ERROR:
        case LZW_BUF_ERROR:
        case LZW_DICT_ERROR:
        default:
            if (stream.msg)
                cli_dbgmsg("cli_pdf: after writing %zu bytes, got error \"%s\" inflating PDF stream in %u %u obj\n",
                           declen, stream.msg, obj->id >> 8, obj->id & 0xff);
            else
                cli_dbgmsg("cli_pdf: after writing %zu bytes, got error %d inflating PDF stream in %u %u obj\n",
                           declen, lzwstat, obj->id >> 8, obj->id & 0xff);

            if (declen == 0) {
                pdfobj_flag(pdf, obj, BAD_FLATESTART);
                cli_dbgmsg("cli_pdf: no bytes were inflated.\n");

                rc = CL_EFORMAT;
            } else {
                pdfobj_flag(pdf, obj, BAD_FLATE);
            }
            break;
    }

done:
    if (stream_initialized) {
        (void)lzwInflateEnd(&stream);
    }

    if (rc == CL_SUCCESS) {
        if (declen == 0) {
            cli_dbgmsg("cli_pdf: empty stream after inflation completed.\n");
            rc = CL_BREAK;
        } else if (!(temp = cli_max_realloc(decoded, declen))) {
            /* Shrink output buffer to final the decoded data length to minimize RAM usage */
            cli_errmsg("cli_pdf: cannot reallocate memory for decoded output\n");
            rc = CL_EMEM;
        } else {
            decoded = temp;
        }
    }

    if ((rc == CL_SUCCESS || rc == CL_BREAK) && (NULL != decoded)) {
        free(token->content);

        token->content = decoded;
        token->length  = declen;
    } else {
        cli_dbgmsg("cli_pdf: error occurred parsing byte decoding lzw filter\n");
        if (NULL != decoded) {
            free(decoded);
        }
    }

    /*
       heuristic checks:
       - full dictionary heuristics?
       - invalid code points?
    */

    return rc;
}

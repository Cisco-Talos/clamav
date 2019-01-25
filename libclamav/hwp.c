/*
 * HWP Stuff
 * 
 * Copyright (C) 2015-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 * 
 * Authors: Kevin Lin
 * 
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License version 2 as published by the
 * Free Software Foundation.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 * 
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#if HAVE_LIBXML2
#include <libxml/xmlreader.h>
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <ctype.h>
#include <zlib.h>

#if HAVE_ICONV
#include <iconv.h>
#endif

#include "clamav.h"
#include "fmap.h"
#include "str.h"
#include "conv.h"
#include "others.h"
#include "scanners.h"
#include "msxml_parser.h"
#include "msxml.h"
#include "json_api.h"
#include "hwp.h"
#if HAVE_JSON
#include "msdoc.h"
#endif

#define HWP5_DEBUG  0
#define HWP3_DEBUG  0
#define HWP3_VERIFY 0
#define HWPML_DEBUG 0
#if HWP5_DEBUG
#define hwp5_debug(...) cli_dbgmsg(__VA_ARGS__)
#else
#define hwp5_debug(...) ;
#endif
#if HWP3_DEBUG
#define hwp3_debug(...) cli_dbgmsg(__VA_ARGS__)
#else
#define hwp3_debug(...) ;
#endif
#if HWPML_DEBUG
#define hwpml_debug(...) cli_dbgmsg(__VA_ARGS__)
#else
#define hwpml_debug(...) ;
#endif

typedef int (*hwp_cb )(void *cbdata, int fd, const char *filepath, cli_ctx *ctx);
static int decompress_and_callback(cli_ctx *ctx, fmap_t *input, off_t at, size_t len, const char *parent, hwp_cb cb, void *cbdata)
{
    int zret, ofd, in, ret = CL_SUCCESS;
    off_t off_in = at;
    size_t count, remain = 1, outsize = 0;
    z_stream zstrm;
    char *tmpname;
    unsigned char inbuf[FILEBUFF], outbuf[FILEBUFF];

    if (!ctx || !input || !cb)
        return CL_ENULLARG;

    if (len)
        remain = len;

    /* reserve tempfile for output and callback */
    if ((ret = cli_gentempfd(ctx->engine->tmpdir, &tmpname, &ofd)) != CL_SUCCESS) {
        cli_errmsg("%s: Can't generate temporary file\n", parent);
        return ret;
    }

    /* initialize zlib inflation stream */
    memset(&zstrm, 0, sizeof(zstrm));
    zstrm.zalloc = Z_NULL;
    zstrm.zfree = Z_NULL;
    zstrm.opaque = Z_NULL;
    zstrm.next_in = inbuf;
    zstrm.next_out = outbuf;
    zstrm.avail_in = 0;
    zstrm.avail_out = FILEBUFF;

    zret = inflateInit2(&zstrm, -15);
    if (zret != Z_OK) {
        cli_errmsg("%s: Can't initialize zlib inflation stream\n", parent);
        ret = CL_EUNPACK;
        goto dc_end;
    }

    /* inflation loop */
    do {
        if (zstrm.avail_in == 0) {
            zstrm.next_in = inbuf;
            in = fmap_readn(input, inbuf, off_in, FILEBUFF);
            if (in < 0) {
                cli_errmsg("%s: Error reading stream\n", parent);
                ret = CL_EUNPACK;
                goto dc_end;
            }
            if (!in)
                break;

            if (len) {
                if (remain < in)
                    in = remain;
                remain -= in;
            }
            zstrm.avail_in = in;
            off_in += in;
        }
        zret = inflate(&zstrm, Z_SYNC_FLUSH);
        count = FILEBUFF - zstrm.avail_out;
        if (count) {
            if ((ret = cli_checklimits("HWP", ctx, outsize + count, 0, 0)) != CL_SUCCESS)
                break;

            if (cli_writen(ofd, outbuf, count) != count) {
                cli_errmsg("%s: Can't write to file %s\n", parent, tmpname);
                ret = CL_EWRITE;
                goto dc_end;
            }
            outsize += count;
        }
        zstrm.next_out = outbuf;
        zstrm.avail_out = FILEBUFF;
    } while(zret == Z_OK && remain);

    cli_dbgmsg("%s: Decompressed %llu bytes to %s\n", parent, (long long unsigned)outsize, tmpname);

    /* post inflation checks */
    if (zret != Z_STREAM_END && zret != Z_OK) {
        if (outsize == 0) {
            cli_infomsg(ctx, "%s: Error decompressing stream. No data decompressed.\n", parent);
            ret = CL_EUNPACK;
            goto dc_end;
        }

        cli_infomsg(ctx, "%s: Error decompressing stream. Scanning what was decompressed.\n", parent);
    }

    /* check for limits exceeded or zlib failure */
    if (ret == CL_SUCCESS && (zret == Z_STREAM_END || zret == Z_OK)) {
        if (len && remain > 0)
            cli_infomsg(ctx, "%s: Error decompressing stream. Not all requested input was converted\n", parent);

        /* scanning inflated stream */
        ret = cb(cbdata, ofd, tmpname, ctx);
    } else {
        /* default to scanning what we got */
        ret = cli_magic_scandesc(ofd, tmpname, ctx);
    }

    /* clean-up */
 dc_end:
    zret = inflateEnd(&zstrm);
    if (zret != Z_OK) {
        cli_errmsg("%s: Error closing zlib inflation stream\n", parent);
        if (ret == CL_SUCCESS)
            ret = CL_EUNPACK;
    }
    close(ofd);
    if (!ctx->engine->keeptmp)
        if (cli_unlink(tmpname))
            ret = CL_EUNLINK;
    free(tmpname);
    return ret;
}

/* convert HANGUL_NUMERICAL to UTF-8 encoding using iconv library, converts to base64 encoding if no iconv or failure */
#define HANGUL_NUMERICAL 0
static char *convert_hstr_to_utf8(const char *begin, size_t sz, const char *parent, int *ret)
{
    int rc = CL_SUCCESS;
    char *res=NULL;
#if HANGUL_NUMERICAL && HAVE_ICONV
    char *p1, *p2, *inbuf = NULL, *outbuf = NULL;
    size_t inlen, outlen;
    iconv_t cd;

    do {
        p1 = inbuf = cli_calloc(1, sz+1);
        if (!inbuf) {
            cli_errmsg("%s: Failed to allocate memory for encoding conversion buffer\n", parent);
            rc = CL_EMEM;
            break;
        }
        memcpy(inbuf, begin, sz);
        p2 = outbuf = cli_calloc(1, sz+1);
        if (!outbuf) {
            cli_errmsg("%s: Failed to allocate memory for encoding conversion buffer\n", parent);
            rc = CL_EMEM;
            break;
        }
        inlen = outlen = sz;

        cd = iconv_open("UTF-8", "UNICODE");
        if (cd == (iconv_t)(-1)) {
            char errbuf[128];
            cli_strerror(errno, errbuf, sizeof(errbuf));
            cli_errmsg("%s: Failed to initialize iconv for encoding %s: %s\n", parent, HANGUL_NUMERICAL, errbuf);
            break;
        }

        iconv(cd, (char **)(&p1), &inlen, &p2, &outlen);
        iconv_close(cd);

        /* no data was converted */
        if (outlen == sz)
            break;

        outbuf[sz - outlen] = '\0';

        if (!(res = strdup(outbuf))) {
            cli_errmsg("%s: Failed to allocate memory for encoding conversion buffer\n", parent);
            rc = CL_EMEM;
            break;
        }
    } while(0);

    if (inbuf)
        free(inbuf);
    if (outbuf)
        free(outbuf);
#endif
    /* safety base64 encoding */
    if (!res && (rc == CL_SUCCESS)) {
        char *tmpbuf;

        tmpbuf = cli_calloc(1, sz+1);
        if (tmpbuf) {
            memcpy(tmpbuf, begin, sz);

            res = (char *)cl_base64_encode(tmpbuf, sz);
            if (res)
                rc = CL_VIRUS; /* used as placeholder */
            else
                rc = CL_EMEM;

            free(tmpbuf);
        } else {
            cli_errmsg("%s: Failed to allocate memory for temporary buffer\n", parent);
            rc = CL_EMEM;
        }
    }

    (*ret) = rc;
    return res;
}

/*** HWPOLE2 ***/
int cli_scanhwpole2(cli_ctx *ctx)
{
    fmap_t *map = *ctx->fmap;
    uint32_t usize, asize;

    asize = (uint32_t)(map->len - sizeof(usize));

    if (fmap_readn(map, &usize, 0, sizeof(usize)) != sizeof(usize)) {
        cli_errmsg("HWPOLE2: Failed to read uncompressed ole2 filesize\n");
        return CL_EREAD;
    }

    if (usize != asize)
        cli_warnmsg("HWPOLE2: Mismatched uncompressed prefix and size: %u != %u\n", usize, asize);
    else
        cli_dbgmsg("HWPOLE2: Matched uncompressed prefix and size: %u == %u\n", usize, asize);

    return cli_map_scandesc(map, 4, 0, ctx, CL_TYPE_ANY);
    //return cli_map_scandesc(map, 4, 0, ctx, CL_TYPE_OLE2);
}

/*** HWP5 ***/

int cli_hwp5header(cli_ctx *ctx, hwp5_header_t *hwp5)
{
    if (!ctx || !hwp5)
        return CL_ENULLARG;

#if HAVE_JSON
    if (SCAN_COLLECT_METADATA) {
        json_object *header, *flags;

        header = cli_jsonobj(ctx->wrkproperty, "Hwp5Header");
        if (!header) {
            cli_errmsg("HWP5.x: No memory for Hwp5Header object\n");
            return CL_EMEM;
        }

        /* magic */
        cli_jsonstr(header, "Magic", (char*)hwp5->signature);

        /* version */
        cli_jsonint(header, "RawVersion", hwp5->version);

        /* flags */
        cli_jsonint(header, "RawFlags", hwp5->flags);

        flags = cli_jsonarray(header, "Flags");
        if (!flags) {
            cli_errmsg("HWP5.x: No memory for Hwp5Header/Flags array\n");
            return CL_EMEM;
        }

        if (hwp5->flags & HWP5_COMPRESSED) {
            cli_jsonstr(flags, NULL, "HWP5_COMPRESSED");
        }
        if (hwp5->flags & HWP5_PASSWORD) {
            cli_jsonstr(flags, NULL, "HWP5_PASSWORD");
        }
        if (hwp5->flags & HWP5_DISTRIBUTABLE) {
            cli_jsonstr(flags, NULL, "HWP5_DISTRIBUTABLE");
        }
        if (hwp5->flags & HWP5_SCRIPT) {
            cli_jsonstr(flags, NULL, "HWP5_SCRIPT");
        }
        if (hwp5->flags & HWP5_DRM) {
            cli_jsonstr(flags, NULL, "HWP5_DRM");
        }
        if (hwp5->flags & HWP5_XMLTEMPLATE) {
            cli_jsonstr(flags, NULL, "HWP5_XMLTEMPLATE");
        }
        if (hwp5->flags & HWP5_HISTORY) {
            cli_jsonstr(flags, NULL, "HWP5_HISTORY");
        }
        if (hwp5->flags & HWP5_CERT_SIGNED) {
            cli_jsonstr(flags, NULL, "HWP5_CERT_SIGNED");
        }
        if (hwp5->flags & HWP5_CERT_ENCRYPTED) {
            cli_jsonstr(flags, NULL, "HWP5_CERT_ENCRYPTED");
        }
        if (hwp5->flags & HWP5_CERT_EXTRA) {
            cli_jsonstr(flags, NULL, "HWP5_CERT_EXTRA");
        }
        if (hwp5->flags & HWP5_CERT_DRM) {
            cli_jsonstr(flags, NULL, "HWP5_CERT_DRM");
        }
        if (hwp5->flags & HWP5_CCL) {
            cli_jsonstr(flags, NULL, "HWP5_CCL");
        }
    }
#endif
    return CL_SUCCESS;
}

static int hwp5_cb(void *cbdata, int fd, const char* filepath, cli_ctx *ctx)
{
    if (fd < 0 || !ctx)
        return CL_ENULLARG;

    return cli_magic_scandesc(fd, filepath, ctx);
}

int cli_scanhwp5_stream(cli_ctx *ctx, hwp5_header_t *hwp5, char *name, int fd, const char *filepath)
{
    hwp5_debug("HWP5.x: NAME: %s\n", name ? name : "(NULL)");

    if (fd < 0) {
        cli_errmsg("HWP5.x: Invalid file descriptor argument\n");
        return CL_ENULLARG;
    }

    if (name) {
        /* encrypted and compressed streams */
        if (!strncmp(name, "bin", 3) || !strncmp(name, "jscriptversion", 14) ||
            !strncmp(name, "defaultjscript", 14) || !strncmp(name, "section", 7) ||
            !strncmp(name, "viewtext", 8) || !strncmp(name, "docinfo", 7)) {

            if (hwp5->flags & HWP5_PASSWORD) {
                cli_dbgmsg("HWP5.x: Password encrypted stream, scanning as-is\n");
                return cli_magic_scandesc(fd, filepath, ctx);
            }

            if (hwp5->flags & HWP5_COMPRESSED) {
                /* DocInfo JSON Handling */
                STATBUF statbuf;
                fmap_t *input;
                int ret;

                hwp5_debug("HWP5.x: Sending %s for decompress and scan\n", name);

                /* fmap the input file for easier manipulation */
                if (FSTAT(fd, &statbuf) == -1) {
                    cli_errmsg("HWP5.x: Can't stat file descriptor\n");
                    return CL_ESTAT;
                }

                input = fmap(fd, 0, statbuf.st_size);
                if (!input) {
                    cli_errmsg("HWP5.x: Failed to get fmap for input stream\n");
                    return CL_EMAP;
                }
                ret = decompress_and_callback(ctx, input, 0, 0, "HWP5.x", hwp5_cb, NULL);
                funmap(input);
                return ret;
            }
        }

#if HAVE_JSON
        /* JSON Output Summary Information */
        if (SCAN_COLLECT_METADATA && ctx->properties != NULL) {
            if (name && !strncmp(name, "_5_hwpsummaryinformation", 24)) {
                cli_dbgmsg("HWP5.x: Detected a '_5_hwpsummaryinformation' stream\n");
                /* JSONOLE2 - what to do if something breaks? */
                if (cli_ole2_summary_json(ctx, fd, 2) == CL_ETIMEOUT)
                    return CL_ETIMEOUT;
            }
        }

#endif
    }

    /* normal streams */
    return cli_magic_scandesc(fd, filepath, ctx);
}

/*** HWP3 ***/

/* all fields use little endian and unicode encoding, if appliable */

//File Identification Information - (30 total bytes)
#define HWP3_IDENTITY_INFO_SIZE 30

//Document Information - (128 total bytes)
#define HWP3_DOCINFO_SIZE 128

#define DI_WRITEPROT   24  /* offset 24 (4 bytes) - write protection */
#define DI_EXTERNAPP   28  /* offset 28 (2 bytes) - external application */
#define DI_PNAME       32  /* offset 32 (40 x 1 bytes) - print name */
#define DI_ANNOTE      72  /* offset 72 (24 x 1 bytes) - annotation */
#define DI_PASSWD      96  /* offset 96 (2 bytes) - password protected */
#define DI_COMPRESSED  124 /* offset 124 (1 byte) - compression */
#define DI_INFOBLKSIZE 126 /* offset 126 (2 bytes) - information block length */
struct hwp3_docinfo {
    uint32_t di_writeprot;
    uint16_t di_externapp;
    uint16_t di_passwd;
    uint8_t  di_compressed;
    uint16_t di_infoblksize;
};

//Document Summary - (1008 total bytes)
#define HWP3_DOCSUMMARY_SIZE 1008
struct hwp3_docsummary_entry {
    off_t offset;
    const char *name;
} hwp3_docsummary_fields[] = {
    { 0,   "Title" },    /* offset 0 (56 x 2 bytes) - title */
    { 112, "Subject" },  /* offset 112 (56 x 2 bytes) - subject */
    { 224, "Author" },   /* offset 224 (56 x 2 bytes) - author */
    { 336, "Date" },     /* offset 336 (56 x 2 bytes) - date */
    { 448, "Keyword1" }, /* offset 448 (2 x 56 x 2 bytes) - keywords */
    { 560, "Keyword2" },

    { 672, "Etc0" },  /* offset 672 (3 x 56 x 2 bytes) - etc */
    { 784, "Etc1" },
    { 896, "Etc2" }
};
#define NUM_DOCSUMMARY_FIELDS sizeof(hwp3_docsummary_fields)/sizeof(struct hwp3_docsummary_entry)

//Document Paragraph Information - (43 or 230 total bytes)
#define HWP3_PARAINFO_SIZE_S  43
#define HWP3_PARAINFO_SIZE_L  230
#define HWP3_LINEINFO_SIZE    14
#define HWP3_CHARSHPDATA_SIZE 31

#define HWP3_FIELD_LENGTH  512

#define PI_PPFS      0  /* offset 0 (1 byte)  - prior paragraph format style */
#define PI_NCHARS    1  /* offset 1 (2 bytes) - character count */
#define PI_NLINES    3  /* offset 3 (2 bytes) - line count */
#define PI_IFSC      5  /* offset 5 (1 byte)  - including font style of characters */
#define PI_FLAGS     6  /* offset 6 (1 byte)  - other flags */
#define PI_SPECIAL   7  /* offset 7 (4 bytes) - special characters markers */
#define PI_ISTYLE    11 /* offset 11 (1 byte) - paragraph style index */

#define PLI_LOFF   0   /* offset 0 (2 bytes) - line starting offset */
#define PLI_LCOR   2   /* offset 2 (2 bytes) - line blank correction */
#define PLI_LHEI   4   /* offset 4 (2 bytes) - line max char height */
#define PLI_LPAG   12  /* offset 12 (2 bytes) - line pagination*/

#define PCSD_SIZE   0  /* offset 0 (2 bytes) - size of characters */
#define PCSD_PROP   26 /* offset 26 (1 byte) - properties */

static inline int parsehwp3_docinfo(cli_ctx *ctx, off_t offset, struct hwp3_docinfo *docinfo)
{
    const uint8_t *hwp3_ptr;
    int iret;

    //TODO: use fmap_readn?
    if (!(hwp3_ptr = fmap_need_off_once(*ctx->fmap, offset, HWP3_DOCINFO_SIZE))) {
        cli_errmsg("HWP3.x: Failed to read fmap for hwp docinfo\n");
        return CL_EMAP;
    }

    memcpy(&(docinfo->di_writeprot), hwp3_ptr+DI_WRITEPROT, sizeof(docinfo->di_writeprot));
    memcpy(&(docinfo->di_externapp), hwp3_ptr+DI_EXTERNAPP, sizeof(docinfo->di_externapp));
    memcpy(&(docinfo->di_passwd), hwp3_ptr+DI_PASSWD, sizeof(docinfo->di_passwd));
    memcpy(&(docinfo->di_compressed), hwp3_ptr+DI_COMPRESSED, sizeof(docinfo->di_compressed));
    memcpy(&(docinfo->di_infoblksize), hwp3_ptr+DI_INFOBLKSIZE, sizeof(docinfo->di_infoblksize));

    docinfo->di_writeprot = le32_to_host(docinfo->di_writeprot);
    docinfo->di_externapp = le16_to_host(docinfo->di_externapp);
    docinfo->di_passwd = le16_to_host(docinfo->di_passwd);
    docinfo->di_infoblksize = le16_to_host(docinfo->di_infoblksize);

    hwp3_debug("HWP3.x: di_writeprot:   %u\n", docinfo->di_writeprot);
    hwp3_debug("HWP3.x: di_externapp:   %u\n", docinfo->di_externapp);
    hwp3_debug("HWP3.x: di_passwd:      %u\n", docinfo->di_passwd);
    hwp3_debug("HWP3.x: di_compressed:  %u\n", docinfo->di_compressed);
    hwp3_debug("HWP3.x: di_infoblksize: %u\n", docinfo->di_infoblksize);

#if HAVE_JSON
    if (SCAN_COLLECT_METADATA) {
        json_object *header, *flags;
        char *str;

        header = cli_jsonobj(ctx->wrkproperty, "Hwp3Header");
        if (!header) {
            cli_errmsg("HWP3.x: No memory for Hwp3Header object\n");
            return CL_EMEM;
        }

        flags = cli_jsonarray(header, "Flags");
        if (!flags) {
            cli_errmsg("HWP5.x: No memory for Hwp5Header/Flags array\n");
            return CL_EMEM;
        }

        if (docinfo->di_writeprot) {
            cli_jsonstr(flags, NULL, "HWP3_WRITEPROTECTED"); /* HWP3_DISTRIBUTABLE */
        }
        if (docinfo->di_externapp) {
            cli_jsonstr(flags, NULL, "HWP3_EXTERNALAPPLICATION");
        }
        if (docinfo->di_passwd) {
            cli_jsonstr(flags, NULL, "HWP3_PASSWORD");
        }
        if (docinfo->di_compressed) {
            cli_jsonstr(flags, NULL, "HWP3_COMPRESSED");
        }

        /* Printed File Name */
        str = convert_hstr_to_utf8((char*)(hwp3_ptr+DI_PNAME), 40, "HWP3.x", &iret);
        if (!str || (iret == CL_EMEM))
            return CL_EMEM;

        if (iret == CL_VIRUS)
            cli_jsonbool(header, "PrintName_base64", 1);

        hwp3_debug("HWP3.x: di_pname:   %s\n", str);
        cli_jsonstr(header, "PrintName", str);
        free(str);

        /* Annotation */
        str = convert_hstr_to_utf8((char*)(hwp3_ptr+DI_ANNOTE), 24, "HWP3.x", &iret);
        if (!str || (iret == CL_EMEM))
            return CL_EMEM;

        if (iret == CL_VIRUS)
            cli_jsonbool(header, "Annotation_base64", 1);

        hwp3_debug("HWP3.x: di_annote:  %s\n", str);
        cli_jsonstr(header, "Annotation", str);
        free(str);
    }
#endif

    return CL_SUCCESS;
}

static inline int parsehwp3_docsummary(cli_ctx *ctx, off_t offset)
{
#if HAVE_JSON
    const uint8_t *hwp3_ptr;
    char *str;
    int i, iret, ret;
    json_object *summary;

    if (!SCAN_COLLECT_METADATA)
        return CL_SUCCESS;

    if (!(hwp3_ptr = fmap_need_off_once(*ctx->fmap, offset, HWP3_DOCSUMMARY_SIZE))) {
        cli_errmsg("HWP3.x: Failed to read fmap for hwp docinfo\n");
        return CL_EMAP;
    }

    summary = cli_jsonobj(ctx->wrkproperty, "Hwp3SummaryInfo");
    if (!summary) {
        cli_errmsg("HWP3.x: No memory for json object\n");
        return CL_EMEM;
    }

    for (i = 0; i < NUM_DOCSUMMARY_FIELDS; i++) {
        str = convert_hstr_to_utf8((char*)(hwp3_ptr + hwp3_docsummary_fields[i].offset), 112, "HWP3.x", &iret);
        if (!str || (iret == CL_EMEM))
            return CL_EMEM;

        if (iret == CL_VIRUS) {
            char *b64;
            size_t b64len = strlen(hwp3_docsummary_fields[i].name)+8;
            b64 = cli_calloc(1, b64len);
            if (!b64) {
                cli_errmsg("HWP3.x: Failed to allocate memory for b64 boolean\n");
                return CL_EMEM;
            }
            snprintf(b64, b64len, "%s_base64", hwp3_docsummary_fields[i].name);
            cli_jsonbool(summary, b64, 1);
            free(b64);
        }

        hwp3_debug("HWP3.x: %s, %s\n", hwp3_docsummary_fields[i].name, str);
        ret = cli_jsonstr(summary, hwp3_docsummary_fields[i].name, str);
        free(str);
        if (ret != CL_SUCCESS)
            return ret;
    }
#else
    UNUSEDPARAM(ctx);
    UNUSEDPARAM(offset);
#endif
    return CL_SUCCESS;
}

#if HWP3_VERIFY
#define HWP3_PSPECIAL_VERIFY(map, offset, second, id, match)            \
    do {                                                                \
    if (fmap_readn(map, &match, offset+second, sizeof(match)) != sizeof(match)) \
        return CL_EREAD;                                                \
                                                                        \
    match = le16_to_host(match);                                        \
                                                                        \
    if (id != match) {                                                  \
        cli_errmsg("HWP3.x: ID %u block fails verification\n", id);     \
        return CL_EFORMAT;                                              \
    }                                                                   \
    } while(0)

#else
#define HWP3_PSPECIAL_VERIFY(map, offset, second, id, match)
#endif

static inline int parsehwp3_paragraph(cli_ctx *ctx, fmap_t *map, int p, int level, off_t *roffset, int *last)
{
    off_t offset = *roffset;
    off_t new_offset;
    uint16_t nchars, nlines, content;
    uint8_t ppfs, ifsc, cfsb;
    int i, c, l, sp = 0, term = 0, ret = CL_SUCCESS;
#if HWP3_VERIFY
    uint16_t match;
#endif
#if HWP3_DEBUG
    /* other paragraph info */
    uint8_t flags, istyle;
    uint16_t fsize;
    uint32_t special;

    /* line info */
    uint16_t loff, lcor, lhei, lpag;

    /* char shape data */
    uint16_t pcsd_size;
    uint8_t pcsd_prop;
#endif

    hwp3_debug("HWP3.x: recursion level: %d\n", level);
    hwp3_debug("HWP3.x: Paragraph[%d, %d] starts @ offset %llu\n", level, p, (long long unsigned)offset);

    if (level >= ctx->engine->maxrechwp3)
        return CL_EMAXREC;

    if (fmap_readn(map, &ppfs, offset+PI_PPFS, sizeof(ppfs)) != sizeof(ppfs))
        return CL_EREAD;

    if (fmap_readn(map, &nchars, offset+PI_NCHARS, sizeof(nchars)) != sizeof(nchars))
        return CL_EREAD;

    nchars = le16_to_host(nchars);

    if (fmap_readn(map, &nlines, offset+PI_NLINES, sizeof(nlines)) != sizeof(nlines))
        return CL_EREAD;

    nlines = le16_to_host(nlines);

    if (fmap_readn(map, &ifsc, offset+PI_IFSC, sizeof(ifsc)) != sizeof(ifsc))
        return CL_EREAD;

    hwp3_debug("HWP3.x: Paragraph[%d, %d]: ppfs   %u\n", level, p, ppfs);
    hwp3_debug("HWP3.x: Paragraph[%d, %d]: nchars %u\n", level, p, nchars);
    hwp3_debug("HWP3.x: Paragraph[%d, %d]: nlines %u\n", level, p, nlines);
    hwp3_debug("HWP3.x: Paragraph[%d, %d]: ifsc   %u\n", level, p, ifsc);

#if HWP3_DEBUG
    if (fmap_readn(map, &flags, offset+PI_FLAGS, sizeof(flags)) != sizeof(flags))
        return CL_EREAD;

    if (fmap_readn(map, &special, offset+PI_SPECIAL, sizeof(special)) != sizeof(special))
        return CL_EREAD;

    if (fmap_readn(map, &istyle, offset+PI_ISTYLE, sizeof(istyle)) != sizeof(istyle))
        return CL_EREAD;

    if (fmap_readn(map, &fsize, offset+12, sizeof(fsize)) != sizeof(fsize))
        return CL_EREAD;

    hwp3_debug("HWP3.x: Paragraph[%d, %d]: flags  %x\n", level, p, flags);
    hwp3_debug("HWP3.x: Paragraph[%d, %d]: spcl   %x\n", level, p, special);
    hwp3_debug("HWP3.x: Paragraph[%d, %d]: istyle %u\n", level, p, istyle);
    hwp3_debug("HWP3.x: Paragraph[%d, %d]: fsize  %u\n", level, p, fsize);
#endif

    /* detected empty paragraph marker => end-of-paragraph list */
    if (nchars == 0) {
        hwp3_debug("HWP3.x: Detected end-of-paragraph list @ offset %llu\n", (long long unsigned)offset);
        hwp3_debug("HWP3.x: end recursion level: %d\n", level);
        (*roffset) = offset + HWP3_PARAINFO_SIZE_S;
        (*last) = 1;
        return CL_SUCCESS;
    }

    if (ppfs)
        offset += HWP3_PARAINFO_SIZE_S;
    else
        offset += HWP3_PARAINFO_SIZE_L;

    /* line information blocks */
#if HWP3_DEBUG
    for (i = 0; (i < nlines) && (offset < map->len); i++) {
        hwp3_debug("HWP3.x: Paragraph[%d, %d]: Line %d information starts @ offset %llu\n", level, p, i, (long long unsigned)offset);
        if (fmap_readn(map, &loff, offset+PLI_LOFF, sizeof(loff)) != sizeof(loff))
            return CL_EREAD;

        if (fmap_readn(map, &lcor, offset+PLI_LCOR, sizeof(lcor)) != sizeof(lcor))
            return CL_EREAD;

        if (fmap_readn(map, &lhei, offset+PLI_LHEI, sizeof(lhei)) != sizeof(lhei))
            return CL_EREAD;

        if (fmap_readn(map, &lpag, offset+PLI_LPAG, sizeof(lpag)) != sizeof(lpag))
            return CL_EREAD;

        loff = le16_to_host(loff);
        lcor = le16_to_host(lcor);
        lhei = le16_to_host(lhei);
        lpag = le16_to_host(lpag);

        hwp3_debug("HWP3.x: Paragraph[%d, %d]: Line %d: loff %u\n", level, p, i, loff);
        hwp3_debug("HWP3.x: Paragraph[%d, %d]: Line %d: lcor %x\n", level, p, i, lcor);
        hwp3_debug("HWP3.x: Paragraph[%d, %d]: Line %d: lhei %u\n", level, p, i, lhei);
        hwp3_debug("HWP3.x: Paragraph[%d, %d]: Line %d: lpag %u\n", level, p, i, lpag);

        offset += HWP3_LINEINFO_SIZE;
    }
#else
    new_offset = offset + (nlines * HWP3_LINEINFO_SIZE);
    if ((new_offset < offset) || (new_offset >= map->len)) {
        cli_errmsg("HWP3.x: Paragraph[%d, %d]: nlines value is too high, invalid. %u\n", level, p, nlines);
        return CL_EPARSE;
    }
    offset = new_offset;
#endif

    if (offset >= map->len)
        return CL_EFORMAT;

    if (ifsc) {
        for (i = 0, c = 0; i < nchars; i++) {
            /* examine byte for cs data type */
            if (fmap_readn(map, &cfsb, offset, sizeof(cfsb)) != sizeof(cfsb))
                return CL_EREAD;

            offset += sizeof(cfsb);

            switch(cfsb) {
            case 0: /* character shape block */
                hwp3_debug("HWP3.x: Paragraph[%d, %d]: character font style data @ offset %llu\n", level, p, (long long unsigned)offset);

#if HWP3_DEBUG
                if (fmap_readn(map, &pcsd_size, offset+PCSD_SIZE, sizeof(pcsd_size)) != sizeof(pcsd_size))
                    return CL_EREAD;

                if (fmap_readn(map, &pcsd_prop, offset+PCSD_PROP, sizeof(pcsd_prop)) != sizeof(pcsd_prop))
                    return CL_EREAD;

                pcsd_size = le16_to_host(pcsd_size);

                hwp3_debug("HWP3.x: Paragraph[%d, %d]: CFS %u: pcsd_size %u\n", level, p, 0, pcsd_size);
                hwp3_debug("HWP3.x: Paragraph[%d, %d]: CFS %u: pcsd_prop %x\n", level, p, 0, pcsd_prop);
#endif

                c++;
                offset += HWP3_CHARSHPDATA_SIZE;
                break;
            case 1: /* normal character - as representation of another character for previous cs block */
                break;
            default:
                cli_errmsg("HWP3.x: Paragraph[%d, %d]: unknown CFS type 0x%x @ offset %llu\n", level, p, cfsb,
                           (long long unsigned)offset);
                cli_errmsg("HWP3.x: Paragraph parsing detected %d of %u characters\n", i, nchars);
                return CL_EPARSE;
            }
        }

        hwp3_debug("HWP3.x: Paragraph[%d, %d]: detected %d CFS block(s) and %d characters\n", level, p, c, i);
    } else {
        hwp3_debug("HWP3.x: Paragraph[%d, %d]: separate character font style segment not stored\n", level, p);
    }

    if (!term)
        hwp3_debug("HWP3.x: Paragraph[%d, %d]: content starts @ offset %llu\n", level, p, (long long unsigned)offset);

    /* scan for end-of-paragraph [0x0d00 on offset parity to current content] */
    while ((!term) &&
           (offset >= 0) &&
           (offset < map->len))
    {
        if (fmap_readn(map, &content, offset, sizeof(content)) != sizeof(content))
            return CL_EREAD;

        content = le16_to_host(content);

        /* special character handling */
        if (content < 32) {
            hwp3_debug("HWP3.x: Paragraph[%d, %d]: detected special character %u @ offset %llu\n", level, p, content,
                (long long unsigned)offset);

            switch(content) {
            case 0:
            case 1:
            case 2:
            case 3:
            case 4:
            case 12:
            case 27:
                {
                    /* reserved */
                    uint32_t length;

                    hwp3_debug("HWP3.x: Paragraph[%d, %d]: detected special character as [reserved]\n", level, p);

                    /*
                     * offset 0 (2 bytes) - special character ID
                     * offset 2 (4 bytes) - length of information = n
                     * offset 6 (2 bytes) - special character ID
                     * offset 8 (n bytes) - information
                     */

                    /* id block verification (only on HWP3_VERIFY) */
                    HWP3_PSPECIAL_VERIFY(map, offset, 6, content, match);

                    if (fmap_readn(map, &length, offset+2, sizeof(length)) != sizeof(length))
                        return CL_EREAD;

                    length = le32_to_host(length);
                    new_offset = offset + (8 + length);
                    if ((new_offset <= offset) || (new_offset > map->len)) {
                        cli_errmsg("HWP3.x: Paragraph[%d, %d]: length value is too high, invalid. %u\n", level, p, length);
                        return CL_EPARSE;
                    }
                    offset = new_offset;

#if HWP3_DEBUG
                    cli_errmsg("HWP3.x: Paragraph[%d, %d]: possible invalid usage of reserved special character %u\n", level, p, content);
                    return CL_EFORMAT;
#endif
                    break;
                }
            case 5: /* field codes */
                {
                    uint32_t length;

                    hwp3_debug("HWP3.x: Paragraph[%d, %d]: detected field code marker @ offset %llu\n", level, p, (long long unsigned)offset);

                    /*
                     * offset 0 (2 bytes) - special character ID
                     * offset 2 (4 bytes) - length of information = n
                     * offset 6 (2 bytes) - special character ID
                     * offset 8 (n bytes) - field code details
                     */

                    /* id block verification (only on HWP3_VERIFY) */
                    HWP3_PSPECIAL_VERIFY(map, offset, 6, content, match);

                    if (fmap_readn(map, &length, offset+2, sizeof(length)) != sizeof(length))
                        return CL_EREAD;

                    length = le32_to_host(length);
                    new_offset = offset + (8 + length);
                    if ((new_offset <= offset) || (new_offset > map->len)) {
                        cli_errmsg("HWP3.x: Paragraph[%d, %d]: length value is too high, invalid. %u\n", level, p, length);
                        return CL_EPARSE;
                    }
                    offset = new_offset;
                    break;
                }
            case 6: /* bookmark */
                {
#if HWP3_VERIFY
                    uint32_t length;
#endif

                    hwp3_debug("HWP3.x: Paragraph[%d, %d]: detected bookmark marker @ offset %llu\n", level, p, (long long unsigned)offset);

                    /*
                     * offset 0 (2 bytes) - special character ID
                     * offset 2 (4 bytes) - length of information = 34
                     * offset 6 (2 bytes) - special character ID
                     * offset 8 (16 x 2 bytes) - bookmark name
                     * offset 40 (2 bytes) - bookmark type
                     * total is always 42 bytes
                     */

#if HWP3_VERIFY
                    /* id block verification (only on HWP3_VERIFY) */
                    HWP3_PSPECIAL_VERIFY(map, offset, 6, content, match);

                    /* length check - always 34 bytes */
                    if (fmap_readn(map, &length, offset+2, sizeof(length)) != sizeof(length))
                        return CL_EREAD;

                    length = le32_to_host(length);

                    if (length != 34) {
                        cli_errmsg("HWP3.x: Bookmark has incorrect length: %u != 34)\n", length);
                        return CL_EFORMAT;
                    }
#endif
                    offset += 42;
                    break;
                }
            case 7: /* date format */
                {
                    hwp3_debug("HWP3.x: Paragraph[%d, %d]: detected date format marker @ offset %llu\n", level, p, (long long unsigned)offset);

                    /*
                     * offset 0 (2 bytes) - special character ID
                     * offset 2 (40 x 2 bytes) - date format as user-defined dialog
                     * offset 82 (2 bytes) - special character ID
                     * total is always 84 bytes
                     */

                    /* id block verification (only on HWP3_VERIFY) */
                    HWP3_PSPECIAL_VERIFY(map, offset, 82, content, match);

                    offset += 84;
                    break;
                }
            case 8: /* date code */
                {
                    hwp3_debug("HWP3.x: Paragraph[%d, %d]: detected date code marker @ offset %llu\n", level, p, (long long unsigned)offset);

                    /*
                     * offset 0 (2 bytes) - special character ID
                     * offset 2 (40 x 2 bytes) - date format string
                     * offset 82 (4 x 2 bytes) - date (year, month, day of week)
                     * offset 90 (2 x 2 bytes) - time (hour, minute)
                     * offset 94 (2 bytes) - special character ID
                     * total is always 96 bytes
                     */

                    /* id block verification (only on HWP3_VERIFY) */
                    HWP3_PSPECIAL_VERIFY(map, offset, 94, content, match);

                    offset += 96;
                    break;
                }
            case 9: /* tab */
                {
                    hwp3_debug("HWP3.x: Paragraph[%d, %d]: detected tab marker @ offset %llu\n", level, p, (long long unsigned)offset);

                    /*
                     * offset 0 (2 bytes) - special character ID
                     * offset 2 (2 bytes) - tab width
                     * offset 4 (2 bytes) - unknown(?)
                     * offset 6 (2 bytes) - special character ID
                     * total is always 8 bytes
                     */

                    /* id block verification (only on HWP3_VERIFY) */
                    HWP3_PSPECIAL_VERIFY(map, offset, 6, content, match);

                    offset += 8;
                    break;
                }
            case 10: /* table, test box, equation, button, hypertext */
                {
                    uint16_t ncells;
#if HWP3_DEBUG
                    uint16_t type;
#endif
                    hwp3_debug("HWP3.x: Paragraph[%d, %d]: detected box object marker @ offset %llu\n", level, p, (long long unsigned)offset);

                    /* verification (only on HWP3_VERIFY) */
                    /* id block verify */
                    HWP3_PSPECIAL_VERIFY(map, offset, 6, content, match);
                    /* extra data block verify */
                    HWP3_PSPECIAL_VERIFY(map, offset, 24, content, match);

                    /* ID block is 8 bytes */
                    offset += 8;

                    /* box information (84 bytes) */
#if HWP3_DEBUG
                    /* box type located at offset 78 of box information */
                    if (fmap_readn(map, &type, offset+78, sizeof(type)) != sizeof(type))
                        return CL_EREAD;

                    type = le16_to_host(type);
                    if (type == 0)
                        hwp3_debug("HWP3.x: Paragraph[%d, %d]: box object detected as table\n", level, p);
                    else if (type == 1)
                        hwp3_debug("HWP3.x: Paragraph[%d, %d]: box object detected as text box\n", level, p);
                    else if (type == 2)
                        hwp3_debug("HWP3.x: Paragraph[%d, %d]: box object detected as equation\n", level, p);
                    else if (type == 3)
                        hwp3_debug("HWP3.x: Paragraph[%d, %d]: box object detected as button\n", level, p);
                   else
                       hwp3_debug("HWP3.x: Paragraph[%d, %d]: box object detected as UNKNOWN(%u)\n", level, p, type);
#endif

                    /* ncells is located at offset 80 of box information */
                    if (fmap_readn(map, &ncells, offset+80, sizeof(ncells)) != sizeof(ncells))
                        return CL_EREAD;

                    ncells = le16_to_host(ncells);
                    offset += 84;

                    hwp3_debug("HWP3.x: Paragraph[%d, %d]: box object contains %u cell(s)\n", level, p, ncells);

                    /* cell information (27 bytes x ncells(offset 80 of table)) */
                    hwp3_debug("HWP3.x: Paragraph[%d, %d]: box cell info array starts @ %llu\n", level, p, (long long unsigned)offset);

                    new_offset = offset + (27 * ncells);
                    if ((new_offset < offset) || (new_offset >= map->len)) {
                        cli_errmsg("HWP3.x: Paragraph[%d, %d]: number of box cells is too high, invalid. %u\n", level, p, ncells);
                        return CL_EPARSE;
                    }
                    offset = new_offset;

                    /* cell paragraph list */
                    hwp3_debug("HWP3.x: Paragraph[%d, %d]: box cell paragraph list starts @ %llu\n", level, p, (long long unsigned)offset);
                    for (i = 0; i < ncells; i++) {
                        l = 0;
                        while (!l && ((ret = parsehwp3_paragraph(ctx, map, sp++, level+1, &offset, &l)) == CL_SUCCESS));
                        if (ret != CL_SUCCESS)
                            return ret;
                    }

                    /* box caption paragraph list */
                    hwp3_debug("HWP3.x: Paragraph[%d, %d]: box cell caption paragraph list starts @ %llu\n", level, p, (long long unsigned)offset);
                    l = 0;
                    while (!l && ((ret = parsehwp3_paragraph(ctx, map, sp++, level+1, &offset, &l)) == CL_SUCCESS));
                    if (ret != CL_SUCCESS)
                        return ret;
                    break;
                }
            case 11: /* drawing */
                {
                    uint32_t size;
                    hwp3_debug("HWP3.x: Paragraph[%d, %d]: detected drawing marker @ offset %llu\n", level, p, (long long unsigned)offset);

                    /* verification (only on HWP3_VERIFY) */
                    /* id block verify */
                    HWP3_PSPECIAL_VERIFY(map, offset, 6, content, match);
                    /* extra data block verify */
                    HWP3_PSPECIAL_VERIFY(map, offset, 24, content, match);

                    /* ID block is 8 bytes */
                    offset += 8;

                    /* Drawing Info Block is 328+n bytes with n = size of image */
                    /* n is located at offset 0 of info block */
                    if (fmap_readn(map, &size, offset, sizeof(size)) != sizeof(size))
                        return CL_EREAD;

                    hwp3_debug("HWP3.x: Paragraph[%d, %d]: drawing is %u additional bytes\n", level, p, size);

                    size = le32_to_host(size);
                    new_offset = offset + (348 + size);
                    if ((new_offset <= offset) || (new_offset >= map->len)) {
                        cli_errmsg("HWP3.x: Paragraph[%d, %d]: image size value is too high, invalid. %u\n", level, p, size);
                        return CL_EPARSE;
                    }
                    offset = new_offset;

                    /* caption paragraph list */
                    hwp3_debug("HWP3.x: Paragraph[%d, %d]: drawing caption paragraph list starts @ %llu\n", level, p, (long long unsigned)offset);
                    l = 0;
                    while (!l && ((ret = parsehwp3_paragraph(ctx, map, sp++, level+1, &offset, &l)) == CL_SUCCESS));
                    if (ret != CL_SUCCESS)
                        return ret;
                    break;
                }
            case 13: /* end-of-paragraph marker - treated identically as character */
                hwp3_debug("HWP3.x: Detected end-of-paragraph marker @ offset %llu\n", (long long unsigned)offset);
                term = 1;

                offset += sizeof(content);
                break;
            case 14: /* line information */
                {
                    hwp3_debug("HWP3.x: Detected line information marker @ offset %llu\n", (long long unsigned)offset);

                    /* verification (only on HWP3_VERIFY) */
                    /* id block verify */
                    HWP3_PSPECIAL_VERIFY(map, offset, 6, content, match);
                    /* extra data block verify */
                    HWP3_PSPECIAL_VERIFY(map, offset, 24, content, match);

                    /* ID block is 8 bytes + line information is always 84 bytes */
                    offset += 92;
                    break;
                }
            case 15: /* hidden description */
                {
                    hwp3_debug("HWP3.x: Detected hidden description marker @ offset %llu\n", (long long unsigned)offset);

                    /*
                     * offset 0 (2 bytes) - special character ID
                     * offset 2 (4 bytes) - reserved
                     * offset 6 (2 bytes) - special character ID
                     * offset 8 (8 bytes) - reserved
                     * total is always 16 bytes
                     */

                    /* id block verification (only on HWP3_VERIFY) */
                    HWP3_PSPECIAL_VERIFY(map, offset, 6, content, match);

                    offset += 16;

                    /* hidden description paragraph list */
                    hwp3_debug("HWP3.x: Paragraph[%d, %d]: hidden description paragraph list starts @ %llu\n", level, p, (long long unsigned)offset);
                    l = 0;
                    while (!l && ((ret = parsehwp3_paragraph(ctx, map, sp++, level+1, &offset, &l)) == CL_SUCCESS));
                    if (ret != CL_SUCCESS)
                        return ret;
                    break;
            }
            case 16: /* header/footer */
                {
#if HWP3_DEBUG
                    uint8_t type;
#endif

                    hwp3_debug("HWP3.x: Paragraph[%d, %d]: detected header/footer marker @ offset %llu\n", level, p, (long long unsigned)offset);

                    /*
                     * offset 0 (2 bytes) - special character ID
                     * offset 2 (4 bytes) - reserved
                     * offset 6 (2 bytes) - special character ID
                     * offset 8 (8 x 1 byte) - reserved
                     * offset 16 (1 byte) - type (header/footer)
                     * offset 17 (1 byte) - kind
                     * total is always 18 bytes
                     */

                    /* id block verification (only on HWP3_VERIFY) */
                    HWP3_PSPECIAL_VERIFY(map, offset, 6, content, match);

#if HWP3_DEBUG
                    if (fmap_readn(map, &type, offset+16, sizeof(type)) != sizeof(type))
                        return CL_EREAD;

                    if (type == 0)
                        hwp3_debug("HWP3.x: Paragraph[%d, %d]: detected header/footer as header\n", level, p);
                    else if (type == 1)
                        hwp3_debug("HWP3.x: Paragraph[%d, %d]: detected header/footer as footer\n", level, p);
                    else
                        hwp3_debug("HWP3.x: Paragraph[%d, %d]: detected header/footer as UNKNOWN(%u)\n", level, p, type);
#endif
                    offset += 18;

                    /* content paragraph list */
                    hwp3_debug("HWP3.x: Paragraph[%d, %d]: header/footer paragraph list starts @ %llu\n", level, p, (long long unsigned)offset);
                    l = 0;
                    while (!l && ((ret = parsehwp3_paragraph(ctx, map, sp++, level+1, &offset, &l)) == CL_SUCCESS));
                    if (ret != CL_SUCCESS)
                        return ret;
                    break;
                }
            case 17: /* footnote/endnote */
                {
                    hwp3_debug("HWP3.x: Detected footnote/endnote marker @ offset %llu\n", (long long unsigned)offset);

                    /*
                     * offset 0 (2 bytes) - special character ID
                     * offset 2 (4 bytes) - reserved
                     * offset 6 (2 bytes) - special character ID
                     * offset 8 (8 x 1 bytes) - reserved
                     * offset 16 (2 bytes) - number
                     * offset 18 (2 bytes) - type
                     * offset 20 (2 bytes) - alignment
                     * total is always 22 bytes
                     */

                    /* id block verification (only on HWP3_VERIFY) */
                    HWP3_PSPECIAL_VERIFY(map, offset, 6, content, match);

                    offset += 22;

                    /* content paragraph list */
                    hwp3_debug("HWP3.x: Paragraph[%d, %d]: footnote/endnote paragraph list starts @ %llu\n", level, p, (long long unsigned)offset);
                    l = 0;
                    while (!l && ((ret = parsehwp3_paragraph(ctx, map, sp++, level+1, &offset, &l)) == CL_SUCCESS));
                    if (ret != CL_SUCCESS)
                        return ret;
                    break;
                }
            case 18: /* paste code number */
                {
#if HWP3_DEBUG
                    uint8_t type;
#endif

                    hwp3_debug("HWP3.x: Paragraph[%d, %d]: detected paste code number marker @ offset %llu\n", level, p, (long long unsigned)offset);

                    /*
                     * offset 0 (2 bytes) - special character ID
                     * offset 2 (2 bytes) - type
                     * offset 4 (2 bytes) - number value
                     * offset 6 (2 bytes) - special character ID
                     * total is always 8 bytes
                     */

                    /* id block verification (only on HWP3_VERIFY) */
                    HWP3_PSPECIAL_VERIFY(map, offset, 6, content, match);

#if HWP3_DEBUG
                    if (fmap_readn(map, &type, offset+2, sizeof(type)) != sizeof(type))
                        return CL_EREAD;

                    if (type == 0)
                        hwp3_debug("HWP3.x: Paragraph[%d, %d]: detected paste code number as side\n", level, p);
                    else if (type == 1)
                        hwp3_debug("HWP3.x: Paragraph[%d, %d]: detected paste code number as footnote\n", level, p);
                    else if (type == 2)
                        hwp3_debug("HWP3.x: Paragraph[%d, %d]: detected paste code number as North America???\n", level, p);
                    else if (type == 3)
                        hwp3_debug("HWP3.x: Paragraph[%d, %d]: detected paste code number as drawing\n", level, p);
                    else if (type == 4)
                        hwp3_debug("HWP3.x: Paragraph[%d, %d]: detected paste code number as table\n", level, p);
                    else if (type == 5)
                        hwp3_debug("HWP3.x: Paragraph[%d, %d]: detected paste code number as equation\n", level, p);
                    else
                        hwp3_debug("HWP3.x: Paragraph[%d, %d]: detected paste code number as UNKNOWN(%u)\n", level, p, type);
#endif
                    offset += 8;
                    break;
                }
            case 19: /* code number change */
                {
                    hwp3_debug("HWP3.x: Paragraph[%d, %d]: detected code number change marker @ offset %llu\n", level, p, (long long unsigned)offset);

                    /*
                     * offset 0 (2 bytes) - special character ID
                     * offset 2 (2 bytes) - type
                     * offset 4 (2 bytes) - new number value
                     * offset 6 (2 bytes) - special character ID
                     * total is always 8 bytes
                     */

                    /* id block verification (only on HWP3_VERIFY) */
                    HWP3_PSPECIAL_VERIFY(map, offset, 6, content, match);

                    offset += 8;
                    break;
                }
            case 20:
                {
                    hwp3_debug("HWP3.x: Paragraph[%d, %d]: detected thread page number marker @ offset %llu\n", level, p, (long long unsigned)offset);

                    /*
                     * offset 0 (2 bytes) - special character ID
                     * offset 2 (2 bytes) - location
                     * offset 4 (2 bytes) - shape
                     * offset 6 (2 bytes) - special character ID
                     * total is always 8 bytes
                     */

                    /* id block verification (only on HWP3_VERIFY) */
                    HWP3_PSPECIAL_VERIFY(map, offset, 6, content, match);

                    offset += 8;
                    break;
                }
            case 21: /* hide special */
                {
                    hwp3_debug("HWP3.x: Paragraph[%d, %d]: detected hide special marker @ offset %llu\n", level, p, (long long unsigned)offset);

                    /*
                     * offset 0 (2 bytes) - special character ID
                     * offset 2 (2 bytes) - type
                     * offset 4 (2 bytes) - target
                     * offset 6 (2 bytes) - special character ID
                     * total is always 8 bytes
                     */

                    /* id block verification (only on HWP3_VERIFY) */
                    HWP3_PSPECIAL_VERIFY(map, offset, 6, content, match);

                    offset += 8;
                    break;
                }
            case 22: /* mail merge display */
                {
                    hwp3_debug("HWP3.x: Paragraph[%d, %d]: detected mail merge display marker @ offset %llu\n", level, p, (long long unsigned)offset);

                    /*
                     * offset 0 (2 bytes) - special character ID
                     * offset 2 (20 x 1 bytes) - field name (in ASCII)
                     * offset 22 (2 bytes) - special character ID
                     * total is always 24 bytes
                     */

                    /* id block verification (only on HWP3_VERIFY) */
                    HWP3_PSPECIAL_VERIFY(map, offset, 22, content, match);

                    offset += 24;
                    break;
                }
            case 23: /* overlapping letters */
                {
                    hwp3_debug("HWP3.x: Paragraph[%d, %d]: detected overlapping marker @ offset %llu\n", level, p, (long long unsigned)offset);

                    /*
                     * offset 0 (2 bytes) - special character ID
                     * offset 2 (3 x 2 bytes) - overlapping letters
                     * offset 8 (2 bytes) - special character ID
                     * total is always 10 bytes
                     */

                    /* id block verification (only on HWP3_VERIFY) */
                    HWP3_PSPECIAL_VERIFY(map, offset, 8, content, match);

                    offset += 10;
                    break;
                }
            case 24: /* hyphen */
                {
                    hwp3_debug("HWP3.x: Paragraph[%d, %d]: detected hyphen marker @ offset %llu\n", level, p, (long long unsigned)offset);

                    /*
                     * offset 0 (2 bytes) - special character ID
                     * offset 2 (2 bytes) - width of hyphen
                     * offset 4 (2 bytes) - special character ID
                     * total is always 6 bytes
                     */

                    /* id block verification (only on HWP3_VERIFY) */
                    HWP3_PSPECIAL_VERIFY(map, offset, 4, content, match);

                    offset += 6;
                    break;
                }
            case 25: /* title/table/picture show times */
                {
                    hwp3_debug("HWP3.x: Paragraph[%d, %d]: detected title/table/picture show times marker @ offset %llu\n", level, p, (long long unsigned)offset);

                    /*
                     * offset 0 (2 bytes) - special character ID
                     * offset 2 (2 bytes) - type
                     * offset 4 (2 bytes) - special character ID
                     * total is always 6 bytes
                     */

                    /* id block verification (only on HWP3_VERIFY) */
                    HWP3_PSPECIAL_VERIFY(map, offset, 4, content, match);

                    offset += 6;
                    break;
                }
            case 26: /* browse displayed */
                {
                    hwp3_debug("HWP3.x: Paragraph[%d, %d]: detected browse displayed marker @ offset %llu\n", level, p, (long long unsigned)offset);

                    /*
                     * offset 0 (2 bytes) - special character ID
                     * offset 2 (60 x 2 bytes) - keyword 1
                     * offset 122 (60 x 2 bytes) - keyword 2
                     * offset 242 (2 bytes) - page number
                     * offset 244 (2 bytes) - special character ID
                     * total is always 246 bytes
                     */

                    /* id block verification (only on HWP3_VERIFY) */
                    HWP3_PSPECIAL_VERIFY(map, offset, 244, content, match);

                    offset += 246;
                    break;
                }
            case 28: /* overview shape/summary number */
                {
                    hwp3_debug("HWP3.x: Paragraph[%d, %d]: detected overview shape/summary number marker @ offset %llu\n", level, p, (long long unsigned)offset);

                    /*
                     * offset 0 (2 bytes) - special character ID
                     * offset 2 (2 bytes) - type
                     * offset 4 (1 byte)  - form
                     * offset 5 (1 byte)  - step
                     * offset 6 (7 x 2 bytes)  - summary number
                     * offset 20 (7 x 2 bytes) - custom
                     * offset 34 (2 x 7 x 2 bytes) - decorative letters
                     * offset 62 (2 bytes) - special character ID
                     * total is always 64 bytes
                     */

                    /* id block verification (only on HWP3_VERIFY) */
                    HWP3_PSPECIAL_VERIFY(map, offset, 62, content, match);

                    offset += 64;
                    break;
                }
            case 29: /* cross-reference */
                {
                    uint32_t length;

                    hwp3_debug("HWP3.x: Paragraph[%d, %d]: detected cross-reference marker @ offset %llu\n", level, p, (long long unsigned)offset);

                    /*
                     * offset 0 (2 bytes) - special character ID
                     * offset 2 (4 bytes) - length of information
                     * offset 6 (2 bytes) - special character ID
                     * offset 8 (n bytes) - ...
                     */

                    /* id block verification (only on HWP3_VERIFY) */
                    HWP3_PSPECIAL_VERIFY(map, offset, 6, content, match);

                    if (fmap_readn(map, &length, offset+2, sizeof(length)) != sizeof(length))
                        return CL_EREAD;

                    length = le32_to_host(length);
                    new_offset = offset + (8 + length);
                    if ((new_offset <= offset) || (new_offset > map->len)) {
                        cli_errmsg("HWP3.x: Paragraph[%d, %d]: length value is too high, invalid. %u\n", level, p, length);
                        return CL_EPARSE;
                    }
                    offset = new_offset;
                    break;
                }
            case 30: /* bundle of blanks (ON SALE for 2.99!) */
                {
                    hwp3_debug("HWP3.x: Paragraph[%d, %d]: detected title/table/picture show times marker @ offset %llu\n", level, p, (long long unsigned)offset);

                    /*
                     * offset 0 (2 bytes) - special character ID
                     * offset 2 (2 bytes) - special character ID
                     * total is always 4 bytes
                     */

                    /* id block verification (only on HWP3_VERIFY) */
                    HWP3_PSPECIAL_VERIFY(map, offset, 2, content, match);

                    offset += 4;
                    break;
                }
            case 31: /* fixed-width space */
                {
                    hwp3_debug("HWP3.x: Paragraph[%d, %d]: detected title/table/picture show times marker @ offset %llu\n", level, p, (long long unsigned)offset);

                    /*
                     * offset 0 (2 bytes) - special character ID
                     * offset 2 (2 bytes) - special character ID
                     * total is always 4 bytes
                     */

                    /* id block verification (only on HWP3_VERIFY) */
                    HWP3_PSPECIAL_VERIFY(map, offset, 2, content, match);

                    offset += 4;
                    break;
                }
            default:
                hwp3_debug("HWP3.x: Paragraph[%d, %d]: detected special character as [UNKNOWN]\n", level, p);
                cli_errmsg("HWP3.x: Paragraph[%d, %d]: cannot understand special character %u\n", level, p, content);
                return CL_EPARSE;
            }
        } else { /* normal characters */
            offset += sizeof(content);
        }
    }

    hwp3_debug("HWP3.x: end recursion level: %d\n", level);

    (*roffset) = offset;
    return CL_SUCCESS;
}

static inline int parsehwp3_infoblk_0(cli_ctx *ctx, fmap_t *dmap, off_t *offset, int *last)
{
    uint16_t infoid, infolen;
    fmap_t *map = (dmap ? dmap : *ctx->fmap);

    return CL_SUCCESS;
}

static inline int parsehwp3_infoblk_1(cli_ctx *ctx, fmap_t *dmap, off_t *offset, int *last)
{
    uint32_t infoid, infolen;
    fmap_t *map = (dmap ? dmap : *ctx->fmap);
    int i, count, ret = CL_SUCCESS;
    long long unsigned infoloc = (long long unsigned)(*offset);
    char field[HWP3_FIELD_LENGTH];
#if HAVE_JSON
    json_object *infoblk_1, *contents, *counter, *entry;
#endif

    hwp3_debug("HWP3.x: Information Block @ offset %llu\n", infoloc);

#if HAVE_JSON
    if (SCAN_COLLECT_METADATA) {
        infoblk_1 = cli_jsonobj(ctx->wrkproperty, "InfoBlk_1");
        if (!infoblk_1) {
            cli_errmsg("HWP5.x: No memory for information block object\n");
            return CL_EMEM;
        }

        contents = cli_jsonarray(infoblk_1, "Contents");
        if (!contents) {
            cli_errmsg("HWP5.x: No memory for information block contents array\n");
            return CL_EMEM;
        }

        if (!json_object_object_get_ex(infoblk_1, "Count", &counter)) { /* object not found */
            cli_jsonint(infoblk_1, "Count", 1);
        } else {
            int value = json_object_get_int(counter);
            cli_jsonint(infoblk_1, "Count", value+1);
        }
    }
#endif

    if (fmap_readn(map, &infoid, (*offset), sizeof(infoid)) != sizeof(infoid)) {
        cli_errmsg("HWP3.x: Failed to read information block id @ %llu\n",
                   (long long unsigned)(*offset));
        return CL_EREAD;
    }
    (*offset) += sizeof(infoid);
    infoid = le32_to_host(infoid);

#if HAVE_JSON
    if (SCAN_COLLECT_METADATA) {
        entry = cli_jsonobj(contents, NULL);
        if (!entry) {
            cli_errmsg("HWP5.x: No memory for information block entry object\n");
            return CL_EMEM;
        }

        cli_jsonint(entry, "ID", infoid);
    }
#endif
    hwp3_debug("HWP3.x: Information Block[%llu]: ID:  %u\n", infoloc, infoid);

    /* Booking Information(5) - no length field and no content */
    if (infoid == 5) {
        hwp3_debug("HWP3.x: Information Block[%llu]: TYPE: Booking Information\n", infoloc);
#if HAVE_JSON
        if (SCAN_COLLECT_METADATA)
            cli_jsonstr(entry, "Type", "Booking Information");
#endif
        return CL_SUCCESS;
    }

    if (fmap_readn(map, &infolen, (*offset), sizeof(infolen)) != sizeof(infolen)) {
        cli_errmsg("HWP3.x: Failed to read information block len @ %llu\n",
                   (long long unsigned)(*offset));
        return CL_EREAD;
    }
    (*offset) += sizeof(infolen);
    infolen = le32_to_host(infolen);

#if HAVE_JSON
    if (SCAN_COLLECT_METADATA) {
        cli_jsonint64(entry, "Offset", infoloc);
        cli_jsonint(entry, "Length", infolen);
    }
#endif
    hwp3_debug("HWP3.x: Information Block[%llu]: LEN: %u\n", infoloc, infolen);

    /* check information block bounds */
    if ((*offset)+infolen > map->len) {
        cli_errmsg("HWP3.x: Information blocks length exceeds remaining map length, %llu > %llu\n",
                   (long long unsigned)((*offset)+infolen), (long long unsigned)(map->len));
        return CL_EREAD;
    }

    /* Information Blocks */
    switch(infoid) {
    case 0: /* Terminating */
        if (infolen == 0) {
            hwp3_debug("HWP3.x: Information Block[%llu]: TYPE: Terminating Entry\n", infoloc);
#if HAVE_JSON
        if (SCAN_COLLECT_METADATA)
            cli_jsonstr(entry, "Type", "Terminating Entry");
#endif
            if (last) *last = 1;
            return CL_SUCCESS;
        } else {
            cli_errmsg("HWP3.x: Information Block[%llu]: TYPE: Invalid Terminating Entry\n", infoloc);
            return CL_EFORMAT;
        }
    case 1: /* Image Data */
        hwp3_debug("HWP3.x: Information Block[%llu]: TYPE: Image Data\n", infoloc);
#if HAVE_JSON
        if (SCAN_COLLECT_METADATA)
            cli_jsonstr(entry, "Type", "Image Data");
#endif
#if HWP3_DEBUG /* additional fields can be added */
        memset(field, 0, HWP3_FIELD_LENGTH);
        if (fmap_readn(map, field, (*offset), 16) != 16) {
            cli_errmsg("HWP3.x: Failed to read information block field @ %llu\n",
                       (long long unsigned)(*offset));
            return CL_EREAD;
        }
        hwp3_debug("HWP3.x: Information Block[%llu]: NAME: %s\n", infoloc, field);

        memset(field, 0, HWP3_FIELD_LENGTH);
        if (fmap_readn(map, field, (*offset)+16, 16) != 16) {
            cli_errmsg("HWP3.x: Failed to read information block field @ %llu\n",
                       (long long unsigned)(*offset));
            return CL_EREAD;
        }
        hwp3_debug("HWP3.x: Information Block[%llu]: FORM: %s\n", infoloc, field);
#endif
        /* 32 bytes for extra data fields */
        if (infolen > 0)
            ret = cli_map_scan(map, (*offset)+32, infolen-32, ctx, CL_TYPE_ANY);
        break;
    case 2: /* OLE2 Data */
        hwp3_debug("HWP3.x: Information Block[%llu]: TYPE: OLE2 Data\n", infoloc);
#if HAVE_JSON
        if (SCAN_COLLECT_METADATA)
            cli_jsonstr(entry, "Type", "OLE2 Data");
#endif
        if (infolen > 0)
            ret = cli_map_scan(map, (*offset), infolen, ctx, CL_TYPE_ANY);
        break;
    case 3: /* Hypertext/Hyperlink Information */
        hwp3_debug("HWP3.x: Information Block[%llu]: TYPE: Hypertext/Hyperlink Information\n", infoloc);
        if (infolen % 617) {
            cli_errmsg("HWP3.x: Information Block[%llu]: Invalid multiple of 617 => %u\n", infoloc, infolen);
            return CL_EFORMAT;
        }

        count = (infolen / 617);
        hwp3_debug("HWP3.x: Information Block[%llu]: COUNT: %d entries\n", infoloc, count);
#if HAVE_JSON
        if (SCAN_COLLECT_METADATA) {
            cli_jsonstr(entry, "Type", "Hypertext/Hyperlink Information");
            cli_jsonint(entry, "Count", count);
        }
#endif

        for (i = 0; i < count; i++) {
#if HWP3_DEBUG /* additional fields can be added */
            memset(field, 0, HWP3_FIELD_LENGTH);
            if (fmap_readn(map, field, (*offset), 256) != 256) {
                cli_errmsg("HWP3.x: Failed to read information block field @ %llu\n",
                           (long long unsigned)(*offset));
                return CL_EREAD;
            }
            hwp3_debug("HWP3.x: Information Block[%llu]: %d: NAME: %s\n", infoloc, i, field);
#endif
            /* scanning macros - TODO - check numbers */
            ret = cli_map_scan(map, (*offset)+(617*i)+288, 325, ctx, CL_TYPE_ANY);
        }
        break;
    case 4: /* Presentation Information */
        hwp3_debug("HWP3.x: Information Block[%llu]: TYPE: Presentation Information\n", infoloc);
#if HAVE_JSON
        if (SCAN_COLLECT_METADATA)
            cli_jsonstr(entry, "Type", "Presentation Information");
#endif
        /* contains nothing of interest to scan */
        break;
    case 5: /* Booking Information */
        /* should never run this as it is short-circuited above */
        hwp3_debug("HWP3.x: Information Block[%llu]: TYPE: Booking Information\n", infoloc);
#if HAVE_JSON
        if (SCAN_COLLECT_METADATA)
            cli_jsonstr(entry, "Type", "Booking Information");
#endif
        break;
    case 6: /* Background Image Data */
        hwp3_debug("HWP3.x: Information Block[%llu]: TYPE: Background Image Data\n", infoloc);
#if HAVE_JSON
        if (SCAN_COLLECT_METADATA) {
            cli_jsonstr(entry, "Type", "Background Image Data");
            cli_jsonint(entry, "ImageSize", infolen-324);
        }
#endif
#if HWP3_DEBUG /* additional fields can be added */
        memset(field, 0, HWP3_FIELD_LENGTH);
        if (fmap_readn(map, field, (*offset)+24, 256) != 256) {
            cli_errmsg("HWP3.x: Failed to read information block field @ %llu\n",
                       (long long unsigned)(*offset));
            return CL_EREAD;
        }
        hwp3_debug("HWP3.x: Information Block[%llu]: NAME: %s\n", infoloc, field);
#endif
        /* 324 bytes for extra data fields */
        if (infolen > 0)
            ret = cli_map_scan(map, (*offset)+324, infolen-324, ctx, CL_TYPE_ANY);
        break;
    case 0x100: /* Table Extension */
        hwp3_debug("HWP3.x: Information Block[%llu]: TYPE: Table Extension\n", infoloc);
#if HAVE_JSON
        if (SCAN_COLLECT_METADATA)
            cli_jsonstr(entry, "Type", "Table Extension");
#endif
        /* contains nothing of interest to scan */
        break;
    case 0x101: /* Press Frame Information Field Name */
        hwp3_debug("HWP3.x: Information Block[%llu]: TYPE: Press Frame Information Field Name\n", infoloc);
#if HAVE_JSON
        if (SCAN_COLLECT_METADATA)
            cli_jsonstr(entry, "Type", "Press Frame Information Field Name");
#endif
        /* contains nothing of interest to scan */
        break;
    default:
        cli_warnmsg("HWP3.x: Information Block[%llu]: TYPE: UNKNOWN(%u)\n", infoloc, infoid);
        if (infolen > 0)
            ret = cli_map_scan(map, (*offset), infolen, ctx, CL_TYPE_ANY);
    }

    (*offset) += infolen;
    return ret;
}

static int hwp3_cb(void *cbdata, int fd, const char* filepath, cli_ctx *ctx)
{
    fmap_t *map, *dmap;
    off_t offset, start, new_offset;
    int i, t = 0, p = 0, last = 0, ret = CL_SUCCESS;
    uint16_t nstyles;
#if HAVE_JSON
    json_object *fonts;
#endif

    offset = start = cbdata ? *(off_t *)cbdata : 0;

    if (offset == 0) {
        if (fd < 0) {
            cli_errmsg("HWP3.x: Invalid file descriptor argument\n");
            return CL_ENULLARG;
        } else {
            STATBUF statbuf;

            if (FSTAT(fd, &statbuf) == -1) {
                cli_errmsg("HWP3.x: Can't stat file descriptor\n");
                return CL_ESTAT;
            }

            map = dmap = fmap(fd, 0, statbuf.st_size);
            if (!map) {
                cli_errmsg("HWP3.x: Failed to get fmap for uncompressed stream\n");
                return CL_EMAP;
            }
        }
    } else {
        hwp3_debug("HWP3.x: Document Content Stream starts @ offset %llu\n", (long long unsigned)offset);

        map = *ctx->fmap;
        dmap = NULL;
    }

    /* Fonts - 7 entries of 2 + (n x 40) bytes where n is the first 2 bytes of the entry */
#if HAVE_JSON
    if (SCAN_COLLECT_METADATA)
        fonts = cli_jsonarray(ctx->wrkproperty, "FontCounts");
#endif
    for (i = 0; i < 7; i++) {
        uint16_t nfonts;

        if (fmap_readn(map, &nfonts, offset, sizeof(nfonts)) != sizeof(nfonts)) {
            if (dmap)
                funmap(dmap);
            return CL_EREAD;
        }
        nfonts = le16_to_host(nfonts);

#if HAVE_JSON
        if (SCAN_COLLECT_METADATA)
            cli_jsonint(fonts, NULL, nfonts);
#endif
        hwp3_debug("HWP3.x: Font Entry %d with %u entries @ offset %llu\n", i+1, nfonts, (long long unsigned)offset);
        new_offset = offset + (2 + nfonts * 40);
        if ((new_offset <= offset) || (new_offset >= map->len)) {
            cli_errmsg("HWP3.x: Font Entry: number of fonts is too high, invalid. %u\n", nfonts);
            return CL_EPARSE;
        }
        offset = new_offset;
    }

    /* Styles - 2 + (n x 238) bytes where n is the first 2 bytes of the section */
    if (fmap_readn(map, &nstyles, offset, sizeof(nstyles)) != sizeof(nstyles)) {
        if (dmap)
            funmap(dmap);
        return CL_EREAD;
    }
    nstyles = le16_to_host(nstyles);

#if HAVE_JSON
    if (SCAN_COLLECT_METADATA)
        cli_jsonint(ctx->wrkproperty, "StyleCount", nstyles);
#endif
    hwp3_debug("HWP3.x: %u Styles @ offset %llu\n", nstyles, (long long unsigned)offset);
    new_offset = offset + (2 + nstyles * 238);
    if ((new_offset <= offset) || (new_offset >= map->len)) {
        cli_errmsg("HWP3.x: Font Entry: number of font styles is too high, invalid. %u\n", nstyles);
        return CL_EPARSE;
    }
    offset += (2 + nstyles * 238);

    last = 0;
    /* Paragraphs - variable */
    /* Paragraphs - are terminated with 0x0d00[13(CR) as hchar], empty paragraph marks end of section and do NOT end with 0x0d00 */
    while (!last && ((ret = parsehwp3_paragraph(ctx, map, p++, 0, &offset, &last)) == CL_SUCCESS));
    /* return is never a virus */
    if (ret != CL_SUCCESS) {
        if (dmap)
            funmap(dmap);
        return ret;
    }
#if HAVE_JSON
    if (SCAN_COLLECT_METADATA)
        cli_jsonint(ctx->wrkproperty, "ParagraphCount", p);
#endif

    last = 0;
    /* 'additional information block #1's - attachments and media */
    while (!last && ((ret = parsehwp3_infoblk_1(ctx, map, &offset, &last)) == CL_SUCCESS));

    /* scan the uncompressed stream - both compressed and uncompressed cases [ALLMATCH] */
    if ((ret == CL_SUCCESS) || ((SCAN_ALLMATCHES) && (ret == CL_VIRUS))) {
        int subret = ret;
        size_t dlen = offset - start;

        ret = cli_map_scandesc(map, start, dlen, ctx, CL_TYPE_ANY);
        //ret = cli_map_scandesc(map, 0, 0, ctx, CL_TYPE_ANY);

        if (ret == CL_SUCCESS)
            ret = subret;
    }

    if (dmap)
        funmap(dmap);
    return ret;
}

int cli_scanhwp3(cli_ctx *ctx)
{
    struct hwp3_docinfo docinfo;
    int ret = CL_SUCCESS;
    off_t offset = 0, new_offset = 0;
    fmap_t *map = *ctx->fmap;

#if HAVE_JSON
    /*
    // magic 
    cli_jsonstr(header, "Magic", hwp5->signature);

    // version
    cli_jsonint(header, "RawVersion", hwp5->version);
    */
#endif
    offset += HWP3_IDENTITY_INFO_SIZE;

    if ((ret = parsehwp3_docinfo(ctx, offset, &docinfo)) != CL_SUCCESS)
        return ret;

    offset += HWP3_DOCINFO_SIZE;

    if ((ret = parsehwp3_docsummary(ctx, offset)) != CL_SUCCESS)
        return ret;

    offset += HWP3_DOCSUMMARY_SIZE;

    /* password-protected document - cannot parse */
    if (docinfo.di_passwd) {
        cli_dbgmsg("HWP3.x: password-protected file, skip parsing\n");
        return CL_SUCCESS;
    }

    if (docinfo.di_infoblksize) {
        /* OPTIONAL TODO: HANDLE OPTIONAL INFORMATION BLOCK #0's FOR PRECLASS */
        new_offset = offset + docinfo.di_infoblksize;
        if ((new_offset <= offset) || (new_offset >= map->len)) {
            cli_errmsg("HWP3.x: Doc info block size is too high, invalid. %u\n", docinfo.di_infoblksize);
            return CL_EPARSE;
        }
        offset = new_offset;
    }

    if (docinfo.di_compressed)
        ret = decompress_and_callback(ctx, *ctx->fmap, offset, 0, "HWP3.x", hwp3_cb, NULL);
    else
        ret = hwp3_cb(&offset, 0, ctx->sub_filepath, ctx);

    if (ret != CL_SUCCESS)
        return ret;

    /* OPTIONAL TODO: HANDLE OPTIONAL ADDITIONAL INFORMATION BLOCK #2's FOR PRECLASS*/

    return ret;
}

/*** HWPML (hijacking the msxml parser) ***/
#if HAVE_LIBXML2
static const struct key_entry hwpml_keys[] = {
    { "hwpml",              "HWPML",              MSXML_JSON_ROOT | MSXML_JSON_ATTRIB },

    /* HEAD - Document Properties */
    //{ "head",               "Head",               MSXML_JSON_WRKPTR },
    { "docsummary",         "DocumentProperties", MSXML_JSON_WRKPTR },
    { "title",              "Title",              MSXML_JSON_WRKPTR | MSXML_JSON_VALUE },
    { "author",             "Author",             MSXML_JSON_WRKPTR | MSXML_JSON_VALUE },
    { "date",               "Date",               MSXML_JSON_WRKPTR | MSXML_JSON_VALUE },
    { "docsetting",         "DocumentSettings",   MSXML_JSON_WRKPTR },
    { "beginnumber",        "BeginNumber",        MSXML_JSON_WRKPTR | MSXML_JSON_ATTRIB },
    { "caretpos",           "CaretPos",           MSXML_JSON_WRKPTR | MSXML_JSON_ATTRIB },
    //{ "bindatalist",        "BinDataList",        MSXML_JSON_WRKPTR },
    //{ "binitem",            "BinItem",            MSXML_JSON_WRKPTR | MSXML_JSON_ATTRIB },
    { "facenamelist",       "FaceNameList",       MSXML_IGNORE_ELEM }, /* fonts list */
    { "borderfilllist",     "BorderFillList",     MSXML_IGNORE_ELEM }, /* borders list */
    { "charshapelist",      "CharShapeList",      MSXML_IGNORE_ELEM }, /* character shapes */
    { "tabdeflist",         "TableDefList",       MSXML_IGNORE_ELEM }, /* table defs */
    { "numberinglist",      "NumberingList",      MSXML_IGNORE_ELEM }, /* numbering list */
    { "parashapelist",      "ParagraphShapeList", MSXML_IGNORE_ELEM }, /* paragraph shapes */
    { "stylelist",          "StyleList",          MSXML_IGNORE_ELEM }, /* styles */
    { "compatibledocument", "WordCompatibility",  MSXML_IGNORE_ELEM }, /* word compatibility data */

    /* BODY - Document Contents */
    { "body",               "Body",               MSXML_IGNORE_ELEM }, /* document contents (we could build a document contents summary */

    /* TAIL - Document Attachments */
    //{ "tail",               "Tail",               MSXML_JSON_WRKPTR },
    { "bindatastorage",     "BinaryDataStorage",  MSXML_JSON_WRKPTR },
    { "bindata",            "BinaryData",         MSXML_SCAN_CB | MSXML_JSON_WRKPTR | MSXML_JSON_ATTRIB },
    { "scriptcode",         "ScriptCodeStorage",  MSXML_JSON_WRKPTR | MSXML_JSON_ATTRIB },
    { "scriptheader",       "ScriptHeader",       MSXML_SCAN_CB | MSXML_JSON_WRKPTR | MSXML_JSON_VALUE },
    { "scriptsource",       "ScriptSource",       MSXML_SCAN_CB | MSXML_JSON_WRKPTR | MSXML_JSON_VALUE }
};
static size_t num_hwpml_keys = sizeof(hwpml_keys) / sizeof(struct key_entry);

/* binary streams needs to be base64-decoded then decompressed if fields are set */
static int hwpml_scan_cb(void *cbdata, int fd, const char* filepath, cli_ctx *ctx)
{
    if (fd < 0 || !ctx)
        return CL_ENULLARG;

    return cli_magic_scandesc(fd, filepath, ctx);
}

static int hwpml_binary_cb(int fd, const char* filepath, cli_ctx *ctx, int num_attribs, struct attrib_entry *attribs, void *cbdata)
{
    int i, ret, df = 0, com = 0, enc = 0;
    char *tempfile;

    UNUSEDPARAM(cbdata);

    /* check attributes for compression and encoding */
    for (i = 0; i < num_attribs; i++) {
        if (!strcmp(attribs[i].key, "Compress")) {
            if (!strcmp(attribs[i].value, "true"))
                com = 1;
            else if (!strcmp(attribs[i].value, "false"))
                com = 0;
            else
                com = -1;
        }

        if (!strcmp(attribs[i].key, "Encoding")) {
            if (!strcmp(attribs[i].value, "Base64"))
                enc = 1;
            else
                enc = -1;
        }
    }

    hwpml_debug("HWPML: Checking attributes: com: %d, enc: %d\n", com, enc);

    /* decode the binary data if needed - base64 */
    if (enc < 0) {
        cli_errmsg("HWPML: Unrecognized encoding method\n");
        return cli_magic_scandesc(fd, filepath, ctx);
    } else if (enc == 1) {
        STATBUF statbuf;
        fmap_t *input;
        const char *instream;
        char *decoded;
        size_t decodedlen;

        hwpml_debug("HWPML: Decoding base64-encoded binary data\n");

        /* fmap the input file for easier manipulation */
        if (FSTAT(fd, &statbuf) == -1) {
            cli_errmsg("HWPML: Can't stat file descriptor\n");
            return CL_ESTAT;
        }

        if (!(input = fmap(fd, 0, statbuf.st_size))) {
            cli_errmsg("HWPML: Failed to get fmap for binary data\n");
            return CL_EMAP;
        }

        /* send data for base64 conversion - TODO: what happens with really big files? */
        if (!(instream = fmap_need_off_once(input, 0, input->len))) {
            cli_errmsg("HWPML: Failed to get input stream from binary data\n");
            funmap(input);
            return CL_EMAP;
        }

        decoded = (char *)cl_base64_decode((char *)instream, input->len, NULL, &decodedlen, 0);
        funmap(input);
        if (!decoded) {
            cli_errmsg("HWPML: Failed to get base64 decode binary data\n");
            return cli_magic_scandesc(fd, filepath, ctx);
        }

        /* open file for writing and scanning */
        if ((ret = cli_gentempfd(ctx->engine->tmpdir, &tempfile, &df)) != CL_SUCCESS) {
            cli_warnmsg("HWPML: Failed to create temporary file for decoded stream scanning\n");
            return ret;
        }

        if(cli_writen(df, decoded, decodedlen) != (int)decodedlen) {
            free(decoded);
            ret = CL_EWRITE;
            goto hwpml_end;
        }
        free(decoded);

        /* keeps the later logic simpler */
        fd = df;

        cli_dbgmsg("HWPML: Decoded binary data to %s\n", tempfile);
    }

    /* decompress the file if needed - zlib */
    if (com) {
        STATBUF statbuf;
        fmap_t *input;

        hwpml_debug("HWPML: Decompressing binary data\n");

        /* fmap the input file for easier manipulation */
        if (FSTAT(fd, &statbuf) == -1) {
            cli_errmsg("HWPML: Can't stat file descriptor\n");
            ret = CL_ESTAT;
            goto hwpml_end;
        }

        input = fmap(fd, 0, statbuf.st_size);
        if (!input) {
            cli_errmsg("HWPML: Failed to get fmap for binary data\n");
            ret = CL_EMAP;
            goto hwpml_end;
        }
        ret = decompress_and_callback(ctx, input, 0, 0, "HWPML", hwpml_scan_cb, NULL);
        funmap(input);
    } else {
        if (fd == df) { /* fd is a decoded tempfile */
            ret = hwpml_scan_cb(NULL, fd, tempfile, ctx);
        } else {        /* fd is the original filepath, no decoding necessary */
            ret = hwpml_scan_cb(NULL, fd, filepath, ctx);
        }
    }

    /* close decoded file descriptor if used */
 hwpml_end:
    if (df) {
        close(df);
        if (!(ctx->engine->keeptmp))
            cli_unlink(tempfile);
        free(tempfile);
    }
    return ret;
}
#endif /* HAVE_LIBXML2 */

int cli_scanhwpml(cli_ctx *ctx)
{
#if HAVE_LIBXML2
    struct msxml_cbdata cbdata;
    struct msxml_ctx mxctx;
    xmlTextReaderPtr reader = NULL;
    int state, ret = CL_SUCCESS;

    cli_dbgmsg("in cli_scanhwpml()\n");

    if (!ctx)
        return CL_ENULLARG;

    memset(&cbdata, 0, sizeof(cbdata));
    cbdata.map = *ctx->fmap;

    reader = xmlReaderForIO(msxml_read_cb, NULL, &cbdata, "hwpml.xml", NULL, CLAMAV_MIN_XMLREADER_FLAGS);
    if (!reader) {
        cli_dbgmsg("cli_scanhwpml: cannot initialize xmlReader\n");

#if HAVE_JSON
        ret = cli_json_parse_error(ctx->wrkproperty, "HWPML_ERROR_XML_READER_IO");
#endif
        return ret; // libxml2 failed!
    }

    memset(&mxctx, 0, sizeof(mxctx));
    mxctx.scan_cb = hwpml_binary_cb;
    ret = cli_msxml_parse_document(ctx, reader, hwpml_keys, num_hwpml_keys, MSXML_FLAG_JSON, &mxctx);

    xmlTextReaderClose(reader);
    xmlFreeTextReader(reader);
    return ret;
#else
    UNUSEDPARAM(ctx);
    cli_dbgmsg("in cli_scanhwpml()\n");
    cli_dbgmsg("cli_scanhwpml: scanning hwpml documents requires libxml2!\n");

    return CL_SUCCESS;
#endif
}

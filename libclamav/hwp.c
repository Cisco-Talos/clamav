/*
 * HWP Stuff
 * 
 * Copyright (C) 2015 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
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
#ifdef _WIN32
#ifndef LIBXML_WRITER_ENABLED
#define LIBXML_WRITER_ENABLED 1
#endif
#endif
#include <libxml/xmlreader.h>
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <ctype.h>
#include <zlib.h>

#include "clamav.h"
#include "fmap.h"
#include "str.h"
#include "others.h"
#include "scanners.h"
#include "msxml_parser.h"
#include "msxml.h"
#include "json_api.h"
#include "hwp.h"
#if HAVE_JSON
#include "msdoc.h"
#endif

#define HWP5_DEBUG 0
#define HWP3_DEBUG 1
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

typedef int (*hwp_cb )(void *cbdata, int fd, cli_ctx *ctx);
static int decompress_and_callback(cli_ctx *ctx, fmap_t *input, off_t at, size_t len, const char *parent, hwp_cb cb, void *cbdata)
{
    int zret, ofd, ret = CL_SUCCESS;
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
            ret = fmap_readn(input, inbuf, off_in, FILEBUFF);
            if (ret < 0) {
                cli_errmsg("%s: Error reading stream\n", parent);
                ret = CL_EUNPACK;
                goto dc_end;
            }
            if (!ret)
                break;

            if (len) {
                if (remain < ret)
                    ret = remain;
                remain -= ret;
            }
            zstrm.avail_in = ret;
            off_in += ret;
        }
        zret = inflate(&zstrm, Z_SYNC_FLUSH);
        count = FILEBUFF - zstrm.avail_out;
        if (count) {
            if (cli_checklimits("HWP", ctx, outsize + count, 0, 0) != CL_SUCCESS)
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

    /* post inflation checks */
    if (zret != Z_STREAM_END && zret != Z_OK) {
        if (outsize == 0) {
            cli_infomsg(ctx, "%s: Error decompressing stream. No data decompressed.\n", parent);
            ret = CL_EUNPACK;
            goto dc_end;
        }

        cli_infomsg(ctx, "%s: Error decompressing stream. Scanning what was decompressed.\n", parent);
    }
    if (len && remain > 0)
        cli_infomsg(ctx, "%s: Error decompressing stream. Not all requested input was converted\n", parent);

    cli_dbgmsg("%s: Decompressed %llu bytes to %s\n", parent, (long long unsigned)outsize, tmpname);

    /* scanning inflated stream */
    ret = cb(cbdata, ofd, ctx);

    /* clean-up */
 dc_end:
    zret = inflateEnd(&zstrm);
    if (zret != Z_OK)
        ret = CL_EUNPACK;
    close(ofd);
    if (!ctx->engine->keeptmp)
        if (cli_unlink(tmpname))
            ret = CL_EUNLINK;
    free(tmpname);
    return ret;
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

    return cli_map_scandesc(map, 4, map->len, ctx, CL_TYPE_ANY);
    //return cli_map_scandesc(map, 4, map->len, ctx, CL_TYPE_OLE2);
}

/*** HWP5 ***/

int cli_hwp5header(cli_ctx *ctx, hwp5_header_t *hwp5)
{
#if HAVE_JSON
    json_object *header, *flags;

    if (!ctx || !hwp5)
        return CL_ENULLARG;

    header = cli_jsonobj(ctx->wrkproperty, "Hwp5Header");
    if (!header) {
        cli_errmsg("HWP5.x: No memory for Hwp5Header object\n");
        return CL_EMEM;
    }

    /* magic */
    cli_jsonstr(header, "Magic", hwp5->signature);

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

#endif
    return CL_SUCCESS;
}

static int hwp5_cb(void *cbdata, int fd, cli_ctx *ctx)
{
    int ret;

    if (fd < 0 || !ctx)
        return CL_ENULLARG;

    return cli_magic_scandesc(fd, ctx);
}

int cli_scanhwp5_stream(cli_ctx *ctx, hwp5_header_t *hwp5, char *name, int fd)
{
    hwp5_debug("HWP5.x: NAME: %s\n", name);

    if (fd < 0) {
        cli_errmsg("HWP5.x: Invalid file descriptor argument\n");
        return CL_ENULLARG;
    }

    /* encrypted and compressed streams */
    if (!strncmp(name, "bin", 3) || !strncmp(name, "jscriptversion", 14) ||
        !strncmp(name, "defaultjscript", 14) || !strncmp(name, "section", 7) ||
        !strncmp(name, "viewtext", 8) || !strncmp(name, "docinfo", 7)) {

        if (hwp5->flags & HWP5_PASSWORD) {
            cli_dbgmsg("HWP5.x: Password encrypted stream, scanning as-is\n");
            return cli_magic_scandesc(fd, ctx);
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
    if (ctx->options & CL_SCAN_FILE_PROPERTIES && ctx->properties != NULL) {
        if (name && !strncmp(name, "_5_hwpsummaryinformation", 24)) {
            cli_dbgmsg("HWP5.x: Detected a '_5_hwpsummaryinformation' stream\n");
            /* JSONOLE2 - what to do if something breaks? */
            if (cli_ole2_summary_json(ctx, fd, 2) == CL_ETIMEOUT)
                return CL_ETIMEOUT;
        }
    }

#endif

    /* normal streams */
    return cli_magic_scandesc(fd, ctx);
}

/*** HWP3 ***/

/* all fields use little endian and unicode encoding, if appliable */

//File Identification Information - (30 total bytes)
#define HWP3_IDENTITY_INFO_SIZE 30

//Document Information - (128 total bytes)
#define HWP3_DOCINFO_SIZE 128

struct hwp3_docinfo {
#define DI_WRITEPROT   24  /* offset 24 (4 bytes) - write protection */
#define DI_EXTERNAPP   28  /* offset 28 (2 bytes) - external application */
#define DI_PASSWD      96  /* offset 96 (2 bytes) - password protected */
#define DI_COMPRESSED  124 /* offset 124 (1 byte) - compression */
#define DI_INFOBLKSIZE 126 /* offset 126 (2 bytes) - information block length */
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
#define HWP3_PARAINFO_SIZE_S 43
#define HWP3_PARAINFO_SIZE_L 230
struct hwp3_parainfo {
#define DI_PPFS      0
#define DI_CHARCOUNT 1
    uint8_t ppfs;        /* preceding paragraph font style - determines if 43 or 230 bytes; 0 => 43 bytes */
    uint16_t char_count; /* 0 => empty paragraph => end of paragraph list */
    /* other information - not interesting */
};

static inline int parsehwp3_docinfo(cli_ctx *ctx, off_t offset, struct hwp3_docinfo *docinfo)
{
    const uint8_t *hwp3_ptr;
#if HAVE_JSON
    json_object *header, *flags;
#endif

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
#endif

    return CL_SUCCESS;
}

static inline int parsehwp3_docsummary(cli_ctx *ctx, off_t offset)
{
#if HAVE_JSON
    const uint8_t *hwp3_ptr;
    char *str;
    int i, ret;
    json_object *summary;

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
        str = cli_utf16_to_utf8(hwp3_ptr+hwp3_docsummary_fields[i].offset, 112, UTF16_LE);
        if (!str) {
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

            str = (char *)cl_base64_encode(hwp3_ptr+hwp3_docsummary_fields[i].offset, 112);
        }
        if (!str) {
            cli_errmsg("HWP3.x: Failed to generate UTF-8 conversion of property string\n");
            return CL_EMEM;
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

/*
  InfoBlock(#1):
  Information Block ID        (16-bytes)
  Information Block Length(n) (16-bytes)
  Information Block Contents  (n-bytes)

  AdditionalInfoBlocks:
  Information Block ID        (32-bytes)
  Information Block Length(n) (32-bytes)
  Information Block Contents  (n-bytes)
*/

static inline int parsehwp3_infoblk_s(cli_ctx *ctx, fmap_t *dmap, off_t *offset, int *last)
{
    uint16_t infoid, infolen;
    fmap_t *map = (dmap ? dmap : *ctx->fmap);

    return CL_SUCCESS;
}

static inline int parsehwp3_infoblk_l(cli_ctx *ctx, fmap_t *dmap, off_t *offset, int *last)
{
    uint32_t infoid, infolen;
    fmap_t *map = (dmap ? dmap : *ctx->fmap);

    hwp3_debug("HWP3.x: Information Block @ offset %llu\n", (long long unsigned)(*offset));

    if (fmap_readn(map, &infoid, (*offset), sizeof(infoid)) != sizeof(infoid)) {
        cli_errmsg("HWP3.x: Failed to read infomation block id @ %llu\n",
                   (long long unsigned)(*offset));
        return CL_EREAD;
    }
    (*offset) += sizeof(infoid);

    if (fmap_readn(map, &infolen, (*offset), sizeof(infolen)) != sizeof(infolen)) {
        cli_errmsg("HWP3.x: Failed to read infomation block len @ %llu\n",
                   (long long unsigned)(*offset));
        return CL_EREAD;
    }
    (*offset) += sizeof(infolen);

    infoid = le32_to_host(infoid);
    infolen = le32_to_host(infolen);

    hwp3_debug("HWP3.x: Information Block[%llu]: ID:  %u\n", (long long unsigned)(*offset), infoid);
    hwp3_debug("HWP3.x: Information Block[%llu]: LEN: %u\n", (long long unsigned)(*offset), infolen);

    /* Possible Information Blocks */
    switch(infoid) {
    case 0:
        if (infolen == 0) {
            hwp3_debug("HWP3.x: Information Block[%llu]: TYPE: Terminating Entry\n",
                       (long long unsigned)(*offset));
            if (last) *last = 1;
            return CL_SUCCESS;
        } else {
            cli_errmsg("HWP3.x: Information Block[%llu]: TYPE: Invalid Terminating Entry\n", 
                       (long long unsigned)(*offset));
            return CL_EFORMAT;
        }
    case 1:
        hwp3_debug("HWP3.x: Information Block[%llu]: TYPE: Image Data\n", (long long unsigned)(*offset));
        (*offset) += (32 + infolen);
        /* TODO: scan image data */
        break;
    default:
        cli_errmsg("HWP3.x: Information Block[%llu]: TYPE: UNKNOWN\n", (long long unsigned)(*offset));
        return CL_EPARSE;
    }

    return CL_SUCCESS;
}

#define PARABUFFERLEN 1024
static int hwp3_cb(void *cbdata, int fd, cli_ctx *ctx)
{
    fmap_t *dmap;
    off_t offset = 0;
    int i, p = 0, last = 0, ret = CL_SUCCESS;
    uint16_t nstyles;
    const char *pbuf;
    struct hwp3_parainfo pinfo;
    size_t plen = 0, pstate = 0, pbuflen;

    if (fd < 0) {
        cli_errmsg("HWP3.x: Invalid file descriptor argument\n");
        return CL_ENULLARG;
    } else {
        STATBUF statbuf;

        if (FSTAT(fd, &statbuf) == -1) {
            cli_errmsg("HWP3.x: Can't stat file descriptor\n");
            return CL_ESTAT;
        }

        dmap = fmap(fd, 0, statbuf.st_size);
        if (!dmap) {
            cli_errmsg("HWP3.x: Failed to get fmap for uncompressed stream\n");
            return CL_EMAP;
        }
    }

    /* Fonts - 7 entries of 2 + (n x 40) bytes where n is the first 2 bytes of the entry */
    for (i = 0; i < 7; i++) {
        uint16_t nfonts;

        if (fmap_readn(dmap, &nfonts, offset, sizeof(nfonts)) != sizeof(nfonts)) {
            funmap(dmap);
            return CL_EREAD;
        }
        nfonts = le16_to_host(nfonts);

        hwp3_debug("HWP3.x: Font Entry %d with %u entries @ offset %llu\n", i+1, nfonts, (long long unsigned)offset);

        offset += (2 + nfonts * 40);
    }

    /* Styles - 2 + (n x 238) bytes where n is the first 2 bytes of the section */
    if (fmap_readn(dmap, &nstyles, offset, sizeof(nstyles)) != sizeof(nstyles)) {
        funmap(dmap);
        return CL_EREAD;
    }
    nstyles = le16_to_host(nstyles);

    hwp3_debug("HWP3.x: %u Styles @ offset %llu\n", nstyles, (long long unsigned)offset);

    offset += (2 + nstyles * 238);

    /* Paragraphs - variable */
    /* Paragraphs - are terminated with 0x0d00[13(CR) as hchar], empty paragraph marks end of section and do NOT end with 0x0d00 */
    do {
        hwp3_debug("HWP3.x: Paragraph %d start @ offset %llu\n", p, (long long unsigned)offset);

        if (fmap_readn(dmap, &(pinfo.ppfs), offset+DI_PPFS, sizeof(pinfo.ppfs)) != sizeof(pinfo.ppfs)) {
            funmap(dmap);
            return CL_EREAD;
        }

        if (fmap_readn(dmap, &(pinfo.char_count), offset+DI_CHARCOUNT, sizeof(pinfo.char_count)) != sizeof(pinfo.char_count)) {
            funmap(dmap);
            return CL_EREAD;
        }

        pinfo.char_count = le16_to_host(pinfo.char_count);

        hwp3_debug("HWP3.x: Paragraph %d: ppfs  %u\n", p, pinfo.ppfs);
        hwp3_debug("HWP3.x: Paragraph %d: chars %u\n", p++, pinfo.char_count);

        if (pinfo.ppfs)
            offset += HWP3_PARAINFO_SIZE_S;
        else
            offset += HWP3_PARAINFO_SIZE_L;

        /* detected empty paragraph marker => end-of-paragraph list */
        if (pinfo.char_count == 0) {
            hwp3_debug("HWP3.x: Detected end-of-paragraph list @ offset %llu\n", (long long unsigned)offset);
            break;
        }

        /* scan for end-of-paragraph [0x0d00 on an even offset] */
        pstate = 0;
        while ((pstate != 2) && (offset < dmap->len)) {
            pbuflen = MIN(dmap->len-offset, PARABUFFERLEN);
            if (!(pbuf = fmap_need_off_once(dmap, offset, pbuflen))) {
                cli_errmsg("HWP3.x: Failed to map buffer @ %llu\n", (long long unsigned)offset);
                return CL_EREAD;
            }

            for (i = 0; i < pbuflen; i++) {
                if ((pbuf[i] == 0x0d) && (((offset+i) % 2) == 0)) {
                    pstate = 1;
                } else if (pstate && pbuf[i] == 0x00) {
                    pstate = 2;
                    i++;
                    break;
                } else {
                    pstate = 0;
                }
            }

            offset += i;
        }
    } while (offset < dmap->len);

    /* Additional Information Block (Internal) - Attachments and Media */
    while (!last && ((ret = parsehwp3_infoblk_l(ctx, dmap, &offset, &last)) == CL_SUCCESS));

    /* scan the uncompressed stream? */
    //ret = cli_map_scandesc(dmap, 0, 0, ctx, CL_TYPE_ANY);

    funmap(dmap);
    return ret;
}

int cli_scanhwp3(cli_ctx *ctx)
{
    struct hwp3_docinfo docinfo;
    int ret = CL_SUCCESS;
    off_t offset = 0;

#if HAVE_JSON
    /*
    /* magic *
    cli_jsonstr(header, "Magic", hwp5->signature);

    /* version *
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

    /* TODO: HANDLE OPTIONAL INFORMATION BLOCKS HERE */
    /*
    if (docinfo.di_infoblksize) {
        if ((ret = parsehwp3_infoblk(ctx, offset)) != CL_SUCCESS)
            return ret;
        /* increment offset? /
    }
    */

    /* TODO: uncompressed segment handler */
    if (docinfo.di_compressed)
        ret = decompress_and_callback(ctx, *ctx->fmap, offset, 0, "HWP3.x", hwp3_cb, NULL);

    if (ret != CL_SUCCESS)
        return ret;

    /* TODO: HANDLE OPTIONAL ADDITIONAL INFORMATION BLOCKS */

    return ret;
}

/*** HWPML (hijacking the msxml parser) ***/

static const struct key_entry hwpml_keys[] = {
    { "hwpml",              "HWPML",              MSXML_JSON_ROOT | MSXML_JSON_ATTRIB },

    /* HEAD - Document Properties */
    { "head",               "Head",               MSXML_JSON_WRKPTR },
    { "docsummary",         "DocumentProperties", MSXML_JSON_WRKPTR },
    { "title",              "Title",              MSXML_JSON_WRKPTR | MSXML_JSON_VALUE },
    { "author",             "Author",             MSXML_JSON_WRKPTR | MSXML_JSON_VALUE },
    { "date",               "Date",               MSXML_JSON_WRKPTR | MSXML_JSON_VALUE },
    { "docsetting",         "DocumentSettings",   MSXML_JSON_WRKPTR },
    { "beginnumber",        "BeginNumber",        MSXML_JSON_WRKPTR | MSXML_JSON_ATTRIB },
    { "caretpos",           "CaretPos",           MSXML_JSON_WRKPTR | MSXML_JSON_ATTRIB },
    { "bindatalist",        "BinDataList",        MSXML_JSON_WRKPTR },
    { "binitem",            "BinItem",            MSXML_JSON_WRKPTR | MSXML_JSON_ATTRIB },
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
    { "tail",               "Tail",               MSXML_JSON_WRKPTR },
    { "bindatastorage",     "BinaryDataStorage",  MSXML_JSON_WRKPTR },
    { "bindata",            "BinaryData",         MSXML_SCAN_CB | MSXML_JSON_WRKPTR | MSXML_JSON_ATTRIB },
    { "scriptcode",         "ScriptCodeStorage",  MSXML_JSON_WRKPTR | MSXML_JSON_ATTRIB },
    { "scriptheader",       "ScriptHeader",       MSXML_SCAN_CB | MSXML_JSON_WRKPTR | MSXML_JSON_VALUE },
    { "scriptsource",       "ScriptSource",       MSXML_SCAN_CB | MSXML_JSON_WRKPTR | MSXML_JSON_VALUE }
};
static size_t num_hwpml_keys = sizeof(hwpml_keys) / sizeof(struct key_entry);

/* binary streams needs to be base64-decoded then decompressed if fields are set */
static int hwpml_scan_cb(void *cbdata, int fd, cli_ctx *ctx)
{
    return cli_magic_scandesc(fd, ctx);
}

static int hwpml_binary_cb(int fd, cli_ctx *ctx, int num_attribs, struct attrib_entry *attribs)
{
    int i, ret, df = 0, com = 0, enc = 0;
    char name[1024], *tempfile = name;

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
        return cli_magic_scandesc(fd, ctx);
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

        decoded = (char *)cl_base64_decode(instream, input->len, NULL, &decodedlen, 0);
        funmap(input);
        if (!decoded) {
            cli_errmsg("HWPML: Failed to get base64 decode binary data\n");
            return cli_magic_scandesc(fd, ctx);
        }

        /* open file for writing and scanning */
        if ((ret = cli_gentempfd(ctx->engine->tmpdir, &tempfile, &df)) != CL_SUCCESS) {
            cli_warnmsg("HWPML: Failed to create temporary file %s\n", tempfile);
            return ret;
        }

        if(cli_writen(df, decoded, decodedlen) != (int)decodedlen) {
            free(decoded);
            close(df);
            return CL_EWRITE;
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
            return CL_ESTAT;
        }

        input = fmap(fd, 0, statbuf.st_size);
        if (!input) {
            cli_errmsg("HWPML: Failed to get fmap for binary data\n");
            return CL_EMAP;
        }
        ret = decompress_and_callback(ctx, input, 0, 0, "HWPML", hwpml_scan_cb, NULL);
        funmap(input);
    } else {
        ret = hwpml_scan_cb(NULL, fd, ctx);
    }

    /* close decoded file descriptor if used */
    if (df) {
        close(df);
        if (!(ctx->engine->keeptmp))
            cli_unlink(tempfile);
    }
    return ret;
}

int cli_scanhwpml(cli_ctx *ctx)
{
#if HAVE_LIBXML2
    struct msxml_cbdata cbdata;
    xmlTextReaderPtr reader = NULL;
    int state, ret = CL_SUCCESS;

    cli_dbgmsg("in cli_scanhwpml()\n");

    if (!ctx)
        return CL_ENULLARG;

    memset(&cbdata, 0, sizeof(cbdata));
    cbdata.map = *ctx->fmap;

    reader = xmlReaderForIO(msxml_read_cb, NULL, &cbdata, "hwpml.xml", NULL, CLAMAV_MIN_XMLREADER_FLAGS);
    if (!reader) {
        cli_dbgmsg("cli_scanhwpml: cannot intialize xmlReader\n");

#if HAVE_JSON
        ret = cli_json_parse_error(ctx->wrkproperty, "HWPML_ERROR_XML_READER_IO");
#endif
        return ret; // libxml2 failed!
    }

    ret = cli_msxml_parse_document(ctx, reader, hwpml_keys, num_hwpml_keys, 1, hwpml_binary_cb);

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

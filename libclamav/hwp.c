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

#if HAVE_ICONV
#include <iconv.h>
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
#include "json_api.h"
#include "hwp.h"
#if HAVE_JSON
#include "msdoc.h"
#endif

#define HWP5_DEBUG 0
#define HWP3_DEBUG 1
#if HWP3_DEBUG
#define hwp3_debug(...) cli_dbgmsg(__VA_ARGS__)
#else
#define hwp3_debug(...) ;
#endif

static int decompress_and_scan(int fd, cli_ctx *ctx, int ole2)
{
    int zret, ofd, ret = CL_SUCCESS;
    fmap_t *input;
    off_t off_in = 0;
    size_t count, outsize = 0;
#ifndef HACKNSLASH
    size_t expect = 0;
#endif
    z_stream zstrm;
    char *tmpname;
    unsigned char inbuf[FILEBUFF], outbuf[FILEBUFF];

    /* fmap the input file for easier manipulation */
    if (fd < 0) {
        cli_dbgmsg("HWP5.x: Invalid file descriptor argument\n");
        return CL_ENULLARG;
    } else {
        STATBUF statbuf;

        if (FSTAT(fd, &statbuf) == -1) {
            cli_dbgmsg("HWP5.x: Can't stat file descriptor\n");
            return CL_ESTAT;
        }

        input = fmap(fd, 0, statbuf.st_size);
        if (!input) {
            cli_dbgmsg("HWP5.x: Failed to get fmap for input stream\n");
            return CL_EMAP;
        }
    }

    /* reserve tempfile for output and scanning */
    if ((ret = cli_gentempfd(ctx->engine->tmpdir, &tmpname, &ofd)) != CL_SUCCESS) {
        cli_errmsg("HWP5.x: Can't generate temporary file\n");
        funmap(input);
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
        cli_dbgmsg("HWP5.x: Can't initialize zlib inflation stream\n");
        ret = CL_EUNPACK;
        goto ds_end;
    }

    /* inflation loop */
    do {
        if (zstrm.avail_in == 0) {
            zstrm.next_in = inbuf;
            ret = fmap_readn(input, inbuf, off_in, FILEBUFF);
            if (ret < 0) {
                cli_errmsg("HWP5.x: Error reading stream\n");
                ret = CL_EUNPACK;
                goto ds_end;
            }
            if (!ret)
                break;

            zstrm.avail_in = ret;
            off_in += ret;
        }
        zret = inflate(&zstrm, Z_SYNC_FLUSH);
        count = FILEBUFF - zstrm.avail_out;
        if (count) {
            if (cli_checklimits("HWP", ctx, outsize + count, 0, 0) != CL_SUCCESS)
                break;

#ifndef HACKNSLASH
            /* remove decompressed size uint32_t prefix */
            if (ole2) {
                ole2 = 0;
                expect = outbuf[0] + (outbuf[1] << 8) + (outbuf[2] << 16) + (outbuf[3] << 24);

                cli_dbgmsg("HWP5.x: Trimmed OLE2 stream prefix: %08x\n", expect);

                if (cli_writen(ofd, outbuf+4, count-4) != count-4) {
                    cli_errmsg("HWP5.x: Can't write to file %s\n", tmpname);
                    ret = CL_EWRITE;
                    goto ds_end;
                }
                outsize += (count-4);
            } else {
#endif
            if (cli_writen(ofd, outbuf, count) != count) {
                cli_errmsg("HWP5.x: Can't write to file %s\n", tmpname);
                ret = CL_EWRITE;
                goto ds_end;
            }
            outsize += count;
#ifndef HACKNSLASH
            }
#endif
        }
        zstrm.next_out = outbuf;
        zstrm.avail_out = FILEBUFF;
    } while(zret == Z_OK);

    /* post inflation checks */
    if (zret != Z_STREAM_END && zret != Z_OK) {
        if (outsize == 0) {
            cli_infomsg(ctx, "HWP5.x: Error decompressing stream. No data decompressed.\n");
            ret = CL_EUNPACK;
            goto ds_end;
        }

        cli_infomsg(ctx, "HWP5.x: Error decompressing stream. Scanning what was decompressed.\n");
    }
    cli_dbgmsg("HWP5.x: Decompressed %llu bytes to %s\n", (long long unsigned)outsize, tmpname);

#ifndef HACKNSLASH
    if (expect) {
        if (outsize != expect) {
            cli_warnmsg("HWP5.x: declared prefix != inflated stream size, %llu != %llu\n",
                        (long long unsigned)expect, (long long unsigned)outsize);
        } else {
            cli_dbgmsg("HWP5.x: declared prefix == inflated stream size, %llu == %llu\n",
                       (long long unsigned)expect, (long long unsigned)outsize);
        }
    }
#endif

    /* scanning inflated stream */
    ret = cli_magic_scandesc(ofd, ctx);

    /* clean-up */
 ds_end:
    zret = inflateEnd(&zstrm);
    if (zret != Z_OK)
        ret = CL_EUNPACK;
    close(ofd);
    if (!ctx->engine->keeptmp)
        if (cli_unlink(tmpname))
            ret = CL_EUNLINK;
    free(tmpname);
    funmap(input);
    return ret;
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

int cli_scanhwp5_stream(cli_ctx *ctx, hwp5_header_t *hwp5, char *name, int fd)
{
    int ole2;

    cli_dbgmsg("HWP5.x: NAME: %s\n", name);

    /* encrypted and compressed streams */
    if (!strncmp(name, "bin", 3) || !strncmp(name, "jscriptversion", 14) ||
        !strncmp(name, "defaultjscript", 14) || !strncmp(name, "section", 7) ||
        !strncmp(name, "viewtext", 8) || !strncmp(name, "docinfo", 7)) {

        ole2 = 0;
        if (strstr(name, ".ole")) {
            cli_dbgmsg("HWP5.x: Detected embedded OLE2 stream\n");
            ole2 = 1;
        }

        if (hwp5->flags & HWP5_PASSWORD) {
            cli_dbgmsg("HWP5.x: Password encrypted stream, scanning as-is\n");
            return cli_magic_scandesc(fd, ctx);
        }

        if (hwp5->flags & HWP5_COMPRESSED) {
            /* DocInfo JSON Handling */
            cli_dbgmsg("HWP5.x: Sending %s for decompress and scan\n", name);
            return decompress_and_scan(fd, ctx, ole2);
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

static inline int parsehwp3_docinfo(cli_ctx *ctx, struct hwp3_docinfo *docinfo)
{
    const uint8_t *hwp3_ptr;
#if HAVE_JSON
    json_object *header, *flags;
#endif

    //TODO: use fmap_readn?
    if (!(hwp3_ptr = fmap_need_off_once(*ctx->fmap, HWP3_IDENTITY_INFO_SIZE, HWP3_DOCINFO_SIZE))) {
        cli_dbgmsg("HWP3.x: Failed to read fmap for hwp docinfo\n");
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

static inline int parsehwp3_docsummary(cli_ctx *ctx)
{
#if HAVE_JSON
    const uint8_t *hwp3_ptr;
    char *str;
    int i, ret;
    json_object *summary;

    if (!(hwp3_ptr = fmap_need_off_once(*ctx->fmap, HWP3_IDENTITY_INFO_SIZE+HWP3_DOCINFO_SIZE, HWP3_DOCSUMMARY_SIZE))) {
        cli_dbgmsg("HWP3.x: Failed to read fmap for hwp docinfo\n");
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
#endif
    return CL_SUCCESS;
}

int cli_scanhwp3(cli_ctx *ctx)
{
    struct hwp3_docinfo docinfo;
    int ret = CL_SUCCESS;

    /*
    /* magic *
    cli_jsonstr(header, "Magic", hwp5->signature);

    /* version *
    cli_jsonint(header, "RawVersion", hwp5->version);

    /* no raw flags, would be a struct *
    */

    if ((ret = parsehwp3_docinfo(ctx, &docinfo)) != CL_SUCCESS)
        return ret;

    if ((ret = parsehwp3_docsummary(ctx)) != CL_SUCCESS)
        return ret;

    /*
    uint32_t write_protect;
    uint16_t external, pass_protect, info_length;
    uint8_t compression;

    write_protect = le32_to_host(write_protect);
    external = le16_to_host(external);
    pass_protect = le16_to_host(pass_protect);
    info_length = le16_to_host(info_length);
    */

    return ret;
}

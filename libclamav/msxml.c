/*
 * Extract component parts of MS XML files (e.g. MS Office 2003 XML Documents)
 * 
 * Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 * Copyright (C) 2007-2013 Sourcefire, Inc.
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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "clamav.h"
#include "others.h"
#include "conv.h"
#include "json_api.h"
#include "msxml.h"
#include "msxml_parser.h"

#if HAVE_LIBXML2
#include <libxml/xmlreader.h>

#define MSXML_VERBIOSE 0
#if MSXML_VERBIOSE
#define cli_msxmlmsg(...) cli_dbgmsg(__VA_ARGS__)
#else
#define cli_msxmlmsg(...)
#endif

#define MSXML_READBUFF SCANBUFF

static const struct key_entry msxml_keys[] = {
    { "worddocument",       "WordDocument",       MSXML_JSON_ROOT | MSXML_JSON_ATTRIB },
    { "workbook",           "Workbook",           MSXML_JSON_ROOT | MSXML_JSON_ATTRIB },

    { "bindata",            "BinaryData",         MSXML_SCAN_B64 | MSXML_JSON_COUNT | MSXML_JSON_ROOT },
    { "documentproperties", "DocumentProperties", MSXML_JSON_ROOT },
    { "author",             "Author",             MSXML_JSON_WRKPTR | MSXML_JSON_VALUE },
    { "lastauthor",         "LastAuthor",         MSXML_JSON_WRKPTR | MSXML_JSON_VALUE },
    { "revision",           "Revision",           MSXML_JSON_WRKPTR | MSXML_JSON_VALUE },
    { "totaltime",          "TotalTime",          MSXML_JSON_WRKPTR | MSXML_JSON_VALUE },
    { "created",            "Created",            MSXML_JSON_WRKPTR | MSXML_JSON_VALUE },
    { "lastsaved",          "LastSaved",          MSXML_JSON_WRKPTR | MSXML_JSON_VALUE },
    { "pages",              "Pages",              MSXML_JSON_WRKPTR | MSXML_JSON_VALUE },
    { "words",              "Words",              MSXML_JSON_WRKPTR | MSXML_JSON_VALUE },
    { "characters",         "Characters",         MSXML_JSON_WRKPTR | MSXML_JSON_VALUE },
    { "lines",              "Lines",              MSXML_JSON_WRKPTR | MSXML_JSON_VALUE },
    { "paragraph",          "Paragraph",          MSXML_JSON_WRKPTR | MSXML_JSON_VALUE },
    { "characterswithspaces", "CharactersWithSpaces", MSXML_JSON_WRKPTR | MSXML_JSON_VALUE },
    { "version",            "Version",            MSXML_JSON_WRKPTR | MSXML_JSON_VALUE },

    { "allowpng",           "AllowPNG",           MSXML_JSON_WRKPTR | MSXML_JSON_VALUE },

    { "fonts",              "Fonts",              MSXML_IGNORE_ELEM },
    { "styles",             "Styles",             MSXML_IGNORE_ELEM }
};
static size_t num_msxml_keys = sizeof(msxml_keys) / sizeof(struct key_entry);

static inline size_t msxml_read_cb_new_window(struct msxml_cbdata *cbdata)
{
    const unsigned char *new_window = NULL;
    off_t new_mappos;
    size_t bytes;

    if (cbdata->mappos == cbdata->map->len) {
        cli_msxmlmsg("msxml_read_cb: fmap REALLY EOF\n");
        return 0;
    }

    new_mappos = cbdata->mappos + cbdata->winsize;
    bytes = MIN(cbdata->map->len - new_mappos, MSXML_READBUFF);
    if (!bytes) {
        cbdata->window = NULL;
        cbdata->winpos = 0;
        cbdata->mappos = cbdata->map->len;
        cbdata->winsize = 0;

        cli_msxmlmsg("msxml_read_cb: fmap EOF\n");
        return 0;
    }

    new_window = fmap_need_off_once(cbdata->map, new_mappos, bytes);
    if (!new_window) {
        cli_errmsg("msxml_read_cb: cannot acquire new window for fmap\n");
        return -1;
    }

    cbdata->window = new_window;
    cbdata->winpos = 0;
    cbdata->mappos = new_mappos;
    cbdata->winsize = bytes;

    cli_msxmlmsg("msxml_read_cb: acquired new window @ [%llu(+%llu)(max:%llu)]\n",
                 (long long unsigned)cbdata->mappos, (long long unsigned)(cbdata->mappos + cbdata->winsize),
                 (long long unsigned)cbdata->map->len);

    return bytes;
}

int msxml_read_cb(void *ctx, char *buffer, int len)
{
    struct msxml_cbdata *cbdata = (struct msxml_cbdata *)ctx;
    size_t wbytes, rbytes;
    int winret;

    cli_msxmlmsg("msxml_read_cb called\n");

    /* initial iteration */
    if (!cbdata->window) {
        if ((winret = msxml_read_cb_new_window(cbdata)) <= 0)
            return winret;
    }

    cli_msxmlmsg("msxml_read_cb: requested %d bytes from offset %llu\n", len, (long long unsigned)(cbdata->mappos+cbdata->winpos));

    wbytes = 0;
    rbytes = cbdata->winsize - cbdata->winpos;

    /* copying loop with preprocessing */
    while (wbytes < len) {
        const unsigned char *read_from;
        char *write_to = buffer + wbytes;
        enum msxml_state *state;
#if MSXML_VERBIOSE
        size_t written;
#endif

        if (!rbytes) {
            if ((winret = msxml_read_cb_new_window(cbdata)) < 0)
                return winret;
            if (winret == 0) {
                cli_msxmlmsg("msxml_read_cb: propagating fmap EOF [%llu]\n", (long long unsigned)wbytes);
                return (int)wbytes;
            }

            rbytes = cbdata->winsize;
        }

#if MSXML_VERBIOSE
        written = MIN(rbytes, len - wbytes);
        cli_msxmlmsg("msxml_read_cb: copying from window [%llu(+%llu)] %llu->~%llu\n",
                     (long long unsigned)(cbdata->winsize - rbytes), (long long unsigned)cbdata->winsize,
                     (long long unsigned)cbdata->winpos, (long long unsigned)(cbdata->winpos + written));
#endif

        read_from = cbdata->window + cbdata->winpos;
        state = &(cbdata->state);

        while (rbytes > 0 && wbytes < len) {
            switch (*state) {
            case MSXML_STATE_NORMAL:
                if ((*read_from) == '&')
                    *state = MSXML_STATE_ENTITY_START_1;
                break;
            case MSXML_STATE_ENTITY_START_1:
                if ((*read_from) == '#')
                    *state = MSXML_STATE_ENTITY_START_2;
                else
                    *state = MSXML_STATE_NORMAL;
                break;
            case MSXML_STATE_ENTITY_START_2:
                if ((*read_from) == 'x')
                    *state = MSXML_STATE_ENTITY_HEX;
                else if (((*read_from) >= '0') && ((*read_from) <= '9'))
                    *state = MSXML_STATE_ENTITY_DEC;
                else
                    *state = MSXML_STATE_NORMAL;
                break;
            case MSXML_STATE_ENTITY_HEX:
                if ((((*read_from) >= '0') && ((*read_from) <= '9')) ||
                    (((*read_from) >= 'a') && ((*read_from) <= 'f')) ||
                    (((*read_from) >= 'A') && ((*read_from) <= 'F'))) {}
                else
                    *state = MSXML_STATE_ENTITY_CLOSE;
                break;
            case MSXML_STATE_ENTITY_DEC:
                if (((*read_from) >= '0') && ((*read_from) <= '9')) {}
                else
                    *state = MSXML_STATE_ENTITY_CLOSE;
                break;
            default:
                cli_errmsg("unknown *state: %d\n", *state);
            }

            if (*state == MSXML_STATE_ENTITY_CLOSE) {
                if ((*read_from) != ';') {
                    cli_msxmlmsg("msxml_read_cb: detected unterminated character entity @ winoff %d\n",
                                 (int)(read_from - cbdata->window));
                    (*write_to++) = ';';
                    wbytes++;
                }
                *state = MSXML_STATE_NORMAL;
                if (wbytes >= len)
                    break;
            }

            *(write_to++) = *(read_from++);
            rbytes--;
            wbytes++;
        }
    }

    cbdata->winpos = cbdata->winsize - rbytes;
    return (int)wbytes;
}
#endif

int cli_scanmsxml(cli_ctx *ctx)
{
#if HAVE_LIBXML2
    struct msxml_cbdata cbdata;
    xmlTextReaderPtr reader = NULL;
    int state, ret = CL_SUCCESS;

    cli_dbgmsg("in cli_scanmsxml()\n");

    if (!ctx)
        return CL_ENULLARG;

    memset(&cbdata, 0, sizeof(cbdata));
    cbdata.map = *ctx->fmap;

    reader = xmlReaderForIO(msxml_read_cb, NULL, &cbdata, "msxml.xml", NULL, CLAMAV_MIN_XMLREADER_FLAGS);
    if (!reader) {
        cli_dbgmsg("cli_scanmsxml: cannot initialize xmlReader\n");

#if HAVE_JSON
        ret = cli_json_parse_error(ctx->wrkproperty, "OOXML_ERROR_XML_READER_IO");
#endif
        return ret; // libxml2 failed!
    }

    ret = cli_msxml_parse_document(ctx, reader, msxml_keys, num_msxml_keys, 1, NULL);

    xmlTextReaderClose(reader);
    xmlFreeTextReader(reader);
    return ret;
#else
    UNUSEDPARAM(ctx);
    cli_dbgmsg("in cli_scanmsxml()\n");
    cli_dbgmsg("cli_scanmsxml: scanning msxml documents requires libxml2!\n");

    return CL_SUCCESS;
#endif
}

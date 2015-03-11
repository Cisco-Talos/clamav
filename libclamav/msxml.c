/*
 * Extract component parts of MS XML files (e.g. MS Office 2003 XML Documents)
 * 
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

#include "clamav.h"
#include "others.h"
#include "json_api.h"
#include "msxml.h"

#if HAVE_LIBXML2
#ifdef _WIN32
#ifndef LIBXML_WRITER_ENABLED
#define LIBXML_WRITER_ENABLED 1
#endif
#endif
#include <libxml/xmlreader.h>
#endif

#define MSXML_READBUFF SCANBUFF

#define check_state(state)                                              \
    do {                                                                \
        if (state == -1) {                                              \
            cli_warnmsg("check_state[msxml]: CL_EPARSE @ ln%d\n", __LINE__); \
            return CL_EPARSE;                                           \
        }                                                               \
        else if (state == 0) {                                          \
            cli_dbgmsg("check_state[msxml]: CL_BREAK @ ln%d\n", __LINE__); \
            return CL_BREAK;                                            \
        }                                                               \
    } while(0)


struct msxml_cbdata {
    fmap_t *map;
    const unsigned char *window;
    off_t winpos, mappos;
    size_t winsize;
};

inline size_t msxml_read_cb_new_window(struct msxml_cbdata *cbdata)
{
    const unsigned char *new_window = NULL;
    off_t new_mappos;
    size_t bytes;

    if (cbdata->mappos == cbdata->map->len) {
        cli_dbgmsg("msxml_read_cb: fmap REALLY EOF\n");
        return 0;
    }

    new_mappos = cbdata->mappos + cbdata->winsize;
    bytes = MIN(cbdata->map->len - new_mappos, MSXML_READBUFF);
    if (!bytes) {
        cbdata->window = NULL;
        cbdata->winpos = 0;
        cbdata->mappos = cbdata->map->len;
        cbdata->winsize = 0;

        cli_dbgmsg("msxml_read_cb: fmap EOF\n");
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

    cli_dbgmsg("msxml_read_cb: acquired new window @ [%llu(+%llu)(max:%llu)]\n",
               (long long unsigned)cbdata->mappos, (long long unsigned)(cbdata->mappos + cbdata->winsize),
               (long long unsigned)cbdata->map->len);

    return bytes;
}

int msxml_read_cb(void *ctx, char *buffer, int len)
{
    struct msxml_cbdata *cbdata = (struct msxml_cbdata *)ctx;
    size_t wbytes, rbytes, winret;

    cli_dbgmsg("msxml_read_cb called\n");

    /* initial iteration */
    if (!cbdata->window) {
        if ((winret = msxml_read_cb_new_window(cbdata)) <= 0)
            return winret;
    }

    cli_dbgmsg("msxml_read_cb: requested %d bytes from offset %llu\n", len, (long long unsigned)(cbdata->mappos+cbdata->winpos));

    wbytes = 0;
    rbytes = cbdata->winsize - cbdata->winpos;

    while (wbytes < len) {
        size_t written = MIN(rbytes, len);

        if (!rbytes) {
            if ((winret = msxml_read_cb_new_window(cbdata)) < 0)
                return winret;
            if (winret == 0) {
                cli_dbgmsg("msxml_read_cb: propagating fmap EOF [%llu]\n", (long long unsigned)wbytes);
                return (int)wbytes;
            }

            rbytes = cbdata->winsize;
        }

        written = MIN(rbytes, len - wbytes);

        cli_dbgmsg("msxml_read_cb: copying from window [%llu(+%llu)] %llu->%llu\n",
                   (long long unsigned)(cbdata->winsize - rbytes), (long long unsigned)cbdata->winsize,
                   (long long unsigned)cbdata->winpos, (long long unsigned)(cbdata->winpos + written));

        memcpy(buffer + wbytes, cbdata->window + cbdata->winpos, written);

        wbytes += written;
        rbytes -= written;
    }

    cbdata->winpos = cbdata->winsize - rbytes;
    return (int)wbytes;
}

int cli_scanmsxml(cli_ctx *ctx)
{
#if HAVE_LIBXML2
    struct msxml_cbdata cbdata;
    xmlTextReaderPtr reader = NULL;
    const xmlChar *node_name = NULL, *node_value = NULL;
    int state, ret = CL_SUCCESS;

    cli_dbgmsg("in cli_scanmsxml()\n");

    if (!ctx)
        return CL_ENULLARG;

    memset(&cbdata, 0, sizeof(cbdata));
    cbdata.map = *ctx->fmap;

    reader = xmlReaderForIO(msxml_read_cb, NULL, &cbdata, "msxml.xml", NULL, CLAMAV_MIN_XMLREADER_FLAGS);
    if (!reader) {
        cli_dbgmsg("cli_scanmsxml: cannot intialize xmlReader\n");
        return CL_SUCCESS; // libxml2 failed!
    }

    /* Main Processing Loop */
    while ((state = xmlTextReaderRead(reader)) == 1) {

    }

    return ret;
#else
    UNUSEDPARAM(ctx);
    cli_dbgmsg("in cli_scanmsxml()\n");
    cli_dbgmsg("cli_scanmsxml: libxml2 needs to enabled!");

    return CL_SUCCESS;
#endif
}

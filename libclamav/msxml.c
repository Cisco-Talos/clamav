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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "clamav.h"
#include "others.h"
#include "conv.h"
#include "json_api.h"
#include "msxml.h"

#if HAVE_LIBXML2
#ifdef _WIN32
#ifndef LIBXML_WRITER_ENABLED
#define LIBXML_WRITER_ENABLED 1
#endif
#endif
#include <libxml/xmlreader.h>

#define MSXML_VERBIOSE 1
#if MSXML_VERBIOSE
#define cli_msxmlmsg(...) cli_dbgmsg(__VA_ARGS__)
#else
#define cli_msxmlmsg(...)
#endif

#define MSXML_RECLEVEL 16
#define MSXML_RECLEVEL_MAX 5
#define MSXML_JSON_STRLEN_MAX 100

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
    size_t wbytes, rbytes, winret;

    cli_msxmlmsg("msxml_read_cb called\n");

    /* initial iteration */
    if (!cbdata->window) {
        if ((winret = msxml_read_cb_new_window(cbdata)) <= 0)
            return winret;
    }

    cli_msxmlmsg("msxml_read_cb: requested %d bytes from offset %llu\n", len, (long long unsigned)(cbdata->mappos+cbdata->winpos));

    wbytes = 0;
    rbytes = cbdata->winsize - cbdata->winpos;

    while (wbytes < len) {
        size_t written = MIN(rbytes, len);

        if (!rbytes) {
            if ((winret = msxml_read_cb_new_window(cbdata)) < 0)
                return winret;
            if (winret == 0) {
                cli_msxmlmsg("msxml_read_cb: propagating fmap EOF [%llu]\n", (long long unsigned)wbytes);
                return (int)wbytes;
            }

            rbytes = cbdata->winsize;
        }

        written = MIN(rbytes, len - wbytes);

        cli_msxmlmsg("msxml_read_cb: copying from window [%llu(+%llu)] %llu->%llu\n",
                     (long long unsigned)(cbdata->winsize - rbytes), (long long unsigned)cbdata->winsize,
                     (long long unsigned)cbdata->winpos, (long long unsigned)(cbdata->winpos + written));

        memcpy(buffer + wbytes, cbdata->window + cbdata->winpos, written);

        wbytes += written;
        rbytes -= written;
    }

    cbdata->winpos = cbdata->winsize - rbytes;
    return (int)wbytes;
}

static int msxml_parse_element(cli_ctx *ctx, xmlTextReaderPtr reader, int rlvl)
{
    const xmlChar *element_name = NULL;
    const xmlChar *node_name = NULL, *node_value = NULL;
    int ret, state, node_type, endtag = 0;

    cli_dbgmsg("in msxml_parse_element @ layer %d\n", rlvl);

    /* check recursion level */
    if (rlvl >= MSXML_RECLEVEL_MAX) {
        cli_dbgmsg("msxml_parse_element: reached msxml json recursion limit\n");
        //cli_jsonbool(root, "HitRecursiveLimit", 1);
        /* skip it */
        state = xmlTextReaderNext(reader);
        check_state(state);
        return CL_SUCCESS;
    }

    /* acquire element type */
    node_type = xmlTextReaderNodeType(reader);
    if (node_type == -1)
        return CL_EPARSE;

    node_name = xmlTextReaderConstLocalName(reader);
    node_value = xmlTextReaderConstValue(reader);

    /* branch on node type */
    switch (node_type) {
    case XML_READER_TYPE_ELEMENT:
        cli_dbgmsg("msxml_parse_element: ELEMENT %s [%d]: %s\n", node_name, node_type, node_value);

        /* storing the element name for verification/collection */
        element_name = xmlTextReaderConstLocalName(reader);
        if (!node_name) {
            cli_dbgmsg("msxml_parse_element: element tag node nameless\n");
            return CL_EPARSE; /* no name, nameless */
        }

        /* handle attributes */
        state = xmlTextReaderHasAttributes(reader);
        if (state == 1) {
            while (xmlTextReaderMoveToNextAttribute(reader) == 1) {
                const xmlChar *name, *value;
                name = xmlTextReaderConstLocalName(reader);
                value = xmlTextReaderConstValue(reader);

                cli_dbgmsg("\t%s: %s\n", name, value);
            }
        }
        else if (state == -1)
            return CL_EPARSE;

        /* check self-containment */
        state = xmlTextReaderMoveToElement(reader);
        check_state(state);

        state = xmlTextReaderIsEmptyElement(reader);
        if (state == 1) {
            cli_dbgmsg("msxml_parse_element: SELF-CLOSING\n");

            state = xmlTextReaderNext(reader);
            check_state(state);
            return CL_SUCCESS;
        } else if (state == -1)
            return CL_EPARSE;

        /* advance to first content node */
        state = xmlTextReaderRead(reader);
        check_state(state);

        while (!endtag) {
            node_type = xmlTextReaderNodeType(reader);
            if (node_type == -1)
                return CL_EPARSE;

            switch (node_type) {
            case XML_READER_TYPE_ELEMENT:
                ret = msxml_parse_element(ctx, reader, rlvl+1);
                if (ret != CL_SUCCESS) {
                    return ret;
                }
                break;

            case XML_READER_TYPE_TEXT:
                node_value = xmlTextReaderConstValue(reader);

                cli_dbgmsg("TEXT: %s\n", node_value);

                if (!strncmp(element_name, "binData", strlen(element_name))) {
                    char name[1024];
                    char *decoded, *tempfile = name;
                    size_t decodedlen;
                    int of;

                    cli_dbgmsg("BINARY DATA!\n");

                    decoded = cl_base64_decode((char *)node_value, strlen((const char *)node_value), NULL, &decodedlen, 0);
                    if (!decoded) {
                        cli_dbgmsg("msxml_parse_element: failed to decode base64-encoded binary data\n");
                        state = xmlTextReaderRead(reader);
                        check_state(state);
                        break;
                    }

                    if(!(tempfile = cli_gentemp(ctx->engine->tmpdir))) {
                        free(decoded);
                        return CL_EMEM;
                    }

                    if((of = open(tempfile, O_RDWR|O_CREAT|O_TRUNC|O_BINARY, S_IRUSR|S_IWUSR))==-1) {
                        cli_warnmsg("msxml_parse_element: failed to create temporary file %s\n", tempfile);
                        free(decoded);
                        return CL_ECREAT;
                    }

                    if(cli_writen(of, decoded, decodedlen) != (int)decodedlen) {
                        free(decoded);
                        close(of);
                        return CL_EWRITE;
                    }
                    free(decoded);

                    cli_dbgmsg("msxml_parse_element: extracted binary data to %s\n", tempfile);

                    ret = cli_magic_scandesc(of, ctx);
                    close(of);
                    if (ret != CL_SUCCESS || (!SCAN_ALL && ret == CL_VIRUS)) {
                        return ret;
                    }

                    /*
                    ret = cli_mem_scandesc(decoded, decodedlen, ctx);
                    free(decoded);
                    if (ret != CL_SUCCESS) {
                        return ret;
                        }*/
                }

                /*
                  ret = ooxml_parse_value(thisjobj, "Value", node_value);
                  if (ret != CL_SUCCESS)
                  return ret;

                  cli_dbgmsg("ooxml_parse_element: added json value [%s: %s]\n", element_tag, node_value);
                */

                /* advance to next node */
                state = xmlTextReaderRead(reader);
                check_state(state);
                break;

            case XML_READER_TYPE_END_ELEMENT:
                cli_dbgmsg("in msxml_parse_element @ layer %d closed\n", rlvl);
                node_name = xmlTextReaderConstLocalName(reader);
                if (!node_name) {
                    cli_dbgmsg("msxml_parse_element: element end tag node nameless\n");
                    return CL_EPARSE; /* no name, nameless */
                }

                if (strncmp(element_name, node_name, strlen(element_name))) {
                    cli_dbgmsg("msxml_parse_element: element tag does not match end tag %s != %s\n", element_name, node_name);
                    return CL_EFORMAT;
                }

                /* advance to next element tag */
                state = xmlTextReaderRead(reader);
                check_state(state);

                endtag = 1;
                break;

            default:
                node_name = xmlTextReaderConstLocalName(reader);
                node_value = xmlTextReaderConstValue(reader);

                cli_dbgmsg("msxml_parse_element: unhandled xml secondary node %s [%d]: %s\n", node_name, node_type, node_value);

                state = xmlTextReaderNext(reader);
                check_state(state);
                return CL_SUCCESS;
            }
        }

        break;
    case XML_READER_TYPE_PROCESSING_INSTRUCTION:
        cli_dbgmsg("msxml_parse_element: PROCESSING INSTRUCTION %s [%d]: %s\n", node_name, node_type, node_value);
        break;
    case XML_READER_TYPE_END_ELEMENT:
        cli_dbgmsg("msxml_parse_element: END ELEMENT %s [%d]: %s\n", node_name, node_type, node_value);
        return CL_SUCCESS;
        break;
    default:
        cli_dbgmsg("msxml_parse_element: unhandled xml primary node %s [%d]: %s\n", node_name, node_type, node_value);
    }

    return CL_SUCCESS;
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
        cli_dbgmsg("cli_scanmsxml: cannot intialize xmlReader\n");
        xmlTextReaderClose(reader);
        xmlFreeTextReader(reader);
        return CL_SUCCESS; // libxml2 failed!
    }

    /* Main Processing Loop */
    while ((state = xmlTextReaderRead(reader)) == 1) {
        ret = msxml_parse_element(ctx, reader, 0);

        if (ret != CL_SUCCESS && ret != CL_ETIMEOUT && ret != CL_BREAK) {
            cli_warnmsg("cli_scanmsxml: encountered issue in parsing properties document\n");
            break;
        }
    }

    if (state == -1)
        ret = CL_EPARSE;

    xmlTextReaderClose(reader);
    xmlFreeTextReader(reader);
    return ret;
#else
    UNUSEDPARAM(ctx);
    cli_dbgmsg("in cli_scanmsxml()\n");
    cli_dbgmsg("cli_scanmsxml: scanning msxml documents requires libxml2!");

    return CL_SUCCESS;
#endif
}

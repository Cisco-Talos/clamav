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
#include "msxml_parser.h"

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


struct key_entry blank_key = { NULL, NULL, 0 };

static const struct key_entry *msxml_check_key(struct msxml_ctx *mxctx, const char *key, size_t keylen)
{
    unsigned i;

    if (keylen > MSXML_JSON_STRLEN_MAX-1) {
        cli_dbgmsg("msxml_check_key: key name too long\n");
        return &blank_key;
    }

    for (i = 0; i < mxctx->num_keys; ++i) {
        //cli_dbgmsg("%d %d %s %s %s %s\n", keylen, strlen(ooxml_keys[i]), key, keycmp, ooxml_keys[i], ooxml_json_keys[i]);
        if (keylen == strlen(mxctx->keys[i].key) && !strncasecmp(key, mxctx->keys[i].key, keylen)) {
            return &mxctx->keys[i];
        }
    }

    return &blank_key;
}

static int msxml_parse_element(struct msxml_ctx *mxctx, xmlTextReaderPtr reader, int rlvl)
{
    const xmlChar *element_name = NULL;
    const xmlChar *node_name = NULL, *node_value = NULL;
    const struct key_entry *keyinfo;
    int ret, state, node_type, endtag = 0;
    cli_ctx *ctx = mxctx->ctx;
#if HAVE_JSON
    json_object *parent = mxctx->wrkptr;
    json_object *thisjobj = NULL;
#endif

    cli_msxmlmsg("in msxml_parse_element @ layer %d\n", rlvl);

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
        cli_msxmlmsg("msxml_parse_element: ELEMENT %s [%d]: %s\n", node_name, node_type, node_value);

        /* storing the element name for verification/collection */
        element_name = xmlTextReaderConstLocalName(reader);
        if (!node_name) {
            cli_dbgmsg("msxml_parse_element: element tag node nameless\n");
            return CL_EPARSE; /* no name, nameless */
        }

        /* determine if the element is interesting */
        keyinfo = msxml_check_key(mxctx, element_name, strlen(element_name));

        cli_msxmlmsg("key:  %s\n", keyinfo->key);
        cli_msxmlmsg("name: %s\n", keyinfo->name);
        cli_msxmlmsg("type: %d\n", keyinfo->type);

#if HAVE_JSON
        if (keyinfo->type & MSXML_JSON_TRACK) {
            if (MSXML_JSON_ROOT)
                thisjobj = cli_jsonobj(mxctx->root, keyinfo->name);
            else if (MSXML_JSON_WRKPTR)
                thisjobj = cli_jsonobj(parent, keyinfo->name);

            if (!thisjobj) {
                return CL_EMEM;
            }
            cli_dbgmsg("msxml_parse_element: generated json object [%s]\n", keyinfo->name);

            /* count this element */
            if (thisjobj && (keyinfo->type & MSXML_JSON_COUNT)) {
                json_object *counter;

                if (!json_object_object_get_ex(thisjobj, "Count", &counter)) { /* object not found */
                    cli_jsonint(thisjobj, "Count", 1);
                    if (!counter) {
                        return CL_EPARSE;
                    }
                } else {
                    int value = json_object_get_int(counter);
                    cli_jsonint(thisjobj, "Count", value+1);
                }
                cli_dbgmsg("msxml_parse_element: retrieved json object [Count]\n");
            }

            /* handle attributes */
            if (thisjobj && (keyinfo->type & MSXML_JSON_ATTRIB)) {
                state = xmlTextReaderHasAttributes(reader);
                if (state == 1) {
                    json_object *attributes;

                    attributes = cli_jsonobj(thisjobj, "Attributes");
                    if (!attributes) {
                        return CL_EPARSE;
                    }
                    cli_dbgmsg("msxml_parse_element: retrieved json object [Attributes]\n");

                    while (xmlTextReaderMoveToNextAttribute(reader) == 1) {
                        const xmlChar *name, *value;
                        name = xmlTextReaderConstLocalName(reader);
                        value = xmlTextReaderConstValue(reader);

                        cli_dbgmsg("\t%s: %s\n", name, value);
                        cli_jsonstr(attributes, name, (const char *)value);
                    }
                }
                else if (state == -1)
                    return CL_EPARSE;
            }
        }
#endif

        /* check self-containment */
        state = xmlTextReaderMoveToElement(reader);
        if (state == -1)
            return CL_EPARSE;

        state = xmlTextReaderIsEmptyElement(reader);
        if (state == 1) {
            cli_msxmlmsg("msxml_parse_element: SELF-CLOSING\n");

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
                ret = msxml_parse_element(mxctx, reader, rlvl+1);
                if (ret != CL_SUCCESS) {
                    return ret;
                }
                break;

            case XML_READER_TYPE_TEXT:
                node_value = xmlTextReaderConstValue(reader);

                cli_msxmlmsg("TEXT: %s\n", node_value);

                /*
                  ret = ooxml_parse_value(thisjobj, "Value", node_value);
                  if (ret != CL_SUCCESS)
                  return ret;

                  cli_dbgmsg("ooxml_parse_element: added json value [%s: %s]\n", element_tag, node_value);
                */


                /* scanning protocol for embedded objects encoded in base64 */
                if (keyinfo->type & MSXML_SCAN_B64) {
                    char name[1024];
                    char *decoded, *tempfile = name;
                    size_t decodedlen;
                    int of;

                    cli_msxmlmsg("BINARY DATA!\n");

                    decoded = cl_base64_decode((char *)node_value, strlen((const char *)node_value), NULL, &decodedlen, 0);
                    if (!decoded) {
                        cli_warnmsg("msxml_parse_element: failed to decode base64-encoded binary data\n");
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

                /* advance to next node */
                state = xmlTextReaderRead(reader);
                check_state(state);
                break;

            case XML_READER_TYPE_SIGNIFICANT_WHITESPACE:
                /* advance to next node */
                state = xmlTextReaderRead(reader);
                check_state(state);
                break;

            case XML_READER_TYPE_END_ELEMENT:
                cli_msxmlmsg("in msxml_parse_element @ layer %d closed\n", rlvl);
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
        cli_msxmlmsg("msxml_parse_element: PROCESSING INSTRUCTION %s [%d]: %s\n", node_name, node_type, node_value);
        break;
    case XML_READER_TYPE_SIGNIFICANT_WHITESPACE:
        cli_msxmlmsg("msxml_parse_element: SIGNIFICANT WHITESPACE %s [%d]: %s\n", node_name, node_type, node_value);
        break;
    case XML_READER_TYPE_END_ELEMENT:
        cli_msxmlmsg("msxml_parse_element: END ELEMENT %s [%d]: %s\n", node_name, node_type, node_value);
        return CL_SUCCESS;
    default:
        cli_dbgmsg("msxml_parse_element: unhandled xml primary node %s [%d]: %s\n", node_name, node_type, node_value);
    }

    return CL_SUCCESS;
}

/* reader intialization and closing handled by caller */
int cli_msxml_parse_document(cli_ctx *ctx, xmlTextReaderPtr reader, const struct key_entry *keys, const size_t num_keys, int mode)
{
    struct msxml_ctx mxctx;
    int state, ret = CL_SUCCESS;

    mxctx.ctx = ctx;
    mxctx.keys = keys;
    mxctx.num_keys = num_keys;
#if HAVE_JSON
    if (mode) {
        mxctx.root = ctx->wrkproperty;
        mxctx.wrkptr = ctx->wrkproperty;
    }
#endif

    /* Main Processing Loop */
    while ((state = xmlTextReaderRead(reader)) == 1) {
        msxml_parse_element(&mxctx, reader, 0);
        if (ret != CL_SUCCESS && ret != CL_ETIMEOUT && ret != CL_BREAK) {
            cli_warnmsg("cli_msxml_parse_document: encountered issue in parsing xml document\n");
            break;
        }
    }

    if (state == -1)
        return CL_EPARSE;

    /* non-critical return supression */
    if (ret == CL_ETIMEOUT || ret == CL_BREAK)
        return CL_SUCCESS;

    return ret;
}

#endif /* HAVE_LIBXML2 */

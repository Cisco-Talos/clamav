/*
 * Extract component parts of various MS XML files (e.g. MS Office 2003 XML Documents)
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
#include "scanners.h"
#include "json_api.h"
#include "msxml_parser.h"

#if HAVE_LIBXML2
#include <libxml/xmlreader.h>

#define MSXML_VERBIOSE 0
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

#define track_json(mxctx) (mxctx->ictx->flags & MSXML_FLAG_JSON)

struct msxml_ictx {
    cli_ctx *ctx;
    uint32_t flags;
    const struct key_entry *keys;
    size_t num_keys;

#if HAVE_JSON
    json_object *root;
    int toval;
#endif
};

struct key_entry blank_key = { NULL, NULL, 0 };

static const struct key_entry *msxml_check_key(struct msxml_ictx *ictx, const xmlChar *key, size_t keylen)
{
    unsigned i;

    if (keylen > MSXML_JSON_STRLEN_MAX-1) {
        cli_dbgmsg("msxml_check_key: key name too long\n");
        return &blank_key;
    }

    for (i = 0; i < ictx->num_keys; ++i) {
        if (keylen == strlen(ictx->keys[i].key) && !strncasecmp((char *)key, ictx->keys[i].key, keylen)) {
            return &ictx->keys[i];
        }
    }

    return &blank_key;
}

static void msxml_error_handler(void* arg, const char* msg, xmlParserSeverities severity, xmlTextReaderLocatorPtr locator)
{
    int line = xmlTextReaderLocatorLineNumber(locator);
    xmlChar *URI = xmlTextReaderLocatorBaseURI(locator);

    switch (severity) {
    case XML_PARSER_SEVERITY_WARNING:
    case XML_PARSER_SEVERITY_VALIDITY_WARNING:
        cli_dbgmsg("%s:%d: parser warning : %s", (char*)URI, line, msg);
        break;
    case XML_PARSER_SEVERITY_ERROR:
    case XML_PARSER_SEVERITY_VALIDITY_ERROR:
        cli_dbgmsg("%s:%d: parser error : %s", (char*)URI, line, msg);
        break;
    default:
        cli_dbgmsg("%s:%d: unknown severity : %s", (char*)URI, line, msg);
        break;
    }
    free(URI);
}

#if HAVE_JSON
static int msxml_is_int(const char *value, size_t len, int32_t *val)
{
    long val2;
    char *endptr = NULL;

    val2 = strtol(value, &endptr, 10);
    if (endptr != value+len) {
        return 0;
    }

    *val = (int32_t)(val2 & 0x0000ffff);

    return 1;
}

static int msxml_parse_value(json_object *wrkptr, const char *arrname, const xmlChar *node_value)
{
    json_object *newobj, *arrobj;
    int val;

    if (!wrkptr)
        return CL_ENULLARG;

    arrobj = cli_jsonarray(wrkptr, arrname);
    if (arrobj == NULL) {
        return CL_EMEM;
    }

    if (msxml_is_int((const char *)node_value, xmlStrlen(node_value), &val)) {
        newobj = json_object_new_int(val);
    }
    else if (!xmlStrcmp(node_value, (const xmlChar *)"true")) {
        newobj = json_object_new_boolean(1);
    }
    else if (!xmlStrcmp(node_value, (const xmlChar *)"false")) {
        newobj = json_object_new_boolean(0);
    }
    else {
        newobj = json_object_new_string((const char *)node_value);
    }

    if (NULL == newobj) {
        cli_errmsg("msxml_parse_value: no memory for json value for [%s]\n", arrname);
        return CL_EMEM;
    }

    json_object_array_add(arrobj, newobj);
    return CL_SUCCESS;
}
#endif /* HAVE_JSON */

#define MAX_ATTRIBS 20
static int msxml_parse_element(struct msxml_ctx *mxctx, xmlTextReaderPtr reader, int rlvl, void *jptr)
{
    const xmlChar *element_name = NULL;
    const xmlChar *node_name = NULL, *node_value = NULL;
    const struct key_entry *keyinfo;
    struct attrib_entry attribs[MAX_ATTRIBS];
    int ret, virus = 0, state, node_type, endtag = 0, num_attribs = 0;
    cli_ctx *ctx = mxctx->ictx->ctx;
#if HAVE_JSON
    json_object *root = mxctx->ictx->root;
    json_object *parent = (json_object *)jptr;
    json_object *thisjobj = NULL;
#else
    void *parent = NULL;
    void *thisjobj = NULL;
#endif

    cli_msxmlmsg("in msxml_parse_element @ layer %d\n", rlvl);

    /* check recursion level */
    if (rlvl >= MSXML_RECLEVEL_MAX) {
        cli_dbgmsg("msxml_parse_element: reached msxml json recursion limit\n");

#if HAVE_JSON
        if (track_json(mxctx)) {
            int tmp = cli_json_parse_error(root, "MSXML_RECURSIVE_LIMIT");
            if (tmp != CL_SUCCESS)
                return tmp;
        }
#endif

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
        element_name = node_name;
        if (!element_name) {
            cli_dbgmsg("msxml_parse_element: element tag node nameless\n");
#if HAVE_JSON
            if (track_json(mxctx)) {
                int tmp = cli_json_parse_error(root, "MSXML_NAMELESS_ELEMENT");
                if (tmp != CL_SUCCESS)
                    return tmp;
            }
#endif
            return CL_EPARSE; /* no name, nameless */
        }

        /* determine if the element is interesting */
        keyinfo = msxml_check_key(mxctx->ictx, element_name, xmlStrlen(element_name));

        cli_msxmlmsg("key:  %s\n", keyinfo->key);
        cli_msxmlmsg("name: %s\n", keyinfo->name);
        cli_msxmlmsg("type: 0x%x\n", keyinfo->type);

        /* element and contents are ignored */
        if (keyinfo->type & MSXML_IGNORE_ELEM) {
            cli_msxmlmsg("msxml_parse_element: IGNORING ELEMENT %s\n", keyinfo->name);

            state = xmlTextReaderNext(reader);
            check_state(state);
            return CL_SUCCESS;
        }

#if HAVE_JSON
        if (track_json(mxctx) && (keyinfo->type & MSXML_JSON_TRACK)) {
            if (keyinfo->type & MSXML_JSON_ROOT)
                thisjobj = cli_jsonobj(root, keyinfo->name);
            else if (keyinfo->type & MSXML_JSON_WRKPTR)
                thisjobj = cli_jsonobj(parent, keyinfo->name);

            if (!thisjobj) {
                return CL_EMEM;
            }
            cli_msxmlmsg("msxml_parse_element: generated json object [%s]\n", keyinfo->name);

            /* count this element */
            if (thisjobj && (keyinfo->type & MSXML_JSON_COUNT)) {
                json_object *counter = NULL;

                if (!json_object_object_get_ex(thisjobj, "Count", &counter)) { /* object not found */
                    cli_jsonint(thisjobj, "Count", 1);
                } else {
                    int value = json_object_get_int(counter);
                    cli_jsonint(thisjobj, "Count", value+1);
                }
                cli_msxmlmsg("msxml_parse_element: retrieved json object [Count]\n");
            }

            /* check if multiple entries are allowed */
            if (thisjobj && (keyinfo->type & MSXML_JSON_MULTI)) {
                /* replace this object with an array entry object */
                json_object *multi = cli_jsonarray(thisjobj, "Multi");
                if (!multi) {
                    return CL_EMEM;
                }
                cli_msxmlmsg("msxml_parse_element: generated or retrieved json multi array\n");

                thisjobj = cli_jsonobj(multi, NULL);
                if (!thisjobj)
                    return CL_EMEM;
                cli_msxmlmsg("msxml_parse_element: generated json multi entry object\n");
            }

            /* handle attributes */
            if (thisjobj && (keyinfo->type & MSXML_JSON_ATTRIB)) {
                state = xmlTextReaderHasAttributes(reader);
                if (state == 1) {
                    json_object *attributes;
                    const xmlChar *name, *value;

                    attributes = cli_jsonobj(thisjobj, "Attributes");
                    if (!attributes) {
                        return CL_EPARSE;
                    }
                    cli_msxmlmsg("msxml_parse_element: retrieved json object [Attributes]\n");

                    while (xmlTextReaderMoveToNextAttribute(reader) == 1) {
                        name = xmlTextReaderConstLocalName(reader);
                        value = xmlTextReaderConstValue(reader);

                        cli_msxmlmsg("\t%s: %s\n", name, value);
                        cli_jsonstr(attributes, (char*)name, (const char *)value);
                    }
                }
                else if (state == -1)
                    return CL_EPARSE;
            }
        }
#endif
        /* populate attributes for scanning callback - BROKEN, probably from the fact the reader is pointed to the attribute from previously parsing attributes */
        if ((keyinfo->type & MSXML_SCAN_CB) && mxctx->scan_cb) {
            state = xmlTextReaderHasAttributes(reader);
            if (state == 0) {
                state = xmlTextReaderMoveToFirstAttribute(reader);
                if (state == 1) {
                    /* read first attribute (current head) */
                    attribs[num_attribs].key = (const char *)xmlTextReaderConstLocalName(reader);
                    attribs[num_attribs].value = (const char *)xmlTextReaderConstValue(reader);
                    num_attribs++;
                } else if (state == -1) {
                    return CL_EPARSE;
                }
            }

            /* start reading attributes or read remainder of attributes */
            if (state == 1) {
                cli_msxmlmsg("msxml_parse_element: adding attributes to scanning context\n");

                while ((num_attribs < MAX_ATTRIBS) && (xmlTextReaderMoveToNextAttribute(reader) == 1)) {
                    attribs[num_attribs].key = (const char *)xmlTextReaderConstLocalName(reader);
                    attribs[num_attribs].value = (const char *)xmlTextReaderConstValue(reader);
                    num_attribs++;
                }
            }
            else if (state == -1) {
                return CL_EPARSE;
            }
        }

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
#if HAVE_JSON
            if (track_json(mxctx) && (cli_json_timeout_cycle_check(ctx, &(mxctx->ictx->toval)) != CL_SUCCESS))
                return CL_ETIMEOUT;
#endif

            node_type = xmlTextReaderNodeType(reader);
            if (node_type == -1)
                return CL_EPARSE;

            switch (node_type) {
            case XML_READER_TYPE_ELEMENT:
                ret = msxml_parse_element(mxctx, reader, rlvl+1, thisjobj ? thisjobj : parent);
                if (ret != CL_SUCCESS || (!SCAN_ALLMATCHES && ret == CL_VIRUS)) {
                    return ret;
                } else if (SCAN_ALLMATCHES && ret == CL_VIRUS) {
                    virus = 1;
                }
                break;

            case XML_READER_TYPE_TEXT:
                node_value = xmlTextReaderConstValue(reader);

                cli_msxmlmsg("TEXT: %s\n", node_value);

#if HAVE_JSON
                if (thisjobj && (keyinfo->type & MSXML_JSON_VALUE)) {

                    ret = msxml_parse_value(thisjobj, "Value", node_value);
                    if (ret != CL_SUCCESS)
                        return ret;

                    cli_msxmlmsg("msxml_parse_element: added json value [%s: %s]\n", keyinfo->name, (const char *)node_value);
                }
#endif
                /* callback-based scanning mechanism for embedded objects (used by HWPML) */
                if ((keyinfo->type & MSXML_SCAN_CB) && mxctx->scan_cb) {
                    char name[1024];
                    char *tempfile = name;
                    int of;
                    size_t vlen = strlen((const char *)node_value);

                    cli_msxmlmsg("BINARY CALLBACK DATA!\n");

                    if ((ret = cli_gentempfd(ctx->engine->tmpdir, &tempfile, &of)) != CL_SUCCESS) {
                        cli_warnmsg("msxml_parse_element: failed to create temporary file %s\n", tempfile);
                        return ret;
                    }

                    if (cli_writen(of, (char *)node_value, vlen) != vlen) {
                        close(of);
                        if (!(ctx->engine->keeptmp))
                            cli_unlink(tempfile);
                        free(tempfile);
                        return CL_EWRITE;
                    }

                    cli_dbgmsg("msxml_parse_element: extracted binary data to %s\n", tempfile);

                    ret = mxctx->scan_cb(of, tempfile, ctx, num_attribs, attribs, mxctx->scan_data);
                    close(of);
                    if (!(ctx->engine->keeptmp))
                        cli_unlink(tempfile);
                    free(tempfile);
                    if (ret != CL_SUCCESS && (ret != CL_VIRUS || (!SCAN_ALLMATCHES && ret == CL_VIRUS))) {
                        return ret;
                    } else if (SCAN_ALLMATCHES && ret == CL_VIRUS) {
                        virus = 1;
                    }
                }

                /* scanning protocol for embedded objects encoded in base64 (used by MSXML) */
                if (keyinfo->type & MSXML_SCAN_B64) {
                    char name[1024];
                    char *decoded, *tempfile = name;
                    size_t decodedlen;
                    int of;

                    cli_msxmlmsg("BINARY DATA!\n");

                    decoded = (char *)cl_base64_decode((char *)node_value, strlen((const char *)node_value), NULL, &decodedlen, 0);
                    if (!decoded) {
                        cli_warnmsg("msxml_parse_element: failed to decode base64-encoded binary data\n");
                        state = xmlTextReaderRead(reader);
                        check_state(state);
                        break;
                    }

                    if ((ret = cli_gentempfd(ctx->engine->tmpdir, &tempfile, &of)) != CL_SUCCESS) {
                        cli_warnmsg("msxml_parse_element: failed to create temporary file %s\n", tempfile);
                        free(decoded);
                        return ret;
                    }

                    if(cli_writen(of, decoded, decodedlen) != (int)decodedlen) {
                        free(decoded);
                        close(of);
                        if (!(ctx->engine->keeptmp))
                            cli_unlink(tempfile);
                        free(tempfile);
                        return CL_EWRITE;
                    }
                    free(decoded);

                    cli_dbgmsg("msxml_parse_element: extracted binary data to %s\n", tempfile);

                    ret = cli_magic_scandesc(of, tempfile, ctx);
                    close(of);
                    if (!(ctx->engine->keeptmp))
                        cli_unlink(tempfile);
                    free(tempfile);
                    if (ret != CL_SUCCESS && (ret != CL_VIRUS || (!SCAN_ALLMATCHES && ret == CL_VIRUS))) {
                        return ret;
                    } else if (SCAN_ALLMATCHES && ret == CL_VIRUS) {
                        virus = 1;
                    }
                }

                /* advance to next node */
                state = xmlTextReaderRead(reader);
                check_state(state);
                break;

            case XML_READER_TYPE_COMMENT:
                node_value = xmlTextReaderConstValue(reader);

                cli_msxmlmsg("COMMENT: %s\n", node_value);

                /* callback-based scanning mechanism for comments (used by MHTML) */
                if ((keyinfo->type & MSXML_COMMENT_CB) && mxctx->comment_cb) {
#if HAVE_JSON
                    ret = mxctx->comment_cb((const char *)node_value, ctx, thisjobj, mxctx->comment_data);
#else
                    ret = mxctx->comment_cb((const char *)node_value, ctx, NULL, mxctx->comment_data);
#endif
                    if (ret != CL_SUCCESS && (ret != CL_VIRUS || (!SCAN_ALLMATCHES && ret == CL_VIRUS))) {
                        return ret;
                    } else if (SCAN_ALLMATCHES && ret == CL_VIRUS) {
                        virus = 1;
                    }

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

                if (xmlStrcmp(element_name, node_name)) {
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

                state = xmlTextReaderRead(reader);
                check_state(state);
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
        return (virus ? CL_VIRUS : CL_SUCCESS);
    default:
        cli_dbgmsg("msxml_parse_element: unhandled xml primary node %s [%d]: %s\n", node_name, node_type, node_value);
    }

    return (virus ? CL_VIRUS : CL_SUCCESS);
}

/* reader initialization and closing handled by caller */
int cli_msxml_parse_document(cli_ctx *ctx, xmlTextReaderPtr reader, const struct key_entry *keys, const size_t num_keys, uint32_t flags, struct msxml_ctx *mxctx)
{
    struct msxml_ctx reserve;
    struct msxml_ictx ictx;
    int state, virus = 0, ret = CL_SUCCESS;

    if (!ctx)
        return CL_ENULLARG;

    if (!mxctx) {
        memset(&reserve, 0, sizeof(reserve));
        mxctx = &reserve;
    }

    ictx.ctx = ctx;
    ictx.flags = flags;
    ictx.keys = keys;
    ictx.num_keys = num_keys;
#if HAVE_JSON
    if (flags & MSXML_FLAG_JSON) {
        ictx.root = ctx->wrkproperty;
        /* JSON Sanity Check */
        if (!ictx.root)
            ictx.flags &= ~MSXML_FLAG_JSON;
        ictx.toval = 0;
    }
#else
    ictx.flags &= ~MSXML_FLAG_JSON;
#endif
    mxctx->ictx = &ictx;

    /* Error Handler (setting handler on tree walker causes segfault) */
    if (!(flags & MSXML_FLAG_WALK))
        //xmlTextReaderSetErrorHandler(reader, NULL, NULL); /* xml default handler */
        xmlTextReaderSetErrorHandler(reader, msxml_error_handler, NULL);

    /* Main Processing Loop */
    while ((state = xmlTextReaderRead(reader)) == 1) {
#if HAVE_JSON
        if ((ictx.flags & MSXML_FLAG_JSON) && (cli_json_timeout_cycle_check(ictx.ctx, &(ictx.toval)) != CL_SUCCESS))
            return CL_ETIMEOUT;

        ret = msxml_parse_element(mxctx, reader, 0, ictx.root);
#else
        ret = msxml_parse_element(mxctx, reader, 0, NULL);
#endif
        if (ret == CL_SUCCESS);
        else if (SCAN_ALLMATCHES && ret == CL_VIRUS) {
            /* non-allmatch simply propagates it down to return through ret */
            virus = 1;
        } else if (ret == CL_VIRUS || ret == CL_ETIMEOUT || ret == CL_BREAK) {
            cli_dbgmsg("cli_msxml_parse_document: encountered halt event in parsing xml document\n");
            break;
        } else {
            cli_warnmsg("cli_msxml_parse_document: encountered issue in parsing xml document\n");
            break;
        }
    }

    if (state == -1)
        ret = CL_EPARSE;

#if HAVE_JSON
    /* Parse General Error Handler */
    if (ictx.flags & MSXML_FLAG_JSON) {
        int tmp = CL_SUCCESS;

        switch(ret) {
        case CL_SUCCESS:
        case CL_BREAK: /* OK */
            break;
        case CL_VIRUS:
            tmp = cli_json_parse_error(ictx.root, "MSXML_INTR_VIRUS");
            break;
        case CL_ETIMEOUT:
            tmp = cli_json_parse_error(ictx.root, "MSXML_INTR_TIMEOUT");
            break;
        case CL_EPARSE:
            tmp = cli_json_parse_error(ictx.root, "MSXML_ERROR_XMLPARSER");
            break;
        case CL_EMEM:
            tmp = cli_json_parse_error(ictx.root, "MSXML_ERROR_OUTOFMEM");
            break;
        case CL_EFORMAT:
            tmp = cli_json_parse_error(ictx.root, "MSXML_ERROR_MALFORMED");
            break;
        default:
            tmp = cli_json_parse_error(ictx.root, "MSXML_ERROR_OTHER");
            break;
        }

        if (tmp)
            return tmp;
    }
#endif

    /* non-critical return suppression */
    if (ret == CL_ETIMEOUT || ret == CL_BREAK)
        ret = CL_SUCCESS;

    /* important but non-critical suppression */
    if (ret == CL_EPARSE) {
        cli_dbgmsg("cli_msxml_parse_document: suppressing parsing error to continue scan\n");
        ret = CL_SUCCESS;
    }

    return (virus ? CL_VIRUS : ret);
}

#endif /* HAVE_LIBXML2 */

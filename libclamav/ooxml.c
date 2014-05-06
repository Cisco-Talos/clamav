/*
 * OOXML JSON Internals
 * 
 * Copyright (C) 2014 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
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

#include <openssl/ssl.h>
#include <openssl/err.h>
#include "libclamav/crypto.h"

#include "cltypes.h"
#include "others.h"
#include "unzip.h"
#if HAVE_JSON
#include "json/json.h"
#endif
#include "json_api.h"

#if HAVE_LIBXML2
#ifdef _WIN32
#ifndef LIBXML_WRITER_ENABLED
#define LIBXML_WRITER_ENABLED 1
#endif
#endif
#include <libxml/xmlreader.h>
#endif

#define OOXML_JSON_RECLEVEL 16
#define OOXML_JSON_RECLEVEL_MAX 32

static int ooxml_is_int(const char *value, size_t len, int32_t *val2)
{
    long val3;
    char *endptr = NULL;

    val3 = strtol(value, &endptr, 10);
    if (endptr != value+len) {
        return 0;
    }

    *val2 = (int32_t)(val3 & 0x0000ffff);

    return 1;
}

static int ooxml_basic_json(int fd, cli_ctx *ctx, const char *key)
{
    int ret = CL_SUCCESS;
#if HAVE_LIBXML2
#if HAVE_JSON
    const xmlChar *stack[OOXML_JSON_RECLEVEL];
    json_object *summary, *wrkptr;
    int type, rlvl = 0;
    int32_t val2;
    const xmlChar *name, *value;
    xmlTextReaderPtr reader = NULL;

    cli_dbgmsg("in ooxml_basic_json\n");

    reader = xmlReaderForFd(fd, "properties.xml", NULL, 0);
    if (reader == NULL) {
        cli_dbgmsg("ooxml_basic_json: xmlReaderForFd error for %s\n", key);
        return CL_SUCCESS; // libxml2 failed!
    }

    summary = json_object_new_object();
    if (NULL == summary) {
        cli_errmsg("ooxml_basic_json: no memory for json object.\n");
        ret = CL_EFORMAT;
        goto ooxml_basic_exit;
    }

    while (xmlTextReaderRead(reader) == 1) {
        name = xmlTextReaderConstLocalName(reader);
        value = xmlTextReaderConstValue(reader);
        type = xmlTextReaderNodeType(reader);

        cli_dbgmsg("%s [%i]: %s\n", name, type, value);

        switch (type) {
        case XML_READER_TYPE_ELEMENT:
            stack[rlvl] = name;
            rlvl++;
            break;
        case XML_READER_TYPE_TEXT:
            {
                wrkptr = summary;
                if (rlvl > 2) { /* 0 is root xml object */
                    int i;
                    for (i = 1; i < rlvl-1; ++i) {
                        json_object *newptr = json_object_object_get(wrkptr, stack[i]);
                        if (!newptr) {
                            newptr = json_object_new_object();
                            if (NULL == newptr) {
                                cli_errmsg("ooxml_basic_json: no memory for json object.\n");
                                ret = CL_EMEM;
                                goto ooxml_basic_exit;
                            }
                            json_object_object_add(wrkptr, stack[i], newptr);
                        }
                        else {
                            /* object already exists */
                            if (!json_object_is_type(newptr, json_type_object)) {
                                cli_warnmsg("ooxml_content_cb: json object already exists as not an object\n");
                                ret = CL_EFORMAT;
                                goto ooxml_basic_exit;
                            } 
                        }
                        wrkptr = newptr;
                        cli_dbgmsg("stack %d: %s\n", i, stack[i]);
                    }
                }
                
                if (ooxml_is_int(value, xmlStrlen(value), &val2)) {
                    ret = cli_jsonint(wrkptr, stack[rlvl-1], val2);
                }
                else if (!xmlStrcmp(value, "true")) {
                    ret = cli_jsonbool(wrkptr, stack[rlvl-1], 1);
                }
                else if (!xmlStrcmp(value, "false")) {
                    ret = cli_jsonbool(wrkptr, stack[rlvl-1], 0);
                }
                else {
                    ret = cli_jsonstr(wrkptr, stack[rlvl-1], value);
                }

                if (ret != CL_SUCCESS)
                    goto ooxml_basic_exit;
            }
            break;
        case XML_READER_TYPE_END_ELEMENT:
            rlvl--;
            break;
        default:
            cli_dbgmsg("ooxml_content_cb: unhandled xml node %s [%i]: %s\n", name, type, value);
            ret = CL_EFORMAT;
            goto ooxml_basic_exit;
        }
    }

    json_object_object_add(ctx->wrkproperty, key, summary);

    if (rlvl != 0) {
        cli_warnmsg("ooxml_basic_json: office property file has unbalanced tags\n");
        /* FAIL */
    }

 ooxml_basic_exit:
    xmlTextReaderClose(reader);
    xmlFreeTextReader(reader);
#else
    cli_dbgmsg("ooxml_basic_json: libjson needs to enabled!\n");
#endif
#else
    cli_dbgmsg("ooxml_basic_json: libxml2 needs to enabled!\n");
#endif
    return ret;
}

static int ooxml_core_cb(int fd, cli_ctx *ctx)
{
    cli_dbgmsg("in ooxml_core_cb\n");
    return ooxml_basic_json(fd, ctx, "CoreProperties");
}

static int ooxml_extn_cb(int fd, cli_ctx *ctx)
{
    cli_dbgmsg("in ooxml_extn_cb\n");
    return ooxml_basic_json(fd, ctx, "ExtendedProperties");
}

static int ooxml_content_cb(int fd, cli_ctx *ctx)
{
#if HAVE_LIBXML2
    int ret = CL_SUCCESS;
    int core=0, extn=0, cust=0;
    const xmlChar *name, *value, *CT, *PN;
    xmlTextReaderPtr reader = NULL;
    uint32_t loff;

    cli_dbgmsg("in ooxml_content_cb\n");

    reader = xmlReaderForFd(fd, "[Content_Types].xml", NULL, 0);
    if (reader == NULL) {
        cli_dbgmsg("ooxml_content_cb: xmlReaderForFd error for ""[Content_Types].xml""\n");
        return CL_SUCCESS; // libxml2 failed!
    }

    /* locate core-properties, extended-properties, and custom-properties (optional)  */
    while (xmlTextReaderRead(reader) == 1) {
        name = xmlTextReaderConstLocalName(reader);
        if (name == NULL) continue;

        if (strcmp(name, "Override")) continue;

        if (!xmlTextReaderHasAttributes(reader)) continue;

        CT = NULL; PN = NULL;
        while (xmlTextReaderMoveToNextAttribute(reader) == 1) {
            name = xmlTextReaderConstLocalName(reader);
            value = xmlTextReaderConstValue(reader);
            if (name == NULL || value == NULL) continue;

            if (!xmlStrcmp(name, "ContentType")) {
                CT = value;
            }
            else if (!xmlStrcmp(name, "PartName")) {
                PN = value;
            }

            cli_dbgmsg("%s: %s\n", name, value);
        }

        if (!CT && !PN) continue;

        if (!core && !xmlStrcmp(CT, "application/vnd.openxmlformats-package.core-properties+xml")) {
            /* default: /docProps/core.xml*/
            if (unzip_search(ctx, PN+1, xmlStrlen(PN)-1, &loff) != CL_VIRUS) {
                cli_dbgmsg("cli_process_ooxml: failed to find core properties file \"%s\"!\n", PN);
            }
            else {
                cli_dbgmsg("ooxml_content_cb: found core properties file \"%s\" @ %x\n", PN, loff);
                ret = unzip_single_internal(ctx, loff, ooxml_core_cb);
            }
            core = 1;
        }
        else if (!extn && !xmlStrcmp(CT, "application/vnd.openxmlformats-officedocument.extended-properties+xml")) {
            /* default: /docProps/app.xml */
            if (unzip_search(ctx, PN+1, xmlStrlen(PN)-1, &loff) != CL_VIRUS) {
                cli_dbgmsg("cli_process_ooxml: failed to find extended properties file \"%s\"!\n", PN);
            }
            else {
                cli_dbgmsg("ooxml_content_cb: found extended properties file \"%s\" @ %x\n", PN, loff);
                ret = unzip_single_internal(ctx, loff, ooxml_extn_cb);
            }
            extn = 1;
        }
        else if (!cust && !xmlStrcmp(CT, "application/vnd.openxmlformats-officedocument.custom-properties+xml")) {
            /* default: /docProps/custom.xml */
            if (unzip_search(ctx, PN+1, xmlStrlen(PN)-1, &loff) != CL_VIRUS) {
                cli_dbgmsg("cli_process_ooxml: failed to find custom properties file \"%s\"!\n", PN);
            }
            else {
                cli_dbgmsg("ooxml_content_cb: found custom properties file \"%s\" @ %x\n", PN, loff);
                /* custom properties ignored for now */
                //ret = unzip_single_internal(ctx, loff, ooxml_cust_cb);
            }
            cust = 1;
        }

        if (ret != CL_SUCCESS)
            goto ooxml_content_exit;
    }

    if (!core) {
        cli_dbgmsg("cli_process_ooxml: file does not contain core properties file\n");
    }
    if (!extn) {
        cli_dbgmsg("cli_process_ooxml: file does not contain extended properties file\n");
    }
    if (!cust) {
        cli_dbgmsg("cli_process_ooxml: file does not contain custom properties file\n");
    }

 ooxml_content_exit:
    xmlTextReaderClose(reader);
    xmlFreeTextReader(reader);
    return ret;
#else
    cli_dbgmsg("ooxml_content_cb: libxml2 needs to enabled!");
    return CL_SUCCESS;
#endif
}

int cli_process_ooxml(cli_ctx *ctx)
{
#if HAVE_LIBXML2
    uint32_t loff = 0;

    cli_dbgmsg("in cli_processooxml\n");
    if (!ctx) {
        return CL_ENULLARG;
    }

    /* find "[Content Types].xml" */
    if (unzip_search(ctx, "[Content_Types].xml", 18, &loff) != CL_VIRUS) {
        cli_dbgmsg("cli_process_ooxml: failed to find ""[Content_Types].xml""!\n");
        return CL_EFORMAT;
    }
    cli_dbgmsg("cli_process_ooxml: found ""[Content_Types].xml"" @ %x\n", loff);

    return unzip_single_internal(ctx, loff, ooxml_content_cb);
#else
    cli_dbgmsg("in cli_processooxml\n");
    cli_dbgmsg("cli_process_ooxml: libxml2 needs to enabled!");
    return CL_SUCCESS;
#endif
}

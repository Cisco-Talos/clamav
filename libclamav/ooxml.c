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
#include "json.h"
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

#if HAVE_LIBXML2 && HAVE_JSON

#define OOXML_JSON_RECLEVEL 16
#define OOXML_JSON_RECLEVEL_MAX 5
#define OOXML_JSON_STRLEN_MAX 100

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

static const char *ooxml_keys[] = {
    "coreproperties",
    "title",
    "subject",
    "creator",
    "keywords",
    "comments",
    "description",
    "lastmodifiedby",
    "revision",
    "created",
    "modified",
    "category",
    "contentstatus",

    "properties",
    "application",
    "appversion",
    "characters",
    "characterswithspaces",
    "company",
    "digsig",
    "docsecurity",
    //"headingpairs",
    "hiddenslides",
    "hlinks",
    "hyperlinkbase",
    "hyperlinkschanged",
    "lines",
    "linksuptodate",
    "manager",
    "mmclips",
    "notes",
    "pages",
    "paragraphs",
    "presentationformat",
    "properties",
    "scalecrop",
    "shareddoc",
    "slides",
    "template",
    //"titlesofparts",
    "totaltime",
    "words"
};
static const char *ooxml_json_keys[] = {
    "CoreProperties",
    "Title",
    "Subject",
    "Author",
    "Keywords",
    "Comments",
    "Description",
    "LastAuthor",
    "Revision",
    "Created",
    "Modified",
    "Category",
    "ContentStatus",

    "ExtendedProperties",
    "Application",
    "AppVersion",
    "Characters",
    "CharactersWithSpaces",
    "Company",
    "DigSig",
    "DocSecurity",
    //"HeadingPairs",
    "HiddenSlides",
    "HLinks",
    "HyperlinkBase",
    "HyperlinksChanged",
    "Lines",
    "LinksUpToDate",
    "Manager",
    "MMClips",
    "Notes",
    "Pages",
    "Paragraphs",
    "PresentationFormat",
    "Properties",
    "ScaleCrop",
    "SharedDoc",
    "Slides",
    "Template",
    //"TitlesOfParts",
    "TotalTime",
    "Words"
};
static size_t num_ooxml_keys = 40; //42

static const char *ooxml_check_key(const char* key, size_t keylen)
{
    unsigned i;
    char keycmp[OOXML_JSON_STRLEN_MAX];

    if (keylen > OOXML_JSON_STRLEN_MAX-1) {
        cli_dbgmsg("ooxml_check_key: key name too long\n");
        return NULL;
    }

    for (i = 0; i < keylen; i++) {
        if (key[i] >= 'A' && key[i] <= 'Z') {
            keycmp[i] = key[i] - 'A' + 'a';
        }
        else {
            keycmp[i] = key[i];
        }
    }
    keycmp[keylen] = '\0';

    for (i = 0; i < num_ooxml_keys; ++i) {
        //cli_dbgmsg("%d %d %s %s %s %s\n", keylen, strlen(ooxml_keys[i]), key, keycmp, ooxml_keys[i], ooxml_json_keys[i]);
        if (keylen == strlen(ooxml_keys[i]) && !strncmp(keycmp, ooxml_keys[i], keylen)) {
            return ooxml_json_keys[i];
        }
    }

    return NULL;
}

static int ooxml_parse_element(xmlTextReaderPtr reader, json_object *wrkptr, int rlvl, int skip)
{
    const char *element_tag = NULL, *end_tag = NULL;
    const xmlChar *node_name = NULL, *node_value = NULL;
    json_object *njptr;
    int node_type, ret = CL_SUCCESS;
    int32_t val2;

    cli_dbgmsg("in ooxml_parse_element @ layer %d\n", rlvl);

    /* check recursion level */
    if (rlvl >= OOXML_JSON_RECLEVEL_MAX) {
        return CL_EMAXREC;
    }

    if (wrkptr == NULL) {
        skip = 1;
    }

    /* acquire element type */
    node_type = xmlTextReaderNodeType(reader);
    if (node_type != XML_READER_TYPE_ELEMENT) {
        cli_dbgmsg("ooxml_parse_element: first node typed %d, not %d\n", node_type, XML_READER_TYPE_ELEMENT);
        return CL_EPARSE; /* first type is not an element */
    }

    /* acquire element tag */
    node_name = xmlTextReaderConstLocalName(reader);
    if (!node_name) {
        cli_dbgmsg("ooxml_parse_element: element tag node nameless\n");
        return CL_EPARSE; /* no name, nameless */
    }
    element_tag = ooxml_check_key(node_name, xmlStrlen(node_name));
    if (!element_tag) {
        cli_dbgmsg("ooxml_parse_element: invalid element tag [%s]\n", node_name);
        skip = 1; /* skipping element */
        //return CL_EFORMAT; /* REMOVE */
    }

    /* handle attributes if you want */

    /* loop across all element contents */
    while (xmlTextReaderRead(reader) == 1) {
        node_type = xmlTextReaderNodeType(reader);
        switch (node_type) {
        case XML_READER_TYPE_ELEMENT:
            if (!skip) {
                njptr = json_object_object_get(wrkptr, element_tag);
                if (!njptr) {
                    njptr = json_object_new_object();
                    if (NULL == njptr) {
                        cli_errmsg("ooxml_basic_json: no memory for json object.\n");
                        return CL_EMEM;
                    }
                    cli_dbgmsg("ooxml_basic_json: added json object [%s]\n", element_tag);
                    json_object_object_add(wrkptr, element_tag, njptr);
                }
                else {
                    if (!json_object_is_type(njptr, json_type_object)) {
                        cli_warnmsg("ooxml_content_cb: json object [%s] already exists as not an object\n", element_tag);
                        return CL_EFORMAT;
                    }
                }
            }
            else {
                njptr = NULL;
            } 

            ret = ooxml_parse_element(reader, njptr, rlvl+1, skip);
            if (ret != CL_SUCCESS) {
                return ret;
            }
            break;
        case XML_READER_TYPE_END_ELEMENT:
            cli_dbgmsg("in ooxml_parse_element @ layer %d closed\n", rlvl);
            node_name = xmlTextReaderConstLocalName(reader);
            if (!node_name) {
                cli_dbgmsg("ooxml_parse_element: element end tag node nameless\n");
                return CL_EPARSE; /* no name, nameless */
            }
            if (!skip) {
                end_tag = ooxml_check_key(node_name, xmlStrlen(node_name));
                if (!end_tag) {
                    cli_dbgmsg("ooxml_parse_element: invalid element end tag [%s]\n", node_name);
                    return CL_EFORMAT; /* unrecognized element tag */
                }
                if (strncmp(element_tag, end_tag, strlen(element_tag))) {
                    cli_dbgmsg("ooxml_parse_element: element tag does not match end tag\n");
                    return CL_EFORMAT;
                }
            }
            return CL_SUCCESS;
        case XML_READER_TYPE_TEXT:
            if (!skip) {
                node_value = xmlTextReaderConstValue(reader);
                njptr = json_object_object_get(wrkptr, element_tag);
                if (njptr) {
                    cli_warnmsg("ooxml_parse_element: json object [%s] already exists\n", element_tag);
                }

                if (ooxml_is_int(node_value, xmlStrlen(node_value), &val2)) {
                    ret = cli_jsonint(wrkptr, element_tag, val2);
                }
                else if (!xmlStrcmp(node_value, "true")) {
                    ret = cli_jsonbool(wrkptr, element_tag, 1);
                }
                else if (!xmlStrcmp(node_value, "false")) {
                    ret = cli_jsonbool(wrkptr, element_tag, 0);
                }
                else {
                    ret = cli_jsonstr(wrkptr, element_tag, node_value);
                }

                if (ret != CL_SUCCESS)
                    return ret;

                cli_dbgmsg("ooxml_basic_json: added json value [%s: %s]\n", element_tag, node_value);
            }
            else {
                node_name = xmlTextReaderConstLocalName(reader);
                node_value = xmlTextReaderConstValue(reader);

                cli_dbgmsg("ooxml_parse_element: not adding xml node %s [%d]: %s\n", node_name, node_type, node_value);
            }
            break;
        default:
            node_name = xmlTextReaderConstLocalName(reader);
            node_value = xmlTextReaderConstValue(reader);

            cli_dbgmsg("ooxml_parse_element: unhandled xml node %s [%d]: %s\n", node_name, node_type, node_value);
            return CL_EPARSE;
        }
    }

    return CL_SUCCESS;
}

static int ooxml_parse_document(int fd, cli_ctx *ctx)
{
    int ret = CL_SUCCESS;
    xmlTextReaderPtr reader = NULL;

    cli_dbgmsg("in ooxml_parse_document\n");

    reader = xmlReaderForFd(fd, "properties.xml", NULL, 0);
    if (reader == NULL) {
        cli_dbgmsg("ooxml_parse_document: xmlReaderForFd error\n");
        return CL_SUCCESS; // internal error from libxml2
    }

    /* move reader to first element */
    if (xmlTextReaderRead(reader) != 1) {
        return CL_SUCCESS; /* libxml2 failed */
    }

    ret = ooxml_parse_element(reader, ctx->wrkproperty, 0, 0);

    xmlTextReaderClose(reader);
    xmlFreeTextReader(reader);
    return ret;
}

static int ooxml_basic_json(int fd, cli_ctx *ctx, const char *key)
{
    int ret = CL_SUCCESS;
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
    return ret;
}

static int ooxml_core_cb(int fd, cli_ctx *ctx)
{
    cli_dbgmsg("in ooxml_core_cb\n");
    return ooxml_parse_document(fd, ctx);
    //return ooxml_basic_json(fd, ctx, "CoreProperties");
}

static int ooxml_extn_cb(int fd, cli_ctx *ctx)
{
    cli_dbgmsg("in ooxml_extn_cb\n");
    return ooxml_parse_document(fd, ctx);
    //return ooxml_basic_json(fd, ctx, "ExtendedProperties");
}

static int ooxml_content_cb(int fd, cli_ctx *ctx)
{
    int ret = CL_SUCCESS;
    int core=0, extn=0, cust=0, dsig=0;
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
                cli_jsonbool(ctx->wrkproperty, "CustomProperties", 1);
                //ret = unzip_single_internal(ctx, loff, ooxml_cust_cb);
            }
            cust = 1;
        }
        else if (!dsig && !xmlStrcmp(CT, "application/vnd.openxmlformats-package.digital-signature-xmlsignature+xml")) {
            if (unzip_search(ctx, PN+1, xmlStrlen(PN)-1, &loff) != CL_VIRUS) {
                cli_dbgmsg("cli_process_ooxml: failed to find digital signature file \"%s\"!\n", PN);
            }
            else {
                cli_dbgmsg("ooxml_content_cb: found digital signature file \"%s\" @ %x\n", PN, loff);
                /* digital signatures ignored for now */
                cli_jsonbool(ctx->wrkproperty, "DigitalSignatures", 1);
                //ret = unzip_single_internal(ctx, loff, ooxml_dsig_cb);
            }
            dsig = 1;
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
}
#endif

int cli_process_ooxml(cli_ctx *ctx)
{
#if HAVE_LIBXML2 && HAVE_JSON
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
#if !HAVE_LIBXML2
    cli_dbgmsg("cli_process_ooxml: libxml2 needs to enabled!");
#endif
#if !HAVE_JSON
    cli_dbgmsg("cli_process_ooxml: libjson needs to enabled!");
#endif
    return CL_SUCCESS;
#endif
}

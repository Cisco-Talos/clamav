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

#define OOXML_DEBUG 0

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
    "MultimediaClips",
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

    if (keylen > OOXML_JSON_STRLEN_MAX-1) {
        cli_dbgmsg("ooxml_check_key: key name too long\n");
        return NULL;
    }

    for (i = 0; i < num_ooxml_keys; ++i) {
        //cli_dbgmsg("%d %d %s %s %s %s\n", keylen, strlen(ooxml_keys[i]), key, keycmp, ooxml_keys[i], ooxml_json_keys[i]);
        if (keylen == strlen(ooxml_keys[i]) && !strncasecmp(key, ooxml_keys[i], keylen)) {
            return ooxml_json_keys[i];
        }
    }

    return NULL;
}

static int ooxml_parse_element(cli_ctx *ctx, xmlTextReaderPtr reader, json_object *wrkptr, int rlvl, int skip)
{
    const char *element_tag = NULL, *end_tag = NULL;
    const xmlChar *node_name = NULL, *node_value = NULL;
    json_object *njptr;
    int node_type, ret = CL_SUCCESS, toval = 0;;
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
    }

    /* handle attributes if you want */

    /* loop across all element contents */
    while (xmlTextReaderRead(reader) == 1) {
        if (cli_json_timeout_cycle_check(ctx, &toval) != CL_SUCCESS) {
            return CL_ETIMEOUT;
        }

        node_type = xmlTextReaderNodeType(reader);
        switch (node_type) {
        case XML_READER_TYPE_ELEMENT:
            if (!skip) {
                njptr = cli_jsonobj(wrkptr, element_tag);
                if (!njptr) {
                    cli_errmsg("ooxml_parse_element: failed to retrieve node for json object [%s]\n", element_tag);
                    return CL_EFORMAT;
                }
                cli_dbgmsg("ooxml_parse_element: added json object [%s]\n", element_tag);
            }
            else {
                njptr = NULL;
            } 

            ret = ooxml_parse_element(ctx, reader, njptr, rlvl+1, skip);
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

                cli_dbgmsg("ooxml_parse_element: added json value [%s: %s]\n", element_tag, node_value);
            }
#if OOXML_DEBUG
            else {
                node_name = xmlTextReaderConstLocalName(reader);
                node_value = xmlTextReaderConstValue(reader);

                cli_dbgmsg("ooxml_parse_element: not adding xml node %s [%d]: %s\n", node_name, node_type, node_value);
            }
#endif
            break;
        default:
#if OOXML_DEBUG
            node_name = xmlTextReaderConstLocalName(reader);
            node_value = xmlTextReaderConstValue(reader);

            cli_dbgmsg("ooxml_parse_element: unhandled xml node %s [%d]: %s\n", node_name, node_type, node_value);
#endif
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

    ret = ooxml_parse_element(ctx, reader, ctx->wrkproperty, 0, 0);

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
    int ret = CL_SUCCESS, tmp, toval = 0;
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
        if (cli_json_timeout_cycle_check(ctx, &toval) != CL_SUCCESS) {
            ret = CL_ETIMEOUT;
            goto ooxml_content_exit;
        }

        name = xmlTextReaderConstLocalName(reader);
        if (name == NULL) continue;

        if (strcmp(name, "Override")) continue;

        if (!xmlTextReaderHasAttributes(reader)) continue;

        CT = PN = NULL;
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

        if (!xmlStrcmp(CT, "application/vnd.openxmlformats-package.core-properties+xml")) {
            if (!core) {
                /* default: /docProps/core.xml*/
                tmp = unzip_search(ctx, PN+1, xmlStrlen(PN)-1, &loff);
                if (tmp == CL_ETIMEOUT) {
                    ret = tmp;
                }
                else if (tmp != CL_VIRUS) {
                    cli_dbgmsg("cli_process_ooxml: failed to find core properties file \"%s\"!\n", PN);
                }
                else {
                    cli_dbgmsg("ooxml_content_cb: found core properties file \"%s\" @ %x\n", PN, loff);
                    ret = unzip_single_internal(ctx, loff, ooxml_core_cb);
                }
            }
            core++;
        }
        else if (!xmlStrcmp(CT, "application/vnd.openxmlformats-officedocument.extended-properties+xml")) {
            if (!extn) {
                /* default: /docProps/app.xml */
                tmp = unzip_search(ctx, PN+1, xmlStrlen(PN)-1, &loff);
                if (tmp == CL_ETIMEOUT) {
                    ret = tmp;
                }
                else if (tmp != CL_VIRUS) {
                    cli_dbgmsg("cli_process_ooxml: failed to find extended properties file \"%s\"!\n", PN);
                }
                else {
                    cli_dbgmsg("ooxml_content_cb: found extended properties file \"%s\" @ %x\n", PN, loff);
                    ret = unzip_single_internal(ctx, loff, ooxml_extn_cb);
                }
            }
            extn++;
        }
        else if (!xmlStrcmp(CT, "application/vnd.openxmlformats-officedocument.custom-properties+xml")) {
            if (!cust) {
                /* default: /docProps/custom.xml */
                tmp = unzip_search(ctx, PN+1, xmlStrlen(PN)-1, &loff);
                if (tmp == CL_ETIMEOUT) {
                    ret = tmp;
                }
                else if (tmp != CL_VIRUS) {
                    cli_dbgmsg("cli_process_ooxml: failed to find custom properties file \"%s\"!\n", PN);
                }
                else {
                    cli_dbgmsg("ooxml_content_cb: found custom properties file \"%s\" @ %x\n", PN, loff);
                    //ret = unzip_single_internal(ctx, loff, ooxml_cust_cb);
                }
            }
            cust++;
        }
        else if (!xmlStrcmp(CT, "application/vnd.openxmlformats-package.digital-signature-xmlsignature+xml")) {
            dsig++;
        }

        if (ret != CL_SUCCESS)
            goto ooxml_content_exit;
    }

    if (core) {
        cli_jsonint(ctx->wrkproperty, "CorePropertiesFileCount", core);
    }
    else {
        cli_dbgmsg("cli_process_ooxml: file does not contain core properties file\n");
    }
    if (extn) {
        cli_jsonint(ctx->wrkproperty, "ExtendedPropertiesFileCount", extn);
    }
    else {
        cli_dbgmsg("cli_process_ooxml: file does not contain extended properties file\n");
    }
    if (cust) {
        cli_jsonint(ctx->wrkproperty, "CustomPropertiesFileCount", cust);
    }
    else {
        cli_dbgmsg("cli_process_ooxml: file does not contain custom properties file\n");
    }
    if (dsig) {
        cli_jsonint(ctx->wrkproperty, "DigitalSignaturesCount", dsig);
    }

 ooxml_content_exit:
    xmlTextReaderClose(reader);
    xmlFreeTextReader(reader);
    return ret;
}
#endif /* HAVE_LIBXML2 && HAVE_JSON */

int cli_process_ooxml(cli_ctx *ctx)
{
#if HAVE_LIBXML2 && HAVE_JSON
    uint32_t loff = 0;
    int tmp = CL_SUCCESS;

    cli_dbgmsg("in cli_processooxml\n");
    if (!ctx) {
        return CL_ENULLARG;
    }

    /* find "[Content Types].xml" */
    tmp = unzip_search(ctx, "[Content_Types].xml", 18, &loff);
    if (tmp == CL_ETIMEOUT) {
        return CL_ETIMEOUT;
    }
    else if (tmp != CL_VIRUS) {
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

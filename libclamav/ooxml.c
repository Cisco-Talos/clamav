/*
 * OOXML JSON Internals
 * 
 * Copyright (C) 2014-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
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
#include "filetypes.h"
#include "others.h"
#include "unzip.h"
#if HAVE_JSON
#include "json.h"
#endif
#include "json_api.h"
#include "msxml_parser.h"
#include "ooxml.h"

#if HAVE_LIBXML2
#include <libxml/xmlreader.h>
#endif



#if HAVE_LIBXML2 && HAVE_JSON

/*** OOXML MSDOC ***/
static const struct key_entry ooxml_keys[] = {
    { "coreproperties",     "CoreProperties",     MSXML_JSON_ROOT | MSXML_JSON_ATTRIB },
    { "title",              "Title",              MSXML_JSON_WRKPTR | MSXML_JSON_VALUE },
    { "subject",            "Subject",            MSXML_JSON_WRKPTR | MSXML_JSON_VALUE },
    { "creator",            "Author",             MSXML_JSON_WRKPTR | MSXML_JSON_VALUE },
    { "keywords",           "Keywords",           MSXML_JSON_WRKPTR | MSXML_JSON_VALUE },
    { "comments",           "Comments",           MSXML_JSON_WRKPTR | MSXML_JSON_VALUE },
    { "description",        "Description",        MSXML_JSON_WRKPTR | MSXML_JSON_VALUE },
    { "lastmodifiedby",     "LastAuthor",         MSXML_JSON_WRKPTR | MSXML_JSON_VALUE },
    { "revision",           "Revision",           MSXML_JSON_WRKPTR | MSXML_JSON_VALUE },
    { "created",            "Created",            MSXML_JSON_WRKPTR | MSXML_JSON_VALUE },
    { "modified",           "Modified",           MSXML_JSON_WRKPTR | MSXML_JSON_VALUE },
    { "category",           "Category",           MSXML_JSON_WRKPTR | MSXML_JSON_VALUE },
    { "contentstatus",      "ContentStatus",      MSXML_JSON_WRKPTR | MSXML_JSON_VALUE },

    { "properties",         "ExtendedProperties", MSXML_JSON_ROOT | MSXML_JSON_ATTRIB },
    { "application",        "Application",        MSXML_JSON_WRKPTR | MSXML_JSON_VALUE },
    { "appversion",         "AppVersion",         MSXML_JSON_WRKPTR | MSXML_JSON_VALUE },
    { "characters",         "Characters",         MSXML_JSON_WRKPTR | MSXML_JSON_VALUE },
    { "characterswithspaces", "CharactersWithSpaces", MSXML_JSON_WRKPTR | MSXML_JSON_VALUE },
    { "company",            "Company",            MSXML_JSON_WRKPTR | MSXML_JSON_VALUE },
    { "digsig",             "DigSig",             MSXML_JSON_WRKPTR | MSXML_JSON_VALUE },
    { "docsecurity",        "DocSecurity",        MSXML_JSON_WRKPTR | MSXML_JSON_VALUE },
    //{ "headingpairs",       "HeadingPairs",       MSXML_JSON_WRKPTR | MSXML_JSON_VALUE },
    { "hiddenslides",       "HiddenSlides",       MSXML_JSON_WRKPTR | MSXML_JSON_VALUE },
    { "hlinks",             "HLinks",             MSXML_JSON_WRKPTR | MSXML_JSON_VALUE },
    { "hyperlinkbase",      "HyperlinkBase",      MSXML_JSON_WRKPTR | MSXML_JSON_VALUE },
    { "hyperlinkschanged",  "HyperlinksChanged",  MSXML_JSON_WRKPTR | MSXML_JSON_VALUE },
    { "lines",              "Lines",              MSXML_JSON_WRKPTR | MSXML_JSON_VALUE },
    { "linksuptodate",      "LinksUpToDate",      MSXML_JSON_WRKPTR | MSXML_JSON_VALUE },
    { "manager",            "Manager",            MSXML_JSON_WRKPTR | MSXML_JSON_VALUE },
    { "mmclips",            "MultimediaClips",    MSXML_JSON_WRKPTR | MSXML_JSON_VALUE },
    { "notes",              "Notes",              MSXML_JSON_WRKPTR | MSXML_JSON_VALUE },
    { "pages",              "Pages",              MSXML_JSON_WRKPTR | MSXML_JSON_VALUE },
    { "paragraphs",         "Paragraphs",         MSXML_JSON_WRKPTR | MSXML_JSON_VALUE },
    { "presentationformat", "PresentationFormat", MSXML_JSON_WRKPTR | MSXML_JSON_VALUE },
    //{ "properties",         "Properties",         MSXML_JSON_WRKPTR | MSXML_JSON_VALUE },
    { "scalecrop",          "ScaleCrop",          MSXML_JSON_WRKPTR | MSXML_JSON_VALUE },
    { "shareddoc",          "SharedDocs",         MSXML_JSON_WRKPTR | MSXML_JSON_VALUE },
    { "slides",             "Slides",             MSXML_JSON_WRKPTR | MSXML_JSON_VALUE },
    { "template",           "Template",           MSXML_JSON_WRKPTR | MSXML_JSON_VALUE },
    //{ "titleofparts",       "TitleOfParts",       MSXML_JSON_WRKPTR | MSXML_JSON_VALUE },
    { "totaltime",          "TotalTime",          MSXML_JSON_WRKPTR | MSXML_JSON_VALUE },
    { "words",              "Words",              MSXML_JSON_WRKPTR | MSXML_JSON_VALUE },

    /* Should NOT Exist */
    { "bindata",            "BinaryData",         MSXML_SCAN_B64 | MSXML_JSON_COUNT | MSXML_JSON_ROOT }
};
static size_t num_ooxml_keys = sizeof(ooxml_keys) / sizeof(struct key_entry);

static int ooxml_updatelimits(int fd, cli_ctx *ctx)
{
    STATBUF sb;
    if (FSTAT(fd, &sb) == -1) {
        cli_errmsg("ooxml_updatelimits: Can't fstat descriptor %d\n", fd);
        return CL_ESTAT;
    }

    return cli_updatelimits(ctx, sb.st_size);
}

static int ooxml_parse_document(int fd, cli_ctx *ctx)
{
    int ret = CL_SUCCESS;
    xmlTextReaderPtr reader = NULL;

    cli_dbgmsg("in ooxml_parse_document\n");

    /* perform engine limit checks in temporary tracking session */
    ret = ooxml_updatelimits(fd, ctx);
    if (ret != CL_CLEAN)
        return ret;

    reader = xmlReaderForFd(fd, "properties.xml", NULL, CLAMAV_MIN_XMLREADER_FLAGS);
    if (reader == NULL) {
        cli_dbgmsg("ooxml_parse_document: xmlReaderForFd error\n");
        return CL_SUCCESS; // internal error from libxml2
    }

    ret = cli_msxml_parse_document(ctx, reader, ooxml_keys, num_ooxml_keys, MSXML_FLAG_JSON, NULL);

    if (ret != CL_SUCCESS && ret != CL_ETIMEOUT && ret != CL_BREAK)
        cli_warnmsg("ooxml_parse_document: encountered issue in parsing properties document\n");

    xmlTextReaderClose(reader);
    xmlFreeTextReader(reader);
    return ret;
}

static int ooxml_core_cb(int fd, const char* filepath, cli_ctx *ctx)
{
    int ret;

    cli_dbgmsg("in ooxml_core_cb\n");
    ret = ooxml_parse_document(fd, ctx);
    if (ret == CL_EPARSE)
        cli_json_parse_error(ctx->wrkproperty, "OOXML_ERROR_CORE_XMLPARSER");
    else if (ret == CL_EFORMAT)
        cli_json_parse_error(ctx->wrkproperty, "OOXML_ERROR_CORE_MALFORMED");

    return ret;
}

static int ooxml_extn_cb(int fd, const char* filepath, cli_ctx *ctx)
{
    int ret;

    cli_dbgmsg("in ooxml_extn_cb\n");
    ret = ooxml_parse_document(fd, ctx);
    if (ret == CL_EPARSE)
        cli_json_parse_error(ctx->wrkproperty, "OOXML_ERROR_EXTN_XMLPARSER");
    else if (ret == CL_EFORMAT)
        cli_json_parse_error(ctx->wrkproperty, "OOXML_ERROR_EXTN_MALFORMED");

    return ret;
}

static int ooxml_content_cb(int fd, const char* filepath, cli_ctx *ctx)
{
    int ret = CL_SUCCESS, tmp, toval = 0, state;
    int core=0, extn=0, cust=0, dsig=0;
    int mcore=0, mextn=0, mcust=0;
    const xmlChar *name, *value, *CT, *PN;
    xmlTextReaderPtr reader = NULL;
    uint32_t loff;

    unsigned long sav_scansize = ctx->scansize;
    unsigned int sav_scannedfiles = ctx->scannedfiles;

    cli_dbgmsg("in ooxml_content_cb\n");

    /* perform engine limit checks in temporary tracking session */
    ret = ooxml_updatelimits(fd, ctx);
    if (ret != CL_CLEAN)
        return ret;

    /* apply a reader to the document */
    reader = xmlReaderForFd(fd, "[Content_Types].xml", NULL, CLAMAV_MIN_XMLREADER_FLAGS);
    if (reader == NULL) {
        cli_dbgmsg("ooxml_content_cb: xmlReaderForFd error for ""[Content_Types].xml""\n");
        cli_json_parse_error(ctx->wrkproperty, "OOXML_ERROR_XML_READER_FD");

        ctx->scansize = sav_scansize;
        ctx->scannedfiles = sav_scannedfiles;
        return CL_SUCCESS; // libxml2 failed!
    }

    /* locate core-properties, extended-properties, and custom-properties (optional) */
    while ((state = xmlTextReaderRead(reader)) == 1) {
        if (cli_json_timeout_cycle_check(ctx, &toval) != CL_SUCCESS) {
            ret = CL_ETIMEOUT;
            goto ooxml_content_exit;
        }

        name = xmlTextReaderConstLocalName(reader);
        if (name == NULL) continue;

        if (strcmp((const char *)name, "Override")) continue;

        if (xmlTextReaderHasAttributes(reader) != 1) continue;

        CT = PN = NULL;
        while (xmlTextReaderMoveToNextAttribute(reader) == 1) {
            name = xmlTextReaderConstLocalName(reader);
            value = xmlTextReaderConstValue(reader);
            if (name == NULL || value == NULL) continue;

            if (!xmlStrcmp(name, (const xmlChar *)"ContentType")) {
                CT = value;
            }
            else if (!xmlStrcmp(name, (const xmlChar *)"PartName")) {
                PN = value;
            }

            cli_dbgmsg("%s: %s\n", name, value);
        }

        if (!CT && !PN) continue;

        if (!xmlStrcmp(CT, (const xmlChar *)"application/vnd.openxmlformats-package.core-properties+xml")) {
            /* default: /docProps/core.xml*/
            tmp = unzip_search_single(ctx, (const char *)(PN+1), xmlStrlen(PN)-1, &loff);
            if (tmp == CL_ETIMEOUT) {
                ret = tmp;
            }
            else if (tmp != CL_VIRUS) {
                cli_dbgmsg("cli_process_ooxml: failed to find core properties file \"%s\"!\n", PN);
                mcore++;
            }
            else {
                cli_dbgmsg("ooxml_content_cb: found core properties file \"%s\" @ %x\n", PN, loff);
                if (!core) {
                    tmp = unzip_single_internal(ctx, loff, ooxml_core_cb);
                    if (tmp == CL_ETIMEOUT || tmp == CL_EMEM) {
                        ret = tmp;
                    }
                }
                core++;
            }
        }
        else if (!xmlStrcmp(CT, (const xmlChar *)"application/vnd.openxmlformats-officedocument.extended-properties+xml")) {
            /* default: /docProps/app.xml */
            tmp = unzip_search_single(ctx, (const char *)(PN+1), xmlStrlen(PN)-1, &loff);
            if (tmp == CL_ETIMEOUT) {
                ret = tmp;
            }
            else if (tmp != CL_VIRUS) {
                cli_dbgmsg("cli_process_ooxml: failed to find extended properties file \"%s\"!\n", PN);
                mextn++;
            }
            else {
                cli_dbgmsg("ooxml_content_cb: found extended properties file \"%s\" @ %x\n", PN, loff);
                if (!extn) {
                    tmp = unzip_single_internal(ctx, loff, ooxml_extn_cb);
                    if (tmp == CL_ETIMEOUT || tmp == CL_EMEM) {
                        ret = tmp;
                    }
                }
                extn++;
            }
        }
        else if (!xmlStrcmp(CT, (const xmlChar *)"application/vnd.openxmlformats-officedocument.custom-properties+xml")) {
            /* default: /docProps/custom.xml */
            tmp = unzip_search_single(ctx, (const char *)(PN+1), xmlStrlen(PN)-1, &loff);
            if (tmp == CL_ETIMEOUT) {
                ret = tmp;
            }
            else if (tmp != CL_VIRUS) {
                cli_dbgmsg("cli_process_ooxml: failed to find custom properties file \"%s\"!\n", PN);
                mcust++;
            }
            else {
                cli_dbgmsg("ooxml_content_cb: found custom properties file \"%s\" @ %x\n", PN, loff);
                /* custom properties are not parsed */
                cust++;
            }
        }
        else if (!xmlStrcmp(CT, (const xmlChar *)"application/vnd.openxmlformats-package.digital-signature-xmlsignature+xml")) {
            dsig++;
        }

        if (ret != CL_SUCCESS)
            goto ooxml_content_exit;
    }

 ooxml_content_exit:
    if (core) {
        cli_jsonint(ctx->wrkproperty, "CorePropertiesFileCount", core);
        if (core > 1)
            cli_json_parse_error(ctx->wrkproperty, "OOXML_ERROR_MULTIPLE_CORE_PROPFILES");
    }
    else if (!mcore)
        cli_dbgmsg("cli_process_ooxml: file does not contain core properties file\n");
    if (mcore) {
        cli_jsonint(ctx->wrkproperty, "CorePropertiesMissingFileCount", mcore);
        cli_json_parse_error(ctx->wrkproperty, "OOXML_ERROR_MISSING_CORE_PROPFILES");
    }

    if (extn) {
        cli_jsonint(ctx->wrkproperty, "ExtendedPropertiesFileCount", extn);
        if (extn > 1)
            cli_json_parse_error(ctx->wrkproperty, "OOXML_ERROR_MULTIPLE_EXTN_PROPFILES");
    }
    else if (!mextn)
        cli_dbgmsg("cli_process_ooxml: file does not contain extended properties file\n");
    if (mextn) {
        cli_jsonint(ctx->wrkproperty, "ExtendedPropertiesMissingFileCount", mextn);
        cli_json_parse_error(ctx->wrkproperty, "OOXML_ERROR_MISSING_EXTN_PROPFILES");
    }

    if (cust) {
        cli_jsonint(ctx->wrkproperty, "CustomPropertiesFileCount", cust);
        if (cust > 1)
            cli_json_parse_error(ctx->wrkproperty, "OOXML_ERROR_MULTIPLE_CUSTOM_PROPFILES");
    }
    else if (!mcust)
        cli_dbgmsg("cli_process_ooxml: file does not contain custom properties file\n");
    if (mcust) {
        cli_jsonint(ctx->wrkproperty, "CustomPropertiesMissingFileCount", mcust);
        cli_json_parse_error(ctx->wrkproperty, "OOXML_ERROR_MISSING_CUST_PROPFILES");
    }

    if (dsig) {
        cli_jsonint(ctx->wrkproperty, "DigitalSignaturesCount", dsig);
    }

    /* restore the engine tracking limits; resets session limit tracking */
    ctx->scansize = sav_scansize;
    ctx->scannedfiles = sav_scannedfiles;

    xmlTextReaderClose(reader);
    xmlFreeTextReader(reader);
    return ret;
}

/*** OOXML HWP ***/
static const struct key_entry ooxml_hwp_keys[] = {
    { "hcfversion",         "HCFVersion",         MSXML_JSON_ROOT | MSXML_JSON_ATTRIB },

    { "package",            "Properties",         MSXML_JSON_ROOT | MSXML_JSON_ATTRIB },
    { "metadata",           "Metadata",           MSXML_JSON_WRKPTR | MSXML_JSON_ATTRIB },
    { "title",              "Title",              MSXML_JSON_WRKPTR | MSXML_JSON_VALUE },
    { "language",           "Language",           MSXML_JSON_WRKPTR | MSXML_JSON_VALUE },
    { "meta",               "MetaFields",         MSXML_JSON_WRKPTR | MSXML_JSON_ATTRIB | MSXML_JSON_VALUE | MSXML_JSON_COUNT | MSXML_JSON_MULTI },
    { "item",               "Contents",           MSXML_JSON_WRKPTR | MSXML_JSON_ATTRIB | MSXML_JSON_COUNT | MSXML_JSON_MULTI }
};
static size_t num_ooxml_hwp_keys = sizeof(ooxml_hwp_keys) / sizeof(struct key_entry);

static int ooxml_hwp_cb(int fd, const char* filepath, cli_ctx *ctx)
{
    int ret = CL_SUCCESS;
    xmlTextReaderPtr reader = NULL;

    cli_dbgmsg("in ooxml_hwp_cb\n");

    /* perform engine limit checks in temporary tracking session */
    ret = ooxml_updatelimits(fd, ctx);
    if (ret != CL_CLEAN)
        return ret;

    reader = xmlReaderForFd(fd, "ooxml_hwp.xml", NULL, CLAMAV_MIN_XMLREADER_FLAGS);
    if (reader == NULL) {
        cli_dbgmsg("ooxml_hwp_cb: xmlReaderForFd error\n");
        return CL_SUCCESS; // internal error from libxml2
    }

    ret = cli_msxml_parse_document(ctx, reader, ooxml_hwp_keys, num_ooxml_hwp_keys, MSXML_FLAG_JSON, NULL);

    if (ret != CL_SUCCESS && ret != CL_ETIMEOUT && ret != CL_BREAK)
        cli_warnmsg("ooxml_hwp_cb: encountered issue in parsing properties document\n");

    xmlTextReaderClose(reader);
    xmlFreeTextReader(reader);
    return ret;
}

#endif /* HAVE_LIBXML2 && HAVE_JSON */

int cli_ooxml_filetype(cli_ctx *ctx, fmap_t *map)
{
    struct zip_requests requests;
    int ret;

    memset(&requests, 0, sizeof(struct zip_requests));

    if ((ret = unzip_search_add(&requests, "xl/", 3)) != CL_SUCCESS) {
        return CL_SUCCESS;
    }
    if ((ret = unzip_search_add(&requests, "ppt/", 4)) != CL_SUCCESS) {
        return CL_SUCCESS;
    }
    if ((ret = unzip_search_add(&requests, "word/", 5)) != CL_SUCCESS) {
        return CL_SUCCESS;
    }
    if ((ret = unzip_search_add(&requests, "Contents/content.hpf", 22)) != CL_SUCCESS) {
        return CL_SUCCESS;
    }

    if ((ret = unzip_search(ctx, map, &requests)) == CL_VIRUS) {
        switch (requests.found) {
        case 0:
            return CL_TYPE_OOXML_XL;
        case 1:
            return CL_TYPE_OOXML_PPT;
        case 2:
            return CL_TYPE_OOXML_WORD;
        case 3:
            return CL_TYPE_OOXML_HWP;
        default:
            return CL_SUCCESS;
        }
    }

    return CL_SUCCESS;
}

int cli_process_ooxml(cli_ctx *ctx, int type)
{
#if HAVE_LIBXML2 && HAVE_JSON
    uint32_t loff = 0;
    int ret = CL_SUCCESS;

    cli_dbgmsg("in cli_process_ooxml\n");
    if (!ctx) {
        return CL_ENULLARG;
    }

    if (type == CL_TYPE_OOXML_HWP) {
        /* two files: version.xml and Contents/content.hpf */
        ret = unzip_search_single(ctx, "version.xml", 11, &loff);
        if (ret == CL_ETIMEOUT) {
            cli_json_parse_error(ctx->wrkproperty, "OOXML_ERROR_TIMEOUT");
            return CL_ETIMEOUT;
        }
        else if (ret != CL_VIRUS) {
            cli_dbgmsg("cli_process_ooxml: failed to find ""version.xml""!\n");
            cli_json_parse_error(ctx->wrkproperty, "OOXML_ERROR_NO_HWP_VERSION");
            return CL_EFORMAT;
        }
        ret = unzip_single_internal(ctx, loff, ooxml_hwp_cb);

        if (ret == CL_SUCCESS) {
            ret = unzip_search_single(ctx, "Contents/content.hpf", 20, &loff);
            if (ret == CL_ETIMEOUT) {
                cli_json_parse_error(ctx->wrkproperty, "OOXML_ERROR_TIMEOUT");
                return CL_ETIMEOUT;
            }
            else if (ret != CL_VIRUS) {
                cli_dbgmsg("cli_process_ooxml: failed to find ""Contents/content.hpf""!\n");
                cli_json_parse_error(ctx->wrkproperty, "OOXML_ERROR_NO_HWP_CONTENT");
                return CL_EFORMAT;
            }
            ret = unzip_single_internal(ctx, loff, ooxml_hwp_cb);
        }
    } else {
        /* find "[Content Types].xml" */
        ret = unzip_search_single(ctx, "[Content_Types].xml", 19, &loff);
        if (ret == CL_ETIMEOUT) {
            cli_json_parse_error(ctx->wrkproperty, "OOXML_ERROR_TIMEOUT");
            return CL_ETIMEOUT;
        }
        else if (ret != CL_VIRUS) {
            cli_dbgmsg("cli_process_ooxml: failed to find ""[Content_Types].xml""!\n");
            cli_json_parse_error(ctx->wrkproperty, "OOXML_ERROR_NO_CONTENT_TYPES");
            return CL_EFORMAT;
        }
        cli_dbgmsg("cli_process_ooxml: found ""[Content_Types].xml"" @ %x\n", loff);

        ret = unzip_single_internal(ctx, loff, ooxml_content_cb);
    }

    if (ret == CL_ETIMEOUT)
        cli_json_parse_error(ctx->wrkproperty, "OOXML_ERROR_TIMEOUT");
    else if (ret == CL_EMEM)
        cli_json_parse_error(ctx->wrkproperty, "OOXML_ERROR_OUTOFMEM");
    else if (ret == CL_EMAXSIZE)
        cli_json_parse_error(ctx->wrkproperty, "OOXML_ERROR_EMAXSIZE");
    else if (ret == CL_EMAXFILES)
        cli_json_parse_error(ctx->wrkproperty, "OOXML_ERROR_EMAXFILES");

    return ret;
#else
    UNUSEDPARAM(ctx);
    cli_dbgmsg("in cli_process_ooxml\n");
#if !HAVE_LIBXML2
    cli_dbgmsg("cli_process_ooxml: libxml2 needs to enabled!\n");
#endif
#if !HAVE_JSON
    cli_dbgmsg("cli_process_ooxml: libjson needs to enabled!\n");
#endif
    return CL_SUCCESS;
#endif
}

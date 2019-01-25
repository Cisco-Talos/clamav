/*
 *  Copyright (C) 2014-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *
 *  Authors: Steven Morgan <smorgan@sourcefire.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA 02110-1301, USA.
 */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif
#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <errno.h>
#include <string.h>

#include "clamav.h"
#include "others.h"
#include "openioc.h"

#ifdef HAVE_LIBXML2
#include <libxml/xmlreader.h>

struct openioc_hash {
    unsigned char * hash;
    void * next;
};

static const xmlChar * openioc_read(xmlTextReaderPtr reader)
{
    const xmlChar * name;
    if (xmlTextReaderRead(reader) != 1)
        return NULL;
    name = xmlTextReaderConstLocalName(reader);
    if (name != NULL) {
        cli_dbgmsg("openioc_parse: xmlTextReaderRead read %s%s\n", name,
                   xmlTextReaderNodeType(reader) == XML_READER_TYPE_END_ELEMENT?" end tag":"");
    }
    return name;   
}


static int openioc_is_context_hash(xmlTextReaderPtr reader)
{
    xmlChar * document = xmlTextReaderGetAttribute(reader, (const xmlChar *)"document");
    xmlChar * search = xmlTextReaderGetAttribute(reader, (const xmlChar *)"search");
    int rc = 0;

    if ((document != NULL && search != NULL) &&
        !xmlStrcmp(document, (const xmlChar *)"FileItem") &&
        (!xmlStrcmp(search, (const xmlChar *)"FileItem/Md5sum") ||
         !xmlStrcmp(search, (const xmlChar *)"FileItem/Sha1sum") ||
         !xmlStrcmp(search, (const xmlChar *)"FileItem/Sha256sum")))
        rc = 1;
    if (document != NULL)
        xmlFree(document);
    if (search != NULL)
        xmlFree(search);
    return rc;
}

static int openioc_parse_content(xmlTextReaderPtr reader, struct openioc_hash ** elems, int context_hash)
{
    const xmlChar * xmlval;
    struct openioc_hash * elem;
    int rc = CL_SUCCESS;

    if (context_hash == 0) {
        xmlChar * type = xmlTextReaderGetAttribute(reader, (const xmlChar *)"type");
        if (type == NULL) {
            cli_dbgmsg("openioc_parse: xmlTextReaderGetAttribute no type attribute "
                       "for <Content> element\n");
            return rc;
        } else { 
            if (xmlStrcasecmp(type, (const xmlChar *)"sha1") &&
                xmlStrcasecmp(type, (const xmlChar *)"sha256") &&
                xmlStrcasecmp(type, (const xmlChar *)"md5")) {
                xmlFree(type);
                return rc;
            }
        }
        xmlFree(type);
    }
    
    if (xmlTextReaderRead(reader) == 1 && xmlTextReaderNodeType(reader) == XML_READER_TYPE_TEXT) {
        xmlval = xmlTextReaderConstValue(reader);
        if (xmlval) {
            elem = cli_calloc(1, sizeof(struct openioc_hash));
            if (NULL == elem) {
                cli_dbgmsg("openioc_parse: calloc fails for openioc_hash.\n");
                return CL_EMEM;
            }
            elem->hash = xmlStrdup(xmlval);
            elem->next = *elems;
            *elems = elem; 
        } else {
            cli_dbgmsg("openioc_parse: xmlTextReaderConstValue() returns NULL for Content md5 value.\n");           
        }
    }
    else {
        cli_dbgmsg("openioc_parse: No text for XML Content element.\n");
    }
    return rc;
}

static int openioc_parse_indicatoritem(xmlTextReaderPtr reader, struct openioc_hash ** elems)
{
    const xmlChar * name;
    int rc = CL_SUCCESS;
    int context_hash = 0;

    while (1) {
        name = openioc_read(reader);
        if (name == NULL)
            break;
        if (xmlStrEqual(name, (const xmlChar *)"Context") && 
            xmlTextReaderNodeType(reader) == XML_READER_TYPE_ELEMENT) {
            context_hash = openioc_is_context_hash(reader);
        } else if (xmlStrEqual(name, (const xmlChar *)"Content") && 
            xmlTextReaderNodeType(reader) == XML_READER_TYPE_ELEMENT) {
            rc = openioc_parse_content(reader, elems, context_hash);
            if (rc != CL_SUCCESS) {
                break;
            }
        } else if (xmlStrEqual(name, (const xmlChar *)"IndicatorItem") &&
                   xmlTextReaderNodeType(reader) == XML_READER_TYPE_END_ELEMENT) {
            break;
        }
    }
    return rc;
}

static int openioc_parse_indicator(xmlTextReaderPtr reader, struct openioc_hash ** elems)
{
    const xmlChar * name;
    int rc = CL_SUCCESS;

    while (1) {
        name = openioc_read(reader);
        if (name == NULL)
            return rc;
        if (xmlStrEqual(name, (const xmlChar *)"Indicator") && 
            xmlTextReaderNodeType(reader) == XML_READER_TYPE_ELEMENT) {
            rc = openioc_parse_indicator(reader, elems);
            if (rc != CL_SUCCESS) {
                cli_dbgmsg("openioc_parse: openioc_parse_indicator recursion error.\n");
                break;
            }
        } else if (xmlStrEqual(name, (const xmlChar *)"IndicatorItem") && 
            xmlTextReaderNodeType(reader) == XML_READER_TYPE_ELEMENT) {
            rc = openioc_parse_indicatoritem(reader, elems);
            if (rc != CL_SUCCESS) {
                break;
            }
        } else if (xmlStrEqual(name, (const xmlChar *)"Indicator") &&
                   xmlTextReaderNodeType(reader) == XML_READER_TYPE_END_ELEMENT) {
            break;
        }
    }
    return rc;
}

int openioc_parse(const char * fname, int fd, struct cl_engine *engine, unsigned int options)
{
    int rc;
    xmlTextReaderPtr reader = NULL;
    const xmlChar * name;
    struct openioc_hash * elems = NULL, * elem = NULL;
    const char * iocp = NULL;
    uint16_t ioclen;
    char * virusname;
    int hash_count = 0;
    
    if (fname == NULL)
        return CL_ENULLARG;

    if (fd < 0)
        return CL_EARG;

    cli_dbgmsg("openioc_parse: XML parsing file %s\n", fname);

    reader = xmlReaderForFd(fd, NULL, NULL, CLAMAV_MIN_XMLREADER_FLAGS);
    if (reader == NULL) {
        cli_dbgmsg("openioc_parse: xmlReaderForFd error\n");
        return CL_EOPEN;
    }
    rc = xmlTextReaderRead(reader);
    while (rc == 1) {
        name = xmlTextReaderConstLocalName(reader);
        cli_dbgmsg("openioc_parse: xmlTextReaderRead read %s\n", name);
        if (xmlStrEqual(name, (const xmlChar *)"Indicator") && 
            xmlTextReaderNodeType(reader) == XML_READER_TYPE_ELEMENT) {
            rc = openioc_parse_indicator(reader, &elems);
            if (rc != CL_SUCCESS) {
                xmlTextReaderClose(reader);
                xmlFreeTextReader(reader);
                return rc;
            }
        }
        if (xmlStrEqual(name, (const xmlChar *)"ioc") &&
            xmlTextReaderNodeType(reader) == XML_READER_TYPE_END_ELEMENT) {
            break;
        }
        rc = xmlTextReaderRead(reader);
    }

    iocp = strrchr(fname, *PATHSEP);

    if (NULL == iocp)
        iocp = fname;
    else
        iocp++;

    ioclen = (uint16_t)strlen(fname);

    if (elems != NULL) {
        if (NULL == engine->hm_hdb) {
            engine->hm_hdb = mpool_calloc(engine->mempool, 1, sizeof(struct cli_matcher));
            if (NULL == engine->hm_hdb) {            
                xmlTextReaderClose(reader);
                xmlFreeTextReader(reader);
                return CL_EMEM;
            }
#ifdef USE_MPOOL
            engine->hm_hdb->mempool = engine->mempool;
#endif
        }
    }

    while (elems != NULL) {
        const char * sp;
        char * hash, * vp;
        int i, hashlen;

        elem = elems;
        elems = elems->next;
        hash = (char *)(elem->hash);
        while (isspace(*hash))
            hash++;
        hashlen = strlen(hash);
        if (hashlen == 0) {
            xmlFree(elem->hash);
            free(elem);
            continue;
        }
        vp = hash+hashlen-1;
        while (isspace(*vp) && vp > hash) {
            *vp-- = '\0';
            hashlen--;
        }
        virusname = calloc(1, ioclen+hashlen+2);
        if (NULL == virusname) {
            cli_dbgmsg("openioc_parse: mpool_malloc for virname memory failed.\n");
            xmlTextReaderClose(reader);
            xmlFreeTextReader(reader);
            return CL_EMEM;
        }
        sp = fname;
        vp = virusname;
        for (i=0; i<ioclen; i++, sp++, vp++) {
            switch (*sp) {
            case '\\':
            case '/':
            case '?':
            case '%':
            case '*':
            case ':':
            case '|':
            case '"':
            case '<':
            case '>':
                *vp = '_';
                break;
            default:
                if (isspace(*sp))
                    *vp = '_';
                else
                    *vp = *sp;
            }
        }
        *vp++ = '.';
        sp = hash;
        for (i=0; i<hashlen; i++, sp++) {
            if (isxdigit(*sp)) {
                *vp++ = *sp;
            }
        }

        vp = virusname;
        virusname = cli_mpool_virname(engine->mempool, virusname, options & CL_DB_OFFICIAL);
        if (!(virusname)) {
            cli_dbgmsg("openioc_parse: mpool_malloc for virname memory failed.\n");
            xmlTextReaderClose(reader);
            xmlFreeTextReader(reader);
            free(vp);
            return CL_EMEM;
        }

        free(vp);

        rc = hm_addhash_str(engine->hm_hdb, hash, 0, virusname);
        if (rc != CL_SUCCESS)
            cli_dbgmsg("openioc_parse: hm_addhash_str failed with %i hash len %i for %s.\n",
                       rc, hashlen, virusname);
        else
            hash_count++;

        xmlFree(elem->hash);
        free(elem);
    }

    if (hash_count == 0)
        cli_warnmsg("openioc_parse: No hash signatures extracted from %s.\n", fname);
    else
        cli_dbgmsg("openioc_parse: %i hash signature%s extracted from %s.\n",
                   hash_count, hash_count==1?"":"s", fname);

    xmlTextReaderClose(reader);
    xmlFreeTextReader(reader);

    return CL_SUCCESS;
}
#else
int openioc_parse(const char * fname, int fd, struct cl_engine *engine, unsigned int options)
{
    cli_dbgmsg("openioc_parse: libxml2 support is compiled out and is needed for OpenIOC support.\n");
    return CL_SUCCESS;
}
#endif

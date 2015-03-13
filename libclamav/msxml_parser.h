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

#ifndef __MSXML_PARSER_H
#define __MSXML_PARSER_H

#if HAVE_LIBXML2

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include "others.h"
#include "json_api.h"

#ifdef _WIN32
#ifndef LIBXML_WRITER_ENABLED
#define LIBXML_WRITER_ENABLED 1
#endif
#endif
#include <libxml/xmlreader.h>


#define MSXML_RECLEVEL_MAX 20
#define MSXML_JSON_STRLEN_MAX 128

struct key_entry {
/* how */
#define MSXML_IGNORE       0x00
#define MSXML_IGNORE_ELEM  0x01
#define MSXML_SCAN_B64     0x02
/* where */
#define MSXML_JSON_ROOT    0x04
#define MSXML_JSON_WRKPTR  0x08

#define MSXML_JSON_TRACK (MSXML_JSON_ROOT | MSXML_JSON_WRKPTR)
/* what */
#define MSXML_JSON_COUNT   0x10
#define MSXML_JSON_VALUE   0x20
#define MSXML_JSON_ATTRIB  0x40

    const char *key;
    const char *name;
    int type;
};

struct msxml_ctx {
    cli_ctx *ctx;
    const struct key_entry *keys;
    size_t num_keys;

#if HAVE_JSON
    json_object *root;
    int mode, toval;
#endif
};

int cli_msxml_parse_document(cli_ctx *ctx, xmlTextReaderPtr reader, const struct key_entry *keys, const size_t num_keys, int mode);

#endif /* HAVE_LIBXML2 */

#endif /* __MSXML_PARSER_H */

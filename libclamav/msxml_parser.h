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

#ifndef __MSXML_PARSER_H
#define __MSXML_PARSER_H

#if HAVE_LIBXML2

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include "others.h"

#ifdef _WIN32
#ifndef LIBXML_WRITER_ENABLED
#define LIBXML_WRITER_ENABLED 1
#endif
#endif
#include <libxml/xmlreader.h>


#define MSXML_RECLEVEL_MAX 20
#define MSXML_JSON_STRLEN_MAX 128

/* reader usage flags */
#define MSXML_FLAG_JSON  0x1
#define MSXML_FLAG_WALK  0x2

struct msxml_ictx;

struct attrib_entry {
    const char *key;
    const char *value;
};

struct key_entry {
/* how */
#define MSXML_IGNORE          0x0
#define MSXML_IGNORE_ELEM     0x1
#define MSXML_SCAN_CB         0x2
#define MSXML_SCAN_B64        0x4
#define MSXML_COMMENT_CB      0x8
/* where */
#define MSXML_JSON_ROOT       0x10
#define MSXML_JSON_WRKPTR     0x20
#define MSXML_JSON_MULTI      0x40

#define MSXML_JSON_TRACK (MSXML_JSON_ROOT | MSXML_JSON_WRKPTR)
/* what */
#define MSXML_JSON_COUNT      0x100
#define MSXML_JSON_VALUE      0x200
#define MSXML_JSON_ATTRIB     0x400

    const char *key;
    const char *name;
    uint32_t type;
};

typedef int (*msxml_scan_cb)(int fd, const char *filepath, cli_ctx *ctx, int num_attribs, struct attrib_entry *attribs, void *cbdata);
typedef int (*msxml_comment_cb)(const char *comment, cli_ctx *ctx, void *wrkjobj, void *cbdata);

struct msxml_ctx {
    msxml_scan_cb scan_cb;
    void *scan_data;
    msxml_comment_cb comment_cb;
    void *comment_data;
    struct msxml_ictx *ictx;
};

int cli_msxml_parse_document(cli_ctx *ctx, xmlTextReaderPtr reader, const struct key_entry *keys, const size_t num_keys, uint32_t flags, struct msxml_ctx *mxctx);

#endif /* HAVE_LIBXML2 */

#endif /* __MSXML_PARSER_H */

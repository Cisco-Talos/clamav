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

#include "clamav.h"
#include "others.h"
#include "json_api.h"
#include "msxml.h"

#if HAVE_LIBXML2
#ifdef _WIN32
#ifndef LIBXML_WRITER_ENABLED
#define LIBXML_WRITER_ENABLED 1
#endif
#endif
#include <libxml/xmlreader.h>
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


int cli_scanmsxml(cli_ctx *ctx)
{
#if HAVE_LIBXML2
    const unsigned char *buffer;
    xmlTextReaderPtr reader = NULL;
    int state, ret = CL_SUCCESS;

    cli_dbgmsg("in cli_scanmsxml()\n");

    buffer = (unsigned char *)fmap_need_off_once(*ctx->fmap, 0, (*ctx->fmap)->len);
    if (!buffer) {
        cli_errmsg("cli_scanmsxml: cannot read in input file for buffer\n");
        return CL_EREAD;
    }

    reader = xmlReaderForMemory(buffer, (*ctx->fmap)->len, "msxml.xml", NULL, CLAMAV_MIN_XMLREADER_FLAGS);
    if (!reader) {
        cli_dbgmsg("cli_scanmsxml: cannot intialize xmlReaderForMemory\n");
        return CL_SUCCESS; // libxml2 failed!
    }

    /* Main Processing Loop */
    while ((state = xmlTextReaderRead(reader)) == 1) {

    }

    return ret;
#else
    UNUSEDPARAM(ctx);
    cli_dbgmsg("in cli_scanmsxml()\n");
    cli_dbgmsg("cli_scanmsxml: libxml2 needs to enabled!");

    return CL_SUCCESS;
#endif
}

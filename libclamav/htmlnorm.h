/*
 *  Copyright (C) 2013-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *
 *  Authors: Trog
 *
 *  Summary: Normalise HTML text. Decode MS Script Encoder protection.
 *           The ScrEnc decoder was initially based upon an analysis by Andreas Marx.
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

#ifndef __HTMLNORM_H
#define __HTMLNORM_H

#include "clamav-types.h"
#include "fmap.h"
#include "dconf.h"
#include "others.h"

typedef struct tag_arguments_tag {
    int count;
    int scanContents;
    unsigned char **tag;
    unsigned char **value;
    unsigned char **contents;
} tag_arguments_t;

typedef struct m_area_tag {
    unsigned char *buffer;
    off_t length;
    off_t offset;
    fmap_t *map;
} m_area_t;

typedef struct form_data_tag {
    char **urls;
    size_t count;
} form_data_t;

bool html_normalise_mem(cli_ctx *ctx, unsigned char *in_buff, off_t in_size, const char *dirname, tag_arguments_t *hrefs, const struct cli_dconf *dconf);
bool html_normalise_mem_form_data(cli_ctx *ctx, unsigned char *in_buff, off_t in_size, const char *dirname, tag_arguments_t *hrefs, const struct cli_dconf *dconf, form_data_t *form_data);
bool html_normalise_map(cli_ctx *ctx, fmap_t *map, const char *dirname, tag_arguments_t *hrefs, const struct cli_dconf *dconf);
bool html_normalise_map_form_data(cli_ctx *ctx, fmap_t *map, const char *dirname, tag_arguments_t *hrefs, const struct cli_dconf *dconf, form_data_t *form_data);
void html_tag_arg_free(tag_arguments_t *tags);
bool html_screnc_decode(fmap_t *map, const char *dirname);
void html_tag_arg_add(tag_arguments_t *tags, const char *tag, char *value);

void html_form_data_tag_free(form_data_t *tags);

#endif

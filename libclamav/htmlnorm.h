/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
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

typedef struct tag_arguments_tag
{
    int count;
    int scanContents;
    unsigned char **tag;
    unsigned char **value;
    unsigned char **contents;
} tag_arguments_t;

typedef struct m_area_tag
{
    unsigned char *buffer;
    off_t length;
    off_t offset;
    fmap_t *map;
} m_area_t;

int html_normalise_mem(unsigned char *in_buff, off_t in_size, const char *dirname, tag_arguments_t *hrefs, const struct cli_dconf *dconf);
int html_normalise_map(fmap_t *map, const char *dirname, tag_arguments_t *hrefs, const struct cli_dconf *dconf);
void html_tag_arg_free(tag_arguments_t *tags);
int html_screnc_decode(fmap_t *map, const char *dirname);
void html_tag_arg_add(tag_arguments_t *tags, const char *tag, char *value);

#endif

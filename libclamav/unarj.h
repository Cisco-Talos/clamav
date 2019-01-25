/*
 *  Extract component parts of ARJ archives
 *
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *
 *  Authors: Nigel Horne
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

#ifndef __UNARJ_H
#define __UNARJ_H

#include "fmap.h"
typedef struct arj_metadata_tag {
	char *filename;
	uint32_t comp_size;
	uint32_t orig_size;
	int encrypted;
	int ofd;
	uint8_t method;
	fmap_t *map;
	size_t offset;
} arj_metadata_t;

int cli_unarj_open(fmap_t *map, const char *dirname, arj_metadata_t *metadata, size_t off);
int cli_unarj_prepare_file(const char *dirname, arj_metadata_t *metadata);
int cli_unarj_extract_file(const char *dirname, arj_metadata_t *metadata);

#endif

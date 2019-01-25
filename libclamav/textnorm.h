/*
 *  Generic text normalizer.
 *
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2008-2013 Sourcefire, Inc.
 *
 *  Authors: Török Edvin
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

#ifndef __TEXTNORM_H
#define __TEXTNORM_H

#include "fmap.h"

struct text_norm_state {
	unsigned char *out;
	size_t out_len;
	size_t out_pos;
	int space_written;
};

#define ASCII_FILE_BUFF_LENGTH 131072
#define MAX_ASCII_FILE_SIZE 20000000

#define MIN_3(x,y,z) ((x)<(y) ? ((x)<(z)?(x):(z)) : ((y)<(z)?(y):(z)))

int text_normalize_init(struct text_norm_state *state, unsigned char *out, size_t out_len);
void text_normalize_reset(struct text_norm_state* state);
size_t text_normalize_buffer(struct text_norm_state *state, const unsigned char *buf, const size_t buf_len);
size_t text_normalize_map(struct text_norm_state *state, fmap_t *map, size_t offset);

#endif

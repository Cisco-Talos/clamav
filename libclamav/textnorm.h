/*
 *  Generic text normalizer.
 *
 *  Copyright (C) 2008 Sourcefire, Inc.
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

struct text_norm_state {
	unsigned char *out;
	size_t out_len;
	size_t out_pos;
	int space_written;
};

int text_normalize_init(struct text_norm_state *state, unsigned char *out, size_t out_len);
void text_normalize_reset(struct text_norm_state* state);
size_t text_normalize_buffer(struct text_norm_state *state, const unsigned char *buf, const size_t buf_len);

/*
 *  Copyright (C) 2006 Michal 'GiM' Spadlinski http://gim.org.pl/
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
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

#ifndef __MEW_H
#define __MEW_H

struct lzmastate {
	char *p0;
	uint32_t p1, p2;
};

int mew_lzma(struct pe_image_section_hdr *, char *, char *, uint32_t, uint32_t, uint32_t);

uint32_t lzma_upack_esi_00(struct lzmastate *, char *, char *, uint32_t);
uint32_t lzma_upack_esi_50(struct lzmastate *, uint32_t, uint32_t, char **, char *, uint32_t *, char *, uint32_t);
uint32_t lzma_upack_esi_54(struct lzmastate *, uint32_t, uint32_t *, char **, uint32_t *, char *, uint32_t);

#endif





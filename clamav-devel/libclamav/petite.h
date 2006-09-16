/*
 *  Copyright (C) 2004 aCaB <acab@clamav.net>
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

#ifndef __PETITE_H
#define __PETITE_H

#include "cltypes.h"
#include "pe.h"

int petite_inflate2x_1to9(char *buf, uint32_t minrva, uint32_t bufsz, struct pe_image_section_hdr *sections, unsigned int sectcount, uint32_t Imagebase, uint32_t pep, int desc, int version, uint32_t ResRva, uint32_t ResSize);

#endif

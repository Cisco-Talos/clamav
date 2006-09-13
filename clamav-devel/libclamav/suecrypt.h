/*
 *  Copyright (C) 2006 aCaB <acab@clamav.net>
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

#ifdef CL_EXPERIMENTAL
#ifndef __UNSUE_H
#define __UNSUE_H

#include "cltypes.h"
#include "rebuildpe.h"

char *sudecrypt(int, size_t, struct pe_image_section_hdr *, uint16_t, char *, uint32_t, uint32_t, uint32_t);

#endif
#endif

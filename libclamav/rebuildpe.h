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
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifndef __REBUILDPE_H
#define __REBUILDPE_H

#include "cltypes.h"

struct SECTION {
    uint32_t rva;
    uint32_t vsz;
    uint32_t raw;
    uint32_t rsz;
};

char *rebuildpe(char *buffer, struct SECTION *sections, int sects, uint32_t base, uint32_t ep, uint32_t ResRva, uint32_t ResSize);

#endif

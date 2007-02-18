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

#ifndef __UPX_H
#define __UPX_H

#include "cltypes.h"

int upx_inflate2b(char *, uint32_t, char *, uint32_t *, uint32_t, uint32_t, uint32_t);
int upx_inflate2d(char *, uint32_t, char *, uint32_t *, uint32_t, uint32_t, uint32_t);
int upx_inflate2e(char *, uint32_t, char *, uint32_t *, uint32_t, uint32_t, uint32_t);

#endif

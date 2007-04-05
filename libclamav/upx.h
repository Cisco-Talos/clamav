/*
 *  Copyright (C) 2004 aCaB <acab@clamav.net>
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

#ifndef __UPX_H
#define __UPX_H

#include "cltypes.h"

int upx_inflate2b(char *, uint32_t, char *, uint32_t *, uint32_t, uint32_t, uint32_t);
int upx_inflate2d(char *, uint32_t, char *, uint32_t *, uint32_t, uint32_t, uint32_t);
int upx_inflate2e(char *, uint32_t, char *, uint32_t *, uint32_t, uint32_t, uint32_t);

#endif

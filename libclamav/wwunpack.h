/*
 *  Copyright (C) 2006 Sensory Networks, Inc.
 *             Written by aCaB <acab@clamav.net>
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

#ifndef __WWP32_H
#define __WWP32_H

#include "cltypes.h"
#include "rebuildpe.h"

int wwunpack(char *, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, char *, uint32_t, uint16_t);

#endif

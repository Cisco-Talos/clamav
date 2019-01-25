/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *
 *  Authors: Alberto Wu
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

#include "clamav-types.h"

int upx_inflate2b(const char *, uint32_t, char *, uint32_t *, uint32_t, uint32_t, uint32_t);
int upx_inflate2d(const char *, uint32_t, char *, uint32_t *, uint32_t, uint32_t, uint32_t);
int upx_inflate2e(const char *, uint32_t, char *, uint32_t *, uint32_t, uint32_t, uint32_t);
int upx_inflatelzma(const char *, uint32_t, char *, uint32_t *, uint32_t, uint32_t, uint32_t, uint32_t);

#endif

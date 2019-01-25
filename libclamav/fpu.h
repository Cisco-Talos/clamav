/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2013 Sourcefire, Inc.
 *
 *  Authors: Steven Morgan <smorgan@sourcefire.com>
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

#ifndef __FPU_H
#define __FPU_H

#define FPU_ENDIAN_INITME	0
#define FPU_ENDIAN_BIG		1
#define FPU_ENDIAN_LITTLE	2
#define FPU_ENDIAN_UNKNOWN	3

/* get_fpu_endian() - identify float point byteorder
 * Parameters - none
 * Returns:
 *   FPU_ENDIAN_BIG - floating point big endian
 *   FPU_ENDIAN_LITTLE - floating point little endian
 *   FPU_ENDIAN_UNKNOWN - floating point endianness unknown
 */
extern int get_fpu_endian(void);

#endif

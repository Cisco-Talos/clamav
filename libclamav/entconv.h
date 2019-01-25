/*
 *  HTML Entity & Encoding normalization.
 *
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
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

#ifndef _ENTITIES_H
#define _ENTITIES_H

#include "clamav-types.h"

#include "hashtab.h"

#define UCS4_1234 "UCS-4BE"
#define UCS4_4321 "UCS-4LE"
#define UCS4_2143 "UCS4"
#define UCS4_3412 "UCS-4"
#define UTF16_BE "UTF-16BE"
#define UTF16_LE "UTF-16LE"
#define UTF8     "UTF-8"
#define UNDECIDED_32_1234 UCS4_1234
#define UNDECIDED_32_4321 UCS4_4321
#define UNDECIDED_32_2143 UCS4_2143
#define UNDECIDED_32_3412 UCS4_3412
#define UNDECIDED_16_BE UTF16_BE
#define UNDECIDED_16_LE UTF16_LE
#define UNDECIDED_8 "ISO-8859-1"

#define MAX_ENTITY_SIZE 22

struct entity_conv {
	unsigned char entity_buff[MAX_ENTITY_SIZE+2];
};

enum encodings {E_UCS4,E_UTF16,E_UCS4_1234,E_UCS4_4321,E_UCS4_2143,E_UCS4_3412,E_UTF16_BE,E_UTF16_LE,E_UTF8, E_UNKNOWN,E_OTHER};

unsigned char* u16_normalize_tobuffer(uint16_t u16, unsigned char* dst, size_t dst_size);
const char* entity_norm(struct entity_conv* conv,const unsigned char* entity);
const char* encoding_detect_bom(const unsigned char* bom, const size_t length);
int encoding_normalize_toascii(const m_area_t* in_m_area, const char* initial_encoding, m_area_t* out_m_area);

#endif


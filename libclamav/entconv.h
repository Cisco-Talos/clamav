/*
 *  HTML Entity & Encoding normalization.
 *
 *  Copyright (C) 2006 Török Edvin <edwin@clamav.net>
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
 *
 */

#ifndef _ENTITIES_H
#define _ENTITIES_H
#include "cltypes.h"

#include "hashtab.h"

#define UCS4_1234 (const unsigned char*)"UCS-4LE"
#define UCS4_4321 (const unsigned char*)"UCS-4BE"
#define UCS4_2143 (const unsigned char*)"UCS4"
#define UCS4_3412 (const unsigned char*)"UCS-4"
#define UTF16_BE (const unsigned char*)"UTF-16BE"
#define UTF16_LE (const unsigned char*)"UTF-16LE"
#define UTF8     (const unsigned char*)"UTF-8"
#define UNDECIDED_32_1234 UCS4_1234
#define UNDECIDED_32_4321 UCS4_4321
#define UNDECIDED_32_2143 UCS4_2143
#define UNDECIDED_32_3412 UCS4_3412
#define UNDECIDED_16_BE UTF16_BE
#define UNDECIDED_16_LE UTF16_LE
#define UNDECIDED_8 (const unsigned char*)"ISO-8859-1"
#define EBCDIC (const unsigned char*)"EBCDIC-US"
#define UNKNOWN (const unsigned char*)"\0"
#define OTHER   (const unsigned char*)"OTHER"

enum encoding_priority {NOPRIO,CONTENT_TYPE,BOM,NOBOM_AUTODETECT,XML_CHARSET,META};

enum encodings {E_UCS4,E_UTF16,E_UCS4_1234,E_UCS4_4321,E_UCS4_2134,E_UCS4_3412,E_UTF16_BE,E_UTF16_LE,E_UTF8,E_UNKNOWN,E_OTHER};
#define MAX_ENTITY_SIZE 22

struct entity_conv {
	unsigned char* encoding;
	const unsigned char* autodetected;
	enum encoding_priority priority;
	unsigned short int encoding_specific;/* sub-encoding, used for ISO*/
	const struct hashtable* ht;
	uint8_t has_bom;
	uint8_t enc_bytes;
	uint8_t bytes_read;
	uint8_t  bom_cnt;
	uint32_t partial;
	unsigned char bom[4];
#if 0	
	char* buffer;
	char* buffer2;
#endif	
	size_t buffer_size;
	size_t buffer_cnt;
	uint8_t entity_buffcnt;
	char entity_buff[MAX_ENTITY_SIZE+2];
	m_area_t tmp_area;
	m_area_t out_area;
	m_area_t norm_area;
	int      msg_zero_shown;
};


int init_entity_converter(struct entity_conv* conv,const unsigned char* encoding,size_t buffer_size);
void process_encoding_set(struct entity_conv* conv,const unsigned char* encoding,enum encoding_priority priority);
int entity_norm_done(struct entity_conv* conv);

unsigned char* encoding_norm_readline(struct entity_conv* conv, FILE* stream_in, m_area_t* in_m_area, const size_t maxlen);
unsigned char* entity_norm(const struct entity_conv* conv,const unsigned char* entity);
int entitynorm_init(void);

#endif


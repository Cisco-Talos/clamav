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
#ifndef _ENCODING_ALIASES_H
#define _ENCODING_ALIASES_H
#include "clamav-config.h"


#include <stdio.h>
#include "hashtab.h"

/* don't change the order of keys, instead use generate_encoding_aliases in contrib/entitynorm.
 * You can safely change the values (on the right) */
static struct element aliases_htable_elements[] = {
	{NULL, 0},
	{NULL, 0},
	{NULL, 0},
	{(const unsigned char*)"UTF8", 8},
	{(const unsigned char*)"ISO-10646/UTF-8", 8},
	{NULL, 0},
	{(const unsigned char*)"UTF-16", 1},
	{(const unsigned char*)"UTF16LE", 7},
	{NULL, 0},
	{(const unsigned char*)"UTF-32", 0},
	{(const unsigned char*)"10646-1:1993/UCS4", 0},
	{NULL, 0},
	{(const unsigned char*)"UTF-16LE", 7},
	{NULL, 0},
	{NULL, 0},
	{NULL, 0},
	{(const unsigned char*)"UCS-4LE", 2},
	{(const unsigned char*)"UCS-4", 0},
	{(const unsigned char*)"UCS2", 1},
	{(const unsigned char*)"UTF-16BE", 6},
	{NULL, 0},
	{(const unsigned char*)"UTF-32LE", 2},
	{NULL, 0},
	{(const unsigned char*)"UTF16BE", 6},
	{(const unsigned char*)"UTF32", 0},
	{(const unsigned char*)"UTF-32BE", 3},
	{(const unsigned char*)"UTF32LE", 2},
	{NULL, 0},
	{NULL, 0},
	{NULL, 0},
	{NULL, 0},
	{NULL, 0},
	{NULL, 0},
	{(const unsigned char*)"UCS-4BE", 3},
	{(const unsigned char*)"ISO-10646/UCS2", 1},
	{NULL, 0},
	{(const unsigned char*)"10646-1:1993", 0},
	{(const unsigned char*)"ISO-10646/UCS4", 0},
	{(const unsigned char*)"ISO-10646", 0},
	{(const unsigned char*)"UTF-8", 8},
	{(const unsigned char*)"UTF32BE", 3},
	{(const unsigned char*)"ISO-10646/UTF8", 8},
	{NULL, 0},
	{NULL, 0},
	{(const unsigned char*)"UCS4", 0},
	{NULL, 0},
	{NULL, 0},
	{NULL, 0},
	{NULL, 0},
	{NULL, 0},
	{NULL, 0},
	{NULL, 0},
	{NULL, 0},
};
const struct hashtable aliases_htable = {
	aliases_htable_elements, 53, 25, 42
};

#endif

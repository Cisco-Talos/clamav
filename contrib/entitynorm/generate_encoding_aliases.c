/*
 *  Copyright (C) 2006 Török Edvin <edwin@clamav.net>
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
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "../../libclamav/htmlnorm.h"
#include "../../libclamav/entconv.h"
#include "../../libclamav/hashtab.h"
#include <string.h>

static const struct {
	const char* alias;
	int   encoding;
} aliases [] = {
	{"UTF8",E_UTF8},
	{"UTF-8",E_UTF8},
	{"ISO-10646/UTF8",E_UTF8},
	{"ISO-10646/UTF-8",E_UTF8},
	{"ISO-10646",E_UCS4},
	{"10646-1:1993",E_UCS4},
	{"UCS4",E_UCS4},
	{"UCS-4",E_UCS4},
	{"UCS-4BE",E_UCS4_4321},
	{"UCS-4LE",E_UCS4_1234},
	{"ISO-10646/UCS4",E_UCS4},
	{"10646-1:1993/UCS4",E_UCS4},
	{"UCS2",E_UTF16},
	{"ISO-10646/UCS2",E_UTF16},
	{"UTF-16",E_UTF16},
	{"UTF-16BE",E_UTF16_BE},
	{"UTF-16LE",E_UTF16_LE},
	{"UTF16BE",E_UTF16_BE},
	{"UTF16LE",E_UTF16_LE},
	{"UTF32",E_UCS4},
	{"UTF32BE",E_UCS4_4321},
	{"UTF32LE",E_UCS4_1234},
	{"UTF-32",E_UCS4},
	{"UTF-32BE",E_UCS4_4321},
	{"UTF-32LE",E_UCS4_1234}
};

static const size_t aliases_cnt = sizeof(aliases)/sizeof(aliases[0]);
extern short cli_debug_flag;

int main(int argc, char* argv[])
{
	struct cli_hashtable ht;
	size_t i;

	cli_debug_flag=1;
	cli_hashtab_init(&ht,aliases_cnt);

	for(i=0;i < aliases_cnt;i++) {
		cli_hashtab_insert(&ht,(const unsigned char*)aliases[i].alias,strlen(aliases[i].alias),aliases[i].encoding);
	}

	cli_hashtab_generate_c(&ht,"aliases_htable");
	return 0;
}

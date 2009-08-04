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
#include <string.h>
#include <stdint.h>
#include "../../libclamav/hashtab.h"
#include <sys/types.h>
#include <dirent.h>

#define MAX_LINE 1024
/* ------------ generating entity tables from .ent files ---------------- */
static uint16_t* map_data = NULL;
static size_t map_data_n = 0;

static void loadEntities(struct cli_hashtable* s)
{
	char line[MAX_LINE];

	while( fgets(line, MAX_LINE, stdin)) {
		const char* name = line;
		char* mapto;
		size_t val;
		struct cli_element* elem;
		uint16_t converted;
		int found=0, i;

		mapto = strchr(line,',');
		if(!mapto) {
			fprintf(stderr,"Invalid line:%s\n",line);
			abort();
		}
		*mapto++ = '\0';

		mapto[strlen(mapto)-1] = '\0';
		if(elem = cli_hashtab_find(s,name,strlen(name))) {
			if(strlen(elem->key) == strlen(name)) {
				fprintf(stderr, "Duplicate entity:%s\n", name);
			}
			continue;
		}
		converted = atoi(mapto);
		cli_hashtab_insert(s,name,strlen(name), converted);
	}
}
extern short cli_debug_flag;

int main(int argc, char* argv[])
{
	struct cli_hashtable ht;
	int i;
	cli_debug_flag=1;
	cli_hashtab_init(&ht,2048);

	loadEntities(&ht);
	cli_hashtab_generate_c(&ht,"entities_htable");
	return 0;
}


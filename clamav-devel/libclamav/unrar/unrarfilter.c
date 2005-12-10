/*
 *  Extract RAR archives
 *
 *  Copyright (C) 2005 trog@uncon.org
 *
 *  This code is based on the work of Alexander L. Roshal
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

#include <unistd.h>

#include "unrar.h"
#include "unrarfilter.h"

void rar_filter_array_init(rar_filter_array_t *filter_a)
{
	filter_a->array = NULL;
	filter_a->num_items = 0;
}

void rar_filter_array_reset(rar_filter_array_t *filter_a)
{
	int i;
	
	if (!filter_a) {
		return;
	}
	for (i=0 ; i < filter_a->num_items ; i++) {
		rar_filter_delete(filter_a->array[i]);
	}
	if (filter_a->array) {
		free(filter_a->array);
	}
	filter_a->array = NULL;
	filter_a->num_items = 0;
}

int rar_filter_array_add(rar_filter_array_t *filter_a, int num)
{
	filter_a->num_items += num;
	filter_a->array = (struct UnpackFilter **) realloc(filter_a->array,
			filter_a->num_items * sizeof(struct UnpackFilter **));
	if (filter_a->array == NULL) {
		filter_a->num_items=0;
		return FALSE;
	}
	filter_a->array[filter_a->num_items-1] = NULL;
	return TRUE;
}

struct UnpackFilter *rar_filter_new(void)
{
	struct UnpackFilter *filter;
	
	filter = (struct UnpackFilter *) malloc(sizeof(struct UnpackFilter));
	if (!filter) {
		return NULL;
	}
	filter->block_start = 0;
  	filter->block_length = 0;
  	filter->exec_count = 0;
  	filter->next_window = 0;
  	
   	rar_cmd_array_init(&filter->prg.cmd);
	filter->prg.global_data = NULL;
	filter->prg.static_data = NULL;
	filter->prg.global_size = filter->prg.static_size = 0;
	filter->prg.filtered_data = NULL;
	filter->prg.filtered_data_size = 0;
  	return filter;
}

void rar_filter_delete(struct UnpackFilter *filter)
{
	if (!filter) {
		return;
	}
	if (filter->prg.global_data) {
		free(filter->prg.global_data);
	}
	if (filter->prg.static_data) {
		free(filter->prg.static_data);
	}
	rar_cmd_array_reset(&filter->prg.cmd);
	free(filter);
}

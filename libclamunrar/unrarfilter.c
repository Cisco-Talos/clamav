/*
 *  Extract RAR archives
 *
 *  Copyright (C) 2005 trog@uncon.org
 *
 *  This code is based on the work of Alexander L. Roshal (C)
 *
 *  The unRAR sources may be used in any software to handle RAR
 *  archives without limitations free of charge, but cannot be used
 *  to re-create the RAR compression algorithm, which is proprietary.
 *  Distribution of modified unRAR sources in separate form or as a
 *  part of other software is permitted, provided that it is clearly
 *  stated in the documentation and source comments that the code may
 *  not be used to develop a RAR (WinRAR) compatible archiver.
 */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#ifdef	HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "libclamunrar/unrar.h"
#include "libclamunrar/unrarfilter.h"

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
	filter_a->array = (struct UnpackFilter **) rar_realloc2(filter_a->array,
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
	
	filter = (struct UnpackFilter *) rar_malloc(sizeof(struct UnpackFilter));
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

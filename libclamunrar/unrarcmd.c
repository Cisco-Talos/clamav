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

#include <string.h>
#include <stdlib.h>

#include "libclamunrar/unrar.h"
#include "libclamunrar/unrarcmd.h"

void rar_cmd_array_init(rar_cmd_array_t *cmd_a)
{
	cmd_a->array = NULL;
	cmd_a->num_items = 0;
}

void rar_cmd_array_reset(rar_cmd_array_t *cmd_a)
{	
	if (!cmd_a) {
		return;
	}
	if (cmd_a->array) {
		free(cmd_a->array);
	}
	cmd_a->array = NULL;
	cmd_a->num_items = 0;
}

int rar_cmd_array_add(rar_cmd_array_t *cmd_a, int num)
{
	cmd_a->num_items += num;
	cmd_a->array = (struct rarvm_prepared_command *) rar_realloc2(cmd_a->array,
			cmd_a->num_items * sizeof(struct rarvm_prepared_command));
	if (cmd_a->array == NULL) {
		return FALSE;
	}
	memset(&cmd_a->array[cmd_a->num_items-1], 0, sizeof(struct rarvm_prepared_command));
	return TRUE;
}

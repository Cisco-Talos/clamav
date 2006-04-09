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
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA 02110-1301, USA.
 */

#include <string.h>
#include <stdlib.h>

#include "unrar.h"
#include "unrarcmd.h"

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
	cmd_a->array = (struct rarvm_prepared_command *) realloc(cmd_a->array,
			cmd_a->num_items * sizeof(struct rarvm_prepared_command));
	if (cmd_a->array == NULL) {
		return FALSE;
	}
	memset(&cmd_a->array[cmd_a->num_items-1], 0, sizeof(struct rarvm_prepared_command));
	return TRUE;
}

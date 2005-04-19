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

#ifndef RAR_CMD_ARRAY_H
#define RAR_CMD_ARRAY_H

#include <stdlib.h>

#include "unrarvm.h"

typedef struct rar_cmd_array_tag
{
	struct rarvm_prepared_command *array;
	size_t num_items;
} rar_cmd_array_t;

void rar_cmd_array_init(rar_cmd_array_t *cmd_a);
void rar_cmd_array_reset(rar_cmd_array_t *cmd_a);
int rar_cmd_array_add(rar_cmd_array_t *cmd_a, int num);

#endif

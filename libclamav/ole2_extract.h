/*
 *  Extract component parts of OLE2 files (e.g. MS Office Documents)
 *
 *  Copyright (C) 2007-2008 Sourcefire, Inc.
 *
 *  Authors: Trog
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

#ifndef __OLE2_EXTRACT_H
#define __OLE2_EXTRACT_H

#include "others.h"
#include "uniq.h"

struct ole2_list_node;
typedef struct ole2_list_node
{
  uint32_t Val;
  struct ole2_list_node *Next;
} ole2_list_node_t;

typedef struct ole2_list
{
  uint32_t Size;
  ole2_list_node_t *Head;
} ole2_list_t;

int ole2_list_init(ole2_list_t*);
int ole2_list_is_empty(ole2_list_t*);
uint32_t ole2_list_size(ole2_list_t*);
int ole2_list_push(ole2_list_t*, uint32_t);
uint32_t ole2_list_pop(ole2_list_t*);
int ole2_list_delete(ole2_list_t*);

int cli_ole2_extract(const char *dirname, cli_ctx *ctx, struct uniq **);

#endif

/*
 *  Copyright (C) 2014-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *
 *  Authors: Kevin Lin <klin@sourcefire.com>
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

#ifndef __PRTN_INTXN_H
#define __PRTN_INTXN_H

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include "clamav-types.h"
#include "others.h"

struct partition_intersection_node;
typedef struct partition_intersection_node {
    off_t Start;
    size_t Size;
    struct partition_intersection_node *Next;
} partition_intersection_node_t;

typedef struct partition_intersection_list {
    struct partition_intersection_node *Head;
    size_t Size; /* for debug */
} partition_intersection_list_t;

cl_error_t partition_intersection_list_init(partition_intersection_list_t *list);
cl_error_t partition_intersection_list_check(partition_intersection_list_t *list, unsigned *pitxn, off_t start, size_t size);
cl_error_t partition_intersection_list_free(partition_intersection_list_t *list);

#endif

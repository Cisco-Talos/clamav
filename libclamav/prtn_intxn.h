/*
 *  Copyright (C) 2014-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
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

#define PRTN_INTXN_DETECTION "heuristic.partitionintersection"

struct prtn_intxn_node;
typedef struct prtn_intxn_node {
    off_t Start;
    size_t Size;
    struct prtn_intxn_node *Next;
} prtn_intxn_node_t;

typedef struct prtn_intxn_list {
    struct prtn_intxn_node *Head;
    size_t Size; /* for debug */
} prtn_intxn_list_t;

int prtn_intxn_list_init(prtn_intxn_list_t *list);
int prtn_intxn_list_check(prtn_intxn_list_t *list, unsigned *pitxn, off_t start, size_t size);
int prtn_intxn_list_free(prtn_intxn_list_t *list);

#endif

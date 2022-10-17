/*
 *  Copyright (C) 2014-2022 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
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

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include "clamav.h"
#include "others.h"
#include "partition_intersection.h"

static bool partition_intersection_list_is_empty(partition_intersection_list_t* list)
{
    return (list->Head == NULL);
}

cl_error_t partition_intersection_list_init(partition_intersection_list_t* list)
{
    list->Head = NULL;
    list->Size = 0;
    return CL_SUCCESS;
}

cl_error_t partition_intersection_list_check(partition_intersection_list_t* list, unsigned* pitxn, off_t start, size_t size)
{
    partition_intersection_node_t *new_node, *check_node;
    cl_error_t ret = CL_CLEAN;

    *pitxn = list->Size;

    check_node = list->Head;
    while (check_node != NULL) {
        (*pitxn)--;

        if (start > check_node->Start) {
            if (check_node->Start + check_node->Size > (unsigned long)start) {
                ret = CL_VIRUS;
                break;
            }
        } else if (start < check_node->Start) {
            if (start + size > (unsigned long)(check_node->Start)) {
                ret = CL_VIRUS;
                break;
            }
        } else {
            ret = CL_VIRUS;
            break;
        }

        check_node = check_node->Next;
    }

    /* allocate new node for partition bounds */
    new_node = (partition_intersection_node_t*)cli_malloc(sizeof(partition_intersection_node_t));
    if (!new_node) {
        cli_dbgmsg("PRTN_INTXN: could not allocate new node for checklist!\n");
        partition_intersection_list_free(list);
        return CL_EMEM;
    }

    new_node->Start = start;
    new_node->Size  = size;
    new_node->Next  = list->Head;

    list->Head = new_node;
    (list->Size)++;
    return ret;
}

cl_error_t partition_intersection_list_free(partition_intersection_list_t* list)
{
    partition_intersection_node_t* next = NULL;

    while (!partition_intersection_list_is_empty(list)) {
        next = list->Head->Next;

        free(list->Head);

        list->Head = next;
        list->Size--;
    }

    return CL_SUCCESS;
}

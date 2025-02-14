/*
 *  Copyright (C) 2019-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *
 *  Authors: Mickey Sola
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

#ifndef __ONAS_SCQUE_H
#define __ONAS_SCQUE_H

/* extremely simple event queue implementation w/ obj number tracking in case we want to place limits later */
struct onas_event_queue {
    struct onas_event_queue_node *head;
    struct onas_event_queue_node *tail;
    uint64_t size;
};

struct onas_event_queue_node {
    struct onas_event_queue_node *next;
    struct onas_event_queue_node *prev;

    struct onas_scan_event *data;
};

void *onas_scan_queue_th(void *arg);

cl_error_t onas_queue_event(struct onas_scan_event *event_data);
cl_error_t onas_scan_queue_start(struct onas_context **ctx);

#endif

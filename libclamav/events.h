/*
 *  (bytecode) events
 *
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2010-2013 Sourcefire, Inc.
 *
 *  Authors: Török Edvin
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

#ifndef EVENTS_H
#define EVENTS_H

#include "clamav-types.h"

struct cli_events;
typedef struct cli_events cli_events_t;

cli_events_t *cli_events_new(unsigned max_event);
void cli_events_free(cli_events_t*);

enum ev_type {
    ev_none = 0,
    ev_string,
    ev_data,
    ev_data_fast,/* checksum, and length */
    ev_int,
    ev_time/* implicit time measurement */
};

enum multiple_handling {
    multiple_last,/* keep only last */
    multiple_chain,/* chain them */
    multiple_sum,/* sum, only for ev_int and ev_time */
    multiple_concat
};

union ev_val {
    const char *v_string;
    void *v_data;
    uint64_t v_int;
    union ev_val *v_chain;
};

/* Defines a new event with the given id, name, type. If event is triggered
 * multiple times then it is handled according to the event type. */
int cli_event_define(cli_events_t *ctx, unsigned id,
		     const char *name, enum ev_type type,
		     enum multiple_handling multiple);

/* error events */
void cli_event_error_str(cli_events_t *ctx, const char *str);
void cli_event_error_oom(cli_events_t *ctx, uint32_t amount);

/* record a data event */
void cli_event_int(cli_events_t *ctx, unsigned id, uint64_t arg);
/* for strings live at _diff_all, usually constant strings */
void cli_event_string(cli_events_t *ctx, unsigned id, const char *str);
/* for random data, alloced and copied */
void cli_event_data(cli_events_t *ctx, unsigned id, const void* data, uint32_t len);
/* don't record data, just a checksum and size */
void cli_event_fastdata(cli_events_t *ctx, unsigned id, const void *data, uint32_t len);

void cli_event_time_start(cli_events_t *ctx, unsigned id);
void cli_event_time_stop(cli_events_t *ctx, unsigned id);
void cli_event_time_nested_start(cli_events_t *ctx, unsigned id, unsigned nestedid);
void cli_event_time_nested_stop(cli_events_t *ctx, unsigned id, unsigned nestedid);

/* event_count is implemented as ev_int, with ev_multiple_sum multiple */
void cli_event_count(cli_events_t *ctx, unsigned id);

void cli_event_get(cli_events_t* ctx, unsigned id, union ev_val *val, uint32_t *count);

const char * cli_event_get_name(cli_events_t* ctx, unsigned id);

/* print all recorded events */
void cli_event_debug_all(cli_events_t *ctx);

/* print specified recorded event */
void cli_event_debug(cli_events_t *ctx, unsigned id);

/* compare 2 events, print diff to debug, and return 0 on equal, 1 on
 * different  */
int cli_event_diff(cli_events_t *ctx1, cli_events_t *ctx2, unsigned id);

/* compare all events, with the specified filter (time events are always
 * ignored), and return 0 for equal, 1 for different */
typedef int (*compare_filter_t)(unsigned id, enum ev_type type);
int cli_event_diff_all(cli_events_t *ctx1, cli_events_t *ctx2, compare_filter_t filter);

/* returns whether the given context had errors */
int cli_event_errors(cli_events_t *ctx);

enum perfev {
    PERFT_SCAN,
    PERFT_PRECB,
    PERFT_POSTCB,
    PERFT_CACHE,
    PERFT_FT,
    PERFT_CONTAINER,
    PERFT_SCRIPT,
    PERFT_PE,
    PERFT_RAW,
    PERFT_RAWTYPENO,
    PERFT_MAP,
    PERFT_BYTECODE,
    PERFT_KTIME,
    PERFT_UTIME,
    PERFT_LAST
};

#endif

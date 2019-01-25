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

#ifndef _WIN32
#include <sys/time.h>
#endif

#include "clamav.h"
#include "events.h"
#include "others.h"
#include "7z/7zCrc.h"
#include "str.h"
#include <string.h>

struct cli_event
{
    const char *name;
    union ev_val u;
    uint32_t count;
    enum ev_type type : 8;
    enum multiple_handling multiple : 8;
};

struct cli_events
{
    struct cli_event *events;
    struct cli_event errors;
    uint64_t oom_total;
    unsigned max;
    unsigned oom_count;
};

cli_events_t *cli_events_new(unsigned max_event)
{
    struct cli_events *ev = cli_calloc(1, sizeof(*ev));
    if (!ev)
        return NULL;
    ev->max = max_event;
    ev->events = cli_calloc(max_event, sizeof(*ev->events));
    if (!ev->events)
    {
        free(ev);
        return NULL;
    }
    ev->errors.name = "errors";
    ev->errors.type = ev_string;
    ev->errors.multiple = multiple_chain;
    return ev;
}

void cli_events_free(cli_events_t *ev)
{
    if (ev)
    {
        /* TODO: free components */
        free(ev->events);
        free(ev);
    }
}

void cli_event_error_oom(cli_events_t *ctx, uint32_t amount)
{
    if (!ctx)
        return;
    ctx->oom_total += amount;
    ctx->oom_count++;
    /* amount == 0 means error already reported, just increment count */
    if (amount)
        cli_errmsg("events: out of memory allocating %u bytes\n", amount);
}

int cli_event_define(cli_events_t *ctx, unsigned id,
                     const char *name, enum ev_type type, enum multiple_handling multiple)
{
    struct cli_event *ev = &ctx->events[id];
    if (id >= ctx->max)
    {
        cli_event_error_str(ctx, "cli_event_define: event id out of range");
        return -1;
    }
    if (multiple == multiple_sum &&
        (type != ev_int && type != ev_time && type != ev_data_fast))
    {
        cli_event_error_str(ctx, "cli_event_define: can only sum ev_int, ev_time, and ev_data_fast");
        return -1;
    }
    if (type == ev_data_fast && multiple != multiple_sum)
    {
        cli_event_error_str(ctx, "cli_event_define: ev_data_fast can only be sumed");
        return -1;
    }
    if (multiple == multiple_concat && type != ev_data)
    {
        cli_event_error_str(ctx, "cli_event_define: only ev_data can be concatenated");
        return -1;
    }
    /* default was ev_none */
    ev->type = type;
    ev->name = name;
    ev->type = type;
    ev->multiple = multiple;
    if (type == ev_data_fast)
        ev->u.v_int = CRC_INIT_VAL;
    return 0;
}

static inline struct cli_event *get_event(cli_events_t *ctx, unsigned id)
{
    if (!ctx)
        return NULL;
    if (id >= ctx->max)
    {
        cli_event_error_str(ctx, "event id out of range");
        return NULL;
    }
    return &ctx->events[id];
}

static inline void ev_chain(cli_events_t *ctx, struct cli_event *ev, union ev_val *val)
{
    union ev_val *chain;
    uint32_t siz = sizeof(*chain) * (ev->count + 1);

    chain = cli_realloc(ev->u.v_chain, siz);
    if (!chain)
    {
        cli_event_error_oom(ctx, siz);
        return;
    }
    ev->u.v_chain = chain;
    ev->u.v_chain[ev->count] = *val;
    ev->count++;
}

const char *cli_event_get_name(cli_events_t *ctx, unsigned id)
{
    struct cli_event *ev = get_event(ctx, id);
    if (!ev)
        return NULL;
    return ev->name;
}

void cli_event_int(cli_events_t *ctx, unsigned id, uint64_t arg)
{
    struct cli_event *ev = get_event(ctx, id);
    if (!ev)
        return;
    if (ev->type != ev_int)
    {
        cli_event_error_str(ctx, "cli_event_int must be called with ev_int type");
        return;
    }
    switch (ev->multiple)
    {
    case multiple_last:
        ev->u.v_int = arg;
        ev->count++;
        break;
    case multiple_sum:
        ev->count++;
        ev->u.v_int += arg;
        break;
    case multiple_chain:
    {
        union ev_val val;
        val.v_int = arg;
        ev_chain(ctx, ev, &val);
        break;
    }
    default:
        // TODO: Consider if we should handle multiple_concat cases.
        break;
    }
}

void cli_event_time_start(cli_events_t *ctx, unsigned id)
{
    struct timeval tv;
    struct cli_event *ev = get_event(ctx, id);
    if (!ev)
        return;
    if (ev->type != ev_time)
    {
        cli_event_error_str(ctx, "cli_event_time* must be called with ev_time type");
        return;
    }
    gettimeofday(&tv, NULL);
    ev->u.v_int -= ((int64_t)tv.tv_sec * 1000000) + tv.tv_usec;
    ev->count++;
}

void cli_event_time_nested_start(cli_events_t *ctx, unsigned id, unsigned nestedid)
{
    struct timeval tv;
    struct cli_event *ev = get_event(ctx, id);
    struct cli_event *evnested = get_event(ctx, nestedid);
    if (!ev || !evnested)
        return;
    if (ev->type != ev_time || evnested->type != ev_time)
    {
        cli_event_error_str(ctx, "cli_event_time* must be called with ev_time type");
        return;
    }
    gettimeofday(&tv, NULL);
    ev->u.v_int -= ((int64_t)tv.tv_sec * 1000000) + tv.tv_usec;
    ev->u.v_int += evnested->u.v_int;
    ev->count++;
}

void cli_event_time_stop(cli_events_t *ctx, unsigned id)
{
    struct timeval tv;
    struct cli_event *ev = get_event(ctx, id);
    if (!ev)
        return;
    if (ev->type != ev_time)
    {
        cli_event_error_str(ctx, "cli_event_time* must be called with ev_time type");
        return;
    }
    gettimeofday(&tv, NULL);
    ev->u.v_int += ((int64_t)tv.tv_sec * 1000000) + tv.tv_usec;
}

void cli_event_time_nested_stop(cli_events_t *ctx, unsigned id, unsigned nestedid)
{
    struct timeval tv;
    struct cli_event *ev = get_event(ctx, id);
    struct cli_event *evnested = get_event(ctx, nestedid);
    if (!ev || !evnested)
        return;
    if (ev->type != ev_time || evnested->type != ev_time)
    {
        cli_event_error_str(ctx, "cli_event_time* must be called with ev_time type");
        return;
    }
    gettimeofday(&tv, NULL);
    ev->u.v_int += ((int64_t)tv.tv_sec * 1000000) + tv.tv_usec;
    ev->u.v_int -= evnested->u.v_int;
}

static void event_string(cli_events_t *ctx, struct cli_event *ev, const char *str)
{
    if (!str)
        str = "";
    switch (ev->multiple)
    {
    case multiple_last:
        ev->u.v_string = str;
        ev->count++;
        break;
    case multiple_chain:
    {
        union ev_val val;
        val.v_string = str;
        ev_chain(ctx, ev, &val);
        break;
    }
    default:
        // TODO: Consider if we should handle multiple_sum, multiple_concat cases.
        break;
    }
}

void cli_event_error_str(cli_events_t *ctx, const char *str)
{
    if (!ctx)
        return;
    cli_warnmsg("events: %s\n", str);
    event_string(ctx, &ctx->errors, str);
}

void cli_event_string(cli_events_t *ctx, unsigned id, const char *str)
{
    struct cli_event *ev = get_event(ctx, id);
    if (!ev)
        return;
    if (ev->type != ev_string)
    {
        cli_event_error_str(ctx, "cli_event_string must be called with ev_string type");
        return;
    }
    event_string(ctx, ev, str);
}

void cli_event_data(cli_events_t *ctx, unsigned id, const void *data, uint32_t len)
{
    struct cli_event *ev = get_event(ctx, id);
    if (!ev)
        return;
    if (ev->type != ev_data)
    {
        cli_event_error_str(ctx, "cli_event_string must be called with ev_data type");
        return;
    }
    switch (ev->multiple)
    {
    case multiple_last:
    {
        void *v_data = cli_realloc2(ev->u.v_data, len);
        if (v_data)
        {
            ev->u.v_data = v_data;
            memcpy(v_data, data, len);
            ev->count = len;
        }
        else
        {
            cli_event_error_oom(ctx, len);
        }
        break;
    }
    case multiple_concat:
    {
        void *v_data = cli_realloc2(ev->u.v_data, ev->count + len);
        if (v_data)
        {
            ev->u.v_data = v_data;
            memcpy((char *)v_data + ev->count, data, len);
            ev->count += len;
        }
        else
        {
            cli_event_error_oom(ctx, ev->count + len);
        }
        break;
    }
    default:
        // TODO: Consider if we should handle multiple_sum, multiple_chain cases.
        break;
    }
}

void cli_event_fastdata(cli_events_t *ctx, unsigned id, const void *data, uint32_t len)
{
    struct cli_event *ev = get_event(ctx, id);
    if (!ev)
        return;
    if (ev->type != ev_data_fast)
    {
        cli_event_error_str(ctx, "cli_event_fastdata must be called with ev_data_fast");
        return;
    }
    ev->u.v_int = CrcUpdate(ev->u.v_int, data, len);
    ev->count += len;
    /* when we are done we should invert all bits, but since we are just
     * comparing it doesn't matter */
}

void cli_event_count(cli_events_t *ctx, unsigned id)
{
    cli_event_int(ctx, id, 1);
}

void cli_event_get(cli_events_t *ctx, unsigned id, union ev_val *val, uint32_t *count)
{
    struct cli_event *ev = get_event(ctx, id);
    if (!ev)
        return;
    memcpy(val, &ev->u, sizeof(*val));
    *count = ev->count;
}

static inline void ev_debug(enum ev_type type, union ev_val *val, uint32_t count)
{
    switch (type)
    {
    case ev_string:
        cli_dbgmsg("\t(%u): %s\n", count, val->v_string);
        break;
    case ev_data:
    {
        char *d = cli_str2hex(val->v_data, count);
        cli_dbgmsg("\t%d bytes\n", count);
        cli_dbgmsg("\t%s\n", d);
        free(d);
        break;
    }
    case ev_data_fast:
        cli_dbgmsg("\t%08x checksum, %u bytes\n", (uint32_t)val->v_int, count);
        break;
    case ev_int:
        cli_dbgmsg("\t(%u): 0x%llx\n", count, (long long)val->v_int);
        break;
    case ev_time:
        cli_dbgmsg("\t(%u): %d.%06us\n", count, (signed)(val->v_int / 1000000),
                   (unsigned)(val->v_int % 1000000));
        break;
    default:
        // TODO: Consider if we should handle ev_none cases.
        break;
    }
}

static inline const char *evtype(enum ev_type type)
{
    switch (type)
    {
    case ev_string:
        return "ev_string";
    case ev_data:
        return "ev_data";
    case ev_data_fast:
        return "ev_data_fast";
    case ev_int:
        return "ev_data_int";
    case ev_time:
        return "ev_time";
    default:
        return "";
    }
}

void cli_event_debug(cli_events_t *ctx, unsigned id)
{
    const char *tstr;
    struct cli_event *ev = get_event(ctx, id);
    if (!ev)
        return;
    tstr = evtype(ev->type);
    if (ev->multiple == multiple_chain && ev->type != ev_data)
    {
        unsigned i;
        cli_dbgmsg("%s: ev_chain %u %s\n", ev->name, ev->count, tstr);
        for (i = 0; i < ev->count; i++)
            ev_debug(ev->type, &ev->u.v_chain[i], i);
    }
    else
    {
        cli_dbgmsg("%s: %s\n", ev->name, tstr);
        ev_debug(ev->type, &ev->u, ev->count);
    }
}

void cli_event_debug_all(cli_events_t *ctx)
{
    unsigned i;
    for (i = 0; i < ctx->max; i++)
    {
        if (ctx->events[i].count)
            cli_event_debug(ctx, i);
    }
}

static int ev_diff(enum ev_type type, union ev_val *v1, union ev_val *v2, uint32_t count)
{
    switch (type)
    {
    case ev_data_fast:
    case ev_int:
        return v1->v_int != v2->v_int;
    case ev_string:
        return strcmp(v1->v_string, v2->v_string);
    case ev_data:
        return memcmp(v1->v_data, v2->v_data, count);
    case ev_time:
        return 0;
    default:
        // TODO: Consider if we should handle ev_none cases.
        break;
    }
    return 0;
}

int cli_event_diff(cli_events_t *ctx1, cli_events_t *ctx2, unsigned id)
{
    int diff = 0;
    struct cli_event *ev1, *ev2;
    ev1 = get_event(ctx1, id);
    ev2 = get_event(ctx2, id);
    if (!ev1 || !ev2)
        return 1;
    if (ev1->type != ev2->type ||
        ev1->multiple != ev2->multiple ||
        ev1->name != ev2->name)
    {
        cli_warnmsg("cli_event_diff: comparing incompatible events");
        return 1;
    }
    if (ev1->count != ev2->count)
    {
        cli_dbgmsg("diff: %s count %u vs %u\n", ev1->name, ev1->count, ev2->count);
        return 1;
    }
    diff = 0;
    if (ev1->multiple == multiple_chain && ev1->type != ev_data)
    {
        unsigned i;
        for (i = 0; i < ev1->count; i++)
        {
            unsigned di = ev_diff(ev1->type, &ev1->u.v_chain[i], &ev2->u.v_chain[i], ev1->count);
            if (di)
            {
                if (!diff)
                    cli_dbgmsg("diff: %s\n", ev1->name);
                ev_debug(ev1->type, &ev1->u.v_chain[i], i);
                ev_debug(ev2->type, &ev2->u.v_chain[i], i);
            }
            diff += di;
        }
    }
    else
    {
        diff = ev_diff(ev1->type, &ev1->u, &ev2->u, ev1->count);
        if (diff)
        {
            cli_dbgmsg("diff: %s\n", ev1->name);
            ev_debug(ev1->type, &ev1->u, ev1->count);
            ev_debug(ev2->type, &ev2->u, ev2->count);
        }
    }
    if (!diff)
        return 0;
    return 1;
}

int cli_event_diff_all(cli_events_t *ctx1, cli_events_t *ctx2, compare_filter_t filter)
{
    unsigned i, diff = 0;
    if (ctx1->max != ctx2->max)
    {
        cli_dbgmsg("diffall: incompatible event maximums %u vs %u\n",
                   ctx1->max, ctx2->max);
        return 1;
    }
    for (i = 0; i < ctx1->max; i++)
    {
        struct cli_event *ev1 = &ctx1->events[i];
        if (filter && filter(i, ev1->type))
            continue;
        diff += cli_event_diff(ctx1, ctx2, i);
    }
    return diff ? 1 : 0;
}

int cli_event_errors(cli_events_t *ctx)
{
    if (!ctx)
        return 0;
    return ctx->errors.count + ctx->oom_count;
}

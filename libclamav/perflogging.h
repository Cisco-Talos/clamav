/*
 *  Gather statistics from performance sensitive code.
 *
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2008-2013 Sourcefire, Inc.
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
#ifndef PERFLOGGING_H
#define PERFLOGGING_H

/* this is a compile-time selectable, default off module to log certain
 * statistics, such as which tries are used, efficiency of filtering and so on.
 * it must have as little overhead as possible */

/* #define CLI_PERF_LOGGING */
#ifdef CLI_PERF_LOGGING

#ifndef __GNUC__
#error "Performance logging requires GNU C compatible compiler"
#else
/*TODO: maybe we need a GCC version check too here */
#include <pthread.h>
#include <assert.h>
#include "clamav-types.h"

enum perf_log_sumable {
	RAW_BYTES_SCANNED,
	FILTER_BYTES_SCANNED,
  AC_SCANNED,
	BM_SCANNED,
	__LAST_SUMABLE
};

enum perf_log_countable {
	TRIE_SCANNED,
	FILTER_LOAD,
	FILTER_END_LOAD,
	TRIE_ORIG_LEN,
	__LAST_COUNTABLE
};

extern __thread int last_flushed;
extern __thread int cli_perf_registered;
extern __thread uint64_t cli_perf_sum_tls[__LAST_SUMABLE];
extern __thread uint64_t cli_perf_count_tls[__LAST_COUNTABLE][256];
extern __thread int last_flushed;

extern uint64_t cli_perf_sum[__LAST_SUMABLE];
extern uint64_t cli_perf_count[__LAST_COUNTABLE][256];

void cli_perf_register(void);
void cli_perf_flush(void);

static inline void cli_perf_enter(void)
{
	if (!cli_perf_registered) cli_perf_register();
	if (cli_perf_sum_tls[RAW_BYTES_SCANNED] - last_flushed > 100*1024*1024) {
		cli_perf_flush();
		last_flushed = cli_perf_sum_tls[RAW_BYTES_SCANNED];
	}
}

static inline void cli_perf_log_add(enum perf_log_sumable kind, uint64_t add)
{
	cli_perf_enter();
	assert( kind < __LAST_SUMABLE);
	cli_perf_sum_tls[kind] += add;
}

static inline void cli_perf_log_count2(enum perf_log_countable kind, uint8_t event, uint64_t cnt)
{
	cli_perf_enter();
	assert( kind < __LAST_COUNTABLE);
	cli_perf_count_tls[kind][event] += cnt;
}

static inline void cli_perf_log_count(enum perf_log_countable kind, uint8_t event)
{
	cli_perf_log_count2(kind, event, 1);
}

#endif

#else
#define cli_perf_log_count(a,b) do {} while(0)
#endif

#endif

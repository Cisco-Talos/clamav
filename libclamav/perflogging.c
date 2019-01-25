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
#ifdef HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include "perflogging.h"
#include <stdio.h>
#ifdef CLI_PERF_LOGGING

__thread last_flushed = 0;
__thread cli_perf_registered = 0;
__thread uint64_t cli_perf_sum_tls[__LAST_SUMABLE];
__thread uint64_t cli_perf_count_tls[__LAST_COUNTABLE][256];

uint64_t cli_perf_sum[__LAST_SUMABLE];
uint64_t cli_perf_count[__LAST_COUNTABLE][256];

static pthread_key_t thread_exit_key;
int pthread_key_create(pthread_key_t *key, void (*destr_function) (void *)); 

static void cli_perf_thread_exit(void* arg)
{
	/* save counters into global */
	cli_perf_flush();
}

void __attribute__((constructor)) __cli_perf_init(void)
{
	pthread_key_create(&thread_exit_key, cli_perf_thread_exit);
}

void __attribute__((destructor)) __cli_perf_exit(void)
{
	cli_perf_thread_exit(NULL);
}

static int dummy;
void cli_perf_register(void)
{
	/* set a fake key, so that destructor gets called */
	pthread_setspecific(thread_exit_key, &dummy);
	cli_perf_registered = 1;
}

static const char *perf_log_names_sum[__LAST_SUMABLE] = {
	"raw scanned",
	"filter scanned",
	"AC scanned",
	"BM scanned"
};

static const char *perf_log_names_cnt[__LAST_COUNTABLE] = {
	"trie bytes scanned",
	"filter position load",
	"filter end load",
	"trie pattern original length"
};

#define NONE __LAST_SUMABLE
static enum perf_log_sumable perf_log_percent[__LAST_SUMABLE] = {
	NONE,
	RAW_BYTES_SCANNED,
	RAW_BYTES_SCANNED,
	RAW_BYTES_SCANNED,
};

static enum perf_log_countable perf_log_percent_cnt[__LAST_COUNTABLE] = {
	RAW_BYTES_SCANNED,
	NONE,
	NONE,
	NONE,
};

static void cli_perf_print(void)
{
	enum perf_log_sumable i;
	enum perf_log_countable j;
	unsigned k;

	uint64_t raw_scanned = cli_perf_sum[RAW_BYTES_SCANNED];
	const double MEGA = 1024*1024.0;

	/* in multiscan mode multiple threads can output, so output a unique id
	 * here*/
	printf("PERF: %p\n", &cli_perf_registered);
	for(i=0;i<__LAST_SUMABLE;i++) {
		printf("PERF: %s: %g MB", perf_log_names_sum[i], cli_perf_sum[i] / MEGA);
		if (perf_log_percent[i] != NONE)
			printf("(%6.3f%%)", 100.0*cli_perf_sum[i] / cli_perf_sum[perf_log_percent[i]]);
		printf("\n");
	}
	printf("\n");
	for(j=0;j<__LAST_COUNTABLE;j++) {
		printf("PERF: %s: ", perf_log_names_cnt[j]);
		for (k=0;k<256;k++)
			if (cli_perf_count[j][k]) {
				printf(" %u -> %ju", k, cli_perf_count[j][k]);
				if (perf_log_percent_cnt[j] != NONE)
					printf("(%6.3f%%)", 100.0*cli_perf_count[j][k] / cli_perf_sum[perf_log_percent_cnt[j]]);
			}
		printf("\n");
	}
	printf("\n");
}

static pthread_mutex_t cli_perf_log_mutex = PTHREAD_MUTEX_INITIALIZER;
void cli_perf_flush(void)
{
	unsigned i, j;

	pthread_mutex_lock(&cli_perf_log_mutex);

	for (i = 0; i < __LAST_SUMABLE; i++) {
		cli_perf_sum[i] += cli_perf_sum_tls[i];
		cli_perf_sum_tls[i] = 0;
	}

	for (i = 0; i < __LAST_COUNTABLE; i++) {
		for (j = 0; j < 256; j++) {
			cli_perf_count[i][j] += cli_perf_count_tls[i][j];
			cli_perf_count_tls[i][j] = 0;
		}
	}

	cli_perf_print();
	pthread_mutex_unlock(&cli_perf_log_mutex);
}
#endif

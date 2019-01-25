/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *
 *  Authors: Tomasz Kojm, Török Edvin
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
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA 02110-1301, USA.
 */

#ifndef __THRMGR_H__
#define __THRMGR_H__

#include <pthread.h>

#ifndef _WIN32
#include <sys/time.h>
#endif

typedef struct work_item_tag {
	struct work_item_tag *next;
	void *data;
	struct timeval time_queued;
} work_item_t;
	
typedef struct work_queue_tag {
	work_item_t *head;
	work_item_t *tail;
	int item_count;
	int popped;
} work_queue_t;

typedef enum {
	POOL_INVALID,
	POOL_VALID,
	POOL_EXIT
} pool_state_t;

struct task_desc {
	const char *filename;
	const char *command;
	struct timeval tv;
	struct task_desc *prv;
	struct task_desc *nxt;
	const struct cl_engine *engine;
};

typedef struct threadpool_tag {
	pthread_mutex_t pool_mutex;
	pthread_cond_t pool_cond;
	pthread_attr_t pool_attr;

	pthread_cond_t  idle_cond;
	pthread_cond_t  queueable_single_cond;
	pthread_cond_t  queueable_bulk_cond;

	pool_state_t state;
	int thr_max;
	int queue_max;
	int thr_alive;
	int thr_idle;
	int thr_multiscan;
	int idle_timeout;
	struct task_desc *tasks;
	
	void (*handler)(void *);

	work_queue_t *bulk_queue;
	work_queue_t *single_queue;
} threadpool_t;

typedef struct jobgroup {
    pthread_mutex_t mutex;
    pthread_cond_t only;
    unsigned	jobs;
    unsigned	exit_ok;
    unsigned	exit_error;
    unsigned	exit_total;
    int		force_exit;
} jobgroup_t;

enum thrmgr_exit {
    EXIT_OK,
    EXIT_ERROR,
    EXIT_OTHER
};

threadpool_t *thrmgr_new(int max_threads, int idle_timeout, int max_queue, void (*handler)(void *));
void thrmgr_destroy(threadpool_t *threadpool);
int thrmgr_dispatch(threadpool_t *threadpool, void *user_data);
int thrmgr_group_dispatch(threadpool_t *threadpool, jobgroup_t *group, void *user_data, int bulk);
void thrmgr_group_waitforall(jobgroup_t *group, unsigned *ok, unsigned *error, unsigned *total);
int thrmgr_group_finished(jobgroup_t *group, enum thrmgr_exit exitc);
int thrmgr_group_need_terminate(jobgroup_t *group);
void thrmgr_group_terminate(jobgroup_t *group);
jobgroup_t *thrmgr_group_new(void);
int thrmgr_printstats(int outfd, char term);
void thrmgr_setactivetask(const char *filename, const char* command);
void thrmgr_setactiveengine(const struct cl_engine *engine);

#endif

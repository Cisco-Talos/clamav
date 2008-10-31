/*
 *  Copyright (C) 2004 Trog <trog@clamav.net>
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

#ifndef C_WINDOWS
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
} work_queue_t;

typedef enum {
	POOL_INVALID,
	POOL_VALID,
	POOL_EXIT
} pool_state_t;

typedef struct threadpool_tag {
	pthread_mutex_t pool_mutex;
	pthread_cond_t pool_cond;
	pthread_attr_t pool_attr;

	pthread_cond_t  idle_cond;
	
	pool_state_t state;
	int thr_max;
	int thr_alive;
	int thr_idle;
	int idle_timeout;
	
	void (*handler)(void *);
	
	work_queue_t *queue;
} threadpool_t;

threadpool_t *thrmgr_new(int max_threads, int idle_timeout, void (*handler)(void *));
void thrmgr_destroy(threadpool_t *threadpool);
int thrmgr_dispatch(threadpool_t *threadpool, void *user_data);

#endif

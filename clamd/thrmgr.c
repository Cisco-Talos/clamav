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
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <pthread.h>
#include <time.h>
#include <errno.h>

#include "thrmgr.h"

#include "others.h"
#include "memory.h"
#include "output.h"

#define FALSE (0)
#define TRUE (1)

work_queue_t *work_queue_new()
{
	work_queue_t *work_q;
	
	work_q = (work_queue_t *) mmalloc(sizeof(work_queue_t));
	
	work_q->head = work_q->tail = NULL;
	work_q->item_count = 0;
	return work_q;
}

void work_queue_add(work_queue_t *work_q, void *data)
{
	work_item_t *work_item;
	
	if (!work_q) {
		return;
	}
	work_item = (work_item_t *) mmalloc(sizeof(work_item_t));
	work_item->next = NULL;
	work_item->data = data;
	gettimeofday(&(work_item->time_queued), NULL);
	
	if (work_q->head == NULL) {
		work_q->head = work_q->tail = work_item;
		work_q->item_count = 1;
	} else {
		work_q->tail->next = work_item;
		work_q->tail = work_item;
		work_q->item_count++;
	}
	return;
}

void *work_queue_pop(work_queue_t *work_q)
{
	work_item_t *work_item;
	void *data;
	
	if (!work_q || !work_q->head) {
		return NULL;
	}
	work_item = work_q->head;
	data = work_item->data;
	work_q->head = work_item->next;
	if (work_q->head == NULL) {
		work_q->tail = NULL;
	}
	free(work_item);
	return data;
}

void thrmgr_destroy(threadpool_t *threadpool)
{
	if (!threadpool || (threadpool->state != POOL_VALID)) {
		return;
	}
  	if (pthread_mutex_lock(&threadpool->pool_mutex) != 0) {
   		logg("!Mutex lock failed\n");
    		exit(-1);
	}
	threadpool->state = POOL_EXIT;
	
	/* wait for threads to exit */
	if (threadpool->thr_alive > 0) {
		if (pthread_cond_broadcast(&(threadpool->pool_cond)) != 0) {
			pthread_mutex_unlock(&threadpool->pool_mutex);
			return;
		}
	}
	while (threadpool->thr_alive > 0) {
		if (pthread_cond_wait (&threadpool->pool_cond, &threadpool->pool_mutex) != 0) {
			pthread_mutex_unlock(&threadpool->pool_mutex);
			return;
		}
	}
  	if (pthread_mutex_unlock(&threadpool->pool_mutex) != 0) {
    		logg("!Mutex unlock failed\n");
    		exit(-1);
  	}
	
	pthread_mutex_destroy(&(threadpool->pool_mutex));
	pthread_cond_destroy(&(threadpool->pool_cond));
	pthread_attr_destroy(&(threadpool->pool_attr));
	free(threadpool);
	return;
}

threadpool_t *thrmgr_new(int max_threads, int idle_timeout, void (*handler)(void *))
{
	threadpool_t *threadpool;
	
	if (max_threads <= 0) {
		return NULL;
	}
	
	threadpool = (threadpool_t *) mmalloc(sizeof(threadpool_t));

	threadpool->queue = work_queue_new();
	if (!threadpool->queue) {
		free(threadpool);
		return NULL;
	}	
	threadpool->thr_max = max_threads;
	threadpool->thr_alive = 0;
	threadpool->thr_idle = 0;
	threadpool->idle_timeout = idle_timeout;
	threadpool->handler = handler;
	
	pthread_mutex_init(&(threadpool->pool_mutex), NULL);
	if (pthread_cond_init(&(threadpool->pool_cond), NULL) != 0) {
		free(threadpool);
		return NULL;
	}
		
	if (pthread_attr_init(&(threadpool->pool_attr)) != 0) {
		free(threadpool);
		return NULL;
	}
	
	if (pthread_attr_setdetachstate(&(threadpool->pool_attr), PTHREAD_CREATE_DETACHED) != 0) {
		free(threadpool);
		return NULL;
	}
	threadpool->state = POOL_VALID;

	return threadpool;
}

void *thrmgr_worker(void *arg)
{
	threadpool_t *threadpool = (threadpool_t *) arg;
	void *job_data;
	int retval, must_exit = FALSE;
	struct timespec timeout;
	
	/* loop looking for work */
	for (;;) {
		if (pthread_mutex_lock(&(threadpool->pool_mutex)) != 0) {
			/* Fatal error */
			logg("!Fatal: mutex lock failed\n");
			exit(-2);
		}
		timeout.tv_sec = time(NULL) + threadpool->idle_timeout;
		timeout.tv_nsec = 0;
		threadpool->thr_idle++;
		while (((job_data=work_queue_pop(threadpool->queue)) == NULL)
				&& (threadpool->state != POOL_EXIT)) {
			/* Sleep, awaiting wakeup */
			retval = pthread_cond_timedwait(&(threadpool->pool_cond),
				&(threadpool->pool_mutex), &timeout);
			if (retval == ETIMEDOUT) {
				must_exit = TRUE;
				break;
			}
		}
		threadpool->thr_idle--;
		if (threadpool->state == POOL_EXIT) {
			must_exit = TRUE;
		}
		
		if (pthread_mutex_unlock(&(threadpool->pool_mutex)) != 0) {
			/* Fatal error */
			logg("!Fatal: mutex unlock failed\n");
			exit(-2);
		}
		if (job_data) {
			threadpool->handler(job_data);
		} else if (must_exit) {
			break;
		}
	}
	if (pthread_mutex_lock(&(threadpool->pool_mutex)) != 0) {
		/* Fatal error */
		logg("!Fatal: mutex lock failed\n");
		exit(-2);
	}
	threadpool->thr_alive--;
	if (threadpool->thr_alive == 0) {
		/* signal that all threads are finished */
		pthread_cond_broadcast(&threadpool->pool_cond);
	}
	if (pthread_mutex_unlock(&(threadpool->pool_mutex)) != 0) {
		/* Fatal error */
		logg("!Fatal: mutex unlock failed\n");
		exit(-2);
	}
	return NULL;
}

int thrmgr_dispatch(threadpool_t *threadpool, void *user_data)
{
	pthread_t thr_id;
	
	if (!threadpool) {
		return FALSE;
	}
	
	/* Lock the threadpool */
	if (pthread_mutex_lock(&(threadpool->pool_mutex)) != 0) {
		logg("!Mutex lock failed\n");
		return FALSE;
	}
	
	if (threadpool->state != POOL_VALID) {
		return FALSE;
	}
	work_queue_add(threadpool->queue, user_data);
	
	if ((threadpool->thr_idle == 0) &&
			(threadpool->thr_alive < threadpool->thr_max)) {
		/* Start a new thread */
		if (pthread_create(&thr_id, &(threadpool->pool_attr),
				thrmgr_worker, threadpool) != 0) {
			logg("!pthread_create failed\n");
		} else {
			threadpool->thr_alive++;
		}
	}
	pthread_cond_signal(&(threadpool->pool_cond));
	
	if (pthread_mutex_unlock(&(threadpool->pool_mutex)) != 0) {
		logg("!Mutex unlock failed\n");
		return FALSE;
	}
	return TRUE;
}

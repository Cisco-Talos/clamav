/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *
 *  Authors: Trog, Török Edvin
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

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdio.h>
#include <pthread.h>
#include <time.h>
#include <errno.h>
#include <string.h>

#include "shared/output.h"

#include "libclamav/clamav.h"
#include "thrmgr.h"
#include "others.h"
#include "mpool.h"
#include "server.h"
#include "libclamav/others.h"

#ifdef HAVE_MALLINFO
#include <malloc.h>
#endif

/* BSD and HP-UX need a bigger stacksize than the system default */
#if defined (C_BSD) || defined (C_HPUX) || defined(C_AIX) || (defined(C_LINUX) && !defined(__GLIBC__))
#define C_BIGSTACK 1
#endif

static work_queue_t *work_queue_new(void)
{
	work_queue_t *work_q;

	work_q = (work_queue_t *) malloc(sizeof(work_queue_t));
	if (!work_q) {
		return NULL;
	}

	work_q->head = work_q->tail = NULL;
	work_q->item_count = 0;
	work_q->popped = 0;
	return work_q;
}

static int work_queue_add(work_queue_t *work_q, void *data)
{
	work_item_t *work_item;

	if (!work_q) {
		return FALSE;
	}
	work_item = (work_item_t *) malloc(sizeof(work_item_t));
	if (!work_item) {
		return FALSE;
	}

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
	return TRUE;
}

static void *work_queue_pop(work_queue_t *work_q)
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
	work_q->item_count--;
	return data;
}

static struct threadpool_list {
	threadpool_t *pool;
	struct threadpool_list *nxt;
} *pools = NULL;
static pthread_mutex_t pools_lock = PTHREAD_MUTEX_INITIALIZER;

static void add_topools(threadpool_t *t)
{
	struct threadpool_list *new = malloc(sizeof(*new));
	if(!new) {
		logg("!Unable to add threadpool to list\n");
		return;
	}
	new->pool = t;
	pthread_mutex_lock(&pools_lock);
	new->nxt = pools;
	pools = new;
	pthread_mutex_unlock(&pools_lock);
}

static void remove_frompools(threadpool_t *t)
{
	struct threadpool_list *l, *prev;
	struct task_desc *desc;
	pthread_mutex_lock(&pools_lock);
	prev = NULL;
	l = pools;
	while(l && l->pool != t) {
		prev = l;
		l = l->nxt;
	}
	if(!l) {
        pthread_mutex_unlock(&pools_lock);
		return;
    }
	if(prev)
		prev->nxt = l->nxt;
	if(l == pools)
		pools = l->nxt;
	free(l);
	desc = t->tasks;
	while(desc) {
		struct task_desc *q = desc;
		desc = desc->nxt;
		free(q);
	}
	t->tasks = NULL;
	pthread_mutex_unlock(&pools_lock);
}

static void print_queue(int f, work_queue_t *queue, struct timeval *tv_now)
{
    long umin=LONG_MAX, umax=0, usum=0;
    unsigned invalids = 0, cnt = 0;
    work_item_t *q;

    if(!queue->head)
	return;
    for(q=queue->head;q;q=q->next) {
	long delta;
	delta = tv_now->tv_usec - q->time_queued.tv_usec;
	delta += (tv_now->tv_sec - q->time_queued.tv_sec)*1000000;
	if(delta < 0) {
	    invalids++;
	    continue;
	}
	if(delta > umax)
	    umax = delta;
	if(delta < umin)
	    umin = delta;
	usum += delta;
	++cnt;
    }
    mdprintf(f," min_wait: %.6f max_wait: %.6f avg_wait: %.6f",
	     umin/1e6, umax/1e6, usum /(1e6*cnt));
    if(invalids)
	mdprintf(f," (INVALID timestamps: %u)", invalids);
    if(cnt + invalids != (unsigned)queue->item_count)
	mdprintf(f," (ERROR: %u != %u)", cnt + invalids,
		 (unsigned)queue->item_count);
}

int thrmgr_printstats(int f, char term)
{
	struct threadpool_list *l;
	unsigned cnt, pool_cnt = 0;
	size_t pool_used = 0, pool_total = 0, seen_cnt = 0, error_flag = 0;
	float mem_heap = 0, mem_mmap = 0, mem_used = 0, mem_free = 0, mem_releasable = 0;
	const struct cl_engine **seen = NULL;
	int has_libc_memstats = 0;

	pthread_mutex_lock(&pools_lock);
	for(cnt=0,l=pools;l;l=l->nxt) cnt++;
	mdprintf(f,"POOLS: %u\n\n", cnt);
	for(l= pools;l && !error_flag;l = l->nxt) {
		threadpool_t *pool = l->pool;
		const char *state;
		struct timeval tv_now;
		struct task_desc *task;
		cnt = 0;

		if(!pool) {
			mdprintf(f,"NULL\n\n");
			continue;
		}
		/* now we can access desc->, knowing that they won't get freed
		 * because the other tasks can't quit while pool_mutex is taken
		 */
		switch(pool->state) {
			case POOL_INVALID:
				state = "INVALID";
				break;
			case POOL_VALID:
				state = "VALID";
				break;
			case POOL_EXIT:
				state = "EXIT";
				break;
			default:
				state = "??";
				break;
		}
		mdprintf(f, "STATE: %s %s\n", state, l->nxt ? "" : "PRIMARY");
		mdprintf(f, "THREADS: live %u  idle %u max %u idle-timeout %u\n"
				,pool->thr_alive, pool->thr_idle, pool->thr_max,
				pool->idle_timeout);
		/* TODO: show both queues */
		mdprintf(f,"QUEUE: %u items", pool->single_queue->item_count + pool->bulk_queue->item_count);
		gettimeofday(&tv_now, NULL);
		print_queue(f, pool->bulk_queue, &tv_now);
		print_queue(f, pool->single_queue, &tv_now);
		mdprintf(f, "\n");
		for(task = pool->tasks; task; task = task->nxt) {
			double delta;
			size_t used, total;

			delta = tv_now.tv_usec - task->tv.tv_usec;
			delta += (tv_now.tv_sec - task->tv.tv_sec)*1000000.0;
			mdprintf(f,"\t%s %f %s\n",
					task->command ? task->command : "N/A",
					delta/1e6,
					task->filename ? task->filename:"");
			if (task->engine) {
				/* we usually have at most 2 engines so a linear
				 * search is good enough */
				size_t i;
				for (i=0;i<seen_cnt;i++) {
					if (seen[i] == task->engine)
						break;
				}
				/* we need to count the memusage from the same
				 * engine only once */
				if (i == seen_cnt) {
					const struct cl_engine **s;
					/* new engine */
					++seen_cnt;
					s = realloc(seen, seen_cnt * sizeof(*seen));
					if (!s) {
						error_flag = 1;
						break;
					}
					seen = s;
					seen[seen_cnt - 1] = task->engine;

					if (mpool_getstats(task->engine, &used, &total) != -1) {
						pool_used += used;
						pool_total += total;
						pool_cnt++;
					}
				}
			}
		}
		mdprintf(f,"\n");
	}
	free(seen);
#ifdef HAVE_MALLINFO
	{
		struct mallinfo inf = mallinfo();
		mem_heap = inf.arena/(1024*1024.0);
		mem_mmap = inf.hblkhd/(1024*1024.0);
		mem_used = (inf.usmblks + inf.uordblks)/(1024*1024.0);
		mem_free = (inf.fsmblks + inf.fordblks)/(1024*1024.0);
		mem_releasable = inf.keepcost/(1024*1024.0);
		has_libc_memstats=1;
	}
#endif
	if (error_flag) {
		mdprintf(f, "ERROR: error encountered while formatting statistics\n");
	} else {
	    if (has_libc_memstats)
		mdprintf(f,"MEMSTATS: heap %.3fM mmap %.3fM used %.3fM free %.3fM releasable %.3fM pools %u pools_used %.3fM pools_total %.3fM\n",
			mem_heap, mem_mmap, mem_used, mem_free, mem_releasable, pool_cnt,
			pool_used/(1024*1024.0), pool_total/(1024*1024.0));
	    else
		mdprintf(f,"MEMSTATS: heap N/A mmap N/A used N/A free N/A releasable N/A pools %u pools_used %.3fM pools_total %.3fM\n",
			 pool_cnt, pool_used/(1024*1024.0), pool_total/(1024*1024.0));
	}
	mdprintf(f,"END%c", term);
	pthread_mutex_unlock(&pools_lock);
	return 0;
}

void thrmgr_destroy(threadpool_t *threadpool)
{
	if (!threadpool) {
		return;
	}
	if (pthread_mutex_lock(&threadpool->pool_mutex) != 0) {
		logg("!Mutex lock failed\n");
		exit(-1);
	}
	if(threadpool->state != POOL_VALID) {
		if (pthread_mutex_unlock(&threadpool->pool_mutex) != 0) {
			logg("!Mutex unlock failed\n");
			exit(-1);
		}
		return;
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
	remove_frompools(threadpool);
	if (pthread_mutex_unlock(&threadpool->pool_mutex) != 0) {
		logg("!Mutex unlock failed\n");
		exit(-1);
	}

	pthread_mutex_destroy(&(threadpool->pool_mutex));
	pthread_cond_destroy(&(threadpool->idle_cond));
	pthread_cond_destroy(&(threadpool->queueable_single_cond));
	pthread_cond_destroy(&(threadpool->queueable_bulk_cond));
	pthread_cond_destroy(&(threadpool->pool_cond));
	pthread_attr_destroy(&(threadpool->pool_attr));
	free(threadpool->single_queue);
	free(threadpool->bulk_queue);
	free(threadpool);
	return;
}

threadpool_t *thrmgr_new(int max_threads, int idle_timeout, int max_queue, void (*handler)(void *))
{
	threadpool_t *threadpool;
#if defined(C_BIGSTACK)
	size_t stacksize;
#endif

	if (max_threads <= 0) {
		return NULL;
	}

	threadpool = (threadpool_t *) malloc(sizeof(threadpool_t));
	if (!threadpool) {
		return NULL;
	}

	threadpool->single_queue = work_queue_new();
	if (!threadpool->single_queue) {
		free(threadpool);
		return NULL;
	}
	threadpool->bulk_queue = work_queue_new();
	if (!threadpool->bulk_queue) {
		free(threadpool->single_queue);
		free(threadpool);
		return NULL;
	}

	threadpool->queue_max = max_queue;

	threadpool->thr_max = max_threads;
	threadpool->thr_alive = 0;
	threadpool->thr_idle = 0;
	threadpool->thr_multiscan = 0;
	threadpool->idle_timeout = idle_timeout;
	threadpool->handler = handler;
	threadpool->tasks = NULL;

	if(pthread_mutex_init(&(threadpool->pool_mutex), NULL)) {
		free(threadpool->single_queue);
		free(threadpool->bulk_queue);
		free(threadpool);
		return NULL;
	}

	if (pthread_cond_init(&(threadpool->pool_cond), NULL) != 0) {
		pthread_mutex_destroy(&(threadpool->pool_mutex));
		free(threadpool->single_queue);
		free(threadpool->bulk_queue);
		free(threadpool);
		return NULL;
	}

	if (pthread_cond_init(&(threadpool->queueable_single_cond), NULL) != 0) {
		pthread_cond_destroy(&(threadpool->pool_cond));
		pthread_mutex_destroy(&(threadpool->pool_mutex));
		free(threadpool->single_queue);
		free(threadpool->bulk_queue);
		free(threadpool);
		return NULL;
	}

	if (pthread_cond_init(&(threadpool->queueable_bulk_cond), NULL) != 0) {
		pthread_cond_destroy(&(threadpool->queueable_single_cond));
		pthread_cond_destroy(&(threadpool->pool_cond));
		pthread_mutex_destroy(&(threadpool->pool_mutex));
		free(threadpool->single_queue);
		free(threadpool->bulk_queue);
		free(threadpool);
		return NULL;
	}


	if (pthread_cond_init(&(threadpool->idle_cond),NULL) != 0)  {
		pthread_cond_destroy(&(threadpool->queueable_single_cond));
		pthread_cond_destroy(&(threadpool->queueable_bulk_cond));
		pthread_cond_destroy(&(threadpool->pool_cond));
		pthread_mutex_destroy(&(threadpool->pool_mutex));
		free(threadpool->single_queue);
		free(threadpool->bulk_queue);
		free(threadpool);
		return NULL;
	}

	if (pthread_attr_init(&(threadpool->pool_attr)) != 0) {
		pthread_cond_destroy(&(threadpool->queueable_single_cond));
		pthread_cond_destroy(&(threadpool->queueable_bulk_cond));
		pthread_cond_destroy(&(threadpool->idle_cond));
		pthread_cond_destroy(&(threadpool->pool_cond));
		pthread_mutex_destroy(&(threadpool->pool_mutex));
		free(threadpool->single_queue);
		free(threadpool->bulk_queue);
		free(threadpool);
		return NULL;
	}

	if (pthread_attr_setdetachstate(&(threadpool->pool_attr), PTHREAD_CREATE_DETACHED) != 0) {
		pthread_cond_destroy(&(threadpool->queueable_single_cond));
		pthread_cond_destroy(&(threadpool->queueable_bulk_cond));
		pthread_attr_destroy(&(threadpool->pool_attr));
		pthread_cond_destroy(&(threadpool->idle_cond));
		pthread_cond_destroy(&(threadpool->pool_cond));
		pthread_mutex_destroy(&(threadpool->pool_mutex));
		free(threadpool->single_queue);
		free(threadpool->bulk_queue);
		free(threadpool);
		return NULL;
	}

#if defined(C_BIGSTACK)
	pthread_attr_getstacksize(&(threadpool->pool_attr), &stacksize);
	stacksize = stacksize + 64 * 1024;
	if (stacksize < 1048576) /* at least 1MB please */
#if defined(C_HPUX) && defined(USE_MPOOL)
		/* Set aside one cli_pagesize() for the stack's pthread header,
		 * giving a 1M region to fit a 1M large-page */
		if(cli_getpagesize() < 1048576)
			stacksize = 1048576 - cli_getpagesize();
		else
#endif
		stacksize = 1048576;
	logg("Set stacksize to %lu\n", (unsigned long int) stacksize);
	pthread_attr_setstacksize(&(threadpool->pool_attr), stacksize);
#endif
	threadpool->state = POOL_VALID;

	add_topools(threadpool);
	return threadpool;
}

static pthread_key_t stats_tls_key;
static pthread_once_t stats_tls_key_once = PTHREAD_ONCE_INIT;

static void stats_tls_key_alloc(void)
{
	pthread_key_create(&stats_tls_key, NULL);
}

static const char *IDLE_TASK = "IDLE";

/* no mutex is needed, we are using  thread local variable */
void thrmgr_setactivetask(const char *filename, const char* cmd)
{
	struct task_desc *desc;
	pthread_once(&stats_tls_key_once, stats_tls_key_alloc);
	desc = pthread_getspecific(stats_tls_key);
	if(!desc)
		return;
	desc->filename = filename;
	if(cmd) {
		if(cmd == IDLE_TASK && desc->command == cmd)
			return;
		desc->command = cmd;
		gettimeofday(&desc->tv, NULL);
	}
}

void thrmgr_setactiveengine(const struct cl_engine *engine)
{
	struct task_desc *desc;
	pthread_once(&stats_tls_key_once, stats_tls_key_alloc);
	desc = pthread_getspecific(stats_tls_key);
	if(!desc)
		return;
	desc->engine = engine;
}

/* thread pool mutex must be held on entry */
static void stats_init(threadpool_t *pool)
{
	struct task_desc *desc = calloc(1, sizeof(*desc));
	if(!desc)
		return;
	pthread_once(&stats_tls_key_once, stats_tls_key_alloc);
	pthread_setspecific(stats_tls_key, desc);
	if(!pool->tasks)
		pool->tasks = desc;
	else {
		desc->nxt = pool->tasks;
		pool->tasks->prv = desc;
		pool->tasks = desc;
	}
}

/* thread pool mutex must be held on entry */
static void stats_destroy(threadpool_t *pool)
{
	struct task_desc *desc = pthread_getspecific(stats_tls_key);
	if(!desc)
		return;
	pthread_mutex_lock(&pools_lock);
	if(desc->prv)
		desc->prv->nxt = desc->nxt;
	if(desc->nxt)
		desc->nxt->prv = desc->prv;
	if(pool->tasks == desc)
		pool->tasks = desc->nxt;
	free(desc);
	pthread_setspecific(stats_tls_key, NULL);
	pthread_mutex_unlock(&pools_lock);
}

static inline int thrmgr_contended(threadpool_t *pool, int bulk)
{
    /* don't allow bulk items to exceed 50% of queue, so that
     * non-bulk items get a chance to be in the queue */
    if (bulk && pool->bulk_queue->item_count >= pool->queue_max/2)
	return 1;
    return pool->bulk_queue->item_count + pool->single_queue->item_count
	+ pool->thr_alive - pool->thr_idle >= pool->queue_max;
}

/* when both queues have tasks, it will pick 4 items from the single queue,
 * and 1 from the bulk */
#define SINGLE_BULK_RATIO 4
#define SINGLE_BULK_SUM (SINGLE_BULK_RATIO + 1)

/* must be called with pool_mutex held */
static void *thrmgr_pop(threadpool_t *pool)
{
    void *task;
    work_queue_t *first, *second;
    int ratio;

    if (pool->single_queue->popped < SINGLE_BULK_RATIO) {
	first = pool->single_queue;
	second = pool->bulk_queue;
	ratio = SINGLE_BULK_RATIO;
    } else {
	second = pool->single_queue;
	first = pool->bulk_queue;
	ratio = SINGLE_BULK_SUM - SINGLE_BULK_RATIO;
    }

    task = work_queue_pop(first);
    if (task) {
	if (++first->popped == ratio)
	    second->popped = 0;
    } else {
	task = work_queue_pop(second);
	if (task) {
	    if (++second->popped == ratio)
		first->popped = 0;
	}
    }

    if (!thrmgr_contended(pool, 0)) {
	logg("$THRMGR: queue (single) crossed low threshold -> signaling\n");
	pthread_cond_signal(&pool->queueable_single_cond);
    }

    if (!thrmgr_contended(pool, 1)) {
	logg("$THRMGR: queue (bulk) crossed low threshold -> signaling\n");
	pthread_cond_signal(&pool->queueable_bulk_cond);
    }

    return task;
}


static void *thrmgr_worker(void *arg)
{
	threadpool_t *threadpool = (threadpool_t *) arg;
	void *job_data;
	int retval, must_exit = FALSE, stats_inited = FALSE;
	struct timespec timeout;

	/* loop looking for work */
	for (;;) {
		if (pthread_mutex_lock(&(threadpool->pool_mutex)) != 0) {
			logg("!Fatal: mutex lock failed\n");
			exit(-2);
		}
		if(!stats_inited) {
			stats_init(threadpool);
			stats_inited = TRUE;
		}
		thrmgr_setactiveengine(NULL);
		thrmgr_setactivetask(NULL, IDLE_TASK);
		timeout.tv_sec = time(NULL) + threadpool->idle_timeout;
		timeout.tv_nsec = 0;
		threadpool->thr_idle++;
		while (((job_data=thrmgr_pop(threadpool)) == NULL)
				&& (threadpool->state != POOL_EXIT)) {
			/* Sleep, awaiting wakeup */
			pthread_cond_signal(&threadpool->idle_cond);
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
	stats_destroy(threadpool);
	if (pthread_mutex_unlock(&(threadpool->pool_mutex)) != 0) {
		/* Fatal error */
		logg("!Fatal: mutex unlock failed\n");
		exit(-2);
	}
	return NULL;
}

static int thrmgr_dispatch_internal(threadpool_t *threadpool, void *user_data, int bulk)
{
	int ret = TRUE;
	pthread_t thr_id;

	if (!threadpool) {
		return FALSE;
	}

	/* Lock the threadpool */
	if (pthread_mutex_lock(&(threadpool->pool_mutex)) != 0) {
		logg("!Mutex lock failed\n");
		return FALSE;
	}

	do {
	    work_queue_t *queue;
	    pthread_cond_t *queueable_cond;
	    int items;

	    if (threadpool->state != POOL_VALID) {
		ret = FALSE;
		break;
	    }

	    if (bulk) {
		queue = threadpool->bulk_queue;
		queueable_cond = &threadpool->queueable_bulk_cond;
	    } else {
		queue = threadpool->single_queue;
		queueable_cond = &threadpool->queueable_single_cond;
	    }

	    while (thrmgr_contended(threadpool, bulk)) {
		logg("$THRMGR: contended, sleeping\n");
		pthread_cond_wait(queueable_cond, &threadpool->pool_mutex);
		logg("$THRMGR: contended, woken\n");
	    }

	    if (!work_queue_add(queue, user_data)) {
		ret = FALSE;
		break;
	    }

	    items = threadpool->single_queue->item_count + threadpool->bulk_queue->item_count;
	    if ((threadpool->thr_idle < items) &&
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

	} while (0);

	if (pthread_mutex_unlock(&(threadpool->pool_mutex)) != 0) {
	    logg("!Mutex unlock failed\n");
	    return FALSE;
	}
	return ret;
}

int thrmgr_dispatch(threadpool_t *threadpool, void *user_data)
{
    return thrmgr_dispatch_internal(threadpool, user_data, 0);
}

int thrmgr_group_dispatch(threadpool_t *threadpool, jobgroup_t *group, void *user_data, int bulk)
{
    int ret;
    if (group) {
	pthread_mutex_lock(&group->mutex);
	group->jobs++;
	logg("$THRMGR: active jobs for %p: %d\n", group, group->jobs);
	pthread_mutex_unlock(&group->mutex);
    }
    if (!(ret = thrmgr_dispatch_internal(threadpool, user_data, bulk)) && group) {
	pthread_mutex_lock(&group->mutex);
	group->jobs--;
	logg("$THRMGR: active jobs for %p: %d\n", group, group->jobs);
	pthread_mutex_unlock(&group->mutex);
    }
    return ret;
}

/* returns
 *   0 - this was not the last thread in the group
 *   1 - this was last thread in group, group freed
 */
int thrmgr_group_finished(jobgroup_t *group, enum thrmgr_exit exitc)
{
    int ret = 0;
    if (!group) {
	/* there is no group, we are obviously the last one */
	return 1;
    }
    pthread_mutex_lock(&group->mutex);
    logg("$THRMGR: group_finished: %p, %d\n", group, group->jobs);
    group->exit_total++;
    switch (exitc) {
	case EXIT_OK:
	    group->exit_ok++;
	    break;
	case EXIT_ERROR:
	    group->exit_error++;
	    break;
	default:
	    break;
    }
    if (group->jobs) {
	if (!--group->jobs) {
	    ret = 1;
	} else
	    logg("$THRMGR: active jobs for %p: %d\n", group, group->jobs);
	if (group->jobs == 1)
	    pthread_cond_signal(&group->only);
    }
    pthread_mutex_unlock(&group->mutex);
    if (ret) {
	logg("$THRMGR: group_finished: freeing %p\n", group);
	pthread_mutex_destroy(&group->mutex);
	pthread_cond_destroy(&group->only);
	free(group);
    }
    return ret;
}

void thrmgr_group_waitforall(jobgroup_t *group, unsigned *ok, unsigned *error, unsigned *total)
{
    int needexit = 0, needfree = 0;
    struct timespec timeout;
    pthread_mutex_lock(&group->mutex);
    while (group->jobs > 1) {
	pthread_mutex_lock(&exit_mutex);
	needexit = progexit;
	pthread_mutex_unlock(&exit_mutex);
	if (needexit)
	    break;
	/* wake to check progexit */
	timeout.tv_sec = time(NULL) + 5;
	timeout.tv_nsec = 0;
	pthread_cond_timedwait(&group->only, &group->mutex, &timeout);
    }
    *ok = group->exit_ok;
    *error = group->exit_error + needexit;
    *total = group->exit_total;
    if(!--group->jobs)
	needfree = 1;
    else
	logg("$THRMGR: active jobs for %p: %d\n", group, group->jobs);
    pthread_mutex_unlock(&group->mutex);
    if (needfree) {
	logg("$THRMGR: group finished freeing %p\n", group);
	free(group);
    }
}

jobgroup_t *thrmgr_group_new(void)
{
    jobgroup_t *group;

    group = malloc(sizeof(*group));
    if (!group)
	return NULL;
    group->jobs = 1;
    group->exit_ok = group->exit_error = group->exit_total = group->force_exit = 0;
    if (pthread_mutex_init(&group->mutex, NULL)) {
	logg("^Failed to initialize group mutex");
	free(group);
	return NULL;
    }
    if (pthread_cond_init(&group->only, NULL)) {
	logg("^Failed to initialize group cond");
	pthread_mutex_destroy(&group->mutex);
	free(group);
	return NULL;
    }
    logg("$THRMGR: new group: %p\n", group);
    return group;
}

int thrmgr_group_need_terminate(jobgroup_t *group)
{
    int ret;
    if (group) {
	pthread_mutex_lock(&group->mutex);
	ret = group->force_exit;
	pthread_mutex_unlock(&group->mutex);
    } else
	ret = 0;
    pthread_mutex_lock(&exit_mutex);
    ret |= progexit;
    pthread_mutex_unlock(&exit_mutex);
    return ret;
}

void thrmgr_group_terminate(jobgroup_t *group)
{
    if (group) {
	/* we may not be the last active job, now
	 * the last active job will free resources */
	pthread_mutex_lock(&group->mutex);
	group->force_exit = 1;
	pthread_mutex_unlock(&group->mutex);
    }
}

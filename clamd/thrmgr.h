/*
 *  Copyright (C) 2004 Trog <trog@clamav.net>
 *
 *  The code is based on the book "Programming with POSIX threads" by Dave
 *  Butenhof
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
/*
 * workq.h
 *
 * This header file defines the interfaces for a "work queue"
 * manager. A "manager object" is created with several
 * parameters, including the required size of a work queue
 * entry, the maximum desired degree of parallelism (number of
 * threads to service the queue), and the address of an
 * execution engine routine.
 *
 * The application requests a work queue entry from the manager,
 * fills in the application-specific fields, and returns it to
 * the queue manager for processing. The manager will create a
 * new thread to service the queue if all current threads are
 * busy and the maximum level of parallelism has not yet been
 * reached.
 *
 * The manager will dequeue items and present them to the
 * processing engine until the queue is empty; at that point,
 * processing threads will begin to shut down. (They will be
 * restarted when work appears.)
 */

#ifndef __THRMGR_H__
#define __THRMGR_H__

#ifdef DEBUG
# define DPRINTF(arg) printf arg
#else
# define DPRINTF(arg)
#endif

#include <pthread.h>
// #include "config.h"

#ifdef BROKEN_COND_SIGNAL
#include <semaphore.h>
#endif

/*
 * Structure to keep track of work requests.
 */
typedef struct work_element_tag {
  struct work_element_tag     *next;
  void                        *data;
} work_element_t;

/*
 * Structure describing a work queue.
 */
typedef struct thrmgr_tag {
  pthread_mutex_t     mutex;
#ifndef BROKEN_COND_SIGNAL
  pthread_cond_t      cond;                    /* wait for work */
#else
  sem_t               semaphore;
#endif
  pthread_attr_t      attr;                    /* create detached threads */
  work_element_t      *first, *last;           /* work queue */
  int                 valid;                   /* set when valid */
  int                 quit;                    /* set when workq should quit */
  int                 parallelism;             /* number of threads required */
  int                 alloc_unit;              /* unit of thread creation */
  int                 counter;                 /* current number of threads */
  int                 idle;                    /* number of idle threads */
  void                (*handler)(void *arg);   /* request handler */
} thrmgr_t;

#define THRMGR_VALID     0xdeadfeed

/*
 * Define work queue functions
 */
extern int thrmgr_init( thrmgr_t *thrmgr,                 /* thread manager */
		        int       max_threads,            /* maximum threads */
		        int       alloc_unit,             /* thread creation unit */
		        void      (*handler)(void *) );   /* request handler */

extern int thrmgr_destroy( thrmgr_t *thrmgr );

extern int thrmgr_add( thrmgr_t *thrmgr,
		       void     *data );

int thrmgr_stat( thrmgr_t     *thrmgr,
		 int *threads,
		 int *idle );

#endif /* __THRMGR_H__ */


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
 * thrmgr.c
 *
 * This file implements the interfaces for a "work queue"
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
#include <pthread.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <errno.h>

#include "thrmgr.h"
#include "others.h"

/*
 * Thread start routine to serve the work queue.
 */
static void *thrmgr_server (void *arg)
{
  thrmgr_t *thrmgr = (thrmgr_t *)arg;
  work_element_t *we;
  int status;

  /*
   * We don't need to validate the thrmgr_t here... we don't
   * create server threads until requests are queued (the
   * queue has been initialized by then!) and we wait for all
   * server threads to terminate before destroying a work
   * queue.
   */
/*    log_message ("A worker is starting"); */
  status = pthread_mutex_lock (&thrmgr->mutex);
  if (status != 0) {
    //log_message ("A worker is dying");
    return(NULL);
  }

  while (1) {
    thrmgr->idle++;

 /*     log_message ("Worker waiting for work - idle:%d", thrmgr->idle); */
    
    while ( (thrmgr->first == NULL) && !thrmgr->quit) {
#ifndef BROKEN_COND_SIGNAL
      status = pthread_cond_wait (&thrmgr->cond, &thrmgr->mutex);
#else
      status = pthread_mutex_unlock (&thrmgr->mutex);
      status = sem_wait(&thrmgr->semaphore);
      pthread_mutex_lock (&thrmgr->mutex);
#endif
      if (status != 0) {
	/*
	 * This shouldn't happen, so the work queue
	 * package should fail. Because the work queue
	 * API is asynchronous, that would add
	 * complication. Because the chances of failure
	 * are slim, I choose to avoid that
	 * complication. The server thread will return,
	 * and allow another server thread to pick up
	 * the work later. Note that, if this was the
	 * only server thread, the queue won't be
	 * serviced until a new work item is
	 * queued. That could be fixed by creating a new
	 * server here.
	 */
	//log_message ("Worker wait failed, %d (%s)",
		     //status, strerror (status));
	thrmgr->counter--;
	thrmgr->idle--;
	pthread_mutex_unlock (&thrmgr->mutex);
	return(NULL);
      }
    }
    we = thrmgr->first;
    
    if (we != NULL) {
      thrmgr->first = we->next;
      if (thrmgr->last == we) {
	thrmgr->last = NULL;
      }
      thrmgr->idle--;
      status = pthread_mutex_unlock (&thrmgr->mutex);
      if (status != 0) {
	//log_message ("A worker is dying");
	return(NULL);
      }
/*        log_message ("Worker calling handler"); */
      thrmgr->handler (we->data);
      free (we);
      status = pthread_mutex_lock (&thrmgr->mutex);
      if (status != 0) {
	//log_message ("A worker is dying");
	return(NULL);
      }
    }
    
    /*
     * If there are no more work requests, and the servers
     * have been asked to quit, then shut down.
     */
    if ( (thrmgr->first == NULL) &&thrmgr->quit) {
      //log_message ("Worker shutting down");
      thrmgr->counter--;
      
      /*
       * NOTE: Just to prove that every rule has an
       * exception, I'm using the "cond" condition for two
       * separate predicates here.  That's OK, since the
       * case used here applies only once during the life
       * of a work queue -- during rundown. The overhead
       * is minimal and it's not worth creating a separate
       * condition variable that would be waited and
       * signaled exactly once!
       */
#ifndef BROKEN_COND_SIGNAL
      if (thrmgr->counter == 0) {
	pthread_cond_broadcast (&thrmgr->cond);
      }
#endif
      pthread_mutex_unlock (&thrmgr->mutex);
      //log_message ("A worker is dying");
      return(NULL);
    }
    
  }

  pthread_mutex_unlock (&thrmgr->mutex);
  //log_message ("Worker exiting");
  return(NULL);
}

/*
 * Initialize a thread manager.
 */
int thrmgr_init( thrmgr_t *thrmgr,                 /* thread manager */
		 int       max_threads,            /* maximum threads */
		 int       alloc_unit,             /* thread creation unit */
		 void      (*handler)(void *arg))  /* request handler */
{
  int status;

  status = pthread_attr_init (&thrmgr->attr);
  if (status != 0)
    return(status);
  status = pthread_attr_setdetachstate (&thrmgr->attr,
					PTHREAD_CREATE_DETACHED);
  if (status != 0) {
    pthread_attr_destroy (&thrmgr->attr);
    return(status);
  }
  status = pthread_mutex_init (&thrmgr->mutex, NULL);
  if (status != 0) {
    pthread_attr_destroy (&thrmgr->attr);
    return(status);
  }
#ifndef BROKEN_COND_SIGNAL
  status = pthread_cond_init (&thrmgr->cond, NULL);
#else
  status = sem_init(&thrmgr->semaphore, 0, 0);
#endif
  if (status != 0) {
    pthread_mutex_destroy (&thrmgr->mutex);
    pthread_attr_destroy (&thrmgr->attr);
    return(status);
  }
  thrmgr->quit = 0;                       /* not time to quit */
  thrmgr->first = thrmgr->last = NULL;    /* no queue entries */
  thrmgr->parallelism = max_threads;      /* max servers */
  thrmgr->alloc_unit = alloc_unit;        /* thread creation unit */
  thrmgr->counter = 0;                    /* no server threads yet */
  thrmgr->idle = 0;                       /* no idle servers */
  thrmgr->handler = handler;
  thrmgr->valid = THRMGR_VALID;
  return(0);
}

/*
 * Destroy a thread manager
 */
int thrmgr_destroy (thrmgr_t *thrmgr)
{
  int status, status1, status2;
  
  if (thrmgr->valid != THRMGR_VALID) {
    return EINVAL;
  }
  status = pthread_mutex_lock (&thrmgr->mutex);
  if (status != 0) {
    return(status);
  }
  thrmgr->valid = 0;             /* prevent any other operations */

  /*
   * Check whether any threads are active, and run them down:
   *
   * 1.       set the quit flag
   * 2.       broadcast to wake any servers that may be asleep
   * 3.       wait for all threads to quit (counter goes to 0)
   *
   */
  if (thrmgr->counter > 0) {
    thrmgr->quit = 1;
    /* if any threads are idling, wake them. */
    if (thrmgr->idle > 0) {
#ifndef BROKEN_COND_SIGNAL
      status = pthread_cond_broadcast (&thrmgr->cond);
      if (status != 0) {
	pthread_mutex_unlock (&thrmgr->mutex);
	return(status);
      }
#endif
    }

    /*
     * Just to prove that every rule has an exception, I'm
     * using the "cv" condition for two separate predicates
     * here. That's OK, since the case used here applies
     * only once during the life of a work queue -- during
     * rundown. The overhead is minimal and it's not worth
     * creating a separate condition variable that would be
     * waited and signalled exactly once!
     */
    while (thrmgr->counter > 0) {
#ifndef BROKEN_COND_SIGNAL
      status = pthread_cond_wait (&thrmgr->cond, &thrmgr->mutex);
      if (status != 0) {
	pthread_mutex_unlock (&thrmgr->mutex);
	return(status);
      }
#endif
    }       
  }
  status = pthread_mutex_unlock (&thrmgr->mutex);
  if (status != 0) {
    return(status);
  }
  status = pthread_mutex_destroy (&thrmgr->mutex);
#ifndef BROKEN_COND_SIGNAL
  status1 = pthread_cond_destroy (&thrmgr->cond);
#else
  status1 = sem_destroy(&thrmgr->semaphore);
#endif
  status2 = pthread_attr_destroy (&thrmgr->attr);
  return (status ? status : (status1 ? status1 : status2));
}

/*
 * Add an item to a work queue.
 */
int thrmgr_add( thrmgr_t *thrmgr,
		void     *element )
{
  work_element_t *item;
  pthread_t id;
  int status;
  int count;

  if (thrmgr->valid != THRMGR_VALID) {
    return(EINVAL);
  }

  /*
   * Create and initialize a request structure.
   */
  item = mmalloc( sizeof (work_element_t) );
  item->data = element;
  item->next = NULL;
  status = pthread_mutex_lock (&thrmgr->mutex);
  if (status != 0) {
    free (item);
    return(status);
  }

  /*
   * Add the request to the end of the queue, updating the
   * first and last pointers.
   */
  if (thrmgr->first == NULL) {
    thrmgr->first = item;
  } else {
    thrmgr->last->next = item;
  }
  thrmgr->last = item;
  
  /*
   * if any threads are idling, wake one.
   */
/*    printf("Idle threads: %d\n", thrmgr->idle); */
  if (thrmgr->idle > 0) {
#ifndef BROKEN_COND_SIGNAL
    status = pthread_cond_signal (&thrmgr->cond);
#else
    status = sem_post(&thrmgr->semaphore);
#endif
    if (status != 0) {
      pthread_mutex_unlock (&thrmgr->mutex);
      return(status);
    }
  } else if (thrmgr->counter < thrmgr->parallelism) {
    /*
     * If there were no idling threads, and we're allowed to
     * create a new thread, do so.
     */
    for ( count=0 ; count < thrmgr->alloc_unit ; count++ ) {
/*        log_message ("Creating new worker"); */
      status = pthread_create (&id, &thrmgr->attr, thrmgr_server, (void*)thrmgr);
      if (status != 0) {
	pthread_mutex_unlock (&thrmgr->mutex);
	return(status);
      }
      thrmgr->counter++;
    }
  }
  pthread_mutex_unlock (&thrmgr->mutex);
  return(0);
}

int thrmgr_stat( thrmgr_t *thrmgr,
		 int      *threads,
		 int      *idle )
{
  int status;

  status = pthread_mutex_lock (&thrmgr->mutex);
  if (status != 0) {
    return(-1);
  }

  *threads = thrmgr->counter;
  *idle = thrmgr->idle;

  pthread_mutex_unlock (&thrmgr->mutex);
  return(0);
}
  


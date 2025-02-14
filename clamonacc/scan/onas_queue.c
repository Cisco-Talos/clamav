/*
 *  Copyright (C) 2019-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *
 *  Authors: Mickey Sola
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

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <pthread.h>
#if defined(__linux__)
#include <sys/prctl.h>
#endif
#include <string.h>

// libclamav
#include "clamav.h"

// common
#include "optparser.h"
#include "output.h"

#include "../misc/utils.h"
#include "../c-thread-pool/thpool.h"
#include "thread.h"
#include "onas_queue.h"

static void onas_scan_queue_exit(void *arg);
static int onas_consume_event(threadpool thpool);
static cl_error_t onas_new_event_queue_node(struct onas_event_queue_node **node);
static void onas_destroy_event_queue_node(struct onas_event_queue_node *node);

static pthread_mutex_t onas_queue_lock = PTHREAD_MUTEX_INITIALIZER;

pthread_cond_t onas_scan_queue_empty_cond = PTHREAD_COND_INITIALIZER;
extern pthread_t scan_queue_pid;
static threadpool g_thpool;

static struct onas_event_queue_node *g_onas_event_queue_head = NULL;
static struct onas_event_queue_node *g_onas_event_queue_tail = NULL;

static struct onas_event_queue g_onas_event_queue;

static cl_error_t onas_new_event_queue_node(struct onas_event_queue_node **node)
{

    *node = malloc(sizeof(struct onas_event_queue_node));
    if (NULL == *node) {
        return CL_EMEM;
    }

    **node = (struct onas_event_queue_node){
        .next = NULL,
        .prev = NULL,

        .data = NULL};

    return CL_SUCCESS;
}

static void *onas_init_event_queue(void)
{

    if (CL_EMEM == onas_new_event_queue_node(&g_onas_event_queue_head)) {
        return NULL;
    }

    if (CL_EMEM == onas_new_event_queue_node(&g_onas_event_queue_tail)) {
        return NULL;
    }

    g_onas_event_queue_tail->prev = g_onas_event_queue_head;
    g_onas_event_queue_head->next = g_onas_event_queue_tail;

    g_onas_event_queue = (struct onas_event_queue){
        .head = g_onas_event_queue_head,
        .tail = g_onas_event_queue_tail,

        .size = 0};

    return &g_onas_event_queue;
}

static void onas_destroy_event_queue_node(struct onas_event_queue_node *node)
{

    if (NULL == node) {
        return;
    }

    node->next = NULL;
    node->prev = NULL;
    node->data = NULL;

    free(node);
    node = NULL;

    return;
}

static void onas_destroy_event_queue(void)
{

    if (NULL == g_onas_event_queue_head) {
        return;
    }

    struct onas_event_queue_node *curr = g_onas_event_queue_head;
    struct onas_event_queue_node *next = curr->next;

    do {
        onas_destroy_event_queue_node(curr);
        curr = next;
        if (curr) {
            next = curr->next;
        }
    } while (curr);

    return;
}

void *onas_scan_queue_th(void *arg)
{
    /* Set thread name for profiling and debugging */
    const char thread_name[] = "clamonacc-sq";

#if defined(__linux__)
    /* Use prctl instead to prevent using _GNU_SOURCE flag and implicit declaration */
    prctl(PR_SET_NAME, thread_name);
#elif defined(__APPLE__) && defined(__MACH__)
    pthread_setname_np(thread_name);
#else
    logg(LOGG_WARNING, "ClamScanQueue: Setting of the thread name is currently not supported on this system\n");
#endif

    /* not a ton of use for context right now, but perhaps in the future we can pass in more options */
    struct onas_context *ctx = (struct onas_context *)arg;
    sigset_t sigset;

    /* ignore all signals except SIGUSR2 */
    sigfillset(&sigset);
    sigdelset(&sigset, SIGUSR2);
    /* The behavior of a process is undefined after it ignores a
     * SIGFPE, SIGILL, SIGSEGV, or SIGBUS signal */
    sigdelset(&sigset, SIGFPE);
    sigdelset(&sigset, SIGILL);
    sigdelset(&sigset, SIGSEGV);
    sigdelset(&sigset, SIGTERM);
    sigdelset(&sigset, SIGINT);
#ifdef SIGBUS
    sigdelset(&sigset, SIGBUS);
#endif
    pthread_sigmask(SIG_SETMASK, &sigset, NULL);

    logg(LOGG_DEBUG, "ClamScanQueue: initializing event queue consumer ... (%d) threads in thread pool\n", ctx->maxthreads);
    onas_init_event_queue();
    threadpool thpool = thpool_init(ctx->maxthreads);
    g_thpool          = thpool;

    /* loop w/ onas_consume_event until we die */
    pthread_cleanup_push(onas_scan_queue_exit, NULL);
    logg(LOGG_DEBUG, "ClamScanQueue: waiting to consume events ...\n");
    do {
        onas_consume_event(thpool);
    } while (1);

    pthread_cleanup_pop(1);
}

static int onas_queue_is_b_empty(void)
{

    if (g_onas_event_queue.head->next == g_onas_event_queue.tail) {
        return 1;
    }

    return 0;
}

static int onas_consume_event(threadpool thpool)
{
    pthread_mutex_lock(&onas_queue_lock);

    while (onas_queue_is_b_empty()) {
        pthread_cond_wait(&onas_scan_queue_empty_cond, &onas_queue_lock);
    }

    struct onas_event_queue_node *popped_node = g_onas_event_queue_head->next;
    g_onas_event_queue_head->next             = g_onas_event_queue_head->next->next;
    g_onas_event_queue_head->next->prev       = g_onas_event_queue_head;
    g_onas_event_queue.size--;

    pthread_mutex_unlock(&onas_queue_lock);

    thpool_add_work(thpool, (void *)onas_scan_worker, (void *)popped_node->data);
    onas_destroy_event_queue_node(popped_node);

    return 1;
}

cl_error_t onas_queue_event(struct onas_scan_event *event_data)
{
    struct onas_event_queue_node *node = NULL;
    if (CL_EMEM == onas_new_event_queue_node(&node))
        return CL_EMEM;

    pthread_mutex_lock(&onas_queue_lock);
    node->next                                                            = g_onas_event_queue_tail;
    node->prev                                                            = g_onas_event_queue_tail->prev;
    ((struct onas_event_queue_node *)g_onas_event_queue_tail->prev)->next = node;
    g_onas_event_queue_tail->prev                                         = node;

    node->data = event_data;

    g_onas_event_queue.size++;

    pthread_cond_signal(&onas_scan_queue_empty_cond);
    pthread_mutex_unlock(&onas_queue_lock);

    return CL_SUCCESS;
}

cl_error_t onas_scan_queue_start(struct onas_context **ctx)
{

    pthread_attr_t scan_queue_attr;
    int32_t thread_started = 1;

    if (!ctx || !*ctx) {
        logg(LOGG_DEBUG, "ClamScanQueue: unable to start clamonacc. (bad context)\n");
        return CL_EARG;
    }

    if (pthread_attr_init(&scan_queue_attr)) {
        return CL_BREAK;
    }
    pthread_attr_setdetachstate(&scan_queue_attr, PTHREAD_CREATE_JOINABLE);
    thread_started = pthread_create(&scan_queue_pid, &scan_queue_attr, onas_scan_queue_th, *ctx);

    if (0 != thread_started) {
        /* Failed to create thread */
        logg(LOGG_DEBUG, "ClamScanQueue: Unable to start event consumer queue thread ... \n");
        return CL_ECREAT;
    }

    return CL_SUCCESS;
}

static void onas_scan_queue_exit(void *arg)
{
    UNUSEDPARAM(arg);

    logg(LOGG_DEBUG, "ClamScanQueue: onas_scan_queue_exit()\n");
    if (g_thpool) {
        thpool_wait(g_thpool);
        thpool_destroy(g_thpool);
        g_thpool = NULL;
    }
    onas_destroy_event_queue();
    logg(LOGG_INFO, "ClamScanQueue: stopped\n");
}

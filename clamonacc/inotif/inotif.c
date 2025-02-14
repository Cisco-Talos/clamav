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
#include <errno.h>
#include <stdbool.h>

#if defined(HAVE_SYS_FANOTIFY_H)
#include <sys/fanotify.h>
#include <sys/inotify.h>
#endif

// libclamav
#include "clamav.h"
#include "scanners.h"

// common
#include "optparser.h"
#include "output.h"
#include "misc.h"
// clamd
#include "server.h"
#include "clamd_others.h"
#include "scanner.h"

#include "../fanotif/fanotif.h"
#include "hash.h"
#include "inotif.h"
#include "../scan/thread.h"
#include "../scan/onas_queue.h"
#include "../misc/utils.h"

#if defined(HAVE_SYS_FANOTIFY_H)

static int onas_ddd_init_ht(uint32_t ht_size);
static int onas_ddd_init_wdlt(uint64_t nwatches);
static int onas_ddd_grow_wdlt(void);

static int onas_ddd_watch(const char *pathname, int fan_fd, uint64_t fan_mask, int in_fd, uint64_t in_mask);
static int onas_ddd_watch_hierarchy(const char *pathname, size_t len, int fd, uint64_t mask, uint32_t type);
static int onas_ddd_unwatch(const char *pathname, int fan_fd, int in_fd);
static int onas_ddd_unwatch_hierarchy(const char *pathname, size_t len, int fd, uint32_t type);

static void onas_ddd_handle_in_moved_to(struct onas_context *ctx, const char *path, const char *child_path, const struct inotify_event *event, int wd, uint64_t in_mask);
static void onas_ddd_handle_in_create(struct onas_context *ctx, const char *path, const char *child_path, const struct inotify_event *event, int wd, uint64_t in_mask);
static void onas_ddd_handle_in_close_write(struct onas_context *ctx, const char *child_path);
static void onas_ddd_handle_in_moved_from(struct onas_context *ctx, const char *path, const char *child_path, const struct inotify_event *event, int wd);
static void onas_ddd_handle_in_delete(struct onas_context *ctx, const char *path, const char *child_path, const struct inotify_event *event, int wd);
static void onas_ddd_handle_extra_scanning(struct onas_context *ctx, const char *pathname, int extra_options);
static void onas_ddd_exit(void *arg);

/* TODO: Unglobalize these. */
static struct onas_ht *ddd_ht;
static char **wdlt;
static uint32_t wdlt_len;
static int onas_in_fd;
extern pthread_t ddd_pid;

static int onas_ddd_init_ht(uint32_t ht_size)
{

    if (ht_size <= 0)
        ht_size = ONAS_DEFAULT_HT_SIZE;

    return onas_ht_init(&ddd_ht, ht_size);
}

/**
 * @brief Initialize watch descriptor lookup table which we use alongside inotify to keep track of which open watchpoints correspond to which objects
 */
static int onas_ddd_init_wdlt(uint64_t nwatches)
{

    if (nwatches <= 0) return CL_EARG;

    wdlt = (char **)calloc(nwatches << 1, sizeof(char *));
    if (!wdlt) return CL_EMEM;

    wdlt_len = nwatches << 1;

    return CL_SUCCESS;
}

/**
 * @brief Initialize watch descriptor lookup table which we use alongside inotify to keep track of which open watchpoints correspond to which objects
 */
static int onas_ddd_grow_wdlt(void)
{

    char **ptr = NULL;

    ptr = (char **)cli_safer_realloc(wdlt, wdlt_len << 1);
    if (ptr) {
        wdlt = ptr;
        memset(&ptr[wdlt_len], 0, sizeof(char *) * (wdlt_len - 1));
    } else {
        return CL_EMEM;
    }

    wdlt_len <<= 1;

    return CL_SUCCESS;
}

/* TODO: Support configuration for changing/setting number of inotify watches. */
int onas_ddd_init(uint64_t nwatches, size_t ht_size)
{

    const char *nwatch_file            = "/proc/sys/fs/inotify/max_user_watches";
    int nwfd                           = 0;
    int ret                            = 0;
    char nwatch_str[MAX_WATCH_LEN + 1] = {0};
    char *p                            = NULL;
    int64_t tmp                        = 0;
    nwatches                           = 0;

    nwfd = open(nwatch_file, O_RDONLY);
    if (nwfd < 0) return CL_EOPEN;

    ret = read(nwfd, nwatch_str, MAX_WATCH_LEN);
    close(nwfd);
    if (ret < 0) return CL_EREAD;

    tmp = strtol(nwatch_str, &p, 10);
    if (tmp < 0 || tmp == LONG_MAX) {
        /*Seems like a sane value (also the value on my ubuntu system)*/
        nwatches = 0x10000;
    } else {
        nwatches = tmp;
    }

    ret = onas_ddd_init_wdlt(nwatches);
    if (ret) return ret;

    ret = onas_ddd_init_ht(ht_size);
    if (ret) return ret;

    return CL_SUCCESS;
}

/**
 * @brief convenience function for adding both inotify and fanotify watchpoints for a single path in one go
 */
static int onas_ddd_watch(const char *pathname, int fan_fd, uint64_t fan_mask, int in_fd, uint64_t in_mask)
{
    if (!pathname || fan_fd <= 0 || in_fd <= 0) return CL_ENULLARG;

    int ret    = CL_SUCCESS;
    size_t len = strlen(pathname);

    ret = onas_ddd_watch_hierarchy(pathname, len, in_fd, in_mask, ONAS_IN);
    if (ret) return ret;

    ret = onas_ddd_watch_hierarchy(pathname, len, fan_fd, fan_mask, ONAS_FAN);
    if (ret) return ret;

    return CL_SUCCESS;
}

/**
 * @brief recursively adds a hierarchy from the hash table and all watches of a single type to specified object
 *
 * @param pathname  the directory to start watching
 * @param len       the size of pathname in bytes
 * @param fd        the fanotify or inotify file descriptor
 * @param mask      options for watching the path
 * @param type      specifies whether or not to add inotify or fanotify watchpoints and the type of fd passed
 */
static int onas_ddd_watch_hierarchy(const char *pathname, size_t len, int fd, uint64_t mask, uint32_t type)
{

    if (!pathname || fd <= 0 || !type) return CL_ENULLARG;

    if (type == (ONAS_IN | ONAS_FAN)) return CL_EARG;

    struct onas_hnode *hnode  = NULL;
    struct onas_element *elem = NULL;
    int wd                    = 0;

    if (onas_ht_get(ddd_ht, pathname, len, &elem) != CL_SUCCESS) {
        logg(LOGG_ERROR, "ClamInotif: could not add element to hash table for %s\n", pathname);
        return CL_EARG;
    }

    hnode = elem->data;

    if (type & ONAS_IN) {
        wd = inotify_add_watch(fd, pathname, (uint32_t)mask);

        if (wd < 0) {
            logg(LOGG_ERROR, "ClamInotif: watch descriptor issue when adding watch for %s\n", pathname);
            return CL_EARG;
        }
        if ((uint32_t)wd >= wdlt_len) {
            onas_ddd_grow_wdlt();
        }

        /* Link the hash node to the watch descriptor lookup table */
        hnode->wd = wd;
        wdlt[wd]  = hnode->pathname;

        hnode->watched |= ONAS_INWATCH;
    } else if (type & ONAS_FAN) {
        if (fanotify_mark(fd, FAN_MARK_ADD, mask, AT_FDCWD, hnode->pathname) < 0) {
            logg(LOGG_ERROR, "ClamInotif: error when marking %s to be watched by fanotify\n", hnode->pathname);
            return CL_EARG;
        }
        hnode->watched |= ONAS_FANWATCH;
    } else {
        logg(LOGG_ERROR, "ClamInotif: when adding watch for %s, neither fanotify or inotify were specified\n", pathname);
        return CL_EARG;
    }

    /* recursively watch all children */
    struct onas_lnode *curr = hnode->childhead;

    while (curr->next != hnode->childtail) {
        curr = curr->next;

        size_t size      = len + strlen(curr->dirname) + 2;
        char *child_path = (char *)malloc(size);
        if (child_path == NULL) {
            logg(LOGG_ERROR, "ClamInotif: out of memory when adding child for %s\n", hnode->pathname);
            return CL_EMEM;
        }

        if (hnode->pathname[len - 1] == '/')
            snprintf(child_path, --size, "%s%s", hnode->pathname, curr->dirname);
        else
            snprintf(child_path, size, "%s/%s", hnode->pathname, curr->dirname);

        if (onas_ddd_watch_hierarchy(child_path, strlen(child_path), fd, mask, type)) {
            logg(LOGG_ERROR, "ClamInotif: issue when adding watch for %s\n", child_path);
            return CL_EARG;
        }
        free(child_path);
    }

    return CL_SUCCESS;
}

/**
 * @brief convenience function for removing both inotify and fanotify watchpoints for a single path in one go
 */
static int onas_ddd_unwatch(const char *pathname, int fan_fd, int in_fd)
{
    if (!pathname || fan_fd <= 0 || in_fd <= 0) return CL_ENULLARG;

    int ret    = CL_SUCCESS;
    size_t len = strlen(pathname);

    ret = onas_ddd_unwatch_hierarchy(pathname, len, in_fd, ONAS_IN);
    if (ret) return ret;

    ret = onas_ddd_unwatch_hierarchy(pathname, len, fan_fd, ONAS_FAN);
    if (ret) return ret;

    return CL_SUCCESS;
}

/**
 * @brief recursively removes a hierarchy from the hash table and drops all watches of a single type from linked objects
 *
 * @param pathname  the directory to stop watching
 * @param len       the size of pathname in bytes
 * @param fd        the fanotify or inotify file descriptor
 * @param type      specifies whether or not to remove inotify or fanotify watchpoints and the type of fd passed
 */
static int onas_ddd_unwatch_hierarchy(const char *pathname, size_t len, int fd, uint32_t type)
{

    if (!pathname || fd <= 0 || !type) return CL_ENULLARG;

    if (type == (ONAS_IN | ONAS_FAN)) return CL_EARG;

    struct onas_hnode *hnode  = NULL;
    struct onas_element *elem = NULL;
    int wd                    = 0;

    if (onas_ht_get(ddd_ht, pathname, len, &elem)) return CL_EARG;

    hnode = elem->data;

    if (type & ONAS_IN) {
        wd = hnode->wd;

        if (!inotify_rm_watch(fd, wd) && errno != ENOENT) return CL_EARG;

        /* Unlink the hash node from the watch descriptor lookup table */
        hnode->wd = 0;
        wdlt[wd]  = NULL;

        hnode->watched = ONAS_STOPWATCH;
    } else if (type & ONAS_FAN) {
        if (fanotify_mark(fd, FAN_MARK_REMOVE, 0, AT_FDCWD, hnode->pathname) < 0) return CL_EARG;
        hnode->watched = ONAS_STOPWATCH;
    } else {
        return CL_EARG;
    }

    /* free all children recursively */
    struct onas_lnode *curr = hnode->childhead;

    while (curr->next != hnode->childtail) {
        curr = curr->next;

        size_t size      = len + strlen(curr->dirname) + 2;
        char *child_path = (char *)malloc(size);
        if (child_path == NULL)
            return CL_EMEM;
        if (hnode->pathname[len - 1] == '/')
            snprintf(child_path, --size, "%s%s", hnode->pathname, curr->dirname);
        else
            snprintf(child_path, size, "%s/%s", hnode->pathname, curr->dirname);

        onas_ddd_unwatch_hierarchy(child_path, strlen(child_path), fd, type);
        free(child_path);
    }

    return CL_SUCCESS;
}

cl_error_t onas_enable_inotif_ddd(struct onas_context **ctx)
{

    pthread_attr_t ddd_attr;
    int32_t thread_started = 1;

    if (!ctx || !*ctx) {
        logg(LOGG_ERROR, "ClamInotif: unable to start clamonacc. (bad context)\n");
        return CL_EARG;
    }

    if ((*ctx)->ddd_enabled) {
        do {
            if (pthread_attr_init(&ddd_attr)) break;
            pthread_attr_setdetachstate(&ddd_attr, PTHREAD_CREATE_JOINABLE);
            thread_started = pthread_create(&ddd_pid, &ddd_attr, onas_ddd_th, *ctx);
        } while (0);
    }

    if (0 != thread_started) {
        /* Failed to create thread */
        logg(LOGG_ERROR, "ClamInotif: Unable to start dynamic directory determination ... \n");
        return CL_ECREAT;
    }

    return CL_SUCCESS;
}

void *onas_ddd_th(void *arg)
{
    /* Set thread name for profiling and debugging */
    const char thread_name[] = "clamonacc-ddd";

#if defined(__linux__)
    /* Use prctl instead to prevent using _GNU_SOURCE flag and implicit declaration */
    prctl(PR_SET_NAME, thread_name);
#elif defined(__APPLE__) && defined(__MACH__)
    pthread_setname_np(thread_name);
#else
    logg(LOGG_WARNING, "ClamInotif: Setting of the thread name is currently not supported on this system\n");
#endif

    struct onas_context *ctx = (struct onas_context *)arg;
    sigset_t sigset;
    const struct optstruct *pt;
    const struct optstruct *pt_tmpdir;
    const char *clamd_tmpdir;
    uint64_t in_mask = IN_ONLYDIR | IN_MOVE | IN_DELETE | IN_CREATE | IN_CLOSE_WRITE;
    fd_set rfds;
    char buf[4096];
    ssize_t bread;
    const struct inotify_event *event;
    int ret, len, idx;

    char **include_list = NULL;
    char **exclude_list = NULL;
    int num_exdirs, num_indirs;
    cl_error_t err;

    /* ignore all signals */
    sigfillset(&sigset);
    sigdelset(&sigset, SIGUSR1);
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

    logg(LOGG_DEBUG, "ClamInotif: starting inotify event loop ...\n");

    onas_in_fd = inotify_init1(IN_NONBLOCK);
    if (onas_in_fd == -1) {
        logg(LOGG_ERROR, "ClamInotif: could not init inotify\n");
        return NULL;
    }

    ret = onas_ddd_init(0, ONAS_DEFAULT_HT_SIZE);
    if (ret) {
        logg(LOGG_ERROR, "ClamInotif: failed to initialize DDD system\n");
        return NULL;
    }

    logg(LOGG_DEBUG, "ClamInotif: dynamically determining directory hierarchy...\n");
    /* Add provided paths recursively. */

    if (!optget(ctx->opts, "watch-list")->enabled && !optget(ctx->clamdopts, "OnAccessIncludePath")->enabled) {
        logg(LOGG_ERROR, "ClamInotif: Please specify at least one path with OnAccessIncludePath\n");
        return NULL;
    }

    pt_tmpdir = optget(ctx->clamdopts, "TemporaryDirectory");
    if (pt_tmpdir->enabled) {
        clamd_tmpdir = pt_tmpdir->strarg;
    } else {
        clamd_tmpdir = cli_gettmpdir();
    }

    if ((pt = optget(ctx->clamdopts, "OnAccessIncludePath"))->enabled) {

        while (pt) {
            if (!strcmp(pt->strarg, "/")) {
                logg(LOGG_ERROR, "ClamInotif: Not watching path '%s' while DDD is enabled\n", pt->strarg);
                logg(LOGG_ERROR, "ClamInotif: Please use the OnAccessMountPath option to watch '%s'\n", pt->strarg);
                pt = (struct optstruct *)pt->nextarg;
                continue;
            }

            if (0 == strcmp(clamd_tmpdir, pt->strarg)) {
                logg(LOGG_ERROR, "ClamInotif: Not watching path '%s'\n", pt->strarg);
                logg(LOGG_ERROR, "ClamInotif: ClamOnAcc should not watch the directory clamd is using for temp files\n");
                logg(LOGG_ERROR, "ClamInotif: Consider setting TemporaryDirectory in clamd.conf to a different directory.\n");
                pt = (struct optstruct *)pt->nextarg;
                continue;
            }

            if (onas_ht_get(ddd_ht, pt->strarg, strlen(pt->strarg), NULL) != CL_SUCCESS) {
                if (onas_ht_add_hierarchy(ddd_ht, pt->strarg)) {
                    logg(LOGG_ERROR, "ClamInotif: can't include '%s'\n", pt->strarg);
                    return NULL;
                } else {
                    logg(LOGG_INFO, "ClamInotif: watching '%s' (and all sub-directories)\n", pt->strarg);
                }
            }

            pt = (struct optstruct *)pt->nextarg;
        }
    }

    if ((pt = optget(ctx->opts, "watch-list"))->enabled) {

        num_indirs = 0;
        err        = CL_SUCCESS;

        include_list = onas_get_opt_list(pt->strarg, &num_indirs, &err);
        if (NULL == include_list) {
            logg(LOGG_ERROR, "ClamInotif: could not parse include list (%s)\n", cl_strerror(err));
            return NULL;
        }

        idx = 0;
        while (NULL != include_list[idx]) {
            if (onas_ht_get(ddd_ht, include_list[idx], strlen(include_list[idx]), NULL) != CL_SUCCESS) {
                if (!strcmp(include_list[idx], "/")) {
                    logg(LOGG_ERROR, "ClamInotif: Not watching path '%s' while DDD is enabled\n", include_list[idx]);
                    logg(LOGG_ERROR, "ClamInotif: Please use the OnAccessMountPath option to watch '%s'\n", include_list[idx]);
                    pt = (struct optstruct *)pt->nextarg;
                    continue;
                }

                if (0 == strcmp(clamd_tmpdir, include_list[idx])) {
                    logg(LOGG_ERROR, "ClamInotif: Not watching path '%s'\n", include_list[idx]);
                    logg(LOGG_ERROR, "ClamInotif: ClamOnAcc should not watch the directory clamd is using for temp files\n");
                    logg(LOGG_ERROR, "ClamInotif: Consider setting TemporaryDirectory in clamd.conf to a different directory.\n");
                    pt = (struct optstruct *)pt->nextarg;
                    continue;
                }

                if (onas_ht_add_hierarchy(ddd_ht, include_list[idx])) {
                    logg(LOGG_ERROR, "ClamInotif: can't include '%s'\n", include_list[idx]);
                    return NULL;
                } else {
                    logg(LOGG_INFO, "ClamInotif: watching '%s' (and all sub-directories)\n", include_list[idx]);
                }
            }

            idx++;
        }
    }

    /* Remove provided paths recursively. */
    if ((pt = optget(ctx->clamdopts, "OnAccessExcludePath"))->enabled) {
        while (pt) {
            struct onas_bucket *ob = ddd_ht->head;
            /* Iterate through the activated buckets to find matched paths */
            while (ob != NULL) {
                struct onas_element *oe = ob->head;
                while (oe != NULL) {
                    if (match_regex(oe->key, pt->strarg)) {
                        if (onas_ht_get(ddd_ht, oe->key, oe->klen, NULL) == CL_SUCCESS) {
                            char *oe_key = cli_safer_strdup(oe->key);
                            if (onas_ht_rm_hierarchy(ddd_ht, oe->key, oe->klen, 0)) {
                                logg(LOGG_ERROR, "ClamInotif: can't exclude '%s'\n", oe_key);
                                free(oe_key);
                                return NULL;
                            } else {
                                logg(LOGG_INFO, "ClamInotif: excluding '%s' (and all sub-directories)\n", oe_key);
                                free(oe_key);
                            }
                        }
                    }
                    oe = oe->next;
                }
                ob = ob->next;
            }
            pt = (struct optstruct *)pt->nextarg;
        }
    }

    if ((pt = optget(ctx->opts, "exclude-list"))->enabled) {

        num_exdirs = 0;
        err        = CL_SUCCESS;

        exclude_list = onas_get_opt_list(pt->strarg, &num_exdirs, &err);
        if (NULL == exclude_list) {
            logg(LOGG_ERROR, "ClamInotif: could not parse exclude list (%s)\n", cl_strerror(err));
            return NULL;
        }

        idx = 0;
        while (exclude_list[idx] != NULL) {
            if (onas_ht_get(ddd_ht, exclude_list[idx], strlen(exclude_list[idx]), NULL) == CL_SUCCESS) {
                if (onas_ht_rm_hierarchy(ddd_ht, exclude_list[idx], strlen(exclude_list[idx]), 0)) {
                    logg(LOGG_ERROR, "ClamInotif: can't exclude '%s'\n", exclude_list[idx]);
                    return NULL;
                } else {
                    logg(LOGG_INFO, "ClamInotif: excluding '%s' (and all sub-directories)\n", exclude_list[idx]);
                }
            }

            idx++;
        }
    }

    /* Also remove the clamd temp directory, in case its parent directory was watched */
    logg(LOGG_DEBUG, "Excluding temp directory: %s\n", clamd_tmpdir);
    if (onas_ht_rm_hierarchy(ddd_ht, clamd_tmpdir, strlen(clamd_tmpdir), 0)) {
        logg(LOGG_DEBUG, "ClamInotif: NVM, didn't actually need to exclude '%s'\n", clamd_tmpdir);
    } else {
        logg(LOGG_INFO, "ClamInotif: excluding '%s' (and all sub-directories)\n", clamd_tmpdir);
    }

    /* Watch provided paths recursively */
    if ((pt = optget(ctx->clamdopts, "OnAccessIncludePath"))->enabled) {
        while (pt) {
            errno        = 0;
            size_t ptlen = strlen(pt->strarg);
            if (onas_ht_get(ddd_ht, pt->strarg, ptlen, NULL) == CL_SUCCESS) {
                err = onas_ddd_watch(pt->strarg, ctx->fan_fd, ctx->fan_mask, onas_in_fd, in_mask);
                if (err) {

                    if (0 == errno) {
                        logg(LOGG_ERROR, "ClamInotif: could not watch path '%s', %s\n ", pt->strarg, cl_strerror(err));
                    } else {
                        logg(LOGG_ERROR, "ClamInotif: could not watch path '%s', %s\n", pt->strarg, strerror(errno));
                        if (errno == EINVAL && optget(ctx->clamdopts, "OnAccessPrevention")->enabled) {
                            logg(LOGG_DEBUG, "ClamInotif: when using the OnAccessPrevention option, please ensure your kernel\n\t\t\twas compiled with CONFIG_FANOTIFY_ACCESS_PERMISSIONS set to Y\n");

                            kill(getpid(), SIGTERM);
                        }
                        if (errno == ENOSPC) {

                            logg(LOGG_DEBUG, "ClamInotif: you likely do not have enough inotify watchpoints available ... run the follow command to increase available watchpoints and try again ...\n");
                            logg(LOGG_DEBUG, "\t $ echo fs.inotify.max_user_watches=524288 | sudo tee -a /etc/sysctl.conf && sudo sysctl -p\n");

                            kill(getpid(), SIGTERM);
                        }
                    }
                }
            }
            pt = (struct optstruct *)pt->nextarg;
        }
    }

    if (NULL != include_list) {
        idx = 0;
        while (NULL != include_list[idx]) {
            errno          = 0;
            uint64_t ptlen = strlen(include_list[idx]);
            if (onas_ht_get(ddd_ht, include_list[idx], ptlen, NULL) == CL_SUCCESS) {
                err = onas_ddd_watch(include_list[idx], ctx->fan_fd, ctx->fan_mask, onas_in_fd, in_mask);
                if (err) {
                    if (0 == errno) {
                        logg(LOGG_ERROR, "ClamInotif: could not watch path '%s', %s\n ", include_list[idx], cl_strerror(err));
                    } else {
                        logg(LOGG_ERROR, "ClamInotif: could not watch path '%s', %s\n", include_list[idx], strerror(errno));
                        if (errno == EINVAL && optget(ctx->clamdopts, "OnAccessPrevention")->enabled) {
                            logg(LOGG_DEBUG, "ClamInotif: when using the OnAccessPrevention option, please ensure your kernel\n\t\t\twas compiled with CONFIG_FANOTIFY_ACCESS_PERMISSIONS set to Y\n");

                            kill(getpid(), SIGTERM);
                        }
                        if (errno == ENOSPC) {

                            logg(LOGG_DEBUG, "ClamInotif: you likely do not have enough inotify watchpoints available ... run the follow command to increase available watchpoints and try again ...\n");
                            logg(LOGG_DEBUG, "\t $ echo fs.inotify.max_user_watches=524288 | sudo tee -a /etc/sysctl.conf && sudo sysctl -p\n");

                            kill(getpid(), SIGTERM);
                        }
                    }
                }
            }
            idx++;
        }
    }

    if (optget(ctx->clamdopts, "OnAccessExtraScanning")->enabled) {
        logg(LOGG_INFO, "ClamInotif: extra scanning on inotify events enabled\n");
    }

    FD_ZERO(&rfds);
    FD_SET(onas_in_fd, &rfds);

    pthread_cleanup_push(onas_ddd_exit, NULL);

    while (1) {
        do {
            ret = select(onas_in_fd + 1, &rfds, NULL, NULL, NULL);
        } while (ret == -1 && errno == EINTR);

        while ((bread = read(onas_in_fd, buf, sizeof(buf))) > 0) {
            pthread_testcancel();
            /* Handle events. */
            int wd;
            char *p           = buf;
            const char *path  = NULL;
            const char *child = NULL;
            for (; p < buf + bread; p += sizeof(struct inotify_event) + event->len) {

                event = (const struct inotify_event *)p;
                wd    = event->wd;
                if (wd >= 0)
                    path = wdlt[wd];
                else
                    path = NULL;
                child = event->name;

                if (path == NULL) {
                    logg(LOGG_DEBUG, "ClamInotif: watch descriptor (wd:%d) not found in lookup table ... skipping\n", wd);
                    continue;
                }

                if (event->mask & IN_UNMOUNT) {
                    logg(LOGG_ERROR, "ClamInotif: inotify event IN_UNMOUNT (mask:%d) occurred, clamonacc should be restarted because a filesystem monitored by inotify was umounted.\n", event->mask);
                } else if (event->mask & IN_Q_OVERFLOW) {
                    logg(LOGG_ERROR, "ClamInotif: inotify event IN_Q_OVERFLOW (mask:%d) occurred, clamonacc should be restarted because inotify events were dropped by the kernel and the internal clamonacc inotify data structures are likely invalid.\n", event->mask);
                } else if (event->mask & IN_IGNORED) {
                    // Ignore for debugging purposes
                } else {
                    len              = strlen(path);
                    size_t size      = strlen(child) + len + 2;
                    char *child_path = (char *)malloc(size);
                    if (child_path == NULL) {
                        logg(LOGG_DEBUG, "ClamInotif: could not allocate space for child path ... aborting\n");
                        return NULL;
                    }

                    if (path[len - 1] == '/') {
                        snprintf(child_path, --size, "%s%s", path, child);
                    } else {
                        snprintf(child_path, size, "%s/%s", path, child);
                    }

                    if (event->mask & IN_DELETE) {
                        onas_ddd_handle_in_delete(ctx, path, child_path, event, wd);

                    } else if (event->mask & IN_MOVED_FROM) {
                        onas_ddd_handle_in_moved_from(ctx, path, child_path, event, wd);

                    } else if (event->mask & IN_CREATE) {
                        onas_ddd_handle_in_create(ctx, path, child_path, event, wd, in_mask);

                    } else if (event->mask & IN_CLOSE_WRITE) {
                        onas_ddd_handle_in_close_write(ctx, child_path);

                    } else if (event->mask & IN_MOVED_TO) {
                        onas_ddd_handle_in_moved_to(ctx, path, child_path, event, wd, in_mask);
                    }

                    free(child_path);
                    child_path = NULL;
                }
            }
        }
    }

    logg(LOGG_DEBUG, "ClamInotif: exiting inotify event thread\n");
    pthread_cleanup_pop(1);
    return NULL;
}

static void onas_ddd_handle_in_delete(struct onas_context *ctx,
                                      const char *path, const char *child_path, const struct inotify_event *event, int wd)
{

    struct stat s;
    if (stat(child_path, &s) == 0 && S_ISREG(s.st_mode)) return;
    if (!(event->mask & IN_ISDIR)) return;

    logg(LOGG_DEBUG, "ClamInotif: DELETE - removing %s from %s with wd:%d\n", child_path, path, wd);
    onas_ddd_unwatch(child_path, ctx->fan_fd, onas_in_fd);
    onas_ht_rm_hierarchy(ddd_ht, child_path, strlen(child_path), 0);

    return;
}

static void onas_ddd_handle_in_moved_from(struct onas_context *ctx,
                                          const char *path, const char *child_path, const struct inotify_event *event, int wd)
{

    struct stat s;
    if (stat(child_path, &s) == 0 && S_ISREG(s.st_mode)) return;
    if (!(event->mask & IN_ISDIR)) return;

    logg(LOGG_DEBUG, "ClamInotif: MOVED_FROM - removing %s from %s with wd:%d\n", child_path, path, wd);
    onas_ddd_unwatch(child_path, ctx->fan_fd, onas_in_fd);
    onas_ht_rm_hierarchy(ddd_ht, child_path, strlen(child_path), 0);

    return;
}

static void onas_ddd_handle_in_create(struct onas_context *ctx,
                                      const char *path, const char *child_path, const struct inotify_event *event, int wd, uint64_t in_mask)
{

    if (!(event->mask & IN_ISDIR)) {
        return;
    }

    if (optget(ctx->clamdopts, "OnAccessExtraScanning")->enabled) {
        logg(LOGG_DEBUG, "ClamInotif: CREATE - adding %s to %s with wd:%d\n", child_path, path, wd);
        onas_ddd_handle_extra_scanning(ctx, child_path, ONAS_SCTH_B_DIR);
    }

    onas_ht_add_hierarchy(ddd_ht, child_path);
    onas_ddd_watch(child_path, ctx->fan_fd, ctx->fan_mask, onas_in_fd, in_mask);

    return;
}

static void onas_ddd_handle_in_close_write(struct onas_context *ctx, const char *child_path)
{
    struct stat s;

    if (optget(ctx->clamdopts, "OnAccessExtraScanning")->enabled) {
        if (stat(child_path, &s) == 0 && S_ISREG(s.st_mode)) {
            onas_ddd_handle_extra_scanning(ctx, child_path, ONAS_SCTH_B_FILE);
        }
    }

    return;
}

static void onas_ddd_handle_in_moved_to(struct onas_context *ctx,
                                        const char *path, const char *child_path, const struct inotify_event *event, int wd, uint64_t in_mask)
{

    struct stat s;
    if (optget(ctx->clamdopts, "OnAccessExtraScanning")->enabled) {
        if (stat(child_path, &s) == 0 && S_ISREG(s.st_mode)) {
            onas_ddd_handle_extra_scanning(ctx, child_path, ONAS_SCTH_B_FILE);

        } else if (event->mask & IN_ISDIR) {
            logg(LOGG_DEBUG, "ClamInotif: MOVED_TO - adding %s to %s with wd:%d\n", child_path, path, wd);
            onas_ddd_handle_extra_scanning(ctx, child_path, ONAS_SCTH_B_DIR);

            onas_ht_add_hierarchy(ddd_ht, child_path);
            onas_ddd_watch(child_path, ctx->fan_fd, ctx->fan_mask, onas_in_fd, in_mask);
        }
    } else {
        if (stat(child_path, &s) == 0 && S_ISREG(s.st_mode)) return;
        if (!(event->mask & IN_ISDIR)) return;

        logg(LOGG_DEBUG, "ClamInotif: MOVED_TO - adding %s to %s with wd:%d\n", child_path, path, wd);
        onas_ht_add_hierarchy(ddd_ht, child_path);
        onas_ddd_watch(child_path, ctx->fan_fd, ctx->fan_mask, onas_in_fd, in_mask);
    }

    return;
}

static void onas_ddd_handle_extra_scanning(struct onas_context *ctx, const char *pathname, int extra_options)
{

    struct onas_scan_event *event_data;

    event_data = (struct onas_scan_event *)calloc(1, sizeof(struct onas_scan_event));
    if (NULL == event_data) {
        logg(LOGG_ERROR, "ClamInotif: could not allocate memory for event data struct\n");
    }

    /* general mapping */
    onas_map_context_info_to_event_data(ctx, &event_data);
    event_data->pathname = cli_safer_strdup(pathname);
    event_data->bool_opts |= ONAS_SCTH_B_SCAN;

    /* inotify specific stuffs */
    event_data->bool_opts |= ONAS_SCTH_B_INOTIFY;
    extra_options &ONAS_SCTH_B_FILE ? event_data->bool_opts |= ONAS_SCTH_B_FILE : extra_options;
    extra_options &ONAS_SCTH_B_DIR ? event_data->bool_opts |= ONAS_SCTH_B_DIR : extra_options;

    logg(LOGG_DEBUG, "ClamInotif: attempting to feed consumer queue\n");
    /* feed consumer queue */
    if (CL_SUCCESS != onas_queue_event(event_data)) {
        logg(LOGG_ERROR, "ClamInotif: error occurred while feeding consumer queue extra event ... continuing ...\n");
        return;
    }

    return;
}

static void onas_ddd_exit(void *arg)
{
    UNUSEDPARAM(arg);

    logg(LOGG_DEBUG, "ClamInotif: onas_ddd_exit()\n");

    if (onas_in_fd) {
        close(onas_in_fd);
    }
    onas_in_fd = 0;

    if (ddd_ht) {
        onas_free_ht(ddd_ht);
    }
    ddd_ht = NULL;

    if (wdlt) {
        free(wdlt);
    }
    wdlt = NULL;

    logg(LOGG_INFO, "ClamInotif: stopped\n");
}

#endif

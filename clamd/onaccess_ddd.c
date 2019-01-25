/*
 *  Copyright (C) 2015-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
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

#if defined(FANOTIFY)

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <pthread.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>

#include <sys/fanotify.h>
#include <sys/inotify.h>

#include "onaccess_fan.h"
#include "onaccess_hash.h"
#include "onaccess_ddd.h"
#include "onaccess_scth.h"

#include "libclamav/clamav.h"
#include "libclamav/scanners.h"

#include "shared/optparser.h"
#include "shared/output.h"

#include "server.h"
#include "others.h"
#include "scanner.h"

static int onas_ddd_init_ht(uint32_t ht_size);
static int onas_ddd_init_wdlt(uint64_t nwatches);
static int onas_ddd_grow_wdlt();

static int onas_ddd_watch(const char *pathname, int fan_fd, uint64_t fan_mask, int in_fd, uint64_t in_mask);
static int onas_ddd_watch_hierarchy(const char* pathname, size_t len, int fd, uint64_t mask, uint32_t type);
static int onas_ddd_unwatch(const char *pathname, int fan_fd, int in_fd);
static int onas_ddd_unwatch_hierarchy(const char* pathname, size_t len, int fd, uint32_t type);

static void onas_ddd_handle_in_moved_to(struct ddd_thrarg *tharg, const char *path, const char *child_path, const struct inotify_event *event, int wd, uint64_t in_mask);
static void onas_ddd_handle_in_create(struct ddd_thrarg *tharg, const char *path, const char *child_path, const struct inotify_event *event, int wd, uint64_t in_mask);
static void onas_ddd_handle_in_moved_from(struct ddd_thrarg *tharg, const char *path, const char *child_path, const struct inotify_event *event, int wd);
static void onas_ddd_handle_in_delete(struct ddd_thrarg *tharg, const char *path, const char *child_path, const struct inotify_event *event, int wd);
static void onas_ddd_handle_extra_scanning(struct ddd_thrarg *tharg, const char *pathname, int extra_options);

static void onas_ddd_exit(int sig);

/* TODO: Unglobalize these. */
static struct onas_ht *ddd_ht;
static char **wdlt;
static uint32_t wdlt_len;
static int onas_in_fd;

static int onas_ddd_init_ht(uint32_t ht_size) {

	if (ht_size <= 0)
		ht_size = ONAS_DEFAULT_HT_SIZE;

	return onas_ht_init(&ddd_ht, ht_size);
}

static int onas_ddd_init_wdlt(uint64_t nwatches) {

	if (nwatches <= 0) return CL_EARG;

	wdlt = (char **) cli_calloc(nwatches << 1, sizeof(char*));
	if (!wdlt) return CL_EMEM;

	wdlt_len = nwatches << 1;

	return CL_SUCCESS;
}

static int onas_ddd_grow_wdlt() {

	char **ptr = NULL;

	ptr = (char **) cli_realloc(wdlt, wdlt_len << 1);
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
int onas_ddd_init(uint64_t nwatches, size_t ht_size) {

	const char* nwatch_file = "/proc/sys/fs/inotify/max_user_watches";
	int nwfd = 0;
	int ret = 0;
	char nwatch_str[MAX_WATCH_LEN];
	char *p = NULL;
	nwatches = 0;

	nwfd = open(nwatch_file, O_RDONLY);
	if (nwfd < 0) return CL_EOPEN;

	ret = read(nwfd, nwatch_str, MAX_WATCH_LEN);
	close(nwfd);
	if (ret < 0) return CL_EREAD;

	nwatches = strtol(nwatch_str, &p, 10);

	ret = onas_ddd_init_wdlt(nwatches);
	if (ret) return ret;

	ret = onas_ddd_init_ht(ht_size);
	if (ret) return ret;

	return CL_SUCCESS;
}

static int onas_ddd_watch(const char *pathname, int fan_fd, uint64_t fan_mask, int in_fd, uint64_t in_mask) {
	if (!pathname || fan_fd <= 0 || in_fd <= 0) return CL_ENULLARG;

	int ret = CL_SUCCESS;
	size_t len = strlen(pathname);

	ret = onas_ddd_watch_hierarchy(pathname, len, in_fd, in_mask, ONAS_IN);
	if (ret) return ret;

	ret = onas_ddd_watch_hierarchy(pathname, len, fan_fd, fan_mask, ONAS_FAN);
	if (ret) return ret;

	return CL_SUCCESS;
}

static int onas_ddd_watch_hierarchy(const char* pathname, size_t len, int fd, uint64_t mask, uint32_t type) {

	if (!pathname || fd <= 0 || !type) return CL_ENULLARG;

	if (type == (ONAS_IN | ONAS_FAN)) return CL_EARG;

	struct onas_hnode *hnode = NULL;
	struct onas_element *elem = NULL;
	int wd = 0;

	if(onas_ht_get(ddd_ht, pathname, len, &elem) != CL_SUCCESS) return CL_EARG;

	hnode = elem->data;

	if (type & ONAS_IN) {
		wd = inotify_add_watch(fd, pathname, (uint32_t) mask);

		if (wd < 0) return CL_EARG;

		if ((uint32_t) wd >= wdlt_len) {
			onas_ddd_grow_wdlt();
		}

		/* Link the hash node to the watch descriptor lookup table */
		hnode->wd = wd;
		wdlt[wd] = hnode->pathname;

		hnode->watched |= ONAS_INWATCH;
	} else if (type & ONAS_FAN) {
		if(fanotify_mark(fd, FAN_MARK_ADD, mask, AT_FDCWD, hnode->pathname) < 0) return CL_EARG;
		hnode->watched |= ONAS_FANWATCH;
	} else {
		return CL_EARG;
	}

	struct onas_lnode *curr = hnode->childhead;

	while (curr->next != hnode->childtail) {
		curr = curr->next;

		size_t size = len + strlen(curr->dirname) + 2;
		char *child_path = (char *) cli_malloc(size);
		if (child_path == NULL)
			return CL_EMEM;
		if (hnode->pathname[len-1] == '/')
			snprintf(child_path, --size, "%s%s", hnode->pathname, curr->dirname);
		else
			snprintf(child_path, size, "%s/%s", hnode->pathname, curr->dirname);

		if(onas_ddd_watch_hierarchy(child_path, strlen(child_path), fd, mask, type)) {
			return CL_EARG;
		}
		free(child_path);
	}

	return CL_SUCCESS;
}

static int onas_ddd_unwatch(const char *pathname, int fan_fd, int in_fd) {
	if (!pathname || fan_fd <= 0 || in_fd <= 0) return CL_ENULLARG;

	int ret = CL_SUCCESS;
	size_t len = strlen(pathname);

	ret = onas_ddd_unwatch_hierarchy(pathname, len, in_fd, ONAS_IN);
	if (ret) return ret;

	ret = onas_ddd_unwatch_hierarchy(pathname, len,fan_fd, ONAS_FAN);
	if (ret) return ret;

	return CL_SUCCESS;
}

static int onas_ddd_unwatch_hierarchy(const char* pathname, size_t len, int fd, uint32_t type) {

	if (!pathname || fd <= 0 || !type) return CL_ENULLARG;

	if (type == (ONAS_IN | ONAS_FAN)) return CL_EARG;

	struct onas_hnode *hnode = NULL;
	struct onas_element *elem = NULL;
	int wd = 0;

	if(onas_ht_get(ddd_ht, pathname, len, &elem)) return CL_EARG;

	hnode = elem->data;

	if (type & ONAS_IN) {
		wd = hnode->wd;

		if(!inotify_rm_watch(fd, wd)) return CL_EARG;

		/* Unlink the hash node from the watch descriptor lookup table */
		hnode->wd = 0;
		wdlt[wd] = NULL;

		hnode->watched = ONAS_STOPWATCH;
	} else if (type & ONAS_FAN) {
		if(fanotify_mark(fd, FAN_MARK_REMOVE, 0, AT_FDCWD, hnode->pathname) < 0) return CL_EARG;
		hnode->watched = ONAS_STOPWATCH;
	} else {
		return CL_EARG;
	}

	struct onas_lnode *curr = hnode->childhead;

	while (curr->next != hnode->childtail) {
		curr = curr->next;

		size_t size = len + strlen(curr->dirname) + 2;
		char *child_path = (char *) cli_malloc(size);
		if (child_path == NULL)
			return CL_EMEM;
		if (hnode->pathname[len-1] == '/')
			snprintf(child_path, --size, "%s%s", hnode->pathname, curr->dirname);
		else
			snprintf(child_path, size, "%s/%s", hnode->pathname, curr->dirname);

		onas_ddd_unwatch_hierarchy(child_path, strlen(child_path), fd, type);
		free(child_path);
	}

	return CL_SUCCESS;
}

void *onas_ddd_th(void *arg) {
	struct ddd_thrarg *tharg = (struct ddd_thrarg *) arg;
	sigset_t sigset;
	struct sigaction act;
	const struct optstruct *pt;
	uint64_t in_mask = IN_ONLYDIR | IN_MOVE | IN_DELETE | IN_CREATE;
	fd_set rfds;
	char buf[4096];
	ssize_t bread;
	const struct inotify_event *event;
	int ret, len;

	/* ignore all signals except SIGUSR1 */
	sigfillset(&sigset);
	sigdelset(&sigset, SIGUSR1);
	/* The behavior of a process is undefined after it ignores a
	 * SIGFPE, SIGILL, SIGSEGV, or SIGBUS signal */
	sigdelset(&sigset, SIGFPE);
	sigdelset(&sigset, SIGILL);
	sigdelset(&sigset, SIGSEGV);
#ifdef SIGBUS
	sigdelset(&sigset, SIGBUS);
#endif
	pthread_sigmask(SIG_SETMASK, &sigset, NULL);
	memset(&act, 0, sizeof(struct sigaction));
	act.sa_handler = onas_ddd_exit;
	sigfillset(&(act.sa_mask));
	sigaction(SIGUSR1, &act, NULL);
	sigaction(SIGSEGV, &act, NULL);

	onas_in_fd = inotify_init1(IN_NONBLOCK);
	if (onas_in_fd == -1) {
		logg("!ScanOnAccess: Could not init inotify.");
		return NULL;
	}

	ret = onas_ddd_init(0, ONAS_DEFAULT_HT_SIZE);
	if (ret) {
		logg("!ScanOnAccess: Failed to initialize 3D. \n");
		return NULL;
	}

	/* Add provided paths recursively. */
	if((pt = optget(tharg->opts, "OnAccessIncludePath"))->enabled) {
		while(pt) {
			if (!strcmp(pt->strarg, "/")) {
				logg("!ScanOnAccess: Not including path '%s' while DDD is enabled\n", pt->strarg);
				logg("!ScanOnAccess: Please use the OnAccessMountPath option to watch '%s'\n", pt->strarg);
				pt = (struct optstruct *) pt->nextarg;
				continue;
			}
			if(onas_ht_get(ddd_ht, pt->strarg, strlen(pt->strarg), NULL) != CL_SUCCESS) {
				if(onas_ht_add_hierarchy(ddd_ht, pt->strarg)) {
					logg("!ScanOnAccess: Can't include path '%s'\n", pt->strarg);
					return NULL;
				} else
					logg("ScanOnAccess: Protecting directory '%s' (and all sub-directories)\n", pt->strarg);
			}

			pt = (struct optstruct *) pt->nextarg;
		}
	} else {
		logg("!ScanOnAccess: Please specify at least one path with OnAccessIncludePath\n");
		return NULL;
	}

	/* Remove provided paths recursively. */
	if((pt = optget(tharg->opts, "OnAccessExcludePath"))->enabled) {
		while(pt) {
			size_t ptlen = strlen(pt->strarg);
			if(onas_ht_get(ddd_ht, pt->strarg, ptlen, NULL) == CL_SUCCESS) {
				if(onas_ht_rm_hierarchy(ddd_ht, pt->strarg, ptlen, 0)) {
					logg("!ScanOnAccess: Can't exclude path '%s'\n", pt->strarg);
					return NULL;
				} else
					logg("ScanOnAccess: Excluding  directory '%s' (and all sub-directories)\n", pt->strarg);
			}

			pt = (struct optstruct *) pt->nextarg;
		}
	}

	/* Watch provided paths recursively */
	if((pt = optget(tharg->opts, "OnAccessIncludePath"))->enabled) {
		while(pt) {
			size_t ptlen = strlen(pt->strarg);
			if(onas_ht_get(ddd_ht, pt->strarg, ptlen, NULL) == CL_SUCCESS) {
				if(onas_ddd_watch(pt->strarg, tharg->fan_fd, tharg->fan_mask, onas_in_fd, in_mask)) {
					logg("!ScanOnAccess: Could not watch path '%s', %s\n", pt->strarg, strerror(errno));
					if(errno == EINVAL && optget(tharg->opts, "OnAccessPrevention")->enabled) {
						logg("!ScanOnAccess: When using the OnAccessPrevention option, please ensure your kernel\n\t\t\twas compiled with CONFIG_FANOTIFY_ACCESS_PERMISSIONS set to Y\n");

						kill(getpid(), SIGTERM);
					}
					return NULL;
				}
			}
			pt = (struct optstruct *) pt->nextarg;
		}
	}

	/* TODO: Re-enable OnAccessExtraScanning once the thread resource consumption issue is resolved. */
#if 0
	if(optget(tharg->opts, "OnAccessExtraScanning")->enabled) {
		logg("ScanOnAccess: Extra scanning and notifications enabled.\n");
}
	#endif


	FD_ZERO(&rfds);
	FD_SET(onas_in_fd, &rfds);

	while (1) {
		do {
			ret = select(onas_in_fd + 1, &rfds, NULL, NULL, NULL);
		} while(ret == -1 && errno == EINTR);

		while((bread = read(onas_in_fd, buf, sizeof(buf))) > 0) {

			/* Handle events. */
			int wd;
			char *p = buf;
			const char *path = NULL;
			const char *child = NULL;
			for(; p < buf + bread; p += sizeof(struct inotify_event) + event->len) {

				event = (const struct inotify_event *) p;
				wd = event->wd;
				path = wdlt[wd];
				child = event->name;

				len = strlen(path);
				size_t size = strlen(child) + len + 2;
				char *child_path = (char *) cli_malloc(size);
				if (child_path == NULL)
					return NULL;

				if (path[len-1] == '/')
					snprintf(child_path, --size, "%s%s", path, child);
				else
					snprintf(child_path, size, "%s/%s", path, child);

				if (event->mask & IN_DELETE) {
					onas_ddd_handle_in_delete(tharg, path, child_path, event, wd);

				} else if (event->mask & IN_MOVED_FROM) {
					onas_ddd_handle_in_moved_from(tharg, path, child_path, event, wd);

				} else if (event->mask & IN_CREATE) {
					onas_ddd_handle_in_create(tharg, path, child_path, event, wd, in_mask);

				} else if (event->mask & IN_MOVED_TO) {
					onas_ddd_handle_in_moved_to(tharg, path, child_path, event, wd, in_mask);
				}
			}
		}
	}

	return NULL;
}

static void onas_ddd_handle_in_delete(struct ddd_thrarg *tharg,
		const char *path, const char *child_path, const struct inotify_event *event, int wd) {

	struct stat s;
	if(stat(child_path, &s) == 0 && S_ISREG(s.st_mode)) return;
	if(!(event->mask & IN_ISDIR)) return;

	logg("*ddd: DELETE - Removing %s from %s with wd:%d\n", child_path, path, wd);
	onas_ddd_unwatch(child_path, tharg->fan_fd, onas_in_fd);
	onas_ht_rm_hierarchy(ddd_ht, child_path, strlen(child_path), 0);

	return;
}


static void onas_ddd_handle_in_moved_from(struct ddd_thrarg *tharg,
		const char *path, const char *child_path, const struct inotify_event *event, int wd) {

	struct stat s;
	if(stat(child_path, &s) == 0 && S_ISREG(s.st_mode)) return;
	if(!(event->mask & IN_ISDIR)) return;

	logg("*ddd: MOVED_FROM - Removing %s from %s with wd:%d\n", child_path, path, wd);
	onas_ddd_unwatch(child_path, tharg->fan_fd, onas_in_fd);
	onas_ht_rm_hierarchy(ddd_ht, child_path, strlen(child_path), 0);

	return;
}


static void onas_ddd_handle_in_create(struct ddd_thrarg *tharg,
		const char *path, const char *child_path, const struct inotify_event *event, int wd, uint64_t in_mask) {

	struct stat s;

	/* TODO: Re-enable OnAccessExtraScanning once the thread resource consumption issue is resolved. */
#if 0
	if (optget(tharg->opts, "OnAccessExtraScanning")->enabled) {
		if(stat(child_path, &s) == 0 && S_ISREG(s.st_mode)) {
			onas_ddd_handle_extra_scanning(tharg, child_path, ONAS_SCTH_ISFILE);

		} else if(stat(child_path, &s) == 0 && S_ISDIR(s.st_mode)) {
			logg("*ddd: CREATE - Adding %s to %s with wd:%d\n", child_path, path, wd);
			onas_ht_add_hierarchy(ddd_ht, child_path);
			onas_ddd_watch(child_path, tharg->fan_fd, tharg->fan_mask, onas_in_fd, in_mask);

			onas_ddd_handle_extra_scanning(tharg, child_path, ONAS_SCTH_ISDIR);
		}
	}
	else
#endif
	{
		if(stat(child_path, &s) == 0 && S_ISREG(s.st_mode)) return;
		if(!(event->mask & IN_ISDIR)) return;

		logg("*ddd: MOVED_TO - Adding %s to %s with wd:%d\n", child_path, path, wd);
		onas_ht_add_hierarchy(ddd_ht, child_path);
		onas_ddd_watch(child_path, tharg->fan_fd, tharg->fan_mask, onas_in_fd, in_mask);
	}

	return;
}

static void onas_ddd_handle_in_moved_to(struct ddd_thrarg *tharg,
		const char *path, const char *child_path, const struct inotify_event *event, int wd, uint64_t in_mask) {

	struct stat s;
	/* TODO: Re-enable OnAccessExtraScanning once the thread resource consumption issue is resolved. */
#if 0
	if (optget(tharg->opts, "OnAccessExtraScanning")->enabled) {
		if(stat(child_path, &s) == 0 && S_ISREG(s.st_mode)) {
			onas_ddd_handle_extra_scanning(tharg, child_path, ONAS_SCTH_ISFILE);

		} else if(stat(child_path, &s) == 0 && S_ISDIR(s.st_mode)) {
			logg("*ddd: MOVED_TO - Adding %s to %s with wd:%d\n", child_path, path, wd);
			onas_ht_add_hierarchy(ddd_ht, child_path);
			onas_ddd_watch(child_path, tharg->fan_fd, tharg->fan_mask, onas_in_fd, in_mask);

			onas_ddd_handle_extra_scanning(tharg, child_path, ONAS_SCTH_ISDIR);
		}
	}
	else
#endif
	{
		if(stat(child_path, &s) == 0 && S_ISREG(s.st_mode)) return;
		if(!(event->mask & IN_ISDIR)) return;

		logg("*ddd: MOVED_TO - Adding %s to %s with wd:%d\n", child_path, path, wd);
		onas_ht_add_hierarchy(ddd_ht, child_path);
		onas_ddd_watch(child_path, tharg->fan_fd, tharg->fan_mask, onas_in_fd, in_mask);
	}

	return;
}

static void onas_ddd_handle_extra_scanning(struct ddd_thrarg *tharg, const char *pathname, int extra_options) {

	int thread_started = 1;
	struct scth_thrarg *scth_tharg = NULL;
	pthread_attr_t scth_attr;
	pthread_t scth_pid = 0;

	do {
		if (pthread_attr_init(&scth_attr)) break;
		pthread_attr_setdetachstate(&scth_attr, PTHREAD_CREATE_JOINABLE);

		/* Allocate memory for arguments. Thread is responsible for freeing it. */
		if (!(scth_tharg = (struct scth_thrarg *) calloc(sizeof(struct scth_thrarg), 1))) break;
		if (!(scth_tharg->options = (struct cl_scan_options *) calloc(sizeof(struct cl_scan_options), 1))) break;

		(void) memcpy(scth_tharg->options, tharg->options, sizeof(struct cl_scan_options));

		scth_tharg->extra_options = extra_options;
		scth_tharg->opts = tharg->opts;
		scth_tharg->pathname = strdup(pathname);
		scth_tharg->engine = tharg->engine;

		thread_started = pthread_create(&scth_pid, &scth_attr, onas_scan_th, scth_tharg);
	} while(0);

	if (0 != thread_started) {
		/* Failed to create thread. Free anything we may have allocated. */
		logg("!ScanOnAccess: Unable to kick off extra scanning.\n");
		if (NULL != scth_tharg) {
			if (NULL != scth_tharg->pathname){
				free(scth_tharg->pathname);
				scth_tharg->pathname = NULL;
			}
			if (NULL != scth_tharg->options) {
				free(scth_tharg->options);
				scth_tharg->options = NULL;
			}
			free(scth_tharg);
			scth_tharg = NULL;
		}
	}
	
	return;
}


static void onas_ddd_exit(int sig) {
	logg("*ScanOnAccess: onas_ddd_exit(), signal %d\n", sig);

	close(onas_in_fd);

	onas_free_ht(ddd_ht);
	free(wdlt);

	pthread_exit(NULL);
	logg("ScanOnAccess: stopped\n");
}
#endif

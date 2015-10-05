/*
 *  Copyright (C) 2015 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2015 Sourcefire, Inc.
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

#ifndef __ONAS_IN_H
#define __ONAS_IN_H

#define ONAS_IN 0x01
#define ONAS_FAN 0x02

#define MAX_WATCH_LEN 7

struct ddd_thrarg {
	int sid;
	int options;
	int fan_fd;
	uint64_t fan_mask;
	const struct optstruct *opts;
	const struct cl_engine *engine;
	const struct cl_limits *limits;
};

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
static void onas_ddd_handle_extra_scanning(struct ddd_thrarg *tharg, const char *pathname, int options);

int onas_ddd_init(uint64_t nwatches, size_t ht_size);
void *onas_ddd_th(void *arg);
static void onas_ddd_exit(int sig);


#endif

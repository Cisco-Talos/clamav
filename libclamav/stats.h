/*
 *  Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 *
 *  Author: Shawn Webb
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

#if !defined(_LIBCLAMAV_STATS_H)
#define _LIBCLAMAV_STATS_H

#define STATS_HOST "intel.clamav.net"
#define STATS_PORT "80"

void clamav_stats_add_sample(const char *virname, const unsigned char *md5, size_t size, stats_section_t *sections, void *cbdata);
void clamav_stats_submit(struct cl_engine *engine, void *cbdata);
void clamav_stats_flush(struct cl_engine *engine, void *cbdata);
void clamav_stats_remove_sample(const char *virname, const unsigned char *md5, size_t size, void *cbdata);
void clamav_stats_decrement_count(const char *virname, const unsigned char *md5, size_t size, void *cbdata);
size_t clamav_stats_get_num(void *cbdata);
size_t clamav_stats_get_size(void *cbdata);
char *clamav_stats_get_hostid(void *cbdata);

#endif

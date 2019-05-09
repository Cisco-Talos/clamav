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

#ifndef __ONAS_SCTH_H
#define __ONAS_SCTH_H


#include <sys/fanotify.h>
#include "shared/optparser.h"
#include "libclamav/clamav.h"

#define ONAS_SCTH_B_DIR         0x01
#define ONAS_SCTH_B_FILE        0x02
#define ONAS_SCTH_B_INOTIFY     0x04
#define ONAS_SCTH_B_FANOTIFY    0x08
#define ONAS_SCTH_B_SCAN        0x10
#define ONAS_SCTH_B_RETRY_ON_E  0x20
#define ONAS_SCTH_B_DENY_ON_E   0x40

struct onas_scan_event {
        const char *tcpaddr;
        int64_t portnum;
    char *pathname;
        int fan_fd;
        struct fanotify_event_metadata *fmd;
        uint8_t retry_attempts;
        uint64_t sizelimit;
        int32_t scantype;
        int64_t maxstream;
        int64_t timeout;
	uint8_t bool_opts;
};

void *onas_scan_th(void *arg);

void *onas_scan_worker(void *arg);

int onas_scan(struct onas_scan_event *event_data, const char *fname, STATBUF sb, int *infected, int *err, cl_error_t *ret_code);
cl_error_t onas_map_context_info_to_event_data(struct onas_context *ctx, struct onas_scan_event **event_data);

#endif

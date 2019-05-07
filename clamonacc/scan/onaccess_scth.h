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

#define ONAS_SCTH_ISDIR 0x01
#define ONAS_SCTH_ISFILE 0x02

struct onas_scan_event {
    char *pathname;
        struct fanotify_event_metadata *fmd;
	int16_t b_inotify;
	int16_t b_fanotify;
        int16_t b_scan;
	uint32_t extra_options;
};

struct scth_thrarg {
	struct onas_scan_event *event_data;
	struct onas_context **ctx;
};

void *onas_scan_th(void *arg);

int onas_scan(struct onas_context **ctx, const char *fname, STATBUF sb, int *infected, int *err, cl_error_t *ret_code);
int onas_scth_handle_file(struct onas_context **ctx, const char *pathname, struct onas_scan_event *event_data);

#endif

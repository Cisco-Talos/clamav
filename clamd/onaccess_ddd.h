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

#ifndef __ONAS_IN_H
#define __ONAS_IN_H

#include "shared/optparser.h"
#include "libclamav/clamav.h"

/*
 * Extra options for onas_scan_th(). 
 */
#define ONAS_IN 	0x01
#define ONAS_FAN 	0x02

#define MAX_WATCH_LEN 7

struct ddd_thrarg {
	int sid;
	struct cl_scan_options *options;
	int fan_fd;
	uint64_t fan_mask;
	const struct optstruct *opts;
	const struct cl_engine *engine;
};


int onas_ddd_init(uint64_t nwatches, size_t ht_size);
void *onas_ddd_th(void *arg);


#endif

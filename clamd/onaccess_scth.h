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

#include "shared/optparser.h"
#include "libclamav/clamav.h"

#define ONAS_SCTH_ISDIR  0x01
#define ONAS_SCTH_ISFILE 0x02

struct scth_thrarg {
	uint32_t extra_options;
	struct cl_scan_options *options;
	const struct optstruct *opts;
	const struct cl_engine *engine;
	char *pathname;
};

void *onas_scan_th(void *arg);

#endif

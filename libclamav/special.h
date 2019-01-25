/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *
 *  Authors: Trog
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

#ifndef __SPECIAL_H
#define __SPECIAL_H

#include "others.h"
#define SWIZZ_MAXERRORS 2000
struct swizz_stats {
	uint16_t gngrams[17576];
	uint32_t total;
	uint32_t suspicious;
	int has_version;
	int has_manifest;
	int errors;
	int entries;
};

int cli_check_mydoom_log(cli_ctx *ctx);
int cli_check_jpeg_exploit(cli_ctx *ctx, off_t offset);
int cli_check_riff_exploit(cli_ctx *ctx);
void cli_detect_swizz_str(const unsigned char *str, uint32_t len, struct swizz_stats *stats, int blob);
int cli_detect_swizz(struct swizz_stats *stats);

#endif

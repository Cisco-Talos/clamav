/*
 *  A fast filter for static patterns.
 *
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2008-2013 Sourcefire, Inc.
 *
 *  Authors: Török Edvin
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
#ifndef FILTER_H
#define FILTER_H
#include "clamav-types.h"
struct filter {
	uint8_t B[65536];
	uint8_t end[65536];
	unsigned long m;
};

struct filter_match_info {
	unsigned long first_match;
};

struct cli_ac_patt;
void filter_init(struct filter *m);
long filter_search(const struct filter *m, const unsigned char *data, unsigned long len);
int filter_search_ext(const struct filter *m, const unsigned char *data, unsigned long len, struct filter_match_info *inf);
int  filter_add_static(struct filter *m, const unsigned char *pattern, unsigned long len, const char *name);
int  filter_add_acpatt(struct filter *m, const struct cli_ac_patt *pat);

#endif

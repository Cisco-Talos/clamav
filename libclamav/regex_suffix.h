/*
 *  Parse a regular expression, and extract a static suffix.
 *
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
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
#ifndef REGEX_SUFFIX_H
#define REGEX_SUFFIX_H
#include "regex/regex.h"

struct regex_list {
	char *pattern;
	regex_t *preg;
	struct regex_list *nxt;
};
typedef int (*suffix_callback)(void *cbdata, const char *suffix, size_t len, const struct regex_list *regex);
int cli_regex2suffix(const char *pattern, regex_t *preg, suffix_callback cb, void *cbdata);
#endif

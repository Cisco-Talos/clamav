/*
 *  Match a string against a list of patterns/regexes.
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


#ifndef _REGEX_LIST_H
#define _REGEX_LIST_H

#include "phishcheck.h"
#include "readdb.h"
#include "matcher.h"
#include "filtering.h"
#include "hashtab.h"
#include <zlib.h> /* for gzFile */

#include "mpool.h"

struct regex_list_ht {
	struct regex_list *head;
	struct regex_list *tail;
};

struct regex_matcher {
	struct cli_hashtable suffix_hash;
	size_t suffix_cnt;
	struct regex_list_ht *suffix_regexes;
	size_t root_regex_idx;
	size_t regex_cnt;
	regex_t **all_pregs;
	struct cli_matcher suffixes;
	struct cli_matcher sha256_hashes;
	struct cli_hashset sha256_pfx_set;
	struct cli_matcher hostkey_prefix;
	struct filter filter;
#ifdef USE_MPOOL
	mpool_t *mempool;
#endif
	int list_inited:2;
	int list_loaded:2;
	int list_built:2;
};

int cli_build_regex_list(struct regex_matcher* matcher);
int regex_list_add_pattern(struct regex_matcher *matcher, char *pattern);
int regex_list_match(struct regex_matcher* matcher, char* real_url,const char* display_url,const struct pre_fixup_info* pre_fixup, int hostOnly,const char **info, int is_whitelist);
int init_regex_list(struct regex_matcher* matcher, uint8_t dconf_prefiltering);
int load_regex_matcher(struct cl_engine *engine,struct regex_matcher* matcher,FILE* fd,unsigned int *signo,unsigned int options,int is_whitelist,struct cli_dbio *dbio,uint8_t dconf_prefiltering);
void regex_list_cleanup(struct regex_matcher* matcher);
void regex_list_done(struct regex_matcher* matcher);
int is_regex_ok(struct regex_matcher* matcher);

#endif


/*
 *  Support for matcher using PCRE
 *
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *  Copyright (C) 2014 Cisco Systems, Inc.
 *  All Rights Reserved.
 *
 *  Authors: Kevin Lin
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

#ifndef __MATCHER_PCRE_H
#define __MATCHER_PCRE_H

#if HAVE_PCRE
#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <sys/types.h>

#include "cltypes.h"
#include "mpool.h"
#include "regex_pcre.h"

struct cli_pcre_refentry {
    uint32_t lsigid[2];
    struct cli_pcre_refentry *next;
};

int cli_pcre_adducondpatt(struct cli_matcher *root, const char *pattern, const uint32_t *lsigid);
int cli_pcre_uncondbuild(struct cli_matcher *root, long long unsigned match_limit, long long unsigned recmatch_limit, unsigned int options);
int cli_pcre_ucondscanbuf(const unsigned char *buffer, uint32_t length, const struct cli_matcher *root, struct cli_ac_data *mdata, cli_ctx *ctx);
void cli_pcre_ucondfree(struct cli_matcher *root);
#endif /* HAVE_PCRE */
#endif /*__MATCHER_PCRE_H*/

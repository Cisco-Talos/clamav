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

#define PCRE_BYPASS "7374756c747a676574737265676578"

struct cli_pcre_meta {
    char *trigger;
    uint32_t lsigid[2];
    struct cli_pcre_data pdata;
    /* internal flags */
};

/* figure out where to handle the pcre options: matcher likes addpatt, but it's currently also in build */
int cli_pcre_addpatt(struct cli_matcher *root, const char *trigger,  const char *pattern, const char *cflags, const uint32_t *lsigid);
int cli_pcre_build(struct cli_matcher *root, long long unsigned match_limit, long long unsigned recmatch_limit);
int cli_pcre_ucondscanbuf(const unsigned char *buffer, uint32_t length, const struct cli_matcher *root, struct cli_ac_data *mdata, cli_ctx *ctx);
void cli_pcre_freemeta(struct cli_pcre_meta *pm);
void cli_pcre_freetable(struct cli_matcher *root);
#endif /* HAVE_PCRE */
#endif /*__MATCHER_PCRE_H*/

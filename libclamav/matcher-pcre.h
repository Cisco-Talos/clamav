/*
 *  Support for matcher using PCRE
 *
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
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

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <sys/types.h>

#include "clamav-types.h"
#include "dconf.h"
#include "mpool.h"
#include "regex_pcre.h"

#define PCRE_SCAN_NONE 0
#define PCRE_SCAN_BUFF 1
#define PCRE_SCAN_FMAP 2

/* stores offset data */
struct cli_pcre_off {
    uint32_t *offset, *shift;
};

#if HAVE_PCRE
#define PCRE_BYPASS "7374756c747a676574737265676578"
#define CLI_PCRE_GLOBAL    0x00000001 /* g */
#define CLI_PCRE_ENCOMPASS 0x00000002 /* e */
#define CLI_PCRE_ROLLING   0x00000004 /* r */

#define CLI_PCRE_DISABLED  0x80000000 /* used for dconf or fail to build */

struct cli_pcre_meta {
    char *trigger;
    char *virname;
    uint32_t lsigid[3]; /* 0=valid, 1=lsigid, 2=subsigid */
    struct cli_pcre_data pdata;
    /* clamav offset data */
    uint32_t offdata[4];
    uint32_t offset_min, offset_max;
    /* internal flags (bitfield?) */
    uint32_t flags;
    /* performance tracking */
    char *statname; /* freed by us, not cli_events_free */
    uint32_t sigtime_id, sigmatch_id;
};

/* PCRE PERFORMANCE DECLARATIONS */
void cli_pcre_perf_print();
void cli_pcre_perf_events_destroy();

/* PCRE MATCHER DECLARATIONS */
int cli_pcre_init();
int cli_pcre_addpatt(struct cli_matcher *root, const char *virname, const char *trigger,  const char *pattern, const char *cflags, const char *offset, const uint32_t *lsigid, unsigned int options);
int cli_pcre_build(struct cli_matcher *root, long long unsigned match_limit, long long unsigned recmatch_limit, const struct cli_dconf *dconf);
int cli_pcre_recaloff(struct cli_matcher *root, struct cli_pcre_off *data, struct cli_target_info *info, cli_ctx *ctx);
void cli_pcre_freeoff(struct cli_pcre_off *data);
int cli_pcre_scanbuf(const unsigned char *buffer, uint32_t length, const char **virname, struct cli_ac_result **res, const struct cli_matcher *root, struct cli_ac_data *mdata, const struct cli_pcre_off *data, cli_ctx *ctx);
void cli_pcre_freemeta(struct cli_matcher *root, struct cli_pcre_meta *pm);
void cli_pcre_freetable(struct cli_matcher *root);
#else
/* NO-PCRE DECLARATIONS - defined because encasing everything in '#if' is a pain and because dynamic library mappings are weird */
#define PCRE_BYPASS ""

void cli_pcre_perf_print();
void cli_pcre_perf_events_destroy();

int cli_pcre_init();
int cli_pcre_build(struct cli_matcher *root, long long unsigned match_limit, long long unsigned recmatch_limit, const struct cli_dconf *dconf);
int cli_pcre_scanbuf(const unsigned char *buffer, uint32_t length, const char **virname, struct cli_ac_result **res, const struct cli_matcher *root, struct cli_ac_data *mdata, const struct cli_pcre_off *data, cli_ctx *ctx);
int cli_pcre_recaloff(struct cli_matcher *root, struct cli_pcre_off *data, struct cli_target_info *info, cli_ctx *ctx);
void cli_pcre_freeoff(struct cli_pcre_off *data);
#endif /* HAVE_PCRE */
#endif /*__MATCHER_PCRE_H*/

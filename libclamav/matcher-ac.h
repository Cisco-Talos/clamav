/*
 *  Copyright (C) 2007-2009 Sourcefire, Inc.
 *
 *  Authors: Tomasz Kojm
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

#ifndef __MATCHER_AC_H
#define __MATCHER_AC_H

#include <sys/types.h>

#include "filetypes.h"
#include "cltypes.h"
#include "fmap.h"
#include "hashtab.h"

#define AC_CH_MAXDIST 32

#define AC_SCAN_VIR 1
#define AC_SCAN_FT  2

struct cli_ac_data {
    int32_t ***offmatrix;
    uint32_t partsigs, lsigs, reloffsigs;
    uint32_t **lsigcnt;
    uint32_t **lsigsuboff_last, **lsigsuboff_first;
    uint32_t *offset;
    uint32_t macro_lastmatch[32];
    /** Hashset for versioninfo matching */
    const struct cli_hashset *vinfo;
    uint32_t min_partno;
};

struct cli_ac_special {
    unsigned char *str;
    struct cli_ac_special *next;
    uint16_t len, num;
    uint8_t type, negative;
};

struct cli_ac_patt {
    uint16_t *pattern, *prefix, length, prefix_length;
    uint32_t mindist, maxdist;
    uint32_t sigid;
    uint32_t lsigid[3];
    uint16_t ch[2];
    char *virname;
    void *customdata;
    uint16_t ch_mindist[2];
    uint16_t ch_maxdist[2];
    uint16_t parts, partno, special, special_pattern;
    struct cli_ac_special **special_table;
    struct cli_ac_patt *next, *next_same;
    uint16_t rtype, type;
    uint32_t offdata[4], offset_min, offset_max;
    uint32_t boundary;
    uint8_t depth;
};

struct cli_ac_node {
    struct cli_ac_patt *list;
    struct cli_ac_node **trans, *fail;
};

#define IS_LEAF(node) (!node->trans)
#define IS_FINAL(node) (!!node->list)

struct cli_ac_result {
    const char *virname;
    void *customdata;
    off_t offset;
    struct cli_ac_result *next;
};

#include "matcher.h"

int cli_ac_addpatt(struct cli_matcher *root, struct cli_ac_patt *pattern);
int cli_ac_initdata(struct cli_ac_data *data, uint32_t partsigs, uint32_t lsigs, uint32_t reloffsigs, uint8_t tracklen);
void cli_ac_chkmacro(struct cli_matcher *root, struct cli_ac_data *data, unsigned lsigid1);
int cli_ac_chklsig(const char *expr, const char *end, uint32_t *lsigcnt, unsigned int *cnt, uint64_t *ids, unsigned int parse_only);
void cli_ac_freedata(struct cli_ac_data *data);
int cli_ac_scanbuff(const unsigned char *buffer, uint32_t length, const char **virname, void **customdata, struct cli_ac_result **res, const struct cli_matcher *root, struct cli_ac_data *mdata, uint32_t offset, cli_file_t ftype, struct cli_matched_type **ftoffset, unsigned int mode, cli_ctx *ctx);
int cli_ac_buildtrie(struct cli_matcher *root);
int cli_ac_init(struct cli_matcher *root, uint8_t mindepth, uint8_t maxdepth, uint8_t dconf_prefiltering);
int cli_ac_caloff(const struct cli_matcher *root, struct cli_ac_data *data, const struct cli_target_info *info);
void cli_ac_free(struct cli_matcher *root);
int cli_ac_addsig(struct cli_matcher *root, const char *virname, const char *hexsig, uint32_t sigid, uint16_t parts, uint16_t partno, uint16_t rtype, uint16_t type, uint32_t mindist, uint32_t maxdist, const char *offset, const uint32_t *lsigid, unsigned int options);

#endif

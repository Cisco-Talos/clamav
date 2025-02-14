/*
 *  Copyright (C) 2013-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
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
#include "clamav-types.h"
#include "fmap.h"
#include "hashtab.h"

#define AC_CH_MAXDIST 32
#define ACPATT_ALTN_MAXNEST 15

/* AC scanning modes */
#define AC_SCAN_VIR 1
#define AC_SCAN_FT 2

/* Pattern options */
#define ACPATT_OPTION_NOOPTS 0x00
#define ACPATT_OPTION_NOCASE 0x01
#define ACPATT_OPTION_FULLWORD 0x02
#define ACPATT_OPTION_WIDE 0x04
#define ACPATT_OPTION_ASCII 0x08

#define ACPATT_OPTION_ONCE 0x80

struct cli_subsig_matches {
    uint32_t last;
    uint32_t next;
    uint32_t offsets[16]; /* offsets[] is variable length */
};

struct cli_lsig_matches {
    uint32_t subsigs;
    struct cli_subsig_matches *matches[1]; /* matches[] is variable length */
};

typedef struct cli_ac_data {
    uint32_t ***offmatrix;
    uint32_t partsigs, lsigs, reloffsigs;
    uint32_t **lsigcnt;
    uint32_t **lsigsuboff_last, **lsigsuboff_first;
    struct cli_lsig_matches **lsig_matches;
    uint8_t *yr_matches;
    uint32_t *offset;
    uint32_t macro_lastmatch[32];
    /** Hashset for versioninfo matching */
    const struct cli_hashset *vinfo;
    uint32_t min_partno;
} cli_ac_data;

struct cli_alt_node {
    uint16_t *str;
    uint16_t len;
    uint8_t unique;
    struct cli_alt_node *next;
};

struct cli_ac_special {
    union {
        unsigned char *byte;
        unsigned char **f_str;
        struct cli_alt_node *v_str;
    } alt;
    uint16_t len[2], num; /* 0=MIN, 1=MAX */
    uint16_t type, negative;
};

struct cli_ac_patt {
    uint16_t *pattern, *prefix, length[3], prefix_length[3];
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
    uint16_t rtype, type;
    uint32_t offdata[4], offset_min, offset_max;
    uint32_t boundary;
    uint8_t depth;
    uint8_t sigopts;
};

struct cli_ac_list {
    struct cli_ac_patt *me;
    union {
        struct cli_ac_node *node;
        struct cli_ac_list *next;
    };
    struct cli_ac_list *next_same;
};

struct cli_ac_node {
    struct cli_ac_list *list;
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

/**
 * @brief Add a simple sub-pattern into the AC trie.
 *
 * Simple sub-patterns may not include any wildcards or [a-b] anchored byte ranges.
 */
cl_error_t cli_ac_addpatt(struct cli_matcher *root, struct cli_ac_patt *pattern);

/**
 * @brief Increment the count for a subsignature of a logical signature.
 *
 * This is and alternative to lsig_increment_subsig_match() for use in subsigs that don't have a specific offset,
 * like byte-compare subsigs and fuzzy-hash subsigs.
 */
void lsig_increment_subsig_match(struct cli_ac_data *mdata, uint32_t lsig_id, uint32_t subsig_id);

cl_error_t cli_ac_initdata(struct cli_ac_data *data, uint32_t partsigs, uint32_t lsigs, uint32_t reloffsigs, uint8_t tracklen);

/**
 * @brief Increment the count for a subsignature of a logical signature.
 *
 * Increment a logical signature subsignature match count.
 *
 * @param root      The root storing all pattern matching data. I.e. "the database in memory."
 * @param mdata     Match result data
 * @param lsig_id   The current logical signature id
 * @param subsig_id The current subsignature id
 * @param realoff   Offset where the match occurred
 * @param partial   0 if whole pattern, or >0 for a partial-patterns. That is one split with wildcards like * or {n-m}.
 * @return cl_error_t
 */
cl_error_t lsig_sub_matched(const struct cli_matcher *root, struct cli_ac_data *mdata, uint32_t lsig_id, uint32_t subsig_id, uint32_t realoff, int partial);

cl_error_t cli_ac_chkmacro(struct cli_matcher *root, struct cli_ac_data *data, unsigned lsigid1);
int cli_ac_chklsig(const char *expr, const char *end, uint32_t *lsigcnt, unsigned int *cnt, uint64_t *ids, unsigned int parse_only);
void cli_ac_freedata(struct cli_ac_data *data);
cl_error_t cli_ac_scanbuff(const unsigned char *buffer, uint32_t length, const char **virname, void **customdata, struct cli_ac_result **res, const struct cli_matcher *root, struct cli_ac_data *mdata, uint32_t offset, cli_file_t ftype, struct cli_matched_type **ftoffset, unsigned int mode, cli_ctx *ctx);
cl_error_t cli_ac_buildtrie(struct cli_matcher *root);
cl_error_t cli_ac_init(struct cli_matcher *root, uint8_t mindepth, uint8_t maxdepth, uint8_t dconf_prefiltering);
cl_error_t cli_ac_caloff(const struct cli_matcher *root, struct cli_ac_data *data, const struct cli_target_info *info);
void cli_ac_free(struct cli_matcher *root);

/**
 * @brief Add a complex sub-pattern into the AC trie.
 *
 * Complex sub-patterns are the body content between `{n-m}` and `{*}` wildcards in content match signatures.
 * And `{n}` wildcards should have already been replaced with `??` characters and are included in the patterns.
 */
cl_error_t cli_ac_addsig(struct cli_matcher *root, const char *virname, const char *hexsig, uint8_t sigopts, uint32_t sigid, uint16_t parts, uint16_t partno, uint16_t rtype, uint16_t type, uint32_t mindist, uint32_t maxdist, const char *offset, const uint32_t *lsigid, unsigned int options);

#endif

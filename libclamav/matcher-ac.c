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

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/stat.h>

#include <assert.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "clamav.h"
#include "others.h"
#include "matcher.h"
#include "matcher-ac.h"
#include "filetypes.h"
#include "str.h"
#include "readdb.h"
#include "default.h"
#include "filtering.h"

#include "mpool.h"

// clang-format off

#define AC_SPECIAL_ALT_CHAR             1
#define AC_SPECIAL_ALT_STR_FIXED        2
#define AC_SPECIAL_ALT_STR              3
#define AC_SPECIAL_LINE_MARKER          4
#define AC_SPECIAL_BOUNDARY             5
#define AC_SPECIAL_WORD_MARKER          6

#define AC_BOUNDARY_LEFT                0x0001
#define AC_BOUNDARY_LEFT_NEGATIVE       0x0002
#define AC_BOUNDARY_RIGHT               0x0004
#define AC_BOUNDARY_RIGHT_NEGATIVE      0x0008
#define AC_LINE_MARKER_LEFT             0x0010
#define AC_LINE_MARKER_LEFT_NEGATIVE    0x0020
#define AC_LINE_MARKER_RIGHT            0x0040
#define AC_LINE_MARKER_RIGHT_NEGATIVE   0x0080
#define AC_WORD_MARKER_LEFT             0x0100
#define AC_WORD_MARKER_LEFT_NEGATIVE    0x0200
#define AC_WORD_MARKER_RIGHT            0x0400
#define AC_WORD_MARKER_RIGHT_NEGATIVE   0x0800

static char boundary[256] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 2, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    3, 0, 2, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 3, 1, 3,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 2, 0,
    1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

// clang-format on

static inline int insert_list(struct cli_matcher *root, struct cli_ac_patt *pattern, struct cli_ac_node *pt)
{
    struct cli_ac_list *new;
    struct cli_ac_list **newtable;

    new = (struct cli_ac_list *)MPOOL_CALLOC(root->mempool, 1, sizeof(struct cli_ac_list));
    if (!new) {
        cli_errmsg("cli_ac_addpatt: Can't allocate memory for list node\n");
        return CL_EMEM;
    }
    new->me   = pattern;
    new->node = pt;

    root->ac_lists++;
    newtable = MPOOL_REALLOC(root->mempool, root->ac_listtable, root->ac_lists * sizeof(struct cli_ac_list *));
    if (!newtable) {
        root->ac_lists--;
        cli_errmsg("cli_ac_addpatt: Can't realloc ac_listtable\n");
        MPOOL_FREE(root->mempool, new);
        return CL_EMEM;
    }

    root->ac_listtable                     = newtable;
    root->ac_listtable[root->ac_lists - 1] = new;
    return CL_SUCCESS;
}

#define RETURN_RES_IF_NE(uia, uib) \
    do {                           \
        if (uia < uib) return -1;  \
        if (uia > uib) return +1;  \
    } while (0)

static int patt_cmp_fn(const struct cli_ac_patt *a, const struct cli_ac_patt *b)
{
    unsigned int i;
    int res;
    RETURN_RES_IF_NE(a->length[0], b->length[0]);
    RETURN_RES_IF_NE(a->prefix_length[0], b->prefix_length[0]);
    RETURN_RES_IF_NE(a->ch[0], b->ch[0]);
    RETURN_RES_IF_NE(a->ch[1], b->ch[1]);
    RETURN_RES_IF_NE(a->boundary, b->boundary);

    /*
     * If the first two arguments to memcmp are NULL, clangs
     * UndefinedBehaviorSanitizer will complain.  It is legal if the length
     * is zero, so don't call memcmp if the length is zero.
     */
    if (a->length[0] > 0) {
        res = memcmp(a->pattern, b->pattern, a->length[0] * sizeof(uint16_t));
        if (res) {
            return res;
        }
    }
    if (a->prefix_length[0] > 0) {
        res = memcmp(a->prefix, b->prefix, a->prefix_length[0] * sizeof(uint16_t));
        if (res) {
            return res;
        }
    }

    RETURN_RES_IF_NE(a->special, b->special);
    if (!a->special && !b->special)
        return 0;

    for (i = 0; i < a->special; i++) {
        struct cli_ac_special *spcl_a = a->special_table[i], *spcl_b = b->special_table[i];

        RETURN_RES_IF_NE(spcl_a->num, spcl_b->num);
        RETURN_RES_IF_NE(spcl_a->negative, spcl_b->negative);
        RETURN_RES_IF_NE(spcl_a->type, spcl_b->type);

        if (spcl_a->type == AC_SPECIAL_ALT_CHAR) {
            res = memcmp((spcl_a->alt).byte, (spcl_b->alt).byte, spcl_a->num);
            if (res) return res;
        } else if (spcl_a->type == AC_SPECIAL_ALT_STR_FIXED) {
            unsigned int j;
            RETURN_RES_IF_NE(spcl_a->len[0], spcl_b->len[0]);
            for (j = 0; j < spcl_a->num; j++) {
                res = memcmp((spcl_a->alt).f_str[j], (spcl_b->alt).f_str[j], spcl_a->len[0]);
                if (res) return res;
            }
        } else if (spcl_a->type == AC_SPECIAL_ALT_STR) {
            struct cli_alt_node *alt_a = (spcl_a->alt).v_str, *alt_b = (spcl_b->alt).v_str;
            while (alt_a && alt_b) {
                RETURN_RES_IF_NE(alt_a->len, alt_b->len);
                res = memcmp(alt_a->str, alt_b->str, alt_a->len);
                if (res) return res;
                alt_a = alt_a->next;
                alt_b = alt_b->next;
            }
            RETURN_RES_IF_NE(alt_a, alt_b);
        }
    }
    return 0;
}

static int sort_list_fn(const void *a, const void *b)
{
    const struct cli_ac_node *node_a = (*(const struct cli_ac_list **)a)->node;
    const struct cli_ac_node *node_b = (*(const struct cli_ac_list **)b)->node;
    const struct cli_ac_patt *patt_a = (*(const struct cli_ac_list **)a)->me;
    const struct cli_ac_patt *patt_b = (*(const struct cli_ac_list **)b)->me;
    int res;

    /* 1. Group by owning node
     * (this is for assigning entries to nodes) */
    RETURN_RES_IF_NE(node_a, node_b);

    /* 2. Group together equal pattern in a node
     * (this is for building the next_same list) */
    res = patt_cmp_fn(patt_a, patt_b);
    if (res)
        return res;

    /* 3. Sort equal patterns in a node by partno in ascending order
     * (this is required by the matcher) */
    RETURN_RES_IF_NE(patt_a->partno, patt_b->partno);

    /* 4. Keep close patterns close
     * (this is for performance) */
    RETURN_RES_IF_NE(patt_a, patt_b);

    return 0;
}

static int sort_heads_by_partno_fn(const void *a, const void *b)
{
    const struct cli_ac_list *list_a = *(const struct cli_ac_list **)a;
    const struct cli_ac_list *list_b = *(const struct cli_ac_list **)b;
    const struct cli_ac_patt *patt_a = list_a->me;
    const struct cli_ac_patt *patt_b = list_b->me;

    /* 1. Sort heads by partno
     * (this is required by the matcher) */
    RETURN_RES_IF_NE(patt_a->partno, patt_b->partno);

    /* 2. Place longer lists earlier
     * (this is for performance) */

    while (1) {
        if (!list_a->next_same) {
            if (!list_b->next_same)
                break;
            return +1;
        }
        if (!list_b->next_same)
            return -1;
        list_a = list_a->next_same;
        list_b = list_b->next_same;
    }

    /* 3. Keep close patterns close
     * (this is for performance) */
    RETURN_RES_IF_NE(patt_a, patt_b);

    return 0;
}

static inline void link_node_lists(struct cli_ac_list **listtable, unsigned int nentries)
{
    struct cli_ac_list *prev = listtable[0];
    struct cli_ac_node *node = prev->node;
    unsigned int i, nheads = 1;

    /* Link equal patterns in the next_same list (entries are already sorted by partno asc) */
    for (i = 1; i < nentries; i++) {
        int ret = patt_cmp_fn(prev->me, listtable[i]->me);
        if (ret) {
            /* This is a new head of a next_same chain */
            prev = listtable[i];
            if (i != nheads) {
                /* Move heads towards the beginning of the table */
                listtable[i]      = listtable[nheads];
                listtable[nheads] = prev;
            }
            nheads++;
        } else {
            prev->next_same = listtable[i];
            prev->next      = NULL;
            prev            = listtable[i];
        }
    }

    cli_qsort(listtable, nheads, sizeof(listtable[0]), sort_heads_by_partno_fn);

    /* Link heads in the next list */
    node->list = listtable[0];
    for (i = 1; i < nheads; i++)
        listtable[i - 1]->next = listtable[i];
    listtable[nheads - 1]->next = NULL;
}

static void link_lists(struct cli_matcher *root)
{
    struct cli_ac_node *curnode;
    unsigned int i, grouplen;

    if (!root->ac_lists)
        return;

    /* Group the list by owning node, pattern equality and sort by partno */
    cli_qsort(root->ac_listtable, root->ac_lists, sizeof(root->ac_listtable[0]), sort_list_fn);

    curnode = root->ac_listtable[0]->node;
    for (i = 1, grouplen = 1; i <= root->ac_lists; i++, grouplen++) {
        if (i == root->ac_lists || root->ac_listtable[i]->node != curnode) {
            link_node_lists(&root->ac_listtable[i - grouplen], grouplen);
            if (i < root->ac_lists) {
                grouplen = 0;
                curnode  = root->ac_listtable[i]->node;
            }
        }
    }
}

/**
 * @brief Inserts newly malloced trans node in the array of nodes to be freed on
 * cleanup.  There is no verification that the added node is not already in the
 * list, so that is up to the caller.
 *
 * @param root      The matcher root.
 * @param trans     The trans node to be tracked.
 * @return bool
 */
static bool store_trans_node(struct cli_matcher *root, struct cli_ac_node **trans)
{
    bool bRet = false;

    if (root->trans_cnt + 1 > root->trans_capacity) {
        size_t newCapacity        = root->trans_capacity + 1024;
        struct cli_ac_node ***ret = MPOOL_REALLOC(root->mempool, root->trans_array, newCapacity * sizeof(struct cli_ac_node **));
        if (NULL == ret) {
            cli_errmsg("cli_ac_addpatt: Can't allocate memory for cleanup storage of trans\n");
            goto done;
        }
        root->trans_capacity = newCapacity;
        root->trans_array    = ret;
    }

    root->trans_array[root->trans_cnt++] = trans;

    bRet = true;
done:
    return bRet;
}

/**
 * @brief Frees all trans nodes for cleanup.
 * cleanup.
 *
 * @param root      The matcher root.
 */
static void free_trans_nodes(struct cli_matcher *root)
{
    uint32_t i = 0;

    for (i = 0; i < root->trans_cnt; i++) {
        MPOOL_FREE(root->mempool, root->trans_array[i]);
    }

    MPOOL_FREE(root->mempool, root->trans_array);
    root->trans_array    = NULL;
    root->trans_cnt      = 0;
    root->trans_capacity = 0;
}

static inline struct cli_ac_node *add_new_node(struct cli_matcher *root, uint16_t i, uint16_t len)
{
    struct cli_ac_node *new;
    struct cli_ac_node **newtable;

    new = (struct cli_ac_node *)MPOOL_CALLOC(root->mempool, 1, sizeof(struct cli_ac_node));
    if (!new) {
        cli_errmsg("cli_ac_addpatt: Can't allocate memory for AC node\n");
        return NULL;
    }

    if (i != len - 1) {
        new->trans = (struct cli_ac_node **)MPOOL_CALLOC(root->mempool, 256, sizeof(struct cli_ac_node *));
        if (!new->trans) {
            cli_errmsg("cli_ac_addpatt: Can't allocate memory for new->trans\n");
            MPOOL_FREE(root->mempool, new);
            return NULL;
        }

        if (!store_trans_node(root, new->trans)) {
            /* Error printed in store_trans_node */
            MPOOL_FREE(root->mempool, new);
            return NULL;
        }
    }

    root->ac_nodes++;
    newtable = MPOOL_REALLOC(root->mempool, root->ac_nodetable, root->ac_nodes * sizeof(struct cli_ac_node *));
    if (!newtable) {
        root->ac_nodes--;
        cli_errmsg("cli_ac_addpatt: Can't realloc ac_nodetable\n");
        if (new->trans)
            MPOOL_FREE(root->mempool, new->trans);
        MPOOL_FREE(root->mempool, new);
        return NULL;
    }

    root->ac_nodetable                     = newtable;
    root->ac_nodetable[root->ac_nodes - 1] = new;

    return new;
}

static int cli_ac_addpatt_recursive(struct cli_matcher *root, struct cli_ac_patt *pattern, struct cli_ac_node *pt, uint16_t i, uint16_t len)
{
    struct cli_ac_node *next;
    int ret;

    /* last node, insert pattern here (base case)*/
    if (i >= len) {
        return insert_list(root, pattern, pt);
    }

    /* if current node has no trans table, generate one */
    if (!pt->trans) {
        pt->trans = (struct cli_ac_node **)MPOOL_CALLOC(root->mempool, 256, sizeof(struct cli_ac_node *));
        if (!pt->trans) {
            cli_errmsg("cli_ac_addpatt: Can't allocate memory for pt->trans\n");
            return CL_EMEM;
        }
        if (!store_trans_node(root, pt->trans)) {
            /* Error printed in store_trans_node */
            return CL_EMEM;
        }
    }

    /* if pattern is nocase, we need to enumerate all the combinations if applicable
     * it's why this function was re-written to be recursive
     */
    if ((pattern->sigopts & ACPATT_OPTION_NOCASE) && (pattern->pattern[i] & 0xff) < 0x80 && isalpha((unsigned char)(pattern->pattern[i] & 0xff))) {
        next = pt->trans[CLI_NOCASEI((unsigned char)(pattern->pattern[i] & 0xff))];
        if (!next)
            next = add_new_node(root, i, len);
        if (!next)
            return CL_EMEM;
        else
            pt->trans[CLI_NOCASEI((unsigned char)(pattern->pattern[i] & 0xff))] = next;

        if ((ret = cli_ac_addpatt_recursive(root, pattern, next, i + 1, len)) != CL_SUCCESS)
            return ret;
    }

    /* normal transition, also enumerates the 'normal' nocase */
    next = pt->trans[(unsigned char)(pattern->pattern[i] & 0xff)];
    if (!next)
        next = add_new_node(root, i, len);
    if (!next)
        return CL_EMEM;
    else
        pt->trans[(unsigned char)(pattern->pattern[i] & 0xff)] = next;

    return cli_ac_addpatt_recursive(root, pattern, next, i + 1, len);
}

cl_error_t cli_ac_addpatt(struct cli_matcher *root, struct cli_ac_patt *pattern)
{
    struct cli_ac_patt **newtable;
    uint16_t len = MIN(root->ac_maxdepth, pattern->length[0]);
    uint16_t i;

    for (i = 0; i < len; i++) {
        if (pattern->pattern[i] & CLI_MATCH_WILDCARD) {
            len = i;
            break;
        }
    }

    if (len < root->ac_mindepth) {
        /* cli_errmsg("cli_ac_addpatt: Signature for %s is too short\n", pattern->virname); */
        return CL_EMALFDB;
    }

    /* pattern added to master list */
    root->ac_patterns++;
    newtable = MPOOL_REALLOC(root->mempool, root->ac_pattable, root->ac_patterns * sizeof(struct cli_ac_patt *));
    if (!newtable) {
        root->ac_patterns--;
        cli_errmsg("cli_ac_addpatt: Can't realloc ac_pattable\n");
        return CL_EMEM;
    }

    root->ac_pattable                        = newtable;
    root->ac_pattable[root->ac_patterns - 1] = pattern;

    pattern->depth = len;

    return cli_ac_addpatt_recursive(root, pattern, root->ac_root, 0, len);
}

struct bfs_list {
    struct cli_ac_node *node;
    struct bfs_list *next;
};

static int bfs_enqueue(struct bfs_list **bfs, struct bfs_list **last, struct cli_ac_node *n)
{
    struct bfs_list *new;

    new = (struct bfs_list *)malloc(sizeof(struct bfs_list));
    if (!new) {
        cli_errmsg("bfs_enqueue: Can't allocate memory for bfs_list\n");
        return CL_EMEM;
    }

    new->next = NULL;
    new->node = n;

    if (*last) {
        (*last)->next = new;
        *last         = new;
    } else {
        *bfs = *last = new;
    }

    return CL_SUCCESS;
}

static struct cli_ac_node *bfs_dequeue(struct bfs_list **bfs, struct bfs_list **last)
{
    struct bfs_list *lpt;
    struct cli_ac_node *pt;

    if (!(lpt = *bfs)) {
        return NULL;
    } else {
        *bfs = (*bfs)->next;
        pt   = lpt->node;

        if (lpt == *last)
            *last = NULL;

        free(lpt);
        return pt;
    }
}

static int ac_maketrans(struct cli_matcher *root)
{
    struct bfs_list *bfs = NULL, *bfs_last = NULL;
    struct cli_ac_node *ac_root = root->ac_root, *child, *node, *fail;
    int i, ret;

    for (i = 0; i < 256; i++) {
        node = ac_root->trans[i];
        if (!node) {
            ac_root->trans[i] = ac_root;
        } else {
            node->fail = ac_root;
            if ((ret = bfs_enqueue(&bfs, &bfs_last, node)))
                return ret;
        }
    }

    while ((node = bfs_dequeue(&bfs, &bfs_last))) {
        if (IS_LEAF(node)) {
            struct cli_ac_node *failtarget = node->fail;

            while (NULL != failtarget && (IS_LEAF(failtarget) || !IS_FINAL(failtarget)))
                failtarget = failtarget->fail;

            if (NULL != failtarget)
                node->fail = failtarget;

            continue;
        }

        for (i = 0; i < 256; i++) {
            child = node->trans[i];
            if (child) {
                fail = node->fail;

                while (IS_LEAF(fail) || !fail->trans[i])
                    fail = fail->fail;

                child->fail = fail->trans[i];

                if ((ret = bfs_enqueue(&bfs, &bfs_last, child)) != 0)
                    return ret;
            }
        }
    }

    bfs = bfs_last = NULL;
    for (i = 0; i < 256; i++) {
        node = ac_root->trans[i];
        if (node != ac_root) {
            if ((ret = bfs_enqueue(&bfs, &bfs_last, node)))
                return ret;
        }
    }

    while ((node = bfs_dequeue(&bfs, &bfs_last))) {
        if (IS_LEAF(node))
            continue;
        for (i = 0; i < 256; i++) {
            child = node->trans[i];
            if (!child || (!IS_FINAL(child) && IS_LEAF(child))) {
                struct cli_ac_node *failtarget = node->fail;

                while (IS_LEAF(failtarget) || !failtarget->trans[i])
                    failtarget = failtarget->fail;

                failtarget     = failtarget->trans[i];
                node->trans[i] = failtarget;
            } else if (IS_FINAL(child) && IS_LEAF(child)) {
                struct cli_ac_list *list;

                list = child->list;
                if (list) {
                    while (list->next)
                        list = list->next;

                    list->next = child->fail->list;
                } else {
                    child->list = child->fail->list;
                }

                child->trans = child->fail->trans;
            } else {
                if ((ret = bfs_enqueue(&bfs, &bfs_last, child)) != 0)
                    return ret;
            }
        }
    }

    return CL_SUCCESS;
}

cl_error_t cli_ac_buildtrie(struct cli_matcher *root)
{
    if (!root)
        return CL_EMALFDB;

    if (!(root->ac_root)) {
        cli_dbgmsg("cli_ac_buildtrie: AC pattern matcher is not initialised\n");
        return CL_SUCCESS;
    }

    if (root->filter)
        cli_dbgmsg("Using filter for trie %d\n", root->type);

    link_lists(root);

    return ac_maketrans(root);
}

cl_error_t cli_ac_init(struct cli_matcher *root, uint8_t mindepth, uint8_t maxdepth, uint8_t dconf_prefiltering)
{
#ifdef USE_MPOOL
    assert(root->mempool && "mempool must be initialized");
#endif

    root->ac_root = (struct cli_ac_node *)MPOOL_CALLOC(root->mempool, 1, sizeof(struct cli_ac_node));
    if (!root->ac_root) {
        cli_errmsg("cli_ac_init: Can't allocate memory for ac_root\n");
        return CL_EMEM;
    }

    root->ac_root->trans = (struct cli_ac_node **)MPOOL_CALLOC(root->mempool, 256, sizeof(struct cli_ac_node *));
    if (!root->ac_root->trans) {
        cli_errmsg("cli_ac_init: Can't allocate memory for ac_root->trans\n");
        MPOOL_FREE(root->mempool, root->ac_root);
        return CL_EMEM;
    }

    root->ac_mindepth = mindepth;
    root->ac_maxdepth = maxdepth;

    if (cli_mtargets[root->type].enable_prefiltering && dconf_prefiltering) {
        root->filter = MPOOL_MALLOC(root->mempool, sizeof(*root->filter));
        if (!root->filter) {
            cli_errmsg("cli_ac_init: Can't allocate memory for ac_root->filter\n");
            MPOOL_FREE(root->mempool, root->ac_root->trans);
            MPOOL_FREE(root->mempool, root->ac_root);
            return CL_EMEM;
        }
        filter_init(root->filter);
    }

    return CL_SUCCESS;
}

#ifdef USE_MPOOL
#define mpool_ac_free_special(a, b) ac_free_special(a, b)
static void ac_free_special(mpool_t *mempool, struct cli_ac_patt *p)
#else
#define mpool_ac_free_special(a, b) ac_free_special(b)
static void ac_free_special(struct cli_ac_patt *p)
#endif
{
    unsigned int i, j;
    struct cli_ac_special *a1;
    struct cli_alt_node *b1, *b2;

    if (!p->special)
        return;

    for (i = 0; i < p->special; i++) {
        a1 = p->special_table[i];
        if (a1->type == AC_SPECIAL_ALT_CHAR) {
            MPOOL_FREE(mempool, (a1->alt).byte);
        } else if (a1->type == AC_SPECIAL_ALT_STR_FIXED) {
            for (j = 0; j < a1->num; j++)
                MPOOL_FREE(mempool, (a1->alt).f_str[j]);
            MPOOL_FREE(mempool, (a1->alt).f_str);
        } else if (a1->type == AC_SPECIAL_ALT_STR) {
            b1 = (a1->alt).v_str;
            while (b1) {
                b2 = b1->next;
                MPOOL_FREE(mempool, b1->str);
                MPOOL_FREE(mempool, b1);
                b1 = b2;
            }
        }
        MPOOL_FREE(mempool, a1);
    }
    MPOOL_FREE(mempool, p->special_table);
}

void cli_ac_free(struct cli_matcher *root)
{
    uint32_t i               = 0;
    struct cli_ac_patt *patt = NULL;

    for (i = 0; i < root->ac_patterns; i++) {
        patt = root->ac_pattable[i];
        MPOOL_FREE(root->mempool, patt->prefix ? patt->prefix : patt->pattern);
        if (!(patt->lsigid[0] == 1)) {
            /* Don't free the virname for patterns lsigs (normal or yara).
               For lsigs, we store the virname in lsig->virname, not in each ac-pattern.
               TODO: never store the virname in the ac pattern and only store it per-signature, not per-pattern. */
            MPOOL_FREE(root->mempool, patt->virname);
        }
        if (patt->special) {
            mpool_ac_free_special(root->mempool, patt);
        }
        MPOOL_FREE(root->mempool, patt);
    }

    if (root->ac_pattable) {
        MPOOL_FREE(root->mempool, root->ac_pattable);
    }

    if (root->ac_reloff) {
        MPOOL_FREE(root->mempool, root->ac_reloff);
    }

    for (i = 0; i < root->ac_lists; i++) {
        MPOOL_FREE(root->mempool, root->ac_listtable[i]);
    }

    if (root->ac_listtable) {
        MPOOL_FREE(root->mempool, root->ac_listtable);
    }

    for (i = 0; i < root->ac_nodes; i++) {
        MPOOL_FREE(root->mempool, root->ac_nodetable[i]);
    }

    if (root->ac_nodetable) {
        MPOOL_FREE(root->mempool, root->ac_nodetable);
    }

    if (root->ac_root) {
        MPOOL_FREE(root->mempool, root->ac_root->trans);
        MPOOL_FREE(root->mempool, root->ac_root);
    }

    if (root->filter) {
        MPOOL_FREE(root->mempool, root->filter);
    }

    free_trans_nodes(root);
}

/*
 * In parse_only mode this function returns -1 on error or the max subsig id
 */
int cli_ac_chklsig(const char *expr, const char *end, uint32_t *lsigcnt, unsigned int *cnt, uint64_t *ids, unsigned int parse_only)
{
    unsigned int i, len = end - expr, pth = 0, opoff = 0, op1off = 0, val;
    unsigned int blkend = 0, id, modval1, modval2 = 0, lcnt = 0, rcnt = 0, tcnt, modoff = 0;
    uint64_t lids = 0, rids = 0, tids;
    int ret, lval, rval;
    char op = 0, op1 = 0, mod = 0, blkmod = 0;
    const char *lstart = expr, *lend = NULL, *rstart = NULL, *rend = end, *pt;

    for (i = 0; i < len; i++) {
        switch (expr[i]) {
            case '(':
                pth++;
                break;

            case ')':
                if (!pth) {
                    cli_errmsg("cli_ac_chklsig: Syntax error: Missing opening parenthesis\n");
                    return -1;
                }
                pth--;
                /* fall-through */

            case '>':
            case '<':
            case '=':
                mod    = expr[i];
                modoff = i;
                break;

            default:
                if (strchr("&|", expr[i])) {
                    if (!pth) {
                        op    = expr[i];
                        opoff = i;
                    } else if (pth == 1) {
                        op1    = expr[i];
                        op1off = i;
                    }
                }
        }

        if (op)
            break;

        if (op1 && !pth) {
            blkend = i;
            if (expr[i + 1] == '>' || expr[i + 1] == '<' || expr[i + 1] == '=') {
                blkmod = expr[i + 1];

                ret = sscanf(&expr[i + 2], "%u,%u", &modval1, &modval2);
                if (ret != 2)
                    ret = sscanf(&expr[i + 2], "%u", &modval1);

                if (!ret || ret == EOF) {
                    cli_errmsg("chklexpr: Syntax error: Missing number after '%c'\n", expr[i + 1]);
                    return -1;
                }

                for (i += 2; i + 1 < len && (isdigit(expr[i + 1]) || expr[i + 1] == ','); i++) {
                    continue;
                }
            }

            if (&expr[i + 1] == rend)
                break;
            else
                blkmod = 0;
        }
    }

    if (pth) {
        cli_errmsg("cli_ac_chklsig: Syntax error: Missing closing parenthesis\n");
        return -1;
    }

    if (!op && !op1) {
        if (expr[0] == '(')
            return cli_ac_chklsig(++expr, --end, lsigcnt, cnt, ids, parse_only);

        ret = sscanf(expr, "%u", &id);
        if (!ret || ret == EOF) {
            cli_errmsg("cli_ac_chklsig: Can't parse %s\n", expr);
            return -1;
        }

        if (parse_only)
            val = id;
        else
            val = lsigcnt[id];

        if (mod) {
            pt  = expr + modoff + 1;
            ret = sscanf(pt, "%u", &modval1);
            if (!ret || ret == EOF) {
                cli_errmsg("chklexpr: Syntax error: Missing number after '%c'\n", mod);
                return -1;
            }

            if (!parse_only) {
                switch (mod) {
                    case '=':
                        if (val != modval1)
                            return 0;
                        break;
                    case '<':
                        if (val >= modval1)
                            return 0;
                        break;
                    case '>':
                        if (val <= modval1)
                            return 0;
                        break;
                    default:
                        return 0;
                }

                *cnt += val;
                *ids |= (uint64_t)1 << id;
                return 1;
            }
        }

        if (parse_only) {
            return val;
        } else {
            if (val) {
                *cnt += val;
                *ids |= (uint64_t)1 << id;
                return 1;
            } else {
                return 0;
            }
        }
    }

    if (!op) {
        op    = op1;
        opoff = op1off;
        lstart++;
        rend = &expr[blkend];
    }

    if (!opoff) {
        cli_errmsg("cli_ac_chklsig: Syntax error: Missing left argument\n");
        return -1;
    }

    lend = &expr[opoff];
    if (opoff + 1 == len) {
        cli_errmsg("cli_ac_chklsig: Syntax error: Missing right argument\n");
        return -1;
    }

    rstart = &expr[opoff + 1];

    lval = cli_ac_chklsig(lstart, lend, lsigcnt, &lcnt, &lids, parse_only);
    if (lval == -1) {
        cli_errmsg("cli_ac_chklsig: Calculation of lval failed\n");
        return -1;
    }

    rval = cli_ac_chklsig(rstart, rend, lsigcnt, &rcnt, &rids, parse_only);
    if (rval == -1) {
        cli_errmsg("cli_ac_chklsig: Calculation of rval failed\n");
        return -1;
    }

    if (parse_only) {
        switch (op) {
            case '&':
            case '|':
                return MAX(lval, rval);
            default:
                cli_errmsg("cli_ac_chklsig: Incorrect operator type\n");
                return -1;
        }
    } else {
        switch (op) {
            case '&':
                ret = lval && rval;
                break;
            case '|':
                ret = lval || rval;
                break;
            default:
                cli_errmsg("cli_ac_chklsig: Incorrect operator type\n");
                return -1;
        }

        if (!blkmod) {
            if (ret) {
                *cnt += lcnt + rcnt;
                *ids |= lids | rids;
            }

            return ret;
        } else {
            if (ret) {
                tcnt = lcnt + rcnt;
                tids = lids | rids;
            } else {
                tcnt = 0;
                tids = 0;
            }

            switch (blkmod) {
                case '=':
                    if (tcnt != modval1)
                        return 0;
                    break;
                case '<':
                    if (tcnt >= modval1)
                        return 0;
                    break;
                case '>':
                    if (tcnt <= modval1)
                        return 0;
                    break;
                default:
                    return 0;
            }

            if (modval2) {
                val = 0;
                while (tids) {
                    val += tids & (uint64_t)1;
                    tids >>= 1;
                }

                if (val < modval2)
                    return 0;
            }

            *cnt += tcnt;
            return 1;
        }
    }
}

inline static int ac_findmatch_special(const unsigned char *buffer, uint32_t offset, uint32_t bp, uint32_t fileoffset, uint32_t length,
                                       const struct cli_ac_patt *pattern, uint32_t pp, uint16_t specialcnt, uint32_t *start, uint32_t *end, int rev);
static int ac_backward_match_branch(const unsigned char *buffer, uint32_t bp, uint32_t offset, uint32_t length, uint32_t fileoffset,
                                    const struct cli_ac_patt *pattern, uint32_t pp, uint16_t specialcnt, uint32_t *start, uint32_t *end);
static int ac_forward_match_branch(const unsigned char *buffer, uint32_t bp, uint32_t offset, uint32_t length, uint32_t fileoffset,
                                   const struct cli_ac_patt *pattern, uint32_t pp, uint16_t specialcnt, uint32_t *start, uint32_t *end);

/* call only by ac_findmatch_special! Does not handle recursive specials */
#define AC_MATCH_CHAR2(p, b)                                         \
    switch (wc = p & CLI_MATCH_METADATA) {                           \
        case CLI_MATCH_CHAR:                                         \
            if ((unsigned char)p != b)                               \
                match = 0;                                           \
            break;                                                   \
                                                                     \
        case CLI_MATCH_NOCASE:                                       \
            if ((unsigned char)(p & 0xff) != CLI_NOCASE(b))          \
                match = 0;                                           \
            break;                                                   \
                                                                     \
        case CLI_MATCH_IGNORE:                                       \
            break;                                                   \
                                                                     \
        case CLI_MATCH_NIBBLE_HIGH:                                  \
            if ((unsigned char)(p & 0x00f0) != (b & 0xf0))           \
                match = 0;                                           \
            break;                                                   \
                                                                     \
        case CLI_MATCH_NIBBLE_LOW:                                   \
            if ((unsigned char)(p & 0x000f) != (b & 0x0f))           \
                match = 0;                                           \
            break;                                                   \
                                                                     \
        default:                                                     \
            cli_errmsg("ac_findmatch: Unknown metatype 0x%x\n", wc); \
            match = 0;                                               \
    }

/* call only by ac_XX_match_branch! */
#define AC_MATCH_CHAR(p, b, rev)                                                              \
    switch (wc = p & CLI_MATCH_METADATA) {                                                    \
        case CLI_MATCH_CHAR:                                                                  \
            if ((unsigned char)p != b)                                                        \
                match = 0;                                                                    \
            break;                                                                            \
                                                                                              \
        case CLI_MATCH_NOCASE:                                                                \
            if ((unsigned char)(p & 0xff) != CLI_NOCASE(b))                                   \
                match = 0;                                                                    \
            break;                                                                            \
                                                                                              \
        case CLI_MATCH_IGNORE:                                                                \
            break;                                                                            \
                                                                                              \
        case CLI_MATCH_SPECIAL:                                                               \
            /* >1 = movement, 0 = fail, <1 = resolved in branch */                            \
            if ((match = ac_findmatch_special(buffer, offset, bp, fileoffset, length,         \
                                              pattern, i, specialcnt, start, end, rev)) <= 0) \
                return match;                                                                 \
                                                                                              \
            if (!rev) {                                                                       \
                bp += (match - 1); /* -1 is for bp++ in parent loop */                        \
                specialcnt++;                                                                 \
            } else {                                                                          \
                bp = bp + 1 - match; /* +1 is for bp-- in parent loop */                      \
                specialcnt--;                                                                 \
            }                                                                                 \
                                                                                              \
            break;                                                                            \
                                                                                              \
        case CLI_MATCH_NIBBLE_HIGH:                                                           \
            if ((unsigned char)(p & 0x00f0) != (b & 0xf0))                                    \
                match = 0;                                                                    \
            break;                                                                            \
                                                                                              \
        case CLI_MATCH_NIBBLE_LOW:                                                            \
            if ((unsigned char)(p & 0x000f) != (b & 0x0f))                                    \
                match = 0;                                                                    \
            break;                                                                            \
                                                                                              \
        default:                                                                              \
            cli_errmsg("ac_findmatch: Unknown metatype 0x%x\n", wc);                          \
            match = 0;                                                                        \
    }

/* special handler */
inline static int ac_findmatch_special(const unsigned char *buffer, uint32_t offset, uint32_t bp, uint32_t fileoffset, uint32_t length,
                                       const struct cli_ac_patt *pattern, uint32_t pp, uint16_t specialcnt, uint32_t *start, uint32_t *end, int rev)
{
    int match, cmp;
    uint16_t j, b = buffer[bp];
    uint16_t wc;
    uint32_t subbp;
    struct cli_ac_special *special = pattern->special_table[specialcnt];
    struct cli_alt_node *alt       = NULL;

    match = special->negative;

    switch (special->type) {
        case AC_SPECIAL_ALT_CHAR: /* single-byte */
            for (j = 0; j < special->num; j++) {
                cmp = b - (special->alt).byte[j];
                if (cmp == 0) {
                    match = !special->negative;
                    break;
                } else if (cmp < 0)
                    break;
            }
            break;

        case AC_SPECIAL_ALT_STR_FIXED: /* fixed length multi-byte */
            if (!rev) {
                if (bp + special->len[0] > length)
                    break;
                subbp = bp;
            } else {
                if (bp < (uint32_t)(special->len[0] - 1))
                    break;
                subbp = bp - (uint32_t)(special->len[0] - 1);
            }

            match *= special->len[0];
            for (j = 0; j < special->num; j++) {
                cmp = memcmp(&buffer[subbp], (special->alt).f_str[j], special->len[0]);
                if (cmp == 0) {
                    match = (!special->negative) * special->len[0];
                    break;
                } else if (cmp < 0)
                    break;
            }
            break;

        case AC_SPECIAL_ALT_STR: /* generic */
            alt = (special->alt).v_str;
            while (alt) {
                if (!rev) {
                    if (bp + alt->len > length) {
                        alt = alt->next;
                        continue;
                    }
                    subbp = bp;
                } else {
                    if (bp < (uint32_t)(alt->len - 1)) {
                        alt = alt->next;
                        continue;
                    }
                    subbp = bp - (uint32_t)(alt->len - 1);
                }

                /* note that generic alternates CANNOT be negated */
                match = 1;
                for (j = 0; j < alt->len; j++) {
                    AC_MATCH_CHAR2(alt->str[j], buffer[subbp + j]);
                    if (!match)
                        break;
                }
                if (match) {
                    /* if match is unique (has no derivatives), we can pass it directly back */
                    if (alt->unique) {
                        match = alt->len;
                        break;
                    }
                    /* branch for backtracking */
                    if (!rev)
                        match = ac_forward_match_branch(buffer, subbp + alt->len, offset, fileoffset, length, pattern, pp + 1, specialcnt + 1, start, end);
                    else
                        match = ac_backward_match_branch(buffer, subbp - 1, offset, fileoffset, length, pattern, pp - 1, specialcnt - 1, start, end);
                    if (match)
                        return -1; /* alerts caller that match has been resolved in child callee */
                }

                alt = alt->next;
            }
            break;

        case AC_SPECIAL_LINE_MARKER:
            if (b == '\n')
                match = !special->negative;
            else if (b == '\r' && (bp + 1 < length && buffer[bp + 1] == '\n'))
                match = (!special->negative) * 2;
            break;

        case AC_SPECIAL_BOUNDARY:
            if (boundary[b])
                match = !special->negative;
            break;

        case AC_SPECIAL_WORD_MARKER:
            if (!isalnum(b))
                match = !special->negative;
            break;

        default:
            cli_errmsg("ac_findmatch: Unknown special\n");
            match = 0;
    }

    return match;
}

/* state should reset on call, recursion depth = number of alternate specials */
/* each loop iteration starts on the NEXT sequence to be validated */
static int ac_backward_match_branch(const unsigned char *buffer, uint32_t bp, uint32_t offset, uint32_t fileoffset, uint32_t length,
                                    const struct cli_ac_patt *pattern, uint32_t pp, uint16_t specialcnt, uint32_t *start, uint32_t *end)
{
    int match = 0;
    uint16_t wc, i;
    uint32_t filestart;

    /* backwards (prefix) validation, determines start */
    if (pattern->prefix && pattern->prefix_length[0]) {
        match = 1;

        for (i = pp; 1; i--) {
            AC_MATCH_CHAR(pattern->prefix[i], buffer[bp], 1);
            if (!match)
                return 0;

            /* needs to perform check before decrement due to unsignedness */
            if (i == 0 || bp == 0)
                break;

            bp--;
        }

        *start    = bp;
        filestart = fileoffset - offset + bp;
    } else {
        /* bp is set to buffer offset */
        *start = bp = offset;
        filestart   = fileoffset;
    }

    /* left-side special checks, bp = start */
    if (pattern->boundary & AC_BOUNDARY_LEFT) {
        match = !!(pattern->boundary & AC_BOUNDARY_LEFT_NEGATIVE);
        if (!filestart || (bp && (boundary[buffer[bp - 1]] == 1 || boundary[buffer[bp - 1]] == 3)))
            match = !match;

        if (!match)
            return 0;
    }

    if (pattern->boundary & AC_LINE_MARKER_LEFT) {
        match = !!(pattern->boundary & AC_LINE_MARKER_LEFT_NEGATIVE);
        if (!filestart || (bp && (buffer[bp - 1] == '\n')))
            match = !match;

        if (!match)
            return 0;
    }

    if (pattern->boundary & AC_WORD_MARKER_LEFT) {
        match = !!(pattern->boundary & AC_WORD_MARKER_LEFT_NEGATIVE);
        if (!filestart)
            match = !match;
        else if (pattern->sigopts & ACPATT_OPTION_WIDE) {
            if (filestart - 1 == 0)
                match = !match;
            if (bp - 1 && bp && !(isalnum(buffer[bp - 2]) && buffer[bp - 1] == '\0'))
                match = !match;
        } else if (bp && !isalnum(buffer[bp - 1]))
            match = !match;

        if (!match)
            return 0;
    }

    /* bp is shifted for left anchor check, thus invalidated as pattern start */
    if (!(pattern->ch[0] & CLI_MATCH_IGNORE)) {
        if (pattern->ch_mindist[0] + (uint32_t)1 > bp)
            return 0;

        bp -= pattern->ch_mindist[0] + 1;
        for (i = pattern->ch_mindist[0]; i <= pattern->ch_maxdist[0]; i++) {
            match = 1;
            AC_MATCH_CHAR(pattern->ch[0], buffer[bp], 1);
            if (match)
                break;

            if (!bp)
                return 0;
            else
                bp--;
        }
        if (!match)
            return 0;
    }

    return 1;
}

/* state should reset on call, recursion depth = number of alternate specials */
/* each loop iteration starts on the NEXT sequence to validate */
static int ac_forward_match_branch(const unsigned char *buffer, uint32_t bp, uint32_t offset, uint32_t fileoffset, uint32_t length,
                                   const struct cli_ac_patt *pattern, uint32_t pp, uint16_t specialcnt, uint32_t *start, uint32_t *end)
{
    int match;
    uint16_t wc, i;

    match = 1;

    /* forward (pattern) validation; determines end */
    for (i = pp; i < pattern->length[0] && bp < length; i++) {
        AC_MATCH_CHAR(pattern->pattern[i], buffer[bp], 0);
        if (!match)
            return 0;

        bp++;
    }
    *end = bp;

    /* right-side special checks, bp = end */
    if (pattern->boundary & AC_BOUNDARY_RIGHT) {
        match = !!(pattern->boundary & AC_BOUNDARY_RIGHT_NEGATIVE);
        if ((length <= SCANBUFF) && (bp == length || boundary[buffer[bp]] >= 2))
            match = !match;

        if (!match)
            return 0;
    }

    if (pattern->boundary & AC_LINE_MARKER_RIGHT) {
        match = !!(pattern->boundary & AC_LINE_MARKER_RIGHT_NEGATIVE);
        if ((length <= SCANBUFF) && (bp == length || buffer[bp] == '\n' || (buffer[bp] == '\r' && bp + 1 < length && buffer[bp + 1] == '\n')))
            match = !match;

        if (!match)
            return 0;
    }

    if (pattern->boundary & AC_WORD_MARKER_RIGHT) {
        match = !!(pattern->boundary & AC_WORD_MARKER_RIGHT_NEGATIVE);
        if (length <= SCANBUFF) {
            if (bp == length)
                match = !match;
            else if ((pattern->sigopts & ACPATT_OPTION_WIDE) && (bp + 1 < length)) {
                if (!(isalnum(buffer[bp]) && buffer[bp + 1] == '\0'))
                    match = !match;
            } else if (!isalnum(buffer[bp]))
                match = !match;
        }

        if (!match)
            return 0;
    }

    /* bp is shifted for right anchor check, thus invalidated as pattern right-side */
    if (!(pattern->ch[1] & CLI_MATCH_IGNORE)) {
        bp += pattern->ch_mindist[1];

        for (i = pattern->ch_mindist[1]; i <= pattern->ch_maxdist[1]; i++) {
            if (bp >= length)
                return 0;

            match = 1;
            AC_MATCH_CHAR(pattern->ch[1], buffer[bp], 0);
            if (match)
                break;

            bp++;
        }

        if (!match)
            return 0;
    }

    return ac_backward_match_branch(buffer, offset - 1, offset, fileoffset, length, pattern, pattern->prefix_length[0] - 1, pattern->special_pattern - 1, start, end);
}

inline static int ac_findmatch(const unsigned char *buffer, uint32_t offset, uint32_t fileoffset, uint32_t length, const struct cli_ac_patt *pattern, uint32_t *start, uint32_t *end)
{
    int match;
    uint16_t specialcnt = pattern->special_pattern;

    /* minimal check as the maximum variable length may exceed the buffer */
    if ((offset + pattern->length[1] > length) || (pattern->prefix_length[1] > offset))
        return 0;

    match = ac_forward_match_branch(buffer, offset + pattern->depth, offset, fileoffset, length, pattern, pattern->depth, specialcnt, start, end);
    if (match)
        return 1;
    return 0;
}

cl_error_t cli_ac_initdata(struct cli_ac_data *data, uint32_t partsigs, uint32_t lsigs, uint32_t reloffsigs, uint8_t tracklen)
{
    unsigned int i, j;

    UNUSEDPARAM(tracklen);

    if (!data) {
        cli_errmsg("cli_ac_init: data == NULL\n");
        return CL_ENULLARG;
    }
    memset((void *)data, 0, sizeof(struct cli_ac_data));

    data->reloffsigs = reloffsigs;
    if (reloffsigs) {
        data->offset = (uint32_t *)malloc(reloffsigs * 2 * sizeof(uint32_t));
        if (!data->offset) {
            cli_errmsg("cli_ac_init: Can't allocate memory for data->offset\n");
            return CL_EMEM;
        }
        for (i = 0; i < reloffsigs * 2; i += 2)
            data->offset[i] = CLI_OFF_NONE;
    }

    data->partsigs = partsigs;
    if (partsigs) {
        data->offmatrix = (uint32_t ***)calloc(partsigs, sizeof(uint32_t **));
        if (!data->offmatrix) {
            cli_errmsg("cli_ac_init: Can't allocate memory for data->offmatrix\n");

            if (reloffsigs)
                free(data->offset);

            return CL_EMEM;
        }
    }

    data->lsigs = lsigs;
    if (lsigs) {
        data->lsigcnt = (uint32_t **)malloc(lsigs * sizeof(uint32_t *));
        if (!data->lsigcnt) {
            if (partsigs)
                free(data->offmatrix);

            if (reloffsigs)
                free(data->offset);

            cli_errmsg("cli_ac_init: Can't allocate memory for data->lsigcnt\n");
            return CL_EMEM;
        }
        data->lsigcnt[0] = (uint32_t *)calloc(lsigs * 64, sizeof(uint32_t));
        if (!data->lsigcnt[0]) {
            free(data->lsigcnt);
            if (partsigs)
                free(data->offmatrix);

            if (reloffsigs)
                free(data->offset);

            cli_errmsg("cli_ac_init: Can't allocate memory for data->lsigcnt[0]\n");
            return CL_EMEM;
        }
        for (i = 1; i < lsigs; i++)
            data->lsigcnt[i] = data->lsigcnt[0] + 64 * i;
        data->yr_matches = (uint8_t *)calloc(lsigs, sizeof(uint8_t));
        if (data->yr_matches == NULL) {
            free(data->lsigcnt[0]);
            free(data->lsigcnt);
            if (partsigs)
                free(data->offmatrix);

            if (reloffsigs)
                free(data->offset);
            return CL_EMEM;
        }

        /* subsig offsets */
        data->lsig_matches = (struct cli_lsig_matches **)calloc(lsigs, sizeof(struct cli_lsig_matches *));
        if (!data->lsig_matches) {
            free(data->yr_matches);
            free(data->lsigcnt[0]);
            free(data->lsigcnt);
            if (partsigs)
                free(data->offmatrix);

            if (reloffsigs)
                free(data->offset);

            cli_errmsg("cli_ac_init: Can't allocate memory for data->lsig_matches\n");
            return CL_EMEM;
        }
        data->lsigsuboff_last  = (uint32_t **)malloc(lsigs * sizeof(uint32_t *));
        data->lsigsuboff_first = (uint32_t **)malloc(lsigs * sizeof(uint32_t *));
        if (!data->lsigsuboff_last || !data->lsigsuboff_first) {
            free(data->lsig_matches);
            free(data->lsigsuboff_last);
            free(data->lsigsuboff_first);
            free(data->yr_matches);
            free(data->lsigcnt[0]);
            free(data->lsigcnt);
            if (partsigs)
                free(data->offmatrix);

            if (reloffsigs)
                free(data->offset);

            cli_errmsg("cli_ac_init: Can't allocate memory for data->lsigsuboff_(last|first)\n");
            return CL_EMEM;
        }
        data->lsigsuboff_last[0]  = (uint32_t *)calloc(lsigs * 64, sizeof(uint32_t));
        data->lsigsuboff_first[0] = (uint32_t *)calloc(lsigs * 64, sizeof(uint32_t));
        if (!data->lsigsuboff_last[0] || !data->lsigsuboff_first[0]) {
            free(data->lsig_matches);
            free(data->lsigsuboff_last[0]);
            free(data->lsigsuboff_first[0]);
            free(data->lsigsuboff_last);
            free(data->lsigsuboff_first);
            free(data->yr_matches);
            free(data->lsigcnt[0]);
            free(data->lsigcnt);
            if (partsigs)
                free(data->offmatrix);

            if (reloffsigs)
                free(data->offset);

            cli_errmsg("cli_ac_init: Can't allocate memory for data->lsigsuboff_(last|first)[0]\n");
            return CL_EMEM;
        }
        for (j = 0; j < 64; j++) {
            data->lsigsuboff_last[0][j]  = CLI_OFF_NONE;
            data->lsigsuboff_first[0][j] = CLI_OFF_NONE;
        }
        for (i = 1; i < lsigs; i++) {
            data->lsigsuboff_last[i]  = data->lsigsuboff_last[0] + 64 * i;
            data->lsigsuboff_first[i] = data->lsigsuboff_first[0] + 64 * i;
            for (j = 0; j < 64; j++) {
                data->lsigsuboff_last[i][j]  = CLI_OFF_NONE;
                data->lsigsuboff_first[i][j] = CLI_OFF_NONE;
            }
        }
    }
    for (i = 0; i < 32; i++)
        data->macro_lastmatch[i] = CLI_OFF_NONE;

    data->min_partno = 1;

    return CL_SUCCESS;
}

cl_error_t cli_ac_caloff(const struct cli_matcher *root, struct cli_ac_data *data, const struct cli_target_info *info)
{
    cl_error_t ret;
    unsigned int i;
    struct cli_ac_patt *patt;

    if (info)
        data->vinfo = &info->exeinfo.vinfo;

    for (i = 0; i < root->ac_reloff_num; i++) {
        patt = root->ac_reloff[i];
        if (!info) {
            data->offset[patt->offset_min] = CLI_OFF_NONE;
        } else if (CL_SUCCESS != (ret = cli_caloff(NULL, info, root->type, patt->offdata, &data->offset[patt->offset_min], &data->offset[patt->offset_max]))) {
            cli_errmsg("cli_ac_caloff: Can't calculate relative offset in signature for %s\n", patt->virname);
            return ret;
        } else if ((data->offset[patt->offset_min] != CLI_OFF_NONE) && (data->offset[patt->offset_min] + patt->length[1] > info->fsize)) {
            data->offset[patt->offset_min] = CLI_OFF_NONE;
        }
    }

    return CL_SUCCESS;
}

void cli_ac_freedata(struct cli_ac_data *data)
{
    uint32_t i;

    if (!data)
        return;

    if (data->partsigs) {
        for (i = 0; i < data->partsigs; i++) {
            if (data->offmatrix[i]) {
                free(data->offmatrix[i][0]);
                free(data->offmatrix[i]);
            }
        }
        free(data->offmatrix);
        data->offmatrix = NULL;
        data->partsigs  = 0;
    }

    if (data->lsigs) {
        if (data->lsig_matches) {
            for (i = 0; i < data->lsigs; i++) {
                struct cli_lsig_matches *ls_matches;
                if ((ls_matches = data->lsig_matches[i])) {
                    uint32_t j;
                    for (j = 0; j < ls_matches->subsigs; j++) {
                        if (ls_matches->matches[j]) {
                            free(ls_matches->matches[j]);
                            ls_matches->matches[j] = 0;
                        }
                    }
                    free(data->lsig_matches[i]);
                    data->lsig_matches[i] = 0;
                }
            }
            free(data->lsig_matches);
            data->lsig_matches = 0;
        }
        free(data->yr_matches);
        free(data->lsigcnt[0]);
        free(data->lsigcnt);
        free(data->lsigsuboff_last[0]);
        free(data->lsigsuboff_last);
        free(data->lsigsuboff_first[0]);
        free(data->lsigsuboff_first);
        data->lsigs = 0;
    }

    if (data->reloffsigs) {
        free(data->offset);
        data->reloffsigs = 0;
    }
}

/**
 * @brief Add a match for an object type to the list of matched types.
 *
 * Important: The caller is responsible for checking limits!
 *
 * @param list Pointer to the list of matched types. *list may be NULL if no types have been added yet.
 * @param type The type of the embedded object.
 * @param offset The offset of the embedded object.
 * @param ctx The context information. May be NULL.
 * @return cl_error_t CL_SUCCESS regardless if added, or CL_EMEM if memory allocation failed.
 */
inline static cl_error_t ac_addtype(struct cli_matched_type **list, cli_file_t type, off_t offset, const cli_ctx *ctx)
{
    struct cli_matched_type *tnode;

    tnode = calloc(1, sizeof(struct cli_matched_type));
    if (NULL == tnode) {
        cli_errmsg("cli_ac_addtype: Can't allocate memory for new type node\n");
        return CL_EMEM;
    }

    tnode->type   = type;
    tnode->offset = offset;

    if (*list) {
        // Add to end of existing list.
        struct cli_matched_type *tnode_last = *list;

        while (tnode_last && tnode_last->next) {
            tnode_last = tnode_last->next;
        }
        tnode_last->next = tnode;
    } else {
        // First type in the list.
        *list = tnode;
    }

    (*list)->cnt++;

    if (UNLIKELY(cli_get_debug_flag())) {
        cli_dbgmsg("ac_addtype: added %s embedded object at offset " STDi64 ". Embedded object count: %d\n", cli_ftname(type), (uint64_t)offset, (*list)->cnt);
    }

    return CL_SUCCESS;
}

void lsig_increment_subsig_match(struct cli_ac_data *mdata, uint32_t lsig_id, uint32_t subsig_id)
{
    mdata->lsigcnt[lsig_id][subsig_id]++;
}

cl_error_t lsig_sub_matched(const struct cli_matcher *root, struct cli_ac_data *mdata, uint32_t lsig_id, uint32_t subsig_id, uint32_t realoff, int partial)
{
    const struct cli_ac_lsig *ac_lsig = root->ac_lsigtable[lsig_id];
    const struct cli_lsig_tdb *tdb    = &ac_lsig->tdb;

    if (realoff != CLI_OFF_NONE) {
        if (mdata->lsigsuboff_first[lsig_id][subsig_id] == CLI_OFF_NONE) {
            /* If this is the first subsig in the lsig, store the offset in the first-list. */
            mdata->lsigsuboff_first[lsig_id][subsig_id] = realoff;
        }

        if (mdata->lsigsuboff_last[lsig_id][subsig_id] != CLI_OFF_NONE &&
            /* If this isn't the first subsig match for this logical sig and the offset
               is earlier in the file than the last subsig match, don't count it. */
            ((!partial && realoff <= mdata->lsigsuboff_last[lsig_id][subsig_id]) ||
             (partial && realoff < mdata->lsigsuboff_last[lsig_id][subsig_id]))) {
            return CL_SUCCESS;
        }

        /* Increment the subsig count for this logical signature */
        mdata->lsigcnt[lsig_id][subsig_id]++;

        if (mdata->lsigcnt[lsig_id][subsig_id] <= 1 || !tdb->macro_ptids || !tdb->macro_ptids[subsig_id]) {
            /* Store the offset of this subsig match in the last-list (except in certain circumstances) */
            mdata->lsigsuboff_last[lsig_id][subsig_id] = realoff;
        }

        if (ac_lsig->type & CLI_YARA_OFFSET) {
            /*
             * There are 3 types of logical signatures: normal, yara-normal, and yara-offset
             *
             * For yara-offset logical signatures we allocate some structures to
             * store yara subsignature match offsets.
             */
            struct cli_subsig_matches *ss_matches;
            struct cli_lsig_matches *ls_matches;

            cli_dbgmsg("lsig_sub_matched lsig %u:%u at %u\n", lsig_id, subsig_id, realoff);

            ls_matches = mdata->lsig_matches[lsig_id];
            if (ls_matches == NULL) { /* allocate cli_lsig_matches */
                ls_matches = mdata->lsig_matches[lsig_id] = (struct cli_lsig_matches *)calloc(1, sizeof(struct cli_lsig_matches) +
                                                                                                     (ac_lsig->tdb.subsigs - 1) * sizeof(struct cli_subsig_matches *));
                if (ls_matches == NULL) {
                    cli_errmsg("lsig_sub_matched: calloc failed for cli_lsig_matches\n");
                    return CL_EMEM;
                }
                ls_matches->subsigs = ac_lsig->tdb.subsigs;
            }
            ss_matches = ls_matches->matches[subsig_id];
            if (ss_matches == NULL) { /*  allocate cli_subsig_matches */
                ss_matches = ls_matches->matches[subsig_id] = malloc(sizeof(struct cli_subsig_matches));
                if (ss_matches == NULL) {
                    cli_errmsg("lsig_sub_matched: malloc failed for cli_subsig_matches struct\n");
                    return CL_EMEM;
                }
                ss_matches->next = 0;
                ss_matches->last = sizeof(ss_matches->offsets) / sizeof(uint32_t) - 1;
            }
            if (ss_matches->next > ss_matches->last) { /* cli_matches out of space? realloc */
                ss_matches = ls_matches->matches[subsig_id] = realloc(ss_matches, sizeof(struct cli_subsig_matches) + sizeof(uint32_t) * ss_matches->last * 2);
                if (ss_matches == NULL) {
                    cli_errmsg("lsig_sub_matched: realloc failed for cli_subsig_matches struct\n");
                    return CL_EMEM;
                }
                ss_matches->last = sizeof(ss_matches->offsets) / sizeof(uint32_t) + ss_matches->last * 2 - 1;
            }

            ss_matches->offsets[ss_matches->next] = realoff; /* finally, store the offset */
            ss_matches->next++;
        }
    }

    if ((tdb->macro_ptids != NULL) &&
        (tdb->macro_ptids[subsig_id] > 0) &&
        (mdata->lsigcnt[lsig_id][subsig_id] > 1)) {
        /*
         * This logical signature has a macro subsignature and this current subsignature has a macro following it.
         *
         * Check that the previous match had a macro match following it at the correct distance.
         * This check is only done after the 1st match.
         */
        const struct cli_ac_patt *macropt;
        uint32_t id, last_macro_match, smin, smax, macro_group_id, last_macroprev_match;

        /*
         * Look up the subsig for the upcoming macro to get anchor-min/max, and macro group id.
         * Reminder: A macro subsignature takes the form:
         *   ${anchor_min - anchor_max} macro_group_id$
         */
        id = tdb->macro_ptids[subsig_id];

        macropt        = root->ac_pattable[id];
        smin           = macropt->ch_mindist[0];
        smax           = macropt->ch_maxdist[0];
        macro_group_id = macropt->sigid;

        /* start of last macro match */
        last_macro_match = mdata->macro_lastmatch[macro_group_id];

        /* start of previous lsig subsig match */
        last_macroprev_match = mdata->lsigsuboff_last[lsig_id][subsig_id];

        if (last_macro_match == CLI_OFF_NONE ||
            last_macroprev_match + smin > last_macro_match ||
            last_macroprev_match + smax < last_macro_match) {
            cli_dbgmsg("Canceled false lsig macro match\n");
            /* Previous match was false - cancel it */
            mdata->lsigcnt[lsig_id][subsig_id]--;
            mdata->lsigsuboff_last[lsig_id][subsig_id] = realoff;
        } else {
            /* mark the macro sig itself matched */
            cli_dbgmsg("Checking macro match: %u + (%u - %u) == %u\n",
                       last_macroprev_match, smin, smax, last_macro_match);

            mdata->lsigcnt[lsig_id][subsig_id + 1]++;
            mdata->lsigsuboff_last[lsig_id][subsig_id + 1] = last_macro_match;
        }
    }

    return CL_SUCCESS;
}

cl_error_t cli_ac_chkmacro(struct cli_matcher *root, struct cli_ac_data *data, unsigned lsig_id)
{
    const struct cli_lsig_tdb *tdb = &root->ac_lsigtable[lsig_id]->tdb;
    unsigned i;
    cl_error_t rc;

    /* Loop through all subsigs, and if they are tied to macros check that the
     * macro matched at a correct distance */
    for (i = 0; i < tdb->subsigs; i++) {
        rc = lsig_sub_matched(root, data, lsig_id, i, CLI_OFF_NONE, 0);
        if (rc != CL_SUCCESS)
            return rc;
    }
    return CL_SUCCESS;
}

cl_error_t cli_ac_scanbuff(
    const unsigned char *buffer,
    uint32_t length,
    const char **virname,
    void **customdata,
    struct cli_ac_result **res,
    const struct cli_matcher *root,
    struct cli_ac_data *mdata,
    uint32_t offset,
    cli_file_t ftype,
    struct cli_matched_type **ftoffset,
    unsigned int mode,
    cli_ctx *ctx)
{
    struct cli_ac_node *current;
    struct cli_ac_list *pattN, *ptN;
    struct cli_ac_patt *patt, *pt;
    uint32_t i, bp, exptoff[2], realoff, matchstart, matchend;
    uint16_t j;
    uint8_t found, viruses_found = 0;
    uint32_t **offmatrix, swp;
    cli_file_t type = CL_TYPE_ANY;
    struct cli_ac_result *newres;
    cl_error_t rc;
    cl_error_t ret;

    if (!root->ac_root)
        return CL_CLEAN;

    if (!mdata && (root->ac_partsigs || root->ac_lsigs || root->ac_reloff_num)) {
        cli_errmsg("cli_ac_scanbuff: mdata == NULL\n");
        return CL_ENULLARG;
    }

    current = root->ac_root;

    for (i = 0; i < length; i++) {
        current = current->trans[buffer[i]];

        if (UNLIKELY(IS_FINAL(current))) {
            struct cli_ac_list *faillist = current->fail->list;
            pattN                        = current->list;
            while (pattN) {
                patt = pattN->me;
                if (patt->partno > mdata->min_partno) {
                    pattN    = faillist;
                    faillist = NULL;
                    continue;
                }
                bp = i + 1 - patt->depth;
                if (patt->offdata[0] != CLI_OFF_VERSION && patt->offdata[0] != CLI_OFF_MACRO && !pattN->next_same && (patt->offset_min != CLI_OFF_ANY) && (!patt->sigid || patt->partno == 1)) {
                    if (patt->offset_min == CLI_OFF_NONE) {
                        pattN = pattN->next;
                        continue;
                    }
                    exptoff[0] = offset + bp - patt->prefix_length[2]; /* lower offset end */
                    exptoff[1] = offset + bp - patt->prefix_length[1]; /* higher offset end */
                    if (patt->offdata[0] == CLI_OFF_ABSOLUTE) {
                        if (patt->offset_max < exptoff[0] || patt->offset_min > exptoff[1]) {
                            pattN = pattN->next;
                            continue;
                        }
                    } else {
                        if (mdata->offset[patt->offset_min] == CLI_OFF_NONE || mdata->offset[patt->offset_max] < exptoff[0] || mdata->offset[patt->offset_min] > exptoff[1]) {
                            pattN = pattN->next;
                            continue;
                        }
                    }
                }

                ptN = pattN;
                if (ac_findmatch(buffer, bp, offset + bp, length, patt, &matchstart, &matchend)) {
                    while (ptN) {
                        pt = ptN->me;
                        if (pt->partno > mdata->min_partno)
                            break;

                        if ((pt->type && !(mode & AC_SCAN_FT)) || (!pt->type && !(mode & AC_SCAN_VIR))) {
                            ptN = ptN->next_same;
                            continue;
                        }

                        realoff = offset + matchstart;
                        if (pt->offdata[0] == CLI_OFF_VERSION) {
                            if (false == cli_hashset_contains_maybe_noalloc(mdata->vinfo, realoff)) {
                                ptN = ptN->next_same;
                                continue;
                            }
                            cli_dbgmsg("cli_ac_scanbuff: VI match for offset %x\n", realoff);
                        } else if (pt->offdata[0] == CLI_OFF_MACRO) {
                            mdata->macro_lastmatch[patt->offdata[1]] = realoff;
                            ptN                                      = ptN->next_same;
                            continue;
                        } else if (pt->offset_min != CLI_OFF_ANY && (!pt->sigid || pt->partno == 1)) {
                            if (pt->offset_min == CLI_OFF_NONE) {
                                ptN = ptN->next_same;
                                continue;
                            }
                            if (pt->offdata[0] == CLI_OFF_ABSOLUTE) {
                                if (pt->offset_max < realoff || pt->offset_min > realoff) {
                                    ptN = ptN->next_same;
                                    continue;
                                }
                            } else {
                                if (mdata->offset[pt->offset_min] == CLI_OFF_NONE || mdata->offset[pt->offset_max] < realoff || mdata->offset[pt->offset_min] > realoff) {
                                    ptN = ptN->next_same;
                                    continue;
                                }
                            }
                        }

                        if (pt->sigid) { /* it's a partial signature */

                            /* if 2nd or later part, confirm some prior part has matched */
                            if (pt->partno != 1 && (!mdata->offmatrix[pt->sigid - 1] || !mdata->offmatrix[pt->sigid - 1][pt->partno - 2][0])) {
                                ptN = ptN->next_same;
                                continue;
                            }

                            if ((uint32_t)(pt->partno + 1) > mdata->min_partno)
                                mdata->min_partno = pt->partno + 1;

                            /* sparsely populated matrix, so allocate and initialize if NULL */
                            if (!mdata->offmatrix[pt->sigid - 1]) {
                                mdata->offmatrix[pt->sigid - 1] = malloc(pt->parts * sizeof(int32_t *));
                                if (!mdata->offmatrix[pt->sigid - 1]) {
                                    cli_errmsg("cli_ac_scanbuff: Can't allocate memory for mdata->offmatrix[%u]\n", pt->sigid - 1);
                                    return CL_EMEM;
                                }

                                mdata->offmatrix[pt->sigid - 1][0] = malloc(pt->parts * (CLI_DEFAULT_AC_TRACKLEN + 2) * sizeof(uint32_t));
                                if (!mdata->offmatrix[pt->sigid - 1][0]) {
                                    cli_errmsg("cli_ac_scanbuff: Can't allocate memory for mdata->offmatrix[%u][0]\n", pt->sigid - 1);
                                    free(mdata->offmatrix[pt->sigid - 1]);
                                    mdata->offmatrix[pt->sigid - 1] = NULL;
                                    return CL_EMEM;
                                }
                                memset(mdata->offmatrix[pt->sigid - 1][0], (uint32_t)-1, pt->parts * (CLI_DEFAULT_AC_TRACKLEN + 2) * sizeof(uint32_t));
                                mdata->offmatrix[pt->sigid - 1][0][0] = 0;
                                for (j = 1; j < pt->parts; j++) {
                                    mdata->offmatrix[pt->sigid - 1][j]    = mdata->offmatrix[pt->sigid - 1][0] + j * (CLI_DEFAULT_AC_TRACKLEN + 2);
                                    mdata->offmatrix[pt->sigid - 1][j][0] = 0;
                                }
                            }
                            offmatrix = mdata->offmatrix[pt->sigid - 1];

                            found = 0;
                            if (pt->partno != 1) {
                                for (j = 1; (j <= CLI_DEFAULT_AC_TRACKLEN + 1) && (offmatrix[pt->partno - 2][j] != (uint32_t)-1); j++) {
                                    found = j;
                                    if (realoff < offmatrix[pt->partno - 2][j])
                                        found = 0;

                                    if (found && pt->maxdist)
                                        if (realoff - offmatrix[pt->partno - 2][j] > pt->maxdist)
                                            found = 0;

                                    if (found && pt->mindist)
                                        if (realoff - offmatrix[pt->partno - 2][j] < pt->mindist)
                                            found = 0;

                                    if (found)
                                        break;
                                }
                            }

                            if (pt->partno == 2 && found > 1) {
                                swp                 = offmatrix[0][1];
                                offmatrix[0][1]     = offmatrix[0][found];
                                offmatrix[0][found] = swp;

                                if (pt->type != CL_TYPE_MSEXE) {
                                    swp                             = offmatrix[pt->parts - 1][1];
                                    offmatrix[pt->parts - 1][1]     = offmatrix[pt->parts - 1][found];
                                    offmatrix[pt->parts - 1][found] = swp;
                                }
                            }

                            if (pt->partno == 1 || (found && (pt->partno != pt->parts))) {
                                if (offmatrix[pt->partno - 1][0] == CLI_DEFAULT_AC_TRACKLEN + 1)
                                    offmatrix[pt->partno - 1][0] = 1; /* wrap, ends up at 2 */
                                offmatrix[pt->partno - 1][0]++;
                                offmatrix[pt->partno - 1][offmatrix[pt->partno - 1][0]] = offset + matchend;

                                if (pt->partno == 1) /* save realoff for the first part */
                                    offmatrix[pt->parts - 1][offmatrix[pt->partno - 1][0]] = realoff;
                            } else if (found && pt->partno == pt->parts) {
                                if (pt->type) {

                                    if (pt->type == CL_TYPE_IGNORED && (!pt->rtype || ftype == pt->rtype))
                                        return CL_TYPE_IGNORED;

                                    if ((pt->type > type || pt->type >= CL_TYPE_SFX || pt->type == CL_TYPE_MSEXE) &&
                                        (pt->rtype == CL_TYPE_ANY || ftype == pt->rtype)) {

                                        cli_dbgmsg("Matched signature for file type %s\n", pt->virname);
                                        type = pt->type;

                                        if (ftoffset != NULL) {
                                            // Caller provided a pointer to record matched types.
                                            bool too_many_types = false;
                                            bool supported_type = false;

                                            if (*ftoffset != NULL) {
                                                // Have some type matches already. Check limits.

                                                if (ctx && ((type == CL_TYPE_ZIPSFX) ||
                                                            (type == CL_TYPE_MSEXE && ftype == CL_TYPE_MSEXE))) {
                                                    // When ctx present, limit the number of type matches using ctx->engine->maxfiles for specific types.
                                                    // Reasoning:
                                                    //   ZIP local file header entries likely to be numerous if a single ZIP appended to the scanned file.
                                                    //   MSEXE can contain many embedded MSEXE entries and MSEXE type false positives matches.

                                                    if (ctx->engine->maxfiles == 0) {
                                                        // Max-files limit is disabled.
                                                    } else if ((*ftoffset)->cnt >= ctx->engine->maxfiles) {
                                                        if (UNLIKELY(cli_get_debug_flag())) {
                                                            cli_dbgmsg("ac_addtype: Can't add %s type at offset " STDu64 " to list of embedded type matches. Reached maxfiles limit of %u\n", cli_ftname(type), (*ftoffset)->offset, ctx->engine->maxfiles);
                                                        }
                                                        too_many_types = true;
                                                    }
                                                } else {
                                                    // Limit the number of type matches using MAX_EMBEDDED_OBJ.
                                                    if ((*ftoffset)->cnt >= MAX_EMBEDDED_OBJ) {
                                                        if (UNLIKELY(cli_get_debug_flag())) {
                                                            cli_dbgmsg("ac_addtype: Can't add %s type at offset " STDu64 " to list of embedded type matches. Reached MAX_EMBEDDED_OBJ limit of %u\n", cli_ftname(type), (*ftoffset)->offset, MAX_EMBEDDED_OBJ);
                                                        }
                                                        too_many_types = true;
                                                    }
                                                }
                                            }

                                            // Filter to supported types.
                                            if (
                                                // Found type is MBR.
                                                type == CL_TYPE_MBR ||
                                                // Found type is any SFX type (i.e., ZIPSFX, RARSFX, 7ZSSFX, etc.).
                                                type >= CL_TYPE_SFX ||
                                                // Found type is an MSEXE, but only if host file type is one of MSEXE, ZIP, or MSOLE2.
                                                (type == CL_TYPE_MSEXE && (ftype == CL_TYPE_MSEXE || ftype == CL_TYPE_ZIP || ftype == CL_TYPE_MSOLE2))) {

                                                supported_type = true;
                                            }

                                            if (supported_type && !too_many_types) {
                                                /* FIXME: the first offset in the array is most likely the correct one but
                                                 * it may happen it is not
                                                 * Until we're certain and can fix this, we add all offsets in the list.
                                                 */
                                                for (j = 1; j <= CLI_DEFAULT_AC_TRACKLEN + 1 && offmatrix[0][j] != (uint32_t)-1; j++) {
                                                    ret = ac_addtype(ftoffset, type, offmatrix[pt->parts - 1][j], ctx);
                                                    if (CL_SUCCESS != ret) {
                                                        return ret;
                                                    }
                                                }
                                            }
                                        }

                                        memset(offmatrix[0], (uint32_t)-1, pt->parts * (CLI_DEFAULT_AC_TRACKLEN + 2) * sizeof(uint32_t));
                                        for (j = 0; j < pt->parts; j++)
                                            offmatrix[j][0] = 0;
                                    }

                                } else { /* !pt->type */
                                    if (pt->lsigid[0]) {
                                        rc = lsig_sub_matched(root, mdata, pt->lsigid[1], pt->lsigid[2], offmatrix[pt->parts - 1][1], 1);
                                        if (rc != CL_SUCCESS)
                                            return rc;
                                        ptN = ptN->next_same;
                                        continue;
                                    }

                                    if (res) {
                                        newres = (struct cli_ac_result *)malloc(sizeof(struct cli_ac_result));
                                        if (!newres) {
                                            cli_errmsg("cli_ac_scanbuff: Can't allocate memory for newres %lu\n", (unsigned long)sizeof(struct cli_ac_result));
                                            return CL_EMEM;
                                        }
                                        newres->virname    = pt->virname;
                                        newres->customdata = pt->customdata;
                                        newres->next       = *res;
                                        newres->offset     = (off_t)offmatrix[pt->parts - 1][1];
                                        *res               = newres;

                                        ptN = ptN->next_same;
                                        continue;
                                    } else {
                                        if (ctx && SCAN_ALLMATCHES) {
                                            ret = cli_append_virus(ctx, (const char *)pt->virname);
                                            if (ret == CL_VIRUS) {
                                                viruses_found = 1;
                                            }
                                        }
                                        if (virname)
                                            *virname = pt->virname;
                                        if (customdata)
                                            *customdata = pt->customdata;
                                        if (!ctx || !SCAN_ALLMATCHES)
                                            return CL_VIRUS;
                                        ptN = ptN->next_same;
                                        continue;
                                    }
                                }
                            }

                        } else { /* old type signature */
                            if (pt->type) {
                                if (pt->type == CL_TYPE_IGNORED && (pt->rtype == CL_TYPE_ANY || ftype == pt->rtype))
                                    return CL_TYPE_IGNORED;

                                if ((pt->type > type || pt->type >= CL_TYPE_SFX || pt->type == CL_TYPE_MSEXE) &&
                                    (pt->rtype == CL_TYPE_ANY || ftype == pt->rtype)) {

                                    cli_dbgmsg("Matched signature for file type %s at %u\n", pt->virname, realoff);
                                    type = pt->type;

                                    if (ftoffset != NULL) {
                                        // Caller provided a pointer to record matched types.
                                        bool too_many_types = false;
                                        bool supported_type = false;

                                        if (*ftoffset != NULL) {
                                            // Have some type matches already. Check limits.

                                            if (ctx && ((type == CL_TYPE_ZIPSFX) ||
                                                        (type == CL_TYPE_MSEXE && ftype == CL_TYPE_MSEXE))) {
                                                // When ctx present, limit the number of type matches using ctx->engine->maxfiles for specific types.
                                                // Reasoning:
                                                //   ZIP local file header entries likely to be numerous if a single ZIP appended to the scanned file.
                                                //   MSEXE can contain many embedded MSEXE entries and MSEXE type false positives matches.

                                                if (ctx->engine->maxfiles == 0) {
                                                    // Max-files limit is disabled.
                                                } else if ((*ftoffset)->cnt >= ctx->engine->maxfiles) {
                                                    if (UNLIKELY(cli_get_debug_flag())) {
                                                        cli_dbgmsg("ac_addtype: Can't add %s type at offset " STDu64 " to list of embedded type matches. Reached maxfiles limit of %u\n", cli_ftname(type), (*ftoffset)->offset, ctx->engine->maxfiles);
                                                    }
                                                    too_many_types = true;
                                                }
                                            } else {
                                                // Limit the number of type matches using MAX_EMBEDDED_OBJ.
                                                if ((*ftoffset)->cnt >= MAX_EMBEDDED_OBJ) {
                                                    if (UNLIKELY(cli_get_debug_flag())) {
                                                        cli_dbgmsg("ac_addtype: Can't add %s type at offset " STDu64 " to list of embedded type matches. Reached MAX_EMBEDDED_OBJ limit of %u\n", cli_ftname(type), (*ftoffset)->offset, MAX_EMBEDDED_OBJ);
                                                    }
                                                    too_many_types = true;
                                                }
                                            }
                                        }

                                        // Filter to supported types.
                                        if (
                                            // Found type is MBR.
                                            type == CL_TYPE_MBR ||
                                            // Found type is any SFX type (i.e., ZIPSFX, RARSFX, 7ZSSFX, etc.).
                                            type >= CL_TYPE_SFX ||
                                            // Found type is an MSEXE, but only if host file type is one of MSEXE, ZIP, or MSOLE2.
                                            (type == CL_TYPE_MSEXE && (ftype == CL_TYPE_MSEXE || ftype == CL_TYPE_ZIP || ftype == CL_TYPE_MSOLE2))) {

                                            supported_type = true;
                                        }

                                        if (supported_type && !too_many_types) {
                                            ret = ac_addtype(ftoffset, type, realoff, ctx);
                                            if (CL_SUCCESS != ret) {
                                                return ret;
                                            }
                                        }
                                    }
                                }
                            } else {
                                if (pt->lsigid[0]) {
                                    rc = lsig_sub_matched(root, mdata, pt->lsigid[1], pt->lsigid[2], realoff, 0);
                                    if (rc != CL_SUCCESS)
                                        return rc;
                                    ptN = ptN->next_same;
                                    continue;
                                }

                                if (res) {
                                    newres = (struct cli_ac_result *)malloc(sizeof(struct cli_ac_result));
                                    if (!newres) {
                                        cli_errmsg("cli_ac_scanbuff: Can't allocate memory for newres %lu\n", (unsigned long)sizeof(struct cli_ac_result));
                                        return CL_EMEM;
                                    }
                                    newres->virname    = pt->virname;
                                    newres->customdata = pt->customdata;
                                    newres->offset     = (off_t)realoff;
                                    newres->next       = *res;
                                    *res               = newres;

                                    ptN = ptN->next_same;
                                    continue;
                                } else {
                                    if (ctx && SCAN_ALLMATCHES) {
                                        ret = cli_append_virus(ctx, (const char *)pt->virname);
                                        if (ret == CL_VIRUS) {
                                            viruses_found = 1;
                                        }
                                    }

                                    if (virname)
                                        *virname = pt->virname;

                                    if (customdata)
                                        *customdata = pt->customdata;

                                    if (!ctx || !SCAN_ALLMATCHES)
                                        return CL_VIRUS;

                                    ptN = ptN->next_same;
                                    continue;
                                }
                            }
                        }
                        ptN = ptN->next_same;
                    }
                }
                pattN = pattN->next;
            }
        }
    }

    if (viruses_found)
        return CL_VIRUS;

    return (mode & AC_SCAN_FT) ? type : CL_CLEAN;
}

static int qcompare_byte(const void *a, const void *b)
{
    return *(const unsigned char *)a - *(const unsigned char *)b;
}

static int qcompare_fstr(const void *arg, const void *a, const void *b)
{
    uint16_t len = *(uint16_t *)arg;
    return memcmp(*(const unsigned char **)a, *(const unsigned char **)b, len);
}

/* returns if level of nesting, end set to MATCHING paren, start AFTER staring paren */
inline static size_t find_paren_end(char *hexstr, char **end)
{
    size_t i;
    size_t nest = 0, level = 0;

    *end = NULL;
    for (i = 0; i < strlen(hexstr); i++) {
        if (hexstr[i] == '(') {
            nest++;
            level++;
        } else if (hexstr[i] == ')') {
            if (!level) {
                *end = &hexstr[i];
                break;
            }
            level--;
        }
    }

    return nest;
}

/* analyzes expr, returns number of subexpr, if fixed length subexpr and longest subexpr len *
 * goes to either end of string or to closing parenthesis; allowed to be unbalanced          *
 * counts applied to start of expr (not end, i.e. numexpr starts at 1 for the first expr     */
inline static int ac_analyze_expr(char *hexstr, int *fixed_len, int *sub_len)
{
    unsigned long i;
    int level = 0, len = 0, numexpr = 1;
    int flen, slen;

    flen = 1;
    slen = 0;
    for (i = 0; i < strlen(hexstr); i++) {
        if (hexstr[i] == '(') {
            flen = 0;
            level++;
        } else if (hexstr[i] == ')') {
            if (!level) {
                if (!slen) {
                    slen = len;
                } else if (len != slen) {
                    flen = 0;
                    if (len > slen)
                        slen = len;
                }
                break;
            }
            level--;
        }
        if (!level && hexstr[i] == '|') {
            if (!slen) {
                slen = len;
            } else if (len != slen) {
                flen = 0;
                if (len > slen)
                    slen = len;
            }
            len = 0;
            numexpr++;
        } else {
            if (hexstr[i] == '?')
                flen = 0;
            len++;
        }
    }
    if (!slen) {
        slen = len;
    } else if (len != slen) {
        flen = 0;
        if (len > slen)
            slen = len;
    }

    if (sub_len)
        *sub_len = slen;
    if (fixed_len)
        *fixed_len = flen;

    return numexpr;
}

inline static int ac_uicmp(uint16_t *a, size_t alen, uint16_t *b, size_t blen, int *wild)
{
    uint16_t awild, bwild, side_wild;
    size_t i, minlen = MIN(alen, blen);

    side_wild = 0;

    for (i = 0; i < minlen; i++) {
        awild = a[i] & CLI_MATCH_WILDCARD;
        bwild = b[i] & CLI_MATCH_WILDCARD;

        if (awild == bwild) {
            switch (awild) {
                case CLI_MATCH_CHAR:
                    if ((a[i] & 0xff) != (b[i] & 0xff)) {
                        return (b[i] & 0xff) - (a[i] & 0xff);
                    }
                    break;
                case CLI_MATCH_IGNORE:
                    break;
                case CLI_MATCH_NIBBLE_HIGH:
                    if ((a[i] & 0xf0) != (b[i] & 0xf0)) {
                        return (b[i] & 0xf0) - (a[i] & 0xf0);
                    }
                    break;
                case CLI_MATCH_NIBBLE_LOW:
                    if ((a[i] & 0x0f) != (b[i] & 0x0f)) {
                        return (b[i] & 0x0f) - (a[i] & 0x0f);
                    }
                    break;
                default:
                    cli_errmsg("ac_uicmp: unhandled wildcard type\n");
                    return 1;
            }
        } else {                           /* not identical wildcard types */
            if (awild == CLI_MATCH_CHAR) { /* b is only wild */
                switch (bwild) {
                    case CLI_MATCH_IGNORE:
                        side_wild |= 2;
                        break;
                    case CLI_MATCH_NIBBLE_HIGH:
                        if ((a[i] & 0xf0) != (b[i] & 0xf0)) {
                            return (b[i] & 0xf0) - (a[i] & 0xff);
                        }
                        side_wild |= 2;
                        break;
                    case CLI_MATCH_NIBBLE_LOW:
                        if ((a[i] & 0x0f) != (b[i] & 0x0f)) {
                            return (b[i] & 0x0f) - (a[i] & 0xff);
                        }
                        side_wild |= 2;
                        break;
                    default:
                        cli_errmsg("ac_uicmp: unhandled wildcard type\n");
                        return -1;
                }
            } else if (bwild == CLI_MATCH_CHAR) { /* a is only wild */
                switch (awild) {
                    case CLI_MATCH_IGNORE:
                        side_wild |= 1;
                        break;
                    case CLI_MATCH_NIBBLE_HIGH:
                        if ((a[i] & 0xf0) != (b[i] & 0xf0)) {
                            return (b[i] & 0xff) - (a[i] & 0xf0);
                        }
                        side_wild |= 1;
                        break;
                    case CLI_MATCH_NIBBLE_LOW:
                        if ((a[i] & 0x0f) != (b[i] & 0x0f)) {
                            return (b[i] & 0xff) - (a[i] & 0x0f);
                        }
                        side_wild |= 1;
                        break;
                    default:
                        cli_errmsg("ac_uicmp: unhandled wild typing\n");
                        return 1;
                }
            } else { /* not identical, both wildcards */
                if (awild == CLI_MATCH_IGNORE || bwild == CLI_MATCH_IGNORE) {
                    if (awild == CLI_MATCH_IGNORE) {
                        side_wild |= 1;
                    } else if (bwild == CLI_MATCH_IGNORE) {
                        side_wild |= 2;
                    }
                } else {
                    /* only high and low nibbles should be left here */
                    side_wild |= 3;
                }
            }
        }

        /* both sides contain a wildcard that contains the other, therefore unique by wildcards */
        if (side_wild == 3)
            return 1;
    }

    if (wild)
        *wild = side_wild;
    return 0;
}

/* add new generic alternate node to special */
inline static int ac_addspecial_add_alt_node(const char *subexpr, uint8_t sigopts, struct cli_ac_special *special, struct cli_matcher *root)
{
    struct cli_alt_node *newnode = NULL;
    struct cli_alt_node **prev   = NULL;
    struct cli_alt_node *ins     = NULL;
    uint16_t *s                  = NULL;
    int i                        = 0;
    int cmp                      = 0;
    int wild                     = 0;

#ifndef USE_MPOOL
    UNUSEDPARAM(root);
#endif

    newnode = (struct cli_alt_node *)MPOOL_CALLOC(root->mempool, 1, sizeof(struct cli_alt_node));
    if (!newnode) {
        cli_errmsg("ac_addspecial_add_alt_node: Can't allocate new alternate node\n");
        return CL_EMEM;
    }

    s = CLI_MPOOL_HEX2UI(root->mempool, subexpr);
    if (!s) {
        MPOOL_FREE(root->mempool, newnode);
        return CL_EMALFDB;
    }

    newnode->str    = s;
    newnode->len    = (uint16_t)strlen(subexpr) / 2;
    newnode->unique = 1;

    /* setting nocase match */
    if (sigopts & ACPATT_OPTION_NOCASE) {
        for (i = 0; i < newnode->len; ++i)
            if ((newnode->str[i] & CLI_MATCH_METADATA) == CLI_MATCH_CHAR) {
                newnode->str[i] = CLI_NOCASE(newnode->str[i] & 0xff);
                newnode->str[i] += CLI_MATCH_NOCASE;
            }
    }

    /* search for uniqueness, TODO: directed acyclic word graph */
    prev = &((special->alt).v_str);
    ins  = (special->alt).v_str;
    while (ins) {
        cmp = ac_uicmp(ins->str, ins->len, newnode->str, newnode->len, &wild);
        if (cmp == 0) {
            if (newnode->len != ins->len) { /* derivative */
                newnode->unique = 0;
                ins->unique     = 0;
            } else if (wild == 0) { /* duplicate */
                MPOOL_FREE(root->mempool, newnode->str);
                MPOOL_FREE(root->mempool, newnode);
                return CL_SUCCESS;
            }
        } /* TODO - possible sorting of altstr uniques and derivative groups? */

        prev = &(ins->next);
        ins  = ins->next;
    }

    *prev         = newnode;
    newnode->next = ins;
    if ((special->num == 0) || (newnode->len < special->len[0]))
        special->len[0] = newnode->len;
    if ((special->num == 0) || (newnode->len > special->len[1]))
        special->len[1] = newnode->len;
    special->num++;
    return CL_SUCCESS;
}

/* recursive special handler for expanding and adding generic alternates */
static int ac_special_altexpand(char *hexpr, char *subexpr, uint16_t maxlen, int lvl, int maxlvl, uint8_t sigopts, struct cli_ac_special *special, struct cli_matcher *root)
{
    int ret, scnt = 0, numexpr;
    char *ept, *sexpr, *end, term;
    char *fp;

    ept = sexpr = hexpr;
    fp          = subexpr + strlen(subexpr);

    numexpr = ac_analyze_expr(hexpr, NULL, NULL);

    /* while there are expressions to resolve */
    while (scnt < numexpr) {
        scnt++;
        while ((*ept != '(') && (*ept != '|') && (*ept != ')') && (*ept != '\0'))
            ept++;

        /* check for invalid negation */
        term = *ept;
        if ((*ept == '(') && (ept >= hexpr + 1)) {
            if (ept[-1] == '!') {
                cli_errmsg("ac_special_altexpand: Generic alternates cannot contain negations\n");
                return CL_EMALFDB;
            }
        }

        /* appended token */
        *ept = 0;
        if (cli_strlcat(subexpr, sexpr, maxlen) >= maxlen) {
            cli_errmsg("ac_special_altexpand: Unexpected expression larger than expected\n");
            return CL_EMEM;
        }

        *ept++ = term;
        sexpr  = ept;

        if (term == '|') {
            if (lvl == 0) {
                if ((ret = ac_addspecial_add_alt_node(subexpr, sigopts, special, root)) != CL_SUCCESS)
                    return ret;
            } else {
                find_paren_end(ept, &end);
                if (!end) {
                    cli_errmsg("ac_special_altexpand: Missing closing parenthesis\n");
                    return CL_EMALFDB;
                }
                end++;

                if ((ret = ac_special_altexpand(end, subexpr, maxlen, lvl - 1, lvl, sigopts, special, root)) != CL_SUCCESS)
                    return ret;
            }

            *fp = 0;
        } else if (term == ')') {
            if (lvl == 0) {
                cli_errmsg("ac_special_altexpand: Unexpected closing parenthesis\n");
                return CL_EPARSE;
            }

            if ((ret = ac_special_altexpand(ept, subexpr, maxlen, lvl - 1, lvl, sigopts, special, root)) != CL_SUCCESS)
                return ret;
            break;
        } else if (term == '(') {
            int inner, found;
            find_paren_end(ept, &end);
            if (!end) {
                cli_errmsg("ac_special_altexpand: Missing closing parenthesis\n");
                return CL_EMALFDB;
            }
            end++;

            if ((ret = ac_special_altexpand(ept, subexpr, maxlen, lvl + 1, lvl + 1, sigopts, special, root)) != CL_SUCCESS)
                return ret;

            /* move ept to end of current alternate expression (recursive call already populates them) */
            ept   = end;
            inner = 0;
            found = 0;
            while (!found && *ept != '\0') {
                switch (*ept) {
                    case '|':
                        if (!inner)
                            found = 1;
                        break;
                    case '(':
                        inner++;
                        break;
                    case ')':
                        inner--;
                        break;
                }
                ept++;
            }
            if (*ept == '|')
                ept++;

            sexpr = ept;
            *fp   = 0;
        } else if (term == '\0') {
            if ((ret = ac_addspecial_add_alt_node(subexpr, sigopts, special, root)) != CL_SUCCESS)
                return ret;
            break;
        }

        if (lvl != maxlvl)
            return CL_SUCCESS;
    }
    if (scnt != numexpr) {
        cli_errmsg("ac_addspecial: Mismatch in parsed and expected signature\n");
        return CL_EMALFDB;
    }

    return CL_SUCCESS;
}

/* alternate string specials (so many specials!) */
inline static int ac_special_altstr(const char *hexpr, uint8_t sigopts, struct cli_ac_special *special, struct cli_matcher *root)
{
    char *hexprcpy, *h, *c;
    int i, ret, num, fixed, slen;

    if (!(hexprcpy = cli_safer_strdup(hexpr))) {
        cli_errmsg("ac_special_altstr: Can't duplicate alternate expression\n");
        return CL_EDUP;
    }

    num = ac_analyze_expr(hexprcpy, &fixed, &slen);

    if (!sigopts && fixed) {
        special->num    = 0;
        special->len[0] = special->len[1] = slen / 2;
        /* single-bytes are len 2 in hex */
        if (slen == 2) {
            special->type       = AC_SPECIAL_ALT_CHAR;
            (special->alt).byte = (unsigned char *)MPOOL_MALLOC(root->mempool, num);
            if (!((special->alt).byte)) {
                cli_errmsg("cli_ac_special_altstr: Can't allocate newspecial->str\n");
                free(hexprcpy);
                return CL_EMEM;
            }
        } else {
            special->type        = AC_SPECIAL_ALT_STR_FIXED;
            (special->alt).f_str = (unsigned char **)MPOOL_MALLOC(root->mempool, num * sizeof(unsigned char *));
            if (!((special->alt).f_str)) {
                cli_errmsg("cli_ac_special_altstr: Can't allocate newspecial->str\n");
                free(hexprcpy);
                return CL_EMEM;
            }
        }

        for (i = 0; i < num; i++) {
            if (num == 1) {
                c = CLI_MPOOL_HEX2STR(root->mempool, hexprcpy);
            } else {
                if (!(h = cli_strtok(hexprcpy, i, "|"))) {
                    free(hexprcpy);
                    return CL_EMEM;
                }
                c = CLI_MPOOL_HEX2STR(root->mempool, h);
                free(h);
            }
            if (!c) {
                free(hexprcpy);
                return CL_EMALFDB;
            }

            if (special->type == AC_SPECIAL_ALT_CHAR) {
                (special->alt).byte[i] = (unsigned char)*c;
                MPOOL_FREE(root->mempool, c);
            } else {
                (special->alt).f_str[i] = (unsigned char *)c;
            }
            special->num++;
        }
        /* sorting byte alternates */
        if (special->num > 1 && special->type == AC_SPECIAL_ALT_CHAR)
            cli_qsort((special->alt).byte, special->num, sizeof(unsigned char), qcompare_byte);
        /* sorting str alternates */
        if (special->num > 1 && special->type == AC_SPECIAL_ALT_STR_FIXED)
            cli_qsort_r((special->alt).f_str, special->num, sizeof(unsigned char *), qcompare_fstr, &(special->len));
    } else { /* generic alternates */
        char *subexpr;
        if (special->negative) {
            cli_errmsg("ac_special_altstr: Can't apply negation operation to generic alternate strings\n");
            free(hexprcpy);
            return CL_EMALFDB;
        }

        special->type = AC_SPECIAL_ALT_STR;

        /* allocate reusable subexpr */
        if (!(subexpr = calloc(slen + 1, sizeof(char)))) {
            cli_errmsg("ac_special_altstr: Can't allocate subexpr container\n");
            free(hexprcpy);
            return CL_EMEM;
        }

        ret = ac_special_altexpand(hexprcpy, subexpr, slen + 1, 0, 0, sigopts, special, root);

        free(subexpr);
        free(hexprcpy);
        return ret;
    }

    free(hexprcpy);
    return CL_SUCCESS;
}

/* FIXME: clean up the code */
cl_error_t cli_ac_addsig(struct cli_matcher *root, const char *virname, const char *hexsig, uint8_t sigopts, uint32_t sigid, uint16_t parts, uint16_t partno, uint16_t rtype, uint16_t type, uint32_t mindist, uint32_t maxdist, const char *offset, const uint32_t *lsigid, unsigned int options)
{
    struct cli_ac_patt *new;
    char *pt, *pt2, *hex = NULL, *hexcpy = NULL;
    uint16_t i, j, ppos = 0, pend, *dec, nzpos = 0;
    uint8_t wprefix = 0, zprefix = 1, plen = 0, nzplen = 0;
    struct cli_ac_special *newspecial, **newtable;
    int ret, error = CL_SUCCESS;
    char *virname_copy = NULL;

    if (!root) {
        cli_errmsg("cli_ac_addsig: root == NULL\n");
        return CL_ENULLARG;
    }

    if (strlen(hexsig) / 2 < root->ac_mindepth) {
        cli_errmsg("cli_ac_addsig: Signature for %s is too short\n", virname);
        return CL_EMALFDB;
    }

    if ((new = (struct cli_ac_patt *)MPOOL_CALLOC(root->mempool, 1, sizeof(struct cli_ac_patt))) == NULL)
        return CL_EMEM;

    new->rtype      = rtype;
    new->type       = type;
    new->sigid      = sigid;
    new->parts      = parts;
    new->partno     = partno;
    new->mindist    = mindist;
    new->maxdist    = maxdist;
    new->customdata = NULL;
    new->ch[0] |= CLI_MATCH_IGNORE;
    new->ch[1] |= CLI_MATCH_IGNORE;
    if (lsigid) {
        new->lsigid[0] = 1;
        memcpy(&new->lsigid[1], lsigid, 2 * sizeof(uint32_t));
    }

    if (strchr(hexsig, '[')) {
        if (!(hexcpy = cli_safer_strdup(hexsig))) {
            MPOOL_FREE(root->mempool, new);
            return CL_EMEM;
        }

        hex = hexcpy;
        for (i = 0; i < 2; i++) {
            unsigned int n, n1, n2;

            if (!(pt = strchr(hex, '[')))
                break;

            *pt++ = 0;

            if (!(pt2 = strchr(pt, ']'))) {
                cli_dbgmsg("cli_ac_addsig: missing closing square bracket\n");
                error = CL_EMALFDB;
                break;
            }

            *pt2++ = 0;

            n = sscanf(pt, "%u-%u", &n1, &n2);
            if (n == 1) {
                n2 = n1;
            } else if (n != 2) {
                cli_dbgmsg("cli_ac_addsig: incorrect range inside square brackets\n");
                error = CL_EMALFDB;
                break;
            }

            if ((n1 > n2) || (n2 > AC_CH_MAXDIST)) {
                cli_dbgmsg("cli_ac_addsig: incorrect range inside square brackets\n");
                error = CL_EMALFDB;
                break;
            }

            if (strlen(hex) == 2) {
                if (i) {
                    error = CL_EMALFDB;
                    break;
                }

                dec = cli_hex2ui(hex);
                if (!dec) {
                    error = CL_EMALFDB;
                    break;
                }

                if ((sigopts & ACPATT_OPTION_NOCASE) && ((*dec & CLI_MATCH_METADATA) == CLI_MATCH_CHAR))
                    new->ch[i] = CLI_NOCASE(*dec) | CLI_MATCH_NOCASE;
                else
                    new->ch[i] = *dec;
                free(dec);
                new->ch_mindist[i] = n1;
                new->ch_maxdist[i] = n2;
                hex                = pt2;
            } else if (strlen(pt2) == 2) {
                i   = 1;
                dec = cli_hex2ui(pt2);
                if (!dec) {
                    error = CL_EMALFDB;
                    break;
                }

                if ((sigopts & ACPATT_OPTION_NOCASE) && ((*dec & CLI_MATCH_METADATA) == CLI_MATCH_CHAR))
                    new->ch[i] = CLI_NOCASE(*dec) | CLI_MATCH_NOCASE;
                else
                    new->ch[i] = *dec;
                free(dec);
                new->ch_mindist[i] = n1;
                new->ch_maxdist[i] = n2;
            } else {
                error = CL_EMALFDB;
                break;
            }
        }

        if (error) {
            free(hexcpy);
            MPOOL_FREE(root->mempool, new);
            return error;
        }

        hex = cli_safer_strdup(hex);
        free(hexcpy);
        if (!hex) {
            MPOOL_FREE(root->mempool, new);
            return CL_EMEM;
        }
    }

    if (strchr(hexsig, '(')) {
        char *hexnew, *start;
        size_t nest;
        size_t hexnewsz;

        if (hex) {
            hexcpy = hex;
        } else if (!(hexcpy = cli_safer_strdup(hexsig))) {
            MPOOL_FREE(root->mempool, new);
            return CL_EMEM;
        }

        hexnewsz = strlen(hexsig) + 1;
        if (!(hexnew = (char *)calloc(1, hexnewsz))) {
            MPOOL_FREE(root->mempool, new);
            free(hexcpy);
            return CL_EMEM;
        }

        start = pt = hexcpy;
        while ((pt = strchr(start, '('))) {
            *pt++ = 0;

            if (!start) {
                error = CL_EMALFDB;
                break;
            }
            newspecial = (struct cli_ac_special *)MPOOL_CALLOC(root->mempool, 1, sizeof(struct cli_ac_special));
            if (!newspecial) {
                cli_errmsg("cli_ac_addsig: Can't allocate newspecial\n");
                error = CL_EMEM;
                break;
            }
            if (pt >= hexcpy + 2) {
                if (pt[-2] == '!') {
                    newspecial->negative = 1;
                    pt[-2]               = 0;
                }
            }
            cli_strlcat(hexnew, start, hexnewsz);

            nest = find_paren_end(pt, &start);
            if (!start) {
                cli_errmsg("cli_ac_addsig: Missing closing parenthesis\n");
                MPOOL_FREE(root->mempool, newspecial);
                error = CL_EMALFDB;
                break;
            }
            *start++ = 0;
            if (!strlen(pt)) {
                cli_errmsg("cli_ac_addsig: Empty block\n");
                MPOOL_FREE(root->mempool, newspecial);
                error = CL_EMALFDB;
                break;
            }

            if (nest > ACPATT_ALTN_MAXNEST) {
                cli_errmsg("ac_addspecial: Expression exceeds maximum alternate nesting limit\n");
                MPOOL_FREE(root->mempool, newspecial);
                error = CL_EMALFDB;
                break;
            }

            /*
             * Detect special character classes
             * - (B) word boundary
             * - (L) CR, CRLF line boundaries
             * - (W) Non-alphanumeric character
             *
             * For more details: https://docs.clamav.net/manual/Signatures/BodySignatureFormat.html#character-classes
             */
            if (!strcmp(pt, "B")) {
                if (!*start) {
                    new->boundary |= AC_BOUNDARY_RIGHT;
                    if (newspecial->negative)
                        new->boundary |= AC_BOUNDARY_RIGHT_NEGATIVE;
                    MPOOL_FREE(root->mempool, newspecial);
                    continue;
                } else if (pt - 1 == hexcpy) {
                    new->boundary |= AC_BOUNDARY_LEFT;
                    if (newspecial->negative)
                        new->boundary |= AC_BOUNDARY_LEFT_NEGATIVE;
                    MPOOL_FREE(root->mempool, newspecial);
                    continue;
                }
            } else if (!strcmp(pt, "L")) {
                if (!*start) {
                    new->boundary |= AC_LINE_MARKER_RIGHT;
                    if (newspecial->negative)
                        new->boundary |= AC_LINE_MARKER_RIGHT_NEGATIVE;
                    MPOOL_FREE(root->mempool, newspecial);
                    continue;
                } else if (pt - 1 == hexcpy) {
                    new->boundary |= AC_LINE_MARKER_LEFT;
                    if (newspecial->negative)
                        new->boundary |= AC_LINE_MARKER_LEFT_NEGATIVE;
                    MPOOL_FREE(root->mempool, newspecial);
                    continue;
                }
            } else if (!strcmp(pt, "W")) {
                if (!*start) {
                    new->boundary |= AC_WORD_MARKER_RIGHT;
                    if (newspecial->negative)
                        new->boundary |= AC_WORD_MARKER_RIGHT_NEGATIVE;
                    MPOOL_FREE(root->mempool, newspecial);
                    continue;
                } else if (pt - 1 == hexcpy) {
                    new->boundary |= AC_WORD_MARKER_LEFT;
                    if (newspecial->negative)
                        new->boundary |= AC_WORD_MARKER_LEFT_NEGATIVE;
                    MPOOL_FREE(root->mempool, newspecial);
                    continue;
                }
            }
            cli_strlcat(hexnew, "()", hexnewsz);
            new->special++;
            newtable = (struct cli_ac_special **)MPOOL_REALLOC(root->mempool, new->special_table, new->special * sizeof(struct cli_ac_special *));
            if (!newtable) {
                new->special--;
                MPOOL_FREE(root->mempool, newspecial);
                cli_errmsg("cli_ac_addsig: Can't realloc new->special_table\n");
                error = CL_EMEM;
                break;
            }
            newtable[new->special - 1] = newspecial;
            new->special_table         = newtable;

            if (!strcmp(pt, "B")) {
                newspecial->type = AC_SPECIAL_BOUNDARY;
            } else if (!strcmp(pt, "L")) {
                newspecial->type = AC_SPECIAL_LINE_MARKER;
            } else if (!strcmp(pt, "W")) {
                newspecial->type = AC_SPECIAL_WORD_MARKER;
            } else {
                if ((ret = ac_special_altstr(pt, sigopts, newspecial, root)) != CL_SUCCESS) {
                    error = ret;
                    break;
                }
            }
        }

        if (start)
            cli_strlcat(hexnew, start, hexnewsz);

        hex = hexnew;
        free(hexcpy);

        if (error) {
            free(hex);
            if (new->special) {
                mpool_ac_free_special(root->mempool, new);
            }
            MPOOL_FREE(root->mempool, new);
            return error;
        }
    }

    /*
     * Convert the hex string pattern to a uint16_t* pattern (flags + byte) patterns.
     */
    new->pattern = CLI_MPOOL_HEX2UI(root->mempool, hex ? hex : hexsig);
    if (new->pattern == NULL) {
        if (new->special)
            mpool_ac_free_special(root->mempool, new);

        MPOOL_FREE(root->mempool, new);
        free(hex);
        return CL_EMALFDB;
    }

    new->length[0] = (uint16_t)strlen(hex ? hex : hexsig) / 2;
    if (new->length[0] < root->ac_mindepth) {
        cli_errmsg("cli_ac_addsig: Subpattern in signature is shorter than the minimum depth of the AC trie. (%u < %u)\n", new->length[0], root->ac_mindepth);
        if (new->special)
            mpool_ac_free_special(root->mempool, new);

        MPOOL_FREE(root->mempool, new->pattern);
        MPOOL_FREE(root->mempool, new);
        free(hex);
        return CL_EMALFDB;
    }

    for (i = 0, j = 0; i < new->length[0]; i++) {
        if ((new->pattern[i] & CLI_MATCH_METADATA) == CLI_MATCH_SPECIAL) {
            new->length[1] += new->special_table[j]->len[0];
            new->length[2] += new->special_table[j]->len[1];
            j++;
        } else {
            new->length[1]++;
            new->length[2]++;
        }
    }

    free(hex);

    new->sigopts = sigopts;
    /* setting nocase match */
    if (sigopts & ACPATT_OPTION_NOCASE) {
        for (i = 0; i < new->length[0]; i++)
            if ((new->pattern[i] & CLI_MATCH_METADATA) == CLI_MATCH_CHAR) {
                new->pattern[i] = CLI_NOCASE(new->pattern[i] & 0xff);
                new->pattern[i] += CLI_MATCH_NOCASE;
            }
    }

    /* TODO - sigopts affect on filters? */
    if (root->filter) {
        /* so that we can show meaningful messages */
        new->virname = (char *)virname;
        if (filter_add_acpatt(root->filter, new) == -1) {
            cli_warnmsg("cli_ac_addsig: cannot use filter for trie\n");
            MPOOL_FREE(root->mempool, root->filter);
            root->filter = NULL;
            return CL_EMALFDB;
        }

        /* TODO: should this affect maxpatlen? */
    }

    /*
     * Check beginning bytes of the pattern up to the max-depth of the AC trie to see if:
     *  a. it contains a wildcard, or
     *  b. the bytes are all zeroes.
     *
     * If it does, we can try to shift the start of the pattern the right, have those beginning
     * bytes be a "prefix" which gets backwards-matched after the AC match.
     * This happens in the call to ac_backward_match_branch() in ac_forward_match_branch()
     */
    for (i = 0; i < root->ac_maxdepth && i < new->length[0]; i++) {
        if (new->pattern[i] & CLI_MATCH_WILDCARD) {
            wprefix = 1;
            break;
        }

        if (zprefix && 0 != new->pattern[i]) {
            zprefix = 0;
        }
    }

    if (wprefix || zprefix) {
        /*
         * This pattern has a wildcard in the first few bytes or starts with some zeroes.
         * We'll try to shift the start of the pattern right a bit to find a static subpattern to use for the bytes that go in the A-C trie.
         */

        // If needed, we can shift the start of the pattern that goes in the A-C Trie right up to the pattern length minus min-depth bytes
        // The original starting bytes will become a "prefix" that gets backward-matched.
        pend = new->length[0] - root->ac_mindepth + 1;

        // Search for static bytes to start the pattern in the A-C trie that starts within original min-depth, and of a length up to max-depth.
        for (i = 0; i < pend; i++) {
            for (j = i; j < i + root->ac_maxdepth && j < new->length[0]; j++) {
                if (new->pattern[j] & CLI_MATCH_WILDCARD) {
                    // Found a wildcard. Shift the pattern start right a byte, relegating this byte to the "prefix"
                    break;
                }

                // This byte is a contender for the start of the pattern.
                // Record the start + length of the shifted prefix.
                if (j - i + 1 >= plen) {
                    plen = j - i + 1;
                    ppos = i;
                }

                // Check if the starting bytes at this offset are both non-zero.  If they are, then that's even better.
                if ((0 != new->pattern[ppos]) ||
                    ((new->length[0] > ppos + 1) && (0 != new->pattern[ppos + 1]))) {
                    // At least one of the first two bytes is non-zero which would be better than starting with two zeroes.

                    if (plen >= root->ac_maxdepth) {
                        // But... we hit max-depth, so nevermind. Let's stop searching.
                        break;
                    }

                    // Save off the position and length so we can roll back to it later, if needed.
                    if (plen >= root->ac_mindepth && plen > nzplen) {
                        // We've found a longer sequence of non-zero bytes we could use for the AC pattern starting position.
                        // Store off the length and position of this starting position with the non-zero bytes, in case we want to roll back to it.
                        nzplen = plen;
                        nzpos  = ppos;
                    }
                }
            }

            if (plen >= root->ac_maxdepth && (0 != new->pattern[ppos] || 0 != new->pattern[ppos + 1])) {
                break;
            }
        }

        if ((0 != nzplen) &&
            (new->length[0] > ppos + 1) &&
            (0 == new->pattern[ppos]) &&
            (0 == new->pattern[ppos + 1])) {
            // The latest shifted position starts with two zeroes.
            // We found a valid static pattern earlier that doesn't start with two zeroes.
            // Let's roll back a little bit to use that instead.
            plen = nzplen;
            ppos = nzpos;
        }

        if (plen < root->ac_mindepth) {
            cli_errmsg("cli_ac_addsig: Can't find a static subpattern of length %u\n", root->ac_mindepth);
            mpool_ac_free_special(root->mempool, new);
            MPOOL_FREE(root->mempool, new->pattern);
            MPOOL_FREE(root->mempool, new);
            return CL_EMALFDB;
        }

        // Store those initial bytes as the pattern "prefix" (the stuff before what goes in the AC Trie)
        new->prefix = new->pattern;
        // The "prefix" length is the number of bytes before the starting position of the pattern that goes in the AC Trie.
        new->prefix_length[0] = ppos;
        for (i = 0, j = 0; i < new->prefix_length[0]; i++) {
            if ((new->prefix[i] & CLI_MATCH_WILDCARD) == CLI_MATCH_SPECIAL)
                new->special_pattern++;

            if ((new->prefix[i] & CLI_MATCH_METADATA) == CLI_MATCH_SPECIAL) {
                new->prefix_length[1] += new->special_table[j]->len[0];
                new->prefix_length[2] += new->special_table[j]->len[1];
                j++;
            } else {
                new->prefix_length[1]++;
                new->prefix_length[2]++;
            }
        }

        // Update the pattern to start at the shifted position with the static bytes.
        new->pattern = &new->prefix[ppos];
        // And update the pattern length to remove the prefix bytes.
        new->length[0] -= new->prefix_length[0];
        new->length[1] -= new->prefix_length[1];
        new->length[2] -= new->prefix_length[2];
    }

    if (new->length[2] + new->prefix_length[2] > root->maxpatlen) {
        // This is the longest pattern we've stored. Update our max-pattern-length record
        root->maxpatlen = new->length[2] + new->prefix_length[2];
    }

    if (0 == new->lsigid[0]) {
        /* For logical signatures, we already recorded the virname in the lsig table entry.
         * For other signature types, continue to store a copy of the virname in each ac_pattern struct.
         *
         * TODO: Don't make a copy of the virname for every ac pattern,
         * because that makes for multipel copies every time a signature has wildcards.
         */
        virname_copy = CLI_MPOOL_VIRNAME(root->mempool, virname, options & CL_DB_OFFICIAL);
        if (NULL == virname_copy) {
            MPOOL_FREE(root->mempool, new->prefix ? new->prefix : new->pattern);
            mpool_ac_free_special(root->mempool, new);
            MPOOL_FREE(root->mempool, new);
            return CL_EMEM;
        }

        new->virname = virname_copy;
    }

    ret = cli_caloff(offset, NULL, root->type, new->offdata, &new->offset_min, &new->offset_max);
    if (ret != CL_SUCCESS) {
        MPOOL_FREE(root->mempool, new->prefix ? new->prefix : new->pattern);
        mpool_ac_free_special(root->mempool, new);
        if (virname_copy) {
            MPOOL_FREE(root->mempool, virname_copy);
        }
        MPOOL_FREE(root->mempool, new);
        return ret;
    }

    if ((ret = cli_ac_addpatt(root, new))) {
        MPOOL_FREE(root->mempool, new->prefix ? new->prefix : new->pattern);
        if (virname_copy) {
            MPOOL_FREE(root->mempool, virname_copy);
        }
        mpool_ac_free_special(root->mempool, new);
        MPOOL_FREE(root->mempool, new);
        return ret;
    }

    if ((new->offdata[0] != CLI_OFF_ANY) &&
        (new->offdata[0] != CLI_OFF_ABSOLUTE) &&
        (new->offdata[0] != CLI_OFF_MACRO)) {

        root->ac_reloff = (struct cli_ac_patt **)MPOOL_REALLOC2(root->mempool, root->ac_reloff, (root->ac_reloff_num + 1) * sizeof(struct cli_ac_patt *));
        if (!root->ac_reloff) {
            cli_errmsg("cli_ac_addsig: Can't allocate memory for root->ac_reloff\n");
            return CL_EMEM;
        }

        root->ac_reloff[root->ac_reloff_num] = new;
        new->offset_min                      = root->ac_reloff_num * 2;
        new->offset_max                      = new->offset_min + 1;
        root->ac_reloff_num++;
    }

    return CL_SUCCESS;
}

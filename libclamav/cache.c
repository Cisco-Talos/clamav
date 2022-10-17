/*
 *  Copyright (C) 2013-2022 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2010-2013 Sourcefire, Inc.
 *
 *  Authors: aCaB <acab@clamav.net>, Török Edvin <edwin@clamav.net>
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

#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <assert.h>

#include "mpool.h"
#include "clamav.h"
#include "cache.h"
#include "fmap.h"

#include "clamav_rust.h"

/* The number of root trees and the chooser function
   Each tree is protected by a mutex against concurrent access */
/* #define TREES 1 */
/* static inline unsigned int getkey(uint8_t *hash) { return 0; } */
#define TREES 256
static inline unsigned int getkey(uint8_t *hash)
{
    if (hash) {
        return *hash;
    }

    return 0;
}
/* #define TREES 4096 */
/* static inline unsigned int getkey(uint8_t *hash) { return hash[0] | ((unsigned int)(hash[1] & 0xf)<<8) ; } */
/* #define TREES 65536 */
/* static inline unsigned int getkey(uint8_t *hash) { return hash[0] | (((unsigned int)hash[1])<<8) ; } */

/* The number of nodes in each tree */
#define NODES 256

/* SPLAY --------------------------------------------------------------------- */
struct node { /* a node */
    int64_t digest[2];
    struct node *left;
    struct node *right;
    struct node *up;
    struct node *next;
    struct node *prev;
    uint32_t size;
    uint32_t minrec;
};

struct cache_set { /* a tree */
    struct node *data;
    struct node *root;
    struct node *first;
    struct node *last;
};

struct CACHE {
    struct cache_set cacheset;
#ifdef CL_THREAD_SAFE
    pthread_mutex_t mutex;
#endif
};

/* Allocates all the nodes and sets up the replacement chain */
static int cacheset_init(struct cache_set *cs, mpool_t *mempool)
{
    unsigned int i;

#ifndef USE_MPOOL
    UNUSEDPARAM(mempool);
#endif

    cs->data = MPOOL_CALLOC(mempool, NODES, sizeof(*cs->data));
    cs->root = NULL;

    if (!cs->data)
        return 1;

    for (i = 1; i < NODES; i++) {
        cs->data[i - 1].next = &cs->data[i];
        cs->data[i].prev     = &cs->data[i - 1];
    }

    cs->first = cs->data;
    cs->last  = &cs->data[NODES - 1];

    return 0;
}

/* Frees all the nodes */
static inline void cacheset_destroy(struct cache_set *cs, mpool_t *mempool)
{
#ifndef USE_MPOOL
    UNUSEDPARAM(mempool);
#endif

    MPOOL_FREE(mempool, cs->data);
    cs->data = NULL;
}

/* The left/right cooser for the splay tree */
static inline int cmp(int64_t *a, ssize_t sa, int64_t *b, ssize_t sb)
{
    if (a[1] < b[1]) return -1;
    if (a[1] > b[1]) return 1;
    if (a[0] < b[0]) return -1;
    if (a[0] > b[0]) return 1;
    if (sa < sb) return -1;
    if (sa > sb) return 1;
    return 0;
}

/* #define PRINT_TREE */
#ifdef PRINT_TREE
#define ptree printf
#else
#define ptree(...)
#endif

/* Debug function to print the tree and check its consistency */
/* #define CHECK_TREE */
#ifdef CHECK_TREE
static int printtree(struct cache_set *cs, struct node *n, int d)
{
    int i;
    int ab = 0;
    if ((n == NULL) || (cs == NULL) || (cs->data == NULL)) return 0;
    if (n == cs->root) {
        ptree("--------------------------\n");
    }
    ab |= printtree(cs, n->right, d + 1);
    if (n->right) {
        if (cmp(n->digest, n->size, n->right->digest, n->right->size) >= 0) {
            for (i = 0; i < d; i++) ptree("        ");
            ptree("^^^^ %lld >= %lld\n", n->digest[1], n->right->digest[1]);
            ab = 1;
        }
    }
    for (i = 0; i < d; i++) ptree("        ");
    ptree("%08x(%02u)\n", n->digest[1] >> 48, n - cs->data);
    if (n->left) {
        if (cmp(n->digest, n->size, n->left->digest, n->left->size) <= 0) {
            for (i = 0; i < d; i++) ptree("        ");
            ptree("vvvv %lld <= %lld\n", n->digest[1], n->left->digest[1]);
            ab = 1;
        }
    }
    if (d) {
        if (!n->up) {
            printf("no parent, [node %02u]!\n", n - cs->data);
            ab = 1;
        } else {
            if (n->up->left != n && n->up->right != n) {
                printf("broken parent [node %02u, parent node %02u]\n", n - cs->data, n->up - cs->data);
                ab = 1;
            }
        }
    } else {
        if (n->up) {
            printf("root with a parent, [node %02u]!\n", n - cs->data);
            ab = 1;
        }
    }
    ab |= printtree(cs, n->left, d + 1);
    return ab;
}
#else
#define printtree(a, b, c) (0)
#endif

/* For troubleshooting only; prints out one specific node */
/* #define PRINT_NODE */
#ifdef PRINT_NODE
static void printnode(const char *prefix, struct cache_set *cs, struct node *n)
{
    if (!prefix || !cs || !cs->data) {
        printf("bad args!\n");
        return;
    }
    if (!n) {
        printf("no node!\n");
        return;
    }
    printf("%s node [%02u]:", prefix, n - cs->data);
    printf(" size=%lu digest=%llx,%llx\n", (unsigned long)(n->size), n->digest[0], n->digest[1]);
    printf("\tleft=");
    if (n->left)
        printf("%02u ", n->left - cs->data);
    else
        printf("NULL ");
    printf("right=");
    if (n->right)
        printf("%02u ", n->right - cs->data);
    else
        printf("NULL ");
    printf("up=");
    if (n->up)
        printf("%02u ", n->up - cs->data);
    else
        printf("NULL ");

    printf("\tprev=");
    if (n->prev)
        printf("%02u ", n->prev - cs->data);
    else
        printf("NULL ");
    printf("next=");
    if (n->next)
        printf("%02u\n", n->next - cs->data);
    else
        printf("NULL\n");
}
#else
#define printnode(a, b, c)
#endif

/* #define PRINT_CHAINS */
#ifdef PRINT_CHAINS
/* For troubleshooting only, print the chain forwards and back */
static inline void printchain(const char *prefix, struct cache_set *cs)
{
    if (!cs || !cs->data) return;
    if (prefix) printf("%s: ", prefix);
    printf("chain by next: ");
    {
        unsigned int i = 0;
        struct node *x = cs->first;
        while (x) {
            printf("%02d,", x - cs->data);
            x = x->next;
            i++;
        }
        printf(" [count=%u]\nchain by prev: ", i);
        x = cs->last;
        i = 0;
        while (x) {
            printf("%02d,", x - cs->data);
            x = x->prev;
            i++;
        }
        printf(" [count=%u]\n", i);
    }
}
#else
#define printchain(a, b)
#endif

/* Looks up a node and splays it up to the root of the tree */
static int splay(int64_t *md5, size_t len, struct cache_set *cs)
{
    struct node next = {{0, 0}, NULL, NULL, NULL, NULL, NULL, 0, 0}, *right = &next, *left = &next, *temp, *root = cs->root;
    int comp, found = 0;

    if (!root)
        return 0;

    while (1) {
        comp = cmp(md5, len, root->digest, root->size);
        if (comp < 0) {
            if (!root->left) break;
            if (cmp(md5, len, root->left->digest, root->left->size) < 0) {
                temp       = root->left;
                root->left = temp->right;
                if (temp->right) temp->right->up = root;
                temp->right = root;
                root->up    = temp;
                root        = temp;
                if (!root->left) break;
            }
            right->left = root;
            root->up    = right;
            right       = root;
            root        = root->left;
        } else if (comp > 0) {
            if (!root->right) break;
            if (cmp(md5, len, root->right->digest, root->right->size) > 0) {
                temp        = root->right;
                root->right = temp->left;
                if (temp->left) temp->left->up = root;
                temp->left = root;
                root->up   = temp;
                root       = temp;
                if (!root->right) break;
            }
            left->right = root;
            root->up    = left;
            left        = root;
            root        = root->right;
        } else {
            found = 1;
            break;
        }
    }

    left->right = root->left;
    if (root->left) root->left->up = left;
    right->left = root->right;
    if (root->right) root->right->up = right;
    root->left = next.right;
    if (next.right) next.right->up = root;
    root->right = next.left;
    if (next.left) next.left->up = root;
    root->up = NULL;
    cs->root = root;
    return found;
}

/* Looks up an hash in the tree and maintains the replacement chain */
static inline int cacheset_lookup(struct cache_set *cs, unsigned char *md5, size_t size, uint32_t recursion_level)
{
    int64_t hash[2];

    memcpy(hash, md5, 16);
    if (splay(hash, size, cs)) {
        struct node *o = cs->root->prev, *p = cs->root, *q = cs->root->next;
#ifdef PRINT_CHAINS
        printf("promoting %02d\n", p - cs->data);
        printchain("before", cs);
#endif
        if (q) {
            if (o)
                o->next = q;
            else
                cs->first = q;
            q->prev        = o;
            cs->last->next = p;
            p->prev        = cs->last;
            p->next        = NULL;
            cs->last       = p;
        }
#ifdef PRINT_CHAINS
        printchain("after", cs);
#endif

        // The recursion_level check here to prevent a "clean" result from exceeding max recursion from
        // causing a false negative if the same file is scanned where the recursion depth is lower.
        // e.g. if max-rec set to 4 and "file5" is malicious, a scan of file1 should not cause a scan of file3 to be "clean"
        //      root
        //      ├── file1 -> file2 -> file3 -> file4 -> file5
        //      └── file3 -> file4 -> file5
        // See: https://bugzilla.clamav.net/show_bug.cgi?id=1856
        if (recursion_level >= p->minrec)
            return 1;
    }
    return 0;
}

/* If the hash is present nothing happens.
   Otherwise a new node is created for the hash picking one from the begin of the chain.
   Used nodes are moved to the end of the chain */
static inline const char *cacheset_add(struct cache_set *cs, unsigned char *md5, size_t size, uint32_t recursion_level)
{
    struct node *newnode;
    int64_t hash[2];

    memcpy(hash, md5, 16);
    if (splay(hash, size, cs)) {
        if (cs->root->minrec > recursion_level)
            cs->root->minrec = recursion_level;
        return NULL; /* Already there */
    }

    ptree("1:\n");
    if (printtree(cs, cs->root, 0)) {
        return "cacheset_add: inconsistent tree before choosing newnode, good luck";
    }

    newnode = cs->first;
    while (newnode) {
        if (!newnode->right && !newnode->left)
            break;
        if (newnode->next) {
            if (newnode == newnode->next) {
                return "cacheset_add: cache chain in a bad state";
            }
            newnode = newnode->next;
        } else {
            return "cacheset_add: end of chain reached";
        }
    }
    if (!newnode) {
        return "cacheset_add: tree has got no end nodes";
    }
    if (newnode->up) {
        if (newnode->up->left == newnode)
            newnode->up->left = NULL;
        else
            newnode->up->right = NULL;
    }
    if (newnode->prev)
        newnode->prev->next = newnode->next;
    if (newnode->next)
        newnode->next->prev = newnode->prev;
    if (cs->first == newnode)
        cs->first = newnode->next;

    newnode->prev  = cs->last;
    newnode->next  = NULL;
    cs->last->next = newnode;
    cs->last       = newnode;

    ptree("2:\n");
    if (printtree(cs, cs->root, 0)) {
        return "cacheset_add: inconsistent tree before adding newnode, good luck";
    }

    if (!cs->root) {
        newnode->left  = NULL;
        newnode->right = NULL;
    } else {
        if (cmp(hash, size, cs->root->digest, cs->root->size) < 0) {
            newnode->left  = cs->root->left;
            newnode->right = cs->root;
            cs->root->left = NULL;
        } else {
            newnode->right  = cs->root->right;
            newnode->left   = cs->root;
            cs->root->right = NULL;
        }
        if (newnode->left) newnode->left->up = newnode;
        if (newnode->right) newnode->right->up = newnode;
    }
    newnode->digest[0] = hash[0];
    newnode->digest[1] = hash[1];
    newnode->up        = NULL;
    newnode->size      = size;
    newnode->minrec    = recursion_level;
    cs->root           = newnode;

    ptree("3: %lld\n", hash[1]);
    if (printtree(cs, cs->root, 0)) {
        return "cacheset_add: inconsistent tree after adding newnode, good luck";
    }
    printnode("newnode", cs, newnode);
    return NULL;
}

/* If the hash is not present nothing happens other than splaying the tree.
   Otherwise the identified node is removed from the tree and then placed back at
   the front of the chain. */
static inline void cacheset_remove(struct cache_set *cs, unsigned char *md5, size_t size)
{
    struct node *targetnode;
    struct node *reattachnode;
    int64_t hash[2];

    memcpy(hash, md5, 16);
    if (splay(hash, size, cs) != 1) {
        cli_dbgmsg("cacheset_remove: node not found in tree\n");
        return; /* No op */
    }

    ptree("cacheset_remove: node found and splayed to root\n");
    targetnode = cs->root;
    printnode("targetnode", cs, targetnode);

    /* First fix the tree */
    if (targetnode->left == NULL) {
        /* At left edge so prune */
        cs->root = targetnode->right;
        if (cs->root)
            cs->root->up = NULL;
    } else {
        /* new root will come from leftside tree */
        cs->root     = targetnode->left;
        cs->root->up = NULL;
        /* splay tree, expecting not found, bringing rightmost member to root */
        splay(hash, size, cs);

        if (targetnode->right) {
            /* reattach right tree to clean right-side attach point */
            reattachnode = cs->root;
            while (reattachnode->right)
                reattachnode = reattachnode->right; /* shouldn't happen, but safer in case of dupe */
            reattachnode->right   = targetnode->right;
            targetnode->right->up = reattachnode;
        }
    }
    targetnode->size      = (size_t)0;
    targetnode->digest[0] = 0;
    targetnode->digest[1] = 0;
    targetnode->up        = NULL;
    targetnode->left      = NULL;
    targetnode->right     = NULL;

    /* Tree is fixed, so now fix chain around targetnode */
    if (targetnode->prev)
        targetnode->prev->next = targetnode->next;
    if (targetnode->next)
        targetnode->next->prev = targetnode->prev;
    if (cs->last == targetnode)
        cs->last = targetnode->prev;

    /* Put targetnode at front of chain, if not there already */
    if (cs->first != targetnode) {
        targetnode->next = cs->first;
        if (cs->first)
            cs->first->prev = targetnode;
        cs->first = targetnode;
    }
    targetnode->prev = NULL;

    printnode("root", cs, cs->root);
    printnode("first", cs, cs->first);
    printnode("last", cs, cs->last);

    printchain("remove (after)", cs);
}

/* Looks up an hash in the proper tree */
static int cache_lookup_hash(unsigned char *md5, size_t len, struct CACHE *cache, uint32_t recursion_level)
{
    unsigned int key = 0;
    int ret          = CL_VIRUS;
    struct CACHE *c;

    if (!md5) {
        cli_dbgmsg("cache_lookup: No hash available. Nothing to look up.\n");
        return ret;
    }

    key = getkey(md5);

    c = &cache[key];

#ifdef CL_THREAD_SAFE
    if (pthread_mutex_lock(&c->mutex)) {
        cli_errmsg("cache_lookup_hash: cache_lookup_hash: mutex lock fail\n");
        return ret;
    }
#endif

    ret = (cacheset_lookup(&c->cacheset, md5, len, recursion_level)) ? CL_CLEAN : CL_VIRUS;

#ifdef CL_THREAD_SAFE
    pthread_mutex_unlock(&c->mutex);
#endif

    return ret;
}

int clean_cache_init(struct cl_engine *engine)
{
    struct CACHE *cache;
    unsigned int i, j;

    if (!engine) {
        cli_errmsg("clean_cache_init: mpool malloc fail\n");
        return 1;
    }

    if (engine->engine_options & ENGINE_OPTIONS_DISABLE_CACHE) {
        cli_dbgmsg("clean_cache_init: Caching disabled.\n");
        return 0;
    }

    if (!(cache = MPOOL_MALLOC(engine->mempool, sizeof(struct CACHE) * TREES))) {
        cli_errmsg("clean_cache_init: mpool malloc fail\n");
        return 1;
    }

    for (i = 0; i < TREES; i++) {
#ifdef CL_THREAD_SAFE
        if (pthread_mutex_init(&cache[i].mutex, NULL)) {
            cli_errmsg("clean_cache_init: mutex init fail\n");
            for (j = 0; j < i; j++) cacheset_destroy(&cache[j].cacheset, engine->mempool);
            for (j = 0; j < i; j++) pthread_mutex_destroy(&cache[j].mutex);
            MPOOL_FREE(engine->mempool, cache);
            return 1;
        }
#endif
        if (cacheset_init(&cache[i].cacheset, engine->mempool)) {
            for (j = 0; j < i; j++) cacheset_destroy(&cache[j].cacheset, engine->mempool);
#ifdef CL_THREAD_SAFE
            for (j = 0; j <= i; j++) pthread_mutex_destroy(&cache[j].mutex);
#endif
            MPOOL_FREE(engine->mempool, cache);
            return 1;
        }
    }
    engine->cache = cache;
    return 0;
}

void clean_cache_destroy(struct cl_engine *engine)
{
    struct CACHE *cache;
    unsigned int i;

    if (!engine || !(cache = engine->cache))
        return;

    if (engine->engine_options & ENGINE_OPTIONS_DISABLE_CACHE) {
        return;
    }

    for (i = 0; i < TREES; i++) {
        cacheset_destroy(&cache[i].cacheset, engine->mempool);
#ifdef CL_THREAD_SAFE
        pthread_mutex_destroy(&cache[i].mutex);
#endif
    }
    MPOOL_FREE(engine->mempool, cache);
}

void clean_cache_add(unsigned char *md5, size_t size, cli_ctx *ctx)
{
    const char *errmsg = NULL;

    unsigned int key = 0;
    uint32_t level;
    struct CACHE *c;

    if (!ctx || !ctx->engine || !ctx->engine->cache)
        return;

    if (ctx->engine->engine_options & ENGINE_OPTIONS_DISABLE_CACHE) {
        cli_dbgmsg("clean_cache_add: Caching disabled. Not adding sample to cache.\n");
        return;
    }

    if (!md5) {
        cli_dbgmsg("clean_cache_add: No hash available. Nothing to add to cache.\n");
        return;
    }

    if (SCAN_COLLECT_METADATA) {
        // Don't cache when using the "collect metadata" feature.
        // We don't cache the JSON, so we can't reproduce it when the cache is positive.
        cli_dbgmsg("clean_cache_add: collect metadata feature enabled, skipping cache\n");
        return;
    }

    if (ctx->fmap && ctx->fmap->dont_cache_flag == true) {
        cli_dbgmsg("clean_cache_add: caching disabled for this layer, skipping cache\n");
        return;
    }

    if (0 < evidence_num_alerts(ctx->evidence)) {
        // TODO: The dont cache flag should take care of preventing caching of files with embedded files that alert.
        //       Consider removing this check to allow caching of other actually clean files found within archives.
        //       It would be a (very) minor optimization.
        cli_dbgmsg("clean_cache_add: alert found within same topfile, skipping cache\n");
        return;
    }

    level = (ctx->fmap && ctx->fmap->dont_cache_flag) ? ctx->recursion_level : 0;

    key = getkey(md5);
    c   = &ctx->engine->cache[key];

#ifdef CL_THREAD_SAFE
    if (pthread_mutex_lock(&c->mutex)) {
        cli_errmsg("cli_add: mutex lock fail\n");
        return;
    }
#endif

    errmsg = cacheset_add(&c->cacheset, md5, size, level);

#ifdef CL_THREAD_SAFE
    pthread_mutex_unlock(&c->mutex);
#endif
    if (errmsg != NULL) {
        cli_errmsg("%s\n", errmsg);
    }

    cli_dbgmsg("clean_cache_add: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x (level %u)\n", md5[0], md5[1], md5[2], md5[3], md5[4], md5[5], md5[6], md5[7], md5[8], md5[9], md5[10], md5[11], md5[12], md5[13], md5[14], md5[15], level);

    return;
}

void clean_cache_remove(unsigned char *md5, size_t size, const struct cl_engine *engine)
{
    unsigned int key = 0;
    struct CACHE *c;

    if (!engine || !engine->cache)
        return;

    if (engine->engine_options & ENGINE_OPTIONS_DISABLE_CACHE) {
        cli_dbgmsg("clean_cache_remove: Caching disabled.\n");
        return;
    }

    if (!md5) {
        cli_dbgmsg("clean_cache_remove: No hash available. Nothing to remove from cache.\n");
        return;
    }

    key = getkey(md5);

    c = &engine->cache[key];
#ifdef CL_THREAD_SAFE
    if (pthread_mutex_lock(&c->mutex)) {
        cli_errmsg("cli_add: mutex lock fail\n");
        return;
    }
#endif

    cacheset_remove(&c->cacheset, md5, size);

#ifdef CL_THREAD_SAFE
    pthread_mutex_unlock(&c->mutex);
#endif
    cli_dbgmsg("clean_cache_remove: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n", md5[0], md5[1], md5[2], md5[3], md5[4], md5[5], md5[6], md5[7], md5[8], md5[9], md5[10], md5[11], md5[12], md5[13], md5[14], md5[15]);
    return;
}

cl_error_t clean_cache_check(unsigned char *md5, size_t size, cli_ctx *ctx)
{
    int ret;

    if (!ctx || !ctx->engine || !ctx->engine->cache)
        return CL_VIRUS;

    if (SCAN_COLLECT_METADATA) {
        // Don't cache when using the "collect metadata" feature.
        // We don't cache the JSON, so we can't reproduce it when the cache is positive.
        cli_dbgmsg("clean_cache_check: collect metadata feature enabled, skipping cache\n");
        return CL_VIRUS;
    }

    if (ctx->engine->engine_options & ENGINE_OPTIONS_DISABLE_CACHE) {
        cli_dbgmsg("clean_cache_check: Caching disabled. Returning CL_VIRUS.\n");
        return CL_VIRUS;
    }

    ret = cache_lookup_hash(md5, size, ctx->engine->cache, ctx->recursion_level);
    cli_dbgmsg("clean_cache_check: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x is %s\n", md5[0], md5[1], md5[2], md5[3], md5[4], md5[5], md5[6], md5[7], md5[8], md5[9], md5[10], md5[11], md5[12], md5[13], md5[14], md5[15], (ret == CL_VIRUS) ? "negative" : "positive");
    return ret;
}

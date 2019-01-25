/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
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

#ifdef CL_THREAD_SAFE
static pthread_mutex_t pool_mutex = PTHREAD_MUTEX_INITIALIZER;
#else
#define pthread_mutex_lock(x) 0
#define pthread_mutex_unlock(x)
#define pthread_mutex_init(a, b) 0
#define pthread_mutex_destroy(a) do { } while(0)
#endif

/* The number of root trees and the chooser function 
   Each tree is protected by a mutex against concurrent access */
/* #define TREES 1 */
/* static inline unsigned int getkey(uint8_t *hash) { return 0; } */
#define TREES 256
static inline unsigned int getkey(uint8_t *hash) { return *hash; }
/* #define TREES 4096 */
/* static inline unsigned int getkey(uint8_t *hash) { return hash[0] | ((unsigned int)(hash[1] & 0xf)<<8) ; } */
/* #define TREES 65536 */
/* static inline unsigned int getkey(uint8_t *hash) { return hash[0] | (((unsigned int)hash[1])<<8) ; } */

/* The number of nodes in each tree */
#define NODES 256


/* The replacement policy algorithm to use */
/* #define USE_LRUHASHCACHE */
#define USE_SPLAY

/* LRUHASHCACHE --------------------------------------------------------------------- */
#ifdef USE_LRUHASHCACHE
struct cache_key {
    int64_t digest[2];
    uint32_t size; /* 0 is used to mark an empty hash slot! */
    struct cache_key *lru_next, *lru_prev;
};

struct cache_set {
    struct cache_key *data;
    size_t maxelements; /* considering load factor */
    size_t maxdeleted;
    size_t elements;
    size_t deleted;
    struct cache_key *lru_head, *lru_tail;
};

#define CACHE_KEY_DELETED ~0u
#define CACHE_KEY_EMPTY 0

static void cacheset_lru_remove(struct cache_set *map, size_t howmany)
{
    while (howmany--) {
	struct cache_key *old;
	assert(map->lru_head);
	/* Remove a key from the head of the list */
	old = map->lru_head;
	assert(!old->lru_prev);
	map->lru_head = old->lru_next;
	old->size = CACHE_KEY_DELETED;
	/* This slot is now deleted, it is not empty,
	 * because previously we could have inserted a key that has seen this
	 * slot as occupied, to find that key we need to ensure that all keys
	 * that were occupied when the key was inserted, are seen as occupied
	 * when searching too.
	 * Of course when inserting a new value, we treat deleted slots as
	 * empty.
	 * We only replace old values with new values, but there is no guarantee
	 * that the newly inserted value would hash to same place as the value
	 * we remove due to LRU! */
	if (old == map->lru_tail)
	    map->lru_tail = 0;
	map->elements--;
	map->deleted++;
    }
}

static inline int cacheset_lookup_internal(struct cache_set *map,
					   const char *md5,  size_t size,
					   uint32_t *insert_pos, int deletedok)
{
    const struct cache_key*data = map->data;
    uint32_t capmask = NODES - 1;
    const struct cache_key *k;
    uint32_t idx, tries = 0;
    uint64_t md5_0, md5_1;
    uint64_t md5a[2];

    memcpy(&md5a, md5, 16);
    md5_0 = md5a[0];
    md5_1 = md5a[1];
    idx = md5_1 & capmask;
    k = &data[idx];
    while (k->size != CACHE_KEY_EMPTY && tries <= capmask) {
	if (k->digest[0] == md5_0 &&
	    k->digest[1] == md5_1 &&
	    k->size == size) {
	    /* found key */
	    *insert_pos = idx;
	    return 1;
	}
	if (deletedok && k->size == CACHE_KEY_DELETED) {
           /* treat deleted slot as empty */
           *insert_pos = idx;
           return 0;
	}
	idx = (idx + tries++) & capmask;
	k = &data[idx];
    }
    /* found empty pos */
    *insert_pos = idx;
    return 0;
}

static inline void lru_remove(struct cache_set *map, struct cache_key *newkey)
{
    if (newkey->lru_next)
	newkey->lru_next->lru_prev = newkey->lru_prev;
    if (newkey->lru_prev)
	newkey->lru_prev->lru_next = newkey->lru_next;
    if (newkey == map->lru_head)
	map->lru_head = newkey->lru_next;
}

static inline void lru_addtail(struct cache_set *map, struct cache_key *newkey)
{
    if (!map->lru_head)
	map->lru_head = newkey;
    if (map->lru_tail)
	map->lru_tail->lru_next = newkey;
    newkey->lru_next = NULL;
    newkey->lru_prev = map->lru_tail;
    map->lru_tail = newkey;
}


static void cacheset_add(struct cache_set *map, unsigned char *md5, size_t size, mpool_t *mempool);
static int cacheset_init(struct cache_set *map, mpool_t *mempool);

static void cacheset_rehash(struct cache_set *map, mpool_t *mempool)
{
    unsigned i;
    int ret;
    struct cache_set tmp_set;
    struct cache_key *key;
    pthread_mutex_lock(&pool_mutex);
    ret = cacheset_init(&tmp_set, mempool);
    pthread_mutex_unlock(&pool_mutex);
    if (ret)
	return;

    key = map->lru_head;
    for (i=0;key && i < tmp_set.maxelements/2;i++) {
	cacheset_add(&tmp_set, (unsigned char*)&key->digest, key->size, mempool);
	key = key->lru_next;
    }
    pthread_mutex_lock(&pool_mutex);
    mpool_free(mempool, map->data);
    pthread_mutex_unlock(&pool_mutex);
    memcpy(map, &tmp_set, sizeof(tmp_set));
}

static void cacheset_add(struct cache_set *map, unsigned char *md5, size_t size, mpool_t *mempool)
{
    int ret;
    uint32_t pos;
    struct cache_key *newkey;

    if (map->elements >= map->maxelements) {
	cacheset_lru_remove(map, 1);
	if (map->deleted >= map->maxdeleted) {
	    cacheset_rehash(map, mempool);
	}
    }
    assert(map->elements < map->maxelements);

    ret = cacheset_lookup_internal(map, md5, size, &pos, 1);
    newkey = &map->data[pos];
    if (newkey->size == CACHE_KEY_DELETED)
	map->deleted--;
    if (ret) {
	/* was already added, remove from LRU list */
	lru_remove(map, newkey);
    }
    /* add new key to tail of LRU list */
    memcpy(&map->data[pos].digest, md5, sizeof(map->data[pos].digest));
    map->data[pos].size = size;
    lru_addtail(map, newkey);

    map->elements++;

    assert(pos < map->maxelements);
}

static void cacheset_remove(struct cache_set *map, unsigned char *md5, size_t size, mpool_t *mempool)
{
    int ret;
    uint32_t pos;
    struct cache_key *newkey;
    ret = cacheset_lookup_internal(map, md5, size, &pos, 1);
    newkey = &map->data[pos];
    if (!ret || (newkey->size == CACHE_KEY_DELETED)) {
        /* already deleted */
        return;
    }
    /* remove from list */
    lru_remove(map, newkey);
    newkey->size = CACHE_KEY_DELETED;
    map->deleted++;
    map->elements--;
    if (map->deleted >= map->maxdeleted) {
        cacheset_rehash(map, mempool);
    }
}

static int cacheset_lookup(struct cache_set *map, unsigned char *md5, size_t size)
{
    struct cache_key *newkey;
    int ret;
    uint32_t pos;

    ret = cacheset_lookup_internal(map, md5, size, &pos, 0);
    if (!ret)
	return 0;
    newkey = &map->data[pos];
    /* update LRU position: move to tail */
    lru_remove(map, newkey);
    lru_addtail(map, newkey);
    return 1;
}

static int cacheset_init(struct cache_set *map, mpool_t *mempool) {
    map->data = mpool_calloc(mempool, NODES, sizeof(*map->data));
    if (!map->data)
	return CL_EMEM;
    map->maxelements = 80 * NODES / 100;
    map->maxdeleted = NODES - map->maxelements - 1;
    map->elements = 0;
    map->lru_head = map->lru_tail = NULL;
    return 0;
}

static inline void cacheset_destroy(struct cache_set *cs, mpool_t *mempool) {
    mpool_free(mempool, cs->data);
    cs->data = NULL;
}

#endif /* USE_LRUHASHCACHE */

/* SPLAY --------------------------------------------------------------------- */
#ifdef USE_SPLAY

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

/* Allocates all the nodes and sets up the replacement chain */
static int cacheset_init(struct cache_set *cs, mpool_t *mempool) {
    unsigned int i;
    cs->data = mpool_calloc(mempool, NODES,  sizeof(*cs->data));
    cs->root = NULL;

    if(!cs->data)
	return 1;

    for(i=1; i<NODES; i++) {
	cs->data[i-1].next = &cs->data[i];
	cs->data[i].prev = &cs->data[i-1];
    }

    cs->first = cs->data;
    cs->last = &cs->data[NODES-1];

    return 0;
}

/* Frees all the nodes */
static inline void cacheset_destroy(struct cache_set *cs, mpool_t *mempool) {
    mpool_free(mempool, cs->data);
    cs->data = NULL;
}

/* The left/right cooser for the splay tree */
static inline int cmp(int64_t *a, ssize_t sa, int64_t *b, ssize_t sb) {
    if(a[1] < b[1]) return -1;
    if(a[1] > b[1]) return 1;
    if(a[0] < b[0]) return -1;
    if(a[0] > b[0]) return 1;
    if(sa < sb) return -1;
    if(sa > sb) return 1;
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
static int printtree(struct cache_set *cs, struct node *n, int d) {
    int i;
    int ab = 0;
    if ((n == NULL) || (cs == NULL) || (cs->data == NULL)) return 0;
    if(n == cs->root) { ptree("--------------------------\n"); }
    ab |= printtree(cs, n->right, d+1);
    if(n->right) {
	if(cmp(n->digest, n->size, n->right->digest, n->right->size) >= 0) {
	    for (i=0; i<d; i++) ptree("        ");
	    ptree("^^^^ %lld >= %lld\n", n->digest[1], n->right->digest[1]);
	    ab = 1;
	}
    }
    for (i=0; i<d; i++) ptree("        ");
    ptree("%08x(%02u)\n", n->digest[1]>>48, n - cs->data);
    if(n->left) {
	if(cmp(n->digest, n->size, n->left->digest, n->left->size) <= 0) {
	    for (i=0; i<d; i++) ptree("        ");
	    ptree("vvvv %lld <= %lld\n", n->digest[1], n->left->digest[1]);
	    ab = 1;
	}
    }
    if(d){
	if(!n->up) {
	    printf("no parent, [node %02u]!\n", n - cs->data);
	    ab = 1;
	} else {
	    if(n->up->left != n && n->up->right != n) {
		printf("broken parent [node %02u, parent node %02u]\n", n - cs->data, n->up - cs->data);
		ab = 1;
	    }
	}
    } else {
	if(n->up) {
	    printf("root with a parent, [node %02u]!\n", n - cs->data);
	    ab = 1;
	}
    }
    ab |= printtree(cs, n->left, d+1);
    return ab;
}
#else
#define printtree(a,b,c) (0)
#endif

/* For troubleshooting only; prints out one specific node */
/* #define PRINT_NODE */
#ifdef PRINT_NODE
static void printnode(const char *prefix, struct cache_set *cs, struct node *n) {
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
    if(n->left)
        printf("%02u ", n->left - cs->data);
    else
        printf("NULL ");
    printf("right=");
    if(n->right)
        printf("%02u ", n->right - cs->data);
    else
        printf("NULL ");
    printf("up=");
    if(n->up)
        printf("%02u ", n->up - cs->data);
    else
        printf("NULL ");

    printf("\tprev=");
    if(n->prev)
        printf("%02u ", n->prev - cs->data);
    else
        printf("NULL ");
    printf("next=");
    if(n->next)
        printf("%02u\n", n->next - cs->data);
    else
        printf("NULL\n");
}
#else
#define printnode(a,b,c) (0)
#endif

/* #define PRINT_CHAINS */
#ifdef PRINT_CHAINS
/* For troubleshooting only, print the chain forwards and back */
static inline void printchain(const char *prefix, struct cache_set *cs) {
    if (!cs || !cs->data) return;
    if (prefix) printf("%s: ", prefix);
    printf("chain by next: ");
    {
        unsigned int i = 0;
        struct node *x = cs->first;
        while(x) {
            printf("%02d,", x - cs->data);
            x=x->next;
            i++;
        }
        printf(" [count=%u]\nchain by prev: ", i);
        x=cs->last;
        i=0;
        while(x) {
            printf("%02d,", x - cs->data);
            x=x->prev;
            i++;
        }
        printf(" [count=%u]\n", i);
    }
}
#else
#define printchain(a,b) (0)
#endif

/* Looks up a node and splays it up to the root of the tree */
static int splay(int64_t *md5, size_t len, struct cache_set *cs) {
    struct node next = {{0, 0}, NULL, NULL, NULL, NULL, NULL, 0, 0}, *right = &next, *left = &next, *temp, *root = cs->root;
    int comp, found = 0;

    if(!root)
	return 0;

    while(1) {
	comp = cmp(md5, len, root->digest, root->size);
	if(comp < 0) {
	    if(!root->left) break;
	    if(cmp(md5, len, root->left->digest, root->left->size) < 0) {
		temp = root->left;
                root->left = temp->right;
		if(temp->right) temp->right->up = root;
                temp->right = root;
		root->up = temp;
                root = temp;
                if(!root->left) break;
	    }
            right->left = root;
	    root->up = right;
            right = root;
            root = root->left;
	} else if(comp > 0) {
	    if(!root->right) break;
	    if(cmp(md5, len, root->right->digest, root->right->size) > 0) {
		temp = root->right;
                root->right = temp->left;
		if(temp->left) temp->left->up = root;
                temp->left = root;
		root->up = temp;
                root = temp;
		if(!root->right) break;
	    }
	    left->right = root;
	    root->up = left;
            left = root;
            root = root->right;
	} else {
	    found = 1;
	    break;
	}
    }

    left->right = root->left;
    if(root->left) root->left->up = left;
    right->left = root->right;
    if(root->right) root->right->up = right;
    root->left = next.right;
    if(next.right) next.right->up = root;
    root->right = next.left;
    if(next.left) next.left->up = root;
    root->up = NULL;
    cs->root = root;
    return found;
}


/* Looks up an hash in the tree and maintains the replacement chain */
static inline int cacheset_lookup(struct cache_set *cs, unsigned char *md5, size_t size, uint32_t reclevel) {
    int64_t hash[2];

    memcpy(hash, md5, 16);
    if(splay(hash, size, cs)) {
	struct node *o = cs->root->prev, *p = cs->root, *q = cs->root->next;
#ifdef PRINT_CHAINS
	printf("promoting %02d\n", p - cs->data);
	printchain("before", cs);
#endif
    	if(q) {
	    if(o)
		o->next = q;
	    else
		cs->first = q;
	    q->prev = o;
	    cs->last->next = p;
	    p->prev = cs->last;
	    p->next = NULL;
	    cs->last = p;
	}
#ifdef PRINT_CHAINS
	printchain("after", cs);
#endif
	if(reclevel >= p->minrec)
	    return 1;
    }
    return 0;
}

/* If the hash is present nothing happens.
   Otherwise a new node is created for the hash picking one from the begin of the chain.
   Used nodes are moved to the end of the chain */
static inline void cacheset_add(struct cache_set *cs, unsigned char *md5, size_t size, uint32_t reclevel) {
    struct node *newnode;
    int64_t hash[2];

    memcpy(hash, md5, 16);
    if(splay(hash, size, cs)) {
	if(cs->root->minrec > reclevel)
	    cs->root->minrec = reclevel;
	return; /* Already there */
    }

    ptree("1:\n");
    if(printtree(cs, cs->root, 0)) {
	cli_errmsg("cacheset_add: inconsistent tree before choosing newnode, good luck\n");
	return;
    }

    newnode = cs->first;
    while(newnode) {
        if(!newnode->right && !newnode->left)
            break;
        if(newnode->next) {
            if(newnode == newnode->next) {
                cli_errmsg("cacheset_add: cache chain in a bad state\n");
                return;
            }
            newnode = newnode->next;
        }
        else {
	    cli_warnmsg("cacheset_add: end of chain reached\n");
	    return;
        }
    }
    if(!newnode) {
	cli_errmsg("cacheset_add: tree has got no end nodes\n");
	return;
    }
    if(newnode->up) {
    	if(newnode->up->left == newnode)
    	    newnode->up->left = NULL;
    	else
    	    newnode->up->right = NULL;
    }
    if(newnode->prev)
    	newnode->prev->next = newnode->next;
    if(newnode->next)
    	newnode->next->prev = newnode->prev;
    if(cs->first == newnode)
    	cs->first = newnode->next;

    newnode->prev = cs->last;
    newnode->next = NULL;
    cs->last->next = newnode;
    cs->last = newnode;

    ptree("2:\n");
    if(printtree(cs, cs->root, 0)) {
	cli_errmsg("cacheset_add: inconsistent tree before adding newnode, good luck\n");
	return;
    }

    if(!cs->root) {
	newnode->left = NULL;
	newnode->right = NULL;
    } else {
	if(cmp(hash, size, cs->root->digest, cs->root->size) < 0) {
	    newnode->left = cs->root->left;
	    newnode->right = cs->root;
	    cs->root->left = NULL;
	} else {
	    newnode->right = cs->root->right;
	    newnode->left = cs->root;
	    cs->root->right = NULL;
	}
	if(newnode->left) newnode->left->up = newnode;
	if(newnode->right) newnode->right->up = newnode;
    }
    newnode->digest[0] = hash[0];
    newnode->digest[1] = hash[1];
    newnode->up = NULL;
    newnode->size = size;
    newnode->minrec = reclevel;
    cs->root = newnode;

    ptree("3: %lld\n", hash[1]);
    if(printtree(cs, cs->root, 0)) {
	cli_errmsg("cacheset_add: inconsistent tree after adding newnode, good luck\n");
	return;
    }
    printnode("newnode", cs, newnode);
}

/* If the hash is not present nothing happens other than splaying the tree.
   Otherwise the identified node is removed from the tree and then placed back at 
   the front of the chain. */
static inline void cacheset_remove(struct cache_set *cs, unsigned char *md5, size_t size) {
    struct node *targetnode;
    struct node *reattachnode;
    int64_t hash[2];

    memcpy(hash, md5, 16);
    if(splay(hash, size, cs) != 1) {
	cli_dbgmsg("cacheset_remove: node not found in tree\n");
	return; /* No op */
    }

    ptree("cacheset_remove: node found and splayed to root\n");
    targetnode = cs->root;
    printnode("targetnode", cs, targetnode);

    /* First fix the tree */
    if(targetnode->left == NULL) {
        /* At left edge so prune */
        cs->root = targetnode->right;
        if(cs->root)
            cs->root->up = NULL;
    }
    else {
        /* new root will come from leftside tree */
        cs->root = targetnode->left;
        cs->root->up = NULL;
        /* splay tree, expecting not found, bringing rightmost member to root */
        splay(hash, size, cs);

        if (targetnode->right) {
            /* reattach right tree to clean right-side attach point */
            reattachnode = cs->root;
            while (reattachnode->right) 
                reattachnode = reattachnode->right; /* shouldn't happen, but safer in case of dupe */
            reattachnode->right = targetnode->right;
            targetnode->right->up = reattachnode;
        }
    }
    targetnode->size = (size_t)0;
    targetnode->digest[0] = 0;
    targetnode->digest[1] = 0;
    targetnode->up = NULL;
    targetnode->left = NULL;
    targetnode->right = NULL;

    /* Tree is fixed, so now fix chain around targetnode */
    if(targetnode->prev) 
        targetnode->prev->next = targetnode->next;
    if(targetnode->next) 
        targetnode->next->prev = targetnode->prev;
    if(cs->last == targetnode)
        cs->last = targetnode->prev;

    /* Put targetnode at front of chain, if not there already */
    if(cs->first != targetnode) {
        targetnode->next = cs->first;
        if(cs->first)
            cs->first->prev = targetnode;
        cs->first = targetnode;
    }
    targetnode->prev = NULL;

    printnode("root", cs, cs->root);
    printnode("first", cs, cs->first);
    printnode("last", cs, cs->last);

    printchain("remove (after)", cs);
}
#endif /* USE_SPLAY */


/* COMMON STUFF --------------------------------------------------------------------- */

struct CACHE {
    struct cache_set cacheset;
#ifdef CL_THREAD_SAFE
    pthread_mutex_t mutex;
#endif
};

/* Allocates the trees for the engine cache */
int cli_cache_init(struct cl_engine *engine) {
    struct CACHE *cache;
    unsigned int i, j;

    if(!engine) {
	cli_errmsg("cli_cache_init: mpool malloc fail\n");
	return 1;
    }

    if (engine->engine_options & ENGINE_OPTIONS_DISABLE_CACHE) {
        cli_dbgmsg("cli_cache_init: Caching disabled.\n");
        return 0;
    }

    if(!(cache = mpool_malloc(engine->mempool, sizeof(struct CACHE) * TREES))) {
	cli_errmsg("cli_cache_init: mpool malloc fail\n");
	return 1;
    }

    for(i=0; i<TREES; i++) {
	if(pthread_mutex_init(&cache[i].mutex, NULL)) {
	    cli_errmsg("cli_cache_init: mutex init fail\n");
	    for(j=0; j<i; j++) cacheset_destroy(&cache[j].cacheset, engine->mempool);
	    for(j=0; j<i; j++) pthread_mutex_destroy(&cache[j].mutex);
	    mpool_free(engine->mempool, cache);
	    return 1;
	}
	if(cacheset_init(&cache[i].cacheset, engine->mempool)) {
	    for(j=0; j<i; j++) cacheset_destroy(&cache[j].cacheset, engine->mempool);
	    for(j=0; j<=i; j++) pthread_mutex_destroy(&cache[j].mutex);
	    mpool_free(engine->mempool, cache);
	    return 1;
	}
    }
    engine->cache = cache;
    return 0;
}

/* Frees the engine cache */
void cli_cache_destroy(struct cl_engine *engine) {
    struct CACHE *cache;
    unsigned int i;

    if(!engine || !(cache = engine->cache))
	return;

    if (engine->engine_options & ENGINE_OPTIONS_DISABLE_CACHE) {
        return;
    }

    for(i=0; i<TREES; i++) {
	cacheset_destroy(&cache[i].cacheset, engine->mempool);
	pthread_mutex_destroy(&cache[i].mutex);
    }
    mpool_free(engine->mempool, cache);
}

/* Looks up an hash in the proper tree */
static int cache_lookup_hash(unsigned char *md5, size_t len, struct CACHE *cache, uint32_t reclevel) {
    unsigned int key = getkey(md5);
    int ret = CL_VIRUS;
    struct CACHE *c;

    c = &cache[key];
    if(pthread_mutex_lock(&c->mutex)) {
	cli_errmsg("cache_lookup_hash: cache_lookup_hash: mutex lock fail\n");
	return ret;
    }

    /* cli_warnmsg("cache_lookup_hash: key is %u\n", key); */

    ret = (cacheset_lookup(&c->cacheset, md5, len, reclevel)) ? CL_CLEAN : CL_VIRUS;
    pthread_mutex_unlock(&c->mutex);
    /* if(ret == CL_CLEAN) cli_warnmsg("cached\n"); */
    return ret;
}

/* Adds an hash to the cache */
void cache_add(unsigned char *md5, size_t size, cli_ctx *ctx) {
    unsigned int key = getkey(md5);
    uint32_t level;
    struct CACHE *c;

    if(!ctx || !ctx->engine || !ctx->engine->cache)
       return;

    if (ctx->engine->engine_options & ENGINE_OPTIONS_DISABLE_CACHE) {
        cli_dbgmsg("cache_add: Caching disabled. Not adding sample to cache.\n");
        return;
    }

    level =  (*ctx->fmap && (*ctx->fmap)->dont_cache_flag) ? ctx->recursion : 0;
    if (ctx->found_possibly_unwanted && (level || !ctx->recursion))
	return;
    if (SCAN_ALLMATCHES && (ctx->num_viruses > 0)) {
	cli_dbgmsg("cache_add: alert found within same topfile, skipping cache\n");
	return;
    }
    c = &ctx->engine->cache[key];
    if(pthread_mutex_lock(&c->mutex)) {
	cli_errmsg("cli_add: mutex lock fail\n");
	return;
    }

    /* cli_warnmsg("cache_add: key is %u\n", key); */

#ifdef USE_LRUHASHCACHE
    cacheset_add(&c->cacheset, md5, size, ctx->engine->mempool);
#else
#ifdef USE_SPLAY
    cacheset_add(&c->cacheset, md5, size, level);
#else
#error #define USE_SPLAY or USE_LRUHASHCACHE
#endif
#endif

    pthread_mutex_unlock(&c->mutex);
    cli_dbgmsg("cache_add: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x (level %u)\n", md5[0], md5[1], md5[2], md5[3], md5[4], md5[5], md5[6], md5[7], md5[8], md5[9], md5[10], md5[11], md5[12], md5[13], md5[14], md5[15], level);
    return;
}

/* Removes a hash from the cache */
void cache_remove(unsigned char *md5, size_t size, const struct cl_engine *engine) {
    unsigned int key = getkey(md5);
    struct CACHE *c;

    if(!engine || !engine->cache)
       return;

    if (engine->engine_options & ENGINE_OPTIONS_DISABLE_CACHE) {
        cli_dbgmsg("cache_remove: Caching disabled.\n");
        return;
    }

    /* cli_warnmsg("cache_remove: key is %u\n", key); */

    c = &engine->cache[key];
    if(pthread_mutex_lock(&c->mutex)) {
	cli_errmsg("cli_add: mutex lock fail\n");
	return;
    }

#ifdef USE_LRUHASHCACHE
    cacheset_remove(&c->cacheset, md5, size, engine->mempool);
#else
#ifdef USE_SPLAY
    cacheset_remove(&c->cacheset, md5, size);
#else
#error #define USE_SPLAY or USE_LRUHASHCACHE
#endif
#endif

    pthread_mutex_unlock(&c->mutex);
    cli_dbgmsg("cache_remove: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n", md5[0], md5[1], md5[2], md5[3], md5[4], md5[5], md5[6], md5[7], md5[8], md5[9], md5[10], md5[11], md5[12], md5[13], md5[14], md5[15]);
    return;
}

int cache_get_MD5(unsigned char *hash, cli_ctx *ctx)
{
    fmap_t *map;
    size_t todo, at = 0;
    void *hashctx;

    map = *ctx->fmap;
    todo = map->len;

    hashctx = cl_hash_init("md5");
    if (!(hashctx))
        return CL_VIRUS;

    while(todo) {
        const void *buf;
        size_t readme = todo < FILEBUFF ? todo : FILEBUFF;

        if(!(buf = fmap_need_off_once(map, at, readme))) {
            cl_hash_destroy(hashctx);
            return CL_EREAD;
        }

        todo -= readme;
        at += readme;

        if (cl_update_hash(hashctx, (void *)buf, readme)) {
            cl_hash_destroy(hashctx);
            cli_errmsg("cache_check: error reading while generating hash!\n");
            return CL_EREAD;
        }
    }

    cl_finish_hash(hashctx, hash);

    return CL_CLEAN;
}

/* Hashes a file onto the provided buffer and looks it up the cache.
   Returns CL_VIRUS if found, CL_CLEAN if not FIXME or a recoverable error,
   and returns CL_EREAD if unrecoverable */
int cache_check(unsigned char *hash, cli_ctx *ctx) {
    fmap_t *map;
    int ret;

    if(!ctx || !ctx->engine || !ctx->engine->cache)
       return CL_VIRUS;

    if (ctx->engine->engine_options & ENGINE_OPTIONS_DISABLE_CACHE) {
        cli_dbgmsg("cache_check: Caching disabled. Returning CL_VIRUS.\n");
        return CL_VIRUS;
    }

    ret = cache_get_MD5(hash, ctx);
    if (ret != CL_CLEAN)
        return ret;
        
    map = *ctx->fmap;
    ret = cache_lookup_hash(hash, map->len, ctx->engine->cache, ctx->recursion);
    cli_dbgmsg("cache_check: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x is %s\n", hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7], hash[8], hash[9], hash[10], hash[11], hash[12], hash[13], hash[14], hash[15], (ret == CL_VIRUS) ? "negative" : "positive");
    return ret;
}

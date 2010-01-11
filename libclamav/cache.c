/*
 *  Copyright (C) 2010 Sourcefire, Inc.
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

#include "md5.h"
#include "mpool.h"
#include "clamav.h"
#include "cache.h"
#include "fmap.h"

static mpool_t *mempool = NULL;

//#define DONT_CACHE
//#define USE_LRUHASHCACHE
#define USE_SPLAY

#ifdef USE_LRUHASHCACHE
struct cache_key {
    char digest[16];
    uint32_t size; /* 0 is used to mark an empty hash slot! */
    struct cache_key *lru_next, *lru_prev;
};

struct cache_set {
    struct cache_key *data;
    size_t capacity;
    size_t maxelements; /* considering load factor */
    size_t elements;
    size_t version;
    struct cache_key *lru_head, *lru_tail;
};

#define CACHE_INVALID_VERSION ~0u
#define CACHE_KEY_DELETED ~0u
#define CACHE_KEY_EMPTY 0

static void cache_setversion(struct cache_set* map, uint32_t version)
{
    unsigned i;
    if (map->version == version)
	return;
    map->version = version;
    map->elements = 0; /* all elements have expired now */
    for (i=0;i<map->capacity;i++)
	map->data[i].size = 0;
    map->lru_head = map->lru_tail = NULL;
}

static void cacheset_lru_remove(struct cache_set *map, size_t howmany)
{
    while (howmany--) {
	struct cache_key *old;
	assert(map->lru_head);
	assert(!old->lru_prev);
	// Remove a key from the head of the list
	old = map->lru_head;
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
    }
}

int cacheset_lookup_internal(struct cache_set *map, unsigned char *md5, size_t size, uint32_t *insert_pos, int deletedok)
{
    uint32_t idx = cli_readint32(md5+8) & (map->capacity -1);
    uint32_t tries = 0;
    struct cache_key *k = &map->data[idx];
    while (k->size != CACHE_KEY_EMPTY && tries < map->capacity) {
	if (k->size == size &&
	    !memcmp(k->digest, md5, 16)) {
	    /* found key */
	    *insert_pos = idx;
	    return 1;
	}
       if (deletedok && k->size == CACHE_KEY_DELETED) {
           /* treat deleted slot as empty */
           *insert_pos = idx;
           return 0;
       }
	idx = (idx + tries++)&(map->capacity-1);
	k = &map->data[idx];
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

static void cacheset_add(struct cache_set *map, unsigned char *md5, size_t size)
{
    int ret;
    uint32_t pos;
    struct cache_key *newkey;
    if (map->elements >= map->maxelements)
	cacheset_lru_remove(map, 1);
    assert(map->elements < map->maxelements);

    ret = cacheset_lookup_internal(map, md5, size, &pos, 1);
    newkey = &map->data[pos];
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

static int cacheset_lookup(struct cache_set *map, unsigned char *md5, size_t size)
{
    struct cache_key *newkey;
    int ret;
    uint32_t pos;
    ret = cacheset_lookup_internal(map, md5, size, &pos, 0);
    if (!ret)
	return CACHE_INVALID_VERSION;
    newkey = &map->data[pos];
    /* update LRU position: move to tail */
    lru_remove(map, newkey);
    lru_addtail(map, newkey);

    return map->version;
}


static int cacheset_init(struct cache_set *map, unsigned int entries) {
    map->data = mpool_calloc(mempool, 256, sizeof(*map->data));
    if (!map->data)
	return CL_EMEM;
    map->capacity = entries;
    map->maxelements = 80*entries / 100;
    map->elements = 0;
    map->version = CACHE_INVALID_VERSION;
    map->lru_head = map->lru_tail = NULL;
    map->version = 1337;
    return 0;
}
#endif /* USE_LRUHASHCACHE */

#ifdef USE_SPLAY
struct node {
    int64_t digest[2];
    struct node *left;
    struct node *right;
    struct node *up;
    uint32_t size;
};

struct cache_set {
    struct node *data;
    struct node *root;
    unsigned int used;
    unsigned int total;
};

static int cacheset_init(struct cache_set *map, unsigned int entries) {
    map->data = mpool_calloc(mempool, entries, sizeof(*map->data));
    map->root = NULL;

    if(!map->data)
	return CL_EMEM;
    map->used = 0;
    map->total = entries;
    return 0;
}

static inline int cmp(int64_t *a, int64_t *b) {
    int64_t ret = a[1] - b[1];
    if(!ret) ret = a[0] - b[0];
    return ret;
}

#ifdef CHECK_TREE
static int check_tree_rec(struct cache_set *cs, unsigned int *beenthere, struct node *node, struct node *parent) {
    unsigned int item = node - cs->data;
    if(!node) return 0;
    if(beenthere[item]) return 1;
    beenthere[item] = 1;
    if(node->up != parent) return 1;
    return check_tree_rec(cs, beenthere, node->left, node) | check_tree_rec(cs, beenthere, node->right, node);
}

static void check_tree(struct cache_set *cs) {
    unsigned int i, been_there[1024];
    memset(been_there, 0, sizeof(been_there));
    if(check_tree_rec(cs, been_there, cs->root, NULL)) {
	cli_errmsg("tree fukkd up\n");
	abort();
    }
    for(i=0; i<cs->used; i++) {
	if(!been_there[i]) {
	    cli_errmsg("tree fukkd up\n");
	    abort();
	}
    }
}
#else
#define check_tree(a)
#endif

static int splay(int64_t *md5, struct cache_set *cs) {
    struct node next = {{0, 0}, NULL, NULL, NULL, 0}, *right = &next, *left = &next, *temp, *root = cs->root;
    int ret = 0;

    if(!root)
	return 0;

    check_tree(cs);

    while(1) {
	int comp = cmp(md5, root->digest);
	if(comp < 0) {
	    if(!root->left) break;
	    if(cmp(md5, root->left->digest) < 0) {
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
	    if(cmp(md5, root->right->digest) > 0) {
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
	    ret = 1;
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

    check_tree(cs);
    return ret;
}


static int cacheset_lookup(struct cache_set *cs, unsigned char *md5, size_t size) {
    int64_t hash[2];

    memcpy(hash, md5, 16);
    return splay(hash, cs) * 1337;
}

static void cacheset_add(struct cache_set *cs, unsigned char *md5, size_t size) {
    struct node *newnode;
    int64_t hash[2];

    memcpy(hash, md5, 16);
    if(splay(hash, cs))
	    return; /* Already there */

    if(cs->used == cs->total) {
	struct node *parent;
	int nodeno, bestnode, parents = 0;
	for(nodeno = 0; nodeno < cs->total; nodeno++) {
	    parent = &cs->data[nodeno];
	    if(!parent->left && !parent->right) {
		int p=0;
		do{ p++; } while(parent = parent->up);
		if(p>=parents) {
		    parents = p;
		    bestnode = nodeno;
		}
	    }
	}
	newnode=&cs->data[bestnode];
	parent = newnode->up;
	if(parent->left == newnode)
	    parent->left = NULL;
	else
	    parent->right = NULL;
    } else
	newnode = &cs->data[cs->used++];

    if(!cs->root) {
	newnode->left = NULL;
	newnode->right = NULL;
    } else {
	if(cmp(hash, cs->root->digest)) {
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
    cs->root = newnode;
}
#endif /* USE_SPLAY */

#define TREES 256
static inline unsigned int getkey(uint8_t *hash) { return *hash; }

/* #define TREES 4096 */
/* static inline unsigned int getkey(uint8_t *hash) { return hash[0] | ((unsigned int)(hash[1] & 0xf)<<8) ; } */

/* #define TREES 65536 */
/* static inline unsigned int getkey(uint8_t *hash) { return hash[0] | (((unsigned int)hash[1])<<8) ; } */

static struct CACHE {
    struct cache_set cacheset;
    pthread_mutex_t mutex;
    uint32_t lastdb;
} *cache = NULL;


int cl_cache_init(unsigned int entries) {
    unsigned int i;
    int ret;

#ifndef DONT_CACHE
    if(!entries)
#endif
	return 0;

    if(!(mempool = mpool_create())) {
	cli_errmsg("mpool init fail\n");
	return 1;
    }
    if(!(cache = mpool_malloc(mempool, sizeof(struct CACHE) * TREES))) {
	cli_errmsg("mpool malloc fail\n");
	mpool_destroy(mempool);
	mempool = NULL;
	return 1;
    }

    for(i=0; i<TREES; i++) {
	if(pthread_mutex_init(&cache[i].mutex, NULL)) {
	    cli_errmsg("mutex init fail\n");
	    mpool_destroy(mempool);
	    mempool = NULL;
	    cache = NULL;
	    return 1;
	}
	ret = cacheset_init(&cache[i].cacheset, entries);
	if(ret) {
	    mpool_destroy(mempool);
	    mempool = NULL;
	    cache = NULL;
	    return 1;
	}
    }
    return 0;
}


static int cache_lookup_hash(unsigned char *md5, cli_ctx *ctx) {
    int ret = CL_VIRUS;
    unsigned int key = getkey(md5);
    struct CACHE *c;

    if(!cache) return ret;

    c = &cache[key];
    if(pthread_mutex_lock(&c->mutex)) {
	cli_errmsg("mutex lock fail\n");
	return ret;
    }

    ret = (cacheset_lookup(&c->cacheset, md5, 1024) == 1337) ? CL_CLEAN : CL_VIRUS;
    if(ret == CL_CLEAN) cli_warnmsg("cached\n");
    pthread_mutex_unlock(&c->mutex);
    return ret;
}

void cache_add(unsigned char *md5, cli_ctx *ctx) {
    unsigned int key = getkey(md5);
    struct CACHE *c;

    if(!cache) return;

    c = &cache[key];
    if(pthread_mutex_lock(&c->mutex)) {
	cli_errmsg("mutex lock fail\n");
	return;
    }

    cacheset_add(&c->cacheset, md5, 1024);

    pthread_mutex_unlock(&c->mutex);
    return;
}

int cache_check(unsigned char *hash, cli_ctx *ctx) {
    fmap_t *map = *ctx->fmap;
    size_t todo = map->len, at = 0;
    cli_md5_ctx md5;

    if(!cache) return CL_VIRUS;

    cli_md5_init(&md5);
    while(todo) {
	void *buf;
	size_t readme = todo < FILEBUFF ? todo : FILEBUFF;
	if(!(buf = fmap_need_off_once(map, at, readme)))
	    return CL_VIRUS;
	todo -= readme;
	at += readme;
	cli_md5_update(&md5, buf, readme);
    }
    cli_md5_final(hash, &md5);
    return cache_lookup_hash(hash, ctx);
}

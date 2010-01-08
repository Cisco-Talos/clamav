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
    }
}

static inline uint32_t hash32shift(uint32_t key)
{
  key = ~key + (key << 15);
  key = key ^ (key >> 12);
  key = key + (key << 2);
  key = key ^ (key >> 4);
  key = (key + (key << 3)) + (key << 11);
  key = key ^ (key >> 16);
  return key;
}

static inline size_t hash(const unsigned char* k,const size_t len,const size_t SIZE)
{
    size_t Hash = 1;
    size_t i;
    for(i=0;i<len;i++) {
	/* a simple add is good, because we use the mixing function below */
	Hash +=  k[i];
	/* mixing function */
	Hash = hash32shift(Hash);
    }
    /* SIZE is power of 2 */
    return Hash & (SIZE - 1);
}

int cacheset_lookup_internal(struct cache_set *map, const struct cache_key *key,
			     uint32_t *insert_pos, int deletedok)
{
    uint32_t idx = hash((const unsigned char*)key, sizeof(*key), map->capacity);
    uint32_t tries = 0;
    struct cache_key *k = &map->data[idx];
    while (k->size != CACHE_KEY_EMPTY) {
	if (k->size == key->size &&
	    !memcmp(k->digest, key, 16)) {
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

static void cacheset_add(struct cache_set *map, const struct cache_key *key)
{
    int ret;
    uint32_t pos;
    struct cache_key *newkey;
    if (map->elements >= map->maxelements)
	cacheset_lru_remove(map, 1);
    assert(map->elements < map->maxelements);

    ret = cacheset_lookup_internal(map, key, &pos, 1);
    newkey = &map->data[pos];
    if (ret) {
	/* was already added, remove from LRU list */
	lru_remove(map, newkey);
    }
    /* add new key to tail of LRU list */
    memcpy(&map->data[pos], key, sizeof(*key));
    lru_addtail(map, newkey);

    map->elements++;

    assert(pos < map->maxelements);

}

static int cacheset_lookup(struct cache_set *map, const struct cache_key *key)
{
    struct cache_key *newkey;
    int ret;
    uint32_t pos;
    ret = cacheset_lookup_internal(map, key, &pos, 0);
    if (!ret)
	return CACHE_INVALID_VERSION;
    newkey = &map->data[pos];
    /* update LRU position: move to tail */
    lru_remove(map, newkey);
    lru_addtail(map, newkey);

    return map->version;
}

static mpool_t *mempool = NULL;
static struct CACHE {
    struct cache_set cacheset;
    pthread_mutex_t mutex;
    uint32_t lastdb;
} *cache = NULL;
static unsigned int cache_entries = 0;

#define TREES 256
static inline unsigned int getkey(uint8_t *hash) { return *hash; }

/* #define TREES 4096 */
/* static inline unsigned int getkey(uint8_t *hash) { return hash[0] | ((unsigned int)(hash[1] & 0xf)<<8) ; } */

/* #define TREES 65536 */
/* static inline unsigned int getkey(uint8_t *hash) { return hash[0] | (((unsigned int)hash[1])<<8) ; } */


int cl_cache_init(unsigned int entries) {
    unsigned int i;

    entries = MAX(entries / (TREES / 256), 10);
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

	cache[i].cacheset.data = mpool_calloc(mempool, 256, sizeof(*cache[i].cacheset.data));
	if (!cache[i].cacheset.data)
	    return CL_EMEM;
	cache_setversion(&cache[i].cacheset, 1337);
	cache[i].cacheset.capacity = 256;
	cache[i].cacheset.maxelements = 80*256 / 100;
	cache[i].cacheset.elements = 0;
	cache[i].cacheset.version = CACHE_INVALID_VERSION;
	cache[i].cacheset.lru_head = cache[i].cacheset.lru_tail = NULL;
    }
    cache_entries = entries;
    return 0;
}

static int cache_lookup_hash(unsigned char *md5, cli_ctx *ctx) {
    struct cache_key entry;
    int ret = CL_VIRUS;
    unsigned int key = getkey(md5);
    struct CACHE *c;

    if(!cache) return ret;

    c = &cache[key];
    if(pthread_mutex_lock(&c->mutex)) {
	cli_errmsg("mutex lock fail\n");
	return ret;
    }
    entry.size = 1024;
    memcpy(entry.digest, md5, 16);
    ret = (cacheset_lookup(&c->cacheset, &entry) == 1337) ? CL_CLEAN : CL_VIRUS;
    pthread_mutex_unlock(&c->mutex);
    if(ret == CL_CLEAN) cli_warnmsg("cached\n");
    return ret;
}

void cache_add(unsigned char *md5, cli_ctx *ctx) {
    struct cache_key entry;
    unsigned int key = getkey(md5);
    struct CACHE *c;

    if(!cache) return;

    c = &cache[key];
    if(pthread_mutex_lock(&c->mutex)) {
	cli_errmsg("mutex lock fail\n");
	return;
    }
    entry.size = 1024;
    memcpy(entry.digest, md5, 16);
    cacheset_add(&c->cacheset, &entry);
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

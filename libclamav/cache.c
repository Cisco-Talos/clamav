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

#define CACHE_PERTURB 10
/* 1/10th */
static mpool_t *mempool = NULL;
static struct CACHE {
    struct CACHE_ENTRY {
	unsigned char hash[15];
	uint32_t dbver;
	uint32_t hits;
    } *items;
    pthread_mutex_t mutex;
    uint32_t lastdb;
} *cache = NULL;
static unsigned int cache_entries = 0;

int cl_cache_init(unsigned int entries) {
    unsigned int i;

    if(!(mempool = mpool_create())) {
	cli_errmsg("mpool init fail\n");
	return 1;
    }
    if(!(cache = mpool_malloc(mempool, sizeof(struct CACHE) * 256))) {
	cli_errmsg("mpool malloc fail\n");
	mpool_destroy(mempool);
	return 1;
    }

    for(i=0; i<256; i++) {
	struct CACHE_ENTRY *e = mpool_calloc(mempool, sizeof(struct CACHE_ENTRY), entries);
	if(!e) {
	    cli_errmsg("mpool calloc fail\n");
	    mpool_destroy(mempool);
	    return 1;
	}
	cache[i].items = e;
	cache[i].lastdb = 0;
	if(pthread_mutex_init(&cache[i].mutex, NULL)) {
	    cli_errmsg("mutex init fail\n");
	    mpool_destroy(mempool);
	    return 1;
	}
    }
    cache_entries = entries;
    return 0;
}

void cache_swap(struct CACHE_ENTRY *e, unsigned int a) {
    struct CACHE_ENTRY t;
    unsigned int b = a-1;

    if(!a || e[a].hits <= e[b].hits)
	return;

    do {
	if(e[a].hits > e[b].hits)
	    continue;
	break;
    } while(b--);
    b++;

    memcpy(&t, &e[a], sizeof(t));
    memcpy(&e[a], &e[b], sizeof(t));
    memcpy(&e[b], &t, sizeof(t));
}

static void updb(uint32_t db, unsigned int skip) {
    unsigned int i;
    for(i=0; i<256; i++) {
	if(i==skip) continue;
	if(pthread_mutex_lock(&cache[i].mutex)) {
	    cli_errmsg("mutex lock fail\n");
	    continue;
	}
	cache[i].lastdb = db;
	pthread_mutex_unlock(&cache[i].mutex);	
    }
}

static int cache_lookup_hash(unsigned char *md5, cli_ctx *ctx) {
    unsigned int i;
    int ret = CL_VIRUS;
    struct CACHE_ENTRY *e;
    struct CACHE *c;

    if(!cache) return ret;

    c = &cache[*md5];
    e = c->items;
    if(pthread_mutex_lock(&c->mutex)) {
	cli_errmsg("mutex lock fail\n");
	return ret;
    }
    if(c->lastdb <= ctx->engine->dbversion[0]) {
	if(c->lastdb < ctx->engine->dbversion[0]) {
	    c->lastdb = ctx->engine->dbversion[0];
	    updb(c->lastdb, *md5);
	} else {
	    for(i=0; i<cache_entries; i++) {
		if(!e[i].hits) break;
		if(e[i].dbver == c->lastdb && !memcmp(e[i].hash, md5 + 1, 15)) {
		    e[i].hits++;
		    cache_swap(e, i);
		    ret = CL_CLEAN;
		    cli_warnmsg("cached\n");
		    break;
		}
	    }
	}
    }
    pthread_mutex_unlock(&c->mutex);
    return ret;
}

void cache_add(unsigned char *md5, cli_ctx *ctx) {
    unsigned int i, replace;
    struct CACHE_ENTRY *e;
    struct CACHE *c;

    if(!cache) return;

    c = &cache[*md5];
    e = c->items;
    if(pthread_mutex_lock(&c->mutex)) {
	cli_errmsg("mutex lock fail\n");
	return;
    }
    if(c->lastdb == ctx->engine->dbversion[0]) {
	replace = cache_entries;
	for(i=0; i<cache_entries; i++) {
	    if(!e[i].hits) break;
	    if(replace == cache_entries && e[i].dbver < c->lastdb) {
		replace = i;
	    } else if(e[i].hits && !memcmp(e[i].hash, md5 + 1, 15)) {
		e[i].hits++;
		cache_swap(e, i);
		pthread_mutex_unlock(&c->mutex);
		return;
	    }
	}
	if(replace == cache_entries)
	    replace = cache_entries - 1 - (rand() % (cache_entries / CACHE_PERTURB));
	e[replace].hits = 1;
	e[replace].dbver = c->lastdb;
	memcpy(e[replace].hash, md5 + 1, 15);
	cache_swap(e, replace);
    }
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
#if 0
#define cli_calloc calloc
#define cli_errmsg(x)
#endif

struct cache_key {
    char digest[16];
    uint32_t size; /* 0 is used to mark an empty hash slot! */
    struct cache_key *lru_next, *lru_prev;
};

struct cache_set {
    struct cache_key *data;
    size_t capacity;
    size_t maxelements;/* considering load factor */
    size_t elements;
    size_t version;
    struct cache_key *lru_head, *lru_tail;
    pthread_mutex_t mutex;
};

#define CACHE_INVALID_VERSION ~0u
#define CACHE_KEY_DELETED ~0u
#define CACHE_KEY_EMPTY 0

/* size must be power of 2! */
static int cacheset_init(struct cache_set* map, size_t maxsize, uint8_t loadfactor)
{
    map->data = cli_calloc(maxsize, sizeof(*map->data));
    if (!map->data)
	return CL_EMEM;
    map->capacity = maxsize;
    map->maxelements = loadfactor*maxsize / 100;
    map->elements = 0;
    map->version = CACHE_INVALID_VERSION;
    map->lru_head = map->lru_tail = NULL;
    if (pthread_mutex_init(&map->mutex, NULL)) {
	cli_errmsg("mutex init fail\n");
	return CL_EMEM;
    }
}

static void cacheset_destroy(struct cache_set *map)
{
    pthread_mutex_destroy(&map->mutex);
    free(map->data);
}

static void cacheset_acquire(struct cache_set *map)
{
    pthread_mutex_lock(&map->mutex);
}

static void cache_setversion(struct cache_set* map, uint32_t version)
{
    unsigned i;
    if (map->version == version)
	return;
    map->version = version;
    map->elements = 0;/* all elements have expired now */
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
    lru_addtail(map, newkey);

    map->elements++;

    assert(pos < map->maxelements);

    memcpy(&map->data[pos], key, sizeof(*key));
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

static void cacheset_release(struct cache_set *map)
{
    pthread_mutex_unlock(&map->mutex);
}

#if 0
int main(int argc, char **argv)
{
    struct cache_key key;
    struct cache_set map;
    cacheset_init(&map, 256, 80);
    cacheset_acquire(&map);
    cache_setversion(&map, 10);

    key.size = 1024;
    memcpy(key.digest, "1234567890123456", 16);
    cacheset_add(&map, &key);
    memcpy(key.digest, "1234567890123457", 16);
    cacheset_add(&map, &key);
    memcpy(key.digest, "0123456789012345", 16);
    cacheset_add(&map, &key);

    key.size = 1024;
    memcpy(key.digest, "1234567890123456", 16);
    if (cacheset_lookup(&map, &key) != 10)
	abort();
    memcpy(key.digest, "1234567890123456", 16);
    if (cacheset_lookup(&map, &key) != 10)
	abort();
    memcpy(key.digest, "1234567890123457", 16);
    if (cacheset_lookup(&map, &key) != 10)
	abort();
    memcpy(key.digest, "0123456789012345", 16);
    if (cacheset_lookup(&map, &key) != 10)
	abort();
    memcpy(key.digest, "0123456789012346", 16);
    if (cacheset_lookup(&map, &key) == 10)
	abort();

    cache_setversion(&map, 1);
    memcpy(key.digest, "1234567890123456", 16);
    if (cacheset_lookup(&map, &key) != CACHE_INVALID_VERSION)
	abort();
    memcpy(key.digest, "1234567890123456", 16);
    if (cacheset_lookup(&map, &key) != CACHE_INVALID_VERSION)
	abort();
    memcpy(key.digest, "1234567890123457", 16);
    if (cacheset_lookup(&map, &key) != CACHE_INVALID_VERSION)
	abort();
    memcpy(key.digest, "0123456789012345", 16);
    if (cacheset_lookup(&map, &key) != CACHE_INVALID_VERSION)
	abort();

    cacheset_release(&map);

    cacheset_destroy(&map);

    cacheset_init(&map, 8, 50);
    cacheset_acquire(&map);
    cache_setversion(&map, 10);

    key.size = 416;
    memcpy(key.digest, "1234567890123456", 16);
    cacheset_add(&map, &key);
    memcpy(key.digest, "1234567890123457", 16);
    cacheset_add(&map, &key);
    memcpy(key.digest, "1234567890123459", 16);
    cacheset_add(&map, &key);
    key.size = 400;
    memcpy(key.digest, "1234567890123450", 16);
    cacheset_add(&map, &key);

    key.size = 416;
    memcpy(key.digest, "1234567890123456", 16);
    if (cacheset_lookup(&map, &key) != 10)
	abort();
    if (cacheset_lookup(&map, &key) != 10)
	abort();
    if (cacheset_lookup(&map, &key) != 10)
	abort();

    key.size = 500;
    cacheset_add(&map, &key);
    memcpy(key.digest, "1234567890123457", 16);
    if (cacheset_lookup(&map, &key) == 10)
	abort();

    cacheset_release(&map);
    cacheset_destroy(&map);

    return 0;
}
#endif

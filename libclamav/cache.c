/*
 *  Copyright (C) 2010 Sourcefire, Inc.
 *
 *  Authors: aCaB <acab@clamav.net>
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

#include <string.h>
#include <stdlib.h>
#include <pthread.h>

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include "md5.h"
#include "mpool.h"
#include "clamav.h"
#include "cache.h"
#include "fmap.h"

#define CACHE_PERTURB 8
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
	struct CACHE_ENTRY *e = mpool_calloc(mempool, sizeof(struct CACHE_ENTRY), entries);
	if(!e) {
	    cli_errmsg("mpool calloc fail\n");
	    mpool_destroy(mempool);
	    mempool = NULL;
	    return 1;
	}
	cache[i].items = e;
	cache[i].lastdb = 0;
	if(pthread_mutex_init(&cache[i].mutex, NULL)) {
	    cli_errmsg("mutex init fail\n");
	    mpool_destroy(mempool);
	    mempool = NULL;
	    cache = NULL;
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
    for(i=0; i<TREES; i++) {
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
    unsigned int key = getkey(md5);
    struct CACHE_ENTRY *e;
    struct CACHE *c;

    if(!cache) return ret;

    c = &cache[key];
    e = c->items;
    if(pthread_mutex_lock(&c->mutex)) {
	cli_errmsg("mutex lock fail\n");
	return ret;
    }
    if(c->lastdb <= ctx->engine->dbversion[0]) {
	if(c->lastdb < ctx->engine->dbversion[0]) {
	    c->lastdb = ctx->engine->dbversion[0];
	    updb(c->lastdb, key);
	} else {
	    for(i=0; i<cache_entries; i++) {
		if(!e[i].hits) break;
		if(e[i].dbver == c->lastdb && !memcmp(e[i].hash, md5 + 1, 15)) {
		    e[i].hits++;
		    cache_swap(e, i);
		    ret = CL_CLEAN;
		    break;
		}
	    }
	}
    }
    pthread_mutex_unlock(&c->mutex);
    return ret;
}

void cache_add(unsigned char *md5, cli_ctx *ctx) {
    unsigned int key = getkey(md5);
    unsigned int i, replace;
    struct CACHE_ENTRY *e;
    struct CACHE *c;

    if(!cache) return;

    c = &cache[key];
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

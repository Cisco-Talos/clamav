/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *
 *  Authors: Török Edvin
 * 
 *  Summary: Hash-table and -set data structures.
 * 
 *  Acknowledgements: hash32shift() is an implementation of Thomas Wang's 
 * 	                  32-bit integer hash function: 
 * 	                  http://www.cris.com/~Ttwang/tech/inthash.htm
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

#ifndef _HASHTAB_H
#define _HASHTAB_H
#include <stdio.h>
#include <stddef.h>
#include <sys/types.h>

#include "clamav-types.h"
#include "clamav-config.h"
#include "mpool.h"
typedef long cli_element_data;

/* define this for debugging/profiling purposes only, NOT in production/release code */
#ifdef PROFILE_HASHTABLE


typedef struct {
	size_t calc_hash;
	size_t found;
	size_t find_req;
	size_t found_tries;
	size_t not_found;
	size_t not_found_tries;
	size_t grow_found;
	size_t grow_found_tries;
	size_t grow;
	size_t update;
	size_t update_tries;
	size_t inserts;
	size_t insert_tries;
	size_t deleted_reuse;
	size_t deleted_tries;
	size_t deletes;
	size_t clear;
	size_t hash_exhausted;
} PROFILE_STRUCT_;

#define STRUCT_PROFILE PROFILE_STRUCT_ PROFILE_STRUCT;
#else

#define STRUCT_PROFILE

#endif
struct cli_element
{
	const char* key;
	cli_element_data data;
	size_t len;
};

struct cli_hashtable {
	struct cli_element* htable;
	size_t capacity;
	size_t used;
	size_t maxfill;/* 80% */

	STRUCT_PROFILE
};

int cli_hashtab_generate_c(const struct cli_hashtable *s,const char* name);
struct cli_element* cli_hashtab_find(const struct cli_hashtable *s, const char* key, const size_t len);
int cli_hashtab_init(struct cli_hashtable *s,size_t capacity);
const struct cli_element* cli_hashtab_insert(struct cli_hashtable *s, const char* key, const size_t len, const cli_element_data data);
void cli_hashtab_delete(struct cli_hashtable *s,const char* key,const size_t len);
void cli_hashtab_clear(struct cli_hashtable *s);
void cli_hashtab_free(struct cli_hashtable *s);
int cli_hashtab_load(FILE* in, struct cli_hashtable *s);
int cli_hashtab_store(const struct cli_hashtable *s,FILE* out);


struct cli_htu32_element {
    uint32_t key;
    union {
	unsigned long as_ulong;
	void *as_ptr;
    } data;
};

struct cli_htu32 {
    struct cli_htu32_element* htable;
    size_t capacity;
    size_t used;
    size_t maxfill;/* 80% */

    STRUCT_PROFILE
};

#ifndef USE_MPOOL
#define cli_htu32_init(A, B, C) cli_htu32_init(A, B)
#define cli_htu32_insert(A, B, C) cli_htu32_insert(A, B)
#define cli_htu32_free(A, B) cli_htu32_free(A)
#endif
int cli_htu32_init(struct cli_htu32 *s, size_t capacity, mpool_t *mempool);
int cli_htu32_insert(struct cli_htu32 *s, const struct cli_htu32_element *item, mpool_t *mempool);
const struct cli_htu32_element *cli_htu32_find(const struct cli_htu32 *s, uint32_t key);
void cli_htu32_delete(struct cli_htu32 *s, uint32_t key);
void cli_htu32_clear(struct cli_htu32 *s);
void cli_htu32_free(struct cli_htu32 *s, mpool_t *mempool);
const struct cli_htu32_element *cli_htu32_next(const struct cli_htu32 *s, const struct cli_htu32_element *current);
size_t cli_htu32_numitems(struct cli_htu32 *s);


/* a hashtable that stores the values too */
struct cli_map_value {
    void *value;
    int32_t valuesize;
};

struct cli_map {
    struct cli_hashtable htab;
    union {
	struct cli_map_value *unsized_values;
	void *sized_values;
    } u;
    uint32_t nvalues;
    int32_t keysize;
    int32_t valuesize;
    int32_t last_insert;
    int32_t last_find;
};
int cli_map_init(struct cli_map *m, int32_t keysize, int32_t valuesize,
		  int32_t capacity);
int  cli_map_addkey(struct cli_map *m, const void *key, int32_t keysize);
int  cli_map_removekey(struct cli_map *m, const void *key, int32_t keysize);
int  cli_map_setvalue(struct cli_map *m, const void* value, int32_t valuesize);
int  cli_map_find(struct cli_map *m, const void *key, int32_t keysize);
int  cli_map_getvalue_size(struct cli_map *m);
void*  cli_map_getvalue(struct cli_map *m);
void cli_map_delete(struct cli_map *m);

/* A set of unique keys. */
struct cli_hashset {
	uint32_t* keys;
	uint32_t* bitmap;
	mpool_t* mempool;
	uint32_t capacity;
	uint32_t mask;
	uint32_t count;
	uint32_t limit;
};

int cli_hashset_init(struct cli_hashset* hs, size_t initial_capacity, uint8_t load_factor);
int cli_hashset_init_pool(struct cli_hashset* hs, size_t initial_capacity, uint8_t load_factor, mpool_t *mempool);
int cli_hashset_addkey(struct cli_hashset* hs, const uint32_t key);
int cli_hashset_removekey(struct cli_hashset* hs, const uint32_t key);
int cli_hashset_contains(const struct cli_hashset* hs, const uint32_t key);
int cli_hashset_clear(struct cli_hashset* hs);
void cli_hashset_destroy(struct cli_hashset* hs);
ssize_t cli_hashset_toarray(const struct cli_hashset* hs, uint32_t** array);
int cli_hashset_removekey(struct cli_hashset* hs, const uint32_t key);

/* Initializes the set without allocating memory, you can do lookups on it
 * using _contains_maybe_noalloc. You need to initialize it using _init
 * before using _addkey or _removekey though */
void cli_hashset_init_noalloc(struct cli_hashset *hs);
/* this works like its _contains counterpart above, except that the hashset may
 * have not been initialized by _init, only by _init_noalloc */
int cli_hashset_contains_maybe_noalloc(const struct cli_hashset *hs, const uint32_t key);
#endif


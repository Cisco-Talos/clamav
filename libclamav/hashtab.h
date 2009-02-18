/*
 *  HTML Entity & Encoding normalization.
 *
 *  Copyright (C) 2007-2008 Sourcefire, Inc.
 *
 *  Authors: Török Edvin
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
#include "cltypes.h"
typedef long element_data;

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
struct element
{
	const char* key;
	element_data data;
	size_t len;
};

struct hashtable {
	struct element* htable;
	size_t capacity;
	size_t used;
	size_t maxfill;/* 80% */

	STRUCT_PROFILE
};



int hashtab_generate_c(const struct hashtable *s,const char* name);
struct element* hashtab_find(const struct hashtable *s, const char* key, const size_t len);
int hashtab_init(struct hashtable *s,size_t capacity);
const struct element* hashtab_insert(struct hashtable *s, const char* key, const size_t len, const element_data data);
void hashtab_delete(struct hashtable *s,const char* key,const size_t len);
void hashtab_clear(struct hashtable *s);
void hashtab_free(struct hashtable *s);
int hashtab_load(FILE* in, struct hashtable *s);
int hashtab_store(const struct hashtable *s,FILE* out);

/* A set of unique keys. */
struct hashset {
	uint32_t* keys;
	uint32_t* bitmap;
	uint32_t capacity;
	uint32_t mask;
	uint32_t count;
	uint32_t limit;
};

int hashset_init(struct hashset* hs, size_t initial_capacity, uint8_t load_factor);
int hashset_addkey(struct hashset* hs, const uint32_t key);
int hashset_removekey(struct hashset* hs, const uint32_t key);
int hashset_contains(const struct hashset* hs, const uint32_t key);
int hashset_clear(struct hashset* hs);
void hashset_destroy(struct hashset* hs);
ssize_t hashset_toarray(const struct hashset* hs, uint32_t** array);
#endif


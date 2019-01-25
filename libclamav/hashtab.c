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
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "clamav.h"
#include "clamav-config.h"
#include "others.h"
#include "hashtab.h"

#define MODULE_NAME "hashtab: "

static const char DELETED_KEY[] = "";
#define DELETED_HTU32_KEY ((uint32_t)(-1))

static unsigned long nearest_power(unsigned long num)
{
	unsigned long n = 64;

	while (n < num) {
		n <<= 1;
		if (n == 0) {
			return num;
		}
	}
	return n;
}

#ifdef PROFILE_HASHTABLE
/* I know, this is ugly, most of these functions get a const s, that gets its const-ness discarded,
 * and then these functions modify something the compiler assumes is readonly.
 * Please, never use PROFILE_HASHTABLE in production code, and in releases. Use it for development only!*/

static inline void PROFILE_INIT(struct cli_hashtable *s)
{
	memset(&s->PROFILE_STRUCT,0,sizeof(s->PROFILE_STRUCT));
}

static inline void PROFILE_CALC_HASH(struct cli_hashtable *s)
{
	s->PROFILE_STRUCT.calc_hash++;
}

static inline void PROFILE_FIND_ELEMENT(struct cli_hashtable *s)
{
	s->PROFILE_STRUCT.find_req++;
}

static inline void PROFILE_FIND_NOTFOUND(struct cli_hashtable *s, size_t tries)
{
	s->PROFILE_STRUCT.not_found++;
	s->PROFILE_STRUCT.not_found_tries += tries;
}

static inline void PROFILE_FIND_FOUND(struct cli_hashtable *s, size_t tries)
{
	s->PROFILE_STRUCT.found++;
	s->PROFILE_STRUCT.found_tries += tries;
}

static inline void PROFILE_HASH_EXHAUSTED(struct cli_hashtable *s)
{
	s->PROFILE_STRUCT.hash_exhausted++;
}

static inline void PROFILE_GROW_START(struct cli_hashtable *s)
{
	s->PROFILE_STRUCT.grow++;
}

static inline void PROFILE_GROW_FOUND(struct cli_hashtable *s, size_t tries)
{
	s->PROFILE_STRUCT.grow_found++;
	s->PROFILE_STRUCT.grow_found_tries += tries;
}

static inline void PROFILE_GROW_DONE(struct cli_hashtable *s)
{
}

static inline void PROFILE_DELETED_REUSE(struct cli_hashtable *s, size_t tries)
{
	s->PROFILE_STRUCT.deleted_reuse++;
	s->PROFILE_STRUCT.deleted_tries += tries;
}

static inline void PROFILE_INSERT(struct cli_hashtable *s, size_t tries)
{
	s->PROFILE_STRUCT.inserts++;
	s->PROFILE_STRUCT.insert_tries += tries;
}

static inline void PROFILE_DATA_UPDATE(struct cli_hashtable *s, size_t tries)
{
	s->PROFILE_STRUCT.update++;
	s->PROFILE_STRUCT.update_tries += tries;
}

static inline void PROFILE_HASH_DELETE(struct cli_hashtable *s)
{
	s->PROFILE_STRUCT.deletes++;
}

static inline void PROFILE_HASH_CLEAR(struct cli_hashtable *s)
{
	s->PROFILE_STRUCT.clear++;
}

static inline void PROFILE_REPORT(const struct cli_hashtable *s)
{
	size_t lookups, queries, insert_tries, inserts;
	cli_dbgmsg("--------Hashtable usage report for %p--------------\n",(const void*)s);
	cli_dbgmsg("hash function calculations:%ld\n",s->PROFILE_STRUCT.calc_hash);
	cli_dbgmsg("successful finds/total searches: %ld/%ld; lookups: %ld\n", s->PROFILE_STRUCT.found, s->PROFILE_STRUCT.find_req, s->PROFILE_STRUCT.found_tries);
	cli_dbgmsg("unsuccessful finds/total searches: %ld/%ld; lookups: %ld\n", s->PROFILE_STRUCT.not_found, s->PROFILE_STRUCT.find_req , s->PROFILE_STRUCT.not_found_tries);
	cli_dbgmsg("successful finds during grow:%ld; lookups: %ld\n",s->PROFILE_STRUCT.grow_found, s->PROFILE_STRUCT.grow_found_tries);
	lookups = s->PROFILE_STRUCT.found_tries + s->PROFILE_STRUCT.not_found_tries + s->PROFILE_STRUCT.grow_found_tries;
	queries = s->PROFILE_STRUCT.find_req + s->PROFILE_STRUCT.grow_found;
	cli_dbgmsg("Find Lookups/total queries: %ld/%ld = %3f\n", lookups, queries, lookups*1.0/queries);
	insert_tries = s->PROFILE_STRUCT.insert_tries + s->PROFILE_STRUCT.update_tries + s->PROFILE_STRUCT.deleted_tries;

	cli_dbgmsg("new item insert tries/new items: %ld/%ld\n", s->PROFILE_STRUCT.insert_tries, s->PROFILE_STRUCT.inserts);
	cli_dbgmsg("update tries/updates: %ld/%ld\n", s->PROFILE_STRUCT.update_tries, s->PROFILE_STRUCT.update);
	cli_dbgmsg("deleted item reuse tries/deleted&reused items: %ld/%ld\n", s->PROFILE_STRUCT.deleted_tries, s->PROFILE_STRUCT.deleted_reuse);
	inserts = s->PROFILE_STRUCT.inserts + s->PROFILE_STRUCT.update + s->PROFILE_STRUCT.deleted_reuse;
	cli_dbgmsg("Insert tries/total inserts: %ld/%ld = %3f\n", insert_tries, inserts, insert_tries*1.0/inserts);

	cli_dbgmsg("Grows: %ld, Deletes : %ld, hashtable clears: %ld\n",s->PROFILE_STRUCT.grow,s->PROFILE_STRUCT.deletes, s->PROFILE_STRUCT.clear);
        cli_dbgmsg("--------Report end-------------\n");	
}

#else
#define PROFILE_INIT(s) 
#define PROFILE_CALC_HASH(s) 
#define PROFILE_FIND_ELEMENT(s) 
#define PROFILE_FIND_NOTFOUND(s, tries) 
#define PROFILE_FIND_FOUND(s, tries)
#define PROFILE_HASH_EXHAUSTED(s)
#define PROFILE_GROW_START(s)
#define PROFILE_GROW_FOUND(s, tries)
#define PROFILE_GROW_DONE(s)
#define PROFILE_DELETED_REUSE(s, tries)
#define PROFILE_INSERT(s, tries)
#define PROFILE_DATA_UPDATE(s, tries)
#define PROFILE_HASH_DELETE(s)
#define PROFILE_HASH_CLEAR(s)
#define PROFILE_REPORT(s)
#endif

int cli_hashtab_init(struct cli_hashtable *s,size_t capacity)
{
	if(!s)
		return CL_ENULLARG;

	PROFILE_INIT(s);

	capacity = nearest_power(capacity);
	s->htable = cli_calloc(capacity,sizeof(*s->htable));
	if(!s->htable)
		return CL_EMEM;
	s->capacity = capacity;
	s->used = 0;
	s->maxfill = 8*capacity/10;
	return 0;
}

int cli_htu32_init(struct cli_htu32 *s, size_t capacity, mpool_t *mempool)
{
	if(!s)
		return CL_ENULLARG;

	PROFILE_INIT(s);

	capacity = nearest_power(capacity);
	s->htable = mpool_calloc(mempool, capacity, sizeof(*s->htable));
	if(!s->htable)
		return CL_EMEM;
	s->capacity = capacity;
	s->used = 0;
	s->maxfill = 8*capacity/10;
	return 0;
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

static inline size_t hash_htu32(uint32_t k, const size_t SIZE)
{
	/* mixing function */
	size_t Hash = hash32shift(k);
	/* SIZE is power of 2 */
	return Hash & (SIZE - 1);
}

/* if returned element has key==NULL, then key was not found in table */
struct cli_element* cli_hashtab_find(const struct cli_hashtable *s,const char* key,const size_t len)
{
	struct cli_element* element;
	size_t tries = 1;
	size_t idx;

	if(!s)
		return NULL;
	PROFILE_CALC_HASH(s);
	PROFILE_FIND_ELEMENT(s);
	idx = hash((const unsigned char*)key, len, s->capacity);
	element = &s->htable[idx];
	do {
		if(!element->key) {
			PROFILE_FIND_NOTFOUND(s, tries);
			return NULL; /* element not found, place is empty*/
		}
		else if(element->key != DELETED_KEY && len == element->len && (key == element->key || strncmp(key, element->key,len)==0)) {
			PROFILE_FIND_FOUND(s, tries);
			return element;/* found */
		}
		else {
			idx = (idx + tries++) & (s->capacity-1);
			element = &s->htable[idx];
		}
	} while (tries <= s->capacity);
	PROFILE_HASH_EXHAUSTED(s);
	return NULL; /* not found */
}


const struct cli_htu32_element *cli_htu32_find(const struct cli_htu32 *s, uint32_t key)
{
	struct cli_htu32_element* element;
	size_t tries = 1;
	size_t idx;

	if(!s)
		return NULL;
	PROFILE_CALC_HASH(s);
	PROFILE_FIND_ELEMENT(s);
	idx = hash_htu32(key, s->capacity);
	element = &s->htable[idx];
	do {
		if(!element->key) {
			PROFILE_FIND_NOTFOUND(s, tries);
			return NULL; /* element not found, place is empty */
		}
		else if(key == element->key) {
			PROFILE_FIND_FOUND(s, tries);
			return element;/* found */
		}
		else {
			idx = (idx + tries++) & (s->capacity-1);
			element = &s->htable[idx];
		}
	} while (tries <= s->capacity);
	PROFILE_HASH_EXHAUSTED(s);
	return NULL; /* not found */
}

/* linear enumeration - start with current = NULL, returns next item if present or NULL if not */
const struct cli_htu32_element *cli_htu32_next(const struct cli_htu32 *s, const struct cli_htu32_element *current) {
	size_t ncur;
	if(!s || !s->capacity)
		return NULL;

	if(!current)
		ncur = 0;
	else {
		ncur = current - s->htable;
		if(ncur >= s->capacity)
			return NULL;

		ncur++;
	}
	for(; ncur<s->capacity; ncur++) {
		const struct cli_htu32_element *item = &s->htable[ncur & (s->capacity - 1)];
		if(item->key && item->key != DELETED_HTU32_KEY)
			return item;
	}
	return NULL;
}


static int cli_hashtab_grow(struct cli_hashtable *s)
{
	const size_t new_capacity = nearest_power(s->capacity + 1);
	struct cli_element* htable;
	size_t i,idx, used = 0;

	cli_dbgmsg("hashtab.c: new capacity: %llu\n",(long long unsigned)new_capacity);
	if(new_capacity == s->capacity) {
		cli_errmsg("hashtab.c: capacity problem growing from: %llu\n",(long long unsigned)s->capacity);
		return CL_EMEM;
	}
	htable = cli_calloc(new_capacity, sizeof(*s->htable));
	if(!htable) {
		return CL_EMEM;
	}

	PROFILE_GROW_START(s);
	cli_dbgmsg("hashtab.c: Warning: growing open-addressing hashtables is slow. Either allocate more storage when initializing, or use other hashtable types!\n");
	for(i=0; i < s->capacity;i++) {
		if(s->htable[i].key && s->htable[i].key != DELETED_KEY) {
			struct cli_element* element;
			size_t tries = 1;

			PROFILE_CALC_HASH(s);
			idx = hash((const unsigned char*)s->htable[i].key, s->htable[i].len, new_capacity);
			element = &htable[idx];

			while(element->key && tries <= new_capacity) {
				idx = (idx + tries++) & (new_capacity-1);
				element = &htable[idx];
			}
			if(!element->key) {
				/* copy element from old hashtable to new */
				PROFILE_GROW_FOUND(s, tries);
				*element = s->htable[i];
				used++;
			}
			else {
				cli_errmsg("hashtab.c: Impossible - unable to rehash table");
				free (htable);
				return CL_EMEM;/* this means we didn't find enough room for all elements in the new table, should never happen */ 
			}
		}
	}
	free(s->htable);
	s->htable = htable;
	s->used = used;
	s->capacity = new_capacity;
	s->maxfill = new_capacity*8/10;
	cli_dbgmsg("Table %p size after grow:%llu\n",(void*)s,(long long unsigned)s->capacity);
	PROFILE_GROW_DONE(s);
	return CL_SUCCESS;
}

#ifndef USE_MPOOL
#define cli_htu32_grow(A, B) cli_htu32_grow(A)
#endif

static int cli_htu32_grow(struct cli_htu32 *s, mpool_t *mempool)
{
	const size_t new_capacity = nearest_power(s->capacity + 1);
	struct cli_htu32_element* htable = mpool_calloc(mempool, new_capacity, sizeof(*s->htable));
	size_t i,idx, used = 0;
	cli_dbgmsg("hashtab.c: new capacity: %llu\n",(long long unsigned)new_capacity);
	if(new_capacity == s->capacity || !htable)
		return CL_EMEM;

	PROFILE_GROW_START(s);

	for(i=0; i < s->capacity; i++) {
		if(s->htable[i].key && s->htable[i].key != DELETED_HTU32_KEY) {
			struct cli_htu32_element* element;
			size_t tries = 1;

			PROFILE_CALC_HASH(s);
			idx = hash_htu32(s->htable[i].key, new_capacity);
			element = &htable[idx];

			while(element->key && tries <= new_capacity) {
				idx = (idx + tries++) & (new_capacity-1);
				element = &htable[idx];
			}
			if(!element->key) {
				/* copy element from old hashtable to new */
				PROFILE_GROW_FOUND(s, tries);
				*element = s->htable[i];
				used++;
			}
			else {
				cli_errmsg("hashtab.c: Impossible - unable to rehash table");
				return CL_EMEM;/* this means we didn't find enough room for all elements in the new table, should never happen */ 
			}
		}
	}
	mpool_free(mempool, s->htable);
	s->htable = htable;
	s->used = used;
	s->capacity = new_capacity;
	s->maxfill = new_capacity*8/10;
	cli_dbgmsg("Table %p size after grow:%llu\n",(void*)s,(long long unsigned)s->capacity);
	PROFILE_GROW_DONE(s);
	return CL_SUCCESS;
}


const struct cli_element* cli_hashtab_insert(struct cli_hashtable *s, const char* key, const size_t len, const cli_element_data data)
{
	struct cli_element* element;
	struct cli_element* deleted_element = NULL;
	size_t tries = 1;
	size_t idx;
	if(!s)
		return NULL;
	if(s->used > s->maxfill) {
		cli_dbgmsg("hashtab.c:Growing hashtable %p, because it has exceeded maxfill, old size:%llu\n",(void*)s,(long long unsigned)s->capacity);
		cli_hashtab_grow(s);
	}
	do {
		PROFILE_CALC_HASH(s);
		idx = hash((const unsigned char*)key, len, s->capacity);
		element = &s->htable[idx];

		do {
			if(!element->key) {
				char* thekey;
				/* element not found, place is empty, insert*/
				if(deleted_element) {
					/* reuse deleted elements*/
					element = deleted_element;
					PROFILE_DELETED_REUSE(s, tries);
				}
				else {
					PROFILE_INSERT(s, tries);
				}
				thekey = cli_malloc(len+1);
				if(!thekey) {
                    cli_errmsg("hashtab.c: Unable to allocate memory for thekey\n");
					return NULL;
                }
				strncpy(thekey, key, len+1);
				thekey[len]='\0';
				element->key = thekey;
				element->data = data;
				element->len = len;
				s->used++;
				return element;
			}
			else if(element->key == DELETED_KEY) {
				deleted_element = element;
				element->key = NULL;
			}
			else if(len == element->len && strncmp(key, element->key, len)==0) {
				PROFILE_DATA_UPDATE(s, tries);
				element->data = data;/* key found, update */
				return element;
			}
			else {
				idx = (idx + tries++) % s->capacity;
				element = &s->htable[idx];
			}
		} while (tries <= s->capacity);
		/* no free place found*/
		PROFILE_HASH_EXHAUSTED(s);
		cli_dbgmsg("hashtab.c: Growing hashtable %p, because its full, old size:%llu.\n",(void*)s,(long long unsigned)s->capacity);
	} while( cli_hashtab_grow(s) >= 0 );
	cli_warnmsg("hashtab.c: Unable to grow hashtable\n");
	return NULL;
}


int cli_htu32_insert(struct cli_htu32 *s, const struct cli_htu32_element *item, mpool_t *mempool)
{
	struct cli_htu32_element* element;
	struct cli_htu32_element* deleted_element = NULL;
	size_t tries = 1;
	size_t idx;
	int ret;

	if(!s)
		return CL_ENULLARG;
	if(s->used > s->maxfill) {
		cli_dbgmsg("hashtab.c:Growing hashtable %p, because it has exceeded maxfill, old size:%llu\n",(void*)s,(long long unsigned)s->capacity);
		cli_htu32_grow(s, mempool);
	}
	do {
		PROFILE_CALC_HASH(s);
		idx = hash_htu32(item->key, s->capacity);
		element = &s->htable[idx];

		do {
			if(!element->key) {
				/* element not found, place is empty, insert*/
				if(deleted_element) {
					/* reuse deleted elements*/
					element = deleted_element;
					PROFILE_DELETED_REUSE(s, tries);
				}
				else {
					PROFILE_INSERT(s, tries);
				}
				*element = *item;
				s->used++;
				return 0;
			}
			else if(element->key == DELETED_HTU32_KEY) {
				deleted_element = element;
				element->key = 0;
			}
			else if(item->key == element->key) {
				PROFILE_DATA_UPDATE(s, tries);
				element->data = item->data;/* key found, update */
				return 0;
			}
			else {
				idx = (idx + tries++) % s->capacity;
				element = &s->htable[idx];
			}
		} while (tries <= s->capacity);
		/* no free place found*/
		PROFILE_HASH_EXHAUSTED(s);
		cli_dbgmsg("hashtab.c: Growing hashtable %p, because its full, old size:%llu.\n",(void*)s,(long long unsigned)s->capacity);
	} while( (ret = cli_htu32_grow(s, mempool)) >= 0 );
	cli_warnmsg("hashtab.c: Unable to grow hashtable\n");
	return ret;
}


void cli_hashtab_delete(struct cli_hashtable *s,const char* key,const size_t len)
{
    struct cli_element *el = cli_hashtab_find(s, key, len);
    if (!el || el->key == DELETED_KEY)
	return;
    free((void*)el->key);
    el->key = DELETED_KEY;
}

void cli_htu32_delete(struct cli_htu32 *s, uint32_t key)
{
	struct cli_htu32_element *el = (struct cli_htu32_element *)cli_htu32_find(s, key);
	if(el)
		el->key = DELETED_HTU32_KEY;
}

void cli_hashtab_clear(struct cli_hashtable *s)
{
	size_t i;
	PROFILE_HASH_CLEAR(s);
	for(i=0;i < s->capacity;i++) {
		if(s->htable[i].key && s->htable[i].key != DELETED_KEY)
			free((void *)s->htable[i].key);
	}
	if(s->htable)
		memset(s->htable, 0, s->capacity * sizeof(*s->htable));
	s->used = 0;
}

void cli_htu32_clear(struct cli_htu32 *s)
{
	PROFILE_HASH_CLEAR(s);
	if(s->htable)
		memset(s->htable, 0, s->capacity * sizeof(struct cli_htu32_element));
	s->used = 0;
}

void cli_hashtab_free(struct cli_hashtable *s)
{
	cli_hashtab_clear(s);
	free(s->htable);
	s->htable = NULL;
	s->capacity = 0;
}

void cli_htu32_free(struct cli_htu32 *s, mpool_t *mempool)
{
	mpool_free(mempool, s->htable);
	s->htable = NULL;
	s->capacity = 0;
}

size_t cli_htu32_numitems(struct cli_htu32 *s) {
	if(!s) return 0;
	return s->capacity;
}

int cli_hashtab_store(const struct cli_hashtable *s,FILE* out)
{
	size_t i;
	for(i=0; i < s->capacity; i++) {
		const struct cli_element* e = &s->htable[i];
		if(e->key && e->key != DELETED_KEY) {
			fprintf(out,"%ld %s\n",e->data,e->key);
		}
	}
	return CL_SUCCESS;
}

int cli_hashtab_generate_c(const struct cli_hashtable *s,const char* name)
{
	size_t i;
	printf("/* TODO: include GPL headers */\n");
	printf("#include <hashtab.h>\n");
	printf("static struct cli_element %s_elements[] = {\n",name);
	for(i=0; i < s->capacity; i++) {
		const struct cli_element* e = &s->htable[i];
		if(!e->key)
			printf("\t{NULL,0,0},\n");
		else if(e->key == DELETED_KEY)
			printf("\t{DELETED_KEY,0,0},\n");
		else
			printf("\t{\"%s\", %ld, %llu},\n", e->key, e->data, (long long unsigned)e->len);
	}
	printf("};\n");
	printf("const struct cli_hashtable %s = {\n",name);
	printf("\t%s_elements, %llu, %llu, %llu", name, (long long unsigned)s->capacity,
	       (long long unsigned)s->used, (long long unsigned)s->maxfill);
	printf("\n};\n");

	PROFILE_REPORT(s);
	return 0;
}

int cli_hashtab_load(FILE* in, struct cli_hashtable *s)
{
	char line[1024];
	while (fgets(line, sizeof(line), in)) {
		char l[1024];
		int val;
		sscanf(line,"%d %1023s",&val,l);
		cli_hashtab_insert(s,l,strlen(l),val);
	}
	return CL_SUCCESS;
}

/* Initialize hashset. @initial_capacity is rounded to nearest power of 2.
 * Load factor is between 50 and 99. When capacity*load_factor/100 is reached, the hashset is growed */
int cli_hashset_init(struct cli_hashset* hs, size_t initial_capacity, uint8_t load_factor)
{
	if(load_factor < 50 || load_factor > 99) {
		cli_dbgmsg(MODULE_NAME "Invalid load factor: %u, using default of 80%%\n", load_factor);
		load_factor = 80;
	}
	initial_capacity = nearest_power(initial_capacity);
	hs->limit = initial_capacity * load_factor / 100;
	hs->capacity = initial_capacity;
	hs->mask = initial_capacity - 1;
	hs->count=0;
	hs->keys = cli_malloc(initial_capacity * sizeof(*hs->keys));
	hs->mempool = NULL;
	if(!hs->keys) {
        cli_errmsg("hashtab.c: Unable to allocate memory for hs->keys\n");
		return CL_EMEM;
	}
	hs->bitmap = cli_calloc(initial_capacity >> 5, sizeof(*hs->bitmap));
	if(!hs->bitmap) {
		free(hs->keys);
        cli_errmsg("hashtab.c: Unable to allocate memory for hs->bitmap\n");
		return CL_EMEM;
	}
	return 0;
}

int cli_hashset_init_pool(struct cli_hashset* hs, size_t initial_capacity, uint8_t load_factor, mpool_t *mempool) {
	if(load_factor < 50 || load_factor > 99) {
		cli_dbgmsg(MODULE_NAME "Invalid load factor: %u, using default of 80%%\n", load_factor);
		load_factor = 80;
	}
	initial_capacity = nearest_power(initial_capacity);
	hs->limit = initial_capacity * load_factor / 100;
	hs->capacity = initial_capacity;
	hs->mask = initial_capacity - 1;
	hs->count=0;
	hs->mempool = mempool;
	hs->keys = mpool_malloc(mempool, initial_capacity * sizeof(*hs->keys));
	if(!hs->keys) {
        cli_errmsg("hashtab.c: Unable to allocate memory pool for hs->keys\n");
		return CL_EMEM;
	}
	hs->bitmap = mpool_calloc(mempool, initial_capacity >> 5, sizeof(*hs->bitmap));
	if(!hs->bitmap) {
		mpool_free(mempool, hs->keys);
        cli_errmsg("hashtab.c: Unable to allocate/initialize memory for hs->keys\n");
		return CL_EMEM;
	}
	return 0;
}


void cli_hashset_destroy(struct cli_hashset* hs)
{
	cli_dbgmsg(MODULE_NAME "Freeing hashset, elements: %u, capacity: %u\n", hs->count, hs->capacity);
	if(hs->mempool) {
		mpool_free(hs->mempool, hs->keys);
		mpool_free(hs->mempool, hs->bitmap);
	} else {
	    free(hs->keys);
	    free(hs->bitmap);
	}
	hs->keys = hs->bitmap = NULL;
	hs->capacity = 0;
}

#define BITMAP_CONTAINS(bmap, val) ((bmap)[(val) >> 5] & (1 << ((val) & 0x1f)))
#define BITMAP_INSERT(bmap, val) ((bmap)[(val) >> 5] |= (1 << ((val) & 0x1f)))
#define BITMAP_REMOVE(bmap, val) ((bmap)[(val) >> 5] &= ~(1 << ((val) & 0x1f)))

/*
 * searches the hashset for the @key.
 * Returns the position the key is at, or a candidate position where it could be inserted.
 */
static inline size_t cli_hashset_search(const struct cli_hashset* hs, const uint32_t key)
{
	/* calculate hash value for this key, and map it to our table */
	size_t idx = hash32shift(key) & (hs->mask);
	size_t tries = 1;

	/* check whether the entry is used, and if the key matches */
	while(BITMAP_CONTAINS(hs->bitmap, idx) && (hs->keys[idx] != key)) {
		/* entry used, key different -> collision */
		idx = (idx + tries++)&(hs->mask);
		/* quadratic probing, with c1 = c2 = 1/2, guaranteed to walk the entire table
		 * for table sizes power of 2.*/
	}
	/* we have either found the key, or a candidate insertion position */
	return idx;
}

static void cli_hashset_addkey_internal(struct cli_hashset* hs, const uint32_t key)
{
	const size_t idx = cli_hashset_search(hs, key);
	/* we know hashtable is not full, when this method is called */

	if(!BITMAP_CONTAINS(hs->bitmap, idx)) {
		/* add new key */
		BITMAP_INSERT(hs->bitmap, idx);
		hs->keys[idx] = key;
		hs->count++;
	}
}

static int cli_hashset_grow(struct cli_hashset *hs)
{
	struct cli_hashset new_hs;
	size_t i;
	int rc;

	/* in-place growing is not possible, since the new keys
	 * will hash to different locations. */
	cli_dbgmsg(MODULE_NAME "Growing hashset, used: %u, capacity: %u\n", hs->count, hs->capacity);
	/* create a bigger hashset */

	if(hs->mempool)
		rc = cli_hashset_init_pool(&new_hs, hs->capacity << 1, hs->limit*100/hs->capacity, hs->mempool);
	else
		rc = cli_hashset_init(&new_hs, hs->capacity << 1, hs->limit*100/hs->capacity);
	if(rc != 0)
		return rc;
	/* and copy keys */
	for(i=0;i < hs->capacity;i++) {
		if(BITMAP_CONTAINS(hs->bitmap, i)) {
			const size_t key = hs->keys[i];
			cli_hashset_addkey_internal(&new_hs, key);
		}
	}
	cli_hashset_destroy(hs);
	/* replace old hashset with new one */
	*hs = new_hs;
	return 0;
}

int cli_hashset_addkey(struct cli_hashset* hs, const uint32_t key)
{
	/* check that we didn't reach the load factor.
	 * Even if we don't know yet whether we'd add this key */
	if(hs->count + 1 > hs->limit) {
		int rc = cli_hashset_grow(hs);
		if(rc) {
			return rc;
		}
	}
	cli_hashset_addkey_internal(hs, key);
	return 0;
}

int cli_hashset_removekey(struct cli_hashset* hs, const uint32_t key)
{
    const size_t idx = cli_hashset_search(hs, key);
    if (BITMAP_CONTAINS(hs->bitmap, idx)) {
	BITMAP_REMOVE(hs->bitmap, idx);
	hs->keys[idx] = 0;
	hs->count--;
	return 0;
    }
    return -1;
}

int cli_hashset_contains(const struct cli_hashset* hs, const uint32_t key)
{
	const size_t idx =  cli_hashset_search(hs, key);
	return BITMAP_CONTAINS(hs->bitmap, idx);
}

ssize_t cli_hashset_toarray(const struct cli_hashset* hs, uint32_t** array)
{
	size_t i, j;
	uint32_t* arr;

	if(!array) {
		return CL_ENULLARG;
	}
	*array = arr = cli_malloc(hs->count * sizeof(*arr));
	if(!arr) {
        cli_errmsg("hashtab.c: Unable to allocate memory for array\n");
		return CL_EMEM;
	}

	for(i=0,j=0 ; i < hs->capacity && j < hs->count;i++) {
		if(BITMAP_CONTAINS(hs->bitmap, i)) {
			arr[j++] = hs->keys[i];
		}
	}
	return j;
}

void cli_hashset_init_noalloc(struct cli_hashset *hs)
{
    memset(hs, 0, sizeof(*hs));
}

int cli_hashset_contains_maybe_noalloc(const struct cli_hashset *hs, const uint32_t key)
{
    if (!hs->keys)
	return 0;
    return cli_hashset_contains(hs, key);
}

int cli_map_init(struct cli_map *m, int32_t keysize, int32_t valuesize,
		  int32_t capacity)
{
    if (keysize <= 0 || valuesize < 0 || capacity <= 0)
	return -CL_EARG;
    memset(m, 0, sizeof(*m));
    cli_hashtab_init(&m->htab, 16);
    m->keysize = keysize;
    m->valuesize = valuesize;
    m->last_insert = -1;
    m->last_find = -1;
    return 0;
}

int  cli_map_addkey(struct cli_map *m, const void *key, int32_t keysize)
{
    unsigned n;
    struct cli_element *el;
    if (m->keysize != keysize)
	return -CL_EARG;
    el = cli_hashtab_find(&m->htab, key, keysize);
    if (el) {
	m->last_insert = el->data;
	return 0;
    }
    n = m->nvalues + 1;
    if (m->valuesize) {
	void *v;
	v = cli_realloc(m->u.sized_values, n*m->valuesize);
	if (!v)
	    return -CL_EMEM;
	m->u.sized_values = v;
	memset((char*)m->u.sized_values + (n-1)*m->valuesize, 0, m->valuesize);
    } else {
	struct cli_map_value *v;
	v = cli_realloc(m->u.unsized_values, n*sizeof(*m->u.unsized_values));
	if (!v)
	    return -CL_EMEM;
	m->u.unsized_values = v;
	memset(&m->u.unsized_values[n-1], 0, sizeof(*m->u.unsized_values));
    }
    m->nvalues = n;
    if (!cli_hashtab_insert(&m->htab, key, keysize, n-1))
	return -CL_EMEM;
    m->last_insert = n-1;
    return 1;
}

int  cli_map_removekey(struct cli_map *m, const void *key, int32_t keysize)
{
    struct cli_element *el;
    if (m->keysize != keysize)
	return -CL_EARG;
    el = cli_hashtab_find(&m->htab, key, keysize);
    if (!el)
	return 0;
    if (el->data >= m->nvalues || el->data < 0)
	return -CL_EARG;
    if (!m->valuesize) {
	struct cli_map_value *v = &m->u.unsized_values[el->data];
	free(v->value);
	v->value = NULL;
	v->valuesize = 0;
    } else {
	char *v = (char*)m->u.sized_values + el->data * m->valuesize;
	memset(v, 0, m->valuesize);
    }
    cli_hashtab_delete(&m->htab, key, keysize);
    return 1;
}

int  cli_map_setvalue(struct cli_map *m, const void* value, int32_t valuesize)
{
    if ((m->valuesize && m->valuesize != valuesize)
	|| (uint32_t)(m->last_insert) >= m->nvalues || m->last_insert < 0)
	return -CL_EARG;
    if (m->valuesize) {
	memcpy((char*)m->u.sized_values + m->last_insert * m->valuesize,
	       value, valuesize);
    } else {
	struct cli_map_value *v = &m->u.unsized_values[m->last_insert];
	if (v->value)
	    free(v->value);
	v->value = cli_malloc(valuesize);
	if (!v->value) {
        cli_errmsg("hashtab.c: Unable to allocate  memory for v->value\n");
        return -CL_EMEM;
    }
	memcpy(v->value, value, valuesize);
	v->valuesize = valuesize;
    }
    return 0;
}

int  cli_map_find(struct cli_map *m, const void *key, int32_t keysize)
{
    struct cli_element *el;
    if (m->keysize != keysize)
	return -CL_EARG;
    el = cli_hashtab_find(&m->htab, key, keysize);
    if (!el)
	return 0;
    m->last_find = el->data;
    return 1;
}

int  cli_map_getvalue_size(struct cli_map *m)
{
    if (m->valuesize)
	return m->valuesize;
    if (m->last_find < 0 || (uint32_t)(m->last_find) >= m->nvalues)
	return -CL_EARG;
    return m->u.unsized_values[m->last_find].valuesize;
}

void* cli_map_getvalue(struct cli_map *m)
{
    if (m->last_find < 0 || (uint32_t)(m->last_find) >= m->nvalues)
	return NULL;
    if (m->valuesize)
	return (char*)m->u.sized_values + m->last_find*m->valuesize;
    return m->u.unsized_values[m->last_find].value;
}

void cli_map_delete(struct cli_map *m)
{
    cli_hashtab_free(&m->htab);
    if (!m->valuesize) {
	unsigned i;
	for (i=0;i<m->nvalues;i++)
	    free(m->u.unsized_values[i].value);
	free(m->u.unsized_values);
    } else {
	free(m->u.sized_values);
    }
    memset(m, 0, sizeof(*m));
}

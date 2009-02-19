/*
 *  Hash-table and -set data structures.
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
#include <clamav-config.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "cltypes.h"
#include "clamav.h"
#include "others.h"
#include "hashtab.h"

#define MODULE_NAME "hashtab: "

static const char DELETED_KEY[] = "";

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

static inline void PROFILE_INIT(struct hashtable *s)
{
	memset(&s->PROFILE_STRUCT,0,sizeof(s->PROFILE_STRUCT));
}

static inline void PROFILE_CALC_HASH(struct hashtable *s)
{
	s->PROFILE_STRUCT.calc_hash++;
}

static inline void PROFILE_FIND_ELEMENT(struct hashtable *s)
{
	s->PROFILE_STRUCT.find_req++;
}

static inline void PROFILE_FIND_NOTFOUND(struct hashtable *s, size_t tries)
{
	s->PROFILE_STRUCT.not_found++;
	s->PROFILE_STRUCT.not_found_tries += tries;
}

static inline void PROFILE_FIND_FOUND(struct hashtable *s, size_t tries)
{
	s->PROFILE_STRUCT.found++;
	s->PROFILE_STRUCT.found_tries += tries;
}

static inline void PROFILE_HASH_EXHAUSTED(struct hashtable *s)
{
	s->PROFILE_STRUCT.hash_exhausted++;
}

static inline void PROFILE_GROW_START(struct hashtable *s)
{
	s->PROFILE_STRUCT.grow++;
}

static inline void PROFILE_GROW_FOUND(struct hashtable *s, size_t tries)
{
	s->PROFILE_STRUCT.grow_found++;
	s->PROFILE_STRUCT.grow_found_tries += tries;
}

static inline void PROFILE_GROW_DONE(struct hashtable *s)
{
}

static inline void PROFILE_DELETED_REUSE(struct hashtable *s, size_t tries)
{
	s->PROFILE_STRUCT.deleted_reuse++;
	s->PROFILE_STRUCT.deleted_tries += tries;
}

static inline void PROFILE_INSERT(struct hashtable *s, size_t tries)
{
	s->PROFILE_STRUCT.inserts++;
	s->PROFILE_STRUCT.insert_tries += tries;
}

static inline void PROFILE_DATA_UPDATE(struct hashtable *s, size_t tries)
{
	s->PROFILE_STRUCT.update++;
	s->PROFILE_STRUCT.update_tries += tries;
}

static inline void PROFILE_HASH_DELETE(struct hashtable *s)
{
	s->PROFILE_STRUCT.deletes++;
}

static inline void PROFILE_HASH_CLEAR(struct hashtable *s)
{
	s->PROFILE_STRUCT.clear++;
}

static inline void PROFILE_REPORT(const struct hashtable *s)
{
	size_t lookups, queries, insert_tries, inserts;
	cli_dbgmsg("--------Hashtable usage report for %p--------------\n",(const void*)s);
	cli_dbgmsg("hash function calculations:%ld\n",s->PROFILE_STRUCT.calc_hash);
	cli_dbgmsg("successfull finds/total searches: %ld/%ld; lookups: %ld\n", s->PROFILE_STRUCT.found, s->PROFILE_STRUCT.find_req, s->PROFILE_STRUCT.found_tries);
	cli_dbgmsg("unsuccessfull finds/total searches: %ld/%ld; lookups: %ld\n", s->PROFILE_STRUCT.not_found, s->PROFILE_STRUCT.find_req , s->PROFILE_STRUCT.not_found_tries);
	cli_dbgmsg("successfull finds during grow:%ld; lookups: %ld\n",s->PROFILE_STRUCT.grow_found, s->PROFILE_STRUCT.grow_found_tries);
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

int hashtab_init(struct hashtable *s,size_t capacity)
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

/* if returned element has key==NULL, then key was not found in table */
struct element* hashtab_find(const struct hashtable *s,const char* key,const size_t len)
{
	struct element* element;
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

static int hashtab_grow(struct hashtable *s)
{
	const size_t new_capacity = nearest_power(s->capacity + 1);
	struct element* htable = cli_calloc(new_capacity, sizeof(*s->htable));
	size_t i,idx, used = 0;
	cli_dbgmsg("hashtab.c: new capacity: %lu\n",new_capacity);
	if(new_capacity == s->capacity || !htable)
		return CL_EMEM;

	PROFILE_GROW_START(s);
	cli_dbgmsg("hashtab.c: Warning: growing open-addressing hashtables is slow. Either allocate more storage when initializing, or use other hashtable types!\n");
	for(i=0; i < s->capacity;i++) {
		if(s->htable[i].key && s->htable[i].key != DELETED_KEY) {
			struct element* element;
			size_t tries = 1;

			PROFILE_CALC_HASH(s);
			idx = hash((const unsigned char*)s->htable[i].key, s->htable[i].len, new_capacity);
			element = &htable[idx];

			while(element->key && tries <= new_capacity) {
				idx = (idx + tries++) % new_capacity;
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
	free(s->htable);
	s->htable = htable;
	s->used = used;
	s->capacity = new_capacity;
	s->maxfill = new_capacity*8/10;
	cli_dbgmsg("Table %p size after grow:%ld\n",(void*)s,s->capacity);
	PROFILE_GROW_DONE(s);
	return CL_SUCCESS;
}

const struct element* hashtab_insert(struct hashtable *s, const char* key, const size_t len, const element_data data)
{
	struct element* element;
	struct element* deleted_element = NULL;
	size_t tries = 1;
	size_t idx;
	if(!s)
		return NULL;
	if(s->used > s->maxfill) {
		cli_dbgmsg("hashtab.c:Growing hashtable %p, because it has exceeded maxfill, old size:%ld\n",(void*)s,s->capacity);
		hashtab_grow(s);
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
				if(!thekey)
					return NULL;
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
		cli_dbgmsg("hashtab.c: Growing hashtable %p, because its full, old size:%ld.\n",(void*)s,s->capacity);
	} while( hashtab_grow(s) >= 0 );
	cli_warnmsg("hashtab.c: Unable to grow hashtable\n");
	return NULL;
}

void hashtab_clear(struct hashtable *s)
{
	size_t i;
	PROFILE_HASH_CLEAR(s);
	for(i=0;i < s->capacity;i++) {
		if(s->htable[i].key && s->htable[i].key != DELETED_KEY)
			free((void *)s->htable[i].key);
	}
	if(s->htable)
		memset(s->htable, 0, s->capacity);
	s->used = 0;
}

void hashtab_free(struct hashtable *s)
{
	hashtab_clear(s);
	free(s->htable);
	s->htable = NULL;
	s->capacity = 0;
}

int hashtab_store(const struct hashtable *s,FILE* out)
{
	size_t i;
	for(i=0; i < s->capacity; i++) {
		const struct element* e = &s->htable[i];
		if(e->key && e->key != DELETED_KEY) {
			fprintf(out,"%ld %s\n",e->data,e->key);
		}
	}
	return CL_SUCCESS;
}

int hashtab_generate_c(const struct hashtable *s,const char* name)
{
	size_t i;
	printf("/* TODO: include GPL headers */\n");
	printf("#include <hashtab.h>\n");
	printf("static struct element %s_elements[] = {\n",name);
	for(i=0; i < s->capacity; i++) {
		const struct element* e = &s->htable[i];
		if(!e->key)
			printf("\t{NULL,0,0},\n");
		else if(e->key == DELETED_KEY)
			printf("\t{DELETED_KEY,0,0},\n");
		else
			printf("\t{\"%s\", %ld, %ld},\n", e->key, e->data, e->len);
	}
	printf("};\n");
	printf("const struct hashtable %s = {\n",name);
	printf("\t%s_elements, %ld, %ld, %ld", name, s->capacity, s->used, s->maxfill);
	printf("\n};\n");

	PROFILE_REPORT(s);
	return 0;
}

int hashtab_load(FILE* in, struct hashtable *s)
{
	char line[1024];
	while (fgets(line, sizeof(line), in)) {
		char l[1024];
		int val;
		sscanf(line,"%d %1023s",&val,l);
		hashtab_insert(s,l,strlen(l),val);
	}
	return CL_SUCCESS;
}

/* Initialize hashset. @initial_capacity is rounded to nearest power of 2.
 * Load factor is between 50 and 99. When capacity*load_factor/100 is reached, the hashset is growed */
int hashset_init(struct hashset* hs, size_t initial_capacity, uint8_t load_factor)
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
	if(!hs->keys) {
		return CL_EMEM;
	}
	hs->bitmap = cli_calloc(initial_capacity / 8, sizeof(*hs->bitmap));
	if(!hs->bitmap) {
		free(hs->keys);
		return CL_EMEM;
	}
	return 0;
}

void hashset_destroy(struct hashset* hs)
{
	cli_dbgmsg(MODULE_NAME "Freeing hashset, elements: %u, capacity: %u\n", hs->count, hs->capacity);
	free(hs->keys);
	free(hs->bitmap);
	hs->keys = hs->bitmap = NULL;
	hs->capacity = 0;
}

#define BITMAP_CONTAINS(bmap, val) ((bmap)[(val) >> 5] & (1 << ((val) & 0x1f)))
#define BITMAP_INSERT(bmap, val) ((bmap)[(val) >> 5] |= (1 << ((val) & 0x1f)))

/*
 * searches the hashset for the @key.
 * Returns the position the key is at, or a candidate position where it could be inserted.
 */
static inline size_t hashset_search(const struct hashset* hs, const uint32_t key)
{
	/* calculate hash value for this key, and map it to our table */
	size_t idx = hash32shift(key) & (hs->mask);
	size_t tries = 1;

	/* check wether the entry is used, and if the key matches */
	while(BITMAP_CONTAINS(hs->bitmap, idx) && (hs->keys[idx] != key)) {
		/* entry used, key different -> collision */
		idx = (idx + tries++)&(hs->mask);
		/* quadratic probing, with c1 = c2 = 1/2, guaranteed to walk the entire table
		 * for table sizes power of 2.*/
	}
	/* we have either found the key, or a candidate insertion position */
	return idx;
}


static void hashset_addkey_internal(struct hashset* hs, const uint32_t key)
{
	const size_t idx = hashset_search(hs, key);
	/* we know hashtable is not full, when this method is called */

	if(!BITMAP_CONTAINS(hs->bitmap, idx)) {
		/* add new key */
		BITMAP_INSERT(hs->bitmap, idx);
		hs->keys[idx] = key;
		hs->count++;
	}
}

static int hashset_grow(struct hashset *hs)
{
	struct hashset new_hs;
	size_t i;
	int rc;

	/* in-place growing is not possible, since the new keys
	 * will hash to different locations. */
	cli_dbgmsg(MODULE_NAME "Growing hashset, used: %u, capacity: %u\n", hs->count, hs->capacity);
	/* create a bigger hashset */
	if((rc = hashset_init(&new_hs, hs->capacity << 1, hs->limit*100/hs->capacity)) < 0) {
		return rc;
	}
	/* and copy keys */
	for(i=0;i < hs->capacity;i++) {
		if(BITMAP_CONTAINS(hs->bitmap, i)) {
			const size_t key = hs->keys[i];
			hashset_addkey_internal(&new_hs, key);
		}
	}
	hashset_destroy(hs);
	/* replace old hashset with new one */
	*hs = new_hs;
	return 0;
}

int hashset_addkey(struct hashset* hs, const uint32_t key)
{
	/* check that we didn't reach the load factor.
	 * Even if we don't know yet whether we'd add this key */
	if(hs->count + 1 > hs->limit) {
		int rc = hashset_grow(hs);
		if(rc) {
			return rc;
		}
	}
	hashset_addkey_internal(hs, key);
	return 0;
}

int hashset_contains(const struct hashset* hs, const uint32_t key)
{
	const size_t idx =  hashset_search(hs, key);
	return BITMAP_CONTAINS(hs->bitmap, idx);
}

ssize_t hashset_toarray(const struct hashset* hs, uint32_t** array)
{
	size_t i, j;
	uint32_t* arr;

	if(!array) {
		return CL_ENULLARG;
	}
	*array = arr = cli_malloc(hs->count * sizeof(*arr));
	if(!arr) {
		return CL_EMEM;
	}

	for(i=0,j=0 ; i < hs->capacity && j < hs->count;i++) {
		if(BITMAP_CONTAINS(hs->bitmap, i)) {
			arr[j++] = hs->keys[i];
		}
	}
	return j;
}

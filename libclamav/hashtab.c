/*
 *  HTML Entity & Encoding normalization.
 *
 *  Copyright (C) 2006-2007 Török Edvin <edwin@clamav.net>
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
 *
 */
#include <clamav-config.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "cltypes.h"
#include "clamav.h"
#include "others.h"
#include "hashtab.h"


static const size_t prime_list[] =
{
     53ul,         97ul,         193ul,       389ul,       769ul,
     1543ul,       3079ul,       6151ul,      12289ul,     24593ul,
     49157ul,      98317ul,      196613ul,    393241ul,    786433ul,
     1572869ul,    3145739ul,    6291469ul,   12582917ul,  25165843ul,
     50331653ul,   100663319ul,  201326611ul, 402653189ul, 805306457ul,
     1610612741ul, 3221225473ul
};


static const size_t prime_n = sizeof(prime_list)/sizeof(prime_list[0]);

static unsigned char DELETED_KEY[] = "";

static size_t get_nearest_capacity(const size_t capacity)
{
	size_t i;
	for(i=0 ;i < prime_n; i++) {
		if (prime_list[i] > capacity)
			return prime_list[i];
	}
	cli_errmsg("Requested hashtable size is too big!");
	return prime_list[prime_n-1];
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

	capacity = get_nearest_capacity(capacity);
	s->htable = cli_calloc(capacity,sizeof(*s->htable));
	if(!s->htable)
		return CL_EMEM;
	s->capacity = capacity;
	s->used = 0;
	s->maxfill = 8*capacity/10;
	return 0;
}

static size_t hash(const unsigned char* k,const size_t len,const size_t SIZE)
{
	size_t Hash = 0;	
	size_t i;
	for(i=len;i>0;i--)
		Hash = ((Hash << 8) + k[i-1]) % SIZE;
	return Hash;
}

/* if returned element has key==NULL, then key was not found in table */
struct element* hashtab_find(const struct hashtable *s,const unsigned char* key,const size_t len)
{
	struct element* element;
	size_t tries = 1; 
	size_t idx;

	if(!s)
		return NULL; 
	PROFILE_CALC_HASH(s);
	PROFILE_FIND_ELEMENT(s);
	idx = hash(key, len, s->capacity); 
	element = &s->htable[idx];
	do {
		if(!element->key) {
			PROFILE_FIND_NOTFOUND(s, tries);
			return NULL; /* element not found, place is empty*/
		}
		else if(element->key != DELETED_KEY && strncmp((const char*)key,(const char*)element->key,len)==0) {
			PROFILE_FIND_FOUND(s, tries);
			return element;/* found */
		}
		else {
			idx = (idx + tries++) % s->capacity;
			element = &s->htable[idx];
		}
	} while (tries <= s->capacity);
	PROFILE_HASH_EXHAUSTED(s);
	return NULL; /* not found */
}

static int hashtab_grow(struct hashtable *s)
{
	const size_t new_capacity = get_nearest_capacity(s->capacity);
	struct element* htable = cli_calloc(new_capacity, sizeof(*s->htable));
	size_t i,idx, used = 0;
	if(new_capacity == s->capacity || !htable)
		return CL_EMEM;

	PROFILE_GROW_START(s);
	cli_dbgmsg("hashtab.c: Warning: growing open-addressing hashtables is slow. Either allocate more storage when initializing, or use other hashtable types!\n");
	for(i=0; i < s->capacity;i++) {
		if(s->htable[i].key && s->htable[i].key != DELETED_KEY) {
			struct element* element;
			size_t tries = 1;				

			PROFILE_CALC_HASH(s);
			idx = hash(s->htable[i].key, strlen((const char*)s->htable[i].key), new_capacity);
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


int hashtab_insert(struct hashtable *s,const unsigned char* key,const size_t len,const element_data data)
{
	struct element* element;
	struct element* deleted_element = NULL;
	size_t tries = 1; 
	size_t idx;
	if(!s)
		return CL_ENULLARG; 
	do {
		PROFILE_CALC_HASH(s);
		idx = hash(key, len, s->capacity); 
		element = &s->htable[idx];

		do {
			if(!element->key) {
				unsigned char* thekey;
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
					return CL_EMEM;
				strncpy((char*)thekey,(const char*)key,len+1);
				element->key = thekey;
				element->data = data;
				s->used++;		
				if(s->used > s->maxfill) {
					cli_dbgmsg("hashtab.c:Growing hashtable %p, because it has exceeded maxfill, old size:%ld\n",(void*)s,s->capacity);
					hashtab_grow(s);
				}
				return 0;
			}
			else if(element->key == DELETED_KEY) {
				deleted_element = element;
			}
			else if(strncmp((const char*)key,(const char*)element->key,len)==0) {
				PROFILE_DATA_UPDATE(s, tries);
				element->data = data;/* key found, update */
				return 0;		
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
	return CL_EMEM;
}

void hashtab_delete(struct hashtable *s,const unsigned char* key,const size_t len)
{
	struct element* e = hashtab_find(s,key,len);
	if(e && e->key) {	
		PROFILE_HASH_DELETE(s);
		free(e->key);/*FIXME: any way to shut up warnings here? if I make key char*, I get tons of warnings in entitylist.h */
		e->key = DELETED_KEY;
		s->used--;
	}
}

void hashtab_clear(struct hashtable *s)
{
	size_t i;
	PROFILE_HASH_CLEAR(s);
	for(i=0;i < s->capacity;i++) {
		if(s->htable[i].key && s->htable[i].key != DELETED_KEY)
			free(s->htable[i].key);/*FIXME: shut up warnings */
	}
	memset(s->htable, 0, s->capacity);
	s->used = 0;
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
			printf("\t{NULL, 0},\n");
		else if(e->key == DELETED_KEY)
			printf("\t{DELETED_KEY,0},\n");
		else
			printf("\t{(const unsigned char*)\"%s\", %ld},\n", e->key, e->data);
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
		unsigned char l[1024];
		int val;
		sscanf(line,"%d %1023s",&val,l);
		hashtab_insert(s,l,strlen((const char*)l),val);
	}
	return CL_SUCCESS;
}


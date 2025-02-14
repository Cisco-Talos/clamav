/*
 *  Copyright (C) 2013-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
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
#include <stdbool.h>

#include "clamav.h"
#include "clamav-config.h"
#include "mpool.h"

/******************************************************************************/
/* A hash table.
 *
 * There are two types:
 * 1. hashtable:
 *    The key is a const char* (string)
 *    The value (data) is a buffer, stored as a size_t (instead of a void *) and an offset.
 *
 * 2. htu32 (hashtable uint32_t)
 *    Th ekey is a uint32_t number
 *    The value (data) is a buffer, stored as either a size_t, or as a void *, and an offset.
 */
/******************************************************************************/

typedef size_t cli_element_data;

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
struct cli_element {
    const char *key;
    cli_element_data data;
    size_t len;
};

struct cli_hashtable {
    struct cli_element *htable;
    size_t capacity;
    size_t used;
    size_t maxfill; /* 80% */

    STRUCT_PROFILE
};

/**
 * @brief Generate C source code that represents the given hash table
 *
 * Comment: We don't really use this.
 *
 * @param s
 * @param name Some string name for the elements of this generated table.
 * @return cl_error_t
 */
cl_error_t cli_hashtab_generate_c(const struct cli_hashtable *s, const char *name);

struct cli_element *cli_hashtab_find(const struct cli_hashtable *s, const char *key, const size_t len);

/**
 * @brief Create a new hashtab with a given capacity.
 *
 * @param s
 * @param capacity
 * @return cl_error_t
 */
cl_error_t cli_hashtab_init(struct cli_hashtable *s, size_t capacity);

/**
 * @brief Insert a new key with data into the hashtable.
 *
 * @param s
 * @param key
 * @param len
 * @param data
 * @return const struct cli_element*
 */
const struct cli_element *cli_hashtab_insert(struct cli_hashtable *s, const char *key, const size_t len, const cli_element_data data);

/**
 * @brief Delete a key from the hash table
 *
 * @param s
 * @param key
 * @param len
 */
void cli_hashtab_delete(struct cli_hashtable *s, const char *key, const size_t len);

/**
 * @brief Remove all keys from the hashtable
 *
 * @param s
 */
void cli_hashtab_clear(struct cli_hashtable *s);

/**
 * @brief Free the hash table
 *
 * This will clear the hash table first. You don't need to clear it manually first.
 *
 * @param s
 */
void cli_hashtab_free(struct cli_hashtable *s);

/**
 * @brief Load a hash table from a file. (unpickle!)
 *
 * @param in
 * @param s
 * @return cl_error_t
 */
cl_error_t cli_hashtab_load(FILE *in, struct cli_hashtable *s);

/**
 * @brief Write a hash table to a file. (pickle!)
 *
 * @param s
 * @param out
 * @return cl_error_t
 */
cl_error_t cli_hashtab_store(const struct cli_hashtable *s, FILE *out);

struct cli_htu32_element {
    uint32_t key;
    union {
        size_t as_size_t;
        void *as_ptr;
    } data;
};

struct cli_htu32 {
    struct cli_htu32_element *htable;
    size_t capacity;
    size_t used;
    size_t maxfill; /* 80% */

    STRUCT_PROFILE
};

#ifdef USE_MPOOL

/**
 * @brief A macro to wrap cli_htu32_init() where you can assume MEMPOOL is enabled,
 * but will replace the last partment with NULL if MEMPOOL is not enabled.
 */
#define CLI_HTU32_INIT(A, B, C) cli_htu32_init(A, B, C)
/**
 * @brief A macro to wrap cli_htu32_insert() where you can assume MEMPOOL is enabled,
 * but will replace the last partment with NULL if MEMPOOL is not enabled.
 */
#define CLI_HTU32_INSERT(A, B, C) cli_htu32_insert(A, B, C)
/**
 * @brief A macro to wrap cli_htu32_free() where you can assume MEMPOOL is enabled,
 * but will replace the last partment with NULL if MEMPOOL is not enabled.
 */
#define CLI_HTU32_FREE(A, B) cli_htu32_free(A, B)

#else

/**
 * @brief A macro to wrap cli_htu32_init() where you can assume MEMPOOL is enabled,
 * but will replace the last partment with NULL if MEMPOOL is not enabled.
 */
#define CLI_HTU32_INIT(A, B, C) cli_htu32_init(A, B, NULL)
/**
 * @brief A macro to wrap cli_htu32_insert() where you can assume MEMPOOL is enabled,
 * but will replace the last partment with NULL if MEMPOOL is not enabled.
 */
#define CLI_HTU32_INSERT(A, B, C) cli_htu32_insert(A, B, NULL)
/**
 * @brief A macro to wrap cli_htu32_free() where you can assume MEMPOOL is enabled,
 * but will replace the last partment with NULL if MEMPOOL is not enabled.
 */
#define CLI_HTU32_FREE(A, B) cli_htu32_free(A, NULL)

#endif

/**
 * @brief Initialize a new u32 hashtable.
 *
 * @param s
 * @param capacity
 * @param mempool   If MEMPOOL not enabled, this can be NULL.
 * @return cl_error_t
 */
cl_error_t cli_htu32_init(struct cli_htu32 *s, size_t capacity, mpool_t *mempool);

/**
 * @brief Insert a new element into the u32 hashtable.
 *
 * @param s
 * @param item
 * @param mempool
 * @return cl_error_t
 */
cl_error_t cli_htu32_insert(struct cli_htu32 *s, const struct cli_htu32_element *item, mpool_t *mempool);

/**
 * @brief Free the u32 hashtable.
 *
 * This will clear the hash table first. You don't need to clear it manually first.
 *
 * @param s
 * @param mempool
 */
void cli_htu32_free(struct cli_htu32 *s, mpool_t *mempool);

/**
 * @brief Find a specific element by key in the u32 hashtable.
 *
 * @param s
 * @param key
 * @return const struct cli_htu32_element*
 */
const struct cli_htu32_element *cli_htu32_find(const struct cli_htu32 *s, uint32_t key);

/**
 * @brief Remove a specific element from the u32 hashtable.
 *
 * @param s
 * @param key
 */
void cli_htu32_delete(struct cli_htu32 *s, uint32_t key);

/**
 * @brief Remove all elements from the u32 hashtable.
 *
 * @param s
 */
void cli_htu32_clear(struct cli_htu32 *s);

/**
 * @brief Get the next element in the table, following the provided element
 *
 * Use this to enumerate the table linearly.
 *
 * @param s
 * @param current  If you feed it NULL, it will give you the first element.
 * @return const struct cli_htu32_element* Will return the next element, or NULL if there are no further elements.
 */
const struct cli_htu32_element *cli_htu32_next(const struct cli_htu32 *s, const struct cli_htu32_element *current);

/**
 * @brief Get the number of items in the u32 hashtable.
 *
 * @param s
 * @return size_t
 */
size_t cli_htu32_numitems(struct cli_htu32 *s);

/******************************************************************************/
/* a hashtable that stores the values too */
/******************************************************************************/

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

/**
 * @brief Initialize a new map
 *
 * @param m
 * @param keysize
 * @param valuesize
 * @param capacity
 * @return cl_error_t CL_SUCCESS on success
 * @return cl_error_t CL_E* if some error occurred
 */
cl_error_t cli_map_init(struct cli_map *m, int32_t keysize, int32_t valuesize,
                        int32_t capacity);

/**
 * @brief add key to the map
 *
 * @param m
 * @param key
 * @param keysize
 * @return cl_error_t CL_SUCCESS if added.
 * @return cl_error_t CL_ECREAT if already present.
 * @return cl_error_t CL_E* if some error occurred.
 */
cl_error_t cli_map_addkey(struct cli_map *m, const void *key, int32_t keysize);

/**
 * @brief remove key from the map
 *
 * @param m
 * @param key
 * @param keysize
 * @return cl_error_t CL_SUCCESS if removed.
 * @return cl_error_t CL_EUNLINK if not present, so didn't need to be removed.
 * @return cl_error_t CL_E* if some error occurred.
 */
cl_error_t cli_map_removekey(struct cli_map *m, const void *key, int32_t keysize);

/**
 * @brief set the value for the last inserted key with map_addkey
 *
 * @param m
 * @param value
 * @param valuesize
 * @return cl_error_t CL_SUCCESS on success
 * @return cl_error_t CL_E* if some error occurred
 */
cl_error_t cli_map_setvalue(struct cli_map *m, const void *value, int32_t valuesize);

/**
 * @brief find key in the map
 *
 * @param m
 * @param key
 * @param keysize
 * @return cl_error_t CL_SUCCESS if found
 * @return cl_error_t CL_EACCES if NOT found
 * @return cl_error_t CL_E* if some error occurred.
 */
cl_error_t cli_map_find(struct cli_map *m, const void *key, int32_t keysize);

/**
 * @brief get the size of value obtained during the last map_find
 *
 * @param m
 * @return int the value size on success
 * @return int -1 on failure
 */
int cli_map_getvalue_size(struct cli_map *m);

/**
 * @brief get the value obtained during the last map_find
 *
 * @param m
 * @return void* the value on success
 * @return void* NULL on failure
 */
void *cli_map_getvalue(struct cli_map *m);

/**
 * @brief delete the map
 *
 * @param m
 */
void cli_map_delete(struct cli_map *m);

/******************************************************************************/
/* A set of unique keys (no values).
 * The keys are just uint32_t numbers. */
/******************************************************************************/

struct cli_hashset {
    uint32_t *keys;
    uint32_t *bitmap;
    mpool_t *mempool;
    uint32_t capacity;
    uint32_t mask;
    uint32_t count;
    uint32_t limit;
};

/**
 * @brief Initialize hashset.
 *
 * When capacity * (load_factor/100) is reached, the hashset is growed.
 *
 * @param hs
 * @param initial_capacity  is rounded to nearest power of 2.
 * @param load_factor       is between 50 and 99.
 * @return cl_error_t
 */
cl_error_t cli_hashset_init(struct cli_hashset *hs, size_t initial_capacity, uint8_t load_factor);

/**
 * @brief Initialize hashset using the clamav MEMPOOL instead of just malloc/realloc.
 *
 * Comment: not presently used in any parsers or signature loaders or anything.
 *
 * @param hs
 * @param initial_capacity  is rounded to nearest power of 2.
 * @param load_factor       is between 50 and 99.
 * @param mempool           the mempool
 * @return cl_error_t
 */
cl_error_t cli_hashset_init_pool(struct cli_hashset *hs, size_t initial_capacity, uint8_t load_factor, mpool_t *mempool);

/**
 * @brief Add a key to the hashset.
 *
 * @param hs
 * @param key
 * @return cl_error_t
 */
cl_error_t cli_hashset_addkey(struct cli_hashset *hs, const uint32_t key);

/**
 * @brief Remove a key from the hashset
 *
 * @param hs
 * @param key
 * @return cl_error_t
 */
cl_error_t cli_hashset_removekey(struct cli_hashset *hs, const uint32_t key);

/**
 * @brief Find out if hashset contains akey
 *
 * @param hs
 * @param key
 * @return true  If found
 * @return false If not found
 */
bool cli_hashset_contains(const struct cli_hashset *hs, const uint32_t key);

/**
 * @brief Destroy/deallocate a hashset.
 *
 * @param hs
 */
void cli_hashset_destroy(struct cli_hashset *hs);

/**
 * @brief Convert the hashset to an array of uint32_t's
 *
 * It will allocate a 0-length array! You are still responsible for freeing it if
 * it returns 0!
 *
 * You don't need to free anything if it returns -1.
 *
 * @param hs
 * @param [out] array  Allocated array of the length returned. Caller must free it.
 * @return ssize_t     The length of the array if success, or else -1 if failed.
 */
ssize_t cli_hashset_toarray(const struct cli_hashset *hs, uint32_t **array);

/**
 * @brief Initializes the set without allocating memory
 *
 * Initializes the set without allocating memory, you can do lookups on it
 * using _contains_maybe_noalloc. You need to initialize it using _init
 * before using _addkey or _removekey though
 *
 * @param hs
 */
void cli_hashset_init_noalloc(struct cli_hashset *hs);

/**
 * @brief
 *
 * this works like cli_hashset_contains (above), except that the hashset may
 * have not been initialized by _init, only by _init_noalloc
 *
 * @param hs
 * @param key
 * @return true  If found
 * @return false If not found
 */
bool cli_hashset_contains_maybe_noalloc(const struct cli_hashset *hs, const uint32_t key);

#endif

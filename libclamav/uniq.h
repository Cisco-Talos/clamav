/*
 *  md5 based hashtab
 *
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2008-2013 Sourcefire, Inc.
 *
 *  Authors: aCaB <acab@clamav.net>
 *
 *  Uniq implements a structure that stores the count of duplicate items.
 *  The count can be retrieved by item name (if you know it).
 *  Additionally, you can retrieve the ascii md5 hash at the same time.
 *
 *  This is essentially a tiny hash table of hashes.
 *  The hashes are in an array instead of dynamically added.
 *  This is faster than alloc'ing for each unique item added, *  but means a max # of unique items must be defined at init.
 *
 *  Example where:
 *   items = 6
 *   max_unique_items = 5
 *   cur_unique_items = 4
 *   md5 #1 has been added 3 times
 *   Two md5's start with the same 2 bytes (#0 and #3)
 *
 *    idx:
 *      -00--01--02--03--04--05--06--07-...
 *      | 0 | 0 | 0 | 2 | 1 | 0 | 0 | ...
 *      ------------------------------...
 *
 *    md5s:
 *      ------------------------------
 *   0  | next:  Address of #3
 *      | count: 1
 *      | md5:   0x01,0x98,0x23,0xa8,0xfd,...
 *      | name:  "019823a8fd..."
 *      ------------------------------
 *   1  | next:  NULL
 *      | count: 3
 *      | md5:   0x03,0x98,0x23,0xa8,0xfd,...
 *      | name:  "019823a8fd..."
 *      ------------------------------
 *   2  | next:  NULL
 *      | count: 1
 *      | md5:   0x01,0x98,0x23,0xa8,0xfd,...
 *      | name:  "019823a8fd..."
 *      ------------------------------
 *   3  | next:  NULL
 *      | count: 1
 *      | md5:   0x01,0xdd,0x2f,0x87,0x6a,...
 *      | name:  "01dd2f876a..."
 *      ------------------------------
 *   4  | next:  NULL
 *      | count: 0
 *      | md5:   0x00,0x00,0x00,0x00,0x00,...
 *      | name:  "\0\0\0\0\0..."
 *      ------------------------------
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

#ifndef _UNIQ_H
#define _UNIQ_H

#include "clamav.h"
#include "clamav-types.h"

/**
 * @brief Store the count of each unique item.
 *
 * These elements are allocated as an array in struct uniq, but they are also
 * linked together using the `next` pointers to form impromptu buckets,
 * categorized using the first two bytes of each md5.
 */
struct UNIQMD5 {
    struct UNIQMD5 *next; /**< Pointer to next UNIQMD5 where the first two bytes are the same. */
    uint32_t count;       /**< Number of times this item has been added. (# duplicates). */
    uint8_t md5[16];      /**< Binary md5 hash of the item. */
    char name[33];        /**< Ascii md5 hash of the item. */
};

/**
 * @brief The main Uniq store structure.
 *
 * Includes array of uniq md5 hashes, and an index table to optimize searches
 * into the hash array, categorized by the first two bytes of the md5.
 */
struct uniq {
    struct UNIQMD5 *md5s;      /**< Array of UNIQMD5 structs. */
    uint32_t items;            /**< Total # of items added (including duplicates) */
    uint32_t cur_unique_items; /**< The # of md5s currently stored in the array. */
    uint32_t max_unique_items; /**< The # of md5s that can be stored the array. */
    uint32_t idx[256];         /**< Array of indices into the md5s array.
                                    Each index represents a linked-list of md5s
                                    sharing the common trait that the first two
                                    bytes are the same. */
};

/**
 * @brief Initialize a Uniq store to count the number of uniq string items.
 *
 * The Uniq store must be free'd with uniq_free().
 * uniq_add()'s will fail if they exceed the number of unique strings initialized with count.
 *
 * @param count         The max number of unique string items that may be added.
 * @return struct uniq* A pointer to the Uniq store object. Will return NULL on failure.
 */
struct uniq *uniq_init(uint32_t);

/**
 * @brief Free the Uniq store and associated memory.
 */
void uniq_free(struct uniq *);

/**
 * @brief Add to the uniq (item md5) count.
 *
 * Adds an item to the list of known items.
 * Increments the count if the item has been seen before.
 * The optional rhash pointer will be valid until `uniq_free()` is called.
 *
 * @param U             The Uniq count store.
 * @param item          (optional) The item to hash and count.
 * @param item_len      The length, in bytes, of the item. May be 0.
 * @param[out] rhash    (optional) A pointer to the item's md5 hash (in ascii).
 * @param[out] count    (optional) The number of times this unique item has been added.
 * @return cl_error_t   CL_SUCCESS if successful, else an error code.
 */
cl_error_t uniq_add(struct uniq *U, const char *item, uint32_t, char **rhash, uint32_t *count);

/**
 * @brief Retrieve the number of times an item has been added to the Uniq count store.
 *
 * The optional rhash pointer will be valid until `uniq_free()` is called.
 *
 * @param U             The Uniq count store.
 * @param item          (optional) The item to hash and count.
 * @param item_len      The length, in bytes, of the item. May be 0.
 * @param[out] rhash    (optional) A pointer to the item's md5 hash (in ascii).
 * @param[out] count    The number of times this unique item has been added.
 * @return cl_error_t   CL_SUCCESS if successful, else an error code.
 */
cl_error_t uniq_get(struct uniq *U, const char *item, uint32_t, char **rhash, uint32_t *count);


#endif

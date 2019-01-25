/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2010-2013 Sourcefire, Inc.
 *
 *  Authors: aCaB
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

#include "matcher.h"
#include "others.h"
#include "str.h"


int hm_addhash_str(struct cli_matcher *root, const char *strhash, uint32_t size, const char *virusname) {
    enum CLI_HASH_TYPE type;
    char binhash[CLI_HASHLEN_MAX];
    int hlen;

    if(!root || !strhash) {
	cli_errmsg("hm_addhash_str: NULL root or hash\n");
	return CL_ENULLARG;
    }

    /* size 0 here is now a wildcard size match */
    if(size == (uint32_t)-1) {
	cli_errmsg("hm_addhash_str: null or invalid size (%u)\n", size);
	return CL_EARG;
    }

    hlen = strlen(strhash);
    switch(hlen) {
    case 32:
	type = CLI_HASH_MD5;
	break;
    case 40:
	type = CLI_HASH_SHA1;
	break;
    case 64:
	type = CLI_HASH_SHA256;
	break;
    default:
	cli_errmsg("hm_addhash_str: invalid hash %s -- FIXME!\n", strhash);
	return CL_EARG;
    }
    if(cli_hex2str_to(strhash, (char *)binhash, hlen)) {
	cli_errmsg("hm_addhash_str: invalid hash %s\n", strhash);
	return CL_EARG;
    }

    return hm_addhash_bin(root, binhash, type, size, virusname);
}

const unsigned int hashlen[] = {
    CLI_HASHLEN_MD5,
    CLI_HASHLEN_SHA1,
    CLI_HASHLEN_SHA256
};

int hm_addhash_bin(struct cli_matcher *root, const void *binhash, enum CLI_HASH_TYPE type, uint32_t size, const char *virusname) {
    const unsigned int hlen = hashlen[type];
    const struct cli_htu32_element *item;
    struct cli_sz_hash *szh;
    struct cli_htu32 *ht;
    int i;

    if (size) {
        /* size non-zero, find sz_hash element in size-driven hashtable  */
        ht = &root->hm.sizehashes[type];
        if(!root->hm.sizehashes[type].capacity) {
            i = cli_htu32_init(ht, 64, root->mempool);
            if(i) return i;
        }

        item = cli_htu32_find(ht, size);
        if(!item) {
	    struct cli_htu32_element htitem;
	    szh = mpool_calloc(root->mempool, 1, sizeof(*szh));
	    if(!szh) {
	        cli_errmsg("hm_addhash_bin: failed to allocate size hash\n");
	        return CL_EMEM;
	    }

	    htitem.key = size;
	    htitem.data.as_ptr = szh;
	    i = cli_htu32_insert(ht, &htitem, root->mempool);
	    if(i) {
	        cli_errmsg("hm_addhash_bin: failed to add item to hashtab");
	        mpool_free(root->mempool, szh);
	        return i;
	    }
        } else
	    szh = (struct cli_sz_hash *)item->data.as_ptr;
    }
    else {
        /* size 0 = wildcard */
        szh = &root->hwild.hashes[type];
    }
    szh->items++;

    szh->hash_array = mpool_realloc2(root->mempool, szh->hash_array, hlen * szh->items);
    if(!szh->hash_array) {
	cli_errmsg("hm_addhash_bin: failed to grow hash array to %u entries\n", szh->items);
	szh->items=0;
	mpool_free(root->mempool, szh->virusnames);
	szh->virusnames = NULL;
	return CL_EMEM;
    }

    szh->virusnames = mpool_realloc2(root->mempool, szh->virusnames, sizeof(*szh->virusnames) * szh->items);
    if(!szh->virusnames) {
	cli_errmsg("hm_addhash_bin: failed to grow virusname array to %u entries\n", szh->items);
	szh->items=0;
	mpool_free(root->mempool, szh->hash_array);
	szh->hash_array = NULL;
	return CL_EMEM;
    }

    memcpy(&szh->hash_array[(szh->items-1) * hlen], binhash, hlen);
    szh->virusnames[(szh->items-1)] = virusname;
    
    return 0;
}

static inline int hm_cmp(const uint8_t *itm, const uint8_t *ref, unsigned int keylen) {
#if WORDS_BIGENDIAN == 0
    uint32_t i = *(uint32_t *)itm, r = *(uint32_t *)ref;
    if(i!=r)
	return (i<r) * 2 -1;
    return memcmp(&itm[4], &ref[4], keylen - 4);
#else
    return memcmp(itm, ref, keylen);
#endif
}

static void hm_sort(struct cli_sz_hash *szh, size_t l, size_t r, unsigned int keylen) {
    uint8_t piv[CLI_HASHLEN_MAX], tmph[CLI_HASHLEN_MAX];
    size_t l1, r1;

    const char *tmpv;

    if(l + 1 >= r)
	return;

    l1 = l+1, r1 = r;

    memcpy(piv, &szh->hash_array[keylen * l], keylen);
    while(l1 < r1) {
	if(hm_cmp(&szh->hash_array[keylen * l1], piv, keylen) > 0) {
	    r1--;
	    if(l1 == r1) break;
	    memcpy(tmph, &szh->hash_array[keylen * l1], keylen);
	    tmpv = szh->virusnames[l1];
	    memcpy(&szh->hash_array[keylen * l1], &szh->hash_array[keylen * r1], keylen);
	    szh->virusnames[l1] = szh->virusnames[r1];
	    memcpy(&szh->hash_array[keylen * r1], tmph, keylen);
	    szh->virusnames[r1] = tmpv;
	} else
	    l1++;
    }

    l1--;
    if(l1!=l) {
	memcpy(tmph, &szh->hash_array[keylen * l1], keylen);
	tmpv = szh->virusnames[l1];
	memcpy(&szh->hash_array[keylen * l1], &szh->hash_array[keylen * l], keylen);
	szh->virusnames[l1] = szh->virusnames[l];
	memcpy(&szh->hash_array[keylen * l], tmph, keylen);
	szh->virusnames[l] = tmpv;
    }

    hm_sort(szh, l, l1, keylen);
    hm_sort(szh, r1, r, keylen);
}

/* flush both size-specific and agnostic hash sets */
void hm_flush(struct cli_matcher *root) {
    enum CLI_HASH_TYPE type;
    unsigned int keylen;
    struct cli_sz_hash *szh;

    if(!root)
	return;

    for(type = CLI_HASH_MD5; type < CLI_HASH_AVAIL_TYPES; type++) {
	struct cli_htu32 *ht = &root->hm.sizehashes[type];
	const struct cli_htu32_element *item = NULL;
	szh = NULL;

	if(!root->hm.sizehashes[type].capacity)
	    continue;

	while((item = cli_htu32_next(ht, item))) {
	    szh = (struct cli_sz_hash *)item->data.as_ptr;
	    keylen = hashlen[type];

	    if(szh->items > 1)
		hm_sort(szh, 0, szh->items, keylen);
	}
    }

    for(type = CLI_HASH_MD5; type < CLI_HASH_AVAIL_TYPES; type++) {
	szh = &root->hwild.hashes[type];
	keylen = hashlen[type];

	if(szh->items > 1)
	    hm_sort(szh, 0, szh->items, keylen);
    }
}


int cli_hm_have_size(const struct cli_matcher *root, enum CLI_HASH_TYPE type, uint32_t size) {
    return (size && size != 0xffffffff && root && root->hm.sizehashes[type].capacity && cli_htu32_find(&root->hm.sizehashes[type], size));
}

int cli_hm_have_wild(const struct cli_matcher *root, enum CLI_HASH_TYPE type) {
    return (root && root->hwild.hashes[type].items);
}

int cli_hm_have_any(const struct cli_matcher *root, enum CLI_HASH_TYPE type) {
    return (root && (root->hwild.hashes[type].items || root->hm.sizehashes[type].capacity));
}

/* cli_hm_scan will scan only size-specific hashes, if any */
static int hm_scan(const unsigned char *digest, const char **virname, const struct cli_sz_hash *szh, enum CLI_HASH_TYPE type) {
    unsigned int keylen;
    size_t l, r;

    if(!digest || !szh || !szh->items)
	return CL_CLEAN;

    keylen = hashlen[type];

    l = 0;
    r = szh->items - 1;
    while(l <= r) {
	size_t c = (l + r) / 2;
	int res = hm_cmp(digest, &szh->hash_array[keylen * c], keylen);

	if(res < 0) {
	    if(!c)
		break;
	    r = c - 1;
	} else if(res > 0)
	    l = c + 1;
	else {
	    if(virname)
		*virname = szh->virusnames[c];
	    return CL_VIRUS;
	}
    }
    return CL_CLEAN;
}

/* cli_hm_scan will scan only size-specific hashes, if any */
int cli_hm_scan(const unsigned char *digest, uint32_t size, const char **virname, const struct cli_matcher *root, enum CLI_HASH_TYPE type) {
    const struct cli_htu32_element *item;
    struct cli_sz_hash *szh;

    if(!digest || !size || size == 0xffffffff || !root || !root->hm.sizehashes[type].capacity)
	return CL_CLEAN;

    item = cli_htu32_find(&root->hm.sizehashes[type], size);
    if(!item)
	return CL_CLEAN;

    szh = (struct cli_sz_hash *)item->data.as_ptr;

    return hm_scan(digest, virname, szh, type);
}

/* cli_hm_scan_wild will scan only size-agnostic hashes, if any */
int cli_hm_scan_wild(const unsigned char *digest, const char **virname, const struct cli_matcher *root, enum CLI_HASH_TYPE type) {
    if(!digest || !root || !root->hwild.hashes[type].items)
	return CL_CLEAN;

    return hm_scan(digest, virname, &root->hwild.hashes[type], type);
}

/* free both size-specific and agnostic hash sets */
void hm_free(struct cli_matcher *root) {
    enum CLI_HASH_TYPE type;

    if(!root)
	return;

    for(type = CLI_HASH_MD5; type < CLI_HASH_AVAIL_TYPES; type++) {
	struct cli_htu32 *ht = &root->hm.sizehashes[type];
	const struct cli_htu32_element *item = NULL;

	if(!root->hm.sizehashes[type].capacity)
	    continue;

	while((item = cli_htu32_next(ht, item))) {
	    struct cli_sz_hash *szh = (struct cli_sz_hash *)item->data.as_ptr;

	    mpool_free(root->mempool, szh->hash_array);
	    while(szh->items)
		mpool_free(root->mempool, (void *)szh->virusnames[--szh->items]);
	    mpool_free(root->mempool, szh->virusnames);
	    mpool_free(root->mempool, szh);
	}
	cli_htu32_free(ht, root->mempool);
    }

    for(type = CLI_HASH_MD5; type < CLI_HASH_AVAIL_TYPES; type++) {
	struct cli_sz_hash *szh = &root->hwild.hashes[type];

	if(!szh->items)
	    continue;

	mpool_free(root->mempool, szh->hash_array);
	while(szh->items)
	    mpool_free(root->mempool, (void *)szh->virusnames[--szh->items]);
	mpool_free(root->mempool, szh->virusnames);
    }
}


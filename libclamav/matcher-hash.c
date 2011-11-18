/*
 *  Copyright (C) 2010 Sourcefire, Inc.
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

#include "matcher.h"
#include "others.h"
#include "str.h"

#include <string.h>
#include <stdlib.h>


int hm_addhash(struct cli_matcher *root, const char *hash, uint32_t size, const char *virusname) {
    const struct cli_htu32_element *item;
    struct cli_sz_hash *szh;
    struct cli_htu32 *ht;
    enum CLI_HASH_TYPE type;
    uint8_t binhash[32];
    int hashlen, i;

    if(!root || !hash) {
	cli_errmsg("hm_addhash: NULL root or hash\n");
	return CL_ENULLARG;
    }

    if(!size || size == (uint32_t)-1) {
	cli_errmsg("hm_addhash: null or invalid size (%u)\n", size);
	return CL_EARG;
    }

    hashlen = strlen(hash);
    switch(hashlen) {
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
	cli_errmsg("hm_addhash: invalid hash %s -- FIXME!\n", hash);
	return CL_EARG;
    }
    if(cli_hex2str_to(hash, (char *)binhash, hashlen)) {
	cli_errmsg("hm_addhash: invalid hash %s\n", hash);
	return CL_EARG;
    }

    hashlen /= 2;
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
	    cli_errmsg("hm_addhash: failed to allocate size hash\n");
	    return CL_EMEM;
	}

	htitem.key = size;
	htitem.data.as_ptr = szh;
	i = cli_htu32_insert(ht, &htitem, root->mempool);
	if(i) {
	    cli_errmsg("ht_addhash: failed to add item to hashtab");
	    mpool_free(root->mempool, szh);
	    return i;
	}
    } else
	szh = (struct cli_sz_hash *)item->data.as_ptr;

    szh->items++;

    szh->hash_array = mpool_realloc2(root->mempool, szh->hash_array, hashlen * szh->items);
    if(!szh->hash_array) {
	cli_errmsg("ht_add: failed to grow hash array to %u entries\n", szh->items);
	szh->items=0;
	mpool_free(root->mempool, szh->virusnames);
	szh->virusnames = NULL;
	return CL_EMEM;
    }

    szh->virusnames = mpool_realloc2(root->mempool, szh->virusnames, sizeof(*szh->virusnames) * szh->items);
    if(!szh->virusnames) {
	cli_errmsg("ht_add: failed to grow virusname array to %u entries\n", szh->items);
	szh->items=0;
	mpool_free(root->mempool, szh->hash_array);
	szh->hash_array = NULL;
	return CL_EMEM;
    }

    memcpy(&szh->hash_array[(szh->items-1) * hashlen], binhash, hashlen);
    szh->virusnames[(szh->items-1)] = virusname;
    
    return 0;
}



static const unsigned int hashlen[] = {
    16, /* CLI_HASH_MD5 */
    20, /* CLI_HASH_SHA1 */
    32, /* CLI_HASH_SHA256 */
};


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
    uint8_t piv[32], tmph[32];
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


void hm_flush(struct cli_matcher *root) {
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
	    unsigned int keylen = hashlen[type];

	    if(szh->items > 1)
		hm_sort(szh, 0, szh->items, keylen);
	}
    }
}


int cli_hm_have_size(const struct cli_matcher *root, enum CLI_HASH_TYPE type, uint32_t size) {
    return (size && size != 0xffffffff && root && root->hm.sizehashes[type].capacity && cli_htu32_find(&root->hm.sizehashes[type], size));
}

int cli_hm_scan(const unsigned char *digest, uint32_t size, const char **virname, const struct cli_matcher *root, enum CLI_HASH_TYPE type) {
    const struct cli_htu32_element *item;
    unsigned int keylen;
    struct cli_sz_hash *szh;
    size_t l, r;

    if(!digest || !size || size == 0xffffffff || !root || !root->hm.sizehashes[type].capacity)
	return CL_CLEAN;

    item = cli_htu32_find(&root->hm.sizehashes[type], size);
    if(!item)
	return CL_CLEAN;

    szh = (struct cli_sz_hash *)item->data.as_ptr;
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
	    unsigned int keylen = hashlen[type];

	    mpool_free(root->mempool, szh->hash_array);
	    while(szh->items)
		mpool_free(root->mempool, (void *)szh->virusnames[--szh->items]);
	    mpool_free(root->mempool, szh->virusnames);
	    mpool_free(root->mempool, szh);
	}
	cli_htu32_free(ht, root->mempool);
    }
}


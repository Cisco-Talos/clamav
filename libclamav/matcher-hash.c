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
    uint8_t binhash[32 + 4];
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
    *(uint32_t *)&binhash[hashlen] = size;
    hashlen += 4;
    szh = &root->hm.sizehashes[type][*binhash % HM_NUM_ENTRIES];

    if(szh->items == szh->max) {
	if(!szh->max)
	    szh->max = 1;
	else
	    szh->max += 1 + szh->max / 2;

	//szh->hash_array = mpool_realloc2(root->mempool, szh->hash_array, hashlen * szh->max);
	szh->hash_array = realloc(szh->hash_array, hashlen * szh->max);
	if(!szh->hash_array) {
	    cli_errmsg("ht_add: failed to grow hash array to %u entries\n", szh->max);
	    return CL_EMEM;
	}

	//szh->virusnames = mpool_realloc2(root->mempool, szh->virusnames, sizeof(*szh->virusnames) * szh->max);
	szh->virusnames = realloc(szh->virusnames, sizeof(*szh->virusnames) * szh->max);
	if(!szh->virusnames) {
	    cli_errmsg("ht_add: failed to grow virusname array to %u entries\n", szh->max);
	    return CL_EMEM;
	}
    }

    memcpy(&szh->hash_array[szh->items * hashlen], binhash, hashlen);
    szh->virusnames[szh->items] = virusname;
    szh->items++;

    return 0;
}



static const unsigned int hashlen[] = {
    16 + 4, /* CLI_HASH_MD5 */
    20 + 4, /* CLI_HASH_SHA1 */
    32 + 4, /* CLI_HASH_SHA256 */
};


static inline int hm_cmp(const uint8_t *itm, const uint8_t *ref, unsigned int keylen) {
    uint32_t i = *(uint32_t *)itm, r = *(uint32_t *)ref;
    if(i!=r)
	return (i<r) * 2 -1;
    return memcmp(&itm[4], &ref[4], keylen - 4);
}

void hm_sort(struct cli_sz_hash *szh, size_t l, size_t r, unsigned int keylen) {
    uint8_t piv[32 + 4], tmph[32 + 4];
    size_t l1, r1;

    const char *tmpv;

    if(l + 1 >= r)
	return;

    l1 = l+1, r1 = r;

    memcpy(piv, &szh->hash_array[keylen * l], keylen);
    while(l1 < r1) {
	if(hm_cmp(&szh->hash_array[keylen * l1], piv, keylen) > 0) {
	    r1--;
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
	int i;
	for(i=0; i<HM_NUM_ENTRIES; i++) {
	    struct cli_sz_hash *szh = szh = &root->hm.sizehashes[type][i];
	    unsigned int keylen = hashlen[type];
	    //cli_errmsg("type %u - entry %u => %u items\n", type, i, szh->items);

	    if(szh->items != szh->max) {
		void *p;
		//p = mpool_realloc(root->mempool, szh->hash_array, keylen * szh->items);
		p = realloc(szh->hash_array, keylen * szh->items);
		if(p) szh->hash_array = p;
		//p = mpool_realloc(root->mempool, szh->virusnames, sizeof(*szh->virusnames) * szh->items);
		p = realloc(szh->virusnames, sizeof(*szh->virusnames) * szh->items);
		if(p) szh->virusnames = p;
		szh->max = szh->items;
	    }
	    if(szh->items > 1)
		hm_sort(szh, 0, szh->items, keylen);
	}
    }
}


int cli_hm_have_size(const struct cli_matcher *root, enum CLI_HASH_TYPE type, uint32_t size) {
    return 1;
}

int cli_hm_scan(const unsigned char *digest, uint32_t size, const char **virname, const struct cli_matcher *root, enum CLI_HASH_TYPE type) {
    unsigned int keylen;
    struct cli_sz_hash *szh;
    uint8_t tmph[32 + 4];
    size_t l, r;

    if(!digest || !size || size == 0xffffffff || !root)
	return CL_CLEAN;

    szh = &root->hm.sizehashes[type][*digest % HM_NUM_ENTRIES];
    if(!szh->items)
	return CL_CLEAN;

    keylen = hashlen[type];
    memcpy(tmph, digest, keylen - 4);
    *(uint32_t *)&tmph[keylen - 4] = size;

    l = 0;
    r = szh->items;
    while(l <= r) {
	size_t c = (l + r) / 2;
	int res = hm_cmp(tmph, &szh->hash_array[keylen * c], keylen);

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

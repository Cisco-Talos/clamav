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

int hm_addhash(struct cli_matcher *root, const char *hash, uint32_t size, const char *virusname) {
    const struct cli_htu32_element *item;
    struct cli_sz_hash *szh;
    struct cli_htu32 *ht;
    enum CLI_HASH_TYPE type;
    uint8_t binhash[64];
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

    ht = &root->hm.sizehashes[type];
    if(!root->hm.htiint[type]) {
	i = cli_htu32_init(ht, 5000, root->mempool);
	if(i) return i;
    }

    item = cli_htu32_find(ht, size);
    if(!item) {
	struct cli_htu32_element htitem;
	szh = mpool_calloc(root->mempool, 1, sizeof(szh));
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

    if(szh->items == szh->max) {
	if(!szh->max)
	    szh->max = 1024;
	else
	    szh->max = szh->max + szh->max / 2;

	szh->hash_array = mpool_realloc2(root->mempool, szh->hash_array, hashlen * szh->max);
	if(!szh->hash_array) {
	    cli_errmsg("ht_add: failed to grow hash array to %u entries\n", szh->max);
	    return CL_EMEM;
	}

	szh->virusnames = mpool_realloc2(root->mempool, szh->hash_array, sizeof(*szh->virusnames) * szh->max);
	if(!szh->virusnames) {
	    cli_errmsg("ht_add: failed to grow virusname array to %u entries\n", szh->max);
	    return CL_EMEM;
	}
    }

    memcpy(&szh->hash_array[szh->items * hashlen], binhash, hashlen / 2);
    szh->virusnames[szh->items] = virusname;
    szh->items++;
    
    return 0;
}

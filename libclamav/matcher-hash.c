/*
 *  Copyright (C) 2013-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
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

const char *cli_hash_name(cli_hash_type_t type)
{
    switch (type) {
        case CLI_HASH_MD5:
            return "md5";
        case CLI_HASH_SHA1:
            return "sha1";
        case CLI_HASH_SHA2_256:
            return "sha2-256";
        case CLI_HASH_SHA2_384:
            return "sha2-384";
        case CLI_HASH_SHA2_512:
            return "sha2-512";
        default:
            return "unknown";
    }
}

const char *to_openssl_alg(const char *alg) {
    cl_error_t ret;
    cli_hash_type_t type;

    ret = cli_hash_type_from_name(alg, &type);
    if (CL_SUCCESS != ret) {
        cli_dbgmsg("to_openssl_alg: unknown hash type %s\n", alg);
        return NULL;
    }

    switch (type) {
        case CLI_HASH_MD5:
            return "md5";
        case CLI_HASH_SHA1:
            return "sha1";
#if OPENSSL_VERSION_MAJOR >= 3
        case CLI_HASH_SHA2_256:
            return "sha2-256";
        case CLI_HASH_SHA2_384:
            return "sha2-384";
        case CLI_HASH_SHA2_512:
            return "sha2-512";
#else
        case CLI_HASH_SHA2_256:
            return "sha256";
        case CLI_HASH_SHA2_384:
            return "sha384";
        case CLI_HASH_SHA2_512:
            return "sha512";
#endif
        default:
            cli_dbgmsg("to_openssl_alg: unknown hash type %d\n", type);
            return NULL; // Unsupported hash type
    }
}

size_t cli_hash_len(cli_hash_type_t type)
{
    switch (type) {
        case CLI_HASH_MD5:
            return MD5_HASH_SIZE;
        case CLI_HASH_SHA1:
            return SHA1_HASH_SIZE;
        case CLI_HASH_SHA2_256:
            return SHA256_HASH_SIZE;
        case CLI_HASH_SHA2_384:
            return SHA384_HASH_SIZE;
        case CLI_HASH_SHA2_512:
            return SHA512_HASH_SIZE;
        default:
            return 0; // Invalid type
    }
}

cl_error_t cli_hash_type_from_name(const char *name, cli_hash_type_t *type_out)
{
    if (!name || !type_out) {
        return CL_ENULLARG;
    }

    if (strcasecmp(name, "md5") == 0) {
        *type_out = CLI_HASH_MD5;
    } else if (strcasecmp(name, "sha1") == 0) {
        *type_out = CLI_HASH_SHA1;
    } else if ((strcasecmp(name, "sha2-256") == 0) || (strcasecmp(name, "sha256") == 0)) {
        *type_out = CLI_HASH_SHA2_256;
    } else if ((strcasecmp(name, "sha2-384") == 0) || (strcasecmp(name, "sha384") == 0)) {
        *type_out = CLI_HASH_SHA2_384;
    } else if ((strcasecmp(name, "sha2-512") == 0) || (strcasecmp(name, "sha512") == 0)) {
        *type_out = CLI_HASH_SHA2_512;
    } else {
        return CL_EARG; // Unknown hash type name
    }

    return CL_SUCCESS;
}

cl_error_t hm_addhash_str(struct cl_engine *engine, hash_purpose_t purpose, const char *strhash, uint32_t size, const char *virusname)
{
    cli_hash_type_t type;
    char binhash[SHA256_HASH_SIZE];
    size_t hlen;

    if (!engine || !strhash) {
        cli_errmsg("hm_addhash_str: NULL engine or hash\n");
        return CL_ENULLARG;
    }

    /* size 0 here is now a wildcard size match */
    if (size == (uint32_t)-1) {
        cli_errmsg("hm_addhash_str: null or invalid size (%u)\n", size);
        return CL_EARG;
    }

    hlen = strlen(strhash);
    switch (hlen) {
        case (MD5_HASH_SIZE * 2):
            type = CLI_HASH_MD5;
            break;
        case (SHA1_HASH_SIZE * 2):
            type = CLI_HASH_SHA1;
            break;
        case (SHA256_HASH_SIZE * 2):
            type = CLI_HASH_SHA2_256;
            break;
        default:
            cli_errmsg("hm_addhash_str: invalid hash %s -- FIXME!\n", strhash);
            return CL_EARG;
    }

    if (cli_hex2str_to(strhash, (char *)binhash, hlen)) {
        cli_errmsg("hm_addhash_str: invalid hash %s\n", strhash);
        return CL_EARG;
    }

    return hm_addhash_bin(engine, purpose, binhash, type, size, virusname);
}

cl_error_t hm_addhash_bin(struct cl_engine *engine, hash_purpose_t purpose, const void *binhash, cli_hash_type_t type, uint32_t size, const char *virusname)
{
    size_t hlen = cli_hash_len(type);
    const struct cli_htu32_element *item;
    struct cli_sz_hash *szh;
    struct cli_htu32 *ht;
    cl_error_t ret;
    struct cli_matcher *root = NULL;

    if (purpose == HASH_PURPOSE_PE_SECTION_DETECT) {
        root = engine->hm_mdb;
    } else if (purpose == HASH_PURPOSE_WHOLE_FILE_DETECT) {
        root = engine->hm_hdb;
    } else if (purpose == HASH_PURPOSE_PE_IMPORT_DETECT) {
        root = engine->hm_imp;
    } else if (purpose == HASH_PURPOSE_WHOLE_FILE_FP_CHECK) {
        if ((type == CLI_HASH_MD5 || type == CLI_HASH_SHA1) &&
            (engine->engine_options & ENGINE_OPTIONS_FIPS_LIMITS)) {
            return CL_SUCCESS; // No error, just skip adding MD5/SHA1 FP hashes in FIPS mode
        }
        root = engine->hm_fp;
    }

    if (NULL == root) {
        if (NULL == (root = MPOOL_CALLOC(engine->mempool, 1, sizeof(*root)))) {
            return CL_EMEM;
        }
#ifdef USE_MPOOL
        root->mempool = engine->mempool;
#endif
        if (purpose == HASH_PURPOSE_WHOLE_FILE_DETECT) {
            engine->hm_hdb = root;
        } else if (purpose == HASH_PURPOSE_PE_SECTION_DETECT) {
            engine->hm_mdb = root;
        } else if (purpose == HASH_PURPOSE_PE_IMPORT_DETECT) {
            engine->hm_imp = root;
        } else if (purpose == HASH_PURPOSE_WHOLE_FILE_FP_CHECK) {
            engine->hm_fp = root;
        }
    }

    if (size) {
        /* size non-zero, find sz_hash element in size-driven hashtable  */
        ht = &root->hm.sizehashes[type];
        if (!root->hm.sizehashes[type].capacity) {
            ret = CLI_HTU32_INIT(ht, 64, root->mempool);
            if (CL_SUCCESS != ret) {
                cli_errmsg("hm_addhash_bin: failed to initialize hash table\n");
                return ret;
            }
        }

        item = cli_htu32_find(ht, size);
        if (!item) {
            struct cli_htu32_element htitem;
            szh = MPOOL_CALLOC(root->mempool, 1, sizeof(*szh));
            if (!szh) {
                cli_errmsg("hm_addhash_bin: failed to allocate size hash\n");
                return CL_EMEM;
            }

            htitem.key         = size;
            htitem.data.as_ptr = szh;
            ret                = CLI_HTU32_INSERT(ht, &htitem, root->mempool);
            if (CL_SUCCESS != ret) {
                cli_errmsg("hm_addhash_bin: failed to add item to hashtab");
                MPOOL_FREE(root->mempool, szh);
                return ret;
            }
        } else {
            szh = (struct cli_sz_hash *)item->data.as_ptr;
        }
    } else {
        /* size 0 = wildcard */
        szh = &root->hwild.hashes[type];
    }
    szh->items++;

    szh->hash_array = MPOOL_REALLOC2(root->mempool, szh->hash_array, hlen * szh->items);
    if (!szh->hash_array) {
        cli_errmsg("hm_addhash_bin: failed to grow hash array to %u entries\n", szh->items);
        szh->items = 0;
        MPOOL_FREE(root->mempool, (void *)szh->virusnames);
        szh->virusnames = NULL;
        return CL_EMEM;
    }

    szh->virusnames = MPOOL_REALLOC2(root->mempool, (void *)szh->virusnames, sizeof(*szh->virusnames) * szh->items);
    if (!szh->virusnames) {
        cli_errmsg("hm_addhash_bin: failed to grow virusname array to %u entries\n", szh->items);
        szh->items = 0;
        MPOOL_FREE(root->mempool, szh->hash_array);
        szh->hash_array = NULL;
        return CL_EMEM;
    }

    memcpy(&szh->hash_array[(szh->items - 1) * hlen], binhash, hlen);
    szh->virusnames[(szh->items - 1)] = virusname;

    return CL_SUCCESS;
}

static inline int hm_cmp(const uint8_t *itm, const uint8_t *ref, unsigned int keylen)
{
#if WORDS_BIGENDIAN == 0
    uint32_t i = *(uint32_t *)itm, r = *(uint32_t *)ref;
    if (i != r)
        return (i < r) * 2 - 1;
    return memcmp(&itm[4], &ref[4], keylen - 4);
#else
    return memcmp(itm, ref, keylen);
#endif
}

static void hm_sort(struct cli_sz_hash *szh, size_t l, size_t r, unsigned int keylen)
{
    uint8_t piv[CLI_HASHLEN_MAX], tmph[CLI_HASHLEN_MAX];
    size_t l1, r1;

    const char *tmpv;

    if (l + 1 >= r)
        return;

    l1 = l + 1, r1 = r;

    memcpy(piv, &szh->hash_array[keylen * l], keylen);
    while (l1 < r1) {
        if (hm_cmp(&szh->hash_array[keylen * l1], piv, keylen) > 0) {
            r1--;
            if (l1 == r1) break;
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
    if (l1 != l) {
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
void hm_flush(struct cli_matcher *root)
{
    cli_hash_type_t type;
    unsigned int keylen;
    struct cli_sz_hash *szh;

    if (!root)
        return;

    for (type = CLI_HASH_MD5; type < CLI_HASH_AVAIL_TYPES; type++) {
        struct cli_htu32 *ht                 = &root->hm.sizehashes[type];
        const struct cli_htu32_element *item = NULL;
        szh                                  = NULL;

        if (!root->hm.sizehashes[type].capacity)
            continue;

        while ((item = cli_htu32_next(ht, item))) {
            szh    = (struct cli_sz_hash *)item->data.as_ptr;
            keylen = cli_hash_len(type);

            if (szh->items > 1)
                hm_sort(szh, 0, szh->items, keylen);
        }
    }

    for (type = CLI_HASH_MD5; type < CLI_HASH_AVAIL_TYPES; type++) {
        szh    = &root->hwild.hashes[type];
        keylen = cli_hash_len(type);

        if (szh->items > 1)
            hm_sort(szh, 0, szh->items, keylen);
    }
}

bool cli_hm_have_size(const struct cli_matcher *root, cli_hash_type_t type, uint32_t size)
{
    return (size && size != 0xffffffff && root && root->hm.sizehashes[type].capacity && cli_htu32_find(&root->hm.sizehashes[type], size));
}

bool cli_hm_have_wild(const struct cli_matcher *root, cli_hash_type_t type)
{
    return (root && root->hwild.hashes[type].items);
}

bool cli_hm_have_any(const struct cli_matcher *root, cli_hash_type_t type)
{
    return (root && (root->hwild.hashes[type].items || root->hm.sizehashes[type].capacity));
}

static cl_error_t hm_scan(const uint8_t *digest, const char **virname, const struct cli_sz_hash *szh, cli_hash_type_t type)
{
    unsigned int keylen;
    size_t l, r;

    if (!digest || !szh || !szh->items)
        return CL_CLEAN;

    keylen = cli_hash_len(type);

    l = 0;
    r = szh->items - 1;
    while (l <= r) {
        size_t c = (l + r) / 2;
        int res  = hm_cmp(digest, &szh->hash_array[keylen * c], keylen);

        if (res < 0) {
            if (!c)
                break;
            r = c - 1;
        } else if (res > 0)
            l = c + 1;
        else {
            if (virname)
                *virname = szh->virusnames[c];
            return CL_VIRUS;
        }
    }
    return CL_CLEAN;
}

/* cli_hm_scan will scan only size-specific hashes, if any */
cl_error_t cli_hm_scan(const uint8_t *digest, uint32_t size, const char **virname, const struct cli_matcher *root, cli_hash_type_t type)
{
    const struct cli_htu32_element *item;
    struct cli_sz_hash *szh;

    if (!digest || !size || size == 0xffffffff || !root || !root->hm.sizehashes[type].capacity)
        return CL_CLEAN;

    item = cli_htu32_find(&root->hm.sizehashes[type], size);
    if (!item)
        return CL_CLEAN;

    szh = (struct cli_sz_hash *)item->data.as_ptr;

    return hm_scan(digest, virname, szh, type);
}

/* cli_hm_scan_wild will scan only size-agnostic hashes, if any */
cl_error_t cli_hm_scan_wild(const uint8_t *digest, const char **virname, const struct cli_matcher *root, cli_hash_type_t type)
{
    if (!digest || !root || !root->hwild.hashes[type].items)
        return CL_CLEAN;

    return hm_scan(digest, virname, &root->hwild.hashes[type], type);
}

/* free both size-specific and agnostic hash sets */
void hm_free(struct cli_matcher *root)
{
    cli_hash_type_t type;

    if (!root)
        return;

    for (type = CLI_HASH_MD5; type < CLI_HASH_AVAIL_TYPES; type++) {
        struct cli_htu32 *ht                 = &root->hm.sizehashes[type];
        const struct cli_htu32_element *item = NULL;

        if (!root->hm.sizehashes[type].capacity)
            continue;

        while ((item = cli_htu32_next(ht, item))) {
            struct cli_sz_hash *szh = (struct cli_sz_hash *)item->data.as_ptr;

            MPOOL_FREE(root->mempool, szh->hash_array);
            while (szh->items)
                MPOOL_FREE(root->mempool, (void *)szh->virusnames[--szh->items]);
            MPOOL_FREE(root->mempool, (void *)szh->virusnames);
            MPOOL_FREE(root->mempool, szh);
        }
        CLI_HTU32_FREE(ht, root->mempool);
    }

    for (type = CLI_HASH_MD5; type < CLI_HASH_AVAIL_TYPES; type++) {
        struct cli_sz_hash *szh = &root->hwild.hashes[type];

        if (!szh->items)
            continue;

        MPOOL_FREE(root->mempool, szh->hash_array);
        while (szh->items)
            MPOOL_FREE(root->mempool, (void *)szh->virusnames[--szh->items]);
        MPOOL_FREE(root->mempool, (void *)szh->virusnames);
    }
}

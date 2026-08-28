/*
 *  Copyright (C) 2013-2026 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
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
#ifdef CL_THREAD_SAFE
#include <pthread.h>
#endif

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

/* ------------------------------------------------------------------ *
 * The name store
 *
 * See matcher-hash.h for the shape. Everything here is either load-time
 * (single threaded, from cli_loadhash() and friends) or match-time
 * (multi threaded, from cli_hm_scan()); nothing in between.
 * ------------------------------------------------------------------ */

/** Bytes per chunk of the load-time name arena. A name may not straddle
 * two chunks: an offset is turned back into a chunk and a position by
 * dividing by this. */
#define HM_NAMETMP_CHUNK (1024 * 1024)

/** Slots the decoded-name cache is first allocated with. */
#define HM_NAME_CACHE_INIT 64

/** The cache grows once it is this full, numerator over denominator.
 * Linear probing degrades sharply past about seven tenths. */
#define HM_NAME_CACHE_LOAD_NUM 7
#define HM_NAME_CACHE_LOAD_DEN 10

/** Multiplier of the cache's hash: 2^32 divided by the golden ratio,
 * Knuth's constant for multiplicative hashing. Odd, so the mapping onto
 * the capacity mask is one to one. */
#define HM_NAME_CACHE_MULT 2654435761U

/** Decoded names, by entry number. Open addressing, plain malloc: this
 * is written while scanning, and the pool has no lock of its own. */
struct hm_namecache {
    uint32_t *keys; /* entry number + 1; 0 marks a free slot */
    char **vals;
    uint32_t capacity; /* power of two, 0 while empty */
    uint32_t used;
};

struct cli_hm_names {
    /* Load time only. Freed whole by hm_flush(). */
    char **chunks;
    uint32_t nchunks;
    uint32_t chunk_used;

    /* Built once by hm_flush(), in the pool, at its final size. */
    uint8_t *blob;
    uint32_t blob_len;
    uint32_t *block_off;
    uint32_t nblocks;
    uint32_t count;

    /* Match time. */
    struct hm_namecache cache;
    int ready; /* blob, block_off and mutex are all usable */
#ifdef CL_THREAD_SAFE
    pthread_mutex_t mutex;
#endif
};

static const char *hm_name_tmp(const struct cli_hm_names *nm, uint32_t off)
{
    return nm->chunks[off / HM_NAMETMP_CHUNK] + (off % HM_NAMETMP_CHUNK);
}

/* Copies name into the load-time arena and returns its offset, or
 * HM_NAME_NONE for a signature added without a name. */
static cl_error_t hm_name_store(struct cli_matcher *root, const char *name, uint32_t *off_out)
{
    struct cli_hm_names *nm;
    size_t len;

    if (!name) {
        *off_out = HM_NAME_NONE;
        return CL_SUCCESS;
    }

    if (!root->hm_names) {
        root->hm_names = MPOOL_CALLOC(root->mempool, 1, sizeof(*root->hm_names));
        if (!root->hm_names) {
            cli_errmsg("hm_name_store: failed to allocate the name store\n");
            return CL_EMEM;
        }
    }
    nm = root->hm_names;

    len = strlen(name) + 1;
    if (len > HM_NAMETMP_CHUNK) {
        cli_errmsg("hm_name_store: signature name of %zu bytes is too long\n", len);
        return CL_EMALFDB;
    }

    if (!nm->nchunks || nm->chunk_used + len > HM_NAMETMP_CHUNK) {
        char **nc;
        char *chunk;

        if ((uint64_t)(nm->nchunks + 1) * HM_NAMETMP_CHUNK >= HM_NAME_NONE) {
            cli_errmsg("hm_name_store: too many signature names to index\n");
            return CL_EMEM;
        }

        nc = cli_safer_realloc(nm->chunks, sizeof(*nm->chunks) * (nm->nchunks + 1));
        if (!nc) {
            cli_errmsg("hm_name_store: failed to grow the name arena\n");
            return CL_EMEM;
        }
        nm->chunks = nc;

        chunk = malloc(HM_NAMETMP_CHUNK);
        if (!chunk) {
            cli_errmsg("hm_name_store: failed to allocate a name chunk\n");
            return CL_EMEM;
        }

        nm->chunks[nm->nchunks++] = chunk;
        nm->chunk_used            = 0;
    }

    *off_out = (nm->nchunks - 1) * HM_NAMETMP_CHUNK + nm->chunk_used;
    memcpy(nm->chunks[nm->nchunks - 1] + nm->chunk_used, name, len);
    nm->chunk_used += (uint32_t)len;

    return CL_SUCCESS;
}

static void hm_nametmp_free(struct cli_hm_names *nm)
{
    uint32_t i;

    for (i = 0; i < nm->nchunks; i++)
        free(nm->chunks[i]);
    free(nm->chunks);

    nm->chunks     = NULL;
    nm->nchunks    = 0;
    nm->chunk_used = 0;
}

/** A length in the blob is a single byte, unless it is this value, which
 * escapes to a 32-bit little-endian length in the four bytes after it. */
#define HM_LEN_ESCAPE 0xff

/** Bytes an escaped length occupies: the escape and the four value bytes. */
#define HM_LEN_ESCAPE_BYTES 5

static uint32_t hm_len_bytes(uint32_t v)
{
    return (v < HM_LEN_ESCAPE) ? 1 : HM_LEN_ESCAPE_BYTES;
}

static void hm_put_len(uint8_t *p, uint32_t *pos, uint32_t v)
{
    if (v < HM_LEN_ESCAPE) {
        p[(*pos)++] = (uint8_t)v;
        return;
    }
    p[(*pos)++] = HM_LEN_ESCAPE;
    p[(*pos)++] = (uint8_t)v;
    p[(*pos)++] = (uint8_t)(v >> 8);
    p[(*pos)++] = (uint8_t)(v >> 16);
    p[(*pos)++] = (uint8_t)(v >> 24);
}

/* Reads a length, or HM_NAME_NONE if the blob ends inside one. A real
 * length can never be HM_NAME_NONE: a name is shorter than a chunk. */
static uint32_t hm_get_len(const uint8_t *p, uint32_t *pos, uint32_t end)
{
    uint32_t v;

    if (*pos >= end)
        return HM_NAME_NONE;

    v = p[(*pos)++];
    if (v == HM_LEN_ESCAPE) {
        if (*pos + 4 > end)
            return HM_NAME_NONE;
        v = (uint32_t)p[*pos] | ((uint32_t)p[*pos + 1] << 8) |
            ((uint32_t)p[*pos + 2] << 16) | ((uint32_t)p[*pos + 3] << 24);
        *pos += 4;
    }

    return v;
}

/** Sets in the array hm_collect_sets() builds before it has to grow it. */
#define HM_NAME_SETS_INIT 64

/* Every hash set of a root, in one order that all three passes below
 * agree on: a signature is paired with its name by counting positions,
 * so the traversal must not vary between them. */
static cl_error_t hm_collect_sets(struct cli_matcher *root, struct cli_sz_hash ***sets_out, uint32_t *nsets_out)
{
    cli_hash_type_t type;
    struct cli_sz_hash **sets = NULL;
    uint32_t n = 0, cap = 0;

    for (type = CLI_HASH_MD5; type < CLI_HASH_AVAIL_TYPES; type++) {
        struct cli_htu32 *ht                 = &root->hm.sizehashes[type];
        const struct cli_htu32_element *item = NULL;

        if (!ht->capacity)
            continue;

        while ((item = cli_htu32_next(ht, item))) {
            if (n == cap) {
                struct cli_sz_hash **ns;

                cap = cap ? cap * 2 : 64;
                ns  = cli_safer_realloc(sets, sizeof(*sets) * cap);
                if (!ns) {
                    free(sets);
                    return CL_EMEM;
                }
                sets = ns;
            }
            sets[n++] = (struct cli_sz_hash *)item->data.as_ptr;
        }
    }

    for (type = CLI_HASH_MD5; type < CLI_HASH_AVAIL_TYPES; type++) {
        if (n == cap) {
            struct cli_sz_hash **ns;

            cap = cap ? cap * 2 : 64;
            ns  = cli_safer_realloc(sets, sizeof(*sets) * cap);
            if (!ns) {
                free(sets);
                return CL_EMEM;
            }
            sets = ns;
        }
        sets[n++] = &root->hwild.hashes[type];
    }

    *sets_out  = sets;
    *nsets_out = n;

    return CL_SUCCESS;
}

/** Bits of the arena offset the presort takes per counting pass; two
 * passes at this width cover a 32-bit offset. */
#define HM_PRESORT_BITS 16
#define HM_PRESORT_RADIX (1u << HM_PRESORT_BITS)
#define HM_PRESORT_MASK (HM_PRESORT_RADIX - 1)

/* Puts the entry order into arena order - the order the names were
 * written in - before a single byte of any name is compared.
 *
 * The order that arrives here is the order the hash tables were walked
 * in, which bears no relation to where a name sits in the arena, so
 * every merge pass below would be a random walk over it and the sort
 * would spend its time waiting for memory rather than comparing. Two
 * counting passes over one digit of the offset cost a sequential sweep
 * each and hand the merge an input whose pages are already resident.
 *
 * This is an optimisation and nothing else - the sort is correct
 * without it - so a failed allocation skips it rather than failing the
 * load. */
static void hm_name_presort(const uint32_t *off, uint32_t *idx, uint32_t *scratch, uint32_t n)
{
    uint32_t *cnt;
    uint32_t i, k;

    cnt = calloc(HM_PRESORT_RADIX + 1, sizeof(*cnt));
    if (!cnt)
        return;

    for (i = 0; i < n; i++)
        cnt[(off[idx[i]] & HM_PRESORT_MASK) + 1]++;
    for (k = 1; k <= HM_PRESORT_RADIX; k++)
        cnt[k] += cnt[k - 1];
    for (i = 0; i < n; i++)
        scratch[cnt[off[idx[i]] & HM_PRESORT_MASK]++] = idx[i];

    memset(cnt, 0, (HM_PRESORT_RADIX + 1) * sizeof(*cnt));

    for (i = 0; i < n; i++)
        cnt[((off[scratch[i]] >> HM_PRESORT_BITS) & HM_PRESORT_MASK) + 1]++;
    for (k = 1; k <= HM_PRESORT_RADIX; k++)
        cnt[k] += cnt[k - 1];
    for (i = 0; i < n; i++)
        idx[cnt[(off[scratch[i]] >> HM_PRESORT_BITS) & HM_PRESORT_MASK]++] = scratch[i];

    free(cnt);
}

/* Bottom-up merge sort of the entry order by name. Not the quicksort
 * hm_sort() uses on hashes: names arrive in database order, which is
 * often close to sorted, and a first-element pivot over millions of
 * entries would degrade badly on exactly that input. */
static void hm_name_msort(const struct cli_hm_names *nm, const uint32_t *off, uint32_t *idx, uint32_t *scratch, uint32_t n)
{
    uint32_t width;

    for (width = 1; width < n; width *= 2) {
        uint32_t i;

        for (i = 0; i < n; i += 2 * width) {
            uint32_t l = i;
            uint32_t m = i + width;
            uint32_t r = i + 2 * width;
            uint32_t a, b, k;

            if (m > n) m = n;
            if (r > n) r = n;

            a = l;
            b = m;
            k = l;

            while (a < m && b < r) {
                if (strcmp(hm_name_tmp(nm, off[idx[a]]), hm_name_tmp(nm, off[idx[b]])) <= 0)
                    scratch[k++] = idx[a++];
                else
                    scratch[k++] = idx[b++];
            }
            while (a < m)
                scratch[k++] = idx[a++];
            while (b < r)
                scratch[k++] = idx[b++];
        }

        memcpy(idx, scratch, sizeof(*idx) * n);
    }
}

/** Bytes the front-coded blob starts at before it has to be grown. */
#define HM_NAME_BLOB_INIT (64 * 1024)

/* Sorts the names, writes the front-coded blob and the block offsets,
 * and turns every signature's arena offset into an entry number. */
static cl_error_t hm_names_build(struct cli_matcher *root)
{
    struct cli_hm_names *nm   = root->hm_names;
    struct cli_sz_hash **sets = NULL;
    uint32_t nsets = 0, named = 0, s, i, j;
    uint32_t *off = NULL, *idx = NULL, *scratch = NULL;
    uint8_t *blob       = NULL;
    uint32_t *block_off = NULL;
    uint32_t blob_len = 0, blob_cap = 0, nblocks = 0, entries = 0;
    const char *prev = NULL;
    cl_error_t ret   = CL_EMEM;

    if (CL_SUCCESS != (ret = hm_collect_sets(root, &sets, &nsets)))
        return ret;

    for (s = 0; s < nsets; s++)
        for (i = 0; i < sets[s]->items; i++)
            if (sets[s]->name_idx[i] != HM_NAME_NONE)
                named++;

    if (!nm || !named) {
        free(sets);
        return CL_SUCCESS;
    }

    off     = malloc(sizeof(*off) * named);
    idx     = malloc(sizeof(*idx) * named);
    scratch = malloc(sizeof(*scratch) * named);
    if (!off || !idx || !scratch) {
        cli_errmsg("hm_names_build: failed to allocate %u name slots\n", named);
        goto done;
    }

    j = 0;
    for (s = 0; s < nsets; s++)
        for (i = 0; i < sets[s]->items; i++)
            if (sets[s]->name_idx[i] != HM_NAME_NONE) {
                off[j] = sets[s]->name_idx[i];
                idx[j] = j;
                j++;
            }

    hm_name_presort(off, idx, scratch, named);
    hm_name_msort(nm, off, idx, scratch, named);

    /* Every one of these arrays is four bytes per hash signature, so
     * each one is given up as soon as it is dead: this runs while the
     * whole name arena is still live, and that is the process's peak. */
    free(scratch);
    scratch = NULL;

    nblocks   = (named + HM_NAME_BLOCK - 1) / HM_NAME_BLOCK;
    block_off = malloc(sizeof(*block_off) * nblocks);
    if (!block_off) {
        cli_errmsg("hm_names_build: failed to allocate %u block offsets\n", nblocks);
        goto done;
    }

    for (j = 0; j < named; j++) {
        const char *cur = hm_name_tmp(nm, off[idx[j]]);
        uint32_t lcp    = 0;
        uint32_t len    = (uint32_t)strlen(cur);

        if (prev && !strcmp(prev, cur)) {
            /* Equal names collapse onto one entry; there are few of
             * them, but they cost nothing to fold in here. */
            off[idx[j]] = entries - 1;
            continue;
        }

        if (entries % HM_NAME_BLOCK == 0) {
            /* A restart point: nothing inherited, so a decode can begin
             * here. This is what block_off[] indexes. */
            block_off[entries / HM_NAME_BLOCK] = blob_len;
        } else {
            while (lcp < len && prev[lcp] && prev[lcp] == cur[lcp])
                lcp++;
        }

        if (blob_len + hm_len_bytes(lcp) + hm_len_bytes(len - lcp) + (len - lcp) > blob_cap) {
            uint8_t *nb;

            blob_cap = blob_cap ? blob_cap * 2 : HM_NAME_BLOB_INIT;
            while (blob_len + hm_len_bytes(lcp) + hm_len_bytes(len - lcp) + (len - lcp) > blob_cap)
                blob_cap *= 2;

            nb = cli_safer_realloc(blob, blob_cap);
            if (!nb) {
                cli_errmsg("hm_names_build: failed to grow the name blob\n");
                goto done;
            }
            blob = nb;
        }

        hm_put_len(blob, &blob_len, lcp);
        hm_put_len(blob, &blob_len, len - lcp);
        memcpy(blob + blob_len, cur + lcp, len - lcp);
        blob_len += len - lcp;

        prev        = cur;
        off[idx[j]] = entries++;
    }

    free(idx);
    idx = NULL;
    hm_nametmp_free(nm);

    /* Into the pool, once, at the final size. */
    nblocks  = (entries + HM_NAME_BLOCK - 1) / HM_NAME_BLOCK;
    nm->blob = MPOOL_MALLOC(root->mempool, blob_len);
    if (!nm->blob) {
        cli_errmsg("hm_names_build: failed to allocate %u name bytes\n", blob_len);
        goto done;
    }
    memcpy(nm->blob, blob, blob_len);

    nm->block_off = MPOOL_MALLOC(root->mempool, sizeof(*nm->block_off) * nblocks);
    if (!nm->block_off) {
        cli_errmsg("hm_names_build: failed to allocate %u block offsets\n", nblocks);
        goto done;
    }
    memcpy(nm->block_off, block_off, sizeof(*nm->block_off) * nblocks);

    nm->blob_len = blob_len;
    nm->nblocks  = nblocks;
    nm->count    = entries;

#ifdef CL_THREAD_SAFE
    if (pthread_mutex_init(&nm->mutex, NULL)) {
        cli_errmsg("hm_names_build: failed to initialise the name cache mutex\n");
        goto done;
    }
#endif
    nm->ready = 1;

    j = 0;
    for (s = 0; s < nsets; s++)
        for (i = 0; i < sets[s]->items; i++)
            if (sets[s]->name_idx[i] != HM_NAME_NONE)
                sets[s]->name_idx[i] = off[j++];

    cli_dbgmsg("hm_names_build: %u names (%u distinct) in %u bytes\n", named, entries, blob_len);

    ret = CL_SUCCESS;

done:
    free(off);
    free(idx);
    free(scratch);
    free(blob);
    free(block_off);
    free(sets);

    /* Harmless if the success path already did it. */
    hm_nametmp_free(nm);

    return ret;
}

/* Rebuilds one name from the blob. The entry inherits a prefix from the
 * one before it, so the walk starts at the block this entry belongs to.
 * Returns a malloc'd string. */
static char *hm_name_decode(const struct cli_hm_names *nm, uint32_t entry)
{
    uint32_t first = (entry / HM_NAME_BLOCK) * HM_NAME_BLOCK;
    uint32_t pos, k, len = 0, maxlen = 0;
    char *buf;

    if (entry >= nm->count)
        return NULL;

    /* First pass: how long the longest name in the walk is, which is
     * how big the buffer the second pass builds in has to be. */
    pos = nm->block_off[entry / HM_NAME_BLOCK];
    for (k = first; k <= entry; k++) {
        uint32_t lcp  = hm_get_len(nm->blob, &pos, nm->blob_len);
        uint32_t tail = hm_get_len(nm->blob, &pos, nm->blob_len);

        /* Written as a subtraction: hm_get_len() leaves pos <= blob_len,
         * so blob_len - pos cannot wrap, whereas pos + tail could. */
        if (lcp == HM_NAME_NONE || tail == HM_NAME_NONE ||
            lcp > len || tail > nm->blob_len - pos)
            return NULL;

        len = lcp + tail;
        if (len > maxlen)
            maxlen = len;
        pos += tail;
    }

    buf = malloc(maxlen + 1);
    if (!buf)
        return NULL;

    /* Second pass walks the same bytes the first pass just validated,
     * so it does not re-check them. */
    len = 0;
    pos = nm->block_off[entry / HM_NAME_BLOCK];
    for (k = first; k <= entry; k++) {
        uint32_t lcp  = hm_get_len(nm->blob, &pos, nm->blob_len);
        uint32_t tail = hm_get_len(nm->blob, &pos, nm->blob_len);

        memcpy(buf + lcp, nm->blob + pos, tail);
        len = lcp + tail;
        pos += tail;
    }
    buf[len] = '\0';

    return buf;
}

/* Where an entry belongs, in one place: the two probe loops in hm_name()
 * and the rehash below have to agree on it. capacity is a power of two
 * and is never zero here. */
static inline uint32_t hm_cache_slot(uint32_t entry, uint32_t capacity)
{
    return (entry * HM_NAME_CACHE_MULT) & (capacity - 1);
}

static cl_error_t hm_cache_grow(struct hm_namecache *c)
{
    uint32_t newcap = c->capacity ? c->capacity * 2 : HM_NAME_CACHE_INIT;
    uint32_t *keys;
    char **vals;
    uint32_t i;

    keys = calloc(newcap, sizeof(*keys));
    vals = calloc(newcap, sizeof(*vals));
    if (!keys || !vals) {
        free(keys);
        free(vals);
        return CL_EMEM;
    }

    for (i = 0; i < c->capacity; i++) {
        uint32_t slot;

        if (!c->keys[i])
            continue;

        slot = hm_cache_slot(c->keys[i] - 1, newcap);
        while (keys[slot])
            slot = (slot + 1) & (newcap - 1);

        keys[slot] = c->keys[i];
        vals[slot] = c->vals[i];
    }

    free(c->keys);
    free(c->vals);
    c->keys     = keys;
    c->vals     = vals;
    c->capacity = newcap;

    return CL_SUCCESS;
}

/* The name of one hash signature, valid for as long as the engine is
 * loaded. NULL means the signature has no name; a decode failure is
 * reported by *failed, because that is not the same thing. */
static const char *hm_name(const struct cli_matcher *root, uint32_t entry, int *failed)
{
    struct cli_hm_names *nm = root->hm_names;
    const char *name        = NULL;
    uint32_t slot;

    *failed = 0;

    if (entry == HM_NAME_NONE)
        return NULL;

    if (!nm || !nm->ready) {
        *failed = 1;
        return NULL;
    }

#ifdef CL_THREAD_SAFE
    if (pthread_mutex_lock(&nm->mutex)) {
        cli_errmsg("hm_name: mutex lock fail\n");
        *failed = 1;
        return NULL;
    }
#endif

    if (nm->cache.capacity) {
        slot = hm_cache_slot(entry, nm->cache.capacity);
        while (nm->cache.keys[slot]) {
            if (nm->cache.keys[slot] == entry + 1) {
                name = nm->cache.vals[slot];
                goto unlock;
            }
            slot = (slot + 1) & (nm->cache.capacity - 1);
        }
    }

    if (nm->cache.used * HM_NAME_CACHE_LOAD_DEN >= nm->cache.capacity * HM_NAME_CACHE_LOAD_NUM)
        if (CL_SUCCESS != hm_cache_grow(&nm->cache)) {
            *failed = 1;
            goto unlock;
        }

    {
        char *decoded = hm_name_decode(nm, entry);

        if (!decoded) {
            *failed = 1;
            goto unlock;
        }

        slot = hm_cache_slot(entry, nm->cache.capacity);
        while (nm->cache.keys[slot])
            slot = (slot + 1) & (nm->cache.capacity - 1);

        nm->cache.keys[slot] = entry + 1;
        nm->cache.vals[slot] = decoded;
        nm->cache.used++;
        name = decoded;
    }

unlock:
#ifdef CL_THREAD_SAFE
    pthread_mutex_unlock(&nm->mutex);
#endif

    return name;
}

static void hm_names_free(struct cli_matcher *root)
{
    struct cli_hm_names *nm = root->hm_names;
    uint32_t i;

    if (!nm)
        return;

    hm_nametmp_free(nm);

    for (i = 0; i < nm->cache.capacity; i++)
        if (nm->cache.keys[i])
            free(nm->cache.vals[i]);
    free(nm->cache.keys);
    free(nm->cache.vals);

    if (nm->blob)
        MPOOL_FREE(root->mempool, nm->blob);
    if (nm->block_off)
        MPOOL_FREE(root->mempool, nm->block_off);

#ifdef CL_THREAD_SAFE
    if (nm->ready)
        pthread_mutex_destroy(&nm->mutex);
#endif

    MPOOL_FREE(root->mempool, nm);
    root->hm_names = NULL;
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
    uint32_t nameoff;
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
    ret = hm_name_store(root, virusname, &nameoff);
    if (CL_SUCCESS != ret)
        return ret;

    szh->items++;

    szh->hash_array = MPOOL_REALLOC2(root->mempool, szh->hash_array, hlen * szh->items);
    if (!szh->hash_array) {
        cli_errmsg("hm_addhash_bin: failed to grow hash array to %u entries\n", szh->items);
        szh->items = 0;
        MPOOL_FREE(root->mempool, szh->name_idx);
        szh->name_idx = NULL;
        return CL_EMEM;
    }

    szh->name_idx = MPOOL_REALLOC2(root->mempool, szh->name_idx, sizeof(*szh->name_idx) * szh->items);
    if (!szh->name_idx) {
        cli_errmsg("hm_addhash_bin: failed to grow name index to %u entries\n", szh->items);
        szh->items = 0;
        MPOOL_FREE(root->mempool, szh->hash_array);
        szh->hash_array = NULL;
        return CL_EMEM;
    }

    memcpy(&szh->hash_array[(szh->items - 1) * hlen], binhash, hlen);
    szh->name_idx[(szh->items - 1)] = nameoff;

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

    uint32_t tmpv;

    if (l + 1 >= r)
        return;

    l1 = l + 1, r1 = r;

    memcpy(piv, &szh->hash_array[keylen * l], keylen);
    while (l1 < r1) {
        if (hm_cmp(&szh->hash_array[keylen * l1], piv, keylen) > 0) {
            r1--;
            if (l1 == r1) break;
            memcpy(tmph, &szh->hash_array[keylen * l1], keylen);
            tmpv = szh->name_idx[l1];
            memcpy(&szh->hash_array[keylen * l1], &szh->hash_array[keylen * r1], keylen);
            szh->name_idx[l1] = szh->name_idx[r1];
            memcpy(&szh->hash_array[keylen * r1], tmph, keylen);
            szh->name_idx[r1] = tmpv;
        } else
            l1++;
    }

    l1--;
    if (l1 != l) {
        memcpy(tmph, &szh->hash_array[keylen * l1], keylen);
        tmpv = szh->name_idx[l1];
        memcpy(&szh->hash_array[keylen * l1], &szh->hash_array[keylen * l], keylen);
        szh->name_idx[l1] = szh->name_idx[l];
        memcpy(&szh->hash_array[keylen * l], tmph, keylen);
        szh->name_idx[l] = tmpv;
    }

    hm_sort(szh, l, l1, keylen);
    hm_sort(szh, r1, r, keylen);
}

/* Sort both size-specific and agnostic hash sets, then build the name
 * table over the result. */
cl_error_t hm_flush(struct cli_matcher *root)
{
    cli_hash_type_t type;
    unsigned int keylen;
    struct cli_sz_hash *szh;

    if (!root)
        return CL_SUCCESS;

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

    return hm_names_build(root);
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

static cl_error_t hm_scan(const struct cli_matcher *root, const uint8_t *digest, const char **virname, const struct cli_sz_hash *szh, cli_hash_type_t type)
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
            if (virname) {
                int failed;

                *virname = hm_name(root, szh->name_idx[c], &failed);
                if (failed) {
                    cli_errmsg("hm_scan: failed to materialise the signature name\n");
                    return CL_EMEM;
                }
            }
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

    return hm_scan(root, digest, virname, szh, type);
}

/* cli_hm_scan_wild will scan only size-agnostic hashes, if any */
cl_error_t cli_hm_scan_wild(const uint8_t *digest, const char **virname, const struct cli_matcher *root, cli_hash_type_t type)
{
    if (!digest || !root || !root->hwild.hashes[type].items)
        return CL_CLEAN;

    return hm_scan(root, digest, virname, &root->hwild.hashes[type], type);
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
            MPOOL_FREE(root->mempool, szh->name_idx);
            MPOOL_FREE(root->mempool, szh);
        }
        CLI_HTU32_FREE(ht, root->mempool);
    }

    for (type = CLI_HASH_MD5; type < CLI_HASH_AVAIL_TYPES; type++) {
        struct cli_sz_hash *szh = &root->hwild.hashes[type];

        if (!szh->items)
            continue;

        MPOOL_FREE(root->mempool, szh->hash_array);
        MPOOL_FREE(root->mempool, szh->name_idx);
    }

    /* One blob, not 3.3 million strings. */
    hm_names_free(root);
}

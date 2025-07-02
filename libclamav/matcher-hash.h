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

#ifndef __MATCHER_HASH_H
#define __MATCHER_HASH_H

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include "clamav-types.h"
#include "matcher-hash-types.h"
#include "hashtab.h"

typedef enum {
    HASH_PURPOSE_PE_SECTION_DETECT = 0, /** PE section hash malware detection (aka .mdb, .mdu, .msb, .msu) */
    HASH_PURPOSE_WHOLE_FILE_DETECT,     /** Whole file hash malware detection (aka .hdb, .hdu, .hsb, .hsu) */
    HASH_PURPOSE_WHOLE_FILE_FP_CHECK,   /** Whole file false positive prevention (aka .fp, .sfp) */
    HASH_PURPOSE_PE_IMPORT_DETECT       /** PE import hash malware detection (aka .imp) */
} hash_purpose_t;

struct cli_sz_hash {
    uint8_t *hash_array;
    const char **virusnames;
    uint32_t items;
};

struct cli_hash_patt {
    struct cli_htu32 sizehashes[CLI_HASH_AVAIL_TYPES];
};

struct cli_hash_wild {
    struct cli_sz_hash hashes[CLI_HASH_AVAIL_TYPES];
};

cl_error_t hm_addhash_str(struct cl_engine *engine, hash_purpose_t purpose, const char *strhash, uint32_t size, const char *virusname);
cl_error_t hm_addhash_bin(struct cl_engine *engine, hash_purpose_t purpose, const void *binhash, cli_hash_type_t type, uint32_t size, const char *virusname);
void hm_flush(struct cli_matcher *root);
cl_error_t cli_hm_scan(const uint8_t *digest, uint32_t size, const char **virname, const struct cli_matcher *root, cli_hash_type_t type);
cl_error_t cli_hm_scan_wild(const uint8_t *digest, const char **virname, const struct cli_matcher *root, cli_hash_type_t type);
bool cli_hm_have_size(const struct cli_matcher *root, cli_hash_type_t type, uint32_t size);
bool cli_hm_have_wild(const struct cli_matcher *root, cli_hash_type_t type);
bool cli_hm_have_any(const struct cli_matcher *root, cli_hash_type_t type);
void hm_free(struct cli_matcher *root);

#endif

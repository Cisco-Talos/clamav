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

#ifndef __MATCHER_HASH_H
#define __MATCHER_HASH_H

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include "cltypes.h"
#include "hashtab.h"

enum CLI_HASH_TYPE {
    CLI_HASH_MD5,
    CLI_HASH_SHA256,
    CLI_HASH_SHA1,

    /* new hash types go above this line */
    CLI_HASH_AVAIL_TYPES
};

struct cli_sz_hash {
    uint8_t *hash_array; /* FIXME: make 256 entries? */
    const char **virusnames;
    uint32_t items;
    uint32_t max;
};


struct cli_hash_patt {
    struct cli_htu32 sizehashes[CLI_HASH_AVAIL_TYPES];
    int htinint[CLI_HASH_AVAIL_TYPES];
};


int hm_addhash(struct cli_matcher *root, const char *hash, uint32_t size, const char *virusname);
void hm_flush(struct cli_matcher *root);

#endif

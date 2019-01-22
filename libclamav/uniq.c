/*
 *  md5 based hashtab
 *
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2008-2013 Sourcefire, Inc.
 *
 *  Authors: aCaB <acab@clamav.net>
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

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdlib.h>
#if HAVE_STRING_H
#include <string.h>
#endif

#include "clamav.h"
#include "uniq.h"
#include "others.h"

struct uniq *uniq_init(uint32_t count) {
  struct uniq *U;

  if(!count) return NULL;
  U = cli_calloc(1, sizeof(*U));
  if(!U) return NULL;

  U->md5s = cli_malloc(count * sizeof(*U->md5s));
  if(!U->md5s) {
    uniq_free(U);
    return NULL;
  }
    U->max_unique_items = count;

  return U;
}

void uniq_free(struct uniq *U) {
  free(U->md5s);
  free(U);
}

cl_error_t uniq_add(struct uniq *U, const char *item, uint32_t item_len, char **rhash, uint32_t *count)
{
  cl_error_t status = CL_EARG;
  unsigned int i;
  uint8_t digest[16];
  struct UNIQMD5 *m = NULL;

    if (!U) {
        /* Invalid args */
        goto done;
    }

    /* Uniq adds are limited by the maximum allocated in uniq_init(). */
    if (U->cur_unique_items >= U->max_unique_items) {
        /* Attempted to add more uniq items than may be stored. */
        status = CL_EMAXSIZE;
        goto done;
    }

    /* Make a hash of the item string */
    if (NULL == cl_hash_data("md5", item, item_len, digest, NULL)) {
        /* Failed to create hash of item. */
        status = CL_EFORMAT;
        goto done;
    }

    /* Check for md5 digest match in md5 collection */
  if(U->items && U->md5s[U->idx[*digest]].md5[0]==*digest)
    for(m=&U->md5s[U->idx[*digest]]; m; m=m->next)
      if(!memcmp(&digest[1], &m->md5[1], 15)) break;
  
  if(!m) {
        /* No match. Add new md5 to list */
    const char HEX[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

    m = &U->md5s[U->items];
    m->count = 0;

    if(U->items && U->md5s[U->idx[*digest]].md5[0]==*digest)
      m->next = &U->md5s[U->idx[*digest]];
    else
      m->next = NULL;

    U->idx[*digest]=U->items;

    for(i = 0; i < 16; i++) {
      m->name[i*2] = HEX[digest[i]>>4 & 0xf];
      m->name[i*2+1] = HEX[digest[i] & 0xf];
      m->md5[i] = digest[i];
    }
    m->name[32] = '\0';

        /* Increment # of unique items. */
        U->cur_unique_items++;
  }

    /* Increment total # of items. */
  U->items++;

    /* Increment # items matching this md5 digest (probably just this 1). */
    m->count++;

    /* Pass back the ascii hash, if requested. */
  if(rhash) *rhash = m->name;

    /* Pass back the count, if requested. */
    if (count) *count = m->count;

    status = CL_SUCCESS;

done:
    return status;
}

cl_error_t uniq_get(struct uniq *U, const char *item, uint32_t item_len, char **rhash, uint32_t *count)
{
  cl_error_t status = CL_EARG;
  uint8_t digest[16];
  struct UNIQMD5 *m = NULL;
    uint32_t idx      = 0;

    if (!U || !count) {
        /* Invalid args */
        goto done;
    }

    *count = 0;

    if (!U->items) {
        goto not_found;
    }

    /* Make a hash of the item string */
    if (NULL == cl_hash_data("md5", item, item_len, digest, NULL)) {
        /* Failed to create hash of item. */
        status = CL_EFORMAT;
        goto done;
    }

    /* Get the md5s array index for the bucket list head. */
    idx = U->idx[*digest];
    m   = &U->md5s[idx];

    if (m->md5[0] != *digest) {
        /*
         * If the first two bytes in the digest doesn't actually match,
         * then the item has never been added.
         * This is a common scenario because the idx table is initialized
         * to 0's.
         */
        goto not_found;
    }

    do {
        if (0 == memcmp(&digest[1], &m->md5[1], 15)) {
            /* The item-hash matched.
             * Pass back the ascii hash value (if requested).
             * Return the count of matching items (will be 1+).
             */
            if (rhash)
                *rhash = m->name;
            *count = m->count;
            break;
  }
        m = m->next;
    } while (NULL != m);

not_found:
    status = CL_SUCCESS;

done:
    return status;
}

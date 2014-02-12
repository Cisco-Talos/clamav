/*
 *  md5 based hashtab
 *
 *  Copyright (C) 2008 Sourcefire, Inc.
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

#include <openssl/ssl.h>
#include <openssl/err.h>
#include "libclamav/crypto.h"

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

  return U;
}

void uniq_free(struct uniq *U) {
  free(U->md5s);
  free(U);
}

uint32_t uniq_add(struct uniq *U, const char *key, uint32_t key_len, char **rhash) {
  unsigned int i;
  uint8_t digest[16];
  struct UNIQMD5 *m = NULL;

  cl_hash_data("md5", key, key_len, digest, NULL);

  if(U->items && U->md5s[U->idx[*digest]].md5[0]==*digest)
    for(m=&U->md5s[U->idx[*digest]]; m; m=m->next)
      if(!memcmp(&digest[1], &m->md5[1], 15)) break;
  
  if(!m) {
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
  }

  U->items++;
  if(rhash) *rhash = m->name;
  return m->count++;
}

uint32_t uniq_get(struct uniq *U, const char *key, uint32_t key_len, char **rhash) {
  uint8_t digest[16];
  struct UNIQMD5 *m = NULL;

  cl_hash_data("md5", key, key_len, digest, NULL);

  if(!U->items || U->md5s[U->idx[*digest]].md5[0]!=*digest)
    return 0;

  for(m=&U->md5s[U->idx[*digest]]; m; m=m->next) {
    if(memcmp(&digest[1], &m->md5[1], 15)) continue;
    if(rhash) *rhash = m->name;
    return m->count;
  }

  return 0;
}

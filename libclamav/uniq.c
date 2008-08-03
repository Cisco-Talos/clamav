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

#include "uniq.h"
#include "md5.h"

#if 0
struct uniq *uniq_init(uint32_t count) {
  struct uniq *U;
  uint32_t i;

  if(!count) return NULL;
  U = cli_calloc(1, sizeof(*U));
  if(!U) return NULL;
  if(cli_ac_init(&U->matcher, 16, 16)) {
    uniq_free(U);
    return NULL;
  }
  U->custs = cli_calloc(count, sizeof(U->custs));
  if(!U->custs) {
    uniq_free(U);
    return NULL;
  }
  U->patts = cli_calloc(count, sizeof(U->patts));
  if(!U->patts) {
    uniq_free(U);
    return NULL;
  }
  U->md5s = cli_malloc(count*sizeof(U->md5s));
  if(!U->md5s) {
    uniq_free(U);
    return NULL;
  }

  U->entries = count;

  for(i=0; i<count; i++) {
    U->patts[i].pattern = U->md5s[i].md5;
    U->patts[i].length = 16;
    U->patts[i].ch[0] = U->patts[i].ch[1] |= CLI_MATCH_IGNORE;
    U->patts[i].customdata = &U->custs[i];
  }

  return U;
}

void uniq_free(struct uniq *U) {
  uint32_t i;
  U->matcher.ac_patterns = 0; /* don't free my arrays! */
  cli_ac_free(&U->matcher);
  if(U->custs) free(U->custs);
  if(U->patts) free(U->patts);
  if(U->md5s) free(U->md5s);
  free(U);
}


uint32_t uniq_add(struct uniq *U, const char *key, uint32_t key_len, char **rhash) {
  uint8_t digest[16];
  struct UNIQCUST *cust;
  struct cli_ac_data mdata;

  cli_md5_ctx md5;
  cli_md5_init(&md5);
  cli_md5_update(&md5, key, key_len);
  cli_md5_final(digest, &md5);

  cli_ac_initdata(&mdata, 0, 0, AC_DEFAULT_TRACKLEN); /* This can't fail as we don't have parts or lsigs */
  if (cli_ac_scanbuff(digest,16, NULL, (void *)&cust, NULL, &U->matcher, &mdata,0,0,-1,NULL,AC_SCAN_VIR,NULL)!=CL_VIRUS) {
    int i;
    char HEX[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
    struct cli_ac_patt *patt = &U->patts[U->matcher.ac_patterns];

    cust = patt->customdata;
    for(i = 0; i < 16; i++) {
      cust->name[i*2] = HEX[digest[i]>>4 & 0xf];
      cust->name[i*2+1] = HEX[digest[i] & 0xf];
      patt->pattern[i] = digest[i];
    }
    cli_ac_addpatt(&U->matcher,patt); /* FIXME this can fail */
    cli_ac_buildtrie(&U->matcher);
  }

  cust->count++;
  if(rhash) *rhash = cust->name;
  return cust->count;
}

uint32_t uniq_get(struct uniq *U, const char *key, uint32_t key_len, char **rhash) {
  uint8_t digest[16];
  struct UNIQCUST *cust;
  struct cli_ac_data mdata;

  cli_md5_ctx md5;
  cli_md5_init(&md5);
  cli_md5_update(&md5, key, key_len);
  cli_md5_final(digest, &md5);

  cli_ac_initdata(&mdata, 0, 0, AC_DEFAULT_TRACKLEN); /* This can't fail as we don't have parts or lsigs */
  if (cli_ac_scanbuff(digest,16, NULL, (void *)&cust, NULL, &U->matcher, &mdata,0,0,-1,NULL,AC_SCAN_VIR,NULL)!=CL_VIRUS)
    return 0;

  if(rhash) *rhash = cust->name;
  return cust->count;
}

#else
#include <string.h>

struct uniq *uniq_init(uint32_t count) {
  struct uniq *U;
  
  if(!count) return NULL;
  U = cli_malloc(sizeof(*U));
  if(!U) return NULL;

  U->md5s = cli_malloc(count * sizeof(*U->md5s));
  if(!U->md5s) {
    uniq_free(U);
    return NULL;
  }

  U->items = 0;
  return U;
}

void uniq_free(struct uniq *U) {
  free(U->md5s);
  free(U);
}

uint32_t uniq_add(struct uniq *U, const char *key, uint32_t key_len, char **rhash) {
  unsigned int i;
  uint8_t digest[16];
  cli_md5_ctx md5;
  struct UNIQMD5 *m;

  cli_md5_init(&md5);
  cli_md5_update(&md5, key, key_len);
  cli_md5_final(digest, &md5);

  for(i=0; i<U->items; i++) {
    if(memcmp(digest, U->md5s[i].md5, 16)) continue;
    m = &U->md5s[i];
    break;
  }
  
  if(i==U->items) {
    char HEX[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
    m = &U->md5s[i];
    m->count = 0;
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
  unsigned int i;
  uint8_t digest[16];
  cli_md5_ctx md5;

  cli_md5_init(&md5);
  cli_md5_update(&md5, key, key_len);
  cli_md5_final(digest, &md5);

  for(i=0; i<U->items; i++) {
    if(memcmp(digest, U->md5s[i].md5, 16)) continue;
    if(rhash) *rhash = U->md5s[i].name;
    return U->md5s[i].count;
  }

  return 0;
}
#endif

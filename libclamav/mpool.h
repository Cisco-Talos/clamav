/*
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

#ifndef MPOOL_H
#define MPOOL_H

#ifdef USE_MPOOL
#include "cltypes.h"
typedef struct MP mp_t;

mp_t *mp_create(void);
void mp_destroy(mp_t *mp);
void *mp_malloc(mp_t *mp, size_t size);
void mp_free(mp_t *mp, void *ptr);
void *mp_calloc(mp_t *mp, size_t nmemb, size_t size);
void *mp_realloc(mp_t *mp, void *ptr, size_t size);
void *mp_realloc2(mp_t *mp, void *ptr, size_t size);
unsigned char *cli_mp_hex2str(mp_t* mp, const unsigned char *src);
char *cli_mp_strdup(mp_t *mp, const char *s);
char *cli_mp_virname(mp_t *mp, const char *virname, unsigned int official);
uint16_t *cli_mp_hex2ui(mp_t *mp, const char *hex);
void mp_flush(mp_t *mp);
int mp_getstats(const struct cl_engine *engine, size_t *used, size_t *total);
#else /* USE_MPOOL */

typedef void mp_t;
#define mp_malloc(a, b) cli_malloc(b)
#define mp_free(a, b) free(b)
#define mp_calloc(a, b, c) cli_calloc(b, c)
#define mp_realloc(a, b, c) cli_realloc(b, c)
#define mp_realloc2(a, b, c) cli_realloc2(b, c)
#define cli_mp_hex2str(mp, src) cli_hex2str(src)
#define cli_mp_strdup(mp, s) cli_strdup(s)
#define cli_mp_virname(mp, a, b) cli_virname(a, b)
#define cli_mp_hex2ui(mp, hex) cli_hex2ui(hex)
#define mp_flush(val)
#define mp_getstats(mp,used,total) -1
#endif /* USE_MPOOL */

#endif

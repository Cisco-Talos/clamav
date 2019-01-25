/*
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

#ifndef MPOOL_H
#define MPOOL_H

#ifdef USE_MPOOL
#include "clamav-types.h"
typedef struct MP mpool_t;
struct cl_engine;

mpool_t *mpool_create(void);
void mpool_destroy(mpool_t *mpool);
void *mpool_malloc(mpool_t *mpool, size_t size);
void mpool_free(mpool_t *mpool, void *ptr);
void *mpool_calloc(mpool_t *mpool, size_t nmemb, size_t size);
void *mpool_realloc(mpool_t *mpool, void *ptr, size_t size);
void *mpool_realloc2(mpool_t *mpool, void *ptr, size_t size);
char *cli_mpool_hex2str(mpool_t* mpool, const char *src);
char *cli_mpool_strdup(mpool_t *mpool, const char *s);
char *cli_mpool_strndup(mpool_t *mpool, const char *s, size_t n);
char *cli_mpool_virname(mpool_t *mpool, const char *virname, unsigned int official);
uint16_t *cli_mpool_hex2ui(mpool_t *mpool, const char *hex);
void mpool_flush(mpool_t *mpool);
int mpool_getstats(const struct cl_engine *engine, size_t *used, size_t *total);
#else /* USE_MPOOL */

typedef void mpool_t;
#define mpool_malloc(a, b) cli_malloc(b)
#define mpool_free(a, b) free(b)
#define mpool_calloc(a, b, c) cli_calloc(b, c)
#define mpool_realloc(a, b, c) cli_realloc(b, c)
#define mpool_realloc2(a, b, c) cli_realloc2(b, c)
#define cli_mpool_hex2str(mpool, src) cli_hex2str(src)
#define cli_mpool_strdup(mpool, s) cli_strdup(s)
#define cli_mpool_strndup(mpool, s, n) cli_strdup(s, n)
#define cli_mpool_virname(mpool, a, b) cli_virname(a, b)
#define cli_mpool_hex2ui(mpool, hex) cli_hex2ui(hex)
#define mpool_flush(val)
#define mpool_getstats(mpool,used,total) -1
#endif /* USE_MPOOL */

#endif

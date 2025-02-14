/*
 *  Copyright (C) 2013-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
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

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

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
char *cli_mpool_hex2str(mpool_t *mpool, const char *src);
char *cli_mpool_strdup(mpool_t *mpool, const char *s);
char *cli_mpool_strndup(mpool_t *mpool, const char *s, size_t n);
char *cli_mpool_virname(mpool_t *mpool, const char *virname, unsigned int official);
uint16_t *cli_mpool_hex2ui(mpool_t *mpool, const char *hex);
void mpool_flush(mpool_t *mpool);
int mpool_getstats(const struct cl_engine *engine, size_t *used, size_t *total);

#define MPOOL_MALLOC(a, b) mpool_malloc(a, b)
#define MPOOL_FREE(a, b) mpool_free(a, b)
#define MPOOL_CALLOC(a, b, c) mpool_calloc(a, b, c)
#define MPOOL_REALLOC(a, b, c) mpool_realloc(a, b, c)
#define MPOOL_REALLOC2(a, b, c) mpool_realloc2(a, b, c)
#define CLI_MPOOL_HEX2STR(mpool, src) cli_mpool_hex2str(mpool, src)
#define CLI_MPOOL_STRDUP(mpool, s) cli_mpool_strdup(mpool, s)
#define CLI_MPOOL_STRNDUP(mpool, s, n) cli_mpool_strndup(mpool, s, n)
#define CLI_MPOOL_VIRNAME(mpool, a, b) cli_mpool_virname(mpool, a, b)
#define CLI_MPOOL_HEX2UI(mpool, hex) cli_mpool_hex2ui(mpool, hex)
#define MPOOL_FLUSH(val) mpool_flush(val)
#define MPOOL_GETSTATS(mpool, used, total) mpool_getstats(mpool, used, total)

#else /* USE_MPOOL */

typedef void mpool_t;

#define MPOOL_MALLOC(a, b) malloc(b)
#define MPOOL_FREE(a, b) free(b)
#define MPOOL_CALLOC(a, b, c) calloc(b, c)
#define MPOOL_REALLOC(a, b, c) cli_safer_realloc(b, c)
#define MPOOL_REALLOC2(a, b, c) cli_safer_realloc_or_free(b, c)
#define CLI_MPOOL_HEX2STR(mpool, src) cli_hex2str(src)
#define CLI_MPOOL_STRDUP(mpool, s) cli_safer_strdup(s)
#define CLI_MPOOL_STRNDUP(mpool, s, n) cli_safer_strdup(s, n)
#define CLI_MPOOL_VIRNAME(mpool, a, b) cli_virname(a, b)
#define CLI_MPOOL_HEX2UI(mpool, hex) cli_hex2ui(hex)
#define MPOOL_FLUSH(val)
#define MPOOL_GETSTATS(mpool, used, total) -1

#endif /* USE_MPOOL */

#endif

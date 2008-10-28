/*
 *  Copyright (C) 2008 Sourcefire, Inc.
 *
 *  Authors: Alberto Wu
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

typedef struct MP mp_t;

mp_t *mp_create(void);
void mp_destroy(mp_t *mp);
void *mp_malloc(mp_t *mp, size_t size);
void mp_free(mp_t *mp, void *ptr);
void *mp_calloc(mp_t *mp, size_t nmemb, size_t size);
void *mp_realloc(mp_t *mp, void *ptr, size_t size);
void *mp_realloc2(mp_t *mp, void *ptr, size_t size);
void mp_flush(mp_t *mp);

#else /* USE_MPOOL */

#define mp_malloc(a, b) cli_malloc(b)
#define mp_free(a, b) free(b)
#define mp_calloc(a, b, c) cli_calloc(b, c)
#define mp_realloc(a, b, c) cli_realloc(b, c)
#define mp_realloc2(a, b, c) cli_realloc2(b, c)

#endif /* USE_MPOOL */

#endif

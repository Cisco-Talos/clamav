/*
 *  Copyright (C) 2009 Sourcefire, Inc.
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

#ifndef __FMAP_H
#define __FMAP_H

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <time.h>
#include <string.h>
#include "cltypes.h"
#include "clamav.h"

struct cl_fmap;
typedef cl_fmap_t fmap_t;

struct cl_fmap {
    /* handle interface */
    void *handle;
    clcb_pread pread_cb;

    /* internal */
    time_t mtime;
    unsigned int pages;
    unsigned int hdrsz;
    unsigned int pgsz;
    unsigned int paged;
    unsigned short aging;
    unsigned short dont_cache_flag;

    /* memory interface */
    void *data;

    /* common interface */
    size_t offset;
    size_t len;

    /* vtable for implementation */
    void        (*unmap)(fmap_t*);
    const void* (*need)(fmap_t*, size_t at, size_t len, int lock);
    const void* (*need_offstr)(fmap_t*, size_t at, size_t len_hint);
    const void* (*gets)(fmap_t*, char *dst, size_t *at, size_t max_len);
    void        (*unneed_off)(fmap_t*, size_t at, size_t len);
#ifdef _WIN32
    HANDLE fh;
    HANDLE mh;
#endif
    uint32_t placeholder_for_bitmap;
};

fmap_t *fmap(int fd, off_t offset, size_t len);
fmap_t *fmap_check_empty(int fd, off_t offset, size_t len, int *empty);

static inline void funmap(fmap_t *m)
{
    m->unmap(m);
}

static inline const void *fmap_need_off(fmap_t *m, size_t at, size_t len)
{
    return m->need(m, at, len, 1);
}

static inline const void *fmap_need_off_once(fmap_t *m, size_t at, size_t len)
{
    return m->need(m, at, len, 0);
}

static inline const void *fmap_need_ptr(fmap_t *m, void *ptr, size_t len)
{
    return m->need(m, (char *)ptr - (char *)m - m->hdrsz, len, 1);
}

static inline const void *fmap_need_ptr_once(fmap_t *m, void *ptr, size_t len)
{
    return m->need(m, (char *)ptr - (char *)m - m->hdrsz, len, 0);
}

static inline void fmap_unneed_off(fmap_t *m, size_t at, size_t len)
{
    m->unneed_off(m, at, len);
}

static inline void fmap_unneed_ptr(fmap_t *m, void *ptr, size_t len)
{
    fmap_unneed_off(m, (char *)ptr - (char *)m - m->hdrsz, len);
}

static inline int fmap_readn(fmap_t *m, void *dst, size_t at, size_t len)
{
    const void *src;

    if(at == m->len)
	return 0;
    if(at > m->len)
	return -1;
    if(len > m->len - at)
	len = m->len - at;
    src = fmap_need_off_once(m, at, len);
    if(!src)
	return -1;
    memcpy(dst, src, len);
    return len;
}

static inline const void *fmap_need_str(fmap_t *m, void *ptr, size_t len_hint)
{
    return m->need_offstr(m, (char *)ptr - (char *)m - m->hdrsz, len_hint);
}

static inline const void *fmap_need_offstr(fmap_t *m, size_t at, size_t len_hint)
{
    return m->need_offstr(m, at, len_hint);
}

static inline const void *fmap_gets(fmap_t *m, char *dst, size_t *at, size_t max_len) {
    return m->gets(m, dst, at, max_len);
}

static inline const void *fmap_need_off_once_len(fmap_t *m, size_t at, size_t len, size_t *lenout)
{
    const void *p;
    if(at >= m->len) {
	*lenout = 0;
	return NULL;
    }
    if(len > m->len - at)
	len = m->len - at;
    p = fmap_need_off_once(m, at, len);
    *lenout = p ? len : 0;
    return p;
}

static inline const void *fmap_need_ptr_once_len(fmap_t *m, const void *ptr, size_t len, size_t *lenout)
{
    return fmap_need_off_once_len(m, (char*)ptr - (char*)m - m->hdrsz, len, lenout);
}

/* deprecated */
int fmap_fd(fmap_t *m);

#endif

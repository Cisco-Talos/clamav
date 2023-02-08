/*
 *  Copyright (C) 2013-2023 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2009-2013 Sourcefire, Inc.
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

/* an mmap "replacement" which doesn't suck */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <libgen.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef ANONYMOUS_MAP
#ifdef HAVE_SYS_MMAN_H
#include <sys/mman.h>
#endif
#endif
#include <errno.h>

#ifdef C_LINUX
#include <pthread.h>
#endif

#include "clamav.h"
#include "others.h"
#include "str.h"

#define FM_MASK_COUNT 0x3fffffff
#define FM_MASK_PAGED 0x40000000
#define FM_MASK_SEEN 0x80000000
#define FM_MASK_LOCKED FM_MASK_SEEN
/* 2 high bits:
00 - not seen - not paged - N/A
01 -    N/A   -   paged   - not locked
10 -   seen   - not paged - N/A
11 -    N/A   -   paged   - locked
*/

/* FIXME: tune this stuff */
#define UNPAGE_THRSHLD_LO 4 * 1024 * 1024
#define UNPAGE_THRSHLD_HI 8 * 1024 * 1024
#define READAHEAD_PAGES 8

#if defined(ANONYMOUS_MAP) && defined(C_LINUX) && defined(CL_THREAD_SAFE)
/*
   WORKAROUND
   Relieve some stress on mmap_sem.
   When mmap_sem is heavily hammered, the scheduler
   tends to fail to wake us up properly.
*/
pthread_mutex_t fmap_mutex = PTHREAD_MUTEX_INITIALIZER;
#define fmap_lock pthread_mutex_lock(&fmap_mutex)
#define fmap_unlock pthread_mutex_unlock(&fmap_mutex);
#else
#define fmap_lock
#define fmap_unlock
#endif

#ifndef MADV_DONTFORK
#define MADV_DONTFORK 0
#endif

#define fmap_bitmap (m->bitmap)

static inline uint64_t fmap_align_items(uint64_t sz, uint64_t al);
static inline uint64_t fmap_align_to(uint64_t sz, uint64_t al);
static inline uint64_t fmap_which_page(fmap_t *m, size_t at);

static const void *handle_need(fmap_t *m, size_t at, size_t len, int lock);
static void handle_unneed_off(fmap_t *m, size_t at, size_t len);
static const void *handle_need_offstr(fmap_t *m, size_t at, size_t len_hint);
static const void *handle_gets(fmap_t *m, char *dst, size_t *at, size_t max_len);

static void unmap_mmap(fmap_t *m);
static void unmap_malloc(fmap_t *m);

#ifndef _WIN32
/* pread proto here in order to avoid the use of XOPEN and BSD_SOURCE
   which may in turn prevent some mmap constants to be defined */
ssize_t pread(int fd, void *buf, size_t count, off_t offset);

/* vvvvv POSIX STUFF BELOW vvvvv */
static off_t pread_cb(void *handle, void *buf, size_t count, off_t offset)
{
    return pread((int)(ssize_t)handle, buf, count, offset);
}

fmap_t *fmap_check_empty(int fd, off_t offset, size_t len, int *empty, const char *name)
{
    STATBUF st;
    fmap_t *m = NULL;

    *empty = 0;
    if (FSTAT(fd, &st)) {
        cli_warnmsg("fmap: fstat failed\n");
        return NULL;
    }

    if (!len) len = st.st_size - offset; /* bound checked later */
    if (!len) {
        cli_dbgmsg("fmap: attempted void mapping\n");
        *empty = 1;
        return NULL;
    }
    if (!CLI_ISCONTAINED_0_TO(st.st_size, offset, len)) {
        cli_warnmsg("fmap: attempted oof mapping\n");
        return NULL;
    }
    m = cl_fmap_open_handle((void *)(ssize_t)fd, offset, len, pread_cb, 1);
    if (!m)
        return NULL;
    m->mtime = st.st_mtime;

    if (NULL != name) {
        m->name = cli_strdup(name);
        if (NULL == m->name) {
            funmap(m);
            return NULL;
        }
    }

    return m;
}
#else
/* vvvvv WIN32 STUFF BELOW vvvvv */
static void unmap_win32(fmap_t *m)
{
    if (NULL != m) {
        if (NULL != m->data) {
            UnmapViewOfFile(m->data);
        }
        if (NULL != m->mh) {
            CloseHandle(m->mh);
        }
        if (NULL != m->name) {
            free(m->name);
        }
        free((void *)m);
    }
}

fmap_t *fmap_check_empty(int fd, off_t offset, size_t len, int *empty, const char *name)
{ /* WIN32 */
    uint64_t pages, mapsz;
    int pgsz = cli_getpagesize();
    STATBUF st;
    fmap_t *m = NULL;
    const void *data;
    HANDLE fh;
    HANDLE mh;

    *empty = 0;
    if (FSTAT(fd, &st)) {
        cli_warnmsg("fmap: fstat failed\n");
        return NULL;
    }
    if (offset < 0 || offset != fmap_align_to(offset, pgsz)) {
        cli_warnmsg("fmap: attempted mapping with unaligned offset\n");
        return NULL;
    }
    if (!len) len = st.st_size - offset; /* bound checked later */
    if (!len) {
        cli_dbgmsg("fmap: attempted void mapping\n");
        *empty = 1;
        return NULL;
    }
    if (!CLI_ISCONTAINED_0_TO(st.st_size, offset, len)) {
        cli_warnmsg("fmap: attempted oof mapping\n");
        return NULL;
    }

    pages = fmap_align_items(len, pgsz);

    if ((fh = (HANDLE)_get_osfhandle(fd)) == INVALID_HANDLE_VALUE) {
        cli_errmsg("fmap: cannot get a valid handle for descriptor %d\n", fd);
        return NULL;
    }
    if (!(mh = CreateFileMapping(fh, NULL, PAGE_READONLY, (DWORD)((len >> 31) >> 1), (DWORD)len, NULL))) {
        cli_errmsg("fmap: cannot create a map of descriptor %d\n", fd);
        return NULL;
    }
    if (!(data = MapViewOfFile(mh, FILE_MAP_READ, (DWORD)((offset >> 31) >> 1), (DWORD)(offset), len))) {
        cli_errmsg("fmap: cannot map file descriptor %d\n", fd);
        CloseHandle(mh);
        return NULL;
    }
    if (!(m = cl_fmap_open_memory(data, len))) {
        cli_errmsg("fmap: cannot allocate fmap_t\n", fd);
        UnmapViewOfFile(data);
        CloseHandle(mh);
        return NULL;
    }
    m->handle       = (void *)(size_t)fd;
    m->handle_is_fd = 1; /* This is probably(?) needed so `fmap_fd()` can return the file descriptor. */
    m->fh           = fh;
    m->mh           = mh;
    m->unmap        = unmap_win32;

    if (NULL != name) {
        m->name = cli_strdup(name);
        if (NULL == m->name) {
            funmap(m);
            return NULL;
        }
    }

    return m;
}
#endif /* _WIN32 */

/* vvvvv SHARED STUFF BELOW vvvvv */

fmap_t *fmap_duplicate(cl_fmap_t *map, size_t offset, size_t length, const char *name)
{
    cl_error_t status        = CL_ERROR;
    cl_fmap_t *duplicate_map = NULL;

    if (NULL == map) {
        cli_warnmsg("fmap_duplicate: map is NULL!\n");
        goto done;
    }

    duplicate_map = cli_malloc(sizeof(cl_fmap_t));
    if (!duplicate_map) {
        cli_warnmsg("fmap_duplicate: map allocation failed\n");
        goto done;
    }

    /* Duplicate the state of the original map */
    memcpy(duplicate_map, map, sizeof(cl_fmap_t));

    if (offset > map->len) {
        /* invalid offset, exceeds length of map */
        cli_warnmsg("fmap_duplicate: requested offset exceeds end of map\n");
        goto done;
    }

    if (offset > 0 || length < map->len) {
        /*
         * Caller requested a window into the current map, not the whole map.
         */

        /* Set the new nested offset and (nested) length for the new map */
        /* Note: We can't change offset because then we'd have to discard/move cached
         * data, instead use nested_offset to reuse the already cached data */
        duplicate_map->nested_offset += offset;
        duplicate_map->len = MIN(length, map->len - offset);

        /* The real_len is the nested_offset + the len of the nested fmap.
           real_len is mostly just a shorthand for when doing bounds checking.
           We do not need to keep track of the original length of the OG fmap */
        duplicate_map->real_len = duplicate_map->nested_offset + duplicate_map->len;

        if (!CLI_ISCONTAINED_2(map->nested_offset, map->len,
                               duplicate_map->nested_offset, duplicate_map->len)) {
            size_t len1, len2;
            len1 = map->nested_offset + map->len;
            len2 = duplicate_map->nested_offset + duplicate_map->len;
            cli_warnmsg("fmap_duplicate: internal map error: %zu, %zu; %zu, %zu\n",
                        map->nested_offset, len1,
                        duplicate_map->nested_offset, len2);
        }

        /* This also means the hash will be different.
         * Clear the have_<hash> flags.
         * It will be calculated when next it is needed. */
        duplicate_map->have_md5    = false;
        duplicate_map->have_sha1   = false;
        duplicate_map->have_sha256 = false;
    }

    if (NULL != name) {
        duplicate_map->name = cli_strdup(name);
        if (NULL == duplicate_map->name) {
            status = CL_EMEM;
            goto done;
        }
    } else {
        duplicate_map->name = NULL;
    }

    status = CL_SUCCESS;

done:
    if (CL_SUCCESS != status) {
        if (NULL != duplicate_map) {
            free(duplicate_map);
            duplicate_map = NULL;
        }
    }

    return duplicate_map;
}

void free_duplicate_fmap(cl_fmap_t *map)
{
    if (NULL != map) {
        if (NULL != map->name) {
            free(map->name);
            map->name = NULL;
        }
        free(map);
    }
}

static void unmap_handle(fmap_t *m)
{
    if (NULL != m) {
        if (NULL != m->data) {
            if (m->aging) {
                unmap_mmap(m);
            } else {
                free((void *)m->data);
            }
            m->data = NULL;
        }
        if (NULL != m->bitmap) {
            free(m->bitmap);
            m->bitmap = NULL;
        }
        if (NULL != m->name) {
            free(m->name);
        }
        free((void *)m);
    }
}

extern cl_fmap_t *cl_fmap_open_handle(void *handle, size_t offset, size_t len,
                                      clcb_pread pread_cb, int use_aging)
{
    cl_error_t status = CL_EMEM;
    uint64_t pages;
    size_t mapsz, bitmap_size;
    cl_fmap_t *m = NULL;
    int pgsz     = cli_getpagesize();

    if ((off_t)offset < 0 || offset != fmap_align_to(offset, pgsz)) {
        cli_warnmsg("fmap: attempted mapping with unaligned offset\n");
        goto done;
    }
    if (!len) {
        cli_dbgmsg("fmap: attempted void mapping\n");
        goto done;
    }
    if (offset >= len) {
        cli_warnmsg("fmap: attempted oof mapping\n");
        goto done;
    }

    pages = fmap_align_items(len, pgsz);

    bitmap_size = pages * sizeof(uint64_t);
    mapsz       = pages * pgsz;

    m = cli_calloc(1, sizeof(fmap_t));
    if (!m) {
        cli_warnmsg("fmap: map header allocation failed\n");
        goto done;
    }

    m->bitmap = cli_calloc(1, bitmap_size);
    if (!m->bitmap) {
        cli_warnmsg("fmap: map header allocation failed\n");
        goto done;
    }

#ifndef ANONYMOUS_MAP
    use_aging = 0;
#endif
#ifdef ANONYMOUS_MAP
    if (use_aging) {
        fmap_lock;
        if ((m->data = (fmap_t *)mmap(NULL,
                                      mapsz,
                                      PROT_READ | PROT_WRITE, MAP_PRIVATE | /* FIXME: MAP_POPULATE is ~8% faster but more memory intensive */ ANONYMOUS_MAP,
                                      -1,
                                      0)) == MAP_FAILED) {
            m->data = NULL;
        } else {
#if HAVE_MADVISE
            madvise((void *)m->data, mapsz, MADV_RANDOM | MADV_DONTFORK);
#endif /* madvise */
        }
        fmap_unlock;
    }
#endif /* ANONYMOUS_MAP */
    if (!use_aging) {
        m->data = (fmap_t *)cli_malloc(mapsz);
    }
    if (!m->data) {
        cli_warnmsg("fmap: map allocation failed\n");
        goto done;
    }
    m->handle          = handle;
    m->pread_cb        = pread_cb;
    m->aging           = use_aging;
    m->offset          = offset;
    m->nested_offset   = 0;
    m->len             = len; /* m->nested_offset + m->len = m->real_len */
    m->real_len        = len;
    m->pages           = pages;
    m->pgsz            = pgsz;
    m->paged           = 0;
    m->dont_cache_flag = false;
    m->unmap           = unmap_handle;
    m->need            = handle_need;
    m->need_offstr     = handle_need_offstr;
    m->gets            = handle_gets;
    m->unneed_off      = handle_unneed_off;
    m->handle_is_fd    = 1;
    m->have_md5        = false;
    m->have_sha1       = false;
    m->have_sha256     = false;

    status = CL_SUCCESS;

done:
    if (CL_SUCCESS != status) {
        unmap_handle(m);
        m = NULL;
    }
    return m;
}

static void fmap_aging(fmap_t *m)
{
#ifdef ANONYMOUS_MAP
    if (!m->aging) return;
    if (m->paged * m->pgsz > UNPAGE_THRSHLD_HI) { /* we alloc'd too much */
        uint64_t i, avail = 0, freeme[2048], maxavail = MIN(sizeof(freeme) / sizeof(*freeme), m->paged - UNPAGE_THRSHLD_LO / m->pgsz) - 1;

        for (i = 0; i < m->pages; i++) {
            uint64_t s = fmap_bitmap[i];
            if ((s & (FM_MASK_PAGED | FM_MASK_LOCKED)) == FM_MASK_PAGED) {
                /* page is paged and not locked: dec age */
                if (s & FM_MASK_COUNT) fmap_bitmap[i]--;
                /* and make it available for unpaging */

                if (!avail) {
                    freeme[0] = i;
                    avail++;
                } else {
                    /* Insert sort onto a stack'd array - same performance as quickselect */
                    uint64_t insert_to = MIN(maxavail, avail) - 1, age = fmap_bitmap[i] & FM_MASK_COUNT;
                    if (avail <= maxavail || (fmap_bitmap[freeme[maxavail]] & FM_MASK_COUNT) > age) {
                        while ((fmap_bitmap[freeme[insert_to]] & FM_MASK_COUNT) > age) {
                            freeme[insert_to + 1] = freeme[insert_to];
                            if (!insert_to--) break;
                        }
                        freeme[insert_to + 1] = i;
                        if (avail <= maxavail) avail++;
                    }
                }
            }
        }
        if (avail) { /* at least one page is paged and not locked */
            char *lastpage  = NULL;
            char *firstpage = NULL;
            for (i = 0; i < avail; i++) {
                char *pptr = (char *)m->data + freeme[i] * m->pgsz;
                /* we mark the page as seen */
                fmap_bitmap[freeme[i]] = FM_MASK_SEEN;
                /* and we mmap the page over so the kernel knows there's nothing good in there */
                /* reduce number of mmap calls: if pages are adjacent only do 1 mmap call */
                if (lastpage && pptr == lastpage) {
                    lastpage = pptr + m->pgsz;
                    continue;
                }
                if (!lastpage) {
                    firstpage = pptr;
                    lastpage  = pptr + m->pgsz;
                    continue;
                }
                fmap_lock;
                if (mmap(firstpage, lastpage - firstpage, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_PRIVATE | ANONYMOUS_MAP, -1, 0) == MAP_FAILED)
                    cli_dbgmsg("fmap_aging: kernel hates you\n");
                fmap_unlock;
                firstpage = pptr;
                lastpage  = pptr + m->pgsz;
            }
            if (lastpage) {
                fmap_lock;
                if (mmap(firstpage, lastpage - firstpage, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_PRIVATE | ANONYMOUS_MAP, -1, 0) == MAP_FAILED)
                    cli_dbgmsg("fmap_aging: kernel hates you\n");
                fmap_unlock;
            }
            m->paged -= avail;
        }
    }
#else
    UNUSEDPARAM(m);
#endif
}

static int fmap_readpage(fmap_t *m, uint64_t first_page, uint64_t count, uint64_t lock_count)
{
    size_t readsz = 0, eintr_off;
    char *pptr    = NULL, errtxt[256];
    uint64_t sbitmap;
    uint64_t i, page = first_page, force_read = 0;

    if ((uint64_t)(m->real_len) > (uint64_t)(m->pages * m->pgsz)) {
        cli_dbgmsg("fmap_readpage: size of file exceeds total prefaultible page size (unpacked file is too large)\n");
        return 1;
    }

    fmap_lock;
    for (i = 0; i < count; i++) { /* prefault */
        /* Not worth checking if the page is already paged, just ping each */
        /* Also not worth reusing the loop below */
        volatile char faultme;
        faultme = ((char *)m->data)[(first_page + i) * m->pgsz];
        (void)faultme; // silence "warning: variable ‘faultme’ set but not used"
    }
    fmap_unlock;
    for (i = 0; i <= count; i++, page++) {
        int lock;
        if (lock_count) {
            lock_count--;
            lock = 1;
        } else
            lock = 0;
        if (i == count) {
            /* we count one page too much to flush pending reads */
            if (!pptr) return 0; /* if we have any */
            force_read = 1;
        } else if ((sbitmap = fmap_bitmap[page]) & FM_MASK_PAGED) {
            /* page already paged */
            if (lock) {
                /* we want locking */
                if (sbitmap & FM_MASK_LOCKED) {
                    /* page already locked */
                    sbitmap &= FM_MASK_COUNT;
                    if (sbitmap == FM_MASK_COUNT) { /* lock count already at max: fial! */
                        cli_errmsg("fmap_readpage: lock count exceeded\n");
                        return 1;
                    }
                    /* acceptable lock count: inc lock count */
                    fmap_bitmap[page]++;
                } else /* page not currently locked: set lock count = 1 */
                    fmap_bitmap[page] = 1 | FM_MASK_LOCKED | FM_MASK_PAGED;
            } else {
                /* we don't want locking */
                if (!(sbitmap & FM_MASK_LOCKED)) {
                    /* page is not locked: we reset aging to max */
                    fmap_bitmap[page] = FM_MASK_PAGED | FM_MASK_COUNT;
                }
            }
            if (!pptr) continue;
            force_read = 1;
        }

        if (force_read) {
            /* we have some pending reads to perform */
            if (m->handle_is_fd) {
                uint64_t j;
                int _fd = (int)(ptrdiff_t)m->handle;
                for (j = first_page; j < page; j++) {
                    if (fmap_bitmap[j] & FM_MASK_SEEN) {
                        /* page we've seen before: check mtime */
                        STATBUF st;
                        if (FSTAT(_fd, &st)) {
                            cli_strerror(errno, errtxt, sizeof(errtxt));
                            cli_warnmsg("fmap_readpage: fstat failed: %s\n", errtxt);
                            return 1;
                        }
                        if (m->mtime != st.st_mtime) {
                            cli_warnmsg("fmap_readpage: file changed as we read it\n");
                            return 1;
                        }
                        break;
                    }
                }
            }

            eintr_off = 0;
            while (readsz) {
                ssize_t got;
                uint64_t target_offset = eintr_off + m->offset + (first_page * m->pgsz);
                got                    = m->pread_cb(m->handle, pptr, readsz, target_offset);

                if (got < 0 && errno == EINTR)
                    continue;

                if (got > 0) {
                    pptr += got;
                    eintr_off += got;
                    readsz -= got;
                    continue;
                }

                if (got < 0) {
                    cli_strerror(errno, errtxt, sizeof(errtxt));
                    cli_errmsg("fmap_readpage: pread error: %s\n", errtxt);
                } else {
                    cli_warnmsg("fmap_readpage: pread fail: asked for %zu bytes @ offset " STDu64 ", got %zd\n", readsz, target_offset, got);
                }
                return 1;
            }

            pptr       = NULL;
            force_read = 0;
            readsz     = 0;
            continue;
        }

        /* page is not already paged */
        if (!pptr) {
            /* set a new start for pending reads if we don't have one */
            pptr       = (char *)m->data + page * m->pgsz;
            first_page = page;
        }
        if ((page == m->pages - 1) && (m->real_len % m->pgsz))
            readsz += m->real_len % m->pgsz;
        else
            readsz += m->pgsz;
        if (lock) /* lock requested: set paged, lock page and set lock count to 1 */
            fmap_bitmap[page] = FM_MASK_PAGED | FM_MASK_LOCKED | 1;
        else /* no locking: set paged and set aging to max */
            fmap_bitmap[page] = FM_MASK_PAGED | FM_MASK_COUNT;
        m->paged++;
    }
    return 0;
}

static const void *handle_need(fmap_t *m, size_t at, size_t len, int lock)
{
    uint64_t first_page, last_page, lock_count;
    char *ret;

    if (!len)
        return NULL;

    at += m->nested_offset;
    if (!CLI_ISCONTAINED(m->nested_offset, m->len, at, len))
        return NULL;

    fmap_aging(m);

    first_page = fmap_which_page(m, at);
    last_page  = fmap_which_page(m, at + len - 1);
    lock_count = (lock != 0) * (last_page - first_page + 1);
#ifdef READAHED_PAGES
    last_page += READAHED_PAGES;
    if (last_page >= m->pages) last_page = m->pages - 1;
#endif

    if (fmap_readpage(m, first_page, last_page - first_page + 1, lock_count))
        return NULL;

    ret = (char *)m->data + at;
    return (void *)ret;
}

static void fmap_unneed_page(fmap_t *m, uint64_t page)
{
    uint64_t s = fmap_bitmap[page];

    if ((s & (FM_MASK_PAGED | FM_MASK_LOCKED)) == (FM_MASK_PAGED | FM_MASK_LOCKED)) {
        /* page is paged and locked: check lock count */
        s &= FM_MASK_COUNT;
        if (s > 1) /* locked more than once: dec lock count */
            fmap_bitmap[page]--;
        else if (s == 1) /* only one lock left: unlock and begin aging */
            fmap_bitmap[page] = FM_MASK_COUNT | FM_MASK_PAGED;
        else
            cli_errmsg("fmap_unneed: inconsistent map state\n");
        return;
    }
    cli_warnmsg("fmap_unneed: unneed on a unlocked page\n");
    return;
}

static void handle_unneed_off(fmap_t *m, size_t at, size_t len)
{
    uint64_t i, first_page, last_page;
    if (!m->aging) return;
    if (!len) {
        cli_warnmsg("fmap_unneed: attempted void unneed\n");
        return;
    }

    at += m->nested_offset;
    if (!CLI_ISCONTAINED(m->nested_offset, m->len, at, len)) {
        cli_warnmsg("fmap: attempted oof unneed\n");
        return;
    }

    first_page = fmap_which_page(m, at);
    last_page  = fmap_which_page(m, at + len - 1);

    for (i = first_page; i <= last_page; i++) {
        fmap_unneed_page(m, i);
    }
}

static void unmap_mmap(fmap_t *m)
{
#ifdef ANONYMOUS_MAP
    size_t len = m->pages * m->pgsz;
    fmap_lock;
    if (munmap((void *)m->data, len) == -1) /* munmap() failed */
        cli_warnmsg("funmap: unable to unmap memory segment at address: %p with length: %zu\n", (void *)m->data, len);
    fmap_unlock;
#else
    UNUSEDPARAM(m);
#endif
}

static void unmap_malloc(fmap_t *m)
{
    if (NULL != m) {
        if (NULL != m->name) {
            free(m->name);
        }
        free((void *)m);
    }
}

static const void *handle_need_offstr(fmap_t *m, size_t at, size_t len_hint)
{
    uint64_t i, first_page, last_page;
    void *ptr;

    at += m->nested_offset;
    ptr = (void *)((char *)m->data + at);

    if (!len_hint || len_hint > m->real_len - at)
        len_hint = m->real_len - at;

    if (!CLI_ISCONTAINED(m->nested_offset, m->len, at, len_hint))
        return NULL;

    fmap_aging(m);

    first_page = fmap_which_page(m, at);
    last_page  = fmap_which_page(m, at + len_hint - 1);

    for (i = first_page; i <= last_page; i++) {
        char *thispage = (char *)m->data + i * m->pgsz;
        uint64_t scanat, scansz;

        if (fmap_readpage(m, i, 1, 1)) {
            last_page = i - 1;
            break;
        }
        if (i == first_page) {
            scanat = at % m->pgsz;
            scansz = MIN(len_hint, m->pgsz - scanat);
        } else {
            scanat = 0;
            scansz = MIN(len_hint, m->pgsz);
        }
        len_hint -= scansz;
        if (memchr(&thispage[scanat], 0, scansz))
            return ptr;
    }
    for (i = first_page; i <= last_page; i++)
        fmap_unneed_page(m, i);
    return NULL;
}

static const void *handle_gets(fmap_t *m, char *dst, size_t *at, size_t max_len)
{
    uint64_t i, first_page, last_page;
    char *src     = (char *)m->data + m->nested_offset + *at;
    char *endptr  = NULL;
    size_t len    = MIN(max_len - 1, m->len - *at);
    size_t fullen = len;

    if (!len || !CLI_ISCONTAINED_0_TO(m->len, *at, len))
        return NULL;

    fmap_aging(m);

    first_page = fmap_which_page(m, m->nested_offset + *at);
    last_page  = fmap_which_page(m, m->nested_offset + *at + len - 1);

    for (i = first_page; i <= last_page; i++) {
        char *thispage = (char *)m->data + i * m->pgsz;
        uint64_t scanat, scansz;

        if (fmap_readpage(m, i, 1, 0))
            return NULL;

        if (i == first_page) {
            scanat = (m->nested_offset + *at) % m->pgsz;
            scansz = MIN(len, m->pgsz - scanat);
        } else {
            scanat = 0;
            scansz = MIN(len, m->pgsz);
        }
        len -= scansz;

        if ((endptr = memchr(&thispage[scanat], '\n', scansz))) {
            endptr++;
            break;
        }
    }
    if (endptr) {
        memcpy(dst, src, endptr - src);
        dst[endptr - src] = '\0';
        *at += endptr - src;
    } else {
        memcpy(dst, src, fullen);
        dst[fullen] = '\0';
        *at += fullen;
    }
    return dst;
}

/* vvvvv MEMORY STUFF BELOW vvvvv */

static const void *mem_need(fmap_t *m, size_t at, size_t len, int lock);
static void mem_unneed_off(fmap_t *m, size_t at, size_t len);
static const void *mem_need_offstr(fmap_t *m, size_t at, size_t len_hint);
static const void *mem_gets(fmap_t *m, char *dst, size_t *at, size_t max_len);

fmap_t *fmap_open_memory(const void *start, size_t len, const char *name)
{
    cl_error_t status = CL_ERROR;

    int pgsz     = cli_getpagesize();
    cl_fmap_t *m = cli_calloc(1, sizeof(*m));
    if (!m) {
        cli_warnmsg("fmap: map allocation failed\n");
        goto done;
    }
    m->data        = start;
    m->len         = len;
    m->real_len    = len;
    m->pgsz        = pgsz;
    m->pages       = fmap_align_items(len, pgsz);
    m->unmap       = unmap_malloc;
    m->need        = mem_need;
    m->need_offstr = mem_need_offstr;
    m->gets        = mem_gets;
    m->unneed_off  = mem_unneed_off;

    if (NULL != name) {
        /* Copy the name, if one is given */
        m->name = cli_strdup(name);
        if (NULL == m->name) {
            cli_warnmsg("fmap: failed to duplicate map name\n");
            goto done;
        }
    }

    status = CL_SUCCESS;

done:
    if (CL_SUCCESS != status) {
        if (NULL != m) {
            if (NULL != m->name) {
                free(m->name);
            }
            free(m);
            m = NULL;
        }
    }

    return m;
}

extern cl_fmap_t *cl_fmap_open_memory(const void *start, size_t len)
{
    return (cl_fmap_t *)fmap_open_memory(start, len, NULL);
}

static const void *mem_need(fmap_t *m, size_t at, size_t len, int lock)
{
    UNUSEDPARAM(lock);
    if (!len) {
        return NULL;
    }
    at += m->nested_offset;
    if (!CLI_ISCONTAINED(m->nested_offset, m->len, at, len)) {
        return NULL;
    }

    return (void *)((char *)m->data + at);
}

static void mem_unneed_off(fmap_t *m, size_t at, size_t len)
{
    UNUSEDPARAM(m);
    UNUSEDPARAM(at);
    UNUSEDPARAM(len);
}

static const void *mem_need_offstr(fmap_t *m, size_t at, size_t len_hint)
{
    char *ptr;

    at += m->nested_offset;
    ptr = (char *)m->data + at;

    if (!len_hint || len_hint > m->real_len - at)
        len_hint = m->real_len - at;

    if (!CLI_ISCONTAINED(m->nested_offset, m->len, at, len_hint))
        return NULL;

    if (memchr(ptr, 0, len_hint))
        return (void *)ptr;
    return NULL;
}

static const void *mem_gets(fmap_t *m, char *dst, size_t *at, size_t max_len)
{
    char *src    = (char *)m->data + m->nested_offset + *at;
    char *endptr = NULL;
    size_t len   = MIN(max_len - 1, m->len - *at);

    if (!len || !CLI_ISCONTAINED_0_TO(m->len, *at, len))
        return NULL;

    if ((endptr = memchr(src, '\n', len))) {
        endptr++;
        memcpy(dst, src, endptr - src);
        dst[endptr - src] = '\0';
        *at += endptr - src;
    } else {
        memcpy(dst, src, len);
        dst[len] = '\0';
        *at += len;
    }
    return dst;
}

fmap_t *fmap(int fd, off_t offset, size_t len, const char *name)
{
    int unused;
    return fmap_check_empty(fd, offset, len, &unused, name);
}

static inline uint64_t fmap_align_items(uint64_t sz, uint64_t al)
{
    return sz / al + (sz % al != 0);
}

static inline uint64_t fmap_align_to(uint64_t sz, uint64_t al)
{
    return al * fmap_align_items(sz, al);
}

static inline uint64_t fmap_which_page(fmap_t *m, size_t at)
{
    return at / m->pgsz;
}

cl_error_t fmap_dump_to_file(fmap_t *map, const char *filepath, const char *tmpdir, char **outname, int *outfd, size_t start_offset, size_t end_offset)
{
    cl_error_t ret = CL_EARG;

    char *filebase = NULL;
    char *prefix   = NULL;

    char *tmpname = NULL;
    int tmpfd     = -1;

    size_t pos = 0, len = 0, bytes_remaining = 0, write_size = 0;

    if ((start_offset > map->real_len) || (end_offset < start_offset)) {
        cli_dbgmsg("fmap_dump_to_file: Invalid offset arguments: start %zu, end %zu\n", start_offset, end_offset);
        return ret;
    }

    pos             = start_offset;
    end_offset      = MIN(end_offset, map->real_len);
    bytes_remaining = end_offset - start_offset;

    /* Create a filename prefix that includes the original filename, if available */
    if (filepath != NULL) {
        if (CL_SUCCESS != cli_basename(filepath, strlen(filepath), &filebase)) {
            cli_dbgmsg("fmap_dump_to_file: Unable to determine basename from filepath.\n");
        } else if ((start_offset != 0) && (end_offset != map->real_len)) {
            /* If we're only dumping a portion of the file, inlcude the offsets in the prefix,...
             * e.g. tmp filename will become something like:  filebase.500-1200.<randhex> */
            size_t prefix_len = strlen(filebase) + 1 + SIZE_T_CHARLEN + 1 + SIZE_T_CHARLEN + 1;
            prefix            = malloc(prefix_len);
            if (NULL == prefix) {
                cli_errmsg("fmap_dump_to_file: Failed to allocate memory for tempfile prefix.\n");
                free(filebase);
                return CL_EMEM;
            }
            snprintf(prefix, prefix_len, "%s.%zu-%zu", filebase, start_offset, end_offset);

            free(filebase);
            filebase = NULL;
        } else {
            /* Else if we're dumping the whole thing, use the filebase as the prefix */
            prefix   = filebase;
            filebase = NULL;
        }
    }

    cli_dbgmsg("fmap_dump_to_file: dumping fmap not backed by file...\n");
    ret = cli_gentempfd_with_prefix(tmpdir, prefix, &tmpname, &tmpfd);
    if (ret != CL_SUCCESS) {
        cli_dbgmsg("fmap_dump_to_file: failed to generate temporary file.\n");
        if (NULL != prefix) {
            free(prefix);
            prefix = NULL;
        }
        return ret;
    }

    if (NULL != prefix) {
        free(prefix);
        prefix = NULL;
    }

    do {
        const char *b;
        len        = 0;
        write_size = MIN(BUFSIZ, bytes_remaining);

        b = fmap_need_off_once_len(map, pos, write_size, &len);
        pos += len;
        if (b && (len > 0)) {
            if (cli_writen(tmpfd, b, len) != len) {
                cli_warnmsg("fmap_dump_to_file: write failed to %s!\n", tmpname);
                close(tmpfd);
                unlink(tmpname);
                free(tmpname);
                return CL_EWRITE;
            }
        }
        if (len <= bytes_remaining) {
            bytes_remaining -= len;
        } else {
            bytes_remaining = 0;
        }
    } while ((len > 0) && (bytes_remaining > 0));

    if (lseek(tmpfd, 0, SEEK_SET) == -1) {
        cli_dbgmsg("fmap_dump_to_file: lseek failed\n");
    }

    *outname = tmpname;
    *outfd   = tmpfd;
    return CL_SUCCESS;
}

int fmap_fd(fmap_t *m)
{
    int fd;
    if (NULL == m) {
        cli_errmsg("fmap_fd: Attempted to get fd for NULL fmap\n");
        return -1;
    }
    if (!m->handle_is_fd) {
        return -1;
    }
    fd = (int)(ptrdiff_t)m->handle;
    lseek(fd, 0, SEEK_SET);
    return fd;
}

extern void cl_fmap_close(cl_fmap_t *map)
{
    funmap(map);
}

cl_error_t fmap_set_hash(fmap_t *map, unsigned char *hash, cli_hash_type_t type)
{
    cl_error_t status = CL_SUCCESS;

    if (NULL == map) {
        cli_errmsg("fmap_set_hash: Attempted to set hash for NULL fmap\n");
        status = CL_EARG;
        goto done;
    }
    if (NULL == hash) {
        cli_errmsg("fmap_set_hash: Attempted to set hash to NULL\n");
        status = CL_EARG;
        goto done;
    }

    switch (type) {
        case CLI_HASH_MD5:
            memcpy(map->md5, hash, CLI_HASHLEN_MD5);
            map->have_md5 = true;
            break;
        case CLI_HASH_SHA1:
            memcpy(map->sha1, hash, CLI_HASHLEN_SHA1);
            map->have_sha1 = true;
            break;
        case CLI_HASH_SHA256:
            memcpy(map->sha256, hash, CLI_HASHLEN_SHA256);
            map->have_sha256 = true;
            break;
        default:
            cli_errmsg("fmap_set_hash: Unsupported hash type %u\n", type);
            status = CL_EARG;
            goto done;
    }

done:
    return status;
}

cl_error_t fmap_get_hash(fmap_t *map, unsigned char **hash, cli_hash_type_t type)
{
    cl_error_t status = CL_ERROR;
    size_t todo, at = 0;
    void *hashctx = NULL;

    todo = map->len;

    switch (type) {
        case CLI_HASH_MD5:
            if (map->have_md5) {
                goto complete;
            }
            break;
        case CLI_HASH_SHA1:
            if (map->have_sha1) {
                goto complete;
            }
            break;
        case CLI_HASH_SHA256:
            if (map->have_sha256) {
                goto complete;
            }
            break;
        default:
            cli_errmsg("fmap_get_hash: Unsupported hash type %u\n", type);
            status = CL_EARG;
            goto done;
    }

    /*
     * Need to calculate the hash.
     */

    switch (type) {
        case CLI_HASH_MD5:
            hashctx = cl_hash_init("md5");
            break;
        case CLI_HASH_SHA1:
            hashctx = cl_hash_init("sha1");
            break;
        case CLI_HASH_SHA256:
            hashctx = cl_hash_init("sha256");
            break;
        default:
            cli_errmsg("fmap_get_hash: Unsupported hash type %u\n", type);
            status = CL_EARG;
            goto done;
    }
    if (!(hashctx)) {
        cli_errmsg("fmap_get_hash: error initializing new md5 hash!\n");
        goto done;
    }

    while (todo) {
        const void *buf;
        size_t readme = todo < 1024 * 1024 * 10 ? todo : 1024 * 1024 * 10;

        if (!(buf = fmap_need_off_once(map, at, readme))) {
            cli_errmsg("fmap_get_hash: error reading while generating hash!\n");
            status = CL_EREAD;
            goto done;
        }

        todo -= readme;
        at += readme;

        if (cl_update_hash(hashctx, (void *)buf, readme)) {
            cli_errmsg("fmap_get_hash: error calculating hash!\n");
            status = CL_EREAD;
            goto done;
        }
    }

    switch (type) {
        case CLI_HASH_MD5:
            cl_finish_hash(hashctx, map->md5);
            map->have_md5 = true;
            break;
        case CLI_HASH_SHA1:
            cl_finish_hash(hashctx, map->sha1);
            map->have_sha1 = true;
            break;
        case CLI_HASH_SHA256:
            cl_finish_hash(hashctx, map->sha256);
            map->have_sha256 = true;
            break;
        default:
            cli_errmsg("fmap_get_hash: Unsupported hash type %u\n", type);
            status = CL_EARG;
            goto done;
    }
    hashctx = NULL;

complete:

    switch (type) {
        case CLI_HASH_MD5:
            *hash = map->md5;
            break;
        case CLI_HASH_SHA1:
            *hash = map->sha1;
            break;
        case CLI_HASH_SHA256:
            *hash = map->sha256;
            break;
        default:
            cli_errmsg("fmap_get_hash: Unsupported hash type %u\n", type);
            status = CL_EARG;
            goto done;
    }

    status = CL_SUCCESS;

done:

    if (NULL != hashctx) {
        cl_hash_destroy(hashctx);
    }

    return status;
}

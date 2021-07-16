/*
 *  Copyright (C) 2013-2021 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
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

#ifndef __FMAP_H
#define __FMAP_H

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <limits.h>
#include <time.h>
#include <string.h>

#include "clamav.h"

struct cl_fmap;
typedef cl_fmap_t fmap_t;

struct cl_fmap {
    /* handle interface */
    void *handle;
    clcb_pread pread_cb;

    /* internal */
    time_t mtime;
    uint64_t pages;
    uint64_t pgsz;
    uint64_t paged;
    uint16_t aging;
    uint16_t dont_cache_flag;
    uint16_t handle_is_fd;

    /* memory interface */
    const void *data;

    /* common interface */
    size_t offset;        /* file offset */
    size_t nested_offset; /* buffer offset for nested scan*/
    size_t real_len;      /* amount of data mapped from file, starting at offset */
    size_t len;           /* length of data accessible via current fmap */

    /* real_len = nested_offset + len
     * file_offset = offset + nested_offset + need_offset
     * maximum offset, length accessible via fmap API: len
     * offset in cached buffer: nested_offset + need_offset
     *
     * This allows scanning a portion of an already mapped file without dumping
     * to disk and remapping (for uncompressed archives for example) */

    /* vtable for implementation */
    void (*unmap)(fmap_t *);
    const void *(*need)(fmap_t *, size_t at, size_t len, int lock);
    const void *(*need_offstr)(fmap_t *, size_t at, size_t len_hint);
    const void *(*gets)(fmap_t *, char *dst, size_t *at, size_t max_len);
    void (*unneed_off)(fmap_t *, size_t at, size_t len);
#ifdef _WIN32
    HANDLE fh;
    HANDLE mh;
#endif
    unsigned char maphash[16];
    uint64_t *bitmap;
    char *name;
};

/**
 * @brief Create a new fmap given a file descriptor.
 *
 * @param fd        File descriptor of file to be mapped.
 * @param offset    Offset into file for start of map.
 * @param len       Length from offset for size of map.
 * @param name      (optional) Original name of the file (to set fmap name metadata)
 * @return fmap_t*  The newly created fmap.  Free it with `funmap()`
 */
fmap_t *fmap(int fd, off_t offset, size_t len, const char *name);

/**
 * @brief Create  new fmap given a file descriptor.
 *
 * This variant of fmap() provides a boolean output variable to indicate on
 * failure if the failure was because the file is empty (not really a failure).
 *
 * @param fd            File descriptor of file to be mapped.
 * @param offset        Offset into file for start of map.
 * @param len           Length from offset for size of map.
 * @param[out] empty    Boolean will be non-zero if the file couldn't be mapped because it is empty.
 * @param name          (optional) Original name of the file (to set fmap name metadata)
 * @return fmap_t*      The newly created fmap.  Free it with `funmap()`
 */
fmap_t *fmap_check_empty(int fd, off_t offset, size_t len, int *empty, const char *name);

/**
 * @brief Create a new fmap given a buffer.
 *
 * @param start     Start of a buffer that the fmap will reference.
 * @param len       Length of the buffer.
 * @param name      (optional) Original name of the file (to set fmap name metadata)
 * @return fmap_t*
 */
fmap_t *fmap_open_memory(const void *start, size_t len, const char *name);

/**
 * @brief Create a new fmap view into another fmap.
 *
 * @param map       The parent fmap.
 * @param offset    Offset for the start of the new fmap into the parent fmap.
 * @param length    Length of the data from the offset for the new fmap.
 * @param name      (optional) Original name of the file (to set fmap name metadata)
 * @return fmap_t*  NULL if failure or a special fmap that the caller must free with free_duplicate_fmap()
 */
fmap_t *fmap_duplicate(cl_fmap_t *map, size_t offset, size_t length, const char *name);

/**
 * @brief Deallocate a _duplicated_ fmap.  Does not unmap the mapped region.
 *
 * This function should be used instead of `free()` to cleanup the optional fmap name.
 *
 * @param m The map to be free'd.
 */
void free_duplicate_fmap(cl_fmap_t *map);

/**
 * @brief Unmap/deallocate an fmap.
 *
 * @param m The map to be free'd.
 */
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

static inline size_t fmap_ptr2off(const fmap_t *m, const void *ptr)
{
    return (size_t)((const char *)ptr - (const char *)m->data) - m->nested_offset;
}

static inline const void *fmap_need_ptr(fmap_t *m, const void *ptr, size_t len)
{
    return m->need(m, fmap_ptr2off(m, ptr), len, 1);
}

static inline const void *fmap_need_ptr_once(fmap_t *m, const void *ptr, size_t len)
{
    return m->need(m, fmap_ptr2off(m, ptr), len, 0);
}

static inline void fmap_unneed_off(fmap_t *m, size_t at, size_t len)
{
    m->unneed_off(m, at, len);
}

static inline void fmap_unneed_ptr(fmap_t *m, const void *ptr, size_t len)
{
    fmap_unneed_off(m, fmap_ptr2off(m, ptr), len);
}

/**
 * @brief Read bytes from fmap at offset into destination buffer.
 *
 * @param m         fmap
 * @param dst       destination buffer
 * @param at        offset into fmap
 * @param len       # of bytes to read
 * @return size_t   # of bytes read
 * @return size_t   (size_t)-1 if error
 */
static inline size_t fmap_readn(fmap_t *m, void *dst, size_t at, size_t len)
{
    const void *src;

    if (at == m->len || !len)
        return 0;
    if (at > m->len)
        return (size_t)-1;
    if (len > m->len - at)
        len = m->len - at;
    src = fmap_need_off_once(m, at, len);
    if (!src)
        return (size_t)-1;
    memcpy(dst, src, len);
    return (len <= INT_MAX) ? len : (size_t)-1;
}

static inline const void *fmap_need_str(fmap_t *m, const void *ptr, size_t len_hint)
{
    return m->need_offstr(m, fmap_ptr2off(m, ptr), len_hint);
}

static inline const void *fmap_need_offstr(fmap_t *m, size_t at, size_t len_hint)
{
    return m->need_offstr(m, at, len_hint);
}

static inline const void *fmap_gets(fmap_t *m, char *dst, size_t *at, size_t max_len)
{
    return m->gets(m, dst, at, max_len);
}

static inline const void *fmap_need_off_once_len(fmap_t *m, size_t at, size_t len, size_t *lenout)
{
    const void *p;
    if (at >= m->len) {
        *lenout = 0;
        return NULL; /* EOF, not read error */
    }
    if (len > m->len - at)
        len = m->len - at;
    p       = fmap_need_off_once(m, at, len);
    *lenout = p ? len : 0;
    return p;
}

static inline const void *fmap_need_ptr_once_len(fmap_t *m, const void *ptr, size_t len, size_t *lenout)
{
    return fmap_need_off_once_len(m, fmap_ptr2off(m, ptr), len, lenout);
}

/**
 * @brief 	Dump a specified range of data from an fmap to a new temp file.
 *
 * @param map           The file map in question
 * @param filepath      (Optional) The full filepath of the file being dumped.
 * @param tmpdir        The directory to drop the file to.
 * @param outname       The filename chosen for the temp file.
 * @param outfd         The file descriptor of the new file, open and seeked to the start of the file.
 * @param start_offset  The start offset of the data that you wish to write to the temp file. Must be less than the length of the fmap and must be less than end_offset.
 * @param end_offset    The end offset of the data you wish to write to the temp file.  May be larger than the size of the fmap.  Use SIZE_MAX to write the entire fmap.
 * @return cl_error_t   CL_SUCCESS on success, else CL_EARG, CL_EWRITE, CL_ECREAT, or CL_EMEM for self-explanatory reasons.
 */
cl_error_t fmap_dump_to_file(fmap_t *map, const char *filepath, const char *tmpdir, char **outname, int *outfd, size_t start_offset, size_t end_offset);

/* deprecated */
/**
 * @brief   Return the open file desciptor for the fmap (if available).
 *
 * This function will only provide the file descriptor if the fmap handle is set,
 * and if the handle is in fact a file descriptor (handle_is_fd != 0).
 *
 * @param m     The fmap.
 * @return int  The file descriptor, or -1 if not available.
 */
int fmap_fd(fmap_t *m);

cl_error_t fmap_get_MD5(unsigned char *hash, fmap_t *map);

#endif

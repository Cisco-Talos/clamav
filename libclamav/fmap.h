/*
 *  Copyright (C) 2013-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
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
#include <stdbool.h>

#include "clamav.h"

#include "matcher-hash-types.h"

struct cl_fmap;
typedef cl_fmap_t fmap_t;

struct cl_fmap {
    /* handle interface */
    void *handle;
    clcb_pread pread_cb;

    /* memory interface */
    const void *data;

    /* internal */
    uint64_t mtime;
    uint64_t pages;
    uint64_t pgsz;
    uint64_t paged;
    bool aging;           /** Indicates if we should age off memory mapped pages */
    bool dont_cache_flag; /** Indicates if we should not cache scan results for this fmap. Used if limits exceeded */
    bool handle_is_fd;    /** Non-zero if `map->handle` is an fd. This is needed so that `fmap_fd()` knows if it can
                              return a file descriptor. If it's some other kind of handle, then `fmap_fd()` has to return -1. */
    size_t offset;        /** File offset representing start of original fmap, if the fmap created reading from a file starting at offset other than 0.
                              `offset` & `len` are critical information for anyone using the file descriptor/handle */
    size_t nested_offset; /** Offset from start of original fmap (data) for nested scan. 0 for orig fmap. */
    size_t real_len;      /** Length from start of original fmap (data) to end of current (possibly nested) map.
                              `real_len == nested_offset + len`.
                              `real_len` is needed for nested maps because we only reference the original mapping data.
                              We convert caller's fmap offsets & lengths to real data offsets using `nested_offset` & `real_len`. */

    /* external */
    size_t len; /** Length of data from nested_offset, accessible via current fmap */

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
    void *windows_file_handle;
    void *windows_map_handle;

    /* flags to indicate if we should calculate a hash next time we calculate any hashes */
    bool will_need_hash[CLI_HASH_AVAIL_TYPES];

    /* flags to indicate if we have calculated a hash */
    bool have_hash[CLI_HASH_AVAIL_TYPES];

    /* hash values */
    uint8_t hash[CLI_HASH_AVAIL_TYPES][CLI_HASHLEN_MAX];

    uint64_t *bitmap;
    char *name; /* name of the file, e.g. as recorded in a zip file entry record */
    char *path; /* path to the file/tempfile, if fmap was created from a file descriptor */
};

/**
 * @brief Create a new fmap given a file descriptor.
 *
 * @param fd        File descriptor of file to be mapped.
 * @param offset    Offset into file for start of map.
 * @param len       Length from offset for size of map.
 * @param name      (optional) Original name of the file (to set fmap name metadata)
 * @param path      (optional) Original path of the file (to set fmap path metadata)
 * @return fmap_t*  The newly created fmap.  Free it with `fmap_free()`
 */
fmap_t *fmap_new(int fd, off_t offset, size_t len, const char *name, const char *path);

/**
 * @brief Create  new fmap given a file descriptor.
 *
 * This variant of fmap_new() provides a boolean output variable to indicate on
 * failure if the failure was because the file is empty (not really a failure).
 *
 * @param fd            File descriptor of file to be mapped.
 * @param offset        Offset into file for start of map.
 * @param len           Length from offset for size of map.
 * @param[out] empty    Boolean will be non-zero if the file couldn't be mapped because it is empty.
 * @param name          (optional) Original name of the file (to set fmap name metadata)
 * @param path          (optional) Original path of the file (to set fmap path metadata)
 * @return fmap_t*      The newly created fmap.  Free it with `fmap_free()`
 */
fmap_t *fmap_check_empty(int fd, off_t offset, size_t len, int *empty, const char *name, const char *path);

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
static inline void fmap_free(fmap_t *m)
{
    m->unmap(m);
}

/**
 * @brief Get a pointer to the file data if the requested offset & len are within the fmap.
 *
 * For fmap's created from file descriptors, this will also page the requested file map pages.
 *
 * This will lock the pages containing the requested data.
 * You must call fmap_unneed_off() / fmap_unneed_ptr() when you're done accessing the data to
 * release the page locks.
 *
 * @param m     The fmap.
 * @param at    The map offset requested.
 * @param len   The data length requested.
 * @return const void* A pointer into to the fmap->data at the requested offset. NULL if offset/len are not contained in the fmap.
 */
static inline const void *fmap_need_off(fmap_t *m, size_t at, size_t len)
{
    return m->need(m, at, len, 1);
}

/**
 * @brief Get a pointer to the file data if the requested offset & len are within the fmap.
 *
 * For fmap's created from file descriptors, this will also page the requested file map pages.
 *
 * This is just like fmap_need_off() except it will not lock the pages, and you don't need
 * to call fmap_unneed_off() / fmap_unneed_ptr() to release the page locks.
 *
 * @param m     The fmap.
 * @param at    The map offset requested.
 * @param len   The data length requested.
 * @return const void* A pointer into to the fmap->data at the requested offset. NULL if offset/len are not contained in the fmap.
 */
static inline const void *fmap_need_off_once(fmap_t *m, size_t at, size_t len)
{
    return m->need(m, at, len, 0);
}

/**
 * @brief Return an offset into the current fmap given a pointer into the fmap data.
 *
 * For a nested (duplicate) fmap, the returned offset will be appropriate to the nested map.
 * For example, if the ptr points to the start of the nested file, the returned offset will be 0.
 * So this should be true, even for a nested fmap:
 *   void *ptr = fmap_need_off(m, 0, 10);
 *   size_t off = fmap_need_ptr(m, ptr, 10);
 *   assert(ptr == off);
 *
 * @param m     The fmap
 * @param ptr   A pointer into the fmap->data
 * @return size_t The offset into the fmap
 */
static inline size_t fmap_ptr2off(const fmap_t *m, const void *ptr)
{
    return (size_t)((const char *)ptr - (const char *)m->data) - m->nested_offset;
}

/**
 * @brief Get a pointer to the file data given a pointer into the map->data & len that are within the fmap.
 *
 * For fmap's created from file descriptors, this will also page the requested file map pages.
 *
 * This will lock the pages containing the requested data.
 * You must call fmap_unneed_off() / fmap_unneed_ptr() when you're done accessing the data to
 * release the page locks.
 *
 * @param m     The fmap.
 * @param ptr   A pointer into the fmap->data.
 * @param len   The data length requested.
 * @return const void* A pointer into to the fmap->data at the requested offset. NULL if offset/len are not contained in the fmap.
 */
static inline const void *fmap_need_ptr(fmap_t *m, const void *ptr, size_t len)
{
    return m->need(m, fmap_ptr2off(m, ptr), len, 1);
}

/**
 * @brief Get a pointer to the file data given a pointer into the map->data & len that are within the fmap.
 *
 * For fmap's created from file descriptors, this will also page the requested file map pages.
 *
 * This is just like fmap_need_ptr() except it will not lock the pages, and you don't need
 * to call fmap_unneed_off() / fmap_unneed_ptr() to release the page locks.
 *
 * @param m     The fmap.
 * @param ptr   A pointer into the fmap->data.
 * @param len   The data length requested.
 * @return const void* A pointer into to the fmap->data at the requested offset. NULL if offset/len are not contained in the fmap.
 */
static inline const void *fmap_need_ptr_once(fmap_t *m, const void *ptr, size_t len)
{
    return m->need(m, fmap_ptr2off(m, ptr), len, 0);
}

/**
 * @brief Release page locks for an fmap.
 *
 * You must call this after "needing" memory with fmap_need_ptr() or fmap_need_off() once
 * you're done accessing the data.
 *
 * @param m     The fmap.
 * @param at    The map offset requested.
 * @param len   The data length requested.
 */
static inline void fmap_unneed_off(fmap_t *m, size_t at, size_t len)
{
    m->unneed_off(m, at, len);
}

/**
 * @brief Release page locks for an fmap.
 *
 * You must call this after "needing" memory with fmap_need_ptr() or fmap_need_off() once
 * you're done accessing the data.
 *
 * @param m     The fmap.
 * @param ptr   A pointer into the fmap->data.
 * @param len   The data length requested.
 */
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

/**
 * @brief Given a pointer into the map data, return that pointer if there is a NULL terminator
 *        between ptr and the len_hint.
 *
 * Like fmap_need_offstr, but takes a pointer into the map data instead of an offset.
 *
 * @param m         The fmap.
 * @param ptr       pointer to the start of string.
 * @param len_hint  max length of string. if 0, will use rest of map as max string length.
 * @return const void* pointer of string, or NULL if no NULL terminator found.
 */
static inline const void *fmap_need_str(fmap_t *m, const void *ptr, size_t len_hint)
{
    return m->need_offstr(m, fmap_ptr2off(m, ptr), len_hint);
}

/**
 * @brief Return a pointer at the given offset into an fmap iff there is a
 *        null terminator between `at` and `len_hint` or the end of the map.
 *        if `len_hint` is 0.
 *
 * @param m         The fmap.
 * @param at        offset of the start of string.
 * @param len_hint  max length of string. if 0, will use rest of map as max string length.
 * @return const void* pointer of string, or NULL if no NULL terminator found.
 */
static inline const void *fmap_need_offstr(fmap_t *m, size_t at, size_t len_hint)
{
    return m->need_offstr(m, at, len_hint);
}

/**
 * @brief Read a string into `dst`, stopping at a newline or at EOF.
 *
 * Kind of like `fgets()`, but for fmaps, and slightly better in that `at` is in/out,
 * giving you the offset in the fmap after the end of the read.
 *
 * Will null-terminate the string read into dst.
 *
 * @param m             The fmap.
 * @param dst           A destination buffer.
 * @param[in,out] at    In: Offset in the map to read from. Out: Offset after the read.
 * @param max_len       Max size to read (aka no bigger than the size of the dst buffer).
 * @return const void*  Returns `dst` on success, else NULL.
 */
static inline const void *fmap_gets(fmap_t *m, char *dst, size_t *at, size_t max_len)
{
    return m->gets(m, dst, at, max_len);
}

/**
 * @brief Get a pointer to the file data if the requested offset & max-len are within the fmap.
 *
 * Just like `fmap_need_off_once()` except the `len` param is a maximum-len.
 * If successful, the `lenout` param will indicate the _actual_ len of data available.
 *
 * @param m             The fmap.
 * @param at            The map offset requested.
 * @param len           Maximum length of data requested.
 * @param[out] lenout   The actual len of data available.
 * @return const void*  A pointer into to the fmap->data at the requested offset. NULL if offset/len are not contained in the fmap.
 */
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

/**
 * @brief Get a pointer to the file data if the requested offset & max-len are within the fmap.
 *
 * Just like `fmap_need_off_once()` except the `len` param is a maximum-len.
 * If successful, the `lenout` param will indicate the _actual_ len of data available.
 *
 * @param m             The fmap.
 * @param ptr           A pointer into the fmap->data.
 * @param len           Maximum length of data requested.
 * @param[out] lenout   The actual len of data available.
 * @return const void* A pointer into to the fmap->data at the requested offset. NULL if offset/len are not contained in the fmap.
 */
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
 * @brief   Return the open file descriptor for the fmap (if available).
 *
 * This function will only provide the file descriptor if the fmap handle is set,
 * and if the handle is in fact a file descriptor (handle_is_fd == true).
 *
 * @param m     The fmap.
 * @return int  The file descriptor, or -1 if not available.
 */
int fmap_fd(fmap_t *m);

/**
 * @brief Indicate that we will want to calculate this hash later.asm
 *
 * Set a flag to provide advanced notice that the next time we get a hash and
 * it has to calculate the hash, it will also calculate this hash.
 *
 * This is an optimization so that all hashes may be calculated in one pass
 * of the file rather than doing multiple passes of the file for each
 * needed hash.
 *
 * @param map       The map in question.
 * @param type      The type of hash we'll need.
 * @return cl_error_t CL_SUCCESS if was able to set the flag, else some error.
 */
cl_error_t fmap_will_need_hash_later(fmap_t *map, cli_hash_type_t type);

/**
 * @brief Get a pointer to the fmap hash.
 *
 * Will calculate the hash if not already previously calculated.
 *
 * @param map       The map in question.
 * @param[out] hash A pointer to the hash.
 * @param type      The type of hash to calculate.
 * @return cl_error_t CL_SUCCESS if was able to get the hash, else some error.
 */
cl_error_t fmap_get_hash(fmap_t *map, uint8_t **hash, cli_hash_type_t type);

/**
 * @brief Set the hash for the fmap that was previously calculated.
 *
 * @param map       The map in question.
 * @param hash      The hash to set.
 * @param type      The type of hash to calculate.
 * @return cl_error_t CL_SUCCESS if was able to set the hash, else some error.
 */
cl_error_t fmap_set_hash(fmap_t *map, uint8_t *hash, cli_hash_type_t type);

#endif

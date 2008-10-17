/*
 * Memory pool defines.
 *
 * Copyright 1996 by Gray Watson.
 *
 * This file is part of the mpool package.
 *
 * Permission to use, copy, modify, and distribute this software for
 * any purpose and without fee is hereby granted, provided that the
 * above copyright notice and this permission notice appear in all
 * copies, and that the name of Gray Watson not be used in advertising
 * or publicity pertaining to distribution of the document or software
 * without specific, written prior permission.
 *
 * Gray Watson makes no representations about the suitability of the
 * software described herein for any purpose.  It is provided "as is"
 * without express or implied warranty.
 *
 * The author may be reached via http://256.com/gray/
 *
 * $Id: mpool.h,v 1.4 2006/05/31 20:26:11 gray Exp $
 */

#ifndef __MPOOL_H__
#define __MPOOL_H__

#include <sys/types.h>

/*
 * mpool flags to mpool_alloc or mpool_set_attr
 */

/*
 * Choose a best fit algorithm not first fit.  This takes more CPU
 * time but will result in a tighter heap.
 */
#define MPOOL_FLAG_BEST_FIT		(1<<0)

/*
 * By default the library adds 2 bytes onto all allocations to insert
 * a magic number that it can look for to determine how large a freed
 * memory chunk is.  This flag indicates that few if any frees are
 * going to be performed on the pool and to not waste memory on these
 * bytes.
 */
#define MPOOL_FLAG_NO_FREE		(1<<1)

/*
 * This enables very heavy packing at the possible expense of CPU.
 * This affects a number of parts of the library.
 *
 * By default the 1st page of memory is reserved for the main mpool
 * structure.  This flag will cause the rest of the 1st block to be
 * available for use as user memory.
 *
 * By default the library looks through the memory when freed looking
 * for a magic value.  There is an internal max size that it will look
 * and then it will give up.  This flag forces it to look until it
 * finds it.
 */
#define MPOOL_FLAG_HEAVY_PACKING	(1<<2)

/*
 * Use sbrk not mmap to allocate pages.  This is not recommended for
 * normal use.
 */
#define MPOOL_FLAG_USE_SBRK		(1<<3)

/*
 * Mpool error codes
 */
#define MPOOL_ERROR_NONE	1	/* no error */
#define MPOOL_ERROR_ARG_NULL	2	/* function argument is null */
#define MPOOL_ERROR_ARG_INVALID	3	/* function argument is invalid */
#define MPOOL_ERROR_PNT		4	/* invalid mpool pointer */
#define MPOOL_ERROR_POOL_OVER	5	/* mpool structure was overwritten */
#define MPOOL_ERROR_PAGE_SIZE	6	/* could not get system page-size */
#define MPOOL_ERROR_OPEN_ZERO	7	/* could not open /dev/zero */
#define MPOOL_ERROR_NO_MEM	8	/* no memory available */
#define MPOOL_ERROR_MMAP	9	/* problems with mmap */
#define MPOOL_ERROR_SIZE	10	/* error processing requested size */
#define MPOOL_ERROR_TOO_BIG	11	/* allocation exceeded max size */
#define MPOOL_ERROR_MEM		12	/* invalid memory address */
#define MPOOL_ERROR_MEM_OVER	13	/* memory lower bounds overwritten */
#define MPOOL_ERROR_NOT_FOUND	14	/* memory block not found in pool */
#define MPOOL_ERROR_IS_FREE	15	/* memory block already free */
#define MPOOL_ERROR_BLOCK_STAT	16	/* invalid internal block status */
#define MPOOL_ERROR_FREE_ADDR	17	/* invalid internal free address */
#define MPOOL_ERROR_SBRK_CONTIG	18	/* sbrk did not return contiguous mem*/
#define MPOOL_ERROR_NO_PAGES	19	/* ran out of pages in pool */
#define MPOOL_ERROR_ALLOC	20	/* calloc,malloc,free,realloc failed */
#define MPOOL_ERROR_PNT_OVER	21	/* pointer structure was overwritten */

/*
 * Mpool function IDs for the mpool_log_func callback function.
 */
#define MPOOL_FUNC_CLOSE	1	/* mpool_close function called */
#define MPOOL_FUNC_CLEAR	2	/* mpool_clear function called */
#define MPOOL_FUNC_ALLOC	3	/* mpool_alloc function called */
#define MPOOL_FUNC_CALLOC	4	/* mpool_calloc function called */
#define MPOOL_FUNC_FREE		5	/* mpool_free function called */
#define MPOOL_FUNC_RESIZE	6	/* mpool_resize function called */

/*
 * void mpool_log_func_t
 *
 * DESCRIPTION:
 *
 * Mpool transaction log function.
 *
 * RETURNS:
 *
 * None.
 *
 * ARGUMENT:
 *
 * mp_p -> Associated mpool address.
 *
 * func_id -> Integer function ID which identifies which mpool
 * function is being called.
 *
 * byte_size -> Optionally specified byte size.
 *
 * ele_n -> Optionally specified element number.  For mpool_calloc
 * only.
 *
 * new_addr -> Optionally specified new address.  For mpool_alloc,
 * mpool_calloc, and mpool_resize only.
 *
 * old_addr -> Optionally specified old address.  For mpool_resize and
 * mpool_free only.
 *
 * old_byte_size -> Optionally specified old byte size.  For
 * mpool_resize only.
 */
typedef void	(*mpool_log_func_t)(const void *mp_p,
				    const int func_id,
				    const unsigned long byte_size,
				    const unsigned long ele_n,
				    const void *old_addr, const void *new_addr,
				    const unsigned long old_byte_size);

#ifdef MPOOL_MAIN

#include "mpool_loc.h"

#else

/* generic mpool type */
typedef	void	mpool_t;

#endif

/*<<<<<<<<<<  The below prototypes are auto-generated by fillproto */

/*
 * mpool_t *mpool_open
 *
 * DESCRIPTION:
 *
 * Open/allocate a new memory pool.
 *
 * RETURNS:
 *
 * Success - Pool pointer which must be passed to mpool_close to
 * deallocate.
 *
 * Failure - NULL
 *
 * ARGUMENTS:
 *
 * flags -> Flags to set attributes of the memory pool.  See the top
 * of mpool.h.
 *
 * page_size -> Set the internal memory page-size.  This must be a
 * multiple of the getpagesize() value.  Set to 0 for the default.
 *
 * start_addr -> Starting address to try and allocate memory pools.
 * This is ignored if the MPOOL_FLAG_USE_SBRK is enabled.
 *
 * error_p <- Pointer to integer which, if not NULL, will be set with
 * a mpool error code.
 */
extern
mpool_t	*mpool_open(const unsigned int flags, const unsigned int page_size,
		    void *start_addr, int *error_p);

/*
 * int mpool_close
 *
 * DESCRIPTION:
 *
 * Close/free a memory allocation pool previously opened with
 * mpool_open.
 *
 * RETURNS:
 *
 * Success - MPOOL_ERROR_NONE
 *
 * Failure - Mpool error code
 *
 * ARGUMENTS:
 *
 * mp_p <-> Pointer to our memory pool.
 */
extern
int	mpool_close(mpool_t *mp_p);

/*
 * int mpool_clear
 *
 * DESCRIPTION:
 *
 * Wipe an opened memory pool clean so we can start again.
 *
 * RETURNS:
 *
 * Success - MPOOL_ERROR_NONE
 *
 * Failure - Mpool error code
 *
 * ARGUMENTS:
 *
 * mp_p <-> Pointer to our memory pool.
 */
extern
int	mpool_clear(mpool_t *mp_p);

/*
 * void *mpool_alloc
 *
 * DESCRIPTION:
 *
 * Allocate space for bytes inside of an already open memory pool.
 *
 * RETURNS:
 *
 * Success - Pointer to the address to use.
 *
 * Failure - NULL
 *
 * ARGUMENTS:
 *
 * mp_p <-> Pointer to the memory pool.  If NULL then it will do a
 * normal malloc.
 *
 * byte_size -> Number of bytes to allocate in the pool.  Must be >0.
 *
 * error_p <- Pointer to integer which, if not NULL, will be set with
 * a mpool error code.
 */
extern
void	*mpool_alloc(mpool_t *mp_p, const unsigned long byte_size,
		     int *error_p);

/*
 * void *mpool_calloc
 *
 * DESCRIPTION:
 *
 * Allocate space for elements of bytes in the memory pool and zero
 * the space afterwards.
 *
 * RETURNS:
 *
 * Success - Pointer to the address to use.
 *
 * Failure - NULL
 *
 * ARGUMENTS:
 *
 * mp_p <-> Pointer to the memory pool.  If NULL then it will do a
 * normal calloc.
 *
 * ele_n -> Number of elements to allocate.
 *
 * ele_size -> Number of bytes per element being allocated.
 *
 * error_p <- Pointer to integer which, if not NULL, will be set with
 * a mpool error code.
 */
extern
void	*mpool_calloc(mpool_t *mp_p, const unsigned long ele_n,
		      const unsigned long ele_size, int *error_p);

/*
 * int mpool_free
 *
 * DESCRIPTION:
 *
 * Free an address from a memory pool.
 *
 * RETURNS:
 *
 * Success - MPOOL_ERROR_NONE
 *
 * Failure - Mpool error code
 *
 * ARGUMENTS:
 *
 * mp_p <-> Pointer to the memory pool.  If NULL then it will do a
 * normal free.
 *
 * addr <-> Address to free.
 *
 * size -> Size of the address being freed.
 */
extern
int	mpool_free(mpool_t *mp_p, void *addr);

/*
 * void *mpool_resize
 *
 * DESCRIPTION:
 *
 * Reallocate an address in a mmeory pool to a new size.  This is
 * different from realloc in that it needs the old address' size.  If
 * you don't have it then you need to allocate new space, copy the
 * data, and free the old pointer yourself.
 *
 * RETURNS:
 *
 * Success - Pointer to the address to use.
 *
 * Failure - NULL
 *
 * ARGUMENTS:
 *
 * mp_p <-> Pointer to the memory pool.  If NULL then it will do a
 * normal realloc.
 *
 * old_addr -> Previously allocated address.
 *
 * old_byte_size -> Size of the old address.  Must be known, cannot be
 * 0.
 *
 * new_byte_size -> New size of the allocation.
 *
 * error_p <- Pointer to integer which, if not NULL, will be set with
 * a mpool error code.
 */
extern
void	*mpool_resize(mpool_t *mp_p, void *old_addr,
		      const unsigned long new_byte_size,
		      int *error_p);

/*
 * int mpool_stats
 *
 * DESCRIPTION:
 *
 * Return stats from the memory pool.
 *
 * RETURNS:
 *
 * Success - MPOOL_ERROR_NONE
 *
 * Failure - Mpool error code
 *
 * ARGUMENTS:
 *
 * mp_p -> Pointer to the memory pool.
 *
 * page_size_p <- Pointer to an unsigned integer which, if not NULL,
 * will be set to the page-size of the pool.
 *
 * num_alloced_p <- Pointer to an unsigned long which, if not NULL,
 * will be set to the number of pointers currently allocated in pool.
 *
 * user_alloced_p <- Pointer to an unsigned long which, if not NULL,
 * will be set to the number of user bytes allocated in this pool.
 *
 * max_alloced_p <- Pointer to an unsigned long which, if not NULL,
 * will be set to the maximum number of user bytes that have been
 * allocated in this pool.
 *
 * tot_alloced_p <- Pointer to an unsigned long which, if not NULL,
 * will be set to the total amount of space (including administrative
 * overhead) used by the pool.
 */
extern
int	mpool_stats(const mpool_t *mp_p, unsigned int *page_size_p,
		    unsigned long *num_alloced_p,
		    unsigned long *user_alloced_p,
		    unsigned long *max_alloced_p,
		    unsigned long *tot_alloced_p);

/*
 * int mpool_set_log_func
 *
 * DESCRIPTION:
 *
 * Set a logging callback function to be called whenever there was a
 * memory transaction.  See mpool_log_func_t.
 *
 * RETURNS:
 *
 * Success - MPOOL_ERROR_NONE
 *
 * Failure - Mpool error code
 *
 * ARGUMENTS:
 *
 * mp_p <-> Pointer to the memory pool.
 *
 * log_func -> Log function (defined in mpool.h) which will be called
 * with each mpool transaction.
 */
extern
int	mpool_set_log_func(mpool_t *mp_p, mpool_log_func_t log_func);

/*
 * int mpool_set_max_pages
 *
 * DESCRIPTION:
 *
 * Set the maximum number of pages that the library will use.  Once it
 * hits the limit it will return MPOOL_ERROR_NO_PAGES.
 *
 * NOTE: if the MPOOL_FLAG_HEAVY_PACKING is set then this max-pages
 * value will include the page with the mpool header structure in it.
 * If the flag is _not_ set then the max-pages will not include this
 * first page.
 *
 * RETURNS:
 *
 * Success - MPOOL_ERROR_NONE
 *
 * Failure - Mpool error code
 *
 * ARGUMENTS:
 *
 * mp_p <-> Pointer to the memory pool.
 *
 * max_pages -> Maximum number of pages used by the library.
 */
extern
int	mpool_set_max_pages(mpool_t *mp_p, const unsigned int max_pages);

/*
 * const char *mpool_strerror
 *
 * DESCRIPTION:
 *
 * Return the corresponding string for the error number.
 *
 * RETURNS:
 *
 * Success - String equivalient of the error.
 *
 * Failure - String "invalid error code"
 *
 * ARGUMENTS:
 *
 * error -> Error number that we are converting.
 */
extern
const char	*mpool_strerror(const int error);

/*<<<<<<<<<<   This is end of the auto-generated output from fillproto. */

#endif /* ! __MPOOL_H__ */

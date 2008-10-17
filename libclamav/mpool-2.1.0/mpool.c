/*
 * Memory pool routines.
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
 * $Id: mpool.c,v 1.5 2006/05/31 20:28:31 gray Exp $
 */

/*
 * Memory-pool allocation routines.  I got sick of the GNU mmalloc
 * library which was close to what we needed but did not exactly do
 * what I wanted.
 *
 * The following uses mmap from /dev/zero.  It allows a number of
 * allocations to be made inside of a memory pool then with a clear or
 * close the pool can be reset without any memory fragmentation and
 * growth problems.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

#ifdef DMALLOC
#include "dmalloc.h"
#endif

#define MPOOL_MAIN

#include "mpool.h"
#include "mpool_loc.h"

#ifdef __GNUC__
#ident "$Id: mpool.c,v 1.5 2006/05/31 20:28:31 gray Exp $"
#else
static char *rcs_id = "$Id: mpool.c,v 1.5 2006/05/31 20:28:31 gray Exp $";
#endif

/* ACAB */
#include <stddef.h>
struct FRAG {
  unsigned long frag_size;
  void *frag_ptr;
};
#define FRAG_OVERHEAD (offsetof(struct FRAG, frag_ptr))

/* version */
static	char *version = "mpool library version 2.1.0";

/* local variables */
static	int		enabled_b = 0;		/* lib initialized? */
static	unsigned int	min_bit_free_next = 0;	/* min size of next pnt */
static	unsigned int	min_bit_free_size = 0;	/* min size of next + size */
static	unsigned long	bit_array[MAX_BITS + 1]; /* size -> bit */

/****************************** local utilities ******************************/

/*
 * static void startup
 *
 * DESCRIPTION:
 *
 * Perform any library level initialization.
 *
 * RETURNS:
 *
 * None.
 *
 * ARGUMENTS:
 *
 * None.
 */
static	void	startup(void)
{
  int		bit_c;
  unsigned long	size = 1;
  
  if (enabled_b) {
    return;
  }
  
  /* allocate our free bit array list */
  for (bit_c = 0; bit_c <= MAX_BITS; bit_c++) {
    bit_array[bit_c] = size;
    
    /*
     * Note our minimum number of bits that can store a pointer.  This
     * is smallest address that we can have a linked list for.
     */
    if (min_bit_free_next == 0 && size >= sizeof(void *)) {
      min_bit_free_next = bit_c;
    }
    /*
     * Note our minimum number of bits that can store a pointer and
     * the size of the block.
     */
    if (min_bit_free_size == 0 && size >= sizeof(mpool_free_t)) {
      min_bit_free_size = bit_c;
    }
    
    size *= 2;
  }
  
  enabled_b = 1;
}

/*
 * static int size_to_bits
 *
 * DESCRIPTION:
 *
 * Calculate the number of bits in a size.
 *
 * RETURNS:
 *
 * Number of bits.
 *
 * ARGUMENTS:
 *
 * size -> Size of memory of which to calculate the number of bits.
 */
static	int	size_to_bits(const unsigned long size)
{
  int		bit_c = 0;
  
  for (bit_c = 0; bit_c <= MAX_BITS; bit_c++) {
    if (size <= bit_array[bit_c]) {
      break;
    }
  }
  
  return bit_c;
}

/*
 * static int size_to_free_bits
 *
 * DESCRIPTION:
 *
 * Calculate the number of bits in a size going on the free list.
 *
 * RETURNS:
 *
 * Number of bits.
 *
 * ARGUMENTS:
 *
 * size -> Size of memory of which to calculate the number of bits.
 */
static	int	size_to_free_bits(const unsigned long size)
{
  int		bit_c = 0;
  
  if (size == 0) {
    return 0;
  }
  
  for (bit_c = 0; bit_c <= MAX_BITS; bit_c++) {
    if (size < bit_array[bit_c]) {
      break;
    }
  }
  
  return bit_c - 1;
}

/*
 * static int bits_to_size
 *
 * DESCRIPTION:
 *
 * Calculate the size represented by a number of bits.
 *
 * RETURNS:
 *
 * Number of bits.
 *
 * ARGUMENTS:
 *
 * bit_n -> Number of bits
 */
static	unsigned long	bits_to_size(const int bit_n)
{
  if (bit_n > MAX_BITS) {
    return bit_array[MAX_BITS];
  }
  else {
    return bit_array[bit_n];
  }
}

/*
 * static void *alloc_pages
 *
 * DESCRIPTION:
 *
 * Allocate space for a number of memory pages in the memory pool.
 *
 * RETURNS:
 *
 * Success - New pages of memory
 *
 * Failure - NULL
 *
 * ARGUMENTS:
 *
 * mp_p <-> Pointer to our memory pool.
 *
 * page_n -> Number of pages to alloc.
 *
 * error_p <- Pointer to integer which, if not NULL, will be set with
 * a mpool error code.
 */
static	void	*alloc_pages(mpool_t *mp_p, const unsigned int page_n,
			     int *error_p)
{
  void		*mem, *fill_mem;
  unsigned long	size, fill;
  int		state;
  
  /* are we over our max-pages? */
  if (mp_p->mp_max_pages > 0 && mp_p->mp_page_c >= mp_p->mp_max_pages) {
    SET_POINTER(error_p, MPOOL_ERROR_NO_PAGES);
    return NULL;
  }
  
  size = SIZE_OF_PAGES(mp_p, page_n);
  
#ifdef DEBUG
  (void)printf("allocating %u pages or %lu bytes\n", page_n, size);
#endif
  
  if (BIT_IS_SET(mp_p->mp_flags, MPOOL_FLAG_USE_SBRK)) {
    mem = sbrk(size);
    if (mem == (void *)-1) {
      SET_POINTER(error_p, MPOOL_ERROR_NO_MEM);
      return NULL;
    }
    fill = (unsigned long)mem % mp_p->mp_page_size;
    
    if (fill > 0) {
      fill = mp_p->mp_page_size - fill;
      fill_mem = sbrk(fill);
      if (fill_mem == (void *)-1) {
	SET_POINTER(error_p, MPOOL_ERROR_NO_MEM);
	return NULL;
      }
      if ((char *)fill_mem != (char *)mem + size) {
	SET_POINTER(error_p, MPOOL_ERROR_SBRK_CONTIG);
	return NULL;
      }
      mem = (char *)mem + fill;
    }
  }
  else {
    state = MAP_PRIVATE;
#ifdef MAP_FILE
    state |= MAP_FILE;
#endif
#ifdef MAP_VARIABLE
    state |= MAP_VARIABLE;
#endif
    
    /* mmap from /dev/zero */
    mem = mmap((caddr_t)mp_p->mp_addr, size, PROT_READ | PROT_WRITE, state,
	       mp_p->mp_fd, mp_p->mp_top);
    if (mem == (void *)MAP_FAILED) {
      if (errno == ENOMEM) {
	SET_POINTER(error_p, MPOOL_ERROR_NO_MEM);
      }
      else {
	SET_POINTER(error_p, MPOOL_ERROR_MMAP);
      }
      return NULL;
    }
    mp_p->mp_top += size;
    if (mp_p->mp_addr != NULL) {
      mp_p->mp_addr = (char *)mp_p->mp_addr + size;
    }
  }
  
  mp_p->mp_page_c += page_n;
  
  SET_POINTER(error_p, MPOOL_ERROR_NONE);
  return mem;
}

/*
 * static int free_pages
 *
 * DESCRIPTION:
 *
 * Free previously allocated pages of memory.
 *
 * RETURNS:
 *
 * Success - MPOOL_ERROR_NONE
 *
 * Failure - Mpool error code
 *
 * ARGUMENTS:
 *
 * pages <-> Pointer to memory pages that we are freeing.
 *
 * size -> Size of the block that we are freeing.
 *
 * sbrk_b -> Set to one if the pages were allocated with sbrk else mmap.
 */
static	int	free_pages(void *pages, const unsigned long size,
			   const int sbrk_b)
{
  if (! sbrk_b) {
    (void)munmap((caddr_t)pages, size);
  }
  
  return MPOOL_ERROR_NONE;
}

/*
 * static int check_magic
 *
 * DESCRIPTION:
 *
 * Check for the existance of the magic ID in a memory pointer.
 *
 * RETURNS:
 *
 * Success - MPOOL_ERROR_NONE
 *
 * Failure - Mpool error code
 *
 * ARGUMENTS:
 *
 * addr -> Address inside of the block that we are tryign to locate.
 *
 * size -> Size of the block.
 */
static	int	check_magic(const void *addr, const unsigned long size)
{
  const unsigned char	*mem_p;
  
  /* set our starting point */
  mem_p = (unsigned char *)addr + size;
  
  if (*mem_p == FENCE_MAGIC0 && *(mem_p + 1) == FENCE_MAGIC1) {
    return MPOOL_ERROR_NONE;
  }
  else {
    return MPOOL_ERROR_PNT_OVER;
  }
}

/*
 * static void write_magic
 *
 * DESCRIPTION:
 *
 * Write the magic ID to the address.
 *
 * RETURNS:
 *
 * None.
 *
 * ARGUMENTS:
 *
 * addr -> Address where to write the magic.
 */
static	void	write_magic(const void *addr)
{
  *(unsigned char *)addr = FENCE_MAGIC0;
  *((unsigned char *)addr + 1) = FENCE_MAGIC1;
}

/*
 * static void free_pointer
 *
 * DESCRIPTION:
 *
 * Moved a pointer into our free lists.
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
 * addr <-> Address where to write the magic.  We may write a next
 * pointer to it.
 *
 * size -> Size of the address space.
 */
static	int	free_pointer(mpool_t *mp_p, void *addr,
			     const unsigned long size)
{
  unsigned int	bit_n;
  unsigned long	real_size;
  mpool_free_t	free_pnt;
  
#ifdef DEBUG
  (void)printf("freeing a block at %lx of %lu bytes\n", (long)addr, size);
#endif
  
  if (size == 0) {
    return MPOOL_ERROR_NONE;
  }
  
  /*
   * if the user size is larger then can fit in an entire block then
   * we change the size
   */
  if (size > MAX_BLOCK_USER_MEMORY(mp_p)) {
    real_size = SIZE_OF_PAGES(mp_p, PAGES_IN_SIZE(mp_p, size)) -
      sizeof(mpool_block_t);
  }
  else {
    real_size = size;
  }
  
  /*
   * We use a specific free bits calculation here because if we are
   * freeing 10 bytes then we will be putting it into the 8-byte free
   * list and not the 16 byte list.  size_to_bits(10) will return 4
   * instead of 3.
   */
  bit_n = size_to_free_bits(real_size);
  
  /*
   * Minimal error checking.  We could go all the way through the
   * list however this might be prohibitive.
   */
  if (mp_p->mp_free[bit_n] == addr) {
    return MPOOL_ERROR_IS_FREE;
  }
  
  /* add the freed pointer to the free list */
  if (bit_n < min_bit_free_next) {
    /*
     * Yes we know this will lose 99% of the allocations but what else
     * can we do?  No space for a next pointer.
     */
    if (mp_p->mp_free[bit_n] == NULL) {
      mp_p->mp_free[bit_n] = addr;
    }
  }
  else if (bit_n < min_bit_free_size) {
    /* we copy, not assign, to maintain the free list */
    memcpy(addr, mp_p->mp_free + bit_n, sizeof(void *));
    mp_p->mp_free[bit_n] = addr;
  }
  else {
    
    /* setup our free list structure */
    free_pnt.mf_next_p = mp_p->mp_free[bit_n];
    free_pnt.mf_size = real_size;
    
    /* we copy the structure in since we don't know about alignment */
    memcpy(addr, &free_pnt, sizeof(free_pnt));
    mp_p->mp_free[bit_n] = addr;
  }
  
  return MPOOL_ERROR_NONE;
}

/*
 * static int split_block
 *
 * DESCRIPTION:
 *
 * When freeing space in a multi-block chunk we have to create new
 * blocks out of the upper areas being freed.
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
 * free_addr -> Address that we are freeing.
 *
 * size -> Size of the space that we are taking from address.
 */
static	int	split_block(mpool_t *mp_p, void *free_addr,
			    const unsigned long size)
{
  mpool_block_t	*block_p, *new_block_p;
  int		ret, page_n;
  void		*end_p;
  
  /*
   * 1st we find the block pointer from our free addr.  At this point
   * the pointer must be the 1st one in the block if it is spans
   * multiple blocks.
   */
  block_p = (mpool_block_t *)((char *)free_addr - sizeof(mpool_block_t));
  if (block_p->mb_magic != BLOCK_MAGIC
      || block_p->mb_magic2 != BLOCK_MAGIC) {
    return MPOOL_ERROR_POOL_OVER;
  }
  
  page_n = PAGES_IN_SIZE(mp_p, size);
  
  /* we are creating a new block structure for the 2nd ... */
  new_block_p = (mpool_block_t *)((char *)block_p +
				  SIZE_OF_PAGES(mp_p, page_n));
  new_block_p->mb_magic = BLOCK_MAGIC;
  /* New bounds is 1st block bounds.  The 1st block's is reset below. */
  new_block_p->mb_bounds_p = block_p->mb_bounds_p;
  /* Continue the linked list.  The 1st block will point to us below. */
  new_block_p->mb_next_p = block_p->mb_next_p;
  new_block_p->mb_magic2 = BLOCK_MAGIC;
  
  /* bounds for the 1st block are reset to the 1st page only */
  block_p->mb_bounds_p = (char *)new_block_p;
  /* the next block pointer for the 1st block is now the new one */
  block_p->mb_next_p = new_block_p;
  
  /* only free the space in the 1st block if it is only 1 block in size */
  if (page_n == 1) {
    /* now free the rest of the 1st block block */
    end_p = (char *)free_addr + size;
    ret = free_pointer(mp_p, end_p,
		       (char *)block_p->mb_bounds_p - (char *)end_p);
    if (ret != MPOOL_ERROR_NONE) {
      return ret;
    }
  }
  
  /* now free the rest of the block */
  ret = free_pointer(mp_p, FIRST_ADDR_IN_BLOCK(new_block_p),
		     MEMORY_IN_BLOCK(new_block_p));
  if (ret != MPOOL_ERROR_NONE) {
    return ret;
  }
  
  return MPOOL_ERROR_NONE;
}

/*
 * static void *get_space
 *
 * DESCRIPTION:
 *
 * Moved a pointer into our free lists.
 *
 * RETURNS:
 *
 * Success - New address that we can use.
 *
 * Failure - NULL
 *
 * ARGUMENTS:
 *
 * mp_p <-> Pointer to the memory pool.
 *
 * byte_size -> Size of the address space that we need.
 *
 * error_p <- Pointer to integer which, if not NULL, will be set with
 * a mpool error code.
 */
static	void	*get_space(mpool_t *mp_p, const unsigned long byte_size,
			   int *error_p)
{
  mpool_block_t	*block_p;
  mpool_free_t	free_pnt;
  int		ret;
  unsigned long	size;
  unsigned int	bit_c, page_n, left;
  void		*free_addr = NULL, *free_end;
  
  size = byte_size;
  while ((size & (sizeof(void *) - 1)) > 0) {
    size++;
  }
  
  /*
   * First we check the free lists looking for something with enough
   * pages.  Maybe we should only look X bits higher in the list.
   *
   * XXX: this is where we'd do the best fit.  We'd look for the
   * closest match.  We then could put the rest of the allocation that
   * we did not use in a lower free list.  Have a define which states
   * how deep in the free list to go to find the closest match.
   */
  for (bit_c = size_to_bits(size); bit_c <= MAX_BITS; bit_c++) {
    if (mp_p->mp_free[bit_c] != NULL) {
      free_addr = mp_p->mp_free[bit_c];
      break;
    }
  }
  
  /*
   * If we haven't allocated any blocks or if the last block doesn't
   * have enough memory then we need a new block.
   */
  if (bit_c > MAX_BITS) {
    
    /* we need to allocate more space */
    
    page_n = PAGES_IN_SIZE(mp_p, size);
    
    /* now we try and get the pages we need/want */
    block_p = alloc_pages(mp_p, page_n, error_p);
    if (block_p == NULL) {
      /* error_p set in alloc_pages */
      return NULL;
    }
    
    /* init the block header */
    block_p->mb_magic = BLOCK_MAGIC;
    block_p->mb_bounds_p = (char *)block_p + SIZE_OF_PAGES(mp_p, page_n);
    block_p->mb_next_p = mp_p->mp_first_p;
    block_p->mb_magic2 = BLOCK_MAGIC;
    
    /*
     * We insert it into the front of the queue.  We could add it to
     * the end but there is not much use.
     */
    mp_p->mp_first_p = block_p;
    if (mp_p->mp_last_p == NULL) {
      mp_p->mp_last_p = block_p;
    }
    
    free_addr = FIRST_ADDR_IN_BLOCK(block_p);
    
#ifdef DEBUG
    (void)printf("had to allocate space for %lx of %lu bytes\n",
		 (long)free_addr, size);
#endif

    free_end = (char *)free_addr + size;
    left = (char *)block_p->mb_bounds_p - (char *)free_end;
  }
  else {
    
    if (bit_c < min_bit_free_next) {
      mp_p->mp_free[bit_c] = NULL;
      /* calculate the number of left over bytes */
      left = bits_to_size(bit_c) - size;
    }
    else if (bit_c < min_bit_free_next) {
      /* grab the next pointer from the freed address into our list */
      memcpy(mp_p->mp_free + bit_c, free_addr, sizeof(void *));
      /* calculate the number of left over bytes */
      left = bits_to_size(bit_c) - size;
    }
    else {
      /* grab the free structure from the address */
      memcpy(&free_pnt, free_addr, sizeof(free_pnt));
      mp_p->mp_free[bit_c] = free_pnt.mf_next_p;
      
      /* are we are splitting up a multiblock chunk into fewer blocks? */
      if (PAGES_IN_SIZE(mp_p, free_pnt.mf_size) > PAGES_IN_SIZE(mp_p, size)) {
	ret = split_block(mp_p, free_addr, size);
	if (ret != MPOOL_ERROR_NONE) {
	  SET_POINTER(error_p, ret);
	  return NULL;
	}
	/* left over memory was taken care of in split_block */
	left = 0;
      }
      else {
	/* calculate the number of left over bytes */
	left = free_pnt.mf_size - size;
      }
    }
    
#ifdef DEBUG
    (void)printf("found a free block at %lx of %lu bytes\n",
		 (long)free_addr, left + size);
#endif
    
    free_end = (char *)free_addr + size;
  }
  
  /*
   * If we have memory left over then we free it so someone else can
   * use it.  We do not free the space if we just allocated a
   * multi-block chunk because we need to have every allocation easily
   * find the start of the block.  Every user address % page-size
   * should take us to the start of the block.
   */
  if (left > 0 && size <= MAX_BLOCK_USER_MEMORY(mp_p)) {
    /* free the rest of the block */
    ret = free_pointer(mp_p, free_end, left);
    if (ret != MPOOL_ERROR_NONE) {
      SET_POINTER(error_p, ret);
      return NULL;
    }
  }
  
  /* update our bounds */
  if (free_addr > mp_p->mp_bounds_p) {
    mp_p->mp_bounds_p = free_addr;
  }
  else if (free_addr < mp_p->mp_min_p) {
    mp_p->mp_min_p = free_addr;
  }
  
  return free_addr;
}

/*
 * static void *alloc_mem
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
static	void	*alloc_mem(mpool_t *mp_p, const unsigned long byte_size,
			   int *error_p)
{
  unsigned long	size, fence;
  void		*addr;
  
  /* make sure we have enough bytes */
  if (byte_size < MIN_ALLOCATION) {
    size = MIN_ALLOCATION;
  }
  else {
    size = byte_size;
  }
  
  if (BIT_IS_SET(mp_p->mp_flags, MPOOL_FLAG_NO_FREE)) {
    fence = 0;
  }
  else {
    fence = FENCE_SIZE;
  }
  
  /* get our free space + the space for the fence post */
  addr = get_space(mp_p, size + fence, error_p);
  if (addr == NULL) {
    /* error_p set in get_space */
    return NULL;
  }
  
  if (! BIT_IS_SET(mp_p->mp_flags, MPOOL_FLAG_NO_FREE)) {
    write_magic((char *)addr + size);
  }
  
  /* maintain our stats */
  mp_p->mp_alloc_c++;
  mp_p->mp_user_alloc += size;
  if (mp_p->mp_user_alloc > mp_p->mp_max_alloc) {
    mp_p->mp_max_alloc = mp_p->mp_user_alloc;
  }
  
  SET_POINTER(error_p, MPOOL_ERROR_NONE);
  return addr;
}

/*
 * static int free_mem
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
static	int	free_mem(mpool_t *mp_p, void *addr, const unsigned long size)
{
  unsigned long	old_size, fence;
  int		ret;
  mpool_block_t	*block_p;
  
  /*
   * If the size is larger than a block then the allocation must be at
   * the front of the block.
   */
  if (size > MAX_BLOCK_USER_MEMORY(mp_p)) {
    block_p = (mpool_block_t *)((char *)addr - sizeof(mpool_block_t));
    if (block_p->mb_magic != BLOCK_MAGIC
	|| block_p->mb_magic2 != BLOCK_MAGIC) {
      return MPOOL_ERROR_POOL_OVER;
    }
  }
  
  /* make sure we have enough bytes */
  if (size < MIN_ALLOCATION) {
    old_size = MIN_ALLOCATION;
  }
  else {
    old_size = size;
  }
  
  /* if we are packing the pool smaller */
  if (BIT_IS_SET(mp_p->mp_flags, MPOOL_FLAG_NO_FREE)) {
    fence = 0;
  }
  else {
    /* find the user's magic numbers if they were written */
    ret = check_magic(addr, old_size);
    if (ret != MPOOL_ERROR_NONE) { 
      return ret;
    }
    fence = FENCE_SIZE;
  }
  
  /* now we free the pointer */
  ret = free_pointer(mp_p, addr, old_size + fence);
  if (ret != MPOOL_ERROR_NONE) {
    return ret;
  }
  mp_p->mp_user_alloc -= old_size;
  
  /* adjust our stats */
  mp_p->mp_alloc_c--;
  
  return MPOOL_ERROR_NONE;
}

/***************************** exported routines *****************************/

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
mpool_t	*mpool_open(const unsigned int flags, const unsigned int page_size,
		    void *start_addr, int *error_p)
{
  mpool_block_t	*block_p;
  int		page_n, ret;
  mpool_t	mp, *mp_p;
  void		*free_addr;
  
  if (! enabled_b) {
    startup();
  }
  
  /* zero our temp struct */
  memset(&mp, 0, sizeof(mp));
  
  mp.mp_magic = MPOOL_MAGIC;
  mp.mp_flags = flags;
  mp.mp_alloc_c = 0;
  mp.mp_user_alloc = 0;
  mp.mp_max_alloc = 0;
  mp.mp_page_c = 0;
  /* mp.mp_page_size set below */
  /* mp.mp_blocks_bit_n set below */
  /* mp.mp_fd set below */
  /* mp.mp_top set below */
  /* mp.mp_addr set below */
  mp.mp_log_func = NULL;
  mp.mp_min_p = NULL;
  mp.mp_bounds_p = NULL;
  mp.mp_first_p = NULL;
  mp.mp_last_p = NULL;
  mp.mp_magic2 = MPOOL_MAGIC;
  
  /* get and sanity check our page size */
  if (page_size > 0) {
    mp.mp_page_size = page_size;
    if (mp.mp_page_size % getpagesize() != 0) {
      SET_POINTER(error_p, MPOOL_ERROR_ARG_INVALID);
      return NULL;
    }
  }
  else {
    mp.mp_page_size = getpagesize() * DEFAULT_PAGE_MULT;
    if (mp.mp_page_size % 1024 != 0) {
      SET_POINTER(error_p, MPOOL_ERROR_PAGE_SIZE);
      return NULL;
    }
  }
  
  if (BIT_IS_SET(flags, MPOOL_FLAG_USE_SBRK)) {
    mp.mp_fd = -1;
    mp.mp_addr = NULL;
    mp.mp_top = 0;
  }
  else {
    /* open dev-zero for our mmaping */
    mp.mp_fd = open("/dev/zero", O_RDWR, 0);
    if (mp.mp_fd < 0) {
      SET_POINTER(error_p, MPOOL_ERROR_OPEN_ZERO);
      return NULL;
    }
    mp.mp_addr = start_addr;
    /* we start at the front of the file */
    mp.mp_top = 0;
  }
  
  /*
   * Find out how many pages we need for our mpool structure.
   *
   * NOTE: this adds possibly unneeded space for mpool_block_t which
   * may not be in this block.
   */
  page_n = PAGES_IN_SIZE(&mp, sizeof(mpool_t));
  
  /* now allocate us space for the actual struct */
  mp_p = alloc_pages(&mp, page_n, error_p);
  if (mp_p == NULL) {
    if (mp.mp_fd >= 0) {
      (void)close(mp.mp_fd);
      mp.mp_fd = -1;
    }
    return NULL;
  }
  
  /*
   * NOTE: we do not normally free the rest of the block here because
   * we want to lesson the chance of an allocation overwriting the
   * main structure.
   */
  if (BIT_IS_SET(flags, MPOOL_FLAG_HEAVY_PACKING)) {
    
    /* we add a block header to the front of the block */
    block_p = (mpool_block_t *)mp_p;
    
    /* init the block header */
    block_p->mb_magic = BLOCK_MAGIC;
    block_p->mb_bounds_p = (char *)block_p + SIZE_OF_PAGES(&mp, page_n);
    block_p->mb_next_p = NULL;
    block_p->mb_magic2 = BLOCK_MAGIC;
    
    /* the mpool pointer is then the 2nd thing in the block */
    mp_p = FIRST_ADDR_IN_BLOCK(block_p);
    free_addr = (char *)mp_p + sizeof(mpool_t);
    
    /* free the rest of the block */
    ret = free_pointer(&mp, free_addr,
		       (char *)block_p->mb_bounds_p - (char *)free_addr);
    if (ret != MPOOL_ERROR_NONE) {
      if (mp.mp_fd >= 0) {
	(void)close(mp.mp_fd);
	mp.mp_fd = -1;
      }
      /* NOTE: after this line mp_p will be invalid */
      (void)free_pages(block_p, SIZE_OF_PAGES(&mp, page_n),
		       BIT_IS_SET(flags, MPOOL_FLAG_USE_SBRK));
      SET_POINTER(error_p, ret);
      return NULL;
    }
    
    /*
     * NOTE: if we are HEAVY_PACKING then the 1st block with the mpool
     * header is not on the block linked list.
     */
    
    /* now copy our tmp structure into our new memory area */
    memcpy(mp_p, &mp, sizeof(mpool_t));
    
    /* we setup min/max to our current address which is as good as any */
    mp_p->mp_min_p = block_p;
    mp_p->mp_bounds_p = block_p->mb_bounds_p;
  }
  else {
    /* now copy our tmp structure into our new memory area */
    memcpy(mp_p, &mp, sizeof(mpool_t));
    
    /* we setup min/max to our current address which is as good as any */
    mp_p->mp_min_p = mp_p;
    mp_p->mp_bounds_p = (char *)mp_p + SIZE_OF_PAGES(mp_p, page_n);
  }
  
  SET_POINTER(error_p, MPOOL_ERROR_NONE);
  return mp_p;
}

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
int	mpool_close(mpool_t *mp_p)
{
  mpool_block_t	*block_p, *next_p;
  void		*addr;
  unsigned long	size;
  int		ret, final = MPOOL_ERROR_NONE;
  
  /* special case, just return no-error */
  if (mp_p == NULL) {
    return MPOOL_ERROR_ARG_NULL;
  }
  if (mp_p->mp_magic != MPOOL_MAGIC) {
    return MPOOL_ERROR_PNT;
  }
  if (mp_p->mp_magic2 != MPOOL_MAGIC) {
    return MPOOL_ERROR_POOL_OVER;
  }
  
  if (mp_p->mp_log_func != NULL) {
    mp_p->mp_log_func(mp_p, MPOOL_FUNC_CLOSE, 0, 0, NULL, NULL, 0);
  }
  
  /*
   * NOTE: if we are HEAVY_PACKING then the 1st block with the mpool
   * header is not on the linked list.
   */
  
  /* free/invalidate the blocks */
  for (block_p = mp_p->mp_first_p; block_p != NULL; block_p = next_p) {
    if (block_p->mb_magic != BLOCK_MAGIC
	|| block_p->mb_magic2 != BLOCK_MAGIC) {
      final = MPOOL_ERROR_POOL_OVER;
      break;
    }
    block_p->mb_magic = 0;
    block_p->mb_magic2 = 0;
    /* record the next pointer because it might be invalidated below */
    next_p = block_p->mb_next_p;
    ret = free_pages(block_p, (char *)block_p->mb_bounds_p - (char *)block_p,
		     BIT_IS_SET(mp_p->mp_flags, MPOOL_FLAG_USE_SBRK));
    if (ret != MPOOL_ERROR_NONE) {
      final = ret;
    }
  }
  
  /* close /dev/zero if necessary */
  if (mp_p->mp_fd >= 0) {
    (void)close(mp_p->mp_fd);
    mp_p->mp_fd = -1;
  }
  
  /* invalidate the mpool before we ditch it */
  mp_p->mp_magic = 0;
  mp_p->mp_magic2 = 0;
  
  /* last we munmap the mpool pointer itself */
  if (! BIT_IS_SET(mp_p->mp_flags, MPOOL_FLAG_USE_SBRK)) {
    
    /* if we are heavy packing then we need to free the 1st block later */
    if (BIT_IS_SET(mp_p->mp_flags, MPOOL_FLAG_HEAVY_PACKING)) {
      addr = (char *)mp_p - sizeof(mpool_block_t);
    }
    else {
      addr = mp_p;
    }
    size = SIZE_OF_PAGES(mp_p, PAGES_IN_SIZE(mp_p, sizeof(mpool_t)));
    
    (void)munmap((caddr_t)addr, size);
  }
  
  return final;
}

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
int	mpool_clear(mpool_t *mp_p)
{
  mpool_block_t	*block_p;
  int		final = MPOOL_ERROR_NONE, bit_n, ret;
  void		*first_p;
  
  /* special case, just return no-error */
  if (mp_p == NULL) {
    return MPOOL_ERROR_ARG_NULL;
  }
  if (mp_p->mp_magic != MPOOL_MAGIC) {
    return MPOOL_ERROR_PNT;
  }
  if (mp_p->mp_magic2 != MPOOL_MAGIC) {
    return MPOOL_ERROR_POOL_OVER;
  }
  
  if (mp_p->mp_log_func != NULL) {
    mp_p->mp_log_func(mp_p, MPOOL_FUNC_CLEAR, 0, 0, NULL, NULL, 0);
  }
  
  /* reset all of our free lists */
  for (bit_n = 0; bit_n <= MAX_BITS; bit_n++) {
    mp_p->mp_free[bit_n] = NULL;
  }
  
  /* free the blocks */
  for (block_p = mp_p->mp_first_p;
       block_p != NULL;
       block_p = block_p->mb_next_p) {
    if (block_p->mb_magic != BLOCK_MAGIC
	|| block_p->mb_magic2 != BLOCK_MAGIC) {
      final = MPOOL_ERROR_POOL_OVER;
      break;
    }
    
    first_p = FIRST_ADDR_IN_BLOCK(block_p);
    
    /* free the memory */
    ret = free_pointer(mp_p, first_p, MEMORY_IN_BLOCK(block_p));
    if (ret != MPOOL_ERROR_NONE) {
      final = ret;
    }
  }
  
  return final;
}

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
 * mp_p <-> Pointer to the memory pool
 *
 * byte_size -> Number of bytes to allocate in the pool.  Must be >0.
 *
 * error_p <- Pointer to integer which, if not NULL, will be set with
 * a mpool error code.
 */
void	*mpool_alloc(mpool_t *mp_p, const unsigned long byte_size,
		     int *error_p)
{
  struct FRAG *frag;
  
  if (!mp_p || mp_p->mp_magic != MPOOL_MAGIC) {
    SET_POINTER(error_p, MPOOL_ERROR_PNT);
    return NULL;
  }
  if (mp_p->mp_magic2 != MPOOL_MAGIC) {
    SET_POINTER(error_p, MPOOL_ERROR_POOL_OVER);
    return NULL;
  }
  
  if (byte_size == 0) {
    SET_POINTER(error_p, MPOOL_ERROR_ARG_INVALID);
    return NULL;
  }
  
  frag = (struct FRAG *)alloc_mem(mp_p, byte_size + FRAG_OVERHEAD, error_p);
  
  if (mp_p->mp_log_func != NULL) {
    mp_p->mp_log_func(mp_p, MPOOL_FUNC_ALLOC, byte_size, 0, (void *)frag, NULL, 0);
  }

  frag->frag_size = byte_size;
  return &frag->frag_ptr;
}

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
 * mp_p <-> Pointer to the memory pool.
 *
 * ele_n -> Number of elements to allocate.
 *
 * ele_size -> Number of bytes per element being allocated.
 *
 * error_p <- Pointer to integer which, if not NULL, will be set with
 * a mpool error code.
 */
void	*mpool_calloc(mpool_t *mp_p, const unsigned long ele_n,
		      const unsigned long ele_size, int *error_p)
{
  struct FRAG *frag;
  unsigned long	byte_size;
  
  if (!mp_p || mp_p->mp_magic != MPOOL_MAGIC) {
    SET_POINTER(error_p, MPOOL_ERROR_PNT);
    return NULL;
  }
  if (mp_p->mp_magic2 != MPOOL_MAGIC) {
    SET_POINTER(error_p, MPOOL_ERROR_POOL_OVER);
    return NULL;
  }
  
  if (ele_n == 0 || ele_size == 0) {
    SET_POINTER(error_p, MPOOL_ERROR_ARG_INVALID);
    return NULL;
  }
  
  byte_size = ele_n * ele_size;

  frag = alloc_mem(mp_p, byte_size + FRAG_OVERHEAD, error_p);
  if (frag != NULL) {
    memset(&frag->frag_ptr, 0, byte_size);
  }

  if (mp_p->mp_log_func != NULL) {
    mp_p->mp_log_func(mp_p, MPOOL_FUNC_CALLOC, ele_size, ele_n, (void *)frag, NULL, 0);
  }

  frag->frag_size = byte_size;
  return &frag->frag_ptr;
}

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
 * mp_p <-> Pointer to the memory pool.
 *
 * addr <-> Address to free.
 *
 * size -> Size of the address being freed.
 */
int	mpool_free(mpool_t *mp_p, void *addr)
{
  struct FRAG *frag = (struct FRAG *) (addr - FRAG_OVERHEAD);

  if (!mp_p || mp_p->mp_magic != MPOOL_MAGIC) {
    return MPOOL_ERROR_PNT;
  }
  if (mp_p->mp_magic2 != MPOOL_MAGIC) {
    return MPOOL_ERROR_POOL_OVER;
  }
  
  if (mp_p->mp_log_func != NULL) {
    mp_p->mp_log_func(mp_p, MPOOL_FUNC_FREE, 0, 0, NULL, addr, 0);
  }
  
  if (addr == NULL) {
    return MPOOL_ERROR_ARG_NULL;
  }

  return free_mem(mp_p, (void *)frag, frag->frag_size + FRAG_OVERHEAD);
}

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
void	*mpool_resize(mpool_t *mp_p, void *old_addr,
		      const unsigned long new_byte_size,
		      int *error_p)
{
  unsigned long	copy_size, new_size, old_size, fence;
  struct FRAG *new_frag;
  mpool_block_t	*block_p;
  int		ret;
  struct FRAG *old_frag = (struct FRAG *)(old_addr - FRAG_OVERHEAD);
  unsigned long old_byte_size;
  
  if (!mp_p || mp_p->mp_magic != MPOOL_MAGIC) {
    SET_POINTER(error_p, MPOOL_ERROR_PNT);
    return NULL;
  }
  if (mp_p->mp_magic2 != MPOOL_MAGIC) {
    SET_POINTER(error_p, MPOOL_ERROR_POOL_OVER);
    return NULL;
  }
  
  if (old_addr == NULL) {
    SET_POINTER(error_p, MPOOL_ERROR_ARG_NULL);
    return NULL;
  }

  old_byte_size = old_frag->frag_size;
  if (old_byte_size == 0) {
    SET_POINTER(error_p, MPOOL_ERROR_ARG_INVALID);
    return NULL;
  }
  
  /*
   * If the size is larger than a block then the allocation must be at
   * the front of the block.
   */
  if (old_byte_size + FRAG_OVERHEAD > MAX_BLOCK_USER_MEMORY(mp_p)) {
    block_p = (mpool_block_t *)((char *)old_frag - sizeof(mpool_block_t));
    if (block_p->mb_magic != BLOCK_MAGIC
	|| block_p->mb_magic2 != BLOCK_MAGIC) {
      SET_POINTER(error_p, MPOOL_ERROR_POOL_OVER);
      return NULL;
    }
  }
  
  /* make sure we have enough bytes */
  if (old_byte_size + FRAG_OVERHEAD < MIN_ALLOCATION) {
    old_size = MIN_ALLOCATION;
  }
  else {
    old_size = old_byte_size + FRAG_OVERHEAD;
  }
  
  /* verify that the size matches exactly if we can */
  if (BIT_IS_SET(mp_p->mp_flags, MPOOL_FLAG_NO_FREE)) {
    fence = 0;
  }
  else if (old_size > 0) {
    ret = check_magic((void *)old_frag, old_size);
    if (ret != MPOOL_ERROR_NONE) {
      SET_POINTER(error_p, ret);
      return NULL;
    }
    fence = FENCE_SIZE;
  }
  
  /* make sure we have enough bytes */
  if (new_byte_size < MIN_ALLOCATION) {
    new_size = MIN_ALLOCATION;
  }
  else {
    new_size = new_byte_size;
  }
  
  /*
   * NOTE: we could here see if the size is the same or less and then
   * use the current memory and free the space above.  This is harder
   * than it sounds if we are changing the block size of the
   * allocation.
   */
  
  /* we need to get another address */
  new_frag = alloc_mem(mp_p, new_byte_size + FRAG_OVERHEAD, error_p);
  if (new_frag == NULL) {
    /* error_p set in mpool_alloc */
    return NULL;
  }
  
  if (new_byte_size > old_byte_size) {
    copy_size = old_byte_size;
  }
  else {
    copy_size = new_byte_size;
  }
  new_frag->frag_size = new_byte_size;
  memcpy(&new_frag->frag_ptr, old_addr, copy_size);
  
  /* free the old address */
  ret = free_mem(mp_p, (void *)old_frag, old_byte_size + FRAG_OVERHEAD);
  if (ret != MPOOL_ERROR_NONE) {
    /* if the old free failed, try and free the new address */
    (void)free_mem(mp_p, (void *)new_frag, new_byte_size + FRAG_OVERHEAD);
    SET_POINTER(error_p, ret);
    return NULL;
  }
  
  if (mp_p->mp_log_func != NULL) {
    mp_p->mp_log_func(mp_p, MPOOL_FUNC_RESIZE, new_byte_size,
		      0, (void *)new_frag, old_addr, old_byte_size);
  }
  
  SET_POINTER(error_p, MPOOL_ERROR_NONE);
  return &new_frag->frag_ptr;
}

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
int	mpool_stats(const mpool_t *mp_p, unsigned int *page_size_p,
		    unsigned long *num_alloced_p,
		    unsigned long *user_alloced_p,
		    unsigned long *max_alloced_p,
		    unsigned long *tot_alloced_p)
{
  if (mp_p == NULL) {
    return MPOOL_ERROR_ARG_NULL;
  }
  if (mp_p->mp_magic != MPOOL_MAGIC) {
    return MPOOL_ERROR_PNT;
  }
  if (mp_p->mp_magic2 != MPOOL_MAGIC) {
    return MPOOL_ERROR_POOL_OVER;
  }
  
  SET_POINTER(page_size_p, mp_p->mp_page_size);
  SET_POINTER(num_alloced_p, mp_p->mp_alloc_c);
  SET_POINTER(user_alloced_p, mp_p->mp_user_alloc);
  SET_POINTER(max_alloced_p, mp_p->mp_max_alloc);
  SET_POINTER(tot_alloced_p, SIZE_OF_PAGES(mp_p, mp_p->mp_page_c));
  
  return MPOOL_ERROR_NONE;
}

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
int	mpool_set_log_func(mpool_t *mp_p, mpool_log_func_t log_func)
{
  if (mp_p == NULL) {
    return MPOOL_ERROR_ARG_NULL;
  }
  if (mp_p->mp_magic != MPOOL_MAGIC) {
    return MPOOL_ERROR_PNT;
  }
  if (mp_p->mp_magic2 != MPOOL_MAGIC) {
    return MPOOL_ERROR_POOL_OVER;
  }
  
  mp_p->mp_log_func = log_func;
  
  return MPOOL_ERROR_NONE;
}

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
int	mpool_set_max_pages(mpool_t *mp_p, const unsigned int max_pages)
{
  if (mp_p == NULL) {
    return MPOOL_ERROR_ARG_NULL;
  }
  if (mp_p->mp_magic != MPOOL_MAGIC) {
    return MPOOL_ERROR_PNT;
  }
  if (mp_p->mp_magic2 != MPOOL_MAGIC) {
    return MPOOL_ERROR_POOL_OVER;
  }
  
  if (BIT_IS_SET(mp_p->mp_flags, MPOOL_FLAG_HEAVY_PACKING)) {
    mp_p->mp_max_pages = max_pages;
  }
  else {
    /*
     * If we are not heavy-packing the pool then we don't count the
     * 1st page allocated which holds the mpool header structure.
     */
    mp_p->mp_max_pages = max_pages + 1;
  }
  
  return MPOOL_ERROR_NONE;
}

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
const char	*mpool_strerror(const int error)
{
  switch (error) {
  case MPOOL_ERROR_NONE:
    return "no error";
    break;
  case MPOOL_ERROR_ARG_NULL:
    return "function argument is null";
    break;
  case MPOOL_ERROR_ARG_INVALID:
    return "function argument is invalid";
    break;
  case MPOOL_ERROR_PNT:
    return "invalid mpool pointer";
    break;
  case MPOOL_ERROR_POOL_OVER:
    return "mpool structure was overwritten";
    break;
  case MPOOL_ERROR_PAGE_SIZE:
    return "could not get system page-size";
    break;
  case MPOOL_ERROR_OPEN_ZERO:
    return "could not open /dev/zero";
    break;
  case MPOOL_ERROR_NO_MEM:
    return "no memory available";
    break;
  case MPOOL_ERROR_MMAP:
    return "problems with mmap";
    break;
  case MPOOL_ERROR_SIZE:
    return "error processing requested size";
    break;
  case MPOOL_ERROR_TOO_BIG:
    return "allocation exceeds pool max size";
    break;
  case MPOOL_ERROR_MEM:
    return "invalid memory address";
    break;
  case MPOOL_ERROR_MEM_OVER:
    return "memory lower bounds overwritten";
    break;
  case MPOOL_ERROR_NOT_FOUND:
    return "memory block not found in pool";
    break;
  case MPOOL_ERROR_IS_FREE:
    return "memory address has already been freed";
    break;
  case MPOOL_ERROR_BLOCK_STAT:
    return "invalid internal block status";
    break;
  case MPOOL_ERROR_FREE_ADDR:
    return "invalid internal free address";
    break;
  case MPOOL_ERROR_SBRK_CONTIG:
    return "sbrk did not return contiguous memory";
    break;
  case MPOOL_ERROR_NO_PAGES:
    return "no available pages left in pool";
    break;
  case MPOOL_ERROR_ALLOC:
    return "system alloc function failed";
    break;
  case MPOOL_ERROR_PNT_OVER:
    return "user pointer admin space overwritten";
    break;
  default:
    break;
  }
  
  return "invalid error code";
}

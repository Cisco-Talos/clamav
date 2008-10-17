/*
 * Memory pool local defines.
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
 * $Id: mpool_loc.h,v 1.2 2005/05/20 20:08:54 gray Exp $
 */

#ifndef __MPOOL_LOC_H__
#define __MPOOL_LOC_H__

#define MPOOL_MAGIC	0xABACABA		/* magic for struct */
#define BLOCK_MAGIC	0xB1B1007		/* magic for blocks */
#define FENCE_MAGIC0	(unsigned char)(0xFAU)	/* 1st magic mem byte */
#define FENCE_MAGIC1	(unsigned char)(0xD3U)	/* 2nd magic mem byte */

#define FENCE_SIZE		2		/* fence space */
#define MIN_ALLOCATION		(sizeof(mpool_free_t))	/* min alloc */
#define MAX_FREE_SEARCH		10240		/* max size to search */
#define MAX_FREE_LIST_SEARCH	100		/* max looking for free mem */ 

/*
 * bitflag tools for Variable and a Flag
 */
#define BIT_FLAG(x)		(1 << (x))
#define BIT_SET(v,f)		(v) |= (f)
#define BIT_CLEAR(v,f)		(v) &= ~(f)
#define BIT_IS_SET(v,f)		((v) & (f))
#define BIT_TOGGLE(v,f)		(v) ^= (f)

#define SET_POINTER(pnt, val) \
	do { \
	  if ((pnt) != NULL) { \
	    (*(pnt)) = (val); \
          } \
        } while(0)

#define BLOCK_FLAG_USED		BIT_FLAG(0)		/* block is used */
#define BLOCK_FLAG_FREE		BIT_FLAG(1)		/* block is free */

#define DEFAULT_PAGE_MULT		16   /* pagesize = this * getpagesize*/

/* How many pages SIZE bytes resides in.  We add in the block header. */
#define PAGES_IN_SIZE(mp_p, size)	(((size) + sizeof(mpool_block_t) + \
					  (mp_p)->mp_page_size - 1) / \
					 (mp_p)->mp_page_size)
#define SIZE_OF_PAGES(mp_p, page_n)	((page_n) * (mp_p)->mp_page_size)
#define MAX_BITS	30		/* we only can allocate 1gb chunks */

#define MAX_BLOCK_USER_MEMORY(mp_p)	((mp_p)->mp_page_size - \
					 sizeof(mpool_block_t))
#define FIRST_ADDR_IN_BLOCK(block_p)	(void *)((char *)(block_p) + \
						 sizeof(mpool_block_t))
#define MEMORY_IN_BLOCK(block_p)	((char *)(block_p)->mb_bounds_p - \
					 ((char *)(block_p) + \
					  sizeof(mpool_block_t)))

typedef struct {
  unsigned int		mp_magic;	/* magic number for struct */
  unsigned int		mp_flags;	/* flags for the struct */
  unsigned long		mp_alloc_c;	/* number of allocations */
  unsigned long		mp_user_alloc;	/* user bytes allocated */
  unsigned long		mp_max_alloc;	/* maximum user bytes allocated */
  unsigned int		mp_page_c;	/* number of pages allocated */
  unsigned int		mp_max_pages;	/* maximum number of pages to use */
  unsigned int		mp_page_size;	/* page-size of our system */
  int			mp_fd;		/* fd for /dev/zero if mmap-ing */
  off_t			mp_top;		/* top of our allocations in fd */ 
  mpool_log_func_t	mp_log_func;	/* log callback function */
  void			*mp_addr;	/* current address for mmaping */
  void			*mp_min_p;	/* min address in pool for checks */
  void			*mp_bounds_p;	/* max address in pool for checks */
  struct mpool_block_st	*mp_first_p;	/* first memory block we are using */
  struct mpool_block_st	*mp_last_p;	/* last memory block we are using */
  struct mpool_block_st	*mp_free[MAX_BITS + 1]; /* free lists based on size */
  unsigned int		mp_magic2;	/* upper magic for overwrite sanity */
} mpool_t;

/* for debuggers to be able to interrogate the generic type in the .h file */
typedef mpool_t	mpool_ext_t;

/*
 * Block header structure.  This structure *MUST* be long-word
 * aligned.
 */
typedef struct mpool_block_st {
  unsigned int		mb_magic;	/* magic number for block header */
  void			*mb_bounds_p;	/* block boundary location */
  struct mpool_block_st	*mb_next_p;	/* linked list next pointer */
  unsigned int		mb_magic2;	/* upper magic for overwrite sanity */
} mpool_block_t;

/*
 * Free list structure.
 */
typedef struct {
  void			*mf_next_p;	/* pointer to the next free address */
  unsigned long		mf_size;	/* size of the free block */
} mpool_free_t;

#endif /* ! __MPOOL_LOC_H__ */

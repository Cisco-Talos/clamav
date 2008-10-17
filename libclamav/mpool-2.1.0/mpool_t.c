/*
 * Memory pool test program.
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
 * $Id: mpool_t.c,v 1.2 2005/05/20 20:08:55 gray Exp $
 */

/*
 * Test program for the malloc library.  Current it is interactive although
 * should be script based.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "mpool.h"

#ifdef __GNUC__
#ident "$Id: mpool_t.c,v 1.2 2005/05/20 20:08:55 gray Exp $"
#else
static char *rcs_id = "$Id: mpool_t.c,v 1.2 2005/05/20 20:08:55 gray Exp $";
#endif

#define DEFAULT_ITERATIONS	10000
#define MAX_POINTERS		1024
#define MAX_ALLOC		(1024 * 1024)
#define MIN_AVAIL		10

#define RANDOM_VALUE(x)		((random() % ((x) * 10)) / 10)

/* pointer tracking structure */
struct pnt_info_st {
  long			pi_crc;			/* crc of storage */
  long			pi_size;		/* size of storage */
  void			*pi_pnt;		/* pnt to storage */
  struct pnt_info_st	*pi_next;		/* pnt to next */
};

typedef struct pnt_info_st pnt_info_t;

static	pnt_info_t	*pointer_grid;

/* argument variables */
static	int		best_fit_b = 0;			/* set best fit flag */
static	int		heavy_pack_b = 0;		/* set heavy pack flg*/
static	int		interactive_b = 0;		/* interactive flag */
static	int		log_trxn_b = 0; 		/* log mem trxns */
static	long		max_alloc = MAX_ALLOC;		/* amt of mem to use */
static	int		max_pages_n = 0;		/* max # pages */
static	int		use_malloc_b = 0; 		/* use system alloc */
static	int		max_pointers = MAX_POINTERS;	/* # of pnts to use */
static	int		no_free_b = 0;			/* set no free flag */
static	long		page_size = 0;			/* mpool pagesize */
static	int		use_sbrk_b = 0;			/* use sbrk not mmap */
static	unsigned int	seed_random = 0;		/* random seed */
static	int		default_iter_n = DEFAULT_ITERATIONS; /* # of iters */
static	int		verbose_b = 0;			/* verbose flag */

/*
 * static long hex_to_long
 *
 * DESCRIPTION:
 *
 * Hexadecimal string to integer translation.
 *
 * RETURNS:
 *
 * Long value of converted hex string.
 *
 * ARGUMENTS:
 *
 * str -> Hex string we are converting.
 */
static	long	hex_to_long(const char *str)
{
  long		ret;
  const char	*str_p = str;
  
  /* strip off spaces */
  for (; *str_p == ' ' || *str_p == '\t'; str_p++) {
  }
  
  /* skip a leading 0[xX] */
  if (*str_p == '0' && (*(str_p + 1) == 'x' || *(str_p + 1) == 'X')) {
    str_p += 2;
  }
  
  for (ret = 0;; str_p++) {
    if (*str_p >= '0' && *str_p <= '9') {
      ret = ret * 16 + (*str_p - '0');
    }
    else if (*str_p >= 'a' && *str_p <= 'f') {
      ret = ret * 16 + (*str_p - 'a' + 10);
    }
    else if (*str_p >= 'A' && *str_p <= 'F') {
      ret = ret * 16 + (*str_p - 'A' + 10);
    }
    else {
      break;
    }
  }
  
  return ret;
}

/*
 * static void* get_address
 *
 * DESCRIPTION:
 *
 * Read an address from the user.
 *
 * RETURNS:
 *
 * Address read in from user.
 *
 * ARGUMENTS:
 *
 * None.
 */
static	void	*get_address(void)
{
  char	line[80];
  void	*pnt;
  
  do {
    (void)printf("Enter a hex address: ");
    if (fgets(line, sizeof(line), stdin) == NULL) {
      return NULL;
    }
  } while (line[0] == '\0');
  
  pnt = (void *)hex_to_long(line);
  
  return pnt;
}

/*
 * static void do_random
 *
 * DESCRIPTION:
 *
 * Try ITER_N random program iterations, returns 1 on success else 0
 *
 * RETURNS:
 *
 * None.
 *
 * ARGUMENTS:
 *
 * pool <-> Out memory pool.
 *
 * iter_n -> Number of iterations to run.
 */
static	void	do_random(mpool_t *pool, const int iter_n)
{
  int		iter_c, free_c, ret;
  long		max = max_alloc, amount;
  char		*chunk_p;
  void		*new_pnt;
  pnt_info_t	*free_p, *used_p = NULL;
  pnt_info_t	*pnt_p, *last_p;
  
  if (use_malloc_b) {
    pointer_grid = (pnt_info_t *)malloc(sizeof(pnt_info_t) * max_pointers);
  }
  else {
    pointer_grid = (pnt_info_t *)mpool_alloc(pool,
					     sizeof(pnt_info_t) * max_pointers,
					     &ret);
  }
  if (pointer_grid == NULL) {
    (void)printf("mpool_t: problems allocating %d pointer slots: %s\n",
		 max_pointers, strerror(errno));
    return;
  }
  
  /* initialize free list */
  free_p = pointer_grid;
  for (pnt_p = pointer_grid; pnt_p < pointer_grid + max_pointers; pnt_p++) {
    pnt_p->pi_size = 0;
    pnt_p->pi_pnt = NULL;
    pnt_p->pi_next = pnt_p + 1;
  }
  /* redo the last next pointer */
  (pnt_p - 1)->pi_next = NULL;
  free_c = max_pointers;
  
  for (iter_c = 0; iter_c < iter_n;) {
    int		which;
    
    /* special case when doing non-linear stuff, sbrk took all memory */
    if (max < MIN_AVAIL && free_c == max_pointers) {
      break;
    }
    
    if (free_c < max_pointers && used_p == NULL) {
      (void)fprintf(stderr, "mpool_t: problem with test program free list\n");
      exit(1);
    }
    
    /* decide whether to malloc a new pointer or free/realloc an existing */
    which = RANDOM_VALUE(4);
    
    /*
     * < MIN_AVAIL means alloc as long as we have enough memory and
     * there are free slots we do an allocation, else we free
     */
    if (free_c == max_pointers
	|| (free_c > 0 && which < 3 && max >= MIN_AVAIL)) {
      
      while (1) {
	amount = RANDOM_VALUE(max / 2);
	if (amount > 0) {
	  break;
	}
      }
      which = RANDOM_VALUE(9);
      pnt_p = NULL;
      
      switch (which) {
	
      case 0: case 1: case 2:
	pnt_p = free_p;
	if (use_malloc_b) {
	  pnt_p->pi_pnt = malloc(amount);
	}
	else {
	  pnt_p->pi_pnt = mpool_alloc(pool, amount, &ret);
	}
	
	if (verbose_b) {
	  (void)printf("%d: malloc %ld (max %ld) into slot %d.  got %#lx\n",
		       iter_c + 1, amount, max, pnt_p - pointer_grid,
		       (long)pnt_p->pi_pnt);
	}
	
	if (pnt_p->pi_pnt == NULL) {
	  (void)printf("malloc of %ld failed: %s\n",
		       amount,
		       (use_malloc_b ? strerror(errno) : mpool_strerror(ret)));
	}
	pnt_p->pi_size = amount;
	break;
	
      case 3: case 4: case 5:
	pnt_p = free_p;
	if (use_malloc_b) {
	  pnt_p->pi_pnt = calloc(amount, sizeof(char));
	}
	else {
	  pnt_p->pi_pnt = mpool_calloc(pool, amount, sizeof(char), &ret);
	}
	
	if (verbose_b) {
	  (void)printf("%d: calloc %ld (max %ld) into slot %d.  got %#lx\n",
		       iter_c + 1, amount, max, pnt_p - pointer_grid,
		       (long)pnt_p->pi_pnt);
	}
	
	/* test the returned block to make sure that is has been cleared */
	if (pnt_p->pi_pnt == NULL) {
	  (void)printf("calloc of %ld failed: %s\n",
		       amount,
		       (use_malloc_b ? strerror(errno) : mpool_strerror(ret)));
	}
	else {
	  for (chunk_p = pnt_p->pi_pnt;
	       chunk_p < (char *)pnt_p->pi_pnt + amount;
	       chunk_p++) {
	    if (*chunk_p != '\0') {
	      (void)printf("calloc of %ld not zeroed on iteration #%d\n",
			   amount, iter_c + 1);
	      break;
	    }
	  }
	  pnt_p->pi_size = amount;
	}
	break;

      case 6: case 7: case 8:
	if (free_c == max_pointers) {
	  continue;
	}
	
	which = RANDOM_VALUE(max_pointers - free_c);
	for (pnt_p = used_p; which > 0; which--) {
	  pnt_p = pnt_p->pi_next;
	}
	
	if (use_malloc_b) {
	  new_pnt = realloc(pnt_p->pi_pnt, amount);
	}
	else {
	  new_pnt = mpool_resize(pool, pnt_p->pi_pnt, amount,
				 &ret);
	}
	
	if (verbose_b) {
	  (void)printf("%d: resize %#lx from %ld to %ld (max %ld) slot %d. "
		       "got %#lx\n",
		       iter_c + 1, (long)pnt_p->pi_pnt, pnt_p->pi_size, amount,
		       max, pnt_p - pointer_grid, (long)new_pnt);
	}
	
	if (new_pnt == NULL) {
	  (void)printf("resize of %#lx old size %ld new size %ld failed: %s\n",
		       (long)pnt_p->pi_pnt, pnt_p->pi_size, amount,
		       (use_malloc_b ? strerror(errno) : mpool_strerror(ret)));
	  pnt_p->pi_pnt = NULL;
	  pnt_p->pi_size = 0;
	}
	else {
	  /* we effectively freed the old memory */
	  max += pnt_p->pi_size;
	  pnt_p->pi_pnt = new_pnt;
	  pnt_p->pi_size = amount;
	}
	break;
	
      default:
	break;
      }
      
      if (pnt_p != NULL && pnt_p->pi_pnt != NULL) {
	if (pnt_p == free_p) {
	  free_p = pnt_p->pi_next;
	  pnt_p->pi_next = used_p;
	  used_p = pnt_p;
	  free_c--;
	}
	
	max -= amount;
	iter_c++;
      }
      continue;
    }
    
    /*
     * choose a rand slot to free and make sure it is not a free-slot
     */
    which = RANDOM_VALUE(max_pointers - free_c);
    /* find pnt in the used list */
    last_p = NULL;
    for (pnt_p = used_p, last_p = NULL;
	 pnt_p != NULL && which > 0;
	 last_p = pnt_p, pnt_p = pnt_p->pi_next, which--) {
    }
    if (pnt_p == NULL) {
      /* huh? error here */
      abort();
    }
    if (last_p == NULL) {
      used_p = pnt_p->pi_next;
    }
    else {
      last_p->pi_next = pnt_p->pi_next;
    }
    
    if (use_malloc_b) {
      free(pnt_p->pi_pnt);
    }
    else {
      ret = mpool_free(pool, pnt_p->pi_pnt);
      if (ret != MPOOL_ERROR_NONE) {
	(void)printf("free error on pointer '%#lx' of size %ld: %s\n",
		     (long)pnt_p->pi_pnt, pnt_p->pi_size,
		     mpool_strerror(ret));
      }
    }
    
    if (verbose_b) {
      (void)printf("%d: free'd %ld bytes from slot %d (%#lx)\n",
		   iter_c + 1, pnt_p->pi_size, pnt_p - pointer_grid,
		   (long)pnt_p->pi_pnt);
    }
    
    pnt_p->pi_pnt = NULL;
    pnt_p->pi_next = free_p;
    free_p = pnt_p;
    free_c++;
    
    max += pnt_p->pi_size;
    iter_c++;
  }
  
  /* free used pointers */
  for (pnt_p = pointer_grid; pnt_p < pointer_grid + max_pointers; pnt_p++) {
    if (pnt_p->pi_pnt != NULL) {
      if (use_malloc_b) {
	free(pnt_p->pi_pnt);
      }
      else {
	ret = mpool_free(pool, pnt_p->pi_pnt);
	if (ret != MPOOL_ERROR_NONE) {
	  (void)printf("free error on pointer '%#lx' of size %ld: %s\n",
		       (long)pnt_p->pi_pnt, pnt_p->pi_size,
		       mpool_strerror(ret));
	}
      }
    }
  }
  
  if (use_malloc_b) {
    free(pointer_grid);
  }
  else {
    ret = mpool_free(pool, pointer_grid);
    if (ret != MPOOL_ERROR_NONE) {
      (void)printf("free error on grid pointer: %s\n", mpool_strerror(ret));
    }
  }
}

/*
 * static void do_interactive
 *
 * DESCRIPTION:
 *
 * Run the interactive section of the program.
 *
 * RETURNS:
 *
 * None.
 *
 * ARGUMENTS:
 *
 * pool <-> Out memory pool.
 */
static	void	do_interactive(mpool_t *pool)
{
  int		len, ret;
  char		line[128], *line_p;
  void		*pnt, *new_pnt;
  
  (void)printf("Mpool test program.  Type 'help' for assistance.\n");
  
  for (;;) {
    (void)printf("> ");
    if (fgets(line, sizeof(line), stdin) == NULL) {
      break;
    }
    line_p = strchr(line, '\n');
    if (line_p != NULL) {
      *line_p = '\0';
    }
    
    len = strlen(line);
    if (len == 0) {
      continue;
    }
    
    if (strncmp(line, "?", len) == 0
	|| strncmp(line, "help", len) == 0) {
      (void)printf("\thelp      - print this message\n\n");
      
      (void)printf("\tmalloc    - allocate memory\n");
      (void)printf("\tcalloc    - allocate/clear memory\n");
      (void)printf("\tresize    - resize memory\n");
      (void)printf("\tfree      - deallocate memory\n\n");
      
      (void)printf("\tclear     - clear the pool\n");
      (void)printf("\toverwrite - overwrite some memory to test errors\n");
      (void)printf("\trandom    - randomly execute a number of [de] allocs\n");
      
      (void)printf("\tquit      - quit this test program\n");
      continue;
    }
    
    if (strncmp(line, "quit", len) == 0) {
      break;
    }
    
    if (strncmp(line, "malloc", len) == 0) {
      int	size;
      
      (void)printf("How much to malloc: ");
      if (fgets(line, sizeof(line), stdin) == NULL) {
	break;
      }
      size = atoi(line);
      pnt = mpool_alloc(pool, size, &ret);
      if (pnt == NULL) {
	(void)printf("malloc(%d) failed: %s\n", size, mpool_strerror(ret));
      }
      else {
	(void)printf("malloc(%d) returned '%#lx'\n", size, (long)pnt);
      }
      continue;
    }
    
    if (strncmp(line, "calloc", len) == 0) {
      int	size;
      
      (void)printf("How much to calloc: ");
      if (fgets(line, sizeof(line), stdin) == NULL) {
	break;
      }
      size = atoi(line);
      pnt = mpool_calloc(pool, size, sizeof(char), &ret);
      if (pnt == NULL) {
	(void)printf("calloc(%d) failed: %s\n", size, mpool_strerror(ret));
      }
      else {
	(void)printf("calloc(%d) returned '%#lx'\n", size, (long)pnt);
      }
      continue;
    }
    
    if (strncmp(line, "resize", len) == 0) {
      int	size, old_size;
      
      pnt = get_address();
      
      (void)printf("Old size of allocation: ");
      if (fgets(line, sizeof(line), stdin) == NULL) {
	break;
      }
      old_size = atoi(line);
      (void)printf("New size of allocation: ");
      if (fgets(line, sizeof(line), stdin) == NULL) {
	break;
      }
      size = atoi(line);
      
      new_pnt = mpool_resize(pool, pnt, size, &ret);
      if (new_pnt == NULL) {
	(void)printf("resize(%#lx, %d) failed: %s\n",
		     (long)pnt, size, mpool_strerror(ret));
      }
      else {
	(void)printf("resize(%#lx, %d) returned '%#lx'\n",
		     (long)pnt, size, (long)new_pnt);
      }
      continue;
    }
    
    if (strncmp(line, "free", len) == 0) {
      int	old_size;
      
      pnt = get_address();
      
      (void)printf("Old minimum size we are freeing: ");
      if (fgets(line, sizeof(line), stdin) == NULL) {
	break;
      }
      old_size = atoi(line);
      ret = mpool_free(pool, pnt);
      if (ret != MPOOL_ERROR_NONE) {
	(void)fprintf(stderr, "free failed: %s\n", mpool_strerror(ret));
      }
      continue;
    }
    
    if (strncmp(line, "clear", len) == 0) {
      ret = mpool_clear(pool);
      if (ret == MPOOL_ERROR_NONE) {
	(void)fprintf(stderr, "clear succeeded\n");
      }
      else {
	(void)fprintf(stderr, "clear failed: %s\n", mpool_strerror(ret));
      }
      continue;
    }
    
    if (strncmp(line, "overwrite", len) == 0) {
      char	*overwrite = "OVERWRITTEN";
      
      pnt = get_address();
      memcpy((char *)pnt, overwrite, strlen(overwrite));
      (void)printf("Done.\n");
      continue;
    }
    
    /* do random heap hits */
    if (strncmp(line, "random", len) == 0) {
      int	iter_n;
      
      (void)printf("How many iterations[%d]: ", default_iter_n);
      if (fgets(line, sizeof(line), stdin) == NULL) {
	break;
      }
      if (line[0] == '\0' || line[0] == '\n') {
	iter_n = default_iter_n;
      }
      else {
	iter_n = atoi(line);
      }
      
      do_random(pool, iter_n);
      continue;
    }
    
    (void)printf("Unknown command '%s'.  Type 'help' for assistance.\n", line);
  }
}

/*
 * static void log_func
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
static	void	log_func(const void *mp_p, const int func_id,
			 const unsigned long byte_size,
			 const unsigned long ele_n,
			 const void *new_addr, const void *old_addr,
			 const unsigned long old_byte_size)
{
  (void)printf("mp %#lx ", (long)mp_p);
  
  switch (func_id) {
    
  case MPOOL_FUNC_CLOSE:
    (void)printf("close\n");
    break;
    
  case MPOOL_FUNC_CLEAR:
    (void)printf("clear\n");
    break;
    
  case MPOOL_FUNC_ALLOC:
    (void)printf("alloc %lu bytes got %#lx\n",
		 byte_size, (long)new_addr);
    break;
    
  case MPOOL_FUNC_CALLOC:
    (void)printf("calloc %lu ele size, %lu ele number, got %#lx\n",
		 byte_size, ele_n, (long)new_addr);
    break;
    
  case MPOOL_FUNC_FREE:
    (void)printf("free %#lx of %lu bytes\n", (long)old_addr, byte_size);
    break;
    
  case MPOOL_FUNC_RESIZE:
    (void)printf("resize %#lx of %lu bytes to %lu bytes, got %#lx\n",
		 (long)old_addr, old_byte_size, byte_size,
		 (long)new_addr);
    break;
    
  default:
    (void)printf("unknown function %d, %lu bytes\n", func_id, byte_size);
    break;
  }
}

/*
 * static void usage
 *
 * DESCRIPTION:
 *
 * Print a usage message.
 *
 * RETURNS:
 *
 * None.
 *
 * ARGUMENTS:
 *
 * None.
 */
static	void	usage(void)
{
  (void)fprintf(stderr,
		"Usage: mpool_t [-bhHilMnsv] [-m size] [-p number] "
		"[-P size] [-S seed] [-t times]\n");
  (void)fprintf(stderr,
		"  -b              set MPOOL_FLAG_BEST_FIT\n"
		"  -h              set MPOOL_FLAG_NO_FREE\n"
		"  -H              use system heap not mpool\n"
		"  -i              turn on interactive mode\n"
		"  -l              log memory transactions\n"
		"  -M              max number pages in mpool\n"
		"  -n              set MPOOL_FLAG_NO_FREE\n"
		"  -s              use sbrk instead of mmap\n"
		"  -v              enable verbose messages\n"
		"  -m size         maximum allocation to test\n"
		"  -p max-pnts     number of pointers to test\n"
		"  -S seed-rand    seed for random function\n"
		"  -t interations  number of iterations to run\n");
  exit(1);      
}

/*
 * static void process_args
 *
 * DESCRIPTION:
 *
 * Process our arguments.
 *
 * RETURNS:
 *
 * None.
 *
 * ARGUMENTS:
 *
 * None.
 */
static	void	process_args(int argc, char ** argv)
{
  argc--, argv++;
  
  /* process the args */
  for (; *argv != NULL; argv++, argc--) {
    if (**argv != '-') {
      continue;
    }
    
    switch (*(*argv + 1)) {
      
    case 'b':
      best_fit_b = 1;
      break;
    case 'h':
      heavy_pack_b = 1;
      break;
    case 'H':
      use_malloc_b = 1;
      break;
    case 'i':
      interactive_b = 1;
      break;
    case 'l':
      log_trxn_b = 1;
      break;
    case 'm':
      argv++, argc--;
      if (argc <= 0) {
	usage();
      }
      max_alloc = atoi(*argv);
      break;
    case 'M':
      max_pages_n = 1;
      break;
    case 'n':
      no_free_b = 1;
      break;
    case 'p':
      argv++, argc--;
      if (argc <= 0) {
	usage();
      }
      max_pointers = atoi(*argv);
      break;
    case 'P':
      argv++, argc--;
      if (argc <= 0) {
	usage();
      }
      page_size = atoi(*argv);
      break;
    case 'S':
      argv++, argc--;
      if (argc <= 0) {
	usage();
      }
      seed_random = atoi(*argv);
      break;
    case 't':
      argv++, argc--;
      if (argc <= 0) {
	usage();
      }
      default_iter_n = atoi(*argv);
      break;
    case 'v':
      verbose_b = 1;
      break;
    default:
      usage();
      break;
    }
  }
}

/*
 * Main routine
 */
int	main(int argc, char **argv)
{
  int		ret;
  unsigned int	flags = 0, pool_page_size;
  unsigned long	num_alloced, user_alloced, max_alloced, tot_alloced;
  mpool_t	*pool;
  
  process_args(argc, argv);
  
  /* repeat until we get a non 0 seed */
  while (seed_random == 0) {
    seed_random = time(0) ^ getpid();
  }
  (void)srandom(seed_random);
  
  (void)printf("Random seed is %u\n", seed_random);
  
  if (best_fit_b) {
    flags |= MPOOL_FLAG_BEST_FIT;
  }
  if (heavy_pack_b) {
    flags |= MPOOL_FLAG_HEAVY_PACKING;
  }
  if (no_free_b) {
    flags |= MPOOL_FLAG_NO_FREE;
  }
  if (use_sbrk_b) {
    flags |= MPOOL_FLAG_USE_SBRK;
  }
  
  /* open our memory pool */
  pool = mpool_open(flags, page_size, NULL, &ret);
  if (pool == NULL) {
    (void)fprintf(stderr, "Error in mpool_open: %s\n", mpool_strerror(ret));
    exit(1);
  }
  
  /* are we logging transactions */
  if (log_trxn_b) {
    ret = mpool_set_log_func(pool, log_func);
    if (ret != MPOOL_ERROR_NONE) {
      (void)fprintf(stderr, "Error in mpool_set_log_func: %s\n",
		    mpool_strerror(ret));
    }
  }
  
  if (max_pages_n > 0) {
    ret = mpool_set_max_pages(pool, max_pages_n);
    if (ret != MPOOL_ERROR_NONE) {
      (void)fprintf(stderr, "Error in mpool_set_max_pages: %s\n",
		    mpool_strerror(ret));
    }
  }
  
  if (interactive_b) {
    do_interactive(pool);
  }
  else {
    (void)printf("Running %d tests (use -i for interactive)...\n",
		 default_iter_n);
    (void)fflush(stdout);
    
    do_random(pool, default_iter_n);
  }
  
  /* get stats from the pool */
  ret = mpool_stats(pool, &pool_page_size, &num_alloced, &user_alloced,
		    &max_alloced, &tot_alloced);
  if (ret == MPOOL_ERROR_NONE) {
    (void)printf("Pool page size = %d.  Number active allocated = %lu\n",
		 pool_page_size, num_alloced);
    (void)printf("User bytes allocated = %lu.  Max space allocated = %lu\n",
		 user_alloced, max_alloced);
    (void)printf("Total space allocated = %lu\n", tot_alloced);
  }
  else {
    (void)fprintf(stderr, "Error in mpool_stats: %s\n", mpool_strerror(ret));
  }
  
  /* close the pool */
  ret = mpool_close(pool);
  if (ret != MPOOL_ERROR_NONE) {
    (void)fprintf(stderr, "Error in mpool_close: %s\n", mpool_strerror(ret));
    exit(1);
  }
  
  exit(0);
}

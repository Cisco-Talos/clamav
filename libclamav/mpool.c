/*
 *  Copyright (C) 2008 Sourcefire, Inc.
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

/* a naive pool allocator */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#ifdef USE_MPOOL

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#endif
#include <sys/mman.h>
#include <stddef.h>

#include "others.h"
#include "str.h"
#include "readdb.h"

#ifdef CL_DEBUG
#include <assert.h>
#define MPOOLMAGIC 0x5adeada5
#define ALLOCPOISON 0x5a
#define FREEPOISON 0xde
#endif

/* #define DEBUGMPOOL */
/* #define EXIT_ON_FLUSH */
#ifdef DEBUGMPOOL
#define spam(...) cli_warnmsg( __VA_ARGS__)
#else
static inline void spam(const char *fmt, ...) { fmt = fmt; } /* gcc STFU */
#endif

#include "mpool.h"

#define MIN_FRAGSIZE 262144

#if SIZEOF_VOID_P==8
static const unsigned int fragsz[] = {
/* SIZE        PERM    TEMP    ACT! */
     16, /*    7631    7189 USE/POW2 */
     24, /*   81785     114      USE */
     32, /* 1099428      78 USE/POW2 */
     40, /*   22466      69      USE */
     48, /*    7438      37      USE */
     56, /*    5567      32      USE */
     64, /*    2801      31 USE/POW2 */
     72, /*  610137      29      USE */
     80, /*    3579      28      USE */
     88, /*    2603      28      USE */
     96, /*    3535      27      USE */
    104, /*    3669      24      USE */
    112, /*    3897      23      USE */
    120, /*    5105      22      USE */
    128, /*    3097      22 USE/POW2 */
    136, /*    3977      21      USE */
    144, /*   32225      21      USE */
    152, /*   12384      20      USE */
    160, /*   17258      20      USE */
    176, /*     504      20      USE */
    192, /*     324      20      USE */
    216, /*     363      20      USE */
    240, /*     478      19      USE */
    256, /*     516      19 USE/POW2 */
    288, /*     249      19      USE */
    312, /*     741      18      USE */
    336, /*      47      18      USE */
    512, /*       1      18     POW2 */
   1024, /*       0      17     POW2 */
   2048, /*       0      16     POW2 */
   2056, /*   11408      16      USE */
   4096, /*       0      16     POW2 */
   8192, /*       0      14     POW2 */
   8736, /*       1      12      USE */
  10240, /*       1      11      USE */
  16384, /*       0       8     POW2 */
  20536, /*       1       7      USE */
  33704, /*       1       6      USE */
  37312, /*       1       5      USE */
  43800, /*       1       3      USE */
  63504, /*       9       3      USE */
  65536, /*       0       3     POW2 */
  89800, /*       1       2      USE */
 102624, /*       1       1      USE */
 131072, /*       0       1     POW2 */
 147296, /*       1       1      USE */
 262144, /*       0       1     POW2 */
 369280, /*       1       0      USE */
 507976, /*       9       0      USE */
 525976, /*       1       0      USE */
1048576, /*       0       0 USE/POW2 */
 /* MAX_ALLOCATION is 184549376 but that's really not need here */
};

#else

static const unsigned int fragsz[] = {
/* SIZE        PERM    TEMP    ACT! */
      8, /*    1992    7188 USE/POW2 */
     16, /*   49976     172 USE/POW2 */
     24, /*  995096     121      USE */
     32, /*  151077      68 USE/POW2 */
     40, /*   15175      58      USE */
     48, /*    7231      55      USE */
     56, /*  613432      47      USE */
     64, /*    1925      44 USE/POW2 */
     72, /*    3192      42      USE */
     80, /*    2782      40      USE */
     88, /*    3524      40      USE */
     96, /*    3395      40      USE */
    104, /*    3593      40      USE */
    112, /*   31850      40      USE */
    120, /*    5260      38      USE */
    128, /*    3231      38 USE/POW2 */
    136, /*    4785      38      USE */
    144, /*    3000      38      USE */
    152, /*   13384      38      USE */
    160, /*   14915      36      USE */
    168, /*     485      36      USE */
    176, /*     379      36      USE */
    184, /*     322      36      USE */
    192, /*     260      36      USE */
    200, /*     410      36      USE */
    208, /*     388      36      USE */
    216, /*     262      36      USE */
    224, /*     256      36      USE */
    232, /*     475      36      USE */
    248, /*     544      36      USE */
    256, /*     206      36     POW2 */
    264, /*     352      36      USE */
    280, /*     258      36      USE */
    296, /*     283      36      USE */
    304, /*     308      36      USE */
    312, /*     566      36      USE */
    328, /*      53      36      USE */
    376, /*      18      36      USE */
    616, /*       7      34      USE */
   1032, /*   11408      32      USE */
   2048, /*       0      32     POW2 */
   4096, /*       0      28     POW2 */
   5456, /*       1      20      USE */
   8192, /*       0      16     POW2 */
  10272, /*       1      14      USE */
  18656, /*       1      11      USE */
  21904, /*       1       6      USE */
  32768, /*       0       6     POW2 */
  44864, /*       1       4      USE */
  51240, /*       1       2      USE */
  65536, /*       0       2     POW2 */
 131072, /*       0       2     POW2 */
 147288, /*       1       2      USE */
 184624, /*       1       0      USE */
 253992, /*       9       0      USE */
 262144, /*       0       0     POW2 */
 525752, /*       1       0      USE */
1048576, /*       0       0 USE/POW2 */
};
#endif
#define FRAGSBITS (sizeof(fragsz)/sizeof(fragsz[0]))

struct MPMAP {
  struct MPMAP *next;
  unsigned int size;
  unsigned int usize;
};

struct MP {
  unsigned int psize;
  struct FRAG *avail[FRAGSBITS];
  struct MPMAP mpm;
};

struct FRAG {
  union {
    struct FRAG *next;
    unsigned int sbits;
  } u;
#ifdef CL_DEBUG
  unsigned int magic;
#endif
  void *fake;
};
#define FRAG_OVERHEAD (offsetof(struct FRAG, fake))

#define align_to_voidptr(size) (((size) / MAX(sizeof(void *), 8) + ((size) % MAX(sizeof(void *), 8) != 0)) * MAX(sizeof(void *), 8))
#define mpool_roundup(size) (FRAG_OVERHEAD + align_to_voidptr(size))

static unsigned int align_to_pagesize(struct MP *mp, unsigned int size) {
  return (size / mp->psize + (size % mp->psize != 0)) * mp->psize;
}

static unsigned int to_bits(unsigned int size) {
  unsigned int i;
  for(i=0; i<FRAGSBITS; i++)
    if(fragsz[i] >= size) return i;
  return FRAGSBITS;
}
static unsigned int from_bits(unsigned int bits) {
  if (bits >= FRAGSBITS) return 0;
  return fragsz[bits];
}

struct MP *mpool_create() {
  struct MP mp, *mpool_p;
  unsigned int sz;
  memset(&mp, 0, sizeof(mp));
  mp.psize = cli_getpagesize();
  sz = align_to_pagesize(&mp, MIN_FRAGSIZE);
  mp.mpm.usize = align_to_voidptr(sizeof(struct MPMAP));
  mp.mpm.size = sz - align_to_voidptr(sizeof(mp));
  if ((mpool_p = (struct MP *)mmap(NULL, sz, PROT_READ | PROT_WRITE, MAP_PRIVATE|ANONYMOUS_MAP, -1, 0)) == MAP_FAILED)
    return NULL;
#ifdef CL_DEBUG
  memset(mpool_p, ALLOCPOISON, sz);
#endif
  memcpy(mpool_p, &mp, sizeof(mp));
  spam("Map created @%p->%p - size %u out of %u - voidptr=%u\n", mpool_p, (char *)mpool_p + mp.mpm.size, mp.mpm.usize, mp.mpm.size, SIZEOF_VOID_P);
  return mpool_p;
}

void mpool_destroy(struct MP *mp) {
  struct MPMAP *mpm_next = mp->mpm.next, *mpm;
  unsigned int mpmsize;

  while((mpm = mpm_next)) {
    mpmsize = mpm->size;
    mpm_next = mpm->next;
#ifdef CL_DEBUG
    memset(mpm, FREEPOISON, mpmsize);
#endif
    munmap((void *)mpm, mpmsize);
  }
  mpmsize = mp->mpm.size;
#ifdef CL_DEBUG
  memset(mp, FREEPOISON, mpmsize + align_to_voidptr(sizeof(*mp)));
#endif
  munmap((void *)mp, mpmsize + align_to_voidptr(sizeof(*mp)));
  spam("Map destroyed @%p\n", mp);
}

void mpool_flush(struct MP *mp) {
    size_t used = 0, mused;
    struct MPMAP *mpm_next = mp->mpm.next, *mpm;

#ifdef EXIT_ON_FLUSH
    exit(0);
#endif

    while((mpm = mpm_next)) {
	mpm_next = mpm->next;
	mused = align_to_pagesize(mp, mpm->usize);
	if(mused < mpm->size) {
#ifdef CL_DEBUG
	    memset((char *)mpm + mused, FREEPOISON, mpm->size - mused);
#endif
	    munmap((char *)mpm + mused, mpm->size - mused);
	    mpm->size = mused;
	}
	used += mpm->size;
    }

    mused = align_to_pagesize(mp, mp->mpm.usize + align_to_voidptr(sizeof(*mp)));
    if (mused < mp->mpm.size + align_to_voidptr(sizeof(*mp))) {
#ifdef CL_DEBUG
	memset((char *)mp + mused, FREEPOISON, mp->mpm.size + align_to_voidptr(sizeof(*mp)) - mused);
#endif
	munmap((char *)mp + mused, mp->mpm.size + align_to_voidptr(sizeof(*mp)) - mused);
	mp->mpm.size = mused - align_to_voidptr(sizeof(*mp));
    }
    used += mp->mpm.size;
    spam("Map flushed @%p, in use: %lu\n", mp, used);
}

int mpool_getstats(const struct cl_engine *eng, size_t *used, size_t *total)
{
  size_t sum_used = 0, sum_total = 0;
  const struct MPMAP *mpm;
  const mpool_t *mp;
  
  /* checking refcount is not necessary, but safer */
  if (!eng || !eng->refcount)
    return -1;
  mp = eng->mempool;
  if (!mp)
    return -1;
  for(mpm = &mp->mpm; mpm; mpm = mpm->next) {
    sum_used += mpm->usize;
    sum_total += mpm->size;
  }
  *used = sum_used;
  *total = sum_total;
  return 0;
}

void *mpool_malloc(struct MP *mp, size_t size) {
  unsigned int i, needed = align_to_voidptr(size + FRAG_OVERHEAD);
  const unsigned int sbits = to_bits(needed);
  struct FRAG *f = NULL;
  struct MPMAP *mpm = &mp->mpm;

  /*  check_all(mp); */
  if (!size || sbits == FRAGSBITS) {
    cli_errmsg("mpool_malloc(): Attempt to allocate %lu bytes. Please report to http://bugs.clamav.net\n", (unsigned long int) size);
    return NULL;
  }

  /* Case 1: We have a free'd frag */
  if((f = mp->avail[sbits])) {
    spam("malloc @%p size %u (freed)\n", f, align_to_voidptr(size + FRAG_OVERHEAD));
    mp->avail[sbits] = f->u.next;
    f->u.sbits = sbits;
#ifdef CL_DEBUG
      f->magic = MPOOLMAGIC;
      memset(&f->fake, ALLOCPOISON, size);
#endif
    return &f->fake;
  }

  if (!(needed = from_bits(sbits))) {
    cli_errmsg("mpool_malloc(): Attempt to allocate %lu bytes. Please report to http://bugs.clamav.net\n", (unsigned long int) size);
    return NULL;
  }

  /* Case 2: We have nuff room available for this frag already */
  while(mpm) {
    if(mpm->size - mpm->usize >= needed) {
      f = (struct FRAG *)((char *)mpm + mpm->usize);
      spam("malloc @%p size %u (hole)\n", f, align_to_voidptr(size + FRAG_OVERHEAD));
      mpm->usize += needed;
      f->u.sbits = sbits;
#ifdef CL_DEBUG
      f->magic = MPOOLMAGIC;
      memset(&f->fake, ALLOCPOISON, size);
#endif
      return &f->fake;
    }
    mpm = mpm->next;
  }

  /* Case 3: We allocate more */
  if (needed + align_to_voidptr(sizeof(*mpm)) > MIN_FRAGSIZE)
  i = align_to_pagesize(mp, needed + align_to_voidptr(sizeof(*mpm)));
  else
  i = align_to_pagesize(mp, MIN_FRAGSIZE);
  
  if ((mpm = (struct MPMAP *)mmap(NULL, i, PROT_READ | PROT_WRITE, MAP_PRIVATE|ANONYMOUS_MAP, -1, 0)) == MAP_FAILED) {
    cli_errmsg("mpool_malloc(): Can't allocate memory (%lu bytes).\n", (unsigned long int)i);
    spam("failed to alloc %u bytes (%u requested)\n", i, size);
    return NULL;
  }
#ifdef CL_DEBUG
  memset(mpm, ALLOCPOISON, i);
#endif
  mpm->size = i;
  mpm->usize = needed + align_to_voidptr(sizeof(*mpm));
  mpm->next = mp->mpm.next;
  mp->mpm.next = mpm;
  f = (struct FRAG *)((char *)mpm + align_to_voidptr(sizeof(*mpm)));
  spam("malloc @%p size %u (new map)\n", f, align_to_voidptr(size + FRAG_OVERHEAD));
  f->u.sbits = sbits;
#ifdef CL_DEBUG
  f->magic = MPOOLMAGIC;
#endif
  return &f->fake;
}

void mpool_free(struct MP *mp, void *ptr) {
  struct FRAG *f = (struct FRAG *)((char *)ptr - FRAG_OVERHEAD);
  unsigned int sbits;
  if (!ptr) return;

#ifdef CL_DEBUG
  assert(f->magic == MPOOLMAGIC && "Attempt to mpool_free a pointer we did not allocate!");
  memset(ptr, FREEPOISON, from_bits(f->u.sbits) - FRAG_OVERHEAD);
#endif

  sbits = f->u.sbits;
  f->u.next = mp->avail[sbits];
  mp->avail[sbits] = f;
  spam("free @%p\n", f);
}

void *mpool_calloc(struct MP *mp, size_t nmemb, size_t size) {
  unsigned int needed = nmemb*size;
  void *ptr;

  if(!needed) return NULL;
  if((ptr = mpool_malloc(mp, needed)))
    memset(ptr, 0, needed);
  return ptr;
}

void *mpool_realloc(struct MP *mp, void *ptr, size_t size) {
  struct FRAG *f = (struct FRAG *)((char *)ptr - FRAG_OVERHEAD);
  unsigned int csize;
  void *new_ptr;
  if (!ptr) return mpool_malloc(mp, size);

  if(!size || !(csize = from_bits(f->u.sbits))) {
    cli_errmsg("mpool_realloc(): Attempt to allocate %lu bytes. Please report to http://bugs.clamav.net\n", (unsigned long int) size);
    return NULL;
  }
  csize -= FRAG_OVERHEAD;
  if (csize >= size && (!f->u.sbits || from_bits(f->u.sbits-1)-FRAG_OVERHEAD < size)) {
    spam("free @%p\n", f);
    spam("malloc @%p size %u (self)\n", f, align_to_voidptr(size + FRAG_OVERHEAD));
    return ptr;
  }
  if (!(new_ptr = mpool_malloc(mp, size)))
    return NULL;
  memcpy(new_ptr, ptr, csize <= size ? csize : size);
  mpool_free(mp, ptr);
  return new_ptr;
}

void *mpool_realloc2(struct MP *mp, void *ptr, size_t size) {
    void *new_ptr = mpool_realloc(mp, ptr, size);
    if(new_ptr)
	return new_ptr;
    mpool_free(mp, ptr);
    return NULL;
}

unsigned char *cli_mpool_hex2str(mpool_t *mp, const unsigned char *hex) {
    unsigned char *str;
    size_t len = strlen((const char*)hex);

    if (len&1) {
	cli_errmsg("cli_hex2str(): Malformed hexstring: %s (length: %u)\n", hex, (unsigned)len);
	return NULL;
    }

    str = mpool_malloc(mp, (len/2) + 1);
    if (cli_hex2str_to(hex, str, len) == -1) {
	mpool_free(mp, str);
	return NULL;
    }
    str[len/2] = '\0';
    return str;
}

char *cli_mpool_strdup(mpool_t *mp, const char *s) {
  char *alloc;
  unsigned int strsz;

  if(s == NULL) {
    cli_errmsg("cli_mpool_strdup(): s == NULL. Please report to http://bugs.clamav.net\n");
    return NULL;
  }

  strsz = strlen(s) + 1;
  alloc = mpool_malloc(mp, strsz);
  if(!alloc)
    cli_errmsg("cli_mpool_strdup(): Can't allocate memory (%u bytes).\n", (unsigned int) strsz);
  else
    memcpy(alloc, s, strsz);
  return alloc;
}

char *cli_mpool_virname(mpool_t *mp, const char *virname, unsigned int official) {
  char *newname, *pt;
  if(!virname)
    return NULL;

  if((pt = strchr(virname, ' ')))
      if((pt = strstr(pt, " (Clam)")))
	  *pt='\0';

  if(!virname[0]) {
    cli_errmsg("cli_virname: Empty virus name\n");
    return NULL;
  }

  if(official)
    return cli_mpool_strdup(mp, virname);

  newname = (char *)mpool_malloc(mp, strlen(virname) + 11 + 1);
  if(!newname) {
    cli_errmsg("cli_virname: Can't allocate memory for newname\n");
    return NULL;
  }
  sprintf(newname, "%s.UNOFFICIAL", virname);
  return newname;
}


uint16_t *cli_mpool_hex2ui(mpool_t *mp, const char *hex) {
  uint16_t *str;
  unsigned int len;
  
  len = strlen(hex);

  if(len % 2 != 0) {
    cli_errmsg("cli_hex2si(): Malformed hexstring: %s (length: %u)\n", hex, len);
    return NULL;
  }

  str = mpool_calloc(mp, (len / 2) + 1, sizeof(uint16_t));
  if(!str)
    return NULL;

  if(cli_realhex2ui(hex, str, len))
    return str;
    
  mpool_free(mp, str);
  return NULL;
}


#ifdef DEBUGMPOOL
void mpool_stats(struct MP *mp) {
  unsigned int i=0, ta=0, tu=0;
  struct MPMAP *mpm = &mp->mpm;

  cli_warnmsg("MEMORY POOL STATISTICS\n map  \tsize\tused\t%\n");
  while(mpm) {
    cli_warnmsg("- %u\t%u\t%u\t%f%%\n", i, mpm->size, mpm->usize, (float)mpm->usize/(float)mpm->size*100);
    ta+=mpm->size;
    tu+=mpm->usize;
    i++;
    mpm = mpm->next;
  }
  cli_warnmsg("MEMORY POOL SUMMARY\nMaps: %u\nTotal: %u\nUsed: %u (%f%%)\n", i, ta, tu, (float)tu/(float)ta*100);
}

void check_all(struct MP *mp) {
  struct MPMAP *mpm = &mp->mpm;
  while(mpm) {
    volatile unsigned char *c = (unsigned char *)mpm;
    unsigned int len = mpm->size;
    spam("checking object %p - size %u\n", mpm, len);
    while (len--) {
      c[len];
    }
    mpm=mpm->next;
  }
}
#endif /* DEBUGMPOOL */


#else
/* dummy definitions to make Solaris linker happy.
 * these symbols are declared in libclamav.map */
void mpool_free() {}
void mpool_create() {}
void mpool_destroy() {}
void mpool_getstats() {}

#endif /* USE_MPOOL */


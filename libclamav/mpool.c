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
#if defined(HAVE_MMAP) && defined(HAVE_SYS_MMAN_H)
#include <sys/mman.h>
#endif
#include <stddef.h>

#include "others.h"
#include "str.h"
#include "readdb.h"

/*#define CL_DEBUG*/
#ifdef CL_DEBUG
#include <assert.h>
#define MPOOLMAGIC 0xadde
#define ALLOCPOISON 0x5a
#define FREEPOISON 0xde
#endif

/*#define DEBUGMPOOL
#define EXIT_ON_FLUSH*/
#ifdef DEBUGMPOOL
#define spam(...) cli_warnmsg( __VA_ARGS__)
#else
static inline void spam(const char *fmt, ...) { fmt = fmt; } /* gcc STFU */
#endif

#include "mpool.h"

#undef CL_DEBUG /* bb#2222 */

#define MIN_FRAGSIZE 262144

#if SIZEOF_VOID_P==8
static const unsigned int fragsz[] = {
/* SIZE,      MAX   */
      8, /*  783293 */
     11, /*    4445 */
     13, /*   10160 */
     15, /*    8365 */
     16, /*   24857 */
     17, /*   24630 */
     19, /*  136608 */
     20, /*   90714 */
     21, /*  176421 */
     23, /*   52766 */
     24, /*  161770 */
     25, /*   38590 */
     29, /*   18023 */
     31, /*   15987 */
     32, /*  104854 */
     33, /*    9312 */
     35, /*  371084 */
     41, /*    5068 */
     43, /*  142581 */
     44, /*   99347 */
     45, /*   74173 */
     47, /*   31516 */
     48, /*  320748 */
     49, /*   45256 */
     56, /*    1543 */
     64, /*     963 */
     74, /*   12397 */
     76, /*   17846 */
     79, /*   15721 */
     80, /*  599771 */
     81, /*    5618 */
     93, /*    2101 */
     97, /*    2425 */
    104, /*    1495 */
    113, /*    3107 */
    116, /*    2403 */
    123, /*    1415 */
    128, /*    2368 */
    131, /*    2697 */
    143, /*   10539 */
    150, /*   10982 */
    151, /*    6869 */
    152, /*   28254 */
    153, /*   13670 */
    229, /*     501 */
    256, /*     830 */
    304, /*     834 */
    320, /*     377 */
    512, /*      17 */
   1024, /*       6 */
   2048, /*       3 */
   2056, /*   10116 */
   4096, /*       3 */
   8192, /*       2 */
   9334, /*       3 */
  12163, /*       4 */
  16392, /*     257 */
  18440, /*       2 */
  21952, /*       1 */
  32768, /*       1 */
  35311, /*       1 */
  43256, /*       2 */
  48914, /*       1 */
  63504, /*       8 */
  65536, /*       0 */
  92794, /*       1 */
 107602, /*       1 */
 131832, /*       7 */
 156920, /*       1 */
 262144, /*       1 */
 374608, /*       1 */
 507976, /*      10 */
 524288, /*       0 */
1048576,
2097152,
4194304,
8388608,
 /* MAX_ALLOCATION is 184549376 but that's really not need here */
};

#else

static const unsigned int fragsz[] = {
/* SIZE,        MAX */
      4, /*  576046 */
      7, /*  205452 */
      8, /*    2448 */
      9, /*    1633 */
     11, /*    2740 */
     12, /*    6315 */
     13, /*    8821 */
     15, /*   15903 */
     16, /*   31401 */
     17, /*   28027 */
     19, /*  136365 */
     20, /*   95662 */
     21, /*  176094 */
     23, /*   54138 */
     24, /*  156993 */
     25, /*   39393 */
     28, /*   16340 */
     29, /*    9807 */
     30, /*    5132 */
     31, /*  176283 */
     32, /*  484214 */
     33, /*  129187 */
     37, /*    1163 */
     40, /*    3311 */
     41, /*    1513 */
     48, /*    3930 */
     49, /*    1018 */
     56, /*    2303 */
     58, /*   13518 */
     59, /*    4709 */
     60, /*   13577 */
     61, /*    3093 */
     62, /*   10407 */
     63, /*    3973 */
     64, /*   26914 */
     65, /*    2963 */
     73, /*    2314 */
     81, /*    2038 */
     85, /*    1306 */
     88, /*    1395 */
     93, /*     885 */
     96, /*     878 */
    104, /*    3746 */
    108, /*     685 */
    113, /*    2940 */
    115, /*    3625 */
    116, /*    3827 */
    117, /*    2517 */
    119, /*    4260 */
    120, /*   17485 */
    121, /*    1945 */
    128, /*    2653 */
    131, /*    2304 */
    136, /*    1090 */
    143, /*   10787 */
    148, /*    1292 */
    152, /*    3494 */
    153, /*   11788 */
    168, /*     505 */
    176, /*     652 */
    200, /*     350 */
    216, /*     312 */
    232, /*     402 */
    248, /*     495 */
    256, /*     140 */
    284, /*     439 */
    309, /*     817 */
    452, /*      57 */
    512, /*       3 */
    784, /*      14 */
   1024, /*       2 */
   1028, /*    3191 */
   1032, /*    7777 */
   2048, /*       5 */
   4096, /*       3 */
   5128, /*       5 */
   8192, /*       3 */
  11264, /*       5 */
  11268, /*     238 */
  11272, /*     243 */
  16384, /*       1 */
  17657, /*       1 */
  21632, /*       2 */
  23188, /*       2 */
  24458, /*       1 */
  32768, /*       1 */
  46398, /*       1 */
  53804, /*       1 */
  63504, /*       7 */
  65536, /*       1 */
 131072, /*       0 */
 131080, /*       7 */
 131544, /*       2 */
 156920, /*       1 */
 187304, /*       1 */
 253988, /*      10 */
 262144, /*       0 */
1048576,
2097152,
4194304,
8388608,
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
  union {
      struct MPMAP mpm;
      uint64_t dummy_align;
  } u;
};

/* alignment of fake handled in the code! */
struct alloced {
    uint8_t padding;
    uint8_t sbits;
    uint8_t fake;
};

struct FRAG {
#ifdef CL_DEBUG
  uint16_t magic;
#endif
  union {
      struct alloced a;
      struct unaligned_ptr next;
  } u;
};
#define FRAG_OVERHEAD (offsetof(struct FRAG, u.a.fake))

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

static inline unsigned int alignof(unsigned int size)
{
    /* conservative estimate of alignment.
     * A struct that needs alignment of 'align' is padded by the compiler
     * so that sizeof(struct)%align == 0 
     * (otherwise you wouldn't be able to use it in an array)
     * Also align = 2^n.
     * Largest alignment we need is 8 bytes (ptr/int64), since we don't use long
     * double or __aligned attribute.
     * This conservatively estimates that size 32 needs alignment of 8 (even if it might only
     * need an alignment of 4).
     */
    switch (size%8) {
	case 0:
	    return 8;
	case 2:
	case 6:
	    return 2;
	case 4:
	    return 4;
	default:
	    return 1;
    }
}

static inline size_t alignto(size_t p, size_t size)
{
    /* size is power of 2 */
    return (p+size-1)&(~(size-1));
}

struct MP *mpool_create() {
  struct MP mp, *mpool_p;
  unsigned int sz;
  memset(&mp, 0, sizeof(mp));
  mp.psize = cli_getpagesize();
  sz = align_to_pagesize(&mp, MIN_FRAGSIZE);
  mp.u.mpm.usize = sizeof(struct MPMAP);
  mp.u.mpm.size = sz - sizeof(mp);
#ifndef _WIN32
  if ((mpool_p = (struct MP *)mmap(NULL, sz, PROT_READ | PROT_WRITE, MAP_PRIVATE|ANONYMOUS_MAP, -1, 0)) == MAP_FAILED)
#else
  if(!(mpool_p = (struct MP *)VirtualAlloc(NULL, sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)))
#endif
    return NULL;
  if (FRAGSBITS > 255) {
      cli_errmsg("At most 255 frags possible!\n");
      return NULL;
  }
  if (fragsz[0] < sizeof(void*)) {
      cli_errmsg("fragsz[0] too small!\n");
      return NULL;
  }
#ifdef CL_DEBUG
  memset(mpool_p, ALLOCPOISON, sz);
#endif
  memcpy(mpool_p, &mp, sizeof(mp));
  spam("Map created @%p->%p - size %u out of %u - voidptr=%u\n", mpool_p, (char *)mpool_p + mp.u.mpm.size, mp.u.mpm.usize, mp.u.mpm.size, SIZEOF_VOID_P);
  return mpool_p;
}

void mpool_destroy(struct MP *mp) {
  struct MPMAP *mpm_next = mp->u.mpm.next, *mpm;
  unsigned int mpmsize;

  while((mpm = mpm_next)) {
    mpmsize = mpm->size;
    mpm_next = mpm->next;
#ifdef CL_DEBUG
    memset(mpm, FREEPOISON, mpmsize);
#endif
#ifndef _WIN32
    munmap((void *)mpm, mpmsize);
#else
    VirtualFree(mpm, 0, MEM_RELEASE);
#endif
  }
  mpmsize = mp->u.mpm.size;
#ifdef CL_DEBUG
  memset(mp, FREEPOISON, mpmsize + sizeof(*mp));
#endif
#ifndef _WIN32
  munmap((void *)mp, mpmsize + sizeof(*mp));
#else
  VirtualFree(mp, 0, MEM_RELEASE);
#endif
  spam("Map destroyed @%p\n", mp);
}

void mpool_flush(struct MP *mp) {
    size_t used = 0, mused;
    struct MPMAP *mpm_next = mp->u.mpm.next, *mpm;

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
#ifndef _WIN32
	    munmap((char *)mpm + mused, mpm->size - mused);
#else
	    VirtualFree((char *)mpm + mused, mpm->size - mused, MEM_DECOMMIT);
#endif
	    mpm->size = mused;
	}
	used += mpm->size;
    }

    mused = align_to_pagesize(mp, mp->u.mpm.usize + sizeof(*mp));
    if (mused < mp->u.mpm.size + sizeof(*mp)) {
#ifdef CL_DEBUG
	memset((char *)mp + mused, FREEPOISON, mp->u.mpm.size + sizeof(*mp) - mused);
#endif
#ifndef _WIN32
	munmap((char *)mp + mused, mp->u.mpm.size + sizeof(*mp) - mused);
#else
	VirtualFree((char *)mp + mused, mp->u.mpm.size + sizeof(*mp) - mused, MEM_DECOMMIT);
#endif
	mp->u.mpm.size = mused - sizeof(*mp);
    }
    used += mp->u.mpm.size;
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
  for(mpm = &mp->u.mpm; mpm; mpm = mpm->next) {
    sum_used += mpm->usize;
    sum_total += mpm->size;
  }
  *used = sum_used;
  *total = sum_total;
  return 0;
}

static inline unsigned align_increase(unsigned size, unsigned a)
{
    /* we must pad with at most a-1 bytes to align start of struct */
    return size + a - 1;
}

static void* allocate_aligned(struct MPMAP *mpm, unsigned long size, unsigned align, const char *dbg)
{
    /* We could always align the size to maxalign (8), however that wastes
     * space.
     * So just align the start of each allocation as needed, and then see in
     * which sbits bin we fit into.
     * Since we are no longer allocating in multiple of 8, we must always
     * align the start of each allocation!
     *| end of previous allocation | padding | FRAG_OVERHEAD | ptr_aligned |*/
    unsigned p = mpm->usize + FRAG_OVERHEAD;
    unsigned p_aligned = alignto(p, align);
    struct FRAG *f = (struct FRAG*)((char*)mpm + p_aligned - FRAG_OVERHEAD);
    unsigned realneed = p_aligned + size - mpm->usize;
    unsigned sbits = to_bits(realneed);
    unsigned needed = from_bits(sbits);
#ifdef CL_DEBUG
    assert(p_aligned + size <= mpm->size);
#endif
    f->u.a.sbits = sbits;
    f->u.a.padding = p_aligned - p;

    mpm->usize += needed;
#ifdef CL_DEBUG
    assert(mpm->usize <= mpm->size);
#endif
    spam("malloc @%p size %u (%s) origsize %u overhead %u\n", f, realneed, dbg, size, needed - size);
#ifdef CL_DEBUG
    f->magic = MPOOLMAGIC;
    memset(&f->u.a.fake, ALLOCPOISON, size);
#endif
    return &f->u.a.fake;
}

void *mpool_malloc(struct MP *mp, size_t size) {
  unsigned align = alignof(size);
  unsigned int i, needed = align_increase(size+FRAG_OVERHEAD, align);
  const unsigned int sbits = to_bits(needed);
  struct FRAG *f = NULL;
  struct MPMAP *mpm = &mp->u.mpm;

  /*  check_all(mp); */
  if (!size || sbits == FRAGSBITS) {
    cli_errmsg("mpool_malloc(): Attempt to allocate %lu bytes. Please report to http://bugs.clamav.net\n", (unsigned long int) size);
    return NULL;
  }

  /* Case 1: We have a free'd frag */
  if((f = mp->avail[sbits])) {
    struct FRAG *fold = f;
    mp->avail[sbits] = f->u.next.ptr;
    /* we always have enough space for this, align_increase ensured that */
    f = (struct FRAG*)(alignto((unsigned long)f + FRAG_OVERHEAD, align)-FRAG_OVERHEAD);
    f->u.a.sbits = sbits;
    f->u.a.padding = (char*)f - (char*)fold;
#ifdef CL_DEBUG
    f->magic = MPOOLMAGIC;
    memset(&f->u.a.fake, ALLOCPOISON, size);
#endif
    spam("malloc @%p size %u (freed) origsize %u overhead %u\n", f, f->u.a.padding + FRAG_OVERHEAD + size, size, needed - size);
    return &f->u.a.fake;
  }

  if (!(needed = from_bits(sbits))) {
    cli_errmsg("mpool_malloc(): Attempt to allocate %lu bytes. Please report to http://bugs.clamav.net\n", (unsigned long int) size);
    return NULL;
  }

  /* Case 2: We have nuff room available for this frag already */
  while(mpm) {
    if(mpm->size - mpm->usize >= needed)
	return allocate_aligned(mpm, size, align, "hole");
    mpm = mpm->next;
  }

  /* Case 3: We allocate more */
  if (needed + sizeof(*mpm) > MIN_FRAGSIZE)
  i = align_to_pagesize(mp, needed + sizeof(*mpm));
  else
  i = align_to_pagesize(mp, MIN_FRAGSIZE);

#ifndef _WIN32
  if ((mpm = (struct MPMAP *)mmap(NULL, i, PROT_READ | PROT_WRITE, MAP_PRIVATE|ANONYMOUS_MAP, -1, 0)) == MAP_FAILED) {
#else
  if (!(mpm = (struct MPMAP *)VirtualAlloc(NULL, i, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE))) {
#endif
    cli_errmsg("mpool_malloc(): Can't allocate memory (%lu bytes).\n", (unsigned long int)i);
    spam("failed to alloc %u bytes (%u requested)\n", i, size);
    return NULL;
  }
#ifdef CL_DEBUG
  memset(mpm, ALLOCPOISON, i);
#endif
  mpm->size = i;
  mpm->usize = sizeof(*mpm);
  mpm->next = mp->u.mpm.next;
  mp->u.mpm.next = mpm;
  return allocate_aligned(mpm, size, align, "new map");
}

static void *allocbase_fromfrag(struct FRAG *f)
{
#ifdef CL_DEBUG
    assert(f->u.a.padding < 8);
#endif
    return (char*)f - f->u.a.padding;
}

void mpool_free(struct MP *mp, void *ptr) {
  struct FRAG *f = (struct FRAG *)((char *)ptr - FRAG_OVERHEAD);
  unsigned int sbits;
  if (!ptr) return;

#ifdef CL_DEBUG
  assert(f->magic == MPOOLMAGIC && "Attempt to mpool_free a pointer we did not allocate!");
#endif

  spam("free @%p\n", f);
  sbits = f->u.a.sbits;
  f = allocbase_fromfrag(f);
#ifdef CL_DEBUG
  memset(f, FREEPOISON, from_bits(sbits));
#endif

  f->u.next.ptr = mp->avail[sbits];
  mp->avail[sbits] = f;
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

  if(!size || !(csize = from_bits(f->u.a.sbits))) {
    cli_errmsg("mpool_realloc(): Attempt to allocate %lu bytes. Please report to http://bugs.clamav.net\n", (unsigned long int) size);
    return NULL;
  }
  csize -= FRAG_OVERHEAD + f->u.a.padding;
  if (csize >= size && (!f->u.a.sbits || from_bits(f->u.a.sbits-1)-FRAG_OVERHEAD-f->u.a.padding < size)) {
    spam("free @%p\n", f);
    spam("malloc @%p size %u (self) origsize %u overhead %u\n", f, size + FRAG_OVERHEAD + f->u.a.padding, size, csize-size+FRAG_OVERHEAD+f->u.a.padding);
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

unsigned char *cli_mpool_hex2str(mpool_t *mp, const char *hex) {
    unsigned char *str;
    size_t len = strlen((const char*)hex);

    if (len&1) {
	cli_errmsg("cli_hex2str(): Malformed hexstring: %s (length: %u)\n", hex, (unsigned)len);
	return NULL;
    }

    str = mpool_malloc(mp, (len/2) + 1);
    if (cli_hex2str_to(hex, (char*)str, len) == -1) {
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

/* #define EXPAND_PUA */
char *cli_mpool_virname(mpool_t *mp, const char *virname, unsigned int official) {
  char *newname, *pt;
#ifdef EXPAND_PUA
  char buf[1024];
#endif

  if(!virname)
    return NULL;

  if((pt = strchr(virname, ' ')))
      if((pt = strstr(pt, " (Clam)")))
	  *pt='\0';

  if(!virname[0]) {
    cli_errmsg("cli_virname: Empty virus name\n");
    return NULL;
  }

#ifdef EXPAND_PUA
    if(!strncmp(virname, "PUA.", 4)) {
	snprintf(buf, sizeof(buf), "Possibly-Unwanted-Application(www.clamav.net/support/pua).%s", virname + 4);
	buf[sizeof(buf)-1] = '\0';
	virname = buf;
    }
#endif
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
    cli_errmsg("cli_mpool_hex2ui(): Malformed hexstring: %s (length: %u)\n", hex, len);
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
  struct MPMAP *mpm = &mp->u.mpm;

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
  struct MPMAP *mpm = &mp->u.mpm;
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


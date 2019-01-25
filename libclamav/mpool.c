/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2008-2013 Sourcefire, Inc.
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

#include "clamav.h"
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
static inline void spam(const char *fmt, ...) { UNUSEDPARAM(fmt); }
#endif

#include "mpool.h"

#undef CL_DEBUG /* bb#2222 */

#ifdef C_HPUX
#define MIN_FRAGSIZE 1048576	/* Goes with LDFLAGS=-Wl,+pd,1M */
#else
#define MIN_FRAGSIZE 262144
#endif

#if SIZEOF_VOID_P==8
static const unsigned int fragsz[] = {
    8,
    11,
    13,
    16,
    17,
    19,
    20,
    21,
    22,
    23,
    24,
    25,
    26,
    27,
    28,
    29,
    30,
    31,
    32,
    33,
    37,
    40,
    41,
    48,
    56,
    72,
    74,
    75,
    76,
    78,
    79,
    80,
    81,
    101,
    104,
    109,
    113,
    116,
    120,
    128,
    131,
    143,
    151,
    152,
    153,
    196,
    256,
    360,
    403,
    404,
    432,
    486,
    514,
    548,
    578,
    604,
    633,
    697,
    743,
    784,
    839,
   1176,
   1536,
   1666,
   2056,
   2168,
   2392,
   2985,
   3221,
   3433,
   3753,
   3832,
   4104,
   4280,
   4696,
   4952,
   5256,
   5826,
   6264,
   7176,
   8440,
   9096,
  16392,
  32780,
  50961,
  63504,
  65558,
 101912,
 131088,
 262144,
 507976,
 524296,
1048584,
2097152,
4194304,
8388608,
16777216,
33554432,
67108864,
134217728,
 /* MAX_ALLOCATION is 184549376 but that's really not need here */
 /* ^^ This MAX_ALLOCATION warning for Mac OS should now be fixed */
};

#else

static const unsigned int fragsz[] = {
    4,
    5,
    8,
    9,
    11,
    12,
    13,
    14,
    15,
    16,
    17,
    19,
    20,
    21,
    22,
    23,
    24,
    25,
    26,
    27,
    28,
    29,
    30,
    31,
    32,
    33,
    35,
    36,
    37,
    39,
    40,
    41,
    44,
    48,
    49,
    52,
    53,
    56,
    58,
    59,
    60,
    61,
    62,
    63,
    64,
    65,
    68,
    69,
    72,
    73,
    77,
    80,
    81,
    83,
    85,
    88,
    89,
    93,
    96,
    99,
    101,
    103,
    104,
    105,
    108,
    112,
    113,
    115,
    116,
    117,
    119,
    120,
    121,
    124,
    128,
    129,
    131,
    133,
    136,
    137,
    141,
    143,
    145,
    148,
    151,
    152,
    153,
    160,
    168,
    173,
    176,
    184,
    194,
    200,
    208,
    216,
    224,
    229,
    232,
    241,
    244,
    248,
    256,
    257,
    264,
    274,
    280,
    293,
    296,
    304,
    307,
    312,
    326,
    344,
    354,
    372,
    396,
    403,
    418,
    456,
    485,
    514,
    546,
    581,
    608,
    646,
    693,
    740,
    776,
    805,
    828,
    902,
    964,
    1028,
    1032,
    1136,
    1238,
    1314,
    1420,
    1501,
    1668,
    1720,
    1832,
    1940,
    2048,
    2119,
    2264,
    2584,
    2724,
    2994,
    3336,
    3428,
    3828,
    4104,
    4471,
    4836,
    5044,
    5176,
    5912,
    6227,
    6792,
    7732,
    8192,
    11272,
    12500,
    16384,
    32768,
    63500,
    65536,
    131080,
    253988,
    262148,
    524292,
    1048576,
    2097152,
    4194304,
    8388608,
   16777216,
   33554432,
   67108864,
  134217728,
};
#endif

#define FRAGSBITS (sizeof(fragsz)/sizeof(fragsz[0]))

struct MPMAP {
  struct MPMAP *next;
  size_t size;
  size_t usize;
};

struct MP {
  size_t psize;
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

static size_t align_to_pagesize(struct MP *mp, size_t size) {
  return (size / mp->psize + (size % mp->psize != 0)) * mp->psize;
}

static unsigned int to_bits(size_t size) {
  unsigned int i;
  for(i=0; i<FRAGSBITS; i++)
    if(fragsz[i] >= size) return i;
  return FRAGSBITS;
}

static size_t from_bits(unsigned int bits) {
  if (bits >= FRAGSBITS) return 0;
  return fragsz[bits];
}

static inline unsigned int alignof(size_t size)
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
  size_t sz;
  memset(&mp, 0, sizeof(mp));
  mp.psize = cli_getpagesize();
  sz = align_to_pagesize(&mp, MIN_FRAGSIZE);
  mp.u.mpm.usize = sizeof(struct MPMAP);
  mp.u.mpm.size = sz - sizeof(mp);
  if (FRAGSBITS > 255) {
      cli_errmsg("At most 255 frags possible!\n");
      return NULL;
  }
  if (fragsz[0] < sizeof(void*)) {
      cli_errmsg("fragsz[0] too small!\n");
      return NULL;
  }
#ifndef _WIN32
  if ((mpool_p = (struct MP *)mmap(NULL, sz, PROT_READ | PROT_WRITE, MAP_PRIVATE|ANONYMOUS_MAP, -1, 0)) == MAP_FAILED)
#else
  if(!(mpool_p = (struct MP *)VirtualAlloc(NULL, sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)))
#endif
    return NULL;
#ifdef CL_DEBUG
  memset(mpool_p, ALLOCPOISON, sz);
#endif
  memcpy(mpool_p, &mp, sizeof(mp));
  spam("Map created @%p->%p - size %lu out of %lu - voidptr=%lu\n", mpool_p, (char *)mpool_p + mp.u.mpm.size, (unsigned long)mp.u.mpm.usize, (unsigned long)mp.u.mpm.size, (unsigned long)SIZEOF_VOID_P);
  return mpool_p;
}

void mpool_destroy(struct MP *mp) {
  struct MPMAP *mpm_next = mp->u.mpm.next, *mpm;
  size_t mpmsize;

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
    cli_dbgmsg("pool memory used: %.3f MB\n", used/(1024*1024.0));
    spam("Map flushed @%p, in use: %lu\n", mp, (unsigned long)used);
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

static inline size_t align_increase(size_t size, size_t a)
{
    /* we must pad with at most a-1 bytes to align start of struct */
    return size + a - 1;
}

static void* allocate_aligned(struct MPMAP *mpm, size_t size, unsigned align, const char *dbg)
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
    unsigned int sbits = to_bits(realneed);
    size_t needed = from_bits(sbits);
#ifdef CL_DEBUG
    assert(p_aligned + size <= mpm->size);
#endif
    f->u.a.sbits = sbits;
    f->u.a.padding = p_aligned - p;

    mpm->usize += needed;
#ifdef CL_DEBUG
    assert(mpm->usize <= mpm->size);
#endif
    spam("malloc @%p size %lu (%s) origsize %lu overhead %lu\n", f, (unsigned long)realneed, dbg, (unsigned long)size, (unsigned long)(needed - size));
#ifdef CL_DEBUG
    f->magic = MPOOLMAGIC;
    memset(&f->u.a.fake, ALLOCPOISON, size);
#endif
    return &f->u.a.fake;
}

void *mpool_malloc(struct MP *mp, size_t size) {
  size_t align = alignof(size);
  size_t i, needed = align_increase(size+FRAG_OVERHEAD, align);
  const unsigned int sbits = to_bits(needed);
  struct FRAG *f = NULL;
  struct MPMAP *mpm = &mp->u.mpm;

  /*  check_all(mp); */
  if (!size || sbits == FRAGSBITS) {
    cli_errmsg("mpool_malloc(): Attempt to allocate %lu bytes. Please report to https://bugzilla.clamav.net\n", (unsigned long) size);
    return NULL;
  }

  /* Case 1: We have a free'd frag */
  if((f = mp->avail[sbits])) {
    struct FRAG *fold = f;
    mp->avail[sbits] = f->u.next.ptr;
    /* we always have enough space for this, align_increase ensured that */
#ifdef _WIN64
    f = (struct FRAG*)(alignto((unsigned long long)f + FRAG_OVERHEAD, align)-FRAG_OVERHEAD);
#else
    f = (struct FRAG*)(alignto((unsigned long)f + FRAG_OVERHEAD, align)-FRAG_OVERHEAD);
#endif
    f->u.a.sbits = sbits;
    f->u.a.padding = (char*)f - (char*)fold;
#ifdef CL_DEBUG
    f->magic = MPOOLMAGIC;
    memset(&f->u.a.fake, ALLOCPOISON, size);
#endif
    spam("malloc @%p size %lu (freed) origsize %lu overhead %lu\n", f, (unsigned long)(f->u.a.padding + FRAG_OVERHEAD + size), (unsigned long)size, (unsigned long)(needed - size));
    return &f->u.a.fake;
  }

  if (!(needed = from_bits(sbits))) {
    cli_errmsg("mpool_malloc(): Attempt to allocate %lu bytes. Please report to https://bugzilla.clamav.net\n", (unsigned long) size);
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
    cli_errmsg("mpool_malloc(): Can't allocate memory (%lu bytes).\n", (unsigned long)i);
    spam("failed to alloc %lu bytes (%lu requested)\n", (unsigned long)i, (unsigned long)size);
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
  size_t needed = nmemb*size;
  void *ptr;

  if(!needed) return NULL;
  if((ptr = mpool_malloc(mp, needed)))
    memset(ptr, 0, needed);
  return ptr;
}

void *mpool_realloc(struct MP *mp, void *ptr, size_t size) {
  struct FRAG *f = (struct FRAG *)((char *)ptr - FRAG_OVERHEAD);
  size_t csize;
  void *new_ptr;
  if (!ptr) return mpool_malloc(mp, size);

  if(!size || !(csize = from_bits(f->u.a.sbits))) {
    cli_errmsg("mpool_realloc(): Attempt to allocate %lu bytes. Please report to https://bugzilla.clamav.net\n", (unsigned long) size);
    return NULL;
  }
  csize -= FRAG_OVERHEAD + f->u.a.padding;
  if (csize >= size && (!f->u.a.sbits || from_bits(f->u.a.sbits-1)-FRAG_OVERHEAD-f->u.a.padding < size)) {
    spam("free @%p\n", f);
    spam("malloc @%p size %lu (self) origsize %lu overhead %lu\n", f, (unsigned long)(size + FRAG_OVERHEAD + f->u.a.padding), (unsigned long)size, (unsigned long)(csize-size+FRAG_OVERHEAD+f->u.a.padding));
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

char *cli_mpool_hex2str(mpool_t *mp, const char *hex) {
    char *str;
    size_t len = strlen((const char*)hex);

    if (len&1) {
	cli_errmsg("cli_hex2str(): Malformed hexstring: %s (length: %lu)\n", hex, (unsigned long)len);
	return NULL;
    }

    str = mpool_malloc(mp, (len/2) + 1);
    if (str == NULL) { /* oops, we have a memory pool allocation failure */
	cli_errmsg("cli_mpool_hex2str(): Can't allocate memory (%lu bytes).\n", (unsigned long)(len/2 + 1));
	return NULL;
    }
    if (cli_hex2str_to(hex, str, len) == -1) {
	mpool_free(mp, str);
	return NULL;
    }
    str[len/2] = '\0';
    return str;
}

char *cli_mpool_strdup(mpool_t *mp, const char *s) {
  char *alloc;
  size_t strsz;

  if(s == NULL) {
    cli_errmsg("cli_mpool_strdup(): s == NULL. Please report to https://bugzilla.clamav.net\n");
    return NULL;
  }

  strsz = strlen(s) + 1;
  alloc = mpool_malloc(mp, strsz);
  if(!alloc)
    cli_errmsg("cli_mpool_strdup(): Can't allocate memory (%lu bytes).\n", (unsigned long) strsz);
  else
    memcpy(alloc, s, strsz);
  return alloc;
}

char *cli_mpool_strndup(mpool_t *mp, const char *s, size_t n) {
  char *alloc;
  size_t strsz;

  if(s == NULL) {
    cli_errmsg("cli_mpool_strndup(): s == NULL. Please report to https://bugzilla.clamav.net\n");
    return NULL;
  }

  strsz = cli_strnlen(s, n) + 1;
  alloc = mpool_malloc(mp, strsz);
  if(!alloc)
    cli_errmsg("cli_mpool_strndup(): Can't allocate memory (%lu bytes).\n", (unsigned long) strsz);
  else
    memcpy(alloc, s, strsz-1);
  alloc[strsz-1] = '\0';
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
  size_t len;
  
  len = strlen(hex);

  if(len % 2 != 0) {
    cli_errmsg("cli_mpool_hex2ui(): Malformed hexstring: %s (length: %lu)\n", hex, (unsigned long)len);
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
  size_t i=0, ta=0, tu=0;
  struct MPMAP *mpm = &mp->u.mpm;

  cli_warnmsg("MEMORY POOL STATISTICS\n map  \tsize\tused\t%\n");
  while(mpm) {
    cli_warnmsg("- %lu\t%lu\t%lu\t%f%%\n", (unsigned long)i, (unsigned long)(mpm->size), (unsigned long)(mpm->usize), (float)mpm->usize/(float)mpm->size*100);
    ta+=mpm->size;
    tu+=mpm->usize;
    i++;
    mpm = mpm->next;
  }
  cli_warnmsg("MEMORY POOL SUMMARY\nMaps: %lu\nTotal: %lu\nUsed: %lu (%f%%)\n", (unsigned long)i, (unsigned long)ta, (unsigned long)tu, (float)tu/(float)ta*100);
}

void check_all(struct MP *mp) {
  struct MPMAP *mpm = &mp->u.mpm;
  while(mpm) {
    volatile unsigned char *c = (unsigned char *)mpm;
    size_t len = mpm->size;
    spam("checking object %p - size %lu\n", mpm, (unsigned long)len);
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
void mpool_calloc() {}

#endif /* USE_MPOOL */



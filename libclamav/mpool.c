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
#ifndef CL_DEBUG
#define NDEBUG
#endif
#include <assert.h>

#define MPOOLMAGIC 0x5adeada5
/*#define DEBUGMPOOL /\* DO NOT define *\/ */
#ifdef DEBUGMPOOL
FILE *lfd = NULL;
#define spam(...) cli_warnmsg( __VA_ARGS__)
#else
#define spam
#endif

#include "mpool.h"

/* #define MIN_FRAGSIZE 4096	/\* 1m2.282s *\/ */
/* #define MIN_FRAGSIZE 8192	/\* 0m46.652s *\/ */
/* #define MIN_FRAGSIZE 16384	/\* 0m8.365s *\/ */
/* #define MIN_FRAGSIZE 32768	/\* 0m3.788s *\/ */
/* #define MIN_FRAGSIZE 65536	/\* 0m2.759s *\/ */
/* #define MIN_FRAGSIZE 131072	/\* 0m2.445s *\/ */
#define MIN_FRAGSIZE 262144	/* 0m2.343s */
/* #define MIN_FRAGSIZE 524288	/\* 0m2.387s *\/ */
/* #define MIN_FRAGSIZE 1048576	/\* 0m2.392s *\/ */
/* #define MIN_FRAGSIZE 2097152	/\* 0m2.402s *\/ */

#if SIZEOF_VOID_P==8
static const unsigned int fragsz[] = {
24, /* (33067) */
32, /* (93970) */
40, /* (731473) */
48, /* (35342) */
56, /* (6967) */
64, /* (442053) */
72, /* (2706) */
80, /* (2281) */
88, /* (3658) */
96, /* (2620) */
104, /* (3705) */
112, /* (3722) */
120, /* (4012) */
128, /* (5161) */
136, /* (22458) */
144, /* (4339) */
152, /* (4315) */
160, /* (12195) */
168, /* (18042) */
/* 176, /\* (341) *\/ */
/* 184, /\* (329) *\/ */
192, /* (202) */
/* 200, /\* (238) *\/ */
/* 208, /\* (166) *\/ */
/* 216, /\* (179) *\/ */
224, /* (216) */
/* 232, /\* (189) *\/ */
/* 240, /\* (157) *\/ */
/* 248, /\* (178) *\/ */
256, /* (133) */
/* 264, /\* (157) *\/ */
/* 272, /\* (140) *\/ */
/* 280, /\* (161) *\/ */
/* 288, /\* (125) *\/ */
/* 296, /\* (141) *\/ */
304, /* (100) */
/* 312, /\* (114) *\/ */
/* 320, /\* (70) *\/ */
/* 328, /\* (13) *\/ */
/* 336, /\* (21) *\/ */
/* 344, /\* (21) *\/ */
352, /* (13) */
/* 360, /\* (26) *\/ */
/* 368, /\* (8) *\/ */
/* 376, /\* (14) *\/ */
/* 384, /\* (5) *\/ */
/* 392, /\* (6) *\/ */
/* 400, /\* (4) *\/ */
/* 408, /\* (2) *\/ */
/* 416, /\* (6) *\/ */
424, /* (20) */
/* 432, /\* (4) *\/ */
/* 440, /\* (4) *\/ */
/* 448, /\* (4) *\/ */
/* 464, /\* (2) *\/ */
/* 472, /\* (2) *\/ */
/* 480, /\* (1) *\/ */
/* 496, /\* (1) *\/ */
/* 512, /\* (2) *\/ */
528, /* (15) */
/* 536, /\* (1) *\/ */
/* 544, /\* (2) *\/ */
/* 552, /\* (1) *\/ */
/* 584, /\* (3) *\/ */
/* 600, /\* (1) *\/ */
/* 624, /\* (1) *\/ */
/* 656, /\* (1) *\/ */
/* 784, /\* (2) *\/ */
1040, /* (15) */
/* 2064, /\* (7456) *\/ */
2072, /* (14) */
4112, /* (14) */
8208, /* (9) */
16400, /* (6) */
32784, /* (4) */
63512, /* (7) */
134408, /* (2) */
507984, /* (7) */
1051040, /* (1) */
2097152
/* ^^ This shouldn't be reached but it's a good fall back
 * MAX_ALLOCATION is 184549376 but that's really not need here */
};

#else

static const unsigned int fragsz[] = {
12, /* (2297) */
16, /* (30785) */
20, /* (41460) */
24, /* (69214) */
28, /* (639488) */
32, /* (107920) */
36, /* (454213) */
40, /* (11497) */
44, /* (1688) */
48, /* (5294) */
52, /* (1496) */
56, /* (3738) */
60, /* (1719) */
64, /* (918) */
68, /* (956) */
72, /* (1324) */
76, /* (1905) */
80, /* (1745) */
84, /* (1053) */
88, /* (1566) */
92, /* (2081) */
96, /* (20851) */
100, /* (1882) */
104, /* (1848) */
108, /* (1931) */
112, /* (2079) */
116, /* (1736) */
120, /* (3425) */
124, /* (2115) */
128, /* (1298) */
132, /* (2307) */
136, /* (2033) */
140, /* (2837) */
144, /* (1479) */
148, /* (1607) */
152, /* (10587) */
156, /* (2719) */
160, /* (15311) */
164, /* (196) */
168, /* (145) */
172, /* (211) */
176, /* (140) */
180, /* (116) */
/* 184, /\* (86) *\/ */
188, /* (119) */
192, /* (104) */
/* 196, /\* (99) *\/ */
/* 200, /\* (84) *\/ */
/* 204, /\* (94) *\/ */
/* 208, /\* (86) *\/ */
212, /* (136) */
/* 216, /\* (80) *\/ */
/* 220, /\* (75) *\/ */
/* 224, /\* (97) *\/ */
/* 228, /\* (99) *\/ */
/* 232, /\* (74) *\/ */
236, /* (114) */
/* 240, /\* (64) *\/ */
/* 244, /\* (73) *\/ */
/* 248, /\* (62) *\/ */
/* 252, /\* (71) *\/ */
/* 256, /\* (69) *\/ */
/* 260, /\* (85) *\/ */
/* 264, /\* (71) *\/ */
268, /* (92) */
/* 272, /\* (69) *\/ */
/* 276, /\* (56) *\/ */
/* 280, /\* (69) *\/ */
/* 284, /\* (71) *\/ */
/* 288, /\* (70) *\/ */
/* 292, /\* (62) *\/ */
/* 296, /\* (39) *\/ */
/* 300, /\* (54) *\/ */
/* 304, /\* (43) *\/ */
/* 308, /\* (54) *\/ */
312, /* (30) */
/* 316, /\* (8) *\/ */
/* 320, /\* (5) *\/ */
/* 324, /\* (7) *\/ */
/* 328, /\* (14) *\/ */
/* 332, /\* (13) *\/ */
/* 336, /\* (8) *\/ */
/* 340, /\* (7) *\/ */
/* 344, /\* (6) *\/ */
/* 348, /\* (2) *\/ */
/* 352, /\* (7) *\/ */
/* 356, /\* (18) *\/ */
/* 360, /\* (5) *\/ */
364, /* (12) */
/* 368, /\* (2) *\/ */
/* 372, /\* (4) *\/ */
/* 376, /\* (2) *\/ */
/* 380, /\* (5) *\/ */
/* 384, /\* (1) *\/ */
/* 392, /\* (4) *\/ */
/* 396, /\* (3) *\/ */
/* 404, /\* (4) *\/ */
/* 408, /\* (2) *\/ */
/* 412, /\* (3) *\/ */
/* 416, /\* (2) *\/ */
/* 420, /\* (3) *\/ */
/* 424, /\* (2) *\/ */
428, /* (16) */
/* 432, /\* (4) *\/ */
/* 436, /\* (1) *\/ */
/* 440, /\* (3) *\/ */
/* 452, /\* (1) *\/ */
/* 456, /\* (2) *\/ */
/* 460, /\* (8) *\/ */
/* 468, /\* (1) *\/ */
/* 472, /\* (2) *\/ */
/* 484, /\* (1) *\/ */
/* 492, /\* (4) *\/ */
/* 500, /\* (1) *\/ */
/* 504, /\* (2) *\/ */
/* 508, /\* (1) *\/ */
/* 516, /\* (2) *\/ */
/* 524, /\* (5) *\/ */
532, /* (15) */
/* 536, /\* (3) *\/ */
/* 540, /\* (1) *\/ */
/* 556, /\* (4) *\/ */
/* 576, /\* (3) *\/ */
/* 588, /\* (8) *\/ */
/* 612, /\* (1) *\/ */
/* 616, /\* (1) *\/ */
/* 620, /\* (5) *\/ */
/* 648, /\* (1) *\/ */
/* 652, /\* (1) *\/ */
/* 680, /\* (1) *\/ */
/* 704, /\* (1) *\/ */
/* 716, /\* (1) *\/ */
/* 772, /\* (1) *\/ */
/* 776, /\* (1) *\/ */
1032, /* (7549) */
/* 1044, /\* (14) *\/ */
2076, /* (14) */
4116, /* (9) */
8212, /* (6) */
16404, /* (4) */
63504, /* (7) */
135636, /* (2) */
253992, /* (7) */
1050864, /* (1) */
2097152
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
  struct FRAG *next;
  unsigned int sbits;
#ifdef CL_DEBUG
  unsigned int magic;
#endif
  void *fake;
};
#define FRAG_OVERHEAD (offsetof(struct FRAG, fake))

#define align_to_voidptr(size) (((size) / sizeof(void *) + ((size) % sizeof(void *) != 0)) * sizeof(void *))
#define roundup(size) (FRAG_OVERHEAD + align_to_voidptr(size))

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

struct MP *mp_create() {
  struct MP mp, *mp_p;
  unsigned int sz;
  memset(&mp, 0, sizeof(mp));
  mp.psize = getpagesize();
#ifdef DEBUGMPOOL
  lfd = fopen("mmpool_log", "w");
#endif
  sz = align_to_pagesize(&mp, MIN_FRAGSIZE);
  mp.mpm.usize = align_to_voidptr(sizeof(struct MPMAP));
  mp.mpm.size = sz - align_to_voidptr(sizeof(mp));
  if ((mp_p = (struct MP *)mmap(NULL, sz, PROT_READ | PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)) == MAP_FAILED)
    return NULL;
  memcpy(mp_p, &mp, sizeof(mp));
  spam("Map created @ %p->%p - size %u out of %u\n", mp_p, (void*)mp_p + mp.mpm.size, mp.mpm.usize, mp.mpm.size);
  return mp_p;
}

void mp_destroy(struct MP *mp) {
  struct MPMAP *mpm_next = mp->mpm.next, *mpm;
  while((mpm = mpm_next)) {
    mpm_next = mpm->next;
    munmap((void *)mpm, mpm->size);
  }
  munmap((void *)mp, mp->mpm.size + align_to_voidptr(sizeof(mp)));
  spam("Map destroyed @ %p\n", mp);
}

void mp_flush(struct MP *mp) {
  struct MPMAP *mpm_next = mp->mpm.next, *mpm;
  while((mpm = mpm_next)) {
    mpm_next = mpm->next;
    munmap((void *)mpm + align_to_pagesize(mp, mpm->usize), mpm->size - align_to_pagesize(mp, mpm->usize));
    mpm->size = mpm->usize = align_to_pagesize(mp, mpm->usize);
  }
  munmap(&mp->mpm + align_to_pagesize(mp, mp->mpm.usize + align_to_voidptr(sizeof(mp))), mp->mpm.size - align_to_pagesize(mp, mp->mpm.usize + align_to_voidptr(sizeof(mp))));
  mp->mpm.size = mp->mpm.usize;
  spam("Map flushed @ %p\n", mp);
}

void *mp_malloc(struct MP *mp, size_t size) {
  unsigned int i, j, needed = align_to_voidptr(size + FRAG_OVERHEAD);
  const unsigned int sbits = to_bits(needed);
  struct FRAG *f = NULL;
  struct MPMAP *mpm = &mp->mpm;

  /*  check_all(mp); */
  if (!size || sbits == FRAGSBITS) {
    cli_errmsg("mp_malloc(): Attempt to allocate %lu bytes. Please report to http://bugs.clamav.net\n", (unsigned long int) size);
    return NULL;
  }

  /* Case 1: We have a free'd frag */
  if((f = mp->avail[sbits])) {
    spam("malloc %p size %u (freed)\n", f, roundup(size));
    mp->avail[sbits] = f->next;
    return &f->fake;
  }

  if (!(needed = from_bits(sbits))) {
    cli_errmsg("mp_malloc(): Attempt to allocate %lu bytes. Please report to http://bugs.clamav.net\n", (unsigned long int) size);
    return NULL;
  }

  /* Case 2: We have nuff room available for this frag already */
  while(mpm) {
    if(mpm->size - mpm->usize >= needed) {
      f = (struct FRAG *)((void *)mpm + mpm->usize);
      spam("malloc %p size %u (hole)\n", f, roundup(size));
      mpm->usize += needed;
      f->sbits = sbits;
#ifdef CL_DEBUG
      f->magic = MPOOLMAGIC;
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
    cli_errmsg("mp_malloc(): Can't allocate memory (%lu bytes).\n", (unsigned long int)i);
    spam("failed to alloc %u bytes (%u requested)\n", i, size);
    return NULL;
  }
  mpm->size = i;
  mpm->usize = needed + align_to_voidptr(sizeof(*mpm));
  mpm->next = mp->mpm.next;
  mp->mpm.next = mpm;
  f = (struct FRAG *)((void *)mpm + align_to_voidptr(sizeof(*mpm)));
  spam("malloc %p size %u (new map)\n", f, roundup(size));
  f->sbits = sbits;
#ifdef CL_DEBUG
      f->magic = MPOOLMAGIC;
#endif
  return &f->fake;
}

void mp_free(struct MP *mp, void *ptr) {
  struct FRAG *f = (struct FRAG *)(ptr - FRAG_OVERHEAD);
  if (!ptr) return;

#ifdef CL_DEBUG
  assert(f->magic == MPOOLMAGIC && "Attempt to mp_free a pointer we did not allocate!");
#endif

  f->next = mp->avail[f->sbits];
  mp->avail[f->sbits] = f;
  spam("free @ %p\n", f);
}

void *mp_calloc(struct MP *mp, size_t nmemb, size_t size) {
  unsigned int needed = nmemb*size;
  void *ptr;

  if(!needed) return NULL;
  if((ptr = mp_malloc(mp, needed)))
    memset(ptr, 0, needed);
  return ptr;
}

void *mp_realloc(struct MP *mp, void *ptr, size_t size) {
  struct FRAG *f = (struct FRAG *)(ptr - FRAG_OVERHEAD);
  unsigned int csize;
  void *new_ptr;
  if (!ptr) return mp_malloc(mp, size);

  spam("realloc @ %p (size %u -> %u))\n", f, from_bits(f->sbits), size);
  if(!size || !(csize = from_bits(f->sbits))) {
    cli_errmsg("mp_realloc(): Attempt to allocate %lu bytes. Please report to http://bugs.clamav.net\n", (unsigned long int) size);
    return NULL;
  }
  csize -= FRAG_OVERHEAD;
  if (csize >= size) return ptr;
  if (!(new_ptr = mp_malloc(mp, size)))
    return NULL;
  memcpy(new_ptr, ptr, csize);
  mp_free(mp, ptr);
  return new_ptr;
}

void *mp_realloc2(struct MP *mp, void *ptr, size_t size) {
  struct FRAG *f = (struct FRAG *)(ptr - FRAG_OVERHEAD);
  unsigned int csize;
  void *new_ptr;
  if (!ptr) return mp_malloc(mp, size);

  spam("realloc @ %p (size %u -> %u))\n", f, from_bits(f->sbits), size);
  if(!size || !(csize = from_bits(f->sbits))) {
    cli_errmsg("mp_realloc2(): Attempt to allocate %lu bytes. Please report to http://bugs.clamav.net\n", (unsigned long int) size);
    mp_free(mp, ptr);
    return NULL;
  }
  csize -= FRAG_OVERHEAD;
  if (csize >= size) return ptr;
  if ((new_ptr = mp_malloc(mp, size)))
    memcpy(new_ptr, ptr, csize);
  mp_free(mp, ptr);
  return new_ptr;
}

#ifdef DEBUGMPOOL
void mp_stats(struct MP *mp) {
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

#endif /* USE_MPOOL */

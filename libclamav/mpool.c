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

/* #define DEBUGMPOOL /\* DO NOT define *\/ */
#ifdef DEBUGMPOOL
#define spam(...) cli_warnmsg( __VA_ARGS__)
#else
static inline void spam(const char *fmt, ...) { fmt = fmt; } /* gcc STFU */
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
/* #define MIN_FRAGSIZE 99688128 */

#if SIZEOF_VOID_P==8
static const unsigned int fragsz[] = {
16, /* 34660 */
24, /* 99132 */
32, /* 935424 */
40, /* 20825 */
48, /* 7338 */
56, /* 536414 */
64, /* 2853 */
72, /* 2355 */
80, /* 3701 */
88, /* 2665 */
96, /* 3719 */
104, /* 3739 */
112, /* 4104 */
120, /* 5151 */
128, /* 25576 */
136, /* 4340 */
144, /* 4308 */
152, /* 12219 */
160, /* 18013 */
168, /* 329 */
176, /* 343 */
184, /* 207 */
192, /* 227 */
200, /* 169 */
208, /* 188 */
216, /* 231 */
224, /* 175 */
232, /* 154 */
240, /* 179 */
248, /* 140 */
256, /* 141 */
264, /* 142 */
272, /* 163 */
280, /* 125 */
288, /* 142 */
296, /* 102 */
304, /* 96 */
312, /* 67 */
320, /* 15 */
328, /* 21 */
336, /* 21 */
344, /* 12 */
352, /* 11 */
360, /* 6 */
368, /* 15 */
376, /* 5 */
384, /* 5 */
392, /* 4 */
400, /* 3 */
408, /* 8 */
416, /* 5 */
424, /* 4 */
432, /* 4 */
440, /* 3 */
456, /* 1 */
464, /* 8 */
472, /* 3 */
488, /* 1 */
496, /* 4 */
504, /* 3 */
512, /* 1 */
520, /* 1 */
528, /* 6 */
536, /* 2 */
544, /* 1 */
560, /* 4 */
576, /* 2 */
592, /* 10 */
616, /* 2 */
624, /* 6 */
656, /* 1 */
680, /* 1 */
704, /* 1 */
720, /* 1 */
776, /* 1 */
2056, /* 8545 */
63504, /* 9 */
144760, /* 1 */
507976, /* 9 */
525800, /* 1 */
1051032, /* (0) */
2097152
/* ^^ This shouldn't be reached but it's a good fall back
 * MAX_ALLOCATION is 184549376 but that's really not need here */
};

#else

static const unsigned int fragsz[] = {
8, /* 2268 */
12, /* 32386 */
16, /* 59865 */
20, /* 58019 */
24, /* 789268 */
28, /* 127523 */
32, /* 539890 */
36, /* 11729 */
40, /* 1840 */
44, /* 5492 */
48, /* 1662 */
52, /* 3855 */
56, /* 1781 */
60, /* 990 */
64, /* 984 */
68, /* 1370 */
72, /* 1923 */
76, /* 1778 */
80, /* 1076 */
84, /* 1591 */
88, /* 2084 */
92, /* 23812 */
96, /* 1873 */
100, /* 1863 */
104, /* 1923 */
108, /* 2177 */
112, /* 1724 */
116, /* 3424 */
120, /* 2098 */
124, /* 1308 */
128, /* 2291 */
132, /* 2032 */
136, /* 2825 */
140, /* 1477 */
144, /* 1594 */
148, /* 10617 */
152, /* 2696 */
156, /* 15313 */
160, /* 182 */
164, /* 144 */
168, /* 197 */
172, /* 144 */
176, /* 118 */
180, /* 85 */
184, /* 121 */
188, /* 105 */
192, /* 84 */
196, /* 85 */
200, /* 97 */
204, /* 90 */
208, /* 149 */
212, /* 83 */
216, /* 75 */
220, /* 98 */
224, /* 83 */
228, /* 73 */
232, /* 114 */
236, /* 63 */
240, /* 75 */
244, /* 65 */
248, /* 72 */
252, /* 67 */
256, /* 69 */
260, /* 73 */
264, /* 93 */
268, /* 69 */
272, /* 56 */
276, /* 68 */
280, /* 71 */
284, /* 72 */
288, /* 61 */
292, /* 41 */
296, /* 53 */
300, /* 42 */
304, /* 37 */
308, /* 30 */
312, /* 9 */
316, /* 5 */
320, /* 6 */
324, /* 13 */
328, /* 13 */
332, /* 8 */
336, /* 5 */
340, /* 5 */
344, /* 3 */
348, /* 7 */
352, /* 1 */
356, /* 4 */
360, /* 14 */
364, /* 2 */
368, /* 3 */
372, /* 2 */
376, /* 4 */
388, /* 4 */
392, /* 3 */
400, /* 3 */
404, /* 3 */
408, /* 3 */
412, /* 2 */
416, /* 3 */
420, /* 1 */
428, /* 4 */
432, /* 1 */
436, /* 2 */
452, /* 2 */
456, /* 8 */
464, /* 1 */
468, /* 2 */
480, /* 1 */
488, /* 4 */
496, /* 1 */
500, /* 1 */
504, /* 1 */
512, /* 1 */
520, /* 6 */
532, /* 1 */
536, /* 1 */
552, /* 4 */
572, /* 3 */
584, /* 9 */
588, /* 1 */
608, /* 1 */
612, /* 1 */
616, /* 6 */
644, /* 1 */
648, /* 1 */
676, /* 1 */
700, /* 1 */
712, /* 1 */
768, /* 1 */
772, /* 1 */
1028, /* 8545 */
63500, /* 9 */
144752, /* 1 */
253988, /* 9 */
525628, /* 1 */
1051032, /* (0) */
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

#define align_to_voidptr(size) (((size) / sizeof(void *) + ((size) % sizeof(void *) != 0)) * sizeof(void *))
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
  mp.psize = getpagesize();
  sz = align_to_pagesize(&mp, MIN_FRAGSIZE);
  mp.mpm.usize = align_to_voidptr(sizeof(struct MPMAP));
  mp.mpm.size = sz - align_to_voidptr(sizeof(mp));
  if ((mpool_p = (struct MP *)mmap(NULL, sz, PROT_READ | PROT_WRITE, MAP_PRIVATE|ANONYMOUS_MAP, -1, 0)) == MAP_FAILED)
    return NULL;
#ifdef CL_DEBUG
  memset(mpool_p, ALLOCPOISON, sz);
#endif
  memcpy(mpool_p, &mp, sizeof(mp));
  spam("Map created @ %p->%p - size %u out of %u\n", mpool_p, (char *)mpool_p + mp.mpm.size, mp.mpm.usize, mp.mpm.size);
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
  spam("Map destroyed @ %p\n", mp);
}

void mpool_flush(struct MP *mp) {
  size_t used = 0, mused;
  struct MPMAP *mpm_next = mp->mpm.next, *mpm;

  while((mpm = mpm_next)) {
    mpm_next = mpm->next;
#ifdef CL_DEBUG
    memset((char *)mpm + align_to_pagesize(mp, mpm->usize), FREEPOISON, mpm->size - align_to_pagesize(mp, mpm->usize));
#endif
    munmap((char *)mpm + align_to_pagesize(mp, mpm->usize), mpm->size - align_to_pagesize(mp, mpm->usize));
    mpm->size = align_to_pagesize(mp, mpm->usize);
    used += mpm->size;
  }
  mused = align_to_pagesize(mp, mp->mpm.usize + align_to_voidptr(sizeof(*mp)));
  if (mused < mp->mpm.size) {
#ifdef CL_DEBUG
    memset((char *)&mp->mpm + mused, FREEPOISON, mp->mpm.size - mused);
#endif
    munmap((char *)&mp->mpm + mused, mp->mpm.size - mused);
    mp->mpm.size = mused;
  }
  used += mp->mpm.size;
  spam("Map flushed @ %p, in use: %lu\n", mp, used);
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
    spam("malloc %p size %u (freed)\n", f, mpool_roundup(size));
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
      spam("malloc %p size %u (hole)\n", f, mpool_roundup(size));
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
  spam("malloc %p size %u (new map)\n", f, mpool_roundup(size));
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
  spam("free @ %p\n", f);
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

  spam("realloc @ %p (size %u -> %u))\n", f, from_bits(f->u.sbits), size);
  if(!size || !(csize = from_bits(f->u.sbits))) {
    cli_errmsg("mpool_realloc(): Attempt to allocate %lu bytes. Please report to http://bugs.clamav.net\n", (unsigned long int) size);
    return NULL;
  }
  csize -= FRAG_OVERHEAD;
  if (csize >= size && (!f->u.sbits || from_bits(f->u.sbits-1)-FRAG_OVERHEAD < size))
    return ptr;
  if (!(new_ptr = mpool_malloc(mp, size)))
    return NULL;
  memcpy(new_ptr, ptr, csize <= size ? csize : size);
  mpool_free(mp, ptr);
  return new_ptr;
}

void *mpool_realloc2(struct MP *mp, void *ptr, size_t size) {
  struct FRAG *f = (struct FRAG *)((char *)ptr - FRAG_OVERHEAD);
  unsigned int csize;
  void *new_ptr;

  if (!ptr) return mpool_malloc(mp, size);

  spam("realloc @ %p (size %u -> %u))\n", f, from_bits(f->u.sbits), size);
  if(!size || !(csize = from_bits(f->u.sbits))) {
    cli_errmsg("mpool_realloc2(): Attempt to allocate %lu bytes. Please report to http://bugs.clamav.net\n", (unsigned long int) size);
    mpool_free(mp, ptr);
    return NULL;
  }
  csize -= FRAG_OVERHEAD;
  if (csize >= size && (!f->u.sbits || from_bits(f->u.sbits-1)-FRAG_OVERHEAD < size))
    return ptr;
  if ((new_ptr = mpool_malloc(mp, size)))
    memcpy(new_ptr, ptr, csize);
  mpool_free(mp, ptr);
  return new_ptr;
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


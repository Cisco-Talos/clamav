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
#include <assert.h>

#define MPOOLMAGIC 0x5adeada5
/* #define DEBUGMPOOL /\* DO NOT define *\/ */
#ifdef DEBUGMPOOL
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
/* #define MIN_FRAGSIZE 99688128 */

#if SIZEOF_VOID_P==8
static const unsigned int fragsz[] = {
16, /* (37189) */
24, /* (94629) */
32, /* (756188) */
40, /* (35658) */
48, /* (6989) */
56, /* (454597) */
64, /* (2736) */
72, /* (2298) */
80, /* (3664) */
88, /* (2636) */
96, /* (3715) */
104, /* (3732) */
112, /* (4021) */
120, /* (5165) */
128, /* (22788) */
136, /* (4343) */
144, /* (4321) */
152, /* (12196) */
160, /* (18044) */
/* 168, /\* (344) *\/ */
/* 176, /\* (335) *\/ */
/* 184, /\* (204) *\/ */
192, /* (226) */
/* 200, /\* (185) *\/ */
/* 208, /\* (181) *\/ */
/* 216, /\* (217) *\/ */
224, /* (172) */
/* 232, /\* (175) *\/ */
/* 240, /\* (178) *\/ */
/* 248, /\* (135) *\/ */
256, /* (140) */
/* 264, /\* (158) *\/ */
/* 272, /\* (161) *\/ */
/* 280, /\* (126) *\/ */
/* 288, /\* (141) *\/ */
296, /* (101) */
/* 304, /\* (97) *\/ */
/* 312, /\* (85) *\/ */
/* 320, /\* (14) *\/ */
/* 328, /\* (21) *\/ */
336, /* (21) */
/* 344, /\* (12) *\/ */
/* 352, /\* (10) *\/ */
/* 360, /\* (7) *\/ */
/* 368, /\* (14) *\/ */
376, /* (21) */
/* 384, /\* (6) *\/ */
/* 392, /\* (4) *\/ */
/* 400, /\* (3) *\/ */
/* 408, /\* (6) *\/ */
/* 416, /\* (5) *\/ */
/* 424, /\* (5) *\/ */
/* 432, /\* (4) *\/ */
440, /* (19) */
/* 456, /\* (2) *\/ */
/* 464, /\* (8) *\/ */
/* 472, /\* (3) *\/ */
/* 488, /\* (1) *\/ */
/* 496, /\* (4) *\/ */
/* 504, /\* (3) *\/ */
/* 512, /\* (1) *\/ */
/* 520, /\* (2) *\/ */
/* 528, /\* (6) *\/ */
/* 536, /\* (3) *\/ */
544, /* (16) */
/* 560, /\* (4) *\/ */
/* 576, /\* (3) *\/ */
/* 592, /\* (8) *\/ */
/* 616, /\* (2) *\/ */
/* 624, /\* (5) *\/ */
/* 648, /\* (1) *\/ */
/* 656, /\* (1) *\/ */
/* 680, /\* (1) *\/ */
/* 704, /\* (1) *\/ */
/* 720, /\* (1) *\/ */
/* 776, /\* (2) *\/ */
1056, /* (15) */
2056, /* (7585) */
/* 2064, /\* (14) *\/ */
2088, /* (14) */
4128, /* (14) */
8224, /* (9) */
16416, /* (6) */
32800, /* (4) */
63504, /* (7) */
136352, /* (1) */
507976, /* (7) */
1051032, /* (1) */
2097152
/* ^^ This shouldn't be reached but it's a good fall back
 * MAX_ALLOCATION is 184549376 but that's really not need here */
};

#else

static const unsigned int fragsz[] = {
8, /* (6381) */
12, /* (30903) */
16, /* (41616) */
20, /* (69507) */
24, /* (646497) */
28, /* (108677) */
32, /* (458074) */
36, /* (11537) */
40, /* (1690) */
44, /* (5326) */
48, /* (1505) */
52, /* (3777) */
56, /* (1730) */
60, /* (943) */
64, /* (963) */
68, /* (1345) */
72, /* (1909) */
76, /* (1765) */
80, /* (1060) */
84, /* (1586) */
88, /* (2082) */
92, /* (21009) */
96, /* (1886) */
100, /* (1869) */
104, /* (1936) */
108, /* (2097) */
112, /* (1736) */
116, /* (3442) */
120, /* (2117) */
124, /* (1317) */
128, /* (2307) */
132, /* (2051) */
136, /* (2839) */
140, /* (1497) */
144, /* (1607) */
148, /* (10604) */
152, /* (2719) */
156, /* (15328) */
160, /* (197) */
/* 164, /\* (161) *\/ */
/* 168, /\* (195) *\/ */
172, /* (156) */
/* 176, /\* (132) *\/ */
/* 180, /\* (86) *\/ */
/* 184, /\* (120) *\/ */
188, /* (122) */
/* 192, /\* (84) *\/ */
/* 196, /\* (84) *\/ */
/* 200, /\* (95) *\/ */
/* 204, /\* (86) *\/ */
208, /* (137) */
/* 212, /\* (95) *\/ */
/* 216, /\* (75) *\/ */
/* 220, /\* (97) *\/ */
/* 224, /\* (84) *\/ */
/* 228, /\* (74) *\/ */
232, /* (114) */
/* 236, /\* (79) *\/ */
/* 240, /\* (73) *\/ */
/* 244, /\* (62) *\/ */
/* 248, /\* (71) *\/ */
/* 252, /\* (69) *\/ */
256, /* (70) */
/* 260, /\* (86) *\/ */
/* 264, /\* (92) *\/ */
/* 268, /\* (69) *\/ */
/* 272, /\* (56) *\/ */
/* 276, /\* (70) *\/ */
280, /* (71) */
/* 284, /\* (70) *\/ */
/* 288, /\* (62) *\/ */
/* 292, /\* (54) *\/ */
/* 296, /\* (54) *\/ */
/* 300, /\* (43) *\/ */
/* 304, /\* (39) *\/ */
308, /* (30) */
/* 312, /\* (9) *\/ */
/* 316, /\* (5) *\/ */
/* 320, /\* (7) *\/ */
/* 324, /\* (14) *\/ */
/* 328, /\* (13) *\/ */
332, /* (23) */
/* 336, /\* (6) *\/ */
/* 340, /\* (6) *\/ */
/* 344, /\* (3) *\/ */
/* 348, /\* (7) *\/ */
/* 352, /\* (3) *\/ */
/* 356, /\* (4) *\/ */
/* 360, /\* (12) *\/ */
/* 364, /\* (2) *\/ */
/* 368, /\* (3) *\/ */
372, /* (17) */
/* 376, /\* (5) *\/ */
/* 380, /\* (1) *\/ */
/* 388, /\* (4) *\/ */
/* 392, /\* (3) *\/ */
/* 400, /\* (4) *\/ */
/* 404, /\* (2) *\/ */
/* 408, /\* (3) *\/ */
/* 412, /\* (2) *\/ */
/* 416, /\* (3) *\/ */
/* 420, /\* (2) *\/ */
/* 428, /\* (4) *\/ */
/* 432, /\* (1) *\/ */
436, /* (18) */
/* 452, /\* (2) *\/ */
/* 456, /\* (8) *\/ */
/* 464, /\* (1) *\/ */
/* 468, /\* (2) *\/ */
/* 480, /\* (1) *\/ */
/* 488, /\* (4) *\/ */
/* 496, /\* (1) *\/ */
/* 500, /\* (2) *\/ */
/* 504, /\* (1) *\/ */
/* 512, /\* (2) *\/ */
/* 520, /\* (6) *\/ */
/* 532, /\* (3) *\/ */
/* 536, /\* (1) *\/ */
540, /* (15) */
/* 552, /\* (4) *\/ */
/* 572, /\* (3) *\/ */
/* 584, /\* (7) *\/ */
/* 588, /\* (1) *\/ */
/* 608, /\* (1) *\/ */
/* 612, /\* (1) *\/ */
/* 616, /\* (5) *\/ */
/* 644, /\* (1) *\/ */
/* 648, /\* (1) *\/ */
/* 676, /\* (1) *\/ */
/* 700, /\* (1) *\/ */
/* 712, /\* (1) *\/ */
/* 768, /\* (1) *\/ */
/* 772, /\* (1) *\/ */
1028, /* (7585) */
1032, /* (14) */
2084, /* (14) */
4124, /* (9) */
8220, /* (6) */
16412, /* (4) */
63500, /* (7) */
136348, /* (1) */
253988, /* (7) */
1050860, /* (1) */
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
#define mp_roundup(size) (FRAG_OVERHEAD + align_to_voidptr(size))

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
  sz = align_to_pagesize(&mp, MIN_FRAGSIZE);
  mp.mpm.usize = align_to_voidptr(sizeof(struct MPMAP));
  mp.mpm.size = sz - align_to_voidptr(sizeof(mp));
  if ((mp_p = (struct MP *)mmap(NULL, sz, PROT_READ | PROT_WRITE, MAP_PRIVATE|ANONYMOUS_MAP, -1, 0)) == MAP_FAILED)
    return NULL;
  memcpy(mp_p, &mp, sizeof(mp));
  spam("Map created @ %p->%p - size %u out of %u\n", mp_p, (char *)mp_p + mp.mpm.size, mp.mpm.usize, mp.mpm.size);
  return mp_p;
}

void mp_destroy(struct MP *mp) {
  struct MPMAP *mpm_next = mp->mpm.next, *mpm;
  while((mpm = mpm_next)) {
    mpm_next = mpm->next;
    munmap((void *)mpm, mpm->size);
  }
  munmap((void *)mp, mp->mpm.size + align_to_voidptr(sizeof(*mp)));
  spam("Map destroyed @ %p\n", mp);
}

void mp_flush(struct MP *mp) {
  size_t used = 0, mused;
  struct MPMAP *mpm_next = mp->mpm.next, *mpm;
  while((mpm = mpm_next)) {
    mpm_next = mpm->next;
    munmap((char *)mpm + align_to_pagesize(mp, mpm->usize), mpm->size - align_to_pagesize(mp, mpm->usize));
    mpm->size = align_to_pagesize(mp, mpm->usize);
    used += mpm->size;
  }
  mused = align_to_pagesize(mp, mp->mpm.usize + align_to_voidptr(sizeof(*mp)));
  if (mused < mp->mpm.size) {
	  munmap(&mp->mpm + mused, mp->mpm.size - mused);
	  mp->mpm.size = mused;
  }
  used += mp->mpm.size;
  spam("Map flushed @ %p, in use: %lu\n", mp, used);
}

int mp_getstats(const struct cl_engine *eng, size_t *used, size_t *total)
{
	size_t sum_used = 0, sum_total = 0;
	const struct MPMAP *mpm;
	const mp_t *mp;
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
    spam("malloc %p size %u (freed)\n", f, mp_roundup(size));
    mp->avail[sbits] = f->u.next;
    f->u.sbits = sbits;
#ifdef CL_DEBUG
      f->magic = MPOOLMAGIC;
#endif
    return &f->fake;
  }

  if (!(needed = from_bits(sbits))) {
    cli_errmsg("mp_malloc(): Attempt to allocate %lu bytes. Please report to http://bugs.clamav.net\n", (unsigned long int) size);
    return NULL;
  }

  /* Case 2: We have nuff room available for this frag already */
  while(mpm) {
    if(mpm->size - mpm->usize >= needed) {
      f = (struct FRAG *)((char *)mpm + mpm->usize);
      spam("malloc %p size %u (hole)\n", f, mp_roundup(size));
      mpm->usize += needed;
      f->u.sbits = sbits;
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
  f = (struct FRAG *)((char *)mpm + align_to_voidptr(sizeof(*mpm)));
  spam("malloc %p size %u (new map)\n", f, mp_roundup(size));
  f->u.sbits = sbits;
#ifdef CL_DEBUG
      f->magic = MPOOLMAGIC;
#endif
  return &f->fake;
}

void mp_free(struct MP *mp, void *ptr) {
  struct FRAG *f = (struct FRAG *)((char *)ptr - FRAG_OVERHEAD);
  unsigned int sbits;
  if (!ptr) return;

#ifdef CL_DEBUG
  assert(f->magic == MPOOLMAGIC && "Attempt to mp_free a pointer we did not allocate!");
#endif

  sbits = f->u.sbits;
  f->u.next = mp->avail[sbits];
  mp->avail[sbits] = f;
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
  struct FRAG *f = (struct FRAG *)((char *)ptr - FRAG_OVERHEAD);
  unsigned int csize, sbits;
  void *new_ptr;
  if (!ptr) return mp_malloc(mp, size);

  spam("realloc @ %p (size %u -> %u))\n", f, from_bits(f->u.sbits), size);
  if(!size || !(csize = from_bits(f->u.sbits))) {
    cli_errmsg("mp_realloc(): Attempt to allocate %lu bytes. Please report to http://bugs.clamav.net\n", (unsigned long int) size);
    return NULL;
  }
  csize -= FRAG_OVERHEAD;
  if (csize >= size && (!f->u.sbits || from_bits(f->u.sbits-1)-FRAG_OVERHEAD < size))
    return ptr;
  if (!(new_ptr = mp_malloc(mp, size)))
    return NULL;
  memcpy(new_ptr, ptr, csize);
  mp_free(mp, ptr);
  return new_ptr;
}

void *mp_realloc2(struct MP *mp, void *ptr, size_t size) {
  struct FRAG *f = (struct FRAG *)((char *)ptr - FRAG_OVERHEAD);
  unsigned int csize;
  void *new_ptr;
  if (!ptr) return mp_malloc(mp, size);

  spam("realloc @ %p (size %u -> %u))\n", f, from_bits(f->u.sbits), size);
  if(!size || !(csize = from_bits(f->u.sbits))) {
    cli_errmsg("mp_realloc2(): Attempt to allocate %lu bytes. Please report to http://bugs.clamav.net\n", (unsigned long int) size);
    mp_free(mp, ptr);
    return NULL;
  }
  csize -= FRAG_OVERHEAD;
  if (csize >= size && (!f->u.sbits || from_bits(f->u.sbits-1)-FRAG_OVERHEAD < size))
    return ptr;
  if ((new_ptr = mp_malloc(mp, size)))
    memcpy(new_ptr, ptr, csize);
  mp_free(mp, ptr);
  return new_ptr;
}

unsigned char *cli_mp_hex2str(mp_t *mp, const unsigned char *str)
{
	unsigned char *tmp = cli_hex2str(str);
	if(tmp) {
		unsigned char *res;
		unsigned int tmpsz = strlen(str) / 2 + 1;
		if((res = mp_malloc(mp, tmpsz)))
			memcpy(res, tmp, tmpsz);
		free(tmp);
		return res;
	}
	return NULL;
}

char *cli_mp_strdup(mp_t *mp, const char *s) {
  char *alloc;
  unsigned int strsz;

  if(s == NULL) {
    cli_errmsg("cli_mp_strdup(): s == NULL. Please report to http://bugs.clamav.net\n");
    return NULL;
  }

  strsz = strlen(s) + 1;
  alloc = mp_malloc(mp, strsz);
  if(!alloc)
    cli_errmsg("cli_mp_strdup(): Can't allocate memory (%u bytes).\n", (unsigned int) strsz);
  else
    memcpy(alloc, s, strsz);
  return alloc;
}

char *cli_mp_virname(mp_t *mp, const char *virname, unsigned int official) {
  char *newname, *pt;
  if(!virname)
    return NULL;

  if((pt = strstr(virname, " (Clam)")))
    *pt='\0';

  if(!virname[0]) {
    cli_errmsg("cli_virname: Empty virus name\n");
    return NULL;
  }

  if(official)
    return cli_mp_strdup(mp, virname);

  newname = (char *)mp_malloc(mp, strlen(virname) + 11 + 1);
  if(!newname) {
    cli_errmsg("cli_virname: Can't allocate memory for newname\n");
    return NULL;
  }
  sprintf(newname, "%s.UNOFFICIAL", virname);
  return newname;
}


uint16_t *cli_mp_hex2ui(mp_t *mp, const char *hex) {
  uint16_t *str;
  unsigned int len;
  
  len = strlen(hex);

  if(len % 2 != 0) {
    cli_errmsg("cli_hex2si(): Malformed hexstring: %s (length: %u)\n", hex, len);
    return NULL;
  }

  str = mp_calloc(mp, (len / 2) + 1, sizeof(uint16_t));
  if(!str)
    return NULL;

  if(cli_realhex2ui(hex, str, len))
    return str;
    
  mp_free(mp, str);
  return NULL;
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


#else
/* dummy definitions to make Solaris linker happy.
 * these symbols are declared in libclamav.map */
void mp_free() {}
void mp_create() {}
void mp_destroy() {}
void mp_getstats() {}

#endif /* USE_MPOOL */


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
/* SIZE        PERM    TEMP     MAX    ACT! */
     16, /* 1487281    7051 1487281      USE */
     24, /*   89506     103   89510      USE */
     32, /* 1313968      65 1313969      USE */
     40, /*   23221      43   23222      USE */
     48, /*  800586      87  800588      USE */
     56, /*    5634      32    5634      USE */
     64, /*    2762      31    2762      USE */
     72, /*    2343      29    2343      USE */
     80, /* 1857605      32 1857606      USE */
     88, /*    2619      28    2619      USE */
     96, /*    3556      27    3556      USE */
    104, /*    3670      24    3670      USE */
    112, /*    3998      23    3998      USE */
    120, /*    5100      22    5100      USE */
    128, /*    3092      22    3092      USE */
    136, /*    4075      22    4075      USE */
    144, /*    4412      22    4412      USE */
    152, /*   41875      21   41875      USE */
    160, /*   17264      21   17264      USE */
    176, /*     517      20     517      USE */
    192, /*     332      20     332      USE */
    208, /*     451      20     451      USE */
    216, /*     408      20     408      USE */
    224, /*     276      20     276      USE */
    240, /*     484      19     484      USE */
    256, /*     529      19     529      USE */
    264, /*     219      19     219      USE */
    272, /*     368      19     368      USE */
    280, /*     239      19     239      USE */
    288, /*     252      19     252      USE */
    312, /*     744      19     744      USE */
    352, /*      23      19      23      USE */
    384, /*      11      18      11      USE */
    408, /*      11      18      11      USE */
    512, /*       1      18       2      USE */
    520, /*       3      18       4      USE */
    632, /*       2      18       3      USE */
   1024, /*       0      17       1      USE */
   2048, /*       0      17       1      USE */
   2056, /*   11920      16   11920      USE */
   4096, /*       0      16       1      USE */
   6144, /*       1      15       1      USE */
   8192, /*       0      14       1      USE */
   8816, /*       1      13       1      USE */
   8872, /*       1      12       1      USE */
  11376, /*       1      10       1      USE */
  16384, /*       0       8       1      USE */
  16392, /*     256       8     257      USE */
  21096, /*       1       7       1      USE */
  32768, /*       0       7       1      USE */
  34752, /*       1       6       2      USE */
  44736, /*       1       4       1      USE */
  48384, /*       1       3       1      USE */
  63504, /*       9       3      10      USE */
  65536, /*       0       3       1      USE */
  91624, /*       1       2       1      USE */
 105568, /*       1       1       1      USE */
 131072, /*       0       1       1      USE */
 131088, /*       6       1       7      USE */
 131784, /*       1       1       2      USE */
 154896, /*       1       1       1      USE */
 262144, /*       0       1       1      USE */
 372712, /*       1       0       1      USE */
 507976, /*       9       0       9      USE */
 524288, /*       0       0       0      USE */
1048576,
2097152,
4194304,
8388608,
 /* MAX_ALLOCATION is 184549376 but that's really not need here */
};

#else

static const unsigned int fragsz[] = {
/* SIZE        PERM    TEMP    ACT! */
     16, /* 1487589    7134 1487589      USE */
     24, /*  116448     127  116452      USE */
     32, /* 1287128      95 1287134      USE */
     40, /*   23174      60   23174      USE */
     48, /*  800778      81  800779      USE */
     56, /*    5633      51    5633      USE */
     64, /* 1857039      49 1857040      USE */
     72, /*    2341      44    2341      USE */
     80, /*    3702      43    3702      USE */
     88, /*    2619      41    2619      USE */
     96, /*    3563      40    3563      USE */
    104, /*    3667      40    3667      USE */
    112, /*    3997      40    3997      USE */
    120, /*   34560      40   34560      USE */
    128, /*    3093      38    3093      USE */
    136, /*    3988      38    3988      USE */
    144, /*    4412      38    4412      USE */
    152, /*   12413      38   12413      USE */
    160, /*   17264      38   17264      USE */
    168, /*     397      38     397      USE */
    176, /*     517      38     517      USE */
    184, /*     328      37     328      USE */
    192, /*     332      36     332      USE */
    208, /*     451      36     451      USE */
    216, /*     408      36     408      USE */
    224, /*     276      36     276      USE */
    240, /*     483      36     483      USE */
    248, /*     254      36     254      USE */
    256, /*     529      36     529      USE */
    264, /*     219      36     219      USE */
    272, /*     368      36     368      USE */
    288, /*     252      36     252      USE */
    304, /*     315      36     315      USE */
    312, /*     744      36     744      USE */
    336, /*      51      36      51      USE */
    352, /*      23      36      23      USE */
    368, /*      29      36      29      USE */
    408, /*      11      36      11      USE */
    440, /*      11      34      11      USE */
    512, /*       1      34       1      USE */
    520, /*       3      34       4      USE */
    592, /*      10      34      10      USE */
    632, /*       2      34       3      USE */
    736, /*       1      34       2      USE */
   1024, /*       0      34       1      USE */
   1032, /*   11920      33   11920      USE */
   2048, /*       0      32       2      USE */
   3080, /*       1      30       1      USE */
   4096, /*       0      28       1      USE */
   4416, /*       1      26       1      USE */
   4440, /*       1      25       1      USE */
   5696, /*       1      20       1      USE */
   8192, /*       0      16       1      USE */
  10248, /*       1      16       2      USE */
  11272, /*     256      14     257      USE */
  16384, /*       0      14       1      USE */
  17384, /*       1      12       2      USE */
  22376, /*       1       8       1      USE */
  24200, /*       1       6       1      USE */
  32768, /*       0       6       1      USE */
  45816, /*       1       5       1      USE */
  52792, /*       1       2       1      USE */
  63504, /*       9       2      10      USE */
  65536, /*       0       2       1      USE */
 131072, /*       0       2       1      USE */
 131088, /*       6       2       7      USE */
 131528, /*       1       2       2      USE */
 154896, /*       1       2       1      USE */
 186360, /*       1       1       1      USE */
 253992, /*       9       0       9      USE */
 262144, /*       0       0       0      USE */
 525752,
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

struct FRAG {
#ifdef CL_DEBUG
  unsigned int magic;
#endif
  union {
    struct FRAG *next;
    unsigned int sbits;
    int64_t dummy_align;
    /* needed to align to 64-bit on sparc, since pointers are 32-bit only,
     * yet we need 64-bit alignment for struct containing int64 members */
  } u;
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
  mp.u.mpm.usize = align_to_voidptr(sizeof(struct MPMAP));
  mp.u.mpm.size = sz - align_to_voidptr(sizeof(mp));
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
  memset(mp, FREEPOISON, mpmsize + align_to_voidptr(sizeof(*mp)));
#endif
#ifndef _WIN32
  munmap((void *)mp, mpmsize + align_to_voidptr(sizeof(*mp)));
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

    mused = align_to_pagesize(mp, mp->u.mpm.usize + align_to_voidptr(sizeof(*mp)));
    if (mused < mp->u.mpm.size + align_to_voidptr(sizeof(*mp))) {
#ifdef CL_DEBUG
	memset((char *)mp + mused, FREEPOISON, mp->u.mpm.size + align_to_voidptr(sizeof(*mp)) - mused);
#endif
#ifndef _WIN32
	munmap((char *)mp + mused, mp->u.mpm.size + align_to_voidptr(sizeof(*mp)) - mused);
#else
	VirtualFree((char *)mp + mused, mp->u.mpm.size + align_to_voidptr(sizeof(*mp)) - mused, MEM_DECOMMIT);
#endif
	mp->u.mpm.size = mused - align_to_voidptr(sizeof(*mp));
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

void *mpool_malloc(struct MP *mp, size_t size) {
  unsigned int i, needed = align_to_voidptr(size + FRAG_OVERHEAD);
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
  mpm->usize = needed + align_to_voidptr(sizeof(*mpm));
  mpm->next = mp->u.mpm.next;
  mp->u.mpm.next = mpm;
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


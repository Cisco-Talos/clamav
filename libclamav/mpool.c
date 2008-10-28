/*
 *  Copyright (C) 2008 Sourcefire, Inc.
 *
 *  Authors: Alberto Wu
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


#define DEBUGMPOOL
#ifdef DEBUGMPOOL
#include <stdio.h>
FILE *lfd = NULL;
#define spam(...) fprintf(lfd, __VA_ARGS__)
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


struct FRAG {
  struct FRAG *next;
  unsigned int sbits;
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
  return i; /* NOTREACHED */
}
static unsigned int from_bits(unsigned int bits) {
  return fragsz[bits];
}
/* static unsigned int to_bits(unsigned int size) { */
/*   unsigned int i; */
/*   for(i=0; i<32; i++) */
/*     if((unsigned int)1<<i >= size) return i; */
/*   return i; /\* NOTREACHED *\/ */
/* } */
/* static unsigned int from_bits(unsigned int bits) { */
/*   return 1<<bits; */
/* } */

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

void *mp_malloc(struct MP *mp, size_t size) {
  unsigned int i, j, needed = align_to_voidptr(size + FRAG_OVERHEAD);
  const unsigned int sbits = to_bits(needed);
  struct FRAG *f = NULL;
  struct MPMAP *mpm = &mp->mpm;

  /*  check_all(mp); */
  if (!size) return NULL;

  j = sbits+2;
  if (j<7) j = 7;
  if (j > 32) j = 32;

  j=sbits;

  for (i=sbits; i<j; i++)
    if((f = mp->avail[i])) break;

  /* Case 1: We have a free'd frag */
  if(f) {
    spam("malloc %p size %u (freed)\n", f, roundup(size));
    mp->avail[i] = f->next;
    return &f->fake;
  }

  needed = from_bits(sbits);

  /* Case 2: We have nuff room available for this frag already */
  while(mpm) {
    if(mpm->size - mpm->usize >= needed) {
      f = (struct FRAG *)((void *)mpm + mpm->usize);
      spam("malloc %p size %u (hole)\n", f, roundup(size));
      mpm->usize += needed;
      f->sbits = sbits;
      return &f->fake;
    }
    mpm = mpm->next;
  }

  /* Case 3: We allocate more */
  if (needed + align_to_voidptr(sizeof(*mpm)) > MIN_FRAGSIZE)
  i = align_to_pagesize(mp, needed + align_to_voidptr(sizeof(*mpm)));
  else
  i = align_to_pagesize(mp, MIN_FRAGSIZE);
  
  if ((mpm = (struct MPMAP *)mmap(NULL, i, PROT_READ | PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)) == MAP_FAILED) {
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
  return &f->fake;
}

void mp_free(struct MP *mp, void *ptr) {
  struct FRAG *f = (struct FRAG *)(ptr - FRAG_OVERHEAD);
  if (!ptr) return;

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
  csize = from_bits(f->sbits) - FRAG_OVERHEAD;
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
  csize = from_bits(f->sbits) - FRAG_OVERHEAD;
  if (csize >= size) return ptr;
  if ((new_ptr = mp_malloc(mp, size)))
    memcpy(new_ptr, ptr, csize);
  mp_free(mp, ptr);
  return new_ptr;
}

#endif /* USE_MPOOL */

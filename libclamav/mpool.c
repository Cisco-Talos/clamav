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

#define MIN_FRAGSIZE 262144

#if SIZEOF_VOID_P==8
static const unsigned int fragsz[] = {
/* SIZE        PERM    TEMP     MAX    ACT! */
/* MINIMUM is 8, 3 has 573758, and 7 has 204930! */
      8, /*    2409       2    2409      USE */
      9, /*     670       0     670      USE */
     10, /*     241      29     241    GROUP */
     11, /*    2710       7    2714    GROUP */
     12, /*    3643      14    3643      USE */
     13, /*    4700       5    4704    GROUP */
     14, /*    4983       0    4983      USE */
     15, /*    6691       0    6691      USE */
     16, /*   17498      98   17500      USE */
     17, /*   21243       4   21247      USE */
     18, /*      20      39      21    GROUP */
     19, /*  136202  709691  136207      USE */
     20, /*  106671       2  106673      USE */
     21, /*  157392       2  157394      USE */
     22, /*      11       0      11    GROUP */
     23, /*   50093       2   50095      USE */
     24, /*  184591      57  184601      USE */
     25, /*   22537       0   22537      USE */
     26, /*      35      17      35    GROUP */
     27, /*    1565       8    1573    GROUP */
     28, /*    1928       0    1928    GROUP */
     29, /*    2436       1    2437      USE */
     30, /*       2       0       2    GROUP */
     31, /*    3645       0    3645    GROUP */
     32, /*  122690      52  122690      USE */
     33, /*    6340       0    6340      USE */
     34, /*      13       9      13    GROUP */
     35, /*  369862      29  369863      USE */
     36, /*     724       0     724    GROUP */
     37, /*     258       0     258    GROUP */
     38, /*       2       0       2    GROUP */
     39, /*     519       0     519    GROUP */
     40, /*    3777      37    3777    GROUP */
     41, /*    1447       0    1447      USE */
     42, /*       9      15      10    GROUP */
     43, /*     573       0     573    GROUP */
     44, /*     510       0     510    GROUP */
     45, /*     139       0     139    GROUP */
     47, /*     260       0     260    GROUP */
     48, /*  713479      55  713484      USE */
     49, /*     958       0     958    GROUP */
     50, /*       8      19       9    GROUP */
     51, /*     824       0     824      USE */
     52, /*     424       0     424    GROUP */
     53, /*     154       0     154    GROUP */
     54, /*       2       0       2    GROUP */
     55, /*     106       0     106    GROUP */
     56, /*    2092      17    2092      USE */
     57, /*     116       0     116    GROUP */
     58, /*       4      17       4    GROUP */
     59, /*     106       0     106    GROUP */
     60, /*     347       0     347    GROUP */
     61, /*     143       0     143    GROUP */
     62, /*       5       0       5    GROUP */
     63, /*     202       0     202    GROUP */
     64, /*    1235      18    1235      USE */
     65, /*     253       0     253      USE */
     68, /*     573       0     573      USE */
     73, /*     585       0     585      USE */
     74, /*    9396       2    9398      USE */
     75, /*    5096      12    5099      USE */
     76, /*   15484      12   15495      USE */
     77, /*    4755       6    4761      USE */
     78, /*    8796       3    8798      USE */
     79, /*    5134       4    5136      USE */
     80, /*  651749      55  651784      USE */
     81, /*    5797       6    5802      USE */
     85, /*     615       0     615      USE */
     88, /*    1484      14    1484      USE */
     93, /*     856       0     856      USE */
     97, /*     232       0     232      USE */
     98, /*      62       1      62      USE */
    101, /*     624       0     624      USE */
    104, /*    1356      12    1356      USE */
    108, /*     714       0     714      USE */
    109, /*     474       1     474      USE */
    113, /*    1473       0    1473      USE */
    116, /*     250       0     250      USE */
    120, /*     848       7     848      USE */
    121, /*     489       0     489      USE */
    124, /*     270       4     270      USE */
    128, /*    2444       9    2444      USE */
    129, /*     155       0     155      USE */
    131, /*    2126       0    2126      USE */
    136, /*     849      12     849      USE */
    141, /*     968       0     968      USE */
    143, /*    9841       0    9841      USE */
    147, /*    2528       0    2528      USE */
    148, /*     814       0     814      USE */
    149, /*    2757       0    2757      USE */
    151, /*    3614       0    3614      USE */
    152, /*   31854      14   31854      USE */
    153, /*   11771       0   11771      USE */
    164, /*     180       0     180      USE */
    174, /*      23       0      23      USE */
    184, /*     213       7     213      USE */
    195, /*       2       0       2      USE */
    200, /*     210      13     210      USE */
    210, /*       3      12       3      USE */
    216, /*     172       9     172      USE */
    220, /*      68       0      68      USE */
    230, /*       9       0       9      USE */
    232, /*     170       9     170      USE */
    242, /*       2      17       2      USE */
    244, /*     367       0     367      USE */
    248, /*     133       3     133      USE */
    256, /*     169       8     169      USE */
    257, /*       1       0       1      USE */
    264, /*     149       7     149      USE */
    272, /*     167       6     167      USE */
    273, /*       4       0       4      USE */
    292, /*     158       0     158      USE */
    304, /*     728       7     728      USE */
    326, /*       1       0       1      USE */
    344, /*      19       7      19      USE */
    364, /*       3       0       3      USE */
    382, /*       1       0       1      USE */
    392, /*       3       7       3      USE */
    413, /*       4       0       4      USE */
    434, /*       1      11       1      USE */
    453, /*       4       0       4      USE */
    512, /*       0       7       1      USE */
    584, /*       1       6       1      USE */
    698, /*       1      13       2      USE */
   1024, /*       0       5       1      USE */
   1490, /*       1      11       2      USE */
   2048, /*       0       7       1      USE */
   2050, /*      17       0      17      USE */
   2056, /*   12115      17   12115      USE */
   2096, /*       1      13       2      USE */
   4096, /*       0      16       1      USE */
   6298, /*       1      13       1      USE */
   8192, /*       0       3       1      USE */
   8202, /*       1      12       2      USE */
   9330, /*       1      10       1      USE */
  12162, /*       1       6       1      USE */
  16384, /*       0       3       1      USE */
  16390, /*      14       1      15      USE */
  16392, /*     256       2     257      USE */
  18440, /*       1       2       2      USE */
  21946, /*       1       4       1      USE */
  32768, /*       0       3       1      USE */
  35306, /*       1       2       1      USE */
  43250, /*       1       1       1      USE */
  48914, /*       1       1       1      USE */
  63505, /*       1       0       1      USE */
  65536, /*       0       1       1      USE */
  92800, /*       1       1       1      USE */
 107602, /*       1       0       1      USE */
 131072, /*       0       1       1      USE */
 131088, /*       6       1       7      USE */
 131089, /*       1       0       1      USE */
 131832, /*       1       1       2      USE */
 156918, /*       1       0       1      USE */
 262144, /*       0       1       1      USE */
 374608, /*       1       0       1      USE */
 507976, /*       9       1      10      USE */
 524288, /*       0       0       0      USE */
1048576,
2097152,
4194304,
8388608,
 /* MAX_ALLOCATION is 184549376 but that's really not need here */
};

#else

static const unsigned int fragsz[] = {
/* SIZE        PERM    TEMP     MAX    ACT! */
/* Minimum is 4, 3 has PERM 573604, so USE 4 */
      4, /*     650    2615     650      USE */
      5, /*      78    4174      78      USE */
      6, /*       6       1       6    GROUP */
      7, /*  204959       1  204959      USE */
      8, /*    3329     122    3329      USE */
      9, /*     689       0     689      USE */
     10, /*       8       1       8    GROUP */
     11, /*    2747       8    2751      USE */
     12, /*    2794      12    2794    GROUP */
     14, /*     199       0     199    GROUP */
     13, /*    6089       7    6093      USE */
     15, /*   10931       2   10931      USE */
     16, /*   38014     156   38016      USE */
     17, /*   26103       5   26107      USE */
     18, /*      36       0      36    GROUP */
     19, /*  136485  709691  136490      USE */
     20, /*   99623       2   99625      USE */
     21, /*  172941       3  172943      USE */
     22, /*     112       2     112    GROUP */
     23, /*   51623      18   51630      USE */
     24, /*  160953      93  160962      USE */
     25, /*   37098      13   37098      USE */
     26, /*      22       0      22    GROUP */
     27, /*    1641       9    1649    GROUP */
     28, /*   15178       2   15178      USE */
     29, /*    9702       2    9703      USE */
     30, /*    5058       1    5058      USE */
     31, /*  174564       1  174564      USE */
     32, /*  484826      65  484826      USE */
     33, /*  129986       0  129986      USE */
     34, /*       1       0       1    GROUP */
     35, /*  369710      29  369711      USE */
     36, /*     778       2     778    GROUP */
     37, /*     304       1     304    GROUP */
     39, /*     560       3     560    GROUP */
     40, /*    3590      58    3590      USE */
     41, /*    1454       0    1454      USE */
     43, /*     573       0     573    GROUP */
     44, /*     499       1     499      USE */
     45, /*     155       0     155    GROUP */
     47, /*     421       8     421    GROUP */
     48, /*    3557      49    3557      USE */
     49, /*     959       1     959    GROUP */
     51, /*     824       0     824      USE */
     52, /*     408       1     408    GROUP */
     53, /*     171       1     171    GROUP */
     54, /*       1       1       1    GROUP */
     55, /*     251       4     251    GROUP */
     56, /*    1954      43    1954      USE */
     57, /*     116       1     116    GROUP */
     58, /*  194720       0  194720      USE */
     59, /*    3957       4    3961    GROUP */
     60, /*   14914       2   14916      USE */
     61, /*    4328      12    4339      USE */
     62, /*  211993       2  211993      USE */
     63, /*    5781      10    5785      USE */
     64, /*   26575      52   26587      USE */
     65, /*  190454       4  190456      USE */
     68, /*     557       2     557      USE */
     73, /*     585       1     585      USE */
     81, /*     760       0     760      USE */
     85, /*     635       1     635      USE */
     88, /*    1486      39    1486      USE */
     91, /*     226       1     226      USE */
     96, /*     964      37     964      USE */
    101, /*     499       1     499      USE */
    104, /*    1288      42    1289      USE */
    108, /*     714       1     714      USE */
    109, /*     328       0     328      USE */
    113, /*    1473       1    1473      USE */
    116, /*    4499       1    4499      USE */
    117, /*    3175       0    3175      USE */
    120, /*   17801      40   17801      USE */
    121, /*    2198       1    2198      USE */
    128, /*    2396      36    2396      USE */
    129, /*     155       0     155      USE */
    131, /*    2126       1    2126      USE */
    136, /*     728      35     728      USE */
    143, /*    9878       0    9878      USE */
    148, /*     753       0     753      USE */
    151, /*    1928       6    1928      USE */
    153, /*   11771       1   11771      USE */
    164, /*     175       2     175      USE */
    172, /*      97       1      97      USE */
    176, /*     249      32     249      USE */
    191, /*       3       0       3      USE */
    192, /*     214      12     214      USE */
    196, /*     227       3     227      USE */
    204, /*     216       0     216      USE */
    206, /*       1       4       1      USE */
    216, /*     185      35     185      USE */
    229, /*       3       0       3      USE */
    231, /*       1       0       1      USE */
    244, /*     365       1     365      USE */
    256, /*     169      33     169      USE */
    257, /*       1       1       2      USE */
    264, /*     171      33     171      USE */
    272, /*     168      34     168      USE */
    280, /*     177       7     177      USE */
    286, /*       1       7       1      USE */
    292, /*     154       1     154      USE */
    304, /*     718      23     718      USE */
    318, /*       1       0       1      USE */
    333, /*       1       0       1      USE */
    340, /*       6       0       6      USE */
    368, /*       6       4       6      USE */
    388, /*      18       8      18      USE */
    422, /*       1      10       2      USE */
    460, /*       1       9       2      USE */
    447, /*       2       3       2      USE */
    471, /*       1       1       2      USE */
    512, /*       2       5       2      USE */
    514, /*       1       6       2      USE */
    580, /*       8       9       8      USE */
    620, /*       1       9       2      USE */
    696, /*       1       9       1      USE */
   1024, /*       0       3       2      USE */
   1026, /*      20       0      20      USE */
   1028, /*    3831       0    3831      USE */
   1032, /*    8256      15    8256      USE */
   1046, /*       1      10       2      USE */
   1052, /*       1      13       2      USE */
   2048, /*       0       3       1      USE */
   3150, /*       1       6       1      USE */
   4096, /*       0       3       1      USE */
   4102, /*       1      11       2      USE */
   5126, /*       1       7       1      USE */
   8192, /*       0       0       0      USE */
  10248, /*       1       1       2      USE */
  11272, /*     225       2     226      USE */
  16384, /*       0       3       2      USE */
  17654, /*       1       4       1      USE */
  24460, /*       1       2       1      USE */
  32768, /*       0       2       1      USE */
  46400, /*       1       0       1      USE */
  53806, /*       1       0       1      USE */
  63504, /*       3       2       5      USE */
  65536, /*       0       1       1      USE */
 131072, /*       0       1       1      USE */
 131080, /*       6       1       7      USE */
 131544, /*       1       1       2      USE */
 156920, /*       1       1       1      USE */
 187304, /*       1       0       1      USE */
 253988, /*       9       1      10      USE */
 262144, /*       0       0       0      USE */
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


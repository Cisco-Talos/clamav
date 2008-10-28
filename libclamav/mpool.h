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

#ifndef MPOOL_H
#define MPOOL_H

#ifdef USE_MPOOL

static const unsigned int fragsz[] = {
24, /* (33067) */
32, /* (93876) */
40, /* (731459) */
48, /* (35286) */
56, /* (6930) */
64, /* (442013) */
72, /* (2706) */
80, /* (2252) */
88, /* (3631) */
96, /* (2594) */
104, /* (3679) */
112, /* (3697) */
120, /* (3991) */
128, /* (5141) */
136, /* (22458) */
144, /* (4320) */
152, /* (4296) */
160, /* (12177) */
168, /* (18024) */
/* 176, /\* (323) *\/ */
/* 184, /\* (329) *\/ */
/* 192, /\* (202) *\/ */
/* 200, /\* (221) *\/ */
/* 208, /\* (166) *\/ */
/* 216, /\* (179) *\/ */
/* 224, /\* (216) *\/ */
/* 232, /\* (172) *\/ */
/* 240, /\* (157) *\/ */
/* 248, /\* (178) *\/ */
256, /* (133) */
/* 264, /\* (157) *\/ */
/* 272, /\* (140) *\/ */
/* 280, /\* (161) *\/ */
/* 288, /\* (125) *\/ */
/* 296, /\* (141) *\/ */
/* 304, /\* (100) *\/ */
/* 312, /\* (97) *\/ */
/* 320, /\* (70) *\/ */
/* 328, /\* (13) *\/ */
/* 336, /\* (21) *\/ */
/* 344, /\* (21) *\/ */
/* 352, /\* (13) *\/ */
/* 360, /\* (9) *\/ */
/* 368, /\* (8) *\/ */
/* 376, /\* (14) *\/ */
/* 384, /\* (5) *\/ */
/* 392, /\* (6) *\/ */
/* 400, /\* (4) *\/ */
/* 408, /\* (2) *\/ */
/* 416, /\* (6) *\/ */
/* 424, /\* (5) *\/ */
/* 432, /\* (4) *\/ */
/* 440, /\* (4) *\/ */
/* 448, /\* (4) *\/ */
/* 464, /\* (2) *\/ */
/* 472, /\* (2) *\/ */
/* 480, /\* (1) *\/ */
/* 496, /\* (1) *\/ */
/* 512, /\* (2) *\/ */
520, /* (11) */
/* 536, /\* (1) *\/ */
/* 544, /\* (2) *\/ */
/* 552, /\* (1) *\/ */
/* 584, /\* (3) *\/ */
/* 600, /\* (1) *\/ */
/* 624, /\* (1) *\/ */
/* 656, /\* (1) *\/ */
/* 784, /\* (2) *\/ */
1032, /* (11) */
/* 2056, /\* (14) *\/ */
2064, /* (7456) */
4104, /* (14) */
8200, /* (9) */
16392, /* (6) */
32776, /* (4) */
63512, /* (7) */
134408, /* (1) */
507984, /* (7) */
1051040, /* (1) */
2097152
};

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

typedef struct MP mp_t;

mp_t *mp_create(void);
void mp_destroy(mp_t *mp);
void *mp_malloc(mp_t *mp, size_t size);
void mp_free(mp_t *mp, void *ptr);
void *mp_calloc(mp_t *mp, size_t nmemb, size_t size);
void *mp_realloc(mp_t *mp, void *ptr, size_t size);
void *mp_realloc2(mp_t *mp, void *ptr, size_t size);
void mp_flush(mp_t *mp);

#else /* USE_MPOOL */

#define mp_malloc(a, b) cli_malloc(b)
#define mp_free(a, b) free(b)
#define mp_calloc(a, b, c) cli_calloc(b, c)
#define mp_realloc(a, b, c) cli_realloc(b, c)
#define mp_realloc2(a, b, c) cli_realloc2(b, c)

#endif /* USE_MPOOL */

#endif



/*-
 * Copyright (c) 1992, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdlib.h>

#include "clamav.h"
#include "platform.h"
#include "others.h"

// clang-format off
static inline char *med3(char *, char *, char *, int (*)(const void *, const void *));
static inline char *med3_r(void *, char *, char *, char *, int (*)(const void *, const void *, const void *));
static inline void swapfunc(char *, char *, int, int);

/*
 * Qsort routine from Bentley & McIlroy's "Engineering a Sort Function".
 */
#define swapcode(TYPE, parmi, parmj, n)         \
    {                                           \
        long i            = (n) / sizeof(TYPE); \
        register TYPE *pi = (TYPE *)(parmi);    \
        register TYPE *pj = (TYPE *)(parmj);    \
        do {                                    \
            register TYPE t = *pi;              \
            *pi++           = *pj;              \
            *pj++           = t;                \
        } while (--i > 0);                      \
    }

#define SWAPINIT(a, es) swaptype = ((char *)a - (char *)0) % sizeof(long) || \
                                           es % sizeof(long)                 \
                                       ? 2                                   \
                                   : es == sizeof(long) ? 0                  \
                                                        : 1;

static inline void
    swapfunc(a, b, n, swaptype) char *a,
    *b;
int n, swaptype;
{
    if (swaptype <= 1)
        swapcode(long, a, b, n) else swapcode(char, a, b, n)
}

#define swap(a, b)                   \
    if (swaptype == 0) {             \
        long t       = *(long *)(a); \
        *(long *)(a) = *(long *)(b); \
        *(long *)(b) = t;            \
    } else                           \
        swapfunc(a, b, es, swaptype)

#define vecswap(a, b, n) \
    if ((n) > 0) swapfunc(a, b, n, swaptype)

#define CMP1(a, b) ((int)(*((uint32_t *)(a)) - *((uint32_t *)(b))))
#define CMP(a, b) (cmp ? (cmp(a, b)) : CMP1(a, b))
#define CMP_R(arg, a, b) (cmp ? (cmp(arg, a, b)) : CMP1(a, b))
#define MED3(a, b, c, d) (d ? (med3(a, b, c, d)) : (CMP1(a, b) < 0 ? (CMP1(b, c) < 0 ? (b) : (CMP1(a, c) < 0 ? (c) : (a))) : (CMP1(b, c) > 0 ? (b) : (CMP1(a, c) < 0 ? (a) : (c)))))
#define MED3_R(arg, a, b, c, d) (d ? (med3_r(arg, a, b, c, d)) : (CMP1(a, b) < 0 ? (CMP1(b, c) < 0 ? (b) : (CMP1(a, c) < 0 ? (c) : (a))) : (CMP1(b, c) > 0 ? (b) : (CMP1(a, c) < 0 ? (a) : (c)))))

static inline char *
    med3(a, b, c, cmp) char *a, *b, *c;
int (*cmp)(const void *, const void *);
{
    return CMP(a, b) < 0 ? (CMP(b, c) < 0 ? b : (CMP(a, c) < 0 ? c : a))
                         : (CMP(b, c) > 0 ? b : (CMP(a, c) < 0 ? a : c));
}

static inline char *
    med3_r(arg, a, b, c, cmp) void *arg;
char *a, *b, *c;
int (*cmp)(const void *, const void *, const void *);
{
    return CMP_R(arg, a, b) < 0 ? (CMP_R(arg, b, c) < 0 ? b : (CMP_R(arg, a, c) < 0 ? c : a))
                                : (CMP_R(arg, b, c) > 0 ? b : (CMP_R(arg, a, c) < 0 ? a : c));
}

void cli_qsort(void *a, size_t n, size_t es, int (*cmp)(const void *, const void *))
{
    char *pa, *pb, *pc, *pd, *pl, *pm, *pn;
    int d, r, swaptype, swap_cnt;

loop:
    SWAPINIT(a, es);
    swap_cnt = 0;
    if (n < 7) {
        for (pm = (char *)a + es; pm < (char *)a + n * es; pm += es)
            for (pl = pm; pl > (char *)a && CMP(pl - es, pl) > 0;
                 pl -= es)
                swap(pl, pl - es);
        return;
    }
    pm = (char *)a + (n / 2) * es;
    if (n > 7) {
        pl = a;
        pn = (char *)a + (n - 1) * es;
        if (n > 40) {
            d  = (n / 8) * es;
            pl = MED3(pl, pl + d, pl + 2 * d, cmp);
            pm = MED3(pm - d, pm, pm + d, cmp);
            pn = MED3(pn - 2 * d, pn - d, pn, cmp);
        }
        pm = MED3(pl, pm, pn, cmp);
    }
    swap(a, pm);
    pa = pb = (char *)a + es;

    pc = pd = (char *)a + (n - 1) * es;
    for (;;) {
        while (pb <= pc && (r = CMP(pb, a)) <= 0) {
            if (r == 0) {
                swap_cnt = 1;
                swap(pa, pb);
                pa += es;
            }
            pb += es;
        }
        while (pb <= pc && (r = CMP(pc, a)) >= 0) {
            if (r == 0) {
                swap_cnt = 1;
                swap(pc, pd);
                pd -= es;
            }
            pc -= es;
        }
        if (pb > pc)
            break;
        swap(pb, pc);
        swap_cnt = 1;
        pb += es;
        pc -= es;
    }
    if (swap_cnt == 0) { /* Switch to insertion sort */
        for (pm = (char *)a + es; pm < (char *)a + n * es; pm += es)
            for (pl = pm; pl > (char *)a && CMP(pl - es, pl) > 0;
                 pl -= es)
                swap(pl, pl - es);
        return;
    }

    pn = (char *)a + n * es;
    r  = MIN(pa - (char *)a, pb - pa);
    vecswap(a, pb - r, r);
    r = MIN((size_t)(pd - pc), (size_t)(pn - pd - es));
    vecswap(pb, pn - r, r);
    if ((size_t)(r = pb - pa) > es)
        cli_qsort(a, r / es, es, cmp);
    if ((size_t)(r = pd - pc) > es) {
        /* Iterate rather than recurse to save stack space */
        a = pn - r;
        n = r / es;
        goto loop;
    }
    /*		cli_qsort(pn - r, r / es, es, cmp);*/
}

void cli_qsort_r(void *a, size_t n, size_t es, int (*cmp)(const void *, const void *, const void *), void *arg)
{
    char *pa, *pb, *pc, *pd, *pl, *pm, *pn;
    int d, r, swaptype, swap_cnt;

loop:
    SWAPINIT(a, es);
    swap_cnt = 0;
    if (n < 7) {
        for (pm = (char *)a + es; pm < (char *)a + n * es; pm += es)
            for (pl = pm; pl > (char *)a && CMP_R(arg, pl - es, pl) > 0;
                 pl -= es)
                swap(pl, pl - es);
        return;
    }
    pm = (char *)a + (n / 2) * es;
    if (n > 7) {
        pl = a;
        pn = (char *)a + (n - 1) * es;
        if (n > 40) {
            d  = (n / 8) * es;
            pl = MED3_R(arg, pl, pl + d, pl + 2 * d, cmp);
            pm = MED3_R(arg, pm - d, pm, pm + d, cmp);
            pn = MED3_R(arg, pn - 2 * d, pn - d, pn, cmp);
        }
        pm = MED3_R(arg, pl, pm, pn, cmp);
    }
    swap(a, pm);
    pa = pb = (char *)a + es;

    pc = pd = (char *)a + (n - 1) * es;
    for (;;) {
        while (pb <= pc && (r = CMP_R(arg, pb, a)) <= 0) {
            if (r == 0) {
                swap_cnt = 1;
                swap(pa, pb);
                pa += es;
            }
            pb += es;
        }
        while (pb <= pc && (r = CMP_R(arg, pc, a)) >= 0) {
            if (r == 0) {
                swap_cnt = 1;
                swap(pc, pd);
                pd -= es;
            }
            pc -= es;
        }
        if (pb > pc)
            break;
        swap(pb, pc);
        swap_cnt = 1;
        pb += es;
        pc -= es;
    }
    if (swap_cnt == 0) { /* Switch to insertion sort */
        for (pm = (char *)a + es; pm < (char *)a + n * es; pm += es)
            for (pl = pm; pl > (char *)a && CMP_R(arg, pl - es, pl) > 0;
                 pl -= es)
                swap(pl, pl - es);
        return;
    }

    pn = (char *)a + n * es;
    r  = MIN(pa - (char *)a, pb - pa);
    vecswap(a, pb - r, r);
    r = MIN((size_t)(pd - pc), (size_t)(pn - pd - es));
    vecswap(pb, pn - r, r);
    if ((size_t)(r = pb - pa) > es)
        cli_qsort_r(a, r / es, es, cmp, arg);
    if ((size_t)(r = pd - pc) > es) {
        /* Iterate rather than recurse to save stack space */
        a = pn - r;
        n = r / es;
        goto loop;
    }
    /*		cli_qsort_r(pn - r, r / es, es, cmp);*/
}
// clang-format on

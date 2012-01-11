/* Start: fp_2expt.c */
/* TomsFastMath, a fast ISO C bignum library.
 * 
 * This project is meant to fill in where LibTomMath
 * falls short.  That is speed ;-)
 *
 * This project is public domain and free for all purposes.
 * 
 * Tom St Denis, tomstdenis@gmail.com
 */
#include "bignum_fast.h"

/* computes a = 2**b */
void fp_2expt(fp_int *a, int b)
{
   int     z;

   /* zero a as per default */
   fp_zero (a);

   if (b < 0) { 
      return;
   }

   z = b / DIGIT_BIT;
   if (z >= FP_SIZE) {
      return; 
   }

  /* set the used count of where the bit will go */
  a->used = z + 1;

  /* put the single bit in its place */
  a->dp[z] = ((fp_digit)1) << (b % DIGIT_BIT);
}


/* $Source: /cvs/libtom/tomsfastmath/src/exptmod/fp_2expt.c,v $ */
/* $Revision: 1.1 $ */
/* $Date: 2006/12/31 21:25:53 $ */

/* End: fp_2expt.c */

/* Start: fp_add.c */
/* TomsFastMath, a fast ISO C bignum library.
 * 
 * This project is meant to fill in where LibTomMath
 * falls short.  That is speed ;-)
 *
 * This project is public domain and free for all purposes.
 * 
 * Tom St Denis, tomstdenis@gmail.com
 */
#include "bignum_fast.h"

void fp_add(fp_int *a, fp_int *b, fp_int *c)
{
  int     sa, sb;

  /* get sign of both inputs */
  sa = a->sign;
  sb = b->sign;

  /* handle two cases, not four */
  if (sa == sb) {
    /* both positive or both negative */
    /* add their magnitudes, copy the sign */
    c->sign = sa;
    s_fp_add (a, b, c);
  } else {
    /* one positive, the other negative */
    /* subtract the one with the greater magnitude from */
    /* the one of the lesser magnitude.  The result gets */
    /* the sign of the one with the greater magnitude. */
    if (fp_cmp_mag (a, b) == FP_LT) {
      c->sign = sb;
      s_fp_sub (b, a, c);
    } else {
      c->sign = sa;
      s_fp_sub (a, b, c);
    }
  }
}

/* $Source: /cvs/libtom/tomsfastmath/src/addsub/fp_add.c,v $ */
/* $Revision: 1.1 $ */
/* $Date: 2006/12/31 21:25:53 $ */

/* End: fp_add.c */

/* Start: fp_add_d.c */
/* TomsFastMath, a fast ISO C bignum library.
 * 
 * This project is meant to fill in where LibTomMath
 * falls short.  That is speed ;-)
 *
 * This project is public domain and free for all purposes.
 * 
 * Tom St Denis, tomstdenis@gmail.com
 */
#include "bignum_fast.h"

/* c = a + b */
void fp_add_d(fp_int *a, fp_digit b, fp_int *c)
{
   fp_int tmp;
   fp_set(&tmp, b);
   fp_add(a,&tmp,c);
}

/* $Source: /cvs/libtom/tomsfastmath/src/addsub/fp_add_d.c,v $ */
/* $Revision: 1.1 $ */
/* $Date: 2006/12/31 21:25:53 $ */

/* End: fp_add_d.c */

/* Start: fp_addmod.c */
/* TomsFastMath, a fast ISO C bignum library.
 * 
 * This project is meant to fill in where LibTomMath
 * falls short.  That is speed ;-)
 *
 * This project is public domain and free for all purposes.
 * 
 * Tom St Denis, tomstdenis@gmail.com
 */
#include "bignum_fast.h"

/* d = a + b (mod c) */
int fp_addmod(fp_int *a, fp_int *b, fp_int *c, fp_int *d)
{
  fp_int tmp;
  fp_zero(&tmp);
  fp_add(a, b, &tmp);
  return fp_mod(&tmp, c, d);
}

/* $Source: /cvs/libtom/tomsfastmath/src/addsub/fp_addmod.c,v $ */
/* $Revision: 1.1 $ */
/* $Date: 2006/12/31 21:25:53 $ */

/* End: fp_addmod.c */

/* Start: fp_cmp.c */
/* TomsFastMath, a fast ISO C bignum library.
 * 
 * This project is meant to fill in where LibTomMath
 * falls short.  That is speed ;-)
 *
 * This project is public domain and free for all purposes.
 * 
 * Tom St Denis, tomstdenis@gmail.com
 */
#include "bignum_fast.h"

int fp_cmp(fp_int *a, fp_int *b)
{
   if (a->sign == FP_NEG && b->sign == FP_ZPOS) {
      return FP_LT;
   } else if (a->sign == FP_ZPOS && b->sign == FP_NEG) {
      return FP_GT;
   } else {
      /* compare digits */
      if (a->sign == FP_NEG) {
         /* if negative compare opposite direction */
         return fp_cmp_mag(b, a);
      } else {
         return fp_cmp_mag(a, b);
      }
   }
}

/* $Source: /cvs/libtom/tomsfastmath/src/addsub/fp_cmp.c,v $ */
/* $Revision: 1.1 $ */
/* $Date: 2006/12/31 21:25:53 $ */

/* End: fp_cmp.c */

/* Start: fp_cmp_d.c */
/* TomsFastMath, a fast ISO C bignum library.
 * 
 * This project is meant to fill in where LibTomMath
 * falls short.  That is speed ;-)
 *
 * This project is public domain and free for all purposes.
 * 
 * Tom St Denis, tomstdenis@gmail.com
 */
#include "bignum_fast.h"

/* compare against a single digit */
int fp_cmp_d(fp_int *a, fp_digit b)
{
  /* compare based on sign */
  if ((b && a->used == 0) || a->sign == FP_NEG) {
    return FP_LT;
  }

  /* compare based on magnitude */
  if (a->used > 1) {
    return FP_GT;
  }

  /* compare the only digit of a to b */
  if (a->dp[0] > b) {
    return FP_GT;
  } else if (a->dp[0] < b) {
    return FP_LT;
  } else {
    return FP_EQ;
  }

}

/* $Source: /cvs/libtom/tomsfastmath/src/addsub/fp_cmp_d.c,v $ */
/* $Revision: 1.1 $ */
/* $Date: 2006/12/31 21:25:53 $ */

/* End: fp_cmp_d.c */

/* Start: fp_cmp_mag.c */
/* TomsFastMath, a fast ISO C bignum library.
 * 
 * This project is meant to fill in where LibTomMath
 * falls short.  That is speed ;-)
 *
 * This project is public domain and free for all purposes.
 * 
 * Tom St Denis, tomstdenis@gmail.com
 */
#include "bignum_fast.h"

int fp_cmp_mag(fp_int *a, fp_int *b)
{
   int x;

   if (a->used > b->used) {
      return FP_GT;
   } else if (a->used < b->used) {
      return FP_LT;
   } else {
      for (x = a->used - 1; x >= 0; x--) {
          if (a->dp[x] > b->dp[x]) {
             return FP_GT;
          } else if (a->dp[x] < b->dp[x]) {
             return FP_LT;
          }
      }
   }
   return FP_EQ;
}


/* $Source: /cvs/libtom/tomsfastmath/src/addsub/fp_cmp_mag.c,v $ */
/* $Revision: 1.1 $ */
/* $Date: 2006/12/31 21:25:53 $ */

/* End: fp_cmp_mag.c */

/* Start: fp_cnt_lsb.c */
/* TomsFastMath, a fast ISO C bignum library.
 * 
 * This project is meant to fill in where LibTomMath
 * falls short.  That is speed ;-)
 *
 * This project is public domain and free for all purposes.
 * 
 * Tom St Denis, tomstdenis@gmail.com
 */
#include "bignum_fast.h"

static const int lnz[16] = {
   4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0
};

/* Counts the number of lsbs which are zero before the first zero bit */
int fp_cnt_lsb(fp_int *a)
{
   int x;
   fp_digit q, qq;

   /* easy out */
   if (fp_iszero(a) == 1) {
      return 0;
   }

   /* scan lower digits until non-zero */
   for (x = 0; x < a->used && a->dp[x] == 0; x++);
   q = a->dp[x];
   x *= DIGIT_BIT;

   /* now scan this digit until a 1 is found */
   if ((q & 1) == 0) {
      do {
         qq  = q & 15;
         x  += lnz[qq];
         q >>= 4;
      } while (qq == 0);
   }
   return x;
}


/* $Source: /cvs/libtom/tomsfastmath/src/bit/fp_cnt_lsb.c,v $ */
/* $Revision: 1.1 $ */
/* $Date: 2006/12/31 21:25:53 $ */

/* End: fp_cnt_lsb.c */

/* Start: fp_count_bits.c */
/* TomsFastMath, a fast ISO C bignum library.
 * 
 * This project is meant to fill in where LibTomMath
 * falls short.  That is speed ;-)
 *
 * This project is public domain and free for all purposes.
 * 
 * Tom St Denis, tomstdenis@gmail.com
 */
#include "bignum_fast.h"

int fp_count_bits (fp_int * a)
{
  int     r;
  fp_digit q;

  /* shortcut */
  if (a->used == 0) {
    return 0;
  }

  /* get number of digits and add that */
  r = (a->used - 1) * DIGIT_BIT;

  /* take the last digit and count the bits in it */
  q = a->dp[a->used - 1];
  while (q > ((fp_digit) 0)) {
    ++r;
    q >>= ((fp_digit) 1);
  }
  return r;
}

/* $Source: /cvs/libtom/tomsfastmath/src/bit/fp_count_bits.c,v $ */
/* $Revision: 1.1 $ */
/* $Date: 2006/12/31 21:25:53 $ */

/* End: fp_count_bits.c */

/* Start: fp_div.c */
/* TomsFastMath, a fast ISO C bignum library.
 * 
 * This project is meant to fill in where LibTomMath
 * falls short.  That is speed ;-)
 *
 * This project is public domain and free for all purposes.
 * 
 * Tom St Denis, tomstdenis@gmail.com
 */
#include "bignum_fast.h"

/* a/b => cb + d == a */
int fp_div(fp_int *a, fp_int *b, fp_int *c, fp_int *d)
{
  fp_int  q, x, y, t1, t2;
  int     n, t, i, norm, neg;

  /* is divisor zero ? */
  if (fp_iszero (b) == 1) {
    return FP_VAL;
  }

  /* if a < b then q=0, r = a */
  if (fp_cmp_mag (a, b) == FP_LT) {
    if (d != NULL) {
      fp_copy (a, d);
    } 
    if (c != NULL) {
      fp_zero (c);
    }
    return FP_OKAY;
  }

  fp_init(&q);
  q.used = a->used + 2;

  fp_init(&t1);
  fp_init(&t2);
  fp_init_copy(&x, a);
  fp_init_copy(&y, b);

  /* fix the sign */
  neg = (a->sign == b->sign) ? FP_ZPOS : FP_NEG;
  x.sign = y.sign = FP_ZPOS;

  /* normalize both x and y, ensure that y >= b/2, [b == 2**DIGIT_BIT] */
  norm = fp_count_bits(&y) % DIGIT_BIT;
  if (norm < (int)(DIGIT_BIT-1)) {
     norm = (DIGIT_BIT-1) - norm;
     fp_mul_2d (&x, norm, &x);
     fp_mul_2d (&y, norm, &y);
  } else {
     norm = 0;
  }

  /* note hac does 0 based, so if used==5 then its 0,1,2,3,4, e.g. use 4 */
  n = x.used - 1;
  t = y.used - 1;

  /* while (x >= y*b**n-t) do { q[n-t] += 1; x -= y*b**{n-t} } */
  fp_lshd (&y, n - t);                                             /* y = y*b**{n-t} */

  while (fp_cmp (&x, &y) != FP_LT) {
    ++(q.dp[n - t]);
    fp_sub (&x, &y, &x);
  }

  /* reset y by shifting it back down */
  fp_rshd (&y, n - t);

  /* step 3. for i from n down to (t + 1) */
  for (i = n; i >= (t + 1); i--) {
    if (i > x.used) {
      continue;
    }

    /* step 3.1 if xi == yt then set q{i-t-1} to b-1, 
     * otherwise set q{i-t-1} to (xi*b + x{i-1})/yt */
    if (x.dp[i] == y.dp[t]) {
      q.dp[i - t - 1] = ((((fp_word)1) << DIGIT_BIT) - 1);
    } else {
      fp_word tmp;
      tmp = ((fp_word) x.dp[i]) << ((fp_word) DIGIT_BIT);
      tmp |= ((fp_word) x.dp[i - 1]);
      tmp /= ((fp_word) y.dp[t]);
      q.dp[i - t - 1] = (fp_digit) (tmp);
    }

    /* while (q{i-t-1} * (yt * b + y{t-1})) > 
             xi * b**2 + xi-1 * b + xi-2 
     
       do q{i-t-1} -= 1; 
    */
    q.dp[i - t - 1] = (q.dp[i - t - 1] + 1);
    do {
      q.dp[i - t - 1] = (q.dp[i - t - 1] - 1);

      /* find left hand */
      fp_zero (&t1);
      t1.dp[0] = (t - 1 < 0) ? 0 : y.dp[t - 1];
      t1.dp[1] = y.dp[t];
      t1.used = 2;
      fp_mul_d (&t1, q.dp[i - t - 1], &t1);

      /* find right hand */
      t2.dp[0] = (i - 2 < 0) ? 0 : x.dp[i - 2];
      t2.dp[1] = (i - 1 < 0) ? 0 : x.dp[i - 1];
      t2.dp[2] = x.dp[i];
      t2.used = 3;
    } while (fp_cmp_mag(&t1, &t2) == FP_GT);

    /* step 3.3 x = x - q{i-t-1} * y * b**{i-t-1} */
    fp_mul_d (&y, q.dp[i - t - 1], &t1);
    fp_lshd  (&t1, i - t - 1);
    fp_sub   (&x, &t1, &x);

    /* if x < 0 then { x = x + y*b**{i-t-1}; q{i-t-1} -= 1; } */
    if (x.sign == FP_NEG) {
      fp_copy (&y, &t1);
      fp_lshd (&t1, i - t - 1);
      fp_add (&x, &t1, &x);
      q.dp[i - t - 1] = q.dp[i - t - 1] - 1;
    }
  }

  /* now q is the quotient and x is the remainder 
   * [which we have to normalize] 
   */
  
  /* get sign before writing to c */
  x.sign = x.used == 0 ? FP_ZPOS : a->sign;

  if (c != NULL) {
    fp_clamp (&q);
    fp_copy (&q, c);
    c->sign = neg;
  }

  if (d != NULL) {
    fp_div_2d (&x, norm, &x, NULL);

/* the following is a kludge, essentially we were seeing the right remainder but 
   with excess digits that should have been zero
 */
    for (i = b->used; i < x.used; i++) {
        x.dp[i] = 0;
    }
    fp_clamp(&x);
    fp_copy (&x, d);
  }

  return FP_OKAY;
}

/* $Source: /cvs/libtom/tomsfastmath/src/divide/fp_div.c,v $ */
/* $Revision: 1.1 $ */
/* $Date: 2006/12/31 21:25:53 $ */

/* End: fp_div.c */

/* Start: fp_div_2.c */
/* TomsFastMath, a fast ISO C bignum library.
 * 
 * This project is meant to fill in where LibTomMath
 * falls short.  That is speed ;-)
 *
 * This project is public domain and free for all purposes.
 * 
 * Tom St Denis, tomstdenis@gmail.com
 */
#include "bignum_fast.h"

/* b = a/2 */
void fp_div_2(fp_int * a, fp_int * b)
{
  int     x, oldused;

  oldused = b->used;
  b->used = a->used;
  {
    register fp_digit r, rr, *tmpa, *tmpb;

    /* source alias */
    tmpa = a->dp + b->used - 1;

    /* dest alias */
    tmpb = b->dp + b->used - 1;

    /* carry */
    r = 0;
    for (x = b->used - 1; x >= 0; x--) {
      /* get the carry for the next iteration */
      rr = *tmpa & 1;

      /* shift the current digit, add in carry and store */
      *tmpb-- = (*tmpa-- >> 1) | (r << (DIGIT_BIT - 1));

      /* forward carry to next iteration */
      r = rr;
    }

    /* zero excess digits */
    tmpb = b->dp + b->used;
    for (x = b->used; x < oldused; x++) {
      *tmpb++ = 0;
    }
  }
  b->sign = a->sign;
  fp_clamp (b);
}

/* $Source: /cvs/libtom/tomsfastmath/src/bit/fp_div_2.c,v $ */
/* $Revision: 1.1 $ */
/* $Date: 2006/12/31 21:25:53 $ */

/* End: fp_div_2.c */

/* Start: fp_div_2d.c */
/* TomsFastMath, a fast ISO C bignum library.
 * 
 * This project is meant to fill in where LibTomMath
 * falls short.  That is speed ;-)
 *
 * This project is public domain and free for all purposes.
 * 
 * Tom St Denis, tomstdenis@gmail.com
 */
#include "bignum_fast.h"

/* c = a / 2**b */
void fp_div_2d(fp_int *a, int b, fp_int *c, fp_int *d)
{
  fp_digit D, r, rr;
  int      x;
  fp_int   t;

  /* if the shift count is <= 0 then we do no work */
  if (b <= 0) {
    fp_copy (a, c);
    if (d != NULL) {
      fp_zero (d);
    }
    return;
  }

  fp_init(&t);

  /* get the remainder */
  if (d != NULL) {
    fp_mod_2d (a, b, &t);
  }

  /* copy */
  fp_copy(a, c);

  /* shift by as many digits in the bit count */
  if (b >= (int)DIGIT_BIT) {
    fp_rshd (c, b / DIGIT_BIT);
  }

  /* shift any bit count < DIGIT_BIT */
  D = (fp_digit) (b % DIGIT_BIT);
  if (D != 0) {
    register fp_digit *tmpc, mask, shift;

    /* mask */
    mask = (((fp_digit)1) << D) - 1;

    /* shift for lsb */
    shift = DIGIT_BIT - D;

    /* alias */
    tmpc = c->dp + (c->used - 1);

    /* carry */
    r = 0;
    for (x = c->used - 1; x >= 0; x--) {
      /* get the lower  bits of this word in a temp */
      rr = *tmpc & mask;

      /* shift the current word and mix in the carry bits from the previous word */
      *tmpc = (*tmpc >> D) | (r << shift);
      --tmpc;

      /* set the carry to the carry bits of the current word found above */
      r = rr;
    }
  }
  fp_clamp (c);
  if (d != NULL) {
    fp_copy (&t, d);
  }
}

/* $Source: /cvs/libtom/tomsfastmath/src/bit/fp_div_2d.c,v $ */
/* $Revision: 1.1 $ */
/* $Date: 2006/12/31 21:25:53 $ */

/* End: fp_div_2d.c */

/* Start: fp_div_d.c */
/* TomsFastMath, a fast ISO C bignum library.
 * 
 * This project is meant to fill in where LibTomMath
 * falls short.  That is speed ;-)
 *
 * This project is public domain and free for all purposes.
 * 
 * Tom St Denis, tomstdenis@gmail.com
 */
#include "bignum_fast.h"

static int s_is_power_of_two(fp_digit b, int *p)
{
   int x;

   /* fast return if no power of two */
   if ((b==0) || (b & (b-1))) {
      return 0;
   }

   for (x = 0; x < DIGIT_BIT; x++) {
      if (b == (((fp_digit)1)<<x)) {
         *p = x;
         return 1;
      }
   }
   return 0;
}

/* a/b => cb + d == a */
int fp_div_d(fp_int *a, fp_digit b, fp_int *c, fp_digit *d)
{
  fp_int   q;
  fp_word  w;
  fp_digit t;
  int      ix;

  /* cannot divide by zero */
  if (b == 0) {
     return FP_VAL;
  }

  /* quick outs */
  if (b == 1 || fp_iszero(a) == 1) {
     if (d != NULL) {
        *d = 0;
     }
     if (c != NULL) {
        fp_copy(a, c);
     }
     return FP_OKAY;
  }

  /* power of two ? */
  if (s_is_power_of_two(b, &ix) == 1) {
     if (d != NULL) {
        *d = a->dp[0] & ((((fp_digit)1)<<ix) - 1);
     }
     if (c != NULL) {
        fp_div_2d(a, ix, c, NULL);
     }
     return FP_OKAY;
  }

  /* no easy answer [c'est la vie].  Just division */
  fp_init(&q);
  
  q.used = a->used;
  q.sign = a->sign;
  w = 0;
  for (ix = a->used - 1; ix >= 0; ix--) {
     w = (w << ((fp_word)DIGIT_BIT)) | ((fp_word)a->dp[ix]);
     
     if (w >= b) {
        t = (fp_digit)(w / b);
        w -= ((fp_word)t) * ((fp_word)b);
      } else {
        t = 0;
      }
      q.dp[ix] = (fp_digit)t;
  }
  
  if (d != NULL) {
     *d = (fp_digit)w;
  }
  
  if (c != NULL) {
     fp_clamp(&q);
     fp_copy(&q, c);
  }
 
  return FP_OKAY;
}


/* $Source: /cvs/libtom/tomsfastmath/src/divide/fp_div_d.c,v $ */
/* $Revision: 1.2 $ */
/* $Date: 2007/01/12 15:13:54 $ */

/* End: fp_div_d.c */

/* Start: fp_exptmod.c */
/* TomsFastMath, a fast ISO C bignum library.
 * 
 * This project is meant to fill in where LibTomMath
 * falls short.  That is speed ;-)
 *
 * This project is public domain and free for all purposes.
 * 
 * Tom St Denis, tomstdenis@gmail.com
 */
#include "bignum_fast.h"

#ifdef TFM_TIMING_RESISTANT

/* timing resistant montgomery ladder based exptmod 

   Based on work by Marc Joye, Sung-Ming Yen, "The Montgomery Powering Ladder", Cryptographic Hardware and Embedded Systems, CHES 2002
*/
static int _fp_exptmod(fp_int * G, fp_int * X, fp_int * P, fp_int * Y)
{
  fp_int   R[2];
  fp_digit buf, mp;
  int      err, bitcnt, digidx, y;

  /* now setup montgomery  */
  if ((err = fp_montgomery_setup (P, &mp)) != FP_OKAY) {
     return err;
  }

  fp_init(&R[0]);   
  fp_init(&R[1]);   
   
  /* now we need R mod m */
  fp_montgomery_calc_normalization (&R[0], P);

  /* now set R[0][1] to G * R mod m */
  if (fp_cmp_mag(P, G) != FP_GT) {
     /* G > P so we reduce it first */
     fp_mod(G, P, &R[1]);
  } else {
     fp_copy(G, &R[1]);
  }
  fp_mulmod (&R[1], &R[0], P, &R[1]);

  /* for j = t-1 downto 0 do
        r_!k = R0*R1; r_k = r_k^2
  */
  
  /* set initial mode and bit cnt */
  bitcnt = 1;
  buf    = 0;
  digidx = X->used - 1;

  for (;;) {
    /* grab next digit as required */
    if (--bitcnt == 0) {
      /* if digidx == -1 we are out of digits so break */
      if (digidx == -1) {
        break;
      }
      /* read next digit and reset bitcnt */
      buf    = X->dp[digidx--];
      bitcnt = (int)DIGIT_BIT;
    }

    /* grab the next msb from the exponent */
    y     = (fp_digit)(buf >> (DIGIT_BIT - 1)) & 1;
    buf <<= (fp_digit)1;

    /* do ops */
    fp_mul(&R[0], &R[1], &R[y^1]); fp_montgomery_reduce(&R[y^1], P, mp);
    fp_sqr(&R[y], &R[y]);          fp_montgomery_reduce(&R[y], P, mp);
  }

   fp_montgomery_reduce(&R[0], P, mp);
   fp_copy(&R[0], Y);
   return FP_OKAY;
}   

#else

/* y = g**x (mod b) 
 * Some restrictions... x must be positive and < b
 */
static int _fp_exptmod(fp_int * G, fp_int * X, fp_int * P, fp_int * Y)
{
  fp_int   M[64], res;
  fp_digit buf, mp;
  int      err, bitbuf, bitcpy, bitcnt, mode, digidx, x, y, winsize;

  /* find window size */
  x = fp_count_bits (X);
  if (x <= 21) {
    winsize = 1;
  } else if (x <= 36) {
    winsize = 3;
  } else if (x <= 140) {
    winsize = 4;
  } else if (x <= 450) {
    winsize = 5;
  } else {
    winsize = 6;
  } 

  /* init M array */
  memset(M, 0, sizeof(M)); 

  /* now setup montgomery  */
  if ((err = fp_montgomery_setup (P, &mp)) != FP_OKAY) {
     return err;
  }

  /* setup result */
  fp_init(&res);

  /* create M table
   *
   * The M table contains powers of the input base, e.g. M[x] = G^x mod P
   *
   * The first half of the table is not computed though accept for M[0] and M[1]
   */

   /* now we need R mod m */
   fp_montgomery_calc_normalization (&res, P);

   /* now set M[1] to G * R mod m */
   if (fp_cmp_mag(P, G) != FP_GT) {
      /* G > P so we reduce it first */
      fp_mod(G, P, &M[1]);
   } else {
      fp_copy(G, &M[1]);
   }
   fp_mulmod (&M[1], &res, P, &M[1]);

  /* compute the value at M[1<<(winsize-1)] by squaring M[1] (winsize-1) times */
  fp_copy (&M[1], &M[1 << (winsize - 1)]);
  for (x = 0; x < (winsize - 1); x++) {
    fp_sqr (&M[1 << (winsize - 1)], &M[1 << (winsize - 1)]);
    fp_montgomery_reduce (&M[1 << (winsize - 1)], P, mp);
  }

  /* create upper table */
  for (x = (1 << (winsize - 1)) + 1; x < (1 << winsize); x++) {
    fp_mul(&M[x - 1], &M[1], &M[x]);
    fp_montgomery_reduce(&M[x], P, mp);
  }

  /* set initial mode and bit cnt */
  mode   = 0;
  bitcnt = 1;
  buf    = 0;
  digidx = X->used - 1;
  bitcpy = 0;
  bitbuf = 0;

  for (;;) {
    /* grab next digit as required */
    if (--bitcnt == 0) {
      /* if digidx == -1 we are out of digits so break */
      if (digidx == -1) {
        break;
      }
      /* read next digit and reset bitcnt */
      buf    = X->dp[digidx--];
      bitcnt = (int)DIGIT_BIT;
    }

    /* grab the next msb from the exponent */
    y     = (fp_digit)(buf >> (DIGIT_BIT - 1)) & 1;
    buf <<= (fp_digit)1;

    /* if the bit is zero and mode == 0 then we ignore it
     * These represent the leading zero bits before the first 1 bit
     * in the exponent.  Technically this opt is not required but it
     * does lower the # of trivial squaring/reductions used
     */
    if (mode == 0 && y == 0) {
      continue;
    }

    /* if the bit is zero and mode == 1 then we square */
    if (mode == 1 && y == 0) {
      fp_sqr(&res, &res);
      fp_montgomery_reduce(&res, P, mp);
      continue;
    }

    /* else we add it to the window */
    bitbuf |= (y << (winsize - ++bitcpy));
    mode    = 2;

    if (bitcpy == winsize) {
      /* ok window is filled so square as required and multiply  */
      /* square first */
      for (x = 0; x < winsize; x++) {
        fp_sqr(&res, &res);
        fp_montgomery_reduce(&res, P, mp);
      }

      /* then multiply */
      fp_mul(&res, &M[bitbuf], &res);
      fp_montgomery_reduce(&res, P, mp);

      /* empty window and reset */
      bitcpy = 0;
      bitbuf = 0;
      mode   = 1;
    }
  }

  /* if bits remain then square/multiply */
  if (mode == 2 && bitcpy > 0) {
    /* square then multiply if the bit is set */
    for (x = 0; x < bitcpy; x++) {
      fp_sqr(&res, &res);
      fp_montgomery_reduce(&res, P, mp);

      /* get next bit of the window */
      bitbuf <<= 1;
      if ((bitbuf & (1 << winsize)) != 0) {
        /* then multiply */
        fp_mul(&res, &M[1], &res);
        fp_montgomery_reduce(&res, P, mp);
      }
    }
  }

  /* fixup result if Montgomery reduction is used
   * recall that any value in a Montgomery system is
   * actually multiplied by R mod n.  So we have
   * to reduce one more time to cancel out the factor
   * of R.
   */
  fp_montgomery_reduce(&res, P, mp);

  /* swap res with Y */
  fp_copy (&res, Y);
  return FP_OKAY;
}

#endif


int fp_exptmod(fp_int * G, fp_int * X, fp_int * P, fp_int * Y)
{
   fp_int tmp;
   int    err;
#define TFM_CHECK
#ifdef TFM_CHECK
   /* prevent overflows */
   if (P->used > (FP_SIZE/2)) {
      return FP_VAL;
   }
#endif

   /* is X negative?  */
   if (X->sign == FP_NEG) {
      /* yes, copy G and invmod it */
      fp_copy(G, &tmp);
      if ((err = fp_invmod(&tmp, P, &tmp)) != FP_OKAY) {
         return err;
      }
      X->sign = FP_ZPOS;
      err =  _fp_exptmod(&tmp, X, P, Y);
      if (X != Y) {
         X->sign = FP_NEG;
      }
      return err;
   } else {
      /* Positive exponent so just exptmod */
      return _fp_exptmod(G, X, P, Y);
   }
}

/* $Source: /cvs/libtom/tomsfastmath/src/exptmod/fp_exptmod.c,v $ */
/* $Revision: 1.1 $ */
/* $Date: 2006/12/31 21:25:53 $ */

/* End: fp_exptmod.c */

/* Start: fp_gcd.c */
/* TomsFastMath, a fast ISO C bignum library.
 * 
 * This project is meant to fill in where LibTomMath
 * falls short.  That is speed ;-)
 *
 * This project is public domain and free for all purposes.
 * 
 * Tom St Denis, tomstdenis@gmail.com
 */
#include "bignum_fast.h"

/* c = (a, b) */
void fp_gcd(fp_int *a, fp_int *b, fp_int *c)
{
   fp_int u, v, r;

   /* either zero than gcd is the largest */
   if (fp_iszero (a) == 1 && fp_iszero (b) == 0) {
     fp_abs (b, c);
     return;
   }
   if (fp_iszero (a) == 0 && fp_iszero (b) == 1) {
     fp_abs (a, c);
     return;
   }

   /* optimized.  At this point if a == 0 then
    * b must equal zero too
    */
   if (fp_iszero (a) == 1) {
     fp_zero(c);
     return;
   }

   /* sort inputs */
   if (fp_cmp_mag(a, b) != FP_LT) {
      fp_init_copy(&u, a);
      fp_init_copy(&v, b);
   } else {
      fp_init_copy(&u, b);
      fp_init_copy(&v, a);
   }
 
   fp_zero(&r);
   while (fp_iszero(&v) == FP_NO) {
      fp_mod(&u, &v, &r);
      fp_copy(&v, &u);
      fp_copy(&r, &v);
   }
   fp_copy(&u, c);
}

/* $Source: /cvs/libtom/tomsfastmath/src/numtheory/fp_gcd.c,v $ */
/* $Revision: 1.1 $ */
/* $Date: 2007/01/24 21:25:19 $ */

/* End: fp_gcd.c */

/* Start: fp_ident.c */
/* TomsFastMath, a fast ISO C bignum library.
 * 
 * This project is meant to fill in where LibTomMath
 * falls short.  That is speed ;-)
 *
 * This project is public domain and free for all purposes.
 * 
 * Tom St Denis, tomstdenis@gmail.com
 */
#include "bignum_fast.h"

const char *fp_ident(void)
{
   static char buf[1024];

   memset(buf, 0, sizeof(buf));
   snprintf(buf, sizeof(buf)-1,
"TomsFastMath (%s)\n"
"\n"
"Sizeofs\n"
"\tfp_digit = %u\n"
"\tfp_word  = %u\n"
"\n"
"FP_MAX_SIZE = %u\n"
"\n"
"Defines: \n"
#ifdef __i386__
" __i386__ "
#endif
#ifdef __x86_64__
" __x86_64__ "
#endif
#ifdef TFM_X86
" TFM_X86 "
#endif
#ifdef TFM_X86_64
" TFM_X86_64 "
#endif
#ifdef TFM_SSE2
" TFM_SSE2 "
#endif
#ifdef TFM_ARM
" TFM_ARM "
#endif
#ifdef TFM_PPC32
" TFM_PPC32 "
#endif
#ifdef TFM_AVR32
" TFM_AVR32 "
#endif
#ifdef TFM_ECC192
" TFM_ECC192 "
#endif
#ifdef TFM_ECC224
" TFM_ECC224 "
#endif
#ifdef TFM_ECC384
" TFM_ECC384 "
#endif
#ifdef TFM_ECC521
" TFM_ECC521 "
#endif

#ifdef TFM_NO_ASM
" TFM_NO_ASM "
#endif
#ifdef FP_64BIT
" FP_64BIT "
#endif
#ifdef TFM_HUGE
" TFM_HUGE "
#endif
"\n", __DATE__, sizeof(fp_digit), sizeof(fp_word), FP_MAX_SIZE);

   if (sizeof(fp_digit) == sizeof(fp_word)) {
      strncat(buf, "WARNING: sizeof(fp_digit) == sizeof(fp_word), this build is likely to not work properly.\n", 
              sizeof(buf)-1);
   }
   return buf;
}

#ifdef STANDALONE

int main(void)
{
   printf("%s\n", fp_ident());
   return 0;
}

#endif


/* $Source: /cvs/libtom/tomsfastmath/src/misc/fp_ident.c,v $ */
/* $Revision: 1.1 $ */
/* $Date: 2006/12/31 21:25:53 $ */

/* End: fp_ident.c */

/* Start: fp_invmod.c */
/* TomsFastMath, a fast ISO C bignum library.
 * 
 * This project is meant to fill in where LibTomMath
 * falls short.  That is speed ;-)
 *
 * This project is public domain and free for all purposes.
 * 
 * Tom St Denis, tomstdenis@gmail.com
 */
#include "bignum_fast.h"

static int fp_invmod_slow (fp_int * a, fp_int * b, fp_int * c)
{
  fp_int  x, y, u, v, A, B, C, D;
  int     res;

  /* b cannot be negative */
  if (b->sign == FP_NEG || fp_iszero(b) == 1) {
    return FP_VAL;
  }

  /* init temps */
  fp_init(&x);    fp_init(&y);
  fp_init(&u);    fp_init(&v);
  fp_init(&A);    fp_init(&B);
  fp_init(&C);    fp_init(&D);

  /* x = a, y = b */
  if ((res = fp_mod(a, b, &x)) != FP_OKAY) {
      return res;
  }
  fp_copy(b, &y);

  /* 2. [modified] if x,y are both even then return an error! */
  if (fp_iseven (&x) == 1 && fp_iseven (&y) == 1) {
    return FP_VAL;
  }

  /* 3. u=x, v=y, A=1, B=0, C=0,D=1 */
  fp_copy (&x, &u);
  fp_copy (&y, &v);
  fp_set (&A, 1);
  fp_set (&D, 1);

top:
  /* 4.  while u is even do */
  while (fp_iseven (&u) == 1) {
    /* 4.1 u = u/2 */
    fp_div_2 (&u, &u);

    /* 4.2 if A or B is odd then */
    if (fp_isodd (&A) == 1 || fp_isodd (&B) == 1) {
      /* A = (A+y)/2, B = (B-x)/2 */
      fp_add (&A, &y, &A);
      fp_sub (&B, &x, &B);
    }
    /* A = A/2, B = B/2 */
    fp_div_2 (&A, &A);
    fp_div_2 (&B, &B);
  }

  /* 5.  while v is even do */
  while (fp_iseven (&v) == 1) {
    /* 5.1 v = v/2 */
    fp_div_2 (&v, &v);

    /* 5.2 if C or D is odd then */
    if (fp_isodd (&C) == 1 || fp_isodd (&D) == 1) {
      /* C = (C+y)/2, D = (D-x)/2 */
      fp_add (&C, &y, &C);
      fp_sub (&D, &x, &D);
    }
    /* C = C/2, D = D/2 */
    fp_div_2 (&C, &C);
    fp_div_2 (&D, &D);
  }

  /* 6.  if u >= v then */
  if (fp_cmp (&u, &v) != FP_LT) {
    /* u = u - v, A = A - C, B = B - D */
    fp_sub (&u, &v, &u);
    fp_sub (&A, &C, &A);
    fp_sub (&B, &D, &B);
  } else {
    /* v - v - u, C = C - A, D = D - B */
    fp_sub (&v, &u, &v);
    fp_sub (&C, &A, &C);
    fp_sub (&D, &B, &D);
  }

  /* if not zero goto step 4 */
  if (fp_iszero (&u) == 0)
    goto top;

  /* now a = C, b = D, gcd == g*v */

  /* if v != 1 then there is no inverse */
  if (fp_cmp_d (&v, 1) != FP_EQ) {
    return FP_VAL;
  }

  /* if its too low */
  while (fp_cmp_d(&C, 0) == FP_LT) {
      fp_add(&C, b, &C);
  }
  
  /* too big */
  while (fp_cmp_mag(&C, b) != FP_LT) {
      fp_sub(&C, b, &C);
  }
  
  /* C is now the inverse */
  fp_copy(&C, c);
  return FP_OKAY;
}

/* c = 1/a (mod b) for odd b only */
int fp_invmod(fp_int *a, fp_int *b, fp_int *c)
{
  fp_int  x, y, u, v, B, D;
  int     neg;

  /* 2. [modified] b must be odd   */
  if (fp_iseven (b) == FP_YES) {
    return fp_invmod_slow(a,b,c);
  }

  /* init all our temps */
  fp_init(&x);  fp_init(&y);
  fp_init(&u);  fp_init(&v);
  fp_init(&B);  fp_init(&D);

  /* x == modulus, y == value to invert */
  fp_copy(b, &x);

  /* we need y = |a| */
  fp_abs(a, &y);

  /* 3. u=x, v=y, A=1, B=0, C=0,D=1 */
  fp_copy(&x, &u);
  fp_copy(&y, &v);
  fp_set (&D, 1);

top:
  /* 4.  while u is even do */
  while (fp_iseven (&u) == FP_YES) {
    /* 4.1 u = u/2 */
    fp_div_2 (&u, &u);

    /* 4.2 if B is odd then */
    if (fp_isodd (&B) == FP_YES) {
      fp_sub (&B, &x, &B);
    }
    /* B = B/2 */
    fp_div_2 (&B, &B);
  }

  /* 5.  while v is even do */
  while (fp_iseven (&v) == FP_YES) {
    /* 5.1 v = v/2 */
    fp_div_2 (&v, &v);

    /* 5.2 if D is odd then */
    if (fp_isodd (&D) == FP_YES) {
      /* D = (D-x)/2 */
      fp_sub (&D, &x, &D);
    }
    /* D = D/2 */
    fp_div_2 (&D, &D);
  }

  /* 6.  if u >= v then */
  if (fp_cmp (&u, &v) != FP_LT) {
    /* u = u - v, B = B - D */
    fp_sub (&u, &v, &u);
    fp_sub (&B, &D, &B);
  } else {
    /* v - v - u, D = D - B */
    fp_sub (&v, &u, &v);
    fp_sub (&D, &B, &D);
  }

  /* if not zero goto step 4 */
  if (fp_iszero (&u) == FP_NO) {
    goto top;
  }

  /* now a = C, b = D, gcd == g*v */

  /* if v != 1 then there is no inverse */
  if (fp_cmp_d (&v, 1) != FP_EQ) {
    return FP_VAL;
  }

  /* b is now the inverse */
  neg = a->sign;
  while (D.sign == FP_NEG) {
    fp_add (&D, b, &D);
  }
  fp_copy (&D, c);
  c->sign = neg;
  return FP_OKAY;
}

/* $Source: /cvs/libtom/tomsfastmath/src/numtheory/fp_invmod.c,v $ */
/* $Revision: 1.1 $ */
/* $Date: 2007/01/24 21:25:19 $ */

/* End: fp_invmod.c */

/* Start: fp_isprime.c */
/* TomsFastMath, a fast ISO C bignum library.
 * 
 * This project is meant to fill in where LibTomMath
 * falls short.  That is speed ;-)
 *
 * This project is public domain and free for all purposes.
 * 
 * Tom St Denis, tomstdenis@gmail.com
 */
#include "bignum_fast.h"

/* a few primes */
static const fp_digit primes[256] = {
  0x0002, 0x0003, 0x0005, 0x0007, 0x000B, 0x000D, 0x0011, 0x0013,
  0x0017, 0x001D, 0x001F, 0x0025, 0x0029, 0x002B, 0x002F, 0x0035,
  0x003B, 0x003D, 0x0043, 0x0047, 0x0049, 0x004F, 0x0053, 0x0059,
  0x0061, 0x0065, 0x0067, 0x006B, 0x006D, 0x0071, 0x007F, 0x0083,
  0x0089, 0x008B, 0x0095, 0x0097, 0x009D, 0x00A3, 0x00A7, 0x00AD,
  0x00B3, 0x00B5, 0x00BF, 0x00C1, 0x00C5, 0x00C7, 0x00D3, 0x00DF,
  0x00E3, 0x00E5, 0x00E9, 0x00EF, 0x00F1, 0x00FB, 0x0101, 0x0107,
  0x010D, 0x010F, 0x0115, 0x0119, 0x011B, 0x0125, 0x0133, 0x0137,

  0x0139, 0x013D, 0x014B, 0x0151, 0x015B, 0x015D, 0x0161, 0x0167,
  0x016F, 0x0175, 0x017B, 0x017F, 0x0185, 0x018D, 0x0191, 0x0199,
  0x01A3, 0x01A5, 0x01AF, 0x01B1, 0x01B7, 0x01BB, 0x01C1, 0x01C9,
  0x01CD, 0x01CF, 0x01D3, 0x01DF, 0x01E7, 0x01EB, 0x01F3, 0x01F7,
  0x01FD, 0x0209, 0x020B, 0x021D, 0x0223, 0x022D, 0x0233, 0x0239,
  0x023B, 0x0241, 0x024B, 0x0251, 0x0257, 0x0259, 0x025F, 0x0265,
  0x0269, 0x026B, 0x0277, 0x0281, 0x0283, 0x0287, 0x028D, 0x0293,
  0x0295, 0x02A1, 0x02A5, 0x02AB, 0x02B3, 0x02BD, 0x02C5, 0x02CF,

  0x02D7, 0x02DD, 0x02E3, 0x02E7, 0x02EF, 0x02F5, 0x02F9, 0x0301,
  0x0305, 0x0313, 0x031D, 0x0329, 0x032B, 0x0335, 0x0337, 0x033B,
  0x033D, 0x0347, 0x0355, 0x0359, 0x035B, 0x035F, 0x036D, 0x0371,
  0x0373, 0x0377, 0x038B, 0x038F, 0x0397, 0x03A1, 0x03A9, 0x03AD,
  0x03B3, 0x03B9, 0x03C7, 0x03CB, 0x03D1, 0x03D7, 0x03DF, 0x03E5,
  0x03F1, 0x03F5, 0x03FB, 0x03FD, 0x0407, 0x0409, 0x040F, 0x0419,
  0x041B, 0x0425, 0x0427, 0x042D, 0x043F, 0x0443, 0x0445, 0x0449,
  0x044F, 0x0455, 0x045D, 0x0463, 0x0469, 0x047F, 0x0481, 0x048B,

  0x0493, 0x049D, 0x04A3, 0x04A9, 0x04B1, 0x04BD, 0x04C1, 0x04C7,
  0x04CD, 0x04CF, 0x04D5, 0x04E1, 0x04EB, 0x04FD, 0x04FF, 0x0503,
  0x0509, 0x050B, 0x0511, 0x0515, 0x0517, 0x051B, 0x0527, 0x0529,
  0x052F, 0x0551, 0x0557, 0x055D, 0x0565, 0x0577, 0x0581, 0x058F,
  0x0593, 0x0595, 0x0599, 0x059F, 0x05A7, 0x05AB, 0x05AD, 0x05B3,
  0x05BF, 0x05C9, 0x05CB, 0x05CF, 0x05D1, 0x05D5, 0x05DB, 0x05E7,
  0x05F3, 0x05FB, 0x0607, 0x060D, 0x0611, 0x0617, 0x061F, 0x0623,
  0x062B, 0x062F, 0x063D, 0x0641, 0x0647, 0x0649, 0x064D, 0x0653
};

int fp_isprime(fp_int *a)
{
   fp_int   b;
   fp_digit d;
   int      r, res;

   /* do trial division */
   for (r = 0; r < 256; r++) {
       fp_mod_d(a, primes[r], &d);
       if (d == 0) {
          return FP_NO;
       }
   }

   /* now do 8 miller rabins */
   fp_init(&b);
   for (r = 0; r < 8; r++) {
       fp_set(&b, primes[r]);
       fp_prime_miller_rabin(a, &b, &res);
       if (res == FP_NO) {
          return FP_NO;
       }
   }
   return FP_YES;
}

/* $Source: /cvs/libtom/tomsfastmath/src/numtheory/fp_isprime.c,v $ */
/* $Revision: 1.1 $ */
/* $Date: 2007/01/24 21:25:19 $ */

/* End: fp_isprime.c */

/* Start: fp_lcm.c */
/* TomsFastMath, a fast ISO C bignum library.
 * 
 * This project is meant to fill in where LibTomMath
 * falls short.  That is speed ;-)
 *
 * This project is public domain and free for all purposes.
 * 
 * Tom St Denis, tomstdenis@gmail.com
 */
#include "bignum_fast.h"

/* c = [a, b] */
void fp_lcm(fp_int *a, fp_int *b, fp_int *c)
{
   fp_int  t1, t2;

   fp_init(&t1);
   fp_init(&t2);
   fp_gcd(a, b, &t1);
   if (fp_cmp_mag(a, b) == FP_GT) {
      fp_div(a, &t1, &t2, NULL);
      fp_mul(b, &t2, c);
   } else {
      fp_div(b, &t1, &t2, NULL);
      fp_mul(a, &t2, c);
   }   
}

/* $Source: /cvs/libtom/tomsfastmath/src/numtheory/fp_lcm.c,v $ */
/* $Revision: 1.1 $ */
/* $Date: 2007/01/24 21:25:19 $ */

/* End: fp_lcm.c */

/* Start: fp_lshd.c */
/* TomsFastMath, a fast ISO C bignum library.
 * 
 * This project is meant to fill in where LibTomMath
 * falls short.  That is speed ;-)
 *
 * This project is public domain and free for all purposes.
 * 
 * Tom St Denis, tomstdenis@gmail.com
 */
#include "bignum_fast.h"

void fp_lshd(fp_int *a, int x)
{
   int y;

   /* move up and truncate as required */
   y = MIN(a->used + x - 1, (int)(FP_SIZE-1));

   /* store new size */
   a->used = y + 1;

   /* move digits */
   for (; y >= x; y--) {
       a->dp[y] = a->dp[y-x];
   }
 
   /* zero lower digits */
   for (; y >= 0; y--) {
       a->dp[y] = 0;
   }

   /* clamp digits */
   fp_clamp(a);
}

/* $Source: /cvs/libtom/tomsfastmath/src/bit/fp_lshd.c,v $ */
/* $Revision: 1.1 $ */
/* $Date: 2006/12/31 21:25:53 $ */

/* End: fp_lshd.c */

/* Start: fp_mod.c */
/* TomsFastMath, a fast ISO C bignum library.
 * 
 * This project is meant to fill in where LibTomMath
 * falls short.  That is speed ;-)
 *
 * This project is public domain and free for all purposes.
 * 
 * Tom St Denis, tomstdenis@gmail.com
 */
#include "bignum_fast.h"

/* c = a mod b, 0 <= c < b  */
int fp_mod(fp_int *a, fp_int *b, fp_int *c)
{
   fp_int t;
   int    err;

   fp_zero(&t);
   if ((err = fp_div(a, b, NULL, &t)) != FP_OKAY) {
      return err;
   }
   if (t.sign != b->sign) {
      fp_add(&t, b, c);
   } else {
      fp_copy(&t, c);
  }
  return FP_OKAY;
}



/* $Source: /cvs/libtom/tomsfastmath/src/divide/fp_mod.c,v $ */
/* $Revision: 1.1 $ */
/* $Date: 2006/12/31 21:25:53 $ */

/* End: fp_mod.c */

/* Start: fp_mod_2d.c */
/* TomsFastMath, a fast ISO C bignum library.
 * 
 * This project is meant to fill in where LibTomMath
 * falls short.  That is speed ;-)
 *
 * This project is public domain and free for all purposes.
 * 
 * Tom St Denis, tomstdenis@gmail.com
 */
#include "bignum_fast.h"

/* c = a mod 2**d */
void fp_mod_2d(fp_int *a, int b, fp_int *c)
{
   int x;

   /* zero if count less than or equal to zero */
   if (b <= 0) {
      fp_zero(c);
      return;
   }

   /* get copy of input */
   fp_copy(a, c);
 
   /* if 2**d is larger than we just return */
   if (b >= (DIGIT_BIT * a->used)) {
      return;
   }

  /* zero digits above the last digit of the modulus */
  for (x = (b / DIGIT_BIT) + ((b % DIGIT_BIT) == 0 ? 0 : 1); x < c->used; x++) {
    c->dp[x] = 0;
  }
  /* clear the digit that is not completely outside/inside the modulus */
  c->dp[b / DIGIT_BIT] &= ~((fp_digit)0) >> (DIGIT_BIT - b);
  fp_clamp (c);
}

/* $Source: /cvs/libtom/tomsfastmath/src/bit/fp_mod_2d.c,v $ */
/* $Revision: 1.1 $ */
/* $Date: 2006/12/31 21:25:53 $ */

/* End: fp_mod_2d.c */

/* Start: fp_mod_d.c */
/* TomsFastMath, a fast ISO C bignum library.
 * 
 * This project is meant to fill in where LibTomMath
 * falls short.  That is speed ;-)
 *
 * This project is public domain and free for all purposes.
 * 
 * Tom St Denis, tomstdenis@gmail.com
 */
#include "bignum_fast.h"

/* c = a mod b, 0 <= c < b  */
int fp_mod_d(fp_int *a, fp_digit b, fp_digit *c)
{
   return fp_div_d(a, b, NULL, c);
}

/* $Source: /cvs/libtom/tomsfastmath/src/divide/fp_mod_d.c,v $ */
/* $Revision: 1.1 $ */
/* $Date: 2006/12/31 21:25:53 $ */

/* End: fp_mod_d.c */

/* Start: fp_montgomery_calc_normalization.c */
/* TomsFastMath, a fast ISO C bignum library.
 * 
 * This project is meant to fill in where LibTomMath
 * falls short.  That is speed ;-)
 *
 * This project is public domain and free for all purposes.
 * 
 * Tom St Denis, tomstdenis@gmail.com
 */
#include "bignum_fast.h"

/* computes a = B**n mod b without division or multiplication useful for
 * normalizing numbers in a Montgomery system.
 */
void fp_montgomery_calc_normalization(fp_int *a, fp_int *b)
{
  int     x, bits;

  /* how many bits of last digit does b use */
  bits = fp_count_bits (b) % DIGIT_BIT;
  if (!bits) bits = DIGIT_BIT;

  /* compute A = B^(n-1) * 2^(bits-1) */
  if (b->used > 1) {
     fp_2expt (a, (b->used - 1) * DIGIT_BIT + bits - 1);
  } else {
     fp_set(a, 1);
     bits = 1;
  }

  /* now compute C = A * B mod b */
  for (x = bits - 1; x < (int)DIGIT_BIT; x++) {
    fp_mul_2 (a, a);
    if (fp_cmp_mag (a, b) != FP_LT) {
      s_fp_sub (a, b, a);
    }
  }
}


/* $Source: /cvs/libtom/tomsfastmath/src/mont/fp_montgomery_calc_normalization.c,v $ */
/* $Revision: 1.1 $ */
/* $Date: 2006/12/31 21:25:53 $ */

/* End: fp_montgomery_calc_normalization.c */

/* Start: fp_montgomery_reduce.c */
/* TomsFastMath, a fast ISO C bignum library.
 * 
 * This project is meant to fill in where LibTomMath
 * falls short.  That is speed ;-)
 *
 * This project is public domain and free for all purposes.
 * 
 * Tom St Denis, tomstdenis@gmail.com
 */
#include "bignum_fast.h"

/******************************************************************/
#if defined(TFM_X86) && !defined(TFM_SSE2) 
/* x86-32 code */

#define MONT_START 
#define MONT_FINI
#define LOOP_END
#define LOOP_START \
   mu = c[x] * mp

#define INNERMUL                                          \
asm(                                                      \
   "movl %5,%%eax \n\t"                                   \
   "mull %4       \n\t"                                   \
   "addl %1,%%eax \n\t"                                   \
   "adcl $0,%%edx \n\t"                                   \
   "addl %%eax,%0 \n\t"                                   \
   "adcl $0,%%edx \n\t"                                   \
   "movl %%edx,%1 \n\t"                                   \
:"=g"(_c[LO]), "=r"(cy)                                   \
:"0"(_c[LO]), "1"(cy), "g"(mu), "g"(*tmpm++)              \
: "%eax", "%edx", "%cc")

#define PROPCARRY                           \
asm(                                        \
   "addl   %1,%0    \n\t"                   \
   "setb   %%al     \n\t"                   \
   "movzbl %%al,%1 \n\t"                    \
:"=g"(_c[LO]), "=r"(cy)                     \
:"0"(_c[LO]), "1"(cy)                       \
: "%eax", "%cc")

/******************************************************************/
#elif defined(TFM_X86_64)
/* x86-64 code */
#define MONT_START 
#define MONT_FINI
#define LOOP_END
#define LOOP_START \
   mu = c[x] * mp

#define INNERMUL                                          \
asm(                                                      \
   "movq %5,%%rax \n\t"                                   \
   "mulq %4       \n\t"                                   \
   "addq %1,%%rax \n\t"                                   \
   "adcq $0,%%rdx \n\t"                                   \
   "addq %%rax,%0 \n\t"                                   \
   "adcq $0,%%rdx \n\t"                                   \
   "movq %%rdx,%1 \n\t"                                   \
:"=g"(_c[LO]), "=r"(cy)                                   \
:"0"(_c[LO]), "1"(cy), "r"(mu), "r"(*tmpm++)              \
: "%rax", "%rdx", "%cc")

#define INNERMUL8 \
 asm(                  \
 "movq 0(%5),%%rax    \n\t"  \
 "movq 0(%2),%%r10    \n\t"  \
 "movq 0x8(%5),%%r11  \n\t"  \
 "mulq %4             \n\t"  \
 "addq %%r10,%%rax    \n\t"  \
 "adcq $0,%%rdx       \n\t"  \
 "movq 0x8(%2),%%r10  \n\t"  \
 "addq %3,%%rax       \n\t"  \
 "adcq $0,%%rdx       \n\t"  \
 "movq %%rax,0(%0)    \n\t"  \
 "movq %%rdx,%1       \n\t"  \
 \
 "movq %%r11,%%rax    \n\t"  \
 "movq 0x10(%5),%%r11 \n\t"  \
 "mulq %4             \n\t"  \
 "addq %%r10,%%rax    \n\t"  \
 "adcq $0,%%rdx       \n\t"  \
 "movq 0x10(%2),%%r10 \n\t"  \
 "addq %3,%%rax       \n\t"  \
 "adcq $0,%%rdx       \n\t"  \
 "movq %%rax,0x8(%0)  \n\t"  \
 "movq %%rdx,%1       \n\t"  \
 \
 "movq %%r11,%%rax    \n\t"  \
 "movq 0x18(%5),%%r11 \n\t"  \
 "mulq %4             \n\t"  \
 "addq %%r10,%%rax    \n\t"  \
 "adcq $0,%%rdx       \n\t"  \
 "movq 0x18(%2),%%r10 \n\t"  \
 "addq %3,%%rax       \n\t"  \
 "adcq $0,%%rdx       \n\t"  \
 "movq %%rax,0x10(%0) \n\t"  \
 "movq %%rdx,%1       \n\t"  \
 \
 "movq %%r11,%%rax    \n\t"  \
 "movq 0x20(%5),%%r11 \n\t"  \
 "mulq %4             \n\t"  \
 "addq %%r10,%%rax    \n\t"  \
 "adcq $0,%%rdx       \n\t"  \
 "movq 0x20(%2),%%r10 \n\t"  \
 "addq %3,%%rax       \n\t"  \
 "adcq $0,%%rdx       \n\t"  \
 "movq %%rax,0x18(%0) \n\t"  \
 "movq %%rdx,%1       \n\t"  \
 \
 "movq %%r11,%%rax    \n\t"  \
 "movq 0x28(%5),%%r11 \n\t"  \
 "mulq %4             \n\t"  \
 "addq %%r10,%%rax    \n\t"  \
 "adcq $0,%%rdx       \n\t"  \
 "movq 0x28(%2),%%r10 \n\t"  \
 "addq %3,%%rax       \n\t"  \
 "adcq $0,%%rdx       \n\t"  \
 "movq %%rax,0x20(%0) \n\t"  \
 "movq %%rdx,%1       \n\t"  \
 \
 "movq %%r11,%%rax    \n\t"  \
 "movq 0x30(%5),%%r11 \n\t"  \
 "mulq %4             \n\t"  \
 "addq %%r10,%%rax    \n\t"  \
 "adcq $0,%%rdx       \n\t"  \
 "movq 0x30(%2),%%r10 \n\t"  \
 "addq %3,%%rax       \n\t"  \
 "adcq $0,%%rdx       \n\t"  \
 "movq %%rax,0x28(%0) \n\t"  \
 "movq %%rdx,%1       \n\t"  \
 \
 "movq %%r11,%%rax    \n\t"  \
 "movq 0x38(%5),%%r11 \n\t"  \
 "mulq %4             \n\t"  \
 "addq %%r10,%%rax    \n\t"  \
 "adcq $0,%%rdx       \n\t"  \
 "movq 0x38(%2),%%r10 \n\t"  \
 "addq %3,%%rax       \n\t"  \
 "adcq $0,%%rdx       \n\t"  \
 "movq %%rax,0x30(%0) \n\t"  \
 "movq %%rdx,%1       \n\t"  \
 \
 "movq %%r11,%%rax    \n\t"  \
 "mulq %4             \n\t"  \
 "addq %%r10,%%rax    \n\t"  \
 "adcq $0,%%rdx       \n\t"  \
 "addq %3,%%rax       \n\t"  \
 "adcq $0,%%rdx       \n\t"  \
 "movq %%rax,0x38(%0) \n\t"  \
 "movq %%rdx,%1       \n\t"  \
 \
:"=r"(_c), "=r"(cy)                    \
: "0"(_c),  "1"(cy), "g"(mu), "r"(tmpm)\
: "%rax", "%rdx", "%r10", "%r11", "%cc")


#define PROPCARRY                           \
asm(                                        \
   "addq   %1,%0    \n\t"                   \
   "setb   %%al     \n\t"                   \
   "movzbq %%al,%1 \n\t"                    \
:"=g"(_c[LO]), "=r"(cy)                     \
:"0"(_c[LO]), "1"(cy)                       \
: "%rax", "%cc")

/******************************************************************/
#elif defined(TFM_SSE2)  
/* SSE2 code (assumes 32-bit fp_digits) */
/* XMM register assignments:
 * xmm0  *tmpm++, then Mu * (*tmpm++)
 * xmm1  c[x], then Mu
 * xmm2  mp
 * xmm3  cy
 * xmm4  _c[LO]
 */

#define MONT_START \
   asm("movd %0,%%mm2"::"g"(mp))

#define MONT_FINI \
   asm("emms")

#define LOOP_START          \
asm(                        \
"movd %0,%%mm1        \n\t" \
"pxor %%mm3,%%mm3     \n\t" \
"pmuludq %%mm2,%%mm1  \n\t" \
:: "g"(c[x]))

/* pmuludq on mmx registers does a 32x32->64 multiply. */
#define INNERMUL               \
asm(                           \
   "movd %1,%%mm4        \n\t" \
   "movd %2,%%mm0        \n\t" \
   "paddq %%mm4,%%mm3    \n\t" \
   "pmuludq %%mm1,%%mm0  \n\t" \
   "paddq %%mm0,%%mm3    \n\t" \
   "movd %%mm3,%0        \n\t" \
   "psrlq $32, %%mm3     \n\t" \
:"=g"(_c[LO]) : "0"(_c[LO]), "g"(*tmpm++) );

#define INNERMUL8 \
asm(                           \
   "movd 0(%1),%%mm4     \n\t" \
   "movd 0(%2),%%mm0     \n\t" \
   "paddq %%mm4,%%mm3    \n\t" \
   "pmuludq %%mm1,%%mm0  \n\t" \
   "movd 4(%2),%%mm5     \n\t" \
   "paddq %%mm0,%%mm3    \n\t" \
   "movd 4(%1),%%mm6     \n\t" \
   "movd %%mm3,0(%0)     \n\t" \
   "psrlq $32, %%mm3     \n\t" \
\
   "paddq %%mm6,%%mm3    \n\t" \
   "pmuludq %%mm1,%%mm5  \n\t" \
   "movd 8(%2),%%mm6     \n\t" \
   "paddq %%mm5,%%mm3    \n\t" \
   "movd 8(%1),%%mm7     \n\t" \
   "movd %%mm3,4(%0)     \n\t" \
   "psrlq $32, %%mm3     \n\t" \
\
   "paddq %%mm7,%%mm3    \n\t" \
   "pmuludq %%mm1,%%mm6  \n\t" \
   "movd 12(%2),%%mm7    \n\t" \
   "paddq %%mm6,%%mm3    \n\t" \
   "movd 12(%1),%%mm5     \n\t" \
   "movd %%mm3,8(%0)     \n\t" \
   "psrlq $32, %%mm3     \n\t" \
\
   "paddq %%mm5,%%mm3    \n\t" \
   "pmuludq %%mm1,%%mm7  \n\t" \
   "movd 16(%2),%%mm5    \n\t" \
   "paddq %%mm7,%%mm3    \n\t" \
   "movd 16(%1),%%mm6    \n\t" \
   "movd %%mm3,12(%0)    \n\t" \
   "psrlq $32, %%mm3     \n\t" \
\
   "paddq %%mm6,%%mm3    \n\t" \
   "pmuludq %%mm1,%%mm5  \n\t" \
   "movd 20(%2),%%mm6    \n\t" \
   "paddq %%mm5,%%mm3    \n\t" \
   "movd 20(%1),%%mm7    \n\t" \
   "movd %%mm3,16(%0)    \n\t" \
   "psrlq $32, %%mm3     \n\t" \
\
   "paddq %%mm7,%%mm3    \n\t" \
   "pmuludq %%mm1,%%mm6  \n\t" \
   "movd 24(%2),%%mm7    \n\t" \
   "paddq %%mm6,%%mm3    \n\t" \
   "movd 24(%1),%%mm5     \n\t" \
   "movd %%mm3,20(%0)    \n\t" \
   "psrlq $32, %%mm3     \n\t" \
\
   "paddq %%mm5,%%mm3    \n\t" \
   "pmuludq %%mm1,%%mm7  \n\t" \
   "movd 28(%2),%%mm5    \n\t" \
   "paddq %%mm7,%%mm3    \n\t" \
   "movd 28(%1),%%mm6    \n\t" \
   "movd %%mm3,24(%0)    \n\t" \
   "psrlq $32, %%mm3     \n\t" \
\
   "paddq %%mm6,%%mm3    \n\t" \
   "pmuludq %%mm1,%%mm5  \n\t" \
   "paddq %%mm5,%%mm3    \n\t" \
   "movd %%mm3,28(%0)    \n\t" \
   "psrlq $32, %%mm3     \n\t" \
:"=r"(_c) : "0"(_c), "g"(tmpm) );

#define LOOP_END \
asm( "movd %%mm3,%0  \n" :"=r"(cy))

#define PROPCARRY                           \
asm(                                        \
   "addl   %1,%0    \n\t"                   \
   "setb   %%al     \n\t"                   \
   "movzbl %%al,%1 \n\t"                    \
:"=g"(_c[LO]), "=r"(cy)                     \
:"0"(_c[LO]), "1"(cy)                       \
: "%eax", "%cc")

/******************************************************************/
#elif defined(TFM_ARM)
   /* ARMv4 code */

#define MONT_START 
#define MONT_FINI
#define LOOP_END
#define LOOP_START \
   mu = c[x] * mp

#define INNERMUL                    \
asm(                                \
    " LDR    r0,%1            \n\t" \
    " ADDS   r0,r0,%0         \n\t" \
    " MOVCS  %0,#1            \n\t" \
    " MOVCC  %0,#0            \n\t" \
    " UMLAL  r0,%0,%3,%4      \n\t" \
    " STR    r0,%1            \n\t" \
:"=r"(cy),"=m"(_c[0]):"0"(cy),"r"(mu),"r"(*tmpm++),"1"(_c[0]):"r0","%cc");

#define PROPCARRY                  \
asm(                               \
    " LDR   r0,%1            \n\t" \
    " ADDS  r0,r0,%0         \n\t" \
    " STR   r0,%1            \n\t" \
    " MOVCS %0,#1            \n\t" \
    " MOVCC %0,#0            \n\t" \
:"=r"(cy),"=m"(_c[0]):"0"(cy),"1"(_c[0]):"r0","%cc");

/******************************************************************/
#elif defined(TFM_PPC32)

/* PPC32 */
#define MONT_START 
#define MONT_FINI
#define LOOP_END
#define LOOP_START \
   mu = c[x] * mp

#define INNERMUL                     \
asm(                                 \
   " mullw    16,%3,%4       \n\t"   \
   " mulhwu   17,%3,%4       \n\t"   \
   " addc     16,16,%0       \n\t"   \
   " addze    17,17          \n\t"   \
   " lwz      18,%1          \n\t"   \
   " addc     16,16,18       \n\t"   \
   " addze    %0,17          \n\t"   \
   " stw      16,%1          \n\t"   \
:"=r"(cy),"=m"(_c[0]):"0"(cy),"r"(mu),"r"(tmpm[0]),"1"(_c[0]):"16", "17", "18","%cc"); ++tmpm;

#define PROPCARRY                    \
asm(                                 \
   " lwz      16,%1         \n\t"    \
   " addc     16,16,%0      \n\t"    \
   " stw      16,%1         \n\t"    \
   " xor      %0,%0,%0      \n\t"    \
   " addze    %0,%0         \n\t"    \
:"=r"(cy),"=m"(_c[0]):"0"(cy),"1"(_c[0]):"16","%cc");

/******************************************************************/
#elif defined(TFM_PPC64)

/* PPC64 */
#define MONT_START 
#define MONT_FINI
#define LOOP_END
#define LOOP_START \
   mu = c[x] * mp

#define INNERMUL                     \
asm(                                 \
   " mulld    r16,%3,%4       \n\t"   \
   " mulhdu   r17,%3,%4       \n\t"   \
   " addc     r16,16,%0       \n\t"   \
   " addze    r17,r17          \n\t"   \
   " ldx      r18,0,%1        \n\t"   \
   " addc     r16,r16,r18       \n\t"   \
   " addze    %0,r17          \n\t"   \
   " sdx      r16,0,%1        \n\t"   \
:"=r"(cy),"=m"(_c[0]):"0"(cy),"r"(mu),"r"(tmpm[0]),"1"(_c[0]):"r16", "r17", "r18","%cc"); ++tmpm;

#define PROPCARRY                    \
asm(                                 \
   " ldx      r16,0,%1       \n\t"    \
   " addc     r16,r16,%0      \n\t"    \
   " sdx      r16,0,%1       \n\t"    \
   " xor      %0,%0,%0      \n\t"    \
   " addze    %0,%0         \n\t"    \
:"=r"(cy),"=m"(_c[0]):"0"(cy),"1"(_c[0]):"r16","%cc");

/******************************************************************/
#elif defined(TFM_AVR32)

/* AVR32 */
#define MONT_START 
#define MONT_FINI
#define LOOP_END
#define LOOP_START \
   mu = c[x] * mp

#define INNERMUL                    \
asm(                                \
    " ld.w   r2,%1            \n\t" \
    " add    r2,%0            \n\t" \
    " eor    r3,r3            \n\t" \
    " acr    r3               \n\t" \
    " macu.d r2,%3,%4         \n\t" \
    " st.w   %1,r2            \n\t" \
    " mov    %0,r3            \n\t" \
:"=r"(cy),"=r"(_c):"0"(cy),"r"(mu),"r"(*tmpm++),"1"(_c):"r2","r3");

#define PROPCARRY                    \
asm(                                 \
   " ld.w     r2,%1         \n\t"    \
   " add      r2,%0         \n\t"    \
   " st.w     %1,r2         \n\t"    \
   " eor      %0,%0         \n\t"    \
   " acr      %0            \n\t"    \
:"=r"(cy),"=r"(&_c[0]):"0"(cy),"1"(&_c[0]):"r2","%cc");

/******************************************************************/
#elif defined(TFM_MIPS)

/* MIPS */
#define MONT_START 
#define MONT_FINI
#define LOOP_END
#define LOOP_START \
   mu = c[x] * mp

#define INNERMUL                     \
asm(                                 \
   " multu    %3,%4          \n\t"   \
   " mflo     $12            \n\t"   \
   " mfhi     $13            \n\t"   \
   " addu     $12,$12,%0     \n\t"   \
   " sltu     $10,$12,%0     \n\t"   \
   " addu     $13,$13,$10    \n\t"   \
   " lw       $10,%1         \n\t"   \
   " addu     $12,$12,$10    \n\t"   \
   " sltu     $10,$12,$10    \n\t"   \
   " addu     %0,$13,$10     \n\t"   \
   " sw       $12,%1         \n\t"   \
:"=r"(cy),"=m"(_c[0]):"0"(cy),"r"(mu),"r"(tmpm[0]),"1"(_c[0]):"$10","$12","$13"); ++tmpm;

#define PROPCARRY                    \
asm(                                 \
   " lw       $10,%1        \n\t"    \
   " addu     $10,$10,%0    \n\t"    \
   " sw       $10,%1        \n\t"    \
   " sltu     %0,$10,%0     \n\t"    \
:"=r"(cy),"=m"(_c[0]):"0"(cy),"1"(_c[0]):"$10");

/******************************************************************/
#else

/* ISO C code */
#define MONT_START 
#define MONT_FINI
#define LOOP_END
#define LOOP_START \
   mu = c[x] * mp

#define INNERMUL                                      \
   do { fp_word t;                                    \
   _c[0] = t  = ((fp_word)_c[0] + (fp_word)cy) +      \
                (((fp_word)mu) * ((fp_word)*tmpm++)); \
   cy = (t >> DIGIT_BIT);                             \
   } while (0)

#define PROPCARRY \
   do { fp_digit t = _c[0] += cy; cy = (t < cy); } while (0)

#endif
/******************************************************************/


#define LO  0

#ifdef TFM_SMALL_MONT_SET
#include "fp_mont_small.i"
#endif

/* computes x/R == x (mod N) via Montgomery Reduction */
void fp_montgomery_reduce(fp_int *a, fp_int *m, fp_digit mp)
{
   fp_digit c[FP_SIZE], *_c, *tmpm, mu;
   int      oldused, x, y, pa;

   /* bail if too large */
   if (m->used > (FP_SIZE/2)) {
      return;
   }

#ifdef TFM_SMALL_MONT_SET
   if (m->used <= 16) {
      fp_montgomery_reduce_small(a, m, mp);
      return;
   }
#endif

#if defined(USE_MEMSET)
   /* now zero the buff */
   memset(c, 0, sizeof c);
#endif
   pa = m->used;

   /* copy the input */
   oldused = a->used;
   for (x = 0; x < oldused; x++) {
       c[x] = a->dp[x];
   }
#if !defined(USE_MEMSET)
   for (; x < 2*pa+1; x++) {
       c[x] = 0;
   }
#endif
   MONT_START;

   for (x = 0; x < pa; x++) {
       fp_digit cy = 0;
       /* get Mu for this round */
       LOOP_START;
       _c   = c + x;
       tmpm = m->dp;
       y = 0;
       #if (defined(TFM_SSE2) || defined(TFM_X86_64))
        for (; y < (pa & ~7); y += 8) {
              INNERMUL8;
              _c   += 8;
              tmpm += 8;
           }
       #endif

       for (; y < pa; y++) {
          INNERMUL;
          ++_c;
       }
       LOOP_END;
       while (cy) {
           PROPCARRY;
           ++_c;
       }
  }         

  /* now copy out */
  _c   = c + pa;
  tmpm = a->dp;
  for (x = 0; x < pa+1; x++) {
     *tmpm++ = *_c++;
  }

  for (; x < oldused; x++)   {
     *tmpm++ = 0;
  }

  MONT_FINI;

  a->used = pa+1;
  fp_clamp(a);
  
  /* if A >= m then A = A - m */
  if (fp_cmp_mag (a, m) != FP_LT) {
    s_fp_sub (a, m, a);
  }
}


/* $Source: /cvs/libtom/tomsfastmath/src/mont/fp_montgomery_reduce.c,v $ */
/* $Revision: 1.2 $ */
/* $Date: 2007/03/14 23:47:42 $ */

/* End: fp_montgomery_reduce.c */

/* Start: fp_montgomery_setup.c */
/* TomsFastMath, a fast ISO C bignum library.
 * 
 * This project is meant to fill in where LibTomMath
 * falls short.  That is speed ;-)
 *
 * This project is public domain and free for all purposes.
 * 
 * Tom St Denis, tomstdenis@gmail.com
 */
#include "bignum_fast.h"

/* setups the montgomery reduction */
int fp_montgomery_setup(fp_int *a, fp_digit *rho)
{
  fp_digit x, b;

/* fast inversion mod 2**k
 *
 * Based on the fact that
 *
 * XA = 1 (mod 2**n)  =>  (X(2-XA)) A = 1 (mod 2**2n)
 *                    =>  2*X*A - X*X*A*A = 1
 *                    =>  2*(1) - (1)     = 1
 */
  b = a->dp[0];

  if ((b & 1) == 0) {
    return FP_VAL;
  }

  x = (((b + 2) & 4) << 1) + b; /* here x*a==1 mod 2**4 */
  x *= 2 - b * x;               /* here x*a==1 mod 2**8 */
  x *= 2 - b * x;               /* here x*a==1 mod 2**16 */
  x *= 2 - b * x;               /* here x*a==1 mod 2**32 */
#ifdef FP_64BIT
  x *= 2 - b * x;               /* here x*a==1 mod 2**64 */
#endif

  /* rho = -1/m mod b */
  *rho = (((fp_word) 1 << ((fp_word) DIGIT_BIT)) - ((fp_word)x));

  return FP_OKAY;
}


/* $Source: /cvs/libtom/tomsfastmath/src/mont/fp_montgomery_setup.c,v $ */
/* $Revision: 1.1 $ */
/* $Date: 2006/12/31 21:25:53 $ */

/* End: fp_montgomery_setup.c */

/* Start: fp_mul.c */
/* TomsFastMath, a fast ISO C bignum library.
 * 
 * This project is meant to fill in where LibTomMath
 * falls short.  That is speed ;-)
 *
 * This project is public domain and free for all purposes.
 * 
 * Tom St Denis, tomstdenis@gmail.com
 */
#include "bignum_fast.h"

/* c = a * b */
void fp_mul(fp_int *A, fp_int *B, fp_int *C)
{
    int   y, yy;

    /* call generic if we're out of range */
    if (A->used + B->used > FP_SIZE) {
       fp_mul_comba(A, B, C);
       return ;
    }

     y  = MAX(A->used, B->used);
     yy = MIN(A->used, B->used);
    /* pick a comba (unrolled 4/8/16/32 x or rolled) based on the size
       of the largest input.  We also want to avoid doing excess mults if the 
       inputs are not close to the next power of two.  That is, for example,
       if say y=17 then we would do (32-17)^2 = 225 unneeded multiplications 
    */

#ifdef TFM_MUL3
        if (y <= 3) {
           fp_mul_comba3(A,B,C);
           return;
        }
#endif
#ifdef TFM_MUL4
        if (y == 4) {
           fp_mul_comba4(A,B,C);
           return;
        }
#endif
#ifdef TFM_MUL6
        if (y <= 6) {
           fp_mul_comba6(A,B,C);
           return;
        }
#endif
#ifdef TFM_MUL7
        if (y == 7) {
           fp_mul_comba7(A,B,C);
           return;
        }
#endif
#ifdef TFM_MUL8
        if (y == 8) {
           fp_mul_comba8(A,B,C);
           return;
        }
#endif
#ifdef TFM_MUL9
        if (y == 9) {
           fp_mul_comba9(A,B,C);
           return;
        }
#endif
#ifdef TFM_MUL12
        if (y <= 12) {
           fp_mul_comba12(A,B,C);
           return;
        }
#endif
#ifdef TFM_MUL17
        if (y <= 17) {
           fp_mul_comba17(A,B,C);
           return;
        }
#endif

#ifdef TFM_SMALL_SET
        if (y <= 16) {
           fp_mul_comba_small(A,B,C);
           return;
        }
#endif        
#if defined(TFM_MUL20)
        if (y <= 20) {
           fp_mul_comba20(A,B,C);
           return;
        }
#endif
#if defined(TFM_MUL24)
        if (yy >= 16 && y <= 24) {
           fp_mul_comba24(A,B,C);
           return;
        }
#endif
#if defined(TFM_MUL28)
        if (yy >= 20 && y <= 28) {
           fp_mul_comba28(A,B,C);
           return;
        }
#endif
#if defined(TFM_MUL32)
        if (yy >= 24 && y <= 32) {
           fp_mul_comba32(A,B,C);
           return;
        }
#endif
#if defined(TFM_MUL48)
        if (yy >= 40 && y <= 48) {
           fp_mul_comba48(A,B,C);
           return;
        }
#endif        
#if defined(TFM_MUL64)
        if (yy >= 56 && y <= 64) {
           fp_mul_comba64(A,B,C);
           return;
        }
#endif
        fp_mul_comba(A,B,C);
}


/* $Source: /cvs/libtom/tomsfastmath/src/mul/fp_mul.c,v $ */
/* $Revision: 1.1 $ */
/* $Date: 2006/12/31 21:25:53 $ */

/* End: fp_mul.c */

/* Start: fp_mul_2.c */
/* TomsFastMath, a fast ISO C bignum library.
 * 
 * This project is meant to fill in where LibTomMath
 * falls short.  That is speed ;-)
 *
 * This project is public domain and free for all purposes.
 * 
 * Tom St Denis, tomstdenis@gmail.com
 */
#include "bignum_fast.h"

void fp_mul_2(fp_int * a, fp_int * b)
{
  int     x, oldused;
   
  oldused = b->used;
  b->used = a->used;

  {
    register fp_digit r, rr, *tmpa, *tmpb;

    /* alias for source */
    tmpa = a->dp;
    
    /* alias for dest */
    tmpb = b->dp;

    /* carry */
    r = 0;
    for (x = 0; x < a->used; x++) {
    
      /* get what will be the *next* carry bit from the 
       * MSB of the current digit 
       */
      rr = *tmpa >> ((fp_digit)(DIGIT_BIT - 1));
      
      /* now shift up this digit, add in the carry [from the previous] */
      *tmpb++ = ((*tmpa++ << ((fp_digit)1)) | r);
      
      /* copy the carry that would be from the source 
       * digit into the next iteration 
       */
      r = rr;
    }

    /* new leading digit? */
    if (r != 0 && b->used != (FP_SIZE-1)) {
      /* add a MSB which is always 1 at this point */
      *tmpb = 1;
      ++(b->used);
    }

    /* now zero any excess digits on the destination 
     * that we didn't write to 
     */
    tmpb = b->dp + b->used;
    for (x = b->used; x < oldused; x++) {
      *tmpb++ = 0;
    }
  }
  b->sign = a->sign;
}


/* $Source: /cvs/libtom/tomsfastmath/src/mul/fp_mul_2.c,v $ */
/* $Revision: 1.1 $ */
/* $Date: 2006/12/31 21:25:53 $ */

/* End: fp_mul_2.c */

/* Start: fp_mul_2d.c */
/* TomsFastMath, a fast ISO C bignum library.
 * 
 * This project is meant to fill in where LibTomMath
 * falls short.  That is speed ;-)
 *
 * This project is public domain and free for all purposes.
 * 
 * Tom St Denis, tomstdenis@gmail.com
 */
#include "bignum_fast.h"

/* c = a * 2**d */
void fp_mul_2d(fp_int *a, int b, fp_int *c)
{
   fp_digit carry, carrytmp, shift;
   int x;

   /* copy it */
   fp_copy(a, c);

   /* handle whole digits */
   if (b >= DIGIT_BIT) {
      fp_lshd(c, b/DIGIT_BIT);
   }
   b %= DIGIT_BIT;

   /* shift the digits */
   if (b != 0) {
      carry = 0;   
      shift = DIGIT_BIT - b;
      for (x = 0; x < c->used; x++) {
          carrytmp = c->dp[x] >> shift;
          c->dp[x] = (c->dp[x] << b) + carry;
          carry = carrytmp;
      }
      /* store last carry if room */
      if (carry && x < FP_SIZE) {
         c->dp[c->used++] = carry;
      }
   }
   fp_clamp(c);
}


/* $Source: /cvs/libtom/tomsfastmath/src/mul/fp_mul_2d.c,v $ */
/* $Revision: 1.1 $ */
/* $Date: 2006/12/31 21:25:53 $ */

/* End: fp_mul_2d.c */

/* Start: fp_mul_comba.c */
/* TomsFastMath, a fast ISO C bignum library.
 * 
 * This project is meant to fill in where LibTomMath
 * falls short.  That is speed ;-)
 *
 * This project is public domain and free for all purposes.
 * 
 * Tom St Denis, tomstdenis@gmail.com
 */

/* About this file...

*/

#include "bignum_fast.h"

#if defined(TFM_PRESCOTT) && defined(TFM_SSE2)
   #undef TFM_SSE2
   #define TFM_X86
#endif

/* these are the combas.  Worship them. */
#if defined(TFM_X86)
/* Generic x86 optimized code */

/* anything you need at the start */
#define COMBA_START

/* clear the chaining variables */
#define COMBA_CLEAR \
   c0 = c1 = c2 = 0;

/* forward the carry to the next digit */
#define COMBA_FORWARD \
   do { c0 = c1; c1 = c2; c2 = 0; } while (0);

/* store the first sum */
#define COMBA_STORE(x) \
   x = c0;

/* store the second sum [carry] */
#define COMBA_STORE2(x) \
   x = c1;

/* anything you need at the end */
#define COMBA_FINI

/* this should multiply i and j  */
#define MULADD(i, j)                                      \
asm(                                                      \
     "movl  %6,%%eax     \n\t"                            \
     "mull  %7           \n\t"                            \
     "addl  %%eax,%0     \n\t"                            \
     "adcl  %%edx,%1     \n\t"                            \
     "adcl  $0,%2        \n\t"                            \
     :"=r"(c0), "=r"(c1), "=r"(c2): "0"(c0), "1"(c1), "2"(c2), "m"(i), "m"(j)  :"%eax","%edx","%cc");

#elif defined(TFM_X86_64)
/* x86-64 optimized */

/* anything you need at the start */
#define COMBA_START

/* clear the chaining variables */
#define COMBA_CLEAR \
   c0 = c1 = c2 = 0;

/* forward the carry to the next digit */
#define COMBA_FORWARD \
   do { c0 = c1; c1 = c2; c2 = 0; } while (0);

/* store the first sum */
#define COMBA_STORE(x) \
   x = c0;

/* store the second sum [carry] */
#define COMBA_STORE2(x) \
   x = c1;

/* anything you need at the end */
#define COMBA_FINI

/* this should multiply i and j  */
#define MULADD(i, j)                                      \
asm  (                                                    \
     "movq  %6,%%rax     \n\t"                            \
     "mulq  %7           \n\t"                            \
     "addq  %%rax,%0     \n\t"                            \
     "adcq  %%rdx,%1     \n\t"                            \
     "adcq  $0,%2        \n\t"                            \
     :"=r"(c0), "=r"(c1), "=r"(c2): "0"(c0), "1"(c1), "2"(c2), "g"(i), "g"(j)  :"%rax","%rdx","%cc");

#elif defined(TFM_SSE2)
/* use SSE2 optimizations */

/* anything you need at the start */
#define COMBA_START

/* clear the chaining variables */
#define COMBA_CLEAR \
   c0 = c1 = c2 = 0;

/* forward the carry to the next digit */
#define COMBA_FORWARD \
   do { c0 = c1; c1 = c2; c2 = 0; } while (0);

/* store the first sum */
#define COMBA_STORE(x) \
   x = c0;

/* store the second sum [carry] */
#define COMBA_STORE2(x) \
   x = c1;

/* anything you need at the end */
#define COMBA_FINI \
   asm("emms");

/* this should multiply i and j  */
#define MULADD(i, j)                                     \
asm(                                                     \
    "movd  %6,%%mm0     \n\t"                            \
    "movd  %7,%%mm1     \n\t"                            \
    "pmuludq %%mm1,%%mm0\n\t"                            \
    "movd  %%mm0,%%eax  \n\t"                            \
    "psrlq $32,%%mm0    \n\t"                            \
    "addl  %%eax,%0     \n\t"                            \
    "movd  %%mm0,%%eax  \n\t"                            \
    "adcl  %%eax,%1     \n\t"                            \
    "adcl  $0,%2        \n\t"                            \
    :"=r"(c0), "=r"(c1), "=r"(c2): "0"(c0), "1"(c1), "2"(c2), "m"(i), "m"(j)  :"%eax","%cc");

#elif defined(TFM_ARM)
/* ARM code */

#define COMBA_START 

#define COMBA_CLEAR \
   c0 = c1 = c2 = 0;

#define COMBA_FORWARD \
   do { c0 = c1; c1 = c2; c2 = 0; } while (0);

#define COMBA_STORE(x) \
   x = c0;

#define COMBA_STORE2(x) \
   x = c1;

#define COMBA_FINI

#define MULADD(i, j)                                          \
asm(                                                          \
"  UMULL  r0,r1,%6,%7           \n\t"                         \
"  ADDS   %0,%0,r0              \n\t"                         \
"  ADCS   %1,%1,r1              \n\t"                         \
"  ADC    %2,%2,#0              \n\t"                         \
:"=r"(c0), "=r"(c1), "=r"(c2) : "0"(c0), "1"(c1), "2"(c2), "r"(i), "r"(j) : "r0", "r1", "%cc");

#elif defined(TFM_PPC32)
/* For 32-bit PPC */

#define COMBA_START

#define COMBA_CLEAR \
   c0 = c1 = c2 = 0;

#define COMBA_FORWARD \
   do { c0 = c1; c1 = c2; c2 = 0; } while (0);

#define COMBA_STORE(x) \
   x = c0;

#define COMBA_STORE2(x) \
   x = c1;

#define COMBA_FINI 
   
/* untested: will mulhwu change the flags?  Docs say no */
#define MULADD(i, j)              \
asm(                              \
   " mullw  16,%6,%7       \n\t" \
   " addc   %0,%0,16       \n\t" \
   " mulhwu 16,%6,%7       \n\t" \
   " adde   %1,%1,16       \n\t" \
   " addze  %2,%2          \n\t" \
:"=r"(c0), "=r"(c1), "=r"(c2):"0"(c0), "1"(c1), "2"(c2), "r"(i), "r"(j):"16");

#elif defined(TFM_PPC64)
/* For 64-bit PPC */

#define COMBA_START

#define COMBA_CLEAR \
   c0 = c1 = c2 = 0;

#define COMBA_FORWARD \
   do { c0 = c1; c1 = c2; c2 = 0; } while (0);

#define COMBA_STORE(x) \
   x = c0;

#define COMBA_STORE2(x) \
   x = c1;

#define COMBA_FINI 
   
/* untested: will mulhdu change the flags?  Docs say no */
#define MULADD(i, j)              \
asm(                              \
   " mulld  r16,%6,%7       \n\t" \
   " addc   %0,%0,16       \n\t" \
   " mulhdu r16,%6,%7       \n\t" \
   " adde   %1,%1,16       \n\t" \
   " addze  %2,%2          \n\t" \
:"=r"(c0), "=r"(c1), "=r"(c2):"0"(c0), "1"(c1), "2"(c2), "r"(i), "r"(j):"r16");

#elif defined(TFM_AVR32)

/* ISO C code */

#define COMBA_START

#define COMBA_CLEAR \
   c0 = c1 = c2 = 0;

#define COMBA_FORWARD \
   do { c0 = c1; c1 = c2; c2 = 0; } while (0);

#define COMBA_STORE(x) \
   x = c0;

#define COMBA_STORE2(x) \
   x = c1;

#define COMBA_FINI 
   
#define MULADD(i, j)             \
asm(                             \
   " mulu.d r2,%6,%7        \n\t"\
   " add    %0,r2           \n\t"\
   " adc    %1,%1,r3        \n\t"\
   " acr    %2              \n\t"\
:"=r"(c0), "=r"(c1), "=r"(c2):"0"(c0), "1"(c1), "2"(c2), "r"(i), "r"(j):"r2","r3");

#elif defined(TFM_MIPS)

#define COMBA_START

#define COMBA_CLEAR \
   c0 = c1 = c2 = 0;

#define COMBA_FORWARD \
   do { c0 = c1; c1 = c2; c2 = 0; } while (0);

#define COMBA_STORE(x) \
   x = c0;

#define COMBA_STORE2(x) \
   x = c1;

#define COMBA_FINI 
   
#define MULADD(i, j)              \
asm(                              \
   " multu  %6,%7          \n\t"  \
   " mflo   $12            \n\t"  \
   " mfhi   $13            \n\t"  \
   " addu    %0,%0,$12     \n\t"  \
   " sltu   $12,%0,$12     \n\t"  \
   " addu    %1,%1,$13     \n\t"  \
   " sltu   $13,%1,$13     \n\t"  \
   " addu    %1,%1,$12     \n\t"  \
   " sltu   $12,%1,$12     \n\t"  \
   " addu    %2,%2,$13     \n\t"  \
   " addu    %2,%2,$12     \n\t"  \
:"=r"(c0), "=r"(c1), "=r"(c2):"0"(c0), "1"(c1), "2"(c2), "r"(i), "r"(j):"$12","$13");

#else
/* ISO C code */

#define COMBA_START

#define COMBA_CLEAR \
   c0 = c1 = c2 = 0;

#define COMBA_FORWARD \
   do { c0 = c1; c1 = c2; c2 = 0; } while (0);

#define COMBA_STORE(x) \
   x = c0;

#define COMBA_STORE2(x) \
   x = c1;

#define COMBA_FINI 
   
#define MULADD(i, j)                                                              \
   do { fp_word t;                                                                \
   t = (fp_word)c0 + ((fp_word)i) * ((fp_word)j); c0 = t;                         \
   t = (fp_word)c1 + (t >> DIGIT_BIT);            c1 = t; c2 += t >> DIGIT_BIT;   \
   } while (0);

#endif

#ifndef TFM_DEFINES

/* generic PxQ multiplier */
void fp_mul_comba(fp_int *A, fp_int *B, fp_int *C)
{
   int       ix, iy, iz, tx, ty, pa;
   fp_digit  c0, c1, c2, *tmpx, *tmpy;
   fp_int    tmp, *dst;

   COMBA_START;
   COMBA_CLEAR;
   
   /* get size of output and trim */
   pa = A->used + B->used;
   if (pa >= FP_SIZE) {
      pa = FP_SIZE-1;
   }

   if (A == C || B == C) {
      fp_zero(&tmp);
      dst = &tmp;
   } else {
      fp_zero(C);
      dst = C;
   }

   for (ix = 0; ix < pa; ix++) {
      /* get offsets into the two bignums */
      ty = MIN(ix, B->used-1);
      tx = ix - ty;

      /* setup temp aliases */
      tmpx = A->dp + tx;
      tmpy = B->dp + ty;

      /* this is the number of times the loop will iterrate, essentially its 
         while (tx++ < a->used && ty-- >= 0) { ... }
       */
      iy = MIN(A->used-tx, ty+1);

      /* execute loop */
      COMBA_FORWARD;
      for (iz = 0; iz < iy; ++iz) {
          MULADD(*tmpx++, *tmpy--);
      }

      /* store term */
      COMBA_STORE(dst->dp[ix]);
  }
  COMBA_FINI;

  dst->used = pa;
  dst->sign = A->sign ^ B->sign;
  fp_clamp(dst);
  fp_copy(dst, C);
}

#endif

/* $Source: /cvs/libtom/tomsfastmath/src/mul/fp_mul_comba.c,v $ */
/* $Revision: 1.4 $ */
/* $Date: 2007/03/14 23:47:42 $ */


/* End: fp_mul_comba.c */

/* Start: fp_mul_comba_12.c */
#define TFM_DEFINES
#include "fp_mul_comba.c"

#ifdef TFM_MUL12
void fp_mul_comba12(fp_int *A, fp_int *B, fp_int *C)
{
   fp_digit c0, c1, c2, at[24];

   memcpy(at, A->dp, 12 * sizeof(fp_digit));
   memcpy(at+12, B->dp, 12 * sizeof(fp_digit));
   COMBA_START;

   COMBA_CLEAR;
   /* 0 */
   MULADD(at[0], at[12]); 
   COMBA_STORE(C->dp[0]);
   /* 1 */
   COMBA_FORWARD;
   MULADD(at[0], at[13]);    MULADD(at[1], at[12]); 
   COMBA_STORE(C->dp[1]);
   /* 2 */
   COMBA_FORWARD;
   MULADD(at[0], at[14]);    MULADD(at[1], at[13]);    MULADD(at[2], at[12]); 
   COMBA_STORE(C->dp[2]);
   /* 3 */
   COMBA_FORWARD;
   MULADD(at[0], at[15]);    MULADD(at[1], at[14]);    MULADD(at[2], at[13]);    MULADD(at[3], at[12]); 
   COMBA_STORE(C->dp[3]);
   /* 4 */
   COMBA_FORWARD;
   MULADD(at[0], at[16]);    MULADD(at[1], at[15]);    MULADD(at[2], at[14]);    MULADD(at[3], at[13]);    MULADD(at[4], at[12]); 
   COMBA_STORE(C->dp[4]);
   /* 5 */
   COMBA_FORWARD;
   MULADD(at[0], at[17]);    MULADD(at[1], at[16]);    MULADD(at[2], at[15]);    MULADD(at[3], at[14]);    MULADD(at[4], at[13]);    MULADD(at[5], at[12]); 
   COMBA_STORE(C->dp[5]);
   /* 6 */
   COMBA_FORWARD;
   MULADD(at[0], at[18]);    MULADD(at[1], at[17]);    MULADD(at[2], at[16]);    MULADD(at[3], at[15]);    MULADD(at[4], at[14]);    MULADD(at[5], at[13]);    MULADD(at[6], at[12]); 
   COMBA_STORE(C->dp[6]);
   /* 7 */
   COMBA_FORWARD;
   MULADD(at[0], at[19]);    MULADD(at[1], at[18]);    MULADD(at[2], at[17]);    MULADD(at[3], at[16]);    MULADD(at[4], at[15]);    MULADD(at[5], at[14]);    MULADD(at[6], at[13]);    MULADD(at[7], at[12]); 
   COMBA_STORE(C->dp[7]);
   /* 8 */
   COMBA_FORWARD;
   MULADD(at[0], at[20]);    MULADD(at[1], at[19]);    MULADD(at[2], at[18]);    MULADD(at[3], at[17]);    MULADD(at[4], at[16]);    MULADD(at[5], at[15]);    MULADD(at[6], at[14]);    MULADD(at[7], at[13]);    MULADD(at[8], at[12]); 
   COMBA_STORE(C->dp[8]);
   /* 9 */
   COMBA_FORWARD;
   MULADD(at[0], at[21]);    MULADD(at[1], at[20]);    MULADD(at[2], at[19]);    MULADD(at[3], at[18]);    MULADD(at[4], at[17]);    MULADD(at[5], at[16]);    MULADD(at[6], at[15]);    MULADD(at[7], at[14]);    MULADD(at[8], at[13]);    MULADD(at[9], at[12]); 
   COMBA_STORE(C->dp[9]);
   /* 10 */
   COMBA_FORWARD;
   MULADD(at[0], at[22]);    MULADD(at[1], at[21]);    MULADD(at[2], at[20]);    MULADD(at[3], at[19]);    MULADD(at[4], at[18]);    MULADD(at[5], at[17]);    MULADD(at[6], at[16]);    MULADD(at[7], at[15]);    MULADD(at[8], at[14]);    MULADD(at[9], at[13]);    MULADD(at[10], at[12]); 
   COMBA_STORE(C->dp[10]);
   /* 11 */
   COMBA_FORWARD;
   MULADD(at[0], at[23]);    MULADD(at[1], at[22]);    MULADD(at[2], at[21]);    MULADD(at[3], at[20]);    MULADD(at[4], at[19]);    MULADD(at[5], at[18]);    MULADD(at[6], at[17]);    MULADD(at[7], at[16]);    MULADD(at[8], at[15]);    MULADD(at[9], at[14]);    MULADD(at[10], at[13]);    MULADD(at[11], at[12]); 
   COMBA_STORE(C->dp[11]);
   /* 12 */
   COMBA_FORWARD;
   MULADD(at[1], at[23]);    MULADD(at[2], at[22]);    MULADD(at[3], at[21]);    MULADD(at[4], at[20]);    MULADD(at[5], at[19]);    MULADD(at[6], at[18]);    MULADD(at[7], at[17]);    MULADD(at[8], at[16]);    MULADD(at[9], at[15]);    MULADD(at[10], at[14]);    MULADD(at[11], at[13]); 
   COMBA_STORE(C->dp[12]);
   /* 13 */
   COMBA_FORWARD;
   MULADD(at[2], at[23]);    MULADD(at[3], at[22]);    MULADD(at[4], at[21]);    MULADD(at[5], at[20]);    MULADD(at[6], at[19]);    MULADD(at[7], at[18]);    MULADD(at[8], at[17]);    MULADD(at[9], at[16]);    MULADD(at[10], at[15]);    MULADD(at[11], at[14]); 
   COMBA_STORE(C->dp[13]);
   /* 14 */
   COMBA_FORWARD;
   MULADD(at[3], at[23]);    MULADD(at[4], at[22]);    MULADD(at[5], at[21]);    MULADD(at[6], at[20]);    MULADD(at[7], at[19]);    MULADD(at[8], at[18]);    MULADD(at[9], at[17]);    MULADD(at[10], at[16]);    MULADD(at[11], at[15]); 
   COMBA_STORE(C->dp[14]);
   /* 15 */
   COMBA_FORWARD;
   MULADD(at[4], at[23]);    MULADD(at[5], at[22]);    MULADD(at[6], at[21]);    MULADD(at[7], at[20]);    MULADD(at[8], at[19]);    MULADD(at[9], at[18]);    MULADD(at[10], at[17]);    MULADD(at[11], at[16]); 
   COMBA_STORE(C->dp[15]);
   /* 16 */
   COMBA_FORWARD;
   MULADD(at[5], at[23]);    MULADD(at[6], at[22]);    MULADD(at[7], at[21]);    MULADD(at[8], at[20]);    MULADD(at[9], at[19]);    MULADD(at[10], at[18]);    MULADD(at[11], at[17]); 
   COMBA_STORE(C->dp[16]);
   /* 17 */
   COMBA_FORWARD;
   MULADD(at[6], at[23]);    MULADD(at[7], at[22]);    MULADD(at[8], at[21]);    MULADD(at[9], at[20]);    MULADD(at[10], at[19]);    MULADD(at[11], at[18]); 
   COMBA_STORE(C->dp[17]);
   /* 18 */
   COMBA_FORWARD;
   MULADD(at[7], at[23]);    MULADD(at[8], at[22]);    MULADD(at[9], at[21]);    MULADD(at[10], at[20]);    MULADD(at[11], at[19]); 
   COMBA_STORE(C->dp[18]);
   /* 19 */
   COMBA_FORWARD;
   MULADD(at[8], at[23]);    MULADD(at[9], at[22]);    MULADD(at[10], at[21]);    MULADD(at[11], at[20]); 
   COMBA_STORE(C->dp[19]);
   /* 20 */
   COMBA_FORWARD;
   MULADD(at[9], at[23]);    MULADD(at[10], at[22]);    MULADD(at[11], at[21]); 
   COMBA_STORE(C->dp[20]);
   /* 21 */
   COMBA_FORWARD;
   MULADD(at[10], at[23]);    MULADD(at[11], at[22]); 
   COMBA_STORE(C->dp[21]);
   /* 22 */
   COMBA_FORWARD;
   MULADD(at[11], at[23]); 
   COMBA_STORE(C->dp[22]);
   COMBA_STORE2(C->dp[23]);
   C->used = 24;
   C->sign = A->sign ^ B->sign;
   fp_clamp(C);
   COMBA_FINI;
}
#endif

/* End: fp_mul_comba_12.c */

/* Start: fp_mul_comba_17.c */
#define TFM_DEFINES
#include "fp_mul_comba.c"

#ifdef TFM_MUL17
void fp_mul_comba17(fp_int *A, fp_int *B, fp_int *C)
{
   fp_digit c0, c1, c2, at[34];

   memcpy(at, A->dp, 17 * sizeof(fp_digit));
   memcpy(at+17, B->dp, 17 * sizeof(fp_digit));
   COMBA_START;

   COMBA_CLEAR;
   /* 0 */
   MULADD(at[0], at[17]); 
   COMBA_STORE(C->dp[0]);
   /* 1 */
   COMBA_FORWARD;
   MULADD(at[0], at[18]);    MULADD(at[1], at[17]); 
   COMBA_STORE(C->dp[1]);
   /* 2 */
   COMBA_FORWARD;
   MULADD(at[0], at[19]);    MULADD(at[1], at[18]);    MULADD(at[2], at[17]); 
   COMBA_STORE(C->dp[2]);
   /* 3 */
   COMBA_FORWARD;
   MULADD(at[0], at[20]);    MULADD(at[1], at[19]);    MULADD(at[2], at[18]);    MULADD(at[3], at[17]); 
   COMBA_STORE(C->dp[3]);
   /* 4 */
   COMBA_FORWARD;
   MULADD(at[0], at[21]);    MULADD(at[1], at[20]);    MULADD(at[2], at[19]);    MULADD(at[3], at[18]);    MULADD(at[4], at[17]); 
   COMBA_STORE(C->dp[4]);
   /* 5 */
   COMBA_FORWARD;
   MULADD(at[0], at[22]);    MULADD(at[1], at[21]);    MULADD(at[2], at[20]);    MULADD(at[3], at[19]);    MULADD(at[4], at[18]);    MULADD(at[5], at[17]); 
   COMBA_STORE(C->dp[5]);
   /* 6 */
   COMBA_FORWARD;
   MULADD(at[0], at[23]);    MULADD(at[1], at[22]);    MULADD(at[2], at[21]);    MULADD(at[3], at[20]);    MULADD(at[4], at[19]);    MULADD(at[5], at[18]);    MULADD(at[6], at[17]); 
   COMBA_STORE(C->dp[6]);
   /* 7 */
   COMBA_FORWARD;
   MULADD(at[0], at[24]);    MULADD(at[1], at[23]);    MULADD(at[2], at[22]);    MULADD(at[3], at[21]);    MULADD(at[4], at[20]);    MULADD(at[5], at[19]);    MULADD(at[6], at[18]);    MULADD(at[7], at[17]); 
   COMBA_STORE(C->dp[7]);
   /* 8 */
   COMBA_FORWARD;
   MULADD(at[0], at[25]);    MULADD(at[1], at[24]);    MULADD(at[2], at[23]);    MULADD(at[3], at[22]);    MULADD(at[4], at[21]);    MULADD(at[5], at[20]);    MULADD(at[6], at[19]);    MULADD(at[7], at[18]);    MULADD(at[8], at[17]); 
   COMBA_STORE(C->dp[8]);
   /* 9 */
   COMBA_FORWARD;
   MULADD(at[0], at[26]);    MULADD(at[1], at[25]);    MULADD(at[2], at[24]);    MULADD(at[3], at[23]);    MULADD(at[4], at[22]);    MULADD(at[5], at[21]);    MULADD(at[6], at[20]);    MULADD(at[7], at[19]);    MULADD(at[8], at[18]);    MULADD(at[9], at[17]); 
   COMBA_STORE(C->dp[9]);
   /* 10 */
   COMBA_FORWARD;
   MULADD(at[0], at[27]);    MULADD(at[1], at[26]);    MULADD(at[2], at[25]);    MULADD(at[3], at[24]);    MULADD(at[4], at[23]);    MULADD(at[5], at[22]);    MULADD(at[6], at[21]);    MULADD(at[7], at[20]);    MULADD(at[8], at[19]);    MULADD(at[9], at[18]);    MULADD(at[10], at[17]); 
   COMBA_STORE(C->dp[10]);
   /* 11 */
   COMBA_FORWARD;
   MULADD(at[0], at[28]);    MULADD(at[1], at[27]);    MULADD(at[2], at[26]);    MULADD(at[3], at[25]);    MULADD(at[4], at[24]);    MULADD(at[5], at[23]);    MULADD(at[6], at[22]);    MULADD(at[7], at[21]);    MULADD(at[8], at[20]);    MULADD(at[9], at[19]);    MULADD(at[10], at[18]);    MULADD(at[11], at[17]); 
   COMBA_STORE(C->dp[11]);
   /* 12 */
   COMBA_FORWARD;
   MULADD(at[0], at[29]);    MULADD(at[1], at[28]);    MULADD(at[2], at[27]);    MULADD(at[3], at[26]);    MULADD(at[4], at[25]);    MULADD(at[5], at[24]);    MULADD(at[6], at[23]);    MULADD(at[7], at[22]);    MULADD(at[8], at[21]);    MULADD(at[9], at[20]);    MULADD(at[10], at[19]);    MULADD(at[11], at[18]);    MULADD(at[12], at[17]); 
   COMBA_STORE(C->dp[12]);
   /* 13 */
   COMBA_FORWARD;
   MULADD(at[0], at[30]);    MULADD(at[1], at[29]);    MULADD(at[2], at[28]);    MULADD(at[3], at[27]);    MULADD(at[4], at[26]);    MULADD(at[5], at[25]);    MULADD(at[6], at[24]);    MULADD(at[7], at[23]);    MULADD(at[8], at[22]);    MULADD(at[9], at[21]);    MULADD(at[10], at[20]);    MULADD(at[11], at[19]);    MULADD(at[12], at[18]);    MULADD(at[13], at[17]); 
   COMBA_STORE(C->dp[13]);
   /* 14 */
   COMBA_FORWARD;
   MULADD(at[0], at[31]);    MULADD(at[1], at[30]);    MULADD(at[2], at[29]);    MULADD(at[3], at[28]);    MULADD(at[4], at[27]);    MULADD(at[5], at[26]);    MULADD(at[6], at[25]);    MULADD(at[7], at[24]);    MULADD(at[8], at[23]);    MULADD(at[9], at[22]);    MULADD(at[10], at[21]);    MULADD(at[11], at[20]);    MULADD(at[12], at[19]);    MULADD(at[13], at[18]);    MULADD(at[14], at[17]); 
   COMBA_STORE(C->dp[14]);
   /* 15 */
   COMBA_FORWARD;
   MULADD(at[0], at[32]);    MULADD(at[1], at[31]);    MULADD(at[2], at[30]);    MULADD(at[3], at[29]);    MULADD(at[4], at[28]);    MULADD(at[5], at[27]);    MULADD(at[6], at[26]);    MULADD(at[7], at[25]);    MULADD(at[8], at[24]);    MULADD(at[9], at[23]);    MULADD(at[10], at[22]);    MULADD(at[11], at[21]);    MULADD(at[12], at[20]);    MULADD(at[13], at[19]);    MULADD(at[14], at[18]);    MULADD(at[15], at[17]); 
   COMBA_STORE(C->dp[15]);
   /* 16 */
   COMBA_FORWARD;
   MULADD(at[0], at[33]);    MULADD(at[1], at[32]);    MULADD(at[2], at[31]);    MULADD(at[3], at[30]);    MULADD(at[4], at[29]);    MULADD(at[5], at[28]);    MULADD(at[6], at[27]);    MULADD(at[7], at[26]);    MULADD(at[8], at[25]);    MULADD(at[9], at[24]);    MULADD(at[10], at[23]);    MULADD(at[11], at[22]);    MULADD(at[12], at[21]);    MULADD(at[13], at[20]);    MULADD(at[14], at[19]);    MULADD(at[15], at[18]);    MULADD(at[16], at[17]); 
   COMBA_STORE(C->dp[16]);
   /* 17 */
   COMBA_FORWARD;
   MULADD(at[1], at[33]);    MULADD(at[2], at[32]);    MULADD(at[3], at[31]);    MULADD(at[4], at[30]);    MULADD(at[5], at[29]);    MULADD(at[6], at[28]);    MULADD(at[7], at[27]);    MULADD(at[8], at[26]);    MULADD(at[9], at[25]);    MULADD(at[10], at[24]);    MULADD(at[11], at[23]);    MULADD(at[12], at[22]);    MULADD(at[13], at[21]);    MULADD(at[14], at[20]);    MULADD(at[15], at[19]);    MULADD(at[16], at[18]); 
   COMBA_STORE(C->dp[17]);
   /* 18 */
   COMBA_FORWARD;
   MULADD(at[2], at[33]);    MULADD(at[3], at[32]);    MULADD(at[4], at[31]);    MULADD(at[5], at[30]);    MULADD(at[6], at[29]);    MULADD(at[7], at[28]);    MULADD(at[8], at[27]);    MULADD(at[9], at[26]);    MULADD(at[10], at[25]);    MULADD(at[11], at[24]);    MULADD(at[12], at[23]);    MULADD(at[13], at[22]);    MULADD(at[14], at[21]);    MULADD(at[15], at[20]);    MULADD(at[16], at[19]); 
   COMBA_STORE(C->dp[18]);
   /* 19 */
   COMBA_FORWARD;
   MULADD(at[3], at[33]);    MULADD(at[4], at[32]);    MULADD(at[5], at[31]);    MULADD(at[6], at[30]);    MULADD(at[7], at[29]);    MULADD(at[8], at[28]);    MULADD(at[9], at[27]);    MULADD(at[10], at[26]);    MULADD(at[11], at[25]);    MULADD(at[12], at[24]);    MULADD(at[13], at[23]);    MULADD(at[14], at[22]);    MULADD(at[15], at[21]);    MULADD(at[16], at[20]); 
   COMBA_STORE(C->dp[19]);
   /* 20 */
   COMBA_FORWARD;
   MULADD(at[4], at[33]);    MULADD(at[5], at[32]);    MULADD(at[6], at[31]);    MULADD(at[7], at[30]);    MULADD(at[8], at[29]);    MULADD(at[9], at[28]);    MULADD(at[10], at[27]);    MULADD(at[11], at[26]);    MULADD(at[12], at[25]);    MULADD(at[13], at[24]);    MULADD(at[14], at[23]);    MULADD(at[15], at[22]);    MULADD(at[16], at[21]); 
   COMBA_STORE(C->dp[20]);
   /* 21 */
   COMBA_FORWARD;
   MULADD(at[5], at[33]);    MULADD(at[6], at[32]);    MULADD(at[7], at[31]);    MULADD(at[8], at[30]);    MULADD(at[9], at[29]);    MULADD(at[10], at[28]);    MULADD(at[11], at[27]);    MULADD(at[12], at[26]);    MULADD(at[13], at[25]);    MULADD(at[14], at[24]);    MULADD(at[15], at[23]);    MULADD(at[16], at[22]); 
   COMBA_STORE(C->dp[21]);
   /* 22 */
   COMBA_FORWARD;
   MULADD(at[6], at[33]);    MULADD(at[7], at[32]);    MULADD(at[8], at[31]);    MULADD(at[9], at[30]);    MULADD(at[10], at[29]);    MULADD(at[11], at[28]);    MULADD(at[12], at[27]);    MULADD(at[13], at[26]);    MULADD(at[14], at[25]);    MULADD(at[15], at[24]);    MULADD(at[16], at[23]); 
   COMBA_STORE(C->dp[22]);
   /* 23 */
   COMBA_FORWARD;
   MULADD(at[7], at[33]);    MULADD(at[8], at[32]);    MULADD(at[9], at[31]);    MULADD(at[10], at[30]);    MULADD(at[11], at[29]);    MULADD(at[12], at[28]);    MULADD(at[13], at[27]);    MULADD(at[14], at[26]);    MULADD(at[15], at[25]);    MULADD(at[16], at[24]); 
   COMBA_STORE(C->dp[23]);
   /* 24 */
   COMBA_FORWARD;
   MULADD(at[8], at[33]);    MULADD(at[9], at[32]);    MULADD(at[10], at[31]);    MULADD(at[11], at[30]);    MULADD(at[12], at[29]);    MULADD(at[13], at[28]);    MULADD(at[14], at[27]);    MULADD(at[15], at[26]);    MULADD(at[16], at[25]); 
   COMBA_STORE(C->dp[24]);
   /* 25 */
   COMBA_FORWARD;
   MULADD(at[9], at[33]);    MULADD(at[10], at[32]);    MULADD(at[11], at[31]);    MULADD(at[12], at[30]);    MULADD(at[13], at[29]);    MULADD(at[14], at[28]);    MULADD(at[15], at[27]);    MULADD(at[16], at[26]); 
   COMBA_STORE(C->dp[25]);
   /* 26 */
   COMBA_FORWARD;
   MULADD(at[10], at[33]);    MULADD(at[11], at[32]);    MULADD(at[12], at[31]);    MULADD(at[13], at[30]);    MULADD(at[14], at[29]);    MULADD(at[15], at[28]);    MULADD(at[16], at[27]); 
   COMBA_STORE(C->dp[26]);
   /* 27 */
   COMBA_FORWARD;
   MULADD(at[11], at[33]);    MULADD(at[12], at[32]);    MULADD(at[13], at[31]);    MULADD(at[14], at[30]);    MULADD(at[15], at[29]);    MULADD(at[16], at[28]); 
   COMBA_STORE(C->dp[27]);
   /* 28 */
   COMBA_FORWARD;
   MULADD(at[12], at[33]);    MULADD(at[13], at[32]);    MULADD(at[14], at[31]);    MULADD(at[15], at[30]);    MULADD(at[16], at[29]); 
   COMBA_STORE(C->dp[28]);
   /* 29 */
   COMBA_FORWARD;
   MULADD(at[13], at[33]);    MULADD(at[14], at[32]);    MULADD(at[15], at[31]);    MULADD(at[16], at[30]); 
   COMBA_STORE(C->dp[29]);
   /* 30 */
   COMBA_FORWARD;
   MULADD(at[14], at[33]);    MULADD(at[15], at[32]);    MULADD(at[16], at[31]); 
   COMBA_STORE(C->dp[30]);
   /* 31 */
   COMBA_FORWARD;
   MULADD(at[15], at[33]);    MULADD(at[16], at[32]); 
   COMBA_STORE(C->dp[31]);
   /* 32 */
   COMBA_FORWARD;
   MULADD(at[16], at[33]); 
   COMBA_STORE(C->dp[32]);
   COMBA_STORE2(C->dp[33]);
   C->used = 34;
   C->sign = A->sign ^ B->sign;
   fp_clamp(C);
   COMBA_FINI;
}
#endif

/* End: fp_mul_comba_17.c */

/* Start: fp_mul_comba_20.c */
#define TFM_DEFINES
#include "fp_mul_comba.c"

#ifdef TFM_MUL20
void fp_mul_comba20(fp_int *A, fp_int *B, fp_int *C)
{
   fp_digit c0, c1, c2, at[40];
   
   memcpy(at, A->dp, 20 * sizeof(fp_digit));
   memcpy(at+20, B->dp, 20 * sizeof(fp_digit));
   COMBA_START;

   COMBA_CLEAR;
   /* 0 */
   MULADD(at[0], at[20]); 
   COMBA_STORE(C->dp[0]);
   /* 1 */
   COMBA_FORWARD;
   MULADD(at[0], at[21]);    MULADD(at[1], at[20]); 
   COMBA_STORE(C->dp[1]);
   /* 2 */
   COMBA_FORWARD;
   MULADD(at[0], at[22]);    MULADD(at[1], at[21]);    MULADD(at[2], at[20]); 
   COMBA_STORE(C->dp[2]);
   /* 3 */
   COMBA_FORWARD;
   MULADD(at[0], at[23]);    MULADD(at[1], at[22]);    MULADD(at[2], at[21]);    MULADD(at[3], at[20]); 
   COMBA_STORE(C->dp[3]);
   /* 4 */
   COMBA_FORWARD;
   MULADD(at[0], at[24]);    MULADD(at[1], at[23]);    MULADD(at[2], at[22]);    MULADD(at[3], at[21]);    MULADD(at[4], at[20]); 
   COMBA_STORE(C->dp[4]);
   /* 5 */
   COMBA_FORWARD;
   MULADD(at[0], at[25]);    MULADD(at[1], at[24]);    MULADD(at[2], at[23]);    MULADD(at[3], at[22]);    MULADD(at[4], at[21]);    MULADD(at[5], at[20]); 
   COMBA_STORE(C->dp[5]);
   /* 6 */
   COMBA_FORWARD;
   MULADD(at[0], at[26]);    MULADD(at[1], at[25]);    MULADD(at[2], at[24]);    MULADD(at[3], at[23]);    MULADD(at[4], at[22]);    MULADD(at[5], at[21]);    MULADD(at[6], at[20]); 
   COMBA_STORE(C->dp[6]);
   /* 7 */
   COMBA_FORWARD;
   MULADD(at[0], at[27]);    MULADD(at[1], at[26]);    MULADD(at[2], at[25]);    MULADD(at[3], at[24]);    MULADD(at[4], at[23]);    MULADD(at[5], at[22]);    MULADD(at[6], at[21]);    MULADD(at[7], at[20]); 
   COMBA_STORE(C->dp[7]);
   /* 8 */
   COMBA_FORWARD;
   MULADD(at[0], at[28]);    MULADD(at[1], at[27]);    MULADD(at[2], at[26]);    MULADD(at[3], at[25]);    MULADD(at[4], at[24]);    MULADD(at[5], at[23]);    MULADD(at[6], at[22]);    MULADD(at[7], at[21]);    MULADD(at[8], at[20]); 
   COMBA_STORE(C->dp[8]);
   /* 9 */
   COMBA_FORWARD;
   MULADD(at[0], at[29]);    MULADD(at[1], at[28]);    MULADD(at[2], at[27]);    MULADD(at[3], at[26]);    MULADD(at[4], at[25]);    MULADD(at[5], at[24]);    MULADD(at[6], at[23]);    MULADD(at[7], at[22]);    MULADD(at[8], at[21]);    MULADD(at[9], at[20]); 
   COMBA_STORE(C->dp[9]);
   /* 10 */
   COMBA_FORWARD;
   MULADD(at[0], at[30]);    MULADD(at[1], at[29]);    MULADD(at[2], at[28]);    MULADD(at[3], at[27]);    MULADD(at[4], at[26]);    MULADD(at[5], at[25]);    MULADD(at[6], at[24]);    MULADD(at[7], at[23]);    MULADD(at[8], at[22]);    MULADD(at[9], at[21]);    MULADD(at[10], at[20]); 
   COMBA_STORE(C->dp[10]);
   /* 11 */
   COMBA_FORWARD;
   MULADD(at[0], at[31]);    MULADD(at[1], at[30]);    MULADD(at[2], at[29]);    MULADD(at[3], at[28]);    MULADD(at[4], at[27]);    MULADD(at[5], at[26]);    MULADD(at[6], at[25]);    MULADD(at[7], at[24]);    MULADD(at[8], at[23]);    MULADD(at[9], at[22]);    MULADD(at[10], at[21]);    MULADD(at[11], at[20]); 
   COMBA_STORE(C->dp[11]);
   /* 12 */
   COMBA_FORWARD;
   MULADD(at[0], at[32]);    MULADD(at[1], at[31]);    MULADD(at[2], at[30]);    MULADD(at[3], at[29]);    MULADD(at[4], at[28]);    MULADD(at[5], at[27]);    MULADD(at[6], at[26]);    MULADD(at[7], at[25]);    MULADD(at[8], at[24]);    MULADD(at[9], at[23]);    MULADD(at[10], at[22]);    MULADD(at[11], at[21]);    MULADD(at[12], at[20]); 
   COMBA_STORE(C->dp[12]);
   /* 13 */
   COMBA_FORWARD;
   MULADD(at[0], at[33]);    MULADD(at[1], at[32]);    MULADD(at[2], at[31]);    MULADD(at[3], at[30]);    MULADD(at[4], at[29]);    MULADD(at[5], at[28]);    MULADD(at[6], at[27]);    MULADD(at[7], at[26]);    MULADD(at[8], at[25]);    MULADD(at[9], at[24]);    MULADD(at[10], at[23]);    MULADD(at[11], at[22]);    MULADD(at[12], at[21]);    MULADD(at[13], at[20]); 
   COMBA_STORE(C->dp[13]);
   /* 14 */
   COMBA_FORWARD;
   MULADD(at[0], at[34]);    MULADD(at[1], at[33]);    MULADD(at[2], at[32]);    MULADD(at[3], at[31]);    MULADD(at[4], at[30]);    MULADD(at[5], at[29]);    MULADD(at[6], at[28]);    MULADD(at[7], at[27]);    MULADD(at[8], at[26]);    MULADD(at[9], at[25]);    MULADD(at[10], at[24]);    MULADD(at[11], at[23]);    MULADD(at[12], at[22]);    MULADD(at[13], at[21]);    MULADD(at[14], at[20]); 
   COMBA_STORE(C->dp[14]);
   /* 15 */
   COMBA_FORWARD;
   MULADD(at[0], at[35]);    MULADD(at[1], at[34]);    MULADD(at[2], at[33]);    MULADD(at[3], at[32]);    MULADD(at[4], at[31]);    MULADD(at[5], at[30]);    MULADD(at[6], at[29]);    MULADD(at[7], at[28]);    MULADD(at[8], at[27]);    MULADD(at[9], at[26]);    MULADD(at[10], at[25]);    MULADD(at[11], at[24]);    MULADD(at[12], at[23]);    MULADD(at[13], at[22]);    MULADD(at[14], at[21]);    MULADD(at[15], at[20]); 
   COMBA_STORE(C->dp[15]);
   /* 16 */
   COMBA_FORWARD;
   MULADD(at[0], at[36]);    MULADD(at[1], at[35]);    MULADD(at[2], at[34]);    MULADD(at[3], at[33]);    MULADD(at[4], at[32]);    MULADD(at[5], at[31]);    MULADD(at[6], at[30]);    MULADD(at[7], at[29]);    MULADD(at[8], at[28]);    MULADD(at[9], at[27]);    MULADD(at[10], at[26]);    MULADD(at[11], at[25]);    MULADD(at[12], at[24]);    MULADD(at[13], at[23]);    MULADD(at[14], at[22]);    MULADD(at[15], at[21]);    MULADD(at[16], at[20]); 
   COMBA_STORE(C->dp[16]);
   /* 17 */
   COMBA_FORWARD;
   MULADD(at[0], at[37]);    MULADD(at[1], at[36]);    MULADD(at[2], at[35]);    MULADD(at[3], at[34]);    MULADD(at[4], at[33]);    MULADD(at[5], at[32]);    MULADD(at[6], at[31]);    MULADD(at[7], at[30]);    MULADD(at[8], at[29]);    MULADD(at[9], at[28]);    MULADD(at[10], at[27]);    MULADD(at[11], at[26]);    MULADD(at[12], at[25]);    MULADD(at[13], at[24]);    MULADD(at[14], at[23]);    MULADD(at[15], at[22]);    MULADD(at[16], at[21]);    MULADD(at[17], at[20]); 
   COMBA_STORE(C->dp[17]);
   /* 18 */
   COMBA_FORWARD;
   MULADD(at[0], at[38]);    MULADD(at[1], at[37]);    MULADD(at[2], at[36]);    MULADD(at[3], at[35]);    MULADD(at[4], at[34]);    MULADD(at[5], at[33]);    MULADD(at[6], at[32]);    MULADD(at[7], at[31]);    MULADD(at[8], at[30]);    MULADD(at[9], at[29]);    MULADD(at[10], at[28]);    MULADD(at[11], at[27]);    MULADD(at[12], at[26]);    MULADD(at[13], at[25]);    MULADD(at[14], at[24]);    MULADD(at[15], at[23]);    MULADD(at[16], at[22]);    MULADD(at[17], at[21]);    MULADD(at[18], at[20]); 
   COMBA_STORE(C->dp[18]);
   /* 19 */
   COMBA_FORWARD;
   MULADD(at[0], at[39]);    MULADD(at[1], at[38]);    MULADD(at[2], at[37]);    MULADD(at[3], at[36]);    MULADD(at[4], at[35]);    MULADD(at[5], at[34]);    MULADD(at[6], at[33]);    MULADD(at[7], at[32]);    MULADD(at[8], at[31]);    MULADD(at[9], at[30]);    MULADD(at[10], at[29]);    MULADD(at[11], at[28]);    MULADD(at[12], at[27]);    MULADD(at[13], at[26]);    MULADD(at[14], at[25]);    MULADD(at[15], at[24]);    MULADD(at[16], at[23]);    MULADD(at[17], at[22]);    MULADD(at[18], at[21]);    MULADD(at[19], at[20]); 
   COMBA_STORE(C->dp[19]);
   /* 20 */
   COMBA_FORWARD;
   MULADD(at[1], at[39]);    MULADD(at[2], at[38]);    MULADD(at[3], at[37]);    MULADD(at[4], at[36]);    MULADD(at[5], at[35]);    MULADD(at[6], at[34]);    MULADD(at[7], at[33]);    MULADD(at[8], at[32]);    MULADD(at[9], at[31]);    MULADD(at[10], at[30]);    MULADD(at[11], at[29]);    MULADD(at[12], at[28]);    MULADD(at[13], at[27]);    MULADD(at[14], at[26]);    MULADD(at[15], at[25]);    MULADD(at[16], at[24]);    MULADD(at[17], at[23]);    MULADD(at[18], at[22]);    MULADD(at[19], at[21]); 
   COMBA_STORE(C->dp[20]);
   /* 21 */
   COMBA_FORWARD;
   MULADD(at[2], at[39]);    MULADD(at[3], at[38]);    MULADD(at[4], at[37]);    MULADD(at[5], at[36]);    MULADD(at[6], at[35]);    MULADD(at[7], at[34]);    MULADD(at[8], at[33]);    MULADD(at[9], at[32]);    MULADD(at[10], at[31]);    MULADD(at[11], at[30]);    MULADD(at[12], at[29]);    MULADD(at[13], at[28]);    MULADD(at[14], at[27]);    MULADD(at[15], at[26]);    MULADD(at[16], at[25]);    MULADD(at[17], at[24]);    MULADD(at[18], at[23]);    MULADD(at[19], at[22]); 
   COMBA_STORE(C->dp[21]);
   /* 22 */
   COMBA_FORWARD;
   MULADD(at[3], at[39]);    MULADD(at[4], at[38]);    MULADD(at[5], at[37]);    MULADD(at[6], at[36]);    MULADD(at[7], at[35]);    MULADD(at[8], at[34]);    MULADD(at[9], at[33]);    MULADD(at[10], at[32]);    MULADD(at[11], at[31]);    MULADD(at[12], at[30]);    MULADD(at[13], at[29]);    MULADD(at[14], at[28]);    MULADD(at[15], at[27]);    MULADD(at[16], at[26]);    MULADD(at[17], at[25]);    MULADD(at[18], at[24]);    MULADD(at[19], at[23]); 
   COMBA_STORE(C->dp[22]);
   /* 23 */
   COMBA_FORWARD;
   MULADD(at[4], at[39]);    MULADD(at[5], at[38]);    MULADD(at[6], at[37]);    MULADD(at[7], at[36]);    MULADD(at[8], at[35]);    MULADD(at[9], at[34]);    MULADD(at[10], at[33]);    MULADD(at[11], at[32]);    MULADD(at[12], at[31]);    MULADD(at[13], at[30]);    MULADD(at[14], at[29]);    MULADD(at[15], at[28]);    MULADD(at[16], at[27]);    MULADD(at[17], at[26]);    MULADD(at[18], at[25]);    MULADD(at[19], at[24]); 
   COMBA_STORE(C->dp[23]);
   /* 24 */
   COMBA_FORWARD;
   MULADD(at[5], at[39]);    MULADD(at[6], at[38]);    MULADD(at[7], at[37]);    MULADD(at[8], at[36]);    MULADD(at[9], at[35]);    MULADD(at[10], at[34]);    MULADD(at[11], at[33]);    MULADD(at[12], at[32]);    MULADD(at[13], at[31]);    MULADD(at[14], at[30]);    MULADD(at[15], at[29]);    MULADD(at[16], at[28]);    MULADD(at[17], at[27]);    MULADD(at[18], at[26]);    MULADD(at[19], at[25]); 
   COMBA_STORE(C->dp[24]);
   /* 25 */
   COMBA_FORWARD;
   MULADD(at[6], at[39]);    MULADD(at[7], at[38]);    MULADD(at[8], at[37]);    MULADD(at[9], at[36]);    MULADD(at[10], at[35]);    MULADD(at[11], at[34]);    MULADD(at[12], at[33]);    MULADD(at[13], at[32]);    MULADD(at[14], at[31]);    MULADD(at[15], at[30]);    MULADD(at[16], at[29]);    MULADD(at[17], at[28]);    MULADD(at[18], at[27]);    MULADD(at[19], at[26]); 
   COMBA_STORE(C->dp[25]);
   /* 26 */
   COMBA_FORWARD;
   MULADD(at[7], at[39]);    MULADD(at[8], at[38]);    MULADD(at[9], at[37]);    MULADD(at[10], at[36]);    MULADD(at[11], at[35]);    MULADD(at[12], at[34]);    MULADD(at[13], at[33]);    MULADD(at[14], at[32]);    MULADD(at[15], at[31]);    MULADD(at[16], at[30]);    MULADD(at[17], at[29]);    MULADD(at[18], at[28]);    MULADD(at[19], at[27]); 
   COMBA_STORE(C->dp[26]);
   /* 27 */
   COMBA_FORWARD;
   MULADD(at[8], at[39]);    MULADD(at[9], at[38]);    MULADD(at[10], at[37]);    MULADD(at[11], at[36]);    MULADD(at[12], at[35]);    MULADD(at[13], at[34]);    MULADD(at[14], at[33]);    MULADD(at[15], at[32]);    MULADD(at[16], at[31]);    MULADD(at[17], at[30]);    MULADD(at[18], at[29]);    MULADD(at[19], at[28]); 
   COMBA_STORE(C->dp[27]);
   /* 28 */
   COMBA_FORWARD;
   MULADD(at[9], at[39]);    MULADD(at[10], at[38]);    MULADD(at[11], at[37]);    MULADD(at[12], at[36]);    MULADD(at[13], at[35]);    MULADD(at[14], at[34]);    MULADD(at[15], at[33]);    MULADD(at[16], at[32]);    MULADD(at[17], at[31]);    MULADD(at[18], at[30]);    MULADD(at[19], at[29]); 
   COMBA_STORE(C->dp[28]);
   /* 29 */
   COMBA_FORWARD;
   MULADD(at[10], at[39]);    MULADD(at[11], at[38]);    MULADD(at[12], at[37]);    MULADD(at[13], at[36]);    MULADD(at[14], at[35]);    MULADD(at[15], at[34]);    MULADD(at[16], at[33]);    MULADD(at[17], at[32]);    MULADD(at[18], at[31]);    MULADD(at[19], at[30]); 
   COMBA_STORE(C->dp[29]);
   /* 30 */
   COMBA_FORWARD;
   MULADD(at[11], at[39]);    MULADD(at[12], at[38]);    MULADD(at[13], at[37]);    MULADD(at[14], at[36]);    MULADD(at[15], at[35]);    MULADD(at[16], at[34]);    MULADD(at[17], at[33]);    MULADD(at[18], at[32]);    MULADD(at[19], at[31]); 
   COMBA_STORE(C->dp[30]);
   /* 31 */
   COMBA_FORWARD;
   MULADD(at[12], at[39]);    MULADD(at[13], at[38]);    MULADD(at[14], at[37]);    MULADD(at[15], at[36]);    MULADD(at[16], at[35]);    MULADD(at[17], at[34]);    MULADD(at[18], at[33]);    MULADD(at[19], at[32]); 
   COMBA_STORE(C->dp[31]);
   /* 32 */
   COMBA_FORWARD;
   MULADD(at[13], at[39]);    MULADD(at[14], at[38]);    MULADD(at[15], at[37]);    MULADD(at[16], at[36]);    MULADD(at[17], at[35]);    MULADD(at[18], at[34]);    MULADD(at[19], at[33]); 
   COMBA_STORE(C->dp[32]);
   /* 33 */
   COMBA_FORWARD;
   MULADD(at[14], at[39]);    MULADD(at[15], at[38]);    MULADD(at[16], at[37]);    MULADD(at[17], at[36]);    MULADD(at[18], at[35]);    MULADD(at[19], at[34]); 
   COMBA_STORE(C->dp[33]);
   /* 34 */
   COMBA_FORWARD;
   MULADD(at[15], at[39]);    MULADD(at[16], at[38]);    MULADD(at[17], at[37]);    MULADD(at[18], at[36]);    MULADD(at[19], at[35]); 
   COMBA_STORE(C->dp[34]);
   /* 35 */
   COMBA_FORWARD;
   MULADD(at[16], at[39]);    MULADD(at[17], at[38]);    MULADD(at[18], at[37]);    MULADD(at[19], at[36]); 
   COMBA_STORE(C->dp[35]);
   /* 36 */
   COMBA_FORWARD;
   MULADD(at[17], at[39]);    MULADD(at[18], at[38]);    MULADD(at[19], at[37]); 
   COMBA_STORE(C->dp[36]);
   /* 37 */
   COMBA_FORWARD;
   MULADD(at[18], at[39]);    MULADD(at[19], at[38]); 
   COMBA_STORE(C->dp[37]);
   /* 38 */
   COMBA_FORWARD;
   MULADD(at[19], at[39]); 
   COMBA_STORE(C->dp[38]);
   COMBA_STORE2(C->dp[39]);
   C->used = 40;
   C->sign = A->sign ^ B->sign;
   fp_clamp(C);
   COMBA_FINI;
}
#endif

/* End: fp_mul_comba_20.c */

/* Start: fp_mul_comba_24.c */
#define TFM_DEFINES
#include "fp_mul_comba.c"

#ifdef TFM_MUL24
void fp_mul_comba24(fp_int *A, fp_int *B, fp_int *C)
{
   fp_digit c0, c1, c2, at[48];

   memcpy(at, A->dp, 24 * sizeof(fp_digit));
   memcpy(at+24, B->dp, 24 * sizeof(fp_digit));
   COMBA_START;

   COMBA_CLEAR;
   /* 0 */
   MULADD(at[0], at[24]); 
   COMBA_STORE(C->dp[0]);
   /* 1 */
   COMBA_FORWARD;
   MULADD(at[0], at[25]);    MULADD(at[1], at[24]); 
   COMBA_STORE(C->dp[1]);
   /* 2 */
   COMBA_FORWARD;
   MULADD(at[0], at[26]);    MULADD(at[1], at[25]);    MULADD(at[2], at[24]); 
   COMBA_STORE(C->dp[2]);
   /* 3 */
   COMBA_FORWARD;
   MULADD(at[0], at[27]);    MULADD(at[1], at[26]);    MULADD(at[2], at[25]);    MULADD(at[3], at[24]); 
   COMBA_STORE(C->dp[3]);
   /* 4 */
   COMBA_FORWARD;
   MULADD(at[0], at[28]);    MULADD(at[1], at[27]);    MULADD(at[2], at[26]);    MULADD(at[3], at[25]);    MULADD(at[4], at[24]); 
   COMBA_STORE(C->dp[4]);
   /* 5 */
   COMBA_FORWARD;
   MULADD(at[0], at[29]);    MULADD(at[1], at[28]);    MULADD(at[2], at[27]);    MULADD(at[3], at[26]);    MULADD(at[4], at[25]);    MULADD(at[5], at[24]); 
   COMBA_STORE(C->dp[5]);
   /* 6 */
   COMBA_FORWARD;
   MULADD(at[0], at[30]);    MULADD(at[1], at[29]);    MULADD(at[2], at[28]);    MULADD(at[3], at[27]);    MULADD(at[4], at[26]);    MULADD(at[5], at[25]);    MULADD(at[6], at[24]); 
   COMBA_STORE(C->dp[6]);
   /* 7 */
   COMBA_FORWARD;
   MULADD(at[0], at[31]);    MULADD(at[1], at[30]);    MULADD(at[2], at[29]);    MULADD(at[3], at[28]);    MULADD(at[4], at[27]);    MULADD(at[5], at[26]);    MULADD(at[6], at[25]);    MULADD(at[7], at[24]); 
   COMBA_STORE(C->dp[7]);
   /* 8 */
   COMBA_FORWARD;
   MULADD(at[0], at[32]);    MULADD(at[1], at[31]);    MULADD(at[2], at[30]);    MULADD(at[3], at[29]);    MULADD(at[4], at[28]);    MULADD(at[5], at[27]);    MULADD(at[6], at[26]);    MULADD(at[7], at[25]);    MULADD(at[8], at[24]); 
   COMBA_STORE(C->dp[8]);
   /* 9 */
   COMBA_FORWARD;
   MULADD(at[0], at[33]);    MULADD(at[1], at[32]);    MULADD(at[2], at[31]);    MULADD(at[3], at[30]);    MULADD(at[4], at[29]);    MULADD(at[5], at[28]);    MULADD(at[6], at[27]);    MULADD(at[7], at[26]);    MULADD(at[8], at[25]);    MULADD(at[9], at[24]); 
   COMBA_STORE(C->dp[9]);
   /* 10 */
   COMBA_FORWARD;
   MULADD(at[0], at[34]);    MULADD(at[1], at[33]);    MULADD(at[2], at[32]);    MULADD(at[3], at[31]);    MULADD(at[4], at[30]);    MULADD(at[5], at[29]);    MULADD(at[6], at[28]);    MULADD(at[7], at[27]);    MULADD(at[8], at[26]);    MULADD(at[9], at[25]);    MULADD(at[10], at[24]); 
   COMBA_STORE(C->dp[10]);
   /* 11 */
   COMBA_FORWARD;
   MULADD(at[0], at[35]);    MULADD(at[1], at[34]);    MULADD(at[2], at[33]);    MULADD(at[3], at[32]);    MULADD(at[4], at[31]);    MULADD(at[5], at[30]);    MULADD(at[6], at[29]);    MULADD(at[7], at[28]);    MULADD(at[8], at[27]);    MULADD(at[9], at[26]);    MULADD(at[10], at[25]);    MULADD(at[11], at[24]); 
   COMBA_STORE(C->dp[11]);
   /* 12 */
   COMBA_FORWARD;
   MULADD(at[0], at[36]);    MULADD(at[1], at[35]);    MULADD(at[2], at[34]);    MULADD(at[3], at[33]);    MULADD(at[4], at[32]);    MULADD(at[5], at[31]);    MULADD(at[6], at[30]);    MULADD(at[7], at[29]);    MULADD(at[8], at[28]);    MULADD(at[9], at[27]);    MULADD(at[10], at[26]);    MULADD(at[11], at[25]);    MULADD(at[12], at[24]); 
   COMBA_STORE(C->dp[12]);
   /* 13 */
   COMBA_FORWARD;
   MULADD(at[0], at[37]);    MULADD(at[1], at[36]);    MULADD(at[2], at[35]);    MULADD(at[3], at[34]);    MULADD(at[4], at[33]);    MULADD(at[5], at[32]);    MULADD(at[6], at[31]);    MULADD(at[7], at[30]);    MULADD(at[8], at[29]);    MULADD(at[9], at[28]);    MULADD(at[10], at[27]);    MULADD(at[11], at[26]);    MULADD(at[12], at[25]);    MULADD(at[13], at[24]); 
   COMBA_STORE(C->dp[13]);
   /* 14 */
   COMBA_FORWARD;
   MULADD(at[0], at[38]);    MULADD(at[1], at[37]);    MULADD(at[2], at[36]);    MULADD(at[3], at[35]);    MULADD(at[4], at[34]);    MULADD(at[5], at[33]);    MULADD(at[6], at[32]);    MULADD(at[7], at[31]);    MULADD(at[8], at[30]);    MULADD(at[9], at[29]);    MULADD(at[10], at[28]);    MULADD(at[11], at[27]);    MULADD(at[12], at[26]);    MULADD(at[13], at[25]);    MULADD(at[14], at[24]); 
   COMBA_STORE(C->dp[14]);
   /* 15 */
   COMBA_FORWARD;
   MULADD(at[0], at[39]);    MULADD(at[1], at[38]);    MULADD(at[2], at[37]);    MULADD(at[3], at[36]);    MULADD(at[4], at[35]);    MULADD(at[5], at[34]);    MULADD(at[6], at[33]);    MULADD(at[7], at[32]);    MULADD(at[8], at[31]);    MULADD(at[9], at[30]);    MULADD(at[10], at[29]);    MULADD(at[11], at[28]);    MULADD(at[12], at[27]);    MULADD(at[13], at[26]);    MULADD(at[14], at[25]);    MULADD(at[15], at[24]); 
   COMBA_STORE(C->dp[15]);
   /* 16 */
   COMBA_FORWARD;
   MULADD(at[0], at[40]);    MULADD(at[1], at[39]);    MULADD(at[2], at[38]);    MULADD(at[3], at[37]);    MULADD(at[4], at[36]);    MULADD(at[5], at[35]);    MULADD(at[6], at[34]);    MULADD(at[7], at[33]);    MULADD(at[8], at[32]);    MULADD(at[9], at[31]);    MULADD(at[10], at[30]);    MULADD(at[11], at[29]);    MULADD(at[12], at[28]);    MULADD(at[13], at[27]);    MULADD(at[14], at[26]);    MULADD(at[15], at[25]);    MULADD(at[16], at[24]); 
   COMBA_STORE(C->dp[16]);
   /* 17 */
   COMBA_FORWARD;
   MULADD(at[0], at[41]);    MULADD(at[1], at[40]);    MULADD(at[2], at[39]);    MULADD(at[3], at[38]);    MULADD(at[4], at[37]);    MULADD(at[5], at[36]);    MULADD(at[6], at[35]);    MULADD(at[7], at[34]);    MULADD(at[8], at[33]);    MULADD(at[9], at[32]);    MULADD(at[10], at[31]);    MULADD(at[11], at[30]);    MULADD(at[12], at[29]);    MULADD(at[13], at[28]);    MULADD(at[14], at[27]);    MULADD(at[15], at[26]);    MULADD(at[16], at[25]);    MULADD(at[17], at[24]); 
   COMBA_STORE(C->dp[17]);
   /* 18 */
   COMBA_FORWARD;
   MULADD(at[0], at[42]);    MULADD(at[1], at[41]);    MULADD(at[2], at[40]);    MULADD(at[3], at[39]);    MULADD(at[4], at[38]);    MULADD(at[5], at[37]);    MULADD(at[6], at[36]);    MULADD(at[7], at[35]);    MULADD(at[8], at[34]);    MULADD(at[9], at[33]);    MULADD(at[10], at[32]);    MULADD(at[11], at[31]);    MULADD(at[12], at[30]);    MULADD(at[13], at[29]);    MULADD(at[14], at[28]);    MULADD(at[15], at[27]);    MULADD(at[16], at[26]);    MULADD(at[17], at[25]);    MULADD(at[18], at[24]); 
   COMBA_STORE(C->dp[18]);
   /* 19 */
   COMBA_FORWARD;
   MULADD(at[0], at[43]);    MULADD(at[1], at[42]);    MULADD(at[2], at[41]);    MULADD(at[3], at[40]);    MULADD(at[4], at[39]);    MULADD(at[5], at[38]);    MULADD(at[6], at[37]);    MULADD(at[7], at[36]);    MULADD(at[8], at[35]);    MULADD(at[9], at[34]);    MULADD(at[10], at[33]);    MULADD(at[11], at[32]);    MULADD(at[12], at[31]);    MULADD(at[13], at[30]);    MULADD(at[14], at[29]);    MULADD(at[15], at[28]);    MULADD(at[16], at[27]);    MULADD(at[17], at[26]);    MULADD(at[18], at[25]);    MULADD(at[19], at[24]); 
   COMBA_STORE(C->dp[19]);
   /* 20 */
   COMBA_FORWARD;
   MULADD(at[0], at[44]);    MULADD(at[1], at[43]);    MULADD(at[2], at[42]);    MULADD(at[3], at[41]);    MULADD(at[4], at[40]);    MULADD(at[5], at[39]);    MULADD(at[6], at[38]);    MULADD(at[7], at[37]);    MULADD(at[8], at[36]);    MULADD(at[9], at[35]);    MULADD(at[10], at[34]);    MULADD(at[11], at[33]);    MULADD(at[12], at[32]);    MULADD(at[13], at[31]);    MULADD(at[14], at[30]);    MULADD(at[15], at[29]);    MULADD(at[16], at[28]);    MULADD(at[17], at[27]);    MULADD(at[18], at[26]);    MULADD(at[19], at[25]);    MULADD(at[20], at[24]); 
   COMBA_STORE(C->dp[20]);
   /* 21 */
   COMBA_FORWARD;
   MULADD(at[0], at[45]);    MULADD(at[1], at[44]);    MULADD(at[2], at[43]);    MULADD(at[3], at[42]);    MULADD(at[4], at[41]);    MULADD(at[5], at[40]);    MULADD(at[6], at[39]);    MULADD(at[7], at[38]);    MULADD(at[8], at[37]);    MULADD(at[9], at[36]);    MULADD(at[10], at[35]);    MULADD(at[11], at[34]);    MULADD(at[12], at[33]);    MULADD(at[13], at[32]);    MULADD(at[14], at[31]);    MULADD(at[15], at[30]);    MULADD(at[16], at[29]);    MULADD(at[17], at[28]);    MULADD(at[18], at[27]);    MULADD(at[19], at[26]);    MULADD(at[20], at[25]);    MULADD(at[21], at[24]); 
   COMBA_STORE(C->dp[21]);
   /* 22 */
   COMBA_FORWARD;
   MULADD(at[0], at[46]);    MULADD(at[1], at[45]);    MULADD(at[2], at[44]);    MULADD(at[3], at[43]);    MULADD(at[4], at[42]);    MULADD(at[5], at[41]);    MULADD(at[6], at[40]);    MULADD(at[7], at[39]);    MULADD(at[8], at[38]);    MULADD(at[9], at[37]);    MULADD(at[10], at[36]);    MULADD(at[11], at[35]);    MULADD(at[12], at[34]);    MULADD(at[13], at[33]);    MULADD(at[14], at[32]);    MULADD(at[15], at[31]);    MULADD(at[16], at[30]);    MULADD(at[17], at[29]);    MULADD(at[18], at[28]);    MULADD(at[19], at[27]);    MULADD(at[20], at[26]);    MULADD(at[21], at[25]);    MULADD(at[22], at[24]); 
   COMBA_STORE(C->dp[22]);
   /* 23 */
   COMBA_FORWARD;
   MULADD(at[0], at[47]);    MULADD(at[1], at[46]);    MULADD(at[2], at[45]);    MULADD(at[3], at[44]);    MULADD(at[4], at[43]);    MULADD(at[5], at[42]);    MULADD(at[6], at[41]);    MULADD(at[7], at[40]);    MULADD(at[8], at[39]);    MULADD(at[9], at[38]);    MULADD(at[10], at[37]);    MULADD(at[11], at[36]);    MULADD(at[12], at[35]);    MULADD(at[13], at[34]);    MULADD(at[14], at[33]);    MULADD(at[15], at[32]);    MULADD(at[16], at[31]);    MULADD(at[17], at[30]);    MULADD(at[18], at[29]);    MULADD(at[19], at[28]);    MULADD(at[20], at[27]);    MULADD(at[21], at[26]);    MULADD(at[22], at[25]);    MULADD(at[23], at[24]); 
   COMBA_STORE(C->dp[23]);
   /* 24 */
   COMBA_FORWARD;
   MULADD(at[1], at[47]);    MULADD(at[2], at[46]);    MULADD(at[3], at[45]);    MULADD(at[4], at[44]);    MULADD(at[5], at[43]);    MULADD(at[6], at[42]);    MULADD(at[7], at[41]);    MULADD(at[8], at[40]);    MULADD(at[9], at[39]);    MULADD(at[10], at[38]);    MULADD(at[11], at[37]);    MULADD(at[12], at[36]);    MULADD(at[13], at[35]);    MULADD(at[14], at[34]);    MULADD(at[15], at[33]);    MULADD(at[16], at[32]);    MULADD(at[17], at[31]);    MULADD(at[18], at[30]);    MULADD(at[19], at[29]);    MULADD(at[20], at[28]);    MULADD(at[21], at[27]);    MULADD(at[22], at[26]);    MULADD(at[23], at[25]); 
   COMBA_STORE(C->dp[24]);
   /* 25 */
   COMBA_FORWARD;
   MULADD(at[2], at[47]);    MULADD(at[3], at[46]);    MULADD(at[4], at[45]);    MULADD(at[5], at[44]);    MULADD(at[6], at[43]);    MULADD(at[7], at[42]);    MULADD(at[8], at[41]);    MULADD(at[9], at[40]);    MULADD(at[10], at[39]);    MULADD(at[11], at[38]);    MULADD(at[12], at[37]);    MULADD(at[13], at[36]);    MULADD(at[14], at[35]);    MULADD(at[15], at[34]);    MULADD(at[16], at[33]);    MULADD(at[17], at[32]);    MULADD(at[18], at[31]);    MULADD(at[19], at[30]);    MULADD(at[20], at[29]);    MULADD(at[21], at[28]);    MULADD(at[22], at[27]);    MULADD(at[23], at[26]); 
   COMBA_STORE(C->dp[25]);
   /* 26 */
   COMBA_FORWARD;
   MULADD(at[3], at[47]);    MULADD(at[4], at[46]);    MULADD(at[5], at[45]);    MULADD(at[6], at[44]);    MULADD(at[7], at[43]);    MULADD(at[8], at[42]);    MULADD(at[9], at[41]);    MULADD(at[10], at[40]);    MULADD(at[11], at[39]);    MULADD(at[12], at[38]);    MULADD(at[13], at[37]);    MULADD(at[14], at[36]);    MULADD(at[15], at[35]);    MULADD(at[16], at[34]);    MULADD(at[17], at[33]);    MULADD(at[18], at[32]);    MULADD(at[19], at[31]);    MULADD(at[20], at[30]);    MULADD(at[21], at[29]);    MULADD(at[22], at[28]);    MULADD(at[23], at[27]); 
   COMBA_STORE(C->dp[26]);
   /* 27 */
   COMBA_FORWARD;
   MULADD(at[4], at[47]);    MULADD(at[5], at[46]);    MULADD(at[6], at[45]);    MULADD(at[7], at[44]);    MULADD(at[8], at[43]);    MULADD(at[9], at[42]);    MULADD(at[10], at[41]);    MULADD(at[11], at[40]);    MULADD(at[12], at[39]);    MULADD(at[13], at[38]);    MULADD(at[14], at[37]);    MULADD(at[15], at[36]);    MULADD(at[16], at[35]);    MULADD(at[17], at[34]);    MULADD(at[18], at[33]);    MULADD(at[19], at[32]);    MULADD(at[20], at[31]);    MULADD(at[21], at[30]);    MULADD(at[22], at[29]);    MULADD(at[23], at[28]); 
   COMBA_STORE(C->dp[27]);
   /* 28 */
   COMBA_FORWARD;
   MULADD(at[5], at[47]);    MULADD(at[6], at[46]);    MULADD(at[7], at[45]);    MULADD(at[8], at[44]);    MULADD(at[9], at[43]);    MULADD(at[10], at[42]);    MULADD(at[11], at[41]);    MULADD(at[12], at[40]);    MULADD(at[13], at[39]);    MULADD(at[14], at[38]);    MULADD(at[15], at[37]);    MULADD(at[16], at[36]);    MULADD(at[17], at[35]);    MULADD(at[18], at[34]);    MULADD(at[19], at[33]);    MULADD(at[20], at[32]);    MULADD(at[21], at[31]);    MULADD(at[22], at[30]);    MULADD(at[23], at[29]); 
   COMBA_STORE(C->dp[28]);
   /* 29 */
   COMBA_FORWARD;
   MULADD(at[6], at[47]);    MULADD(at[7], at[46]);    MULADD(at[8], at[45]);    MULADD(at[9], at[44]);    MULADD(at[10], at[43]);    MULADD(at[11], at[42]);    MULADD(at[12], at[41]);    MULADD(at[13], at[40]);    MULADD(at[14], at[39]);    MULADD(at[15], at[38]);    MULADD(at[16], at[37]);    MULADD(at[17], at[36]);    MULADD(at[18], at[35]);    MULADD(at[19], at[34]);    MULADD(at[20], at[33]);    MULADD(at[21], at[32]);    MULADD(at[22], at[31]);    MULADD(at[23], at[30]); 
   COMBA_STORE(C->dp[29]);
   /* 30 */
   COMBA_FORWARD;
   MULADD(at[7], at[47]);    MULADD(at[8], at[46]);    MULADD(at[9], at[45]);    MULADD(at[10], at[44]);    MULADD(at[11], at[43]);    MULADD(at[12], at[42]);    MULADD(at[13], at[41]);    MULADD(at[14], at[40]);    MULADD(at[15], at[39]);    MULADD(at[16], at[38]);    MULADD(at[17], at[37]);    MULADD(at[18], at[36]);    MULADD(at[19], at[35]);    MULADD(at[20], at[34]);    MULADD(at[21], at[33]);    MULADD(at[22], at[32]);    MULADD(at[23], at[31]); 
   COMBA_STORE(C->dp[30]);
   /* 31 */
   COMBA_FORWARD;
   MULADD(at[8], at[47]);    MULADD(at[9], at[46]);    MULADD(at[10], at[45]);    MULADD(at[11], at[44]);    MULADD(at[12], at[43]);    MULADD(at[13], at[42]);    MULADD(at[14], at[41]);    MULADD(at[15], at[40]);    MULADD(at[16], at[39]);    MULADD(at[17], at[38]);    MULADD(at[18], at[37]);    MULADD(at[19], at[36]);    MULADD(at[20], at[35]);    MULADD(at[21], at[34]);    MULADD(at[22], at[33]);    MULADD(at[23], at[32]); 
   COMBA_STORE(C->dp[31]);
   /* 32 */
   COMBA_FORWARD;
   MULADD(at[9], at[47]);    MULADD(at[10], at[46]);    MULADD(at[11], at[45]);    MULADD(at[12], at[44]);    MULADD(at[13], at[43]);    MULADD(at[14], at[42]);    MULADD(at[15], at[41]);    MULADD(at[16], at[40]);    MULADD(at[17], at[39]);    MULADD(at[18], at[38]);    MULADD(at[19], at[37]);    MULADD(at[20], at[36]);    MULADD(at[21], at[35]);    MULADD(at[22], at[34]);    MULADD(at[23], at[33]); 
   COMBA_STORE(C->dp[32]);
   /* 33 */
   COMBA_FORWARD;
   MULADD(at[10], at[47]);    MULADD(at[11], at[46]);    MULADD(at[12], at[45]);    MULADD(at[13], at[44]);    MULADD(at[14], at[43]);    MULADD(at[15], at[42]);    MULADD(at[16], at[41]);    MULADD(at[17], at[40]);    MULADD(at[18], at[39]);    MULADD(at[19], at[38]);    MULADD(at[20], at[37]);    MULADD(at[21], at[36]);    MULADD(at[22], at[35]);    MULADD(at[23], at[34]); 
   COMBA_STORE(C->dp[33]);
   /* 34 */
   COMBA_FORWARD;
   MULADD(at[11], at[47]);    MULADD(at[12], at[46]);    MULADD(at[13], at[45]);    MULADD(at[14], at[44]);    MULADD(at[15], at[43]);    MULADD(at[16], at[42]);    MULADD(at[17], at[41]);    MULADD(at[18], at[40]);    MULADD(at[19], at[39]);    MULADD(at[20], at[38]);    MULADD(at[21], at[37]);    MULADD(at[22], at[36]);    MULADD(at[23], at[35]); 
   COMBA_STORE(C->dp[34]);
   /* 35 */
   COMBA_FORWARD;
   MULADD(at[12], at[47]);    MULADD(at[13], at[46]);    MULADD(at[14], at[45]);    MULADD(at[15], at[44]);    MULADD(at[16], at[43]);    MULADD(at[17], at[42]);    MULADD(at[18], at[41]);    MULADD(at[19], at[40]);    MULADD(at[20], at[39]);    MULADD(at[21], at[38]);    MULADD(at[22], at[37]);    MULADD(at[23], at[36]); 
   COMBA_STORE(C->dp[35]);
   /* 36 */
   COMBA_FORWARD;
   MULADD(at[13], at[47]);    MULADD(at[14], at[46]);    MULADD(at[15], at[45]);    MULADD(at[16], at[44]);    MULADD(at[17], at[43]);    MULADD(at[18], at[42]);    MULADD(at[19], at[41]);    MULADD(at[20], at[40]);    MULADD(at[21], at[39]);    MULADD(at[22], at[38]);    MULADD(at[23], at[37]); 
   COMBA_STORE(C->dp[36]);
   /* 37 */
   COMBA_FORWARD;
   MULADD(at[14], at[47]);    MULADD(at[15], at[46]);    MULADD(at[16], at[45]);    MULADD(at[17], at[44]);    MULADD(at[18], at[43]);    MULADD(at[19], at[42]);    MULADD(at[20], at[41]);    MULADD(at[21], at[40]);    MULADD(at[22], at[39]);    MULADD(at[23], at[38]); 
   COMBA_STORE(C->dp[37]);
   /* 38 */
   COMBA_FORWARD;
   MULADD(at[15], at[47]);    MULADD(at[16], at[46]);    MULADD(at[17], at[45]);    MULADD(at[18], at[44]);    MULADD(at[19], at[43]);    MULADD(at[20], at[42]);    MULADD(at[21], at[41]);    MULADD(at[22], at[40]);    MULADD(at[23], at[39]); 
   COMBA_STORE(C->dp[38]);
   /* 39 */
   COMBA_FORWARD;
   MULADD(at[16], at[47]);    MULADD(at[17], at[46]);    MULADD(at[18], at[45]);    MULADD(at[19], at[44]);    MULADD(at[20], at[43]);    MULADD(at[21], at[42]);    MULADD(at[22], at[41]);    MULADD(at[23], at[40]); 
   COMBA_STORE(C->dp[39]);
   /* 40 */
   COMBA_FORWARD;
   MULADD(at[17], at[47]);    MULADD(at[18], at[46]);    MULADD(at[19], at[45]);    MULADD(at[20], at[44]);    MULADD(at[21], at[43]);    MULADD(at[22], at[42]);    MULADD(at[23], at[41]); 
   COMBA_STORE(C->dp[40]);
   /* 41 */
   COMBA_FORWARD;
   MULADD(at[18], at[47]);    MULADD(at[19], at[46]);    MULADD(at[20], at[45]);    MULADD(at[21], at[44]);    MULADD(at[22], at[43]);    MULADD(at[23], at[42]); 
   COMBA_STORE(C->dp[41]);
   /* 42 */
   COMBA_FORWARD;
   MULADD(at[19], at[47]);    MULADD(at[20], at[46]);    MULADD(at[21], at[45]);    MULADD(at[22], at[44]);    MULADD(at[23], at[43]); 
   COMBA_STORE(C->dp[42]);
   /* 43 */
   COMBA_FORWARD;
   MULADD(at[20], at[47]);    MULADD(at[21], at[46]);    MULADD(at[22], at[45]);    MULADD(at[23], at[44]); 
   COMBA_STORE(C->dp[43]);
   /* 44 */
   COMBA_FORWARD;
   MULADD(at[21], at[47]);    MULADD(at[22], at[46]);    MULADD(at[23], at[45]); 
   COMBA_STORE(C->dp[44]);
   /* 45 */
   COMBA_FORWARD;
   MULADD(at[22], at[47]);    MULADD(at[23], at[46]); 
   COMBA_STORE(C->dp[45]);
   /* 46 */
   COMBA_FORWARD;
   MULADD(at[23], at[47]); 
   COMBA_STORE(C->dp[46]);
   COMBA_STORE2(C->dp[47]);
   C->used = 48;
   C->sign = A->sign ^ B->sign;
   fp_clamp(C);
   COMBA_FINI;
}
#endif

/* End: fp_mul_comba_24.c */

/* Start: fp_mul_comba_28.c */
#define TFM_DEFINES
#include "fp_mul_comba.c"

#ifdef TFM_MUL28
void fp_mul_comba28(fp_int *A, fp_int *B, fp_int *C)
{
   fp_digit c0, c1, c2, at[56];

   memcpy(at, A->dp, 28 * sizeof(fp_digit));
   memcpy(at+28, B->dp, 28 * sizeof(fp_digit));
   COMBA_START;

   COMBA_CLEAR;
   /* 0 */
   MULADD(at[0], at[28]); 
   COMBA_STORE(C->dp[0]);
   /* 1 */
   COMBA_FORWARD;
   MULADD(at[0], at[29]);    MULADD(at[1], at[28]); 
   COMBA_STORE(C->dp[1]);
   /* 2 */
   COMBA_FORWARD;
   MULADD(at[0], at[30]);    MULADD(at[1], at[29]);    MULADD(at[2], at[28]); 
   COMBA_STORE(C->dp[2]);
   /* 3 */
   COMBA_FORWARD;
   MULADD(at[0], at[31]);    MULADD(at[1], at[30]);    MULADD(at[2], at[29]);    MULADD(at[3], at[28]); 
   COMBA_STORE(C->dp[3]);
   /* 4 */
   COMBA_FORWARD;
   MULADD(at[0], at[32]);    MULADD(at[1], at[31]);    MULADD(at[2], at[30]);    MULADD(at[3], at[29]);    MULADD(at[4], at[28]); 
   COMBA_STORE(C->dp[4]);
   /* 5 */
   COMBA_FORWARD;
   MULADD(at[0], at[33]);    MULADD(at[1], at[32]);    MULADD(at[2], at[31]);    MULADD(at[3], at[30]);    MULADD(at[4], at[29]);    MULADD(at[5], at[28]); 
   COMBA_STORE(C->dp[5]);
   /* 6 */
   COMBA_FORWARD;
   MULADD(at[0], at[34]);    MULADD(at[1], at[33]);    MULADD(at[2], at[32]);    MULADD(at[3], at[31]);    MULADD(at[4], at[30]);    MULADD(at[5], at[29]);    MULADD(at[6], at[28]); 
   COMBA_STORE(C->dp[6]);
   /* 7 */
   COMBA_FORWARD;
   MULADD(at[0], at[35]);    MULADD(at[1], at[34]);    MULADD(at[2], at[33]);    MULADD(at[3], at[32]);    MULADD(at[4], at[31]);    MULADD(at[5], at[30]);    MULADD(at[6], at[29]);    MULADD(at[7], at[28]); 
   COMBA_STORE(C->dp[7]);
   /* 8 */
   COMBA_FORWARD;
   MULADD(at[0], at[36]);    MULADD(at[1], at[35]);    MULADD(at[2], at[34]);    MULADD(at[3], at[33]);    MULADD(at[4], at[32]);    MULADD(at[5], at[31]);    MULADD(at[6], at[30]);    MULADD(at[7], at[29]);    MULADD(at[8], at[28]); 
   COMBA_STORE(C->dp[8]);
   /* 9 */
   COMBA_FORWARD;
   MULADD(at[0], at[37]);    MULADD(at[1], at[36]);    MULADD(at[2], at[35]);    MULADD(at[3], at[34]);    MULADD(at[4], at[33]);    MULADD(at[5], at[32]);    MULADD(at[6], at[31]);    MULADD(at[7], at[30]);    MULADD(at[8], at[29]);    MULADD(at[9], at[28]); 
   COMBA_STORE(C->dp[9]);
   /* 10 */
   COMBA_FORWARD;
   MULADD(at[0], at[38]);    MULADD(at[1], at[37]);    MULADD(at[2], at[36]);    MULADD(at[3], at[35]);    MULADD(at[4], at[34]);    MULADD(at[5], at[33]);    MULADD(at[6], at[32]);    MULADD(at[7], at[31]);    MULADD(at[8], at[30]);    MULADD(at[9], at[29]);    MULADD(at[10], at[28]); 
   COMBA_STORE(C->dp[10]);
   /* 11 */
   COMBA_FORWARD;
   MULADD(at[0], at[39]);    MULADD(at[1], at[38]);    MULADD(at[2], at[37]);    MULADD(at[3], at[36]);    MULADD(at[4], at[35]);    MULADD(at[5], at[34]);    MULADD(at[6], at[33]);    MULADD(at[7], at[32]);    MULADD(at[8], at[31]);    MULADD(at[9], at[30]);    MULADD(at[10], at[29]);    MULADD(at[11], at[28]); 
   COMBA_STORE(C->dp[11]);
   /* 12 */
   COMBA_FORWARD;
   MULADD(at[0], at[40]);    MULADD(at[1], at[39]);    MULADD(at[2], at[38]);    MULADD(at[3], at[37]);    MULADD(at[4], at[36]);    MULADD(at[5], at[35]);    MULADD(at[6], at[34]);    MULADD(at[7], at[33]);    MULADD(at[8], at[32]);    MULADD(at[9], at[31]);    MULADD(at[10], at[30]);    MULADD(at[11], at[29]);    MULADD(at[12], at[28]); 
   COMBA_STORE(C->dp[12]);
   /* 13 */
   COMBA_FORWARD;
   MULADD(at[0], at[41]);    MULADD(at[1], at[40]);    MULADD(at[2], at[39]);    MULADD(at[3], at[38]);    MULADD(at[4], at[37]);    MULADD(at[5], at[36]);    MULADD(at[6], at[35]);    MULADD(at[7], at[34]);    MULADD(at[8], at[33]);    MULADD(at[9], at[32]);    MULADD(at[10], at[31]);    MULADD(at[11], at[30]);    MULADD(at[12], at[29]);    MULADD(at[13], at[28]); 
   COMBA_STORE(C->dp[13]);
   /* 14 */
   COMBA_FORWARD;
   MULADD(at[0], at[42]);    MULADD(at[1], at[41]);    MULADD(at[2], at[40]);    MULADD(at[3], at[39]);    MULADD(at[4], at[38]);    MULADD(at[5], at[37]);    MULADD(at[6], at[36]);    MULADD(at[7], at[35]);    MULADD(at[8], at[34]);    MULADD(at[9], at[33]);    MULADD(at[10], at[32]);    MULADD(at[11], at[31]);    MULADD(at[12], at[30]);    MULADD(at[13], at[29]);    MULADD(at[14], at[28]); 
   COMBA_STORE(C->dp[14]);
   /* 15 */
   COMBA_FORWARD;
   MULADD(at[0], at[43]);    MULADD(at[1], at[42]);    MULADD(at[2], at[41]);    MULADD(at[3], at[40]);    MULADD(at[4], at[39]);    MULADD(at[5], at[38]);    MULADD(at[6], at[37]);    MULADD(at[7], at[36]);    MULADD(at[8], at[35]);    MULADD(at[9], at[34]);    MULADD(at[10], at[33]);    MULADD(at[11], at[32]);    MULADD(at[12], at[31]);    MULADD(at[13], at[30]);    MULADD(at[14], at[29]);    MULADD(at[15], at[28]); 
   COMBA_STORE(C->dp[15]);
   /* 16 */
   COMBA_FORWARD;
   MULADD(at[0], at[44]);    MULADD(at[1], at[43]);    MULADD(at[2], at[42]);    MULADD(at[3], at[41]);    MULADD(at[4], at[40]);    MULADD(at[5], at[39]);    MULADD(at[6], at[38]);    MULADD(at[7], at[37]);    MULADD(at[8], at[36]);    MULADD(at[9], at[35]);    MULADD(at[10], at[34]);    MULADD(at[11], at[33]);    MULADD(at[12], at[32]);    MULADD(at[13], at[31]);    MULADD(at[14], at[30]);    MULADD(at[15], at[29]);    MULADD(at[16], at[28]); 
   COMBA_STORE(C->dp[16]);
   /* 17 */
   COMBA_FORWARD;
   MULADD(at[0], at[45]);    MULADD(at[1], at[44]);    MULADD(at[2], at[43]);    MULADD(at[3], at[42]);    MULADD(at[4], at[41]);    MULADD(at[5], at[40]);    MULADD(at[6], at[39]);    MULADD(at[7], at[38]);    MULADD(at[8], at[37]);    MULADD(at[9], at[36]);    MULADD(at[10], at[35]);    MULADD(at[11], at[34]);    MULADD(at[12], at[33]);    MULADD(at[13], at[32]);    MULADD(at[14], at[31]);    MULADD(at[15], at[30]);    MULADD(at[16], at[29]);    MULADD(at[17], at[28]); 
   COMBA_STORE(C->dp[17]);
   /* 18 */
   COMBA_FORWARD;
   MULADD(at[0], at[46]);    MULADD(at[1], at[45]);    MULADD(at[2], at[44]);    MULADD(at[3], at[43]);    MULADD(at[4], at[42]);    MULADD(at[5], at[41]);    MULADD(at[6], at[40]);    MULADD(at[7], at[39]);    MULADD(at[8], at[38]);    MULADD(at[9], at[37]);    MULADD(at[10], at[36]);    MULADD(at[11], at[35]);    MULADD(at[12], at[34]);    MULADD(at[13], at[33]);    MULADD(at[14], at[32]);    MULADD(at[15], at[31]);    MULADD(at[16], at[30]);    MULADD(at[17], at[29]);    MULADD(at[18], at[28]); 
   COMBA_STORE(C->dp[18]);
   /* 19 */
   COMBA_FORWARD;
   MULADD(at[0], at[47]);    MULADD(at[1], at[46]);    MULADD(at[2], at[45]);    MULADD(at[3], at[44]);    MULADD(at[4], at[43]);    MULADD(at[5], at[42]);    MULADD(at[6], at[41]);    MULADD(at[7], at[40]);    MULADD(at[8], at[39]);    MULADD(at[9], at[38]);    MULADD(at[10], at[37]);    MULADD(at[11], at[36]);    MULADD(at[12], at[35]);    MULADD(at[13], at[34]);    MULADD(at[14], at[33]);    MULADD(at[15], at[32]);    MULADD(at[16], at[31]);    MULADD(at[17], at[30]);    MULADD(at[18], at[29]);    MULADD(at[19], at[28]); 
   COMBA_STORE(C->dp[19]);
   /* 20 */
   COMBA_FORWARD;
   MULADD(at[0], at[48]);    MULADD(at[1], at[47]);    MULADD(at[2], at[46]);    MULADD(at[3], at[45]);    MULADD(at[4], at[44]);    MULADD(at[5], at[43]);    MULADD(at[6], at[42]);    MULADD(at[7], at[41]);    MULADD(at[8], at[40]);    MULADD(at[9], at[39]);    MULADD(at[10], at[38]);    MULADD(at[11], at[37]);    MULADD(at[12], at[36]);    MULADD(at[13], at[35]);    MULADD(at[14], at[34]);    MULADD(at[15], at[33]);    MULADD(at[16], at[32]);    MULADD(at[17], at[31]);    MULADD(at[18], at[30]);    MULADD(at[19], at[29]);    MULADD(at[20], at[28]); 
   COMBA_STORE(C->dp[20]);
   /* 21 */
   COMBA_FORWARD;
   MULADD(at[0], at[49]);    MULADD(at[1], at[48]);    MULADD(at[2], at[47]);    MULADD(at[3], at[46]);    MULADD(at[4], at[45]);    MULADD(at[5], at[44]);    MULADD(at[6], at[43]);    MULADD(at[7], at[42]);    MULADD(at[8], at[41]);    MULADD(at[9], at[40]);    MULADD(at[10], at[39]);    MULADD(at[11], at[38]);    MULADD(at[12], at[37]);    MULADD(at[13], at[36]);    MULADD(at[14], at[35]);    MULADD(at[15], at[34]);    MULADD(at[16], at[33]);    MULADD(at[17], at[32]);    MULADD(at[18], at[31]);    MULADD(at[19], at[30]);    MULADD(at[20], at[29]);    MULADD(at[21], at[28]); 
   COMBA_STORE(C->dp[21]);
   /* 22 */
   COMBA_FORWARD;
   MULADD(at[0], at[50]);    MULADD(at[1], at[49]);    MULADD(at[2], at[48]);    MULADD(at[3], at[47]);    MULADD(at[4], at[46]);    MULADD(at[5], at[45]);    MULADD(at[6], at[44]);    MULADD(at[7], at[43]);    MULADD(at[8], at[42]);    MULADD(at[9], at[41]);    MULADD(at[10], at[40]);    MULADD(at[11], at[39]);    MULADD(at[12], at[38]);    MULADD(at[13], at[37]);    MULADD(at[14], at[36]);    MULADD(at[15], at[35]);    MULADD(at[16], at[34]);    MULADD(at[17], at[33]);    MULADD(at[18], at[32]);    MULADD(at[19], at[31]);    MULADD(at[20], at[30]);    MULADD(at[21], at[29]);    MULADD(at[22], at[28]); 
   COMBA_STORE(C->dp[22]);
   /* 23 */
   COMBA_FORWARD;
   MULADD(at[0], at[51]);    MULADD(at[1], at[50]);    MULADD(at[2], at[49]);    MULADD(at[3], at[48]);    MULADD(at[4], at[47]);    MULADD(at[5], at[46]);    MULADD(at[6], at[45]);    MULADD(at[7], at[44]);    MULADD(at[8], at[43]);    MULADD(at[9], at[42]);    MULADD(at[10], at[41]);    MULADD(at[11], at[40]);    MULADD(at[12], at[39]);    MULADD(at[13], at[38]);    MULADD(at[14], at[37]);    MULADD(at[15], at[36]);    MULADD(at[16], at[35]);    MULADD(at[17], at[34]);    MULADD(at[18], at[33]);    MULADD(at[19], at[32]);    MULADD(at[20], at[31]);    MULADD(at[21], at[30]);    MULADD(at[22], at[29]);    MULADD(at[23], at[28]); 
   COMBA_STORE(C->dp[23]);
   /* 24 */
   COMBA_FORWARD;
   MULADD(at[0], at[52]);    MULADD(at[1], at[51]);    MULADD(at[2], at[50]);    MULADD(at[3], at[49]);    MULADD(at[4], at[48]);    MULADD(at[5], at[47]);    MULADD(at[6], at[46]);    MULADD(at[7], at[45]);    MULADD(at[8], at[44]);    MULADD(at[9], at[43]);    MULADD(at[10], at[42]);    MULADD(at[11], at[41]);    MULADD(at[12], at[40]);    MULADD(at[13], at[39]);    MULADD(at[14], at[38]);    MULADD(at[15], at[37]);    MULADD(at[16], at[36]);    MULADD(at[17], at[35]);    MULADD(at[18], at[34]);    MULADD(at[19], at[33]);    MULADD(at[20], at[32]);    MULADD(at[21], at[31]);    MULADD(at[22], at[30]);    MULADD(at[23], at[29]);    MULADD(at[24], at[28]); 
   COMBA_STORE(C->dp[24]);
   /* 25 */
   COMBA_FORWARD;
   MULADD(at[0], at[53]);    MULADD(at[1], at[52]);    MULADD(at[2], at[51]);    MULADD(at[3], at[50]);    MULADD(at[4], at[49]);    MULADD(at[5], at[48]);    MULADD(at[6], at[47]);    MULADD(at[7], at[46]);    MULADD(at[8], at[45]);    MULADD(at[9], at[44]);    MULADD(at[10], at[43]);    MULADD(at[11], at[42]);    MULADD(at[12], at[41]);    MULADD(at[13], at[40]);    MULADD(at[14], at[39]);    MULADD(at[15], at[38]);    MULADD(at[16], at[37]);    MULADD(at[17], at[36]);    MULADD(at[18], at[35]);    MULADD(at[19], at[34]);    MULADD(at[20], at[33]);    MULADD(at[21], at[32]);    MULADD(at[22], at[31]);    MULADD(at[23], at[30]);    MULADD(at[24], at[29]);    MULADD(at[25], at[28]); 
   COMBA_STORE(C->dp[25]);
   /* 26 */
   COMBA_FORWARD;
   MULADD(at[0], at[54]);    MULADD(at[1], at[53]);    MULADD(at[2], at[52]);    MULADD(at[3], at[51]);    MULADD(at[4], at[50]);    MULADD(at[5], at[49]);    MULADD(at[6], at[48]);    MULADD(at[7], at[47]);    MULADD(at[8], at[46]);    MULADD(at[9], at[45]);    MULADD(at[10], at[44]);    MULADD(at[11], at[43]);    MULADD(at[12], at[42]);    MULADD(at[13], at[41]);    MULADD(at[14], at[40]);    MULADD(at[15], at[39]);    MULADD(at[16], at[38]);    MULADD(at[17], at[37]);    MULADD(at[18], at[36]);    MULADD(at[19], at[35]);    MULADD(at[20], at[34]);    MULADD(at[21], at[33]);    MULADD(at[22], at[32]);    MULADD(at[23], at[31]);    MULADD(at[24], at[30]);    MULADD(at[25], at[29]);    MULADD(at[26], at[28]); 
   COMBA_STORE(C->dp[26]);
   /* 27 */
   COMBA_FORWARD;
   MULADD(at[0], at[55]);    MULADD(at[1], at[54]);    MULADD(at[2], at[53]);    MULADD(at[3], at[52]);    MULADD(at[4], at[51]);    MULADD(at[5], at[50]);    MULADD(at[6], at[49]);    MULADD(at[7], at[48]);    MULADD(at[8], at[47]);    MULADD(at[9], at[46]);    MULADD(at[10], at[45]);    MULADD(at[11], at[44]);    MULADD(at[12], at[43]);    MULADD(at[13], at[42]);    MULADD(at[14], at[41]);    MULADD(at[15], at[40]);    MULADD(at[16], at[39]);    MULADD(at[17], at[38]);    MULADD(at[18], at[37]);    MULADD(at[19], at[36]);    MULADD(at[20], at[35]);    MULADD(at[21], at[34]);    MULADD(at[22], at[33]);    MULADD(at[23], at[32]);    MULADD(at[24], at[31]);    MULADD(at[25], at[30]);    MULADD(at[26], at[29]);    MULADD(at[27], at[28]); 
   COMBA_STORE(C->dp[27]);
   /* 28 */
   COMBA_FORWARD;
   MULADD(at[1], at[55]);    MULADD(at[2], at[54]);    MULADD(at[3], at[53]);    MULADD(at[4], at[52]);    MULADD(at[5], at[51]);    MULADD(at[6], at[50]);    MULADD(at[7], at[49]);    MULADD(at[8], at[48]);    MULADD(at[9], at[47]);    MULADD(at[10], at[46]);    MULADD(at[11], at[45]);    MULADD(at[12], at[44]);    MULADD(at[13], at[43]);    MULADD(at[14], at[42]);    MULADD(at[15], at[41]);    MULADD(at[16], at[40]);    MULADD(at[17], at[39]);    MULADD(at[18], at[38]);    MULADD(at[19], at[37]);    MULADD(at[20], at[36]);    MULADD(at[21], at[35]);    MULADD(at[22], at[34]);    MULADD(at[23], at[33]);    MULADD(at[24], at[32]);    MULADD(at[25], at[31]);    MULADD(at[26], at[30]);    MULADD(at[27], at[29]); 
   COMBA_STORE(C->dp[28]);
   /* 29 */
   COMBA_FORWARD;
   MULADD(at[2], at[55]);    MULADD(at[3], at[54]);    MULADD(at[4], at[53]);    MULADD(at[5], at[52]);    MULADD(at[6], at[51]);    MULADD(at[7], at[50]);    MULADD(at[8], at[49]);    MULADD(at[9], at[48]);    MULADD(at[10], at[47]);    MULADD(at[11], at[46]);    MULADD(at[12], at[45]);    MULADD(at[13], at[44]);    MULADD(at[14], at[43]);    MULADD(at[15], at[42]);    MULADD(at[16], at[41]);    MULADD(at[17], at[40]);    MULADD(at[18], at[39]);    MULADD(at[19], at[38]);    MULADD(at[20], at[37]);    MULADD(at[21], at[36]);    MULADD(at[22], at[35]);    MULADD(at[23], at[34]);    MULADD(at[24], at[33]);    MULADD(at[25], at[32]);    MULADD(at[26], at[31]);    MULADD(at[27], at[30]); 
   COMBA_STORE(C->dp[29]);
   /* 30 */
   COMBA_FORWARD;
   MULADD(at[3], at[55]);    MULADD(at[4], at[54]);    MULADD(at[5], at[53]);    MULADD(at[6], at[52]);    MULADD(at[7], at[51]);    MULADD(at[8], at[50]);    MULADD(at[9], at[49]);    MULADD(at[10], at[48]);    MULADD(at[11], at[47]);    MULADD(at[12], at[46]);    MULADD(at[13], at[45]);    MULADD(at[14], at[44]);    MULADD(at[15], at[43]);    MULADD(at[16], at[42]);    MULADD(at[17], at[41]);    MULADD(at[18], at[40]);    MULADD(at[19], at[39]);    MULADD(at[20], at[38]);    MULADD(at[21], at[37]);    MULADD(at[22], at[36]);    MULADD(at[23], at[35]);    MULADD(at[24], at[34]);    MULADD(at[25], at[33]);    MULADD(at[26], at[32]);    MULADD(at[27], at[31]); 
   COMBA_STORE(C->dp[30]);
   /* 31 */
   COMBA_FORWARD;
   MULADD(at[4], at[55]);    MULADD(at[5], at[54]);    MULADD(at[6], at[53]);    MULADD(at[7], at[52]);    MULADD(at[8], at[51]);    MULADD(at[9], at[50]);    MULADD(at[10], at[49]);    MULADD(at[11], at[48]);    MULADD(at[12], at[47]);    MULADD(at[13], at[46]);    MULADD(at[14], at[45]);    MULADD(at[15], at[44]);    MULADD(at[16], at[43]);    MULADD(at[17], at[42]);    MULADD(at[18], at[41]);    MULADD(at[19], at[40]);    MULADD(at[20], at[39]);    MULADD(at[21], at[38]);    MULADD(at[22], at[37]);    MULADD(at[23], at[36]);    MULADD(at[24], at[35]);    MULADD(at[25], at[34]);    MULADD(at[26], at[33]);    MULADD(at[27], at[32]); 
   COMBA_STORE(C->dp[31]);
   /* 32 */
   COMBA_FORWARD;
   MULADD(at[5], at[55]);    MULADD(at[6], at[54]);    MULADD(at[7], at[53]);    MULADD(at[8], at[52]);    MULADD(at[9], at[51]);    MULADD(at[10], at[50]);    MULADD(at[11], at[49]);    MULADD(at[12], at[48]);    MULADD(at[13], at[47]);    MULADD(at[14], at[46]);    MULADD(at[15], at[45]);    MULADD(at[16], at[44]);    MULADD(at[17], at[43]);    MULADD(at[18], at[42]);    MULADD(at[19], at[41]);    MULADD(at[20], at[40]);    MULADD(at[21], at[39]);    MULADD(at[22], at[38]);    MULADD(at[23], at[37]);    MULADD(at[24], at[36]);    MULADD(at[25], at[35]);    MULADD(at[26], at[34]);    MULADD(at[27], at[33]); 
   COMBA_STORE(C->dp[32]);
   /* 33 */
   COMBA_FORWARD;
   MULADD(at[6], at[55]);    MULADD(at[7], at[54]);    MULADD(at[8], at[53]);    MULADD(at[9], at[52]);    MULADD(at[10], at[51]);    MULADD(at[11], at[50]);    MULADD(at[12], at[49]);    MULADD(at[13], at[48]);    MULADD(at[14], at[47]);    MULADD(at[15], at[46]);    MULADD(at[16], at[45]);    MULADD(at[17], at[44]);    MULADD(at[18], at[43]);    MULADD(at[19], at[42]);    MULADD(at[20], at[41]);    MULADD(at[21], at[40]);    MULADD(at[22], at[39]);    MULADD(at[23], at[38]);    MULADD(at[24], at[37]);    MULADD(at[25], at[36]);    MULADD(at[26], at[35]);    MULADD(at[27], at[34]); 
   COMBA_STORE(C->dp[33]);
   /* 34 */
   COMBA_FORWARD;
   MULADD(at[7], at[55]);    MULADD(at[8], at[54]);    MULADD(at[9], at[53]);    MULADD(at[10], at[52]);    MULADD(at[11], at[51]);    MULADD(at[12], at[50]);    MULADD(at[13], at[49]);    MULADD(at[14], at[48]);    MULADD(at[15], at[47]);    MULADD(at[16], at[46]);    MULADD(at[17], at[45]);    MULADD(at[18], at[44]);    MULADD(at[19], at[43]);    MULADD(at[20], at[42]);    MULADD(at[21], at[41]);    MULADD(at[22], at[40]);    MULADD(at[23], at[39]);    MULADD(at[24], at[38]);    MULADD(at[25], at[37]);    MULADD(at[26], at[36]);    MULADD(at[27], at[35]); 
   COMBA_STORE(C->dp[34]);
   /* 35 */
   COMBA_FORWARD;
   MULADD(at[8], at[55]);    MULADD(at[9], at[54]);    MULADD(at[10], at[53]);    MULADD(at[11], at[52]);    MULADD(at[12], at[51]);    MULADD(at[13], at[50]);    MULADD(at[14], at[49]);    MULADD(at[15], at[48]);    MULADD(at[16], at[47]);    MULADD(at[17], at[46]);    MULADD(at[18], at[45]);    MULADD(at[19], at[44]);    MULADD(at[20], at[43]);    MULADD(at[21], at[42]);    MULADD(at[22], at[41]);    MULADD(at[23], at[40]);    MULADD(at[24], at[39]);    MULADD(at[25], at[38]);    MULADD(at[26], at[37]);    MULADD(at[27], at[36]); 
   COMBA_STORE(C->dp[35]);
   /* 36 */
   COMBA_FORWARD;
   MULADD(at[9], at[55]);    MULADD(at[10], at[54]);    MULADD(at[11], at[53]);    MULADD(at[12], at[52]);    MULADD(at[13], at[51]);    MULADD(at[14], at[50]);    MULADD(at[15], at[49]);    MULADD(at[16], at[48]);    MULADD(at[17], at[47]);    MULADD(at[18], at[46]);    MULADD(at[19], at[45]);    MULADD(at[20], at[44]);    MULADD(at[21], at[43]);    MULADD(at[22], at[42]);    MULADD(at[23], at[41]);    MULADD(at[24], at[40]);    MULADD(at[25], at[39]);    MULADD(at[26], at[38]);    MULADD(at[27], at[37]); 
   COMBA_STORE(C->dp[36]);
   /* 37 */
   COMBA_FORWARD;
   MULADD(at[10], at[55]);    MULADD(at[11], at[54]);    MULADD(at[12], at[53]);    MULADD(at[13], at[52]);    MULADD(at[14], at[51]);    MULADD(at[15], at[50]);    MULADD(at[16], at[49]);    MULADD(at[17], at[48]);    MULADD(at[18], at[47]);    MULADD(at[19], at[46]);    MULADD(at[20], at[45]);    MULADD(at[21], at[44]);    MULADD(at[22], at[43]);    MULADD(at[23], at[42]);    MULADD(at[24], at[41]);    MULADD(at[25], at[40]);    MULADD(at[26], at[39]);    MULADD(at[27], at[38]); 
   COMBA_STORE(C->dp[37]);
   /* 38 */
   COMBA_FORWARD;
   MULADD(at[11], at[55]);    MULADD(at[12], at[54]);    MULADD(at[13], at[53]);    MULADD(at[14], at[52]);    MULADD(at[15], at[51]);    MULADD(at[16], at[50]);    MULADD(at[17], at[49]);    MULADD(at[18], at[48]);    MULADD(at[19], at[47]);    MULADD(at[20], at[46]);    MULADD(at[21], at[45]);    MULADD(at[22], at[44]);    MULADD(at[23], at[43]);    MULADD(at[24], at[42]);    MULADD(at[25], at[41]);    MULADD(at[26], at[40]);    MULADD(at[27], at[39]); 
   COMBA_STORE(C->dp[38]);
   /* 39 */
   COMBA_FORWARD;
   MULADD(at[12], at[55]);    MULADD(at[13], at[54]);    MULADD(at[14], at[53]);    MULADD(at[15], at[52]);    MULADD(at[16], at[51]);    MULADD(at[17], at[50]);    MULADD(at[18], at[49]);    MULADD(at[19], at[48]);    MULADD(at[20], at[47]);    MULADD(at[21], at[46]);    MULADD(at[22], at[45]);    MULADD(at[23], at[44]);    MULADD(at[24], at[43]);    MULADD(at[25], at[42]);    MULADD(at[26], at[41]);    MULADD(at[27], at[40]); 
   COMBA_STORE(C->dp[39]);
   /* 40 */
   COMBA_FORWARD;
   MULADD(at[13], at[55]);    MULADD(at[14], at[54]);    MULADD(at[15], at[53]);    MULADD(at[16], at[52]);    MULADD(at[17], at[51]);    MULADD(at[18], at[50]);    MULADD(at[19], at[49]);    MULADD(at[20], at[48]);    MULADD(at[21], at[47]);    MULADD(at[22], at[46]);    MULADD(at[23], at[45]);    MULADD(at[24], at[44]);    MULADD(at[25], at[43]);    MULADD(at[26], at[42]);    MULADD(at[27], at[41]); 
   COMBA_STORE(C->dp[40]);
   /* 41 */
   COMBA_FORWARD;
   MULADD(at[14], at[55]);    MULADD(at[15], at[54]);    MULADD(at[16], at[53]);    MULADD(at[17], at[52]);    MULADD(at[18], at[51]);    MULADD(at[19], at[50]);    MULADD(at[20], at[49]);    MULADD(at[21], at[48]);    MULADD(at[22], at[47]);    MULADD(at[23], at[46]);    MULADD(at[24], at[45]);    MULADD(at[25], at[44]);    MULADD(at[26], at[43]);    MULADD(at[27], at[42]); 
   COMBA_STORE(C->dp[41]);
   /* 42 */
   COMBA_FORWARD;
   MULADD(at[15], at[55]);    MULADD(at[16], at[54]);    MULADD(at[17], at[53]);    MULADD(at[18], at[52]);    MULADD(at[19], at[51]);    MULADD(at[20], at[50]);    MULADD(at[21], at[49]);    MULADD(at[22], at[48]);    MULADD(at[23], at[47]);    MULADD(at[24], at[46]);    MULADD(at[25], at[45]);    MULADD(at[26], at[44]);    MULADD(at[27], at[43]); 
   COMBA_STORE(C->dp[42]);
   /* 43 */
   COMBA_FORWARD;
   MULADD(at[16], at[55]);    MULADD(at[17], at[54]);    MULADD(at[18], at[53]);    MULADD(at[19], at[52]);    MULADD(at[20], at[51]);    MULADD(at[21], at[50]);    MULADD(at[22], at[49]);    MULADD(at[23], at[48]);    MULADD(at[24], at[47]);    MULADD(at[25], at[46]);    MULADD(at[26], at[45]);    MULADD(at[27], at[44]); 
   COMBA_STORE(C->dp[43]);
   /* 44 */
   COMBA_FORWARD;
   MULADD(at[17], at[55]);    MULADD(at[18], at[54]);    MULADD(at[19], at[53]);    MULADD(at[20], at[52]);    MULADD(at[21], at[51]);    MULADD(at[22], at[50]);    MULADD(at[23], at[49]);    MULADD(at[24], at[48]);    MULADD(at[25], at[47]);    MULADD(at[26], at[46]);    MULADD(at[27], at[45]); 
   COMBA_STORE(C->dp[44]);
   /* 45 */
   COMBA_FORWARD;
   MULADD(at[18], at[55]);    MULADD(at[19], at[54]);    MULADD(at[20], at[53]);    MULADD(at[21], at[52]);    MULADD(at[22], at[51]);    MULADD(at[23], at[50]);    MULADD(at[24], at[49]);    MULADD(at[25], at[48]);    MULADD(at[26], at[47]);    MULADD(at[27], at[46]); 
   COMBA_STORE(C->dp[45]);
   /* 46 */
   COMBA_FORWARD;
   MULADD(at[19], at[55]);    MULADD(at[20], at[54]);    MULADD(at[21], at[53]);    MULADD(at[22], at[52]);    MULADD(at[23], at[51]);    MULADD(at[24], at[50]);    MULADD(at[25], at[49]);    MULADD(at[26], at[48]);    MULADD(at[27], at[47]); 
   COMBA_STORE(C->dp[46]);
   /* 47 */
   COMBA_FORWARD;
   MULADD(at[20], at[55]);    MULADD(at[21], at[54]);    MULADD(at[22], at[53]);    MULADD(at[23], at[52]);    MULADD(at[24], at[51]);    MULADD(at[25], at[50]);    MULADD(at[26], at[49]);    MULADD(at[27], at[48]); 
   COMBA_STORE(C->dp[47]);
   /* 48 */
   COMBA_FORWARD;
   MULADD(at[21], at[55]);    MULADD(at[22], at[54]);    MULADD(at[23], at[53]);    MULADD(at[24], at[52]);    MULADD(at[25], at[51]);    MULADD(at[26], at[50]);    MULADD(at[27], at[49]); 
   COMBA_STORE(C->dp[48]);
   /* 49 */
   COMBA_FORWARD;
   MULADD(at[22], at[55]);    MULADD(at[23], at[54]);    MULADD(at[24], at[53]);    MULADD(at[25], at[52]);    MULADD(at[26], at[51]);    MULADD(at[27], at[50]); 
   COMBA_STORE(C->dp[49]);
   /* 50 */
   COMBA_FORWARD;
   MULADD(at[23], at[55]);    MULADD(at[24], at[54]);    MULADD(at[25], at[53]);    MULADD(at[26], at[52]);    MULADD(at[27], at[51]); 
   COMBA_STORE(C->dp[50]);
   /* 51 */
   COMBA_FORWARD;
   MULADD(at[24], at[55]);    MULADD(at[25], at[54]);    MULADD(at[26], at[53]);    MULADD(at[27], at[52]); 
   COMBA_STORE(C->dp[51]);
   /* 52 */
   COMBA_FORWARD;
   MULADD(at[25], at[55]);    MULADD(at[26], at[54]);    MULADD(at[27], at[53]); 
   COMBA_STORE(C->dp[52]);
   /* 53 */
   COMBA_FORWARD;
   MULADD(at[26], at[55]);    MULADD(at[27], at[54]); 
   COMBA_STORE(C->dp[53]);
   /* 54 */
   COMBA_FORWARD;
   MULADD(at[27], at[55]); 
   COMBA_STORE(C->dp[54]);
   COMBA_STORE2(C->dp[55]);
   C->used = 56;
   C->sign = A->sign ^ B->sign;
   fp_clamp(C);
   COMBA_FINI;
}
#endif

/* End: fp_mul_comba_28.c */

/* Start: fp_mul_comba_3.c */
#define TFM_DEFINES
#include "fp_mul_comba.c"

#ifdef TFM_MUL3
void fp_mul_comba3(fp_int *A, fp_int *B, fp_int *C)
{
   fp_digit c0, c1, c2, at[6];

   memcpy(at, A->dp, 3 * sizeof(fp_digit));
   memcpy(at+3, B->dp, 3 * sizeof(fp_digit));
   COMBA_START;

   COMBA_CLEAR;
   /* 0 */
   MULADD(at[0], at[3]); 
   COMBA_STORE(C->dp[0]);
   /* 1 */
   COMBA_FORWARD;
   MULADD(at[0], at[4]);    MULADD(at[1], at[3]); 
   COMBA_STORE(C->dp[1]);
   /* 2 */
   COMBA_FORWARD;
   MULADD(at[0], at[5]);    MULADD(at[1], at[4]);    MULADD(at[2], at[3]); 
   COMBA_STORE(C->dp[2]);
   /* 3 */
   COMBA_FORWARD;
   MULADD(at[1], at[5]);    MULADD(at[2], at[4]); 
   COMBA_STORE(C->dp[3]);
   /* 4 */
   COMBA_FORWARD;
   MULADD(at[2], at[5]); 
   COMBA_STORE(C->dp[4]);
   COMBA_STORE2(C->dp[5]);
   C->used = 6;
   C->sign = A->sign ^ B->sign;
   fp_clamp(C);
   COMBA_FINI;
}
#endif

/* End: fp_mul_comba_3.c */

/* Start: fp_mul_comba_32.c */
#define TFM_DEFINES
#include "fp_mul_comba.c"

#ifdef TFM_MUL32
void fp_mul_comba32(fp_int *A, fp_int *B, fp_int *C)
{
   fp_digit c0, c1, c2, at[64];
   int out_size;

   out_size = A->used + B->used;
   memcpy(at, A->dp, 32 * sizeof(fp_digit));
   memcpy(at+32, B->dp, 32 * sizeof(fp_digit));
   COMBA_START;

   COMBA_CLEAR;
   /* 0 */
   MULADD(at[0], at[32]); 
   COMBA_STORE(C->dp[0]);
   /* 1 */
   COMBA_FORWARD;
   MULADD(at[0], at[33]);    MULADD(at[1], at[32]); 
   COMBA_STORE(C->dp[1]);
   /* 2 */
   COMBA_FORWARD;
   MULADD(at[0], at[34]);    MULADD(at[1], at[33]);    MULADD(at[2], at[32]); 
   COMBA_STORE(C->dp[2]);
   /* 3 */
   COMBA_FORWARD;
   MULADD(at[0], at[35]);    MULADD(at[1], at[34]);    MULADD(at[2], at[33]);    MULADD(at[3], at[32]); 
   COMBA_STORE(C->dp[3]);
   /* 4 */
   COMBA_FORWARD;
   MULADD(at[0], at[36]);    MULADD(at[1], at[35]);    MULADD(at[2], at[34]);    MULADD(at[3], at[33]);    MULADD(at[4], at[32]); 
   COMBA_STORE(C->dp[4]);
   /* 5 */
   COMBA_FORWARD;
   MULADD(at[0], at[37]);    MULADD(at[1], at[36]);    MULADD(at[2], at[35]);    MULADD(at[3], at[34]);    MULADD(at[4], at[33]);    MULADD(at[5], at[32]); 
   COMBA_STORE(C->dp[5]);
   /* 6 */
   COMBA_FORWARD;
   MULADD(at[0], at[38]);    MULADD(at[1], at[37]);    MULADD(at[2], at[36]);    MULADD(at[3], at[35]);    MULADD(at[4], at[34]);    MULADD(at[5], at[33]);    MULADD(at[6], at[32]); 
   COMBA_STORE(C->dp[6]);
   /* 7 */
   COMBA_FORWARD;
   MULADD(at[0], at[39]);    MULADD(at[1], at[38]);    MULADD(at[2], at[37]);    MULADD(at[3], at[36]);    MULADD(at[4], at[35]);    MULADD(at[5], at[34]);    MULADD(at[6], at[33]);    MULADD(at[7], at[32]); 
   COMBA_STORE(C->dp[7]);
   /* 8 */
   COMBA_FORWARD;
   MULADD(at[0], at[40]);    MULADD(at[1], at[39]);    MULADD(at[2], at[38]);    MULADD(at[3], at[37]);    MULADD(at[4], at[36]);    MULADD(at[5], at[35]);    MULADD(at[6], at[34]);    MULADD(at[7], at[33]);    MULADD(at[8], at[32]); 
   COMBA_STORE(C->dp[8]);
   /* 9 */
   COMBA_FORWARD;
   MULADD(at[0], at[41]);    MULADD(at[1], at[40]);    MULADD(at[2], at[39]);    MULADD(at[3], at[38]);    MULADD(at[4], at[37]);    MULADD(at[5], at[36]);    MULADD(at[6], at[35]);    MULADD(at[7], at[34]);    MULADD(at[8], at[33]);    MULADD(at[9], at[32]); 
   COMBA_STORE(C->dp[9]);
   /* 10 */
   COMBA_FORWARD;
   MULADD(at[0], at[42]);    MULADD(at[1], at[41]);    MULADD(at[2], at[40]);    MULADD(at[3], at[39]);    MULADD(at[4], at[38]);    MULADD(at[5], at[37]);    MULADD(at[6], at[36]);    MULADD(at[7], at[35]);    MULADD(at[8], at[34]);    MULADD(at[9], at[33]);    MULADD(at[10], at[32]); 
   COMBA_STORE(C->dp[10]);
   /* 11 */
   COMBA_FORWARD;
   MULADD(at[0], at[43]);    MULADD(at[1], at[42]);    MULADD(at[2], at[41]);    MULADD(at[3], at[40]);    MULADD(at[4], at[39]);    MULADD(at[5], at[38]);    MULADD(at[6], at[37]);    MULADD(at[7], at[36]);    MULADD(at[8], at[35]);    MULADD(at[9], at[34]);    MULADD(at[10], at[33]);    MULADD(at[11], at[32]); 
   COMBA_STORE(C->dp[11]);
   /* 12 */
   COMBA_FORWARD;
   MULADD(at[0], at[44]);    MULADD(at[1], at[43]);    MULADD(at[2], at[42]);    MULADD(at[3], at[41]);    MULADD(at[4], at[40]);    MULADD(at[5], at[39]);    MULADD(at[6], at[38]);    MULADD(at[7], at[37]);    MULADD(at[8], at[36]);    MULADD(at[9], at[35]);    MULADD(at[10], at[34]);    MULADD(at[11], at[33]);    MULADD(at[12], at[32]); 
   COMBA_STORE(C->dp[12]);
   /* 13 */
   COMBA_FORWARD;
   MULADD(at[0], at[45]);    MULADD(at[1], at[44]);    MULADD(at[2], at[43]);    MULADD(at[3], at[42]);    MULADD(at[4], at[41]);    MULADD(at[5], at[40]);    MULADD(at[6], at[39]);    MULADD(at[7], at[38]);    MULADD(at[8], at[37]);    MULADD(at[9], at[36]);    MULADD(at[10], at[35]);    MULADD(at[11], at[34]);    MULADD(at[12], at[33]);    MULADD(at[13], at[32]); 
   COMBA_STORE(C->dp[13]);
   /* 14 */
   COMBA_FORWARD;
   MULADD(at[0], at[46]);    MULADD(at[1], at[45]);    MULADD(at[2], at[44]);    MULADD(at[3], at[43]);    MULADD(at[4], at[42]);    MULADD(at[5], at[41]);    MULADD(at[6], at[40]);    MULADD(at[7], at[39]);    MULADD(at[8], at[38]);    MULADD(at[9], at[37]);    MULADD(at[10], at[36]);    MULADD(at[11], at[35]);    MULADD(at[12], at[34]);    MULADD(at[13], at[33]);    MULADD(at[14], at[32]); 
   COMBA_STORE(C->dp[14]);
   /* 15 */
   COMBA_FORWARD;
   MULADD(at[0], at[47]);    MULADD(at[1], at[46]);    MULADD(at[2], at[45]);    MULADD(at[3], at[44]);    MULADD(at[4], at[43]);    MULADD(at[5], at[42]);    MULADD(at[6], at[41]);    MULADD(at[7], at[40]);    MULADD(at[8], at[39]);    MULADD(at[9], at[38]);    MULADD(at[10], at[37]);    MULADD(at[11], at[36]);    MULADD(at[12], at[35]);    MULADD(at[13], at[34]);    MULADD(at[14], at[33]);    MULADD(at[15], at[32]); 
   COMBA_STORE(C->dp[15]);
   /* 16 */
   COMBA_FORWARD;
   MULADD(at[0], at[48]);    MULADD(at[1], at[47]);    MULADD(at[2], at[46]);    MULADD(at[3], at[45]);    MULADD(at[4], at[44]);    MULADD(at[5], at[43]);    MULADD(at[6], at[42]);    MULADD(at[7], at[41]);    MULADD(at[8], at[40]);    MULADD(at[9], at[39]);    MULADD(at[10], at[38]);    MULADD(at[11], at[37]);    MULADD(at[12], at[36]);    MULADD(at[13], at[35]);    MULADD(at[14], at[34]);    MULADD(at[15], at[33]);    MULADD(at[16], at[32]); 
   COMBA_STORE(C->dp[16]);
   /* 17 */
   COMBA_FORWARD;
   MULADD(at[0], at[49]);    MULADD(at[1], at[48]);    MULADD(at[2], at[47]);    MULADD(at[3], at[46]);    MULADD(at[4], at[45]);    MULADD(at[5], at[44]);    MULADD(at[6], at[43]);    MULADD(at[7], at[42]);    MULADD(at[8], at[41]);    MULADD(at[9], at[40]);    MULADD(at[10], at[39]);    MULADD(at[11], at[38]);    MULADD(at[12], at[37]);    MULADD(at[13], at[36]);    MULADD(at[14], at[35]);    MULADD(at[15], at[34]);    MULADD(at[16], at[33]);    MULADD(at[17], at[32]); 
   COMBA_STORE(C->dp[17]);
   /* 18 */
   COMBA_FORWARD;
   MULADD(at[0], at[50]);    MULADD(at[1], at[49]);    MULADD(at[2], at[48]);    MULADD(at[3], at[47]);    MULADD(at[4], at[46]);    MULADD(at[5], at[45]);    MULADD(at[6], at[44]);    MULADD(at[7], at[43]);    MULADD(at[8], at[42]);    MULADD(at[9], at[41]);    MULADD(at[10], at[40]);    MULADD(at[11], at[39]);    MULADD(at[12], at[38]);    MULADD(at[13], at[37]);    MULADD(at[14], at[36]);    MULADD(at[15], at[35]);    MULADD(at[16], at[34]);    MULADD(at[17], at[33]);    MULADD(at[18], at[32]); 
   COMBA_STORE(C->dp[18]);
   /* 19 */
   COMBA_FORWARD;
   MULADD(at[0], at[51]);    MULADD(at[1], at[50]);    MULADD(at[2], at[49]);    MULADD(at[3], at[48]);    MULADD(at[4], at[47]);    MULADD(at[5], at[46]);    MULADD(at[6], at[45]);    MULADD(at[7], at[44]);    MULADD(at[8], at[43]);    MULADD(at[9], at[42]);    MULADD(at[10], at[41]);    MULADD(at[11], at[40]);    MULADD(at[12], at[39]);    MULADD(at[13], at[38]);    MULADD(at[14], at[37]);    MULADD(at[15], at[36]);    MULADD(at[16], at[35]);    MULADD(at[17], at[34]);    MULADD(at[18], at[33]);    MULADD(at[19], at[32]); 
   COMBA_STORE(C->dp[19]);
   /* 20 */
   COMBA_FORWARD;
   MULADD(at[0], at[52]);    MULADD(at[1], at[51]);    MULADD(at[2], at[50]);    MULADD(at[3], at[49]);    MULADD(at[4], at[48]);    MULADD(at[5], at[47]);    MULADD(at[6], at[46]);    MULADD(at[7], at[45]);    MULADD(at[8], at[44]);    MULADD(at[9], at[43]);    MULADD(at[10], at[42]);    MULADD(at[11], at[41]);    MULADD(at[12], at[40]);    MULADD(at[13], at[39]);    MULADD(at[14], at[38]);    MULADD(at[15], at[37]);    MULADD(at[16], at[36]);    MULADD(at[17], at[35]);    MULADD(at[18], at[34]);    MULADD(at[19], at[33]);    MULADD(at[20], at[32]); 
   COMBA_STORE(C->dp[20]);
   /* 21 */
   COMBA_FORWARD;
   MULADD(at[0], at[53]);    MULADD(at[1], at[52]);    MULADD(at[2], at[51]);    MULADD(at[3], at[50]);    MULADD(at[4], at[49]);    MULADD(at[5], at[48]);    MULADD(at[6], at[47]);    MULADD(at[7], at[46]);    MULADD(at[8], at[45]);    MULADD(at[9], at[44]);    MULADD(at[10], at[43]);    MULADD(at[11], at[42]);    MULADD(at[12], at[41]);    MULADD(at[13], at[40]);    MULADD(at[14], at[39]);    MULADD(at[15], at[38]);    MULADD(at[16], at[37]);    MULADD(at[17], at[36]);    MULADD(at[18], at[35]);    MULADD(at[19], at[34]);    MULADD(at[20], at[33]);    MULADD(at[21], at[32]); 
   COMBA_STORE(C->dp[21]);
   /* 22 */
   COMBA_FORWARD;
   MULADD(at[0], at[54]);    MULADD(at[1], at[53]);    MULADD(at[2], at[52]);    MULADD(at[3], at[51]);    MULADD(at[4], at[50]);    MULADD(at[5], at[49]);    MULADD(at[6], at[48]);    MULADD(at[7], at[47]);    MULADD(at[8], at[46]);    MULADD(at[9], at[45]);    MULADD(at[10], at[44]);    MULADD(at[11], at[43]);    MULADD(at[12], at[42]);    MULADD(at[13], at[41]);    MULADD(at[14], at[40]);    MULADD(at[15], at[39]);    MULADD(at[16], at[38]);    MULADD(at[17], at[37]);    MULADD(at[18], at[36]);    MULADD(at[19], at[35]);    MULADD(at[20], at[34]);    MULADD(at[21], at[33]);    MULADD(at[22], at[32]); 
   COMBA_STORE(C->dp[22]);
   /* 23 */
   COMBA_FORWARD;
   MULADD(at[0], at[55]);    MULADD(at[1], at[54]);    MULADD(at[2], at[53]);    MULADD(at[3], at[52]);    MULADD(at[4], at[51]);    MULADD(at[5], at[50]);    MULADD(at[6], at[49]);    MULADD(at[7], at[48]);    MULADD(at[8], at[47]);    MULADD(at[9], at[46]);    MULADD(at[10], at[45]);    MULADD(at[11], at[44]);    MULADD(at[12], at[43]);    MULADD(at[13], at[42]);    MULADD(at[14], at[41]);    MULADD(at[15], at[40]);    MULADD(at[16], at[39]);    MULADD(at[17], at[38]);    MULADD(at[18], at[37]);    MULADD(at[19], at[36]);    MULADD(at[20], at[35]);    MULADD(at[21], at[34]);    MULADD(at[22], at[33]);    MULADD(at[23], at[32]); 
   COMBA_STORE(C->dp[23]);
   /* 24 */
   COMBA_FORWARD;
   MULADD(at[0], at[56]);    MULADD(at[1], at[55]);    MULADD(at[2], at[54]);    MULADD(at[3], at[53]);    MULADD(at[4], at[52]);    MULADD(at[5], at[51]);    MULADD(at[6], at[50]);    MULADD(at[7], at[49]);    MULADD(at[8], at[48]);    MULADD(at[9], at[47]);    MULADD(at[10], at[46]);    MULADD(at[11], at[45]);    MULADD(at[12], at[44]);    MULADD(at[13], at[43]);    MULADD(at[14], at[42]);    MULADD(at[15], at[41]);    MULADD(at[16], at[40]);    MULADD(at[17], at[39]);    MULADD(at[18], at[38]);    MULADD(at[19], at[37]);    MULADD(at[20], at[36]);    MULADD(at[21], at[35]);    MULADD(at[22], at[34]);    MULADD(at[23], at[33]);    MULADD(at[24], at[32]); 
   COMBA_STORE(C->dp[24]);
   /* 25 */
   COMBA_FORWARD;
   MULADD(at[0], at[57]);    MULADD(at[1], at[56]);    MULADD(at[2], at[55]);    MULADD(at[3], at[54]);    MULADD(at[4], at[53]);    MULADD(at[5], at[52]);    MULADD(at[6], at[51]);    MULADD(at[7], at[50]);    MULADD(at[8], at[49]);    MULADD(at[9], at[48]);    MULADD(at[10], at[47]);    MULADD(at[11], at[46]);    MULADD(at[12], at[45]);    MULADD(at[13], at[44]);    MULADD(at[14], at[43]);    MULADD(at[15], at[42]);    MULADD(at[16], at[41]);    MULADD(at[17], at[40]);    MULADD(at[18], at[39]);    MULADD(at[19], at[38]);    MULADD(at[20], at[37]);    MULADD(at[21], at[36]);    MULADD(at[22], at[35]);    MULADD(at[23], at[34]);    MULADD(at[24], at[33]);    MULADD(at[25], at[32]); 
   COMBA_STORE(C->dp[25]);
   /* 26 */
   COMBA_FORWARD;
   MULADD(at[0], at[58]);    MULADD(at[1], at[57]);    MULADD(at[2], at[56]);    MULADD(at[3], at[55]);    MULADD(at[4], at[54]);    MULADD(at[5], at[53]);    MULADD(at[6], at[52]);    MULADD(at[7], at[51]);    MULADD(at[8], at[50]);    MULADD(at[9], at[49]);    MULADD(at[10], at[48]);    MULADD(at[11], at[47]);    MULADD(at[12], at[46]);    MULADD(at[13], at[45]);    MULADD(at[14], at[44]);    MULADD(at[15], at[43]);    MULADD(at[16], at[42]);    MULADD(at[17], at[41]);    MULADD(at[18], at[40]);    MULADD(at[19], at[39]);    MULADD(at[20], at[38]);    MULADD(at[21], at[37]);    MULADD(at[22], at[36]);    MULADD(at[23], at[35]);    MULADD(at[24], at[34]);    MULADD(at[25], at[33]);    MULADD(at[26], at[32]); 
   COMBA_STORE(C->dp[26]);
   /* 27 */
   COMBA_FORWARD;
   MULADD(at[0], at[59]);    MULADD(at[1], at[58]);    MULADD(at[2], at[57]);    MULADD(at[3], at[56]);    MULADD(at[4], at[55]);    MULADD(at[5], at[54]);    MULADD(at[6], at[53]);    MULADD(at[7], at[52]);    MULADD(at[8], at[51]);    MULADD(at[9], at[50]);    MULADD(at[10], at[49]);    MULADD(at[11], at[48]);    MULADD(at[12], at[47]);    MULADD(at[13], at[46]);    MULADD(at[14], at[45]);    MULADD(at[15], at[44]);    MULADD(at[16], at[43]);    MULADD(at[17], at[42]);    MULADD(at[18], at[41]);    MULADD(at[19], at[40]);    MULADD(at[20], at[39]);    MULADD(at[21], at[38]);    MULADD(at[22], at[37]);    MULADD(at[23], at[36]);    MULADD(at[24], at[35]);    MULADD(at[25], at[34]);    MULADD(at[26], at[33]);    MULADD(at[27], at[32]); 
   COMBA_STORE(C->dp[27]);
   /* 28 */
   COMBA_FORWARD;
   MULADD(at[0], at[60]);    MULADD(at[1], at[59]);    MULADD(at[2], at[58]);    MULADD(at[3], at[57]);    MULADD(at[4], at[56]);    MULADD(at[5], at[55]);    MULADD(at[6], at[54]);    MULADD(at[7], at[53]);    MULADD(at[8], at[52]);    MULADD(at[9], at[51]);    MULADD(at[10], at[50]);    MULADD(at[11], at[49]);    MULADD(at[12], at[48]);    MULADD(at[13], at[47]);    MULADD(at[14], at[46]);    MULADD(at[15], at[45]);    MULADD(at[16], at[44]);    MULADD(at[17], at[43]);    MULADD(at[18], at[42]);    MULADD(at[19], at[41]);    MULADD(at[20], at[40]);    MULADD(at[21], at[39]);    MULADD(at[22], at[38]);    MULADD(at[23], at[37]);    MULADD(at[24], at[36]);    MULADD(at[25], at[35]);    MULADD(at[26], at[34]);    MULADD(at[27], at[33]);    MULADD(at[28], at[32]); 
   COMBA_STORE(C->dp[28]);
   /* 29 */
   COMBA_FORWARD;
   MULADD(at[0], at[61]);    MULADD(at[1], at[60]);    MULADD(at[2], at[59]);    MULADD(at[3], at[58]);    MULADD(at[4], at[57]);    MULADD(at[5], at[56]);    MULADD(at[6], at[55]);    MULADD(at[7], at[54]);    MULADD(at[8], at[53]);    MULADD(at[9], at[52]);    MULADD(at[10], at[51]);    MULADD(at[11], at[50]);    MULADD(at[12], at[49]);    MULADD(at[13], at[48]);    MULADD(at[14], at[47]);    MULADD(at[15], at[46]);    MULADD(at[16], at[45]);    MULADD(at[17], at[44]);    MULADD(at[18], at[43]);    MULADD(at[19], at[42]);    MULADD(at[20], at[41]);    MULADD(at[21], at[40]);    MULADD(at[22], at[39]);    MULADD(at[23], at[38]);    MULADD(at[24], at[37]);    MULADD(at[25], at[36]);    MULADD(at[26], at[35]);    MULADD(at[27], at[34]);    MULADD(at[28], at[33]);    MULADD(at[29], at[32]); 
   COMBA_STORE(C->dp[29]);
   /* 30 */
   COMBA_FORWARD;
   MULADD(at[0], at[62]);    MULADD(at[1], at[61]);    MULADD(at[2], at[60]);    MULADD(at[3], at[59]);    MULADD(at[4], at[58]);    MULADD(at[5], at[57]);    MULADD(at[6], at[56]);    MULADD(at[7], at[55]);    MULADD(at[8], at[54]);    MULADD(at[9], at[53]);    MULADD(at[10], at[52]);    MULADD(at[11], at[51]);    MULADD(at[12], at[50]);    MULADD(at[13], at[49]);    MULADD(at[14], at[48]);    MULADD(at[15], at[47]);    MULADD(at[16], at[46]);    MULADD(at[17], at[45]);    MULADD(at[18], at[44]);    MULADD(at[19], at[43]);    MULADD(at[20], at[42]);    MULADD(at[21], at[41]);    MULADD(at[22], at[40]);    MULADD(at[23], at[39]);    MULADD(at[24], at[38]);    MULADD(at[25], at[37]);    MULADD(at[26], at[36]);    MULADD(at[27], at[35]);    MULADD(at[28], at[34]);    MULADD(at[29], at[33]);    MULADD(at[30], at[32]); 
   COMBA_STORE(C->dp[30]);
   /* 31 */
   COMBA_FORWARD;
   MULADD(at[0], at[63]);    MULADD(at[1], at[62]);    MULADD(at[2], at[61]);    MULADD(at[3], at[60]);    MULADD(at[4], at[59]);    MULADD(at[5], at[58]);    MULADD(at[6], at[57]);    MULADD(at[7], at[56]);    MULADD(at[8], at[55]);    MULADD(at[9], at[54]);    MULADD(at[10], at[53]);    MULADD(at[11], at[52]);    MULADD(at[12], at[51]);    MULADD(at[13], at[50]);    MULADD(at[14], at[49]);    MULADD(at[15], at[48]);    MULADD(at[16], at[47]);    MULADD(at[17], at[46]);    MULADD(at[18], at[45]);    MULADD(at[19], at[44]);    MULADD(at[20], at[43]);    MULADD(at[21], at[42]);    MULADD(at[22], at[41]);    MULADD(at[23], at[40]);    MULADD(at[24], at[39]);    MULADD(at[25], at[38]);    MULADD(at[26], at[37]);    MULADD(at[27], at[36]);    MULADD(at[28], at[35]);    MULADD(at[29], at[34]);    MULADD(at[30], at[33]);    MULADD(at[31], at[32]); 
   COMBA_STORE(C->dp[31]);
   /* 32 */
   COMBA_FORWARD;
   MULADD(at[1], at[63]);    MULADD(at[2], at[62]);    MULADD(at[3], at[61]);    MULADD(at[4], at[60]);    MULADD(at[5], at[59]);    MULADD(at[6], at[58]);    MULADD(at[7], at[57]);    MULADD(at[8], at[56]);    MULADD(at[9], at[55]);    MULADD(at[10], at[54]);    MULADD(at[11], at[53]);    MULADD(at[12], at[52]);    MULADD(at[13], at[51]);    MULADD(at[14], at[50]);    MULADD(at[15], at[49]);    MULADD(at[16], at[48]);    MULADD(at[17], at[47]);    MULADD(at[18], at[46]);    MULADD(at[19], at[45]);    MULADD(at[20], at[44]);    MULADD(at[21], at[43]);    MULADD(at[22], at[42]);    MULADD(at[23], at[41]);    MULADD(at[24], at[40]);    MULADD(at[25], at[39]);    MULADD(at[26], at[38]);    MULADD(at[27], at[37]);    MULADD(at[28], at[36]);    MULADD(at[29], at[35]);    MULADD(at[30], at[34]);    MULADD(at[31], at[33]); 
   COMBA_STORE(C->dp[32]);
   /* 33 */
   COMBA_FORWARD;
   MULADD(at[2], at[63]);    MULADD(at[3], at[62]);    MULADD(at[4], at[61]);    MULADD(at[5], at[60]);    MULADD(at[6], at[59]);    MULADD(at[7], at[58]);    MULADD(at[8], at[57]);    MULADD(at[9], at[56]);    MULADD(at[10], at[55]);    MULADD(at[11], at[54]);    MULADD(at[12], at[53]);    MULADD(at[13], at[52]);    MULADD(at[14], at[51]);    MULADD(at[15], at[50]);    MULADD(at[16], at[49]);    MULADD(at[17], at[48]);    MULADD(at[18], at[47]);    MULADD(at[19], at[46]);    MULADD(at[20], at[45]);    MULADD(at[21], at[44]);    MULADD(at[22], at[43]);    MULADD(at[23], at[42]);    MULADD(at[24], at[41]);    MULADD(at[25], at[40]);    MULADD(at[26], at[39]);    MULADD(at[27], at[38]);    MULADD(at[28], at[37]);    MULADD(at[29], at[36]);    MULADD(at[30], at[35]);    MULADD(at[31], at[34]); 
   COMBA_STORE(C->dp[33]);
   /* 34 */
   COMBA_FORWARD;
   MULADD(at[3], at[63]);    MULADD(at[4], at[62]);    MULADD(at[5], at[61]);    MULADD(at[6], at[60]);    MULADD(at[7], at[59]);    MULADD(at[8], at[58]);    MULADD(at[9], at[57]);    MULADD(at[10], at[56]);    MULADD(at[11], at[55]);    MULADD(at[12], at[54]);    MULADD(at[13], at[53]);    MULADD(at[14], at[52]);    MULADD(at[15], at[51]);    MULADD(at[16], at[50]);    MULADD(at[17], at[49]);    MULADD(at[18], at[48]);    MULADD(at[19], at[47]);    MULADD(at[20], at[46]);    MULADD(at[21], at[45]);    MULADD(at[22], at[44]);    MULADD(at[23], at[43]);    MULADD(at[24], at[42]);    MULADD(at[25], at[41]);    MULADD(at[26], at[40]);    MULADD(at[27], at[39]);    MULADD(at[28], at[38]);    MULADD(at[29], at[37]);    MULADD(at[30], at[36]);    MULADD(at[31], at[35]); 
   COMBA_STORE(C->dp[34]);
   /* 35 */
   COMBA_FORWARD;
   MULADD(at[4], at[63]);    MULADD(at[5], at[62]);    MULADD(at[6], at[61]);    MULADD(at[7], at[60]);    MULADD(at[8], at[59]);    MULADD(at[9], at[58]);    MULADD(at[10], at[57]);    MULADD(at[11], at[56]);    MULADD(at[12], at[55]);    MULADD(at[13], at[54]);    MULADD(at[14], at[53]);    MULADD(at[15], at[52]);    MULADD(at[16], at[51]);    MULADD(at[17], at[50]);    MULADD(at[18], at[49]);    MULADD(at[19], at[48]);    MULADD(at[20], at[47]);    MULADD(at[21], at[46]);    MULADD(at[22], at[45]);    MULADD(at[23], at[44]);    MULADD(at[24], at[43]);    MULADD(at[25], at[42]);    MULADD(at[26], at[41]);    MULADD(at[27], at[40]);    MULADD(at[28], at[39]);    MULADD(at[29], at[38]);    MULADD(at[30], at[37]);    MULADD(at[31], at[36]); 
   COMBA_STORE(C->dp[35]);
   /* 36 */
   COMBA_FORWARD;
   MULADD(at[5], at[63]);    MULADD(at[6], at[62]);    MULADD(at[7], at[61]);    MULADD(at[8], at[60]);    MULADD(at[9], at[59]);    MULADD(at[10], at[58]);    MULADD(at[11], at[57]);    MULADD(at[12], at[56]);    MULADD(at[13], at[55]);    MULADD(at[14], at[54]);    MULADD(at[15], at[53]);    MULADD(at[16], at[52]);    MULADD(at[17], at[51]);    MULADD(at[18], at[50]);    MULADD(at[19], at[49]);    MULADD(at[20], at[48]);    MULADD(at[21], at[47]);    MULADD(at[22], at[46]);    MULADD(at[23], at[45]);    MULADD(at[24], at[44]);    MULADD(at[25], at[43]);    MULADD(at[26], at[42]);    MULADD(at[27], at[41]);    MULADD(at[28], at[40]);    MULADD(at[29], at[39]);    MULADD(at[30], at[38]);    MULADD(at[31], at[37]); 
   COMBA_STORE(C->dp[36]);
   /* 37 */
   COMBA_FORWARD;
   MULADD(at[6], at[63]);    MULADD(at[7], at[62]);    MULADD(at[8], at[61]);    MULADD(at[9], at[60]);    MULADD(at[10], at[59]);    MULADD(at[11], at[58]);    MULADD(at[12], at[57]);    MULADD(at[13], at[56]);    MULADD(at[14], at[55]);    MULADD(at[15], at[54]);    MULADD(at[16], at[53]);    MULADD(at[17], at[52]);    MULADD(at[18], at[51]);    MULADD(at[19], at[50]);    MULADD(at[20], at[49]);    MULADD(at[21], at[48]);    MULADD(at[22], at[47]);    MULADD(at[23], at[46]);    MULADD(at[24], at[45]);    MULADD(at[25], at[44]);    MULADD(at[26], at[43]);    MULADD(at[27], at[42]);    MULADD(at[28], at[41]);    MULADD(at[29], at[40]);    MULADD(at[30], at[39]);    MULADD(at[31], at[38]); 
   COMBA_STORE(C->dp[37]);
   /* 38 */
   COMBA_FORWARD;
   MULADD(at[7], at[63]);    MULADD(at[8], at[62]);    MULADD(at[9], at[61]);    MULADD(at[10], at[60]);    MULADD(at[11], at[59]);    MULADD(at[12], at[58]);    MULADD(at[13], at[57]);    MULADD(at[14], at[56]);    MULADD(at[15], at[55]);    MULADD(at[16], at[54]);    MULADD(at[17], at[53]);    MULADD(at[18], at[52]);    MULADD(at[19], at[51]);    MULADD(at[20], at[50]);    MULADD(at[21], at[49]);    MULADD(at[22], at[48]);    MULADD(at[23], at[47]);    MULADD(at[24], at[46]);    MULADD(at[25], at[45]);    MULADD(at[26], at[44]);    MULADD(at[27], at[43]);    MULADD(at[28], at[42]);    MULADD(at[29], at[41]);    MULADD(at[30], at[40]);    MULADD(at[31], at[39]); 
   COMBA_STORE(C->dp[38]);

   /* early out at 40 digits, 40*32==1280, or two 640 bit operands */
   if (out_size <= 40) { COMBA_STORE2(C->dp[39]); C->used = 40; C->sign = A->sign ^ B->sign; fp_clamp(C); COMBA_FINI; return; }

   /* 39 */
   COMBA_FORWARD;
   MULADD(at[8], at[63]);    MULADD(at[9], at[62]);    MULADD(at[10], at[61]);    MULADD(at[11], at[60]);    MULADD(at[12], at[59]);    MULADD(at[13], at[58]);    MULADD(at[14], at[57]);    MULADD(at[15], at[56]);    MULADD(at[16], at[55]);    MULADD(at[17], at[54]);    MULADD(at[18], at[53]);    MULADD(at[19], at[52]);    MULADD(at[20], at[51]);    MULADD(at[21], at[50]);    MULADD(at[22], at[49]);    MULADD(at[23], at[48]);    MULADD(at[24], at[47]);    MULADD(at[25], at[46]);    MULADD(at[26], at[45]);    MULADD(at[27], at[44]);    MULADD(at[28], at[43]);    MULADD(at[29], at[42]);    MULADD(at[30], at[41]);    MULADD(at[31], at[40]); 
   COMBA_STORE(C->dp[39]);
   /* 40 */
   COMBA_FORWARD;
   MULADD(at[9], at[63]);    MULADD(at[10], at[62]);    MULADD(at[11], at[61]);    MULADD(at[12], at[60]);    MULADD(at[13], at[59]);    MULADD(at[14], at[58]);    MULADD(at[15], at[57]);    MULADD(at[16], at[56]);    MULADD(at[17], at[55]);    MULADD(at[18], at[54]);    MULADD(at[19], at[53]);    MULADD(at[20], at[52]);    MULADD(at[21], at[51]);    MULADD(at[22], at[50]);    MULADD(at[23], at[49]);    MULADD(at[24], at[48]);    MULADD(at[25], at[47]);    MULADD(at[26], at[46]);    MULADD(at[27], at[45]);    MULADD(at[28], at[44]);    MULADD(at[29], at[43]);    MULADD(at[30], at[42]);    MULADD(at[31], at[41]); 
   COMBA_STORE(C->dp[40]);
   /* 41 */
   COMBA_FORWARD;
   MULADD(at[10], at[63]);    MULADD(at[11], at[62]);    MULADD(at[12], at[61]);    MULADD(at[13], at[60]);    MULADD(at[14], at[59]);    MULADD(at[15], at[58]);    MULADD(at[16], at[57]);    MULADD(at[17], at[56]);    MULADD(at[18], at[55]);    MULADD(at[19], at[54]);    MULADD(at[20], at[53]);    MULADD(at[21], at[52]);    MULADD(at[22], at[51]);    MULADD(at[23], at[50]);    MULADD(at[24], at[49]);    MULADD(at[25], at[48]);    MULADD(at[26], at[47]);    MULADD(at[27], at[46]);    MULADD(at[28], at[45]);    MULADD(at[29], at[44]);    MULADD(at[30], at[43]);    MULADD(at[31], at[42]); 
   COMBA_STORE(C->dp[41]);
   /* 42 */
   COMBA_FORWARD;
   MULADD(at[11], at[63]);    MULADD(at[12], at[62]);    MULADD(at[13], at[61]);    MULADD(at[14], at[60]);    MULADD(at[15], at[59]);    MULADD(at[16], at[58]);    MULADD(at[17], at[57]);    MULADD(at[18], at[56]);    MULADD(at[19], at[55]);    MULADD(at[20], at[54]);    MULADD(at[21], at[53]);    MULADD(at[22], at[52]);    MULADD(at[23], at[51]);    MULADD(at[24], at[50]);    MULADD(at[25], at[49]);    MULADD(at[26], at[48]);    MULADD(at[27], at[47]);    MULADD(at[28], at[46]);    MULADD(at[29], at[45]);    MULADD(at[30], at[44]);    MULADD(at[31], at[43]); 
   COMBA_STORE(C->dp[42]);
   /* 43 */
   COMBA_FORWARD;
   MULADD(at[12], at[63]);    MULADD(at[13], at[62]);    MULADD(at[14], at[61]);    MULADD(at[15], at[60]);    MULADD(at[16], at[59]);    MULADD(at[17], at[58]);    MULADD(at[18], at[57]);    MULADD(at[19], at[56]);    MULADD(at[20], at[55]);    MULADD(at[21], at[54]);    MULADD(at[22], at[53]);    MULADD(at[23], at[52]);    MULADD(at[24], at[51]);    MULADD(at[25], at[50]);    MULADD(at[26], at[49]);    MULADD(at[27], at[48]);    MULADD(at[28], at[47]);    MULADD(at[29], at[46]);    MULADD(at[30], at[45]);    MULADD(at[31], at[44]); 
   COMBA_STORE(C->dp[43]);
   /* 44 */
   COMBA_FORWARD;
   MULADD(at[13], at[63]);    MULADD(at[14], at[62]);    MULADD(at[15], at[61]);    MULADD(at[16], at[60]);    MULADD(at[17], at[59]);    MULADD(at[18], at[58]);    MULADD(at[19], at[57]);    MULADD(at[20], at[56]);    MULADD(at[21], at[55]);    MULADD(at[22], at[54]);    MULADD(at[23], at[53]);    MULADD(at[24], at[52]);    MULADD(at[25], at[51]);    MULADD(at[26], at[50]);    MULADD(at[27], at[49]);    MULADD(at[28], at[48]);    MULADD(at[29], at[47]);    MULADD(at[30], at[46]);    MULADD(at[31], at[45]); 
   COMBA_STORE(C->dp[44]);
   /* 45 */
   COMBA_FORWARD;
   MULADD(at[14], at[63]);    MULADD(at[15], at[62]);    MULADD(at[16], at[61]);    MULADD(at[17], at[60]);    MULADD(at[18], at[59]);    MULADD(at[19], at[58]);    MULADD(at[20], at[57]);    MULADD(at[21], at[56]);    MULADD(at[22], at[55]);    MULADD(at[23], at[54]);    MULADD(at[24], at[53]);    MULADD(at[25], at[52]);    MULADD(at[26], at[51]);    MULADD(at[27], at[50]);    MULADD(at[28], at[49]);    MULADD(at[29], at[48]);    MULADD(at[30], at[47]);    MULADD(at[31], at[46]); 
   COMBA_STORE(C->dp[45]);
   /* 46 */
   COMBA_FORWARD;
   MULADD(at[15], at[63]);    MULADD(at[16], at[62]);    MULADD(at[17], at[61]);    MULADD(at[18], at[60]);    MULADD(at[19], at[59]);    MULADD(at[20], at[58]);    MULADD(at[21], at[57]);    MULADD(at[22], at[56]);    MULADD(at[23], at[55]);    MULADD(at[24], at[54]);    MULADD(at[25], at[53]);    MULADD(at[26], at[52]);    MULADD(at[27], at[51]);    MULADD(at[28], at[50]);    MULADD(at[29], at[49]);    MULADD(at[30], at[48]);    MULADD(at[31], at[47]); 
   COMBA_STORE(C->dp[46]);

   /* early out at 48 digits, 48*32==1536, or two 768 bit operands */
   if (out_size <= 48) { COMBA_STORE2(C->dp[47]); C->used = 48; C->sign = A->sign ^ B->sign; fp_clamp(C); COMBA_FINI; return; }

   /* 47 */
   COMBA_FORWARD;
   MULADD(at[16], at[63]);    MULADD(at[17], at[62]);    MULADD(at[18], at[61]);    MULADD(at[19], at[60]);    MULADD(at[20], at[59]);    MULADD(at[21], at[58]);    MULADD(at[22], at[57]);    MULADD(at[23], at[56]);    MULADD(at[24], at[55]);    MULADD(at[25], at[54]);    MULADD(at[26], at[53]);    MULADD(at[27], at[52]);    MULADD(at[28], at[51]);    MULADD(at[29], at[50]);    MULADD(at[30], at[49]);    MULADD(at[31], at[48]); 
   COMBA_STORE(C->dp[47]);
   /* 48 */
   COMBA_FORWARD;
   MULADD(at[17], at[63]);    MULADD(at[18], at[62]);    MULADD(at[19], at[61]);    MULADD(at[20], at[60]);    MULADD(at[21], at[59]);    MULADD(at[22], at[58]);    MULADD(at[23], at[57]);    MULADD(at[24], at[56]);    MULADD(at[25], at[55]);    MULADD(at[26], at[54]);    MULADD(at[27], at[53]);    MULADD(at[28], at[52]);    MULADD(at[29], at[51]);    MULADD(at[30], at[50]);    MULADD(at[31], at[49]); 
   COMBA_STORE(C->dp[48]);
   /* 49 */
   COMBA_FORWARD;
   MULADD(at[18], at[63]);    MULADD(at[19], at[62]);    MULADD(at[20], at[61]);    MULADD(at[21], at[60]);    MULADD(at[22], at[59]);    MULADD(at[23], at[58]);    MULADD(at[24], at[57]);    MULADD(at[25], at[56]);    MULADD(at[26], at[55]);    MULADD(at[27], at[54]);    MULADD(at[28], at[53]);    MULADD(at[29], at[52]);    MULADD(at[30], at[51]);    MULADD(at[31], at[50]); 
   COMBA_STORE(C->dp[49]);
   /* 50 */
   COMBA_FORWARD;
   MULADD(at[19], at[63]);    MULADD(at[20], at[62]);    MULADD(at[21], at[61]);    MULADD(at[22], at[60]);    MULADD(at[23], at[59]);    MULADD(at[24], at[58]);    MULADD(at[25], at[57]);    MULADD(at[26], at[56]);    MULADD(at[27], at[55]);    MULADD(at[28], at[54]);    MULADD(at[29], at[53]);    MULADD(at[30], at[52]);    MULADD(at[31], at[51]); 
   COMBA_STORE(C->dp[50]);
   /* 51 */
   COMBA_FORWARD;
   MULADD(at[20], at[63]);    MULADD(at[21], at[62]);    MULADD(at[22], at[61]);    MULADD(at[23], at[60]);    MULADD(at[24], at[59]);    MULADD(at[25], at[58]);    MULADD(at[26], at[57]);    MULADD(at[27], at[56]);    MULADD(at[28], at[55]);    MULADD(at[29], at[54]);    MULADD(at[30], at[53]);    MULADD(at[31], at[52]); 
   COMBA_STORE(C->dp[51]);
   /* 52 */
   COMBA_FORWARD;
   MULADD(at[21], at[63]);    MULADD(at[22], at[62]);    MULADD(at[23], at[61]);    MULADD(at[24], at[60]);    MULADD(at[25], at[59]);    MULADD(at[26], at[58]);    MULADD(at[27], at[57]);    MULADD(at[28], at[56]);    MULADD(at[29], at[55]);    MULADD(at[30], at[54]);    MULADD(at[31], at[53]); 
   COMBA_STORE(C->dp[52]);
   /* 53 */
   COMBA_FORWARD;
   MULADD(at[22], at[63]);    MULADD(at[23], at[62]);    MULADD(at[24], at[61]);    MULADD(at[25], at[60]);    MULADD(at[26], at[59]);    MULADD(at[27], at[58]);    MULADD(at[28], at[57]);    MULADD(at[29], at[56]);    MULADD(at[30], at[55]);    MULADD(at[31], at[54]); 
   COMBA_STORE(C->dp[53]);
   /* 54 */
   COMBA_FORWARD;
   MULADD(at[23], at[63]);    MULADD(at[24], at[62]);    MULADD(at[25], at[61]);    MULADD(at[26], at[60]);    MULADD(at[27], at[59]);    MULADD(at[28], at[58]);    MULADD(at[29], at[57]);    MULADD(at[30], at[56]);    MULADD(at[31], at[55]); 
   COMBA_STORE(C->dp[54]);

   /* early out at 56 digits, 56*32==1792, or two 896 bit operands */
   if (out_size <= 56) { COMBA_STORE2(C->dp[55]); C->used = 56; C->sign = A->sign ^ B->sign; fp_clamp(C); COMBA_FINI; return; }

   /* 55 */
   COMBA_FORWARD;
   MULADD(at[24], at[63]);    MULADD(at[25], at[62]);    MULADD(at[26], at[61]);    MULADD(at[27], at[60]);    MULADD(at[28], at[59]);    MULADD(at[29], at[58]);    MULADD(at[30], at[57]);    MULADD(at[31], at[56]); 
   COMBA_STORE(C->dp[55]);
   /* 56 */
   COMBA_FORWARD;
   MULADD(at[25], at[63]);    MULADD(at[26], at[62]);    MULADD(at[27], at[61]);    MULADD(at[28], at[60]);    MULADD(at[29], at[59]);    MULADD(at[30], at[58]);    MULADD(at[31], at[57]); 
   COMBA_STORE(C->dp[56]);
   /* 57 */
   COMBA_FORWARD;
   MULADD(at[26], at[63]);    MULADD(at[27], at[62]);    MULADD(at[28], at[61]);    MULADD(at[29], at[60]);    MULADD(at[30], at[59]);    MULADD(at[31], at[58]); 
   COMBA_STORE(C->dp[57]);
   /* 58 */
   COMBA_FORWARD;
   MULADD(at[27], at[63]);    MULADD(at[28], at[62]);    MULADD(at[29], at[61]);    MULADD(at[30], at[60]);    MULADD(at[31], at[59]); 
   COMBA_STORE(C->dp[58]);
   /* 59 */
   COMBA_FORWARD;
   MULADD(at[28], at[63]);    MULADD(at[29], at[62]);    MULADD(at[30], at[61]);    MULADD(at[31], at[60]); 
   COMBA_STORE(C->dp[59]);
   /* 60 */
   COMBA_FORWARD;
   MULADD(at[29], at[63]);    MULADD(at[30], at[62]);    MULADD(at[31], at[61]); 
   COMBA_STORE(C->dp[60]);
   /* 61 */
   COMBA_FORWARD;
   MULADD(at[30], at[63]);    MULADD(at[31], at[62]); 
   COMBA_STORE(C->dp[61]);
   /* 62 */
   COMBA_FORWARD;
   MULADD(at[31], at[63]); 
   COMBA_STORE(C->dp[62]);
   COMBA_STORE2(C->dp[63]);
   C->used = 64;
   C->sign = A->sign ^ B->sign;
   fp_clamp(C);
   COMBA_FINI;
}
#endif

/* End: fp_mul_comba_32.c */

/* Start: fp_mul_comba_4.c */
#define TFM_DEFINES
#include "fp_mul_comba.c"

#ifdef TFM_MUL4
void fp_mul_comba4(fp_int *A, fp_int *B, fp_int *C)
{
   fp_digit c0, c1, c2, at[8];

   memcpy(at, A->dp, 4 * sizeof(fp_digit));
   memcpy(at+4, B->dp, 4 * sizeof(fp_digit));
   COMBA_START;

   COMBA_CLEAR;
   /* 0 */
   MULADD(at[0], at[4]); 
   COMBA_STORE(C->dp[0]);
   /* 1 */
   COMBA_FORWARD;
   MULADD(at[0], at[5]);    MULADD(at[1], at[4]); 
   COMBA_STORE(C->dp[1]);
   /* 2 */
   COMBA_FORWARD;
   MULADD(at[0], at[6]);    MULADD(at[1], at[5]);    MULADD(at[2], at[4]); 
   COMBA_STORE(C->dp[2]);
   /* 3 */
   COMBA_FORWARD;
   MULADD(at[0], at[7]);    MULADD(at[1], at[6]);    MULADD(at[2], at[5]);    MULADD(at[3], at[4]); 
   COMBA_STORE(C->dp[3]);
   /* 4 */
   COMBA_FORWARD;
   MULADD(at[1], at[7]);    MULADD(at[2], at[6]);    MULADD(at[3], at[5]); 
   COMBA_STORE(C->dp[4]);
   /* 5 */
   COMBA_FORWARD;
   MULADD(at[2], at[7]);    MULADD(at[3], at[6]); 
   COMBA_STORE(C->dp[5]);
   /* 6 */
   COMBA_FORWARD;
   MULADD(at[3], at[7]); 
   COMBA_STORE(C->dp[6]);
   COMBA_STORE2(C->dp[7]);
   C->used = 8;
   C->sign = A->sign ^ B->sign;
   fp_clamp(C);
   COMBA_FINI;
}
#endif

/* End: fp_mul_comba_4.c */

/* Start: fp_mul_comba_48.c */
#define TFM_DEFINES
#include "fp_mul_comba.c"

#ifdef TFM_MUL48
void fp_mul_comba48(fp_int *A, fp_int *B, fp_int *C)
{
   fp_digit c0, c1, c2, at[96];

   memcpy(at, A->dp, 48 * sizeof(fp_digit));
   memcpy(at+48, B->dp, 48 * sizeof(fp_digit));
   COMBA_START;

   COMBA_CLEAR;
   /* 0 */
   MULADD(at[0], at[48]); 
   COMBA_STORE(C->dp[0]);
   /* 1 */
   COMBA_FORWARD;
   MULADD(at[0], at[49]);    MULADD(at[1], at[48]); 
   COMBA_STORE(C->dp[1]);
   /* 2 */
   COMBA_FORWARD;
   MULADD(at[0], at[50]);    MULADD(at[1], at[49]);    MULADD(at[2], at[48]); 
   COMBA_STORE(C->dp[2]);
   /* 3 */
   COMBA_FORWARD;
   MULADD(at[0], at[51]);    MULADD(at[1], at[50]);    MULADD(at[2], at[49]);    MULADD(at[3], at[48]); 
   COMBA_STORE(C->dp[3]);
   /* 4 */
   COMBA_FORWARD;
   MULADD(at[0], at[52]);    MULADD(at[1], at[51]);    MULADD(at[2], at[50]);    MULADD(at[3], at[49]);    MULADD(at[4], at[48]); 
   COMBA_STORE(C->dp[4]);
   /* 5 */
   COMBA_FORWARD;
   MULADD(at[0], at[53]);    MULADD(at[1], at[52]);    MULADD(at[2], at[51]);    MULADD(at[3], at[50]);    MULADD(at[4], at[49]);    MULADD(at[5], at[48]); 
   COMBA_STORE(C->dp[5]);
   /* 6 */
   COMBA_FORWARD;
   MULADD(at[0], at[54]);    MULADD(at[1], at[53]);    MULADD(at[2], at[52]);    MULADD(at[3], at[51]);    MULADD(at[4], at[50]);    MULADD(at[5], at[49]);    MULADD(at[6], at[48]); 
   COMBA_STORE(C->dp[6]);
   /* 7 */
   COMBA_FORWARD;
   MULADD(at[0], at[55]);    MULADD(at[1], at[54]);    MULADD(at[2], at[53]);    MULADD(at[3], at[52]);    MULADD(at[4], at[51]);    MULADD(at[5], at[50]);    MULADD(at[6], at[49]);    MULADD(at[7], at[48]); 
   COMBA_STORE(C->dp[7]);
   /* 8 */
   COMBA_FORWARD;
   MULADD(at[0], at[56]);    MULADD(at[1], at[55]);    MULADD(at[2], at[54]);    MULADD(at[3], at[53]);    MULADD(at[4], at[52]);    MULADD(at[5], at[51]);    MULADD(at[6], at[50]);    MULADD(at[7], at[49]);    MULADD(at[8], at[48]); 
   COMBA_STORE(C->dp[8]);
   /* 9 */
   COMBA_FORWARD;
   MULADD(at[0], at[57]);    MULADD(at[1], at[56]);    MULADD(at[2], at[55]);    MULADD(at[3], at[54]);    MULADD(at[4], at[53]);    MULADD(at[5], at[52]);    MULADD(at[6], at[51]);    MULADD(at[7], at[50]);    MULADD(at[8], at[49]);    MULADD(at[9], at[48]); 
   COMBA_STORE(C->dp[9]);
   /* 10 */
   COMBA_FORWARD;
   MULADD(at[0], at[58]);    MULADD(at[1], at[57]);    MULADD(at[2], at[56]);    MULADD(at[3], at[55]);    MULADD(at[4], at[54]);    MULADD(at[5], at[53]);    MULADD(at[6], at[52]);    MULADD(at[7], at[51]);    MULADD(at[8], at[50]);    MULADD(at[9], at[49]);    MULADD(at[10], at[48]); 
   COMBA_STORE(C->dp[10]);
   /* 11 */
   COMBA_FORWARD;
   MULADD(at[0], at[59]);    MULADD(at[1], at[58]);    MULADD(at[2], at[57]);    MULADD(at[3], at[56]);    MULADD(at[4], at[55]);    MULADD(at[5], at[54]);    MULADD(at[6], at[53]);    MULADD(at[7], at[52]);    MULADD(at[8], at[51]);    MULADD(at[9], at[50]);    MULADD(at[10], at[49]);    MULADD(at[11], at[48]); 
   COMBA_STORE(C->dp[11]);
   /* 12 */
   COMBA_FORWARD;
   MULADD(at[0], at[60]);    MULADD(at[1], at[59]);    MULADD(at[2], at[58]);    MULADD(at[3], at[57]);    MULADD(at[4], at[56]);    MULADD(at[5], at[55]);    MULADD(at[6], at[54]);    MULADD(at[7], at[53]);    MULADD(at[8], at[52]);    MULADD(at[9], at[51]);    MULADD(at[10], at[50]);    MULADD(at[11], at[49]);    MULADD(at[12], at[48]); 
   COMBA_STORE(C->dp[12]);
   /* 13 */
   COMBA_FORWARD;
   MULADD(at[0], at[61]);    MULADD(at[1], at[60]);    MULADD(at[2], at[59]);    MULADD(at[3], at[58]);    MULADD(at[4], at[57]);    MULADD(at[5], at[56]);    MULADD(at[6], at[55]);    MULADD(at[7], at[54]);    MULADD(at[8], at[53]);    MULADD(at[9], at[52]);    MULADD(at[10], at[51]);    MULADD(at[11], at[50]);    MULADD(at[12], at[49]);    MULADD(at[13], at[48]); 
   COMBA_STORE(C->dp[13]);
   /* 14 */
   COMBA_FORWARD;
   MULADD(at[0], at[62]);    MULADD(at[1], at[61]);    MULADD(at[2], at[60]);    MULADD(at[3], at[59]);    MULADD(at[4], at[58]);    MULADD(at[5], at[57]);    MULADD(at[6], at[56]);    MULADD(at[7], at[55]);    MULADD(at[8], at[54]);    MULADD(at[9], at[53]);    MULADD(at[10], at[52]);    MULADD(at[11], at[51]);    MULADD(at[12], at[50]);    MULADD(at[13], at[49]);    MULADD(at[14], at[48]); 
   COMBA_STORE(C->dp[14]);
   /* 15 */
   COMBA_FORWARD;
   MULADD(at[0], at[63]);    MULADD(at[1], at[62]);    MULADD(at[2], at[61]);    MULADD(at[3], at[60]);    MULADD(at[4], at[59]);    MULADD(at[5], at[58]);    MULADD(at[6], at[57]);    MULADD(at[7], at[56]);    MULADD(at[8], at[55]);    MULADD(at[9], at[54]);    MULADD(at[10], at[53]);    MULADD(at[11], at[52]);    MULADD(at[12], at[51]);    MULADD(at[13], at[50]);    MULADD(at[14], at[49]);    MULADD(at[15], at[48]); 
   COMBA_STORE(C->dp[15]);
   /* 16 */
   COMBA_FORWARD;
   MULADD(at[0], at[64]);    MULADD(at[1], at[63]);    MULADD(at[2], at[62]);    MULADD(at[3], at[61]);    MULADD(at[4], at[60]);    MULADD(at[5], at[59]);    MULADD(at[6], at[58]);    MULADD(at[7], at[57]);    MULADD(at[8], at[56]);    MULADD(at[9], at[55]);    MULADD(at[10], at[54]);    MULADD(at[11], at[53]);    MULADD(at[12], at[52]);    MULADD(at[13], at[51]);    MULADD(at[14], at[50]);    MULADD(at[15], at[49]);    MULADD(at[16], at[48]); 
   COMBA_STORE(C->dp[16]);
   /* 17 */
   COMBA_FORWARD;
   MULADD(at[0], at[65]);    MULADD(at[1], at[64]);    MULADD(at[2], at[63]);    MULADD(at[3], at[62]);    MULADD(at[4], at[61]);    MULADD(at[5], at[60]);    MULADD(at[6], at[59]);    MULADD(at[7], at[58]);    MULADD(at[8], at[57]);    MULADD(at[9], at[56]);    MULADD(at[10], at[55]);    MULADD(at[11], at[54]);    MULADD(at[12], at[53]);    MULADD(at[13], at[52]);    MULADD(at[14], at[51]);    MULADD(at[15], at[50]);    MULADD(at[16], at[49]);    MULADD(at[17], at[48]); 
   COMBA_STORE(C->dp[17]);
   /* 18 */
   COMBA_FORWARD;
   MULADD(at[0], at[66]);    MULADD(at[1], at[65]);    MULADD(at[2], at[64]);    MULADD(at[3], at[63]);    MULADD(at[4], at[62]);    MULADD(at[5], at[61]);    MULADD(at[6], at[60]);    MULADD(at[7], at[59]);    MULADD(at[8], at[58]);    MULADD(at[9], at[57]);    MULADD(at[10], at[56]);    MULADD(at[11], at[55]);    MULADD(at[12], at[54]);    MULADD(at[13], at[53]);    MULADD(at[14], at[52]);    MULADD(at[15], at[51]);    MULADD(at[16], at[50]);    MULADD(at[17], at[49]);    MULADD(at[18], at[48]); 
   COMBA_STORE(C->dp[18]);
   /* 19 */
   COMBA_FORWARD;
   MULADD(at[0], at[67]);    MULADD(at[1], at[66]);    MULADD(at[2], at[65]);    MULADD(at[3], at[64]);    MULADD(at[4], at[63]);    MULADD(at[5], at[62]);    MULADD(at[6], at[61]);    MULADD(at[7], at[60]);    MULADD(at[8], at[59]);    MULADD(at[9], at[58]);    MULADD(at[10], at[57]);    MULADD(at[11], at[56]);    MULADD(at[12], at[55]);    MULADD(at[13], at[54]);    MULADD(at[14], at[53]);    MULADD(at[15], at[52]);    MULADD(at[16], at[51]);    MULADD(at[17], at[50]);    MULADD(at[18], at[49]);    MULADD(at[19], at[48]); 
   COMBA_STORE(C->dp[19]);
   /* 20 */
   COMBA_FORWARD;
   MULADD(at[0], at[68]);    MULADD(at[1], at[67]);    MULADD(at[2], at[66]);    MULADD(at[3], at[65]);    MULADD(at[4], at[64]);    MULADD(at[5], at[63]);    MULADD(at[6], at[62]);    MULADD(at[7], at[61]);    MULADD(at[8], at[60]);    MULADD(at[9], at[59]);    MULADD(at[10], at[58]);    MULADD(at[11], at[57]);    MULADD(at[12], at[56]);    MULADD(at[13], at[55]);    MULADD(at[14], at[54]);    MULADD(at[15], at[53]);    MULADD(at[16], at[52]);    MULADD(at[17], at[51]);    MULADD(at[18], at[50]);    MULADD(at[19], at[49]);    MULADD(at[20], at[48]); 
   COMBA_STORE(C->dp[20]);
   /* 21 */
   COMBA_FORWARD;
   MULADD(at[0], at[69]);    MULADD(at[1], at[68]);    MULADD(at[2], at[67]);    MULADD(at[3], at[66]);    MULADD(at[4], at[65]);    MULADD(at[5], at[64]);    MULADD(at[6], at[63]);    MULADD(at[7], at[62]);    MULADD(at[8], at[61]);    MULADD(at[9], at[60]);    MULADD(at[10], at[59]);    MULADD(at[11], at[58]);    MULADD(at[12], at[57]);    MULADD(at[13], at[56]);    MULADD(at[14], at[55]);    MULADD(at[15], at[54]);    MULADD(at[16], at[53]);    MULADD(at[17], at[52]);    MULADD(at[18], at[51]);    MULADD(at[19], at[50]);    MULADD(at[20], at[49]);    MULADD(at[21], at[48]); 
   COMBA_STORE(C->dp[21]);
   /* 22 */
   COMBA_FORWARD;
   MULADD(at[0], at[70]);    MULADD(at[1], at[69]);    MULADD(at[2], at[68]);    MULADD(at[3], at[67]);    MULADD(at[4], at[66]);    MULADD(at[5], at[65]);    MULADD(at[6], at[64]);    MULADD(at[7], at[63]);    MULADD(at[8], at[62]);    MULADD(at[9], at[61]);    MULADD(at[10], at[60]);    MULADD(at[11], at[59]);    MULADD(at[12], at[58]);    MULADD(at[13], at[57]);    MULADD(at[14], at[56]);    MULADD(at[15], at[55]);    MULADD(at[16], at[54]);    MULADD(at[17], at[53]);    MULADD(at[18], at[52]);    MULADD(at[19], at[51]);    MULADD(at[20], at[50]);    MULADD(at[21], at[49]);    MULADD(at[22], at[48]); 
   COMBA_STORE(C->dp[22]);
   /* 23 */
   COMBA_FORWARD;
   MULADD(at[0], at[71]);    MULADD(at[1], at[70]);    MULADD(at[2], at[69]);    MULADD(at[3], at[68]);    MULADD(at[4], at[67]);    MULADD(at[5], at[66]);    MULADD(at[6], at[65]);    MULADD(at[7], at[64]);    MULADD(at[8], at[63]);    MULADD(at[9], at[62]);    MULADD(at[10], at[61]);    MULADD(at[11], at[60]);    MULADD(at[12], at[59]);    MULADD(at[13], at[58]);    MULADD(at[14], at[57]);    MULADD(at[15], at[56]);    MULADD(at[16], at[55]);    MULADD(at[17], at[54]);    MULADD(at[18], at[53]);    MULADD(at[19], at[52]);    MULADD(at[20], at[51]);    MULADD(at[21], at[50]);    MULADD(at[22], at[49]);    MULADD(at[23], at[48]); 
   COMBA_STORE(C->dp[23]);
   /* 24 */
   COMBA_FORWARD;
   MULADD(at[0], at[72]);    MULADD(at[1], at[71]);    MULADD(at[2], at[70]);    MULADD(at[3], at[69]);    MULADD(at[4], at[68]);    MULADD(at[5], at[67]);    MULADD(at[6], at[66]);    MULADD(at[7], at[65]);    MULADD(at[8], at[64]);    MULADD(at[9], at[63]);    MULADD(at[10], at[62]);    MULADD(at[11], at[61]);    MULADD(at[12], at[60]);    MULADD(at[13], at[59]);    MULADD(at[14], at[58]);    MULADD(at[15], at[57]);    MULADD(at[16], at[56]);    MULADD(at[17], at[55]);    MULADD(at[18], at[54]);    MULADD(at[19], at[53]);    MULADD(at[20], at[52]);    MULADD(at[21], at[51]);    MULADD(at[22], at[50]);    MULADD(at[23], at[49]);    MULADD(at[24], at[48]); 
   COMBA_STORE(C->dp[24]);
   /* 25 */
   COMBA_FORWARD;
   MULADD(at[0], at[73]);    MULADD(at[1], at[72]);    MULADD(at[2], at[71]);    MULADD(at[3], at[70]);    MULADD(at[4], at[69]);    MULADD(at[5], at[68]);    MULADD(at[6], at[67]);    MULADD(at[7], at[66]);    MULADD(at[8], at[65]);    MULADD(at[9], at[64]);    MULADD(at[10], at[63]);    MULADD(at[11], at[62]);    MULADD(at[12], at[61]);    MULADD(at[13], at[60]);    MULADD(at[14], at[59]);    MULADD(at[15], at[58]);    MULADD(at[16], at[57]);    MULADD(at[17], at[56]);    MULADD(at[18], at[55]);    MULADD(at[19], at[54]);    MULADD(at[20], at[53]);    MULADD(at[21], at[52]);    MULADD(at[22], at[51]);    MULADD(at[23], at[50]);    MULADD(at[24], at[49]);    MULADD(at[25], at[48]); 
   COMBA_STORE(C->dp[25]);
   /* 26 */
   COMBA_FORWARD;
   MULADD(at[0], at[74]);    MULADD(at[1], at[73]);    MULADD(at[2], at[72]);    MULADD(at[3], at[71]);    MULADD(at[4], at[70]);    MULADD(at[5], at[69]);    MULADD(at[6], at[68]);    MULADD(at[7], at[67]);    MULADD(at[8], at[66]);    MULADD(at[9], at[65]);    MULADD(at[10], at[64]);    MULADD(at[11], at[63]);    MULADD(at[12], at[62]);    MULADD(at[13], at[61]);    MULADD(at[14], at[60]);    MULADD(at[15], at[59]);    MULADD(at[16], at[58]);    MULADD(at[17], at[57]);    MULADD(at[18], at[56]);    MULADD(at[19], at[55]);    MULADD(at[20], at[54]);    MULADD(at[21], at[53]);    MULADD(at[22], at[52]);    MULADD(at[23], at[51]);    MULADD(at[24], at[50]);    MULADD(at[25], at[49]);    MULADD(at[26], at[48]); 
   COMBA_STORE(C->dp[26]);
   /* 27 */
   COMBA_FORWARD;
   MULADD(at[0], at[75]);    MULADD(at[1], at[74]);    MULADD(at[2], at[73]);    MULADD(at[3], at[72]);    MULADD(at[4], at[71]);    MULADD(at[5], at[70]);    MULADD(at[6], at[69]);    MULADD(at[7], at[68]);    MULADD(at[8], at[67]);    MULADD(at[9], at[66]);    MULADD(at[10], at[65]);    MULADD(at[11], at[64]);    MULADD(at[12], at[63]);    MULADD(at[13], at[62]);    MULADD(at[14], at[61]);    MULADD(at[15], at[60]);    MULADD(at[16], at[59]);    MULADD(at[17], at[58]);    MULADD(at[18], at[57]);    MULADD(at[19], at[56]);    MULADD(at[20], at[55]);    MULADD(at[21], at[54]);    MULADD(at[22], at[53]);    MULADD(at[23], at[52]);    MULADD(at[24], at[51]);    MULADD(at[25], at[50]);    MULADD(at[26], at[49]);    MULADD(at[27], at[48]); 
   COMBA_STORE(C->dp[27]);
   /* 28 */
   COMBA_FORWARD;
   MULADD(at[0], at[76]);    MULADD(at[1], at[75]);    MULADD(at[2], at[74]);    MULADD(at[3], at[73]);    MULADD(at[4], at[72]);    MULADD(at[5], at[71]);    MULADD(at[6], at[70]);    MULADD(at[7], at[69]);    MULADD(at[8], at[68]);    MULADD(at[9], at[67]);    MULADD(at[10], at[66]);    MULADD(at[11], at[65]);    MULADD(at[12], at[64]);    MULADD(at[13], at[63]);    MULADD(at[14], at[62]);    MULADD(at[15], at[61]);    MULADD(at[16], at[60]);    MULADD(at[17], at[59]);    MULADD(at[18], at[58]);    MULADD(at[19], at[57]);    MULADD(at[20], at[56]);    MULADD(at[21], at[55]);    MULADD(at[22], at[54]);    MULADD(at[23], at[53]);    MULADD(at[24], at[52]);    MULADD(at[25], at[51]);    MULADD(at[26], at[50]);    MULADD(at[27], at[49]);    MULADD(at[28], at[48]); 
   COMBA_STORE(C->dp[28]);
   /* 29 */
   COMBA_FORWARD;
   MULADD(at[0], at[77]);    MULADD(at[1], at[76]);    MULADD(at[2], at[75]);    MULADD(at[3], at[74]);    MULADD(at[4], at[73]);    MULADD(at[5], at[72]);    MULADD(at[6], at[71]);    MULADD(at[7], at[70]);    MULADD(at[8], at[69]);    MULADD(at[9], at[68]);    MULADD(at[10], at[67]);    MULADD(at[11], at[66]);    MULADD(at[12], at[65]);    MULADD(at[13], at[64]);    MULADD(at[14], at[63]);    MULADD(at[15], at[62]);    MULADD(at[16], at[61]);    MULADD(at[17], at[60]);    MULADD(at[18], at[59]);    MULADD(at[19], at[58]);    MULADD(at[20], at[57]);    MULADD(at[21], at[56]);    MULADD(at[22], at[55]);    MULADD(at[23], at[54]);    MULADD(at[24], at[53]);    MULADD(at[25], at[52]);    MULADD(at[26], at[51]);    MULADD(at[27], at[50]);    MULADD(at[28], at[49]);    MULADD(at[29], at[48]); 
   COMBA_STORE(C->dp[29]);
   /* 30 */
   COMBA_FORWARD;
   MULADD(at[0], at[78]);    MULADD(at[1], at[77]);    MULADD(at[2], at[76]);    MULADD(at[3], at[75]);    MULADD(at[4], at[74]);    MULADD(at[5], at[73]);    MULADD(at[6], at[72]);    MULADD(at[7], at[71]);    MULADD(at[8], at[70]);    MULADD(at[9], at[69]);    MULADD(at[10], at[68]);    MULADD(at[11], at[67]);    MULADD(at[12], at[66]);    MULADD(at[13], at[65]);    MULADD(at[14], at[64]);    MULADD(at[15], at[63]);    MULADD(at[16], at[62]);    MULADD(at[17], at[61]);    MULADD(at[18], at[60]);    MULADD(at[19], at[59]);    MULADD(at[20], at[58]);    MULADD(at[21], at[57]);    MULADD(at[22], at[56]);    MULADD(at[23], at[55]);    MULADD(at[24], at[54]);    MULADD(at[25], at[53]);    MULADD(at[26], at[52]);    MULADD(at[27], at[51]);    MULADD(at[28], at[50]);    MULADD(at[29], at[49]);    MULADD(at[30], at[48]); 
   COMBA_STORE(C->dp[30]);
   /* 31 */
   COMBA_FORWARD;
   MULADD(at[0], at[79]);    MULADD(at[1], at[78]);    MULADD(at[2], at[77]);    MULADD(at[3], at[76]);    MULADD(at[4], at[75]);    MULADD(at[5], at[74]);    MULADD(at[6], at[73]);    MULADD(at[7], at[72]);    MULADD(at[8], at[71]);    MULADD(at[9], at[70]);    MULADD(at[10], at[69]);    MULADD(at[11], at[68]);    MULADD(at[12], at[67]);    MULADD(at[13], at[66]);    MULADD(at[14], at[65]);    MULADD(at[15], at[64]);    MULADD(at[16], at[63]);    MULADD(at[17], at[62]);    MULADD(at[18], at[61]);    MULADD(at[19], at[60]);    MULADD(at[20], at[59]);    MULADD(at[21], at[58]);    MULADD(at[22], at[57]);    MULADD(at[23], at[56]);    MULADD(at[24], at[55]);    MULADD(at[25], at[54]);    MULADD(at[26], at[53]);    MULADD(at[27], at[52]);    MULADD(at[28], at[51]);    MULADD(at[29], at[50]);    MULADD(at[30], at[49]);    MULADD(at[31], at[48]); 
   COMBA_STORE(C->dp[31]);
   /* 32 */
   COMBA_FORWARD;
   MULADD(at[0], at[80]);    MULADD(at[1], at[79]);    MULADD(at[2], at[78]);    MULADD(at[3], at[77]);    MULADD(at[4], at[76]);    MULADD(at[5], at[75]);    MULADD(at[6], at[74]);    MULADD(at[7], at[73]);    MULADD(at[8], at[72]);    MULADD(at[9], at[71]);    MULADD(at[10], at[70]);    MULADD(at[11], at[69]);    MULADD(at[12], at[68]);    MULADD(at[13], at[67]);    MULADD(at[14], at[66]);    MULADD(at[15], at[65]);    MULADD(at[16], at[64]);    MULADD(at[17], at[63]);    MULADD(at[18], at[62]);    MULADD(at[19], at[61]);    MULADD(at[20], at[60]);    MULADD(at[21], at[59]);    MULADD(at[22], at[58]);    MULADD(at[23], at[57]);    MULADD(at[24], at[56]);    MULADD(at[25], at[55]);    MULADD(at[26], at[54]);    MULADD(at[27], at[53]);    MULADD(at[28], at[52]);    MULADD(at[29], at[51]);    MULADD(at[30], at[50]);    MULADD(at[31], at[49]);    MULADD(at[32], at[48]); 
   COMBA_STORE(C->dp[32]);
   /* 33 */
   COMBA_FORWARD;
   MULADD(at[0], at[81]);    MULADD(at[1], at[80]);    MULADD(at[2], at[79]);    MULADD(at[3], at[78]);    MULADD(at[4], at[77]);    MULADD(at[5], at[76]);    MULADD(at[6], at[75]);    MULADD(at[7], at[74]);    MULADD(at[8], at[73]);    MULADD(at[9], at[72]);    MULADD(at[10], at[71]);    MULADD(at[11], at[70]);    MULADD(at[12], at[69]);    MULADD(at[13], at[68]);    MULADD(at[14], at[67]);    MULADD(at[15], at[66]);    MULADD(at[16], at[65]);    MULADD(at[17], at[64]);    MULADD(at[18], at[63]);    MULADD(at[19], at[62]);    MULADD(at[20], at[61]);    MULADD(at[21], at[60]);    MULADD(at[22], at[59]);    MULADD(at[23], at[58]);    MULADD(at[24], at[57]);    MULADD(at[25], at[56]);    MULADD(at[26], at[55]);    MULADD(at[27], at[54]);    MULADD(at[28], at[53]);    MULADD(at[29], at[52]);    MULADD(at[30], at[51]);    MULADD(at[31], at[50]);    MULADD(at[32], at[49]);    MULADD(at[33], at[48]); 
   COMBA_STORE(C->dp[33]);
   /* 34 */
   COMBA_FORWARD;
   MULADD(at[0], at[82]);    MULADD(at[1], at[81]);    MULADD(at[2], at[80]);    MULADD(at[3], at[79]);    MULADD(at[4], at[78]);    MULADD(at[5], at[77]);    MULADD(at[6], at[76]);    MULADD(at[7], at[75]);    MULADD(at[8], at[74]);    MULADD(at[9], at[73]);    MULADD(at[10], at[72]);    MULADD(at[11], at[71]);    MULADD(at[12], at[70]);    MULADD(at[13], at[69]);    MULADD(at[14], at[68]);    MULADD(at[15], at[67]);    MULADD(at[16], at[66]);    MULADD(at[17], at[65]);    MULADD(at[18], at[64]);    MULADD(at[19], at[63]);    MULADD(at[20], at[62]);    MULADD(at[21], at[61]);    MULADD(at[22], at[60]);    MULADD(at[23], at[59]);    MULADD(at[24], at[58]);    MULADD(at[25], at[57]);    MULADD(at[26], at[56]);    MULADD(at[27], at[55]);    MULADD(at[28], at[54]);    MULADD(at[29], at[53]);    MULADD(at[30], at[52]);    MULADD(at[31], at[51]);    MULADD(at[32], at[50]);    MULADD(at[33], at[49]);    MULADD(at[34], at[48]); 
   COMBA_STORE(C->dp[34]);
   /* 35 */
   COMBA_FORWARD;
   MULADD(at[0], at[83]);    MULADD(at[1], at[82]);    MULADD(at[2], at[81]);    MULADD(at[3], at[80]);    MULADD(at[4], at[79]);    MULADD(at[5], at[78]);    MULADD(at[6], at[77]);    MULADD(at[7], at[76]);    MULADD(at[8], at[75]);    MULADD(at[9], at[74]);    MULADD(at[10], at[73]);    MULADD(at[11], at[72]);    MULADD(at[12], at[71]);    MULADD(at[13], at[70]);    MULADD(at[14], at[69]);    MULADD(at[15], at[68]);    MULADD(at[16], at[67]);    MULADD(at[17], at[66]);    MULADD(at[18], at[65]);    MULADD(at[19], at[64]);    MULADD(at[20], at[63]);    MULADD(at[21], at[62]);    MULADD(at[22], at[61]);    MULADD(at[23], at[60]);    MULADD(at[24], at[59]);    MULADD(at[25], at[58]);    MULADD(at[26], at[57]);    MULADD(at[27], at[56]);    MULADD(at[28], at[55]);    MULADD(at[29], at[54]);    MULADD(at[30], at[53]);    MULADD(at[31], at[52]);    MULADD(at[32], at[51]);    MULADD(at[33], at[50]);    MULADD(at[34], at[49]);    MULADD(at[35], at[48]); 
   COMBA_STORE(C->dp[35]);
   /* 36 */
   COMBA_FORWARD;
   MULADD(at[0], at[84]);    MULADD(at[1], at[83]);    MULADD(at[2], at[82]);    MULADD(at[3], at[81]);    MULADD(at[4], at[80]);    MULADD(at[5], at[79]);    MULADD(at[6], at[78]);    MULADD(at[7], at[77]);    MULADD(at[8], at[76]);    MULADD(at[9], at[75]);    MULADD(at[10], at[74]);    MULADD(at[11], at[73]);    MULADD(at[12], at[72]);    MULADD(at[13], at[71]);    MULADD(at[14], at[70]);    MULADD(at[15], at[69]);    MULADD(at[16], at[68]);    MULADD(at[17], at[67]);    MULADD(at[18], at[66]);    MULADD(at[19], at[65]);    MULADD(at[20], at[64]);    MULADD(at[21], at[63]);    MULADD(at[22], at[62]);    MULADD(at[23], at[61]);    MULADD(at[24], at[60]);    MULADD(at[25], at[59]);    MULADD(at[26], at[58]);    MULADD(at[27], at[57]);    MULADD(at[28], at[56]);    MULADD(at[29], at[55]);    MULADD(at[30], at[54]);    MULADD(at[31], at[53]);    MULADD(at[32], at[52]);    MULADD(at[33], at[51]);    MULADD(at[34], at[50]);    MULADD(at[35], at[49]);    MULADD(at[36], at[48]); 
   COMBA_STORE(C->dp[36]);
   /* 37 */
   COMBA_FORWARD;
   MULADD(at[0], at[85]);    MULADD(at[1], at[84]);    MULADD(at[2], at[83]);    MULADD(at[3], at[82]);    MULADD(at[4], at[81]);    MULADD(at[5], at[80]);    MULADD(at[6], at[79]);    MULADD(at[7], at[78]);    MULADD(at[8], at[77]);    MULADD(at[9], at[76]);    MULADD(at[10], at[75]);    MULADD(at[11], at[74]);    MULADD(at[12], at[73]);    MULADD(at[13], at[72]);    MULADD(at[14], at[71]);    MULADD(at[15], at[70]);    MULADD(at[16], at[69]);    MULADD(at[17], at[68]);    MULADD(at[18], at[67]);    MULADD(at[19], at[66]);    MULADD(at[20], at[65]);    MULADD(at[21], at[64]);    MULADD(at[22], at[63]);    MULADD(at[23], at[62]);    MULADD(at[24], at[61]);    MULADD(at[25], at[60]);    MULADD(at[26], at[59]);    MULADD(at[27], at[58]);    MULADD(at[28], at[57]);    MULADD(at[29], at[56]);    MULADD(at[30], at[55]);    MULADD(at[31], at[54]);    MULADD(at[32], at[53]);    MULADD(at[33], at[52]);    MULADD(at[34], at[51]);    MULADD(at[35], at[50]);    MULADD(at[36], at[49]);    MULADD(at[37], at[48]); 
   COMBA_STORE(C->dp[37]);
   /* 38 */
   COMBA_FORWARD;
   MULADD(at[0], at[86]);    MULADD(at[1], at[85]);    MULADD(at[2], at[84]);    MULADD(at[3], at[83]);    MULADD(at[4], at[82]);    MULADD(at[5], at[81]);    MULADD(at[6], at[80]);    MULADD(at[7], at[79]);    MULADD(at[8], at[78]);    MULADD(at[9], at[77]);    MULADD(at[10], at[76]);    MULADD(at[11], at[75]);    MULADD(at[12], at[74]);    MULADD(at[13], at[73]);    MULADD(at[14], at[72]);    MULADD(at[15], at[71]);    MULADD(at[16], at[70]);    MULADD(at[17], at[69]);    MULADD(at[18], at[68]);    MULADD(at[19], at[67]);    MULADD(at[20], at[66]);    MULADD(at[21], at[65]);    MULADD(at[22], at[64]);    MULADD(at[23], at[63]);    MULADD(at[24], at[62]);    MULADD(at[25], at[61]);    MULADD(at[26], at[60]);    MULADD(at[27], at[59]);    MULADD(at[28], at[58]);    MULADD(at[29], at[57]);    MULADD(at[30], at[56]);    MULADD(at[31], at[55]);    MULADD(at[32], at[54]);    MULADD(at[33], at[53]);    MULADD(at[34], at[52]);    MULADD(at[35], at[51]);    MULADD(at[36], at[50]);    MULADD(at[37], at[49]);    MULADD(at[38], at[48]); 
   COMBA_STORE(C->dp[38]);
   /* 39 */
   COMBA_FORWARD;
   MULADD(at[0], at[87]);    MULADD(at[1], at[86]);    MULADD(at[2], at[85]);    MULADD(at[3], at[84]);    MULADD(at[4], at[83]);    MULADD(at[5], at[82]);    MULADD(at[6], at[81]);    MULADD(at[7], at[80]);    MULADD(at[8], at[79]);    MULADD(at[9], at[78]);    MULADD(at[10], at[77]);    MULADD(at[11], at[76]);    MULADD(at[12], at[75]);    MULADD(at[13], at[74]);    MULADD(at[14], at[73]);    MULADD(at[15], at[72]);    MULADD(at[16], at[71]);    MULADD(at[17], at[70]);    MULADD(at[18], at[69]);    MULADD(at[19], at[68]);    MULADD(at[20], at[67]);    MULADD(at[21], at[66]);    MULADD(at[22], at[65]);    MULADD(at[23], at[64]);    MULADD(at[24], at[63]);    MULADD(at[25], at[62]);    MULADD(at[26], at[61]);    MULADD(at[27], at[60]);    MULADD(at[28], at[59]);    MULADD(at[29], at[58]);    MULADD(at[30], at[57]);    MULADD(at[31], at[56]);    MULADD(at[32], at[55]);    MULADD(at[33], at[54]);    MULADD(at[34], at[53]);    MULADD(at[35], at[52]);    MULADD(at[36], at[51]);    MULADD(at[37], at[50]);    MULADD(at[38], at[49]);    MULADD(at[39], at[48]); 
   COMBA_STORE(C->dp[39]);
   /* 40 */
   COMBA_FORWARD;
   MULADD(at[0], at[88]);    MULADD(at[1], at[87]);    MULADD(at[2], at[86]);    MULADD(at[3], at[85]);    MULADD(at[4], at[84]);    MULADD(at[5], at[83]);    MULADD(at[6], at[82]);    MULADD(at[7], at[81]);    MULADD(at[8], at[80]);    MULADD(at[9], at[79]);    MULADD(at[10], at[78]);    MULADD(at[11], at[77]);    MULADD(at[12], at[76]);    MULADD(at[13], at[75]);    MULADD(at[14], at[74]);    MULADD(at[15], at[73]);    MULADD(at[16], at[72]);    MULADD(at[17], at[71]);    MULADD(at[18], at[70]);    MULADD(at[19], at[69]);    MULADD(at[20], at[68]);    MULADD(at[21], at[67]);    MULADD(at[22], at[66]);    MULADD(at[23], at[65]);    MULADD(at[24], at[64]);    MULADD(at[25], at[63]);    MULADD(at[26], at[62]);    MULADD(at[27], at[61]);    MULADD(at[28], at[60]);    MULADD(at[29], at[59]);    MULADD(at[30], at[58]);    MULADD(at[31], at[57]);    MULADD(at[32], at[56]);    MULADD(at[33], at[55]);    MULADD(at[34], at[54]);    MULADD(at[35], at[53]);    MULADD(at[36], at[52]);    MULADD(at[37], at[51]);    MULADD(at[38], at[50]);    MULADD(at[39], at[49]);    MULADD(at[40], at[48]); 
   COMBA_STORE(C->dp[40]);
   /* 41 */
   COMBA_FORWARD;
   MULADD(at[0], at[89]);    MULADD(at[1], at[88]);    MULADD(at[2], at[87]);    MULADD(at[3], at[86]);    MULADD(at[4], at[85]);    MULADD(at[5], at[84]);    MULADD(at[6], at[83]);    MULADD(at[7], at[82]);    MULADD(at[8], at[81]);    MULADD(at[9], at[80]);    MULADD(at[10], at[79]);    MULADD(at[11], at[78]);    MULADD(at[12], at[77]);    MULADD(at[13], at[76]);    MULADD(at[14], at[75]);    MULADD(at[15], at[74]);    MULADD(at[16], at[73]);    MULADD(at[17], at[72]);    MULADD(at[18], at[71]);    MULADD(at[19], at[70]);    MULADD(at[20], at[69]);    MULADD(at[21], at[68]);    MULADD(at[22], at[67]);    MULADD(at[23], at[66]);    MULADD(at[24], at[65]);    MULADD(at[25], at[64]);    MULADD(at[26], at[63]);    MULADD(at[27], at[62]);    MULADD(at[28], at[61]);    MULADD(at[29], at[60]);    MULADD(at[30], at[59]);    MULADD(at[31], at[58]);    MULADD(at[32], at[57]);    MULADD(at[33], at[56]);    MULADD(at[34], at[55]);    MULADD(at[35], at[54]);    MULADD(at[36], at[53]);    MULADD(at[37], at[52]);    MULADD(at[38], at[51]);    MULADD(at[39], at[50]);    MULADD(at[40], at[49]);    MULADD(at[41], at[48]); 
   COMBA_STORE(C->dp[41]);
   /* 42 */
   COMBA_FORWARD;
   MULADD(at[0], at[90]);    MULADD(at[1], at[89]);    MULADD(at[2], at[88]);    MULADD(at[3], at[87]);    MULADD(at[4], at[86]);    MULADD(at[5], at[85]);    MULADD(at[6], at[84]);    MULADD(at[7], at[83]);    MULADD(at[8], at[82]);    MULADD(at[9], at[81]);    MULADD(at[10], at[80]);    MULADD(at[11], at[79]);    MULADD(at[12], at[78]);    MULADD(at[13], at[77]);    MULADD(at[14], at[76]);    MULADD(at[15], at[75]);    MULADD(at[16], at[74]);    MULADD(at[17], at[73]);    MULADD(at[18], at[72]);    MULADD(at[19], at[71]);    MULADD(at[20], at[70]);    MULADD(at[21], at[69]);    MULADD(at[22], at[68]);    MULADD(at[23], at[67]);    MULADD(at[24], at[66]);    MULADD(at[25], at[65]);    MULADD(at[26], at[64]);    MULADD(at[27], at[63]);    MULADD(at[28], at[62]);    MULADD(at[29], at[61]);    MULADD(at[30], at[60]);    MULADD(at[31], at[59]);    MULADD(at[32], at[58]);    MULADD(at[33], at[57]);    MULADD(at[34], at[56]);    MULADD(at[35], at[55]);    MULADD(at[36], at[54]);    MULADD(at[37], at[53]);    MULADD(at[38], at[52]);    MULADD(at[39], at[51]);    MULADD(at[40], at[50]);    MULADD(at[41], at[49]);    MULADD(at[42], at[48]); 
   COMBA_STORE(C->dp[42]);
   /* 43 */
   COMBA_FORWARD;
   MULADD(at[0], at[91]);    MULADD(at[1], at[90]);    MULADD(at[2], at[89]);    MULADD(at[3], at[88]);    MULADD(at[4], at[87]);    MULADD(at[5], at[86]);    MULADD(at[6], at[85]);    MULADD(at[7], at[84]);    MULADD(at[8], at[83]);    MULADD(at[9], at[82]);    MULADD(at[10], at[81]);    MULADD(at[11], at[80]);    MULADD(at[12], at[79]);    MULADD(at[13], at[78]);    MULADD(at[14], at[77]);    MULADD(at[15], at[76]);    MULADD(at[16], at[75]);    MULADD(at[17], at[74]);    MULADD(at[18], at[73]);    MULADD(at[19], at[72]);    MULADD(at[20], at[71]);    MULADD(at[21], at[70]);    MULADD(at[22], at[69]);    MULADD(at[23], at[68]);    MULADD(at[24], at[67]);    MULADD(at[25], at[66]);    MULADD(at[26], at[65]);    MULADD(at[27], at[64]);    MULADD(at[28], at[63]);    MULADD(at[29], at[62]);    MULADD(at[30], at[61]);    MULADD(at[31], at[60]);    MULADD(at[32], at[59]);    MULADD(at[33], at[58]);    MULADD(at[34], at[57]);    MULADD(at[35], at[56]);    MULADD(at[36], at[55]);    MULADD(at[37], at[54]);    MULADD(at[38], at[53]);    MULADD(at[39], at[52]);    MULADD(at[40], at[51]);    MULADD(at[41], at[50]);    MULADD(at[42], at[49]);    MULADD(at[43], at[48]); 
   COMBA_STORE(C->dp[43]);
   /* 44 */
   COMBA_FORWARD;
   MULADD(at[0], at[92]);    MULADD(at[1], at[91]);    MULADD(at[2], at[90]);    MULADD(at[3], at[89]);    MULADD(at[4], at[88]);    MULADD(at[5], at[87]);    MULADD(at[6], at[86]);    MULADD(at[7], at[85]);    MULADD(at[8], at[84]);    MULADD(at[9], at[83]);    MULADD(at[10], at[82]);    MULADD(at[11], at[81]);    MULADD(at[12], at[80]);    MULADD(at[13], at[79]);    MULADD(at[14], at[78]);    MULADD(at[15], at[77]);    MULADD(at[16], at[76]);    MULADD(at[17], at[75]);    MULADD(at[18], at[74]);    MULADD(at[19], at[73]);    MULADD(at[20], at[72]);    MULADD(at[21], at[71]);    MULADD(at[22], at[70]);    MULADD(at[23], at[69]);    MULADD(at[24], at[68]);    MULADD(at[25], at[67]);    MULADD(at[26], at[66]);    MULADD(at[27], at[65]);    MULADD(at[28], at[64]);    MULADD(at[29], at[63]);    MULADD(at[30], at[62]);    MULADD(at[31], at[61]);    MULADD(at[32], at[60]);    MULADD(at[33], at[59]);    MULADD(at[34], at[58]);    MULADD(at[35], at[57]);    MULADD(at[36], at[56]);    MULADD(at[37], at[55]);    MULADD(at[38], at[54]);    MULADD(at[39], at[53]);    MULADD(at[40], at[52]);    MULADD(at[41], at[51]);    MULADD(at[42], at[50]);    MULADD(at[43], at[49]);    MULADD(at[44], at[48]); 
   COMBA_STORE(C->dp[44]);
   /* 45 */
   COMBA_FORWARD;
   MULADD(at[0], at[93]);    MULADD(at[1], at[92]);    MULADD(at[2], at[91]);    MULADD(at[3], at[90]);    MULADD(at[4], at[89]);    MULADD(at[5], at[88]);    MULADD(at[6], at[87]);    MULADD(at[7], at[86]);    MULADD(at[8], at[85]);    MULADD(at[9], at[84]);    MULADD(at[10], at[83]);    MULADD(at[11], at[82]);    MULADD(at[12], at[81]);    MULADD(at[13], at[80]);    MULADD(at[14], at[79]);    MULADD(at[15], at[78]);    MULADD(at[16], at[77]);    MULADD(at[17], at[76]);    MULADD(at[18], at[75]);    MULADD(at[19], at[74]);    MULADD(at[20], at[73]);    MULADD(at[21], at[72]);    MULADD(at[22], at[71]);    MULADD(at[23], at[70]);    MULADD(at[24], at[69]);    MULADD(at[25], at[68]);    MULADD(at[26], at[67]);    MULADD(at[27], at[66]);    MULADD(at[28], at[65]);    MULADD(at[29], at[64]);    MULADD(at[30], at[63]);    MULADD(at[31], at[62]);    MULADD(at[32], at[61]);    MULADD(at[33], at[60]);    MULADD(at[34], at[59]);    MULADD(at[35], at[58]);    MULADD(at[36], at[57]);    MULADD(at[37], at[56]);    MULADD(at[38], at[55]);    MULADD(at[39], at[54]);    MULADD(at[40], at[53]);    MULADD(at[41], at[52]);    MULADD(at[42], at[51]);    MULADD(at[43], at[50]);    MULADD(at[44], at[49]);    MULADD(at[45], at[48]); 
   COMBA_STORE(C->dp[45]);
   /* 46 */
   COMBA_FORWARD;
   MULADD(at[0], at[94]);    MULADD(at[1], at[93]);    MULADD(at[2], at[92]);    MULADD(at[3], at[91]);    MULADD(at[4], at[90]);    MULADD(at[5], at[89]);    MULADD(at[6], at[88]);    MULADD(at[7], at[87]);    MULADD(at[8], at[86]);    MULADD(at[9], at[85]);    MULADD(at[10], at[84]);    MULADD(at[11], at[83]);    MULADD(at[12], at[82]);    MULADD(at[13], at[81]);    MULADD(at[14], at[80]);    MULADD(at[15], at[79]);    MULADD(at[16], at[78]);    MULADD(at[17], at[77]);    MULADD(at[18], at[76]);    MULADD(at[19], at[75]);    MULADD(at[20], at[74]);    MULADD(at[21], at[73]);    MULADD(at[22], at[72]);    MULADD(at[23], at[71]);    MULADD(at[24], at[70]);    MULADD(at[25], at[69]);    MULADD(at[26], at[68]);    MULADD(at[27], at[67]);    MULADD(at[28], at[66]);    MULADD(at[29], at[65]);    MULADD(at[30], at[64]);    MULADD(at[31], at[63]);    MULADD(at[32], at[62]);    MULADD(at[33], at[61]);    MULADD(at[34], at[60]);    MULADD(at[35], at[59]);    MULADD(at[36], at[58]);    MULADD(at[37], at[57]);    MULADD(at[38], at[56]);    MULADD(at[39], at[55]);    MULADD(at[40], at[54]);    MULADD(at[41], at[53]);    MULADD(at[42], at[52]);    MULADD(at[43], at[51]);    MULADD(at[44], at[50]);    MULADD(at[45], at[49]);    MULADD(at[46], at[48]); 
   COMBA_STORE(C->dp[46]);
   /* 47 */
   COMBA_FORWARD;
   MULADD(at[0], at[95]);    MULADD(at[1], at[94]);    MULADD(at[2], at[93]);    MULADD(at[3], at[92]);    MULADD(at[4], at[91]);    MULADD(at[5], at[90]);    MULADD(at[6], at[89]);    MULADD(at[7], at[88]);    MULADD(at[8], at[87]);    MULADD(at[9], at[86]);    MULADD(at[10], at[85]);    MULADD(at[11], at[84]);    MULADD(at[12], at[83]);    MULADD(at[13], at[82]);    MULADD(at[14], at[81]);    MULADD(at[15], at[80]);    MULADD(at[16], at[79]);    MULADD(at[17], at[78]);    MULADD(at[18], at[77]);    MULADD(at[19], at[76]);    MULADD(at[20], at[75]);    MULADD(at[21], at[74]);    MULADD(at[22], at[73]);    MULADD(at[23], at[72]);    MULADD(at[24], at[71]);    MULADD(at[25], at[70]);    MULADD(at[26], at[69]);    MULADD(at[27], at[68]);    MULADD(at[28], at[67]);    MULADD(at[29], at[66]);    MULADD(at[30], at[65]);    MULADD(at[31], at[64]);    MULADD(at[32], at[63]);    MULADD(at[33], at[62]);    MULADD(at[34], at[61]);    MULADD(at[35], at[60]);    MULADD(at[36], at[59]);    MULADD(at[37], at[58]);    MULADD(at[38], at[57]);    MULADD(at[39], at[56]);    MULADD(at[40], at[55]);    MULADD(at[41], at[54]);    MULADD(at[42], at[53]);    MULADD(at[43], at[52]);    MULADD(at[44], at[51]);    MULADD(at[45], at[50]);    MULADD(at[46], at[49]);    MULADD(at[47], at[48]); 
   COMBA_STORE(C->dp[47]);
   /* 48 */
   COMBA_FORWARD;
   MULADD(at[1], at[95]);    MULADD(at[2], at[94]);    MULADD(at[3], at[93]);    MULADD(at[4], at[92]);    MULADD(at[5], at[91]);    MULADD(at[6], at[90]);    MULADD(at[7], at[89]);    MULADD(at[8], at[88]);    MULADD(at[9], at[87]);    MULADD(at[10], at[86]);    MULADD(at[11], at[85]);    MULADD(at[12], at[84]);    MULADD(at[13], at[83]);    MULADD(at[14], at[82]);    MULADD(at[15], at[81]);    MULADD(at[16], at[80]);    MULADD(at[17], at[79]);    MULADD(at[18], at[78]);    MULADD(at[19], at[77]);    MULADD(at[20], at[76]);    MULADD(at[21], at[75]);    MULADD(at[22], at[74]);    MULADD(at[23], at[73]);    MULADD(at[24], at[72]);    MULADD(at[25], at[71]);    MULADD(at[26], at[70]);    MULADD(at[27], at[69]);    MULADD(at[28], at[68]);    MULADD(at[29], at[67]);    MULADD(at[30], at[66]);    MULADD(at[31], at[65]);    MULADD(at[32], at[64]);    MULADD(at[33], at[63]);    MULADD(at[34], at[62]);    MULADD(at[35], at[61]);    MULADD(at[36], at[60]);    MULADD(at[37], at[59]);    MULADD(at[38], at[58]);    MULADD(at[39], at[57]);    MULADD(at[40], at[56]);    MULADD(at[41], at[55]);    MULADD(at[42], at[54]);    MULADD(at[43], at[53]);    MULADD(at[44], at[52]);    MULADD(at[45], at[51]);    MULADD(at[46], at[50]);    MULADD(at[47], at[49]); 
   COMBA_STORE(C->dp[48]);
   /* 49 */
   COMBA_FORWARD;
   MULADD(at[2], at[95]);    MULADD(at[3], at[94]);    MULADD(at[4], at[93]);    MULADD(at[5], at[92]);    MULADD(at[6], at[91]);    MULADD(at[7], at[90]);    MULADD(at[8], at[89]);    MULADD(at[9], at[88]);    MULADD(at[10], at[87]);    MULADD(at[11], at[86]);    MULADD(at[12], at[85]);    MULADD(at[13], at[84]);    MULADD(at[14], at[83]);    MULADD(at[15], at[82]);    MULADD(at[16], at[81]);    MULADD(at[17], at[80]);    MULADD(at[18], at[79]);    MULADD(at[19], at[78]);    MULADD(at[20], at[77]);    MULADD(at[21], at[76]);    MULADD(at[22], at[75]);    MULADD(at[23], at[74]);    MULADD(at[24], at[73]);    MULADD(at[25], at[72]);    MULADD(at[26], at[71]);    MULADD(at[27], at[70]);    MULADD(at[28], at[69]);    MULADD(at[29], at[68]);    MULADD(at[30], at[67]);    MULADD(at[31], at[66]);    MULADD(at[32], at[65]);    MULADD(at[33], at[64]);    MULADD(at[34], at[63]);    MULADD(at[35], at[62]);    MULADD(at[36], at[61]);    MULADD(at[37], at[60]);    MULADD(at[38], at[59]);    MULADD(at[39], at[58]);    MULADD(at[40], at[57]);    MULADD(at[41], at[56]);    MULADD(at[42], at[55]);    MULADD(at[43], at[54]);    MULADD(at[44], at[53]);    MULADD(at[45], at[52]);    MULADD(at[46], at[51]);    MULADD(at[47], at[50]); 
   COMBA_STORE(C->dp[49]);
   /* 50 */
   COMBA_FORWARD;
   MULADD(at[3], at[95]);    MULADD(at[4], at[94]);    MULADD(at[5], at[93]);    MULADD(at[6], at[92]);    MULADD(at[7], at[91]);    MULADD(at[8], at[90]);    MULADD(at[9], at[89]);    MULADD(at[10], at[88]);    MULADD(at[11], at[87]);    MULADD(at[12], at[86]);    MULADD(at[13], at[85]);    MULADD(at[14], at[84]);    MULADD(at[15], at[83]);    MULADD(at[16], at[82]);    MULADD(at[17], at[81]);    MULADD(at[18], at[80]);    MULADD(at[19], at[79]);    MULADD(at[20], at[78]);    MULADD(at[21], at[77]);    MULADD(at[22], at[76]);    MULADD(at[23], at[75]);    MULADD(at[24], at[74]);    MULADD(at[25], at[73]);    MULADD(at[26], at[72]);    MULADD(at[27], at[71]);    MULADD(at[28], at[70]);    MULADD(at[29], at[69]);    MULADD(at[30], at[68]);    MULADD(at[31], at[67]);    MULADD(at[32], at[66]);    MULADD(at[33], at[65]);    MULADD(at[34], at[64]);    MULADD(at[35], at[63]);    MULADD(at[36], at[62]);    MULADD(at[37], at[61]);    MULADD(at[38], at[60]);    MULADD(at[39], at[59]);    MULADD(at[40], at[58]);    MULADD(at[41], at[57]);    MULADD(at[42], at[56]);    MULADD(at[43], at[55]);    MULADD(at[44], at[54]);    MULADD(at[45], at[53]);    MULADD(at[46], at[52]);    MULADD(at[47], at[51]); 
   COMBA_STORE(C->dp[50]);
   /* 51 */
   COMBA_FORWARD;
   MULADD(at[4], at[95]);    MULADD(at[5], at[94]);    MULADD(at[6], at[93]);    MULADD(at[7], at[92]);    MULADD(at[8], at[91]);    MULADD(at[9], at[90]);    MULADD(at[10], at[89]);    MULADD(at[11], at[88]);    MULADD(at[12], at[87]);    MULADD(at[13], at[86]);    MULADD(at[14], at[85]);    MULADD(at[15], at[84]);    MULADD(at[16], at[83]);    MULADD(at[17], at[82]);    MULADD(at[18], at[81]);    MULADD(at[19], at[80]);    MULADD(at[20], at[79]);    MULADD(at[21], at[78]);    MULADD(at[22], at[77]);    MULADD(at[23], at[76]);    MULADD(at[24], at[75]);    MULADD(at[25], at[74]);    MULADD(at[26], at[73]);    MULADD(at[27], at[72]);    MULADD(at[28], at[71]);    MULADD(at[29], at[70]);    MULADD(at[30], at[69]);    MULADD(at[31], at[68]);    MULADD(at[32], at[67]);    MULADD(at[33], at[66]);    MULADD(at[34], at[65]);    MULADD(at[35], at[64]);    MULADD(at[36], at[63]);    MULADD(at[37], at[62]);    MULADD(at[38], at[61]);    MULADD(at[39], at[60]);    MULADD(at[40], at[59]);    MULADD(at[41], at[58]);    MULADD(at[42], at[57]);    MULADD(at[43], at[56]);    MULADD(at[44], at[55]);    MULADD(at[45], at[54]);    MULADD(at[46], at[53]);    MULADD(at[47], at[52]); 
   COMBA_STORE(C->dp[51]);
   /* 52 */
   COMBA_FORWARD;
   MULADD(at[5], at[95]);    MULADD(at[6], at[94]);    MULADD(at[7], at[93]);    MULADD(at[8], at[92]);    MULADD(at[9], at[91]);    MULADD(at[10], at[90]);    MULADD(at[11], at[89]);    MULADD(at[12], at[88]);    MULADD(at[13], at[87]);    MULADD(at[14], at[86]);    MULADD(at[15], at[85]);    MULADD(at[16], at[84]);    MULADD(at[17], at[83]);    MULADD(at[18], at[82]);    MULADD(at[19], at[81]);    MULADD(at[20], at[80]);    MULADD(at[21], at[79]);    MULADD(at[22], at[78]);    MULADD(at[23], at[77]);    MULADD(at[24], at[76]);    MULADD(at[25], at[75]);    MULADD(at[26], at[74]);    MULADD(at[27], at[73]);    MULADD(at[28], at[72]);    MULADD(at[29], at[71]);    MULADD(at[30], at[70]);    MULADD(at[31], at[69]);    MULADD(at[32], at[68]);    MULADD(at[33], at[67]);    MULADD(at[34], at[66]);    MULADD(at[35], at[65]);    MULADD(at[36], at[64]);    MULADD(at[37], at[63]);    MULADD(at[38], at[62]);    MULADD(at[39], at[61]);    MULADD(at[40], at[60]);    MULADD(at[41], at[59]);    MULADD(at[42], at[58]);    MULADD(at[43], at[57]);    MULADD(at[44], at[56]);    MULADD(at[45], at[55]);    MULADD(at[46], at[54]);    MULADD(at[47], at[53]); 
   COMBA_STORE(C->dp[52]);
   /* 53 */
   COMBA_FORWARD;
   MULADD(at[6], at[95]);    MULADD(at[7], at[94]);    MULADD(at[8], at[93]);    MULADD(at[9], at[92]);    MULADD(at[10], at[91]);    MULADD(at[11], at[90]);    MULADD(at[12], at[89]);    MULADD(at[13], at[88]);    MULADD(at[14], at[87]);    MULADD(at[15], at[86]);    MULADD(at[16], at[85]);    MULADD(at[17], at[84]);    MULADD(at[18], at[83]);    MULADD(at[19], at[82]);    MULADD(at[20], at[81]);    MULADD(at[21], at[80]);    MULADD(at[22], at[79]);    MULADD(at[23], at[78]);    MULADD(at[24], at[77]);    MULADD(at[25], at[76]);    MULADD(at[26], at[75]);    MULADD(at[27], at[74]);    MULADD(at[28], at[73]);    MULADD(at[29], at[72]);    MULADD(at[30], at[71]);    MULADD(at[31], at[70]);    MULADD(at[32], at[69]);    MULADD(at[33], at[68]);    MULADD(at[34], at[67]);    MULADD(at[35], at[66]);    MULADD(at[36], at[65]);    MULADD(at[37], at[64]);    MULADD(at[38], at[63]);    MULADD(at[39], at[62]);    MULADD(at[40], at[61]);    MULADD(at[41], at[60]);    MULADD(at[42], at[59]);    MULADD(at[43], at[58]);    MULADD(at[44], at[57]);    MULADD(at[45], at[56]);    MULADD(at[46], at[55]);    MULADD(at[47], at[54]); 
   COMBA_STORE(C->dp[53]);
   /* 54 */
   COMBA_FORWARD;
   MULADD(at[7], at[95]);    MULADD(at[8], at[94]);    MULADD(at[9], at[93]);    MULADD(at[10], at[92]);    MULADD(at[11], at[91]);    MULADD(at[12], at[90]);    MULADD(at[13], at[89]);    MULADD(at[14], at[88]);    MULADD(at[15], at[87]);    MULADD(at[16], at[86]);    MULADD(at[17], at[85]);    MULADD(at[18], at[84]);    MULADD(at[19], at[83]);    MULADD(at[20], at[82]);    MULADD(at[21], at[81]);    MULADD(at[22], at[80]);    MULADD(at[23], at[79]);    MULADD(at[24], at[78]);    MULADD(at[25], at[77]);    MULADD(at[26], at[76]);    MULADD(at[27], at[75]);    MULADD(at[28], at[74]);    MULADD(at[29], at[73]);    MULADD(at[30], at[72]);    MULADD(at[31], at[71]);    MULADD(at[32], at[70]);    MULADD(at[33], at[69]);    MULADD(at[34], at[68]);    MULADD(at[35], at[67]);    MULADD(at[36], at[66]);    MULADD(at[37], at[65]);    MULADD(at[38], at[64]);    MULADD(at[39], at[63]);    MULADD(at[40], at[62]);    MULADD(at[41], at[61]);    MULADD(at[42], at[60]);    MULADD(at[43], at[59]);    MULADD(at[44], at[58]);    MULADD(at[45], at[57]);    MULADD(at[46], at[56]);    MULADD(at[47], at[55]); 
   COMBA_STORE(C->dp[54]);
   /* 55 */
   COMBA_FORWARD;
   MULADD(at[8], at[95]);    MULADD(at[9], at[94]);    MULADD(at[10], at[93]);    MULADD(at[11], at[92]);    MULADD(at[12], at[91]);    MULADD(at[13], at[90]);    MULADD(at[14], at[89]);    MULADD(at[15], at[88]);    MULADD(at[16], at[87]);    MULADD(at[17], at[86]);    MULADD(at[18], at[85]);    MULADD(at[19], at[84]);    MULADD(at[20], at[83]);    MULADD(at[21], at[82]);    MULADD(at[22], at[81]);    MULADD(at[23], at[80]);    MULADD(at[24], at[79]);    MULADD(at[25], at[78]);    MULADD(at[26], at[77]);    MULADD(at[27], at[76]);    MULADD(at[28], at[75]);    MULADD(at[29], at[74]);    MULADD(at[30], at[73]);    MULADD(at[31], at[72]);    MULADD(at[32], at[71]);    MULADD(at[33], at[70]);    MULADD(at[34], at[69]);    MULADD(at[35], at[68]);    MULADD(at[36], at[67]);    MULADD(at[37], at[66]);    MULADD(at[38], at[65]);    MULADD(at[39], at[64]);    MULADD(at[40], at[63]);    MULADD(at[41], at[62]);    MULADD(at[42], at[61]);    MULADD(at[43], at[60]);    MULADD(at[44], at[59]);    MULADD(at[45], at[58]);    MULADD(at[46], at[57]);    MULADD(at[47], at[56]); 
   COMBA_STORE(C->dp[55]);
   /* 56 */
   COMBA_FORWARD;
   MULADD(at[9], at[95]);    MULADD(at[10], at[94]);    MULADD(at[11], at[93]);    MULADD(at[12], at[92]);    MULADD(at[13], at[91]);    MULADD(at[14], at[90]);    MULADD(at[15], at[89]);    MULADD(at[16], at[88]);    MULADD(at[17], at[87]);    MULADD(at[18], at[86]);    MULADD(at[19], at[85]);    MULADD(at[20], at[84]);    MULADD(at[21], at[83]);    MULADD(at[22], at[82]);    MULADD(at[23], at[81]);    MULADD(at[24], at[80]);    MULADD(at[25], at[79]);    MULADD(at[26], at[78]);    MULADD(at[27], at[77]);    MULADD(at[28], at[76]);    MULADD(at[29], at[75]);    MULADD(at[30], at[74]);    MULADD(at[31], at[73]);    MULADD(at[32], at[72]);    MULADD(at[33], at[71]);    MULADD(at[34], at[70]);    MULADD(at[35], at[69]);    MULADD(at[36], at[68]);    MULADD(at[37], at[67]);    MULADD(at[38], at[66]);    MULADD(at[39], at[65]);    MULADD(at[40], at[64]);    MULADD(at[41], at[63]);    MULADD(at[42], at[62]);    MULADD(at[43], at[61]);    MULADD(at[44], at[60]);    MULADD(at[45], at[59]);    MULADD(at[46], at[58]);    MULADD(at[47], at[57]); 
   COMBA_STORE(C->dp[56]);
   /* 57 */
   COMBA_FORWARD;
   MULADD(at[10], at[95]);    MULADD(at[11], at[94]);    MULADD(at[12], at[93]);    MULADD(at[13], at[92]);    MULADD(at[14], at[91]);    MULADD(at[15], at[90]);    MULADD(at[16], at[89]);    MULADD(at[17], at[88]);    MULADD(at[18], at[87]);    MULADD(at[19], at[86]);    MULADD(at[20], at[85]);    MULADD(at[21], at[84]);    MULADD(at[22], at[83]);    MULADD(at[23], at[82]);    MULADD(at[24], at[81]);    MULADD(at[25], at[80]);    MULADD(at[26], at[79]);    MULADD(at[27], at[78]);    MULADD(at[28], at[77]);    MULADD(at[29], at[76]);    MULADD(at[30], at[75]);    MULADD(at[31], at[74]);    MULADD(at[32], at[73]);    MULADD(at[33], at[72]);    MULADD(at[34], at[71]);    MULADD(at[35], at[70]);    MULADD(at[36], at[69]);    MULADD(at[37], at[68]);    MULADD(at[38], at[67]);    MULADD(at[39], at[66]);    MULADD(at[40], at[65]);    MULADD(at[41], at[64]);    MULADD(at[42], at[63]);    MULADD(at[43], at[62]);    MULADD(at[44], at[61]);    MULADD(at[45], at[60]);    MULADD(at[46], at[59]);    MULADD(at[47], at[58]); 
   COMBA_STORE(C->dp[57]);
   /* 58 */
   COMBA_FORWARD;
   MULADD(at[11], at[95]);    MULADD(at[12], at[94]);    MULADD(at[13], at[93]);    MULADD(at[14], at[92]);    MULADD(at[15], at[91]);    MULADD(at[16], at[90]);    MULADD(at[17], at[89]);    MULADD(at[18], at[88]);    MULADD(at[19], at[87]);    MULADD(at[20], at[86]);    MULADD(at[21], at[85]);    MULADD(at[22], at[84]);    MULADD(at[23], at[83]);    MULADD(at[24], at[82]);    MULADD(at[25], at[81]);    MULADD(at[26], at[80]);    MULADD(at[27], at[79]);    MULADD(at[28], at[78]);    MULADD(at[29], at[77]);    MULADD(at[30], at[76]);    MULADD(at[31], at[75]);    MULADD(at[32], at[74]);    MULADD(at[33], at[73]);    MULADD(at[34], at[72]);    MULADD(at[35], at[71]);    MULADD(at[36], at[70]);    MULADD(at[37], at[69]);    MULADD(at[38], at[68]);    MULADD(at[39], at[67]);    MULADD(at[40], at[66]);    MULADD(at[41], at[65]);    MULADD(at[42], at[64]);    MULADD(at[43], at[63]);    MULADD(at[44], at[62]);    MULADD(at[45], at[61]);    MULADD(at[46], at[60]);    MULADD(at[47], at[59]); 
   COMBA_STORE(C->dp[58]);
   /* 59 */
   COMBA_FORWARD;
   MULADD(at[12], at[95]);    MULADD(at[13], at[94]);    MULADD(at[14], at[93]);    MULADD(at[15], at[92]);    MULADD(at[16], at[91]);    MULADD(at[17], at[90]);    MULADD(at[18], at[89]);    MULADD(at[19], at[88]);    MULADD(at[20], at[87]);    MULADD(at[21], at[86]);    MULADD(at[22], at[85]);    MULADD(at[23], at[84]);    MULADD(at[24], at[83]);    MULADD(at[25], at[82]);    MULADD(at[26], at[81]);    MULADD(at[27], at[80]);    MULADD(at[28], at[79]);    MULADD(at[29], at[78]);    MULADD(at[30], at[77]);    MULADD(at[31], at[76]);    MULADD(at[32], at[75]);    MULADD(at[33], at[74]);    MULADD(at[34], at[73]);    MULADD(at[35], at[72]);    MULADD(at[36], at[71]);    MULADD(at[37], at[70]);    MULADD(at[38], at[69]);    MULADD(at[39], at[68]);    MULADD(at[40], at[67]);    MULADD(at[41], at[66]);    MULADD(at[42], at[65]);    MULADD(at[43], at[64]);    MULADD(at[44], at[63]);    MULADD(at[45], at[62]);    MULADD(at[46], at[61]);    MULADD(at[47], at[60]); 
   COMBA_STORE(C->dp[59]);
   /* 60 */
   COMBA_FORWARD;
   MULADD(at[13], at[95]);    MULADD(at[14], at[94]);    MULADD(at[15], at[93]);    MULADD(at[16], at[92]);    MULADD(at[17], at[91]);    MULADD(at[18], at[90]);    MULADD(at[19], at[89]);    MULADD(at[20], at[88]);    MULADD(at[21], at[87]);    MULADD(at[22], at[86]);    MULADD(at[23], at[85]);    MULADD(at[24], at[84]);    MULADD(at[25], at[83]);    MULADD(at[26], at[82]);    MULADD(at[27], at[81]);    MULADD(at[28], at[80]);    MULADD(at[29], at[79]);    MULADD(at[30], at[78]);    MULADD(at[31], at[77]);    MULADD(at[32], at[76]);    MULADD(at[33], at[75]);    MULADD(at[34], at[74]);    MULADD(at[35], at[73]);    MULADD(at[36], at[72]);    MULADD(at[37], at[71]);    MULADD(at[38], at[70]);    MULADD(at[39], at[69]);    MULADD(at[40], at[68]);    MULADD(at[41], at[67]);    MULADD(at[42], at[66]);    MULADD(at[43], at[65]);    MULADD(at[44], at[64]);    MULADD(at[45], at[63]);    MULADD(at[46], at[62]);    MULADD(at[47], at[61]); 
   COMBA_STORE(C->dp[60]);
   /* 61 */
   COMBA_FORWARD;
   MULADD(at[14], at[95]);    MULADD(at[15], at[94]);    MULADD(at[16], at[93]);    MULADD(at[17], at[92]);    MULADD(at[18], at[91]);    MULADD(at[19], at[90]);    MULADD(at[20], at[89]);    MULADD(at[21], at[88]);    MULADD(at[22], at[87]);    MULADD(at[23], at[86]);    MULADD(at[24], at[85]);    MULADD(at[25], at[84]);    MULADD(at[26], at[83]);    MULADD(at[27], at[82]);    MULADD(at[28], at[81]);    MULADD(at[29], at[80]);    MULADD(at[30], at[79]);    MULADD(at[31], at[78]);    MULADD(at[32], at[77]);    MULADD(at[33], at[76]);    MULADD(at[34], at[75]);    MULADD(at[35], at[74]);    MULADD(at[36], at[73]);    MULADD(at[37], at[72]);    MULADD(at[38], at[71]);    MULADD(at[39], at[70]);    MULADD(at[40], at[69]);    MULADD(at[41], at[68]);    MULADD(at[42], at[67]);    MULADD(at[43], at[66]);    MULADD(at[44], at[65]);    MULADD(at[45], at[64]);    MULADD(at[46], at[63]);    MULADD(at[47], at[62]); 
   COMBA_STORE(C->dp[61]);
   /* 62 */
   COMBA_FORWARD;
   MULADD(at[15], at[95]);    MULADD(at[16], at[94]);    MULADD(at[17], at[93]);    MULADD(at[18], at[92]);    MULADD(at[19], at[91]);    MULADD(at[20], at[90]);    MULADD(at[21], at[89]);    MULADD(at[22], at[88]);    MULADD(at[23], at[87]);    MULADD(at[24], at[86]);    MULADD(at[25], at[85]);    MULADD(at[26], at[84]);    MULADD(at[27], at[83]);    MULADD(at[28], at[82]);    MULADD(at[29], at[81]);    MULADD(at[30], at[80]);    MULADD(at[31], at[79]);    MULADD(at[32], at[78]);    MULADD(at[33], at[77]);    MULADD(at[34], at[76]);    MULADD(at[35], at[75]);    MULADD(at[36], at[74]);    MULADD(at[37], at[73]);    MULADD(at[38], at[72]);    MULADD(at[39], at[71]);    MULADD(at[40], at[70]);    MULADD(at[41], at[69]);    MULADD(at[42], at[68]);    MULADD(at[43], at[67]);    MULADD(at[44], at[66]);    MULADD(at[45], at[65]);    MULADD(at[46], at[64]);    MULADD(at[47], at[63]); 
   COMBA_STORE(C->dp[62]);
   /* 63 */
   COMBA_FORWARD;
   MULADD(at[16], at[95]);    MULADD(at[17], at[94]);    MULADD(at[18], at[93]);    MULADD(at[19], at[92]);    MULADD(at[20], at[91]);    MULADD(at[21], at[90]);    MULADD(at[22], at[89]);    MULADD(at[23], at[88]);    MULADD(at[24], at[87]);    MULADD(at[25], at[86]);    MULADD(at[26], at[85]);    MULADD(at[27], at[84]);    MULADD(at[28], at[83]);    MULADD(at[29], at[82]);    MULADD(at[30], at[81]);    MULADD(at[31], at[80]);    MULADD(at[32], at[79]);    MULADD(at[33], at[78]);    MULADD(at[34], at[77]);    MULADD(at[35], at[76]);    MULADD(at[36], at[75]);    MULADD(at[37], at[74]);    MULADD(at[38], at[73]);    MULADD(at[39], at[72]);    MULADD(at[40], at[71]);    MULADD(at[41], at[70]);    MULADD(at[42], at[69]);    MULADD(at[43], at[68]);    MULADD(at[44], at[67]);    MULADD(at[45], at[66]);    MULADD(at[46], at[65]);    MULADD(at[47], at[64]); 
   COMBA_STORE(C->dp[63]);
   /* 64 */
   COMBA_FORWARD;
   MULADD(at[17], at[95]);    MULADD(at[18], at[94]);    MULADD(at[19], at[93]);    MULADD(at[20], at[92]);    MULADD(at[21], at[91]);    MULADD(at[22], at[90]);    MULADD(at[23], at[89]);    MULADD(at[24], at[88]);    MULADD(at[25], at[87]);    MULADD(at[26], at[86]);    MULADD(at[27], at[85]);    MULADD(at[28], at[84]);    MULADD(at[29], at[83]);    MULADD(at[30], at[82]);    MULADD(at[31], at[81]);    MULADD(at[32], at[80]);    MULADD(at[33], at[79]);    MULADD(at[34], at[78]);    MULADD(at[35], at[77]);    MULADD(at[36], at[76]);    MULADD(at[37], at[75]);    MULADD(at[38], at[74]);    MULADD(at[39], at[73]);    MULADD(at[40], at[72]);    MULADD(at[41], at[71]);    MULADD(at[42], at[70]);    MULADD(at[43], at[69]);    MULADD(at[44], at[68]);    MULADD(at[45], at[67]);    MULADD(at[46], at[66]);    MULADD(at[47], at[65]); 
   COMBA_STORE(C->dp[64]);
   /* 65 */
   COMBA_FORWARD;
   MULADD(at[18], at[95]);    MULADD(at[19], at[94]);    MULADD(at[20], at[93]);    MULADD(at[21], at[92]);    MULADD(at[22], at[91]);    MULADD(at[23], at[90]);    MULADD(at[24], at[89]);    MULADD(at[25], at[88]);    MULADD(at[26], at[87]);    MULADD(at[27], at[86]);    MULADD(at[28], at[85]);    MULADD(at[29], at[84]);    MULADD(at[30], at[83]);    MULADD(at[31], at[82]);    MULADD(at[32], at[81]);    MULADD(at[33], at[80]);    MULADD(at[34], at[79]);    MULADD(at[35], at[78]);    MULADD(at[36], at[77]);    MULADD(at[37], at[76]);    MULADD(at[38], at[75]);    MULADD(at[39], at[74]);    MULADD(at[40], at[73]);    MULADD(at[41], at[72]);    MULADD(at[42], at[71]);    MULADD(at[43], at[70]);    MULADD(at[44], at[69]);    MULADD(at[45], at[68]);    MULADD(at[46], at[67]);    MULADD(at[47], at[66]); 
   COMBA_STORE(C->dp[65]);
   /* 66 */
   COMBA_FORWARD;
   MULADD(at[19], at[95]);    MULADD(at[20], at[94]);    MULADD(at[21], at[93]);    MULADD(at[22], at[92]);    MULADD(at[23], at[91]);    MULADD(at[24], at[90]);    MULADD(at[25], at[89]);    MULADD(at[26], at[88]);    MULADD(at[27], at[87]);    MULADD(at[28], at[86]);    MULADD(at[29], at[85]);    MULADD(at[30], at[84]);    MULADD(at[31], at[83]);    MULADD(at[32], at[82]);    MULADD(at[33], at[81]);    MULADD(at[34], at[80]);    MULADD(at[35], at[79]);    MULADD(at[36], at[78]);    MULADD(at[37], at[77]);    MULADD(at[38], at[76]);    MULADD(at[39], at[75]);    MULADD(at[40], at[74]);    MULADD(at[41], at[73]);    MULADD(at[42], at[72]);    MULADD(at[43], at[71]);    MULADD(at[44], at[70]);    MULADD(at[45], at[69]);    MULADD(at[46], at[68]);    MULADD(at[47], at[67]); 
   COMBA_STORE(C->dp[66]);
   /* 67 */
   COMBA_FORWARD;
   MULADD(at[20], at[95]);    MULADD(at[21], at[94]);    MULADD(at[22], at[93]);    MULADD(at[23], at[92]);    MULADD(at[24], at[91]);    MULADD(at[25], at[90]);    MULADD(at[26], at[89]);    MULADD(at[27], at[88]);    MULADD(at[28], at[87]);    MULADD(at[29], at[86]);    MULADD(at[30], at[85]);    MULADD(at[31], at[84]);    MULADD(at[32], at[83]);    MULADD(at[33], at[82]);    MULADD(at[34], at[81]);    MULADD(at[35], at[80]);    MULADD(at[36], at[79]);    MULADD(at[37], at[78]);    MULADD(at[38], at[77]);    MULADD(at[39], at[76]);    MULADD(at[40], at[75]);    MULADD(at[41], at[74]);    MULADD(at[42], at[73]);    MULADD(at[43], at[72]);    MULADD(at[44], at[71]);    MULADD(at[45], at[70]);    MULADD(at[46], at[69]);    MULADD(at[47], at[68]); 
   COMBA_STORE(C->dp[67]);
   /* 68 */
   COMBA_FORWARD;
   MULADD(at[21], at[95]);    MULADD(at[22], at[94]);    MULADD(at[23], at[93]);    MULADD(at[24], at[92]);    MULADD(at[25], at[91]);    MULADD(at[26], at[90]);    MULADD(at[27], at[89]);    MULADD(at[28], at[88]);    MULADD(at[29], at[87]);    MULADD(at[30], at[86]);    MULADD(at[31], at[85]);    MULADD(at[32], at[84]);    MULADD(at[33], at[83]);    MULADD(at[34], at[82]);    MULADD(at[35], at[81]);    MULADD(at[36], at[80]);    MULADD(at[37], at[79]);    MULADD(at[38], at[78]);    MULADD(at[39], at[77]);    MULADD(at[40], at[76]);    MULADD(at[41], at[75]);    MULADD(at[42], at[74]);    MULADD(at[43], at[73]);    MULADD(at[44], at[72]);    MULADD(at[45], at[71]);    MULADD(at[46], at[70]);    MULADD(at[47], at[69]); 
   COMBA_STORE(C->dp[68]);
   /* 69 */
   COMBA_FORWARD;
   MULADD(at[22], at[95]);    MULADD(at[23], at[94]);    MULADD(at[24], at[93]);    MULADD(at[25], at[92]);    MULADD(at[26], at[91]);    MULADD(at[27], at[90]);    MULADD(at[28], at[89]);    MULADD(at[29], at[88]);    MULADD(at[30], at[87]);    MULADD(at[31], at[86]);    MULADD(at[32], at[85]);    MULADD(at[33], at[84]);    MULADD(at[34], at[83]);    MULADD(at[35], at[82]);    MULADD(at[36], at[81]);    MULADD(at[37], at[80]);    MULADD(at[38], at[79]);    MULADD(at[39], at[78]);    MULADD(at[40], at[77]);    MULADD(at[41], at[76]);    MULADD(at[42], at[75]);    MULADD(at[43], at[74]);    MULADD(at[44], at[73]);    MULADD(at[45], at[72]);    MULADD(at[46], at[71]);    MULADD(at[47], at[70]); 
   COMBA_STORE(C->dp[69]);
   /* 70 */
   COMBA_FORWARD;
   MULADD(at[23], at[95]);    MULADD(at[24], at[94]);    MULADD(at[25], at[93]);    MULADD(at[26], at[92]);    MULADD(at[27], at[91]);    MULADD(at[28], at[90]);    MULADD(at[29], at[89]);    MULADD(at[30], at[88]);    MULADD(at[31], at[87]);    MULADD(at[32], at[86]);    MULADD(at[33], at[85]);    MULADD(at[34], at[84]);    MULADD(at[35], at[83]);    MULADD(at[36], at[82]);    MULADD(at[37], at[81]);    MULADD(at[38], at[80]);    MULADD(at[39], at[79]);    MULADD(at[40], at[78]);    MULADD(at[41], at[77]);    MULADD(at[42], at[76]);    MULADD(at[43], at[75]);    MULADD(at[44], at[74]);    MULADD(at[45], at[73]);    MULADD(at[46], at[72]);    MULADD(at[47], at[71]); 
   COMBA_STORE(C->dp[70]);
   /* 71 */
   COMBA_FORWARD;
   MULADD(at[24], at[95]);    MULADD(at[25], at[94]);    MULADD(at[26], at[93]);    MULADD(at[27], at[92]);    MULADD(at[28], at[91]);    MULADD(at[29], at[90]);    MULADD(at[30], at[89]);    MULADD(at[31], at[88]);    MULADD(at[32], at[87]);    MULADD(at[33], at[86]);    MULADD(at[34], at[85]);    MULADD(at[35], at[84]);    MULADD(at[36], at[83]);    MULADD(at[37], at[82]);    MULADD(at[38], at[81]);    MULADD(at[39], at[80]);    MULADD(at[40], at[79]);    MULADD(at[41], at[78]);    MULADD(at[42], at[77]);    MULADD(at[43], at[76]);    MULADD(at[44], at[75]);    MULADD(at[45], at[74]);    MULADD(at[46], at[73]);    MULADD(at[47], at[72]); 
   COMBA_STORE(C->dp[71]);
   /* 72 */
   COMBA_FORWARD;
   MULADD(at[25], at[95]);    MULADD(at[26], at[94]);    MULADD(at[27], at[93]);    MULADD(at[28], at[92]);    MULADD(at[29], at[91]);    MULADD(at[30], at[90]);    MULADD(at[31], at[89]);    MULADD(at[32], at[88]);    MULADD(at[33], at[87]);    MULADD(at[34], at[86]);    MULADD(at[35], at[85]);    MULADD(at[36], at[84]);    MULADD(at[37], at[83]);    MULADD(at[38], at[82]);    MULADD(at[39], at[81]);    MULADD(at[40], at[80]);    MULADD(at[41], at[79]);    MULADD(at[42], at[78]);    MULADD(at[43], at[77]);    MULADD(at[44], at[76]);    MULADD(at[45], at[75]);    MULADD(at[46], at[74]);    MULADD(at[47], at[73]); 
   COMBA_STORE(C->dp[72]);
   /* 73 */
   COMBA_FORWARD;
   MULADD(at[26], at[95]);    MULADD(at[27], at[94]);    MULADD(at[28], at[93]);    MULADD(at[29], at[92]);    MULADD(at[30], at[91]);    MULADD(at[31], at[90]);    MULADD(at[32], at[89]);    MULADD(at[33], at[88]);    MULADD(at[34], at[87]);    MULADD(at[35], at[86]);    MULADD(at[36], at[85]);    MULADD(at[37], at[84]);    MULADD(at[38], at[83]);    MULADD(at[39], at[82]);    MULADD(at[40], at[81]);    MULADD(at[41], at[80]);    MULADD(at[42], at[79]);    MULADD(at[43], at[78]);    MULADD(at[44], at[77]);    MULADD(at[45], at[76]);    MULADD(at[46], at[75]);    MULADD(at[47], at[74]); 
   COMBA_STORE(C->dp[73]);
   /* 74 */
   COMBA_FORWARD;
   MULADD(at[27], at[95]);    MULADD(at[28], at[94]);    MULADD(at[29], at[93]);    MULADD(at[30], at[92]);    MULADD(at[31], at[91]);    MULADD(at[32], at[90]);    MULADD(at[33], at[89]);    MULADD(at[34], at[88]);    MULADD(at[35], at[87]);    MULADD(at[36], at[86]);    MULADD(at[37], at[85]);    MULADD(at[38], at[84]);    MULADD(at[39], at[83]);    MULADD(at[40], at[82]);    MULADD(at[41], at[81]);    MULADD(at[42], at[80]);    MULADD(at[43], at[79]);    MULADD(at[44], at[78]);    MULADD(at[45], at[77]);    MULADD(at[46], at[76]);    MULADD(at[47], at[75]); 
   COMBA_STORE(C->dp[74]);
   /* 75 */
   COMBA_FORWARD;
   MULADD(at[28], at[95]);    MULADD(at[29], at[94]);    MULADD(at[30], at[93]);    MULADD(at[31], at[92]);    MULADD(at[32], at[91]);    MULADD(at[33], at[90]);    MULADD(at[34], at[89]);    MULADD(at[35], at[88]);    MULADD(at[36], at[87]);    MULADD(at[37], at[86]);    MULADD(at[38], at[85]);    MULADD(at[39], at[84]);    MULADD(at[40], at[83]);    MULADD(at[41], at[82]);    MULADD(at[42], at[81]);    MULADD(at[43], at[80]);    MULADD(at[44], at[79]);    MULADD(at[45], at[78]);    MULADD(at[46], at[77]);    MULADD(at[47], at[76]); 
   COMBA_STORE(C->dp[75]);
   /* 76 */
   COMBA_FORWARD;
   MULADD(at[29], at[95]);    MULADD(at[30], at[94]);    MULADD(at[31], at[93]);    MULADD(at[32], at[92]);    MULADD(at[33], at[91]);    MULADD(at[34], at[90]);    MULADD(at[35], at[89]);    MULADD(at[36], at[88]);    MULADD(at[37], at[87]);    MULADD(at[38], at[86]);    MULADD(at[39], at[85]);    MULADD(at[40], at[84]);    MULADD(at[41], at[83]);    MULADD(at[42], at[82]);    MULADD(at[43], at[81]);    MULADD(at[44], at[80]);    MULADD(at[45], at[79]);    MULADD(at[46], at[78]);    MULADD(at[47], at[77]); 
   COMBA_STORE(C->dp[76]);
   /* 77 */
   COMBA_FORWARD;
   MULADD(at[30], at[95]);    MULADD(at[31], at[94]);    MULADD(at[32], at[93]);    MULADD(at[33], at[92]);    MULADD(at[34], at[91]);    MULADD(at[35], at[90]);    MULADD(at[36], at[89]);    MULADD(at[37], at[88]);    MULADD(at[38], at[87]);    MULADD(at[39], at[86]);    MULADD(at[40], at[85]);    MULADD(at[41], at[84]);    MULADD(at[42], at[83]);    MULADD(at[43], at[82]);    MULADD(at[44], at[81]);    MULADD(at[45], at[80]);    MULADD(at[46], at[79]);    MULADD(at[47], at[78]); 
   COMBA_STORE(C->dp[77]);
   /* 78 */
   COMBA_FORWARD;
   MULADD(at[31], at[95]);    MULADD(at[32], at[94]);    MULADD(at[33], at[93]);    MULADD(at[34], at[92]);    MULADD(at[35], at[91]);    MULADD(at[36], at[90]);    MULADD(at[37], at[89]);    MULADD(at[38], at[88]);    MULADD(at[39], at[87]);    MULADD(at[40], at[86]);    MULADD(at[41], at[85]);    MULADD(at[42], at[84]);    MULADD(at[43], at[83]);    MULADD(at[44], at[82]);    MULADD(at[45], at[81]);    MULADD(at[46], at[80]);    MULADD(at[47], at[79]); 
   COMBA_STORE(C->dp[78]);
   /* 79 */
   COMBA_FORWARD;
   MULADD(at[32], at[95]);    MULADD(at[33], at[94]);    MULADD(at[34], at[93]);    MULADD(at[35], at[92]);    MULADD(at[36], at[91]);    MULADD(at[37], at[90]);    MULADD(at[38], at[89]);    MULADD(at[39], at[88]);    MULADD(at[40], at[87]);    MULADD(at[41], at[86]);    MULADD(at[42], at[85]);    MULADD(at[43], at[84]);    MULADD(at[44], at[83]);    MULADD(at[45], at[82]);    MULADD(at[46], at[81]);    MULADD(at[47], at[80]); 
   COMBA_STORE(C->dp[79]);
   /* 80 */
   COMBA_FORWARD;
   MULADD(at[33], at[95]);    MULADD(at[34], at[94]);    MULADD(at[35], at[93]);    MULADD(at[36], at[92]);    MULADD(at[37], at[91]);    MULADD(at[38], at[90]);    MULADD(at[39], at[89]);    MULADD(at[40], at[88]);    MULADD(at[41], at[87]);    MULADD(at[42], at[86]);    MULADD(at[43], at[85]);    MULADD(at[44], at[84]);    MULADD(at[45], at[83]);    MULADD(at[46], at[82]);    MULADD(at[47], at[81]); 
   COMBA_STORE(C->dp[80]);
   /* 81 */
   COMBA_FORWARD;
   MULADD(at[34], at[95]);    MULADD(at[35], at[94]);    MULADD(at[36], at[93]);    MULADD(at[37], at[92]);    MULADD(at[38], at[91]);    MULADD(at[39], at[90]);    MULADD(at[40], at[89]);    MULADD(at[41], at[88]);    MULADD(at[42], at[87]);    MULADD(at[43], at[86]);    MULADD(at[44], at[85]);    MULADD(at[45], at[84]);    MULADD(at[46], at[83]);    MULADD(at[47], at[82]); 
   COMBA_STORE(C->dp[81]);
   /* 82 */
   COMBA_FORWARD;
   MULADD(at[35], at[95]);    MULADD(at[36], at[94]);    MULADD(at[37], at[93]);    MULADD(at[38], at[92]);    MULADD(at[39], at[91]);    MULADD(at[40], at[90]);    MULADD(at[41], at[89]);    MULADD(at[42], at[88]);    MULADD(at[43], at[87]);    MULADD(at[44], at[86]);    MULADD(at[45], at[85]);    MULADD(at[46], at[84]);    MULADD(at[47], at[83]); 
   COMBA_STORE(C->dp[82]);
   /* 83 */
   COMBA_FORWARD;
   MULADD(at[36], at[95]);    MULADD(at[37], at[94]);    MULADD(at[38], at[93]);    MULADD(at[39], at[92]);    MULADD(at[40], at[91]);    MULADD(at[41], at[90]);    MULADD(at[42], at[89]);    MULADD(at[43], at[88]);    MULADD(at[44], at[87]);    MULADD(at[45], at[86]);    MULADD(at[46], at[85]);    MULADD(at[47], at[84]); 
   COMBA_STORE(C->dp[83]);
   /* 84 */
   COMBA_FORWARD;
   MULADD(at[37], at[95]);    MULADD(at[38], at[94]);    MULADD(at[39], at[93]);    MULADD(at[40], at[92]);    MULADD(at[41], at[91]);    MULADD(at[42], at[90]);    MULADD(at[43], at[89]);    MULADD(at[44], at[88]);    MULADD(at[45], at[87]);    MULADD(at[46], at[86]);    MULADD(at[47], at[85]); 
   COMBA_STORE(C->dp[84]);
   /* 85 */
   COMBA_FORWARD;
   MULADD(at[38], at[95]);    MULADD(at[39], at[94]);    MULADD(at[40], at[93]);    MULADD(at[41], at[92]);    MULADD(at[42], at[91]);    MULADD(at[43], at[90]);    MULADD(at[44], at[89]);    MULADD(at[45], at[88]);    MULADD(at[46], at[87]);    MULADD(at[47], at[86]); 
   COMBA_STORE(C->dp[85]);
   /* 86 */
   COMBA_FORWARD;
   MULADD(at[39], at[95]);    MULADD(at[40], at[94]);    MULADD(at[41], at[93]);    MULADD(at[42], at[92]);    MULADD(at[43], at[91]);    MULADD(at[44], at[90]);    MULADD(at[45], at[89]);    MULADD(at[46], at[88]);    MULADD(at[47], at[87]); 
   COMBA_STORE(C->dp[86]);
   /* 87 */
   COMBA_FORWARD;
   MULADD(at[40], at[95]);    MULADD(at[41], at[94]);    MULADD(at[42], at[93]);    MULADD(at[43], at[92]);    MULADD(at[44], at[91]);    MULADD(at[45], at[90]);    MULADD(at[46], at[89]);    MULADD(at[47], at[88]); 
   COMBA_STORE(C->dp[87]);
   /* 88 */
   COMBA_FORWARD;
   MULADD(at[41], at[95]);    MULADD(at[42], at[94]);    MULADD(at[43], at[93]);    MULADD(at[44], at[92]);    MULADD(at[45], at[91]);    MULADD(at[46], at[90]);    MULADD(at[47], at[89]); 
   COMBA_STORE(C->dp[88]);
   /* 89 */
   COMBA_FORWARD;
   MULADD(at[42], at[95]);    MULADD(at[43], at[94]);    MULADD(at[44], at[93]);    MULADD(at[45], at[92]);    MULADD(at[46], at[91]);    MULADD(at[47], at[90]); 
   COMBA_STORE(C->dp[89]);
   /* 90 */
   COMBA_FORWARD;
   MULADD(at[43], at[95]);    MULADD(at[44], at[94]);    MULADD(at[45], at[93]);    MULADD(at[46], at[92]);    MULADD(at[47], at[91]); 
   COMBA_STORE(C->dp[90]);
   /* 91 */
   COMBA_FORWARD;
   MULADD(at[44], at[95]);    MULADD(at[45], at[94]);    MULADD(at[46], at[93]);    MULADD(at[47], at[92]); 
   COMBA_STORE(C->dp[91]);
   /* 92 */
   COMBA_FORWARD;
   MULADD(at[45], at[95]);    MULADD(at[46], at[94]);    MULADD(at[47], at[93]); 
   COMBA_STORE(C->dp[92]);
   /* 93 */
   COMBA_FORWARD;
   MULADD(at[46], at[95]);    MULADD(at[47], at[94]); 
   COMBA_STORE(C->dp[93]);
   /* 94 */
   COMBA_FORWARD;
   MULADD(at[47], at[95]); 
   COMBA_STORE(C->dp[94]);
   COMBA_STORE2(C->dp[95]);
   C->used = 96;
   C->sign = A->sign ^ B->sign;
   fp_clamp(C);
   COMBA_FINI;
}
#endif

/* End: fp_mul_comba_48.c */

/* Start: fp_mul_comba_6.c */
#define TFM_DEFINES
#include "fp_mul_comba.c"

#ifdef TFM_MUL6
void fp_mul_comba6(fp_int *A, fp_int *B, fp_int *C)
{
   fp_digit c0, c1, c2, at[12];

   memcpy(at, A->dp, 6 * sizeof(fp_digit));
   memcpy(at+6, B->dp, 6 * sizeof(fp_digit));
   COMBA_START;

   COMBA_CLEAR;
   /* 0 */
   MULADD(at[0], at[6]); 
   COMBA_STORE(C->dp[0]);
   /* 1 */
   COMBA_FORWARD;
   MULADD(at[0], at[7]);    MULADD(at[1], at[6]); 
   COMBA_STORE(C->dp[1]);
   /* 2 */
   COMBA_FORWARD;
   MULADD(at[0], at[8]);    MULADD(at[1], at[7]);    MULADD(at[2], at[6]); 
   COMBA_STORE(C->dp[2]);
   /* 3 */
   COMBA_FORWARD;
   MULADD(at[0], at[9]);    MULADD(at[1], at[8]);    MULADD(at[2], at[7]);    MULADD(at[3], at[6]); 
   COMBA_STORE(C->dp[3]);
   /* 4 */
   COMBA_FORWARD;
   MULADD(at[0], at[10]);    MULADD(at[1], at[9]);    MULADD(at[2], at[8]);    MULADD(at[3], at[7]);    MULADD(at[4], at[6]); 
   COMBA_STORE(C->dp[4]);
   /* 5 */
   COMBA_FORWARD;
   MULADD(at[0], at[11]);    MULADD(at[1], at[10]);    MULADD(at[2], at[9]);    MULADD(at[3], at[8]);    MULADD(at[4], at[7]);    MULADD(at[5], at[6]); 
   COMBA_STORE(C->dp[5]);
   /* 6 */
   COMBA_FORWARD;
   MULADD(at[1], at[11]);    MULADD(at[2], at[10]);    MULADD(at[3], at[9]);    MULADD(at[4], at[8]);    MULADD(at[5], at[7]); 
   COMBA_STORE(C->dp[6]);
   /* 7 */
   COMBA_FORWARD;
   MULADD(at[2], at[11]);    MULADD(at[3], at[10]);    MULADD(at[4], at[9]);    MULADD(at[5], at[8]); 
   COMBA_STORE(C->dp[7]);
   /* 8 */
   COMBA_FORWARD;
   MULADD(at[3], at[11]);    MULADD(at[4], at[10]);    MULADD(at[5], at[9]); 
   COMBA_STORE(C->dp[8]);
   /* 9 */
   COMBA_FORWARD;
   MULADD(at[4], at[11]);    MULADD(at[5], at[10]); 
   COMBA_STORE(C->dp[9]);
   /* 10 */
   COMBA_FORWARD;
   MULADD(at[5], at[11]); 
   COMBA_STORE(C->dp[10]);
   COMBA_STORE2(C->dp[11]);
   C->used = 12;
   C->sign = A->sign ^ B->sign;
   fp_clamp(C);
   COMBA_FINI;
}
#endif

/* End: fp_mul_comba_6.c */

/* Start: fp_mul_comba_64.c */
#define TFM_DEFINES
#include "fp_mul_comba.c"

#ifdef TFM_MUL64
void fp_mul_comba64(fp_int *A, fp_int *B, fp_int *C)
{
   fp_digit c0, c1, c2, at[128];

   memcpy(at, A->dp, 64 * sizeof(fp_digit));
   memcpy(at+64, B->dp, 64 * sizeof(fp_digit));
   COMBA_START;

   COMBA_CLEAR;
   /* 0 */
   MULADD(at[0], at[64]); 
   COMBA_STORE(C->dp[0]);
   /* 1 */
   COMBA_FORWARD;
   MULADD(at[0], at[65]);    MULADD(at[1], at[64]); 
   COMBA_STORE(C->dp[1]);
   /* 2 */
   COMBA_FORWARD;
   MULADD(at[0], at[66]);    MULADD(at[1], at[65]);    MULADD(at[2], at[64]); 
   COMBA_STORE(C->dp[2]);
   /* 3 */
   COMBA_FORWARD;
   MULADD(at[0], at[67]);    MULADD(at[1], at[66]);    MULADD(at[2], at[65]);    MULADD(at[3], at[64]); 
   COMBA_STORE(C->dp[3]);
   /* 4 */
   COMBA_FORWARD;
   MULADD(at[0], at[68]);    MULADD(at[1], at[67]);    MULADD(at[2], at[66]);    MULADD(at[3], at[65]);    MULADD(at[4], at[64]); 
   COMBA_STORE(C->dp[4]);
   /* 5 */
   COMBA_FORWARD;
   MULADD(at[0], at[69]);    MULADD(at[1], at[68]);    MULADD(at[2], at[67]);    MULADD(at[3], at[66]);    MULADD(at[4], at[65]);    MULADD(at[5], at[64]); 
   COMBA_STORE(C->dp[5]);
   /* 6 */
   COMBA_FORWARD;
   MULADD(at[0], at[70]);    MULADD(at[1], at[69]);    MULADD(at[2], at[68]);    MULADD(at[3], at[67]);    MULADD(at[4], at[66]);    MULADD(at[5], at[65]);    MULADD(at[6], at[64]); 
   COMBA_STORE(C->dp[6]);
   /* 7 */
   COMBA_FORWARD;
   MULADD(at[0], at[71]);    MULADD(at[1], at[70]);    MULADD(at[2], at[69]);    MULADD(at[3], at[68]);    MULADD(at[4], at[67]);    MULADD(at[5], at[66]);    MULADD(at[6], at[65]);    MULADD(at[7], at[64]); 
   COMBA_STORE(C->dp[7]);
   /* 8 */
   COMBA_FORWARD;
   MULADD(at[0], at[72]);    MULADD(at[1], at[71]);    MULADD(at[2], at[70]);    MULADD(at[3], at[69]);    MULADD(at[4], at[68]);    MULADD(at[5], at[67]);    MULADD(at[6], at[66]);    MULADD(at[7], at[65]);    MULADD(at[8], at[64]); 
   COMBA_STORE(C->dp[8]);
   /* 9 */
   COMBA_FORWARD;
   MULADD(at[0], at[73]);    MULADD(at[1], at[72]);    MULADD(at[2], at[71]);    MULADD(at[3], at[70]);    MULADD(at[4], at[69]);    MULADD(at[5], at[68]);    MULADD(at[6], at[67]);    MULADD(at[7], at[66]);    MULADD(at[8], at[65]);    MULADD(at[9], at[64]); 
   COMBA_STORE(C->dp[9]);
   /* 10 */
   COMBA_FORWARD;
   MULADD(at[0], at[74]);    MULADD(at[1], at[73]);    MULADD(at[2], at[72]);    MULADD(at[3], at[71]);    MULADD(at[4], at[70]);    MULADD(at[5], at[69]);    MULADD(at[6], at[68]);    MULADD(at[7], at[67]);    MULADD(at[8], at[66]);    MULADD(at[9], at[65]);    MULADD(at[10], at[64]); 
   COMBA_STORE(C->dp[10]);
   /* 11 */
   COMBA_FORWARD;
   MULADD(at[0], at[75]);    MULADD(at[1], at[74]);    MULADD(at[2], at[73]);    MULADD(at[3], at[72]);    MULADD(at[4], at[71]);    MULADD(at[5], at[70]);    MULADD(at[6], at[69]);    MULADD(at[7], at[68]);    MULADD(at[8], at[67]);    MULADD(at[9], at[66]);    MULADD(at[10], at[65]);    MULADD(at[11], at[64]); 
   COMBA_STORE(C->dp[11]);
   /* 12 */
   COMBA_FORWARD;
   MULADD(at[0], at[76]);    MULADD(at[1], at[75]);    MULADD(at[2], at[74]);    MULADD(at[3], at[73]);    MULADD(at[4], at[72]);    MULADD(at[5], at[71]);    MULADD(at[6], at[70]);    MULADD(at[7], at[69]);    MULADD(at[8], at[68]);    MULADD(at[9], at[67]);    MULADD(at[10], at[66]);    MULADD(at[11], at[65]);    MULADD(at[12], at[64]); 
   COMBA_STORE(C->dp[12]);
   /* 13 */
   COMBA_FORWARD;
   MULADD(at[0], at[77]);    MULADD(at[1], at[76]);    MULADD(at[2], at[75]);    MULADD(at[3], at[74]);    MULADD(at[4], at[73]);    MULADD(at[5], at[72]);    MULADD(at[6], at[71]);    MULADD(at[7], at[70]);    MULADD(at[8], at[69]);    MULADD(at[9], at[68]);    MULADD(at[10], at[67]);    MULADD(at[11], at[66]);    MULADD(at[12], at[65]);    MULADD(at[13], at[64]); 
   COMBA_STORE(C->dp[13]);
   /* 14 */
   COMBA_FORWARD;
   MULADD(at[0], at[78]);    MULADD(at[1], at[77]);    MULADD(at[2], at[76]);    MULADD(at[3], at[75]);    MULADD(at[4], at[74]);    MULADD(at[5], at[73]);    MULADD(at[6], at[72]);    MULADD(at[7], at[71]);    MULADD(at[8], at[70]);    MULADD(at[9], at[69]);    MULADD(at[10], at[68]);    MULADD(at[11], at[67]);    MULADD(at[12], at[66]);    MULADD(at[13], at[65]);    MULADD(at[14], at[64]); 
   COMBA_STORE(C->dp[14]);
   /* 15 */
   COMBA_FORWARD;
   MULADD(at[0], at[79]);    MULADD(at[1], at[78]);    MULADD(at[2], at[77]);    MULADD(at[3], at[76]);    MULADD(at[4], at[75]);    MULADD(at[5], at[74]);    MULADD(at[6], at[73]);    MULADD(at[7], at[72]);    MULADD(at[8], at[71]);    MULADD(at[9], at[70]);    MULADD(at[10], at[69]);    MULADD(at[11], at[68]);    MULADD(at[12], at[67]);    MULADD(at[13], at[66]);    MULADD(at[14], at[65]);    MULADD(at[15], at[64]); 
   COMBA_STORE(C->dp[15]);
   /* 16 */
   COMBA_FORWARD;
   MULADD(at[0], at[80]);    MULADD(at[1], at[79]);    MULADD(at[2], at[78]);    MULADD(at[3], at[77]);    MULADD(at[4], at[76]);    MULADD(at[5], at[75]);    MULADD(at[6], at[74]);    MULADD(at[7], at[73]);    MULADD(at[8], at[72]);    MULADD(at[9], at[71]);    MULADD(at[10], at[70]);    MULADD(at[11], at[69]);    MULADD(at[12], at[68]);    MULADD(at[13], at[67]);    MULADD(at[14], at[66]);    MULADD(at[15], at[65]);    MULADD(at[16], at[64]); 
   COMBA_STORE(C->dp[16]);
   /* 17 */
   COMBA_FORWARD;
   MULADD(at[0], at[81]);    MULADD(at[1], at[80]);    MULADD(at[2], at[79]);    MULADD(at[3], at[78]);    MULADD(at[4], at[77]);    MULADD(at[5], at[76]);    MULADD(at[6], at[75]);    MULADD(at[7], at[74]);    MULADD(at[8], at[73]);    MULADD(at[9], at[72]);    MULADD(at[10], at[71]);    MULADD(at[11], at[70]);    MULADD(at[12], at[69]);    MULADD(at[13], at[68]);    MULADD(at[14], at[67]);    MULADD(at[15], at[66]);    MULADD(at[16], at[65]);    MULADD(at[17], at[64]); 
   COMBA_STORE(C->dp[17]);
   /* 18 */
   COMBA_FORWARD;
   MULADD(at[0], at[82]);    MULADD(at[1], at[81]);    MULADD(at[2], at[80]);    MULADD(at[3], at[79]);    MULADD(at[4], at[78]);    MULADD(at[5], at[77]);    MULADD(at[6], at[76]);    MULADD(at[7], at[75]);    MULADD(at[8], at[74]);    MULADD(at[9], at[73]);    MULADD(at[10], at[72]);    MULADD(at[11], at[71]);    MULADD(at[12], at[70]);    MULADD(at[13], at[69]);    MULADD(at[14], at[68]);    MULADD(at[15], at[67]);    MULADD(at[16], at[66]);    MULADD(at[17], at[65]);    MULADD(at[18], at[64]); 
   COMBA_STORE(C->dp[18]);
   /* 19 */
   COMBA_FORWARD;
   MULADD(at[0], at[83]);    MULADD(at[1], at[82]);    MULADD(at[2], at[81]);    MULADD(at[3], at[80]);    MULADD(at[4], at[79]);    MULADD(at[5], at[78]);    MULADD(at[6], at[77]);    MULADD(at[7], at[76]);    MULADD(at[8], at[75]);    MULADD(at[9], at[74]);    MULADD(at[10], at[73]);    MULADD(at[11], at[72]);    MULADD(at[12], at[71]);    MULADD(at[13], at[70]);    MULADD(at[14], at[69]);    MULADD(at[15], at[68]);    MULADD(at[16], at[67]);    MULADD(at[17], at[66]);    MULADD(at[18], at[65]);    MULADD(at[19], at[64]); 
   COMBA_STORE(C->dp[19]);
   /* 20 */
   COMBA_FORWARD;
   MULADD(at[0], at[84]);    MULADD(at[1], at[83]);    MULADD(at[2], at[82]);    MULADD(at[3], at[81]);    MULADD(at[4], at[80]);    MULADD(at[5], at[79]);    MULADD(at[6], at[78]);    MULADD(at[7], at[77]);    MULADD(at[8], at[76]);    MULADD(at[9], at[75]);    MULADD(at[10], at[74]);    MULADD(at[11], at[73]);    MULADD(at[12], at[72]);    MULADD(at[13], at[71]);    MULADD(at[14], at[70]);    MULADD(at[15], at[69]);    MULADD(at[16], at[68]);    MULADD(at[17], at[67]);    MULADD(at[18], at[66]);    MULADD(at[19], at[65]);    MULADD(at[20], at[64]); 
   COMBA_STORE(C->dp[20]);
   /* 21 */
   COMBA_FORWARD;
   MULADD(at[0], at[85]);    MULADD(at[1], at[84]);    MULADD(at[2], at[83]);    MULADD(at[3], at[82]);    MULADD(at[4], at[81]);    MULADD(at[5], at[80]);    MULADD(at[6], at[79]);    MULADD(at[7], at[78]);    MULADD(at[8], at[77]);    MULADD(at[9], at[76]);    MULADD(at[10], at[75]);    MULADD(at[11], at[74]);    MULADD(at[12], at[73]);    MULADD(at[13], at[72]);    MULADD(at[14], at[71]);    MULADD(at[15], at[70]);    MULADD(at[16], at[69]);    MULADD(at[17], at[68]);    MULADD(at[18], at[67]);    MULADD(at[19], at[66]);    MULADD(at[20], at[65]);    MULADD(at[21], at[64]); 
   COMBA_STORE(C->dp[21]);
   /* 22 */
   COMBA_FORWARD;
   MULADD(at[0], at[86]);    MULADD(at[1], at[85]);    MULADD(at[2], at[84]);    MULADD(at[3], at[83]);    MULADD(at[4], at[82]);    MULADD(at[5], at[81]);    MULADD(at[6], at[80]);    MULADD(at[7], at[79]);    MULADD(at[8], at[78]);    MULADD(at[9], at[77]);    MULADD(at[10], at[76]);    MULADD(at[11], at[75]);    MULADD(at[12], at[74]);    MULADD(at[13], at[73]);    MULADD(at[14], at[72]);    MULADD(at[15], at[71]);    MULADD(at[16], at[70]);    MULADD(at[17], at[69]);    MULADD(at[18], at[68]);    MULADD(at[19], at[67]);    MULADD(at[20], at[66]);    MULADD(at[21], at[65]);    MULADD(at[22], at[64]); 
   COMBA_STORE(C->dp[22]);
   /* 23 */
   COMBA_FORWARD;
   MULADD(at[0], at[87]);    MULADD(at[1], at[86]);    MULADD(at[2], at[85]);    MULADD(at[3], at[84]);    MULADD(at[4], at[83]);    MULADD(at[5], at[82]);    MULADD(at[6], at[81]);    MULADD(at[7], at[80]);    MULADD(at[8], at[79]);    MULADD(at[9], at[78]);    MULADD(at[10], at[77]);    MULADD(at[11], at[76]);    MULADD(at[12], at[75]);    MULADD(at[13], at[74]);    MULADD(at[14], at[73]);    MULADD(at[15], at[72]);    MULADD(at[16], at[71]);    MULADD(at[17], at[70]);    MULADD(at[18], at[69]);    MULADD(at[19], at[68]);    MULADD(at[20], at[67]);    MULADD(at[21], at[66]);    MULADD(at[22], at[65]);    MULADD(at[23], at[64]); 
   COMBA_STORE(C->dp[23]);
   /* 24 */
   COMBA_FORWARD;
   MULADD(at[0], at[88]);    MULADD(at[1], at[87]);    MULADD(at[2], at[86]);    MULADD(at[3], at[85]);    MULADD(at[4], at[84]);    MULADD(at[5], at[83]);    MULADD(at[6], at[82]);    MULADD(at[7], at[81]);    MULADD(at[8], at[80]);    MULADD(at[9], at[79]);    MULADD(at[10], at[78]);    MULADD(at[11], at[77]);    MULADD(at[12], at[76]);    MULADD(at[13], at[75]);    MULADD(at[14], at[74]);    MULADD(at[15], at[73]);    MULADD(at[16], at[72]);    MULADD(at[17], at[71]);    MULADD(at[18], at[70]);    MULADD(at[19], at[69]);    MULADD(at[20], at[68]);    MULADD(at[21], at[67]);    MULADD(at[22], at[66]);    MULADD(at[23], at[65]);    MULADD(at[24], at[64]); 
   COMBA_STORE(C->dp[24]);
   /* 25 */
   COMBA_FORWARD;
   MULADD(at[0], at[89]);    MULADD(at[1], at[88]);    MULADD(at[2], at[87]);    MULADD(at[3], at[86]);    MULADD(at[4], at[85]);    MULADD(at[5], at[84]);    MULADD(at[6], at[83]);    MULADD(at[7], at[82]);    MULADD(at[8], at[81]);    MULADD(at[9], at[80]);    MULADD(at[10], at[79]);    MULADD(at[11], at[78]);    MULADD(at[12], at[77]);    MULADD(at[13], at[76]);    MULADD(at[14], at[75]);    MULADD(at[15], at[74]);    MULADD(at[16], at[73]);    MULADD(at[17], at[72]);    MULADD(at[18], at[71]);    MULADD(at[19], at[70]);    MULADD(at[20], at[69]);    MULADD(at[21], at[68]);    MULADD(at[22], at[67]);    MULADD(at[23], at[66]);    MULADD(at[24], at[65]);    MULADD(at[25], at[64]); 
   COMBA_STORE(C->dp[25]);
   /* 26 */
   COMBA_FORWARD;
   MULADD(at[0], at[90]);    MULADD(at[1], at[89]);    MULADD(at[2], at[88]);    MULADD(at[3], at[87]);    MULADD(at[4], at[86]);    MULADD(at[5], at[85]);    MULADD(at[6], at[84]);    MULADD(at[7], at[83]);    MULADD(at[8], at[82]);    MULADD(at[9], at[81]);    MULADD(at[10], at[80]);    MULADD(at[11], at[79]);    MULADD(at[12], at[78]);    MULADD(at[13], at[77]);    MULADD(at[14], at[76]);    MULADD(at[15], at[75]);    MULADD(at[16], at[74]);    MULADD(at[17], at[73]);    MULADD(at[18], at[72]);    MULADD(at[19], at[71]);    MULADD(at[20], at[70]);    MULADD(at[21], at[69]);    MULADD(at[22], at[68]);    MULADD(at[23], at[67]);    MULADD(at[24], at[66]);    MULADD(at[25], at[65]);    MULADD(at[26], at[64]); 
   COMBA_STORE(C->dp[26]);
   /* 27 */
   COMBA_FORWARD;
   MULADD(at[0], at[91]);    MULADD(at[1], at[90]);    MULADD(at[2], at[89]);    MULADD(at[3], at[88]);    MULADD(at[4], at[87]);    MULADD(at[5], at[86]);    MULADD(at[6], at[85]);    MULADD(at[7], at[84]);    MULADD(at[8], at[83]);    MULADD(at[9], at[82]);    MULADD(at[10], at[81]);    MULADD(at[11], at[80]);    MULADD(at[12], at[79]);    MULADD(at[13], at[78]);    MULADD(at[14], at[77]);    MULADD(at[15], at[76]);    MULADD(at[16], at[75]);    MULADD(at[17], at[74]);    MULADD(at[18], at[73]);    MULADD(at[19], at[72]);    MULADD(at[20], at[71]);    MULADD(at[21], at[70]);    MULADD(at[22], at[69]);    MULADD(at[23], at[68]);    MULADD(at[24], at[67]);    MULADD(at[25], at[66]);    MULADD(at[26], at[65]);    MULADD(at[27], at[64]); 
   COMBA_STORE(C->dp[27]);
   /* 28 */
   COMBA_FORWARD;
   MULADD(at[0], at[92]);    MULADD(at[1], at[91]);    MULADD(at[2], at[90]);    MULADD(at[3], at[89]);    MULADD(at[4], at[88]);    MULADD(at[5], at[87]);    MULADD(at[6], at[86]);    MULADD(at[7], at[85]);    MULADD(at[8], at[84]);    MULADD(at[9], at[83]);    MULADD(at[10], at[82]);    MULADD(at[11], at[81]);    MULADD(at[12], at[80]);    MULADD(at[13], at[79]);    MULADD(at[14], at[78]);    MULADD(at[15], at[77]);    MULADD(at[16], at[76]);    MULADD(at[17], at[75]);    MULADD(at[18], at[74]);    MULADD(at[19], at[73]);    MULADD(at[20], at[72]);    MULADD(at[21], at[71]);    MULADD(at[22], at[70]);    MULADD(at[23], at[69]);    MULADD(at[24], at[68]);    MULADD(at[25], at[67]);    MULADD(at[26], at[66]);    MULADD(at[27], at[65]);    MULADD(at[28], at[64]); 
   COMBA_STORE(C->dp[28]);
   /* 29 */
   COMBA_FORWARD;
   MULADD(at[0], at[93]);    MULADD(at[1], at[92]);    MULADD(at[2], at[91]);    MULADD(at[3], at[90]);    MULADD(at[4], at[89]);    MULADD(at[5], at[88]);    MULADD(at[6], at[87]);    MULADD(at[7], at[86]);    MULADD(at[8], at[85]);    MULADD(at[9], at[84]);    MULADD(at[10], at[83]);    MULADD(at[11], at[82]);    MULADD(at[12], at[81]);    MULADD(at[13], at[80]);    MULADD(at[14], at[79]);    MULADD(at[15], at[78]);    MULADD(at[16], at[77]);    MULADD(at[17], at[76]);    MULADD(at[18], at[75]);    MULADD(at[19], at[74]);    MULADD(at[20], at[73]);    MULADD(at[21], at[72]);    MULADD(at[22], at[71]);    MULADD(at[23], at[70]);    MULADD(at[24], at[69]);    MULADD(at[25], at[68]);    MULADD(at[26], at[67]);    MULADD(at[27], at[66]);    MULADD(at[28], at[65]);    MULADD(at[29], at[64]); 
   COMBA_STORE(C->dp[29]);
   /* 30 */
   COMBA_FORWARD;
   MULADD(at[0], at[94]);    MULADD(at[1], at[93]);    MULADD(at[2], at[92]);    MULADD(at[3], at[91]);    MULADD(at[4], at[90]);    MULADD(at[5], at[89]);    MULADD(at[6], at[88]);    MULADD(at[7], at[87]);    MULADD(at[8], at[86]);    MULADD(at[9], at[85]);    MULADD(at[10], at[84]);    MULADD(at[11], at[83]);    MULADD(at[12], at[82]);    MULADD(at[13], at[81]);    MULADD(at[14], at[80]);    MULADD(at[15], at[79]);    MULADD(at[16], at[78]);    MULADD(at[17], at[77]);    MULADD(at[18], at[76]);    MULADD(at[19], at[75]);    MULADD(at[20], at[74]);    MULADD(at[21], at[73]);    MULADD(at[22], at[72]);    MULADD(at[23], at[71]);    MULADD(at[24], at[70]);    MULADD(at[25], at[69]);    MULADD(at[26], at[68]);    MULADD(at[27], at[67]);    MULADD(at[28], at[66]);    MULADD(at[29], at[65]);    MULADD(at[30], at[64]); 
   COMBA_STORE(C->dp[30]);
   /* 31 */
   COMBA_FORWARD;
   MULADD(at[0], at[95]);    MULADD(at[1], at[94]);    MULADD(at[2], at[93]);    MULADD(at[3], at[92]);    MULADD(at[4], at[91]);    MULADD(at[5], at[90]);    MULADD(at[6], at[89]);    MULADD(at[7], at[88]);    MULADD(at[8], at[87]);    MULADD(at[9], at[86]);    MULADD(at[10], at[85]);    MULADD(at[11], at[84]);    MULADD(at[12], at[83]);    MULADD(at[13], at[82]);    MULADD(at[14], at[81]);    MULADD(at[15], at[80]);    MULADD(at[16], at[79]);    MULADD(at[17], at[78]);    MULADD(at[18], at[77]);    MULADD(at[19], at[76]);    MULADD(at[20], at[75]);    MULADD(at[21], at[74]);    MULADD(at[22], at[73]);    MULADD(at[23], at[72]);    MULADD(at[24], at[71]);    MULADD(at[25], at[70]);    MULADD(at[26], at[69]);    MULADD(at[27], at[68]);    MULADD(at[28], at[67]);    MULADD(at[29], at[66]);    MULADD(at[30], at[65]);    MULADD(at[31], at[64]); 
   COMBA_STORE(C->dp[31]);
   /* 32 */
   COMBA_FORWARD;
   MULADD(at[0], at[96]);    MULADD(at[1], at[95]);    MULADD(at[2], at[94]);    MULADD(at[3], at[93]);    MULADD(at[4], at[92]);    MULADD(at[5], at[91]);    MULADD(at[6], at[90]);    MULADD(at[7], at[89]);    MULADD(at[8], at[88]);    MULADD(at[9], at[87]);    MULADD(at[10], at[86]);    MULADD(at[11], at[85]);    MULADD(at[12], at[84]);    MULADD(at[13], at[83]);    MULADD(at[14], at[82]);    MULADD(at[15], at[81]);    MULADD(at[16], at[80]);    MULADD(at[17], at[79]);    MULADD(at[18], at[78]);    MULADD(at[19], at[77]);    MULADD(at[20], at[76]);    MULADD(at[21], at[75]);    MULADD(at[22], at[74]);    MULADD(at[23], at[73]);    MULADD(at[24], at[72]);    MULADD(at[25], at[71]);    MULADD(at[26], at[70]);    MULADD(at[27], at[69]);    MULADD(at[28], at[68]);    MULADD(at[29], at[67]);    MULADD(at[30], at[66]);    MULADD(at[31], at[65]);    MULADD(at[32], at[64]); 
   COMBA_STORE(C->dp[32]);
   /* 33 */
   COMBA_FORWARD;
   MULADD(at[0], at[97]);    MULADD(at[1], at[96]);    MULADD(at[2], at[95]);    MULADD(at[3], at[94]);    MULADD(at[4], at[93]);    MULADD(at[5], at[92]);    MULADD(at[6], at[91]);    MULADD(at[7], at[90]);    MULADD(at[8], at[89]);    MULADD(at[9], at[88]);    MULADD(at[10], at[87]);    MULADD(at[11], at[86]);    MULADD(at[12], at[85]);    MULADD(at[13], at[84]);    MULADD(at[14], at[83]);    MULADD(at[15], at[82]);    MULADD(at[16], at[81]);    MULADD(at[17], at[80]);    MULADD(at[18], at[79]);    MULADD(at[19], at[78]);    MULADD(at[20], at[77]);    MULADD(at[21], at[76]);    MULADD(at[22], at[75]);    MULADD(at[23], at[74]);    MULADD(at[24], at[73]);    MULADD(at[25], at[72]);    MULADD(at[26], at[71]);    MULADD(at[27], at[70]);    MULADD(at[28], at[69]);    MULADD(at[29], at[68]);    MULADD(at[30], at[67]);    MULADD(at[31], at[66]);    MULADD(at[32], at[65]);    MULADD(at[33], at[64]); 
   COMBA_STORE(C->dp[33]);
   /* 34 */
   COMBA_FORWARD;
   MULADD(at[0], at[98]);    MULADD(at[1], at[97]);    MULADD(at[2], at[96]);    MULADD(at[3], at[95]);    MULADD(at[4], at[94]);    MULADD(at[5], at[93]);    MULADD(at[6], at[92]);    MULADD(at[7], at[91]);    MULADD(at[8], at[90]);    MULADD(at[9], at[89]);    MULADD(at[10], at[88]);    MULADD(at[11], at[87]);    MULADD(at[12], at[86]);    MULADD(at[13], at[85]);    MULADD(at[14], at[84]);    MULADD(at[15], at[83]);    MULADD(at[16], at[82]);    MULADD(at[17], at[81]);    MULADD(at[18], at[80]);    MULADD(at[19], at[79]);    MULADD(at[20], at[78]);    MULADD(at[21], at[77]);    MULADD(at[22], at[76]);    MULADD(at[23], at[75]);    MULADD(at[24], at[74]);    MULADD(at[25], at[73]);    MULADD(at[26], at[72]);    MULADD(at[27], at[71]);    MULADD(at[28], at[70]);    MULADD(at[29], at[69]);    MULADD(at[30], at[68]);    MULADD(at[31], at[67]);    MULADD(at[32], at[66]);    MULADD(at[33], at[65]);    MULADD(at[34], at[64]); 
   COMBA_STORE(C->dp[34]);
   /* 35 */
   COMBA_FORWARD;
   MULADD(at[0], at[99]);    MULADD(at[1], at[98]);    MULADD(at[2], at[97]);    MULADD(at[3], at[96]);    MULADD(at[4], at[95]);    MULADD(at[5], at[94]);    MULADD(at[6], at[93]);    MULADD(at[7], at[92]);    MULADD(at[8], at[91]);    MULADD(at[9], at[90]);    MULADD(at[10], at[89]);    MULADD(at[11], at[88]);    MULADD(at[12], at[87]);    MULADD(at[13], at[86]);    MULADD(at[14], at[85]);    MULADD(at[15], at[84]);    MULADD(at[16], at[83]);    MULADD(at[17], at[82]);    MULADD(at[18], at[81]);    MULADD(at[19], at[80]);    MULADD(at[20], at[79]);    MULADD(at[21], at[78]);    MULADD(at[22], at[77]);    MULADD(at[23], at[76]);    MULADD(at[24], at[75]);    MULADD(at[25], at[74]);    MULADD(at[26], at[73]);    MULADD(at[27], at[72]);    MULADD(at[28], at[71]);    MULADD(at[29], at[70]);    MULADD(at[30], at[69]);    MULADD(at[31], at[68]);    MULADD(at[32], at[67]);    MULADD(at[33], at[66]);    MULADD(at[34], at[65]);    MULADD(at[35], at[64]); 
   COMBA_STORE(C->dp[35]);
   /* 36 */
   COMBA_FORWARD;
   MULADD(at[0], at[100]);    MULADD(at[1], at[99]);    MULADD(at[2], at[98]);    MULADD(at[3], at[97]);    MULADD(at[4], at[96]);    MULADD(at[5], at[95]);    MULADD(at[6], at[94]);    MULADD(at[7], at[93]);    MULADD(at[8], at[92]);    MULADD(at[9], at[91]);    MULADD(at[10], at[90]);    MULADD(at[11], at[89]);    MULADD(at[12], at[88]);    MULADD(at[13], at[87]);    MULADD(at[14], at[86]);    MULADD(at[15], at[85]);    MULADD(at[16], at[84]);    MULADD(at[17], at[83]);    MULADD(at[18], at[82]);    MULADD(at[19], at[81]);    MULADD(at[20], at[80]);    MULADD(at[21], at[79]);    MULADD(at[22], at[78]);    MULADD(at[23], at[77]);    MULADD(at[24], at[76]);    MULADD(at[25], at[75]);    MULADD(at[26], at[74]);    MULADD(at[27], at[73]);    MULADD(at[28], at[72]);    MULADD(at[29], at[71]);    MULADD(at[30], at[70]);    MULADD(at[31], at[69]);    MULADD(at[32], at[68]);    MULADD(at[33], at[67]);    MULADD(at[34], at[66]);    MULADD(at[35], at[65]);    MULADD(at[36], at[64]); 
   COMBA_STORE(C->dp[36]);
   /* 37 */
   COMBA_FORWARD;
   MULADD(at[0], at[101]);    MULADD(at[1], at[100]);    MULADD(at[2], at[99]);    MULADD(at[3], at[98]);    MULADD(at[4], at[97]);    MULADD(at[5], at[96]);    MULADD(at[6], at[95]);    MULADD(at[7], at[94]);    MULADD(at[8], at[93]);    MULADD(at[9], at[92]);    MULADD(at[10], at[91]);    MULADD(at[11], at[90]);    MULADD(at[12], at[89]);    MULADD(at[13], at[88]);    MULADD(at[14], at[87]);    MULADD(at[15], at[86]);    MULADD(at[16], at[85]);    MULADD(at[17], at[84]);    MULADD(at[18], at[83]);    MULADD(at[19], at[82]);    MULADD(at[20], at[81]);    MULADD(at[21], at[80]);    MULADD(at[22], at[79]);    MULADD(at[23], at[78]);    MULADD(at[24], at[77]);    MULADD(at[25], at[76]);    MULADD(at[26], at[75]);    MULADD(at[27], at[74]);    MULADD(at[28], at[73]);    MULADD(at[29], at[72]);    MULADD(at[30], at[71]);    MULADD(at[31], at[70]);    MULADD(at[32], at[69]);    MULADD(at[33], at[68]);    MULADD(at[34], at[67]);    MULADD(at[35], at[66]);    MULADD(at[36], at[65]);    MULADD(at[37], at[64]); 
   COMBA_STORE(C->dp[37]);
   /* 38 */
   COMBA_FORWARD;
   MULADD(at[0], at[102]);    MULADD(at[1], at[101]);    MULADD(at[2], at[100]);    MULADD(at[3], at[99]);    MULADD(at[4], at[98]);    MULADD(at[5], at[97]);    MULADD(at[6], at[96]);    MULADD(at[7], at[95]);    MULADD(at[8], at[94]);    MULADD(at[9], at[93]);    MULADD(at[10], at[92]);    MULADD(at[11], at[91]);    MULADD(at[12], at[90]);    MULADD(at[13], at[89]);    MULADD(at[14], at[88]);    MULADD(at[15], at[87]);    MULADD(at[16], at[86]);    MULADD(at[17], at[85]);    MULADD(at[18], at[84]);    MULADD(at[19], at[83]);    MULADD(at[20], at[82]);    MULADD(at[21], at[81]);    MULADD(at[22], at[80]);    MULADD(at[23], at[79]);    MULADD(at[24], at[78]);    MULADD(at[25], at[77]);    MULADD(at[26], at[76]);    MULADD(at[27], at[75]);    MULADD(at[28], at[74]);    MULADD(at[29], at[73]);    MULADD(at[30], at[72]);    MULADD(at[31], at[71]);    MULADD(at[32], at[70]);    MULADD(at[33], at[69]);    MULADD(at[34], at[68]);    MULADD(at[35], at[67]);    MULADD(at[36], at[66]);    MULADD(at[37], at[65]);    MULADD(at[38], at[64]); 
   COMBA_STORE(C->dp[38]);
   /* 39 */
   COMBA_FORWARD;
   MULADD(at[0], at[103]);    MULADD(at[1], at[102]);    MULADD(at[2], at[101]);    MULADD(at[3], at[100]);    MULADD(at[4], at[99]);    MULADD(at[5], at[98]);    MULADD(at[6], at[97]);    MULADD(at[7], at[96]);    MULADD(at[8], at[95]);    MULADD(at[9], at[94]);    MULADD(at[10], at[93]);    MULADD(at[11], at[92]);    MULADD(at[12], at[91]);    MULADD(at[13], at[90]);    MULADD(at[14], at[89]);    MULADD(at[15], at[88]);    MULADD(at[16], at[87]);    MULADD(at[17], at[86]);    MULADD(at[18], at[85]);    MULADD(at[19], at[84]);    MULADD(at[20], at[83]);    MULADD(at[21], at[82]);    MULADD(at[22], at[81]);    MULADD(at[23], at[80]);    MULADD(at[24], at[79]);    MULADD(at[25], at[78]);    MULADD(at[26], at[77]);    MULADD(at[27], at[76]);    MULADD(at[28], at[75]);    MULADD(at[29], at[74]);    MULADD(at[30], at[73]);    MULADD(at[31], at[72]);    MULADD(at[32], at[71]);    MULADD(at[33], at[70]);    MULADD(at[34], at[69]);    MULADD(at[35], at[68]);    MULADD(at[36], at[67]);    MULADD(at[37], at[66]);    MULADD(at[38], at[65]);    MULADD(at[39], at[64]); 
   COMBA_STORE(C->dp[39]);
   /* 40 */
   COMBA_FORWARD;
   MULADD(at[0], at[104]);    MULADD(at[1], at[103]);    MULADD(at[2], at[102]);    MULADD(at[3], at[101]);    MULADD(at[4], at[100]);    MULADD(at[5], at[99]);    MULADD(at[6], at[98]);    MULADD(at[7], at[97]);    MULADD(at[8], at[96]);    MULADD(at[9], at[95]);    MULADD(at[10], at[94]);    MULADD(at[11], at[93]);    MULADD(at[12], at[92]);    MULADD(at[13], at[91]);    MULADD(at[14], at[90]);    MULADD(at[15], at[89]);    MULADD(at[16], at[88]);    MULADD(at[17], at[87]);    MULADD(at[18], at[86]);    MULADD(at[19], at[85]);    MULADD(at[20], at[84]);    MULADD(at[21], at[83]);    MULADD(at[22], at[82]);    MULADD(at[23], at[81]);    MULADD(at[24], at[80]);    MULADD(at[25], at[79]);    MULADD(at[26], at[78]);    MULADD(at[27], at[77]);    MULADD(at[28], at[76]);    MULADD(at[29], at[75]);    MULADD(at[30], at[74]);    MULADD(at[31], at[73]);    MULADD(at[32], at[72]);    MULADD(at[33], at[71]);    MULADD(at[34], at[70]);    MULADD(at[35], at[69]);    MULADD(at[36], at[68]);    MULADD(at[37], at[67]);    MULADD(at[38], at[66]);    MULADD(at[39], at[65]);    MULADD(at[40], at[64]); 
   COMBA_STORE(C->dp[40]);
   /* 41 */
   COMBA_FORWARD;
   MULADD(at[0], at[105]);    MULADD(at[1], at[104]);    MULADD(at[2], at[103]);    MULADD(at[3], at[102]);    MULADD(at[4], at[101]);    MULADD(at[5], at[100]);    MULADD(at[6], at[99]);    MULADD(at[7], at[98]);    MULADD(at[8], at[97]);    MULADD(at[9], at[96]);    MULADD(at[10], at[95]);    MULADD(at[11], at[94]);    MULADD(at[12], at[93]);    MULADD(at[13], at[92]);    MULADD(at[14], at[91]);    MULADD(at[15], at[90]);    MULADD(at[16], at[89]);    MULADD(at[17], at[88]);    MULADD(at[18], at[87]);    MULADD(at[19], at[86]);    MULADD(at[20], at[85]);    MULADD(at[21], at[84]);    MULADD(at[22], at[83]);    MULADD(at[23], at[82]);    MULADD(at[24], at[81]);    MULADD(at[25], at[80]);    MULADD(at[26], at[79]);    MULADD(at[27], at[78]);    MULADD(at[28], at[77]);    MULADD(at[29], at[76]);    MULADD(at[30], at[75]);    MULADD(at[31], at[74]);    MULADD(at[32], at[73]);    MULADD(at[33], at[72]);    MULADD(at[34], at[71]);    MULADD(at[35], at[70]);    MULADD(at[36], at[69]);    MULADD(at[37], at[68]);    MULADD(at[38], at[67]);    MULADD(at[39], at[66]);    MULADD(at[40], at[65]);    MULADD(at[41], at[64]); 
   COMBA_STORE(C->dp[41]);
   /* 42 */
   COMBA_FORWARD;
   MULADD(at[0], at[106]);    MULADD(at[1], at[105]);    MULADD(at[2], at[104]);    MULADD(at[3], at[103]);    MULADD(at[4], at[102]);    MULADD(at[5], at[101]);    MULADD(at[6], at[100]);    MULADD(at[7], at[99]);    MULADD(at[8], at[98]);    MULADD(at[9], at[97]);    MULADD(at[10], at[96]);    MULADD(at[11], at[95]);    MULADD(at[12], at[94]);    MULADD(at[13], at[93]);    MULADD(at[14], at[92]);    MULADD(at[15], at[91]);    MULADD(at[16], at[90]);    MULADD(at[17], at[89]);    MULADD(at[18], at[88]);    MULADD(at[19], at[87]);    MULADD(at[20], at[86]);    MULADD(at[21], at[85]);    MULADD(at[22], at[84]);    MULADD(at[23], at[83]);    MULADD(at[24], at[82]);    MULADD(at[25], at[81]);    MULADD(at[26], at[80]);    MULADD(at[27], at[79]);    MULADD(at[28], at[78]);    MULADD(at[29], at[77]);    MULADD(at[30], at[76]);    MULADD(at[31], at[75]);    MULADD(at[32], at[74]);    MULADD(at[33], at[73]);    MULADD(at[34], at[72]);    MULADD(at[35], at[71]);    MULADD(at[36], at[70]);    MULADD(at[37], at[69]);    MULADD(at[38], at[68]);    MULADD(at[39], at[67]);    MULADD(at[40], at[66]);    MULADD(at[41], at[65]);    MULADD(at[42], at[64]); 
   COMBA_STORE(C->dp[42]);
   /* 43 */
   COMBA_FORWARD;
   MULADD(at[0], at[107]);    MULADD(at[1], at[106]);    MULADD(at[2], at[105]);    MULADD(at[3], at[104]);    MULADD(at[4], at[103]);    MULADD(at[5], at[102]);    MULADD(at[6], at[101]);    MULADD(at[7], at[100]);    MULADD(at[8], at[99]);    MULADD(at[9], at[98]);    MULADD(at[10], at[97]);    MULADD(at[11], at[96]);    MULADD(at[12], at[95]);    MULADD(at[13], at[94]);    MULADD(at[14], at[93]);    MULADD(at[15], at[92]);    MULADD(at[16], at[91]);    MULADD(at[17], at[90]);    MULADD(at[18], at[89]);    MULADD(at[19], at[88]);    MULADD(at[20], at[87]);    MULADD(at[21], at[86]);    MULADD(at[22], at[85]);    MULADD(at[23], at[84]);    MULADD(at[24], at[83]);    MULADD(at[25], at[82]);    MULADD(at[26], at[81]);    MULADD(at[27], at[80]);    MULADD(at[28], at[79]);    MULADD(at[29], at[78]);    MULADD(at[30], at[77]);    MULADD(at[31], at[76]);    MULADD(at[32], at[75]);    MULADD(at[33], at[74]);    MULADD(at[34], at[73]);    MULADD(at[35], at[72]);    MULADD(at[36], at[71]);    MULADD(at[37], at[70]);    MULADD(at[38], at[69]);    MULADD(at[39], at[68]);    MULADD(at[40], at[67]);    MULADD(at[41], at[66]);    MULADD(at[42], at[65]);    MULADD(at[43], at[64]); 
   COMBA_STORE(C->dp[43]);
   /* 44 */
   COMBA_FORWARD;
   MULADD(at[0], at[108]);    MULADD(at[1], at[107]);    MULADD(at[2], at[106]);    MULADD(at[3], at[105]);    MULADD(at[4], at[104]);    MULADD(at[5], at[103]);    MULADD(at[6], at[102]);    MULADD(at[7], at[101]);    MULADD(at[8], at[100]);    MULADD(at[9], at[99]);    MULADD(at[10], at[98]);    MULADD(at[11], at[97]);    MULADD(at[12], at[96]);    MULADD(at[13], at[95]);    MULADD(at[14], at[94]);    MULADD(at[15], at[93]);    MULADD(at[16], at[92]);    MULADD(at[17], at[91]);    MULADD(at[18], at[90]);    MULADD(at[19], at[89]);    MULADD(at[20], at[88]);    MULADD(at[21], at[87]);    MULADD(at[22], at[86]);    MULADD(at[23], at[85]);    MULADD(at[24], at[84]);    MULADD(at[25], at[83]);    MULADD(at[26], at[82]);    MULADD(at[27], at[81]);    MULADD(at[28], at[80]);    MULADD(at[29], at[79]);    MULADD(at[30], at[78]);    MULADD(at[31], at[77]);    MULADD(at[32], at[76]);    MULADD(at[33], at[75]);    MULADD(at[34], at[74]);    MULADD(at[35], at[73]);    MULADD(at[36], at[72]);    MULADD(at[37], at[71]);    MULADD(at[38], at[70]);    MULADD(at[39], at[69]);    MULADD(at[40], at[68]);    MULADD(at[41], at[67]);    MULADD(at[42], at[66]);    MULADD(at[43], at[65]);    MULADD(at[44], at[64]); 
   COMBA_STORE(C->dp[44]);
   /* 45 */
   COMBA_FORWARD;
   MULADD(at[0], at[109]);    MULADD(at[1], at[108]);    MULADD(at[2], at[107]);    MULADD(at[3], at[106]);    MULADD(at[4], at[105]);    MULADD(at[5], at[104]);    MULADD(at[6], at[103]);    MULADD(at[7], at[102]);    MULADD(at[8], at[101]);    MULADD(at[9], at[100]);    MULADD(at[10], at[99]);    MULADD(at[11], at[98]);    MULADD(at[12], at[97]);    MULADD(at[13], at[96]);    MULADD(at[14], at[95]);    MULADD(at[15], at[94]);    MULADD(at[16], at[93]);    MULADD(at[17], at[92]);    MULADD(at[18], at[91]);    MULADD(at[19], at[90]);    MULADD(at[20], at[89]);    MULADD(at[21], at[88]);    MULADD(at[22], at[87]);    MULADD(at[23], at[86]);    MULADD(at[24], at[85]);    MULADD(at[25], at[84]);    MULADD(at[26], at[83]);    MULADD(at[27], at[82]);    MULADD(at[28], at[81]);    MULADD(at[29], at[80]);    MULADD(at[30], at[79]);    MULADD(at[31], at[78]);    MULADD(at[32], at[77]);    MULADD(at[33], at[76]);    MULADD(at[34], at[75]);    MULADD(at[35], at[74]);    MULADD(at[36], at[73]);    MULADD(at[37], at[72]);    MULADD(at[38], at[71]);    MULADD(at[39], at[70]);    MULADD(at[40], at[69]);    MULADD(at[41], at[68]);    MULADD(at[42], at[67]);    MULADD(at[43], at[66]);    MULADD(at[44], at[65]);    MULADD(at[45], at[64]); 
   COMBA_STORE(C->dp[45]);
   /* 46 */
   COMBA_FORWARD;
   MULADD(at[0], at[110]);    MULADD(at[1], at[109]);    MULADD(at[2], at[108]);    MULADD(at[3], at[107]);    MULADD(at[4], at[106]);    MULADD(at[5], at[105]);    MULADD(at[6], at[104]);    MULADD(at[7], at[103]);    MULADD(at[8], at[102]);    MULADD(at[9], at[101]);    MULADD(at[10], at[100]);    MULADD(at[11], at[99]);    MULADD(at[12], at[98]);    MULADD(at[13], at[97]);    MULADD(at[14], at[96]);    MULADD(at[15], at[95]);    MULADD(at[16], at[94]);    MULADD(at[17], at[93]);    MULADD(at[18], at[92]);    MULADD(at[19], at[91]);    MULADD(at[20], at[90]);    MULADD(at[21], at[89]);    MULADD(at[22], at[88]);    MULADD(at[23], at[87]);    MULADD(at[24], at[86]);    MULADD(at[25], at[85]);    MULADD(at[26], at[84]);    MULADD(at[27], at[83]);    MULADD(at[28], at[82]);    MULADD(at[29], at[81]);    MULADD(at[30], at[80]);    MULADD(at[31], at[79]);    MULADD(at[32], at[78]);    MULADD(at[33], at[77]);    MULADD(at[34], at[76]);    MULADD(at[35], at[75]);    MULADD(at[36], at[74]);    MULADD(at[37], at[73]);    MULADD(at[38], at[72]);    MULADD(at[39], at[71]);    MULADD(at[40], at[70]);    MULADD(at[41], at[69]);    MULADD(at[42], at[68]);    MULADD(at[43], at[67]);    MULADD(at[44], at[66]);    MULADD(at[45], at[65]);    MULADD(at[46], at[64]); 
   COMBA_STORE(C->dp[46]);
   /* 47 */
   COMBA_FORWARD;
   MULADD(at[0], at[111]);    MULADD(at[1], at[110]);    MULADD(at[2], at[109]);    MULADD(at[3], at[108]);    MULADD(at[4], at[107]);    MULADD(at[5], at[106]);    MULADD(at[6], at[105]);    MULADD(at[7], at[104]);    MULADD(at[8], at[103]);    MULADD(at[9], at[102]);    MULADD(at[10], at[101]);    MULADD(at[11], at[100]);    MULADD(at[12], at[99]);    MULADD(at[13], at[98]);    MULADD(at[14], at[97]);    MULADD(at[15], at[96]);    MULADD(at[16], at[95]);    MULADD(at[17], at[94]);    MULADD(at[18], at[93]);    MULADD(at[19], at[92]);    MULADD(at[20], at[91]);    MULADD(at[21], at[90]);    MULADD(at[22], at[89]);    MULADD(at[23], at[88]);    MULADD(at[24], at[87]);    MULADD(at[25], at[86]);    MULADD(at[26], at[85]);    MULADD(at[27], at[84]);    MULADD(at[28], at[83]);    MULADD(at[29], at[82]);    MULADD(at[30], at[81]);    MULADD(at[31], at[80]);    MULADD(at[32], at[79]);    MULADD(at[33], at[78]);    MULADD(at[34], at[77]);    MULADD(at[35], at[76]);    MULADD(at[36], at[75]);    MULADD(at[37], at[74]);    MULADD(at[38], at[73]);    MULADD(at[39], at[72]);    MULADD(at[40], at[71]);    MULADD(at[41], at[70]);    MULADD(at[42], at[69]);    MULADD(at[43], at[68]);    MULADD(at[44], at[67]);    MULADD(at[45], at[66]);    MULADD(at[46], at[65]);    MULADD(at[47], at[64]); 
   COMBA_STORE(C->dp[47]);
   /* 48 */
   COMBA_FORWARD;
   MULADD(at[0], at[112]);    MULADD(at[1], at[111]);    MULADD(at[2], at[110]);    MULADD(at[3], at[109]);    MULADD(at[4], at[108]);    MULADD(at[5], at[107]);    MULADD(at[6], at[106]);    MULADD(at[7], at[105]);    MULADD(at[8], at[104]);    MULADD(at[9], at[103]);    MULADD(at[10], at[102]);    MULADD(at[11], at[101]);    MULADD(at[12], at[100]);    MULADD(at[13], at[99]);    MULADD(at[14], at[98]);    MULADD(at[15], at[97]);    MULADD(at[16], at[96]);    MULADD(at[17], at[95]);    MULADD(at[18], at[94]);    MULADD(at[19], at[93]);    MULADD(at[20], at[92]);    MULADD(at[21], at[91]);    MULADD(at[22], at[90]);    MULADD(at[23], at[89]);    MULADD(at[24], at[88]);    MULADD(at[25], at[87]);    MULADD(at[26], at[86]);    MULADD(at[27], at[85]);    MULADD(at[28], at[84]);    MULADD(at[29], at[83]);    MULADD(at[30], at[82]);    MULADD(at[31], at[81]);    MULADD(at[32], at[80]);    MULADD(at[33], at[79]);    MULADD(at[34], at[78]);    MULADD(at[35], at[77]);    MULADD(at[36], at[76]);    MULADD(at[37], at[75]);    MULADD(at[38], at[74]);    MULADD(at[39], at[73]);    MULADD(at[40], at[72]);    MULADD(at[41], at[71]);    MULADD(at[42], at[70]);    MULADD(at[43], at[69]);    MULADD(at[44], at[68]);    MULADD(at[45], at[67]);    MULADD(at[46], at[66]);    MULADD(at[47], at[65]);    MULADD(at[48], at[64]); 
   COMBA_STORE(C->dp[48]);
   /* 49 */
   COMBA_FORWARD;
   MULADD(at[0], at[113]);    MULADD(at[1], at[112]);    MULADD(at[2], at[111]);    MULADD(at[3], at[110]);    MULADD(at[4], at[109]);    MULADD(at[5], at[108]);    MULADD(at[6], at[107]);    MULADD(at[7], at[106]);    MULADD(at[8], at[105]);    MULADD(at[9], at[104]);    MULADD(at[10], at[103]);    MULADD(at[11], at[102]);    MULADD(at[12], at[101]);    MULADD(at[13], at[100]);    MULADD(at[14], at[99]);    MULADD(at[15], at[98]);    MULADD(at[16], at[97]);    MULADD(at[17], at[96]);    MULADD(at[18], at[95]);    MULADD(at[19], at[94]);    MULADD(at[20], at[93]);    MULADD(at[21], at[92]);    MULADD(at[22], at[91]);    MULADD(at[23], at[90]);    MULADD(at[24], at[89]);    MULADD(at[25], at[88]);    MULADD(at[26], at[87]);    MULADD(at[27], at[86]);    MULADD(at[28], at[85]);    MULADD(at[29], at[84]);    MULADD(at[30], at[83]);    MULADD(at[31], at[82]);    MULADD(at[32], at[81]);    MULADD(at[33], at[80]);    MULADD(at[34], at[79]);    MULADD(at[35], at[78]);    MULADD(at[36], at[77]);    MULADD(at[37], at[76]);    MULADD(at[38], at[75]);    MULADD(at[39], at[74]);    MULADD(at[40], at[73]);    MULADD(at[41], at[72]);    MULADD(at[42], at[71]);    MULADD(at[43], at[70]);    MULADD(at[44], at[69]);    MULADD(at[45], at[68]);    MULADD(at[46], at[67]);    MULADD(at[47], at[66]);    MULADD(at[48], at[65]);    MULADD(at[49], at[64]); 
   COMBA_STORE(C->dp[49]);
   /* 50 */
   COMBA_FORWARD;
   MULADD(at[0], at[114]);    MULADD(at[1], at[113]);    MULADD(at[2], at[112]);    MULADD(at[3], at[111]);    MULADD(at[4], at[110]);    MULADD(at[5], at[109]);    MULADD(at[6], at[108]);    MULADD(at[7], at[107]);    MULADD(at[8], at[106]);    MULADD(at[9], at[105]);    MULADD(at[10], at[104]);    MULADD(at[11], at[103]);    MULADD(at[12], at[102]);    MULADD(at[13], at[101]);    MULADD(at[14], at[100]);    MULADD(at[15], at[99]);    MULADD(at[16], at[98]);    MULADD(at[17], at[97]);    MULADD(at[18], at[96]);    MULADD(at[19], at[95]);    MULADD(at[20], at[94]);    MULADD(at[21], at[93]);    MULADD(at[22], at[92]);    MULADD(at[23], at[91]);    MULADD(at[24], at[90]);    MULADD(at[25], at[89]);    MULADD(at[26], at[88]);    MULADD(at[27], at[87]);    MULADD(at[28], at[86]);    MULADD(at[29], at[85]);    MULADD(at[30], at[84]);    MULADD(at[31], at[83]);    MULADD(at[32], at[82]);    MULADD(at[33], at[81]);    MULADD(at[34], at[80]);    MULADD(at[35], at[79]);    MULADD(at[36], at[78]);    MULADD(at[37], at[77]);    MULADD(at[38], at[76]);    MULADD(at[39], at[75]);    MULADD(at[40], at[74]);    MULADD(at[41], at[73]);    MULADD(at[42], at[72]);    MULADD(at[43], at[71]);    MULADD(at[44], at[70]);    MULADD(at[45], at[69]);    MULADD(at[46], at[68]);    MULADD(at[47], at[67]);    MULADD(at[48], at[66]);    MULADD(at[49], at[65]);    MULADD(at[50], at[64]); 
   COMBA_STORE(C->dp[50]);
   /* 51 */
   COMBA_FORWARD;
   MULADD(at[0], at[115]);    MULADD(at[1], at[114]);    MULADD(at[2], at[113]);    MULADD(at[3], at[112]);    MULADD(at[4], at[111]);    MULADD(at[5], at[110]);    MULADD(at[6], at[109]);    MULADD(at[7], at[108]);    MULADD(at[8], at[107]);    MULADD(at[9], at[106]);    MULADD(at[10], at[105]);    MULADD(at[11], at[104]);    MULADD(at[12], at[103]);    MULADD(at[13], at[102]);    MULADD(at[14], at[101]);    MULADD(at[15], at[100]);    MULADD(at[16], at[99]);    MULADD(at[17], at[98]);    MULADD(at[18], at[97]);    MULADD(at[19], at[96]);    MULADD(at[20], at[95]);    MULADD(at[21], at[94]);    MULADD(at[22], at[93]);    MULADD(at[23], at[92]);    MULADD(at[24], at[91]);    MULADD(at[25], at[90]);    MULADD(at[26], at[89]);    MULADD(at[27], at[88]);    MULADD(at[28], at[87]);    MULADD(at[29], at[86]);    MULADD(at[30], at[85]);    MULADD(at[31], at[84]);    MULADD(at[32], at[83]);    MULADD(at[33], at[82]);    MULADD(at[34], at[81]);    MULADD(at[35], at[80]);    MULADD(at[36], at[79]);    MULADD(at[37], at[78]);    MULADD(at[38], at[77]);    MULADD(at[39], at[76]);    MULADD(at[40], at[75]);    MULADD(at[41], at[74]);    MULADD(at[42], at[73]);    MULADD(at[43], at[72]);    MULADD(at[44], at[71]);    MULADD(at[45], at[70]);    MULADD(at[46], at[69]);    MULADD(at[47], at[68]);    MULADD(at[48], at[67]);    MULADD(at[49], at[66]);    MULADD(at[50], at[65]);    MULADD(at[51], at[64]); 
   COMBA_STORE(C->dp[51]);
   /* 52 */
   COMBA_FORWARD;
   MULADD(at[0], at[116]);    MULADD(at[1], at[115]);    MULADD(at[2], at[114]);    MULADD(at[3], at[113]);    MULADD(at[4], at[112]);    MULADD(at[5], at[111]);    MULADD(at[6], at[110]);    MULADD(at[7], at[109]);    MULADD(at[8], at[108]);    MULADD(at[9], at[107]);    MULADD(at[10], at[106]);    MULADD(at[11], at[105]);    MULADD(at[12], at[104]);    MULADD(at[13], at[103]);    MULADD(at[14], at[102]);    MULADD(at[15], at[101]);    MULADD(at[16], at[100]);    MULADD(at[17], at[99]);    MULADD(at[18], at[98]);    MULADD(at[19], at[97]);    MULADD(at[20], at[96]);    MULADD(at[21], at[95]);    MULADD(at[22], at[94]);    MULADD(at[23], at[93]);    MULADD(at[24], at[92]);    MULADD(at[25], at[91]);    MULADD(at[26], at[90]);    MULADD(at[27], at[89]);    MULADD(at[28], at[88]);    MULADD(at[29], at[87]);    MULADD(at[30], at[86]);    MULADD(at[31], at[85]);    MULADD(at[32], at[84]);    MULADD(at[33], at[83]);    MULADD(at[34], at[82]);    MULADD(at[35], at[81]);    MULADD(at[36], at[80]);    MULADD(at[37], at[79]);    MULADD(at[38], at[78]);    MULADD(at[39], at[77]);    MULADD(at[40], at[76]);    MULADD(at[41], at[75]);    MULADD(at[42], at[74]);    MULADD(at[43], at[73]);    MULADD(at[44], at[72]);    MULADD(at[45], at[71]);    MULADD(at[46], at[70]);    MULADD(at[47], at[69]);    MULADD(at[48], at[68]);    MULADD(at[49], at[67]);    MULADD(at[50], at[66]);    MULADD(at[51], at[65]);    MULADD(at[52], at[64]); 
   COMBA_STORE(C->dp[52]);
   /* 53 */
   COMBA_FORWARD;
   MULADD(at[0], at[117]);    MULADD(at[1], at[116]);    MULADD(at[2], at[115]);    MULADD(at[3], at[114]);    MULADD(at[4], at[113]);    MULADD(at[5], at[112]);    MULADD(at[6], at[111]);    MULADD(at[7], at[110]);    MULADD(at[8], at[109]);    MULADD(at[9], at[108]);    MULADD(at[10], at[107]);    MULADD(at[11], at[106]);    MULADD(at[12], at[105]);    MULADD(at[13], at[104]);    MULADD(at[14], at[103]);    MULADD(at[15], at[102]);    MULADD(at[16], at[101]);    MULADD(at[17], at[100]);    MULADD(at[18], at[99]);    MULADD(at[19], at[98]);    MULADD(at[20], at[97]);    MULADD(at[21], at[96]);    MULADD(at[22], at[95]);    MULADD(at[23], at[94]);    MULADD(at[24], at[93]);    MULADD(at[25], at[92]);    MULADD(at[26], at[91]);    MULADD(at[27], at[90]);    MULADD(at[28], at[89]);    MULADD(at[29], at[88]);    MULADD(at[30], at[87]);    MULADD(at[31], at[86]);    MULADD(at[32], at[85]);    MULADD(at[33], at[84]);    MULADD(at[34], at[83]);    MULADD(at[35], at[82]);    MULADD(at[36], at[81]);    MULADD(at[37], at[80]);    MULADD(at[38], at[79]);    MULADD(at[39], at[78]);    MULADD(at[40], at[77]);    MULADD(at[41], at[76]);    MULADD(at[42], at[75]);    MULADD(at[43], at[74]);    MULADD(at[44], at[73]);    MULADD(at[45], at[72]);    MULADD(at[46], at[71]);    MULADD(at[47], at[70]);    MULADD(at[48], at[69]);    MULADD(at[49], at[68]);    MULADD(at[50], at[67]);    MULADD(at[51], at[66]);    MULADD(at[52], at[65]);    MULADD(at[53], at[64]); 
   COMBA_STORE(C->dp[53]);
   /* 54 */
   COMBA_FORWARD;
   MULADD(at[0], at[118]);    MULADD(at[1], at[117]);    MULADD(at[2], at[116]);    MULADD(at[3], at[115]);    MULADD(at[4], at[114]);    MULADD(at[5], at[113]);    MULADD(at[6], at[112]);    MULADD(at[7], at[111]);    MULADD(at[8], at[110]);    MULADD(at[9], at[109]);    MULADD(at[10], at[108]);    MULADD(at[11], at[107]);    MULADD(at[12], at[106]);    MULADD(at[13], at[105]);    MULADD(at[14], at[104]);    MULADD(at[15], at[103]);    MULADD(at[16], at[102]);    MULADD(at[17], at[101]);    MULADD(at[18], at[100]);    MULADD(at[19], at[99]);    MULADD(at[20], at[98]);    MULADD(at[21], at[97]);    MULADD(at[22], at[96]);    MULADD(at[23], at[95]);    MULADD(at[24], at[94]);    MULADD(at[25], at[93]);    MULADD(at[26], at[92]);    MULADD(at[27], at[91]);    MULADD(at[28], at[90]);    MULADD(at[29], at[89]);    MULADD(at[30], at[88]);    MULADD(at[31], at[87]);    MULADD(at[32], at[86]);    MULADD(at[33], at[85]);    MULADD(at[34], at[84]);    MULADD(at[35], at[83]);    MULADD(at[36], at[82]);    MULADD(at[37], at[81]);    MULADD(at[38], at[80]);    MULADD(at[39], at[79]);    MULADD(at[40], at[78]);    MULADD(at[41], at[77]);    MULADD(at[42], at[76]);    MULADD(at[43], at[75]);    MULADD(at[44], at[74]);    MULADD(at[45], at[73]);    MULADD(at[46], at[72]);    MULADD(at[47], at[71]);    MULADD(at[48], at[70]);    MULADD(at[49], at[69]);    MULADD(at[50], at[68]);    MULADD(at[51], at[67]);    MULADD(at[52], at[66]);    MULADD(at[53], at[65]);    MULADD(at[54], at[64]); 
   COMBA_STORE(C->dp[54]);
   /* 55 */
   COMBA_FORWARD;
   MULADD(at[0], at[119]);    MULADD(at[1], at[118]);    MULADD(at[2], at[117]);    MULADD(at[3], at[116]);    MULADD(at[4], at[115]);    MULADD(at[5], at[114]);    MULADD(at[6], at[113]);    MULADD(at[7], at[112]);    MULADD(at[8], at[111]);    MULADD(at[9], at[110]);    MULADD(at[10], at[109]);    MULADD(at[11], at[108]);    MULADD(at[12], at[107]);    MULADD(at[13], at[106]);    MULADD(at[14], at[105]);    MULADD(at[15], at[104]);    MULADD(at[16], at[103]);    MULADD(at[17], at[102]);    MULADD(at[18], at[101]);    MULADD(at[19], at[100]);    MULADD(at[20], at[99]);    MULADD(at[21], at[98]);    MULADD(at[22], at[97]);    MULADD(at[23], at[96]);    MULADD(at[24], at[95]);    MULADD(at[25], at[94]);    MULADD(at[26], at[93]);    MULADD(at[27], at[92]);    MULADD(at[28], at[91]);    MULADD(at[29], at[90]);    MULADD(at[30], at[89]);    MULADD(at[31], at[88]);    MULADD(at[32], at[87]);    MULADD(at[33], at[86]);    MULADD(at[34], at[85]);    MULADD(at[35], at[84]);    MULADD(at[36], at[83]);    MULADD(at[37], at[82]);    MULADD(at[38], at[81]);    MULADD(at[39], at[80]);    MULADD(at[40], at[79]);    MULADD(at[41], at[78]);    MULADD(at[42], at[77]);    MULADD(at[43], at[76]);    MULADD(at[44], at[75]);    MULADD(at[45], at[74]);    MULADD(at[46], at[73]);    MULADD(at[47], at[72]);    MULADD(at[48], at[71]);    MULADD(at[49], at[70]);    MULADD(at[50], at[69]);    MULADD(at[51], at[68]);    MULADD(at[52], at[67]);    MULADD(at[53], at[66]);    MULADD(at[54], at[65]);    MULADD(at[55], at[64]); 
   COMBA_STORE(C->dp[55]);
   /* 56 */
   COMBA_FORWARD;
   MULADD(at[0], at[120]);    MULADD(at[1], at[119]);    MULADD(at[2], at[118]);    MULADD(at[3], at[117]);    MULADD(at[4], at[116]);    MULADD(at[5], at[115]);    MULADD(at[6], at[114]);    MULADD(at[7], at[113]);    MULADD(at[8], at[112]);    MULADD(at[9], at[111]);    MULADD(at[10], at[110]);    MULADD(at[11], at[109]);    MULADD(at[12], at[108]);    MULADD(at[13], at[107]);    MULADD(at[14], at[106]);    MULADD(at[15], at[105]);    MULADD(at[16], at[104]);    MULADD(at[17], at[103]);    MULADD(at[18], at[102]);    MULADD(at[19], at[101]);    MULADD(at[20], at[100]);    MULADD(at[21], at[99]);    MULADD(at[22], at[98]);    MULADD(at[23], at[97]);    MULADD(at[24], at[96]);    MULADD(at[25], at[95]);    MULADD(at[26], at[94]);    MULADD(at[27], at[93]);    MULADD(at[28], at[92]);    MULADD(at[29], at[91]);    MULADD(at[30], at[90]);    MULADD(at[31], at[89]);    MULADD(at[32], at[88]);    MULADD(at[33], at[87]);    MULADD(at[34], at[86]);    MULADD(at[35], at[85]);    MULADD(at[36], at[84]);    MULADD(at[37], at[83]);    MULADD(at[38], at[82]);    MULADD(at[39], at[81]);    MULADD(at[40], at[80]);    MULADD(at[41], at[79]);    MULADD(at[42], at[78]);    MULADD(at[43], at[77]);    MULADD(at[44], at[76]);    MULADD(at[45], at[75]);    MULADD(at[46], at[74]);    MULADD(at[47], at[73]);    MULADD(at[48], at[72]);    MULADD(at[49], at[71]);    MULADD(at[50], at[70]);    MULADD(at[51], at[69]);    MULADD(at[52], at[68]);    MULADD(at[53], at[67]);    MULADD(at[54], at[66]);    MULADD(at[55], at[65]);    MULADD(at[56], at[64]); 
   COMBA_STORE(C->dp[56]);
   /* 57 */
   COMBA_FORWARD;
   MULADD(at[0], at[121]);    MULADD(at[1], at[120]);    MULADD(at[2], at[119]);    MULADD(at[3], at[118]);    MULADD(at[4], at[117]);    MULADD(at[5], at[116]);    MULADD(at[6], at[115]);    MULADD(at[7], at[114]);    MULADD(at[8], at[113]);    MULADD(at[9], at[112]);    MULADD(at[10], at[111]);    MULADD(at[11], at[110]);    MULADD(at[12], at[109]);    MULADD(at[13], at[108]);    MULADD(at[14], at[107]);    MULADD(at[15], at[106]);    MULADD(at[16], at[105]);    MULADD(at[17], at[104]);    MULADD(at[18], at[103]);    MULADD(at[19], at[102]);    MULADD(at[20], at[101]);    MULADD(at[21], at[100]);    MULADD(at[22], at[99]);    MULADD(at[23], at[98]);    MULADD(at[24], at[97]);    MULADD(at[25], at[96]);    MULADD(at[26], at[95]);    MULADD(at[27], at[94]);    MULADD(at[28], at[93]);    MULADD(at[29], at[92]);    MULADD(at[30], at[91]);    MULADD(at[31], at[90]);    MULADD(at[32], at[89]);    MULADD(at[33], at[88]);    MULADD(at[34], at[87]);    MULADD(at[35], at[86]);    MULADD(at[36], at[85]);    MULADD(at[37], at[84]);    MULADD(at[38], at[83]);    MULADD(at[39], at[82]);    MULADD(at[40], at[81]);    MULADD(at[41], at[80]);    MULADD(at[42], at[79]);    MULADD(at[43], at[78]);    MULADD(at[44], at[77]);    MULADD(at[45], at[76]);    MULADD(at[46], at[75]);    MULADD(at[47], at[74]);    MULADD(at[48], at[73]);    MULADD(at[49], at[72]);    MULADD(at[50], at[71]);    MULADD(at[51], at[70]);    MULADD(at[52], at[69]);    MULADD(at[53], at[68]);    MULADD(at[54], at[67]);    MULADD(at[55], at[66]);    MULADD(at[56], at[65]);    MULADD(at[57], at[64]); 
   COMBA_STORE(C->dp[57]);
   /* 58 */
   COMBA_FORWARD;
   MULADD(at[0], at[122]);    MULADD(at[1], at[121]);    MULADD(at[2], at[120]);    MULADD(at[3], at[119]);    MULADD(at[4], at[118]);    MULADD(at[5], at[117]);    MULADD(at[6], at[116]);    MULADD(at[7], at[115]);    MULADD(at[8], at[114]);    MULADD(at[9], at[113]);    MULADD(at[10], at[112]);    MULADD(at[11], at[111]);    MULADD(at[12], at[110]);    MULADD(at[13], at[109]);    MULADD(at[14], at[108]);    MULADD(at[15], at[107]);    MULADD(at[16], at[106]);    MULADD(at[17], at[105]);    MULADD(at[18], at[104]);    MULADD(at[19], at[103]);    MULADD(at[20], at[102]);    MULADD(at[21], at[101]);    MULADD(at[22], at[100]);    MULADD(at[23], at[99]);    MULADD(at[24], at[98]);    MULADD(at[25], at[97]);    MULADD(at[26], at[96]);    MULADD(at[27], at[95]);    MULADD(at[28], at[94]);    MULADD(at[29], at[93]);    MULADD(at[30], at[92]);    MULADD(at[31], at[91]);    MULADD(at[32], at[90]);    MULADD(at[33], at[89]);    MULADD(at[34], at[88]);    MULADD(at[35], at[87]);    MULADD(at[36], at[86]);    MULADD(at[37], at[85]);    MULADD(at[38], at[84]);    MULADD(at[39], at[83]);    MULADD(at[40], at[82]);    MULADD(at[41], at[81]);    MULADD(at[42], at[80]);    MULADD(at[43], at[79]);    MULADD(at[44], at[78]);    MULADD(at[45], at[77]);    MULADD(at[46], at[76]);    MULADD(at[47], at[75]);    MULADD(at[48], at[74]);    MULADD(at[49], at[73]);    MULADD(at[50], at[72]);    MULADD(at[51], at[71]);    MULADD(at[52], at[70]);    MULADD(at[53], at[69]);    MULADD(at[54], at[68]);    MULADD(at[55], at[67]);    MULADD(at[56], at[66]);    MULADD(at[57], at[65]);    MULADD(at[58], at[64]); 
   COMBA_STORE(C->dp[58]);
   /* 59 */
   COMBA_FORWARD;
   MULADD(at[0], at[123]);    MULADD(at[1], at[122]);    MULADD(at[2], at[121]);    MULADD(at[3], at[120]);    MULADD(at[4], at[119]);    MULADD(at[5], at[118]);    MULADD(at[6], at[117]);    MULADD(at[7], at[116]);    MULADD(at[8], at[115]);    MULADD(at[9], at[114]);    MULADD(at[10], at[113]);    MULADD(at[11], at[112]);    MULADD(at[12], at[111]);    MULADD(at[13], at[110]);    MULADD(at[14], at[109]);    MULADD(at[15], at[108]);    MULADD(at[16], at[107]);    MULADD(at[17], at[106]);    MULADD(at[18], at[105]);    MULADD(at[19], at[104]);    MULADD(at[20], at[103]);    MULADD(at[21], at[102]);    MULADD(at[22], at[101]);    MULADD(at[23], at[100]);    MULADD(at[24], at[99]);    MULADD(at[25], at[98]);    MULADD(at[26], at[97]);    MULADD(at[27], at[96]);    MULADD(at[28], at[95]);    MULADD(at[29], at[94]);    MULADD(at[30], at[93]);    MULADD(at[31], at[92]);    MULADD(at[32], at[91]);    MULADD(at[33], at[90]);    MULADD(at[34], at[89]);    MULADD(at[35], at[88]);    MULADD(at[36], at[87]);    MULADD(at[37], at[86]);    MULADD(at[38], at[85]);    MULADD(at[39], at[84]);    MULADD(at[40], at[83]);    MULADD(at[41], at[82]);    MULADD(at[42], at[81]);    MULADD(at[43], at[80]);    MULADD(at[44], at[79]);    MULADD(at[45], at[78]);    MULADD(at[46], at[77]);    MULADD(at[47], at[76]);    MULADD(at[48], at[75]);    MULADD(at[49], at[74]);    MULADD(at[50], at[73]);    MULADD(at[51], at[72]);    MULADD(at[52], at[71]);    MULADD(at[53], at[70]);    MULADD(at[54], at[69]);    MULADD(at[55], at[68]);    MULADD(at[56], at[67]);    MULADD(at[57], at[66]);    MULADD(at[58], at[65]);    MULADD(at[59], at[64]); 
   COMBA_STORE(C->dp[59]);
   /* 60 */
   COMBA_FORWARD;
   MULADD(at[0], at[124]);    MULADD(at[1], at[123]);    MULADD(at[2], at[122]);    MULADD(at[3], at[121]);    MULADD(at[4], at[120]);    MULADD(at[5], at[119]);    MULADD(at[6], at[118]);    MULADD(at[7], at[117]);    MULADD(at[8], at[116]);    MULADD(at[9], at[115]);    MULADD(at[10], at[114]);    MULADD(at[11], at[113]);    MULADD(at[12], at[112]);    MULADD(at[13], at[111]);    MULADD(at[14], at[110]);    MULADD(at[15], at[109]);    MULADD(at[16], at[108]);    MULADD(at[17], at[107]);    MULADD(at[18], at[106]);    MULADD(at[19], at[105]);    MULADD(at[20], at[104]);    MULADD(at[21], at[103]);    MULADD(at[22], at[102]);    MULADD(at[23], at[101]);    MULADD(at[24], at[100]);    MULADD(at[25], at[99]);    MULADD(at[26], at[98]);    MULADD(at[27], at[97]);    MULADD(at[28], at[96]);    MULADD(at[29], at[95]);    MULADD(at[30], at[94]);    MULADD(at[31], at[93]);    MULADD(at[32], at[92]);    MULADD(at[33], at[91]);    MULADD(at[34], at[90]);    MULADD(at[35], at[89]);    MULADD(at[36], at[88]);    MULADD(at[37], at[87]);    MULADD(at[38], at[86]);    MULADD(at[39], at[85]);    MULADD(at[40], at[84]);    MULADD(at[41], at[83]);    MULADD(at[42], at[82]);    MULADD(at[43], at[81]);    MULADD(at[44], at[80]);    MULADD(at[45], at[79]);    MULADD(at[46], at[78]);    MULADD(at[47], at[77]);    MULADD(at[48], at[76]);    MULADD(at[49], at[75]);    MULADD(at[50], at[74]);    MULADD(at[51], at[73]);    MULADD(at[52], at[72]);    MULADD(at[53], at[71]);    MULADD(at[54], at[70]);    MULADD(at[55], at[69]);    MULADD(at[56], at[68]);    MULADD(at[57], at[67]);    MULADD(at[58], at[66]);    MULADD(at[59], at[65]);    MULADD(at[60], at[64]); 
   COMBA_STORE(C->dp[60]);
   /* 61 */
   COMBA_FORWARD;
   MULADD(at[0], at[125]);    MULADD(at[1], at[124]);    MULADD(at[2], at[123]);    MULADD(at[3], at[122]);    MULADD(at[4], at[121]);    MULADD(at[5], at[120]);    MULADD(at[6], at[119]);    MULADD(at[7], at[118]);    MULADD(at[8], at[117]);    MULADD(at[9], at[116]);    MULADD(at[10], at[115]);    MULADD(at[11], at[114]);    MULADD(at[12], at[113]);    MULADD(at[13], at[112]);    MULADD(at[14], at[111]);    MULADD(at[15], at[110]);    MULADD(at[16], at[109]);    MULADD(at[17], at[108]);    MULADD(at[18], at[107]);    MULADD(at[19], at[106]);    MULADD(at[20], at[105]);    MULADD(at[21], at[104]);    MULADD(at[22], at[103]);    MULADD(at[23], at[102]);    MULADD(at[24], at[101]);    MULADD(at[25], at[100]);    MULADD(at[26], at[99]);    MULADD(at[27], at[98]);    MULADD(at[28], at[97]);    MULADD(at[29], at[96]);    MULADD(at[30], at[95]);    MULADD(at[31], at[94]);    MULADD(at[32], at[93]);    MULADD(at[33], at[92]);    MULADD(at[34], at[91]);    MULADD(at[35], at[90]);    MULADD(at[36], at[89]);    MULADD(at[37], at[88]);    MULADD(at[38], at[87]);    MULADD(at[39], at[86]);    MULADD(at[40], at[85]);    MULADD(at[41], at[84]);    MULADD(at[42], at[83]);    MULADD(at[43], at[82]);    MULADD(at[44], at[81]);    MULADD(at[45], at[80]);    MULADD(at[46], at[79]);    MULADD(at[47], at[78]);    MULADD(at[48], at[77]);    MULADD(at[49], at[76]);    MULADD(at[50], at[75]);    MULADD(at[51], at[74]);    MULADD(at[52], at[73]);    MULADD(at[53], at[72]);    MULADD(at[54], at[71]);    MULADD(at[55], at[70]);    MULADD(at[56], at[69]);    MULADD(at[57], at[68]);    MULADD(at[58], at[67]);    MULADD(at[59], at[66]);    MULADD(at[60], at[65]);    MULADD(at[61], at[64]); 
   COMBA_STORE(C->dp[61]);
   /* 62 */
   COMBA_FORWARD;
   MULADD(at[0], at[126]);    MULADD(at[1], at[125]);    MULADD(at[2], at[124]);    MULADD(at[3], at[123]);    MULADD(at[4], at[122]);    MULADD(at[5], at[121]);    MULADD(at[6], at[120]);    MULADD(at[7], at[119]);    MULADD(at[8], at[118]);    MULADD(at[9], at[117]);    MULADD(at[10], at[116]);    MULADD(at[11], at[115]);    MULADD(at[12], at[114]);    MULADD(at[13], at[113]);    MULADD(at[14], at[112]);    MULADD(at[15], at[111]);    MULADD(at[16], at[110]);    MULADD(at[17], at[109]);    MULADD(at[18], at[108]);    MULADD(at[19], at[107]);    MULADD(at[20], at[106]);    MULADD(at[21], at[105]);    MULADD(at[22], at[104]);    MULADD(at[23], at[103]);    MULADD(at[24], at[102]);    MULADD(at[25], at[101]);    MULADD(at[26], at[100]);    MULADD(at[27], at[99]);    MULADD(at[28], at[98]);    MULADD(at[29], at[97]);    MULADD(at[30], at[96]);    MULADD(at[31], at[95]);    MULADD(at[32], at[94]);    MULADD(at[33], at[93]);    MULADD(at[34], at[92]);    MULADD(at[35], at[91]);    MULADD(at[36], at[90]);    MULADD(at[37], at[89]);    MULADD(at[38], at[88]);    MULADD(at[39], at[87]);    MULADD(at[40], at[86]);    MULADD(at[41], at[85]);    MULADD(at[42], at[84]);    MULADD(at[43], at[83]);    MULADD(at[44], at[82]);    MULADD(at[45], at[81]);    MULADD(at[46], at[80]);    MULADD(at[47], at[79]);    MULADD(at[48], at[78]);    MULADD(at[49], at[77]);    MULADD(at[50], at[76]);    MULADD(at[51], at[75]);    MULADD(at[52], at[74]);    MULADD(at[53], at[73]);    MULADD(at[54], at[72]);    MULADD(at[55], at[71]);    MULADD(at[56], at[70]);    MULADD(at[57], at[69]);    MULADD(at[58], at[68]);    MULADD(at[59], at[67]);    MULADD(at[60], at[66]);    MULADD(at[61], at[65]);    MULADD(at[62], at[64]); 
   COMBA_STORE(C->dp[62]);
   /* 63 */
   COMBA_FORWARD;
   MULADD(at[0], at[127]);    MULADD(at[1], at[126]);    MULADD(at[2], at[125]);    MULADD(at[3], at[124]);    MULADD(at[4], at[123]);    MULADD(at[5], at[122]);    MULADD(at[6], at[121]);    MULADD(at[7], at[120]);    MULADD(at[8], at[119]);    MULADD(at[9], at[118]);    MULADD(at[10], at[117]);    MULADD(at[11], at[116]);    MULADD(at[12], at[115]);    MULADD(at[13], at[114]);    MULADD(at[14], at[113]);    MULADD(at[15], at[112]);    MULADD(at[16], at[111]);    MULADD(at[17], at[110]);    MULADD(at[18], at[109]);    MULADD(at[19], at[108]);    MULADD(at[20], at[107]);    MULADD(at[21], at[106]);    MULADD(at[22], at[105]);    MULADD(at[23], at[104]);    MULADD(at[24], at[103]);    MULADD(at[25], at[102]);    MULADD(at[26], at[101]);    MULADD(at[27], at[100]);    MULADD(at[28], at[99]);    MULADD(at[29], at[98]);    MULADD(at[30], at[97]);    MULADD(at[31], at[96]);    MULADD(at[32], at[95]);    MULADD(at[33], at[94]);    MULADD(at[34], at[93]);    MULADD(at[35], at[92]);    MULADD(at[36], at[91]);    MULADD(at[37], at[90]);    MULADD(at[38], at[89]);    MULADD(at[39], at[88]);    MULADD(at[40], at[87]);    MULADD(at[41], at[86]);    MULADD(at[42], at[85]);    MULADD(at[43], at[84]);    MULADD(at[44], at[83]);    MULADD(at[45], at[82]);    MULADD(at[46], at[81]);    MULADD(at[47], at[80]);    MULADD(at[48], at[79]);    MULADD(at[49], at[78]);    MULADD(at[50], at[77]);    MULADD(at[51], at[76]);    MULADD(at[52], at[75]);    MULADD(at[53], at[74]);    MULADD(at[54], at[73]);    MULADD(at[55], at[72]);    MULADD(at[56], at[71]);    MULADD(at[57], at[70]);    MULADD(at[58], at[69]);    MULADD(at[59], at[68]);    MULADD(at[60], at[67]);    MULADD(at[61], at[66]);    MULADD(at[62], at[65]);    MULADD(at[63], at[64]); 
   COMBA_STORE(C->dp[63]);
   /* 64 */
   COMBA_FORWARD;
   MULADD(at[1], at[127]);    MULADD(at[2], at[126]);    MULADD(at[3], at[125]);    MULADD(at[4], at[124]);    MULADD(at[5], at[123]);    MULADD(at[6], at[122]);    MULADD(at[7], at[121]);    MULADD(at[8], at[120]);    MULADD(at[9], at[119]);    MULADD(at[10], at[118]);    MULADD(at[11], at[117]);    MULADD(at[12], at[116]);    MULADD(at[13], at[115]);    MULADD(at[14], at[114]);    MULADD(at[15], at[113]);    MULADD(at[16], at[112]);    MULADD(at[17], at[111]);    MULADD(at[18], at[110]);    MULADD(at[19], at[109]);    MULADD(at[20], at[108]);    MULADD(at[21], at[107]);    MULADD(at[22], at[106]);    MULADD(at[23], at[105]);    MULADD(at[24], at[104]);    MULADD(at[25], at[103]);    MULADD(at[26], at[102]);    MULADD(at[27], at[101]);    MULADD(at[28], at[100]);    MULADD(at[29], at[99]);    MULADD(at[30], at[98]);    MULADD(at[31], at[97]);    MULADD(at[32], at[96]);    MULADD(at[33], at[95]);    MULADD(at[34], at[94]);    MULADD(at[35], at[93]);    MULADD(at[36], at[92]);    MULADD(at[37], at[91]);    MULADD(at[38], at[90]);    MULADD(at[39], at[89]);    MULADD(at[40], at[88]);    MULADD(at[41], at[87]);    MULADD(at[42], at[86]);    MULADD(at[43], at[85]);    MULADD(at[44], at[84]);    MULADD(at[45], at[83]);    MULADD(at[46], at[82]);    MULADD(at[47], at[81]);    MULADD(at[48], at[80]);    MULADD(at[49], at[79]);    MULADD(at[50], at[78]);    MULADD(at[51], at[77]);    MULADD(at[52], at[76]);    MULADD(at[53], at[75]);    MULADD(at[54], at[74]);    MULADD(at[55], at[73]);    MULADD(at[56], at[72]);    MULADD(at[57], at[71]);    MULADD(at[58], at[70]);    MULADD(at[59], at[69]);    MULADD(at[60], at[68]);    MULADD(at[61], at[67]);    MULADD(at[62], at[66]);    MULADD(at[63], at[65]); 
   COMBA_STORE(C->dp[64]);
   /* 65 */
   COMBA_FORWARD;
   MULADD(at[2], at[127]);    MULADD(at[3], at[126]);    MULADD(at[4], at[125]);    MULADD(at[5], at[124]);    MULADD(at[6], at[123]);    MULADD(at[7], at[122]);    MULADD(at[8], at[121]);    MULADD(at[9], at[120]);    MULADD(at[10], at[119]);    MULADD(at[11], at[118]);    MULADD(at[12], at[117]);    MULADD(at[13], at[116]);    MULADD(at[14], at[115]);    MULADD(at[15], at[114]);    MULADD(at[16], at[113]);    MULADD(at[17], at[112]);    MULADD(at[18], at[111]);    MULADD(at[19], at[110]);    MULADD(at[20], at[109]);    MULADD(at[21], at[108]);    MULADD(at[22], at[107]);    MULADD(at[23], at[106]);    MULADD(at[24], at[105]);    MULADD(at[25], at[104]);    MULADD(at[26], at[103]);    MULADD(at[27], at[102]);    MULADD(at[28], at[101]);    MULADD(at[29], at[100]);    MULADD(at[30], at[99]);    MULADD(at[31], at[98]);    MULADD(at[32], at[97]);    MULADD(at[33], at[96]);    MULADD(at[34], at[95]);    MULADD(at[35], at[94]);    MULADD(at[36], at[93]);    MULADD(at[37], at[92]);    MULADD(at[38], at[91]);    MULADD(at[39], at[90]);    MULADD(at[40], at[89]);    MULADD(at[41], at[88]);    MULADD(at[42], at[87]);    MULADD(at[43], at[86]);    MULADD(at[44], at[85]);    MULADD(at[45], at[84]);    MULADD(at[46], at[83]);    MULADD(at[47], at[82]);    MULADD(at[48], at[81]);    MULADD(at[49], at[80]);    MULADD(at[50], at[79]);    MULADD(at[51], at[78]);    MULADD(at[52], at[77]);    MULADD(at[53], at[76]);    MULADD(at[54], at[75]);    MULADD(at[55], at[74]);    MULADD(at[56], at[73]);    MULADD(at[57], at[72]);    MULADD(at[58], at[71]);    MULADD(at[59], at[70]);    MULADD(at[60], at[69]);    MULADD(at[61], at[68]);    MULADD(at[62], at[67]);    MULADD(at[63], at[66]); 
   COMBA_STORE(C->dp[65]);
   /* 66 */
   COMBA_FORWARD;
   MULADD(at[3], at[127]);    MULADD(at[4], at[126]);    MULADD(at[5], at[125]);    MULADD(at[6], at[124]);    MULADD(at[7], at[123]);    MULADD(at[8], at[122]);    MULADD(at[9], at[121]);    MULADD(at[10], at[120]);    MULADD(at[11], at[119]);    MULADD(at[12], at[118]);    MULADD(at[13], at[117]);    MULADD(at[14], at[116]);    MULADD(at[15], at[115]);    MULADD(at[16], at[114]);    MULADD(at[17], at[113]);    MULADD(at[18], at[112]);    MULADD(at[19], at[111]);    MULADD(at[20], at[110]);    MULADD(at[21], at[109]);    MULADD(at[22], at[108]);    MULADD(at[23], at[107]);    MULADD(at[24], at[106]);    MULADD(at[25], at[105]);    MULADD(at[26], at[104]);    MULADD(at[27], at[103]);    MULADD(at[28], at[102]);    MULADD(at[29], at[101]);    MULADD(at[30], at[100]);    MULADD(at[31], at[99]);    MULADD(at[32], at[98]);    MULADD(at[33], at[97]);    MULADD(at[34], at[96]);    MULADD(at[35], at[95]);    MULADD(at[36], at[94]);    MULADD(at[37], at[93]);    MULADD(at[38], at[92]);    MULADD(at[39], at[91]);    MULADD(at[40], at[90]);    MULADD(at[41], at[89]);    MULADD(at[42], at[88]);    MULADD(at[43], at[87]);    MULADD(at[44], at[86]);    MULADD(at[45], at[85]);    MULADD(at[46], at[84]);    MULADD(at[47], at[83]);    MULADD(at[48], at[82]);    MULADD(at[49], at[81]);    MULADD(at[50], at[80]);    MULADD(at[51], at[79]);    MULADD(at[52], at[78]);    MULADD(at[53], at[77]);    MULADD(at[54], at[76]);    MULADD(at[55], at[75]);    MULADD(at[56], at[74]);    MULADD(at[57], at[73]);    MULADD(at[58], at[72]);    MULADD(at[59], at[71]);    MULADD(at[60], at[70]);    MULADD(at[61], at[69]);    MULADD(at[62], at[68]);    MULADD(at[63], at[67]); 
   COMBA_STORE(C->dp[66]);
   /* 67 */
   COMBA_FORWARD;
   MULADD(at[4], at[127]);    MULADD(at[5], at[126]);    MULADD(at[6], at[125]);    MULADD(at[7], at[124]);    MULADD(at[8], at[123]);    MULADD(at[9], at[122]);    MULADD(at[10], at[121]);    MULADD(at[11], at[120]);    MULADD(at[12], at[119]);    MULADD(at[13], at[118]);    MULADD(at[14], at[117]);    MULADD(at[15], at[116]);    MULADD(at[16], at[115]);    MULADD(at[17], at[114]);    MULADD(at[18], at[113]);    MULADD(at[19], at[112]);    MULADD(at[20], at[111]);    MULADD(at[21], at[110]);    MULADD(at[22], at[109]);    MULADD(at[23], at[108]);    MULADD(at[24], at[107]);    MULADD(at[25], at[106]);    MULADD(at[26], at[105]);    MULADD(at[27], at[104]);    MULADD(at[28], at[103]);    MULADD(at[29], at[102]);    MULADD(at[30], at[101]);    MULADD(at[31], at[100]);    MULADD(at[32], at[99]);    MULADD(at[33], at[98]);    MULADD(at[34], at[97]);    MULADD(at[35], at[96]);    MULADD(at[36], at[95]);    MULADD(at[37], at[94]);    MULADD(at[38], at[93]);    MULADD(at[39], at[92]);    MULADD(at[40], at[91]);    MULADD(at[41], at[90]);    MULADD(at[42], at[89]);    MULADD(at[43], at[88]);    MULADD(at[44], at[87]);    MULADD(at[45], at[86]);    MULADD(at[46], at[85]);    MULADD(at[47], at[84]);    MULADD(at[48], at[83]);    MULADD(at[49], at[82]);    MULADD(at[50], at[81]);    MULADD(at[51], at[80]);    MULADD(at[52], at[79]);    MULADD(at[53], at[78]);    MULADD(at[54], at[77]);    MULADD(at[55], at[76]);    MULADD(at[56], at[75]);    MULADD(at[57], at[74]);    MULADD(at[58], at[73]);    MULADD(at[59], at[72]);    MULADD(at[60], at[71]);    MULADD(at[61], at[70]);    MULADD(at[62], at[69]);    MULADD(at[63], at[68]); 
   COMBA_STORE(C->dp[67]);
   /* 68 */
   COMBA_FORWARD;
   MULADD(at[5], at[127]);    MULADD(at[6], at[126]);    MULADD(at[7], at[125]);    MULADD(at[8], at[124]);    MULADD(at[9], at[123]);    MULADD(at[10], at[122]);    MULADD(at[11], at[121]);    MULADD(at[12], at[120]);    MULADD(at[13], at[119]);    MULADD(at[14], at[118]);    MULADD(at[15], at[117]);    MULADD(at[16], at[116]);    MULADD(at[17], at[115]);    MULADD(at[18], at[114]);    MULADD(at[19], at[113]);    MULADD(at[20], at[112]);    MULADD(at[21], at[111]);    MULADD(at[22], at[110]);    MULADD(at[23], at[109]);    MULADD(at[24], at[108]);    MULADD(at[25], at[107]);    MULADD(at[26], at[106]);    MULADD(at[27], at[105]);    MULADD(at[28], at[104]);    MULADD(at[29], at[103]);    MULADD(at[30], at[102]);    MULADD(at[31], at[101]);    MULADD(at[32], at[100]);    MULADD(at[33], at[99]);    MULADD(at[34], at[98]);    MULADD(at[35], at[97]);    MULADD(at[36], at[96]);    MULADD(at[37], at[95]);    MULADD(at[38], at[94]);    MULADD(at[39], at[93]);    MULADD(at[40], at[92]);    MULADD(at[41], at[91]);    MULADD(at[42], at[90]);    MULADD(at[43], at[89]);    MULADD(at[44], at[88]);    MULADD(at[45], at[87]);    MULADD(at[46], at[86]);    MULADD(at[47], at[85]);    MULADD(at[48], at[84]);    MULADD(at[49], at[83]);    MULADD(at[50], at[82]);    MULADD(at[51], at[81]);    MULADD(at[52], at[80]);    MULADD(at[53], at[79]);    MULADD(at[54], at[78]);    MULADD(at[55], at[77]);    MULADD(at[56], at[76]);    MULADD(at[57], at[75]);    MULADD(at[58], at[74]);    MULADD(at[59], at[73]);    MULADD(at[60], at[72]);    MULADD(at[61], at[71]);    MULADD(at[62], at[70]);    MULADD(at[63], at[69]); 
   COMBA_STORE(C->dp[68]);
   /* 69 */
   COMBA_FORWARD;
   MULADD(at[6], at[127]);    MULADD(at[7], at[126]);    MULADD(at[8], at[125]);    MULADD(at[9], at[124]);    MULADD(at[10], at[123]);    MULADD(at[11], at[122]);    MULADD(at[12], at[121]);    MULADD(at[13], at[120]);    MULADD(at[14], at[119]);    MULADD(at[15], at[118]);    MULADD(at[16], at[117]);    MULADD(at[17], at[116]);    MULADD(at[18], at[115]);    MULADD(at[19], at[114]);    MULADD(at[20], at[113]);    MULADD(at[21], at[112]);    MULADD(at[22], at[111]);    MULADD(at[23], at[110]);    MULADD(at[24], at[109]);    MULADD(at[25], at[108]);    MULADD(at[26], at[107]);    MULADD(at[27], at[106]);    MULADD(at[28], at[105]);    MULADD(at[29], at[104]);    MULADD(at[30], at[103]);    MULADD(at[31], at[102]);    MULADD(at[32], at[101]);    MULADD(at[33], at[100]);    MULADD(at[34], at[99]);    MULADD(at[35], at[98]);    MULADD(at[36], at[97]);    MULADD(at[37], at[96]);    MULADD(at[38], at[95]);    MULADD(at[39], at[94]);    MULADD(at[40], at[93]);    MULADD(at[41], at[92]);    MULADD(at[42], at[91]);    MULADD(at[43], at[90]);    MULADD(at[44], at[89]);    MULADD(at[45], at[88]);    MULADD(at[46], at[87]);    MULADD(at[47], at[86]);    MULADD(at[48], at[85]);    MULADD(at[49], at[84]);    MULADD(at[50], at[83]);    MULADD(at[51], at[82]);    MULADD(at[52], at[81]);    MULADD(at[53], at[80]);    MULADD(at[54], at[79]);    MULADD(at[55], at[78]);    MULADD(at[56], at[77]);    MULADD(at[57], at[76]);    MULADD(at[58], at[75]);    MULADD(at[59], at[74]);    MULADD(at[60], at[73]);    MULADD(at[61], at[72]);    MULADD(at[62], at[71]);    MULADD(at[63], at[70]); 
   COMBA_STORE(C->dp[69]);
   /* 70 */
   COMBA_FORWARD;
   MULADD(at[7], at[127]);    MULADD(at[8], at[126]);    MULADD(at[9], at[125]);    MULADD(at[10], at[124]);    MULADD(at[11], at[123]);    MULADD(at[12], at[122]);    MULADD(at[13], at[121]);    MULADD(at[14], at[120]);    MULADD(at[15], at[119]);    MULADD(at[16], at[118]);    MULADD(at[17], at[117]);    MULADD(at[18], at[116]);    MULADD(at[19], at[115]);    MULADD(at[20], at[114]);    MULADD(at[21], at[113]);    MULADD(at[22], at[112]);    MULADD(at[23], at[111]);    MULADD(at[24], at[110]);    MULADD(at[25], at[109]);    MULADD(at[26], at[108]);    MULADD(at[27], at[107]);    MULADD(at[28], at[106]);    MULADD(at[29], at[105]);    MULADD(at[30], at[104]);    MULADD(at[31], at[103]);    MULADD(at[32], at[102]);    MULADD(at[33], at[101]);    MULADD(at[34], at[100]);    MULADD(at[35], at[99]);    MULADD(at[36], at[98]);    MULADD(at[37], at[97]);    MULADD(at[38], at[96]);    MULADD(at[39], at[95]);    MULADD(at[40], at[94]);    MULADD(at[41], at[93]);    MULADD(at[42], at[92]);    MULADD(at[43], at[91]);    MULADD(at[44], at[90]);    MULADD(at[45], at[89]);    MULADD(at[46], at[88]);    MULADD(at[47], at[87]);    MULADD(at[48], at[86]);    MULADD(at[49], at[85]);    MULADD(at[50], at[84]);    MULADD(at[51], at[83]);    MULADD(at[52], at[82]);    MULADD(at[53], at[81]);    MULADD(at[54], at[80]);    MULADD(at[55], at[79]);    MULADD(at[56], at[78]);    MULADD(at[57], at[77]);    MULADD(at[58], at[76]);    MULADD(at[59], at[75]);    MULADD(at[60], at[74]);    MULADD(at[61], at[73]);    MULADD(at[62], at[72]);    MULADD(at[63], at[71]); 
   COMBA_STORE(C->dp[70]);
   /* 71 */
   COMBA_FORWARD;
   MULADD(at[8], at[127]);    MULADD(at[9], at[126]);    MULADD(at[10], at[125]);    MULADD(at[11], at[124]);    MULADD(at[12], at[123]);    MULADD(at[13], at[122]);    MULADD(at[14], at[121]);    MULADD(at[15], at[120]);    MULADD(at[16], at[119]);    MULADD(at[17], at[118]);    MULADD(at[18], at[117]);    MULADD(at[19], at[116]);    MULADD(at[20], at[115]);    MULADD(at[21], at[114]);    MULADD(at[22], at[113]);    MULADD(at[23], at[112]);    MULADD(at[24], at[111]);    MULADD(at[25], at[110]);    MULADD(at[26], at[109]);    MULADD(at[27], at[108]);    MULADD(at[28], at[107]);    MULADD(at[29], at[106]);    MULADD(at[30], at[105]);    MULADD(at[31], at[104]);    MULADD(at[32], at[103]);    MULADD(at[33], at[102]);    MULADD(at[34], at[101]);    MULADD(at[35], at[100]);    MULADD(at[36], at[99]);    MULADD(at[37], at[98]);    MULADD(at[38], at[97]);    MULADD(at[39], at[96]);    MULADD(at[40], at[95]);    MULADD(at[41], at[94]);    MULADD(at[42], at[93]);    MULADD(at[43], at[92]);    MULADD(at[44], at[91]);    MULADD(at[45], at[90]);    MULADD(at[46], at[89]);    MULADD(at[47], at[88]);    MULADD(at[48], at[87]);    MULADD(at[49], at[86]);    MULADD(at[50], at[85]);    MULADD(at[51], at[84]);    MULADD(at[52], at[83]);    MULADD(at[53], at[82]);    MULADD(at[54], at[81]);    MULADD(at[55], at[80]);    MULADD(at[56], at[79]);    MULADD(at[57], at[78]);    MULADD(at[58], at[77]);    MULADD(at[59], at[76]);    MULADD(at[60], at[75]);    MULADD(at[61], at[74]);    MULADD(at[62], at[73]);    MULADD(at[63], at[72]); 
   COMBA_STORE(C->dp[71]);
   /* 72 */
   COMBA_FORWARD;
   MULADD(at[9], at[127]);    MULADD(at[10], at[126]);    MULADD(at[11], at[125]);    MULADD(at[12], at[124]);    MULADD(at[13], at[123]);    MULADD(at[14], at[122]);    MULADD(at[15], at[121]);    MULADD(at[16], at[120]);    MULADD(at[17], at[119]);    MULADD(at[18], at[118]);    MULADD(at[19], at[117]);    MULADD(at[20], at[116]);    MULADD(at[21], at[115]);    MULADD(at[22], at[114]);    MULADD(at[23], at[113]);    MULADD(at[24], at[112]);    MULADD(at[25], at[111]);    MULADD(at[26], at[110]);    MULADD(at[27], at[109]);    MULADD(at[28], at[108]);    MULADD(at[29], at[107]);    MULADD(at[30], at[106]);    MULADD(at[31], at[105]);    MULADD(at[32], at[104]);    MULADD(at[33], at[103]);    MULADD(at[34], at[102]);    MULADD(at[35], at[101]);    MULADD(at[36], at[100]);    MULADD(at[37], at[99]);    MULADD(at[38], at[98]);    MULADD(at[39], at[97]);    MULADD(at[40], at[96]);    MULADD(at[41], at[95]);    MULADD(at[42], at[94]);    MULADD(at[43], at[93]);    MULADD(at[44], at[92]);    MULADD(at[45], at[91]);    MULADD(at[46], at[90]);    MULADD(at[47], at[89]);    MULADD(at[48], at[88]);    MULADD(at[49], at[87]);    MULADD(at[50], at[86]);    MULADD(at[51], at[85]);    MULADD(at[52], at[84]);    MULADD(at[53], at[83]);    MULADD(at[54], at[82]);    MULADD(at[55], at[81]);    MULADD(at[56], at[80]);    MULADD(at[57], at[79]);    MULADD(at[58], at[78]);    MULADD(at[59], at[77]);    MULADD(at[60], at[76]);    MULADD(at[61], at[75]);    MULADD(at[62], at[74]);    MULADD(at[63], at[73]); 
   COMBA_STORE(C->dp[72]);
   /* 73 */
   COMBA_FORWARD;
   MULADD(at[10], at[127]);    MULADD(at[11], at[126]);    MULADD(at[12], at[125]);    MULADD(at[13], at[124]);    MULADD(at[14], at[123]);    MULADD(at[15], at[122]);    MULADD(at[16], at[121]);    MULADD(at[17], at[120]);    MULADD(at[18], at[119]);    MULADD(at[19], at[118]);    MULADD(at[20], at[117]);    MULADD(at[21], at[116]);    MULADD(at[22], at[115]);    MULADD(at[23], at[114]);    MULADD(at[24], at[113]);    MULADD(at[25], at[112]);    MULADD(at[26], at[111]);    MULADD(at[27], at[110]);    MULADD(at[28], at[109]);    MULADD(at[29], at[108]);    MULADD(at[30], at[107]);    MULADD(at[31], at[106]);    MULADD(at[32], at[105]);    MULADD(at[33], at[104]);    MULADD(at[34], at[103]);    MULADD(at[35], at[102]);    MULADD(at[36], at[101]);    MULADD(at[37], at[100]);    MULADD(at[38], at[99]);    MULADD(at[39], at[98]);    MULADD(at[40], at[97]);    MULADD(at[41], at[96]);    MULADD(at[42], at[95]);    MULADD(at[43], at[94]);    MULADD(at[44], at[93]);    MULADD(at[45], at[92]);    MULADD(at[46], at[91]);    MULADD(at[47], at[90]);    MULADD(at[48], at[89]);    MULADD(at[49], at[88]);    MULADD(at[50], at[87]);    MULADD(at[51], at[86]);    MULADD(at[52], at[85]);    MULADD(at[53], at[84]);    MULADD(at[54], at[83]);    MULADD(at[55], at[82]);    MULADD(at[56], at[81]);    MULADD(at[57], at[80]);    MULADD(at[58], at[79]);    MULADD(at[59], at[78]);    MULADD(at[60], at[77]);    MULADD(at[61], at[76]);    MULADD(at[62], at[75]);    MULADD(at[63], at[74]); 
   COMBA_STORE(C->dp[73]);
   /* 74 */
   COMBA_FORWARD;
   MULADD(at[11], at[127]);    MULADD(at[12], at[126]);    MULADD(at[13], at[125]);    MULADD(at[14], at[124]);    MULADD(at[15], at[123]);    MULADD(at[16], at[122]);    MULADD(at[17], at[121]);    MULADD(at[18], at[120]);    MULADD(at[19], at[119]);    MULADD(at[20], at[118]);    MULADD(at[21], at[117]);    MULADD(at[22], at[116]);    MULADD(at[23], at[115]);    MULADD(at[24], at[114]);    MULADD(at[25], at[113]);    MULADD(at[26], at[112]);    MULADD(at[27], at[111]);    MULADD(at[28], at[110]);    MULADD(at[29], at[109]);    MULADD(at[30], at[108]);    MULADD(at[31], at[107]);    MULADD(at[32], at[106]);    MULADD(at[33], at[105]);    MULADD(at[34], at[104]);    MULADD(at[35], at[103]);    MULADD(at[36], at[102]);    MULADD(at[37], at[101]);    MULADD(at[38], at[100]);    MULADD(at[39], at[99]);    MULADD(at[40], at[98]);    MULADD(at[41], at[97]);    MULADD(at[42], at[96]);    MULADD(at[43], at[95]);    MULADD(at[44], at[94]);    MULADD(at[45], at[93]);    MULADD(at[46], at[92]);    MULADD(at[47], at[91]);    MULADD(at[48], at[90]);    MULADD(at[49], at[89]);    MULADD(at[50], at[88]);    MULADD(at[51], at[87]);    MULADD(at[52], at[86]);    MULADD(at[53], at[85]);    MULADD(at[54], at[84]);    MULADD(at[55], at[83]);    MULADD(at[56], at[82]);    MULADD(at[57], at[81]);    MULADD(at[58], at[80]);    MULADD(at[59], at[79]);    MULADD(at[60], at[78]);    MULADD(at[61], at[77]);    MULADD(at[62], at[76]);    MULADD(at[63], at[75]); 
   COMBA_STORE(C->dp[74]);
   /* 75 */
   COMBA_FORWARD;
   MULADD(at[12], at[127]);    MULADD(at[13], at[126]);    MULADD(at[14], at[125]);    MULADD(at[15], at[124]);    MULADD(at[16], at[123]);    MULADD(at[17], at[122]);    MULADD(at[18], at[121]);    MULADD(at[19], at[120]);    MULADD(at[20], at[119]);    MULADD(at[21], at[118]);    MULADD(at[22], at[117]);    MULADD(at[23], at[116]);    MULADD(at[24], at[115]);    MULADD(at[25], at[114]);    MULADD(at[26], at[113]);    MULADD(at[27], at[112]);    MULADD(at[28], at[111]);    MULADD(at[29], at[110]);    MULADD(at[30], at[109]);    MULADD(at[31], at[108]);    MULADD(at[32], at[107]);    MULADD(at[33], at[106]);    MULADD(at[34], at[105]);    MULADD(at[35], at[104]);    MULADD(at[36], at[103]);    MULADD(at[37], at[102]);    MULADD(at[38], at[101]);    MULADD(at[39], at[100]);    MULADD(at[40], at[99]);    MULADD(at[41], at[98]);    MULADD(at[42], at[97]);    MULADD(at[43], at[96]);    MULADD(at[44], at[95]);    MULADD(at[45], at[94]);    MULADD(at[46], at[93]);    MULADD(at[47], at[92]);    MULADD(at[48], at[91]);    MULADD(at[49], at[90]);    MULADD(at[50], at[89]);    MULADD(at[51], at[88]);    MULADD(at[52], at[87]);    MULADD(at[53], at[86]);    MULADD(at[54], at[85]);    MULADD(at[55], at[84]);    MULADD(at[56], at[83]);    MULADD(at[57], at[82]);    MULADD(at[58], at[81]);    MULADD(at[59], at[80]);    MULADD(at[60], at[79]);    MULADD(at[61], at[78]);    MULADD(at[62], at[77]);    MULADD(at[63], at[76]); 
   COMBA_STORE(C->dp[75]);
   /* 76 */
   COMBA_FORWARD;
   MULADD(at[13], at[127]);    MULADD(at[14], at[126]);    MULADD(at[15], at[125]);    MULADD(at[16], at[124]);    MULADD(at[17], at[123]);    MULADD(at[18], at[122]);    MULADD(at[19], at[121]);    MULADD(at[20], at[120]);    MULADD(at[21], at[119]);    MULADD(at[22], at[118]);    MULADD(at[23], at[117]);    MULADD(at[24], at[116]);    MULADD(at[25], at[115]);    MULADD(at[26], at[114]);    MULADD(at[27], at[113]);    MULADD(at[28], at[112]);    MULADD(at[29], at[111]);    MULADD(at[30], at[110]);    MULADD(at[31], at[109]);    MULADD(at[32], at[108]);    MULADD(at[33], at[107]);    MULADD(at[34], at[106]);    MULADD(at[35], at[105]);    MULADD(at[36], at[104]);    MULADD(at[37], at[103]);    MULADD(at[38], at[102]);    MULADD(at[39], at[101]);    MULADD(at[40], at[100]);    MULADD(at[41], at[99]);    MULADD(at[42], at[98]);    MULADD(at[43], at[97]);    MULADD(at[44], at[96]);    MULADD(at[45], at[95]);    MULADD(at[46], at[94]);    MULADD(at[47], at[93]);    MULADD(at[48], at[92]);    MULADD(at[49], at[91]);    MULADD(at[50], at[90]);    MULADD(at[51], at[89]);    MULADD(at[52], at[88]);    MULADD(at[53], at[87]);    MULADD(at[54], at[86]);    MULADD(at[55], at[85]);    MULADD(at[56], at[84]);    MULADD(at[57], at[83]);    MULADD(at[58], at[82]);    MULADD(at[59], at[81]);    MULADD(at[60], at[80]);    MULADD(at[61], at[79]);    MULADD(at[62], at[78]);    MULADD(at[63], at[77]); 
   COMBA_STORE(C->dp[76]);
   /* 77 */
   COMBA_FORWARD;
   MULADD(at[14], at[127]);    MULADD(at[15], at[126]);    MULADD(at[16], at[125]);    MULADD(at[17], at[124]);    MULADD(at[18], at[123]);    MULADD(at[19], at[122]);    MULADD(at[20], at[121]);    MULADD(at[21], at[120]);    MULADD(at[22], at[119]);    MULADD(at[23], at[118]);    MULADD(at[24], at[117]);    MULADD(at[25], at[116]);    MULADD(at[26], at[115]);    MULADD(at[27], at[114]);    MULADD(at[28], at[113]);    MULADD(at[29], at[112]);    MULADD(at[30], at[111]);    MULADD(at[31], at[110]);    MULADD(at[32], at[109]);    MULADD(at[33], at[108]);    MULADD(at[34], at[107]);    MULADD(at[35], at[106]);    MULADD(at[36], at[105]);    MULADD(at[37], at[104]);    MULADD(at[38], at[103]);    MULADD(at[39], at[102]);    MULADD(at[40], at[101]);    MULADD(at[41], at[100]);    MULADD(at[42], at[99]);    MULADD(at[43], at[98]);    MULADD(at[44], at[97]);    MULADD(at[45], at[96]);    MULADD(at[46], at[95]);    MULADD(at[47], at[94]);    MULADD(at[48], at[93]);    MULADD(at[49], at[92]);    MULADD(at[50], at[91]);    MULADD(at[51], at[90]);    MULADD(at[52], at[89]);    MULADD(at[53], at[88]);    MULADD(at[54], at[87]);    MULADD(at[55], at[86]);    MULADD(at[56], at[85]);    MULADD(at[57], at[84]);    MULADD(at[58], at[83]);    MULADD(at[59], at[82]);    MULADD(at[60], at[81]);    MULADD(at[61], at[80]);    MULADD(at[62], at[79]);    MULADD(at[63], at[78]); 
   COMBA_STORE(C->dp[77]);
   /* 78 */
   COMBA_FORWARD;
   MULADD(at[15], at[127]);    MULADD(at[16], at[126]);    MULADD(at[17], at[125]);    MULADD(at[18], at[124]);    MULADD(at[19], at[123]);    MULADD(at[20], at[122]);    MULADD(at[21], at[121]);    MULADD(at[22], at[120]);    MULADD(at[23], at[119]);    MULADD(at[24], at[118]);    MULADD(at[25], at[117]);    MULADD(at[26], at[116]);    MULADD(at[27], at[115]);    MULADD(at[28], at[114]);    MULADD(at[29], at[113]);    MULADD(at[30], at[112]);    MULADD(at[31], at[111]);    MULADD(at[32], at[110]);    MULADD(at[33], at[109]);    MULADD(at[34], at[108]);    MULADD(at[35], at[107]);    MULADD(at[36], at[106]);    MULADD(at[37], at[105]);    MULADD(at[38], at[104]);    MULADD(at[39], at[103]);    MULADD(at[40], at[102]);    MULADD(at[41], at[101]);    MULADD(at[42], at[100]);    MULADD(at[43], at[99]);    MULADD(at[44], at[98]);    MULADD(at[45], at[97]);    MULADD(at[46], at[96]);    MULADD(at[47], at[95]);    MULADD(at[48], at[94]);    MULADD(at[49], at[93]);    MULADD(at[50], at[92]);    MULADD(at[51], at[91]);    MULADD(at[52], at[90]);    MULADD(at[53], at[89]);    MULADD(at[54], at[88]);    MULADD(at[55], at[87]);    MULADD(at[56], at[86]);    MULADD(at[57], at[85]);    MULADD(at[58], at[84]);    MULADD(at[59], at[83]);    MULADD(at[60], at[82]);    MULADD(at[61], at[81]);    MULADD(at[62], at[80]);    MULADD(at[63], at[79]); 
   COMBA_STORE(C->dp[78]);
   /* 79 */
   COMBA_FORWARD;
   MULADD(at[16], at[127]);    MULADD(at[17], at[126]);    MULADD(at[18], at[125]);    MULADD(at[19], at[124]);    MULADD(at[20], at[123]);    MULADD(at[21], at[122]);    MULADD(at[22], at[121]);    MULADD(at[23], at[120]);    MULADD(at[24], at[119]);    MULADD(at[25], at[118]);    MULADD(at[26], at[117]);    MULADD(at[27], at[116]);    MULADD(at[28], at[115]);    MULADD(at[29], at[114]);    MULADD(at[30], at[113]);    MULADD(at[31], at[112]);    MULADD(at[32], at[111]);    MULADD(at[33], at[110]);    MULADD(at[34], at[109]);    MULADD(at[35], at[108]);    MULADD(at[36], at[107]);    MULADD(at[37], at[106]);    MULADD(at[38], at[105]);    MULADD(at[39], at[104]);    MULADD(at[40], at[103]);    MULADD(at[41], at[102]);    MULADD(at[42], at[101]);    MULADD(at[43], at[100]);    MULADD(at[44], at[99]);    MULADD(at[45], at[98]);    MULADD(at[46], at[97]);    MULADD(at[47], at[96]);    MULADD(at[48], at[95]);    MULADD(at[49], at[94]);    MULADD(at[50], at[93]);    MULADD(at[51], at[92]);    MULADD(at[52], at[91]);    MULADD(at[53], at[90]);    MULADD(at[54], at[89]);    MULADD(at[55], at[88]);    MULADD(at[56], at[87]);    MULADD(at[57], at[86]);    MULADD(at[58], at[85]);    MULADD(at[59], at[84]);    MULADD(at[60], at[83]);    MULADD(at[61], at[82]);    MULADD(at[62], at[81]);    MULADD(at[63], at[80]); 
   COMBA_STORE(C->dp[79]);
   /* 80 */
   COMBA_FORWARD;
   MULADD(at[17], at[127]);    MULADD(at[18], at[126]);    MULADD(at[19], at[125]);    MULADD(at[20], at[124]);    MULADD(at[21], at[123]);    MULADD(at[22], at[122]);    MULADD(at[23], at[121]);    MULADD(at[24], at[120]);    MULADD(at[25], at[119]);    MULADD(at[26], at[118]);    MULADD(at[27], at[117]);    MULADD(at[28], at[116]);    MULADD(at[29], at[115]);    MULADD(at[30], at[114]);    MULADD(at[31], at[113]);    MULADD(at[32], at[112]);    MULADD(at[33], at[111]);    MULADD(at[34], at[110]);    MULADD(at[35], at[109]);    MULADD(at[36], at[108]);    MULADD(at[37], at[107]);    MULADD(at[38], at[106]);    MULADD(at[39], at[105]);    MULADD(at[40], at[104]);    MULADD(at[41], at[103]);    MULADD(at[42], at[102]);    MULADD(at[43], at[101]);    MULADD(at[44], at[100]);    MULADD(at[45], at[99]);    MULADD(at[46], at[98]);    MULADD(at[47], at[97]);    MULADD(at[48], at[96]);    MULADD(at[49], at[95]);    MULADD(at[50], at[94]);    MULADD(at[51], at[93]);    MULADD(at[52], at[92]);    MULADD(at[53], at[91]);    MULADD(at[54], at[90]);    MULADD(at[55], at[89]);    MULADD(at[56], at[88]);    MULADD(at[57], at[87]);    MULADD(at[58], at[86]);    MULADD(at[59], at[85]);    MULADD(at[60], at[84]);    MULADD(at[61], at[83]);    MULADD(at[62], at[82]);    MULADD(at[63], at[81]); 
   COMBA_STORE(C->dp[80]);
   /* 81 */
   COMBA_FORWARD;
   MULADD(at[18], at[127]);    MULADD(at[19], at[126]);    MULADD(at[20], at[125]);    MULADD(at[21], at[124]);    MULADD(at[22], at[123]);    MULADD(at[23], at[122]);    MULADD(at[24], at[121]);    MULADD(at[25], at[120]);    MULADD(at[26], at[119]);    MULADD(at[27], at[118]);    MULADD(at[28], at[117]);    MULADD(at[29], at[116]);    MULADD(at[30], at[115]);    MULADD(at[31], at[114]);    MULADD(at[32], at[113]);    MULADD(at[33], at[112]);    MULADD(at[34], at[111]);    MULADD(at[35], at[110]);    MULADD(at[36], at[109]);    MULADD(at[37], at[108]);    MULADD(at[38], at[107]);    MULADD(at[39], at[106]);    MULADD(at[40], at[105]);    MULADD(at[41], at[104]);    MULADD(at[42], at[103]);    MULADD(at[43], at[102]);    MULADD(at[44], at[101]);    MULADD(at[45], at[100]);    MULADD(at[46], at[99]);    MULADD(at[47], at[98]);    MULADD(at[48], at[97]);    MULADD(at[49], at[96]);    MULADD(at[50], at[95]);    MULADD(at[51], at[94]);    MULADD(at[52], at[93]);    MULADD(at[53], at[92]);    MULADD(at[54], at[91]);    MULADD(at[55], at[90]);    MULADD(at[56], at[89]);    MULADD(at[57], at[88]);    MULADD(at[58], at[87]);    MULADD(at[59], at[86]);    MULADD(at[60], at[85]);    MULADD(at[61], at[84]);    MULADD(at[62], at[83]);    MULADD(at[63], at[82]); 
   COMBA_STORE(C->dp[81]);
   /* 82 */
   COMBA_FORWARD;
   MULADD(at[19], at[127]);    MULADD(at[20], at[126]);    MULADD(at[21], at[125]);    MULADD(at[22], at[124]);    MULADD(at[23], at[123]);    MULADD(at[24], at[122]);    MULADD(at[25], at[121]);    MULADD(at[26], at[120]);    MULADD(at[27], at[119]);    MULADD(at[28], at[118]);    MULADD(at[29], at[117]);    MULADD(at[30], at[116]);    MULADD(at[31], at[115]);    MULADD(at[32], at[114]);    MULADD(at[33], at[113]);    MULADD(at[34], at[112]);    MULADD(at[35], at[111]);    MULADD(at[36], at[110]);    MULADD(at[37], at[109]);    MULADD(at[38], at[108]);    MULADD(at[39], at[107]);    MULADD(at[40], at[106]);    MULADD(at[41], at[105]);    MULADD(at[42], at[104]);    MULADD(at[43], at[103]);    MULADD(at[44], at[102]);    MULADD(at[45], at[101]);    MULADD(at[46], at[100]);    MULADD(at[47], at[99]);    MULADD(at[48], at[98]);    MULADD(at[49], at[97]);    MULADD(at[50], at[96]);    MULADD(at[51], at[95]);    MULADD(at[52], at[94]);    MULADD(at[53], at[93]);    MULADD(at[54], at[92]);    MULADD(at[55], at[91]);    MULADD(at[56], at[90]);    MULADD(at[57], at[89]);    MULADD(at[58], at[88]);    MULADD(at[59], at[87]);    MULADD(at[60], at[86]);    MULADD(at[61], at[85]);    MULADD(at[62], at[84]);    MULADD(at[63], at[83]); 
   COMBA_STORE(C->dp[82]);
   /* 83 */
   COMBA_FORWARD;
   MULADD(at[20], at[127]);    MULADD(at[21], at[126]);    MULADD(at[22], at[125]);    MULADD(at[23], at[124]);    MULADD(at[24], at[123]);    MULADD(at[25], at[122]);    MULADD(at[26], at[121]);    MULADD(at[27], at[120]);    MULADD(at[28], at[119]);    MULADD(at[29], at[118]);    MULADD(at[30], at[117]);    MULADD(at[31], at[116]);    MULADD(at[32], at[115]);    MULADD(at[33], at[114]);    MULADD(at[34], at[113]);    MULADD(at[35], at[112]);    MULADD(at[36], at[111]);    MULADD(at[37], at[110]);    MULADD(at[38], at[109]);    MULADD(at[39], at[108]);    MULADD(at[40], at[107]);    MULADD(at[41], at[106]);    MULADD(at[42], at[105]);    MULADD(at[43], at[104]);    MULADD(at[44], at[103]);    MULADD(at[45], at[102]);    MULADD(at[46], at[101]);    MULADD(at[47], at[100]);    MULADD(at[48], at[99]);    MULADD(at[49], at[98]);    MULADD(at[50], at[97]);    MULADD(at[51], at[96]);    MULADD(at[52], at[95]);    MULADD(at[53], at[94]);    MULADD(at[54], at[93]);    MULADD(at[55], at[92]);    MULADD(at[56], at[91]);    MULADD(at[57], at[90]);    MULADD(at[58], at[89]);    MULADD(at[59], at[88]);    MULADD(at[60], at[87]);    MULADD(at[61], at[86]);    MULADD(at[62], at[85]);    MULADD(at[63], at[84]); 
   COMBA_STORE(C->dp[83]);
   /* 84 */
   COMBA_FORWARD;
   MULADD(at[21], at[127]);    MULADD(at[22], at[126]);    MULADD(at[23], at[125]);    MULADD(at[24], at[124]);    MULADD(at[25], at[123]);    MULADD(at[26], at[122]);    MULADD(at[27], at[121]);    MULADD(at[28], at[120]);    MULADD(at[29], at[119]);    MULADD(at[30], at[118]);    MULADD(at[31], at[117]);    MULADD(at[32], at[116]);    MULADD(at[33], at[115]);    MULADD(at[34], at[114]);    MULADD(at[35], at[113]);    MULADD(at[36], at[112]);    MULADD(at[37], at[111]);    MULADD(at[38], at[110]);    MULADD(at[39], at[109]);    MULADD(at[40], at[108]);    MULADD(at[41], at[107]);    MULADD(at[42], at[106]);    MULADD(at[43], at[105]);    MULADD(at[44], at[104]);    MULADD(at[45], at[103]);    MULADD(at[46], at[102]);    MULADD(at[47], at[101]);    MULADD(at[48], at[100]);    MULADD(at[49], at[99]);    MULADD(at[50], at[98]);    MULADD(at[51], at[97]);    MULADD(at[52], at[96]);    MULADD(at[53], at[95]);    MULADD(at[54], at[94]);    MULADD(at[55], at[93]);    MULADD(at[56], at[92]);    MULADD(at[57], at[91]);    MULADD(at[58], at[90]);    MULADD(at[59], at[89]);    MULADD(at[60], at[88]);    MULADD(at[61], at[87]);    MULADD(at[62], at[86]);    MULADD(at[63], at[85]); 
   COMBA_STORE(C->dp[84]);
   /* 85 */
   COMBA_FORWARD;
   MULADD(at[22], at[127]);    MULADD(at[23], at[126]);    MULADD(at[24], at[125]);    MULADD(at[25], at[124]);    MULADD(at[26], at[123]);    MULADD(at[27], at[122]);    MULADD(at[28], at[121]);    MULADD(at[29], at[120]);    MULADD(at[30], at[119]);    MULADD(at[31], at[118]);    MULADD(at[32], at[117]);    MULADD(at[33], at[116]);    MULADD(at[34], at[115]);    MULADD(at[35], at[114]);    MULADD(at[36], at[113]);    MULADD(at[37], at[112]);    MULADD(at[38], at[111]);    MULADD(at[39], at[110]);    MULADD(at[40], at[109]);    MULADD(at[41], at[108]);    MULADD(at[42], at[107]);    MULADD(at[43], at[106]);    MULADD(at[44], at[105]);    MULADD(at[45], at[104]);    MULADD(at[46], at[103]);    MULADD(at[47], at[102]);    MULADD(at[48], at[101]);    MULADD(at[49], at[100]);    MULADD(at[50], at[99]);    MULADD(at[51], at[98]);    MULADD(at[52], at[97]);    MULADD(at[53], at[96]);    MULADD(at[54], at[95]);    MULADD(at[55], at[94]);    MULADD(at[56], at[93]);    MULADD(at[57], at[92]);    MULADD(at[58], at[91]);    MULADD(at[59], at[90]);    MULADD(at[60], at[89]);    MULADD(at[61], at[88]);    MULADD(at[62], at[87]);    MULADD(at[63], at[86]); 
   COMBA_STORE(C->dp[85]);
   /* 86 */
   COMBA_FORWARD;
   MULADD(at[23], at[127]);    MULADD(at[24], at[126]);    MULADD(at[25], at[125]);    MULADD(at[26], at[124]);    MULADD(at[27], at[123]);    MULADD(at[28], at[122]);    MULADD(at[29], at[121]);    MULADD(at[30], at[120]);    MULADD(at[31], at[119]);    MULADD(at[32], at[118]);    MULADD(at[33], at[117]);    MULADD(at[34], at[116]);    MULADD(at[35], at[115]);    MULADD(at[36], at[114]);    MULADD(at[37], at[113]);    MULADD(at[38], at[112]);    MULADD(at[39], at[111]);    MULADD(at[40], at[110]);    MULADD(at[41], at[109]);    MULADD(at[42], at[108]);    MULADD(at[43], at[107]);    MULADD(at[44], at[106]);    MULADD(at[45], at[105]);    MULADD(at[46], at[104]);    MULADD(at[47], at[103]);    MULADD(at[48], at[102]);    MULADD(at[49], at[101]);    MULADD(at[50], at[100]);    MULADD(at[51], at[99]);    MULADD(at[52], at[98]);    MULADD(at[53], at[97]);    MULADD(at[54], at[96]);    MULADD(at[55], at[95]);    MULADD(at[56], at[94]);    MULADD(at[57], at[93]);    MULADD(at[58], at[92]);    MULADD(at[59], at[91]);    MULADD(at[60], at[90]);    MULADD(at[61], at[89]);    MULADD(at[62], at[88]);    MULADD(at[63], at[87]); 
   COMBA_STORE(C->dp[86]);
   /* 87 */
   COMBA_FORWARD;
   MULADD(at[24], at[127]);    MULADD(at[25], at[126]);    MULADD(at[26], at[125]);    MULADD(at[27], at[124]);    MULADD(at[28], at[123]);    MULADD(at[29], at[122]);    MULADD(at[30], at[121]);    MULADD(at[31], at[120]);    MULADD(at[32], at[119]);    MULADD(at[33], at[118]);    MULADD(at[34], at[117]);    MULADD(at[35], at[116]);    MULADD(at[36], at[115]);    MULADD(at[37], at[114]);    MULADD(at[38], at[113]);    MULADD(at[39], at[112]);    MULADD(at[40], at[111]);    MULADD(at[41], at[110]);    MULADD(at[42], at[109]);    MULADD(at[43], at[108]);    MULADD(at[44], at[107]);    MULADD(at[45], at[106]);    MULADD(at[46], at[105]);    MULADD(at[47], at[104]);    MULADD(at[48], at[103]);    MULADD(at[49], at[102]);    MULADD(at[50], at[101]);    MULADD(at[51], at[100]);    MULADD(at[52], at[99]);    MULADD(at[53], at[98]);    MULADD(at[54], at[97]);    MULADD(at[55], at[96]);    MULADD(at[56], at[95]);    MULADD(at[57], at[94]);    MULADD(at[58], at[93]);    MULADD(at[59], at[92]);    MULADD(at[60], at[91]);    MULADD(at[61], at[90]);    MULADD(at[62], at[89]);    MULADD(at[63], at[88]); 
   COMBA_STORE(C->dp[87]);
   /* 88 */
   COMBA_FORWARD;
   MULADD(at[25], at[127]);    MULADD(at[26], at[126]);    MULADD(at[27], at[125]);    MULADD(at[28], at[124]);    MULADD(at[29], at[123]);    MULADD(at[30], at[122]);    MULADD(at[31], at[121]);    MULADD(at[32], at[120]);    MULADD(at[33], at[119]);    MULADD(at[34], at[118]);    MULADD(at[35], at[117]);    MULADD(at[36], at[116]);    MULADD(at[37], at[115]);    MULADD(at[38], at[114]);    MULADD(at[39], at[113]);    MULADD(at[40], at[112]);    MULADD(at[41], at[111]);    MULADD(at[42], at[110]);    MULADD(at[43], at[109]);    MULADD(at[44], at[108]);    MULADD(at[45], at[107]);    MULADD(at[46], at[106]);    MULADD(at[47], at[105]);    MULADD(at[48], at[104]);    MULADD(at[49], at[103]);    MULADD(at[50], at[102]);    MULADD(at[51], at[101]);    MULADD(at[52], at[100]);    MULADD(at[53], at[99]);    MULADD(at[54], at[98]);    MULADD(at[55], at[97]);    MULADD(at[56], at[96]);    MULADD(at[57], at[95]);    MULADD(at[58], at[94]);    MULADD(at[59], at[93]);    MULADD(at[60], at[92]);    MULADD(at[61], at[91]);    MULADD(at[62], at[90]);    MULADD(at[63], at[89]); 
   COMBA_STORE(C->dp[88]);
   /* 89 */
   COMBA_FORWARD;
   MULADD(at[26], at[127]);    MULADD(at[27], at[126]);    MULADD(at[28], at[125]);    MULADD(at[29], at[124]);    MULADD(at[30], at[123]);    MULADD(at[31], at[122]);    MULADD(at[32], at[121]);    MULADD(at[33], at[120]);    MULADD(at[34], at[119]);    MULADD(at[35], at[118]);    MULADD(at[36], at[117]);    MULADD(at[37], at[116]);    MULADD(at[38], at[115]);    MULADD(at[39], at[114]);    MULADD(at[40], at[113]);    MULADD(at[41], at[112]);    MULADD(at[42], at[111]);    MULADD(at[43], at[110]);    MULADD(at[44], at[109]);    MULADD(at[45], at[108]);    MULADD(at[46], at[107]);    MULADD(at[47], at[106]);    MULADD(at[48], at[105]);    MULADD(at[49], at[104]);    MULADD(at[50], at[103]);    MULADD(at[51], at[102]);    MULADD(at[52], at[101]);    MULADD(at[53], at[100]);    MULADD(at[54], at[99]);    MULADD(at[55], at[98]);    MULADD(at[56], at[97]);    MULADD(at[57], at[96]);    MULADD(at[58], at[95]);    MULADD(at[59], at[94]);    MULADD(at[60], at[93]);    MULADD(at[61], at[92]);    MULADD(at[62], at[91]);    MULADD(at[63], at[90]); 
   COMBA_STORE(C->dp[89]);
   /* 90 */
   COMBA_FORWARD;
   MULADD(at[27], at[127]);    MULADD(at[28], at[126]);    MULADD(at[29], at[125]);    MULADD(at[30], at[124]);    MULADD(at[31], at[123]);    MULADD(at[32], at[122]);    MULADD(at[33], at[121]);    MULADD(at[34], at[120]);    MULADD(at[35], at[119]);    MULADD(at[36], at[118]);    MULADD(at[37], at[117]);    MULADD(at[38], at[116]);    MULADD(at[39], at[115]);    MULADD(at[40], at[114]);    MULADD(at[41], at[113]);    MULADD(at[42], at[112]);    MULADD(at[43], at[111]);    MULADD(at[44], at[110]);    MULADD(at[45], at[109]);    MULADD(at[46], at[108]);    MULADD(at[47], at[107]);    MULADD(at[48], at[106]);    MULADD(at[49], at[105]);    MULADD(at[50], at[104]);    MULADD(at[51], at[103]);    MULADD(at[52], at[102]);    MULADD(at[53], at[101]);    MULADD(at[54], at[100]);    MULADD(at[55], at[99]);    MULADD(at[56], at[98]);    MULADD(at[57], at[97]);    MULADD(at[58], at[96]);    MULADD(at[59], at[95]);    MULADD(at[60], at[94]);    MULADD(at[61], at[93]);    MULADD(at[62], at[92]);    MULADD(at[63], at[91]); 
   COMBA_STORE(C->dp[90]);
   /* 91 */
   COMBA_FORWARD;
   MULADD(at[28], at[127]);    MULADD(at[29], at[126]);    MULADD(at[30], at[125]);    MULADD(at[31], at[124]);    MULADD(at[32], at[123]);    MULADD(at[33], at[122]);    MULADD(at[34], at[121]);    MULADD(at[35], at[120]);    MULADD(at[36], at[119]);    MULADD(at[37], at[118]);    MULADD(at[38], at[117]);    MULADD(at[39], at[116]);    MULADD(at[40], at[115]);    MULADD(at[41], at[114]);    MULADD(at[42], at[113]);    MULADD(at[43], at[112]);    MULADD(at[44], at[111]);    MULADD(at[45], at[110]);    MULADD(at[46], at[109]);    MULADD(at[47], at[108]);    MULADD(at[48], at[107]);    MULADD(at[49], at[106]);    MULADD(at[50], at[105]);    MULADD(at[51], at[104]);    MULADD(at[52], at[103]);    MULADD(at[53], at[102]);    MULADD(at[54], at[101]);    MULADD(at[55], at[100]);    MULADD(at[56], at[99]);    MULADD(at[57], at[98]);    MULADD(at[58], at[97]);    MULADD(at[59], at[96]);    MULADD(at[60], at[95]);    MULADD(at[61], at[94]);    MULADD(at[62], at[93]);    MULADD(at[63], at[92]); 
   COMBA_STORE(C->dp[91]);
   /* 92 */
   COMBA_FORWARD;
   MULADD(at[29], at[127]);    MULADD(at[30], at[126]);    MULADD(at[31], at[125]);    MULADD(at[32], at[124]);    MULADD(at[33], at[123]);    MULADD(at[34], at[122]);    MULADD(at[35], at[121]);    MULADD(at[36], at[120]);    MULADD(at[37], at[119]);    MULADD(at[38], at[118]);    MULADD(at[39], at[117]);    MULADD(at[40], at[116]);    MULADD(at[41], at[115]);    MULADD(at[42], at[114]);    MULADD(at[43], at[113]);    MULADD(at[44], at[112]);    MULADD(at[45], at[111]);    MULADD(at[46], at[110]);    MULADD(at[47], at[109]);    MULADD(at[48], at[108]);    MULADD(at[49], at[107]);    MULADD(at[50], at[106]);    MULADD(at[51], at[105]);    MULADD(at[52], at[104]);    MULADD(at[53], at[103]);    MULADD(at[54], at[102]);    MULADD(at[55], at[101]);    MULADD(at[56], at[100]);    MULADD(at[57], at[99]);    MULADD(at[58], at[98]);    MULADD(at[59], at[97]);    MULADD(at[60], at[96]);    MULADD(at[61], at[95]);    MULADD(at[62], at[94]);    MULADD(at[63], at[93]); 
   COMBA_STORE(C->dp[92]);
   /* 93 */
   COMBA_FORWARD;
   MULADD(at[30], at[127]);    MULADD(at[31], at[126]);    MULADD(at[32], at[125]);    MULADD(at[33], at[124]);    MULADD(at[34], at[123]);    MULADD(at[35], at[122]);    MULADD(at[36], at[121]);    MULADD(at[37], at[120]);    MULADD(at[38], at[119]);    MULADD(at[39], at[118]);    MULADD(at[40], at[117]);    MULADD(at[41], at[116]);    MULADD(at[42], at[115]);    MULADD(at[43], at[114]);    MULADD(at[44], at[113]);    MULADD(at[45], at[112]);    MULADD(at[46], at[111]);    MULADD(at[47], at[110]);    MULADD(at[48], at[109]);    MULADD(at[49], at[108]);    MULADD(at[50], at[107]);    MULADD(at[51], at[106]);    MULADD(at[52], at[105]);    MULADD(at[53], at[104]);    MULADD(at[54], at[103]);    MULADD(at[55], at[102]);    MULADD(at[56], at[101]);    MULADD(at[57], at[100]);    MULADD(at[58], at[99]);    MULADD(at[59], at[98]);    MULADD(at[60], at[97]);    MULADD(at[61], at[96]);    MULADD(at[62], at[95]);    MULADD(at[63], at[94]); 
   COMBA_STORE(C->dp[93]);
   /* 94 */
   COMBA_FORWARD;
   MULADD(at[31], at[127]);    MULADD(at[32], at[126]);    MULADD(at[33], at[125]);    MULADD(at[34], at[124]);    MULADD(at[35], at[123]);    MULADD(at[36], at[122]);    MULADD(at[37], at[121]);    MULADD(at[38], at[120]);    MULADD(at[39], at[119]);    MULADD(at[40], at[118]);    MULADD(at[41], at[117]);    MULADD(at[42], at[116]);    MULADD(at[43], at[115]);    MULADD(at[44], at[114]);    MULADD(at[45], at[113]);    MULADD(at[46], at[112]);    MULADD(at[47], at[111]);    MULADD(at[48], at[110]);    MULADD(at[49], at[109]);    MULADD(at[50], at[108]);    MULADD(at[51], at[107]);    MULADD(at[52], at[106]);    MULADD(at[53], at[105]);    MULADD(at[54], at[104]);    MULADD(at[55], at[103]);    MULADD(at[56], at[102]);    MULADD(at[57], at[101]);    MULADD(at[58], at[100]);    MULADD(at[59], at[99]);    MULADD(at[60], at[98]);    MULADD(at[61], at[97]);    MULADD(at[62], at[96]);    MULADD(at[63], at[95]); 
   COMBA_STORE(C->dp[94]);
   /* 95 */
   COMBA_FORWARD;
   MULADD(at[32], at[127]);    MULADD(at[33], at[126]);    MULADD(at[34], at[125]);    MULADD(at[35], at[124]);    MULADD(at[36], at[123]);    MULADD(at[37], at[122]);    MULADD(at[38], at[121]);    MULADD(at[39], at[120]);    MULADD(at[40], at[119]);    MULADD(at[41], at[118]);    MULADD(at[42], at[117]);    MULADD(at[43], at[116]);    MULADD(at[44], at[115]);    MULADD(at[45], at[114]);    MULADD(at[46], at[113]);    MULADD(at[47], at[112]);    MULADD(at[48], at[111]);    MULADD(at[49], at[110]);    MULADD(at[50], at[109]);    MULADD(at[51], at[108]);    MULADD(at[52], at[107]);    MULADD(at[53], at[106]);    MULADD(at[54], at[105]);    MULADD(at[55], at[104]);    MULADD(at[56], at[103]);    MULADD(at[57], at[102]);    MULADD(at[58], at[101]);    MULADD(at[59], at[100]);    MULADD(at[60], at[99]);    MULADD(at[61], at[98]);    MULADD(at[62], at[97]);    MULADD(at[63], at[96]); 
   COMBA_STORE(C->dp[95]);
   /* 96 */
   COMBA_FORWARD;
   MULADD(at[33], at[127]);    MULADD(at[34], at[126]);    MULADD(at[35], at[125]);    MULADD(at[36], at[124]);    MULADD(at[37], at[123]);    MULADD(at[38], at[122]);    MULADD(at[39], at[121]);    MULADD(at[40], at[120]);    MULADD(at[41], at[119]);    MULADD(at[42], at[118]);    MULADD(at[43], at[117]);    MULADD(at[44], at[116]);    MULADD(at[45], at[115]);    MULADD(at[46], at[114]);    MULADD(at[47], at[113]);    MULADD(at[48], at[112]);    MULADD(at[49], at[111]);    MULADD(at[50], at[110]);    MULADD(at[51], at[109]);    MULADD(at[52], at[108]);    MULADD(at[53], at[107]);    MULADD(at[54], at[106]);    MULADD(at[55], at[105]);    MULADD(at[56], at[104]);    MULADD(at[57], at[103]);    MULADD(at[58], at[102]);    MULADD(at[59], at[101]);    MULADD(at[60], at[100]);    MULADD(at[61], at[99]);    MULADD(at[62], at[98]);    MULADD(at[63], at[97]); 
   COMBA_STORE(C->dp[96]);
   /* 97 */
   COMBA_FORWARD;
   MULADD(at[34], at[127]);    MULADD(at[35], at[126]);    MULADD(at[36], at[125]);    MULADD(at[37], at[124]);    MULADD(at[38], at[123]);    MULADD(at[39], at[122]);    MULADD(at[40], at[121]);    MULADD(at[41], at[120]);    MULADD(at[42], at[119]);    MULADD(at[43], at[118]);    MULADD(at[44], at[117]);    MULADD(at[45], at[116]);    MULADD(at[46], at[115]);    MULADD(at[47], at[114]);    MULADD(at[48], at[113]);    MULADD(at[49], at[112]);    MULADD(at[50], at[111]);    MULADD(at[51], at[110]);    MULADD(at[52], at[109]);    MULADD(at[53], at[108]);    MULADD(at[54], at[107]);    MULADD(at[55], at[106]);    MULADD(at[56], at[105]);    MULADD(at[57], at[104]);    MULADD(at[58], at[103]);    MULADD(at[59], at[102]);    MULADD(at[60], at[101]);    MULADD(at[61], at[100]);    MULADD(at[62], at[99]);    MULADD(at[63], at[98]); 
   COMBA_STORE(C->dp[97]);
   /* 98 */
   COMBA_FORWARD;
   MULADD(at[35], at[127]);    MULADD(at[36], at[126]);    MULADD(at[37], at[125]);    MULADD(at[38], at[124]);    MULADD(at[39], at[123]);    MULADD(at[40], at[122]);    MULADD(at[41], at[121]);    MULADD(at[42], at[120]);    MULADD(at[43], at[119]);    MULADD(at[44], at[118]);    MULADD(at[45], at[117]);    MULADD(at[46], at[116]);    MULADD(at[47], at[115]);    MULADD(at[48], at[114]);    MULADD(at[49], at[113]);    MULADD(at[50], at[112]);    MULADD(at[51], at[111]);    MULADD(at[52], at[110]);    MULADD(at[53], at[109]);    MULADD(at[54], at[108]);    MULADD(at[55], at[107]);    MULADD(at[56], at[106]);    MULADD(at[57], at[105]);    MULADD(at[58], at[104]);    MULADD(at[59], at[103]);    MULADD(at[60], at[102]);    MULADD(at[61], at[101]);    MULADD(at[62], at[100]);    MULADD(at[63], at[99]); 
   COMBA_STORE(C->dp[98]);
   /* 99 */
   COMBA_FORWARD;
   MULADD(at[36], at[127]);    MULADD(at[37], at[126]);    MULADD(at[38], at[125]);    MULADD(at[39], at[124]);    MULADD(at[40], at[123]);    MULADD(at[41], at[122]);    MULADD(at[42], at[121]);    MULADD(at[43], at[120]);    MULADD(at[44], at[119]);    MULADD(at[45], at[118]);    MULADD(at[46], at[117]);    MULADD(at[47], at[116]);    MULADD(at[48], at[115]);    MULADD(at[49], at[114]);    MULADD(at[50], at[113]);    MULADD(at[51], at[112]);    MULADD(at[52], at[111]);    MULADD(at[53], at[110]);    MULADD(at[54], at[109]);    MULADD(at[55], at[108]);    MULADD(at[56], at[107]);    MULADD(at[57], at[106]);    MULADD(at[58], at[105]);    MULADD(at[59], at[104]);    MULADD(at[60], at[103]);    MULADD(at[61], at[102]);    MULADD(at[62], at[101]);    MULADD(at[63], at[100]); 
   COMBA_STORE(C->dp[99]);
   /* 100 */
   COMBA_FORWARD;
   MULADD(at[37], at[127]);    MULADD(at[38], at[126]);    MULADD(at[39], at[125]);    MULADD(at[40], at[124]);    MULADD(at[41], at[123]);    MULADD(at[42], at[122]);    MULADD(at[43], at[121]);    MULADD(at[44], at[120]);    MULADD(at[45], at[119]);    MULADD(at[46], at[118]);    MULADD(at[47], at[117]);    MULADD(at[48], at[116]);    MULADD(at[49], at[115]);    MULADD(at[50], at[114]);    MULADD(at[51], at[113]);    MULADD(at[52], at[112]);    MULADD(at[53], at[111]);    MULADD(at[54], at[110]);    MULADD(at[55], at[109]);    MULADD(at[56], at[108]);    MULADD(at[57], at[107]);    MULADD(at[58], at[106]);    MULADD(at[59], at[105]);    MULADD(at[60], at[104]);    MULADD(at[61], at[103]);    MULADD(at[62], at[102]);    MULADD(at[63], at[101]); 
   COMBA_STORE(C->dp[100]);
   /* 101 */
   COMBA_FORWARD;
   MULADD(at[38], at[127]);    MULADD(at[39], at[126]);    MULADD(at[40], at[125]);    MULADD(at[41], at[124]);    MULADD(at[42], at[123]);    MULADD(at[43], at[122]);    MULADD(at[44], at[121]);    MULADD(at[45], at[120]);    MULADD(at[46], at[119]);    MULADD(at[47], at[118]);    MULADD(at[48], at[117]);    MULADD(at[49], at[116]);    MULADD(at[50], at[115]);    MULADD(at[51], at[114]);    MULADD(at[52], at[113]);    MULADD(at[53], at[112]);    MULADD(at[54], at[111]);    MULADD(at[55], at[110]);    MULADD(at[56], at[109]);    MULADD(at[57], at[108]);    MULADD(at[58], at[107]);    MULADD(at[59], at[106]);    MULADD(at[60], at[105]);    MULADD(at[61], at[104]);    MULADD(at[62], at[103]);    MULADD(at[63], at[102]); 
   COMBA_STORE(C->dp[101]);
   /* 102 */
   COMBA_FORWARD;
   MULADD(at[39], at[127]);    MULADD(at[40], at[126]);    MULADD(at[41], at[125]);    MULADD(at[42], at[124]);    MULADD(at[43], at[123]);    MULADD(at[44], at[122]);    MULADD(at[45], at[121]);    MULADD(at[46], at[120]);    MULADD(at[47], at[119]);    MULADD(at[48], at[118]);    MULADD(at[49], at[117]);    MULADD(at[50], at[116]);    MULADD(at[51], at[115]);    MULADD(at[52], at[114]);    MULADD(at[53], at[113]);    MULADD(at[54], at[112]);    MULADD(at[55], at[111]);    MULADD(at[56], at[110]);    MULADD(at[57], at[109]);    MULADD(at[58], at[108]);    MULADD(at[59], at[107]);    MULADD(at[60], at[106]);    MULADD(at[61], at[105]);    MULADD(at[62], at[104]);    MULADD(at[63], at[103]); 
   COMBA_STORE(C->dp[102]);
   /* 103 */
   COMBA_FORWARD;
   MULADD(at[40], at[127]);    MULADD(at[41], at[126]);    MULADD(at[42], at[125]);    MULADD(at[43], at[124]);    MULADD(at[44], at[123]);    MULADD(at[45], at[122]);    MULADD(at[46], at[121]);    MULADD(at[47], at[120]);    MULADD(at[48], at[119]);    MULADD(at[49], at[118]);    MULADD(at[50], at[117]);    MULADD(at[51], at[116]);    MULADD(at[52], at[115]);    MULADD(at[53], at[114]);    MULADD(at[54], at[113]);    MULADD(at[55], at[112]);    MULADD(at[56], at[111]);    MULADD(at[57], at[110]);    MULADD(at[58], at[109]);    MULADD(at[59], at[108]);    MULADD(at[60], at[107]);    MULADD(at[61], at[106]);    MULADD(at[62], at[105]);    MULADD(at[63], at[104]); 
   COMBA_STORE(C->dp[103]);
   /* 104 */
   COMBA_FORWARD;
   MULADD(at[41], at[127]);    MULADD(at[42], at[126]);    MULADD(at[43], at[125]);    MULADD(at[44], at[124]);    MULADD(at[45], at[123]);    MULADD(at[46], at[122]);    MULADD(at[47], at[121]);    MULADD(at[48], at[120]);    MULADD(at[49], at[119]);    MULADD(at[50], at[118]);    MULADD(at[51], at[117]);    MULADD(at[52], at[116]);    MULADD(at[53], at[115]);    MULADD(at[54], at[114]);    MULADD(at[55], at[113]);    MULADD(at[56], at[112]);    MULADD(at[57], at[111]);    MULADD(at[58], at[110]);    MULADD(at[59], at[109]);    MULADD(at[60], at[108]);    MULADD(at[61], at[107]);    MULADD(at[62], at[106]);    MULADD(at[63], at[105]); 
   COMBA_STORE(C->dp[104]);
   /* 105 */
   COMBA_FORWARD;
   MULADD(at[42], at[127]);    MULADD(at[43], at[126]);    MULADD(at[44], at[125]);    MULADD(at[45], at[124]);    MULADD(at[46], at[123]);    MULADD(at[47], at[122]);    MULADD(at[48], at[121]);    MULADD(at[49], at[120]);    MULADD(at[50], at[119]);    MULADD(at[51], at[118]);    MULADD(at[52], at[117]);    MULADD(at[53], at[116]);    MULADD(at[54], at[115]);    MULADD(at[55], at[114]);    MULADD(at[56], at[113]);    MULADD(at[57], at[112]);    MULADD(at[58], at[111]);    MULADD(at[59], at[110]);    MULADD(at[60], at[109]);    MULADD(at[61], at[108]);    MULADD(at[62], at[107]);    MULADD(at[63], at[106]); 
   COMBA_STORE(C->dp[105]);
   /* 106 */
   COMBA_FORWARD;
   MULADD(at[43], at[127]);    MULADD(at[44], at[126]);    MULADD(at[45], at[125]);    MULADD(at[46], at[124]);    MULADD(at[47], at[123]);    MULADD(at[48], at[122]);    MULADD(at[49], at[121]);    MULADD(at[50], at[120]);    MULADD(at[51], at[119]);    MULADD(at[52], at[118]);    MULADD(at[53], at[117]);    MULADD(at[54], at[116]);    MULADD(at[55], at[115]);    MULADD(at[56], at[114]);    MULADD(at[57], at[113]);    MULADD(at[58], at[112]);    MULADD(at[59], at[111]);    MULADD(at[60], at[110]);    MULADD(at[61], at[109]);    MULADD(at[62], at[108]);    MULADD(at[63], at[107]); 
   COMBA_STORE(C->dp[106]);
   /* 107 */
   COMBA_FORWARD;
   MULADD(at[44], at[127]);    MULADD(at[45], at[126]);    MULADD(at[46], at[125]);    MULADD(at[47], at[124]);    MULADD(at[48], at[123]);    MULADD(at[49], at[122]);    MULADD(at[50], at[121]);    MULADD(at[51], at[120]);    MULADD(at[52], at[119]);    MULADD(at[53], at[118]);    MULADD(at[54], at[117]);    MULADD(at[55], at[116]);    MULADD(at[56], at[115]);    MULADD(at[57], at[114]);    MULADD(at[58], at[113]);    MULADD(at[59], at[112]);    MULADD(at[60], at[111]);    MULADD(at[61], at[110]);    MULADD(at[62], at[109]);    MULADD(at[63], at[108]); 
   COMBA_STORE(C->dp[107]);
   /* 108 */
   COMBA_FORWARD;
   MULADD(at[45], at[127]);    MULADD(at[46], at[126]);    MULADD(at[47], at[125]);    MULADD(at[48], at[124]);    MULADD(at[49], at[123]);    MULADD(at[50], at[122]);    MULADD(at[51], at[121]);    MULADD(at[52], at[120]);    MULADD(at[53], at[119]);    MULADD(at[54], at[118]);    MULADD(at[55], at[117]);    MULADD(at[56], at[116]);    MULADD(at[57], at[115]);    MULADD(at[58], at[114]);    MULADD(at[59], at[113]);    MULADD(at[60], at[112]);    MULADD(at[61], at[111]);    MULADD(at[62], at[110]);    MULADD(at[63], at[109]); 
   COMBA_STORE(C->dp[108]);
   /* 109 */
   COMBA_FORWARD;
   MULADD(at[46], at[127]);    MULADD(at[47], at[126]);    MULADD(at[48], at[125]);    MULADD(at[49], at[124]);    MULADD(at[50], at[123]);    MULADD(at[51], at[122]);    MULADD(at[52], at[121]);    MULADD(at[53], at[120]);    MULADD(at[54], at[119]);    MULADD(at[55], at[118]);    MULADD(at[56], at[117]);    MULADD(at[57], at[116]);    MULADD(at[58], at[115]);    MULADD(at[59], at[114]);    MULADD(at[60], at[113]);    MULADD(at[61], at[112]);    MULADD(at[62], at[111]);    MULADD(at[63], at[110]); 
   COMBA_STORE(C->dp[109]);
   /* 110 */
   COMBA_FORWARD;
   MULADD(at[47], at[127]);    MULADD(at[48], at[126]);    MULADD(at[49], at[125]);    MULADD(at[50], at[124]);    MULADD(at[51], at[123]);    MULADD(at[52], at[122]);    MULADD(at[53], at[121]);    MULADD(at[54], at[120]);    MULADD(at[55], at[119]);    MULADD(at[56], at[118]);    MULADD(at[57], at[117]);    MULADD(at[58], at[116]);    MULADD(at[59], at[115]);    MULADD(at[60], at[114]);    MULADD(at[61], at[113]);    MULADD(at[62], at[112]);    MULADD(at[63], at[111]); 
   COMBA_STORE(C->dp[110]);
   /* 111 */
   COMBA_FORWARD;
   MULADD(at[48], at[127]);    MULADD(at[49], at[126]);    MULADD(at[50], at[125]);    MULADD(at[51], at[124]);    MULADD(at[52], at[123]);    MULADD(at[53], at[122]);    MULADD(at[54], at[121]);    MULADD(at[55], at[120]);    MULADD(at[56], at[119]);    MULADD(at[57], at[118]);    MULADD(at[58], at[117]);    MULADD(at[59], at[116]);    MULADD(at[60], at[115]);    MULADD(at[61], at[114]);    MULADD(at[62], at[113]);    MULADD(at[63], at[112]); 
   COMBA_STORE(C->dp[111]);
   /* 112 */
   COMBA_FORWARD;
   MULADD(at[49], at[127]);    MULADD(at[50], at[126]);    MULADD(at[51], at[125]);    MULADD(at[52], at[124]);    MULADD(at[53], at[123]);    MULADD(at[54], at[122]);    MULADD(at[55], at[121]);    MULADD(at[56], at[120]);    MULADD(at[57], at[119]);    MULADD(at[58], at[118]);    MULADD(at[59], at[117]);    MULADD(at[60], at[116]);    MULADD(at[61], at[115]);    MULADD(at[62], at[114]);    MULADD(at[63], at[113]); 
   COMBA_STORE(C->dp[112]);
   /* 113 */
   COMBA_FORWARD;
   MULADD(at[50], at[127]);    MULADD(at[51], at[126]);    MULADD(at[52], at[125]);    MULADD(at[53], at[124]);    MULADD(at[54], at[123]);    MULADD(at[55], at[122]);    MULADD(at[56], at[121]);    MULADD(at[57], at[120]);    MULADD(at[58], at[119]);    MULADD(at[59], at[118]);    MULADD(at[60], at[117]);    MULADD(at[61], at[116]);    MULADD(at[62], at[115]);    MULADD(at[63], at[114]); 
   COMBA_STORE(C->dp[113]);
   /* 114 */
   COMBA_FORWARD;
   MULADD(at[51], at[127]);    MULADD(at[52], at[126]);    MULADD(at[53], at[125]);    MULADD(at[54], at[124]);    MULADD(at[55], at[123]);    MULADD(at[56], at[122]);    MULADD(at[57], at[121]);    MULADD(at[58], at[120]);    MULADD(at[59], at[119]);    MULADD(at[60], at[118]);    MULADD(at[61], at[117]);    MULADD(at[62], at[116]);    MULADD(at[63], at[115]); 
   COMBA_STORE(C->dp[114]);
   /* 115 */
   COMBA_FORWARD;
   MULADD(at[52], at[127]);    MULADD(at[53], at[126]);    MULADD(at[54], at[125]);    MULADD(at[55], at[124]);    MULADD(at[56], at[123]);    MULADD(at[57], at[122]);    MULADD(at[58], at[121]);    MULADD(at[59], at[120]);    MULADD(at[60], at[119]);    MULADD(at[61], at[118]);    MULADD(at[62], at[117]);    MULADD(at[63], at[116]); 
   COMBA_STORE(C->dp[115]);
   /* 116 */
   COMBA_FORWARD;
   MULADD(at[53], at[127]);    MULADD(at[54], at[126]);    MULADD(at[55], at[125]);    MULADD(at[56], at[124]);    MULADD(at[57], at[123]);    MULADD(at[58], at[122]);    MULADD(at[59], at[121]);    MULADD(at[60], at[120]);    MULADD(at[61], at[119]);    MULADD(at[62], at[118]);    MULADD(at[63], at[117]); 
   COMBA_STORE(C->dp[116]);
   /* 117 */
   COMBA_FORWARD;
   MULADD(at[54], at[127]);    MULADD(at[55], at[126]);    MULADD(at[56], at[125]);    MULADD(at[57], at[124]);    MULADD(at[58], at[123]);    MULADD(at[59], at[122]);    MULADD(at[60], at[121]);    MULADD(at[61], at[120]);    MULADD(at[62], at[119]);    MULADD(at[63], at[118]); 
   COMBA_STORE(C->dp[117]);
   /* 118 */
   COMBA_FORWARD;
   MULADD(at[55], at[127]);    MULADD(at[56], at[126]);    MULADD(at[57], at[125]);    MULADD(at[58], at[124]);    MULADD(at[59], at[123]);    MULADD(at[60], at[122]);    MULADD(at[61], at[121]);    MULADD(at[62], at[120]);    MULADD(at[63], at[119]); 
   COMBA_STORE(C->dp[118]);
   /* 119 */
   COMBA_FORWARD;
   MULADD(at[56], at[127]);    MULADD(at[57], at[126]);    MULADD(at[58], at[125]);    MULADD(at[59], at[124]);    MULADD(at[60], at[123]);    MULADD(at[61], at[122]);    MULADD(at[62], at[121]);    MULADD(at[63], at[120]); 
   COMBA_STORE(C->dp[119]);
   /* 120 */
   COMBA_FORWARD;
   MULADD(at[57], at[127]);    MULADD(at[58], at[126]);    MULADD(at[59], at[125]);    MULADD(at[60], at[124]);    MULADD(at[61], at[123]);    MULADD(at[62], at[122]);    MULADD(at[63], at[121]); 
   COMBA_STORE(C->dp[120]);
   /* 121 */
   COMBA_FORWARD;
   MULADD(at[58], at[127]);    MULADD(at[59], at[126]);    MULADD(at[60], at[125]);    MULADD(at[61], at[124]);    MULADD(at[62], at[123]);    MULADD(at[63], at[122]); 
   COMBA_STORE(C->dp[121]);
   /* 122 */
   COMBA_FORWARD;
   MULADD(at[59], at[127]);    MULADD(at[60], at[126]);    MULADD(at[61], at[125]);    MULADD(at[62], at[124]);    MULADD(at[63], at[123]); 
   COMBA_STORE(C->dp[122]);
   /* 123 */
   COMBA_FORWARD;
   MULADD(at[60], at[127]);    MULADD(at[61], at[126]);    MULADD(at[62], at[125]);    MULADD(at[63], at[124]); 
   COMBA_STORE(C->dp[123]);
   /* 124 */
   COMBA_FORWARD;
   MULADD(at[61], at[127]);    MULADD(at[62], at[126]);    MULADD(at[63], at[125]); 
   COMBA_STORE(C->dp[124]);
   /* 125 */
   COMBA_FORWARD;
   MULADD(at[62], at[127]);    MULADD(at[63], at[126]); 
   COMBA_STORE(C->dp[125]);
   /* 126 */
   COMBA_FORWARD;
   MULADD(at[63], at[127]); 
   COMBA_STORE(C->dp[126]);
   COMBA_STORE2(C->dp[127]);
   C->used = 128;
   C->sign = A->sign ^ B->sign;
   fp_clamp(C);
   COMBA_FINI;
}
#endif

/* End: fp_mul_comba_64.c */

/* Start: fp_mul_comba_7.c */
#define TFM_DEFINES
#include "fp_mul_comba.c"

#ifdef TFM_MUL7
void fp_mul_comba7(fp_int *A, fp_int *B, fp_int *C)
{
   fp_digit c0, c1, c2, at[14];

   memcpy(at, A->dp, 7 * sizeof(fp_digit));
   memcpy(at+7, B->dp, 7 * sizeof(fp_digit));
   COMBA_START;

   COMBA_CLEAR;
   /* 0 */
   MULADD(at[0], at[7]); 
   COMBA_STORE(C->dp[0]);
   /* 1 */
   COMBA_FORWARD;
   MULADD(at[0], at[8]);    MULADD(at[1], at[7]); 
   COMBA_STORE(C->dp[1]);
   /* 2 */
   COMBA_FORWARD;
   MULADD(at[0], at[9]);    MULADD(at[1], at[8]);    MULADD(at[2], at[7]); 
   COMBA_STORE(C->dp[2]);
   /* 3 */
   COMBA_FORWARD;
   MULADD(at[0], at[10]);    MULADD(at[1], at[9]);    MULADD(at[2], at[8]);    MULADD(at[3], at[7]); 
   COMBA_STORE(C->dp[3]);
   /* 4 */
   COMBA_FORWARD;
   MULADD(at[0], at[11]);    MULADD(at[1], at[10]);    MULADD(at[2], at[9]);    MULADD(at[3], at[8]);    MULADD(at[4], at[7]); 
   COMBA_STORE(C->dp[4]);
   /* 5 */
   COMBA_FORWARD;
   MULADD(at[0], at[12]);    MULADD(at[1], at[11]);    MULADD(at[2], at[10]);    MULADD(at[3], at[9]);    MULADD(at[4], at[8]);    MULADD(at[5], at[7]); 
   COMBA_STORE(C->dp[5]);
   /* 6 */
   COMBA_FORWARD;
   MULADD(at[0], at[13]);    MULADD(at[1], at[12]);    MULADD(at[2], at[11]);    MULADD(at[3], at[10]);    MULADD(at[4], at[9]);    MULADD(at[5], at[8]);    MULADD(at[6], at[7]); 
   COMBA_STORE(C->dp[6]);
   /* 7 */
   COMBA_FORWARD;
   MULADD(at[1], at[13]);    MULADD(at[2], at[12]);    MULADD(at[3], at[11]);    MULADD(at[4], at[10]);    MULADD(at[5], at[9]);    MULADD(at[6], at[8]); 
   COMBA_STORE(C->dp[7]);
   /* 8 */
   COMBA_FORWARD;
   MULADD(at[2], at[13]);    MULADD(at[3], at[12]);    MULADD(at[4], at[11]);    MULADD(at[5], at[10]);    MULADD(at[6], at[9]); 
   COMBA_STORE(C->dp[8]);
   /* 9 */
   COMBA_FORWARD;
   MULADD(at[3], at[13]);    MULADD(at[4], at[12]);    MULADD(at[5], at[11]);    MULADD(at[6], at[10]); 
   COMBA_STORE(C->dp[9]);
   /* 10 */
   COMBA_FORWARD;
   MULADD(at[4], at[13]);    MULADD(at[5], at[12]);    MULADD(at[6], at[11]); 
   COMBA_STORE(C->dp[10]);
   /* 11 */
   COMBA_FORWARD;
   MULADD(at[5], at[13]);    MULADD(at[6], at[12]); 
   COMBA_STORE(C->dp[11]);
   /* 12 */
   COMBA_FORWARD;
   MULADD(at[6], at[13]); 
   COMBA_STORE(C->dp[12]);
   COMBA_STORE2(C->dp[13]);
   C->used = 14;
   C->sign = A->sign ^ B->sign;
   fp_clamp(C);
   COMBA_FINI;
}
#endif

/* End: fp_mul_comba_7.c */

/* Start: fp_mul_comba_8.c */
#define TFM_DEFINES
#include "fp_mul_comba.c"

#ifdef TFM_MUL8
void fp_mul_comba8(fp_int *A, fp_int *B, fp_int *C)
{
   fp_digit c0, c1, c2, at[16];

   memcpy(at, A->dp, 8 * sizeof(fp_digit));
   memcpy(at+8, B->dp, 8 * sizeof(fp_digit));
   COMBA_START;

   COMBA_CLEAR;
   /* 0 */
   MULADD(at[0], at[8]); 
   COMBA_STORE(C->dp[0]);
   /* 1 */
   COMBA_FORWARD;
   MULADD(at[0], at[9]);    MULADD(at[1], at[8]); 
   COMBA_STORE(C->dp[1]);
   /* 2 */
   COMBA_FORWARD;
   MULADD(at[0], at[10]);    MULADD(at[1], at[9]);    MULADD(at[2], at[8]); 
   COMBA_STORE(C->dp[2]);
   /* 3 */
   COMBA_FORWARD;
   MULADD(at[0], at[11]);    MULADD(at[1], at[10]);    MULADD(at[2], at[9]);    MULADD(at[3], at[8]); 
   COMBA_STORE(C->dp[3]);
   /* 4 */
   COMBA_FORWARD;
   MULADD(at[0], at[12]);    MULADD(at[1], at[11]);    MULADD(at[2], at[10]);    MULADD(at[3], at[9]);    MULADD(at[4], at[8]); 
   COMBA_STORE(C->dp[4]);
   /* 5 */
   COMBA_FORWARD;
   MULADD(at[0], at[13]);    MULADD(at[1], at[12]);    MULADD(at[2], at[11]);    MULADD(at[3], at[10]);    MULADD(at[4], at[9]);    MULADD(at[5], at[8]); 
   COMBA_STORE(C->dp[5]);
   /* 6 */
   COMBA_FORWARD;
   MULADD(at[0], at[14]);    MULADD(at[1], at[13]);    MULADD(at[2], at[12]);    MULADD(at[3], at[11]);    MULADD(at[4], at[10]);    MULADD(at[5], at[9]);    MULADD(at[6], at[8]); 
   COMBA_STORE(C->dp[6]);
   /* 7 */
   COMBA_FORWARD;
   MULADD(at[0], at[15]);    MULADD(at[1], at[14]);    MULADD(at[2], at[13]);    MULADD(at[3], at[12]);    MULADD(at[4], at[11]);    MULADD(at[5], at[10]);    MULADD(at[6], at[9]);    MULADD(at[7], at[8]); 
   COMBA_STORE(C->dp[7]);
   /* 8 */
   COMBA_FORWARD;
   MULADD(at[1], at[15]);    MULADD(at[2], at[14]);    MULADD(at[3], at[13]);    MULADD(at[4], at[12]);    MULADD(at[5], at[11]);    MULADD(at[6], at[10]);    MULADD(at[7], at[9]); 
   COMBA_STORE(C->dp[8]);
   /* 9 */
   COMBA_FORWARD;
   MULADD(at[2], at[15]);    MULADD(at[3], at[14]);    MULADD(at[4], at[13]);    MULADD(at[5], at[12]);    MULADD(at[6], at[11]);    MULADD(at[7], at[10]); 
   COMBA_STORE(C->dp[9]);
   /* 10 */
   COMBA_FORWARD;
   MULADD(at[3], at[15]);    MULADD(at[4], at[14]);    MULADD(at[5], at[13]);    MULADD(at[6], at[12]);    MULADD(at[7], at[11]); 
   COMBA_STORE(C->dp[10]);
   /* 11 */
   COMBA_FORWARD;
   MULADD(at[4], at[15]);    MULADD(at[5], at[14]);    MULADD(at[6], at[13]);    MULADD(at[7], at[12]); 
   COMBA_STORE(C->dp[11]);
   /* 12 */
   COMBA_FORWARD;
   MULADD(at[5], at[15]);    MULADD(at[6], at[14]);    MULADD(at[7], at[13]); 
   COMBA_STORE(C->dp[12]);
   /* 13 */
   COMBA_FORWARD;
   MULADD(at[6], at[15]);    MULADD(at[7], at[14]); 
   COMBA_STORE(C->dp[13]);
   /* 14 */
   COMBA_FORWARD;
   MULADD(at[7], at[15]); 
   COMBA_STORE(C->dp[14]);
   COMBA_STORE2(C->dp[15]);
   C->used = 16;
   C->sign = A->sign ^ B->sign;
   fp_clamp(C);
   COMBA_FINI;
}
#endif

/* End: fp_mul_comba_8.c */

/* Start: fp_mul_comba_9.c */
#define TFM_DEFINES
#include "fp_mul_comba.c"

#ifdef TFM_MUL9
void fp_mul_comba9(fp_int *A, fp_int *B, fp_int *C)
{
   fp_digit c0, c1, c2, at[18];

   memcpy(at, A->dp, 9 * sizeof(fp_digit));
   memcpy(at+9, B->dp, 9 * sizeof(fp_digit));
   COMBA_START;

   COMBA_CLEAR;
   /* 0 */
   MULADD(at[0], at[9]); 
   COMBA_STORE(C->dp[0]);
   /* 1 */
   COMBA_FORWARD;
   MULADD(at[0], at[10]);    MULADD(at[1], at[9]); 
   COMBA_STORE(C->dp[1]);
   /* 2 */
   COMBA_FORWARD;
   MULADD(at[0], at[11]);    MULADD(at[1], at[10]);    MULADD(at[2], at[9]); 
   COMBA_STORE(C->dp[2]);
   /* 3 */
   COMBA_FORWARD;
   MULADD(at[0], at[12]);    MULADD(at[1], at[11]);    MULADD(at[2], at[10]);    MULADD(at[3], at[9]); 
   COMBA_STORE(C->dp[3]);
   /* 4 */
   COMBA_FORWARD;
   MULADD(at[0], at[13]);    MULADD(at[1], at[12]);    MULADD(at[2], at[11]);    MULADD(at[3], at[10]);    MULADD(at[4], at[9]); 
   COMBA_STORE(C->dp[4]);
   /* 5 */
   COMBA_FORWARD;
   MULADD(at[0], at[14]);    MULADD(at[1], at[13]);    MULADD(at[2], at[12]);    MULADD(at[3], at[11]);    MULADD(at[4], at[10]);    MULADD(at[5], at[9]); 
   COMBA_STORE(C->dp[5]);
   /* 6 */
   COMBA_FORWARD;
   MULADD(at[0], at[15]);    MULADD(at[1], at[14]);    MULADD(at[2], at[13]);    MULADD(at[3], at[12]);    MULADD(at[4], at[11]);    MULADD(at[5], at[10]);    MULADD(at[6], at[9]); 
   COMBA_STORE(C->dp[6]);
   /* 7 */
   COMBA_FORWARD;
   MULADD(at[0], at[16]);    MULADD(at[1], at[15]);    MULADD(at[2], at[14]);    MULADD(at[3], at[13]);    MULADD(at[4], at[12]);    MULADD(at[5], at[11]);    MULADD(at[6], at[10]);    MULADD(at[7], at[9]); 
   COMBA_STORE(C->dp[7]);
   /* 8 */
   COMBA_FORWARD;
   MULADD(at[0], at[17]);    MULADD(at[1], at[16]);    MULADD(at[2], at[15]);    MULADD(at[3], at[14]);    MULADD(at[4], at[13]);    MULADD(at[5], at[12]);    MULADD(at[6], at[11]);    MULADD(at[7], at[10]);    MULADD(at[8], at[9]); 
   COMBA_STORE(C->dp[8]);
   /* 9 */
   COMBA_FORWARD;
   MULADD(at[1], at[17]);    MULADD(at[2], at[16]);    MULADD(at[3], at[15]);    MULADD(at[4], at[14]);    MULADD(at[5], at[13]);    MULADD(at[6], at[12]);    MULADD(at[7], at[11]);    MULADD(at[8], at[10]); 
   COMBA_STORE(C->dp[9]);
   /* 10 */
   COMBA_FORWARD;
   MULADD(at[2], at[17]);    MULADD(at[3], at[16]);    MULADD(at[4], at[15]);    MULADD(at[5], at[14]);    MULADD(at[6], at[13]);    MULADD(at[7], at[12]);    MULADD(at[8], at[11]); 
   COMBA_STORE(C->dp[10]);
   /* 11 */
   COMBA_FORWARD;
   MULADD(at[3], at[17]);    MULADD(at[4], at[16]);    MULADD(at[5], at[15]);    MULADD(at[6], at[14]);    MULADD(at[7], at[13]);    MULADD(at[8], at[12]); 
   COMBA_STORE(C->dp[11]);
   /* 12 */
   COMBA_FORWARD;
   MULADD(at[4], at[17]);    MULADD(at[5], at[16]);    MULADD(at[6], at[15]);    MULADD(at[7], at[14]);    MULADD(at[8], at[13]); 
   COMBA_STORE(C->dp[12]);
   /* 13 */
   COMBA_FORWARD;
   MULADD(at[5], at[17]);    MULADD(at[6], at[16]);    MULADD(at[7], at[15]);    MULADD(at[8], at[14]); 
   COMBA_STORE(C->dp[13]);
   /* 14 */
   COMBA_FORWARD;
   MULADD(at[6], at[17]);    MULADD(at[7], at[16]);    MULADD(at[8], at[15]); 
   COMBA_STORE(C->dp[14]);
   /* 15 */
   COMBA_FORWARD;
   MULADD(at[7], at[17]);    MULADD(at[8], at[16]); 
   COMBA_STORE(C->dp[15]);
   /* 16 */
   COMBA_FORWARD;
   MULADD(at[8], at[17]); 
   COMBA_STORE(C->dp[16]);
   COMBA_STORE2(C->dp[17]);
   C->used = 18;
   C->sign = A->sign ^ B->sign;
   fp_clamp(C);
   COMBA_FINI;
}
#endif

/* End: fp_mul_comba_9.c */

/* Start: fp_mul_comba_small_set.c */
#define TFM_DEFINES
#include "fp_mul_comba.c"

#if defined(TFM_SMALL_SET)
void fp_mul_comba_small(fp_int *A, fp_int *B, fp_int *C)
{
   fp_digit c0, c1, c2, at[32];
   switch (MAX(A->used, B->used)) { 

   case 1:
      memcpy(at, A->dp, 1 * sizeof(fp_digit));
      memcpy(at+1, B->dp, 1 * sizeof(fp_digit));
      COMBA_START;

      COMBA_CLEAR;
      /* 0 */
      MULADD(at[0], at[1]); 
      COMBA_STORE(C->dp[0]);
      COMBA_STORE2(C->dp[1]);
      C->used = 2;
      C->sign = A->sign ^ B->sign;
      fp_clamp(C);
      COMBA_FINI;
      break;

   case 2:
      memcpy(at, A->dp, 2 * sizeof(fp_digit));
      memcpy(at+2, B->dp, 2 * sizeof(fp_digit));
      COMBA_START;

      COMBA_CLEAR;
      /* 0 */
      MULADD(at[0], at[2]); 
      COMBA_STORE(C->dp[0]);
      /* 1 */
      COMBA_FORWARD;
      MULADD(at[0], at[3]);       MULADD(at[1], at[2]); 
      COMBA_STORE(C->dp[1]);
      /* 2 */
      COMBA_FORWARD;
      MULADD(at[1], at[3]); 
      COMBA_STORE(C->dp[2]);
      COMBA_STORE2(C->dp[3]);
      C->used = 4;
      C->sign = A->sign ^ B->sign;
      fp_clamp(C);
      COMBA_FINI;
      break;

   case 3:
      memcpy(at, A->dp, 3 * sizeof(fp_digit));
      memcpy(at+3, B->dp, 3 * sizeof(fp_digit));
      COMBA_START;

      COMBA_CLEAR;
      /* 0 */
      MULADD(at[0], at[3]); 
      COMBA_STORE(C->dp[0]);
      /* 1 */
      COMBA_FORWARD;
      MULADD(at[0], at[4]);       MULADD(at[1], at[3]); 
      COMBA_STORE(C->dp[1]);
      /* 2 */
      COMBA_FORWARD;
      MULADD(at[0], at[5]);       MULADD(at[1], at[4]);       MULADD(at[2], at[3]); 
      COMBA_STORE(C->dp[2]);
      /* 3 */
      COMBA_FORWARD;
      MULADD(at[1], at[5]);       MULADD(at[2], at[4]); 
      COMBA_STORE(C->dp[3]);
      /* 4 */
      COMBA_FORWARD;
      MULADD(at[2], at[5]); 
      COMBA_STORE(C->dp[4]);
      COMBA_STORE2(C->dp[5]);
      C->used = 6;
      C->sign = A->sign ^ B->sign;
      fp_clamp(C);
      COMBA_FINI;
      break;

   case 4:
      memcpy(at, A->dp, 4 * sizeof(fp_digit));
      memcpy(at+4, B->dp, 4 * sizeof(fp_digit));
      COMBA_START;

      COMBA_CLEAR;
      /* 0 */
      MULADD(at[0], at[4]); 
      COMBA_STORE(C->dp[0]);
      /* 1 */
      COMBA_FORWARD;
      MULADD(at[0], at[5]);       MULADD(at[1], at[4]); 
      COMBA_STORE(C->dp[1]);
      /* 2 */
      COMBA_FORWARD;
      MULADD(at[0], at[6]);       MULADD(at[1], at[5]);       MULADD(at[2], at[4]); 
      COMBA_STORE(C->dp[2]);
      /* 3 */
      COMBA_FORWARD;
      MULADD(at[0], at[7]);       MULADD(at[1], at[6]);       MULADD(at[2], at[5]);       MULADD(at[3], at[4]); 
      COMBA_STORE(C->dp[3]);
      /* 4 */
      COMBA_FORWARD;
      MULADD(at[1], at[7]);       MULADD(at[2], at[6]);       MULADD(at[3], at[5]); 
      COMBA_STORE(C->dp[4]);
      /* 5 */
      COMBA_FORWARD;
      MULADD(at[2], at[7]);       MULADD(at[3], at[6]); 
      COMBA_STORE(C->dp[5]);
      /* 6 */
      COMBA_FORWARD;
      MULADD(at[3], at[7]); 
      COMBA_STORE(C->dp[6]);
      COMBA_STORE2(C->dp[7]);
      C->used = 8;
      C->sign = A->sign ^ B->sign;
      fp_clamp(C);
      COMBA_FINI;
      break;

   case 5:
      memcpy(at, A->dp, 5 * sizeof(fp_digit));
      memcpy(at+5, B->dp, 5 * sizeof(fp_digit));
      COMBA_START;

      COMBA_CLEAR;
      /* 0 */
      MULADD(at[0], at[5]); 
      COMBA_STORE(C->dp[0]);
      /* 1 */
      COMBA_FORWARD;
      MULADD(at[0], at[6]);       MULADD(at[1], at[5]); 
      COMBA_STORE(C->dp[1]);
      /* 2 */
      COMBA_FORWARD;
      MULADD(at[0], at[7]);       MULADD(at[1], at[6]);       MULADD(at[2], at[5]); 
      COMBA_STORE(C->dp[2]);
      /* 3 */
      COMBA_FORWARD;
      MULADD(at[0], at[8]);       MULADD(at[1], at[7]);       MULADD(at[2], at[6]);       MULADD(at[3], at[5]); 
      COMBA_STORE(C->dp[3]);
      /* 4 */
      COMBA_FORWARD;
      MULADD(at[0], at[9]);       MULADD(at[1], at[8]);       MULADD(at[2], at[7]);       MULADD(at[3], at[6]);       MULADD(at[4], at[5]); 
      COMBA_STORE(C->dp[4]);
      /* 5 */
      COMBA_FORWARD;
      MULADD(at[1], at[9]);       MULADD(at[2], at[8]);       MULADD(at[3], at[7]);       MULADD(at[4], at[6]); 
      COMBA_STORE(C->dp[5]);
      /* 6 */
      COMBA_FORWARD;
      MULADD(at[2], at[9]);       MULADD(at[3], at[8]);       MULADD(at[4], at[7]); 
      COMBA_STORE(C->dp[6]);
      /* 7 */
      COMBA_FORWARD;
      MULADD(at[3], at[9]);       MULADD(at[4], at[8]); 
      COMBA_STORE(C->dp[7]);
      /* 8 */
      COMBA_FORWARD;
      MULADD(at[4], at[9]); 
      COMBA_STORE(C->dp[8]);
      COMBA_STORE2(C->dp[9]);
      C->used = 10;
      C->sign = A->sign ^ B->sign;
      fp_clamp(C);
      COMBA_FINI;
      break;

   case 6:
      memcpy(at, A->dp, 6 * sizeof(fp_digit));
      memcpy(at+6, B->dp, 6 * sizeof(fp_digit));
      COMBA_START;

      COMBA_CLEAR;
      /* 0 */
      MULADD(at[0], at[6]); 
      COMBA_STORE(C->dp[0]);
      /* 1 */
      COMBA_FORWARD;
      MULADD(at[0], at[7]);       MULADD(at[1], at[6]); 
      COMBA_STORE(C->dp[1]);
      /* 2 */
      COMBA_FORWARD;
      MULADD(at[0], at[8]);       MULADD(at[1], at[7]);       MULADD(at[2], at[6]); 
      COMBA_STORE(C->dp[2]);
      /* 3 */
      COMBA_FORWARD;
      MULADD(at[0], at[9]);       MULADD(at[1], at[8]);       MULADD(at[2], at[7]);       MULADD(at[3], at[6]); 
      COMBA_STORE(C->dp[3]);
      /* 4 */
      COMBA_FORWARD;
      MULADD(at[0], at[10]);       MULADD(at[1], at[9]);       MULADD(at[2], at[8]);       MULADD(at[3], at[7]);       MULADD(at[4], at[6]); 
      COMBA_STORE(C->dp[4]);
      /* 5 */
      COMBA_FORWARD;
      MULADD(at[0], at[11]);       MULADD(at[1], at[10]);       MULADD(at[2], at[9]);       MULADD(at[3], at[8]);       MULADD(at[4], at[7]);       MULADD(at[5], at[6]); 
      COMBA_STORE(C->dp[5]);
      /* 6 */
      COMBA_FORWARD;
      MULADD(at[1], at[11]);       MULADD(at[2], at[10]);       MULADD(at[3], at[9]);       MULADD(at[4], at[8]);       MULADD(at[5], at[7]); 
      COMBA_STORE(C->dp[6]);
      /* 7 */
      COMBA_FORWARD;
      MULADD(at[2], at[11]);       MULADD(at[3], at[10]);       MULADD(at[4], at[9]);       MULADD(at[5], at[8]); 
      COMBA_STORE(C->dp[7]);
      /* 8 */
      COMBA_FORWARD;
      MULADD(at[3], at[11]);       MULADD(at[4], at[10]);       MULADD(at[5], at[9]); 
      COMBA_STORE(C->dp[8]);
      /* 9 */
      COMBA_FORWARD;
      MULADD(at[4], at[11]);       MULADD(at[5], at[10]); 
      COMBA_STORE(C->dp[9]);
      /* 10 */
      COMBA_FORWARD;
      MULADD(at[5], at[11]); 
      COMBA_STORE(C->dp[10]);
      COMBA_STORE2(C->dp[11]);
      C->used = 12;
      C->sign = A->sign ^ B->sign;
      fp_clamp(C);
      COMBA_FINI;
      break;

   case 7:
      memcpy(at, A->dp, 7 * sizeof(fp_digit));
      memcpy(at+7, B->dp, 7 * sizeof(fp_digit));
      COMBA_START;

      COMBA_CLEAR;
      /* 0 */
      MULADD(at[0], at[7]); 
      COMBA_STORE(C->dp[0]);
      /* 1 */
      COMBA_FORWARD;
      MULADD(at[0], at[8]);       MULADD(at[1], at[7]); 
      COMBA_STORE(C->dp[1]);
      /* 2 */
      COMBA_FORWARD;
      MULADD(at[0], at[9]);       MULADD(at[1], at[8]);       MULADD(at[2], at[7]); 
      COMBA_STORE(C->dp[2]);
      /* 3 */
      COMBA_FORWARD;
      MULADD(at[0], at[10]);       MULADD(at[1], at[9]);       MULADD(at[2], at[8]);       MULADD(at[3], at[7]); 
      COMBA_STORE(C->dp[3]);
      /* 4 */
      COMBA_FORWARD;
      MULADD(at[0], at[11]);       MULADD(at[1], at[10]);       MULADD(at[2], at[9]);       MULADD(at[3], at[8]);       MULADD(at[4], at[7]); 
      COMBA_STORE(C->dp[4]);
      /* 5 */
      COMBA_FORWARD;
      MULADD(at[0], at[12]);       MULADD(at[1], at[11]);       MULADD(at[2], at[10]);       MULADD(at[3], at[9]);       MULADD(at[4], at[8]);       MULADD(at[5], at[7]); 
      COMBA_STORE(C->dp[5]);
      /* 6 */
      COMBA_FORWARD;
      MULADD(at[0], at[13]);       MULADD(at[1], at[12]);       MULADD(at[2], at[11]);       MULADD(at[3], at[10]);       MULADD(at[4], at[9]);       MULADD(at[5], at[8]);       MULADD(at[6], at[7]); 
      COMBA_STORE(C->dp[6]);
      /* 7 */
      COMBA_FORWARD;
      MULADD(at[1], at[13]);       MULADD(at[2], at[12]);       MULADD(at[3], at[11]);       MULADD(at[4], at[10]);       MULADD(at[5], at[9]);       MULADD(at[6], at[8]); 
      COMBA_STORE(C->dp[7]);
      /* 8 */
      COMBA_FORWARD;
      MULADD(at[2], at[13]);       MULADD(at[3], at[12]);       MULADD(at[4], at[11]);       MULADD(at[5], at[10]);       MULADD(at[6], at[9]); 
      COMBA_STORE(C->dp[8]);
      /* 9 */
      COMBA_FORWARD;
      MULADD(at[3], at[13]);       MULADD(at[4], at[12]);       MULADD(at[5], at[11]);       MULADD(at[6], at[10]); 
      COMBA_STORE(C->dp[9]);
      /* 10 */
      COMBA_FORWARD;
      MULADD(at[4], at[13]);       MULADD(at[5], at[12]);       MULADD(at[6], at[11]); 
      COMBA_STORE(C->dp[10]);
      /* 11 */
      COMBA_FORWARD;
      MULADD(at[5], at[13]);       MULADD(at[6], at[12]); 
      COMBA_STORE(C->dp[11]);
      /* 12 */
      COMBA_FORWARD;
      MULADD(at[6], at[13]); 
      COMBA_STORE(C->dp[12]);
      COMBA_STORE2(C->dp[13]);
      C->used = 14;
      C->sign = A->sign ^ B->sign;
      fp_clamp(C);
      COMBA_FINI;
      break;

   case 8:
      memcpy(at, A->dp, 8 * sizeof(fp_digit));
      memcpy(at+8, B->dp, 8 * sizeof(fp_digit));
      COMBA_START;

      COMBA_CLEAR;
      /* 0 */
      MULADD(at[0], at[8]); 
      COMBA_STORE(C->dp[0]);
      /* 1 */
      COMBA_FORWARD;
      MULADD(at[0], at[9]);       MULADD(at[1], at[8]); 
      COMBA_STORE(C->dp[1]);
      /* 2 */
      COMBA_FORWARD;
      MULADD(at[0], at[10]);       MULADD(at[1], at[9]);       MULADD(at[2], at[8]); 
      COMBA_STORE(C->dp[2]);
      /* 3 */
      COMBA_FORWARD;
      MULADD(at[0], at[11]);       MULADD(at[1], at[10]);       MULADD(at[2], at[9]);       MULADD(at[3], at[8]); 
      COMBA_STORE(C->dp[3]);
      /* 4 */
      COMBA_FORWARD;
      MULADD(at[0], at[12]);       MULADD(at[1], at[11]);       MULADD(at[2], at[10]);       MULADD(at[3], at[9]);       MULADD(at[4], at[8]); 
      COMBA_STORE(C->dp[4]);
      /* 5 */
      COMBA_FORWARD;
      MULADD(at[0], at[13]);       MULADD(at[1], at[12]);       MULADD(at[2], at[11]);       MULADD(at[3], at[10]);       MULADD(at[4], at[9]);       MULADD(at[5], at[8]); 
      COMBA_STORE(C->dp[5]);
      /* 6 */
      COMBA_FORWARD;
      MULADD(at[0], at[14]);       MULADD(at[1], at[13]);       MULADD(at[2], at[12]);       MULADD(at[3], at[11]);       MULADD(at[4], at[10]);       MULADD(at[5], at[9]);       MULADD(at[6], at[8]); 
      COMBA_STORE(C->dp[6]);
      /* 7 */
      COMBA_FORWARD;
      MULADD(at[0], at[15]);       MULADD(at[1], at[14]);       MULADD(at[2], at[13]);       MULADD(at[3], at[12]);       MULADD(at[4], at[11]);       MULADD(at[5], at[10]);       MULADD(at[6], at[9]);       MULADD(at[7], at[8]); 
      COMBA_STORE(C->dp[7]);
      /* 8 */
      COMBA_FORWARD;
      MULADD(at[1], at[15]);       MULADD(at[2], at[14]);       MULADD(at[3], at[13]);       MULADD(at[4], at[12]);       MULADD(at[5], at[11]);       MULADD(at[6], at[10]);       MULADD(at[7], at[9]); 
      COMBA_STORE(C->dp[8]);
      /* 9 */
      COMBA_FORWARD;
      MULADD(at[2], at[15]);       MULADD(at[3], at[14]);       MULADD(at[4], at[13]);       MULADD(at[5], at[12]);       MULADD(at[6], at[11]);       MULADD(at[7], at[10]); 
      COMBA_STORE(C->dp[9]);
      /* 10 */
      COMBA_FORWARD;
      MULADD(at[3], at[15]);       MULADD(at[4], at[14]);       MULADD(at[5], at[13]);       MULADD(at[6], at[12]);       MULADD(at[7], at[11]); 
      COMBA_STORE(C->dp[10]);
      /* 11 */
      COMBA_FORWARD;
      MULADD(at[4], at[15]);       MULADD(at[5], at[14]);       MULADD(at[6], at[13]);       MULADD(at[7], at[12]); 
      COMBA_STORE(C->dp[11]);
      /* 12 */
      COMBA_FORWARD;
      MULADD(at[5], at[15]);       MULADD(at[6], at[14]);       MULADD(at[7], at[13]); 
      COMBA_STORE(C->dp[12]);
      /* 13 */
      COMBA_FORWARD;
      MULADD(at[6], at[15]);       MULADD(at[7], at[14]); 
      COMBA_STORE(C->dp[13]);
      /* 14 */
      COMBA_FORWARD;
      MULADD(at[7], at[15]); 
      COMBA_STORE(C->dp[14]);
      COMBA_STORE2(C->dp[15]);
      C->used = 16;
      C->sign = A->sign ^ B->sign;
      fp_clamp(C);
      COMBA_FINI;
      break;

   case 9:
      memcpy(at, A->dp, 9 * sizeof(fp_digit));
      memcpy(at+9, B->dp, 9 * sizeof(fp_digit));
      COMBA_START;

      COMBA_CLEAR;
      /* 0 */
      MULADD(at[0], at[9]); 
      COMBA_STORE(C->dp[0]);
      /* 1 */
      COMBA_FORWARD;
      MULADD(at[0], at[10]);       MULADD(at[1], at[9]); 
      COMBA_STORE(C->dp[1]);
      /* 2 */
      COMBA_FORWARD;
      MULADD(at[0], at[11]);       MULADD(at[1], at[10]);       MULADD(at[2], at[9]); 
      COMBA_STORE(C->dp[2]);
      /* 3 */
      COMBA_FORWARD;
      MULADD(at[0], at[12]);       MULADD(at[1], at[11]);       MULADD(at[2], at[10]);       MULADD(at[3], at[9]); 
      COMBA_STORE(C->dp[3]);
      /* 4 */
      COMBA_FORWARD;
      MULADD(at[0], at[13]);       MULADD(at[1], at[12]);       MULADD(at[2], at[11]);       MULADD(at[3], at[10]);       MULADD(at[4], at[9]); 
      COMBA_STORE(C->dp[4]);
      /* 5 */
      COMBA_FORWARD;
      MULADD(at[0], at[14]);       MULADD(at[1], at[13]);       MULADD(at[2], at[12]);       MULADD(at[3], at[11]);       MULADD(at[4], at[10]);       MULADD(at[5], at[9]); 
      COMBA_STORE(C->dp[5]);
      /* 6 */
      COMBA_FORWARD;
      MULADD(at[0], at[15]);       MULADD(at[1], at[14]);       MULADD(at[2], at[13]);       MULADD(at[3], at[12]);       MULADD(at[4], at[11]);       MULADD(at[5], at[10]);       MULADD(at[6], at[9]); 
      COMBA_STORE(C->dp[6]);
      /* 7 */
      COMBA_FORWARD;
      MULADD(at[0], at[16]);       MULADD(at[1], at[15]);       MULADD(at[2], at[14]);       MULADD(at[3], at[13]);       MULADD(at[4], at[12]);       MULADD(at[5], at[11]);       MULADD(at[6], at[10]);       MULADD(at[7], at[9]); 
      COMBA_STORE(C->dp[7]);
      /* 8 */
      COMBA_FORWARD;
      MULADD(at[0], at[17]);       MULADD(at[1], at[16]);       MULADD(at[2], at[15]);       MULADD(at[3], at[14]);       MULADD(at[4], at[13]);       MULADD(at[5], at[12]);       MULADD(at[6], at[11]);       MULADD(at[7], at[10]);       MULADD(at[8], at[9]); 
      COMBA_STORE(C->dp[8]);
      /* 9 */
      COMBA_FORWARD;
      MULADD(at[1], at[17]);       MULADD(at[2], at[16]);       MULADD(at[3], at[15]);       MULADD(at[4], at[14]);       MULADD(at[5], at[13]);       MULADD(at[6], at[12]);       MULADD(at[7], at[11]);       MULADD(at[8], at[10]); 
      COMBA_STORE(C->dp[9]);
      /* 10 */
      COMBA_FORWARD;
      MULADD(at[2], at[17]);       MULADD(at[3], at[16]);       MULADD(at[4], at[15]);       MULADD(at[5], at[14]);       MULADD(at[6], at[13]);       MULADD(at[7], at[12]);       MULADD(at[8], at[11]); 
      COMBA_STORE(C->dp[10]);
      /* 11 */
      COMBA_FORWARD;
      MULADD(at[3], at[17]);       MULADD(at[4], at[16]);       MULADD(at[5], at[15]);       MULADD(at[6], at[14]);       MULADD(at[7], at[13]);       MULADD(at[8], at[12]); 
      COMBA_STORE(C->dp[11]);
      /* 12 */
      COMBA_FORWARD;
      MULADD(at[4], at[17]);       MULADD(at[5], at[16]);       MULADD(at[6], at[15]);       MULADD(at[7], at[14]);       MULADD(at[8], at[13]); 
      COMBA_STORE(C->dp[12]);
      /* 13 */
      COMBA_FORWARD;
      MULADD(at[5], at[17]);       MULADD(at[6], at[16]);       MULADD(at[7], at[15]);       MULADD(at[8], at[14]); 
      COMBA_STORE(C->dp[13]);
      /* 14 */
      COMBA_FORWARD;
      MULADD(at[6], at[17]);       MULADD(at[7], at[16]);       MULADD(at[8], at[15]); 
      COMBA_STORE(C->dp[14]);
      /* 15 */
      COMBA_FORWARD;
      MULADD(at[7], at[17]);       MULADD(at[8], at[16]); 
      COMBA_STORE(C->dp[15]);
      /* 16 */
      COMBA_FORWARD;
      MULADD(at[8], at[17]); 
      COMBA_STORE(C->dp[16]);
      COMBA_STORE2(C->dp[17]);
      C->used = 18;
      C->sign = A->sign ^ B->sign;
      fp_clamp(C);
      COMBA_FINI;
      break;

   case 10:
      memcpy(at, A->dp, 10 * sizeof(fp_digit));
      memcpy(at+10, B->dp, 10 * sizeof(fp_digit));
      COMBA_START;

      COMBA_CLEAR;
      /* 0 */
      MULADD(at[0], at[10]); 
      COMBA_STORE(C->dp[0]);
      /* 1 */
      COMBA_FORWARD;
      MULADD(at[0], at[11]);       MULADD(at[1], at[10]); 
      COMBA_STORE(C->dp[1]);
      /* 2 */
      COMBA_FORWARD;
      MULADD(at[0], at[12]);       MULADD(at[1], at[11]);       MULADD(at[2], at[10]); 
      COMBA_STORE(C->dp[2]);
      /* 3 */
      COMBA_FORWARD;
      MULADD(at[0], at[13]);       MULADD(at[1], at[12]);       MULADD(at[2], at[11]);       MULADD(at[3], at[10]); 
      COMBA_STORE(C->dp[3]);
      /* 4 */
      COMBA_FORWARD;
      MULADD(at[0], at[14]);       MULADD(at[1], at[13]);       MULADD(at[2], at[12]);       MULADD(at[3], at[11]);       MULADD(at[4], at[10]); 
      COMBA_STORE(C->dp[4]);
      /* 5 */
      COMBA_FORWARD;
      MULADD(at[0], at[15]);       MULADD(at[1], at[14]);       MULADD(at[2], at[13]);       MULADD(at[3], at[12]);       MULADD(at[4], at[11]);       MULADD(at[5], at[10]); 
      COMBA_STORE(C->dp[5]);
      /* 6 */
      COMBA_FORWARD;
      MULADD(at[0], at[16]);       MULADD(at[1], at[15]);       MULADD(at[2], at[14]);       MULADD(at[3], at[13]);       MULADD(at[4], at[12]);       MULADD(at[5], at[11]);       MULADD(at[6], at[10]); 
      COMBA_STORE(C->dp[6]);
      /* 7 */
      COMBA_FORWARD;
      MULADD(at[0], at[17]);       MULADD(at[1], at[16]);       MULADD(at[2], at[15]);       MULADD(at[3], at[14]);       MULADD(at[4], at[13]);       MULADD(at[5], at[12]);       MULADD(at[6], at[11]);       MULADD(at[7], at[10]); 
      COMBA_STORE(C->dp[7]);
      /* 8 */
      COMBA_FORWARD;
      MULADD(at[0], at[18]);       MULADD(at[1], at[17]);       MULADD(at[2], at[16]);       MULADD(at[3], at[15]);       MULADD(at[4], at[14]);       MULADD(at[5], at[13]);       MULADD(at[6], at[12]);       MULADD(at[7], at[11]);       MULADD(at[8], at[10]); 
      COMBA_STORE(C->dp[8]);
      /* 9 */
      COMBA_FORWARD;
      MULADD(at[0], at[19]);       MULADD(at[1], at[18]);       MULADD(at[2], at[17]);       MULADD(at[3], at[16]);       MULADD(at[4], at[15]);       MULADD(at[5], at[14]);       MULADD(at[6], at[13]);       MULADD(at[7], at[12]);       MULADD(at[8], at[11]);       MULADD(at[9], at[10]); 
      COMBA_STORE(C->dp[9]);
      /* 10 */
      COMBA_FORWARD;
      MULADD(at[1], at[19]);       MULADD(at[2], at[18]);       MULADD(at[3], at[17]);       MULADD(at[4], at[16]);       MULADD(at[5], at[15]);       MULADD(at[6], at[14]);       MULADD(at[7], at[13]);       MULADD(at[8], at[12]);       MULADD(at[9], at[11]); 
      COMBA_STORE(C->dp[10]);
      /* 11 */
      COMBA_FORWARD;
      MULADD(at[2], at[19]);       MULADD(at[3], at[18]);       MULADD(at[4], at[17]);       MULADD(at[5], at[16]);       MULADD(at[6], at[15]);       MULADD(at[7], at[14]);       MULADD(at[8], at[13]);       MULADD(at[9], at[12]); 
      COMBA_STORE(C->dp[11]);
      /* 12 */
      COMBA_FORWARD;
      MULADD(at[3], at[19]);       MULADD(at[4], at[18]);       MULADD(at[5], at[17]);       MULADD(at[6], at[16]);       MULADD(at[7], at[15]);       MULADD(at[8], at[14]);       MULADD(at[9], at[13]); 
      COMBA_STORE(C->dp[12]);
      /* 13 */
      COMBA_FORWARD;
      MULADD(at[4], at[19]);       MULADD(at[5], at[18]);       MULADD(at[6], at[17]);       MULADD(at[7], at[16]);       MULADD(at[8], at[15]);       MULADD(at[9], at[14]); 
      COMBA_STORE(C->dp[13]);
      /* 14 */
      COMBA_FORWARD;
      MULADD(at[5], at[19]);       MULADD(at[6], at[18]);       MULADD(at[7], at[17]);       MULADD(at[8], at[16]);       MULADD(at[9], at[15]); 
      COMBA_STORE(C->dp[14]);
      /* 15 */
      COMBA_FORWARD;
      MULADD(at[6], at[19]);       MULADD(at[7], at[18]);       MULADD(at[8], at[17]);       MULADD(at[9], at[16]); 
      COMBA_STORE(C->dp[15]);
      /* 16 */
      COMBA_FORWARD;
      MULADD(at[7], at[19]);       MULADD(at[8], at[18]);       MULADD(at[9], at[17]); 
      COMBA_STORE(C->dp[16]);
      /* 17 */
      COMBA_FORWARD;
      MULADD(at[8], at[19]);       MULADD(at[9], at[18]); 
      COMBA_STORE(C->dp[17]);
      /* 18 */
      COMBA_FORWARD;
      MULADD(at[9], at[19]); 
      COMBA_STORE(C->dp[18]);
      COMBA_STORE2(C->dp[19]);
      C->used = 20;
      C->sign = A->sign ^ B->sign;
      fp_clamp(C);
      COMBA_FINI;
      break;

   case 11:
      memcpy(at, A->dp, 11 * sizeof(fp_digit));
      memcpy(at+11, B->dp, 11 * sizeof(fp_digit));
      COMBA_START;

      COMBA_CLEAR;
      /* 0 */
      MULADD(at[0], at[11]); 
      COMBA_STORE(C->dp[0]);
      /* 1 */
      COMBA_FORWARD;
      MULADD(at[0], at[12]);       MULADD(at[1], at[11]); 
      COMBA_STORE(C->dp[1]);
      /* 2 */
      COMBA_FORWARD;
      MULADD(at[0], at[13]);       MULADD(at[1], at[12]);       MULADD(at[2], at[11]); 
      COMBA_STORE(C->dp[2]);
      /* 3 */
      COMBA_FORWARD;
      MULADD(at[0], at[14]);       MULADD(at[1], at[13]);       MULADD(at[2], at[12]);       MULADD(at[3], at[11]); 
      COMBA_STORE(C->dp[3]);
      /* 4 */
      COMBA_FORWARD;
      MULADD(at[0], at[15]);       MULADD(at[1], at[14]);       MULADD(at[2], at[13]);       MULADD(at[3], at[12]);       MULADD(at[4], at[11]); 
      COMBA_STORE(C->dp[4]);
      /* 5 */
      COMBA_FORWARD;
      MULADD(at[0], at[16]);       MULADD(at[1], at[15]);       MULADD(at[2], at[14]);       MULADD(at[3], at[13]);       MULADD(at[4], at[12]);       MULADD(at[5], at[11]); 
      COMBA_STORE(C->dp[5]);
      /* 6 */
      COMBA_FORWARD;
      MULADD(at[0], at[17]);       MULADD(at[1], at[16]);       MULADD(at[2], at[15]);       MULADD(at[3], at[14]);       MULADD(at[4], at[13]);       MULADD(at[5], at[12]);       MULADD(at[6], at[11]); 
      COMBA_STORE(C->dp[6]);
      /* 7 */
      COMBA_FORWARD;
      MULADD(at[0], at[18]);       MULADD(at[1], at[17]);       MULADD(at[2], at[16]);       MULADD(at[3], at[15]);       MULADD(at[4], at[14]);       MULADD(at[5], at[13]);       MULADD(at[6], at[12]);       MULADD(at[7], at[11]); 
      COMBA_STORE(C->dp[7]);
      /* 8 */
      COMBA_FORWARD;
      MULADD(at[0], at[19]);       MULADD(at[1], at[18]);       MULADD(at[2], at[17]);       MULADD(at[3], at[16]);       MULADD(at[4], at[15]);       MULADD(at[5], at[14]);       MULADD(at[6], at[13]);       MULADD(at[7], at[12]);       MULADD(at[8], at[11]); 
      COMBA_STORE(C->dp[8]);
      /* 9 */
      COMBA_FORWARD;
      MULADD(at[0], at[20]);       MULADD(at[1], at[19]);       MULADD(at[2], at[18]);       MULADD(at[3], at[17]);       MULADD(at[4], at[16]);       MULADD(at[5], at[15]);       MULADD(at[6], at[14]);       MULADD(at[7], at[13]);       MULADD(at[8], at[12]);       MULADD(at[9], at[11]); 
      COMBA_STORE(C->dp[9]);
      /* 10 */
      COMBA_FORWARD;
      MULADD(at[0], at[21]);       MULADD(at[1], at[20]);       MULADD(at[2], at[19]);       MULADD(at[3], at[18]);       MULADD(at[4], at[17]);       MULADD(at[5], at[16]);       MULADD(at[6], at[15]);       MULADD(at[7], at[14]);       MULADD(at[8], at[13]);       MULADD(at[9], at[12]);       MULADD(at[10], at[11]); 
      COMBA_STORE(C->dp[10]);
      /* 11 */
      COMBA_FORWARD;
      MULADD(at[1], at[21]);       MULADD(at[2], at[20]);       MULADD(at[3], at[19]);       MULADD(at[4], at[18]);       MULADD(at[5], at[17]);       MULADD(at[6], at[16]);       MULADD(at[7], at[15]);       MULADD(at[8], at[14]);       MULADD(at[9], at[13]);       MULADD(at[10], at[12]); 
      COMBA_STORE(C->dp[11]);
      /* 12 */
      COMBA_FORWARD;
      MULADD(at[2], at[21]);       MULADD(at[3], at[20]);       MULADD(at[4], at[19]);       MULADD(at[5], at[18]);       MULADD(at[6], at[17]);       MULADD(at[7], at[16]);       MULADD(at[8], at[15]);       MULADD(at[9], at[14]);       MULADD(at[10], at[13]); 
      COMBA_STORE(C->dp[12]);
      /* 13 */
      COMBA_FORWARD;
      MULADD(at[3], at[21]);       MULADD(at[4], at[20]);       MULADD(at[5], at[19]);       MULADD(at[6], at[18]);       MULADD(at[7], at[17]);       MULADD(at[8], at[16]);       MULADD(at[9], at[15]);       MULADD(at[10], at[14]); 
      COMBA_STORE(C->dp[13]);
      /* 14 */
      COMBA_FORWARD;
      MULADD(at[4], at[21]);       MULADD(at[5], at[20]);       MULADD(at[6], at[19]);       MULADD(at[7], at[18]);       MULADD(at[8], at[17]);       MULADD(at[9], at[16]);       MULADD(at[10], at[15]); 
      COMBA_STORE(C->dp[14]);
      /* 15 */
      COMBA_FORWARD;
      MULADD(at[5], at[21]);       MULADD(at[6], at[20]);       MULADD(at[7], at[19]);       MULADD(at[8], at[18]);       MULADD(at[9], at[17]);       MULADD(at[10], at[16]); 
      COMBA_STORE(C->dp[15]);
      /* 16 */
      COMBA_FORWARD;
      MULADD(at[6], at[21]);       MULADD(at[7], at[20]);       MULADD(at[8], at[19]);       MULADD(at[9], at[18]);       MULADD(at[10], at[17]); 
      COMBA_STORE(C->dp[16]);
      /* 17 */
      COMBA_FORWARD;
      MULADD(at[7], at[21]);       MULADD(at[8], at[20]);       MULADD(at[9], at[19]);       MULADD(at[10], at[18]); 
      COMBA_STORE(C->dp[17]);
      /* 18 */
      COMBA_FORWARD;
      MULADD(at[8], at[21]);       MULADD(at[9], at[20]);       MULADD(at[10], at[19]); 
      COMBA_STORE(C->dp[18]);
      /* 19 */
      COMBA_FORWARD;
      MULADD(at[9], at[21]);       MULADD(at[10], at[20]); 
      COMBA_STORE(C->dp[19]);
      /* 20 */
      COMBA_FORWARD;
      MULADD(at[10], at[21]); 
      COMBA_STORE(C->dp[20]);
      COMBA_STORE2(C->dp[21]);
      C->used = 22;
      C->sign = A->sign ^ B->sign;
      fp_clamp(C);
      COMBA_FINI;
      break;

   case 12:
      memcpy(at, A->dp, 12 * sizeof(fp_digit));
      memcpy(at+12, B->dp, 12 * sizeof(fp_digit));
      COMBA_START;

      COMBA_CLEAR;
      /* 0 */
      MULADD(at[0], at[12]); 
      COMBA_STORE(C->dp[0]);
      /* 1 */
      COMBA_FORWARD;
      MULADD(at[0], at[13]);       MULADD(at[1], at[12]); 
      COMBA_STORE(C->dp[1]);
      /* 2 */
      COMBA_FORWARD;
      MULADD(at[0], at[14]);       MULADD(at[1], at[13]);       MULADD(at[2], at[12]); 
      COMBA_STORE(C->dp[2]);
      /* 3 */
      COMBA_FORWARD;
      MULADD(at[0], at[15]);       MULADD(at[1], at[14]);       MULADD(at[2], at[13]);       MULADD(at[3], at[12]); 
      COMBA_STORE(C->dp[3]);
      /* 4 */
      COMBA_FORWARD;
      MULADD(at[0], at[16]);       MULADD(at[1], at[15]);       MULADD(at[2], at[14]);       MULADD(at[3], at[13]);       MULADD(at[4], at[12]); 
      COMBA_STORE(C->dp[4]);
      /* 5 */
      COMBA_FORWARD;
      MULADD(at[0], at[17]);       MULADD(at[1], at[16]);       MULADD(at[2], at[15]);       MULADD(at[3], at[14]);       MULADD(at[4], at[13]);       MULADD(at[5], at[12]); 
      COMBA_STORE(C->dp[5]);
      /* 6 */
      COMBA_FORWARD;
      MULADD(at[0], at[18]);       MULADD(at[1], at[17]);       MULADD(at[2], at[16]);       MULADD(at[3], at[15]);       MULADD(at[4], at[14]);       MULADD(at[5], at[13]);       MULADD(at[6], at[12]); 
      COMBA_STORE(C->dp[6]);
      /* 7 */
      COMBA_FORWARD;
      MULADD(at[0], at[19]);       MULADD(at[1], at[18]);       MULADD(at[2], at[17]);       MULADD(at[3], at[16]);       MULADD(at[4], at[15]);       MULADD(at[5], at[14]);       MULADD(at[6], at[13]);       MULADD(at[7], at[12]); 
      COMBA_STORE(C->dp[7]);
      /* 8 */
      COMBA_FORWARD;
      MULADD(at[0], at[20]);       MULADD(at[1], at[19]);       MULADD(at[2], at[18]);       MULADD(at[3], at[17]);       MULADD(at[4], at[16]);       MULADD(at[5], at[15]);       MULADD(at[6], at[14]);       MULADD(at[7], at[13]);       MULADD(at[8], at[12]); 
      COMBA_STORE(C->dp[8]);
      /* 9 */
      COMBA_FORWARD;
      MULADD(at[0], at[21]);       MULADD(at[1], at[20]);       MULADD(at[2], at[19]);       MULADD(at[3], at[18]);       MULADD(at[4], at[17]);       MULADD(at[5], at[16]);       MULADD(at[6], at[15]);       MULADD(at[7], at[14]);       MULADD(at[8], at[13]);       MULADD(at[9], at[12]); 
      COMBA_STORE(C->dp[9]);
      /* 10 */
      COMBA_FORWARD;
      MULADD(at[0], at[22]);       MULADD(at[1], at[21]);       MULADD(at[2], at[20]);       MULADD(at[3], at[19]);       MULADD(at[4], at[18]);       MULADD(at[5], at[17]);       MULADD(at[6], at[16]);       MULADD(at[7], at[15]);       MULADD(at[8], at[14]);       MULADD(at[9], at[13]);       MULADD(at[10], at[12]); 
      COMBA_STORE(C->dp[10]);
      /* 11 */
      COMBA_FORWARD;
      MULADD(at[0], at[23]);       MULADD(at[1], at[22]);       MULADD(at[2], at[21]);       MULADD(at[3], at[20]);       MULADD(at[4], at[19]);       MULADD(at[5], at[18]);       MULADD(at[6], at[17]);       MULADD(at[7], at[16]);       MULADD(at[8], at[15]);       MULADD(at[9], at[14]);       MULADD(at[10], at[13]);       MULADD(at[11], at[12]); 
      COMBA_STORE(C->dp[11]);
      /* 12 */
      COMBA_FORWARD;
      MULADD(at[1], at[23]);       MULADD(at[2], at[22]);       MULADD(at[3], at[21]);       MULADD(at[4], at[20]);       MULADD(at[5], at[19]);       MULADD(at[6], at[18]);       MULADD(at[7], at[17]);       MULADD(at[8], at[16]);       MULADD(at[9], at[15]);       MULADD(at[10], at[14]);       MULADD(at[11], at[13]); 
      COMBA_STORE(C->dp[12]);
      /* 13 */
      COMBA_FORWARD;
      MULADD(at[2], at[23]);       MULADD(at[3], at[22]);       MULADD(at[4], at[21]);       MULADD(at[5], at[20]);       MULADD(at[6], at[19]);       MULADD(at[7], at[18]);       MULADD(at[8], at[17]);       MULADD(at[9], at[16]);       MULADD(at[10], at[15]);       MULADD(at[11], at[14]); 
      COMBA_STORE(C->dp[13]);
      /* 14 */
      COMBA_FORWARD;
      MULADD(at[3], at[23]);       MULADD(at[4], at[22]);       MULADD(at[5], at[21]);       MULADD(at[6], at[20]);       MULADD(at[7], at[19]);       MULADD(at[8], at[18]);       MULADD(at[9], at[17]);       MULADD(at[10], at[16]);       MULADD(at[11], at[15]); 
      COMBA_STORE(C->dp[14]);
      /* 15 */
      COMBA_FORWARD;
      MULADD(at[4], at[23]);       MULADD(at[5], at[22]);       MULADD(at[6], at[21]);       MULADD(at[7], at[20]);       MULADD(at[8], at[19]);       MULADD(at[9], at[18]);       MULADD(at[10], at[17]);       MULADD(at[11], at[16]); 
      COMBA_STORE(C->dp[15]);
      /* 16 */
      COMBA_FORWARD;
      MULADD(at[5], at[23]);       MULADD(at[6], at[22]);       MULADD(at[7], at[21]);       MULADD(at[8], at[20]);       MULADD(at[9], at[19]);       MULADD(at[10], at[18]);       MULADD(at[11], at[17]); 
      COMBA_STORE(C->dp[16]);
      /* 17 */
      COMBA_FORWARD;
      MULADD(at[6], at[23]);       MULADD(at[7], at[22]);       MULADD(at[8], at[21]);       MULADD(at[9], at[20]);       MULADD(at[10], at[19]);       MULADD(at[11], at[18]); 
      COMBA_STORE(C->dp[17]);
      /* 18 */
      COMBA_FORWARD;
      MULADD(at[7], at[23]);       MULADD(at[8], at[22]);       MULADD(at[9], at[21]);       MULADD(at[10], at[20]);       MULADD(at[11], at[19]); 
      COMBA_STORE(C->dp[18]);
      /* 19 */
      COMBA_FORWARD;
      MULADD(at[8], at[23]);       MULADD(at[9], at[22]);       MULADD(at[10], at[21]);       MULADD(at[11], at[20]); 
      COMBA_STORE(C->dp[19]);
      /* 20 */
      COMBA_FORWARD;
      MULADD(at[9], at[23]);       MULADD(at[10], at[22]);       MULADD(at[11], at[21]); 
      COMBA_STORE(C->dp[20]);
      /* 21 */
      COMBA_FORWARD;
      MULADD(at[10], at[23]);       MULADD(at[11], at[22]); 
      COMBA_STORE(C->dp[21]);
      /* 22 */
      COMBA_FORWARD;
      MULADD(at[11], at[23]); 
      COMBA_STORE(C->dp[22]);
      COMBA_STORE2(C->dp[23]);
      C->used = 24;
      C->sign = A->sign ^ B->sign;
      fp_clamp(C);
      COMBA_FINI;
      break;

   case 13:
      memcpy(at, A->dp, 13 * sizeof(fp_digit));
      memcpy(at+13, B->dp, 13 * sizeof(fp_digit));
      COMBA_START;

      COMBA_CLEAR;
      /* 0 */
      MULADD(at[0], at[13]); 
      COMBA_STORE(C->dp[0]);
      /* 1 */
      COMBA_FORWARD;
      MULADD(at[0], at[14]);       MULADD(at[1], at[13]); 
      COMBA_STORE(C->dp[1]);
      /* 2 */
      COMBA_FORWARD;
      MULADD(at[0], at[15]);       MULADD(at[1], at[14]);       MULADD(at[2], at[13]); 
      COMBA_STORE(C->dp[2]);
      /* 3 */
      COMBA_FORWARD;
      MULADD(at[0], at[16]);       MULADD(at[1], at[15]);       MULADD(at[2], at[14]);       MULADD(at[3], at[13]); 
      COMBA_STORE(C->dp[3]);
      /* 4 */
      COMBA_FORWARD;
      MULADD(at[0], at[17]);       MULADD(at[1], at[16]);       MULADD(at[2], at[15]);       MULADD(at[3], at[14]);       MULADD(at[4], at[13]); 
      COMBA_STORE(C->dp[4]);
      /* 5 */
      COMBA_FORWARD;
      MULADD(at[0], at[18]);       MULADD(at[1], at[17]);       MULADD(at[2], at[16]);       MULADD(at[3], at[15]);       MULADD(at[4], at[14]);       MULADD(at[5], at[13]); 
      COMBA_STORE(C->dp[5]);
      /* 6 */
      COMBA_FORWARD;
      MULADD(at[0], at[19]);       MULADD(at[1], at[18]);       MULADD(at[2], at[17]);       MULADD(at[3], at[16]);       MULADD(at[4], at[15]);       MULADD(at[5], at[14]);       MULADD(at[6], at[13]); 
      COMBA_STORE(C->dp[6]);
      /* 7 */
      COMBA_FORWARD;
      MULADD(at[0], at[20]);       MULADD(at[1], at[19]);       MULADD(at[2], at[18]);       MULADD(at[3], at[17]);       MULADD(at[4], at[16]);       MULADD(at[5], at[15]);       MULADD(at[6], at[14]);       MULADD(at[7], at[13]); 
      COMBA_STORE(C->dp[7]);
      /* 8 */
      COMBA_FORWARD;
      MULADD(at[0], at[21]);       MULADD(at[1], at[20]);       MULADD(at[2], at[19]);       MULADD(at[3], at[18]);       MULADD(at[4], at[17]);       MULADD(at[5], at[16]);       MULADD(at[6], at[15]);       MULADD(at[7], at[14]);       MULADD(at[8], at[13]); 
      COMBA_STORE(C->dp[8]);
      /* 9 */
      COMBA_FORWARD;
      MULADD(at[0], at[22]);       MULADD(at[1], at[21]);       MULADD(at[2], at[20]);       MULADD(at[3], at[19]);       MULADD(at[4], at[18]);       MULADD(at[5], at[17]);       MULADD(at[6], at[16]);       MULADD(at[7], at[15]);       MULADD(at[8], at[14]);       MULADD(at[9], at[13]); 
      COMBA_STORE(C->dp[9]);
      /* 10 */
      COMBA_FORWARD;
      MULADD(at[0], at[23]);       MULADD(at[1], at[22]);       MULADD(at[2], at[21]);       MULADD(at[3], at[20]);       MULADD(at[4], at[19]);       MULADD(at[5], at[18]);       MULADD(at[6], at[17]);       MULADD(at[7], at[16]);       MULADD(at[8], at[15]);       MULADD(at[9], at[14]);       MULADD(at[10], at[13]); 
      COMBA_STORE(C->dp[10]);
      /* 11 */
      COMBA_FORWARD;
      MULADD(at[0], at[24]);       MULADD(at[1], at[23]);       MULADD(at[2], at[22]);       MULADD(at[3], at[21]);       MULADD(at[4], at[20]);       MULADD(at[5], at[19]);       MULADD(at[6], at[18]);       MULADD(at[7], at[17]);       MULADD(at[8], at[16]);       MULADD(at[9], at[15]);       MULADD(at[10], at[14]);       MULADD(at[11], at[13]); 
      COMBA_STORE(C->dp[11]);
      /* 12 */
      COMBA_FORWARD;
      MULADD(at[0], at[25]);       MULADD(at[1], at[24]);       MULADD(at[2], at[23]);       MULADD(at[3], at[22]);       MULADD(at[4], at[21]);       MULADD(at[5], at[20]);       MULADD(at[6], at[19]);       MULADD(at[7], at[18]);       MULADD(at[8], at[17]);       MULADD(at[9], at[16]);       MULADD(at[10], at[15]);       MULADD(at[11], at[14]);       MULADD(at[12], at[13]); 
      COMBA_STORE(C->dp[12]);
      /* 13 */
      COMBA_FORWARD;
      MULADD(at[1], at[25]);       MULADD(at[2], at[24]);       MULADD(at[3], at[23]);       MULADD(at[4], at[22]);       MULADD(at[5], at[21]);       MULADD(at[6], at[20]);       MULADD(at[7], at[19]);       MULADD(at[8], at[18]);       MULADD(at[9], at[17]);       MULADD(at[10], at[16]);       MULADD(at[11], at[15]);       MULADD(at[12], at[14]); 
      COMBA_STORE(C->dp[13]);
      /* 14 */
      COMBA_FORWARD;
      MULADD(at[2], at[25]);       MULADD(at[3], at[24]);       MULADD(at[4], at[23]);       MULADD(at[5], at[22]);       MULADD(at[6], at[21]);       MULADD(at[7], at[20]);       MULADD(at[8], at[19]);       MULADD(at[9], at[18]);       MULADD(at[10], at[17]);       MULADD(at[11], at[16]);       MULADD(at[12], at[15]); 
      COMBA_STORE(C->dp[14]);
      /* 15 */
      COMBA_FORWARD;
      MULADD(at[3], at[25]);       MULADD(at[4], at[24]);       MULADD(at[5], at[23]);       MULADD(at[6], at[22]);       MULADD(at[7], at[21]);       MULADD(at[8], at[20]);       MULADD(at[9], at[19]);       MULADD(at[10], at[18]);       MULADD(at[11], at[17]);       MULADD(at[12], at[16]); 
      COMBA_STORE(C->dp[15]);
      /* 16 */
      COMBA_FORWARD;
      MULADD(at[4], at[25]);       MULADD(at[5], at[24]);       MULADD(at[6], at[23]);       MULADD(at[7], at[22]);       MULADD(at[8], at[21]);       MULADD(at[9], at[20]);       MULADD(at[10], at[19]);       MULADD(at[11], at[18]);       MULADD(at[12], at[17]); 
      COMBA_STORE(C->dp[16]);
      /* 17 */
      COMBA_FORWARD;
      MULADD(at[5], at[25]);       MULADD(at[6], at[24]);       MULADD(at[7], at[23]);       MULADD(at[8], at[22]);       MULADD(at[9], at[21]);       MULADD(at[10], at[20]);       MULADD(at[11], at[19]);       MULADD(at[12], at[18]); 
      COMBA_STORE(C->dp[17]);
      /* 18 */
      COMBA_FORWARD;
      MULADD(at[6], at[25]);       MULADD(at[7], at[24]);       MULADD(at[8], at[23]);       MULADD(at[9], at[22]);       MULADD(at[10], at[21]);       MULADD(at[11], at[20]);       MULADD(at[12], at[19]); 
      COMBA_STORE(C->dp[18]);
      /* 19 */
      COMBA_FORWARD;
      MULADD(at[7], at[25]);       MULADD(at[8], at[24]);       MULADD(at[9], at[23]);       MULADD(at[10], at[22]);       MULADD(at[11], at[21]);       MULADD(at[12], at[20]); 
      COMBA_STORE(C->dp[19]);
      /* 20 */
      COMBA_FORWARD;
      MULADD(at[8], at[25]);       MULADD(at[9], at[24]);       MULADD(at[10], at[23]);       MULADD(at[11], at[22]);       MULADD(at[12], at[21]); 
      COMBA_STORE(C->dp[20]);
      /* 21 */
      COMBA_FORWARD;
      MULADD(at[9], at[25]);       MULADD(at[10], at[24]);       MULADD(at[11], at[23]);       MULADD(at[12], at[22]); 
      COMBA_STORE(C->dp[21]);
      /* 22 */
      COMBA_FORWARD;
      MULADD(at[10], at[25]);       MULADD(at[11], at[24]);       MULADD(at[12], at[23]); 
      COMBA_STORE(C->dp[22]);
      /* 23 */
      COMBA_FORWARD;
      MULADD(at[11], at[25]);       MULADD(at[12], at[24]); 
      COMBA_STORE(C->dp[23]);
      /* 24 */
      COMBA_FORWARD;
      MULADD(at[12], at[25]); 
      COMBA_STORE(C->dp[24]);
      COMBA_STORE2(C->dp[25]);
      C->used = 26;
      C->sign = A->sign ^ B->sign;
      fp_clamp(C);
      COMBA_FINI;
      break;

   case 14:
      memcpy(at, A->dp, 14 * sizeof(fp_digit));
      memcpy(at+14, B->dp, 14 * sizeof(fp_digit));
      COMBA_START;

      COMBA_CLEAR;
      /* 0 */
      MULADD(at[0], at[14]); 
      COMBA_STORE(C->dp[0]);
      /* 1 */
      COMBA_FORWARD;
      MULADD(at[0], at[15]);       MULADD(at[1], at[14]); 
      COMBA_STORE(C->dp[1]);
      /* 2 */
      COMBA_FORWARD;
      MULADD(at[0], at[16]);       MULADD(at[1], at[15]);       MULADD(at[2], at[14]); 
      COMBA_STORE(C->dp[2]);
      /* 3 */
      COMBA_FORWARD;
      MULADD(at[0], at[17]);       MULADD(at[1], at[16]);       MULADD(at[2], at[15]);       MULADD(at[3], at[14]); 
      COMBA_STORE(C->dp[3]);
      /* 4 */
      COMBA_FORWARD;
      MULADD(at[0], at[18]);       MULADD(at[1], at[17]);       MULADD(at[2], at[16]);       MULADD(at[3], at[15]);       MULADD(at[4], at[14]); 
      COMBA_STORE(C->dp[4]);
      /* 5 */
      COMBA_FORWARD;
      MULADD(at[0], at[19]);       MULADD(at[1], at[18]);       MULADD(at[2], at[17]);       MULADD(at[3], at[16]);       MULADD(at[4], at[15]);       MULADD(at[5], at[14]); 
      COMBA_STORE(C->dp[5]);
      /* 6 */
      COMBA_FORWARD;
      MULADD(at[0], at[20]);       MULADD(at[1], at[19]);       MULADD(at[2], at[18]);       MULADD(at[3], at[17]);       MULADD(at[4], at[16]);       MULADD(at[5], at[15]);       MULADD(at[6], at[14]); 
      COMBA_STORE(C->dp[6]);
      /* 7 */
      COMBA_FORWARD;
      MULADD(at[0], at[21]);       MULADD(at[1], at[20]);       MULADD(at[2], at[19]);       MULADD(at[3], at[18]);       MULADD(at[4], at[17]);       MULADD(at[5], at[16]);       MULADD(at[6], at[15]);       MULADD(at[7], at[14]); 
      COMBA_STORE(C->dp[7]);
      /* 8 */
      COMBA_FORWARD;
      MULADD(at[0], at[22]);       MULADD(at[1], at[21]);       MULADD(at[2], at[20]);       MULADD(at[3], at[19]);       MULADD(at[4], at[18]);       MULADD(at[5], at[17]);       MULADD(at[6], at[16]);       MULADD(at[7], at[15]);       MULADD(at[8], at[14]); 
      COMBA_STORE(C->dp[8]);
      /* 9 */
      COMBA_FORWARD;
      MULADD(at[0], at[23]);       MULADD(at[1], at[22]);       MULADD(at[2], at[21]);       MULADD(at[3], at[20]);       MULADD(at[4], at[19]);       MULADD(at[5], at[18]);       MULADD(at[6], at[17]);       MULADD(at[7], at[16]);       MULADD(at[8], at[15]);       MULADD(at[9], at[14]); 
      COMBA_STORE(C->dp[9]);
      /* 10 */
      COMBA_FORWARD;
      MULADD(at[0], at[24]);       MULADD(at[1], at[23]);       MULADD(at[2], at[22]);       MULADD(at[3], at[21]);       MULADD(at[4], at[20]);       MULADD(at[5], at[19]);       MULADD(at[6], at[18]);       MULADD(at[7], at[17]);       MULADD(at[8], at[16]);       MULADD(at[9], at[15]);       MULADD(at[10], at[14]); 
      COMBA_STORE(C->dp[10]);
      /* 11 */
      COMBA_FORWARD;
      MULADD(at[0], at[25]);       MULADD(at[1], at[24]);       MULADD(at[2], at[23]);       MULADD(at[3], at[22]);       MULADD(at[4], at[21]);       MULADD(at[5], at[20]);       MULADD(at[6], at[19]);       MULADD(at[7], at[18]);       MULADD(at[8], at[17]);       MULADD(at[9], at[16]);       MULADD(at[10], at[15]);       MULADD(at[11], at[14]); 
      COMBA_STORE(C->dp[11]);
      /* 12 */
      COMBA_FORWARD;
      MULADD(at[0], at[26]);       MULADD(at[1], at[25]);       MULADD(at[2], at[24]);       MULADD(at[3], at[23]);       MULADD(at[4], at[22]);       MULADD(at[5], at[21]);       MULADD(at[6], at[20]);       MULADD(at[7], at[19]);       MULADD(at[8], at[18]);       MULADD(at[9], at[17]);       MULADD(at[10], at[16]);       MULADD(at[11], at[15]);       MULADD(at[12], at[14]); 
      COMBA_STORE(C->dp[12]);
      /* 13 */
      COMBA_FORWARD;
      MULADD(at[0], at[27]);       MULADD(at[1], at[26]);       MULADD(at[2], at[25]);       MULADD(at[3], at[24]);       MULADD(at[4], at[23]);       MULADD(at[5], at[22]);       MULADD(at[6], at[21]);       MULADD(at[7], at[20]);       MULADD(at[8], at[19]);       MULADD(at[9], at[18]);       MULADD(at[10], at[17]);       MULADD(at[11], at[16]);       MULADD(at[12], at[15]);       MULADD(at[13], at[14]); 
      COMBA_STORE(C->dp[13]);
      /* 14 */
      COMBA_FORWARD;
      MULADD(at[1], at[27]);       MULADD(at[2], at[26]);       MULADD(at[3], at[25]);       MULADD(at[4], at[24]);       MULADD(at[5], at[23]);       MULADD(at[6], at[22]);       MULADD(at[7], at[21]);       MULADD(at[8], at[20]);       MULADD(at[9], at[19]);       MULADD(at[10], at[18]);       MULADD(at[11], at[17]);       MULADD(at[12], at[16]);       MULADD(at[13], at[15]); 
      COMBA_STORE(C->dp[14]);
      /* 15 */
      COMBA_FORWARD;
      MULADD(at[2], at[27]);       MULADD(at[3], at[26]);       MULADD(at[4], at[25]);       MULADD(at[5], at[24]);       MULADD(at[6], at[23]);       MULADD(at[7], at[22]);       MULADD(at[8], at[21]);       MULADD(at[9], at[20]);       MULADD(at[10], at[19]);       MULADD(at[11], at[18]);       MULADD(at[12], at[17]);       MULADD(at[13], at[16]); 
      COMBA_STORE(C->dp[15]);
      /* 16 */
      COMBA_FORWARD;
      MULADD(at[3], at[27]);       MULADD(at[4], at[26]);       MULADD(at[5], at[25]);       MULADD(at[6], at[24]);       MULADD(at[7], at[23]);       MULADD(at[8], at[22]);       MULADD(at[9], at[21]);       MULADD(at[10], at[20]);       MULADD(at[11], at[19]);       MULADD(at[12], at[18]);       MULADD(at[13], at[17]); 
      COMBA_STORE(C->dp[16]);
      /* 17 */
      COMBA_FORWARD;
      MULADD(at[4], at[27]);       MULADD(at[5], at[26]);       MULADD(at[6], at[25]);       MULADD(at[7], at[24]);       MULADD(at[8], at[23]);       MULADD(at[9], at[22]);       MULADD(at[10], at[21]);       MULADD(at[11], at[20]);       MULADD(at[12], at[19]);       MULADD(at[13], at[18]); 
      COMBA_STORE(C->dp[17]);
      /* 18 */
      COMBA_FORWARD;
      MULADD(at[5], at[27]);       MULADD(at[6], at[26]);       MULADD(at[7], at[25]);       MULADD(at[8], at[24]);       MULADD(at[9], at[23]);       MULADD(at[10], at[22]);       MULADD(at[11], at[21]);       MULADD(at[12], at[20]);       MULADD(at[13], at[19]); 
      COMBA_STORE(C->dp[18]);
      /* 19 */
      COMBA_FORWARD;
      MULADD(at[6], at[27]);       MULADD(at[7], at[26]);       MULADD(at[8], at[25]);       MULADD(at[9], at[24]);       MULADD(at[10], at[23]);       MULADD(at[11], at[22]);       MULADD(at[12], at[21]);       MULADD(at[13], at[20]); 
      COMBA_STORE(C->dp[19]);
      /* 20 */
      COMBA_FORWARD;
      MULADD(at[7], at[27]);       MULADD(at[8], at[26]);       MULADD(at[9], at[25]);       MULADD(at[10], at[24]);       MULADD(at[11], at[23]);       MULADD(at[12], at[22]);       MULADD(at[13], at[21]); 
      COMBA_STORE(C->dp[20]);
      /* 21 */
      COMBA_FORWARD;
      MULADD(at[8], at[27]);       MULADD(at[9], at[26]);       MULADD(at[10], at[25]);       MULADD(at[11], at[24]);       MULADD(at[12], at[23]);       MULADD(at[13], at[22]); 
      COMBA_STORE(C->dp[21]);
      /* 22 */
      COMBA_FORWARD;
      MULADD(at[9], at[27]);       MULADD(at[10], at[26]);       MULADD(at[11], at[25]);       MULADD(at[12], at[24]);       MULADD(at[13], at[23]); 
      COMBA_STORE(C->dp[22]);
      /* 23 */
      COMBA_FORWARD;
      MULADD(at[10], at[27]);       MULADD(at[11], at[26]);       MULADD(at[12], at[25]);       MULADD(at[13], at[24]); 
      COMBA_STORE(C->dp[23]);
      /* 24 */
      COMBA_FORWARD;
      MULADD(at[11], at[27]);       MULADD(at[12], at[26]);       MULADD(at[13], at[25]); 
      COMBA_STORE(C->dp[24]);
      /* 25 */
      COMBA_FORWARD;
      MULADD(at[12], at[27]);       MULADD(at[13], at[26]); 
      COMBA_STORE(C->dp[25]);
      /* 26 */
      COMBA_FORWARD;
      MULADD(at[13], at[27]); 
      COMBA_STORE(C->dp[26]);
      COMBA_STORE2(C->dp[27]);
      C->used = 28;
      C->sign = A->sign ^ B->sign;
      fp_clamp(C);
      COMBA_FINI;
      break;

   case 15:
      memcpy(at, A->dp, 15 * sizeof(fp_digit));
      memcpy(at+15, B->dp, 15 * sizeof(fp_digit));
      COMBA_START;

      COMBA_CLEAR;
      /* 0 */
      MULADD(at[0], at[15]); 
      COMBA_STORE(C->dp[0]);
      /* 1 */
      COMBA_FORWARD;
      MULADD(at[0], at[16]);       MULADD(at[1], at[15]); 
      COMBA_STORE(C->dp[1]);
      /* 2 */
      COMBA_FORWARD;
      MULADD(at[0], at[17]);       MULADD(at[1], at[16]);       MULADD(at[2], at[15]); 
      COMBA_STORE(C->dp[2]);
      /* 3 */
      COMBA_FORWARD;
      MULADD(at[0], at[18]);       MULADD(at[1], at[17]);       MULADD(at[2], at[16]);       MULADD(at[3], at[15]); 
      COMBA_STORE(C->dp[3]);
      /* 4 */
      COMBA_FORWARD;
      MULADD(at[0], at[19]);       MULADD(at[1], at[18]);       MULADD(at[2], at[17]);       MULADD(at[3], at[16]);       MULADD(at[4], at[15]); 
      COMBA_STORE(C->dp[4]);
      /* 5 */
      COMBA_FORWARD;
      MULADD(at[0], at[20]);       MULADD(at[1], at[19]);       MULADD(at[2], at[18]);       MULADD(at[3], at[17]);       MULADD(at[4], at[16]);       MULADD(at[5], at[15]); 
      COMBA_STORE(C->dp[5]);
      /* 6 */
      COMBA_FORWARD;
      MULADD(at[0], at[21]);       MULADD(at[1], at[20]);       MULADD(at[2], at[19]);       MULADD(at[3], at[18]);       MULADD(at[4], at[17]);       MULADD(at[5], at[16]);       MULADD(at[6], at[15]); 
      COMBA_STORE(C->dp[6]);
      /* 7 */
      COMBA_FORWARD;
      MULADD(at[0], at[22]);       MULADD(at[1], at[21]);       MULADD(at[2], at[20]);       MULADD(at[3], at[19]);       MULADD(at[4], at[18]);       MULADD(at[5], at[17]);       MULADD(at[6], at[16]);       MULADD(at[7], at[15]); 
      COMBA_STORE(C->dp[7]);
      /* 8 */
      COMBA_FORWARD;
      MULADD(at[0], at[23]);       MULADD(at[1], at[22]);       MULADD(at[2], at[21]);       MULADD(at[3], at[20]);       MULADD(at[4], at[19]);       MULADD(at[5], at[18]);       MULADD(at[6], at[17]);       MULADD(at[7], at[16]);       MULADD(at[8], at[15]); 
      COMBA_STORE(C->dp[8]);
      /* 9 */
      COMBA_FORWARD;
      MULADD(at[0], at[24]);       MULADD(at[1], at[23]);       MULADD(at[2], at[22]);       MULADD(at[3], at[21]);       MULADD(at[4], at[20]);       MULADD(at[5], at[19]);       MULADD(at[6], at[18]);       MULADD(at[7], at[17]);       MULADD(at[8], at[16]);       MULADD(at[9], at[15]); 
      COMBA_STORE(C->dp[9]);
      /* 10 */
      COMBA_FORWARD;
      MULADD(at[0], at[25]);       MULADD(at[1], at[24]);       MULADD(at[2], at[23]);       MULADD(at[3], at[22]);       MULADD(at[4], at[21]);       MULADD(at[5], at[20]);       MULADD(at[6], at[19]);       MULADD(at[7], at[18]);       MULADD(at[8], at[17]);       MULADD(at[9], at[16]);       MULADD(at[10], at[15]); 
      COMBA_STORE(C->dp[10]);
      /* 11 */
      COMBA_FORWARD;
      MULADD(at[0], at[26]);       MULADD(at[1], at[25]);       MULADD(at[2], at[24]);       MULADD(at[3], at[23]);       MULADD(at[4], at[22]);       MULADD(at[5], at[21]);       MULADD(at[6], at[20]);       MULADD(at[7], at[19]);       MULADD(at[8], at[18]);       MULADD(at[9], at[17]);       MULADD(at[10], at[16]);       MULADD(at[11], at[15]); 
      COMBA_STORE(C->dp[11]);
      /* 12 */
      COMBA_FORWARD;
      MULADD(at[0], at[27]);       MULADD(at[1], at[26]);       MULADD(at[2], at[25]);       MULADD(at[3], at[24]);       MULADD(at[4], at[23]);       MULADD(at[5], at[22]);       MULADD(at[6], at[21]);       MULADD(at[7], at[20]);       MULADD(at[8], at[19]);       MULADD(at[9], at[18]);       MULADD(at[10], at[17]);       MULADD(at[11], at[16]);       MULADD(at[12], at[15]); 
      COMBA_STORE(C->dp[12]);
      /* 13 */
      COMBA_FORWARD;
      MULADD(at[0], at[28]);       MULADD(at[1], at[27]);       MULADD(at[2], at[26]);       MULADD(at[3], at[25]);       MULADD(at[4], at[24]);       MULADD(at[5], at[23]);       MULADD(at[6], at[22]);       MULADD(at[7], at[21]);       MULADD(at[8], at[20]);       MULADD(at[9], at[19]);       MULADD(at[10], at[18]);       MULADD(at[11], at[17]);       MULADD(at[12], at[16]);       MULADD(at[13], at[15]); 
      COMBA_STORE(C->dp[13]);
      /* 14 */
      COMBA_FORWARD;
      MULADD(at[0], at[29]);       MULADD(at[1], at[28]);       MULADD(at[2], at[27]);       MULADD(at[3], at[26]);       MULADD(at[4], at[25]);       MULADD(at[5], at[24]);       MULADD(at[6], at[23]);       MULADD(at[7], at[22]);       MULADD(at[8], at[21]);       MULADD(at[9], at[20]);       MULADD(at[10], at[19]);       MULADD(at[11], at[18]);       MULADD(at[12], at[17]);       MULADD(at[13], at[16]);       MULADD(at[14], at[15]); 
      COMBA_STORE(C->dp[14]);
      /* 15 */
      COMBA_FORWARD;
      MULADD(at[1], at[29]);       MULADD(at[2], at[28]);       MULADD(at[3], at[27]);       MULADD(at[4], at[26]);       MULADD(at[5], at[25]);       MULADD(at[6], at[24]);       MULADD(at[7], at[23]);       MULADD(at[8], at[22]);       MULADD(at[9], at[21]);       MULADD(at[10], at[20]);       MULADD(at[11], at[19]);       MULADD(at[12], at[18]);       MULADD(at[13], at[17]);       MULADD(at[14], at[16]); 
      COMBA_STORE(C->dp[15]);
      /* 16 */
      COMBA_FORWARD;
      MULADD(at[2], at[29]);       MULADD(at[3], at[28]);       MULADD(at[4], at[27]);       MULADD(at[5], at[26]);       MULADD(at[6], at[25]);       MULADD(at[7], at[24]);       MULADD(at[8], at[23]);       MULADD(at[9], at[22]);       MULADD(at[10], at[21]);       MULADD(at[11], at[20]);       MULADD(at[12], at[19]);       MULADD(at[13], at[18]);       MULADD(at[14], at[17]); 
      COMBA_STORE(C->dp[16]);
      /* 17 */
      COMBA_FORWARD;
      MULADD(at[3], at[29]);       MULADD(at[4], at[28]);       MULADD(at[5], at[27]);       MULADD(at[6], at[26]);       MULADD(at[7], at[25]);       MULADD(at[8], at[24]);       MULADD(at[9], at[23]);       MULADD(at[10], at[22]);       MULADD(at[11], at[21]);       MULADD(at[12], at[20]);       MULADD(at[13], at[19]);       MULADD(at[14], at[18]); 
      COMBA_STORE(C->dp[17]);
      /* 18 */
      COMBA_FORWARD;
      MULADD(at[4], at[29]);       MULADD(at[5], at[28]);       MULADD(at[6], at[27]);       MULADD(at[7], at[26]);       MULADD(at[8], at[25]);       MULADD(at[9], at[24]);       MULADD(at[10], at[23]);       MULADD(at[11], at[22]);       MULADD(at[12], at[21]);       MULADD(at[13], at[20]);       MULADD(at[14], at[19]); 
      COMBA_STORE(C->dp[18]);
      /* 19 */
      COMBA_FORWARD;
      MULADD(at[5], at[29]);       MULADD(at[6], at[28]);       MULADD(at[7], at[27]);       MULADD(at[8], at[26]);       MULADD(at[9], at[25]);       MULADD(at[10], at[24]);       MULADD(at[11], at[23]);       MULADD(at[12], at[22]);       MULADD(at[13], at[21]);       MULADD(at[14], at[20]); 
      COMBA_STORE(C->dp[19]);
      /* 20 */
      COMBA_FORWARD;
      MULADD(at[6], at[29]);       MULADD(at[7], at[28]);       MULADD(at[8], at[27]);       MULADD(at[9], at[26]);       MULADD(at[10], at[25]);       MULADD(at[11], at[24]);       MULADD(at[12], at[23]);       MULADD(at[13], at[22]);       MULADD(at[14], at[21]); 
      COMBA_STORE(C->dp[20]);
      /* 21 */
      COMBA_FORWARD;
      MULADD(at[7], at[29]);       MULADD(at[8], at[28]);       MULADD(at[9], at[27]);       MULADD(at[10], at[26]);       MULADD(at[11], at[25]);       MULADD(at[12], at[24]);       MULADD(at[13], at[23]);       MULADD(at[14], at[22]); 
      COMBA_STORE(C->dp[21]);
      /* 22 */
      COMBA_FORWARD;
      MULADD(at[8], at[29]);       MULADD(at[9], at[28]);       MULADD(at[10], at[27]);       MULADD(at[11], at[26]);       MULADD(at[12], at[25]);       MULADD(at[13], at[24]);       MULADD(at[14], at[23]); 
      COMBA_STORE(C->dp[22]);
      /* 23 */
      COMBA_FORWARD;
      MULADD(at[9], at[29]);       MULADD(at[10], at[28]);       MULADD(at[11], at[27]);       MULADD(at[12], at[26]);       MULADD(at[13], at[25]);       MULADD(at[14], at[24]); 
      COMBA_STORE(C->dp[23]);
      /* 24 */
      COMBA_FORWARD;
      MULADD(at[10], at[29]);       MULADD(at[11], at[28]);       MULADD(at[12], at[27]);       MULADD(at[13], at[26]);       MULADD(at[14], at[25]); 
      COMBA_STORE(C->dp[24]);
      /* 25 */
      COMBA_FORWARD;
      MULADD(at[11], at[29]);       MULADD(at[12], at[28]);       MULADD(at[13], at[27]);       MULADD(at[14], at[26]); 
      COMBA_STORE(C->dp[25]);
      /* 26 */
      COMBA_FORWARD;
      MULADD(at[12], at[29]);       MULADD(at[13], at[28]);       MULADD(at[14], at[27]); 
      COMBA_STORE(C->dp[26]);
      /* 27 */
      COMBA_FORWARD;
      MULADD(at[13], at[29]);       MULADD(at[14], at[28]); 
      COMBA_STORE(C->dp[27]);
      /* 28 */
      COMBA_FORWARD;
      MULADD(at[14], at[29]); 
      COMBA_STORE(C->dp[28]);
      COMBA_STORE2(C->dp[29]);
      C->used = 30;
      C->sign = A->sign ^ B->sign;
      fp_clamp(C);
      COMBA_FINI;
      break;

   case 16:
      memcpy(at, A->dp, 16 * sizeof(fp_digit));
      memcpy(at+16, B->dp, 16 * sizeof(fp_digit));
      COMBA_START;

      COMBA_CLEAR;
      /* 0 */
      MULADD(at[0], at[16]); 
      COMBA_STORE(C->dp[0]);
      /* 1 */
      COMBA_FORWARD;
      MULADD(at[0], at[17]);       MULADD(at[1], at[16]); 
      COMBA_STORE(C->dp[1]);
      /* 2 */
      COMBA_FORWARD;
      MULADD(at[0], at[18]);       MULADD(at[1], at[17]);       MULADD(at[2], at[16]); 
      COMBA_STORE(C->dp[2]);
      /* 3 */
      COMBA_FORWARD;
      MULADD(at[0], at[19]);       MULADD(at[1], at[18]);       MULADD(at[2], at[17]);       MULADD(at[3], at[16]); 
      COMBA_STORE(C->dp[3]);
      /* 4 */
      COMBA_FORWARD;
      MULADD(at[0], at[20]);       MULADD(at[1], at[19]);       MULADD(at[2], at[18]);       MULADD(at[3], at[17]);       MULADD(at[4], at[16]); 
      COMBA_STORE(C->dp[4]);
      /* 5 */
      COMBA_FORWARD;
      MULADD(at[0], at[21]);       MULADD(at[1], at[20]);       MULADD(at[2], at[19]);       MULADD(at[3], at[18]);       MULADD(at[4], at[17]);       MULADD(at[5], at[16]); 
      COMBA_STORE(C->dp[5]);
      /* 6 */
      COMBA_FORWARD;
      MULADD(at[0], at[22]);       MULADD(at[1], at[21]);       MULADD(at[2], at[20]);       MULADD(at[3], at[19]);       MULADD(at[4], at[18]);       MULADD(at[5], at[17]);       MULADD(at[6], at[16]); 
      COMBA_STORE(C->dp[6]);
      /* 7 */
      COMBA_FORWARD;
      MULADD(at[0], at[23]);       MULADD(at[1], at[22]);       MULADD(at[2], at[21]);       MULADD(at[3], at[20]);       MULADD(at[4], at[19]);       MULADD(at[5], at[18]);       MULADD(at[6], at[17]);       MULADD(at[7], at[16]); 
      COMBA_STORE(C->dp[7]);
      /* 8 */
      COMBA_FORWARD;
      MULADD(at[0], at[24]);       MULADD(at[1], at[23]);       MULADD(at[2], at[22]);       MULADD(at[3], at[21]);       MULADD(at[4], at[20]);       MULADD(at[5], at[19]);       MULADD(at[6], at[18]);       MULADD(at[7], at[17]);       MULADD(at[8], at[16]); 
      COMBA_STORE(C->dp[8]);
      /* 9 */
      COMBA_FORWARD;
      MULADD(at[0], at[25]);       MULADD(at[1], at[24]);       MULADD(at[2], at[23]);       MULADD(at[3], at[22]);       MULADD(at[4], at[21]);       MULADD(at[5], at[20]);       MULADD(at[6], at[19]);       MULADD(at[7], at[18]);       MULADD(at[8], at[17]);       MULADD(at[9], at[16]); 
      COMBA_STORE(C->dp[9]);
      /* 10 */
      COMBA_FORWARD;
      MULADD(at[0], at[26]);       MULADD(at[1], at[25]);       MULADD(at[2], at[24]);       MULADD(at[3], at[23]);       MULADD(at[4], at[22]);       MULADD(at[5], at[21]);       MULADD(at[6], at[20]);       MULADD(at[7], at[19]);       MULADD(at[8], at[18]);       MULADD(at[9], at[17]);       MULADD(at[10], at[16]); 
      COMBA_STORE(C->dp[10]);
      /* 11 */
      COMBA_FORWARD;
      MULADD(at[0], at[27]);       MULADD(at[1], at[26]);       MULADD(at[2], at[25]);       MULADD(at[3], at[24]);       MULADD(at[4], at[23]);       MULADD(at[5], at[22]);       MULADD(at[6], at[21]);       MULADD(at[7], at[20]);       MULADD(at[8], at[19]);       MULADD(at[9], at[18]);       MULADD(at[10], at[17]);       MULADD(at[11], at[16]); 
      COMBA_STORE(C->dp[11]);
      /* 12 */
      COMBA_FORWARD;
      MULADD(at[0], at[28]);       MULADD(at[1], at[27]);       MULADD(at[2], at[26]);       MULADD(at[3], at[25]);       MULADD(at[4], at[24]);       MULADD(at[5], at[23]);       MULADD(at[6], at[22]);       MULADD(at[7], at[21]);       MULADD(at[8], at[20]);       MULADD(at[9], at[19]);       MULADD(at[10], at[18]);       MULADD(at[11], at[17]);       MULADD(at[12], at[16]); 
      COMBA_STORE(C->dp[12]);
      /* 13 */
      COMBA_FORWARD;
      MULADD(at[0], at[29]);       MULADD(at[1], at[28]);       MULADD(at[2], at[27]);       MULADD(at[3], at[26]);       MULADD(at[4], at[25]);       MULADD(at[5], at[24]);       MULADD(at[6], at[23]);       MULADD(at[7], at[22]);       MULADD(at[8], at[21]);       MULADD(at[9], at[20]);       MULADD(at[10], at[19]);       MULADD(at[11], at[18]);       MULADD(at[12], at[17]);       MULADD(at[13], at[16]); 
      COMBA_STORE(C->dp[13]);
      /* 14 */
      COMBA_FORWARD;
      MULADD(at[0], at[30]);       MULADD(at[1], at[29]);       MULADD(at[2], at[28]);       MULADD(at[3], at[27]);       MULADD(at[4], at[26]);       MULADD(at[5], at[25]);       MULADD(at[6], at[24]);       MULADD(at[7], at[23]);       MULADD(at[8], at[22]);       MULADD(at[9], at[21]);       MULADD(at[10], at[20]);       MULADD(at[11], at[19]);       MULADD(at[12], at[18]);       MULADD(at[13], at[17]);       MULADD(at[14], at[16]); 
      COMBA_STORE(C->dp[14]);
      /* 15 */
      COMBA_FORWARD;
      MULADD(at[0], at[31]);       MULADD(at[1], at[30]);       MULADD(at[2], at[29]);       MULADD(at[3], at[28]);       MULADD(at[4], at[27]);       MULADD(at[5], at[26]);       MULADD(at[6], at[25]);       MULADD(at[7], at[24]);       MULADD(at[8], at[23]);       MULADD(at[9], at[22]);       MULADD(at[10], at[21]);       MULADD(at[11], at[20]);       MULADD(at[12], at[19]);       MULADD(at[13], at[18]);       MULADD(at[14], at[17]);       MULADD(at[15], at[16]); 
      COMBA_STORE(C->dp[15]);
      /* 16 */
      COMBA_FORWARD;
      MULADD(at[1], at[31]);       MULADD(at[2], at[30]);       MULADD(at[3], at[29]);       MULADD(at[4], at[28]);       MULADD(at[5], at[27]);       MULADD(at[6], at[26]);       MULADD(at[7], at[25]);       MULADD(at[8], at[24]);       MULADD(at[9], at[23]);       MULADD(at[10], at[22]);       MULADD(at[11], at[21]);       MULADD(at[12], at[20]);       MULADD(at[13], at[19]);       MULADD(at[14], at[18]);       MULADD(at[15], at[17]); 
      COMBA_STORE(C->dp[16]);
      /* 17 */
      COMBA_FORWARD;
      MULADD(at[2], at[31]);       MULADD(at[3], at[30]);       MULADD(at[4], at[29]);       MULADD(at[5], at[28]);       MULADD(at[6], at[27]);       MULADD(at[7], at[26]);       MULADD(at[8], at[25]);       MULADD(at[9], at[24]);       MULADD(at[10], at[23]);       MULADD(at[11], at[22]);       MULADD(at[12], at[21]);       MULADD(at[13], at[20]);       MULADD(at[14], at[19]);       MULADD(at[15], at[18]); 
      COMBA_STORE(C->dp[17]);
      /* 18 */
      COMBA_FORWARD;
      MULADD(at[3], at[31]);       MULADD(at[4], at[30]);       MULADD(at[5], at[29]);       MULADD(at[6], at[28]);       MULADD(at[7], at[27]);       MULADD(at[8], at[26]);       MULADD(at[9], at[25]);       MULADD(at[10], at[24]);       MULADD(at[11], at[23]);       MULADD(at[12], at[22]);       MULADD(at[13], at[21]);       MULADD(at[14], at[20]);       MULADD(at[15], at[19]); 
      COMBA_STORE(C->dp[18]);
      /* 19 */
      COMBA_FORWARD;
      MULADD(at[4], at[31]);       MULADD(at[5], at[30]);       MULADD(at[6], at[29]);       MULADD(at[7], at[28]);       MULADD(at[8], at[27]);       MULADD(at[9], at[26]);       MULADD(at[10], at[25]);       MULADD(at[11], at[24]);       MULADD(at[12], at[23]);       MULADD(at[13], at[22]);       MULADD(at[14], at[21]);       MULADD(at[15], at[20]); 
      COMBA_STORE(C->dp[19]);
      /* 20 */
      COMBA_FORWARD;
      MULADD(at[5], at[31]);       MULADD(at[6], at[30]);       MULADD(at[7], at[29]);       MULADD(at[8], at[28]);       MULADD(at[9], at[27]);       MULADD(at[10], at[26]);       MULADD(at[11], at[25]);       MULADD(at[12], at[24]);       MULADD(at[13], at[23]);       MULADD(at[14], at[22]);       MULADD(at[15], at[21]); 
      COMBA_STORE(C->dp[20]);
      /* 21 */
      COMBA_FORWARD;
      MULADD(at[6], at[31]);       MULADD(at[7], at[30]);       MULADD(at[8], at[29]);       MULADD(at[9], at[28]);       MULADD(at[10], at[27]);       MULADD(at[11], at[26]);       MULADD(at[12], at[25]);       MULADD(at[13], at[24]);       MULADD(at[14], at[23]);       MULADD(at[15], at[22]); 
      COMBA_STORE(C->dp[21]);
      /* 22 */
      COMBA_FORWARD;
      MULADD(at[7], at[31]);       MULADD(at[8], at[30]);       MULADD(at[9], at[29]);       MULADD(at[10], at[28]);       MULADD(at[11], at[27]);       MULADD(at[12], at[26]);       MULADD(at[13], at[25]);       MULADD(at[14], at[24]);       MULADD(at[15], at[23]); 
      COMBA_STORE(C->dp[22]);
      /* 23 */
      COMBA_FORWARD;
      MULADD(at[8], at[31]);       MULADD(at[9], at[30]);       MULADD(at[10], at[29]);       MULADD(at[11], at[28]);       MULADD(at[12], at[27]);       MULADD(at[13], at[26]);       MULADD(at[14], at[25]);       MULADD(at[15], at[24]); 
      COMBA_STORE(C->dp[23]);
      /* 24 */
      COMBA_FORWARD;
      MULADD(at[9], at[31]);       MULADD(at[10], at[30]);       MULADD(at[11], at[29]);       MULADD(at[12], at[28]);       MULADD(at[13], at[27]);       MULADD(at[14], at[26]);       MULADD(at[15], at[25]); 
      COMBA_STORE(C->dp[24]);
      /* 25 */
      COMBA_FORWARD;
      MULADD(at[10], at[31]);       MULADD(at[11], at[30]);       MULADD(at[12], at[29]);       MULADD(at[13], at[28]);       MULADD(at[14], at[27]);       MULADD(at[15], at[26]); 
      COMBA_STORE(C->dp[25]);
      /* 26 */
      COMBA_FORWARD;
      MULADD(at[11], at[31]);       MULADD(at[12], at[30]);       MULADD(at[13], at[29]);       MULADD(at[14], at[28]);       MULADD(at[15], at[27]); 
      COMBA_STORE(C->dp[26]);
      /* 27 */
      COMBA_FORWARD;
      MULADD(at[12], at[31]);       MULADD(at[13], at[30]);       MULADD(at[14], at[29]);       MULADD(at[15], at[28]); 
      COMBA_STORE(C->dp[27]);
      /* 28 */
      COMBA_FORWARD;
      MULADD(at[13], at[31]);       MULADD(at[14], at[30]);       MULADD(at[15], at[29]); 
      COMBA_STORE(C->dp[28]);
      /* 29 */
      COMBA_FORWARD;
      MULADD(at[14], at[31]);       MULADD(at[15], at[30]); 
      COMBA_STORE(C->dp[29]);
      /* 30 */
      COMBA_FORWARD;
      MULADD(at[15], at[31]); 
      COMBA_STORE(C->dp[30]);
      COMBA_STORE2(C->dp[31]);
      C->used = 32;
      C->sign = A->sign ^ B->sign;
      fp_clamp(C);
      COMBA_FINI;
      break;
   }
}

#endif

/* End: fp_mul_comba_small_set.c */

/* Start: fp_mul_d.c */
/* TomsFastMath, a fast ISO C bignum library.
 * 
 * This project is meant to fill in where LibTomMath
 * falls short.  That is speed ;-)
 *
 * This project is public domain and free for all purposes.
 * 
 * Tom St Denis, tomstdenis@gmail.com
 */
#include "bignum_fast.h"

/* c = a * b */
void fp_mul_d(fp_int *a, fp_digit b, fp_int *c)
{
   fp_word  w;
   int      x, oldused;

   oldused = c->used;
   c->used = a->used;
   c->sign = a->sign;
   w       = 0;
   for (x = 0; x < a->used; x++) {
       w         = ((fp_word)a->dp[x]) * ((fp_word)b) + w;
       c->dp[x]  = (fp_digit)w;
       w         = w >> DIGIT_BIT;
   }
   if (w != 0 && (a->used != FP_SIZE)) {
      c->dp[c->used++] = w;
      ++x;
   }
   for (; x < oldused; x++) {
      c->dp[x] = 0;
   }
   fp_clamp(c);
}


/* $Source: /cvs/libtom/tomsfastmath/src/mul/fp_mul_d.c,v $ */
/* $Revision: 1.1 $ */
/* $Date: 2006/12/31 21:25:53 $ */

/* End: fp_mul_d.c */

/* Start: fp_mulmod.c */
/* TomsFastMath, a fast ISO C bignum library.
 * 
 * This project is meant to fill in where LibTomMath
 * falls short.  That is speed ;-)
 *
 * This project is public domain and free for all purposes.
 * 
 * Tom St Denis, tomstdenis@gmail.com
 */
#include "bignum_fast.h"
/* d = a * b (mod c) */
int fp_mulmod(fp_int *a, fp_int *b, fp_int *c, fp_int *d)
{
  fp_int tmp;
  fp_zero(&tmp);
  fp_mul(a, b, &tmp);
  return fp_mod(&tmp, c, d);
}

/* $Source: /cvs/libtom/tomsfastmath/src/mul/fp_mulmod.c,v $ */
/* $Revision: 1.1 $ */
/* $Date: 2006/12/31 21:25:53 $ */

/* End: fp_mulmod.c */

/* Start: fp_prime_miller_rabin.c */
/* TomsFastMath, a fast ISO C bignum library.
 * 
 * This project is meant to fill in where LibTomMath
 * falls short.  That is speed ;-)
 *
 * This project is public domain and free for all purposes.
 * 
 * Tom St Denis, tomstdenis@gmail.com
 */
#include "bignum_fast.h"

/* Miller-Rabin test of "a" to the base of "b" as described in 
 * HAC pp. 139 Algorithm 4.24
 *
 * Sets result to 0 if definitely composite or 1 if probably prime.
 * Randomly the chance of error is no more than 1/4 and often 
 * very much lower.
 */
void fp_prime_miller_rabin (fp_int * a, fp_int * b, int *result)
{
  fp_int  n1, y, r;
  int     s, j;

  /* default */
  *result = FP_NO;

  /* ensure b > 1 */
  if (fp_cmp_d(b, 1) != FP_GT) {
     return;
  }     

  /* get n1 = a - 1 */
  fp_init_copy(&n1, a);
  fp_sub_d(&n1, 1, &n1);

  /* set 2**s * r = n1 */
  fp_init_copy(&r, &n1);

  /* count the number of least significant bits
   * which are zero
   */
  s = fp_cnt_lsb(&r);

  /* now divide n - 1 by 2**s */
  fp_div_2d (&r, s, &r, NULL);

  /* compute y = b**r mod a */
  fp_init(&y);
  fp_exptmod(b, &r, a, &y);

  /* if y != 1 and y != n1 do */
  if (fp_cmp_d (&y, 1) != FP_EQ && fp_cmp (&y, &n1) != FP_EQ) {
    j = 1;
    /* while j <= s-1 and y != n1 */
    while ((j <= (s - 1)) && fp_cmp (&y, &n1) != FP_EQ) {
      fp_sqrmod (&y, a, &y);

      /* if y == 1 then composite */
      if (fp_cmp_d (&y, 1) == FP_EQ) {
         return;
      }
      ++j;
    }

    /* if y != n1 then composite */
    if (fp_cmp (&y, &n1) != FP_EQ) {
       return;
    }
  }

  /* probably prime now */
  *result = FP_YES;
}

/* $Source: /cvs/libtom/tomsfastmath/src/numtheory/fp_prime_miller_rabin.c,v $ */
/* $Revision: 1.1 $ */
/* $Date: 2007/01/24 21:25:19 $ */

/* End: fp_prime_miller_rabin.c */

/* Start: fp_prime_random_ex.c */
/* TomsFastMath, a fast ISO C bignum library.
 * 
 * This project is meant to fill in where LibTomMath
 * falls short.  That is speed ;-)
 *
 * This project is public domain and free for all purposes.
 * 
 * Tom St Denis, tomstdenis@gmail.com
 */
#include "bignum_fast.h"

/* This is possibly the mother of all prime generation functions, muahahahahaha! */
int fp_prime_random_ex(fp_int *a, int t, int size, int flags, tfm_prime_callback cb, void *dat)
{
   unsigned char *tmp, maskAND, maskOR_msb, maskOR_lsb;
   int res, err, bsize, maskOR_msb_offset;

   /* sanity check the input */
   if (size <= 1 || t <= 0) {
      return FP_VAL;
   }

   /* TFM_PRIME_SAFE implies TFM_PRIME_BBS */
   if (flags & TFM_PRIME_SAFE) {
      flags |= TFM_PRIME_BBS;
   }

   /* calc the byte size */
   bsize = (size>>3)+(size&7?1:0);

   /* we need a buffer of bsize bytes */
   tmp = malloc(bsize);
   if (tmp == NULL) {
      return FP_MEM;
   }

   /* calc the maskAND value for the MSbyte*/
   maskAND = 0xFF >> (8 - (size & 7));

   /* calc the maskOR_msb */
   maskOR_msb        = 0;
   maskOR_msb_offset = (size - 2) >> 3;
   if (flags & TFM_PRIME_2MSB_ON) {
      maskOR_msb     |= 1 << ((size - 2) & 7);
   } else if (flags & TFM_PRIME_2MSB_OFF) {
      maskAND        &= ~(1 << ((size - 2) & 7));
   }

   /* get the maskOR_lsb */
   maskOR_lsb         = 1;
   if (flags & TFM_PRIME_BBS) {
      maskOR_lsb     |= 3;
   }

   do {
      /* read the bytes */
      if (cb(tmp, bsize, dat) != bsize) {
         err = FP_VAL;
         goto error;
      }
 
      /* work over the MSbyte */
      tmp[0]    &= maskAND;
      tmp[0]    |= 1 << ((size - 1) & 7);

      /* mix in the maskORs */
      tmp[maskOR_msb_offset]   |= maskOR_msb;
      tmp[bsize-1]             |= maskOR_lsb;

      /* read it in */
      fp_read_unsigned_bin(a, tmp, bsize);

      /* is it prime? */
      res = fp_isprime(a);
      if (res == FP_NO) continue;

      if (flags & TFM_PRIME_SAFE) {
         /* see if (a-1)/2 is prime */
         fp_sub_d(a, 1, a);
         fp_div_2(a, a);
 
         /* is it prime? */
         res = fp_isprime(a);
      }
   } while (res == FP_NO);

   if (flags & TFM_PRIME_SAFE) {
      /* restore a to the original value */
      fp_mul_2(a, a);
      fp_add_d(a, 1, a);
   }

   err = FP_OKAY;
error:
   free(tmp);
   return err;
}

/* $Source: /cvs/libtom/tomsfastmath/src/numtheory/fp_prime_random_ex.c,v $ */
/* $Revision: 1.1 $ */
/* $Date: 2007/01/24 21:25:19 $ */

/* End: fp_prime_random_ex.c */

/* Start: fp_radix_size.c */
/* TomsFastMath, a fast ISO C bignum library.
 * 
 * This project is meant to fill in where LibTomMath
 * falls short.  That is speed ;-)
 *
 * This project is public domain and free for all purposes.
 * 
 * Tom St Denis, tomstdenis@gmail.com
 */
#include "bignum_fast.h"

int fp_radix_size(fp_int *a, int radix, int *size)
{
  int     digs;
  fp_int  t;
  fp_digit d;
   
  *size = 0;

  /* check range of the radix */
  if (radix < 2 || radix > 64) {
    return FP_VAL;
  }

  /* quick out if its zero */
  if (fp_iszero(a) == 1) {
     *size = 2;
     return FP_OKAY;
  }

  fp_init_copy(&t, a);

  /* if it is negative output a - */
  if (t.sign == FP_NEG) {
    (*size)++;
    t.sign = FP_ZPOS;
  }

  digs = 0;
  while (fp_iszero (&t) == FP_NO) {
    fp_div_d (&t, (fp_digit) radix, &t, &d);
    (*size)++;
  }

  /* append a NULL so the string is properly terminated */
  (*size)++;
  return FP_OKAY;

}

/* $Source: /cvs/libtom/tomsfastmath/src/bin/fp_radix_size.c,v $ */
/* $Revision: 1.1 $ */
/* $Date: 2006/12/31 21:25:53 $ */

/* End: fp_radix_size.c */

/* Start: fp_read_radix.c */
/* TomsFastMath, a fast ISO C bignum library.
 * 
 * This project is meant to fill in where LibTomMath
 * falls short.  That is speed ;-)
 *
 * This project is public domain and free for all purposes.
 * 
 * Tom St Denis, tomstdenis@gmail.com
 */
#include "bignum_fast.h"

int fp_read_radix(fp_int *a, const char *str, int radix)
{
  int     y, neg;
  char    ch;

  /* make sure the radix is ok */
  if (radix < 2 || radix > 64) {
    return FP_VAL;
  }

  /* if the leading digit is a
   * minus set the sign to negative.
   */
  if (*str == '-') {
    ++str;
    neg = FP_NEG;
  } else {
    neg = FP_ZPOS;
  }

  /* set the integer to the default of zero */
  fp_zero (a);

  /* process each digit of the string */
  while (*str) {
    /* if the radix < 36 the conversion is case insensitive
     * this allows numbers like 1AB and 1ab to represent the same  value
     * [e.g. in hex]
     */
    ch = (char) ((radix < 36) ? toupper (*str) : *str);
    for (y = 0; y < 64; y++) {
      if (ch == fp_s_rmap[y]) {
         break;
      }
    }

    /* if the char was found in the map
     * and is less than the given radix add it
     * to the number, otherwise exit the loop.
     */
    if (y < radix) {
      fp_mul_d (a, (fp_digit) radix, a);
      fp_add_d (a, (fp_digit) y, a);
    } else {
      break;
    }
    ++str;
  }

  /* set the sign only if a != 0 */
  if (fp_iszero(a) != FP_YES) {
     a->sign = neg;
  }
  return FP_OKAY;
}

/* $Source: /cvs/libtom/tomsfastmath/src/bin/fp_read_radix.c,v $ */
/* $Revision: 1.1 $ */
/* $Date: 2006/12/31 21:25:53 $ */

/* End: fp_read_radix.c */

/* Start: fp_read_signed_bin.c */
/* TomsFastMath, a fast ISO C bignum library.
 * 
 * This project is meant to fill in where LibTomMath
 * falls short.  That is speed ;-)
 *
 * This project is public domain and free for all purposes.
 * 
 * Tom St Denis, tomstdenis@gmail.com
 */
#include "bignum_fast.h"

void fp_read_signed_bin(fp_int *a, unsigned char *b, int c)
{
  /* read magnitude */
  fp_read_unsigned_bin (a, b + 1, c - 1);

  /* first byte is 0 for positive, non-zero for negative */
  if (b[0] == 0) {
     a->sign = FP_ZPOS;
  } else {
     a->sign = FP_NEG;
  }
}

/* $Source: /cvs/libtom/tomsfastmath/src/bin/fp_read_signed_bin.c,v $ */
/* $Revision: 1.1 $ */
/* $Date: 2006/12/31 21:25:53 $ */

/* End: fp_read_signed_bin.c */

/* Start: fp_read_unsigned_bin.c */
/* TomsFastMath, a fast ISO C bignum library.
 * 
 * This project is meant to fill in where LibTomMath
 * falls short.  That is speed ;-)
 *
 * This project is public domain and free for all purposes.
 * 
 * Tom St Denis, tomstdenis@gmail.com
 */
#include "bignum_fast.h"

void fp_read_unsigned_bin(fp_int *a, const unsigned char *b, int c)
{
  /* zero the int */
  fp_zero (a);

  /* If we know the endianness of this architecture, and we're using
     32-bit fp_digits, we can optimize this */
#if (defined(ENDIAN_LITTLE) || defined(ENDIAN_BIG)) && !defined(FP_64BIT)
  /* But not for both simultaneously */
#if defined(ENDIAN_LITTLE) && defined(ENDIAN_BIG)
#error Both ENDIAN_LITTLE and ENDIAN_BIG defined.
#endif
  {
     unsigned char *pd = (unsigned char *)a->dp;

     if ((unsigned)c > (FP_SIZE * sizeof(fp_digit))) {
        int excess = c - (FP_SIZE * sizeof(fp_digit));
        c -= excess;
        b += excess;
     }
     a->used = (c + sizeof(fp_digit) - 1)/sizeof(fp_digit);
     /* read the bytes in */
#ifdef ENDIAN_BIG
     {
       /* Use Duff's device to unroll the loop. */
       int idx = (c - 1) & ~3;
       switch (c % 4) {
       case 0:	do { pd[idx+0] = *b++;
       case 3:	     pd[idx+1] = *b++;
       case 2:	     pd[idx+2] = *b++;
       case 1:	     pd[idx+3] = *b++;
                     idx -= 4;
	 	        } while ((c -= 4) > 0);
       }
     }
#else
     for (c -= 1; c >= 0; c -= 1) {
       pd[c] = *b++;
     }
#endif
  }
#else
  /* read the bytes in */
  for (; c > 0; c--) {
     fp_mul_2d (a, 8, a);
     a->dp[0] |= *b++;
     a->used += 1;
  }
#endif
  fp_clamp (a);
}

/* $Source: /cvs/libtom/tomsfastmath/src/bin/fp_read_unsigned_bin.c,v $ */
/* $Revision: 1.2 $ */
/* $Date: 2007/02/17 02:58:19 $ */

/* End: fp_read_unsigned_bin.c */

/* Start: fp_reverse.c */
/* TomsFastMath, a fast ISO C bignum library.
 * 
 * This project is meant to fill in where LibTomMath
 * falls short.  That is speed ;-)
 *
 * This project is public domain and free for all purposes.
 * 
 * Tom St Denis, tomstdenis@gmail.com
 */
#include "bignum_fast.h"

/* reverse an array, used for radix code */
void fp_reverse (unsigned char *s, int len)
{
  int     ix, iy;
  unsigned char t;

  ix = 0;
  iy = len - 1;
  while (ix < iy) {
    t     = s[ix];
    s[ix] = s[iy];
    s[iy] = t;
    ++ix;
    --iy;
  }
}

/* $Source: /cvs/libtom/tomsfastmath/src/bin/fp_reverse.c,v $ */
/* $Revision: 1.2 $ */
/* $Date: 2007/02/27 02:38:44 $ */

/* End: fp_reverse.c */

/* Start: fp_rshd.c */
/* TomsFastMath, a fast ISO C bignum library.
 * 
 * This project is meant to fill in where LibTomMath
 * falls short.  That is speed ;-)
 *
 * This project is public domain and free for all purposes.
 * 
 * Tom St Denis, tomstdenis@gmail.com
 */
#include "bignum_fast.h"

void fp_rshd(fp_int *a, int x)
{
  int y;

  /* too many digits just zero and return */
  if (x >= a->used) {
     fp_zero(a);
     return;
  }

   /* shift */
   for (y = 0; y < a->used - x; y++) {
      a->dp[y] = a->dp[y+x];
   }

   /* zero rest */
   for (; y < a->used; y++) {
      a->dp[y] = 0;
   }
   
   /* decrement count */
   a->used -= x;
   fp_clamp(a);
}


/* $Source: /cvs/libtom/tomsfastmath/src/bit/fp_rshd.c,v $ */
/* $Revision: 1.1 $ */
/* $Date: 2006/12/31 21:25:53 $ */

/* End: fp_rshd.c */

/* Start: fp_s_rmap.c */
/* TomsFastMath, a fast ISO C bignum library.
 * 
 * This project is meant to fill in where LibTomMath
 * falls short.  That is speed ;-)
 *
 * This project is public domain and free for all purposes.
 * 
 * Tom St Denis, tomstdenis@gmail.com
 */
#include "bignum_fast.h"

/* chars used in radix conversions */
const char *fp_s_rmap = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/";

/* $Source: /cvs/libtom/tomsfastmath/src/bin/fp_s_rmap.c,v $ */
/* $Revision: 1.1 $ */
/* $Date: 2006/12/31 21:25:53 $ */

/* End: fp_s_rmap.c */

/* Start: fp_set.c */
/* TomsFastMath, a fast ISO C bignum library.
 * 
 * This project is meant to fill in where LibTomMath
 * falls short.  That is speed ;-)
 *
 * This project is public domain and free for all purposes.
 * 
 * Tom St Denis, tomstdenis@gmail.com
 */
#include "bignum_fast.h"

void fp_set(fp_int *a, fp_digit b)
{
   fp_zero(a);
   a->dp[0] = b;
   a->used  = a->dp[0] ? 1 : 0;
}

/* $Source: /cvs/libtom/tomsfastmath/src/misc/fp_set.c,v $ */
/* $Revision: 1.1 $ */
/* $Date: 2006/12/31 21:25:53 $ */

/* End: fp_set.c */

/* Start: fp_signed_bin_size.c */
/* TomsFastMath, a fast ISO C bignum library.
 * 
 * This project is meant to fill in where LibTomMath
 * falls short.  That is speed ;-)
 *
 * This project is public domain and free for all purposes.
 * 
 * Tom St Denis, tomstdenis@gmail.com
 */
#include "bignum_fast.h"

int fp_signed_bin_size(fp_int *a)
{
  return 1 + fp_unsigned_bin_size (a);
}

/* $Source: /cvs/libtom/tomsfastmath/src/bin/fp_signed_bin_size.c,v $ */
/* $Revision: 1.1 $ */
/* $Date: 2006/12/31 21:25:53 $ */

/* End: fp_signed_bin_size.c */

/* Start: fp_sqr.c */
/* TomsFastMath, a fast ISO C bignum library.
 * 
 * This project is meant to fill in where LibTomMath
 * falls short.  That is speed ;-)
 *
 * This project is public domain and free for all purposes.
 * 
 * Tom St Denis, tomstdenis@gmail.com
 */
#include "bignum_fast.h"

/* b = a*a  */
void fp_sqr(fp_int *A, fp_int *B)
{
    int     y;

    /* call generic if we're out of range */
    if (A->used + A->used > FP_SIZE) {
       fp_sqr_comba(A, B);
       return ;
    }

    y = A->used;
#if defined(TFM_SQR3)
        if (y <= 3) {
           fp_sqr_comba3(A,B);
           return;
        }
#endif
#if defined(TFM_SQR4)
        if (y == 4) {
           fp_sqr_comba4(A,B);
           return;
        }
#endif
#if defined(TFM_SQR6)
        if (y <= 6) {
           fp_sqr_comba6(A,B);
           return;
        }
#endif
#if defined(TFM_SQR7)
        if (y == 7) {
           fp_sqr_comba7(A,B);
           return;
        }
#endif
#if defined(TFM_SQR8)
        if (y == 8) {
           fp_sqr_comba8(A,B);
           return;
        }
#endif
#if defined(TFM_SQR9)
        if (y == 9) {
           fp_sqr_comba9(A,B);
           return;
        }
#endif
#if defined(TFM_SQR12)
        if (y <= 12) {
           fp_sqr_comba12(A,B);
           return;
        }
#endif
#if defined(TFM_SQR17)
        if (y <= 17) {
           fp_sqr_comba17(A,B);
           return;
        }
#endif
#if defined(TFM_SMALL_SET)
        if (y <= 16) {
           fp_sqr_comba_small(A,B);
           return;
        }
#endif
#if defined(TFM_SQR20)
        if (y <= 20) {
           fp_sqr_comba20(A,B);
           return;
        }
#endif
#if defined(TFM_SQR24)
        if (y <= 24) {
           fp_sqr_comba24(A,B);
           return;
        }
#endif
#if defined(TFM_SQR28)
        if (y <= 28) {
           fp_sqr_comba28(A,B);
           return;
        }
#endif
#if defined(TFM_SQR32)
        if (y <= 32) {
           fp_sqr_comba32(A,B);
           return;
        }
#endif
#if defined(TFM_SQR48)
        if (y <= 48) {
           fp_sqr_comba48(A,B);
           return;
        }
#endif
#if defined(TFM_SQR64)
        if (y <= 64) {
           fp_sqr_comba64(A,B);
           return;
        }
#endif
       fp_sqr_comba(A, B);
}


/* $Source: /cvs/libtom/tomsfastmath/src/sqr/fp_sqr.c,v $ */
/* $Revision: 1.1 $ */
/* $Date: 2006/12/31 21:25:53 $ */

/* End: fp_sqr.c */

/* Start: fp_sqr_comba.c */
/*
 * 
 * This project is meant to fill in where LibTomMath
 * falls short.  That is speed ;-)
 *
 * This project is public domain and free for all purposes.
 * 
 * Tom St Denis, tomstdenis@gmail.com
 */
#include "bignum_fast.h"

#if defined(TFM_PRESCOTT) && defined(TFM_SSE2)
   #undef TFM_SSE2
   #define TFM_X86
#endif

#if defined(TFM_X86)

/* x86-32 optimized */

#define COMBA_START

#define CLEAR_CARRY \
   c0 = c1 = c2 = 0;

#define COMBA_STORE(x) \
   x = c0;

#define COMBA_STORE2(x) \
   x = c1;

#define CARRY_FORWARD \
   do { c0 = c1; c1 = c2; c2 = 0; } while (0);

#define COMBA_FINI

#define SQRADD(i, j)                                      \
asm(                                            \
     "movl  %6,%%eax     \n\t"                            \
     "mull  %%eax        \n\t"                            \
     "addl  %%eax,%0     \n\t"                            \
     "adcl  %%edx,%1     \n\t"                            \
     "adcl  $0,%2        \n\t"                            \
     :"=r"(c0), "=r"(c1), "=r"(c2): "0"(c0), "1"(c1), "2"(c2), "m"(i) :"%eax","%edx","%cc");

#define SQRADD2(i, j)                                     \
asm(                                            \
     "movl  %6,%%eax     \n\t"                            \
     "mull  %7           \n\t"                            \
     "addl  %%eax,%0     \n\t"                            \
     "adcl  %%edx,%1     \n\t"                            \
     "adcl  $0,%2        \n\t"                            \
     "addl  %%eax,%0     \n\t"                            \
     "adcl  %%edx,%1     \n\t"                            \
     "adcl  $0,%2        \n\t"                            \
     :"=r"(c0), "=r"(c1), "=r"(c2): "0"(c0), "1"(c1), "2"(c2), "m"(i), "m"(j)  :"%eax","%edx","%cc");

#define SQRADDSC(i, j)                                    \
asm(                                                     \
     "movl  %6,%%eax     \n\t"                            \
     "mull  %7           \n\t"                            \
     "movl  %%eax,%0     \n\t"                            \
     "movl  %%edx,%1     \n\t"                            \
     "xorl  %2,%2        \n\t"                            \
     :"=r"(sc0), "=r"(sc1), "=r"(sc2): "0"(sc0), "1"(sc1), "2"(sc2), "g"(i), "g"(j) :"%eax","%edx","%cc");

#define SQRADDAC(i, j)                                    \
asm(                                                     \
     "movl  %6,%%eax     \n\t"                            \
     "mull  %7           \n\t"                            \
     "addl  %%eax,%0     \n\t"                            \
     "adcl  %%edx,%1     \n\t"                            \
     "adcl  $0,%2        \n\t"                            \
     :"=r"(sc0), "=r"(sc1), "=r"(sc2): "0"(sc0), "1"(sc1), "2"(sc2), "g"(i), "g"(j) :"%eax","%edx","%cc");

#define SQRADDDB                                          \
asm(                                                     \
     "addl %6,%0         \n\t"                            \
     "adcl %7,%1         \n\t"                            \
     "adcl %8,%2         \n\t"                            \
     "addl %6,%0         \n\t"                            \
     "adcl %7,%1         \n\t"                            \
     "adcl %8,%2         \n\t"                            \
     :"=r"(c0), "=r"(c1), "=r"(c2) : "0"(c0), "1"(c1), "2"(c2), "r"(sc0), "r"(sc1), "r"(sc2) : "%cc");

#elif defined(TFM_X86_64)
/* x86-64 optimized */

#define COMBA_START

#define CLEAR_CARRY \
   c0 = c1 = c2 = 0;

#define COMBA_STORE(x) \
   x = c0;

#define COMBA_STORE2(x) \
   x = c1;

#define CARRY_FORWARD \
   do { c0 = c1; c1 = c2; c2 = 0; } while (0);

#define COMBA_FINI

#define SQRADD(i, j)                                      \
asm(                                                     \
     "movq  %6,%%rax     \n\t"                            \
     "mulq  %%rax        \n\t"                            \
     "addq  %%rax,%0     \n\t"                            \
     "adcq  %%rdx,%1     \n\t"                            \
     "adcq  $0,%2        \n\t"                            \
     :"=r"(c0), "=r"(c1), "=r"(c2): "0"(c0), "1"(c1), "2"(c2), "g"(i) :"%rax","%rdx","%cc");

#define SQRADD2(i, j)                                     \
asm(                                                     \
     "movq  %6,%%rax     \n\t"                            \
     "mulq  %7           \n\t"                            \
     "addq  %%rax,%0     \n\t"                            \
     "adcq  %%rdx,%1     \n\t"                            \
     "adcq  $0,%2        \n\t"                            \
     "addq  %%rax,%0     \n\t"                            \
     "adcq  %%rdx,%1     \n\t"                            \
     "adcq  $0,%2        \n\t"                            \
     :"=r"(c0), "=r"(c1), "=r"(c2): "0"(c0), "1"(c1), "2"(c2), "g"(i), "g"(j)  :"%rax","%rdx","%cc");

#define SQRADDSC(i, j)                                    \
asm(                                                     \
     "movq  %6,%%rax     \n\t"                            \
     "mulq  %7           \n\t"                            \
     "movq  %%rax,%0     \n\t"                            \
     "movq  %%rdx,%1     \n\t"                            \
     "xorq  %2,%2        \n\t"                            \
     :"=r"(sc0), "=r"(sc1), "=r"(sc2): "0"(sc0), "1"(sc1), "2"(sc2), "g"(i), "g"(j) :"%rax","%rdx","%cc");

#define SQRADDAC(i, j)                                                         \
asm(                                                     \
     "movq  %6,%%rax     \n\t"                            \
     "mulq  %7           \n\t"                            \
     "addq  %%rax,%0     \n\t"                            \
     "adcq  %%rdx,%1     \n\t"                            \
     "adcq  $0,%2        \n\t"                            \
     :"=r"(sc0), "=r"(sc1), "=r"(sc2): "0"(sc0), "1"(sc1), "2"(sc2), "g"(i), "g"(j) :"%rax","%rdx","%cc");

#define SQRADDDB                                          \
asm(                                                     \
     "addq %6,%0         \n\t"                            \
     "adcq %7,%1         \n\t"                            \
     "adcq %8,%2         \n\t"                            \
     "addq %6,%0         \n\t"                            \
     "adcq %7,%1         \n\t"                            \
     "adcq %8,%2         \n\t"                            \
     :"=r"(c0), "=r"(c1), "=r"(c2) : "0"(c0), "1"(c1), "2"(c2), "r"(sc0), "r"(sc1), "r"(sc2) : "%cc");

#elif defined(TFM_SSE2)

/* SSE2 Optimized */
#define COMBA_START

#define CLEAR_CARRY \
   c0 = c1 = c2 = 0;

#define COMBA_STORE(x) \
   x = c0;

#define COMBA_STORE2(x) \
   x = c1;

#define CARRY_FORWARD \
   do { c0 = c1; c1 = c2; c2 = 0; } while (0);

#define COMBA_FINI \
   asm("emms");

#define SQRADD(i, j)                                      \
asm(                                            \
     "movd  %6,%%mm0     \n\t"                            \
     "pmuludq %%mm0,%%mm0\n\t"                            \
     "movd  %%mm0,%%eax  \n\t"                            \
     "psrlq $32,%%mm0    \n\t"                            \
     "addl  %%eax,%0     \n\t"                            \
     "movd  %%mm0,%%eax  \n\t"                            \
     "adcl  %%eax,%1     \n\t"                            \
     "adcl  $0,%2        \n\t"                            \
     :"=r"(c0), "=r"(c1), "=r"(c2): "0"(c0), "1"(c1), "2"(c2), "m"(i) :"%eax","%cc");

#define SQRADD2(i, j)                                     \
asm(                                            \
     "movd  %6,%%mm0     \n\t"                            \
     "movd  %7,%%mm1     \n\t"                            \
     "pmuludq %%mm1,%%mm0\n\t"                            \
     "movd  %%mm0,%%eax  \n\t"                            \
     "psrlq $32,%%mm0    \n\t"                            \
     "movd  %%mm0,%%edx  \n\t"                            \
     "addl  %%eax,%0     \n\t"                            \
     "adcl  %%edx,%1     \n\t"                            \
     "adcl  $0,%2        \n\t"                            \
     "addl  %%eax,%0     \n\t"                            \
     "adcl  %%edx,%1     \n\t"                            \
     "adcl  $0,%2        \n\t"                            \
     :"=r"(c0), "=r"(c1), "=r"(c2): "0"(c0), "1"(c1), "2"(c2), "m"(i), "m"(j)  :"%eax","%edx","%cc");

#define SQRADDSC(i, j)                                                         \
asm(                                            \
     "movd  %6,%%mm0     \n\t"                            \
     "movd  %7,%%mm1     \n\t"                            \
     "pmuludq %%mm1,%%mm0\n\t"                            \
     "movd  %%mm0,%0     \n\t"                            \
     "psrlq $32,%%mm0    \n\t"                            \
     "movd  %%mm0,%1     \n\t"                            \
     "xorl  %2,%2        \n\t"                            \
     :"=r"(sc0), "=r"(sc1), "=r"(sc2): "0"(sc0), "1"(sc1), "2"(sc2), "m"(i), "m"(j));

#define SQRADDAC(i, j)                                                         \
asm(                                            \
     "movd  %6,%%mm0     \n\t"                            \
     "movd  %7,%%mm1     \n\t"                            \
     "pmuludq %%mm1,%%mm0\n\t"                            \
     "movd  %%mm0,%%eax  \n\t"                            \
     "psrlq $32,%%mm0    \n\t"                            \
     "movd  %%mm0,%%edx  \n\t"                            \
     "addl  %%eax,%0     \n\t"                            \
     "adcl  %%edx,%1     \n\t"                            \
     "adcl  $0,%2        \n\t"                            \
     :"=r"(sc0), "=r"(sc1), "=r"(sc2): "0"(sc0), "1"(sc1), "2"(sc2), "m"(i), "m"(j)  :"%eax","%edx","%cc");

#define SQRADDDB                                          \
asm(                                                     \
     "addl %6,%0         \n\t"                            \
     "adcl %7,%1         \n\t"                            \
     "adcl %8,%2         \n\t"                            \
     "addl %6,%0         \n\t"                            \
     "adcl %7,%1         \n\t"                            \
     "adcl %8,%2         \n\t"                            \
     :"=r"(c0), "=r"(c1), "=r"(c2) : "0"(c0), "1"(c1), "2"(c2), "r"(sc0), "r"(sc1), "r"(sc2) : "%cc");

#elif defined(TFM_ARM)

/* ARM code */

#define COMBA_START

#define CLEAR_CARRY \
   c0 = c1 = c2 = 0;

#define COMBA_STORE(x) \
   x = c0;

#define COMBA_STORE2(x) \
   x = c1;

#define CARRY_FORWARD \
   do { c0 = c1; c1 = c2; c2 = 0; } while (0);

#define COMBA_FINI

/* multiplies point i and j, updates carry "c1" and digit c2 */
#define SQRADD(i, j)                                             \
asm(                                                             \
"  UMULL  r0,r1,%6,%6              \n\t"                         \
"  ADDS   %0,%0,r0                 \n\t"                         \
"  ADCS   %1,%1,r1                 \n\t"                         \
"  ADC    %2,%2,#0                 \n\t"                         \
:"=r"(c0), "=r"(c1), "=r"(c2) : "0"(c0), "1"(c1), "2"(c2), "r"(i) : "r0", "r1", "%cc");
	
/* for squaring some of the terms are doubled... */
#define SQRADD2(i, j)                                            \
asm(                                                             \
"  UMULL  r0,r1,%6,%7              \n\t"                         \
"  ADDS   %0,%0,r0                 \n\t"                         \
"  ADCS   %1,%1,r1                 \n\t"                         \
"  ADC    %2,%2,#0                 \n\t"                         \
"  ADDS   %0,%0,r0                 \n\t"                         \
"  ADCS   %1,%1,r1                 \n\t"                         \
"  ADC    %2,%2,#0                 \n\t"                         \
:"=r"(c0), "=r"(c1), "=r"(c2) : "0"(c0), "1"(c1), "2"(c2), "r"(i), "r"(j) : "r0", "r1", "%cc");

#define SQRADDSC(i, j)                                           \
asm(                                                             \
"  UMULL  %0,%1,%6,%7              \n\t"                         \
"  SUB    %2,%2,%2                 \n\t"                         \
:"=r"(sc0), "=r"(sc1), "=r"(sc2) : "0"(sc0), "1"(sc1), "2"(sc2), "r"(i), "r"(j) : "%cc");

#define SQRADDAC(i, j)                                           \
asm(                                                             \
"  UMULL  r0,r1,%6,%7              \n\t"                         \
"  ADDS   %0,%0,r0                 \n\t"                         \
"  ADCS   %1,%1,r1                 \n\t"                         \
"  ADC    %2,%2,#0                 \n\t"                         \
:"=r"(sc0), "=r"(sc1), "=r"(sc2) : "0"(sc0), "1"(sc1), "2"(sc2), "r"(i), "r"(j) : "r0", "r1", "%cc");

#define SQRADDDB                                                 \
asm(                                                             \
"  ADDS  %0,%0,%3                     \n\t"                      \
"  ADCS  %1,%1,%4                     \n\t"                      \
"  ADC   %2,%2,%5                     \n\t"                      \
"  ADDS  %0,%0,%3                     \n\t"                      \
"  ADCS  %1,%1,%4                     \n\t"                      \
"  ADC   %2,%2,%5                     \n\t"                      \
:"=r"(c0), "=r"(c1), "=r"(c2) : "r"(sc0), "r"(sc1), "r"(sc2), "0"(c0), "1"(c1), "2"(c2) : "%cc");

#elif defined(TFM_PPC32)

/* PPC32 */

#define COMBA_START

#define CLEAR_CARRY \
   c0 = c1 = c2 = 0;

#define COMBA_STORE(x) \
   x = c0;

#define COMBA_STORE2(x) \
   x = c1;

#define CARRY_FORWARD \
   do { c0 = c1; c1 = c2; c2 = 0; } while (0);

#define COMBA_FINI

/* multiplies point i and j, updates carry "c1" and digit c2 */
#define SQRADD(i, j)             \
asm(                             \
   " mullw  16,%6,%6       \n\t" \
   " addc   %0,%0,16       \n\t" \
   " mulhwu 16,%6,%6       \n\t" \
   " adde   %1,%1,16       \n\t" \
   " addze  %2,%2          \n\t" \
:"=r"(c0), "=r"(c1), "=r"(c2):"0"(c0), "1"(c1), "2"(c2), "r"(i):"16","%cc");

/* for squaring some of the terms are doubled... */
#define SQRADD2(i, j)            \
asm(                             \
   " mullw  16,%6,%7       \n\t" \
   " mulhwu 17,%6,%7       \n\t" \
   " addc   %0,%0,16       \n\t" \
   " adde   %1,%1,17       \n\t" \
   " addze  %2,%2          \n\t" \
   " addc   %0,%0,16       \n\t" \
   " adde   %1,%1,17       \n\t" \
   " addze  %2,%2          \n\t" \
:"=r"(c0), "=r"(c1), "=r"(c2):"0"(c0), "1"(c1), "2"(c2), "r"(i), "r"(j):"16", "17","%cc");

#define SQRADDSC(i, j)            \
asm(                              \
   " mullw  %0,%6,%7        \n\t" \
   " mulhwu %1,%6,%7        \n\t" \
   " xor    %2,%2,%2        \n\t" \
:"=r"(sc0), "=r"(sc1), "=r"(sc2):"0"(sc0), "1"(sc1), "2"(sc2), "r"(i),"r"(j) : "%cc");

#define SQRADDAC(i, j)           \
asm(                             \
   " mullw  16,%6,%7       \n\t" \
   " addc   %0,%0,16       \n\t" \
   " mulhwu 16,%6,%7       \n\t" \
   " adde   %1,%1,16       \n\t" \
   " addze  %2,%2          \n\t" \
:"=r"(sc0), "=r"(sc1), "=r"(sc2):"0"(sc0), "1"(sc1), "2"(sc2), "r"(i), "r"(j):"16", "%cc");

#define SQRADDDB                  \
asm(                              \
   " addc   %0,%0,%3        \n\t" \
   " adde   %1,%1,%4        \n\t" \
   " adde   %2,%2,%5        \n\t" \
   " addc   %0,%0,%3        \n\t" \
   " adde   %1,%1,%4        \n\t" \
   " adde   %2,%2,%5        \n\t" \
:"=r"(c0), "=r"(c1), "=r"(c2) : "r"(sc0), "r"(sc1), "r"(sc2), "0"(c0), "1"(c1), "2"(c2) : "%cc");

#elif defined(TFM_PPC64)
/* PPC64 */

#define COMBA_START

#define CLEAR_CARRY \
   c0 = c1 = c2 = 0;

#define COMBA_STORE(x) \
   x = c0;

#define COMBA_STORE2(x) \
   x = c1;

#define CARRY_FORWARD \
   do { c0 = c1; c1 = c2; c2 = 0; } while (0);

#define COMBA_FINI

/* multiplies point i and j, updates carry "c1" and digit c2 */
#define SQRADD(i, j)             \
asm(                             \
   " mulld  r16,%6,%6       \n\t" \
   " addc   %0,%0,r16       \n\t" \
   " mulhdu r16,%6,%6       \n\t" \
   " adde   %1,%1,r16       \n\t" \
   " addze  %2,%2          \n\t" \
:"=r"(c0), "=r"(c1), "=r"(c2):"0"(c0), "1"(c1), "2"(c2), "r"(i):"r16","%cc");

/* for squaring some of the terms are doubled... */
#define SQRADD2(i, j)            \
asm(                             \
   " mulld  r16,%6,%7       \n\t" \
   " mulhdu r17,%6,%7       \n\t" \
   " addc   %0,%0,r16       \n\t" \
   " adde   %1,%1,r17       \n\t" \
   " addze  %2,%2          \n\t" \
   " addc   %0,%0,r16       \n\t" \
   " adde   %1,%1,r17       \n\t" \
   " addze  %2,%2          \n\t" \
:"=r"(c0), "=r"(c1), "=r"(c2):"0"(c0), "1"(c1), "2"(c2), "r"(i), "r"(j):"r16", "r17","%cc");

#define SQRADDSC(i, j)            \
asm(                              \
   " mulld  %0,%6,%7        \n\t" \
   " mulhdu %1,%6,%7        \n\t" \
   " xor    %2,%2,%2        \n\t" \
:"=r"(sc0), "=r"(sc1), "=r"(sc2):"0"(sc0), "1"(sc1), "2"(sc2), "r"(i),"r"(j) : "%cc");

#define SQRADDAC(i, j)           \
asm(                             \
   " mulld  r16,%6,%7       \n\t" \
   " addc   %0,%0,r16       \n\t" \
   " mulhdu r16,%6,%7       \n\t" \
   " adde   %1,%1,r16       \n\t" \
   " addze  %2,%2          \n\t" \
:"=r"(sc0), "=r"(sc1), "=r"(sc2):"0"(sc0), "1"(sc1), "2"(sc2), "r"(i), "r"(j):"r16", "%cc");

#define SQRADDDB                  \
asm(                              \
   " addc   %0,%0,%3        \n\t" \
   " adde   %1,%1,%4        \n\t" \
   " adde   %2,%2,%5        \n\t" \
   " addc   %0,%0,%3        \n\t" \
   " adde   %1,%1,%4        \n\t" \
   " adde   %2,%2,%5        \n\t" \
:"=r"(c0), "=r"(c1), "=r"(c2) : "r"(sc0), "r"(sc1), "r"(sc2), "0"(c0), "1"(c1), "2"(c2) : "%cc");


#elif defined(TFM_AVR32)

/* AVR32 */

#define COMBA_START

#define CLEAR_CARRY \
   c0 = c1 = c2 = 0;

#define COMBA_STORE(x) \
   x = c0;

#define COMBA_STORE2(x) \
   x = c1;

#define CARRY_FORWARD \
   do { c0 = c1; c1 = c2; c2 = 0; } while (0);

#define COMBA_FINI

/* multiplies point i and j, updates carry "c1" and digit c2 */
#define SQRADD(i, j)             \
asm(                             \
   " mulu.d r2,%6,%6       \n\t" \
   " add    %0,%0,r2       \n\t" \
   " adc    %1,%1,r3       \n\t" \
   " acr    %2             \n\t" \
:"=r"(c0), "=r"(c1), "=r"(c2):"0"(c0), "1"(c1), "2"(c2), "r"(i):"r2","r3");

/* for squaring some of the terms are doubled... */
#define SQRADD2(i, j)            \
asm(                             \
   " mulu.d r2,%6,%7       \n\t" \
   " add    %0,%0,r2       \n\t" \
   " adc    %1,%1,r3       \n\t" \
   " acr    %2,            \n\t" \
   " add    %0,%0,r2       \n\t" \
   " adc    %1,%1,r3       \n\t" \
   " acr    %2,            \n\t" \
:"=r"(c0), "=r"(c1), "=r"(c2):"0"(c0), "1"(c1), "2"(c2), "r"(i), "r"(j):"r2", "r3");

#define SQRADDSC(i, j)            \
asm(                              \
   " mulu.d r2,%6,%7        \n\t" \
   " mov    %0,r2           \n\t" \
   " mov    %1,r3           \n\t" \
   " eor    %2,%2           \n\t" \
:"=r"(sc0), "=r"(sc1), "=r"(sc2):"0"(sc0), "1"(sc1), "2"(sc2), "r"(i),"r"(j) : "r2", "r3");

#define SQRADDAC(i, j)           \
asm(                             \
   " mulu.d r2,%6,%7       \n\t" \
   " add    %0,%0,r2       \n\t" \
   " adc    %1,%1,r3       \n\t" \
   " acr    %2             \n\t" \
:"=r"(sc0), "=r"(sc1), "=r"(sc2):"0"(sc0), "1"(sc1), "2"(sc2), "r"(i), "r"(j):"r2", "r3");

#define SQRADDDB                  \
asm(                              \
   " add    %0,%0,%3        \n\t" \
   " adc    %1,%1,%4        \n\t" \
   " adc    %2,%2,%5        \n\t" \
   " add    %0,%0,%3        \n\t" \
   " adc    %1,%1,%4        \n\t" \
   " adc    %2,%2,%5        \n\t" \
:"=r"(c0), "=r"(c1), "=r"(c2) : "r"(sc0), "r"(sc1), "r"(sc2), "0"(c0), "1"(c1), "2"(c2) : "%cc");

#elif defined(TFM_MIPS)

/* MIPS */

#define COMBA_START

#define CLEAR_CARRY \
   c0 = c1 = c2 = 0;

#define COMBA_STORE(x) \
   x = c0;

#define COMBA_STORE2(x) \
   x = c1;

#define CARRY_FORWARD \
   do { c0 = c1; c1 = c2; c2 = 0; } while (0);

#define COMBA_FINI

/* multiplies point i and j, updates carry "c1" and digit c2 */
#define SQRADD(i, j)              \
asm(                              \
   " multu  %6,%6          \n\t"  \
   " mflo   $12            \n\t"  \
   " mfhi   $13            \n\t"  \
   " addu    %0,%0,$12     \n\t"  \
   " sltu   $12,%0,$12     \n\t"  \
   " addu    %1,%1,$13     \n\t"  \
   " sltu   $13,%1,$13     \n\t"  \
   " addu    %1,%1,$12     \n\t"  \
   " sltu   $12,%1,$12     \n\t"  \
   " addu    %2,%2,$13     \n\t"  \
   " addu    %2,%2,$12     \n\t"  \
:"=r"(c0), "=r"(c1), "=r"(c2):"0"(c0), "1"(c1), "2"(c2), "r"(i):"$12","$13");

/* for squaring some of the terms are doubled... */
#define SQRADD2(i, j)            \
asm(                             \
   " multu  %6,%7          \n\t" \
   " mflo   $12            \n\t" \
   " mfhi   $13            \n\t" \
                                 \
   " addu    %0,%0,$12     \n\t" \
   " sltu   $14,%0,$12     \n\t" \
   " addu    %1,%1,$13     \n\t" \
   " sltu   $15,%1,$13     \n\t" \
   " addu    %1,%1,$14     \n\t" \
   " sltu   $14,%1,$14     \n\t" \
   " addu    %2,%2,$15     \n\t" \
   " addu    %2,%2,$14     \n\t" \
                                 \
   " addu    %0,%0,$12     \n\t" \
   " sltu   $14,%0,$12     \n\t" \
   " addu    %1,%1,$13     \n\t" \
   " sltu   $15,%1,$13     \n\t" \
   " addu    %1,%1,$14     \n\t" \
   " sltu   $14,%1,$14     \n\t" \
   " addu    %2,%2,$15     \n\t" \
   " addu    %2,%2,$14     \n\t" \
:"=r"(c0), "=r"(c1), "=r"(c2):"0"(c0), "1"(c1), "2"(c2), "r"(i), "r"(j):"$12", "$13", "$14", "$15");

#define SQRADDSC(i, j)            \
asm(                              \
   " multu  %6,%7          \n\t"  \
   " mflo   %0             \n\t"  \
   " mfhi   %1             \n\t"  \
   " xor    %2,%2,%2       \n\t"  \
:"=r"(sc0), "=r"(sc1), "=r"(sc2):"0"(sc0), "1"(sc1), "2"(sc2), "r"(i),"r"(j) : "%cc");

#define SQRADDAC(i, j)           \
asm(                             \
   " multu  %6,%7          \n\t" \
   " mflo   $12            \n\t" \
   " mfhi   $13            \n\t" \
   " addu    %0,%0,$12     \n\t" \
   " sltu   $12,%0,$12     \n\t" \
   " addu    %1,%1,$13     \n\t" \
   " sltu   $13,%1,$13     \n\t" \
   " addu    %1,%1,$12     \n\t" \
   " sltu   $12,%1,$12     \n\t" \
   " addu    %2,%2,$13     \n\t" \
   " addu    %2,%2,$12     \n\t" \
:"=r"(sc0), "=r"(sc1), "=r"(sc2):"0"(sc0), "1"(sc1), "2"(sc2), "r"(i), "r"(j):"$12", "$13", "$14");

#define SQRADDDB                  \
asm(                              \
   " addu    %0,%0,%3       \n\t" \
   " sltu   $10,%0,%3       \n\t" \
   " addu    %1,%1,$10      \n\t" \
   " sltu   $10,%1,$10      \n\t" \
   " addu    %1,%1,%4       \n\t" \
   " sltu   $11,%1,%4       \n\t" \
   " addu    %2,%2,$10      \n\t" \
   " addu    %2,%2,$11      \n\t" \
   " addu    %2,%2,%5       \n\t" \
                                  \
   " addu    %0,%0,%3       \n\t" \
   " sltu   $10,%0,%3       \n\t" \
   " addu    %1,%1,$10      \n\t" \
   " sltu   $10,%1,$10      \n\t" \
   " addu    %1,%1,%4       \n\t" \
   " sltu   $11,%1,%4       \n\t" \
   " addu    %2,%2,$10      \n\t" \
   " addu    %2,%2,$11      \n\t" \
   " addu    %2,%2,%5       \n\t" \
:"=r"(c0), "=r"(c1), "=r"(c2) : "r"(sc0), "r"(sc1), "r"(sc2), "0"(c0), "1"(c1), "2"(c2) : "$10", "$11");

#else

#define TFM_ISO

/* ISO C portable code */

#define COMBA_START

#define CLEAR_CARRY \
   c0 = c1 = c2 = 0;

#define COMBA_STORE(x) \
   x = c0;

#define COMBA_STORE2(x) \
   x = c1;

#define CARRY_FORWARD \
   do { c0 = c1; c1 = c2; c2 = 0; } while (0);

#define COMBA_FINI

/* multiplies point i and j, updates carry "c1" and digit c2 */
#define SQRADD(i, j)                                 \
   do { fp_word t;                                   \
   t = c0 + ((fp_word)i) * ((fp_word)j);  c0 = t;    \
   t = c1 + (t >> DIGIT_BIT);             c1 = t; c2 += t >> DIGIT_BIT; \
   } while (0);
  

/* for squaring some of the terms are doubled... */
#define SQRADD2(i, j)                                                 \
   do { fp_word t;                                                    \
   t  = ((fp_word)i) * ((fp_word)j);                                  \
   tt = (fp_word)c0 + t;                 c0 = tt;                              \
   tt = (fp_word)c1 + (tt >> DIGIT_BIT); c1 = tt; c2 += tt >> DIGIT_BIT;       \
   tt = (fp_word)c0 + t;                 c0 = tt;                              \
   tt = (fp_word)c1 + (tt >> DIGIT_BIT); c1 = tt; c2 += tt >> DIGIT_BIT;       \
   } while (0);

#define SQRADDSC(i, j)                                                         \
   do { fp_word t;                                                             \
      t =  ((fp_word)i) * ((fp_word)j);                                        \
      sc0 = (fp_digit)t; sc1 = (t >> DIGIT_BIT); sc2 = 0;                      \
   } while (0);

#define SQRADDAC(i, j)                                                         \
   do { fp_word t;                                                             \
   t = sc0 + ((fp_word)i) * ((fp_word)j);  sc0 = t;                            \
   t = sc1 + (t >> DIGIT_BIT);             sc1 = t; sc2 += t >> DIGIT_BIT;     \
   } while (0);

#define SQRADDDB                                                               \
   do { fp_word t;                                                             \
   t = ((fp_word)sc0) + ((fp_word)sc0) + c0; c0 = t;                                                 \
   t = ((fp_word)sc1) + ((fp_word)sc1) + c1 + (t >> DIGIT_BIT); c1 = t;                              \
   c2 = c2 + ((fp_word)sc2) + ((fp_word)sc2) + (t >> DIGIT_BIT);                                     \
   } while (0);

#endif

/* $Source: /cvs/libtom/tomsfastmath/src/sqr/fp_sqr_comba.c,v $ */
/* $Revision: 1.4 $ */
/* $Date: 2007/03/14 23:47:42 $ */

/* End: fp_sqr_comba.c */

/* Start: fp_sqr_comba_12.c */
#define TFM_DEFINES
#include "fp_sqr_comba.c"

#ifdef TFM_SQR12
void fp_sqr_comba12(fp_int *A, fp_int *B)
{
   fp_digit *a, b[24], c0, c1, c2, sc0, sc1, sc2;
#ifdef TFM_ISO
   fp_word tt;
#endif

   a = A->dp;
   COMBA_START; 

   /* clear carries */
   CLEAR_CARRY;

   /* output 0 */
   SQRADD(a[0],a[0]);
   COMBA_STORE(b[0]);

   /* output 1 */
   CARRY_FORWARD;
   SQRADD2(a[0], a[1]); 
   COMBA_STORE(b[1]);

   /* output 2 */
   CARRY_FORWARD;
   SQRADD2(a[0], a[2]); SQRADD(a[1], a[1]); 
   COMBA_STORE(b[2]);

   /* output 3 */
   CARRY_FORWARD;
   SQRADD2(a[0], a[3]); SQRADD2(a[1], a[2]); 
   COMBA_STORE(b[3]);

   /* output 4 */
   CARRY_FORWARD;
   SQRADD2(a[0], a[4]); SQRADD2(a[1], a[3]); SQRADD(a[2], a[2]); 
   COMBA_STORE(b[4]);

   /* output 5 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[5]); SQRADDAC(a[1], a[4]); SQRADDAC(a[2], a[3]); SQRADDDB; 
   COMBA_STORE(b[5]);

   /* output 6 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[6]); SQRADDAC(a[1], a[5]); SQRADDAC(a[2], a[4]); SQRADDDB; SQRADD(a[3], a[3]); 
   COMBA_STORE(b[6]);

   /* output 7 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[7]); SQRADDAC(a[1], a[6]); SQRADDAC(a[2], a[5]); SQRADDAC(a[3], a[4]); SQRADDDB; 
   COMBA_STORE(b[7]);

   /* output 8 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[8]); SQRADDAC(a[1], a[7]); SQRADDAC(a[2], a[6]); SQRADDAC(a[3], a[5]); SQRADDDB; SQRADD(a[4], a[4]); 
   COMBA_STORE(b[8]);

   /* output 9 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[9]); SQRADDAC(a[1], a[8]); SQRADDAC(a[2], a[7]); SQRADDAC(a[3], a[6]); SQRADDAC(a[4], a[5]); SQRADDDB; 
   COMBA_STORE(b[9]);

   /* output 10 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[10]); SQRADDAC(a[1], a[9]); SQRADDAC(a[2], a[8]); SQRADDAC(a[3], a[7]); SQRADDAC(a[4], a[6]); SQRADDDB; SQRADD(a[5], a[5]); 
   COMBA_STORE(b[10]);

   /* output 11 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[11]); SQRADDAC(a[1], a[10]); SQRADDAC(a[2], a[9]); SQRADDAC(a[3], a[8]); SQRADDAC(a[4], a[7]); SQRADDAC(a[5], a[6]); SQRADDDB; 
   COMBA_STORE(b[11]);

   /* output 12 */
   CARRY_FORWARD;
   SQRADDSC(a[1], a[11]); SQRADDAC(a[2], a[10]); SQRADDAC(a[3], a[9]); SQRADDAC(a[4], a[8]); SQRADDAC(a[5], a[7]); SQRADDDB; SQRADD(a[6], a[6]); 
   COMBA_STORE(b[12]);

   /* output 13 */
   CARRY_FORWARD;
   SQRADDSC(a[2], a[11]); SQRADDAC(a[3], a[10]); SQRADDAC(a[4], a[9]); SQRADDAC(a[5], a[8]); SQRADDAC(a[6], a[7]); SQRADDDB; 
   COMBA_STORE(b[13]);

   /* output 14 */
   CARRY_FORWARD;
   SQRADDSC(a[3], a[11]); SQRADDAC(a[4], a[10]); SQRADDAC(a[5], a[9]); SQRADDAC(a[6], a[8]); SQRADDDB; SQRADD(a[7], a[7]); 
   COMBA_STORE(b[14]);

   /* output 15 */
   CARRY_FORWARD;
   SQRADDSC(a[4], a[11]); SQRADDAC(a[5], a[10]); SQRADDAC(a[6], a[9]); SQRADDAC(a[7], a[8]); SQRADDDB; 
   COMBA_STORE(b[15]);

   /* output 16 */
   CARRY_FORWARD;
   SQRADDSC(a[5], a[11]); SQRADDAC(a[6], a[10]); SQRADDAC(a[7], a[9]); SQRADDDB; SQRADD(a[8], a[8]); 
   COMBA_STORE(b[16]);

   /* output 17 */
   CARRY_FORWARD;
   SQRADDSC(a[6], a[11]); SQRADDAC(a[7], a[10]); SQRADDAC(a[8], a[9]); SQRADDDB; 
   COMBA_STORE(b[17]);

   /* output 18 */
   CARRY_FORWARD;
   SQRADD2(a[7], a[11]); SQRADD2(a[8], a[10]); SQRADD(a[9], a[9]); 
   COMBA_STORE(b[18]);

   /* output 19 */
   CARRY_FORWARD;
   SQRADD2(a[8], a[11]); SQRADD2(a[9], a[10]); 
   COMBA_STORE(b[19]);

   /* output 20 */
   CARRY_FORWARD;
   SQRADD2(a[9], a[11]); SQRADD(a[10], a[10]); 
   COMBA_STORE(b[20]);

   /* output 21 */
   CARRY_FORWARD;
   SQRADD2(a[10], a[11]); 
   COMBA_STORE(b[21]);

   /* output 22 */
   CARRY_FORWARD;
   SQRADD(a[11], a[11]); 
   COMBA_STORE(b[22]);
   COMBA_STORE2(b[23]);
   COMBA_FINI;

   B->used = 24;
   B->sign = FP_ZPOS;
   memcpy(B->dp, b, 24 * sizeof(fp_digit));
   fp_clamp(B);
}
#endif


/* $Source: /cvs/libtom/tomsfastmath/src/sqr/fp_sqr_comba_12.c,v $ */
/* $Revision: 1.2 $ */
/* $Date: 2007/02/17 03:39:01 $ */

/* End: fp_sqr_comba_12.c */

/* Start: fp_sqr_comba_17.c */
#define TFM_DEFINES
#include "fp_sqr_comba.c"

#ifdef TFM_SQR17
void fp_sqr_comba17(fp_int *A, fp_int *B)
{
   fp_digit *a, b[34], c0, c1, c2, sc0, sc1, sc2;
#ifdef TFM_ISO
   fp_word tt;
#endif

   a = A->dp;
   COMBA_START; 

   /* clear carries */
   CLEAR_CARRY;

   /* output 0 */
   SQRADD(a[0],a[0]);
   COMBA_STORE(b[0]);

   /* output 1 */
   CARRY_FORWARD;
   SQRADD2(a[0], a[1]); 
   COMBA_STORE(b[1]);

   /* output 2 */
   CARRY_FORWARD;
   SQRADD2(a[0], a[2]); SQRADD(a[1], a[1]); 
   COMBA_STORE(b[2]);

   /* output 3 */
   CARRY_FORWARD;
   SQRADD2(a[0], a[3]); SQRADD2(a[1], a[2]); 
   COMBA_STORE(b[3]);

   /* output 4 */
   CARRY_FORWARD;
   SQRADD2(a[0], a[4]); SQRADD2(a[1], a[3]); SQRADD(a[2], a[2]); 
   COMBA_STORE(b[4]);

   /* output 5 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[5]); SQRADDAC(a[1], a[4]); SQRADDAC(a[2], a[3]); SQRADDDB; 
   COMBA_STORE(b[5]);

   /* output 6 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[6]); SQRADDAC(a[1], a[5]); SQRADDAC(a[2], a[4]); SQRADDDB; SQRADD(a[3], a[3]); 
   COMBA_STORE(b[6]);

   /* output 7 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[7]); SQRADDAC(a[1], a[6]); SQRADDAC(a[2], a[5]); SQRADDAC(a[3], a[4]); SQRADDDB; 
   COMBA_STORE(b[7]);

   /* output 8 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[8]); SQRADDAC(a[1], a[7]); SQRADDAC(a[2], a[6]); SQRADDAC(a[3], a[5]); SQRADDDB; SQRADD(a[4], a[4]); 
   COMBA_STORE(b[8]);

   /* output 9 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[9]); SQRADDAC(a[1], a[8]); SQRADDAC(a[2], a[7]); SQRADDAC(a[3], a[6]); SQRADDAC(a[4], a[5]); SQRADDDB; 
   COMBA_STORE(b[9]);

   /* output 10 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[10]); SQRADDAC(a[1], a[9]); SQRADDAC(a[2], a[8]); SQRADDAC(a[3], a[7]); SQRADDAC(a[4], a[6]); SQRADDDB; SQRADD(a[5], a[5]); 
   COMBA_STORE(b[10]);

   /* output 11 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[11]); SQRADDAC(a[1], a[10]); SQRADDAC(a[2], a[9]); SQRADDAC(a[3], a[8]); SQRADDAC(a[4], a[7]); SQRADDAC(a[5], a[6]); SQRADDDB; 
   COMBA_STORE(b[11]);

   /* output 12 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[12]); SQRADDAC(a[1], a[11]); SQRADDAC(a[2], a[10]); SQRADDAC(a[3], a[9]); SQRADDAC(a[4], a[8]); SQRADDAC(a[5], a[7]); SQRADDDB; SQRADD(a[6], a[6]); 
   COMBA_STORE(b[12]);

   /* output 13 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[13]); SQRADDAC(a[1], a[12]); SQRADDAC(a[2], a[11]); SQRADDAC(a[3], a[10]); SQRADDAC(a[4], a[9]); SQRADDAC(a[5], a[8]); SQRADDAC(a[6], a[7]); SQRADDDB; 
   COMBA_STORE(b[13]);

   /* output 14 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[14]); SQRADDAC(a[1], a[13]); SQRADDAC(a[2], a[12]); SQRADDAC(a[3], a[11]); SQRADDAC(a[4], a[10]); SQRADDAC(a[5], a[9]); SQRADDAC(a[6], a[8]); SQRADDDB; SQRADD(a[7], a[7]); 
   COMBA_STORE(b[14]);

   /* output 15 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[15]); SQRADDAC(a[1], a[14]); SQRADDAC(a[2], a[13]); SQRADDAC(a[3], a[12]); SQRADDAC(a[4], a[11]); SQRADDAC(a[5], a[10]); SQRADDAC(a[6], a[9]); SQRADDAC(a[7], a[8]); SQRADDDB; 
   COMBA_STORE(b[15]);

   /* output 16 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[16]); SQRADDAC(a[1], a[15]); SQRADDAC(a[2], a[14]); SQRADDAC(a[3], a[13]); SQRADDAC(a[4], a[12]); SQRADDAC(a[5], a[11]); SQRADDAC(a[6], a[10]); SQRADDAC(a[7], a[9]); SQRADDDB; SQRADD(a[8], a[8]); 
   COMBA_STORE(b[16]);

   /* output 17 */
   CARRY_FORWARD;
   SQRADDSC(a[1], a[16]); SQRADDAC(a[2], a[15]); SQRADDAC(a[3], a[14]); SQRADDAC(a[4], a[13]); SQRADDAC(a[5], a[12]); SQRADDAC(a[6], a[11]); SQRADDAC(a[7], a[10]); SQRADDAC(a[8], a[9]); SQRADDDB; 
   COMBA_STORE(b[17]);

   /* output 18 */
   CARRY_FORWARD;
   SQRADDSC(a[2], a[16]); SQRADDAC(a[3], a[15]); SQRADDAC(a[4], a[14]); SQRADDAC(a[5], a[13]); SQRADDAC(a[6], a[12]); SQRADDAC(a[7], a[11]); SQRADDAC(a[8], a[10]); SQRADDDB; SQRADD(a[9], a[9]); 
   COMBA_STORE(b[18]);

   /* output 19 */
   CARRY_FORWARD;
   SQRADDSC(a[3], a[16]); SQRADDAC(a[4], a[15]); SQRADDAC(a[5], a[14]); SQRADDAC(a[6], a[13]); SQRADDAC(a[7], a[12]); SQRADDAC(a[8], a[11]); SQRADDAC(a[9], a[10]); SQRADDDB; 
   COMBA_STORE(b[19]);

   /* output 20 */
   CARRY_FORWARD;
   SQRADDSC(a[4], a[16]); SQRADDAC(a[5], a[15]); SQRADDAC(a[6], a[14]); SQRADDAC(a[7], a[13]); SQRADDAC(a[8], a[12]); SQRADDAC(a[9], a[11]); SQRADDDB; SQRADD(a[10], a[10]); 
   COMBA_STORE(b[20]);

   /* output 21 */
   CARRY_FORWARD;
   SQRADDSC(a[5], a[16]); SQRADDAC(a[6], a[15]); SQRADDAC(a[7], a[14]); SQRADDAC(a[8], a[13]); SQRADDAC(a[9], a[12]); SQRADDAC(a[10], a[11]); SQRADDDB; 
   COMBA_STORE(b[21]);

   /* output 22 */
   CARRY_FORWARD;
   SQRADDSC(a[6], a[16]); SQRADDAC(a[7], a[15]); SQRADDAC(a[8], a[14]); SQRADDAC(a[9], a[13]); SQRADDAC(a[10], a[12]); SQRADDDB; SQRADD(a[11], a[11]); 
   COMBA_STORE(b[22]);

   /* output 23 */
   CARRY_FORWARD;
   SQRADDSC(a[7], a[16]); SQRADDAC(a[8], a[15]); SQRADDAC(a[9], a[14]); SQRADDAC(a[10], a[13]); SQRADDAC(a[11], a[12]); SQRADDDB; 
   COMBA_STORE(b[23]);

   /* output 24 */
   CARRY_FORWARD;
   SQRADDSC(a[8], a[16]); SQRADDAC(a[9], a[15]); SQRADDAC(a[10], a[14]); SQRADDAC(a[11], a[13]); SQRADDDB; SQRADD(a[12], a[12]); 
   COMBA_STORE(b[24]);

   /* output 25 */
   CARRY_FORWARD;
   SQRADDSC(a[9], a[16]); SQRADDAC(a[10], a[15]); SQRADDAC(a[11], a[14]); SQRADDAC(a[12], a[13]); SQRADDDB; 
   COMBA_STORE(b[25]);

   /* output 26 */
   CARRY_FORWARD;
   SQRADDSC(a[10], a[16]); SQRADDAC(a[11], a[15]); SQRADDAC(a[12], a[14]); SQRADDDB; SQRADD(a[13], a[13]); 
   COMBA_STORE(b[26]);

   /* output 27 */
   CARRY_FORWARD;
   SQRADDSC(a[11], a[16]); SQRADDAC(a[12], a[15]); SQRADDAC(a[13], a[14]); SQRADDDB; 
   COMBA_STORE(b[27]);

   /* output 28 */
   CARRY_FORWARD;
   SQRADD2(a[12], a[16]); SQRADD2(a[13], a[15]); SQRADD(a[14], a[14]); 
   COMBA_STORE(b[28]);

   /* output 29 */
   CARRY_FORWARD;
   SQRADD2(a[13], a[16]); SQRADD2(a[14], a[15]); 
   COMBA_STORE(b[29]);

   /* output 30 */
   CARRY_FORWARD;
   SQRADD2(a[14], a[16]); SQRADD(a[15], a[15]); 
   COMBA_STORE(b[30]);

   /* output 31 */
   CARRY_FORWARD;
   SQRADD2(a[15], a[16]); 
   COMBA_STORE(b[31]);

   /* output 32 */
   CARRY_FORWARD;
   SQRADD(a[16], a[16]); 
   COMBA_STORE(b[32]);
   COMBA_STORE2(b[33]);
   COMBA_FINI;

   B->used = 34;
   B->sign = FP_ZPOS;
   memcpy(B->dp, b, 34 * sizeof(fp_digit));
   fp_clamp(B);
}
#endif


/* $Source: /cvs/libtom/tomsfastmath/src/sqr/fp_sqr_comba_17.c,v $ */
/* $Revision: 1.2 $ */
/* $Date: 2007/02/17 03:39:01 $ */

/* End: fp_sqr_comba_17.c */

/* Start: fp_sqr_comba_20.c */
#define TFM_DEFINES
#include "fp_sqr_comba.c"

#ifdef TFM_SQR20
void fp_sqr_comba20(fp_int *A, fp_int *B)
{
   fp_digit *a, b[40], c0, c1, c2, sc0, sc1, sc2;
#ifdef TFM_ISO
   fp_word tt;
#endif

   a = A->dp;
   COMBA_START; 

   /* clear carries */
   CLEAR_CARRY;

   /* output 0 */
   SQRADD(a[0],a[0]);
   COMBA_STORE(b[0]);

   /* output 1 */
   CARRY_FORWARD;
   SQRADD2(a[0], a[1]); 
   COMBA_STORE(b[1]);

   /* output 2 */
   CARRY_FORWARD;
   SQRADD2(a[0], a[2]); SQRADD(a[1], a[1]); 
   COMBA_STORE(b[2]);

   /* output 3 */
   CARRY_FORWARD;
   SQRADD2(a[0], a[3]); SQRADD2(a[1], a[2]); 
   COMBA_STORE(b[3]);

   /* output 4 */
   CARRY_FORWARD;
   SQRADD2(a[0], a[4]); SQRADD2(a[1], a[3]); SQRADD(a[2], a[2]); 
   COMBA_STORE(b[4]);

   /* output 5 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[5]); SQRADDAC(a[1], a[4]); SQRADDAC(a[2], a[3]); SQRADDDB; 
   COMBA_STORE(b[5]);

   /* output 6 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[6]); SQRADDAC(a[1], a[5]); SQRADDAC(a[2], a[4]); SQRADDDB; SQRADD(a[3], a[3]); 
   COMBA_STORE(b[6]);

   /* output 7 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[7]); SQRADDAC(a[1], a[6]); SQRADDAC(a[2], a[5]); SQRADDAC(a[3], a[4]); SQRADDDB; 
   COMBA_STORE(b[7]);

   /* output 8 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[8]); SQRADDAC(a[1], a[7]); SQRADDAC(a[2], a[6]); SQRADDAC(a[3], a[5]); SQRADDDB; SQRADD(a[4], a[4]); 
   COMBA_STORE(b[8]);

   /* output 9 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[9]); SQRADDAC(a[1], a[8]); SQRADDAC(a[2], a[7]); SQRADDAC(a[3], a[6]); SQRADDAC(a[4], a[5]); SQRADDDB; 
   COMBA_STORE(b[9]);

   /* output 10 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[10]); SQRADDAC(a[1], a[9]); SQRADDAC(a[2], a[8]); SQRADDAC(a[3], a[7]); SQRADDAC(a[4], a[6]); SQRADDDB; SQRADD(a[5], a[5]); 
   COMBA_STORE(b[10]);

   /* output 11 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[11]); SQRADDAC(a[1], a[10]); SQRADDAC(a[2], a[9]); SQRADDAC(a[3], a[8]); SQRADDAC(a[4], a[7]); SQRADDAC(a[5], a[6]); SQRADDDB; 
   COMBA_STORE(b[11]);

   /* output 12 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[12]); SQRADDAC(a[1], a[11]); SQRADDAC(a[2], a[10]); SQRADDAC(a[3], a[9]); SQRADDAC(a[4], a[8]); SQRADDAC(a[5], a[7]); SQRADDDB; SQRADD(a[6], a[6]); 
   COMBA_STORE(b[12]);

   /* output 13 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[13]); SQRADDAC(a[1], a[12]); SQRADDAC(a[2], a[11]); SQRADDAC(a[3], a[10]); SQRADDAC(a[4], a[9]); SQRADDAC(a[5], a[8]); SQRADDAC(a[6], a[7]); SQRADDDB; 
   COMBA_STORE(b[13]);

   /* output 14 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[14]); SQRADDAC(a[1], a[13]); SQRADDAC(a[2], a[12]); SQRADDAC(a[3], a[11]); SQRADDAC(a[4], a[10]); SQRADDAC(a[5], a[9]); SQRADDAC(a[6], a[8]); SQRADDDB; SQRADD(a[7], a[7]); 
   COMBA_STORE(b[14]);

   /* output 15 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[15]); SQRADDAC(a[1], a[14]); SQRADDAC(a[2], a[13]); SQRADDAC(a[3], a[12]); SQRADDAC(a[4], a[11]); SQRADDAC(a[5], a[10]); SQRADDAC(a[6], a[9]); SQRADDAC(a[7], a[8]); SQRADDDB; 
   COMBA_STORE(b[15]);

   /* output 16 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[16]); SQRADDAC(a[1], a[15]); SQRADDAC(a[2], a[14]); SQRADDAC(a[3], a[13]); SQRADDAC(a[4], a[12]); SQRADDAC(a[5], a[11]); SQRADDAC(a[6], a[10]); SQRADDAC(a[7], a[9]); SQRADDDB; SQRADD(a[8], a[8]); 
   COMBA_STORE(b[16]);

   /* output 17 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[17]); SQRADDAC(a[1], a[16]); SQRADDAC(a[2], a[15]); SQRADDAC(a[3], a[14]); SQRADDAC(a[4], a[13]); SQRADDAC(a[5], a[12]); SQRADDAC(a[6], a[11]); SQRADDAC(a[7], a[10]); SQRADDAC(a[8], a[9]); SQRADDDB; 
   COMBA_STORE(b[17]);

   /* output 18 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[18]); SQRADDAC(a[1], a[17]); SQRADDAC(a[2], a[16]); SQRADDAC(a[3], a[15]); SQRADDAC(a[4], a[14]); SQRADDAC(a[5], a[13]); SQRADDAC(a[6], a[12]); SQRADDAC(a[7], a[11]); SQRADDAC(a[8], a[10]); SQRADDDB; SQRADD(a[9], a[9]); 
   COMBA_STORE(b[18]);

   /* output 19 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[19]); SQRADDAC(a[1], a[18]); SQRADDAC(a[2], a[17]); SQRADDAC(a[3], a[16]); SQRADDAC(a[4], a[15]); SQRADDAC(a[5], a[14]); SQRADDAC(a[6], a[13]); SQRADDAC(a[7], a[12]); SQRADDAC(a[8], a[11]); SQRADDAC(a[9], a[10]); SQRADDDB; 
   COMBA_STORE(b[19]);

   /* output 20 */
   CARRY_FORWARD;
   SQRADDSC(a[1], a[19]); SQRADDAC(a[2], a[18]); SQRADDAC(a[3], a[17]); SQRADDAC(a[4], a[16]); SQRADDAC(a[5], a[15]); SQRADDAC(a[6], a[14]); SQRADDAC(a[7], a[13]); SQRADDAC(a[8], a[12]); SQRADDAC(a[9], a[11]); SQRADDDB; SQRADD(a[10], a[10]); 
   COMBA_STORE(b[20]);

   /* output 21 */
   CARRY_FORWARD;
   SQRADDSC(a[2], a[19]); SQRADDAC(a[3], a[18]); SQRADDAC(a[4], a[17]); SQRADDAC(a[5], a[16]); SQRADDAC(a[6], a[15]); SQRADDAC(a[7], a[14]); SQRADDAC(a[8], a[13]); SQRADDAC(a[9], a[12]); SQRADDAC(a[10], a[11]); SQRADDDB; 
   COMBA_STORE(b[21]);

   /* output 22 */
   CARRY_FORWARD;
   SQRADDSC(a[3], a[19]); SQRADDAC(a[4], a[18]); SQRADDAC(a[5], a[17]); SQRADDAC(a[6], a[16]); SQRADDAC(a[7], a[15]); SQRADDAC(a[8], a[14]); SQRADDAC(a[9], a[13]); SQRADDAC(a[10], a[12]); SQRADDDB; SQRADD(a[11], a[11]); 
   COMBA_STORE(b[22]);

   /* output 23 */
   CARRY_FORWARD;
   SQRADDSC(a[4], a[19]); SQRADDAC(a[5], a[18]); SQRADDAC(a[6], a[17]); SQRADDAC(a[7], a[16]); SQRADDAC(a[8], a[15]); SQRADDAC(a[9], a[14]); SQRADDAC(a[10], a[13]); SQRADDAC(a[11], a[12]); SQRADDDB; 
   COMBA_STORE(b[23]);

   /* output 24 */
   CARRY_FORWARD;
   SQRADDSC(a[5], a[19]); SQRADDAC(a[6], a[18]); SQRADDAC(a[7], a[17]); SQRADDAC(a[8], a[16]); SQRADDAC(a[9], a[15]); SQRADDAC(a[10], a[14]); SQRADDAC(a[11], a[13]); SQRADDDB; SQRADD(a[12], a[12]); 
   COMBA_STORE(b[24]);

   /* output 25 */
   CARRY_FORWARD;
   SQRADDSC(a[6], a[19]); SQRADDAC(a[7], a[18]); SQRADDAC(a[8], a[17]); SQRADDAC(a[9], a[16]); SQRADDAC(a[10], a[15]); SQRADDAC(a[11], a[14]); SQRADDAC(a[12], a[13]); SQRADDDB; 
   COMBA_STORE(b[25]);

   /* output 26 */
   CARRY_FORWARD;
   SQRADDSC(a[7], a[19]); SQRADDAC(a[8], a[18]); SQRADDAC(a[9], a[17]); SQRADDAC(a[10], a[16]); SQRADDAC(a[11], a[15]); SQRADDAC(a[12], a[14]); SQRADDDB; SQRADD(a[13], a[13]); 
   COMBA_STORE(b[26]);

   /* output 27 */
   CARRY_FORWARD;
   SQRADDSC(a[8], a[19]); SQRADDAC(a[9], a[18]); SQRADDAC(a[10], a[17]); SQRADDAC(a[11], a[16]); SQRADDAC(a[12], a[15]); SQRADDAC(a[13], a[14]); SQRADDDB; 
   COMBA_STORE(b[27]);

   /* output 28 */
   CARRY_FORWARD;
   SQRADDSC(a[9], a[19]); SQRADDAC(a[10], a[18]); SQRADDAC(a[11], a[17]); SQRADDAC(a[12], a[16]); SQRADDAC(a[13], a[15]); SQRADDDB; SQRADD(a[14], a[14]); 
   COMBA_STORE(b[28]);

   /* output 29 */
   CARRY_FORWARD;
   SQRADDSC(a[10], a[19]); SQRADDAC(a[11], a[18]); SQRADDAC(a[12], a[17]); SQRADDAC(a[13], a[16]); SQRADDAC(a[14], a[15]); SQRADDDB; 
   COMBA_STORE(b[29]);

   /* output 30 */
   CARRY_FORWARD;
   SQRADDSC(a[11], a[19]); SQRADDAC(a[12], a[18]); SQRADDAC(a[13], a[17]); SQRADDAC(a[14], a[16]); SQRADDDB; SQRADD(a[15], a[15]); 
   COMBA_STORE(b[30]);

   /* output 31 */
   CARRY_FORWARD;
   SQRADDSC(a[12], a[19]); SQRADDAC(a[13], a[18]); SQRADDAC(a[14], a[17]); SQRADDAC(a[15], a[16]); SQRADDDB; 
   COMBA_STORE(b[31]);

   /* output 32 */
   CARRY_FORWARD;
   SQRADDSC(a[13], a[19]); SQRADDAC(a[14], a[18]); SQRADDAC(a[15], a[17]); SQRADDDB; SQRADD(a[16], a[16]); 
   COMBA_STORE(b[32]);

   /* output 33 */
   CARRY_FORWARD;
   SQRADDSC(a[14], a[19]); SQRADDAC(a[15], a[18]); SQRADDAC(a[16], a[17]); SQRADDDB; 
   COMBA_STORE(b[33]);

   /* output 34 */
   CARRY_FORWARD;
   SQRADD2(a[15], a[19]); SQRADD2(a[16], a[18]); SQRADD(a[17], a[17]); 
   COMBA_STORE(b[34]);

   /* output 35 */
   CARRY_FORWARD;
   SQRADD2(a[16], a[19]); SQRADD2(a[17], a[18]); 
   COMBA_STORE(b[35]);

   /* output 36 */
   CARRY_FORWARD;
   SQRADD2(a[17], a[19]); SQRADD(a[18], a[18]); 
   COMBA_STORE(b[36]);

   /* output 37 */
   CARRY_FORWARD;
   SQRADD2(a[18], a[19]); 
   COMBA_STORE(b[37]);

   /* output 38 */
   CARRY_FORWARD;
   SQRADD(a[19], a[19]); 
   COMBA_STORE(b[38]);
   COMBA_STORE2(b[39]);
   COMBA_FINI;

   B->used = 40;
   B->sign = FP_ZPOS;
   memcpy(B->dp, b, 40 * sizeof(fp_digit));
   fp_clamp(B);
}
#endif


/* $Source: /cvs/libtom/tomsfastmath/src/sqr/fp_sqr_comba_20.c,v $ */
/* $Revision: 1.2 $ */
/* $Date: 2007/02/17 03:39:01 $ */

/* End: fp_sqr_comba_20.c */

/* Start: fp_sqr_comba_24.c */
#define TFM_DEFINES
#include "fp_sqr_comba.c"

#ifdef TFM_SQR24
void fp_sqr_comba24(fp_int *A, fp_int *B)
{
   fp_digit *a, b[48], c0, c1, c2, sc0, sc1, sc2;
#ifdef TFM_ISO
   fp_word tt;
#endif

   a = A->dp;
   COMBA_START; 

   /* clear carries */
   CLEAR_CARRY;

   /* output 0 */
   SQRADD(a[0],a[0]);
   COMBA_STORE(b[0]);

   /* output 1 */
   CARRY_FORWARD;
   SQRADD2(a[0], a[1]); 
   COMBA_STORE(b[1]);

   /* output 2 */
   CARRY_FORWARD;
   SQRADD2(a[0], a[2]); SQRADD(a[1], a[1]); 
   COMBA_STORE(b[2]);

   /* output 3 */
   CARRY_FORWARD;
   SQRADD2(a[0], a[3]); SQRADD2(a[1], a[2]); 
   COMBA_STORE(b[3]);

   /* output 4 */
   CARRY_FORWARD;
   SQRADD2(a[0], a[4]); SQRADD2(a[1], a[3]); SQRADD(a[2], a[2]); 
   COMBA_STORE(b[4]);

   /* output 5 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[5]); SQRADDAC(a[1], a[4]); SQRADDAC(a[2], a[3]); SQRADDDB; 
   COMBA_STORE(b[5]);

   /* output 6 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[6]); SQRADDAC(a[1], a[5]); SQRADDAC(a[2], a[4]); SQRADDDB; SQRADD(a[3], a[3]); 
   COMBA_STORE(b[6]);

   /* output 7 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[7]); SQRADDAC(a[1], a[6]); SQRADDAC(a[2], a[5]); SQRADDAC(a[3], a[4]); SQRADDDB; 
   COMBA_STORE(b[7]);

   /* output 8 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[8]); SQRADDAC(a[1], a[7]); SQRADDAC(a[2], a[6]); SQRADDAC(a[3], a[5]); SQRADDDB; SQRADD(a[4], a[4]); 
   COMBA_STORE(b[8]);

   /* output 9 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[9]); SQRADDAC(a[1], a[8]); SQRADDAC(a[2], a[7]); SQRADDAC(a[3], a[6]); SQRADDAC(a[4], a[5]); SQRADDDB; 
   COMBA_STORE(b[9]);

   /* output 10 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[10]); SQRADDAC(a[1], a[9]); SQRADDAC(a[2], a[8]); SQRADDAC(a[3], a[7]); SQRADDAC(a[4], a[6]); SQRADDDB; SQRADD(a[5], a[5]); 
   COMBA_STORE(b[10]);

   /* output 11 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[11]); SQRADDAC(a[1], a[10]); SQRADDAC(a[2], a[9]); SQRADDAC(a[3], a[8]); SQRADDAC(a[4], a[7]); SQRADDAC(a[5], a[6]); SQRADDDB; 
   COMBA_STORE(b[11]);

   /* output 12 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[12]); SQRADDAC(a[1], a[11]); SQRADDAC(a[2], a[10]); SQRADDAC(a[3], a[9]); SQRADDAC(a[4], a[8]); SQRADDAC(a[5], a[7]); SQRADDDB; SQRADD(a[6], a[6]); 
   COMBA_STORE(b[12]);

   /* output 13 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[13]); SQRADDAC(a[1], a[12]); SQRADDAC(a[2], a[11]); SQRADDAC(a[3], a[10]); SQRADDAC(a[4], a[9]); SQRADDAC(a[5], a[8]); SQRADDAC(a[6], a[7]); SQRADDDB; 
   COMBA_STORE(b[13]);

   /* output 14 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[14]); SQRADDAC(a[1], a[13]); SQRADDAC(a[2], a[12]); SQRADDAC(a[3], a[11]); SQRADDAC(a[4], a[10]); SQRADDAC(a[5], a[9]); SQRADDAC(a[6], a[8]); SQRADDDB; SQRADD(a[7], a[7]); 
   COMBA_STORE(b[14]);

   /* output 15 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[15]); SQRADDAC(a[1], a[14]); SQRADDAC(a[2], a[13]); SQRADDAC(a[3], a[12]); SQRADDAC(a[4], a[11]); SQRADDAC(a[5], a[10]); SQRADDAC(a[6], a[9]); SQRADDAC(a[7], a[8]); SQRADDDB; 
   COMBA_STORE(b[15]);

   /* output 16 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[16]); SQRADDAC(a[1], a[15]); SQRADDAC(a[2], a[14]); SQRADDAC(a[3], a[13]); SQRADDAC(a[4], a[12]); SQRADDAC(a[5], a[11]); SQRADDAC(a[6], a[10]); SQRADDAC(a[7], a[9]); SQRADDDB; SQRADD(a[8], a[8]); 
   COMBA_STORE(b[16]);

   /* output 17 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[17]); SQRADDAC(a[1], a[16]); SQRADDAC(a[2], a[15]); SQRADDAC(a[3], a[14]); SQRADDAC(a[4], a[13]); SQRADDAC(a[5], a[12]); SQRADDAC(a[6], a[11]); SQRADDAC(a[7], a[10]); SQRADDAC(a[8], a[9]); SQRADDDB; 
   COMBA_STORE(b[17]);

   /* output 18 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[18]); SQRADDAC(a[1], a[17]); SQRADDAC(a[2], a[16]); SQRADDAC(a[3], a[15]); SQRADDAC(a[4], a[14]); SQRADDAC(a[5], a[13]); SQRADDAC(a[6], a[12]); SQRADDAC(a[7], a[11]); SQRADDAC(a[8], a[10]); SQRADDDB; SQRADD(a[9], a[9]); 
   COMBA_STORE(b[18]);

   /* output 19 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[19]); SQRADDAC(a[1], a[18]); SQRADDAC(a[2], a[17]); SQRADDAC(a[3], a[16]); SQRADDAC(a[4], a[15]); SQRADDAC(a[5], a[14]); SQRADDAC(a[6], a[13]); SQRADDAC(a[7], a[12]); SQRADDAC(a[8], a[11]); SQRADDAC(a[9], a[10]); SQRADDDB; 
   COMBA_STORE(b[19]);

   /* output 20 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[20]); SQRADDAC(a[1], a[19]); SQRADDAC(a[2], a[18]); SQRADDAC(a[3], a[17]); SQRADDAC(a[4], a[16]); SQRADDAC(a[5], a[15]); SQRADDAC(a[6], a[14]); SQRADDAC(a[7], a[13]); SQRADDAC(a[8], a[12]); SQRADDAC(a[9], a[11]); SQRADDDB; SQRADD(a[10], a[10]); 
   COMBA_STORE(b[20]);

   /* output 21 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[21]); SQRADDAC(a[1], a[20]); SQRADDAC(a[2], a[19]); SQRADDAC(a[3], a[18]); SQRADDAC(a[4], a[17]); SQRADDAC(a[5], a[16]); SQRADDAC(a[6], a[15]); SQRADDAC(a[7], a[14]); SQRADDAC(a[8], a[13]); SQRADDAC(a[9], a[12]); SQRADDAC(a[10], a[11]); SQRADDDB; 
   COMBA_STORE(b[21]);

   /* output 22 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[22]); SQRADDAC(a[1], a[21]); SQRADDAC(a[2], a[20]); SQRADDAC(a[3], a[19]); SQRADDAC(a[4], a[18]); SQRADDAC(a[5], a[17]); SQRADDAC(a[6], a[16]); SQRADDAC(a[7], a[15]); SQRADDAC(a[8], a[14]); SQRADDAC(a[9], a[13]); SQRADDAC(a[10], a[12]); SQRADDDB; SQRADD(a[11], a[11]); 
   COMBA_STORE(b[22]);

   /* output 23 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[23]); SQRADDAC(a[1], a[22]); SQRADDAC(a[2], a[21]); SQRADDAC(a[3], a[20]); SQRADDAC(a[4], a[19]); SQRADDAC(a[5], a[18]); SQRADDAC(a[6], a[17]); SQRADDAC(a[7], a[16]); SQRADDAC(a[8], a[15]); SQRADDAC(a[9], a[14]); SQRADDAC(a[10], a[13]); SQRADDAC(a[11], a[12]); SQRADDDB; 
   COMBA_STORE(b[23]);

   /* output 24 */
   CARRY_FORWARD;
   SQRADDSC(a[1], a[23]); SQRADDAC(a[2], a[22]); SQRADDAC(a[3], a[21]); SQRADDAC(a[4], a[20]); SQRADDAC(a[5], a[19]); SQRADDAC(a[6], a[18]); SQRADDAC(a[7], a[17]); SQRADDAC(a[8], a[16]); SQRADDAC(a[9], a[15]); SQRADDAC(a[10], a[14]); SQRADDAC(a[11], a[13]); SQRADDDB; SQRADD(a[12], a[12]); 
   COMBA_STORE(b[24]);

   /* output 25 */
   CARRY_FORWARD;
   SQRADDSC(a[2], a[23]); SQRADDAC(a[3], a[22]); SQRADDAC(a[4], a[21]); SQRADDAC(a[5], a[20]); SQRADDAC(a[6], a[19]); SQRADDAC(a[7], a[18]); SQRADDAC(a[8], a[17]); SQRADDAC(a[9], a[16]); SQRADDAC(a[10], a[15]); SQRADDAC(a[11], a[14]); SQRADDAC(a[12], a[13]); SQRADDDB; 
   COMBA_STORE(b[25]);

   /* output 26 */
   CARRY_FORWARD;
   SQRADDSC(a[3], a[23]); SQRADDAC(a[4], a[22]); SQRADDAC(a[5], a[21]); SQRADDAC(a[6], a[20]); SQRADDAC(a[7], a[19]); SQRADDAC(a[8], a[18]); SQRADDAC(a[9], a[17]); SQRADDAC(a[10], a[16]); SQRADDAC(a[11], a[15]); SQRADDAC(a[12], a[14]); SQRADDDB; SQRADD(a[13], a[13]); 
   COMBA_STORE(b[26]);

   /* output 27 */
   CARRY_FORWARD;
   SQRADDSC(a[4], a[23]); SQRADDAC(a[5], a[22]); SQRADDAC(a[6], a[21]); SQRADDAC(a[7], a[20]); SQRADDAC(a[8], a[19]); SQRADDAC(a[9], a[18]); SQRADDAC(a[10], a[17]); SQRADDAC(a[11], a[16]); SQRADDAC(a[12], a[15]); SQRADDAC(a[13], a[14]); SQRADDDB; 
   COMBA_STORE(b[27]);

   /* output 28 */
   CARRY_FORWARD;
   SQRADDSC(a[5], a[23]); SQRADDAC(a[6], a[22]); SQRADDAC(a[7], a[21]); SQRADDAC(a[8], a[20]); SQRADDAC(a[9], a[19]); SQRADDAC(a[10], a[18]); SQRADDAC(a[11], a[17]); SQRADDAC(a[12], a[16]); SQRADDAC(a[13], a[15]); SQRADDDB; SQRADD(a[14], a[14]); 
   COMBA_STORE(b[28]);

   /* output 29 */
   CARRY_FORWARD;
   SQRADDSC(a[6], a[23]); SQRADDAC(a[7], a[22]); SQRADDAC(a[8], a[21]); SQRADDAC(a[9], a[20]); SQRADDAC(a[10], a[19]); SQRADDAC(a[11], a[18]); SQRADDAC(a[12], a[17]); SQRADDAC(a[13], a[16]); SQRADDAC(a[14], a[15]); SQRADDDB; 
   COMBA_STORE(b[29]);

   /* output 30 */
   CARRY_FORWARD;
   SQRADDSC(a[7], a[23]); SQRADDAC(a[8], a[22]); SQRADDAC(a[9], a[21]); SQRADDAC(a[10], a[20]); SQRADDAC(a[11], a[19]); SQRADDAC(a[12], a[18]); SQRADDAC(a[13], a[17]); SQRADDAC(a[14], a[16]); SQRADDDB; SQRADD(a[15], a[15]); 
   COMBA_STORE(b[30]);

   /* output 31 */
   CARRY_FORWARD;
   SQRADDSC(a[8], a[23]); SQRADDAC(a[9], a[22]); SQRADDAC(a[10], a[21]); SQRADDAC(a[11], a[20]); SQRADDAC(a[12], a[19]); SQRADDAC(a[13], a[18]); SQRADDAC(a[14], a[17]); SQRADDAC(a[15], a[16]); SQRADDDB; 
   COMBA_STORE(b[31]);

   /* output 32 */
   CARRY_FORWARD;
   SQRADDSC(a[9], a[23]); SQRADDAC(a[10], a[22]); SQRADDAC(a[11], a[21]); SQRADDAC(a[12], a[20]); SQRADDAC(a[13], a[19]); SQRADDAC(a[14], a[18]); SQRADDAC(a[15], a[17]); SQRADDDB; SQRADD(a[16], a[16]); 
   COMBA_STORE(b[32]);

   /* output 33 */
   CARRY_FORWARD;
   SQRADDSC(a[10], a[23]); SQRADDAC(a[11], a[22]); SQRADDAC(a[12], a[21]); SQRADDAC(a[13], a[20]); SQRADDAC(a[14], a[19]); SQRADDAC(a[15], a[18]); SQRADDAC(a[16], a[17]); SQRADDDB; 
   COMBA_STORE(b[33]);

   /* output 34 */
   CARRY_FORWARD;
   SQRADDSC(a[11], a[23]); SQRADDAC(a[12], a[22]); SQRADDAC(a[13], a[21]); SQRADDAC(a[14], a[20]); SQRADDAC(a[15], a[19]); SQRADDAC(a[16], a[18]); SQRADDDB; SQRADD(a[17], a[17]); 
   COMBA_STORE(b[34]);

   /* output 35 */
   CARRY_FORWARD;
   SQRADDSC(a[12], a[23]); SQRADDAC(a[13], a[22]); SQRADDAC(a[14], a[21]); SQRADDAC(a[15], a[20]); SQRADDAC(a[16], a[19]); SQRADDAC(a[17], a[18]); SQRADDDB; 
   COMBA_STORE(b[35]);

   /* output 36 */
   CARRY_FORWARD;
   SQRADDSC(a[13], a[23]); SQRADDAC(a[14], a[22]); SQRADDAC(a[15], a[21]); SQRADDAC(a[16], a[20]); SQRADDAC(a[17], a[19]); SQRADDDB; SQRADD(a[18], a[18]); 
   COMBA_STORE(b[36]);

   /* output 37 */
   CARRY_FORWARD;
   SQRADDSC(a[14], a[23]); SQRADDAC(a[15], a[22]); SQRADDAC(a[16], a[21]); SQRADDAC(a[17], a[20]); SQRADDAC(a[18], a[19]); SQRADDDB; 
   COMBA_STORE(b[37]);

   /* output 38 */
   CARRY_FORWARD;
   SQRADDSC(a[15], a[23]); SQRADDAC(a[16], a[22]); SQRADDAC(a[17], a[21]); SQRADDAC(a[18], a[20]); SQRADDDB; SQRADD(a[19], a[19]); 
   COMBA_STORE(b[38]);

   /* output 39 */
   CARRY_FORWARD;
   SQRADDSC(a[16], a[23]); SQRADDAC(a[17], a[22]); SQRADDAC(a[18], a[21]); SQRADDAC(a[19], a[20]); SQRADDDB; 
   COMBA_STORE(b[39]);

   /* output 40 */
   CARRY_FORWARD;
   SQRADDSC(a[17], a[23]); SQRADDAC(a[18], a[22]); SQRADDAC(a[19], a[21]); SQRADDDB; SQRADD(a[20], a[20]); 
   COMBA_STORE(b[40]);

   /* output 41 */
   CARRY_FORWARD;
   SQRADDSC(a[18], a[23]); SQRADDAC(a[19], a[22]); SQRADDAC(a[20], a[21]); SQRADDDB; 
   COMBA_STORE(b[41]);

   /* output 42 */
   CARRY_FORWARD;
   SQRADD2(a[19], a[23]); SQRADD2(a[20], a[22]); SQRADD(a[21], a[21]); 
   COMBA_STORE(b[42]);

   /* output 43 */
   CARRY_FORWARD;
   SQRADD2(a[20], a[23]); SQRADD2(a[21], a[22]); 
   COMBA_STORE(b[43]);

   /* output 44 */
   CARRY_FORWARD;
   SQRADD2(a[21], a[23]); SQRADD(a[22], a[22]); 
   COMBA_STORE(b[44]);

   /* output 45 */
   CARRY_FORWARD;
   SQRADD2(a[22], a[23]); 
   COMBA_STORE(b[45]);

   /* output 46 */
   CARRY_FORWARD;
   SQRADD(a[23], a[23]); 
   COMBA_STORE(b[46]);
   COMBA_STORE2(b[47]);
   COMBA_FINI;

   B->used = 48;
   B->sign = FP_ZPOS;
   memcpy(B->dp, b, 48 * sizeof(fp_digit));
   fp_clamp(B);
}
#endif


/* $Source: /cvs/libtom/tomsfastmath/src/sqr/fp_sqr_comba_24.c,v $ */
/* $Revision: 1.2 $ */
/* $Date: 2007/02/17 03:39:01 $ */

/* End: fp_sqr_comba_24.c */

/* Start: fp_sqr_comba_28.c */
#define TFM_DEFINES
#include "fp_sqr_comba.c"

#ifdef TFM_SQR28
void fp_sqr_comba28(fp_int *A, fp_int *B)
{
   fp_digit *a, b[56], c0, c1, c2, sc0, sc1, sc2;
#ifdef TFM_ISO
   fp_word tt;
#endif

   a = A->dp;
   COMBA_START; 

   /* clear carries */
   CLEAR_CARRY;

   /* output 0 */
   SQRADD(a[0],a[0]);
   COMBA_STORE(b[0]);

   /* output 1 */
   CARRY_FORWARD;
   SQRADD2(a[0], a[1]); 
   COMBA_STORE(b[1]);

   /* output 2 */
   CARRY_FORWARD;
   SQRADD2(a[0], a[2]); SQRADD(a[1], a[1]); 
   COMBA_STORE(b[2]);

   /* output 3 */
   CARRY_FORWARD;
   SQRADD2(a[0], a[3]); SQRADD2(a[1], a[2]); 
   COMBA_STORE(b[3]);

   /* output 4 */
   CARRY_FORWARD;
   SQRADD2(a[0], a[4]); SQRADD2(a[1], a[3]); SQRADD(a[2], a[2]); 
   COMBA_STORE(b[4]);

   /* output 5 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[5]); SQRADDAC(a[1], a[4]); SQRADDAC(a[2], a[3]); SQRADDDB; 
   COMBA_STORE(b[5]);

   /* output 6 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[6]); SQRADDAC(a[1], a[5]); SQRADDAC(a[2], a[4]); SQRADDDB; SQRADD(a[3], a[3]); 
   COMBA_STORE(b[6]);

   /* output 7 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[7]); SQRADDAC(a[1], a[6]); SQRADDAC(a[2], a[5]); SQRADDAC(a[3], a[4]); SQRADDDB; 
   COMBA_STORE(b[7]);

   /* output 8 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[8]); SQRADDAC(a[1], a[7]); SQRADDAC(a[2], a[6]); SQRADDAC(a[3], a[5]); SQRADDDB; SQRADD(a[4], a[4]); 
   COMBA_STORE(b[8]);

   /* output 9 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[9]); SQRADDAC(a[1], a[8]); SQRADDAC(a[2], a[7]); SQRADDAC(a[3], a[6]); SQRADDAC(a[4], a[5]); SQRADDDB; 
   COMBA_STORE(b[9]);

   /* output 10 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[10]); SQRADDAC(a[1], a[9]); SQRADDAC(a[2], a[8]); SQRADDAC(a[3], a[7]); SQRADDAC(a[4], a[6]); SQRADDDB; SQRADD(a[5], a[5]); 
   COMBA_STORE(b[10]);

   /* output 11 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[11]); SQRADDAC(a[1], a[10]); SQRADDAC(a[2], a[9]); SQRADDAC(a[3], a[8]); SQRADDAC(a[4], a[7]); SQRADDAC(a[5], a[6]); SQRADDDB; 
   COMBA_STORE(b[11]);

   /* output 12 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[12]); SQRADDAC(a[1], a[11]); SQRADDAC(a[2], a[10]); SQRADDAC(a[3], a[9]); SQRADDAC(a[4], a[8]); SQRADDAC(a[5], a[7]); SQRADDDB; SQRADD(a[6], a[6]); 
   COMBA_STORE(b[12]);

   /* output 13 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[13]); SQRADDAC(a[1], a[12]); SQRADDAC(a[2], a[11]); SQRADDAC(a[3], a[10]); SQRADDAC(a[4], a[9]); SQRADDAC(a[5], a[8]); SQRADDAC(a[6], a[7]); SQRADDDB; 
   COMBA_STORE(b[13]);

   /* output 14 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[14]); SQRADDAC(a[1], a[13]); SQRADDAC(a[2], a[12]); SQRADDAC(a[3], a[11]); SQRADDAC(a[4], a[10]); SQRADDAC(a[5], a[9]); SQRADDAC(a[6], a[8]); SQRADDDB; SQRADD(a[7], a[7]); 
   COMBA_STORE(b[14]);

   /* output 15 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[15]); SQRADDAC(a[1], a[14]); SQRADDAC(a[2], a[13]); SQRADDAC(a[3], a[12]); SQRADDAC(a[4], a[11]); SQRADDAC(a[5], a[10]); SQRADDAC(a[6], a[9]); SQRADDAC(a[7], a[8]); SQRADDDB; 
   COMBA_STORE(b[15]);

   /* output 16 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[16]); SQRADDAC(a[1], a[15]); SQRADDAC(a[2], a[14]); SQRADDAC(a[3], a[13]); SQRADDAC(a[4], a[12]); SQRADDAC(a[5], a[11]); SQRADDAC(a[6], a[10]); SQRADDAC(a[7], a[9]); SQRADDDB; SQRADD(a[8], a[8]); 
   COMBA_STORE(b[16]);

   /* output 17 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[17]); SQRADDAC(a[1], a[16]); SQRADDAC(a[2], a[15]); SQRADDAC(a[3], a[14]); SQRADDAC(a[4], a[13]); SQRADDAC(a[5], a[12]); SQRADDAC(a[6], a[11]); SQRADDAC(a[7], a[10]); SQRADDAC(a[8], a[9]); SQRADDDB; 
   COMBA_STORE(b[17]);

   /* output 18 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[18]); SQRADDAC(a[1], a[17]); SQRADDAC(a[2], a[16]); SQRADDAC(a[3], a[15]); SQRADDAC(a[4], a[14]); SQRADDAC(a[5], a[13]); SQRADDAC(a[6], a[12]); SQRADDAC(a[7], a[11]); SQRADDAC(a[8], a[10]); SQRADDDB; SQRADD(a[9], a[9]); 
   COMBA_STORE(b[18]);

   /* output 19 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[19]); SQRADDAC(a[1], a[18]); SQRADDAC(a[2], a[17]); SQRADDAC(a[3], a[16]); SQRADDAC(a[4], a[15]); SQRADDAC(a[5], a[14]); SQRADDAC(a[6], a[13]); SQRADDAC(a[7], a[12]); SQRADDAC(a[8], a[11]); SQRADDAC(a[9], a[10]); SQRADDDB; 
   COMBA_STORE(b[19]);

   /* output 20 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[20]); SQRADDAC(a[1], a[19]); SQRADDAC(a[2], a[18]); SQRADDAC(a[3], a[17]); SQRADDAC(a[4], a[16]); SQRADDAC(a[5], a[15]); SQRADDAC(a[6], a[14]); SQRADDAC(a[7], a[13]); SQRADDAC(a[8], a[12]); SQRADDAC(a[9], a[11]); SQRADDDB; SQRADD(a[10], a[10]); 
   COMBA_STORE(b[20]);

   /* output 21 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[21]); SQRADDAC(a[1], a[20]); SQRADDAC(a[2], a[19]); SQRADDAC(a[3], a[18]); SQRADDAC(a[4], a[17]); SQRADDAC(a[5], a[16]); SQRADDAC(a[6], a[15]); SQRADDAC(a[7], a[14]); SQRADDAC(a[8], a[13]); SQRADDAC(a[9], a[12]); SQRADDAC(a[10], a[11]); SQRADDDB; 
   COMBA_STORE(b[21]);

   /* output 22 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[22]); SQRADDAC(a[1], a[21]); SQRADDAC(a[2], a[20]); SQRADDAC(a[3], a[19]); SQRADDAC(a[4], a[18]); SQRADDAC(a[5], a[17]); SQRADDAC(a[6], a[16]); SQRADDAC(a[7], a[15]); SQRADDAC(a[8], a[14]); SQRADDAC(a[9], a[13]); SQRADDAC(a[10], a[12]); SQRADDDB; SQRADD(a[11], a[11]); 
   COMBA_STORE(b[22]);

   /* output 23 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[23]); SQRADDAC(a[1], a[22]); SQRADDAC(a[2], a[21]); SQRADDAC(a[3], a[20]); SQRADDAC(a[4], a[19]); SQRADDAC(a[5], a[18]); SQRADDAC(a[6], a[17]); SQRADDAC(a[7], a[16]); SQRADDAC(a[8], a[15]); SQRADDAC(a[9], a[14]); SQRADDAC(a[10], a[13]); SQRADDAC(a[11], a[12]); SQRADDDB; 
   COMBA_STORE(b[23]);

   /* output 24 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[24]); SQRADDAC(a[1], a[23]); SQRADDAC(a[2], a[22]); SQRADDAC(a[3], a[21]); SQRADDAC(a[4], a[20]); SQRADDAC(a[5], a[19]); SQRADDAC(a[6], a[18]); SQRADDAC(a[7], a[17]); SQRADDAC(a[8], a[16]); SQRADDAC(a[9], a[15]); SQRADDAC(a[10], a[14]); SQRADDAC(a[11], a[13]); SQRADDDB; SQRADD(a[12], a[12]); 
   COMBA_STORE(b[24]);

   /* output 25 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[25]); SQRADDAC(a[1], a[24]); SQRADDAC(a[2], a[23]); SQRADDAC(a[3], a[22]); SQRADDAC(a[4], a[21]); SQRADDAC(a[5], a[20]); SQRADDAC(a[6], a[19]); SQRADDAC(a[7], a[18]); SQRADDAC(a[8], a[17]); SQRADDAC(a[9], a[16]); SQRADDAC(a[10], a[15]); SQRADDAC(a[11], a[14]); SQRADDAC(a[12], a[13]); SQRADDDB; 
   COMBA_STORE(b[25]);

   /* output 26 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[26]); SQRADDAC(a[1], a[25]); SQRADDAC(a[2], a[24]); SQRADDAC(a[3], a[23]); SQRADDAC(a[4], a[22]); SQRADDAC(a[5], a[21]); SQRADDAC(a[6], a[20]); SQRADDAC(a[7], a[19]); SQRADDAC(a[8], a[18]); SQRADDAC(a[9], a[17]); SQRADDAC(a[10], a[16]); SQRADDAC(a[11], a[15]); SQRADDAC(a[12], a[14]); SQRADDDB; SQRADD(a[13], a[13]); 
   COMBA_STORE(b[26]);

   /* output 27 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[27]); SQRADDAC(a[1], a[26]); SQRADDAC(a[2], a[25]); SQRADDAC(a[3], a[24]); SQRADDAC(a[4], a[23]); SQRADDAC(a[5], a[22]); SQRADDAC(a[6], a[21]); SQRADDAC(a[7], a[20]); SQRADDAC(a[8], a[19]); SQRADDAC(a[9], a[18]); SQRADDAC(a[10], a[17]); SQRADDAC(a[11], a[16]); SQRADDAC(a[12], a[15]); SQRADDAC(a[13], a[14]); SQRADDDB; 
   COMBA_STORE(b[27]);

   /* output 28 */
   CARRY_FORWARD;
   SQRADDSC(a[1], a[27]); SQRADDAC(a[2], a[26]); SQRADDAC(a[3], a[25]); SQRADDAC(a[4], a[24]); SQRADDAC(a[5], a[23]); SQRADDAC(a[6], a[22]); SQRADDAC(a[7], a[21]); SQRADDAC(a[8], a[20]); SQRADDAC(a[9], a[19]); SQRADDAC(a[10], a[18]); SQRADDAC(a[11], a[17]); SQRADDAC(a[12], a[16]); SQRADDAC(a[13], a[15]); SQRADDDB; SQRADD(a[14], a[14]); 
   COMBA_STORE(b[28]);

   /* output 29 */
   CARRY_FORWARD;
   SQRADDSC(a[2], a[27]); SQRADDAC(a[3], a[26]); SQRADDAC(a[4], a[25]); SQRADDAC(a[5], a[24]); SQRADDAC(a[6], a[23]); SQRADDAC(a[7], a[22]); SQRADDAC(a[8], a[21]); SQRADDAC(a[9], a[20]); SQRADDAC(a[10], a[19]); SQRADDAC(a[11], a[18]); SQRADDAC(a[12], a[17]); SQRADDAC(a[13], a[16]); SQRADDAC(a[14], a[15]); SQRADDDB; 
   COMBA_STORE(b[29]);

   /* output 30 */
   CARRY_FORWARD;
   SQRADDSC(a[3], a[27]); SQRADDAC(a[4], a[26]); SQRADDAC(a[5], a[25]); SQRADDAC(a[6], a[24]); SQRADDAC(a[7], a[23]); SQRADDAC(a[8], a[22]); SQRADDAC(a[9], a[21]); SQRADDAC(a[10], a[20]); SQRADDAC(a[11], a[19]); SQRADDAC(a[12], a[18]); SQRADDAC(a[13], a[17]); SQRADDAC(a[14], a[16]); SQRADDDB; SQRADD(a[15], a[15]); 
   COMBA_STORE(b[30]);

   /* output 31 */
   CARRY_FORWARD;
   SQRADDSC(a[4], a[27]); SQRADDAC(a[5], a[26]); SQRADDAC(a[6], a[25]); SQRADDAC(a[7], a[24]); SQRADDAC(a[8], a[23]); SQRADDAC(a[9], a[22]); SQRADDAC(a[10], a[21]); SQRADDAC(a[11], a[20]); SQRADDAC(a[12], a[19]); SQRADDAC(a[13], a[18]); SQRADDAC(a[14], a[17]); SQRADDAC(a[15], a[16]); SQRADDDB; 
   COMBA_STORE(b[31]);

   /* output 32 */
   CARRY_FORWARD;
   SQRADDSC(a[5], a[27]); SQRADDAC(a[6], a[26]); SQRADDAC(a[7], a[25]); SQRADDAC(a[8], a[24]); SQRADDAC(a[9], a[23]); SQRADDAC(a[10], a[22]); SQRADDAC(a[11], a[21]); SQRADDAC(a[12], a[20]); SQRADDAC(a[13], a[19]); SQRADDAC(a[14], a[18]); SQRADDAC(a[15], a[17]); SQRADDDB; SQRADD(a[16], a[16]); 
   COMBA_STORE(b[32]);

   /* output 33 */
   CARRY_FORWARD;
   SQRADDSC(a[6], a[27]); SQRADDAC(a[7], a[26]); SQRADDAC(a[8], a[25]); SQRADDAC(a[9], a[24]); SQRADDAC(a[10], a[23]); SQRADDAC(a[11], a[22]); SQRADDAC(a[12], a[21]); SQRADDAC(a[13], a[20]); SQRADDAC(a[14], a[19]); SQRADDAC(a[15], a[18]); SQRADDAC(a[16], a[17]); SQRADDDB; 
   COMBA_STORE(b[33]);

   /* output 34 */
   CARRY_FORWARD;
   SQRADDSC(a[7], a[27]); SQRADDAC(a[8], a[26]); SQRADDAC(a[9], a[25]); SQRADDAC(a[10], a[24]); SQRADDAC(a[11], a[23]); SQRADDAC(a[12], a[22]); SQRADDAC(a[13], a[21]); SQRADDAC(a[14], a[20]); SQRADDAC(a[15], a[19]); SQRADDAC(a[16], a[18]); SQRADDDB; SQRADD(a[17], a[17]); 
   COMBA_STORE(b[34]);

   /* output 35 */
   CARRY_FORWARD;
   SQRADDSC(a[8], a[27]); SQRADDAC(a[9], a[26]); SQRADDAC(a[10], a[25]); SQRADDAC(a[11], a[24]); SQRADDAC(a[12], a[23]); SQRADDAC(a[13], a[22]); SQRADDAC(a[14], a[21]); SQRADDAC(a[15], a[20]); SQRADDAC(a[16], a[19]); SQRADDAC(a[17], a[18]); SQRADDDB; 
   COMBA_STORE(b[35]);

   /* output 36 */
   CARRY_FORWARD;
   SQRADDSC(a[9], a[27]); SQRADDAC(a[10], a[26]); SQRADDAC(a[11], a[25]); SQRADDAC(a[12], a[24]); SQRADDAC(a[13], a[23]); SQRADDAC(a[14], a[22]); SQRADDAC(a[15], a[21]); SQRADDAC(a[16], a[20]); SQRADDAC(a[17], a[19]); SQRADDDB; SQRADD(a[18], a[18]); 
   COMBA_STORE(b[36]);

   /* output 37 */
   CARRY_FORWARD;
   SQRADDSC(a[10], a[27]); SQRADDAC(a[11], a[26]); SQRADDAC(a[12], a[25]); SQRADDAC(a[13], a[24]); SQRADDAC(a[14], a[23]); SQRADDAC(a[15], a[22]); SQRADDAC(a[16], a[21]); SQRADDAC(a[17], a[20]); SQRADDAC(a[18], a[19]); SQRADDDB; 
   COMBA_STORE(b[37]);

   /* output 38 */
   CARRY_FORWARD;
   SQRADDSC(a[11], a[27]); SQRADDAC(a[12], a[26]); SQRADDAC(a[13], a[25]); SQRADDAC(a[14], a[24]); SQRADDAC(a[15], a[23]); SQRADDAC(a[16], a[22]); SQRADDAC(a[17], a[21]); SQRADDAC(a[18], a[20]); SQRADDDB; SQRADD(a[19], a[19]); 
   COMBA_STORE(b[38]);

   /* output 39 */
   CARRY_FORWARD;
   SQRADDSC(a[12], a[27]); SQRADDAC(a[13], a[26]); SQRADDAC(a[14], a[25]); SQRADDAC(a[15], a[24]); SQRADDAC(a[16], a[23]); SQRADDAC(a[17], a[22]); SQRADDAC(a[18], a[21]); SQRADDAC(a[19], a[20]); SQRADDDB; 
   COMBA_STORE(b[39]);

   /* output 40 */
   CARRY_FORWARD;
   SQRADDSC(a[13], a[27]); SQRADDAC(a[14], a[26]); SQRADDAC(a[15], a[25]); SQRADDAC(a[16], a[24]); SQRADDAC(a[17], a[23]); SQRADDAC(a[18], a[22]); SQRADDAC(a[19], a[21]); SQRADDDB; SQRADD(a[20], a[20]); 
   COMBA_STORE(b[40]);

   /* output 41 */
   CARRY_FORWARD;
   SQRADDSC(a[14], a[27]); SQRADDAC(a[15], a[26]); SQRADDAC(a[16], a[25]); SQRADDAC(a[17], a[24]); SQRADDAC(a[18], a[23]); SQRADDAC(a[19], a[22]); SQRADDAC(a[20], a[21]); SQRADDDB; 
   COMBA_STORE(b[41]);

   /* output 42 */
   CARRY_FORWARD;
   SQRADDSC(a[15], a[27]); SQRADDAC(a[16], a[26]); SQRADDAC(a[17], a[25]); SQRADDAC(a[18], a[24]); SQRADDAC(a[19], a[23]); SQRADDAC(a[20], a[22]); SQRADDDB; SQRADD(a[21], a[21]); 
   COMBA_STORE(b[42]);

   /* output 43 */
   CARRY_FORWARD;
   SQRADDSC(a[16], a[27]); SQRADDAC(a[17], a[26]); SQRADDAC(a[18], a[25]); SQRADDAC(a[19], a[24]); SQRADDAC(a[20], a[23]); SQRADDAC(a[21], a[22]); SQRADDDB; 
   COMBA_STORE(b[43]);

   /* output 44 */
   CARRY_FORWARD;
   SQRADDSC(a[17], a[27]); SQRADDAC(a[18], a[26]); SQRADDAC(a[19], a[25]); SQRADDAC(a[20], a[24]); SQRADDAC(a[21], a[23]); SQRADDDB; SQRADD(a[22], a[22]); 
   COMBA_STORE(b[44]);

   /* output 45 */
   CARRY_FORWARD;
   SQRADDSC(a[18], a[27]); SQRADDAC(a[19], a[26]); SQRADDAC(a[20], a[25]); SQRADDAC(a[21], a[24]); SQRADDAC(a[22], a[23]); SQRADDDB; 
   COMBA_STORE(b[45]);

   /* output 46 */
   CARRY_FORWARD;
   SQRADDSC(a[19], a[27]); SQRADDAC(a[20], a[26]); SQRADDAC(a[21], a[25]); SQRADDAC(a[22], a[24]); SQRADDDB; SQRADD(a[23], a[23]); 
   COMBA_STORE(b[46]);

   /* output 47 */
   CARRY_FORWARD;
   SQRADDSC(a[20], a[27]); SQRADDAC(a[21], a[26]); SQRADDAC(a[22], a[25]); SQRADDAC(a[23], a[24]); SQRADDDB; 
   COMBA_STORE(b[47]);

   /* output 48 */
   CARRY_FORWARD;
   SQRADDSC(a[21], a[27]); SQRADDAC(a[22], a[26]); SQRADDAC(a[23], a[25]); SQRADDDB; SQRADD(a[24], a[24]); 
   COMBA_STORE(b[48]);

   /* output 49 */
   CARRY_FORWARD;
   SQRADDSC(a[22], a[27]); SQRADDAC(a[23], a[26]); SQRADDAC(a[24], a[25]); SQRADDDB; 
   COMBA_STORE(b[49]);

   /* output 50 */
   CARRY_FORWARD;
   SQRADD2(a[23], a[27]); SQRADD2(a[24], a[26]); SQRADD(a[25], a[25]); 
   COMBA_STORE(b[50]);

   /* output 51 */
   CARRY_FORWARD;
   SQRADD2(a[24], a[27]); SQRADD2(a[25], a[26]); 
   COMBA_STORE(b[51]);

   /* output 52 */
   CARRY_FORWARD;
   SQRADD2(a[25], a[27]); SQRADD(a[26], a[26]); 
   COMBA_STORE(b[52]);

   /* output 53 */
   CARRY_FORWARD;
   SQRADD2(a[26], a[27]); 
   COMBA_STORE(b[53]);

   /* output 54 */
   CARRY_FORWARD;
   SQRADD(a[27], a[27]); 
   COMBA_STORE(b[54]);
   COMBA_STORE2(b[55]);
   COMBA_FINI;

   B->used = 56;
   B->sign = FP_ZPOS;
   memcpy(B->dp, b, 56 * sizeof(fp_digit));
   fp_clamp(B);
}
#endif


/* $Source: /cvs/libtom/tomsfastmath/src/sqr/fp_sqr_comba_28.c,v $ */
/* $Revision: 1.2 $ */
/* $Date: 2007/02/17 03:39:01 $ */

/* End: fp_sqr_comba_28.c */

/* Start: fp_sqr_comba_3.c */
#define TFM_DEFINES
#include "fp_sqr_comba.c"

#ifdef TFM_SQR3
void fp_sqr_comba3(fp_int *A, fp_int *B)
{
   fp_digit *a, b[6], c0, c1, c2, sc0, sc1, sc2;
#ifdef TFM_ISO
   fp_word tt;
#endif

   a = A->dp;
   COMBA_START; 

   /* clear carries */
   CLEAR_CARRY;

   /* output 0 */
   SQRADD(a[0],a[0]);
   COMBA_STORE(b[0]);

   /* output 1 */
   CARRY_FORWARD;
   SQRADD2(a[0], a[1]); 
   COMBA_STORE(b[1]);

   /* output 2 */
   CARRY_FORWARD;
   SQRADD2(a[0], a[2]); SQRADD(a[1], a[1]); 
   COMBA_STORE(b[2]);

   /* output 3 */
   CARRY_FORWARD;
   SQRADD2(a[1], a[2]); 
   COMBA_STORE(b[3]);

   /* output 4 */
   CARRY_FORWARD;
   SQRADD(a[2], a[2]); 
   COMBA_STORE(b[4]);
   COMBA_STORE2(b[5]);
   COMBA_FINI;

   B->used = 6;
   B->sign = FP_ZPOS;
   memcpy(B->dp, b, 6 * sizeof(fp_digit));
   fp_clamp(B);
}
#endif


/* $Source: /cvs/libtom/tomsfastmath/src/sqr/fp_sqr_comba_3.c,v $ */
/* $Revision: 1.2 $ */
/* $Date: 2007/02/17 03:39:01 $ */

/* End: fp_sqr_comba_3.c */

/* Start: fp_sqr_comba_32.c */
#define TFM_DEFINES
#include "fp_sqr_comba.c"

#ifdef TFM_SQR32
void fp_sqr_comba32(fp_int *A, fp_int *B)
{
   fp_digit *a, b[64], c0, c1, c2, sc0, sc1, sc2;
#ifdef TFM_ISO
   fp_word tt;
#endif

   a = A->dp;
   COMBA_START; 

   /* clear carries */
   CLEAR_CARRY;

   /* output 0 */
   SQRADD(a[0],a[0]);
   COMBA_STORE(b[0]);

   /* output 1 */
   CARRY_FORWARD;
   SQRADD2(a[0], a[1]); 
   COMBA_STORE(b[1]);

   /* output 2 */
   CARRY_FORWARD;
   SQRADD2(a[0], a[2]); SQRADD(a[1], a[1]); 
   COMBA_STORE(b[2]);

   /* output 3 */
   CARRY_FORWARD;
   SQRADD2(a[0], a[3]); SQRADD2(a[1], a[2]); 
   COMBA_STORE(b[3]);

   /* output 4 */
   CARRY_FORWARD;
   SQRADD2(a[0], a[4]); SQRADD2(a[1], a[3]); SQRADD(a[2], a[2]); 
   COMBA_STORE(b[4]);

   /* output 5 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[5]); SQRADDAC(a[1], a[4]); SQRADDAC(a[2], a[3]); SQRADDDB; 
   COMBA_STORE(b[5]);

   /* output 6 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[6]); SQRADDAC(a[1], a[5]); SQRADDAC(a[2], a[4]); SQRADDDB; SQRADD(a[3], a[3]); 
   COMBA_STORE(b[6]);

   /* output 7 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[7]); SQRADDAC(a[1], a[6]); SQRADDAC(a[2], a[5]); SQRADDAC(a[3], a[4]); SQRADDDB; 
   COMBA_STORE(b[7]);

   /* output 8 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[8]); SQRADDAC(a[1], a[7]); SQRADDAC(a[2], a[6]); SQRADDAC(a[3], a[5]); SQRADDDB; SQRADD(a[4], a[4]); 
   COMBA_STORE(b[8]);

   /* output 9 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[9]); SQRADDAC(a[1], a[8]); SQRADDAC(a[2], a[7]); SQRADDAC(a[3], a[6]); SQRADDAC(a[4], a[5]); SQRADDDB; 
   COMBA_STORE(b[9]);

   /* output 10 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[10]); SQRADDAC(a[1], a[9]); SQRADDAC(a[2], a[8]); SQRADDAC(a[3], a[7]); SQRADDAC(a[4], a[6]); SQRADDDB; SQRADD(a[5], a[5]); 
   COMBA_STORE(b[10]);

   /* output 11 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[11]); SQRADDAC(a[1], a[10]); SQRADDAC(a[2], a[9]); SQRADDAC(a[3], a[8]); SQRADDAC(a[4], a[7]); SQRADDAC(a[5], a[6]); SQRADDDB; 
   COMBA_STORE(b[11]);

   /* output 12 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[12]); SQRADDAC(a[1], a[11]); SQRADDAC(a[2], a[10]); SQRADDAC(a[3], a[9]); SQRADDAC(a[4], a[8]); SQRADDAC(a[5], a[7]); SQRADDDB; SQRADD(a[6], a[6]); 
   COMBA_STORE(b[12]);

   /* output 13 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[13]); SQRADDAC(a[1], a[12]); SQRADDAC(a[2], a[11]); SQRADDAC(a[3], a[10]); SQRADDAC(a[4], a[9]); SQRADDAC(a[5], a[8]); SQRADDAC(a[6], a[7]); SQRADDDB; 
   COMBA_STORE(b[13]);

   /* output 14 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[14]); SQRADDAC(a[1], a[13]); SQRADDAC(a[2], a[12]); SQRADDAC(a[3], a[11]); SQRADDAC(a[4], a[10]); SQRADDAC(a[5], a[9]); SQRADDAC(a[6], a[8]); SQRADDDB; SQRADD(a[7], a[7]); 
   COMBA_STORE(b[14]);

   /* output 15 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[15]); SQRADDAC(a[1], a[14]); SQRADDAC(a[2], a[13]); SQRADDAC(a[3], a[12]); SQRADDAC(a[4], a[11]); SQRADDAC(a[5], a[10]); SQRADDAC(a[6], a[9]); SQRADDAC(a[7], a[8]); SQRADDDB; 
   COMBA_STORE(b[15]);

   /* output 16 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[16]); SQRADDAC(a[1], a[15]); SQRADDAC(a[2], a[14]); SQRADDAC(a[3], a[13]); SQRADDAC(a[4], a[12]); SQRADDAC(a[5], a[11]); SQRADDAC(a[6], a[10]); SQRADDAC(a[7], a[9]); SQRADDDB; SQRADD(a[8], a[8]); 
   COMBA_STORE(b[16]);

   /* output 17 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[17]); SQRADDAC(a[1], a[16]); SQRADDAC(a[2], a[15]); SQRADDAC(a[3], a[14]); SQRADDAC(a[4], a[13]); SQRADDAC(a[5], a[12]); SQRADDAC(a[6], a[11]); SQRADDAC(a[7], a[10]); SQRADDAC(a[8], a[9]); SQRADDDB; 
   COMBA_STORE(b[17]);

   /* output 18 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[18]); SQRADDAC(a[1], a[17]); SQRADDAC(a[2], a[16]); SQRADDAC(a[3], a[15]); SQRADDAC(a[4], a[14]); SQRADDAC(a[5], a[13]); SQRADDAC(a[6], a[12]); SQRADDAC(a[7], a[11]); SQRADDAC(a[8], a[10]); SQRADDDB; SQRADD(a[9], a[9]); 
   COMBA_STORE(b[18]);

   /* output 19 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[19]); SQRADDAC(a[1], a[18]); SQRADDAC(a[2], a[17]); SQRADDAC(a[3], a[16]); SQRADDAC(a[4], a[15]); SQRADDAC(a[5], a[14]); SQRADDAC(a[6], a[13]); SQRADDAC(a[7], a[12]); SQRADDAC(a[8], a[11]); SQRADDAC(a[9], a[10]); SQRADDDB; 
   COMBA_STORE(b[19]);

   /* output 20 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[20]); SQRADDAC(a[1], a[19]); SQRADDAC(a[2], a[18]); SQRADDAC(a[3], a[17]); SQRADDAC(a[4], a[16]); SQRADDAC(a[5], a[15]); SQRADDAC(a[6], a[14]); SQRADDAC(a[7], a[13]); SQRADDAC(a[8], a[12]); SQRADDAC(a[9], a[11]); SQRADDDB; SQRADD(a[10], a[10]); 
   COMBA_STORE(b[20]);

   /* output 21 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[21]); SQRADDAC(a[1], a[20]); SQRADDAC(a[2], a[19]); SQRADDAC(a[3], a[18]); SQRADDAC(a[4], a[17]); SQRADDAC(a[5], a[16]); SQRADDAC(a[6], a[15]); SQRADDAC(a[7], a[14]); SQRADDAC(a[8], a[13]); SQRADDAC(a[9], a[12]); SQRADDAC(a[10], a[11]); SQRADDDB; 
   COMBA_STORE(b[21]);

   /* output 22 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[22]); SQRADDAC(a[1], a[21]); SQRADDAC(a[2], a[20]); SQRADDAC(a[3], a[19]); SQRADDAC(a[4], a[18]); SQRADDAC(a[5], a[17]); SQRADDAC(a[6], a[16]); SQRADDAC(a[7], a[15]); SQRADDAC(a[8], a[14]); SQRADDAC(a[9], a[13]); SQRADDAC(a[10], a[12]); SQRADDDB; SQRADD(a[11], a[11]); 
   COMBA_STORE(b[22]);

   /* output 23 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[23]); SQRADDAC(a[1], a[22]); SQRADDAC(a[2], a[21]); SQRADDAC(a[3], a[20]); SQRADDAC(a[4], a[19]); SQRADDAC(a[5], a[18]); SQRADDAC(a[6], a[17]); SQRADDAC(a[7], a[16]); SQRADDAC(a[8], a[15]); SQRADDAC(a[9], a[14]); SQRADDAC(a[10], a[13]); SQRADDAC(a[11], a[12]); SQRADDDB; 
   COMBA_STORE(b[23]);

   /* output 24 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[24]); SQRADDAC(a[1], a[23]); SQRADDAC(a[2], a[22]); SQRADDAC(a[3], a[21]); SQRADDAC(a[4], a[20]); SQRADDAC(a[5], a[19]); SQRADDAC(a[6], a[18]); SQRADDAC(a[7], a[17]); SQRADDAC(a[8], a[16]); SQRADDAC(a[9], a[15]); SQRADDAC(a[10], a[14]); SQRADDAC(a[11], a[13]); SQRADDDB; SQRADD(a[12], a[12]); 
   COMBA_STORE(b[24]);

   /* output 25 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[25]); SQRADDAC(a[1], a[24]); SQRADDAC(a[2], a[23]); SQRADDAC(a[3], a[22]); SQRADDAC(a[4], a[21]); SQRADDAC(a[5], a[20]); SQRADDAC(a[6], a[19]); SQRADDAC(a[7], a[18]); SQRADDAC(a[8], a[17]); SQRADDAC(a[9], a[16]); SQRADDAC(a[10], a[15]); SQRADDAC(a[11], a[14]); SQRADDAC(a[12], a[13]); SQRADDDB; 
   COMBA_STORE(b[25]);

   /* output 26 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[26]); SQRADDAC(a[1], a[25]); SQRADDAC(a[2], a[24]); SQRADDAC(a[3], a[23]); SQRADDAC(a[4], a[22]); SQRADDAC(a[5], a[21]); SQRADDAC(a[6], a[20]); SQRADDAC(a[7], a[19]); SQRADDAC(a[8], a[18]); SQRADDAC(a[9], a[17]); SQRADDAC(a[10], a[16]); SQRADDAC(a[11], a[15]); SQRADDAC(a[12], a[14]); SQRADDDB; SQRADD(a[13], a[13]); 
   COMBA_STORE(b[26]);

   /* output 27 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[27]); SQRADDAC(a[1], a[26]); SQRADDAC(a[2], a[25]); SQRADDAC(a[3], a[24]); SQRADDAC(a[4], a[23]); SQRADDAC(a[5], a[22]); SQRADDAC(a[6], a[21]); SQRADDAC(a[7], a[20]); SQRADDAC(a[8], a[19]); SQRADDAC(a[9], a[18]); SQRADDAC(a[10], a[17]); SQRADDAC(a[11], a[16]); SQRADDAC(a[12], a[15]); SQRADDAC(a[13], a[14]); SQRADDDB; 
   COMBA_STORE(b[27]);

   /* output 28 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[28]); SQRADDAC(a[1], a[27]); SQRADDAC(a[2], a[26]); SQRADDAC(a[3], a[25]); SQRADDAC(a[4], a[24]); SQRADDAC(a[5], a[23]); SQRADDAC(a[6], a[22]); SQRADDAC(a[7], a[21]); SQRADDAC(a[8], a[20]); SQRADDAC(a[9], a[19]); SQRADDAC(a[10], a[18]); SQRADDAC(a[11], a[17]); SQRADDAC(a[12], a[16]); SQRADDAC(a[13], a[15]); SQRADDDB; SQRADD(a[14], a[14]); 
   COMBA_STORE(b[28]);

   /* output 29 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[29]); SQRADDAC(a[1], a[28]); SQRADDAC(a[2], a[27]); SQRADDAC(a[3], a[26]); SQRADDAC(a[4], a[25]); SQRADDAC(a[5], a[24]); SQRADDAC(a[6], a[23]); SQRADDAC(a[7], a[22]); SQRADDAC(a[8], a[21]); SQRADDAC(a[9], a[20]); SQRADDAC(a[10], a[19]); SQRADDAC(a[11], a[18]); SQRADDAC(a[12], a[17]); SQRADDAC(a[13], a[16]); SQRADDAC(a[14], a[15]); SQRADDDB; 
   COMBA_STORE(b[29]);

   /* output 30 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[30]); SQRADDAC(a[1], a[29]); SQRADDAC(a[2], a[28]); SQRADDAC(a[3], a[27]); SQRADDAC(a[4], a[26]); SQRADDAC(a[5], a[25]); SQRADDAC(a[6], a[24]); SQRADDAC(a[7], a[23]); SQRADDAC(a[8], a[22]); SQRADDAC(a[9], a[21]); SQRADDAC(a[10], a[20]); SQRADDAC(a[11], a[19]); SQRADDAC(a[12], a[18]); SQRADDAC(a[13], a[17]); SQRADDAC(a[14], a[16]); SQRADDDB; SQRADD(a[15], a[15]); 
   COMBA_STORE(b[30]);

   /* output 31 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[31]); SQRADDAC(a[1], a[30]); SQRADDAC(a[2], a[29]); SQRADDAC(a[3], a[28]); SQRADDAC(a[4], a[27]); SQRADDAC(a[5], a[26]); SQRADDAC(a[6], a[25]); SQRADDAC(a[7], a[24]); SQRADDAC(a[8], a[23]); SQRADDAC(a[9], a[22]); SQRADDAC(a[10], a[21]); SQRADDAC(a[11], a[20]); SQRADDAC(a[12], a[19]); SQRADDAC(a[13], a[18]); SQRADDAC(a[14], a[17]); SQRADDAC(a[15], a[16]); SQRADDDB; 
   COMBA_STORE(b[31]);

   /* output 32 */
   CARRY_FORWARD;
   SQRADDSC(a[1], a[31]); SQRADDAC(a[2], a[30]); SQRADDAC(a[3], a[29]); SQRADDAC(a[4], a[28]); SQRADDAC(a[5], a[27]); SQRADDAC(a[6], a[26]); SQRADDAC(a[7], a[25]); SQRADDAC(a[8], a[24]); SQRADDAC(a[9], a[23]); SQRADDAC(a[10], a[22]); SQRADDAC(a[11], a[21]); SQRADDAC(a[12], a[20]); SQRADDAC(a[13], a[19]); SQRADDAC(a[14], a[18]); SQRADDAC(a[15], a[17]); SQRADDDB; SQRADD(a[16], a[16]); 
   COMBA_STORE(b[32]);

   /* output 33 */
   CARRY_FORWARD;
   SQRADDSC(a[2], a[31]); SQRADDAC(a[3], a[30]); SQRADDAC(a[4], a[29]); SQRADDAC(a[5], a[28]); SQRADDAC(a[6], a[27]); SQRADDAC(a[7], a[26]); SQRADDAC(a[8], a[25]); SQRADDAC(a[9], a[24]); SQRADDAC(a[10], a[23]); SQRADDAC(a[11], a[22]); SQRADDAC(a[12], a[21]); SQRADDAC(a[13], a[20]); SQRADDAC(a[14], a[19]); SQRADDAC(a[15], a[18]); SQRADDAC(a[16], a[17]); SQRADDDB; 
   COMBA_STORE(b[33]);

   /* output 34 */
   CARRY_FORWARD;
   SQRADDSC(a[3], a[31]); SQRADDAC(a[4], a[30]); SQRADDAC(a[5], a[29]); SQRADDAC(a[6], a[28]); SQRADDAC(a[7], a[27]); SQRADDAC(a[8], a[26]); SQRADDAC(a[9], a[25]); SQRADDAC(a[10], a[24]); SQRADDAC(a[11], a[23]); SQRADDAC(a[12], a[22]); SQRADDAC(a[13], a[21]); SQRADDAC(a[14], a[20]); SQRADDAC(a[15], a[19]); SQRADDAC(a[16], a[18]); SQRADDDB; SQRADD(a[17], a[17]); 
   COMBA_STORE(b[34]);

   /* output 35 */
   CARRY_FORWARD;
   SQRADDSC(a[4], a[31]); SQRADDAC(a[5], a[30]); SQRADDAC(a[6], a[29]); SQRADDAC(a[7], a[28]); SQRADDAC(a[8], a[27]); SQRADDAC(a[9], a[26]); SQRADDAC(a[10], a[25]); SQRADDAC(a[11], a[24]); SQRADDAC(a[12], a[23]); SQRADDAC(a[13], a[22]); SQRADDAC(a[14], a[21]); SQRADDAC(a[15], a[20]); SQRADDAC(a[16], a[19]); SQRADDAC(a[17], a[18]); SQRADDDB; 
   COMBA_STORE(b[35]);

   /* output 36 */
   CARRY_FORWARD;
   SQRADDSC(a[5], a[31]); SQRADDAC(a[6], a[30]); SQRADDAC(a[7], a[29]); SQRADDAC(a[8], a[28]); SQRADDAC(a[9], a[27]); SQRADDAC(a[10], a[26]); SQRADDAC(a[11], a[25]); SQRADDAC(a[12], a[24]); SQRADDAC(a[13], a[23]); SQRADDAC(a[14], a[22]); SQRADDAC(a[15], a[21]); SQRADDAC(a[16], a[20]); SQRADDAC(a[17], a[19]); SQRADDDB; SQRADD(a[18], a[18]); 
   COMBA_STORE(b[36]);

   /* output 37 */
   CARRY_FORWARD;
   SQRADDSC(a[6], a[31]); SQRADDAC(a[7], a[30]); SQRADDAC(a[8], a[29]); SQRADDAC(a[9], a[28]); SQRADDAC(a[10], a[27]); SQRADDAC(a[11], a[26]); SQRADDAC(a[12], a[25]); SQRADDAC(a[13], a[24]); SQRADDAC(a[14], a[23]); SQRADDAC(a[15], a[22]); SQRADDAC(a[16], a[21]); SQRADDAC(a[17], a[20]); SQRADDAC(a[18], a[19]); SQRADDDB; 
   COMBA_STORE(b[37]);

   /* output 38 */
   CARRY_FORWARD;
   SQRADDSC(a[7], a[31]); SQRADDAC(a[8], a[30]); SQRADDAC(a[9], a[29]); SQRADDAC(a[10], a[28]); SQRADDAC(a[11], a[27]); SQRADDAC(a[12], a[26]); SQRADDAC(a[13], a[25]); SQRADDAC(a[14], a[24]); SQRADDAC(a[15], a[23]); SQRADDAC(a[16], a[22]); SQRADDAC(a[17], a[21]); SQRADDAC(a[18], a[20]); SQRADDDB; SQRADD(a[19], a[19]); 
   COMBA_STORE(b[38]);

   /* output 39 */
   CARRY_FORWARD;
   SQRADDSC(a[8], a[31]); SQRADDAC(a[9], a[30]); SQRADDAC(a[10], a[29]); SQRADDAC(a[11], a[28]); SQRADDAC(a[12], a[27]); SQRADDAC(a[13], a[26]); SQRADDAC(a[14], a[25]); SQRADDAC(a[15], a[24]); SQRADDAC(a[16], a[23]); SQRADDAC(a[17], a[22]); SQRADDAC(a[18], a[21]); SQRADDAC(a[19], a[20]); SQRADDDB; 
   COMBA_STORE(b[39]);

   /* output 40 */
   CARRY_FORWARD;
   SQRADDSC(a[9], a[31]); SQRADDAC(a[10], a[30]); SQRADDAC(a[11], a[29]); SQRADDAC(a[12], a[28]); SQRADDAC(a[13], a[27]); SQRADDAC(a[14], a[26]); SQRADDAC(a[15], a[25]); SQRADDAC(a[16], a[24]); SQRADDAC(a[17], a[23]); SQRADDAC(a[18], a[22]); SQRADDAC(a[19], a[21]); SQRADDDB; SQRADD(a[20], a[20]); 
   COMBA_STORE(b[40]);

   /* output 41 */
   CARRY_FORWARD;
   SQRADDSC(a[10], a[31]); SQRADDAC(a[11], a[30]); SQRADDAC(a[12], a[29]); SQRADDAC(a[13], a[28]); SQRADDAC(a[14], a[27]); SQRADDAC(a[15], a[26]); SQRADDAC(a[16], a[25]); SQRADDAC(a[17], a[24]); SQRADDAC(a[18], a[23]); SQRADDAC(a[19], a[22]); SQRADDAC(a[20], a[21]); SQRADDDB; 
   COMBA_STORE(b[41]);

   /* output 42 */
   CARRY_FORWARD;
   SQRADDSC(a[11], a[31]); SQRADDAC(a[12], a[30]); SQRADDAC(a[13], a[29]); SQRADDAC(a[14], a[28]); SQRADDAC(a[15], a[27]); SQRADDAC(a[16], a[26]); SQRADDAC(a[17], a[25]); SQRADDAC(a[18], a[24]); SQRADDAC(a[19], a[23]); SQRADDAC(a[20], a[22]); SQRADDDB; SQRADD(a[21], a[21]); 
   COMBA_STORE(b[42]);

   /* output 43 */
   CARRY_FORWARD;
   SQRADDSC(a[12], a[31]); SQRADDAC(a[13], a[30]); SQRADDAC(a[14], a[29]); SQRADDAC(a[15], a[28]); SQRADDAC(a[16], a[27]); SQRADDAC(a[17], a[26]); SQRADDAC(a[18], a[25]); SQRADDAC(a[19], a[24]); SQRADDAC(a[20], a[23]); SQRADDAC(a[21], a[22]); SQRADDDB; 
   COMBA_STORE(b[43]);

   /* output 44 */
   CARRY_FORWARD;
   SQRADDSC(a[13], a[31]); SQRADDAC(a[14], a[30]); SQRADDAC(a[15], a[29]); SQRADDAC(a[16], a[28]); SQRADDAC(a[17], a[27]); SQRADDAC(a[18], a[26]); SQRADDAC(a[19], a[25]); SQRADDAC(a[20], a[24]); SQRADDAC(a[21], a[23]); SQRADDDB; SQRADD(a[22], a[22]); 
   COMBA_STORE(b[44]);

   /* output 45 */
   CARRY_FORWARD;
   SQRADDSC(a[14], a[31]); SQRADDAC(a[15], a[30]); SQRADDAC(a[16], a[29]); SQRADDAC(a[17], a[28]); SQRADDAC(a[18], a[27]); SQRADDAC(a[19], a[26]); SQRADDAC(a[20], a[25]); SQRADDAC(a[21], a[24]); SQRADDAC(a[22], a[23]); SQRADDDB; 
   COMBA_STORE(b[45]);

   /* output 46 */
   CARRY_FORWARD;
   SQRADDSC(a[15], a[31]); SQRADDAC(a[16], a[30]); SQRADDAC(a[17], a[29]); SQRADDAC(a[18], a[28]); SQRADDAC(a[19], a[27]); SQRADDAC(a[20], a[26]); SQRADDAC(a[21], a[25]); SQRADDAC(a[22], a[24]); SQRADDDB; SQRADD(a[23], a[23]); 
   COMBA_STORE(b[46]);

   /* output 47 */
   CARRY_FORWARD;
   SQRADDSC(a[16], a[31]); SQRADDAC(a[17], a[30]); SQRADDAC(a[18], a[29]); SQRADDAC(a[19], a[28]); SQRADDAC(a[20], a[27]); SQRADDAC(a[21], a[26]); SQRADDAC(a[22], a[25]); SQRADDAC(a[23], a[24]); SQRADDDB; 
   COMBA_STORE(b[47]);

   /* output 48 */
   CARRY_FORWARD;
   SQRADDSC(a[17], a[31]); SQRADDAC(a[18], a[30]); SQRADDAC(a[19], a[29]); SQRADDAC(a[20], a[28]); SQRADDAC(a[21], a[27]); SQRADDAC(a[22], a[26]); SQRADDAC(a[23], a[25]); SQRADDDB; SQRADD(a[24], a[24]); 
   COMBA_STORE(b[48]);

   /* output 49 */
   CARRY_FORWARD;
   SQRADDSC(a[18], a[31]); SQRADDAC(a[19], a[30]); SQRADDAC(a[20], a[29]); SQRADDAC(a[21], a[28]); SQRADDAC(a[22], a[27]); SQRADDAC(a[23], a[26]); SQRADDAC(a[24], a[25]); SQRADDDB; 
   COMBA_STORE(b[49]);

   /* output 50 */
   CARRY_FORWARD;
   SQRADDSC(a[19], a[31]); SQRADDAC(a[20], a[30]); SQRADDAC(a[21], a[29]); SQRADDAC(a[22], a[28]); SQRADDAC(a[23], a[27]); SQRADDAC(a[24], a[26]); SQRADDDB; SQRADD(a[25], a[25]); 
   COMBA_STORE(b[50]);

   /* output 51 */
   CARRY_FORWARD;
   SQRADDSC(a[20], a[31]); SQRADDAC(a[21], a[30]); SQRADDAC(a[22], a[29]); SQRADDAC(a[23], a[28]); SQRADDAC(a[24], a[27]); SQRADDAC(a[25], a[26]); SQRADDDB; 
   COMBA_STORE(b[51]);

   /* output 52 */
   CARRY_FORWARD;
   SQRADDSC(a[21], a[31]); SQRADDAC(a[22], a[30]); SQRADDAC(a[23], a[29]); SQRADDAC(a[24], a[28]); SQRADDAC(a[25], a[27]); SQRADDDB; SQRADD(a[26], a[26]); 
   COMBA_STORE(b[52]);

   /* output 53 */
   CARRY_FORWARD;
   SQRADDSC(a[22], a[31]); SQRADDAC(a[23], a[30]); SQRADDAC(a[24], a[29]); SQRADDAC(a[25], a[28]); SQRADDAC(a[26], a[27]); SQRADDDB; 
   COMBA_STORE(b[53]);

   /* output 54 */
   CARRY_FORWARD;
   SQRADDSC(a[23], a[31]); SQRADDAC(a[24], a[30]); SQRADDAC(a[25], a[29]); SQRADDAC(a[26], a[28]); SQRADDDB; SQRADD(a[27], a[27]); 
   COMBA_STORE(b[54]);

   /* output 55 */
   CARRY_FORWARD;
   SQRADDSC(a[24], a[31]); SQRADDAC(a[25], a[30]); SQRADDAC(a[26], a[29]); SQRADDAC(a[27], a[28]); SQRADDDB; 
   COMBA_STORE(b[55]);

   /* output 56 */
   CARRY_FORWARD;
   SQRADDSC(a[25], a[31]); SQRADDAC(a[26], a[30]); SQRADDAC(a[27], a[29]); SQRADDDB; SQRADD(a[28], a[28]); 
   COMBA_STORE(b[56]);

   /* output 57 */
   CARRY_FORWARD;
   SQRADDSC(a[26], a[31]); SQRADDAC(a[27], a[30]); SQRADDAC(a[28], a[29]); SQRADDDB; 
   COMBA_STORE(b[57]);

   /* output 58 */
   CARRY_FORWARD;
   SQRADD2(a[27], a[31]); SQRADD2(a[28], a[30]); SQRADD(a[29], a[29]); 
   COMBA_STORE(b[58]);

   /* output 59 */
   CARRY_FORWARD;
   SQRADD2(a[28], a[31]); SQRADD2(a[29], a[30]); 
   COMBA_STORE(b[59]);

   /* output 60 */
   CARRY_FORWARD;
   SQRADD2(a[29], a[31]); SQRADD(a[30], a[30]); 
   COMBA_STORE(b[60]);

   /* output 61 */
   CARRY_FORWARD;
   SQRADD2(a[30], a[31]); 
   COMBA_STORE(b[61]);

   /* output 62 */
   CARRY_FORWARD;
   SQRADD(a[31], a[31]); 
   COMBA_STORE(b[62]);
   COMBA_STORE2(b[63]);
   COMBA_FINI;

   B->used = 64;
   B->sign = FP_ZPOS;
   memcpy(B->dp, b, 64 * sizeof(fp_digit));
   fp_clamp(B);
}
#endif


/* $Source: /cvs/libtom/tomsfastmath/src/sqr/fp_sqr_comba_32.c,v $ */
/* $Revision: 1.2 $ */
/* $Date: 2007/02/17 03:39:01 $ */

/* End: fp_sqr_comba_32.c */

/* Start: fp_sqr_comba_4.c */
#define TFM_DEFINES
#include "fp_sqr_comba.c"

#ifdef TFM_SQR4
void fp_sqr_comba4(fp_int *A, fp_int *B)
{
   fp_digit *a, b[8], c0, c1, c2, sc0, sc1, sc2;
#ifdef TFM_ISO
   fp_word tt;
#endif

   a = A->dp;
   COMBA_START; 

   /* clear carries */
   CLEAR_CARRY;

   /* output 0 */
   SQRADD(a[0],a[0]);
   COMBA_STORE(b[0]);

   /* output 1 */
   CARRY_FORWARD;
   SQRADD2(a[0], a[1]); 
   COMBA_STORE(b[1]);

   /* output 2 */
   CARRY_FORWARD;
   SQRADD2(a[0], a[2]); SQRADD(a[1], a[1]); 
   COMBA_STORE(b[2]);

   /* output 3 */
   CARRY_FORWARD;
   SQRADD2(a[0], a[3]); SQRADD2(a[1], a[2]); 
   COMBA_STORE(b[3]);

   /* output 4 */
   CARRY_FORWARD;
   SQRADD2(a[1], a[3]); SQRADD(a[2], a[2]); 
   COMBA_STORE(b[4]);

   /* output 5 */
   CARRY_FORWARD;
   SQRADD2(a[2], a[3]); 
   COMBA_STORE(b[5]);

   /* output 6 */
   CARRY_FORWARD;
   SQRADD(a[3], a[3]); 
   COMBA_STORE(b[6]);
   COMBA_STORE2(b[7]);
   COMBA_FINI;

   B->used = 8;
   B->sign = FP_ZPOS;
   memcpy(B->dp, b, 8 * sizeof(fp_digit));
   fp_clamp(B);
}
#endif


/* $Source: /cvs/libtom/tomsfastmath/src/sqr/fp_sqr_comba_4.c,v $ */
/* $Revision: 1.2 $ */
/* $Date: 2007/02/17 03:39:01 $ */

/* End: fp_sqr_comba_4.c */

/* Start: fp_sqr_comba_48.c */
#define TFM_DEFINES
#include "fp_sqr_comba.c"

#ifdef TFM_SQR48
void fp_sqr_comba48(fp_int *A, fp_int *B)
{
   fp_digit *a, b[96], c0, c1, c2, sc0, sc1, sc2;
#ifdef TFM_ISO
   fp_word tt;
#endif

   a = A->dp;
   COMBA_START; 

   /* clear carries */
   CLEAR_CARRY;

   /* output 0 */
   SQRADD(a[0],a[0]);
   COMBA_STORE(b[0]);

   /* output 1 */
   CARRY_FORWARD;
   SQRADD2(a[0], a[1]); 
   COMBA_STORE(b[1]);

   /* output 2 */
   CARRY_FORWARD;
   SQRADD2(a[0], a[2]); SQRADD(a[1], a[1]); 
   COMBA_STORE(b[2]);

   /* output 3 */
   CARRY_FORWARD;
   SQRADD2(a[0], a[3]); SQRADD2(a[1], a[2]); 
   COMBA_STORE(b[3]);

   /* output 4 */
   CARRY_FORWARD;
   SQRADD2(a[0], a[4]); SQRADD2(a[1], a[3]); SQRADD(a[2], a[2]); 
   COMBA_STORE(b[4]);

   /* output 5 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[5]); SQRADDAC(a[1], a[4]); SQRADDAC(a[2], a[3]); SQRADDDB; 
   COMBA_STORE(b[5]);

   /* output 6 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[6]); SQRADDAC(a[1], a[5]); SQRADDAC(a[2], a[4]); SQRADDDB; SQRADD(a[3], a[3]); 
   COMBA_STORE(b[6]);

   /* output 7 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[7]); SQRADDAC(a[1], a[6]); SQRADDAC(a[2], a[5]); SQRADDAC(a[3], a[4]); SQRADDDB; 
   COMBA_STORE(b[7]);

   /* output 8 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[8]); SQRADDAC(a[1], a[7]); SQRADDAC(a[2], a[6]); SQRADDAC(a[3], a[5]); SQRADDDB; SQRADD(a[4], a[4]); 
   COMBA_STORE(b[8]);

   /* output 9 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[9]); SQRADDAC(a[1], a[8]); SQRADDAC(a[2], a[7]); SQRADDAC(a[3], a[6]); SQRADDAC(a[4], a[5]); SQRADDDB; 
   COMBA_STORE(b[9]);

   /* output 10 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[10]); SQRADDAC(a[1], a[9]); SQRADDAC(a[2], a[8]); SQRADDAC(a[3], a[7]); SQRADDAC(a[4], a[6]); SQRADDDB; SQRADD(a[5], a[5]); 
   COMBA_STORE(b[10]);

   /* output 11 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[11]); SQRADDAC(a[1], a[10]); SQRADDAC(a[2], a[9]); SQRADDAC(a[3], a[8]); SQRADDAC(a[4], a[7]); SQRADDAC(a[5], a[6]); SQRADDDB; 
   COMBA_STORE(b[11]);

   /* output 12 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[12]); SQRADDAC(a[1], a[11]); SQRADDAC(a[2], a[10]); SQRADDAC(a[3], a[9]); SQRADDAC(a[4], a[8]); SQRADDAC(a[5], a[7]); SQRADDDB; SQRADD(a[6], a[6]); 
   COMBA_STORE(b[12]);

   /* output 13 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[13]); SQRADDAC(a[1], a[12]); SQRADDAC(a[2], a[11]); SQRADDAC(a[3], a[10]); SQRADDAC(a[4], a[9]); SQRADDAC(a[5], a[8]); SQRADDAC(a[6], a[7]); SQRADDDB; 
   COMBA_STORE(b[13]);

   /* output 14 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[14]); SQRADDAC(a[1], a[13]); SQRADDAC(a[2], a[12]); SQRADDAC(a[3], a[11]); SQRADDAC(a[4], a[10]); SQRADDAC(a[5], a[9]); SQRADDAC(a[6], a[8]); SQRADDDB; SQRADD(a[7], a[7]); 
   COMBA_STORE(b[14]);

   /* output 15 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[15]); SQRADDAC(a[1], a[14]); SQRADDAC(a[2], a[13]); SQRADDAC(a[3], a[12]); SQRADDAC(a[4], a[11]); SQRADDAC(a[5], a[10]); SQRADDAC(a[6], a[9]); SQRADDAC(a[7], a[8]); SQRADDDB; 
   COMBA_STORE(b[15]);

   /* output 16 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[16]); SQRADDAC(a[1], a[15]); SQRADDAC(a[2], a[14]); SQRADDAC(a[3], a[13]); SQRADDAC(a[4], a[12]); SQRADDAC(a[5], a[11]); SQRADDAC(a[6], a[10]); SQRADDAC(a[7], a[9]); SQRADDDB; SQRADD(a[8], a[8]); 
   COMBA_STORE(b[16]);

   /* output 17 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[17]); SQRADDAC(a[1], a[16]); SQRADDAC(a[2], a[15]); SQRADDAC(a[3], a[14]); SQRADDAC(a[4], a[13]); SQRADDAC(a[5], a[12]); SQRADDAC(a[6], a[11]); SQRADDAC(a[7], a[10]); SQRADDAC(a[8], a[9]); SQRADDDB; 
   COMBA_STORE(b[17]);

   /* output 18 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[18]); SQRADDAC(a[1], a[17]); SQRADDAC(a[2], a[16]); SQRADDAC(a[3], a[15]); SQRADDAC(a[4], a[14]); SQRADDAC(a[5], a[13]); SQRADDAC(a[6], a[12]); SQRADDAC(a[7], a[11]); SQRADDAC(a[8], a[10]); SQRADDDB; SQRADD(a[9], a[9]); 
   COMBA_STORE(b[18]);

   /* output 19 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[19]); SQRADDAC(a[1], a[18]); SQRADDAC(a[2], a[17]); SQRADDAC(a[3], a[16]); SQRADDAC(a[4], a[15]); SQRADDAC(a[5], a[14]); SQRADDAC(a[6], a[13]); SQRADDAC(a[7], a[12]); SQRADDAC(a[8], a[11]); SQRADDAC(a[9], a[10]); SQRADDDB; 
   COMBA_STORE(b[19]);

   /* output 20 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[20]); SQRADDAC(a[1], a[19]); SQRADDAC(a[2], a[18]); SQRADDAC(a[3], a[17]); SQRADDAC(a[4], a[16]); SQRADDAC(a[5], a[15]); SQRADDAC(a[6], a[14]); SQRADDAC(a[7], a[13]); SQRADDAC(a[8], a[12]); SQRADDAC(a[9], a[11]); SQRADDDB; SQRADD(a[10], a[10]); 
   COMBA_STORE(b[20]);

   /* output 21 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[21]); SQRADDAC(a[1], a[20]); SQRADDAC(a[2], a[19]); SQRADDAC(a[3], a[18]); SQRADDAC(a[4], a[17]); SQRADDAC(a[5], a[16]); SQRADDAC(a[6], a[15]); SQRADDAC(a[7], a[14]); SQRADDAC(a[8], a[13]); SQRADDAC(a[9], a[12]); SQRADDAC(a[10], a[11]); SQRADDDB; 
   COMBA_STORE(b[21]);

   /* output 22 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[22]); SQRADDAC(a[1], a[21]); SQRADDAC(a[2], a[20]); SQRADDAC(a[3], a[19]); SQRADDAC(a[4], a[18]); SQRADDAC(a[5], a[17]); SQRADDAC(a[6], a[16]); SQRADDAC(a[7], a[15]); SQRADDAC(a[8], a[14]); SQRADDAC(a[9], a[13]); SQRADDAC(a[10], a[12]); SQRADDDB; SQRADD(a[11], a[11]); 
   COMBA_STORE(b[22]);

   /* output 23 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[23]); SQRADDAC(a[1], a[22]); SQRADDAC(a[2], a[21]); SQRADDAC(a[3], a[20]); SQRADDAC(a[4], a[19]); SQRADDAC(a[5], a[18]); SQRADDAC(a[6], a[17]); SQRADDAC(a[7], a[16]); SQRADDAC(a[8], a[15]); SQRADDAC(a[9], a[14]); SQRADDAC(a[10], a[13]); SQRADDAC(a[11], a[12]); SQRADDDB; 
   COMBA_STORE(b[23]);

   /* output 24 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[24]); SQRADDAC(a[1], a[23]); SQRADDAC(a[2], a[22]); SQRADDAC(a[3], a[21]); SQRADDAC(a[4], a[20]); SQRADDAC(a[5], a[19]); SQRADDAC(a[6], a[18]); SQRADDAC(a[7], a[17]); SQRADDAC(a[8], a[16]); SQRADDAC(a[9], a[15]); SQRADDAC(a[10], a[14]); SQRADDAC(a[11], a[13]); SQRADDDB; SQRADD(a[12], a[12]); 
   COMBA_STORE(b[24]);

   /* output 25 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[25]); SQRADDAC(a[1], a[24]); SQRADDAC(a[2], a[23]); SQRADDAC(a[3], a[22]); SQRADDAC(a[4], a[21]); SQRADDAC(a[5], a[20]); SQRADDAC(a[6], a[19]); SQRADDAC(a[7], a[18]); SQRADDAC(a[8], a[17]); SQRADDAC(a[9], a[16]); SQRADDAC(a[10], a[15]); SQRADDAC(a[11], a[14]); SQRADDAC(a[12], a[13]); SQRADDDB; 
   COMBA_STORE(b[25]);

   /* output 26 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[26]); SQRADDAC(a[1], a[25]); SQRADDAC(a[2], a[24]); SQRADDAC(a[3], a[23]); SQRADDAC(a[4], a[22]); SQRADDAC(a[5], a[21]); SQRADDAC(a[6], a[20]); SQRADDAC(a[7], a[19]); SQRADDAC(a[8], a[18]); SQRADDAC(a[9], a[17]); SQRADDAC(a[10], a[16]); SQRADDAC(a[11], a[15]); SQRADDAC(a[12], a[14]); SQRADDDB; SQRADD(a[13], a[13]); 
   COMBA_STORE(b[26]);

   /* output 27 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[27]); SQRADDAC(a[1], a[26]); SQRADDAC(a[2], a[25]); SQRADDAC(a[3], a[24]); SQRADDAC(a[4], a[23]); SQRADDAC(a[5], a[22]); SQRADDAC(a[6], a[21]); SQRADDAC(a[7], a[20]); SQRADDAC(a[8], a[19]); SQRADDAC(a[9], a[18]); SQRADDAC(a[10], a[17]); SQRADDAC(a[11], a[16]); SQRADDAC(a[12], a[15]); SQRADDAC(a[13], a[14]); SQRADDDB; 
   COMBA_STORE(b[27]);

   /* output 28 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[28]); SQRADDAC(a[1], a[27]); SQRADDAC(a[2], a[26]); SQRADDAC(a[3], a[25]); SQRADDAC(a[4], a[24]); SQRADDAC(a[5], a[23]); SQRADDAC(a[6], a[22]); SQRADDAC(a[7], a[21]); SQRADDAC(a[8], a[20]); SQRADDAC(a[9], a[19]); SQRADDAC(a[10], a[18]); SQRADDAC(a[11], a[17]); SQRADDAC(a[12], a[16]); SQRADDAC(a[13], a[15]); SQRADDDB; SQRADD(a[14], a[14]); 
   COMBA_STORE(b[28]);

   /* output 29 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[29]); SQRADDAC(a[1], a[28]); SQRADDAC(a[2], a[27]); SQRADDAC(a[3], a[26]); SQRADDAC(a[4], a[25]); SQRADDAC(a[5], a[24]); SQRADDAC(a[6], a[23]); SQRADDAC(a[7], a[22]); SQRADDAC(a[8], a[21]); SQRADDAC(a[9], a[20]); SQRADDAC(a[10], a[19]); SQRADDAC(a[11], a[18]); SQRADDAC(a[12], a[17]); SQRADDAC(a[13], a[16]); SQRADDAC(a[14], a[15]); SQRADDDB; 
   COMBA_STORE(b[29]);

   /* output 30 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[30]); SQRADDAC(a[1], a[29]); SQRADDAC(a[2], a[28]); SQRADDAC(a[3], a[27]); SQRADDAC(a[4], a[26]); SQRADDAC(a[5], a[25]); SQRADDAC(a[6], a[24]); SQRADDAC(a[7], a[23]); SQRADDAC(a[8], a[22]); SQRADDAC(a[9], a[21]); SQRADDAC(a[10], a[20]); SQRADDAC(a[11], a[19]); SQRADDAC(a[12], a[18]); SQRADDAC(a[13], a[17]); SQRADDAC(a[14], a[16]); SQRADDDB; SQRADD(a[15], a[15]); 
   COMBA_STORE(b[30]);

   /* output 31 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[31]); SQRADDAC(a[1], a[30]); SQRADDAC(a[2], a[29]); SQRADDAC(a[3], a[28]); SQRADDAC(a[4], a[27]); SQRADDAC(a[5], a[26]); SQRADDAC(a[6], a[25]); SQRADDAC(a[7], a[24]); SQRADDAC(a[8], a[23]); SQRADDAC(a[9], a[22]); SQRADDAC(a[10], a[21]); SQRADDAC(a[11], a[20]); SQRADDAC(a[12], a[19]); SQRADDAC(a[13], a[18]); SQRADDAC(a[14], a[17]); SQRADDAC(a[15], a[16]); SQRADDDB; 
   COMBA_STORE(b[31]);

   /* output 32 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[32]); SQRADDAC(a[1], a[31]); SQRADDAC(a[2], a[30]); SQRADDAC(a[3], a[29]); SQRADDAC(a[4], a[28]); SQRADDAC(a[5], a[27]); SQRADDAC(a[6], a[26]); SQRADDAC(a[7], a[25]); SQRADDAC(a[8], a[24]); SQRADDAC(a[9], a[23]); SQRADDAC(a[10], a[22]); SQRADDAC(a[11], a[21]); SQRADDAC(a[12], a[20]); SQRADDAC(a[13], a[19]); SQRADDAC(a[14], a[18]); SQRADDAC(a[15], a[17]); SQRADDDB; SQRADD(a[16], a[16]); 
   COMBA_STORE(b[32]);

   /* output 33 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[33]); SQRADDAC(a[1], a[32]); SQRADDAC(a[2], a[31]); SQRADDAC(a[3], a[30]); SQRADDAC(a[4], a[29]); SQRADDAC(a[5], a[28]); SQRADDAC(a[6], a[27]); SQRADDAC(a[7], a[26]); SQRADDAC(a[8], a[25]); SQRADDAC(a[9], a[24]); SQRADDAC(a[10], a[23]); SQRADDAC(a[11], a[22]); SQRADDAC(a[12], a[21]); SQRADDAC(a[13], a[20]); SQRADDAC(a[14], a[19]); SQRADDAC(a[15], a[18]); SQRADDAC(a[16], a[17]); SQRADDDB; 
   COMBA_STORE(b[33]);

   /* output 34 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[34]); SQRADDAC(a[1], a[33]); SQRADDAC(a[2], a[32]); SQRADDAC(a[3], a[31]); SQRADDAC(a[4], a[30]); SQRADDAC(a[5], a[29]); SQRADDAC(a[6], a[28]); SQRADDAC(a[7], a[27]); SQRADDAC(a[8], a[26]); SQRADDAC(a[9], a[25]); SQRADDAC(a[10], a[24]); SQRADDAC(a[11], a[23]); SQRADDAC(a[12], a[22]); SQRADDAC(a[13], a[21]); SQRADDAC(a[14], a[20]); SQRADDAC(a[15], a[19]); SQRADDAC(a[16], a[18]); SQRADDDB; SQRADD(a[17], a[17]); 
   COMBA_STORE(b[34]);

   /* output 35 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[35]); SQRADDAC(a[1], a[34]); SQRADDAC(a[2], a[33]); SQRADDAC(a[3], a[32]); SQRADDAC(a[4], a[31]); SQRADDAC(a[5], a[30]); SQRADDAC(a[6], a[29]); SQRADDAC(a[7], a[28]); SQRADDAC(a[8], a[27]); SQRADDAC(a[9], a[26]); SQRADDAC(a[10], a[25]); SQRADDAC(a[11], a[24]); SQRADDAC(a[12], a[23]); SQRADDAC(a[13], a[22]); SQRADDAC(a[14], a[21]); SQRADDAC(a[15], a[20]); SQRADDAC(a[16], a[19]); SQRADDAC(a[17], a[18]); SQRADDDB; 
   COMBA_STORE(b[35]);

   /* output 36 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[36]); SQRADDAC(a[1], a[35]); SQRADDAC(a[2], a[34]); SQRADDAC(a[3], a[33]); SQRADDAC(a[4], a[32]); SQRADDAC(a[5], a[31]); SQRADDAC(a[6], a[30]); SQRADDAC(a[7], a[29]); SQRADDAC(a[8], a[28]); SQRADDAC(a[9], a[27]); SQRADDAC(a[10], a[26]); SQRADDAC(a[11], a[25]); SQRADDAC(a[12], a[24]); SQRADDAC(a[13], a[23]); SQRADDAC(a[14], a[22]); SQRADDAC(a[15], a[21]); SQRADDAC(a[16], a[20]); SQRADDAC(a[17], a[19]); SQRADDDB; SQRADD(a[18], a[18]); 
   COMBA_STORE(b[36]);

   /* output 37 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[37]); SQRADDAC(a[1], a[36]); SQRADDAC(a[2], a[35]); SQRADDAC(a[3], a[34]); SQRADDAC(a[4], a[33]); SQRADDAC(a[5], a[32]); SQRADDAC(a[6], a[31]); SQRADDAC(a[7], a[30]); SQRADDAC(a[8], a[29]); SQRADDAC(a[9], a[28]); SQRADDAC(a[10], a[27]); SQRADDAC(a[11], a[26]); SQRADDAC(a[12], a[25]); SQRADDAC(a[13], a[24]); SQRADDAC(a[14], a[23]); SQRADDAC(a[15], a[22]); SQRADDAC(a[16], a[21]); SQRADDAC(a[17], a[20]); SQRADDAC(a[18], a[19]); SQRADDDB; 
   COMBA_STORE(b[37]);

   /* output 38 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[38]); SQRADDAC(a[1], a[37]); SQRADDAC(a[2], a[36]); SQRADDAC(a[3], a[35]); SQRADDAC(a[4], a[34]); SQRADDAC(a[5], a[33]); SQRADDAC(a[6], a[32]); SQRADDAC(a[7], a[31]); SQRADDAC(a[8], a[30]); SQRADDAC(a[9], a[29]); SQRADDAC(a[10], a[28]); SQRADDAC(a[11], a[27]); SQRADDAC(a[12], a[26]); SQRADDAC(a[13], a[25]); SQRADDAC(a[14], a[24]); SQRADDAC(a[15], a[23]); SQRADDAC(a[16], a[22]); SQRADDAC(a[17], a[21]); SQRADDAC(a[18], a[20]); SQRADDDB; SQRADD(a[19], a[19]); 
   COMBA_STORE(b[38]);

   /* output 39 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[39]); SQRADDAC(a[1], a[38]); SQRADDAC(a[2], a[37]); SQRADDAC(a[3], a[36]); SQRADDAC(a[4], a[35]); SQRADDAC(a[5], a[34]); SQRADDAC(a[6], a[33]); SQRADDAC(a[7], a[32]); SQRADDAC(a[8], a[31]); SQRADDAC(a[9], a[30]); SQRADDAC(a[10], a[29]); SQRADDAC(a[11], a[28]); SQRADDAC(a[12], a[27]); SQRADDAC(a[13], a[26]); SQRADDAC(a[14], a[25]); SQRADDAC(a[15], a[24]); SQRADDAC(a[16], a[23]); SQRADDAC(a[17], a[22]); SQRADDAC(a[18], a[21]); SQRADDAC(a[19], a[20]); SQRADDDB; 
   COMBA_STORE(b[39]);

   /* output 40 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[40]); SQRADDAC(a[1], a[39]); SQRADDAC(a[2], a[38]); SQRADDAC(a[3], a[37]); SQRADDAC(a[4], a[36]); SQRADDAC(a[5], a[35]); SQRADDAC(a[6], a[34]); SQRADDAC(a[7], a[33]); SQRADDAC(a[8], a[32]); SQRADDAC(a[9], a[31]); SQRADDAC(a[10], a[30]); SQRADDAC(a[11], a[29]); SQRADDAC(a[12], a[28]); SQRADDAC(a[13], a[27]); SQRADDAC(a[14], a[26]); SQRADDAC(a[15], a[25]); SQRADDAC(a[16], a[24]); SQRADDAC(a[17], a[23]); SQRADDAC(a[18], a[22]); SQRADDAC(a[19], a[21]); SQRADDDB; SQRADD(a[20], a[20]); 
   COMBA_STORE(b[40]);

   /* output 41 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[41]); SQRADDAC(a[1], a[40]); SQRADDAC(a[2], a[39]); SQRADDAC(a[3], a[38]); SQRADDAC(a[4], a[37]); SQRADDAC(a[5], a[36]); SQRADDAC(a[6], a[35]); SQRADDAC(a[7], a[34]); SQRADDAC(a[8], a[33]); SQRADDAC(a[9], a[32]); SQRADDAC(a[10], a[31]); SQRADDAC(a[11], a[30]); SQRADDAC(a[12], a[29]); SQRADDAC(a[13], a[28]); SQRADDAC(a[14], a[27]); SQRADDAC(a[15], a[26]); SQRADDAC(a[16], a[25]); SQRADDAC(a[17], a[24]); SQRADDAC(a[18], a[23]); SQRADDAC(a[19], a[22]); SQRADDAC(a[20], a[21]); SQRADDDB; 
   COMBA_STORE(b[41]);

   /* output 42 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[42]); SQRADDAC(a[1], a[41]); SQRADDAC(a[2], a[40]); SQRADDAC(a[3], a[39]); SQRADDAC(a[4], a[38]); SQRADDAC(a[5], a[37]); SQRADDAC(a[6], a[36]); SQRADDAC(a[7], a[35]); SQRADDAC(a[8], a[34]); SQRADDAC(a[9], a[33]); SQRADDAC(a[10], a[32]); SQRADDAC(a[11], a[31]); SQRADDAC(a[12], a[30]); SQRADDAC(a[13], a[29]); SQRADDAC(a[14], a[28]); SQRADDAC(a[15], a[27]); SQRADDAC(a[16], a[26]); SQRADDAC(a[17], a[25]); SQRADDAC(a[18], a[24]); SQRADDAC(a[19], a[23]); SQRADDAC(a[20], a[22]); SQRADDDB; SQRADD(a[21], a[21]); 
   COMBA_STORE(b[42]);

   /* output 43 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[43]); SQRADDAC(a[1], a[42]); SQRADDAC(a[2], a[41]); SQRADDAC(a[3], a[40]); SQRADDAC(a[4], a[39]); SQRADDAC(a[5], a[38]); SQRADDAC(a[6], a[37]); SQRADDAC(a[7], a[36]); SQRADDAC(a[8], a[35]); SQRADDAC(a[9], a[34]); SQRADDAC(a[10], a[33]); SQRADDAC(a[11], a[32]); SQRADDAC(a[12], a[31]); SQRADDAC(a[13], a[30]); SQRADDAC(a[14], a[29]); SQRADDAC(a[15], a[28]); SQRADDAC(a[16], a[27]); SQRADDAC(a[17], a[26]); SQRADDAC(a[18], a[25]); SQRADDAC(a[19], a[24]); SQRADDAC(a[20], a[23]); SQRADDAC(a[21], a[22]); SQRADDDB; 
   COMBA_STORE(b[43]);

   /* output 44 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[44]); SQRADDAC(a[1], a[43]); SQRADDAC(a[2], a[42]); SQRADDAC(a[3], a[41]); SQRADDAC(a[4], a[40]); SQRADDAC(a[5], a[39]); SQRADDAC(a[6], a[38]); SQRADDAC(a[7], a[37]); SQRADDAC(a[8], a[36]); SQRADDAC(a[9], a[35]); SQRADDAC(a[10], a[34]); SQRADDAC(a[11], a[33]); SQRADDAC(a[12], a[32]); SQRADDAC(a[13], a[31]); SQRADDAC(a[14], a[30]); SQRADDAC(a[15], a[29]); SQRADDAC(a[16], a[28]); SQRADDAC(a[17], a[27]); SQRADDAC(a[18], a[26]); SQRADDAC(a[19], a[25]); SQRADDAC(a[20], a[24]); SQRADDAC(a[21], a[23]); SQRADDDB; SQRADD(a[22], a[22]); 
   COMBA_STORE(b[44]);

   /* output 45 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[45]); SQRADDAC(a[1], a[44]); SQRADDAC(a[2], a[43]); SQRADDAC(a[3], a[42]); SQRADDAC(a[4], a[41]); SQRADDAC(a[5], a[40]); SQRADDAC(a[6], a[39]); SQRADDAC(a[7], a[38]); SQRADDAC(a[8], a[37]); SQRADDAC(a[9], a[36]); SQRADDAC(a[10], a[35]); SQRADDAC(a[11], a[34]); SQRADDAC(a[12], a[33]); SQRADDAC(a[13], a[32]); SQRADDAC(a[14], a[31]); SQRADDAC(a[15], a[30]); SQRADDAC(a[16], a[29]); SQRADDAC(a[17], a[28]); SQRADDAC(a[18], a[27]); SQRADDAC(a[19], a[26]); SQRADDAC(a[20], a[25]); SQRADDAC(a[21], a[24]); SQRADDAC(a[22], a[23]); SQRADDDB; 
   COMBA_STORE(b[45]);

   /* output 46 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[46]); SQRADDAC(a[1], a[45]); SQRADDAC(a[2], a[44]); SQRADDAC(a[3], a[43]); SQRADDAC(a[4], a[42]); SQRADDAC(a[5], a[41]); SQRADDAC(a[6], a[40]); SQRADDAC(a[7], a[39]); SQRADDAC(a[8], a[38]); SQRADDAC(a[9], a[37]); SQRADDAC(a[10], a[36]); SQRADDAC(a[11], a[35]); SQRADDAC(a[12], a[34]); SQRADDAC(a[13], a[33]); SQRADDAC(a[14], a[32]); SQRADDAC(a[15], a[31]); SQRADDAC(a[16], a[30]); SQRADDAC(a[17], a[29]); SQRADDAC(a[18], a[28]); SQRADDAC(a[19], a[27]); SQRADDAC(a[20], a[26]); SQRADDAC(a[21], a[25]); SQRADDAC(a[22], a[24]); SQRADDDB; SQRADD(a[23], a[23]); 
   COMBA_STORE(b[46]);

   /* output 47 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[47]); SQRADDAC(a[1], a[46]); SQRADDAC(a[2], a[45]); SQRADDAC(a[3], a[44]); SQRADDAC(a[4], a[43]); SQRADDAC(a[5], a[42]); SQRADDAC(a[6], a[41]); SQRADDAC(a[7], a[40]); SQRADDAC(a[8], a[39]); SQRADDAC(a[9], a[38]); SQRADDAC(a[10], a[37]); SQRADDAC(a[11], a[36]); SQRADDAC(a[12], a[35]); SQRADDAC(a[13], a[34]); SQRADDAC(a[14], a[33]); SQRADDAC(a[15], a[32]); SQRADDAC(a[16], a[31]); SQRADDAC(a[17], a[30]); SQRADDAC(a[18], a[29]); SQRADDAC(a[19], a[28]); SQRADDAC(a[20], a[27]); SQRADDAC(a[21], a[26]); SQRADDAC(a[22], a[25]); SQRADDAC(a[23], a[24]); SQRADDDB; 
   COMBA_STORE(b[47]);

   /* output 48 */
   CARRY_FORWARD;
   SQRADDSC(a[1], a[47]); SQRADDAC(a[2], a[46]); SQRADDAC(a[3], a[45]); SQRADDAC(a[4], a[44]); SQRADDAC(a[5], a[43]); SQRADDAC(a[6], a[42]); SQRADDAC(a[7], a[41]); SQRADDAC(a[8], a[40]); SQRADDAC(a[9], a[39]); SQRADDAC(a[10], a[38]); SQRADDAC(a[11], a[37]); SQRADDAC(a[12], a[36]); SQRADDAC(a[13], a[35]); SQRADDAC(a[14], a[34]); SQRADDAC(a[15], a[33]); SQRADDAC(a[16], a[32]); SQRADDAC(a[17], a[31]); SQRADDAC(a[18], a[30]); SQRADDAC(a[19], a[29]); SQRADDAC(a[20], a[28]); SQRADDAC(a[21], a[27]); SQRADDAC(a[22], a[26]); SQRADDAC(a[23], a[25]); SQRADDDB; SQRADD(a[24], a[24]); 
   COMBA_STORE(b[48]);

   /* output 49 */
   CARRY_FORWARD;
   SQRADDSC(a[2], a[47]); SQRADDAC(a[3], a[46]); SQRADDAC(a[4], a[45]); SQRADDAC(a[5], a[44]); SQRADDAC(a[6], a[43]); SQRADDAC(a[7], a[42]); SQRADDAC(a[8], a[41]); SQRADDAC(a[9], a[40]); SQRADDAC(a[10], a[39]); SQRADDAC(a[11], a[38]); SQRADDAC(a[12], a[37]); SQRADDAC(a[13], a[36]); SQRADDAC(a[14], a[35]); SQRADDAC(a[15], a[34]); SQRADDAC(a[16], a[33]); SQRADDAC(a[17], a[32]); SQRADDAC(a[18], a[31]); SQRADDAC(a[19], a[30]); SQRADDAC(a[20], a[29]); SQRADDAC(a[21], a[28]); SQRADDAC(a[22], a[27]); SQRADDAC(a[23], a[26]); SQRADDAC(a[24], a[25]); SQRADDDB; 
   COMBA_STORE(b[49]);

   /* output 50 */
   CARRY_FORWARD;
   SQRADDSC(a[3], a[47]); SQRADDAC(a[4], a[46]); SQRADDAC(a[5], a[45]); SQRADDAC(a[6], a[44]); SQRADDAC(a[7], a[43]); SQRADDAC(a[8], a[42]); SQRADDAC(a[9], a[41]); SQRADDAC(a[10], a[40]); SQRADDAC(a[11], a[39]); SQRADDAC(a[12], a[38]); SQRADDAC(a[13], a[37]); SQRADDAC(a[14], a[36]); SQRADDAC(a[15], a[35]); SQRADDAC(a[16], a[34]); SQRADDAC(a[17], a[33]); SQRADDAC(a[18], a[32]); SQRADDAC(a[19], a[31]); SQRADDAC(a[20], a[30]); SQRADDAC(a[21], a[29]); SQRADDAC(a[22], a[28]); SQRADDAC(a[23], a[27]); SQRADDAC(a[24], a[26]); SQRADDDB; SQRADD(a[25], a[25]); 
   COMBA_STORE(b[50]);

   /* output 51 */
   CARRY_FORWARD;
   SQRADDSC(a[4], a[47]); SQRADDAC(a[5], a[46]); SQRADDAC(a[6], a[45]); SQRADDAC(a[7], a[44]); SQRADDAC(a[8], a[43]); SQRADDAC(a[9], a[42]); SQRADDAC(a[10], a[41]); SQRADDAC(a[11], a[40]); SQRADDAC(a[12], a[39]); SQRADDAC(a[13], a[38]); SQRADDAC(a[14], a[37]); SQRADDAC(a[15], a[36]); SQRADDAC(a[16], a[35]); SQRADDAC(a[17], a[34]); SQRADDAC(a[18], a[33]); SQRADDAC(a[19], a[32]); SQRADDAC(a[20], a[31]); SQRADDAC(a[21], a[30]); SQRADDAC(a[22], a[29]); SQRADDAC(a[23], a[28]); SQRADDAC(a[24], a[27]); SQRADDAC(a[25], a[26]); SQRADDDB; 
   COMBA_STORE(b[51]);

   /* output 52 */
   CARRY_FORWARD;
   SQRADDSC(a[5], a[47]); SQRADDAC(a[6], a[46]); SQRADDAC(a[7], a[45]); SQRADDAC(a[8], a[44]); SQRADDAC(a[9], a[43]); SQRADDAC(a[10], a[42]); SQRADDAC(a[11], a[41]); SQRADDAC(a[12], a[40]); SQRADDAC(a[13], a[39]); SQRADDAC(a[14], a[38]); SQRADDAC(a[15], a[37]); SQRADDAC(a[16], a[36]); SQRADDAC(a[17], a[35]); SQRADDAC(a[18], a[34]); SQRADDAC(a[19], a[33]); SQRADDAC(a[20], a[32]); SQRADDAC(a[21], a[31]); SQRADDAC(a[22], a[30]); SQRADDAC(a[23], a[29]); SQRADDAC(a[24], a[28]); SQRADDAC(a[25], a[27]); SQRADDDB; SQRADD(a[26], a[26]); 
   COMBA_STORE(b[52]);

   /* output 53 */
   CARRY_FORWARD;
   SQRADDSC(a[6], a[47]); SQRADDAC(a[7], a[46]); SQRADDAC(a[8], a[45]); SQRADDAC(a[9], a[44]); SQRADDAC(a[10], a[43]); SQRADDAC(a[11], a[42]); SQRADDAC(a[12], a[41]); SQRADDAC(a[13], a[40]); SQRADDAC(a[14], a[39]); SQRADDAC(a[15], a[38]); SQRADDAC(a[16], a[37]); SQRADDAC(a[17], a[36]); SQRADDAC(a[18], a[35]); SQRADDAC(a[19], a[34]); SQRADDAC(a[20], a[33]); SQRADDAC(a[21], a[32]); SQRADDAC(a[22], a[31]); SQRADDAC(a[23], a[30]); SQRADDAC(a[24], a[29]); SQRADDAC(a[25], a[28]); SQRADDAC(a[26], a[27]); SQRADDDB; 
   COMBA_STORE(b[53]);

   /* output 54 */
   CARRY_FORWARD;
   SQRADDSC(a[7], a[47]); SQRADDAC(a[8], a[46]); SQRADDAC(a[9], a[45]); SQRADDAC(a[10], a[44]); SQRADDAC(a[11], a[43]); SQRADDAC(a[12], a[42]); SQRADDAC(a[13], a[41]); SQRADDAC(a[14], a[40]); SQRADDAC(a[15], a[39]); SQRADDAC(a[16], a[38]); SQRADDAC(a[17], a[37]); SQRADDAC(a[18], a[36]); SQRADDAC(a[19], a[35]); SQRADDAC(a[20], a[34]); SQRADDAC(a[21], a[33]); SQRADDAC(a[22], a[32]); SQRADDAC(a[23], a[31]); SQRADDAC(a[24], a[30]); SQRADDAC(a[25], a[29]); SQRADDAC(a[26], a[28]); SQRADDDB; SQRADD(a[27], a[27]); 
   COMBA_STORE(b[54]);

   /* output 55 */
   CARRY_FORWARD;
   SQRADDSC(a[8], a[47]); SQRADDAC(a[9], a[46]); SQRADDAC(a[10], a[45]); SQRADDAC(a[11], a[44]); SQRADDAC(a[12], a[43]); SQRADDAC(a[13], a[42]); SQRADDAC(a[14], a[41]); SQRADDAC(a[15], a[40]); SQRADDAC(a[16], a[39]); SQRADDAC(a[17], a[38]); SQRADDAC(a[18], a[37]); SQRADDAC(a[19], a[36]); SQRADDAC(a[20], a[35]); SQRADDAC(a[21], a[34]); SQRADDAC(a[22], a[33]); SQRADDAC(a[23], a[32]); SQRADDAC(a[24], a[31]); SQRADDAC(a[25], a[30]); SQRADDAC(a[26], a[29]); SQRADDAC(a[27], a[28]); SQRADDDB; 
   COMBA_STORE(b[55]);

   /* output 56 */
   CARRY_FORWARD;
   SQRADDSC(a[9], a[47]); SQRADDAC(a[10], a[46]); SQRADDAC(a[11], a[45]); SQRADDAC(a[12], a[44]); SQRADDAC(a[13], a[43]); SQRADDAC(a[14], a[42]); SQRADDAC(a[15], a[41]); SQRADDAC(a[16], a[40]); SQRADDAC(a[17], a[39]); SQRADDAC(a[18], a[38]); SQRADDAC(a[19], a[37]); SQRADDAC(a[20], a[36]); SQRADDAC(a[21], a[35]); SQRADDAC(a[22], a[34]); SQRADDAC(a[23], a[33]); SQRADDAC(a[24], a[32]); SQRADDAC(a[25], a[31]); SQRADDAC(a[26], a[30]); SQRADDAC(a[27], a[29]); SQRADDDB; SQRADD(a[28], a[28]); 
   COMBA_STORE(b[56]);

   /* output 57 */
   CARRY_FORWARD;
   SQRADDSC(a[10], a[47]); SQRADDAC(a[11], a[46]); SQRADDAC(a[12], a[45]); SQRADDAC(a[13], a[44]); SQRADDAC(a[14], a[43]); SQRADDAC(a[15], a[42]); SQRADDAC(a[16], a[41]); SQRADDAC(a[17], a[40]); SQRADDAC(a[18], a[39]); SQRADDAC(a[19], a[38]); SQRADDAC(a[20], a[37]); SQRADDAC(a[21], a[36]); SQRADDAC(a[22], a[35]); SQRADDAC(a[23], a[34]); SQRADDAC(a[24], a[33]); SQRADDAC(a[25], a[32]); SQRADDAC(a[26], a[31]); SQRADDAC(a[27], a[30]); SQRADDAC(a[28], a[29]); SQRADDDB; 
   COMBA_STORE(b[57]);

   /* output 58 */
   CARRY_FORWARD;
   SQRADDSC(a[11], a[47]); SQRADDAC(a[12], a[46]); SQRADDAC(a[13], a[45]); SQRADDAC(a[14], a[44]); SQRADDAC(a[15], a[43]); SQRADDAC(a[16], a[42]); SQRADDAC(a[17], a[41]); SQRADDAC(a[18], a[40]); SQRADDAC(a[19], a[39]); SQRADDAC(a[20], a[38]); SQRADDAC(a[21], a[37]); SQRADDAC(a[22], a[36]); SQRADDAC(a[23], a[35]); SQRADDAC(a[24], a[34]); SQRADDAC(a[25], a[33]); SQRADDAC(a[26], a[32]); SQRADDAC(a[27], a[31]); SQRADDAC(a[28], a[30]); SQRADDDB; SQRADD(a[29], a[29]); 
   COMBA_STORE(b[58]);

   /* output 59 */
   CARRY_FORWARD;
   SQRADDSC(a[12], a[47]); SQRADDAC(a[13], a[46]); SQRADDAC(a[14], a[45]); SQRADDAC(a[15], a[44]); SQRADDAC(a[16], a[43]); SQRADDAC(a[17], a[42]); SQRADDAC(a[18], a[41]); SQRADDAC(a[19], a[40]); SQRADDAC(a[20], a[39]); SQRADDAC(a[21], a[38]); SQRADDAC(a[22], a[37]); SQRADDAC(a[23], a[36]); SQRADDAC(a[24], a[35]); SQRADDAC(a[25], a[34]); SQRADDAC(a[26], a[33]); SQRADDAC(a[27], a[32]); SQRADDAC(a[28], a[31]); SQRADDAC(a[29], a[30]); SQRADDDB; 
   COMBA_STORE(b[59]);

   /* output 60 */
   CARRY_FORWARD;
   SQRADDSC(a[13], a[47]); SQRADDAC(a[14], a[46]); SQRADDAC(a[15], a[45]); SQRADDAC(a[16], a[44]); SQRADDAC(a[17], a[43]); SQRADDAC(a[18], a[42]); SQRADDAC(a[19], a[41]); SQRADDAC(a[20], a[40]); SQRADDAC(a[21], a[39]); SQRADDAC(a[22], a[38]); SQRADDAC(a[23], a[37]); SQRADDAC(a[24], a[36]); SQRADDAC(a[25], a[35]); SQRADDAC(a[26], a[34]); SQRADDAC(a[27], a[33]); SQRADDAC(a[28], a[32]); SQRADDAC(a[29], a[31]); SQRADDDB; SQRADD(a[30], a[30]); 
   COMBA_STORE(b[60]);

   /* output 61 */
   CARRY_FORWARD;
   SQRADDSC(a[14], a[47]); SQRADDAC(a[15], a[46]); SQRADDAC(a[16], a[45]); SQRADDAC(a[17], a[44]); SQRADDAC(a[18], a[43]); SQRADDAC(a[19], a[42]); SQRADDAC(a[20], a[41]); SQRADDAC(a[21], a[40]); SQRADDAC(a[22], a[39]); SQRADDAC(a[23], a[38]); SQRADDAC(a[24], a[37]); SQRADDAC(a[25], a[36]); SQRADDAC(a[26], a[35]); SQRADDAC(a[27], a[34]); SQRADDAC(a[28], a[33]); SQRADDAC(a[29], a[32]); SQRADDAC(a[30], a[31]); SQRADDDB; 
   COMBA_STORE(b[61]);

   /* output 62 */
   CARRY_FORWARD;
   SQRADDSC(a[15], a[47]); SQRADDAC(a[16], a[46]); SQRADDAC(a[17], a[45]); SQRADDAC(a[18], a[44]); SQRADDAC(a[19], a[43]); SQRADDAC(a[20], a[42]); SQRADDAC(a[21], a[41]); SQRADDAC(a[22], a[40]); SQRADDAC(a[23], a[39]); SQRADDAC(a[24], a[38]); SQRADDAC(a[25], a[37]); SQRADDAC(a[26], a[36]); SQRADDAC(a[27], a[35]); SQRADDAC(a[28], a[34]); SQRADDAC(a[29], a[33]); SQRADDAC(a[30], a[32]); SQRADDDB; SQRADD(a[31], a[31]); 
   COMBA_STORE(b[62]);

   /* output 63 */
   CARRY_FORWARD;
   SQRADDSC(a[16], a[47]); SQRADDAC(a[17], a[46]); SQRADDAC(a[18], a[45]); SQRADDAC(a[19], a[44]); SQRADDAC(a[20], a[43]); SQRADDAC(a[21], a[42]); SQRADDAC(a[22], a[41]); SQRADDAC(a[23], a[40]); SQRADDAC(a[24], a[39]); SQRADDAC(a[25], a[38]); SQRADDAC(a[26], a[37]); SQRADDAC(a[27], a[36]); SQRADDAC(a[28], a[35]); SQRADDAC(a[29], a[34]); SQRADDAC(a[30], a[33]); SQRADDAC(a[31], a[32]); SQRADDDB; 
   COMBA_STORE(b[63]);

   /* output 64 */
   CARRY_FORWARD;
   SQRADDSC(a[17], a[47]); SQRADDAC(a[18], a[46]); SQRADDAC(a[19], a[45]); SQRADDAC(a[20], a[44]); SQRADDAC(a[21], a[43]); SQRADDAC(a[22], a[42]); SQRADDAC(a[23], a[41]); SQRADDAC(a[24], a[40]); SQRADDAC(a[25], a[39]); SQRADDAC(a[26], a[38]); SQRADDAC(a[27], a[37]); SQRADDAC(a[28], a[36]); SQRADDAC(a[29], a[35]); SQRADDAC(a[30], a[34]); SQRADDAC(a[31], a[33]); SQRADDDB; SQRADD(a[32], a[32]); 
   COMBA_STORE(b[64]);

   /* output 65 */
   CARRY_FORWARD;
   SQRADDSC(a[18], a[47]); SQRADDAC(a[19], a[46]); SQRADDAC(a[20], a[45]); SQRADDAC(a[21], a[44]); SQRADDAC(a[22], a[43]); SQRADDAC(a[23], a[42]); SQRADDAC(a[24], a[41]); SQRADDAC(a[25], a[40]); SQRADDAC(a[26], a[39]); SQRADDAC(a[27], a[38]); SQRADDAC(a[28], a[37]); SQRADDAC(a[29], a[36]); SQRADDAC(a[30], a[35]); SQRADDAC(a[31], a[34]); SQRADDAC(a[32], a[33]); SQRADDDB; 
   COMBA_STORE(b[65]);

   /* output 66 */
   CARRY_FORWARD;
   SQRADDSC(a[19], a[47]); SQRADDAC(a[20], a[46]); SQRADDAC(a[21], a[45]); SQRADDAC(a[22], a[44]); SQRADDAC(a[23], a[43]); SQRADDAC(a[24], a[42]); SQRADDAC(a[25], a[41]); SQRADDAC(a[26], a[40]); SQRADDAC(a[27], a[39]); SQRADDAC(a[28], a[38]); SQRADDAC(a[29], a[37]); SQRADDAC(a[30], a[36]); SQRADDAC(a[31], a[35]); SQRADDAC(a[32], a[34]); SQRADDDB; SQRADD(a[33], a[33]); 
   COMBA_STORE(b[66]);

   /* output 67 */
   CARRY_FORWARD;
   SQRADDSC(a[20], a[47]); SQRADDAC(a[21], a[46]); SQRADDAC(a[22], a[45]); SQRADDAC(a[23], a[44]); SQRADDAC(a[24], a[43]); SQRADDAC(a[25], a[42]); SQRADDAC(a[26], a[41]); SQRADDAC(a[27], a[40]); SQRADDAC(a[28], a[39]); SQRADDAC(a[29], a[38]); SQRADDAC(a[30], a[37]); SQRADDAC(a[31], a[36]); SQRADDAC(a[32], a[35]); SQRADDAC(a[33], a[34]); SQRADDDB; 
   COMBA_STORE(b[67]);

   /* output 68 */
   CARRY_FORWARD;
   SQRADDSC(a[21], a[47]); SQRADDAC(a[22], a[46]); SQRADDAC(a[23], a[45]); SQRADDAC(a[24], a[44]); SQRADDAC(a[25], a[43]); SQRADDAC(a[26], a[42]); SQRADDAC(a[27], a[41]); SQRADDAC(a[28], a[40]); SQRADDAC(a[29], a[39]); SQRADDAC(a[30], a[38]); SQRADDAC(a[31], a[37]); SQRADDAC(a[32], a[36]); SQRADDAC(a[33], a[35]); SQRADDDB; SQRADD(a[34], a[34]); 
   COMBA_STORE(b[68]);

   /* output 69 */
   CARRY_FORWARD;
   SQRADDSC(a[22], a[47]); SQRADDAC(a[23], a[46]); SQRADDAC(a[24], a[45]); SQRADDAC(a[25], a[44]); SQRADDAC(a[26], a[43]); SQRADDAC(a[27], a[42]); SQRADDAC(a[28], a[41]); SQRADDAC(a[29], a[40]); SQRADDAC(a[30], a[39]); SQRADDAC(a[31], a[38]); SQRADDAC(a[32], a[37]); SQRADDAC(a[33], a[36]); SQRADDAC(a[34], a[35]); SQRADDDB; 
   COMBA_STORE(b[69]);

   /* output 70 */
   CARRY_FORWARD;
   SQRADDSC(a[23], a[47]); SQRADDAC(a[24], a[46]); SQRADDAC(a[25], a[45]); SQRADDAC(a[26], a[44]); SQRADDAC(a[27], a[43]); SQRADDAC(a[28], a[42]); SQRADDAC(a[29], a[41]); SQRADDAC(a[30], a[40]); SQRADDAC(a[31], a[39]); SQRADDAC(a[32], a[38]); SQRADDAC(a[33], a[37]); SQRADDAC(a[34], a[36]); SQRADDDB; SQRADD(a[35], a[35]); 
   COMBA_STORE(b[70]);

   /* output 71 */
   CARRY_FORWARD;
   SQRADDSC(a[24], a[47]); SQRADDAC(a[25], a[46]); SQRADDAC(a[26], a[45]); SQRADDAC(a[27], a[44]); SQRADDAC(a[28], a[43]); SQRADDAC(a[29], a[42]); SQRADDAC(a[30], a[41]); SQRADDAC(a[31], a[40]); SQRADDAC(a[32], a[39]); SQRADDAC(a[33], a[38]); SQRADDAC(a[34], a[37]); SQRADDAC(a[35], a[36]); SQRADDDB; 
   COMBA_STORE(b[71]);

   /* output 72 */
   CARRY_FORWARD;
   SQRADDSC(a[25], a[47]); SQRADDAC(a[26], a[46]); SQRADDAC(a[27], a[45]); SQRADDAC(a[28], a[44]); SQRADDAC(a[29], a[43]); SQRADDAC(a[30], a[42]); SQRADDAC(a[31], a[41]); SQRADDAC(a[32], a[40]); SQRADDAC(a[33], a[39]); SQRADDAC(a[34], a[38]); SQRADDAC(a[35], a[37]); SQRADDDB; SQRADD(a[36], a[36]); 
   COMBA_STORE(b[72]);

   /* output 73 */
   CARRY_FORWARD;
   SQRADDSC(a[26], a[47]); SQRADDAC(a[27], a[46]); SQRADDAC(a[28], a[45]); SQRADDAC(a[29], a[44]); SQRADDAC(a[30], a[43]); SQRADDAC(a[31], a[42]); SQRADDAC(a[32], a[41]); SQRADDAC(a[33], a[40]); SQRADDAC(a[34], a[39]); SQRADDAC(a[35], a[38]); SQRADDAC(a[36], a[37]); SQRADDDB; 
   COMBA_STORE(b[73]);

   /* output 74 */
   CARRY_FORWARD;
   SQRADDSC(a[27], a[47]); SQRADDAC(a[28], a[46]); SQRADDAC(a[29], a[45]); SQRADDAC(a[30], a[44]); SQRADDAC(a[31], a[43]); SQRADDAC(a[32], a[42]); SQRADDAC(a[33], a[41]); SQRADDAC(a[34], a[40]); SQRADDAC(a[35], a[39]); SQRADDAC(a[36], a[38]); SQRADDDB; SQRADD(a[37], a[37]); 
   COMBA_STORE(b[74]);

   /* output 75 */
   CARRY_FORWARD;
   SQRADDSC(a[28], a[47]); SQRADDAC(a[29], a[46]); SQRADDAC(a[30], a[45]); SQRADDAC(a[31], a[44]); SQRADDAC(a[32], a[43]); SQRADDAC(a[33], a[42]); SQRADDAC(a[34], a[41]); SQRADDAC(a[35], a[40]); SQRADDAC(a[36], a[39]); SQRADDAC(a[37], a[38]); SQRADDDB; 
   COMBA_STORE(b[75]);

   /* output 76 */
   CARRY_FORWARD;
   SQRADDSC(a[29], a[47]); SQRADDAC(a[30], a[46]); SQRADDAC(a[31], a[45]); SQRADDAC(a[32], a[44]); SQRADDAC(a[33], a[43]); SQRADDAC(a[34], a[42]); SQRADDAC(a[35], a[41]); SQRADDAC(a[36], a[40]); SQRADDAC(a[37], a[39]); SQRADDDB; SQRADD(a[38], a[38]); 
   COMBA_STORE(b[76]);

   /* output 77 */
   CARRY_FORWARD;
   SQRADDSC(a[30], a[47]); SQRADDAC(a[31], a[46]); SQRADDAC(a[32], a[45]); SQRADDAC(a[33], a[44]); SQRADDAC(a[34], a[43]); SQRADDAC(a[35], a[42]); SQRADDAC(a[36], a[41]); SQRADDAC(a[37], a[40]); SQRADDAC(a[38], a[39]); SQRADDDB; 
   COMBA_STORE(b[77]);

   /* output 78 */
   CARRY_FORWARD;
   SQRADDSC(a[31], a[47]); SQRADDAC(a[32], a[46]); SQRADDAC(a[33], a[45]); SQRADDAC(a[34], a[44]); SQRADDAC(a[35], a[43]); SQRADDAC(a[36], a[42]); SQRADDAC(a[37], a[41]); SQRADDAC(a[38], a[40]); SQRADDDB; SQRADD(a[39], a[39]); 
   COMBA_STORE(b[78]);

   /* output 79 */
   CARRY_FORWARD;
   SQRADDSC(a[32], a[47]); SQRADDAC(a[33], a[46]); SQRADDAC(a[34], a[45]); SQRADDAC(a[35], a[44]); SQRADDAC(a[36], a[43]); SQRADDAC(a[37], a[42]); SQRADDAC(a[38], a[41]); SQRADDAC(a[39], a[40]); SQRADDDB; 
   COMBA_STORE(b[79]);

   /* output 80 */
   CARRY_FORWARD;
   SQRADDSC(a[33], a[47]); SQRADDAC(a[34], a[46]); SQRADDAC(a[35], a[45]); SQRADDAC(a[36], a[44]); SQRADDAC(a[37], a[43]); SQRADDAC(a[38], a[42]); SQRADDAC(a[39], a[41]); SQRADDDB; SQRADD(a[40], a[40]); 
   COMBA_STORE(b[80]);

   /* output 81 */
   CARRY_FORWARD;
   SQRADDSC(a[34], a[47]); SQRADDAC(a[35], a[46]); SQRADDAC(a[36], a[45]); SQRADDAC(a[37], a[44]); SQRADDAC(a[38], a[43]); SQRADDAC(a[39], a[42]); SQRADDAC(a[40], a[41]); SQRADDDB; 
   COMBA_STORE(b[81]);

   /* output 82 */
   CARRY_FORWARD;
   SQRADDSC(a[35], a[47]); SQRADDAC(a[36], a[46]); SQRADDAC(a[37], a[45]); SQRADDAC(a[38], a[44]); SQRADDAC(a[39], a[43]); SQRADDAC(a[40], a[42]); SQRADDDB; SQRADD(a[41], a[41]); 
   COMBA_STORE(b[82]);

   /* output 83 */
   CARRY_FORWARD;
   SQRADDSC(a[36], a[47]); SQRADDAC(a[37], a[46]); SQRADDAC(a[38], a[45]); SQRADDAC(a[39], a[44]); SQRADDAC(a[40], a[43]); SQRADDAC(a[41], a[42]); SQRADDDB; 
   COMBA_STORE(b[83]);

   /* output 84 */
   CARRY_FORWARD;
   SQRADDSC(a[37], a[47]); SQRADDAC(a[38], a[46]); SQRADDAC(a[39], a[45]); SQRADDAC(a[40], a[44]); SQRADDAC(a[41], a[43]); SQRADDDB; SQRADD(a[42], a[42]); 
   COMBA_STORE(b[84]);

   /* output 85 */
   CARRY_FORWARD;
   SQRADDSC(a[38], a[47]); SQRADDAC(a[39], a[46]); SQRADDAC(a[40], a[45]); SQRADDAC(a[41], a[44]); SQRADDAC(a[42], a[43]); SQRADDDB; 
   COMBA_STORE(b[85]);

   /* output 86 */
   CARRY_FORWARD;
   SQRADDSC(a[39], a[47]); SQRADDAC(a[40], a[46]); SQRADDAC(a[41], a[45]); SQRADDAC(a[42], a[44]); SQRADDDB; SQRADD(a[43], a[43]); 
   COMBA_STORE(b[86]);

   /* output 87 */
   CARRY_FORWARD;
   SQRADDSC(a[40], a[47]); SQRADDAC(a[41], a[46]); SQRADDAC(a[42], a[45]); SQRADDAC(a[43], a[44]); SQRADDDB; 
   COMBA_STORE(b[87]);

   /* output 88 */
   CARRY_FORWARD;
   SQRADDSC(a[41], a[47]); SQRADDAC(a[42], a[46]); SQRADDAC(a[43], a[45]); SQRADDDB; SQRADD(a[44], a[44]); 
   COMBA_STORE(b[88]);

   /* output 89 */
   CARRY_FORWARD;
   SQRADDSC(a[42], a[47]); SQRADDAC(a[43], a[46]); SQRADDAC(a[44], a[45]); SQRADDDB; 
   COMBA_STORE(b[89]);

   /* output 90 */
   CARRY_FORWARD;
   SQRADD2(a[43], a[47]); SQRADD2(a[44], a[46]); SQRADD(a[45], a[45]); 
   COMBA_STORE(b[90]);

   /* output 91 */
   CARRY_FORWARD;
   SQRADD2(a[44], a[47]); SQRADD2(a[45], a[46]); 
   COMBA_STORE(b[91]);

   /* output 92 */
   CARRY_FORWARD;
   SQRADD2(a[45], a[47]); SQRADD(a[46], a[46]); 
   COMBA_STORE(b[92]);

   /* output 93 */
   CARRY_FORWARD;
   SQRADD2(a[46], a[47]); 
   COMBA_STORE(b[93]);

   /* output 94 */
   CARRY_FORWARD;
   SQRADD(a[47], a[47]); 
   COMBA_STORE(b[94]);
   COMBA_STORE2(b[95]);
   COMBA_FINI;

   B->used = 96;
   B->sign = FP_ZPOS;
   memcpy(B->dp, b, 96 * sizeof(fp_digit));
   fp_clamp(B);
}
#endif


/* $Source: /cvs/libtom/tomsfastmath/src/sqr/fp_sqr_comba_48.c,v $ */
/* $Revision: 1.2 $ */
/* $Date: 2007/02/17 03:39:01 $ */

/* End: fp_sqr_comba_48.c */

/* Start: fp_sqr_comba_6.c */
#define TFM_DEFINES
#include "fp_sqr_comba.c"

#ifdef TFM_SQR6
void fp_sqr_comba6(fp_int *A, fp_int *B)
{
   fp_digit *a, b[12], c0, c1, c2, sc0, sc1, sc2;
#ifdef TFM_ISO
   fp_word tt;
#endif

   a = A->dp;
   COMBA_START; 

   /* clear carries */
   CLEAR_CARRY;

   /* output 0 */
   SQRADD(a[0],a[0]);
   COMBA_STORE(b[0]);

   /* output 1 */
   CARRY_FORWARD;
   SQRADD2(a[0], a[1]); 
   COMBA_STORE(b[1]);

   /* output 2 */
   CARRY_FORWARD;
   SQRADD2(a[0], a[2]); SQRADD(a[1], a[1]); 
   COMBA_STORE(b[2]);

   /* output 3 */
   CARRY_FORWARD;
   SQRADD2(a[0], a[3]); SQRADD2(a[1], a[2]); 
   COMBA_STORE(b[3]);

   /* output 4 */
   CARRY_FORWARD;
   SQRADD2(a[0], a[4]); SQRADD2(a[1], a[3]); SQRADD(a[2], a[2]); 
   COMBA_STORE(b[4]);

   /* output 5 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[5]); SQRADDAC(a[1], a[4]); SQRADDAC(a[2], a[3]); SQRADDDB; 
   COMBA_STORE(b[5]);

   /* output 6 */
   CARRY_FORWARD;
   SQRADD2(a[1], a[5]); SQRADD2(a[2], a[4]); SQRADD(a[3], a[3]); 
   COMBA_STORE(b[6]);

   /* output 7 */
   CARRY_FORWARD;
   SQRADD2(a[2], a[5]); SQRADD2(a[3], a[4]); 
   COMBA_STORE(b[7]);

   /* output 8 */
   CARRY_FORWARD;
   SQRADD2(a[3], a[5]); SQRADD(a[4], a[4]); 
   COMBA_STORE(b[8]);

   /* output 9 */
   CARRY_FORWARD;
   SQRADD2(a[4], a[5]); 
   COMBA_STORE(b[9]);

   /* output 10 */
   CARRY_FORWARD;
   SQRADD(a[5], a[5]); 
   COMBA_STORE(b[10]);
   COMBA_STORE2(b[11]);
   COMBA_FINI;

   B->used = 12;
   B->sign = FP_ZPOS;
   memcpy(B->dp, b, 12 * sizeof(fp_digit));
   fp_clamp(B);
}
#endif


/* $Source: /cvs/libtom/tomsfastmath/src/sqr/fp_sqr_comba_6.c,v $ */
/* $Revision: 1.2 $ */
/* $Date: 2007/02/17 03:39:01 $ */

/* End: fp_sqr_comba_6.c */

/* Start: fp_sqr_comba_64.c */
#define TFM_DEFINES
#include "fp_sqr_comba.c"

#ifdef TFM_SQR64
void fp_sqr_comba64(fp_int *A, fp_int *B)
{
   fp_digit *a, b[128], c0, c1, c2, sc0, sc1, sc2;
#ifdef TFM_ISO
   fp_word tt;
#endif

   a = A->dp;
   COMBA_START; 

   /* clear carries */
   CLEAR_CARRY;

   /* output 0 */
   SQRADD(a[0],a[0]);
   COMBA_STORE(b[0]);

   /* output 1 */
   CARRY_FORWARD;
   SQRADD2(a[0], a[1]); 
   COMBA_STORE(b[1]);

   /* output 2 */
   CARRY_FORWARD;
   SQRADD2(a[0], a[2]); SQRADD(a[1], a[1]); 
   COMBA_STORE(b[2]);

   /* output 3 */
   CARRY_FORWARD;
   SQRADD2(a[0], a[3]); SQRADD2(a[1], a[2]); 
   COMBA_STORE(b[3]);

   /* output 4 */
   CARRY_FORWARD;
   SQRADD2(a[0], a[4]); SQRADD2(a[1], a[3]); SQRADD(a[2], a[2]); 
   COMBA_STORE(b[4]);

   /* output 5 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[5]); SQRADDAC(a[1], a[4]); SQRADDAC(a[2], a[3]); SQRADDDB; 
   COMBA_STORE(b[5]);

   /* output 6 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[6]); SQRADDAC(a[1], a[5]); SQRADDAC(a[2], a[4]); SQRADDDB; SQRADD(a[3], a[3]); 
   COMBA_STORE(b[6]);

   /* output 7 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[7]); SQRADDAC(a[1], a[6]); SQRADDAC(a[2], a[5]); SQRADDAC(a[3], a[4]); SQRADDDB; 
   COMBA_STORE(b[7]);

   /* output 8 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[8]); SQRADDAC(a[1], a[7]); SQRADDAC(a[2], a[6]); SQRADDAC(a[3], a[5]); SQRADDDB; SQRADD(a[4], a[4]); 
   COMBA_STORE(b[8]);

   /* output 9 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[9]); SQRADDAC(a[1], a[8]); SQRADDAC(a[2], a[7]); SQRADDAC(a[3], a[6]); SQRADDAC(a[4], a[5]); SQRADDDB; 
   COMBA_STORE(b[9]);

   /* output 10 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[10]); SQRADDAC(a[1], a[9]); SQRADDAC(a[2], a[8]); SQRADDAC(a[3], a[7]); SQRADDAC(a[4], a[6]); SQRADDDB; SQRADD(a[5], a[5]); 
   COMBA_STORE(b[10]);

   /* output 11 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[11]); SQRADDAC(a[1], a[10]); SQRADDAC(a[2], a[9]); SQRADDAC(a[3], a[8]); SQRADDAC(a[4], a[7]); SQRADDAC(a[5], a[6]); SQRADDDB; 
   COMBA_STORE(b[11]);

   /* output 12 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[12]); SQRADDAC(a[1], a[11]); SQRADDAC(a[2], a[10]); SQRADDAC(a[3], a[9]); SQRADDAC(a[4], a[8]); SQRADDAC(a[5], a[7]); SQRADDDB; SQRADD(a[6], a[6]); 
   COMBA_STORE(b[12]);

   /* output 13 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[13]); SQRADDAC(a[1], a[12]); SQRADDAC(a[2], a[11]); SQRADDAC(a[3], a[10]); SQRADDAC(a[4], a[9]); SQRADDAC(a[5], a[8]); SQRADDAC(a[6], a[7]); SQRADDDB; 
   COMBA_STORE(b[13]);

   /* output 14 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[14]); SQRADDAC(a[1], a[13]); SQRADDAC(a[2], a[12]); SQRADDAC(a[3], a[11]); SQRADDAC(a[4], a[10]); SQRADDAC(a[5], a[9]); SQRADDAC(a[6], a[8]); SQRADDDB; SQRADD(a[7], a[7]); 
   COMBA_STORE(b[14]);

   /* output 15 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[15]); SQRADDAC(a[1], a[14]); SQRADDAC(a[2], a[13]); SQRADDAC(a[3], a[12]); SQRADDAC(a[4], a[11]); SQRADDAC(a[5], a[10]); SQRADDAC(a[6], a[9]); SQRADDAC(a[7], a[8]); SQRADDDB; 
   COMBA_STORE(b[15]);

   /* output 16 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[16]); SQRADDAC(a[1], a[15]); SQRADDAC(a[2], a[14]); SQRADDAC(a[3], a[13]); SQRADDAC(a[4], a[12]); SQRADDAC(a[5], a[11]); SQRADDAC(a[6], a[10]); SQRADDAC(a[7], a[9]); SQRADDDB; SQRADD(a[8], a[8]); 
   COMBA_STORE(b[16]);

   /* output 17 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[17]); SQRADDAC(a[1], a[16]); SQRADDAC(a[2], a[15]); SQRADDAC(a[3], a[14]); SQRADDAC(a[4], a[13]); SQRADDAC(a[5], a[12]); SQRADDAC(a[6], a[11]); SQRADDAC(a[7], a[10]); SQRADDAC(a[8], a[9]); SQRADDDB; 
   COMBA_STORE(b[17]);

   /* output 18 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[18]); SQRADDAC(a[1], a[17]); SQRADDAC(a[2], a[16]); SQRADDAC(a[3], a[15]); SQRADDAC(a[4], a[14]); SQRADDAC(a[5], a[13]); SQRADDAC(a[6], a[12]); SQRADDAC(a[7], a[11]); SQRADDAC(a[8], a[10]); SQRADDDB; SQRADD(a[9], a[9]); 
   COMBA_STORE(b[18]);

   /* output 19 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[19]); SQRADDAC(a[1], a[18]); SQRADDAC(a[2], a[17]); SQRADDAC(a[3], a[16]); SQRADDAC(a[4], a[15]); SQRADDAC(a[5], a[14]); SQRADDAC(a[6], a[13]); SQRADDAC(a[7], a[12]); SQRADDAC(a[8], a[11]); SQRADDAC(a[9], a[10]); SQRADDDB; 
   COMBA_STORE(b[19]);

   /* output 20 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[20]); SQRADDAC(a[1], a[19]); SQRADDAC(a[2], a[18]); SQRADDAC(a[3], a[17]); SQRADDAC(a[4], a[16]); SQRADDAC(a[5], a[15]); SQRADDAC(a[6], a[14]); SQRADDAC(a[7], a[13]); SQRADDAC(a[8], a[12]); SQRADDAC(a[9], a[11]); SQRADDDB; SQRADD(a[10], a[10]); 
   COMBA_STORE(b[20]);

   /* output 21 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[21]); SQRADDAC(a[1], a[20]); SQRADDAC(a[2], a[19]); SQRADDAC(a[3], a[18]); SQRADDAC(a[4], a[17]); SQRADDAC(a[5], a[16]); SQRADDAC(a[6], a[15]); SQRADDAC(a[7], a[14]); SQRADDAC(a[8], a[13]); SQRADDAC(a[9], a[12]); SQRADDAC(a[10], a[11]); SQRADDDB; 
   COMBA_STORE(b[21]);

   /* output 22 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[22]); SQRADDAC(a[1], a[21]); SQRADDAC(a[2], a[20]); SQRADDAC(a[3], a[19]); SQRADDAC(a[4], a[18]); SQRADDAC(a[5], a[17]); SQRADDAC(a[6], a[16]); SQRADDAC(a[7], a[15]); SQRADDAC(a[8], a[14]); SQRADDAC(a[9], a[13]); SQRADDAC(a[10], a[12]); SQRADDDB; SQRADD(a[11], a[11]); 
   COMBA_STORE(b[22]);

   /* output 23 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[23]); SQRADDAC(a[1], a[22]); SQRADDAC(a[2], a[21]); SQRADDAC(a[3], a[20]); SQRADDAC(a[4], a[19]); SQRADDAC(a[5], a[18]); SQRADDAC(a[6], a[17]); SQRADDAC(a[7], a[16]); SQRADDAC(a[8], a[15]); SQRADDAC(a[9], a[14]); SQRADDAC(a[10], a[13]); SQRADDAC(a[11], a[12]); SQRADDDB; 
   COMBA_STORE(b[23]);

   /* output 24 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[24]); SQRADDAC(a[1], a[23]); SQRADDAC(a[2], a[22]); SQRADDAC(a[3], a[21]); SQRADDAC(a[4], a[20]); SQRADDAC(a[5], a[19]); SQRADDAC(a[6], a[18]); SQRADDAC(a[7], a[17]); SQRADDAC(a[8], a[16]); SQRADDAC(a[9], a[15]); SQRADDAC(a[10], a[14]); SQRADDAC(a[11], a[13]); SQRADDDB; SQRADD(a[12], a[12]); 
   COMBA_STORE(b[24]);

   /* output 25 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[25]); SQRADDAC(a[1], a[24]); SQRADDAC(a[2], a[23]); SQRADDAC(a[3], a[22]); SQRADDAC(a[4], a[21]); SQRADDAC(a[5], a[20]); SQRADDAC(a[6], a[19]); SQRADDAC(a[7], a[18]); SQRADDAC(a[8], a[17]); SQRADDAC(a[9], a[16]); SQRADDAC(a[10], a[15]); SQRADDAC(a[11], a[14]); SQRADDAC(a[12], a[13]); SQRADDDB; 
   COMBA_STORE(b[25]);

   /* output 26 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[26]); SQRADDAC(a[1], a[25]); SQRADDAC(a[2], a[24]); SQRADDAC(a[3], a[23]); SQRADDAC(a[4], a[22]); SQRADDAC(a[5], a[21]); SQRADDAC(a[6], a[20]); SQRADDAC(a[7], a[19]); SQRADDAC(a[8], a[18]); SQRADDAC(a[9], a[17]); SQRADDAC(a[10], a[16]); SQRADDAC(a[11], a[15]); SQRADDAC(a[12], a[14]); SQRADDDB; SQRADD(a[13], a[13]); 
   COMBA_STORE(b[26]);

   /* output 27 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[27]); SQRADDAC(a[1], a[26]); SQRADDAC(a[2], a[25]); SQRADDAC(a[3], a[24]); SQRADDAC(a[4], a[23]); SQRADDAC(a[5], a[22]); SQRADDAC(a[6], a[21]); SQRADDAC(a[7], a[20]); SQRADDAC(a[8], a[19]); SQRADDAC(a[9], a[18]); SQRADDAC(a[10], a[17]); SQRADDAC(a[11], a[16]); SQRADDAC(a[12], a[15]); SQRADDAC(a[13], a[14]); SQRADDDB; 
   COMBA_STORE(b[27]);

   /* output 28 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[28]); SQRADDAC(a[1], a[27]); SQRADDAC(a[2], a[26]); SQRADDAC(a[3], a[25]); SQRADDAC(a[4], a[24]); SQRADDAC(a[5], a[23]); SQRADDAC(a[6], a[22]); SQRADDAC(a[7], a[21]); SQRADDAC(a[8], a[20]); SQRADDAC(a[9], a[19]); SQRADDAC(a[10], a[18]); SQRADDAC(a[11], a[17]); SQRADDAC(a[12], a[16]); SQRADDAC(a[13], a[15]); SQRADDDB; SQRADD(a[14], a[14]); 
   COMBA_STORE(b[28]);

   /* output 29 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[29]); SQRADDAC(a[1], a[28]); SQRADDAC(a[2], a[27]); SQRADDAC(a[3], a[26]); SQRADDAC(a[4], a[25]); SQRADDAC(a[5], a[24]); SQRADDAC(a[6], a[23]); SQRADDAC(a[7], a[22]); SQRADDAC(a[8], a[21]); SQRADDAC(a[9], a[20]); SQRADDAC(a[10], a[19]); SQRADDAC(a[11], a[18]); SQRADDAC(a[12], a[17]); SQRADDAC(a[13], a[16]); SQRADDAC(a[14], a[15]); SQRADDDB; 
   COMBA_STORE(b[29]);

   /* output 30 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[30]); SQRADDAC(a[1], a[29]); SQRADDAC(a[2], a[28]); SQRADDAC(a[3], a[27]); SQRADDAC(a[4], a[26]); SQRADDAC(a[5], a[25]); SQRADDAC(a[6], a[24]); SQRADDAC(a[7], a[23]); SQRADDAC(a[8], a[22]); SQRADDAC(a[9], a[21]); SQRADDAC(a[10], a[20]); SQRADDAC(a[11], a[19]); SQRADDAC(a[12], a[18]); SQRADDAC(a[13], a[17]); SQRADDAC(a[14], a[16]); SQRADDDB; SQRADD(a[15], a[15]); 
   COMBA_STORE(b[30]);

   /* output 31 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[31]); SQRADDAC(a[1], a[30]); SQRADDAC(a[2], a[29]); SQRADDAC(a[3], a[28]); SQRADDAC(a[4], a[27]); SQRADDAC(a[5], a[26]); SQRADDAC(a[6], a[25]); SQRADDAC(a[7], a[24]); SQRADDAC(a[8], a[23]); SQRADDAC(a[9], a[22]); SQRADDAC(a[10], a[21]); SQRADDAC(a[11], a[20]); SQRADDAC(a[12], a[19]); SQRADDAC(a[13], a[18]); SQRADDAC(a[14], a[17]); SQRADDAC(a[15], a[16]); SQRADDDB; 
   COMBA_STORE(b[31]);

   /* output 32 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[32]); SQRADDAC(a[1], a[31]); SQRADDAC(a[2], a[30]); SQRADDAC(a[3], a[29]); SQRADDAC(a[4], a[28]); SQRADDAC(a[5], a[27]); SQRADDAC(a[6], a[26]); SQRADDAC(a[7], a[25]); SQRADDAC(a[8], a[24]); SQRADDAC(a[9], a[23]); SQRADDAC(a[10], a[22]); SQRADDAC(a[11], a[21]); SQRADDAC(a[12], a[20]); SQRADDAC(a[13], a[19]); SQRADDAC(a[14], a[18]); SQRADDAC(a[15], a[17]); SQRADDDB; SQRADD(a[16], a[16]); 
   COMBA_STORE(b[32]);

   /* output 33 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[33]); SQRADDAC(a[1], a[32]); SQRADDAC(a[2], a[31]); SQRADDAC(a[3], a[30]); SQRADDAC(a[4], a[29]); SQRADDAC(a[5], a[28]); SQRADDAC(a[6], a[27]); SQRADDAC(a[7], a[26]); SQRADDAC(a[8], a[25]); SQRADDAC(a[9], a[24]); SQRADDAC(a[10], a[23]); SQRADDAC(a[11], a[22]); SQRADDAC(a[12], a[21]); SQRADDAC(a[13], a[20]); SQRADDAC(a[14], a[19]); SQRADDAC(a[15], a[18]); SQRADDAC(a[16], a[17]); SQRADDDB; 
   COMBA_STORE(b[33]);

   /* output 34 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[34]); SQRADDAC(a[1], a[33]); SQRADDAC(a[2], a[32]); SQRADDAC(a[3], a[31]); SQRADDAC(a[4], a[30]); SQRADDAC(a[5], a[29]); SQRADDAC(a[6], a[28]); SQRADDAC(a[7], a[27]); SQRADDAC(a[8], a[26]); SQRADDAC(a[9], a[25]); SQRADDAC(a[10], a[24]); SQRADDAC(a[11], a[23]); SQRADDAC(a[12], a[22]); SQRADDAC(a[13], a[21]); SQRADDAC(a[14], a[20]); SQRADDAC(a[15], a[19]); SQRADDAC(a[16], a[18]); SQRADDDB; SQRADD(a[17], a[17]); 
   COMBA_STORE(b[34]);

   /* output 35 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[35]); SQRADDAC(a[1], a[34]); SQRADDAC(a[2], a[33]); SQRADDAC(a[3], a[32]); SQRADDAC(a[4], a[31]); SQRADDAC(a[5], a[30]); SQRADDAC(a[6], a[29]); SQRADDAC(a[7], a[28]); SQRADDAC(a[8], a[27]); SQRADDAC(a[9], a[26]); SQRADDAC(a[10], a[25]); SQRADDAC(a[11], a[24]); SQRADDAC(a[12], a[23]); SQRADDAC(a[13], a[22]); SQRADDAC(a[14], a[21]); SQRADDAC(a[15], a[20]); SQRADDAC(a[16], a[19]); SQRADDAC(a[17], a[18]); SQRADDDB; 
   COMBA_STORE(b[35]);

   /* output 36 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[36]); SQRADDAC(a[1], a[35]); SQRADDAC(a[2], a[34]); SQRADDAC(a[3], a[33]); SQRADDAC(a[4], a[32]); SQRADDAC(a[5], a[31]); SQRADDAC(a[6], a[30]); SQRADDAC(a[7], a[29]); SQRADDAC(a[8], a[28]); SQRADDAC(a[9], a[27]); SQRADDAC(a[10], a[26]); SQRADDAC(a[11], a[25]); SQRADDAC(a[12], a[24]); SQRADDAC(a[13], a[23]); SQRADDAC(a[14], a[22]); SQRADDAC(a[15], a[21]); SQRADDAC(a[16], a[20]); SQRADDAC(a[17], a[19]); SQRADDDB; SQRADD(a[18], a[18]); 
   COMBA_STORE(b[36]);

   /* output 37 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[37]); SQRADDAC(a[1], a[36]); SQRADDAC(a[2], a[35]); SQRADDAC(a[3], a[34]); SQRADDAC(a[4], a[33]); SQRADDAC(a[5], a[32]); SQRADDAC(a[6], a[31]); SQRADDAC(a[7], a[30]); SQRADDAC(a[8], a[29]); SQRADDAC(a[9], a[28]); SQRADDAC(a[10], a[27]); SQRADDAC(a[11], a[26]); SQRADDAC(a[12], a[25]); SQRADDAC(a[13], a[24]); SQRADDAC(a[14], a[23]); SQRADDAC(a[15], a[22]); SQRADDAC(a[16], a[21]); SQRADDAC(a[17], a[20]); SQRADDAC(a[18], a[19]); SQRADDDB; 
   COMBA_STORE(b[37]);

   /* output 38 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[38]); SQRADDAC(a[1], a[37]); SQRADDAC(a[2], a[36]); SQRADDAC(a[3], a[35]); SQRADDAC(a[4], a[34]); SQRADDAC(a[5], a[33]); SQRADDAC(a[6], a[32]); SQRADDAC(a[7], a[31]); SQRADDAC(a[8], a[30]); SQRADDAC(a[9], a[29]); SQRADDAC(a[10], a[28]); SQRADDAC(a[11], a[27]); SQRADDAC(a[12], a[26]); SQRADDAC(a[13], a[25]); SQRADDAC(a[14], a[24]); SQRADDAC(a[15], a[23]); SQRADDAC(a[16], a[22]); SQRADDAC(a[17], a[21]); SQRADDAC(a[18], a[20]); SQRADDDB; SQRADD(a[19], a[19]); 
   COMBA_STORE(b[38]);

   /* output 39 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[39]); SQRADDAC(a[1], a[38]); SQRADDAC(a[2], a[37]); SQRADDAC(a[3], a[36]); SQRADDAC(a[4], a[35]); SQRADDAC(a[5], a[34]); SQRADDAC(a[6], a[33]); SQRADDAC(a[7], a[32]); SQRADDAC(a[8], a[31]); SQRADDAC(a[9], a[30]); SQRADDAC(a[10], a[29]); SQRADDAC(a[11], a[28]); SQRADDAC(a[12], a[27]); SQRADDAC(a[13], a[26]); SQRADDAC(a[14], a[25]); SQRADDAC(a[15], a[24]); SQRADDAC(a[16], a[23]); SQRADDAC(a[17], a[22]); SQRADDAC(a[18], a[21]); SQRADDAC(a[19], a[20]); SQRADDDB; 
   COMBA_STORE(b[39]);

   /* output 40 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[40]); SQRADDAC(a[1], a[39]); SQRADDAC(a[2], a[38]); SQRADDAC(a[3], a[37]); SQRADDAC(a[4], a[36]); SQRADDAC(a[5], a[35]); SQRADDAC(a[6], a[34]); SQRADDAC(a[7], a[33]); SQRADDAC(a[8], a[32]); SQRADDAC(a[9], a[31]); SQRADDAC(a[10], a[30]); SQRADDAC(a[11], a[29]); SQRADDAC(a[12], a[28]); SQRADDAC(a[13], a[27]); SQRADDAC(a[14], a[26]); SQRADDAC(a[15], a[25]); SQRADDAC(a[16], a[24]); SQRADDAC(a[17], a[23]); SQRADDAC(a[18], a[22]); SQRADDAC(a[19], a[21]); SQRADDDB; SQRADD(a[20], a[20]); 
   COMBA_STORE(b[40]);

   /* output 41 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[41]); SQRADDAC(a[1], a[40]); SQRADDAC(a[2], a[39]); SQRADDAC(a[3], a[38]); SQRADDAC(a[4], a[37]); SQRADDAC(a[5], a[36]); SQRADDAC(a[6], a[35]); SQRADDAC(a[7], a[34]); SQRADDAC(a[8], a[33]); SQRADDAC(a[9], a[32]); SQRADDAC(a[10], a[31]); SQRADDAC(a[11], a[30]); SQRADDAC(a[12], a[29]); SQRADDAC(a[13], a[28]); SQRADDAC(a[14], a[27]); SQRADDAC(a[15], a[26]); SQRADDAC(a[16], a[25]); SQRADDAC(a[17], a[24]); SQRADDAC(a[18], a[23]); SQRADDAC(a[19], a[22]); SQRADDAC(a[20], a[21]); SQRADDDB; 
   COMBA_STORE(b[41]);

   /* output 42 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[42]); SQRADDAC(a[1], a[41]); SQRADDAC(a[2], a[40]); SQRADDAC(a[3], a[39]); SQRADDAC(a[4], a[38]); SQRADDAC(a[5], a[37]); SQRADDAC(a[6], a[36]); SQRADDAC(a[7], a[35]); SQRADDAC(a[8], a[34]); SQRADDAC(a[9], a[33]); SQRADDAC(a[10], a[32]); SQRADDAC(a[11], a[31]); SQRADDAC(a[12], a[30]); SQRADDAC(a[13], a[29]); SQRADDAC(a[14], a[28]); SQRADDAC(a[15], a[27]); SQRADDAC(a[16], a[26]); SQRADDAC(a[17], a[25]); SQRADDAC(a[18], a[24]); SQRADDAC(a[19], a[23]); SQRADDAC(a[20], a[22]); SQRADDDB; SQRADD(a[21], a[21]); 
   COMBA_STORE(b[42]);

   /* output 43 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[43]); SQRADDAC(a[1], a[42]); SQRADDAC(a[2], a[41]); SQRADDAC(a[3], a[40]); SQRADDAC(a[4], a[39]); SQRADDAC(a[5], a[38]); SQRADDAC(a[6], a[37]); SQRADDAC(a[7], a[36]); SQRADDAC(a[8], a[35]); SQRADDAC(a[9], a[34]); SQRADDAC(a[10], a[33]); SQRADDAC(a[11], a[32]); SQRADDAC(a[12], a[31]); SQRADDAC(a[13], a[30]); SQRADDAC(a[14], a[29]); SQRADDAC(a[15], a[28]); SQRADDAC(a[16], a[27]); SQRADDAC(a[17], a[26]); SQRADDAC(a[18], a[25]); SQRADDAC(a[19], a[24]); SQRADDAC(a[20], a[23]); SQRADDAC(a[21], a[22]); SQRADDDB; 
   COMBA_STORE(b[43]);

   /* output 44 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[44]); SQRADDAC(a[1], a[43]); SQRADDAC(a[2], a[42]); SQRADDAC(a[3], a[41]); SQRADDAC(a[4], a[40]); SQRADDAC(a[5], a[39]); SQRADDAC(a[6], a[38]); SQRADDAC(a[7], a[37]); SQRADDAC(a[8], a[36]); SQRADDAC(a[9], a[35]); SQRADDAC(a[10], a[34]); SQRADDAC(a[11], a[33]); SQRADDAC(a[12], a[32]); SQRADDAC(a[13], a[31]); SQRADDAC(a[14], a[30]); SQRADDAC(a[15], a[29]); SQRADDAC(a[16], a[28]); SQRADDAC(a[17], a[27]); SQRADDAC(a[18], a[26]); SQRADDAC(a[19], a[25]); SQRADDAC(a[20], a[24]); SQRADDAC(a[21], a[23]); SQRADDDB; SQRADD(a[22], a[22]); 
   COMBA_STORE(b[44]);

   /* output 45 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[45]); SQRADDAC(a[1], a[44]); SQRADDAC(a[2], a[43]); SQRADDAC(a[3], a[42]); SQRADDAC(a[4], a[41]); SQRADDAC(a[5], a[40]); SQRADDAC(a[6], a[39]); SQRADDAC(a[7], a[38]); SQRADDAC(a[8], a[37]); SQRADDAC(a[9], a[36]); SQRADDAC(a[10], a[35]); SQRADDAC(a[11], a[34]); SQRADDAC(a[12], a[33]); SQRADDAC(a[13], a[32]); SQRADDAC(a[14], a[31]); SQRADDAC(a[15], a[30]); SQRADDAC(a[16], a[29]); SQRADDAC(a[17], a[28]); SQRADDAC(a[18], a[27]); SQRADDAC(a[19], a[26]); SQRADDAC(a[20], a[25]); SQRADDAC(a[21], a[24]); SQRADDAC(a[22], a[23]); SQRADDDB; 
   COMBA_STORE(b[45]);

   /* output 46 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[46]); SQRADDAC(a[1], a[45]); SQRADDAC(a[2], a[44]); SQRADDAC(a[3], a[43]); SQRADDAC(a[4], a[42]); SQRADDAC(a[5], a[41]); SQRADDAC(a[6], a[40]); SQRADDAC(a[7], a[39]); SQRADDAC(a[8], a[38]); SQRADDAC(a[9], a[37]); SQRADDAC(a[10], a[36]); SQRADDAC(a[11], a[35]); SQRADDAC(a[12], a[34]); SQRADDAC(a[13], a[33]); SQRADDAC(a[14], a[32]); SQRADDAC(a[15], a[31]); SQRADDAC(a[16], a[30]); SQRADDAC(a[17], a[29]); SQRADDAC(a[18], a[28]); SQRADDAC(a[19], a[27]); SQRADDAC(a[20], a[26]); SQRADDAC(a[21], a[25]); SQRADDAC(a[22], a[24]); SQRADDDB; SQRADD(a[23], a[23]); 
   COMBA_STORE(b[46]);

   /* output 47 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[47]); SQRADDAC(a[1], a[46]); SQRADDAC(a[2], a[45]); SQRADDAC(a[3], a[44]); SQRADDAC(a[4], a[43]); SQRADDAC(a[5], a[42]); SQRADDAC(a[6], a[41]); SQRADDAC(a[7], a[40]); SQRADDAC(a[8], a[39]); SQRADDAC(a[9], a[38]); SQRADDAC(a[10], a[37]); SQRADDAC(a[11], a[36]); SQRADDAC(a[12], a[35]); SQRADDAC(a[13], a[34]); SQRADDAC(a[14], a[33]); SQRADDAC(a[15], a[32]); SQRADDAC(a[16], a[31]); SQRADDAC(a[17], a[30]); SQRADDAC(a[18], a[29]); SQRADDAC(a[19], a[28]); SQRADDAC(a[20], a[27]); SQRADDAC(a[21], a[26]); SQRADDAC(a[22], a[25]); SQRADDAC(a[23], a[24]); SQRADDDB; 
   COMBA_STORE(b[47]);

   /* output 48 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[48]); SQRADDAC(a[1], a[47]); SQRADDAC(a[2], a[46]); SQRADDAC(a[3], a[45]); SQRADDAC(a[4], a[44]); SQRADDAC(a[5], a[43]); SQRADDAC(a[6], a[42]); SQRADDAC(a[7], a[41]); SQRADDAC(a[8], a[40]); SQRADDAC(a[9], a[39]); SQRADDAC(a[10], a[38]); SQRADDAC(a[11], a[37]); SQRADDAC(a[12], a[36]); SQRADDAC(a[13], a[35]); SQRADDAC(a[14], a[34]); SQRADDAC(a[15], a[33]); SQRADDAC(a[16], a[32]); SQRADDAC(a[17], a[31]); SQRADDAC(a[18], a[30]); SQRADDAC(a[19], a[29]); SQRADDAC(a[20], a[28]); SQRADDAC(a[21], a[27]); SQRADDAC(a[22], a[26]); SQRADDAC(a[23], a[25]); SQRADDDB; SQRADD(a[24], a[24]); 
   COMBA_STORE(b[48]);

   /* output 49 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[49]); SQRADDAC(a[1], a[48]); SQRADDAC(a[2], a[47]); SQRADDAC(a[3], a[46]); SQRADDAC(a[4], a[45]); SQRADDAC(a[5], a[44]); SQRADDAC(a[6], a[43]); SQRADDAC(a[7], a[42]); SQRADDAC(a[8], a[41]); SQRADDAC(a[9], a[40]); SQRADDAC(a[10], a[39]); SQRADDAC(a[11], a[38]); SQRADDAC(a[12], a[37]); SQRADDAC(a[13], a[36]); SQRADDAC(a[14], a[35]); SQRADDAC(a[15], a[34]); SQRADDAC(a[16], a[33]); SQRADDAC(a[17], a[32]); SQRADDAC(a[18], a[31]); SQRADDAC(a[19], a[30]); SQRADDAC(a[20], a[29]); SQRADDAC(a[21], a[28]); SQRADDAC(a[22], a[27]); SQRADDAC(a[23], a[26]); SQRADDAC(a[24], a[25]); SQRADDDB; 
   COMBA_STORE(b[49]);

   /* output 50 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[50]); SQRADDAC(a[1], a[49]); SQRADDAC(a[2], a[48]); SQRADDAC(a[3], a[47]); SQRADDAC(a[4], a[46]); SQRADDAC(a[5], a[45]); SQRADDAC(a[6], a[44]); SQRADDAC(a[7], a[43]); SQRADDAC(a[8], a[42]); SQRADDAC(a[9], a[41]); SQRADDAC(a[10], a[40]); SQRADDAC(a[11], a[39]); SQRADDAC(a[12], a[38]); SQRADDAC(a[13], a[37]); SQRADDAC(a[14], a[36]); SQRADDAC(a[15], a[35]); SQRADDAC(a[16], a[34]); SQRADDAC(a[17], a[33]); SQRADDAC(a[18], a[32]); SQRADDAC(a[19], a[31]); SQRADDAC(a[20], a[30]); SQRADDAC(a[21], a[29]); SQRADDAC(a[22], a[28]); SQRADDAC(a[23], a[27]); SQRADDAC(a[24], a[26]); SQRADDDB; SQRADD(a[25], a[25]); 
   COMBA_STORE(b[50]);

   /* output 51 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[51]); SQRADDAC(a[1], a[50]); SQRADDAC(a[2], a[49]); SQRADDAC(a[3], a[48]); SQRADDAC(a[4], a[47]); SQRADDAC(a[5], a[46]); SQRADDAC(a[6], a[45]); SQRADDAC(a[7], a[44]); SQRADDAC(a[8], a[43]); SQRADDAC(a[9], a[42]); SQRADDAC(a[10], a[41]); SQRADDAC(a[11], a[40]); SQRADDAC(a[12], a[39]); SQRADDAC(a[13], a[38]); SQRADDAC(a[14], a[37]); SQRADDAC(a[15], a[36]); SQRADDAC(a[16], a[35]); SQRADDAC(a[17], a[34]); SQRADDAC(a[18], a[33]); SQRADDAC(a[19], a[32]); SQRADDAC(a[20], a[31]); SQRADDAC(a[21], a[30]); SQRADDAC(a[22], a[29]); SQRADDAC(a[23], a[28]); SQRADDAC(a[24], a[27]); SQRADDAC(a[25], a[26]); SQRADDDB; 
   COMBA_STORE(b[51]);

   /* output 52 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[52]); SQRADDAC(a[1], a[51]); SQRADDAC(a[2], a[50]); SQRADDAC(a[3], a[49]); SQRADDAC(a[4], a[48]); SQRADDAC(a[5], a[47]); SQRADDAC(a[6], a[46]); SQRADDAC(a[7], a[45]); SQRADDAC(a[8], a[44]); SQRADDAC(a[9], a[43]); SQRADDAC(a[10], a[42]); SQRADDAC(a[11], a[41]); SQRADDAC(a[12], a[40]); SQRADDAC(a[13], a[39]); SQRADDAC(a[14], a[38]); SQRADDAC(a[15], a[37]); SQRADDAC(a[16], a[36]); SQRADDAC(a[17], a[35]); SQRADDAC(a[18], a[34]); SQRADDAC(a[19], a[33]); SQRADDAC(a[20], a[32]); SQRADDAC(a[21], a[31]); SQRADDAC(a[22], a[30]); SQRADDAC(a[23], a[29]); SQRADDAC(a[24], a[28]); SQRADDAC(a[25], a[27]); SQRADDDB; SQRADD(a[26], a[26]); 
   COMBA_STORE(b[52]);

   /* output 53 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[53]); SQRADDAC(a[1], a[52]); SQRADDAC(a[2], a[51]); SQRADDAC(a[3], a[50]); SQRADDAC(a[4], a[49]); SQRADDAC(a[5], a[48]); SQRADDAC(a[6], a[47]); SQRADDAC(a[7], a[46]); SQRADDAC(a[8], a[45]); SQRADDAC(a[9], a[44]); SQRADDAC(a[10], a[43]); SQRADDAC(a[11], a[42]); SQRADDAC(a[12], a[41]); SQRADDAC(a[13], a[40]); SQRADDAC(a[14], a[39]); SQRADDAC(a[15], a[38]); SQRADDAC(a[16], a[37]); SQRADDAC(a[17], a[36]); SQRADDAC(a[18], a[35]); SQRADDAC(a[19], a[34]); SQRADDAC(a[20], a[33]); SQRADDAC(a[21], a[32]); SQRADDAC(a[22], a[31]); SQRADDAC(a[23], a[30]); SQRADDAC(a[24], a[29]); SQRADDAC(a[25], a[28]); SQRADDAC(a[26], a[27]); SQRADDDB; 
   COMBA_STORE(b[53]);

   /* output 54 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[54]); SQRADDAC(a[1], a[53]); SQRADDAC(a[2], a[52]); SQRADDAC(a[3], a[51]); SQRADDAC(a[4], a[50]); SQRADDAC(a[5], a[49]); SQRADDAC(a[6], a[48]); SQRADDAC(a[7], a[47]); SQRADDAC(a[8], a[46]); SQRADDAC(a[9], a[45]); SQRADDAC(a[10], a[44]); SQRADDAC(a[11], a[43]); SQRADDAC(a[12], a[42]); SQRADDAC(a[13], a[41]); SQRADDAC(a[14], a[40]); SQRADDAC(a[15], a[39]); SQRADDAC(a[16], a[38]); SQRADDAC(a[17], a[37]); SQRADDAC(a[18], a[36]); SQRADDAC(a[19], a[35]); SQRADDAC(a[20], a[34]); SQRADDAC(a[21], a[33]); SQRADDAC(a[22], a[32]); SQRADDAC(a[23], a[31]); SQRADDAC(a[24], a[30]); SQRADDAC(a[25], a[29]); SQRADDAC(a[26], a[28]); SQRADDDB; SQRADD(a[27], a[27]); 
   COMBA_STORE(b[54]);

   /* output 55 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[55]); SQRADDAC(a[1], a[54]); SQRADDAC(a[2], a[53]); SQRADDAC(a[3], a[52]); SQRADDAC(a[4], a[51]); SQRADDAC(a[5], a[50]); SQRADDAC(a[6], a[49]); SQRADDAC(a[7], a[48]); SQRADDAC(a[8], a[47]); SQRADDAC(a[9], a[46]); SQRADDAC(a[10], a[45]); SQRADDAC(a[11], a[44]); SQRADDAC(a[12], a[43]); SQRADDAC(a[13], a[42]); SQRADDAC(a[14], a[41]); SQRADDAC(a[15], a[40]); SQRADDAC(a[16], a[39]); SQRADDAC(a[17], a[38]); SQRADDAC(a[18], a[37]); SQRADDAC(a[19], a[36]); SQRADDAC(a[20], a[35]); SQRADDAC(a[21], a[34]); SQRADDAC(a[22], a[33]); SQRADDAC(a[23], a[32]); SQRADDAC(a[24], a[31]); SQRADDAC(a[25], a[30]); SQRADDAC(a[26], a[29]); SQRADDAC(a[27], a[28]); SQRADDDB; 
   COMBA_STORE(b[55]);

   /* output 56 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[56]); SQRADDAC(a[1], a[55]); SQRADDAC(a[2], a[54]); SQRADDAC(a[3], a[53]); SQRADDAC(a[4], a[52]); SQRADDAC(a[5], a[51]); SQRADDAC(a[6], a[50]); SQRADDAC(a[7], a[49]); SQRADDAC(a[8], a[48]); SQRADDAC(a[9], a[47]); SQRADDAC(a[10], a[46]); SQRADDAC(a[11], a[45]); SQRADDAC(a[12], a[44]); SQRADDAC(a[13], a[43]); SQRADDAC(a[14], a[42]); SQRADDAC(a[15], a[41]); SQRADDAC(a[16], a[40]); SQRADDAC(a[17], a[39]); SQRADDAC(a[18], a[38]); SQRADDAC(a[19], a[37]); SQRADDAC(a[20], a[36]); SQRADDAC(a[21], a[35]); SQRADDAC(a[22], a[34]); SQRADDAC(a[23], a[33]); SQRADDAC(a[24], a[32]); SQRADDAC(a[25], a[31]); SQRADDAC(a[26], a[30]); SQRADDAC(a[27], a[29]); SQRADDDB; SQRADD(a[28], a[28]); 
   COMBA_STORE(b[56]);

   /* output 57 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[57]); SQRADDAC(a[1], a[56]); SQRADDAC(a[2], a[55]); SQRADDAC(a[3], a[54]); SQRADDAC(a[4], a[53]); SQRADDAC(a[5], a[52]); SQRADDAC(a[6], a[51]); SQRADDAC(a[7], a[50]); SQRADDAC(a[8], a[49]); SQRADDAC(a[9], a[48]); SQRADDAC(a[10], a[47]); SQRADDAC(a[11], a[46]); SQRADDAC(a[12], a[45]); SQRADDAC(a[13], a[44]); SQRADDAC(a[14], a[43]); SQRADDAC(a[15], a[42]); SQRADDAC(a[16], a[41]); SQRADDAC(a[17], a[40]); SQRADDAC(a[18], a[39]); SQRADDAC(a[19], a[38]); SQRADDAC(a[20], a[37]); SQRADDAC(a[21], a[36]); SQRADDAC(a[22], a[35]); SQRADDAC(a[23], a[34]); SQRADDAC(a[24], a[33]); SQRADDAC(a[25], a[32]); SQRADDAC(a[26], a[31]); SQRADDAC(a[27], a[30]); SQRADDAC(a[28], a[29]); SQRADDDB; 
   COMBA_STORE(b[57]);

   /* output 58 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[58]); SQRADDAC(a[1], a[57]); SQRADDAC(a[2], a[56]); SQRADDAC(a[3], a[55]); SQRADDAC(a[4], a[54]); SQRADDAC(a[5], a[53]); SQRADDAC(a[6], a[52]); SQRADDAC(a[7], a[51]); SQRADDAC(a[8], a[50]); SQRADDAC(a[9], a[49]); SQRADDAC(a[10], a[48]); SQRADDAC(a[11], a[47]); SQRADDAC(a[12], a[46]); SQRADDAC(a[13], a[45]); SQRADDAC(a[14], a[44]); SQRADDAC(a[15], a[43]); SQRADDAC(a[16], a[42]); SQRADDAC(a[17], a[41]); SQRADDAC(a[18], a[40]); SQRADDAC(a[19], a[39]); SQRADDAC(a[20], a[38]); SQRADDAC(a[21], a[37]); SQRADDAC(a[22], a[36]); SQRADDAC(a[23], a[35]); SQRADDAC(a[24], a[34]); SQRADDAC(a[25], a[33]); SQRADDAC(a[26], a[32]); SQRADDAC(a[27], a[31]); SQRADDAC(a[28], a[30]); SQRADDDB; SQRADD(a[29], a[29]); 
   COMBA_STORE(b[58]);

   /* output 59 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[59]); SQRADDAC(a[1], a[58]); SQRADDAC(a[2], a[57]); SQRADDAC(a[3], a[56]); SQRADDAC(a[4], a[55]); SQRADDAC(a[5], a[54]); SQRADDAC(a[6], a[53]); SQRADDAC(a[7], a[52]); SQRADDAC(a[8], a[51]); SQRADDAC(a[9], a[50]); SQRADDAC(a[10], a[49]); SQRADDAC(a[11], a[48]); SQRADDAC(a[12], a[47]); SQRADDAC(a[13], a[46]); SQRADDAC(a[14], a[45]); SQRADDAC(a[15], a[44]); SQRADDAC(a[16], a[43]); SQRADDAC(a[17], a[42]); SQRADDAC(a[18], a[41]); SQRADDAC(a[19], a[40]); SQRADDAC(a[20], a[39]); SQRADDAC(a[21], a[38]); SQRADDAC(a[22], a[37]); SQRADDAC(a[23], a[36]); SQRADDAC(a[24], a[35]); SQRADDAC(a[25], a[34]); SQRADDAC(a[26], a[33]); SQRADDAC(a[27], a[32]); SQRADDAC(a[28], a[31]); SQRADDAC(a[29], a[30]); SQRADDDB; 
   COMBA_STORE(b[59]);

   /* output 60 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[60]); SQRADDAC(a[1], a[59]); SQRADDAC(a[2], a[58]); SQRADDAC(a[3], a[57]); SQRADDAC(a[4], a[56]); SQRADDAC(a[5], a[55]); SQRADDAC(a[6], a[54]); SQRADDAC(a[7], a[53]); SQRADDAC(a[8], a[52]); SQRADDAC(a[9], a[51]); SQRADDAC(a[10], a[50]); SQRADDAC(a[11], a[49]); SQRADDAC(a[12], a[48]); SQRADDAC(a[13], a[47]); SQRADDAC(a[14], a[46]); SQRADDAC(a[15], a[45]); SQRADDAC(a[16], a[44]); SQRADDAC(a[17], a[43]); SQRADDAC(a[18], a[42]); SQRADDAC(a[19], a[41]); SQRADDAC(a[20], a[40]); SQRADDAC(a[21], a[39]); SQRADDAC(a[22], a[38]); SQRADDAC(a[23], a[37]); SQRADDAC(a[24], a[36]); SQRADDAC(a[25], a[35]); SQRADDAC(a[26], a[34]); SQRADDAC(a[27], a[33]); SQRADDAC(a[28], a[32]); SQRADDAC(a[29], a[31]); SQRADDDB; SQRADD(a[30], a[30]); 
   COMBA_STORE(b[60]);

   /* output 61 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[61]); SQRADDAC(a[1], a[60]); SQRADDAC(a[2], a[59]); SQRADDAC(a[3], a[58]); SQRADDAC(a[4], a[57]); SQRADDAC(a[5], a[56]); SQRADDAC(a[6], a[55]); SQRADDAC(a[7], a[54]); SQRADDAC(a[8], a[53]); SQRADDAC(a[9], a[52]); SQRADDAC(a[10], a[51]); SQRADDAC(a[11], a[50]); SQRADDAC(a[12], a[49]); SQRADDAC(a[13], a[48]); SQRADDAC(a[14], a[47]); SQRADDAC(a[15], a[46]); SQRADDAC(a[16], a[45]); SQRADDAC(a[17], a[44]); SQRADDAC(a[18], a[43]); SQRADDAC(a[19], a[42]); SQRADDAC(a[20], a[41]); SQRADDAC(a[21], a[40]); SQRADDAC(a[22], a[39]); SQRADDAC(a[23], a[38]); SQRADDAC(a[24], a[37]); SQRADDAC(a[25], a[36]); SQRADDAC(a[26], a[35]); SQRADDAC(a[27], a[34]); SQRADDAC(a[28], a[33]); SQRADDAC(a[29], a[32]); SQRADDAC(a[30], a[31]); SQRADDDB; 
   COMBA_STORE(b[61]);

   /* output 62 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[62]); SQRADDAC(a[1], a[61]); SQRADDAC(a[2], a[60]); SQRADDAC(a[3], a[59]); SQRADDAC(a[4], a[58]); SQRADDAC(a[5], a[57]); SQRADDAC(a[6], a[56]); SQRADDAC(a[7], a[55]); SQRADDAC(a[8], a[54]); SQRADDAC(a[9], a[53]); SQRADDAC(a[10], a[52]); SQRADDAC(a[11], a[51]); SQRADDAC(a[12], a[50]); SQRADDAC(a[13], a[49]); SQRADDAC(a[14], a[48]); SQRADDAC(a[15], a[47]); SQRADDAC(a[16], a[46]); SQRADDAC(a[17], a[45]); SQRADDAC(a[18], a[44]); SQRADDAC(a[19], a[43]); SQRADDAC(a[20], a[42]); SQRADDAC(a[21], a[41]); SQRADDAC(a[22], a[40]); SQRADDAC(a[23], a[39]); SQRADDAC(a[24], a[38]); SQRADDAC(a[25], a[37]); SQRADDAC(a[26], a[36]); SQRADDAC(a[27], a[35]); SQRADDAC(a[28], a[34]); SQRADDAC(a[29], a[33]); SQRADDAC(a[30], a[32]); SQRADDDB; SQRADD(a[31], a[31]); 
   COMBA_STORE(b[62]);

   /* output 63 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[63]); SQRADDAC(a[1], a[62]); SQRADDAC(a[2], a[61]); SQRADDAC(a[3], a[60]); SQRADDAC(a[4], a[59]); SQRADDAC(a[5], a[58]); SQRADDAC(a[6], a[57]); SQRADDAC(a[7], a[56]); SQRADDAC(a[8], a[55]); SQRADDAC(a[9], a[54]); SQRADDAC(a[10], a[53]); SQRADDAC(a[11], a[52]); SQRADDAC(a[12], a[51]); SQRADDAC(a[13], a[50]); SQRADDAC(a[14], a[49]); SQRADDAC(a[15], a[48]); SQRADDAC(a[16], a[47]); SQRADDAC(a[17], a[46]); SQRADDAC(a[18], a[45]); SQRADDAC(a[19], a[44]); SQRADDAC(a[20], a[43]); SQRADDAC(a[21], a[42]); SQRADDAC(a[22], a[41]); SQRADDAC(a[23], a[40]); SQRADDAC(a[24], a[39]); SQRADDAC(a[25], a[38]); SQRADDAC(a[26], a[37]); SQRADDAC(a[27], a[36]); SQRADDAC(a[28], a[35]); SQRADDAC(a[29], a[34]); SQRADDAC(a[30], a[33]); SQRADDAC(a[31], a[32]); SQRADDDB; 
   COMBA_STORE(b[63]);

   /* output 64 */
   CARRY_FORWARD;
   SQRADDSC(a[1], a[63]); SQRADDAC(a[2], a[62]); SQRADDAC(a[3], a[61]); SQRADDAC(a[4], a[60]); SQRADDAC(a[5], a[59]); SQRADDAC(a[6], a[58]); SQRADDAC(a[7], a[57]); SQRADDAC(a[8], a[56]); SQRADDAC(a[9], a[55]); SQRADDAC(a[10], a[54]); SQRADDAC(a[11], a[53]); SQRADDAC(a[12], a[52]); SQRADDAC(a[13], a[51]); SQRADDAC(a[14], a[50]); SQRADDAC(a[15], a[49]); SQRADDAC(a[16], a[48]); SQRADDAC(a[17], a[47]); SQRADDAC(a[18], a[46]); SQRADDAC(a[19], a[45]); SQRADDAC(a[20], a[44]); SQRADDAC(a[21], a[43]); SQRADDAC(a[22], a[42]); SQRADDAC(a[23], a[41]); SQRADDAC(a[24], a[40]); SQRADDAC(a[25], a[39]); SQRADDAC(a[26], a[38]); SQRADDAC(a[27], a[37]); SQRADDAC(a[28], a[36]); SQRADDAC(a[29], a[35]); SQRADDAC(a[30], a[34]); SQRADDAC(a[31], a[33]); SQRADDDB; SQRADD(a[32], a[32]); 
   COMBA_STORE(b[64]);

   /* output 65 */
   CARRY_FORWARD;
   SQRADDSC(a[2], a[63]); SQRADDAC(a[3], a[62]); SQRADDAC(a[4], a[61]); SQRADDAC(a[5], a[60]); SQRADDAC(a[6], a[59]); SQRADDAC(a[7], a[58]); SQRADDAC(a[8], a[57]); SQRADDAC(a[9], a[56]); SQRADDAC(a[10], a[55]); SQRADDAC(a[11], a[54]); SQRADDAC(a[12], a[53]); SQRADDAC(a[13], a[52]); SQRADDAC(a[14], a[51]); SQRADDAC(a[15], a[50]); SQRADDAC(a[16], a[49]); SQRADDAC(a[17], a[48]); SQRADDAC(a[18], a[47]); SQRADDAC(a[19], a[46]); SQRADDAC(a[20], a[45]); SQRADDAC(a[21], a[44]); SQRADDAC(a[22], a[43]); SQRADDAC(a[23], a[42]); SQRADDAC(a[24], a[41]); SQRADDAC(a[25], a[40]); SQRADDAC(a[26], a[39]); SQRADDAC(a[27], a[38]); SQRADDAC(a[28], a[37]); SQRADDAC(a[29], a[36]); SQRADDAC(a[30], a[35]); SQRADDAC(a[31], a[34]); SQRADDAC(a[32], a[33]); SQRADDDB; 
   COMBA_STORE(b[65]);

   /* output 66 */
   CARRY_FORWARD;
   SQRADDSC(a[3], a[63]); SQRADDAC(a[4], a[62]); SQRADDAC(a[5], a[61]); SQRADDAC(a[6], a[60]); SQRADDAC(a[7], a[59]); SQRADDAC(a[8], a[58]); SQRADDAC(a[9], a[57]); SQRADDAC(a[10], a[56]); SQRADDAC(a[11], a[55]); SQRADDAC(a[12], a[54]); SQRADDAC(a[13], a[53]); SQRADDAC(a[14], a[52]); SQRADDAC(a[15], a[51]); SQRADDAC(a[16], a[50]); SQRADDAC(a[17], a[49]); SQRADDAC(a[18], a[48]); SQRADDAC(a[19], a[47]); SQRADDAC(a[20], a[46]); SQRADDAC(a[21], a[45]); SQRADDAC(a[22], a[44]); SQRADDAC(a[23], a[43]); SQRADDAC(a[24], a[42]); SQRADDAC(a[25], a[41]); SQRADDAC(a[26], a[40]); SQRADDAC(a[27], a[39]); SQRADDAC(a[28], a[38]); SQRADDAC(a[29], a[37]); SQRADDAC(a[30], a[36]); SQRADDAC(a[31], a[35]); SQRADDAC(a[32], a[34]); SQRADDDB; SQRADD(a[33], a[33]); 
   COMBA_STORE(b[66]);

   /* output 67 */
   CARRY_FORWARD;
   SQRADDSC(a[4], a[63]); SQRADDAC(a[5], a[62]); SQRADDAC(a[6], a[61]); SQRADDAC(a[7], a[60]); SQRADDAC(a[8], a[59]); SQRADDAC(a[9], a[58]); SQRADDAC(a[10], a[57]); SQRADDAC(a[11], a[56]); SQRADDAC(a[12], a[55]); SQRADDAC(a[13], a[54]); SQRADDAC(a[14], a[53]); SQRADDAC(a[15], a[52]); SQRADDAC(a[16], a[51]); SQRADDAC(a[17], a[50]); SQRADDAC(a[18], a[49]); SQRADDAC(a[19], a[48]); SQRADDAC(a[20], a[47]); SQRADDAC(a[21], a[46]); SQRADDAC(a[22], a[45]); SQRADDAC(a[23], a[44]); SQRADDAC(a[24], a[43]); SQRADDAC(a[25], a[42]); SQRADDAC(a[26], a[41]); SQRADDAC(a[27], a[40]); SQRADDAC(a[28], a[39]); SQRADDAC(a[29], a[38]); SQRADDAC(a[30], a[37]); SQRADDAC(a[31], a[36]); SQRADDAC(a[32], a[35]); SQRADDAC(a[33], a[34]); SQRADDDB; 
   COMBA_STORE(b[67]);

   /* output 68 */
   CARRY_FORWARD;
   SQRADDSC(a[5], a[63]); SQRADDAC(a[6], a[62]); SQRADDAC(a[7], a[61]); SQRADDAC(a[8], a[60]); SQRADDAC(a[9], a[59]); SQRADDAC(a[10], a[58]); SQRADDAC(a[11], a[57]); SQRADDAC(a[12], a[56]); SQRADDAC(a[13], a[55]); SQRADDAC(a[14], a[54]); SQRADDAC(a[15], a[53]); SQRADDAC(a[16], a[52]); SQRADDAC(a[17], a[51]); SQRADDAC(a[18], a[50]); SQRADDAC(a[19], a[49]); SQRADDAC(a[20], a[48]); SQRADDAC(a[21], a[47]); SQRADDAC(a[22], a[46]); SQRADDAC(a[23], a[45]); SQRADDAC(a[24], a[44]); SQRADDAC(a[25], a[43]); SQRADDAC(a[26], a[42]); SQRADDAC(a[27], a[41]); SQRADDAC(a[28], a[40]); SQRADDAC(a[29], a[39]); SQRADDAC(a[30], a[38]); SQRADDAC(a[31], a[37]); SQRADDAC(a[32], a[36]); SQRADDAC(a[33], a[35]); SQRADDDB; SQRADD(a[34], a[34]); 
   COMBA_STORE(b[68]);

   /* output 69 */
   CARRY_FORWARD;
   SQRADDSC(a[6], a[63]); SQRADDAC(a[7], a[62]); SQRADDAC(a[8], a[61]); SQRADDAC(a[9], a[60]); SQRADDAC(a[10], a[59]); SQRADDAC(a[11], a[58]); SQRADDAC(a[12], a[57]); SQRADDAC(a[13], a[56]); SQRADDAC(a[14], a[55]); SQRADDAC(a[15], a[54]); SQRADDAC(a[16], a[53]); SQRADDAC(a[17], a[52]); SQRADDAC(a[18], a[51]); SQRADDAC(a[19], a[50]); SQRADDAC(a[20], a[49]); SQRADDAC(a[21], a[48]); SQRADDAC(a[22], a[47]); SQRADDAC(a[23], a[46]); SQRADDAC(a[24], a[45]); SQRADDAC(a[25], a[44]); SQRADDAC(a[26], a[43]); SQRADDAC(a[27], a[42]); SQRADDAC(a[28], a[41]); SQRADDAC(a[29], a[40]); SQRADDAC(a[30], a[39]); SQRADDAC(a[31], a[38]); SQRADDAC(a[32], a[37]); SQRADDAC(a[33], a[36]); SQRADDAC(a[34], a[35]); SQRADDDB; 
   COMBA_STORE(b[69]);

   /* output 70 */
   CARRY_FORWARD;
   SQRADDSC(a[7], a[63]); SQRADDAC(a[8], a[62]); SQRADDAC(a[9], a[61]); SQRADDAC(a[10], a[60]); SQRADDAC(a[11], a[59]); SQRADDAC(a[12], a[58]); SQRADDAC(a[13], a[57]); SQRADDAC(a[14], a[56]); SQRADDAC(a[15], a[55]); SQRADDAC(a[16], a[54]); SQRADDAC(a[17], a[53]); SQRADDAC(a[18], a[52]); SQRADDAC(a[19], a[51]); SQRADDAC(a[20], a[50]); SQRADDAC(a[21], a[49]); SQRADDAC(a[22], a[48]); SQRADDAC(a[23], a[47]); SQRADDAC(a[24], a[46]); SQRADDAC(a[25], a[45]); SQRADDAC(a[26], a[44]); SQRADDAC(a[27], a[43]); SQRADDAC(a[28], a[42]); SQRADDAC(a[29], a[41]); SQRADDAC(a[30], a[40]); SQRADDAC(a[31], a[39]); SQRADDAC(a[32], a[38]); SQRADDAC(a[33], a[37]); SQRADDAC(a[34], a[36]); SQRADDDB; SQRADD(a[35], a[35]); 
   COMBA_STORE(b[70]);

   /* output 71 */
   CARRY_FORWARD;
   SQRADDSC(a[8], a[63]); SQRADDAC(a[9], a[62]); SQRADDAC(a[10], a[61]); SQRADDAC(a[11], a[60]); SQRADDAC(a[12], a[59]); SQRADDAC(a[13], a[58]); SQRADDAC(a[14], a[57]); SQRADDAC(a[15], a[56]); SQRADDAC(a[16], a[55]); SQRADDAC(a[17], a[54]); SQRADDAC(a[18], a[53]); SQRADDAC(a[19], a[52]); SQRADDAC(a[20], a[51]); SQRADDAC(a[21], a[50]); SQRADDAC(a[22], a[49]); SQRADDAC(a[23], a[48]); SQRADDAC(a[24], a[47]); SQRADDAC(a[25], a[46]); SQRADDAC(a[26], a[45]); SQRADDAC(a[27], a[44]); SQRADDAC(a[28], a[43]); SQRADDAC(a[29], a[42]); SQRADDAC(a[30], a[41]); SQRADDAC(a[31], a[40]); SQRADDAC(a[32], a[39]); SQRADDAC(a[33], a[38]); SQRADDAC(a[34], a[37]); SQRADDAC(a[35], a[36]); SQRADDDB; 
   COMBA_STORE(b[71]);

   /* output 72 */
   CARRY_FORWARD;
   SQRADDSC(a[9], a[63]); SQRADDAC(a[10], a[62]); SQRADDAC(a[11], a[61]); SQRADDAC(a[12], a[60]); SQRADDAC(a[13], a[59]); SQRADDAC(a[14], a[58]); SQRADDAC(a[15], a[57]); SQRADDAC(a[16], a[56]); SQRADDAC(a[17], a[55]); SQRADDAC(a[18], a[54]); SQRADDAC(a[19], a[53]); SQRADDAC(a[20], a[52]); SQRADDAC(a[21], a[51]); SQRADDAC(a[22], a[50]); SQRADDAC(a[23], a[49]); SQRADDAC(a[24], a[48]); SQRADDAC(a[25], a[47]); SQRADDAC(a[26], a[46]); SQRADDAC(a[27], a[45]); SQRADDAC(a[28], a[44]); SQRADDAC(a[29], a[43]); SQRADDAC(a[30], a[42]); SQRADDAC(a[31], a[41]); SQRADDAC(a[32], a[40]); SQRADDAC(a[33], a[39]); SQRADDAC(a[34], a[38]); SQRADDAC(a[35], a[37]); SQRADDDB; SQRADD(a[36], a[36]); 
   COMBA_STORE(b[72]);

   /* output 73 */
   CARRY_FORWARD;
   SQRADDSC(a[10], a[63]); SQRADDAC(a[11], a[62]); SQRADDAC(a[12], a[61]); SQRADDAC(a[13], a[60]); SQRADDAC(a[14], a[59]); SQRADDAC(a[15], a[58]); SQRADDAC(a[16], a[57]); SQRADDAC(a[17], a[56]); SQRADDAC(a[18], a[55]); SQRADDAC(a[19], a[54]); SQRADDAC(a[20], a[53]); SQRADDAC(a[21], a[52]); SQRADDAC(a[22], a[51]); SQRADDAC(a[23], a[50]); SQRADDAC(a[24], a[49]); SQRADDAC(a[25], a[48]); SQRADDAC(a[26], a[47]); SQRADDAC(a[27], a[46]); SQRADDAC(a[28], a[45]); SQRADDAC(a[29], a[44]); SQRADDAC(a[30], a[43]); SQRADDAC(a[31], a[42]); SQRADDAC(a[32], a[41]); SQRADDAC(a[33], a[40]); SQRADDAC(a[34], a[39]); SQRADDAC(a[35], a[38]); SQRADDAC(a[36], a[37]); SQRADDDB; 
   COMBA_STORE(b[73]);

   /* output 74 */
   CARRY_FORWARD;
   SQRADDSC(a[11], a[63]); SQRADDAC(a[12], a[62]); SQRADDAC(a[13], a[61]); SQRADDAC(a[14], a[60]); SQRADDAC(a[15], a[59]); SQRADDAC(a[16], a[58]); SQRADDAC(a[17], a[57]); SQRADDAC(a[18], a[56]); SQRADDAC(a[19], a[55]); SQRADDAC(a[20], a[54]); SQRADDAC(a[21], a[53]); SQRADDAC(a[22], a[52]); SQRADDAC(a[23], a[51]); SQRADDAC(a[24], a[50]); SQRADDAC(a[25], a[49]); SQRADDAC(a[26], a[48]); SQRADDAC(a[27], a[47]); SQRADDAC(a[28], a[46]); SQRADDAC(a[29], a[45]); SQRADDAC(a[30], a[44]); SQRADDAC(a[31], a[43]); SQRADDAC(a[32], a[42]); SQRADDAC(a[33], a[41]); SQRADDAC(a[34], a[40]); SQRADDAC(a[35], a[39]); SQRADDAC(a[36], a[38]); SQRADDDB; SQRADD(a[37], a[37]); 
   COMBA_STORE(b[74]);

   /* output 75 */
   CARRY_FORWARD;
   SQRADDSC(a[12], a[63]); SQRADDAC(a[13], a[62]); SQRADDAC(a[14], a[61]); SQRADDAC(a[15], a[60]); SQRADDAC(a[16], a[59]); SQRADDAC(a[17], a[58]); SQRADDAC(a[18], a[57]); SQRADDAC(a[19], a[56]); SQRADDAC(a[20], a[55]); SQRADDAC(a[21], a[54]); SQRADDAC(a[22], a[53]); SQRADDAC(a[23], a[52]); SQRADDAC(a[24], a[51]); SQRADDAC(a[25], a[50]); SQRADDAC(a[26], a[49]); SQRADDAC(a[27], a[48]); SQRADDAC(a[28], a[47]); SQRADDAC(a[29], a[46]); SQRADDAC(a[30], a[45]); SQRADDAC(a[31], a[44]); SQRADDAC(a[32], a[43]); SQRADDAC(a[33], a[42]); SQRADDAC(a[34], a[41]); SQRADDAC(a[35], a[40]); SQRADDAC(a[36], a[39]); SQRADDAC(a[37], a[38]); SQRADDDB; 
   COMBA_STORE(b[75]);

   /* output 76 */
   CARRY_FORWARD;
   SQRADDSC(a[13], a[63]); SQRADDAC(a[14], a[62]); SQRADDAC(a[15], a[61]); SQRADDAC(a[16], a[60]); SQRADDAC(a[17], a[59]); SQRADDAC(a[18], a[58]); SQRADDAC(a[19], a[57]); SQRADDAC(a[20], a[56]); SQRADDAC(a[21], a[55]); SQRADDAC(a[22], a[54]); SQRADDAC(a[23], a[53]); SQRADDAC(a[24], a[52]); SQRADDAC(a[25], a[51]); SQRADDAC(a[26], a[50]); SQRADDAC(a[27], a[49]); SQRADDAC(a[28], a[48]); SQRADDAC(a[29], a[47]); SQRADDAC(a[30], a[46]); SQRADDAC(a[31], a[45]); SQRADDAC(a[32], a[44]); SQRADDAC(a[33], a[43]); SQRADDAC(a[34], a[42]); SQRADDAC(a[35], a[41]); SQRADDAC(a[36], a[40]); SQRADDAC(a[37], a[39]); SQRADDDB; SQRADD(a[38], a[38]); 
   COMBA_STORE(b[76]);

   /* output 77 */
   CARRY_FORWARD;
   SQRADDSC(a[14], a[63]); SQRADDAC(a[15], a[62]); SQRADDAC(a[16], a[61]); SQRADDAC(a[17], a[60]); SQRADDAC(a[18], a[59]); SQRADDAC(a[19], a[58]); SQRADDAC(a[20], a[57]); SQRADDAC(a[21], a[56]); SQRADDAC(a[22], a[55]); SQRADDAC(a[23], a[54]); SQRADDAC(a[24], a[53]); SQRADDAC(a[25], a[52]); SQRADDAC(a[26], a[51]); SQRADDAC(a[27], a[50]); SQRADDAC(a[28], a[49]); SQRADDAC(a[29], a[48]); SQRADDAC(a[30], a[47]); SQRADDAC(a[31], a[46]); SQRADDAC(a[32], a[45]); SQRADDAC(a[33], a[44]); SQRADDAC(a[34], a[43]); SQRADDAC(a[35], a[42]); SQRADDAC(a[36], a[41]); SQRADDAC(a[37], a[40]); SQRADDAC(a[38], a[39]); SQRADDDB; 
   COMBA_STORE(b[77]);

   /* output 78 */
   CARRY_FORWARD;
   SQRADDSC(a[15], a[63]); SQRADDAC(a[16], a[62]); SQRADDAC(a[17], a[61]); SQRADDAC(a[18], a[60]); SQRADDAC(a[19], a[59]); SQRADDAC(a[20], a[58]); SQRADDAC(a[21], a[57]); SQRADDAC(a[22], a[56]); SQRADDAC(a[23], a[55]); SQRADDAC(a[24], a[54]); SQRADDAC(a[25], a[53]); SQRADDAC(a[26], a[52]); SQRADDAC(a[27], a[51]); SQRADDAC(a[28], a[50]); SQRADDAC(a[29], a[49]); SQRADDAC(a[30], a[48]); SQRADDAC(a[31], a[47]); SQRADDAC(a[32], a[46]); SQRADDAC(a[33], a[45]); SQRADDAC(a[34], a[44]); SQRADDAC(a[35], a[43]); SQRADDAC(a[36], a[42]); SQRADDAC(a[37], a[41]); SQRADDAC(a[38], a[40]); SQRADDDB; SQRADD(a[39], a[39]); 
   COMBA_STORE(b[78]);

   /* output 79 */
   CARRY_FORWARD;
   SQRADDSC(a[16], a[63]); SQRADDAC(a[17], a[62]); SQRADDAC(a[18], a[61]); SQRADDAC(a[19], a[60]); SQRADDAC(a[20], a[59]); SQRADDAC(a[21], a[58]); SQRADDAC(a[22], a[57]); SQRADDAC(a[23], a[56]); SQRADDAC(a[24], a[55]); SQRADDAC(a[25], a[54]); SQRADDAC(a[26], a[53]); SQRADDAC(a[27], a[52]); SQRADDAC(a[28], a[51]); SQRADDAC(a[29], a[50]); SQRADDAC(a[30], a[49]); SQRADDAC(a[31], a[48]); SQRADDAC(a[32], a[47]); SQRADDAC(a[33], a[46]); SQRADDAC(a[34], a[45]); SQRADDAC(a[35], a[44]); SQRADDAC(a[36], a[43]); SQRADDAC(a[37], a[42]); SQRADDAC(a[38], a[41]); SQRADDAC(a[39], a[40]); SQRADDDB; 
   COMBA_STORE(b[79]);

   /* output 80 */
   CARRY_FORWARD;
   SQRADDSC(a[17], a[63]); SQRADDAC(a[18], a[62]); SQRADDAC(a[19], a[61]); SQRADDAC(a[20], a[60]); SQRADDAC(a[21], a[59]); SQRADDAC(a[22], a[58]); SQRADDAC(a[23], a[57]); SQRADDAC(a[24], a[56]); SQRADDAC(a[25], a[55]); SQRADDAC(a[26], a[54]); SQRADDAC(a[27], a[53]); SQRADDAC(a[28], a[52]); SQRADDAC(a[29], a[51]); SQRADDAC(a[30], a[50]); SQRADDAC(a[31], a[49]); SQRADDAC(a[32], a[48]); SQRADDAC(a[33], a[47]); SQRADDAC(a[34], a[46]); SQRADDAC(a[35], a[45]); SQRADDAC(a[36], a[44]); SQRADDAC(a[37], a[43]); SQRADDAC(a[38], a[42]); SQRADDAC(a[39], a[41]); SQRADDDB; SQRADD(a[40], a[40]); 
   COMBA_STORE(b[80]);

   /* output 81 */
   CARRY_FORWARD;
   SQRADDSC(a[18], a[63]); SQRADDAC(a[19], a[62]); SQRADDAC(a[20], a[61]); SQRADDAC(a[21], a[60]); SQRADDAC(a[22], a[59]); SQRADDAC(a[23], a[58]); SQRADDAC(a[24], a[57]); SQRADDAC(a[25], a[56]); SQRADDAC(a[26], a[55]); SQRADDAC(a[27], a[54]); SQRADDAC(a[28], a[53]); SQRADDAC(a[29], a[52]); SQRADDAC(a[30], a[51]); SQRADDAC(a[31], a[50]); SQRADDAC(a[32], a[49]); SQRADDAC(a[33], a[48]); SQRADDAC(a[34], a[47]); SQRADDAC(a[35], a[46]); SQRADDAC(a[36], a[45]); SQRADDAC(a[37], a[44]); SQRADDAC(a[38], a[43]); SQRADDAC(a[39], a[42]); SQRADDAC(a[40], a[41]); SQRADDDB; 
   COMBA_STORE(b[81]);

   /* output 82 */
   CARRY_FORWARD;
   SQRADDSC(a[19], a[63]); SQRADDAC(a[20], a[62]); SQRADDAC(a[21], a[61]); SQRADDAC(a[22], a[60]); SQRADDAC(a[23], a[59]); SQRADDAC(a[24], a[58]); SQRADDAC(a[25], a[57]); SQRADDAC(a[26], a[56]); SQRADDAC(a[27], a[55]); SQRADDAC(a[28], a[54]); SQRADDAC(a[29], a[53]); SQRADDAC(a[30], a[52]); SQRADDAC(a[31], a[51]); SQRADDAC(a[32], a[50]); SQRADDAC(a[33], a[49]); SQRADDAC(a[34], a[48]); SQRADDAC(a[35], a[47]); SQRADDAC(a[36], a[46]); SQRADDAC(a[37], a[45]); SQRADDAC(a[38], a[44]); SQRADDAC(a[39], a[43]); SQRADDAC(a[40], a[42]); SQRADDDB; SQRADD(a[41], a[41]); 
   COMBA_STORE(b[82]);

   /* output 83 */
   CARRY_FORWARD;
   SQRADDSC(a[20], a[63]); SQRADDAC(a[21], a[62]); SQRADDAC(a[22], a[61]); SQRADDAC(a[23], a[60]); SQRADDAC(a[24], a[59]); SQRADDAC(a[25], a[58]); SQRADDAC(a[26], a[57]); SQRADDAC(a[27], a[56]); SQRADDAC(a[28], a[55]); SQRADDAC(a[29], a[54]); SQRADDAC(a[30], a[53]); SQRADDAC(a[31], a[52]); SQRADDAC(a[32], a[51]); SQRADDAC(a[33], a[50]); SQRADDAC(a[34], a[49]); SQRADDAC(a[35], a[48]); SQRADDAC(a[36], a[47]); SQRADDAC(a[37], a[46]); SQRADDAC(a[38], a[45]); SQRADDAC(a[39], a[44]); SQRADDAC(a[40], a[43]); SQRADDAC(a[41], a[42]); SQRADDDB; 
   COMBA_STORE(b[83]);

   /* output 84 */
   CARRY_FORWARD;
   SQRADDSC(a[21], a[63]); SQRADDAC(a[22], a[62]); SQRADDAC(a[23], a[61]); SQRADDAC(a[24], a[60]); SQRADDAC(a[25], a[59]); SQRADDAC(a[26], a[58]); SQRADDAC(a[27], a[57]); SQRADDAC(a[28], a[56]); SQRADDAC(a[29], a[55]); SQRADDAC(a[30], a[54]); SQRADDAC(a[31], a[53]); SQRADDAC(a[32], a[52]); SQRADDAC(a[33], a[51]); SQRADDAC(a[34], a[50]); SQRADDAC(a[35], a[49]); SQRADDAC(a[36], a[48]); SQRADDAC(a[37], a[47]); SQRADDAC(a[38], a[46]); SQRADDAC(a[39], a[45]); SQRADDAC(a[40], a[44]); SQRADDAC(a[41], a[43]); SQRADDDB; SQRADD(a[42], a[42]); 
   COMBA_STORE(b[84]);

   /* output 85 */
   CARRY_FORWARD;
   SQRADDSC(a[22], a[63]); SQRADDAC(a[23], a[62]); SQRADDAC(a[24], a[61]); SQRADDAC(a[25], a[60]); SQRADDAC(a[26], a[59]); SQRADDAC(a[27], a[58]); SQRADDAC(a[28], a[57]); SQRADDAC(a[29], a[56]); SQRADDAC(a[30], a[55]); SQRADDAC(a[31], a[54]); SQRADDAC(a[32], a[53]); SQRADDAC(a[33], a[52]); SQRADDAC(a[34], a[51]); SQRADDAC(a[35], a[50]); SQRADDAC(a[36], a[49]); SQRADDAC(a[37], a[48]); SQRADDAC(a[38], a[47]); SQRADDAC(a[39], a[46]); SQRADDAC(a[40], a[45]); SQRADDAC(a[41], a[44]); SQRADDAC(a[42], a[43]); SQRADDDB; 
   COMBA_STORE(b[85]);

   /* output 86 */
   CARRY_FORWARD;
   SQRADDSC(a[23], a[63]); SQRADDAC(a[24], a[62]); SQRADDAC(a[25], a[61]); SQRADDAC(a[26], a[60]); SQRADDAC(a[27], a[59]); SQRADDAC(a[28], a[58]); SQRADDAC(a[29], a[57]); SQRADDAC(a[30], a[56]); SQRADDAC(a[31], a[55]); SQRADDAC(a[32], a[54]); SQRADDAC(a[33], a[53]); SQRADDAC(a[34], a[52]); SQRADDAC(a[35], a[51]); SQRADDAC(a[36], a[50]); SQRADDAC(a[37], a[49]); SQRADDAC(a[38], a[48]); SQRADDAC(a[39], a[47]); SQRADDAC(a[40], a[46]); SQRADDAC(a[41], a[45]); SQRADDAC(a[42], a[44]); SQRADDDB; SQRADD(a[43], a[43]); 
   COMBA_STORE(b[86]);

   /* output 87 */
   CARRY_FORWARD;
   SQRADDSC(a[24], a[63]); SQRADDAC(a[25], a[62]); SQRADDAC(a[26], a[61]); SQRADDAC(a[27], a[60]); SQRADDAC(a[28], a[59]); SQRADDAC(a[29], a[58]); SQRADDAC(a[30], a[57]); SQRADDAC(a[31], a[56]); SQRADDAC(a[32], a[55]); SQRADDAC(a[33], a[54]); SQRADDAC(a[34], a[53]); SQRADDAC(a[35], a[52]); SQRADDAC(a[36], a[51]); SQRADDAC(a[37], a[50]); SQRADDAC(a[38], a[49]); SQRADDAC(a[39], a[48]); SQRADDAC(a[40], a[47]); SQRADDAC(a[41], a[46]); SQRADDAC(a[42], a[45]); SQRADDAC(a[43], a[44]); SQRADDDB; 
   COMBA_STORE(b[87]);

   /* output 88 */
   CARRY_FORWARD;
   SQRADDSC(a[25], a[63]); SQRADDAC(a[26], a[62]); SQRADDAC(a[27], a[61]); SQRADDAC(a[28], a[60]); SQRADDAC(a[29], a[59]); SQRADDAC(a[30], a[58]); SQRADDAC(a[31], a[57]); SQRADDAC(a[32], a[56]); SQRADDAC(a[33], a[55]); SQRADDAC(a[34], a[54]); SQRADDAC(a[35], a[53]); SQRADDAC(a[36], a[52]); SQRADDAC(a[37], a[51]); SQRADDAC(a[38], a[50]); SQRADDAC(a[39], a[49]); SQRADDAC(a[40], a[48]); SQRADDAC(a[41], a[47]); SQRADDAC(a[42], a[46]); SQRADDAC(a[43], a[45]); SQRADDDB; SQRADD(a[44], a[44]); 
   COMBA_STORE(b[88]);

   /* output 89 */
   CARRY_FORWARD;
   SQRADDSC(a[26], a[63]); SQRADDAC(a[27], a[62]); SQRADDAC(a[28], a[61]); SQRADDAC(a[29], a[60]); SQRADDAC(a[30], a[59]); SQRADDAC(a[31], a[58]); SQRADDAC(a[32], a[57]); SQRADDAC(a[33], a[56]); SQRADDAC(a[34], a[55]); SQRADDAC(a[35], a[54]); SQRADDAC(a[36], a[53]); SQRADDAC(a[37], a[52]); SQRADDAC(a[38], a[51]); SQRADDAC(a[39], a[50]); SQRADDAC(a[40], a[49]); SQRADDAC(a[41], a[48]); SQRADDAC(a[42], a[47]); SQRADDAC(a[43], a[46]); SQRADDAC(a[44], a[45]); SQRADDDB; 
   COMBA_STORE(b[89]);

   /* output 90 */
   CARRY_FORWARD;
   SQRADDSC(a[27], a[63]); SQRADDAC(a[28], a[62]); SQRADDAC(a[29], a[61]); SQRADDAC(a[30], a[60]); SQRADDAC(a[31], a[59]); SQRADDAC(a[32], a[58]); SQRADDAC(a[33], a[57]); SQRADDAC(a[34], a[56]); SQRADDAC(a[35], a[55]); SQRADDAC(a[36], a[54]); SQRADDAC(a[37], a[53]); SQRADDAC(a[38], a[52]); SQRADDAC(a[39], a[51]); SQRADDAC(a[40], a[50]); SQRADDAC(a[41], a[49]); SQRADDAC(a[42], a[48]); SQRADDAC(a[43], a[47]); SQRADDAC(a[44], a[46]); SQRADDDB; SQRADD(a[45], a[45]); 
   COMBA_STORE(b[90]);

   /* output 91 */
   CARRY_FORWARD;
   SQRADDSC(a[28], a[63]); SQRADDAC(a[29], a[62]); SQRADDAC(a[30], a[61]); SQRADDAC(a[31], a[60]); SQRADDAC(a[32], a[59]); SQRADDAC(a[33], a[58]); SQRADDAC(a[34], a[57]); SQRADDAC(a[35], a[56]); SQRADDAC(a[36], a[55]); SQRADDAC(a[37], a[54]); SQRADDAC(a[38], a[53]); SQRADDAC(a[39], a[52]); SQRADDAC(a[40], a[51]); SQRADDAC(a[41], a[50]); SQRADDAC(a[42], a[49]); SQRADDAC(a[43], a[48]); SQRADDAC(a[44], a[47]); SQRADDAC(a[45], a[46]); SQRADDDB; 
   COMBA_STORE(b[91]);

   /* output 92 */
   CARRY_FORWARD;
   SQRADDSC(a[29], a[63]); SQRADDAC(a[30], a[62]); SQRADDAC(a[31], a[61]); SQRADDAC(a[32], a[60]); SQRADDAC(a[33], a[59]); SQRADDAC(a[34], a[58]); SQRADDAC(a[35], a[57]); SQRADDAC(a[36], a[56]); SQRADDAC(a[37], a[55]); SQRADDAC(a[38], a[54]); SQRADDAC(a[39], a[53]); SQRADDAC(a[40], a[52]); SQRADDAC(a[41], a[51]); SQRADDAC(a[42], a[50]); SQRADDAC(a[43], a[49]); SQRADDAC(a[44], a[48]); SQRADDAC(a[45], a[47]); SQRADDDB; SQRADD(a[46], a[46]); 
   COMBA_STORE(b[92]);

   /* output 93 */
   CARRY_FORWARD;
   SQRADDSC(a[30], a[63]); SQRADDAC(a[31], a[62]); SQRADDAC(a[32], a[61]); SQRADDAC(a[33], a[60]); SQRADDAC(a[34], a[59]); SQRADDAC(a[35], a[58]); SQRADDAC(a[36], a[57]); SQRADDAC(a[37], a[56]); SQRADDAC(a[38], a[55]); SQRADDAC(a[39], a[54]); SQRADDAC(a[40], a[53]); SQRADDAC(a[41], a[52]); SQRADDAC(a[42], a[51]); SQRADDAC(a[43], a[50]); SQRADDAC(a[44], a[49]); SQRADDAC(a[45], a[48]); SQRADDAC(a[46], a[47]); SQRADDDB; 
   COMBA_STORE(b[93]);

   /* output 94 */
   CARRY_FORWARD;
   SQRADDSC(a[31], a[63]); SQRADDAC(a[32], a[62]); SQRADDAC(a[33], a[61]); SQRADDAC(a[34], a[60]); SQRADDAC(a[35], a[59]); SQRADDAC(a[36], a[58]); SQRADDAC(a[37], a[57]); SQRADDAC(a[38], a[56]); SQRADDAC(a[39], a[55]); SQRADDAC(a[40], a[54]); SQRADDAC(a[41], a[53]); SQRADDAC(a[42], a[52]); SQRADDAC(a[43], a[51]); SQRADDAC(a[44], a[50]); SQRADDAC(a[45], a[49]); SQRADDAC(a[46], a[48]); SQRADDDB; SQRADD(a[47], a[47]); 
   COMBA_STORE(b[94]);

   /* output 95 */
   CARRY_FORWARD;
   SQRADDSC(a[32], a[63]); SQRADDAC(a[33], a[62]); SQRADDAC(a[34], a[61]); SQRADDAC(a[35], a[60]); SQRADDAC(a[36], a[59]); SQRADDAC(a[37], a[58]); SQRADDAC(a[38], a[57]); SQRADDAC(a[39], a[56]); SQRADDAC(a[40], a[55]); SQRADDAC(a[41], a[54]); SQRADDAC(a[42], a[53]); SQRADDAC(a[43], a[52]); SQRADDAC(a[44], a[51]); SQRADDAC(a[45], a[50]); SQRADDAC(a[46], a[49]); SQRADDAC(a[47], a[48]); SQRADDDB; 
   COMBA_STORE(b[95]);

   /* output 96 */
   CARRY_FORWARD;
   SQRADDSC(a[33], a[63]); SQRADDAC(a[34], a[62]); SQRADDAC(a[35], a[61]); SQRADDAC(a[36], a[60]); SQRADDAC(a[37], a[59]); SQRADDAC(a[38], a[58]); SQRADDAC(a[39], a[57]); SQRADDAC(a[40], a[56]); SQRADDAC(a[41], a[55]); SQRADDAC(a[42], a[54]); SQRADDAC(a[43], a[53]); SQRADDAC(a[44], a[52]); SQRADDAC(a[45], a[51]); SQRADDAC(a[46], a[50]); SQRADDAC(a[47], a[49]); SQRADDDB; SQRADD(a[48], a[48]); 
   COMBA_STORE(b[96]);

   /* output 97 */
   CARRY_FORWARD;
   SQRADDSC(a[34], a[63]); SQRADDAC(a[35], a[62]); SQRADDAC(a[36], a[61]); SQRADDAC(a[37], a[60]); SQRADDAC(a[38], a[59]); SQRADDAC(a[39], a[58]); SQRADDAC(a[40], a[57]); SQRADDAC(a[41], a[56]); SQRADDAC(a[42], a[55]); SQRADDAC(a[43], a[54]); SQRADDAC(a[44], a[53]); SQRADDAC(a[45], a[52]); SQRADDAC(a[46], a[51]); SQRADDAC(a[47], a[50]); SQRADDAC(a[48], a[49]); SQRADDDB; 
   COMBA_STORE(b[97]);

   /* output 98 */
   CARRY_FORWARD;
   SQRADDSC(a[35], a[63]); SQRADDAC(a[36], a[62]); SQRADDAC(a[37], a[61]); SQRADDAC(a[38], a[60]); SQRADDAC(a[39], a[59]); SQRADDAC(a[40], a[58]); SQRADDAC(a[41], a[57]); SQRADDAC(a[42], a[56]); SQRADDAC(a[43], a[55]); SQRADDAC(a[44], a[54]); SQRADDAC(a[45], a[53]); SQRADDAC(a[46], a[52]); SQRADDAC(a[47], a[51]); SQRADDAC(a[48], a[50]); SQRADDDB; SQRADD(a[49], a[49]); 
   COMBA_STORE(b[98]);

   /* output 99 */
   CARRY_FORWARD;
   SQRADDSC(a[36], a[63]); SQRADDAC(a[37], a[62]); SQRADDAC(a[38], a[61]); SQRADDAC(a[39], a[60]); SQRADDAC(a[40], a[59]); SQRADDAC(a[41], a[58]); SQRADDAC(a[42], a[57]); SQRADDAC(a[43], a[56]); SQRADDAC(a[44], a[55]); SQRADDAC(a[45], a[54]); SQRADDAC(a[46], a[53]); SQRADDAC(a[47], a[52]); SQRADDAC(a[48], a[51]); SQRADDAC(a[49], a[50]); SQRADDDB; 
   COMBA_STORE(b[99]);

   /* output 100 */
   CARRY_FORWARD;
   SQRADDSC(a[37], a[63]); SQRADDAC(a[38], a[62]); SQRADDAC(a[39], a[61]); SQRADDAC(a[40], a[60]); SQRADDAC(a[41], a[59]); SQRADDAC(a[42], a[58]); SQRADDAC(a[43], a[57]); SQRADDAC(a[44], a[56]); SQRADDAC(a[45], a[55]); SQRADDAC(a[46], a[54]); SQRADDAC(a[47], a[53]); SQRADDAC(a[48], a[52]); SQRADDAC(a[49], a[51]); SQRADDDB; SQRADD(a[50], a[50]); 
   COMBA_STORE(b[100]);

   /* output 101 */
   CARRY_FORWARD;
   SQRADDSC(a[38], a[63]); SQRADDAC(a[39], a[62]); SQRADDAC(a[40], a[61]); SQRADDAC(a[41], a[60]); SQRADDAC(a[42], a[59]); SQRADDAC(a[43], a[58]); SQRADDAC(a[44], a[57]); SQRADDAC(a[45], a[56]); SQRADDAC(a[46], a[55]); SQRADDAC(a[47], a[54]); SQRADDAC(a[48], a[53]); SQRADDAC(a[49], a[52]); SQRADDAC(a[50], a[51]); SQRADDDB; 
   COMBA_STORE(b[101]);

   /* output 102 */
   CARRY_FORWARD;
   SQRADDSC(a[39], a[63]); SQRADDAC(a[40], a[62]); SQRADDAC(a[41], a[61]); SQRADDAC(a[42], a[60]); SQRADDAC(a[43], a[59]); SQRADDAC(a[44], a[58]); SQRADDAC(a[45], a[57]); SQRADDAC(a[46], a[56]); SQRADDAC(a[47], a[55]); SQRADDAC(a[48], a[54]); SQRADDAC(a[49], a[53]); SQRADDAC(a[50], a[52]); SQRADDDB; SQRADD(a[51], a[51]); 
   COMBA_STORE(b[102]);

   /* output 103 */
   CARRY_FORWARD;
   SQRADDSC(a[40], a[63]); SQRADDAC(a[41], a[62]); SQRADDAC(a[42], a[61]); SQRADDAC(a[43], a[60]); SQRADDAC(a[44], a[59]); SQRADDAC(a[45], a[58]); SQRADDAC(a[46], a[57]); SQRADDAC(a[47], a[56]); SQRADDAC(a[48], a[55]); SQRADDAC(a[49], a[54]); SQRADDAC(a[50], a[53]); SQRADDAC(a[51], a[52]); SQRADDDB; 
   COMBA_STORE(b[103]);

   /* output 104 */
   CARRY_FORWARD;
   SQRADDSC(a[41], a[63]); SQRADDAC(a[42], a[62]); SQRADDAC(a[43], a[61]); SQRADDAC(a[44], a[60]); SQRADDAC(a[45], a[59]); SQRADDAC(a[46], a[58]); SQRADDAC(a[47], a[57]); SQRADDAC(a[48], a[56]); SQRADDAC(a[49], a[55]); SQRADDAC(a[50], a[54]); SQRADDAC(a[51], a[53]); SQRADDDB; SQRADD(a[52], a[52]); 
   COMBA_STORE(b[104]);

   /* output 105 */
   CARRY_FORWARD;
   SQRADDSC(a[42], a[63]); SQRADDAC(a[43], a[62]); SQRADDAC(a[44], a[61]); SQRADDAC(a[45], a[60]); SQRADDAC(a[46], a[59]); SQRADDAC(a[47], a[58]); SQRADDAC(a[48], a[57]); SQRADDAC(a[49], a[56]); SQRADDAC(a[50], a[55]); SQRADDAC(a[51], a[54]); SQRADDAC(a[52], a[53]); SQRADDDB; 
   COMBA_STORE(b[105]);

   /* output 106 */
   CARRY_FORWARD;
   SQRADDSC(a[43], a[63]); SQRADDAC(a[44], a[62]); SQRADDAC(a[45], a[61]); SQRADDAC(a[46], a[60]); SQRADDAC(a[47], a[59]); SQRADDAC(a[48], a[58]); SQRADDAC(a[49], a[57]); SQRADDAC(a[50], a[56]); SQRADDAC(a[51], a[55]); SQRADDAC(a[52], a[54]); SQRADDDB; SQRADD(a[53], a[53]); 
   COMBA_STORE(b[106]);

   /* output 107 */
   CARRY_FORWARD;
   SQRADDSC(a[44], a[63]); SQRADDAC(a[45], a[62]); SQRADDAC(a[46], a[61]); SQRADDAC(a[47], a[60]); SQRADDAC(a[48], a[59]); SQRADDAC(a[49], a[58]); SQRADDAC(a[50], a[57]); SQRADDAC(a[51], a[56]); SQRADDAC(a[52], a[55]); SQRADDAC(a[53], a[54]); SQRADDDB; 
   COMBA_STORE(b[107]);

   /* output 108 */
   CARRY_FORWARD;
   SQRADDSC(a[45], a[63]); SQRADDAC(a[46], a[62]); SQRADDAC(a[47], a[61]); SQRADDAC(a[48], a[60]); SQRADDAC(a[49], a[59]); SQRADDAC(a[50], a[58]); SQRADDAC(a[51], a[57]); SQRADDAC(a[52], a[56]); SQRADDAC(a[53], a[55]); SQRADDDB; SQRADD(a[54], a[54]); 
   COMBA_STORE(b[108]);

   /* output 109 */
   CARRY_FORWARD;
   SQRADDSC(a[46], a[63]); SQRADDAC(a[47], a[62]); SQRADDAC(a[48], a[61]); SQRADDAC(a[49], a[60]); SQRADDAC(a[50], a[59]); SQRADDAC(a[51], a[58]); SQRADDAC(a[52], a[57]); SQRADDAC(a[53], a[56]); SQRADDAC(a[54], a[55]); SQRADDDB; 
   COMBA_STORE(b[109]);

   /* output 110 */
   CARRY_FORWARD;
   SQRADDSC(a[47], a[63]); SQRADDAC(a[48], a[62]); SQRADDAC(a[49], a[61]); SQRADDAC(a[50], a[60]); SQRADDAC(a[51], a[59]); SQRADDAC(a[52], a[58]); SQRADDAC(a[53], a[57]); SQRADDAC(a[54], a[56]); SQRADDDB; SQRADD(a[55], a[55]); 
   COMBA_STORE(b[110]);

   /* output 111 */
   CARRY_FORWARD;
   SQRADDSC(a[48], a[63]); SQRADDAC(a[49], a[62]); SQRADDAC(a[50], a[61]); SQRADDAC(a[51], a[60]); SQRADDAC(a[52], a[59]); SQRADDAC(a[53], a[58]); SQRADDAC(a[54], a[57]); SQRADDAC(a[55], a[56]); SQRADDDB; 
   COMBA_STORE(b[111]);

   /* output 112 */
   CARRY_FORWARD;
   SQRADDSC(a[49], a[63]); SQRADDAC(a[50], a[62]); SQRADDAC(a[51], a[61]); SQRADDAC(a[52], a[60]); SQRADDAC(a[53], a[59]); SQRADDAC(a[54], a[58]); SQRADDAC(a[55], a[57]); SQRADDDB; SQRADD(a[56], a[56]); 
   COMBA_STORE(b[112]);

   /* output 113 */
   CARRY_FORWARD;
   SQRADDSC(a[50], a[63]); SQRADDAC(a[51], a[62]); SQRADDAC(a[52], a[61]); SQRADDAC(a[53], a[60]); SQRADDAC(a[54], a[59]); SQRADDAC(a[55], a[58]); SQRADDAC(a[56], a[57]); SQRADDDB; 
   COMBA_STORE(b[113]);

   /* output 114 */
   CARRY_FORWARD;
   SQRADDSC(a[51], a[63]); SQRADDAC(a[52], a[62]); SQRADDAC(a[53], a[61]); SQRADDAC(a[54], a[60]); SQRADDAC(a[55], a[59]); SQRADDAC(a[56], a[58]); SQRADDDB; SQRADD(a[57], a[57]); 
   COMBA_STORE(b[114]);

   /* output 115 */
   CARRY_FORWARD;
   SQRADDSC(a[52], a[63]); SQRADDAC(a[53], a[62]); SQRADDAC(a[54], a[61]); SQRADDAC(a[55], a[60]); SQRADDAC(a[56], a[59]); SQRADDAC(a[57], a[58]); SQRADDDB; 
   COMBA_STORE(b[115]);

   /* output 116 */
   CARRY_FORWARD;
   SQRADDSC(a[53], a[63]); SQRADDAC(a[54], a[62]); SQRADDAC(a[55], a[61]); SQRADDAC(a[56], a[60]); SQRADDAC(a[57], a[59]); SQRADDDB; SQRADD(a[58], a[58]); 
   COMBA_STORE(b[116]);

   /* output 117 */
   CARRY_FORWARD;
   SQRADDSC(a[54], a[63]); SQRADDAC(a[55], a[62]); SQRADDAC(a[56], a[61]); SQRADDAC(a[57], a[60]); SQRADDAC(a[58], a[59]); SQRADDDB; 
   COMBA_STORE(b[117]);

   /* output 118 */
   CARRY_FORWARD;
   SQRADDSC(a[55], a[63]); SQRADDAC(a[56], a[62]); SQRADDAC(a[57], a[61]); SQRADDAC(a[58], a[60]); SQRADDDB; SQRADD(a[59], a[59]); 
   COMBA_STORE(b[118]);

   /* output 119 */
   CARRY_FORWARD;
   SQRADDSC(a[56], a[63]); SQRADDAC(a[57], a[62]); SQRADDAC(a[58], a[61]); SQRADDAC(a[59], a[60]); SQRADDDB; 
   COMBA_STORE(b[119]);

   /* output 120 */
   CARRY_FORWARD;
   SQRADDSC(a[57], a[63]); SQRADDAC(a[58], a[62]); SQRADDAC(a[59], a[61]); SQRADDDB; SQRADD(a[60], a[60]); 
   COMBA_STORE(b[120]);

   /* output 121 */
   CARRY_FORWARD;
   SQRADDSC(a[58], a[63]); SQRADDAC(a[59], a[62]); SQRADDAC(a[60], a[61]); SQRADDDB; 
   COMBA_STORE(b[121]);

   /* output 122 */
   CARRY_FORWARD;
   SQRADD2(a[59], a[63]); SQRADD2(a[60], a[62]); SQRADD(a[61], a[61]); 
   COMBA_STORE(b[122]);

   /* output 123 */
   CARRY_FORWARD;
   SQRADD2(a[60], a[63]); SQRADD2(a[61], a[62]); 
   COMBA_STORE(b[123]);

   /* output 124 */
   CARRY_FORWARD;
   SQRADD2(a[61], a[63]); SQRADD(a[62], a[62]); 
   COMBA_STORE(b[124]);

   /* output 125 */
   CARRY_FORWARD;
   SQRADD2(a[62], a[63]); 
   COMBA_STORE(b[125]);

   /* output 126 */
   CARRY_FORWARD;
   SQRADD(a[63], a[63]); 
   COMBA_STORE(b[126]);
   COMBA_STORE2(b[127]);
   COMBA_FINI;

   B->used = 128;
   B->sign = FP_ZPOS;
   memcpy(B->dp, b, 128 * sizeof(fp_digit));
   fp_clamp(B);
}
#endif


/* $Source: /cvs/libtom/tomsfastmath/src/sqr/fp_sqr_comba_64.c,v $ */
/* $Revision: 1.2 $ */
/* $Date: 2007/02/17 03:39:01 $ */

/* End: fp_sqr_comba_64.c */

/* Start: fp_sqr_comba_7.c */
#define TFM_DEFINES
#include "fp_sqr_comba.c"

#ifdef TFM_SQR7
void fp_sqr_comba7(fp_int *A, fp_int *B)
{
   fp_digit *a, b[14], c0, c1, c2, sc0, sc1, sc2;
#ifdef TFM_ISO
   fp_word tt;
#endif

   a = A->dp;
   COMBA_START; 

   /* clear carries */
   CLEAR_CARRY;

   /* output 0 */
   SQRADD(a[0],a[0]);
   COMBA_STORE(b[0]);

   /* output 1 */
   CARRY_FORWARD;
   SQRADD2(a[0], a[1]); 
   COMBA_STORE(b[1]);

   /* output 2 */
   CARRY_FORWARD;
   SQRADD2(a[0], a[2]); SQRADD(a[1], a[1]); 
   COMBA_STORE(b[2]);

   /* output 3 */
   CARRY_FORWARD;
   SQRADD2(a[0], a[3]); SQRADD2(a[1], a[2]); 
   COMBA_STORE(b[3]);

   /* output 4 */
   CARRY_FORWARD;
   SQRADD2(a[0], a[4]); SQRADD2(a[1], a[3]); SQRADD(a[2], a[2]); 
   COMBA_STORE(b[4]);

   /* output 5 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[5]); SQRADDAC(a[1], a[4]); SQRADDAC(a[2], a[3]); SQRADDDB; 
   COMBA_STORE(b[5]);

   /* output 6 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[6]); SQRADDAC(a[1], a[5]); SQRADDAC(a[2], a[4]); SQRADDDB; SQRADD(a[3], a[3]); 
   COMBA_STORE(b[6]);

   /* output 7 */
   CARRY_FORWARD;
   SQRADDSC(a[1], a[6]); SQRADDAC(a[2], a[5]); SQRADDAC(a[3], a[4]); SQRADDDB; 
   COMBA_STORE(b[7]);

   /* output 8 */
   CARRY_FORWARD;
   SQRADD2(a[2], a[6]); SQRADD2(a[3], a[5]); SQRADD(a[4], a[4]); 
   COMBA_STORE(b[8]);

   /* output 9 */
   CARRY_FORWARD;
   SQRADD2(a[3], a[6]); SQRADD2(a[4], a[5]); 
   COMBA_STORE(b[9]);

   /* output 10 */
   CARRY_FORWARD;
   SQRADD2(a[4], a[6]); SQRADD(a[5], a[5]); 
   COMBA_STORE(b[10]);

   /* output 11 */
   CARRY_FORWARD;
   SQRADD2(a[5], a[6]); 
   COMBA_STORE(b[11]);

   /* output 12 */
   CARRY_FORWARD;
   SQRADD(a[6], a[6]); 
   COMBA_STORE(b[12]);
   COMBA_STORE2(b[13]);
   COMBA_FINI;

   B->used = 14;
   B->sign = FP_ZPOS;
   memcpy(B->dp, b, 14 * sizeof(fp_digit));
   fp_clamp(B);
}
#endif


/* $Source: /cvs/libtom/tomsfastmath/src/sqr/fp_sqr_comba_7.c,v $ */
/* $Revision: 1.2 $ */
/* $Date: 2007/02/17 03:39:01 $ */

/* End: fp_sqr_comba_7.c */

/* Start: fp_sqr_comba_8.c */
#define TFM_DEFINES
#include "fp_sqr_comba.c"

#ifdef TFM_SQR8
void fp_sqr_comba8(fp_int *A, fp_int *B)
{
   fp_digit *a, b[16], c0, c1, c2, sc0, sc1, sc2;
#ifdef TFM_ISO
   fp_word tt;
#endif

   a = A->dp;
   COMBA_START; 

   /* clear carries */
   CLEAR_CARRY;

   /* output 0 */
   SQRADD(a[0],a[0]);
   COMBA_STORE(b[0]);

   /* output 1 */
   CARRY_FORWARD;
   SQRADD2(a[0], a[1]); 
   COMBA_STORE(b[1]);

   /* output 2 */
   CARRY_FORWARD;
   SQRADD2(a[0], a[2]); SQRADD(a[1], a[1]); 
   COMBA_STORE(b[2]);

   /* output 3 */
   CARRY_FORWARD;
   SQRADD2(a[0], a[3]); SQRADD2(a[1], a[2]); 
   COMBA_STORE(b[3]);

   /* output 4 */
   CARRY_FORWARD;
   SQRADD2(a[0], a[4]); SQRADD2(a[1], a[3]); SQRADD(a[2], a[2]); 
   COMBA_STORE(b[4]);

   /* output 5 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[5]); SQRADDAC(a[1], a[4]); SQRADDAC(a[2], a[3]); SQRADDDB; 
   COMBA_STORE(b[5]);

   /* output 6 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[6]); SQRADDAC(a[1], a[5]); SQRADDAC(a[2], a[4]); SQRADDDB; SQRADD(a[3], a[3]); 
   COMBA_STORE(b[6]);

   /* output 7 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[7]); SQRADDAC(a[1], a[6]); SQRADDAC(a[2], a[5]); SQRADDAC(a[3], a[4]); SQRADDDB; 
   COMBA_STORE(b[7]);

   /* output 8 */
   CARRY_FORWARD;
   SQRADDSC(a[1], a[7]); SQRADDAC(a[2], a[6]); SQRADDAC(a[3], a[5]); SQRADDDB; SQRADD(a[4], a[4]); 
   COMBA_STORE(b[8]);

   /* output 9 */
   CARRY_FORWARD;
   SQRADDSC(a[2], a[7]); SQRADDAC(a[3], a[6]); SQRADDAC(a[4], a[5]); SQRADDDB; 
   COMBA_STORE(b[9]);

   /* output 10 */
   CARRY_FORWARD;
   SQRADD2(a[3], a[7]); SQRADD2(a[4], a[6]); SQRADD(a[5], a[5]); 
   COMBA_STORE(b[10]);

   /* output 11 */
   CARRY_FORWARD;
   SQRADD2(a[4], a[7]); SQRADD2(a[5], a[6]); 
   COMBA_STORE(b[11]);

   /* output 12 */
   CARRY_FORWARD;
   SQRADD2(a[5], a[7]); SQRADD(a[6], a[6]); 
   COMBA_STORE(b[12]);

   /* output 13 */
   CARRY_FORWARD;
   SQRADD2(a[6], a[7]); 
   COMBA_STORE(b[13]);

   /* output 14 */
   CARRY_FORWARD;
   SQRADD(a[7], a[7]); 
   COMBA_STORE(b[14]);
   COMBA_STORE2(b[15]);
   COMBA_FINI;

   B->used = 16;
   B->sign = FP_ZPOS;
   memcpy(B->dp, b, 16 * sizeof(fp_digit));
   fp_clamp(B);
}
#endif


/* $Source: /cvs/libtom/tomsfastmath/src/sqr/fp_sqr_comba_8.c,v $ */
/* $Revision: 1.2 $ */
/* $Date: 2007/02/17 03:39:01 $ */

/* End: fp_sqr_comba_8.c */

/* Start: fp_sqr_comba_9.c */
#define TFM_DEFINES
#include "fp_sqr_comba.c"

#ifdef TFM_SQR9
void fp_sqr_comba9(fp_int *A, fp_int *B)
{
   fp_digit *a, b[18], c0, c1, c2, sc0, sc1, sc2;
#ifdef TFM_ISO
   fp_word tt;
#endif

   a = A->dp;
   COMBA_START; 

   /* clear carries */
   CLEAR_CARRY;

   /* output 0 */
   SQRADD(a[0],a[0]);
   COMBA_STORE(b[0]);

   /* output 1 */
   CARRY_FORWARD;
   SQRADD2(a[0], a[1]); 
   COMBA_STORE(b[1]);

   /* output 2 */
   CARRY_FORWARD;
   SQRADD2(a[0], a[2]); SQRADD(a[1], a[1]); 
   COMBA_STORE(b[2]);

   /* output 3 */
   CARRY_FORWARD;
   SQRADD2(a[0], a[3]); SQRADD2(a[1], a[2]); 
   COMBA_STORE(b[3]);

   /* output 4 */
   CARRY_FORWARD;
   SQRADD2(a[0], a[4]); SQRADD2(a[1], a[3]); SQRADD(a[2], a[2]); 
   COMBA_STORE(b[4]);

   /* output 5 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[5]); SQRADDAC(a[1], a[4]); SQRADDAC(a[2], a[3]); SQRADDDB; 
   COMBA_STORE(b[5]);

   /* output 6 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[6]); SQRADDAC(a[1], a[5]); SQRADDAC(a[2], a[4]); SQRADDDB; SQRADD(a[3], a[3]); 
   COMBA_STORE(b[6]);

   /* output 7 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[7]); SQRADDAC(a[1], a[6]); SQRADDAC(a[2], a[5]); SQRADDAC(a[3], a[4]); SQRADDDB; 
   COMBA_STORE(b[7]);

   /* output 8 */
   CARRY_FORWARD;
   SQRADDSC(a[0], a[8]); SQRADDAC(a[1], a[7]); SQRADDAC(a[2], a[6]); SQRADDAC(a[3], a[5]); SQRADDDB; SQRADD(a[4], a[4]); 
   COMBA_STORE(b[8]);

   /* output 9 */
   CARRY_FORWARD;
   SQRADDSC(a[1], a[8]); SQRADDAC(a[2], a[7]); SQRADDAC(a[3], a[6]); SQRADDAC(a[4], a[5]); SQRADDDB; 
   COMBA_STORE(b[9]);

   /* output 10 */
   CARRY_FORWARD;
   SQRADDSC(a[2], a[8]); SQRADDAC(a[3], a[7]); SQRADDAC(a[4], a[6]); SQRADDDB; SQRADD(a[5], a[5]); 
   COMBA_STORE(b[10]);

   /* output 11 */
   CARRY_FORWARD;
   SQRADDSC(a[3], a[8]); SQRADDAC(a[4], a[7]); SQRADDAC(a[5], a[6]); SQRADDDB; 
   COMBA_STORE(b[11]);

   /* output 12 */
   CARRY_FORWARD;
   SQRADD2(a[4], a[8]); SQRADD2(a[5], a[7]); SQRADD(a[6], a[6]); 
   COMBA_STORE(b[12]);

   /* output 13 */
   CARRY_FORWARD;
   SQRADD2(a[5], a[8]); SQRADD2(a[6], a[7]); 
   COMBA_STORE(b[13]);

   /* output 14 */
   CARRY_FORWARD;
   SQRADD2(a[6], a[8]); SQRADD(a[7], a[7]); 
   COMBA_STORE(b[14]);

   /* output 15 */
   CARRY_FORWARD;
   SQRADD2(a[7], a[8]); 
   COMBA_STORE(b[15]);

   /* output 16 */
   CARRY_FORWARD;
   SQRADD(a[8], a[8]); 
   COMBA_STORE(b[16]);
   COMBA_STORE2(b[17]);
   COMBA_FINI;

   B->used = 18;
   B->sign = FP_ZPOS;
   memcpy(B->dp, b, 18 * sizeof(fp_digit));
   fp_clamp(B);
}
#endif


/* $Source: /cvs/libtom/tomsfastmath/src/sqr/fp_sqr_comba_9.c,v $ */
/* $Revision: 1.2 $ */
/* $Date: 2007/02/17 03:39:01 $ */

/* End: fp_sqr_comba_9.c */

/* Start: fp_sqr_comba_small_set.c */
#define TFM_DEFINES
#include "fp_sqr_comba.c"

#if defined(TFM_SMALL_SET)
void fp_sqr_comba_small(fp_int *A, fp_int *B)
{
   fp_digit *a, b[32], c0, c1, c2, sc0, sc1, sc2;
#ifdef TFM_ISO
   fp_word   tt;   
#endif   
   switch (A->used) { 
   case 1:
      a = A->dp;
      COMBA_START; 

      /* clear carries */
      CLEAR_CARRY;

      /* output 0 */
      SQRADD(a[0],a[0]);
      COMBA_STORE(b[0]);
      COMBA_STORE2(b[1]);
      COMBA_FINI;

      B->used = 2;
      B->sign = FP_ZPOS;
      memcpy(B->dp, b, 2 * sizeof(fp_digit));
      fp_clamp(B);
      break;

   case 2:
      a = A->dp;
      COMBA_START; 

      /* clear carries */
      CLEAR_CARRY;

      /* output 0 */
      SQRADD(a[0],a[0]);
      COMBA_STORE(b[0]);

      /* output 1 */
      CARRY_FORWARD;
      SQRADD2(a[0], a[1]); 
      COMBA_STORE(b[1]);

      /* output 2 */
      CARRY_FORWARD;
      SQRADD(a[1], a[1]); 
      COMBA_STORE(b[2]);
      COMBA_STORE2(b[3]);
      COMBA_FINI;

      B->used = 4;
      B->sign = FP_ZPOS;
      memcpy(B->dp, b, 4 * sizeof(fp_digit));
      fp_clamp(B);
      break;

   case 3:
      a = A->dp;
      COMBA_START; 

      /* clear carries */
      CLEAR_CARRY;

      /* output 0 */
      SQRADD(a[0],a[0]);
      COMBA_STORE(b[0]);

      /* output 1 */
      CARRY_FORWARD;
      SQRADD2(a[0], a[1]); 
      COMBA_STORE(b[1]);

      /* output 2 */
      CARRY_FORWARD;
      SQRADD2(a[0], a[2]);    SQRADD(a[1], a[1]); 
      COMBA_STORE(b[2]);

      /* output 3 */
      CARRY_FORWARD;
      SQRADD2(a[1], a[2]); 
      COMBA_STORE(b[3]);

      /* output 4 */
      CARRY_FORWARD;
      SQRADD(a[2], a[2]); 
      COMBA_STORE(b[4]);
      COMBA_STORE2(b[5]);
      COMBA_FINI;

      B->used = 6;
      B->sign = FP_ZPOS;
      memcpy(B->dp, b, 6 * sizeof(fp_digit));
      fp_clamp(B);
      break;

   case 4:
      a = A->dp;
      COMBA_START; 

      /* clear carries */
      CLEAR_CARRY;

      /* output 0 */
      SQRADD(a[0],a[0]);
      COMBA_STORE(b[0]);

      /* output 1 */
      CARRY_FORWARD;
      SQRADD2(a[0], a[1]); 
      COMBA_STORE(b[1]);

      /* output 2 */
      CARRY_FORWARD;
      SQRADD2(a[0], a[2]);    SQRADD(a[1], a[1]); 
      COMBA_STORE(b[2]);

      /* output 3 */
      CARRY_FORWARD;
      SQRADD2(a[0], a[3]);    SQRADD2(a[1], a[2]); 
      COMBA_STORE(b[3]);

      /* output 4 */
      CARRY_FORWARD;
      SQRADD2(a[1], a[3]);    SQRADD(a[2], a[2]); 
      COMBA_STORE(b[4]);

      /* output 5 */
      CARRY_FORWARD;
      SQRADD2(a[2], a[3]); 
      COMBA_STORE(b[5]);

      /* output 6 */
      CARRY_FORWARD;
      SQRADD(a[3], a[3]); 
      COMBA_STORE(b[6]);
      COMBA_STORE2(b[7]);
      COMBA_FINI;

      B->used = 8;
      B->sign = FP_ZPOS;
      memcpy(B->dp, b, 8 * sizeof(fp_digit));
      fp_clamp(B);
      break;

   case 5:
      a = A->dp;
      COMBA_START; 

      /* clear carries */
      CLEAR_CARRY;

      /* output 0 */
      SQRADD(a[0],a[0]);
      COMBA_STORE(b[0]);

      /* output 1 */
      CARRY_FORWARD;
      SQRADD2(a[0], a[1]); 
      COMBA_STORE(b[1]);

      /* output 2 */
      CARRY_FORWARD;
      SQRADD2(a[0], a[2]);    SQRADD(a[1], a[1]); 
      COMBA_STORE(b[2]);

      /* output 3 */
      CARRY_FORWARD;
      SQRADD2(a[0], a[3]);    SQRADD2(a[1], a[2]); 
      COMBA_STORE(b[3]);

      /* output 4 */
      CARRY_FORWARD;
      SQRADD2(a[0], a[4]);    SQRADD2(a[1], a[3]);    SQRADD(a[2], a[2]); 
      COMBA_STORE(b[4]);

      /* output 5 */
      CARRY_FORWARD;
      SQRADD2(a[1], a[4]);    SQRADD2(a[2], a[3]); 
      COMBA_STORE(b[5]);

      /* output 6 */
      CARRY_FORWARD;
      SQRADD2(a[2], a[4]);    SQRADD(a[3], a[3]); 
      COMBA_STORE(b[6]);

      /* output 7 */
      CARRY_FORWARD;
      SQRADD2(a[3], a[4]); 
      COMBA_STORE(b[7]);

      /* output 8 */
      CARRY_FORWARD;
      SQRADD(a[4], a[4]); 
      COMBA_STORE(b[8]);
      COMBA_STORE2(b[9]);
      COMBA_FINI;

      B->used = 10;
      B->sign = FP_ZPOS;
      memcpy(B->dp, b, 10 * sizeof(fp_digit));
      fp_clamp(B);
      break;

   case 6:
      a = A->dp;
      COMBA_START; 

      /* clear carries */
      CLEAR_CARRY;

      /* output 0 */
      SQRADD(a[0],a[0]);
      COMBA_STORE(b[0]);

      /* output 1 */
      CARRY_FORWARD;
      SQRADD2(a[0], a[1]); 
      COMBA_STORE(b[1]);

      /* output 2 */
      CARRY_FORWARD;
      SQRADD2(a[0], a[2]);    SQRADD(a[1], a[1]); 
      COMBA_STORE(b[2]);

      /* output 3 */
      CARRY_FORWARD;
      SQRADD2(a[0], a[3]);    SQRADD2(a[1], a[2]); 
      COMBA_STORE(b[3]);

      /* output 4 */
      CARRY_FORWARD;
      SQRADD2(a[0], a[4]);    SQRADD2(a[1], a[3]);    SQRADD(a[2], a[2]); 
      COMBA_STORE(b[4]);

      /* output 5 */
      CARRY_FORWARD;
   SQRADDSC(a[0], a[5]); SQRADDAC(a[1], a[4]); SQRADDAC(a[2], a[3]); SQRADDDB; 
      COMBA_STORE(b[5]);

      /* output 6 */
      CARRY_FORWARD;
      SQRADD2(a[1], a[5]);    SQRADD2(a[2], a[4]);    SQRADD(a[3], a[3]); 
      COMBA_STORE(b[6]);

      /* output 7 */
      CARRY_FORWARD;
      SQRADD2(a[2], a[5]);    SQRADD2(a[3], a[4]); 
      COMBA_STORE(b[7]);

      /* output 8 */
      CARRY_FORWARD;
      SQRADD2(a[3], a[5]);    SQRADD(a[4], a[4]); 
      COMBA_STORE(b[8]);

      /* output 9 */
      CARRY_FORWARD;
      SQRADD2(a[4], a[5]); 
      COMBA_STORE(b[9]);

      /* output 10 */
      CARRY_FORWARD;
      SQRADD(a[5], a[5]); 
      COMBA_STORE(b[10]);
      COMBA_STORE2(b[11]);
      COMBA_FINI;

      B->used = 12;
      B->sign = FP_ZPOS;
      memcpy(B->dp, b, 12 * sizeof(fp_digit));
      fp_clamp(B);
      break;

   case 7:
      a = A->dp;
      COMBA_START; 

      /* clear carries */
      CLEAR_CARRY;

      /* output 0 */
      SQRADD(a[0],a[0]);
      COMBA_STORE(b[0]);

      /* output 1 */
      CARRY_FORWARD;
      SQRADD2(a[0], a[1]); 
      COMBA_STORE(b[1]);

      /* output 2 */
      CARRY_FORWARD;
      SQRADD2(a[0], a[2]);    SQRADD(a[1], a[1]); 
      COMBA_STORE(b[2]);

      /* output 3 */
      CARRY_FORWARD;
      SQRADD2(a[0], a[3]);    SQRADD2(a[1], a[2]); 
      COMBA_STORE(b[3]);

      /* output 4 */
      CARRY_FORWARD;
      SQRADD2(a[0], a[4]);    SQRADD2(a[1], a[3]);    SQRADD(a[2], a[2]); 
      COMBA_STORE(b[4]);

      /* output 5 */
      CARRY_FORWARD;
   SQRADDSC(a[0], a[5]); SQRADDAC(a[1], a[4]); SQRADDAC(a[2], a[3]); SQRADDDB; 
      COMBA_STORE(b[5]);

      /* output 6 */
      CARRY_FORWARD;
   SQRADDSC(a[0], a[6]); SQRADDAC(a[1], a[5]); SQRADDAC(a[2], a[4]); SQRADDDB; SQRADD(a[3], a[3]); 
      COMBA_STORE(b[6]);

      /* output 7 */
      CARRY_FORWARD;
   SQRADDSC(a[1], a[6]); SQRADDAC(a[2], a[5]); SQRADDAC(a[3], a[4]); SQRADDDB; 
      COMBA_STORE(b[7]);

      /* output 8 */
      CARRY_FORWARD;
      SQRADD2(a[2], a[6]);    SQRADD2(a[3], a[5]);    SQRADD(a[4], a[4]); 
      COMBA_STORE(b[8]);

      /* output 9 */
      CARRY_FORWARD;
      SQRADD2(a[3], a[6]);    SQRADD2(a[4], a[5]); 
      COMBA_STORE(b[9]);

      /* output 10 */
      CARRY_FORWARD;
      SQRADD2(a[4], a[6]);    SQRADD(a[5], a[5]); 
      COMBA_STORE(b[10]);

      /* output 11 */
      CARRY_FORWARD;
      SQRADD2(a[5], a[6]); 
      COMBA_STORE(b[11]);

      /* output 12 */
      CARRY_FORWARD;
      SQRADD(a[6], a[6]); 
      COMBA_STORE(b[12]);
      COMBA_STORE2(b[13]);
      COMBA_FINI;

      B->used = 14;
      B->sign = FP_ZPOS;
      memcpy(B->dp, b, 14 * sizeof(fp_digit));
      fp_clamp(B);
      break;

   case 8:
      a = A->dp;
      COMBA_START; 

      /* clear carries */
      CLEAR_CARRY;

      /* output 0 */
      SQRADD(a[0],a[0]);
      COMBA_STORE(b[0]);

      /* output 1 */
      CARRY_FORWARD;
      SQRADD2(a[0], a[1]); 
      COMBA_STORE(b[1]);

      /* output 2 */
      CARRY_FORWARD;
      SQRADD2(a[0], a[2]);    SQRADD(a[1], a[1]); 
      COMBA_STORE(b[2]);

      /* output 3 */
      CARRY_FORWARD;
      SQRADD2(a[0], a[3]);    SQRADD2(a[1], a[2]); 
      COMBA_STORE(b[3]);

      /* output 4 */
      CARRY_FORWARD;
      SQRADD2(a[0], a[4]);    SQRADD2(a[1], a[3]);    SQRADD(a[2], a[2]); 
      COMBA_STORE(b[4]);

      /* output 5 */
      CARRY_FORWARD;
   SQRADDSC(a[0], a[5]); SQRADDAC(a[1], a[4]); SQRADDAC(a[2], a[3]); SQRADDDB; 
      COMBA_STORE(b[5]);

      /* output 6 */
      CARRY_FORWARD;
   SQRADDSC(a[0], a[6]); SQRADDAC(a[1], a[5]); SQRADDAC(a[2], a[4]); SQRADDDB; SQRADD(a[3], a[3]); 
      COMBA_STORE(b[6]);

      /* output 7 */
      CARRY_FORWARD;
   SQRADDSC(a[0], a[7]); SQRADDAC(a[1], a[6]); SQRADDAC(a[2], a[5]); SQRADDAC(a[3], a[4]); SQRADDDB; 
      COMBA_STORE(b[7]);

      /* output 8 */
      CARRY_FORWARD;
   SQRADDSC(a[1], a[7]); SQRADDAC(a[2], a[6]); SQRADDAC(a[3], a[5]); SQRADDDB; SQRADD(a[4], a[4]); 
      COMBA_STORE(b[8]);

      /* output 9 */
      CARRY_FORWARD;
   SQRADDSC(a[2], a[7]); SQRADDAC(a[3], a[6]); SQRADDAC(a[4], a[5]); SQRADDDB; 
      COMBA_STORE(b[9]);

      /* output 10 */
      CARRY_FORWARD;
      SQRADD2(a[3], a[7]);    SQRADD2(a[4], a[6]);    SQRADD(a[5], a[5]); 
      COMBA_STORE(b[10]);

      /* output 11 */
      CARRY_FORWARD;
      SQRADD2(a[4], a[7]);    SQRADD2(a[5], a[6]); 
      COMBA_STORE(b[11]);

      /* output 12 */
      CARRY_FORWARD;
      SQRADD2(a[5], a[7]);    SQRADD(a[6], a[6]); 
      COMBA_STORE(b[12]);

      /* output 13 */
      CARRY_FORWARD;
      SQRADD2(a[6], a[7]); 
      COMBA_STORE(b[13]);

      /* output 14 */
      CARRY_FORWARD;
      SQRADD(a[7], a[7]); 
      COMBA_STORE(b[14]);
      COMBA_STORE2(b[15]);
      COMBA_FINI;

      B->used = 16;
      B->sign = FP_ZPOS;
      memcpy(B->dp, b, 16 * sizeof(fp_digit));
      fp_clamp(B);
      break;

   case 9:
      a = A->dp;
      COMBA_START; 

      /* clear carries */
      CLEAR_CARRY;

      /* output 0 */
      SQRADD(a[0],a[0]);
      COMBA_STORE(b[0]);

      /* output 1 */
      CARRY_FORWARD;
      SQRADD2(a[0], a[1]); 
      COMBA_STORE(b[1]);

      /* output 2 */
      CARRY_FORWARD;
      SQRADD2(a[0], a[2]);    SQRADD(a[1], a[1]); 
      COMBA_STORE(b[2]);

      /* output 3 */
      CARRY_FORWARD;
      SQRADD2(a[0], a[3]);    SQRADD2(a[1], a[2]); 
      COMBA_STORE(b[3]);

      /* output 4 */
      CARRY_FORWARD;
      SQRADD2(a[0], a[4]);    SQRADD2(a[1], a[3]);    SQRADD(a[2], a[2]); 
      COMBA_STORE(b[4]);

      /* output 5 */
      CARRY_FORWARD;
   SQRADDSC(a[0], a[5]); SQRADDAC(a[1], a[4]); SQRADDAC(a[2], a[3]); SQRADDDB; 
      COMBA_STORE(b[5]);

      /* output 6 */
      CARRY_FORWARD;
   SQRADDSC(a[0], a[6]); SQRADDAC(a[1], a[5]); SQRADDAC(a[2], a[4]); SQRADDDB; SQRADD(a[3], a[3]); 
      COMBA_STORE(b[6]);

      /* output 7 */
      CARRY_FORWARD;
   SQRADDSC(a[0], a[7]); SQRADDAC(a[1], a[6]); SQRADDAC(a[2], a[5]); SQRADDAC(a[3], a[4]); SQRADDDB; 
      COMBA_STORE(b[7]);

      /* output 8 */
      CARRY_FORWARD;
   SQRADDSC(a[0], a[8]); SQRADDAC(a[1], a[7]); SQRADDAC(a[2], a[6]); SQRADDAC(a[3], a[5]); SQRADDDB; SQRADD(a[4], a[4]); 
      COMBA_STORE(b[8]);

      /* output 9 */
      CARRY_FORWARD;
   SQRADDSC(a[1], a[8]); SQRADDAC(a[2], a[7]); SQRADDAC(a[3], a[6]); SQRADDAC(a[4], a[5]); SQRADDDB; 
      COMBA_STORE(b[9]);

      /* output 10 */
      CARRY_FORWARD;
   SQRADDSC(a[2], a[8]); SQRADDAC(a[3], a[7]); SQRADDAC(a[4], a[6]); SQRADDDB; SQRADD(a[5], a[5]); 
      COMBA_STORE(b[10]);

      /* output 11 */
      CARRY_FORWARD;
   SQRADDSC(a[3], a[8]); SQRADDAC(a[4], a[7]); SQRADDAC(a[5], a[6]); SQRADDDB; 
      COMBA_STORE(b[11]);

      /* output 12 */
      CARRY_FORWARD;
      SQRADD2(a[4], a[8]);    SQRADD2(a[5], a[7]);    SQRADD(a[6], a[6]); 
      COMBA_STORE(b[12]);

      /* output 13 */
      CARRY_FORWARD;
      SQRADD2(a[5], a[8]);    SQRADD2(a[6], a[7]); 
      COMBA_STORE(b[13]);

      /* output 14 */
      CARRY_FORWARD;
      SQRADD2(a[6], a[8]);    SQRADD(a[7], a[7]); 
      COMBA_STORE(b[14]);

      /* output 15 */
      CARRY_FORWARD;
      SQRADD2(a[7], a[8]); 
      COMBA_STORE(b[15]);

      /* output 16 */
      CARRY_FORWARD;
      SQRADD(a[8], a[8]); 
      COMBA_STORE(b[16]);
      COMBA_STORE2(b[17]);
      COMBA_FINI;

      B->used = 18;
      B->sign = FP_ZPOS;
      memcpy(B->dp, b, 18 * sizeof(fp_digit));
      fp_clamp(B);
      break;

   case 10:
      a = A->dp;
      COMBA_START; 

      /* clear carries */
      CLEAR_CARRY;

      /* output 0 */
      SQRADD(a[0],a[0]);
      COMBA_STORE(b[0]);

      /* output 1 */
      CARRY_FORWARD;
      SQRADD2(a[0], a[1]); 
      COMBA_STORE(b[1]);

      /* output 2 */
      CARRY_FORWARD;
      SQRADD2(a[0], a[2]);    SQRADD(a[1], a[1]); 
      COMBA_STORE(b[2]);

      /* output 3 */
      CARRY_FORWARD;
      SQRADD2(a[0], a[3]);    SQRADD2(a[1], a[2]); 
      COMBA_STORE(b[3]);

      /* output 4 */
      CARRY_FORWARD;
      SQRADD2(a[0], a[4]);    SQRADD2(a[1], a[3]);    SQRADD(a[2], a[2]); 
      COMBA_STORE(b[4]);

      /* output 5 */
      CARRY_FORWARD;
   SQRADDSC(a[0], a[5]); SQRADDAC(a[1], a[4]); SQRADDAC(a[2], a[3]); SQRADDDB; 
      COMBA_STORE(b[5]);

      /* output 6 */
      CARRY_FORWARD;
   SQRADDSC(a[0], a[6]); SQRADDAC(a[1], a[5]); SQRADDAC(a[2], a[4]); SQRADDDB; SQRADD(a[3], a[3]); 
      COMBA_STORE(b[6]);

      /* output 7 */
      CARRY_FORWARD;
   SQRADDSC(a[0], a[7]); SQRADDAC(a[1], a[6]); SQRADDAC(a[2], a[5]); SQRADDAC(a[3], a[4]); SQRADDDB; 
      COMBA_STORE(b[7]);

      /* output 8 */
      CARRY_FORWARD;
   SQRADDSC(a[0], a[8]); SQRADDAC(a[1], a[7]); SQRADDAC(a[2], a[6]); SQRADDAC(a[3], a[5]); SQRADDDB; SQRADD(a[4], a[4]); 
      COMBA_STORE(b[8]);

      /* output 9 */
      CARRY_FORWARD;
   SQRADDSC(a[0], a[9]); SQRADDAC(a[1], a[8]); SQRADDAC(a[2], a[7]); SQRADDAC(a[3], a[6]); SQRADDAC(a[4], a[5]); SQRADDDB; 
      COMBA_STORE(b[9]);

      /* output 10 */
      CARRY_FORWARD;
   SQRADDSC(a[1], a[9]); SQRADDAC(a[2], a[8]); SQRADDAC(a[3], a[7]); SQRADDAC(a[4], a[6]); SQRADDDB; SQRADD(a[5], a[5]); 
      COMBA_STORE(b[10]);

      /* output 11 */
      CARRY_FORWARD;
   SQRADDSC(a[2], a[9]); SQRADDAC(a[3], a[8]); SQRADDAC(a[4], a[7]); SQRADDAC(a[5], a[6]); SQRADDDB; 
      COMBA_STORE(b[11]);

      /* output 12 */
      CARRY_FORWARD;
   SQRADDSC(a[3], a[9]); SQRADDAC(a[4], a[8]); SQRADDAC(a[5], a[7]); SQRADDDB; SQRADD(a[6], a[6]); 
      COMBA_STORE(b[12]);

      /* output 13 */
      CARRY_FORWARD;
   SQRADDSC(a[4], a[9]); SQRADDAC(a[5], a[8]); SQRADDAC(a[6], a[7]); SQRADDDB; 
      COMBA_STORE(b[13]);

      /* output 14 */
      CARRY_FORWARD;
      SQRADD2(a[5], a[9]);    SQRADD2(a[6], a[8]);    SQRADD(a[7], a[7]); 
      COMBA_STORE(b[14]);

      /* output 15 */
      CARRY_FORWARD;
      SQRADD2(a[6], a[9]);    SQRADD2(a[7], a[8]); 
      COMBA_STORE(b[15]);

      /* output 16 */
      CARRY_FORWARD;
      SQRADD2(a[7], a[9]);    SQRADD(a[8], a[8]); 
      COMBA_STORE(b[16]);

      /* output 17 */
      CARRY_FORWARD;
      SQRADD2(a[8], a[9]); 
      COMBA_STORE(b[17]);

      /* output 18 */
      CARRY_FORWARD;
      SQRADD(a[9], a[9]); 
      COMBA_STORE(b[18]);
      COMBA_STORE2(b[19]);
      COMBA_FINI;

      B->used = 20;
      B->sign = FP_ZPOS;
      memcpy(B->dp, b, 20 * sizeof(fp_digit));
      fp_clamp(B);
      break;

   case 11:
      a = A->dp;
      COMBA_START; 

      /* clear carries */
      CLEAR_CARRY;

      /* output 0 */
      SQRADD(a[0],a[0]);
      COMBA_STORE(b[0]);

      /* output 1 */
      CARRY_FORWARD;
      SQRADD2(a[0], a[1]); 
      COMBA_STORE(b[1]);

      /* output 2 */
      CARRY_FORWARD;
      SQRADD2(a[0], a[2]);    SQRADD(a[1], a[1]); 
      COMBA_STORE(b[2]);

      /* output 3 */
      CARRY_FORWARD;
      SQRADD2(a[0], a[3]);    SQRADD2(a[1], a[2]); 
      COMBA_STORE(b[3]);

      /* output 4 */
      CARRY_FORWARD;
      SQRADD2(a[0], a[4]);    SQRADD2(a[1], a[3]);    SQRADD(a[2], a[2]); 
      COMBA_STORE(b[4]);

      /* output 5 */
      CARRY_FORWARD;
   SQRADDSC(a[0], a[5]); SQRADDAC(a[1], a[4]); SQRADDAC(a[2], a[3]); SQRADDDB; 
      COMBA_STORE(b[5]);

      /* output 6 */
      CARRY_FORWARD;
   SQRADDSC(a[0], a[6]); SQRADDAC(a[1], a[5]); SQRADDAC(a[2], a[4]); SQRADDDB; SQRADD(a[3], a[3]); 
      COMBA_STORE(b[6]);

      /* output 7 */
      CARRY_FORWARD;
   SQRADDSC(a[0], a[7]); SQRADDAC(a[1], a[6]); SQRADDAC(a[2], a[5]); SQRADDAC(a[3], a[4]); SQRADDDB; 
      COMBA_STORE(b[7]);

      /* output 8 */
      CARRY_FORWARD;
   SQRADDSC(a[0], a[8]); SQRADDAC(a[1], a[7]); SQRADDAC(a[2], a[6]); SQRADDAC(a[3], a[5]); SQRADDDB; SQRADD(a[4], a[4]); 
      COMBA_STORE(b[8]);

      /* output 9 */
      CARRY_FORWARD;
   SQRADDSC(a[0], a[9]); SQRADDAC(a[1], a[8]); SQRADDAC(a[2], a[7]); SQRADDAC(a[3], a[6]); SQRADDAC(a[4], a[5]); SQRADDDB; 
      COMBA_STORE(b[9]);

      /* output 10 */
      CARRY_FORWARD;
   SQRADDSC(a[0], a[10]); SQRADDAC(a[1], a[9]); SQRADDAC(a[2], a[8]); SQRADDAC(a[3], a[7]); SQRADDAC(a[4], a[6]); SQRADDDB; SQRADD(a[5], a[5]); 
      COMBA_STORE(b[10]);

      /* output 11 */
      CARRY_FORWARD;
   SQRADDSC(a[1], a[10]); SQRADDAC(a[2], a[9]); SQRADDAC(a[3], a[8]); SQRADDAC(a[4], a[7]); SQRADDAC(a[5], a[6]); SQRADDDB; 
      COMBA_STORE(b[11]);

      /* output 12 */
      CARRY_FORWARD;
   SQRADDSC(a[2], a[10]); SQRADDAC(a[3], a[9]); SQRADDAC(a[4], a[8]); SQRADDAC(a[5], a[7]); SQRADDDB; SQRADD(a[6], a[6]); 
      COMBA_STORE(b[12]);

      /* output 13 */
      CARRY_FORWARD;
   SQRADDSC(a[3], a[10]); SQRADDAC(a[4], a[9]); SQRADDAC(a[5], a[8]); SQRADDAC(a[6], a[7]); SQRADDDB; 
      COMBA_STORE(b[13]);

      /* output 14 */
      CARRY_FORWARD;
   SQRADDSC(a[4], a[10]); SQRADDAC(a[5], a[9]); SQRADDAC(a[6], a[8]); SQRADDDB; SQRADD(a[7], a[7]); 
      COMBA_STORE(b[14]);

      /* output 15 */
      CARRY_FORWARD;
   SQRADDSC(a[5], a[10]); SQRADDAC(a[6], a[9]); SQRADDAC(a[7], a[8]); SQRADDDB; 
      COMBA_STORE(b[15]);

      /* output 16 */
      CARRY_FORWARD;
      SQRADD2(a[6], a[10]);    SQRADD2(a[7], a[9]);    SQRADD(a[8], a[8]); 
      COMBA_STORE(b[16]);

      /* output 17 */
      CARRY_FORWARD;
      SQRADD2(a[7], a[10]);    SQRADD2(a[8], a[9]); 
      COMBA_STORE(b[17]);

      /* output 18 */
      CARRY_FORWARD;
      SQRADD2(a[8], a[10]);    SQRADD(a[9], a[9]); 
      COMBA_STORE(b[18]);

      /* output 19 */
      CARRY_FORWARD;
      SQRADD2(a[9], a[10]); 
      COMBA_STORE(b[19]);

      /* output 20 */
      CARRY_FORWARD;
      SQRADD(a[10], a[10]); 
      COMBA_STORE(b[20]);
      COMBA_STORE2(b[21]);
      COMBA_FINI;

      B->used = 22;
      B->sign = FP_ZPOS;
      memcpy(B->dp, b, 22 * sizeof(fp_digit));
      fp_clamp(B);
      break;

   case 12:
      a = A->dp;
      COMBA_START; 

      /* clear carries */
      CLEAR_CARRY;

      /* output 0 */
      SQRADD(a[0],a[0]);
      COMBA_STORE(b[0]);

      /* output 1 */
      CARRY_FORWARD;
      SQRADD2(a[0], a[1]); 
      COMBA_STORE(b[1]);

      /* output 2 */
      CARRY_FORWARD;
      SQRADD2(a[0], a[2]);    SQRADD(a[1], a[1]); 
      COMBA_STORE(b[2]);

      /* output 3 */
      CARRY_FORWARD;
      SQRADD2(a[0], a[3]);    SQRADD2(a[1], a[2]); 
      COMBA_STORE(b[3]);

      /* output 4 */
      CARRY_FORWARD;
      SQRADD2(a[0], a[4]);    SQRADD2(a[1], a[3]);    SQRADD(a[2], a[2]); 
      COMBA_STORE(b[4]);

      /* output 5 */
      CARRY_FORWARD;
   SQRADDSC(a[0], a[5]); SQRADDAC(a[1], a[4]); SQRADDAC(a[2], a[3]); SQRADDDB; 
      COMBA_STORE(b[5]);

      /* output 6 */
      CARRY_FORWARD;
   SQRADDSC(a[0], a[6]); SQRADDAC(a[1], a[5]); SQRADDAC(a[2], a[4]); SQRADDDB; SQRADD(a[3], a[3]); 
      COMBA_STORE(b[6]);

      /* output 7 */
      CARRY_FORWARD;
   SQRADDSC(a[0], a[7]); SQRADDAC(a[1], a[6]); SQRADDAC(a[2], a[5]); SQRADDAC(a[3], a[4]); SQRADDDB; 
      COMBA_STORE(b[7]);

      /* output 8 */
      CARRY_FORWARD;
   SQRADDSC(a[0], a[8]); SQRADDAC(a[1], a[7]); SQRADDAC(a[2], a[6]); SQRADDAC(a[3], a[5]); SQRADDDB; SQRADD(a[4], a[4]); 
      COMBA_STORE(b[8]);

      /* output 9 */
      CARRY_FORWARD;
   SQRADDSC(a[0], a[9]); SQRADDAC(a[1], a[8]); SQRADDAC(a[2], a[7]); SQRADDAC(a[3], a[6]); SQRADDAC(a[4], a[5]); SQRADDDB; 
      COMBA_STORE(b[9]);

      /* output 10 */
      CARRY_FORWARD;
   SQRADDSC(a[0], a[10]); SQRADDAC(a[1], a[9]); SQRADDAC(a[2], a[8]); SQRADDAC(a[3], a[7]); SQRADDAC(a[4], a[6]); SQRADDDB; SQRADD(a[5], a[5]); 
      COMBA_STORE(b[10]);

      /* output 11 */
      CARRY_FORWARD;
   SQRADDSC(a[0], a[11]); SQRADDAC(a[1], a[10]); SQRADDAC(a[2], a[9]); SQRADDAC(a[3], a[8]); SQRADDAC(a[4], a[7]); SQRADDAC(a[5], a[6]); SQRADDDB; 
      COMBA_STORE(b[11]);

      /* output 12 */
      CARRY_FORWARD;
   SQRADDSC(a[1], a[11]); SQRADDAC(a[2], a[10]); SQRADDAC(a[3], a[9]); SQRADDAC(a[4], a[8]); SQRADDAC(a[5], a[7]); SQRADDDB; SQRADD(a[6], a[6]); 
      COMBA_STORE(b[12]);

      /* output 13 */
      CARRY_FORWARD;
   SQRADDSC(a[2], a[11]); SQRADDAC(a[3], a[10]); SQRADDAC(a[4], a[9]); SQRADDAC(a[5], a[8]); SQRADDAC(a[6], a[7]); SQRADDDB; 
      COMBA_STORE(b[13]);

      /* output 14 */
      CARRY_FORWARD;
   SQRADDSC(a[3], a[11]); SQRADDAC(a[4], a[10]); SQRADDAC(a[5], a[9]); SQRADDAC(a[6], a[8]); SQRADDDB; SQRADD(a[7], a[7]); 
      COMBA_STORE(b[14]);

      /* output 15 */
      CARRY_FORWARD;
   SQRADDSC(a[4], a[11]); SQRADDAC(a[5], a[10]); SQRADDAC(a[6], a[9]); SQRADDAC(a[7], a[8]); SQRADDDB; 
      COMBA_STORE(b[15]);

      /* output 16 */
      CARRY_FORWARD;
   SQRADDSC(a[5], a[11]); SQRADDAC(a[6], a[10]); SQRADDAC(a[7], a[9]); SQRADDDB; SQRADD(a[8], a[8]); 
      COMBA_STORE(b[16]);

      /* output 17 */
      CARRY_FORWARD;
   SQRADDSC(a[6], a[11]); SQRADDAC(a[7], a[10]); SQRADDAC(a[8], a[9]); SQRADDDB; 
      COMBA_STORE(b[17]);

      /* output 18 */
      CARRY_FORWARD;
      SQRADD2(a[7], a[11]);    SQRADD2(a[8], a[10]);    SQRADD(a[9], a[9]); 
      COMBA_STORE(b[18]);

      /* output 19 */
      CARRY_FORWARD;
      SQRADD2(a[8], a[11]);    SQRADD2(a[9], a[10]); 
      COMBA_STORE(b[19]);

      /* output 20 */
      CARRY_FORWARD;
      SQRADD2(a[9], a[11]);    SQRADD(a[10], a[10]); 
      COMBA_STORE(b[20]);

      /* output 21 */
      CARRY_FORWARD;
      SQRADD2(a[10], a[11]); 
      COMBA_STORE(b[21]);

      /* output 22 */
      CARRY_FORWARD;
      SQRADD(a[11], a[11]); 
      COMBA_STORE(b[22]);
      COMBA_STORE2(b[23]);
      COMBA_FINI;

      B->used = 24;
      B->sign = FP_ZPOS;
      memcpy(B->dp, b, 24 * sizeof(fp_digit));
      fp_clamp(B);
      break;

   case 13:
      a = A->dp;
      COMBA_START; 

      /* clear carries */
      CLEAR_CARRY;

      /* output 0 */
      SQRADD(a[0],a[0]);
      COMBA_STORE(b[0]);

      /* output 1 */
      CARRY_FORWARD;
      SQRADD2(a[0], a[1]); 
      COMBA_STORE(b[1]);

      /* output 2 */
      CARRY_FORWARD;
      SQRADD2(a[0], a[2]);    SQRADD(a[1], a[1]); 
      COMBA_STORE(b[2]);

      /* output 3 */
      CARRY_FORWARD;
      SQRADD2(a[0], a[3]);    SQRADD2(a[1], a[2]); 
      COMBA_STORE(b[3]);

      /* output 4 */
      CARRY_FORWARD;
      SQRADD2(a[0], a[4]);    SQRADD2(a[1], a[3]);    SQRADD(a[2], a[2]); 
      COMBA_STORE(b[4]);

      /* output 5 */
      CARRY_FORWARD;
   SQRADDSC(a[0], a[5]); SQRADDAC(a[1], a[4]); SQRADDAC(a[2], a[3]); SQRADDDB; 
      COMBA_STORE(b[5]);

      /* output 6 */
      CARRY_FORWARD;
   SQRADDSC(a[0], a[6]); SQRADDAC(a[1], a[5]); SQRADDAC(a[2], a[4]); SQRADDDB; SQRADD(a[3], a[3]); 
      COMBA_STORE(b[6]);

      /* output 7 */
      CARRY_FORWARD;
   SQRADDSC(a[0], a[7]); SQRADDAC(a[1], a[6]); SQRADDAC(a[2], a[5]); SQRADDAC(a[3], a[4]); SQRADDDB; 
      COMBA_STORE(b[7]);

      /* output 8 */
      CARRY_FORWARD;
   SQRADDSC(a[0], a[8]); SQRADDAC(a[1], a[7]); SQRADDAC(a[2], a[6]); SQRADDAC(a[3], a[5]); SQRADDDB; SQRADD(a[4], a[4]); 
      COMBA_STORE(b[8]);

      /* output 9 */
      CARRY_FORWARD;
   SQRADDSC(a[0], a[9]); SQRADDAC(a[1], a[8]); SQRADDAC(a[2], a[7]); SQRADDAC(a[3], a[6]); SQRADDAC(a[4], a[5]); SQRADDDB; 
      COMBA_STORE(b[9]);

      /* output 10 */
      CARRY_FORWARD;
   SQRADDSC(a[0], a[10]); SQRADDAC(a[1], a[9]); SQRADDAC(a[2], a[8]); SQRADDAC(a[3], a[7]); SQRADDAC(a[4], a[6]); SQRADDDB; SQRADD(a[5], a[5]); 
      COMBA_STORE(b[10]);

      /* output 11 */
      CARRY_FORWARD;
   SQRADDSC(a[0], a[11]); SQRADDAC(a[1], a[10]); SQRADDAC(a[2], a[9]); SQRADDAC(a[3], a[8]); SQRADDAC(a[4], a[7]); SQRADDAC(a[5], a[6]); SQRADDDB; 
      COMBA_STORE(b[11]);

      /* output 12 */
      CARRY_FORWARD;
   SQRADDSC(a[0], a[12]); SQRADDAC(a[1], a[11]); SQRADDAC(a[2], a[10]); SQRADDAC(a[3], a[9]); SQRADDAC(a[4], a[8]); SQRADDAC(a[5], a[7]); SQRADDDB; SQRADD(a[6], a[6]); 
      COMBA_STORE(b[12]);

      /* output 13 */
      CARRY_FORWARD;
   SQRADDSC(a[1], a[12]); SQRADDAC(a[2], a[11]); SQRADDAC(a[3], a[10]); SQRADDAC(a[4], a[9]); SQRADDAC(a[5], a[8]); SQRADDAC(a[6], a[7]); SQRADDDB; 
      COMBA_STORE(b[13]);

      /* output 14 */
      CARRY_FORWARD;
   SQRADDSC(a[2], a[12]); SQRADDAC(a[3], a[11]); SQRADDAC(a[4], a[10]); SQRADDAC(a[5], a[9]); SQRADDAC(a[6], a[8]); SQRADDDB; SQRADD(a[7], a[7]); 
      COMBA_STORE(b[14]);

      /* output 15 */
      CARRY_FORWARD;
   SQRADDSC(a[3], a[12]); SQRADDAC(a[4], a[11]); SQRADDAC(a[5], a[10]); SQRADDAC(a[6], a[9]); SQRADDAC(a[7], a[8]); SQRADDDB; 
      COMBA_STORE(b[15]);

      /* output 16 */
      CARRY_FORWARD;
   SQRADDSC(a[4], a[12]); SQRADDAC(a[5], a[11]); SQRADDAC(a[6], a[10]); SQRADDAC(a[7], a[9]); SQRADDDB; SQRADD(a[8], a[8]); 
      COMBA_STORE(b[16]);

      /* output 17 */
      CARRY_FORWARD;
   SQRADDSC(a[5], a[12]); SQRADDAC(a[6], a[11]); SQRADDAC(a[7], a[10]); SQRADDAC(a[8], a[9]); SQRADDDB; 
      COMBA_STORE(b[17]);

      /* output 18 */
      CARRY_FORWARD;
   SQRADDSC(a[6], a[12]); SQRADDAC(a[7], a[11]); SQRADDAC(a[8], a[10]); SQRADDDB; SQRADD(a[9], a[9]); 
      COMBA_STORE(b[18]);

      /* output 19 */
      CARRY_FORWARD;
   SQRADDSC(a[7], a[12]); SQRADDAC(a[8], a[11]); SQRADDAC(a[9], a[10]); SQRADDDB; 
      COMBA_STORE(b[19]);

      /* output 20 */
      CARRY_FORWARD;
      SQRADD2(a[8], a[12]);    SQRADD2(a[9], a[11]);    SQRADD(a[10], a[10]); 
      COMBA_STORE(b[20]);

      /* output 21 */
      CARRY_FORWARD;
      SQRADD2(a[9], a[12]);    SQRADD2(a[10], a[11]); 
      COMBA_STORE(b[21]);

      /* output 22 */
      CARRY_FORWARD;
      SQRADD2(a[10], a[12]);    SQRADD(a[11], a[11]); 
      COMBA_STORE(b[22]);

      /* output 23 */
      CARRY_FORWARD;
      SQRADD2(a[11], a[12]); 
      COMBA_STORE(b[23]);

      /* output 24 */
      CARRY_FORWARD;
      SQRADD(a[12], a[12]); 
      COMBA_STORE(b[24]);
      COMBA_STORE2(b[25]);
      COMBA_FINI;

      B->used = 26;
      B->sign = FP_ZPOS;
      memcpy(B->dp, b, 26 * sizeof(fp_digit));
      fp_clamp(B);
      break;

   case 14:
      a = A->dp;
      COMBA_START; 

      /* clear carries */
      CLEAR_CARRY;

      /* output 0 */
      SQRADD(a[0],a[0]);
      COMBA_STORE(b[0]);

      /* output 1 */
      CARRY_FORWARD;
      SQRADD2(a[0], a[1]); 
      COMBA_STORE(b[1]);

      /* output 2 */
      CARRY_FORWARD;
      SQRADD2(a[0], a[2]);    SQRADD(a[1], a[1]); 
      COMBA_STORE(b[2]);

      /* output 3 */
      CARRY_FORWARD;
      SQRADD2(a[0], a[3]);    SQRADD2(a[1], a[2]); 
      COMBA_STORE(b[3]);

      /* output 4 */
      CARRY_FORWARD;
      SQRADD2(a[0], a[4]);    SQRADD2(a[1], a[3]);    SQRADD(a[2], a[2]); 
      COMBA_STORE(b[4]);

      /* output 5 */
      CARRY_FORWARD;
   SQRADDSC(a[0], a[5]); SQRADDAC(a[1], a[4]); SQRADDAC(a[2], a[3]); SQRADDDB; 
      COMBA_STORE(b[5]);

      /* output 6 */
      CARRY_FORWARD;
   SQRADDSC(a[0], a[6]); SQRADDAC(a[1], a[5]); SQRADDAC(a[2], a[4]); SQRADDDB; SQRADD(a[3], a[3]); 
      COMBA_STORE(b[6]);

      /* output 7 */
      CARRY_FORWARD;
   SQRADDSC(a[0], a[7]); SQRADDAC(a[1], a[6]); SQRADDAC(a[2], a[5]); SQRADDAC(a[3], a[4]); SQRADDDB; 
      COMBA_STORE(b[7]);

      /* output 8 */
      CARRY_FORWARD;
   SQRADDSC(a[0], a[8]); SQRADDAC(a[1], a[7]); SQRADDAC(a[2], a[6]); SQRADDAC(a[3], a[5]); SQRADDDB; SQRADD(a[4], a[4]); 
      COMBA_STORE(b[8]);

      /* output 9 */
      CARRY_FORWARD;
   SQRADDSC(a[0], a[9]); SQRADDAC(a[1], a[8]); SQRADDAC(a[2], a[7]); SQRADDAC(a[3], a[6]); SQRADDAC(a[4], a[5]); SQRADDDB; 
      COMBA_STORE(b[9]);

      /* output 10 */
      CARRY_FORWARD;
   SQRADDSC(a[0], a[10]); SQRADDAC(a[1], a[9]); SQRADDAC(a[2], a[8]); SQRADDAC(a[3], a[7]); SQRADDAC(a[4], a[6]); SQRADDDB; SQRADD(a[5], a[5]); 
      COMBA_STORE(b[10]);

      /* output 11 */
      CARRY_FORWARD;
   SQRADDSC(a[0], a[11]); SQRADDAC(a[1], a[10]); SQRADDAC(a[2], a[9]); SQRADDAC(a[3], a[8]); SQRADDAC(a[4], a[7]); SQRADDAC(a[5], a[6]); SQRADDDB; 
      COMBA_STORE(b[11]);

      /* output 12 */
      CARRY_FORWARD;
   SQRADDSC(a[0], a[12]); SQRADDAC(a[1], a[11]); SQRADDAC(a[2], a[10]); SQRADDAC(a[3], a[9]); SQRADDAC(a[4], a[8]); SQRADDAC(a[5], a[7]); SQRADDDB; SQRADD(a[6], a[6]); 
      COMBA_STORE(b[12]);

      /* output 13 */
      CARRY_FORWARD;
   SQRADDSC(a[0], a[13]); SQRADDAC(a[1], a[12]); SQRADDAC(a[2], a[11]); SQRADDAC(a[3], a[10]); SQRADDAC(a[4], a[9]); SQRADDAC(a[5], a[8]); SQRADDAC(a[6], a[7]); SQRADDDB; 
      COMBA_STORE(b[13]);

      /* output 14 */
      CARRY_FORWARD;
   SQRADDSC(a[1], a[13]); SQRADDAC(a[2], a[12]); SQRADDAC(a[3], a[11]); SQRADDAC(a[4], a[10]); SQRADDAC(a[5], a[9]); SQRADDAC(a[6], a[8]); SQRADDDB; SQRADD(a[7], a[7]); 
      COMBA_STORE(b[14]);

      /* output 15 */
      CARRY_FORWARD;
   SQRADDSC(a[2], a[13]); SQRADDAC(a[3], a[12]); SQRADDAC(a[4], a[11]); SQRADDAC(a[5], a[10]); SQRADDAC(a[6], a[9]); SQRADDAC(a[7], a[8]); SQRADDDB; 
      COMBA_STORE(b[15]);

      /* output 16 */
      CARRY_FORWARD;
   SQRADDSC(a[3], a[13]); SQRADDAC(a[4], a[12]); SQRADDAC(a[5], a[11]); SQRADDAC(a[6], a[10]); SQRADDAC(a[7], a[9]); SQRADDDB; SQRADD(a[8], a[8]); 
      COMBA_STORE(b[16]);

      /* output 17 */
      CARRY_FORWARD;
   SQRADDSC(a[4], a[13]); SQRADDAC(a[5], a[12]); SQRADDAC(a[6], a[11]); SQRADDAC(a[7], a[10]); SQRADDAC(a[8], a[9]); SQRADDDB; 
      COMBA_STORE(b[17]);

      /* output 18 */
      CARRY_FORWARD;
   SQRADDSC(a[5], a[13]); SQRADDAC(a[6], a[12]); SQRADDAC(a[7], a[11]); SQRADDAC(a[8], a[10]); SQRADDDB; SQRADD(a[9], a[9]); 
      COMBA_STORE(b[18]);

      /* output 19 */
      CARRY_FORWARD;
   SQRADDSC(a[6], a[13]); SQRADDAC(a[7], a[12]); SQRADDAC(a[8], a[11]); SQRADDAC(a[9], a[10]); SQRADDDB; 
      COMBA_STORE(b[19]);

      /* output 20 */
      CARRY_FORWARD;
   SQRADDSC(a[7], a[13]); SQRADDAC(a[8], a[12]); SQRADDAC(a[9], a[11]); SQRADDDB; SQRADD(a[10], a[10]); 
      COMBA_STORE(b[20]);

      /* output 21 */
      CARRY_FORWARD;
   SQRADDSC(a[8], a[13]); SQRADDAC(a[9], a[12]); SQRADDAC(a[10], a[11]); SQRADDDB; 
      COMBA_STORE(b[21]);

      /* output 22 */
      CARRY_FORWARD;
      SQRADD2(a[9], a[13]);    SQRADD2(a[10], a[12]);    SQRADD(a[11], a[11]); 
      COMBA_STORE(b[22]);

      /* output 23 */
      CARRY_FORWARD;
      SQRADD2(a[10], a[13]);    SQRADD2(a[11], a[12]); 
      COMBA_STORE(b[23]);

      /* output 24 */
      CARRY_FORWARD;
      SQRADD2(a[11], a[13]);    SQRADD(a[12], a[12]); 
      COMBA_STORE(b[24]);

      /* output 25 */
      CARRY_FORWARD;
      SQRADD2(a[12], a[13]); 
      COMBA_STORE(b[25]);

      /* output 26 */
      CARRY_FORWARD;
      SQRADD(a[13], a[13]); 
      COMBA_STORE(b[26]);
      COMBA_STORE2(b[27]);
      COMBA_FINI;

      B->used = 28;
      B->sign = FP_ZPOS;
      memcpy(B->dp, b, 28 * sizeof(fp_digit));
      fp_clamp(B);
      break;

   case 15:
      a = A->dp;
      COMBA_START; 

      /* clear carries */
      CLEAR_CARRY;

      /* output 0 */
      SQRADD(a[0],a[0]);
      COMBA_STORE(b[0]);

      /* output 1 */
      CARRY_FORWARD;
      SQRADD2(a[0], a[1]); 
      COMBA_STORE(b[1]);

      /* output 2 */
      CARRY_FORWARD;
      SQRADD2(a[0], a[2]);    SQRADD(a[1], a[1]); 
      COMBA_STORE(b[2]);

      /* output 3 */
      CARRY_FORWARD;
      SQRADD2(a[0], a[3]);    SQRADD2(a[1], a[2]); 
      COMBA_STORE(b[3]);

      /* output 4 */
      CARRY_FORWARD;
      SQRADD2(a[0], a[4]);    SQRADD2(a[1], a[3]);    SQRADD(a[2], a[2]); 
      COMBA_STORE(b[4]);

      /* output 5 */
      CARRY_FORWARD;
   SQRADDSC(a[0], a[5]); SQRADDAC(a[1], a[4]); SQRADDAC(a[2], a[3]); SQRADDDB; 
      COMBA_STORE(b[5]);

      /* output 6 */
      CARRY_FORWARD;
   SQRADDSC(a[0], a[6]); SQRADDAC(a[1], a[5]); SQRADDAC(a[2], a[4]); SQRADDDB; SQRADD(a[3], a[3]); 
      COMBA_STORE(b[6]);

      /* output 7 */
      CARRY_FORWARD;
   SQRADDSC(a[0], a[7]); SQRADDAC(a[1], a[6]); SQRADDAC(a[2], a[5]); SQRADDAC(a[3], a[4]); SQRADDDB; 
      COMBA_STORE(b[7]);

      /* output 8 */
      CARRY_FORWARD;
   SQRADDSC(a[0], a[8]); SQRADDAC(a[1], a[7]); SQRADDAC(a[2], a[6]); SQRADDAC(a[3], a[5]); SQRADDDB; SQRADD(a[4], a[4]); 
      COMBA_STORE(b[8]);

      /* output 9 */
      CARRY_FORWARD;
   SQRADDSC(a[0], a[9]); SQRADDAC(a[1], a[8]); SQRADDAC(a[2], a[7]); SQRADDAC(a[3], a[6]); SQRADDAC(a[4], a[5]); SQRADDDB; 
      COMBA_STORE(b[9]);

      /* output 10 */
      CARRY_FORWARD;
   SQRADDSC(a[0], a[10]); SQRADDAC(a[1], a[9]); SQRADDAC(a[2], a[8]); SQRADDAC(a[3], a[7]); SQRADDAC(a[4], a[6]); SQRADDDB; SQRADD(a[5], a[5]); 
      COMBA_STORE(b[10]);

      /* output 11 */
      CARRY_FORWARD;
   SQRADDSC(a[0], a[11]); SQRADDAC(a[1], a[10]); SQRADDAC(a[2], a[9]); SQRADDAC(a[3], a[8]); SQRADDAC(a[4], a[7]); SQRADDAC(a[5], a[6]); SQRADDDB; 
      COMBA_STORE(b[11]);

      /* output 12 */
      CARRY_FORWARD;
   SQRADDSC(a[0], a[12]); SQRADDAC(a[1], a[11]); SQRADDAC(a[2], a[10]); SQRADDAC(a[3], a[9]); SQRADDAC(a[4], a[8]); SQRADDAC(a[5], a[7]); SQRADDDB; SQRADD(a[6], a[6]); 
      COMBA_STORE(b[12]);

      /* output 13 */
      CARRY_FORWARD;
   SQRADDSC(a[0], a[13]); SQRADDAC(a[1], a[12]); SQRADDAC(a[2], a[11]); SQRADDAC(a[3], a[10]); SQRADDAC(a[4], a[9]); SQRADDAC(a[5], a[8]); SQRADDAC(a[6], a[7]); SQRADDDB; 
      COMBA_STORE(b[13]);

      /* output 14 */
      CARRY_FORWARD;
   SQRADDSC(a[0], a[14]); SQRADDAC(a[1], a[13]); SQRADDAC(a[2], a[12]); SQRADDAC(a[3], a[11]); SQRADDAC(a[4], a[10]); SQRADDAC(a[5], a[9]); SQRADDAC(a[6], a[8]); SQRADDDB; SQRADD(a[7], a[7]); 
      COMBA_STORE(b[14]);

      /* output 15 */
      CARRY_FORWARD;
   SQRADDSC(a[1], a[14]); SQRADDAC(a[2], a[13]); SQRADDAC(a[3], a[12]); SQRADDAC(a[4], a[11]); SQRADDAC(a[5], a[10]); SQRADDAC(a[6], a[9]); SQRADDAC(a[7], a[8]); SQRADDDB; 
      COMBA_STORE(b[15]);

      /* output 16 */
      CARRY_FORWARD;
   SQRADDSC(a[2], a[14]); SQRADDAC(a[3], a[13]); SQRADDAC(a[4], a[12]); SQRADDAC(a[5], a[11]); SQRADDAC(a[6], a[10]); SQRADDAC(a[7], a[9]); SQRADDDB; SQRADD(a[8], a[8]); 
      COMBA_STORE(b[16]);

      /* output 17 */
      CARRY_FORWARD;
   SQRADDSC(a[3], a[14]); SQRADDAC(a[4], a[13]); SQRADDAC(a[5], a[12]); SQRADDAC(a[6], a[11]); SQRADDAC(a[7], a[10]); SQRADDAC(a[8], a[9]); SQRADDDB; 
      COMBA_STORE(b[17]);

      /* output 18 */
      CARRY_FORWARD;
   SQRADDSC(a[4], a[14]); SQRADDAC(a[5], a[13]); SQRADDAC(a[6], a[12]); SQRADDAC(a[7], a[11]); SQRADDAC(a[8], a[10]); SQRADDDB; SQRADD(a[9], a[9]); 
      COMBA_STORE(b[18]);

      /* output 19 */
      CARRY_FORWARD;
   SQRADDSC(a[5], a[14]); SQRADDAC(a[6], a[13]); SQRADDAC(a[7], a[12]); SQRADDAC(a[8], a[11]); SQRADDAC(a[9], a[10]); SQRADDDB; 
      COMBA_STORE(b[19]);

      /* output 20 */
      CARRY_FORWARD;
   SQRADDSC(a[6], a[14]); SQRADDAC(a[7], a[13]); SQRADDAC(a[8], a[12]); SQRADDAC(a[9], a[11]); SQRADDDB; SQRADD(a[10], a[10]); 
      COMBA_STORE(b[20]);

      /* output 21 */
      CARRY_FORWARD;
   SQRADDSC(a[7], a[14]); SQRADDAC(a[8], a[13]); SQRADDAC(a[9], a[12]); SQRADDAC(a[10], a[11]); SQRADDDB; 
      COMBA_STORE(b[21]);

      /* output 22 */
      CARRY_FORWARD;
   SQRADDSC(a[8], a[14]); SQRADDAC(a[9], a[13]); SQRADDAC(a[10], a[12]); SQRADDDB; SQRADD(a[11], a[11]); 
      COMBA_STORE(b[22]);

      /* output 23 */
      CARRY_FORWARD;
   SQRADDSC(a[9], a[14]); SQRADDAC(a[10], a[13]); SQRADDAC(a[11], a[12]); SQRADDDB; 
      COMBA_STORE(b[23]);

      /* output 24 */
      CARRY_FORWARD;
      SQRADD2(a[10], a[14]);    SQRADD2(a[11], a[13]);    SQRADD(a[12], a[12]); 
      COMBA_STORE(b[24]);

      /* output 25 */
      CARRY_FORWARD;
      SQRADD2(a[11], a[14]);    SQRADD2(a[12], a[13]); 
      COMBA_STORE(b[25]);

      /* output 26 */
      CARRY_FORWARD;
      SQRADD2(a[12], a[14]);    SQRADD(a[13], a[13]); 
      COMBA_STORE(b[26]);

      /* output 27 */
      CARRY_FORWARD;
      SQRADD2(a[13], a[14]); 
      COMBA_STORE(b[27]);

      /* output 28 */
      CARRY_FORWARD;
      SQRADD(a[14], a[14]); 
      COMBA_STORE(b[28]);
      COMBA_STORE2(b[29]);
      COMBA_FINI;

      B->used = 30;
      B->sign = FP_ZPOS;
      memcpy(B->dp, b, 30 * sizeof(fp_digit));
      fp_clamp(B);
      break;

   case 16:
      a = A->dp;
      COMBA_START; 

      /* clear carries */
      CLEAR_CARRY;

      /* output 0 */
      SQRADD(a[0],a[0]);
      COMBA_STORE(b[0]);

      /* output 1 */
      CARRY_FORWARD;
      SQRADD2(a[0], a[1]); 
      COMBA_STORE(b[1]);

      /* output 2 */
      CARRY_FORWARD;
      SQRADD2(a[0], a[2]);    SQRADD(a[1], a[1]); 
      COMBA_STORE(b[2]);

      /* output 3 */
      CARRY_FORWARD;
      SQRADD2(a[0], a[3]);    SQRADD2(a[1], a[2]); 
      COMBA_STORE(b[3]);

      /* output 4 */
      CARRY_FORWARD;
      SQRADD2(a[0], a[4]);    SQRADD2(a[1], a[3]);    SQRADD(a[2], a[2]); 
      COMBA_STORE(b[4]);

      /* output 5 */
      CARRY_FORWARD;
   SQRADDSC(a[0], a[5]); SQRADDAC(a[1], a[4]); SQRADDAC(a[2], a[3]); SQRADDDB; 
      COMBA_STORE(b[5]);

      /* output 6 */
      CARRY_FORWARD;
   SQRADDSC(a[0], a[6]); SQRADDAC(a[1], a[5]); SQRADDAC(a[2], a[4]); SQRADDDB; SQRADD(a[3], a[3]); 
      COMBA_STORE(b[6]);

      /* output 7 */
      CARRY_FORWARD;
   SQRADDSC(a[0], a[7]); SQRADDAC(a[1], a[6]); SQRADDAC(a[2], a[5]); SQRADDAC(a[3], a[4]); SQRADDDB; 
      COMBA_STORE(b[7]);

      /* output 8 */
      CARRY_FORWARD;
   SQRADDSC(a[0], a[8]); SQRADDAC(a[1], a[7]); SQRADDAC(a[2], a[6]); SQRADDAC(a[3], a[5]); SQRADDDB; SQRADD(a[4], a[4]); 
      COMBA_STORE(b[8]);

      /* output 9 */
      CARRY_FORWARD;
   SQRADDSC(a[0], a[9]); SQRADDAC(a[1], a[8]); SQRADDAC(a[2], a[7]); SQRADDAC(a[3], a[6]); SQRADDAC(a[4], a[5]); SQRADDDB; 
      COMBA_STORE(b[9]);

      /* output 10 */
      CARRY_FORWARD;
   SQRADDSC(a[0], a[10]); SQRADDAC(a[1], a[9]); SQRADDAC(a[2], a[8]); SQRADDAC(a[3], a[7]); SQRADDAC(a[4], a[6]); SQRADDDB; SQRADD(a[5], a[5]); 
      COMBA_STORE(b[10]);

      /* output 11 */
      CARRY_FORWARD;
   SQRADDSC(a[0], a[11]); SQRADDAC(a[1], a[10]); SQRADDAC(a[2], a[9]); SQRADDAC(a[3], a[8]); SQRADDAC(a[4], a[7]); SQRADDAC(a[5], a[6]); SQRADDDB; 
      COMBA_STORE(b[11]);

      /* output 12 */
      CARRY_FORWARD;
   SQRADDSC(a[0], a[12]); SQRADDAC(a[1], a[11]); SQRADDAC(a[2], a[10]); SQRADDAC(a[3], a[9]); SQRADDAC(a[4], a[8]); SQRADDAC(a[5], a[7]); SQRADDDB; SQRADD(a[6], a[6]); 
      COMBA_STORE(b[12]);

      /* output 13 */
      CARRY_FORWARD;
   SQRADDSC(a[0], a[13]); SQRADDAC(a[1], a[12]); SQRADDAC(a[2], a[11]); SQRADDAC(a[3], a[10]); SQRADDAC(a[4], a[9]); SQRADDAC(a[5], a[8]); SQRADDAC(a[6], a[7]); SQRADDDB; 
      COMBA_STORE(b[13]);

      /* output 14 */
      CARRY_FORWARD;
   SQRADDSC(a[0], a[14]); SQRADDAC(a[1], a[13]); SQRADDAC(a[2], a[12]); SQRADDAC(a[3], a[11]); SQRADDAC(a[4], a[10]); SQRADDAC(a[5], a[9]); SQRADDAC(a[6], a[8]); SQRADDDB; SQRADD(a[7], a[7]); 
      COMBA_STORE(b[14]);

      /* output 15 */
      CARRY_FORWARD;
   SQRADDSC(a[0], a[15]); SQRADDAC(a[1], a[14]); SQRADDAC(a[2], a[13]); SQRADDAC(a[3], a[12]); SQRADDAC(a[4], a[11]); SQRADDAC(a[5], a[10]); SQRADDAC(a[6], a[9]); SQRADDAC(a[7], a[8]); SQRADDDB; 
      COMBA_STORE(b[15]);

      /* output 16 */
      CARRY_FORWARD;
   SQRADDSC(a[1], a[15]); SQRADDAC(a[2], a[14]); SQRADDAC(a[3], a[13]); SQRADDAC(a[4], a[12]); SQRADDAC(a[5], a[11]); SQRADDAC(a[6], a[10]); SQRADDAC(a[7], a[9]); SQRADDDB; SQRADD(a[8], a[8]); 
      COMBA_STORE(b[16]);

      /* output 17 */
      CARRY_FORWARD;
   SQRADDSC(a[2], a[15]); SQRADDAC(a[3], a[14]); SQRADDAC(a[4], a[13]); SQRADDAC(a[5], a[12]); SQRADDAC(a[6], a[11]); SQRADDAC(a[7], a[10]); SQRADDAC(a[8], a[9]); SQRADDDB; 
      COMBA_STORE(b[17]);

      /* output 18 */
      CARRY_FORWARD;
   SQRADDSC(a[3], a[15]); SQRADDAC(a[4], a[14]); SQRADDAC(a[5], a[13]); SQRADDAC(a[6], a[12]); SQRADDAC(a[7], a[11]); SQRADDAC(a[8], a[10]); SQRADDDB; SQRADD(a[9], a[9]); 
      COMBA_STORE(b[18]);

      /* output 19 */
      CARRY_FORWARD;
   SQRADDSC(a[4], a[15]); SQRADDAC(a[5], a[14]); SQRADDAC(a[6], a[13]); SQRADDAC(a[7], a[12]); SQRADDAC(a[8], a[11]); SQRADDAC(a[9], a[10]); SQRADDDB; 
      COMBA_STORE(b[19]);

      /* output 20 */
      CARRY_FORWARD;
   SQRADDSC(a[5], a[15]); SQRADDAC(a[6], a[14]); SQRADDAC(a[7], a[13]); SQRADDAC(a[8], a[12]); SQRADDAC(a[9], a[11]); SQRADDDB; SQRADD(a[10], a[10]); 
      COMBA_STORE(b[20]);

      /* output 21 */
      CARRY_FORWARD;
   SQRADDSC(a[6], a[15]); SQRADDAC(a[7], a[14]); SQRADDAC(a[8], a[13]); SQRADDAC(a[9], a[12]); SQRADDAC(a[10], a[11]); SQRADDDB; 
      COMBA_STORE(b[21]);

      /* output 22 */
      CARRY_FORWARD;
   SQRADDSC(a[7], a[15]); SQRADDAC(a[8], a[14]); SQRADDAC(a[9], a[13]); SQRADDAC(a[10], a[12]); SQRADDDB; SQRADD(a[11], a[11]); 
      COMBA_STORE(b[22]);

      /* output 23 */
      CARRY_FORWARD;
   SQRADDSC(a[8], a[15]); SQRADDAC(a[9], a[14]); SQRADDAC(a[10], a[13]); SQRADDAC(a[11], a[12]); SQRADDDB; 
      COMBA_STORE(b[23]);

      /* output 24 */
      CARRY_FORWARD;
   SQRADDSC(a[9], a[15]); SQRADDAC(a[10], a[14]); SQRADDAC(a[11], a[13]); SQRADDDB; SQRADD(a[12], a[12]); 
      COMBA_STORE(b[24]);

      /* output 25 */
      CARRY_FORWARD;
   SQRADDSC(a[10], a[15]); SQRADDAC(a[11], a[14]); SQRADDAC(a[12], a[13]); SQRADDDB; 
      COMBA_STORE(b[25]);

      /* output 26 */
      CARRY_FORWARD;
      SQRADD2(a[11], a[15]);    SQRADD2(a[12], a[14]);    SQRADD(a[13], a[13]); 
      COMBA_STORE(b[26]);

      /* output 27 */
      CARRY_FORWARD;
      SQRADD2(a[12], a[15]);    SQRADD2(a[13], a[14]); 
      COMBA_STORE(b[27]);

      /* output 28 */
      CARRY_FORWARD;
      SQRADD2(a[13], a[15]);    SQRADD(a[14], a[14]); 
      COMBA_STORE(b[28]);

      /* output 29 */
      CARRY_FORWARD;
      SQRADD2(a[14], a[15]); 
      COMBA_STORE(b[29]);

      /* output 30 */
      CARRY_FORWARD;
      SQRADD(a[15], a[15]); 
      COMBA_STORE(b[30]);
      COMBA_STORE2(b[31]);
      COMBA_FINI;

      B->used = 32;
      B->sign = FP_ZPOS;
      memcpy(B->dp, b, 32 * sizeof(fp_digit));
      fp_clamp(B);
      break;
}
}

#endif /* TFM_SMALL_SET */

/* $Source: /cvs/libtom/tomsfastmath/src/sqr/fp_sqr_comba_small_set.c,v $ */
/* $Revision: 1.1 $ */
/* $Date: 2007/02/15 00:31:32 $ */

/* End: fp_sqr_comba_small_set.c */

/* Start: fp_sqrmod.c */
/* TomsFastMath, a fast ISO C bignum library.
 * 
 * This project is meant to fill in where LibTomMath
 * falls short.  That is speed ;-)
 *
 * This project is public domain and free for all purposes.
 * 
 * Tom St Denis, tomstdenis@gmail.com
 */
#include "bignum_fast.h"

/* c = a * a (mod b) */
int fp_sqrmod(fp_int *a, fp_int *b, fp_int *c)
{
  fp_int tmp;
  fp_zero(&tmp);
  fp_sqr(a, &tmp);
  return fp_mod(&tmp, b, c);
}

/* $Source: /cvs/libtom/tomsfastmath/src/sqr/fp_sqrmod.c,v $ */
/* $Revision: 1.1 $ */
/* $Date: 2006/12/31 21:25:53 $ */

/* End: fp_sqrmod.c */

/* Start: fp_sub.c */
/* TomsFastMath, a fast ISO C bignum library.
 * 
 * This project is meant to fill in where LibTomMath
 * falls short.  That is speed ;-)
 *
 * This project is public domain and free for all purposes.
 * 
 * Tom St Denis, tomstdenis@gmail.com
 */
#include "bignum_fast.h"

/* c = a - b */
void fp_sub(fp_int *a, fp_int *b, fp_int *c)
{
  int     sa, sb;

  sa = a->sign;
  sb = b->sign;

  if (sa != sb) {
    /* subtract a negative from a positive, OR */
    /* subtract a positive from a negative. */
    /* In either case, ADD their magnitudes, */
    /* and use the sign of the first number. */
    c->sign = sa;
    s_fp_add (a, b, c);
  } else {
    /* subtract a positive from a positive, OR */
    /* subtract a negative from a negative. */
    /* First, take the difference between their */
    /* magnitudes, then... */
    if (fp_cmp_mag (a, b) != FP_LT) {
      /* Copy the sign from the first */
      c->sign = sa;
      /* The first has a larger or equal magnitude */
      s_fp_sub (a, b, c);
    } else {
      /* The result has the *opposite* sign from */
      /* the first number. */
      c->sign = (sa == FP_ZPOS) ? FP_NEG : FP_ZPOS;
      /* The second has a larger magnitude */
      s_fp_sub (b, a, c);
    }
  }
}


/* $Source: /cvs/libtom/tomsfastmath/src/addsub/fp_sub.c,v $ */
/* $Revision: 1.1 $ */
/* $Date: 2006/12/31 21:25:53 $ */

/* End: fp_sub.c */

/* Start: fp_sub_d.c */
/* TomsFastMath, a fast ISO C bignum library.
 * 
 * This project is meant to fill in where LibTomMath
 * falls short.  That is speed ;-)
 *
 * This project is public domain and free for all purposes.
 * 
 * Tom St Denis, tomstdenis@gmail.com
 */
#include "bignum_fast.h"

/* c = a - b */
void fp_sub_d(fp_int *a, fp_digit b, fp_int *c)
{
   fp_int tmp;
   fp_set(&tmp, b);
   fp_sub(a, &tmp, c);
}

/* $Source: /cvs/libtom/tomsfastmath/src/addsub/fp_sub_d.c,v $ */
/* $Revision: 1.1 $ */
/* $Date: 2006/12/31 21:25:53 $ */

/* End: fp_sub_d.c */

/* Start: fp_submod.c */
/* TomsFastMath, a fast ISO C bignum library.
 * 
 * This project is meant to fill in where LibTomMath
 * falls short.  That is speed ;-)
 *
 * This project is public domain and free for all purposes.
 * 
 * Tom St Denis, tomstdenis@gmail.com
 */
#include "bignum_fast.h"

/* d = a - b (mod c) */
int fp_submod(fp_int *a, fp_int *b, fp_int *c, fp_int *d)
{
  fp_int tmp;
  fp_zero(&tmp);
  fp_sub(a, b, &tmp);
  return fp_mod(&tmp, c, d);
}


/* $Source: /cvs/libtom/tomsfastmath/src/addsub/fp_submod.c,v $ */
/* $Revision: 1.1 $ */
/* $Date: 2006/12/31 21:25:53 $ */

/* End: fp_submod.c */

/* Start: fp_to_signed_bin.c */
/* TomsFastMath, a fast ISO C bignum library.
 * 
 * This project is meant to fill in where LibTomMath
 * falls short.  That is speed ;-)
 *
 * This project is public domain and free for all purposes.
 * 
 * Tom St Denis, tomstdenis@gmail.com
 */
#include "bignum_fast.h"

void fp_to_signed_bin(fp_int *a, unsigned char *b)
{
  fp_to_unsigned_bin (a, b + 1);
  b[0] = (unsigned char) ((a->sign == FP_ZPOS) ? 0 : 1);
}

/* $Source: /cvs/libtom/tomsfastmath/src/bin/fp_to_signed_bin.c,v $ */
/* $Revision: 1.1 $ */
/* $Date: 2006/12/31 21:25:53 $ */

/* End: fp_to_signed_bin.c */

/* Start: fp_to_unsigned_bin.c */
/* TomsFastMath, a fast ISO C bignum library.
 * 
 * This project is meant to fill in where LibTomMath
 * falls short.  That is speed ;-)
 *
 * This project is public domain and free for all purposes.
 * 
 * Tom St Denis, tomstdenis@gmail.com
 */
#include "bignum_fast.h"

void fp_to_unsigned_bin(fp_int *a, unsigned char *b)
{
  int     x;
  fp_int  t;

  fp_init_copy(&t, a);

  x = 0;
  while (fp_iszero (&t) == FP_NO) {
      b[x++] = (unsigned char) (t.dp[0] & 255);
      fp_div_2d (&t, 8, &t, NULL);
  }
  fp_reverse (b, x);
}

/* $Source: /cvs/libtom/tomsfastmath/src/bin/fp_to_unsigned_bin.c,v $ */
/* $Revision: 1.2 $ */
/* $Date: 2007/02/27 02:38:44 $ */

/* End: fp_to_unsigned_bin.c */

/* Start: fp_toradix.c */
/* TomsFastMath, a fast ISO C bignum library.
 * 
 * This project is meant to fill in where LibTomMath
 * falls short.  That is speed ;-)
 *
 * This project is public domain and free for all purposes.
 * 
 * Tom St Denis, tomstdenis@gmail.com
 */
#include "bignum_fast.h"

int fp_toradix(fp_int *a, char *str, int radix)
{
  int     digs;
  fp_int  t;
  fp_digit d;
  char   *_s = str;

  /* check range of the radix */
  if (radix < 2 || radix > 64) {
    return FP_VAL;
  }

  /* quick out if its zero */
  if (fp_iszero(a) == 1) {
     *str++ = '0';
     *str = '\0';
     return FP_OKAY;
  }

  fp_init_copy(&t, a);

  /* if it is negative output a - */
  if (t.sign == FP_NEG) {
    ++_s;
    *str++ = '-';
    t.sign = FP_ZPOS;
  }

  digs = 0;
  while (fp_iszero (&t) == FP_NO) {
    fp_div_d (&t, (fp_digit) radix, &t, &d);
    *str++ = fp_s_rmap[d];
    ++digs;
  }

  /* reverse the digits of the string.  In this case _s points
   * to the first digit [exluding the sign] of the number]
   */
  fp_reverse ((unsigned char *)_s, digs);

  /* append a NULL so the string is properly terminated */
  *str = '\0';
  return FP_OKAY;
}

/* $Source: /cvs/libtom/tomsfastmath/src/bin/fp_toradix.c,v $ */
/* $Revision: 1.2 $ */
/* $Date: 2007/02/27 02:38:44 $ */

/* End: fp_toradix.c */

/* Start: fp_unsigned_bin_size.c */
/* TomsFastMath, a fast ISO C bignum library.
 * 
 * This project is meant to fill in where LibTomMath
 * falls short.  That is speed ;-)
 *
 * This project is public domain and free for all purposes.
 * 
 * Tom St Denis, tomstdenis@gmail.com
 */
#include "bignum_fast.h"

int fp_unsigned_bin_size(fp_int *a)
{
  int     size = fp_count_bits (a);
  return (size / 8 + ((size & 7) != 0 ? 1 : 0));
}

/* $Source: /cvs/libtom/tomsfastmath/src/bin/fp_unsigned_bin_size.c,v $ */
/* $Revision: 1.1 $ */
/* $Date: 2006/12/31 21:25:53 $ */

/* End: fp_unsigned_bin_size.c */

/* Start: s_fp_add.c */
/* TomsFastMath, a fast ISO C bignum library.
 * 
 * This project is meant to fill in where LibTomMath
 * falls short.  That is speed ;-)
 *
 * This project is public domain and free for all purposes.
 * 
 * Tom St Denis, tomstdenis@gmail.com
 */
#include "bignum_fast.h"

/* unsigned addition */
void s_fp_add(fp_int *a, fp_int *b, fp_int *c)
{
  int      x, y, oldused;
  register fp_word  t;

  y       = MAX(a->used, b->used);
  oldused = c->used;
  c->used = y;
 
  t = 0;
  for (x = 0; x < y; x++) {
      t         += ((fp_word)a->dp[x]) + ((fp_word)b->dp[x]);
      c->dp[x]   = (fp_digit)t;
      t        >>= DIGIT_BIT;
  }
  if (t != 0 && x < FP_SIZE) {
     c->dp[c->used++] = (fp_digit)t;
     ++x;
  }

  c->used = x;
  for (; x < oldused; x++) {
     c->dp[x] = 0;
  }
  fp_clamp(c);
}

/* $Source: /cvs/libtom/tomsfastmath/src/addsub/s_fp_add.c,v $ */
/* $Revision: 1.1 $ */
/* $Date: 2006/12/31 21:25:53 $ */

/* End: s_fp_add.c */

/* Start: s_fp_sub.c */
/* TomsFastMath, a fast ISO C bignum library.
 * 
 * This project is meant to fill in where LibTomMath
 * falls short.  That is speed ;-)
 *
 * This project is public domain and free for all purposes.
 * 
 * Tom St Denis, tomstdenis@gmail.com
 */
#include "bignum_fast.h"

/* unsigned subtraction ||a|| >= ||b|| ALWAYS! */
void s_fp_sub(fp_int *a, fp_int *b, fp_int *c)
{
  int      x, oldbused, oldused;
  fp_word  t;

  oldused  = c->used;
  oldbused = b->used;
  c->used  = a->used;
  t       = 0;
  for (x = 0; x < oldbused; x++) {
     t         = ((fp_word)a->dp[x]) - (((fp_word)b->dp[x]) + t);
     c->dp[x]  = (fp_digit)t;
     t         = (t >> DIGIT_BIT)&1;
  }
  for (; x < a->used; x++) {
     t         = ((fp_word)a->dp[x]) - t;
     c->dp[x]  = (fp_digit)t;
     t         = (t >> DIGIT_BIT);
   }
  for (; x < oldused; x++) {
     c->dp[x] = 0;
  }
  fp_clamp(c);
}

/* $Source: /cvs/libtom/tomsfastmath/src/addsub/s_fp_sub.c,v $ */
/* $Revision: 1.1 $ */
/* $Date: 2006/12/31 21:25:53 $ */

/* End: s_fp_sub.c */


/* EOF */
/* TomsFastMath, a fast ISO C bignum library.
 * 
 * This project is meant to fill in where LibTomMath
 * falls short.  That is speed ;-)
 *
 * This project is public domain and free for all purposes.
 * 
 * Tom St Denis, tomstdenis@gmail.com
 */

#define TFM_DEFINES
#include "fp_sqr_comba.c"

/* generic comba squarer */
void fp_sqr_comba(fp_int *A, fp_int *B)
{
  int       pa, ix, iz;
  fp_digit  c0, c1, c2;
  fp_int    tmp, *dst;
#ifdef TFM_ISO
  fp_word   tt;
#endif    

  /* get size of output and trim */
  pa = A->used + A->used;
  if (pa >= FP_SIZE) {
     pa = FP_SIZE-1;
  }

  /* number of output digits to produce */
  COMBA_START;
  CLEAR_CARRY;

  if (A == B) {
     fp_zero(&tmp);
     dst = &tmp;
  } else {
     fp_zero(B);
     dst = B;
  }

  for (ix = 0; ix < pa; ix++) { 
      int      tx, ty, iy;
      fp_digit *tmpy, *tmpx;

      /* get offsets into the two bignums */
      ty = MIN(A->used-1, ix);
      tx = ix - ty;

      /* setup temp aliases */
      tmpx = A->dp + tx;
      tmpy = A->dp + ty;

      /* this is the number of times the loop will iterrate,
         while (tx++ < a->used && ty-- >= 0) { ... }
       */
      iy = MIN(A->used-tx, ty+1);

      /* now for squaring tx can never equal ty 
       * we halve the distance since they approach 
       * at a rate of 2x and we have to round because 
       * odd cases need to be executed
       */
      iy = MIN(iy, (ty-tx+1)>>1);

      /* forward carries */
      CARRY_FORWARD;

      /* execute loop */
      for (iz = 0; iz < iy; iz++) {
          SQRADD2(*tmpx++, *tmpy--);
      }

      /* even columns have the square term in them */
      if ((ix&1) == 0) {
          SQRADD(A->dp[ix>>1], A->dp[ix>>1]);
      }

      /* store it */
      COMBA_STORE(dst->dp[ix]);
  }

  COMBA_FINI;

  /* setup dest */
  dst->used = pa;
  fp_clamp (dst);
  if (dst != B) {
     fp_copy(dst, B);
  }
}

/* $Source: /cvs/libtom/tomsfastmath/src/sqr/Attic/fp_sqr_comba_generic.c,v $ */
/* $Revision: 1.3 $ */
/* $Date: 2007/02/15 00:31:32 $ */

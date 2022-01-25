/* TomsFastMath, a fast ISO C bignum library.
 *
 * This project is meant to fill in where LibTomMath
 * falls short.  That is speed ;-)
 *
 * This project is public domain and free for all purposes.
 *
 * Tom St Denis, tomstdenis@gmail.com
 */
#include <tfm_private.h>

#if FP_GEN_RANDOM_MAX == 0xffffffff
  #define FP_GEN_RANDOM_SHIFT  32
#elif FP_GEN_RANDOM_MAX == 32767
  /* SHRT_MAX */
  #define FP_GEN_RANDOM_SHIFT  15
#elif FP_GEN_RANDOM_MAX == 2147483647
  /* INT_MAX */
  #define FP_GEN_RANDOM_SHIFT  31
#elif !defined(FP_GEN_RANDOM_SHIFT)
#error Thou shalt define their own valid FP_GEN_RANDOM_SHIFT
#endif

/* makes a pseudo-random int of a given size */
static fp_digit fp_gen_random(void)
{
  fp_digit d = 0, msk = 0;
  do {
    d <<= FP_GEN_RANDOM_SHIFT;
    d |= ((fp_digit) FP_GEN_RANDOM());
    msk <<= FP_GEN_RANDOM_SHIFT;
    msk |= FP_GEN_RANDOM_MAX;
  } while ((FP_MASK & msk) != FP_MASK);
  d &= FP_MASK;
  return d;
}

void fp_rand(fp_int *a, int digits)
{
   fp_digit d;

   fp_zero(a);
   if (digits <= 0) {
     return;
   }

   /* first place a random non-zero digit */
   do {
     d = fp_gen_random();
   } while (d == 0);

   fp_add_d (a, d, a);

   while (--digits > 0) {
     fp_lshd (a, 1);
     fp_add_d (a, fp_gen_random(), a);
   }

   return;

}

/* $Source$ */
/* $Revision$ */
/* $Date$ */

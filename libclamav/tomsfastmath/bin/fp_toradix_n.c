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

int fp_toradix_n(fp_int *a, char *str, int radix, int maxlen)
{
   int digs;
   fp_int t;
   fp_digit d;
   char *_s = str;

   /* check range of the radix */
   if (maxlen < 2 || radix < 2 || radix > 64)
      return FP_VAL;

   /* quick check for zero */
   if (fp_iszero(a) == FP_YES) {
      *str++ = '0';
      *str = '\0';
      return FP_OKAY;
   }

   fp_init_copy(&t, a);

   /* if it is negative output a - */
   if (t.sign == FP_NEG) {
      /* we have to reverse our digits later... but not the - sign!! */
      ++_s;

      /* store the flag and mark the number as positive */
      *str++ = '-';
      t.sign = FP_ZPOS;

      /* subtract a char */
      --maxlen;
   }

   digs = 0;
   while (fp_iszero (&t) == FP_NO) {
      if (--maxlen < 1) {
         /* no more room */
         break;
      }
      fp_div_d(&t, (fp_digit) radix, &t, &d);
      *str++ = fp_s_rmap[d];
      ++digs;
   }

   /* reverse the digits of the string.  In this case _s points
    * to the first digit [exluding the sign] of the number]
    */
   fp_reverse((unsigned char *) _s, digs);

   /* append a NULL so the string is properly terminated */
   *str = '\0';

   if (maxlen < 1)
      return FP_VAL;
   return FP_OKAY;
}

/* $Source$ */
/* $Revision$ */
/* $Date$ */

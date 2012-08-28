/* TomsFastMath, a fast ISO C bignum library.
 * That project is public domain and free for all purposes.
 * fp_toradix_n included in TomsFastMath specification (tfm.h), but unimplemented until now.
 * It is based on conversion of mp_toradix_n from libtommath
 * Will send the body of this function back to the LibTom projects, if they want it
 */
#include "bignum_fast.h"

int fp_toradix_n(fp_int *a, char *str, int radix, int maxlen)
{
  int     digs;
  fp_int  t;
  fp_digit d;
  char   *_s = str;

  /* check range of the maxlen, radix */
  if (maxlen < 2 || radix < 2 || radix > 64) {
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
    --maxlen;
  }

  digs = 0;
  while (fp_iszero (&t) == FP_NO) {
    if (--maxlen < 1) {
       /* no more room */
       break;
    }
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


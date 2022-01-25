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

/**
 * a:		pointer to fp_int representing the input number
 * str:		output buffer
 * radix:	number of character to use for encoding of the number
 *
 * The radix value can be in the range 2 to 64. This function converts number
 * a into a string str. Please don't use this function because a too small
 * chosen str buffer would lead to an overflow which can not be detected.
 * Please use fp_toradix_n() instead.
 *
 * Return: FP_VAL on error, FP_OKAY on success.
 */
int fp_toradix(fp_int *a, char *str, int radix)
{
   return fp_toradix_n(a, str, radix, INT_MAX);
}

/* $Source$ */
/* $Revision$ */
/* $Date$ */

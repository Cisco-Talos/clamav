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

/* b = a*a  */
void fp_sqr(fp_int *A, fp_int *B)
{
    int     y, old_used;

    old_used = B->used;

    /* call generic if we're out of range */
    if (A->used + A->used > FP_SIZE) {
       fp_sqr_comba(A, B);
       goto clean;
    }

    y = A->used;
#if defined(TFM_SQR3) && FP_SIZE >= 6
        if (y <= 3) {
           fp_sqr_comba3(A,B);
           goto clean;
        }
#endif
#if defined(TFM_SQR4) && FP_SIZE >= 8
        if (y == 4) {
           fp_sqr_comba4(A,B);
           goto clean;
        }
#endif
#if defined(TFM_SQR6) && FP_SIZE >= 12
        if (y <= 6) {
           fp_sqr_comba6(A,B);
           goto clean;
        }
#endif
#if defined(TFM_SQR7) && FP_SIZE >= 14
        if (y == 7) {
           fp_sqr_comba7(A,B);
           goto clean;
        }
#endif
#if defined(TFM_SQR8) && FP_SIZE >= 16
        if (y == 8) {
           fp_sqr_comba8(A,B);
           goto clean;
        }
#endif
#if defined(TFM_SQR9) && FP_SIZE >= 18
        if (y == 9) {
           fp_sqr_comba9(A,B);
           goto clean;
        }
#endif
#if defined(TFM_SQR12) && FP_SIZE >= 24
        if (y <= 12) {
           fp_sqr_comba12(A,B);
           goto clean;
        }
#endif
#if defined(TFM_SQR17) && FP_SIZE >= 34
        if (y <= 17) {
           fp_sqr_comba17(A,B);
           goto clean;
        }
#endif
#if defined(TFM_SMALL_SET)
        if (y <= 16) {
           fp_sqr_comba_small(A,B);
           goto clean;
        }
#endif
#if defined(TFM_SQR20) && FP_SIZE >= 40
        if (y <= 20) {
           fp_sqr_comba20(A,B);
           goto clean;
        }
#endif
#if defined(TFM_SQR24) && FP_SIZE >= 48
        if (y <= 24) {
           fp_sqr_comba24(A,B);
           goto clean;
        }
#endif
#if defined(TFM_SQR28) && FP_SIZE >= 56
        if (y <= 28) {
           fp_sqr_comba28(A,B);
           goto clean;
        }
#endif
#if defined(TFM_SQR32) && FP_SIZE >= 64
        if (y <= 32) {
           fp_sqr_comba32(A,B);
           goto clean;
        }
#endif
#if defined(TFM_SQR48) && FP_SIZE >= 96
        if (y <= 48) {
           fp_sqr_comba48(A,B);
           goto clean;
        }
#endif
#if defined(TFM_SQR64) && FP_SIZE >= 128
        if (y <= 64) {
           fp_sqr_comba64(A,B);
           goto clean;
        }
#endif
       fp_sqr_comba(A, B);
clean:
    for (y = B->used; y < old_used; y++) {
       B->dp[y] = 0;
    }
}


/* $Source: /cvs/libtom/tomsfastmath/src/sqr/fp_sqr.c,v $ */
/* $Revision: 1.1 $ */
/* $Date: 2006/12/31 21:25:53 $ */

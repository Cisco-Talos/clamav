/* TomsFastMath, a fast ISO C bignum library.
 *
 * This project is meant to fill in where LibTomMath
 * falls short.  That is speed ;-)
 *
 * This project is public domain and free for all purposes.
 *
 * Tom St Denis, tomstdenis@gmail.com
 */
#ifndef TFM_PRIVATE_H_
#define TFM_PRIVATE_H_

#include <tfm.h>

/* VARIOUS LOW LEVEL STUFFS */
void s_fp_add(fp_int *a, fp_int *b, fp_int *c);
void s_fp_sub(fp_int *a, fp_int *b, fp_int *c);
void fp_reverse(unsigned char *s, int len);

void fp_mul_comba(fp_int *A, fp_int *B, fp_int *C);

#ifdef TFM_SMALL_SET
void fp_mul_comba_small(fp_int *A, fp_int *B, fp_int *C);
#endif

#ifdef TFM_MUL3
void fp_mul_comba3(fp_int *A, fp_int *B, fp_int *C);
#endif
#ifdef TFM_MUL4
void fp_mul_comba4(fp_int *A, fp_int *B, fp_int *C);
#endif
#ifdef TFM_MUL6
void fp_mul_comba6(fp_int *A, fp_int *B, fp_int *C);
#endif
#ifdef TFM_MUL7
void fp_mul_comba7(fp_int *A, fp_int *B, fp_int *C);
#endif
#ifdef TFM_MUL8
void fp_mul_comba8(fp_int *A, fp_int *B, fp_int *C);
#endif
#ifdef TFM_MUL9
void fp_mul_comba9(fp_int *A, fp_int *B, fp_int *C);
#endif
#ifdef TFM_MUL12
void fp_mul_comba12(fp_int *A, fp_int *B, fp_int *C);
#endif
#ifdef TFM_MUL17
void fp_mul_comba17(fp_int *A, fp_int *B, fp_int *C);
#endif

#ifdef TFM_MUL20
void fp_mul_comba20(fp_int *A, fp_int *B, fp_int *C);
#endif
#ifdef TFM_MUL24
void fp_mul_comba24(fp_int *A, fp_int *B, fp_int *C);
#endif
#ifdef TFM_MUL28
void fp_mul_comba28(fp_int *A, fp_int *B, fp_int *C);
#endif
#ifdef TFM_MUL32
void fp_mul_comba32(fp_int *A, fp_int *B, fp_int *C);
#endif
#ifdef TFM_MUL48
void fp_mul_comba48(fp_int *A, fp_int *B, fp_int *C);
#endif
#ifdef TFM_MUL64
void fp_mul_comba64(fp_int *A, fp_int *B, fp_int *C);
#endif

void fp_sqr_comba(fp_int *A, fp_int *B);

#ifdef TFM_SMALL_SET
void fp_sqr_comba_small(fp_int *A, fp_int *B);
#endif

#ifdef TFM_SQR3
void fp_sqr_comba3(fp_int *A, fp_int *B);
#endif
#ifdef TFM_SQR4
void fp_sqr_comba4(fp_int *A, fp_int *B);
#endif
#ifdef TFM_SQR6
void fp_sqr_comba6(fp_int *A, fp_int *B);
#endif
#ifdef TFM_SQR7
void fp_sqr_comba7(fp_int *A, fp_int *B);
#endif
#ifdef TFM_SQR8
void fp_sqr_comba8(fp_int *A, fp_int *B);
#endif
#ifdef TFM_SQR9
void fp_sqr_comba9(fp_int *A, fp_int *B);
#endif
#ifdef TFM_SQR12
void fp_sqr_comba12(fp_int *A, fp_int *B);
#endif
#ifdef TFM_SQR17
void fp_sqr_comba17(fp_int *A, fp_int *B);
#endif

#ifdef TFM_SQR20
void fp_sqr_comba20(fp_int *A, fp_int *B);
#endif
#ifdef TFM_SQR24
void fp_sqr_comba24(fp_int *A, fp_int *B);
#endif
#ifdef TFM_SQR28
void fp_sqr_comba28(fp_int *A, fp_int *B);
#endif
#ifdef TFM_SQR32
void fp_sqr_comba32(fp_int *A, fp_int *B);
#endif
#ifdef TFM_SQR48
void fp_sqr_comba48(fp_int *A, fp_int *B);
#endif
#ifdef TFM_SQR64
void fp_sqr_comba64(fp_int *A, fp_int *B);
#endif
extern const char *fp_s_rmap;

#endif

/* $Source$ */
/* $Revision$ */
/* $Date$ */

/* TomsFastMath, a fast ISO C bignum library.
 *
 * This project is meant to fill in where LibTomMath
 * falls short.  That is speed ;-)
 *
 * This project is public domain and free for all purposes.
 *
 * Tom St Denis, tomstdenis@gmail.com
 */

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
   int x, y, z, N, f;
   N = atoi(argv[1]);

printf(
"#define TFM_DEFINES\n"
"#include \"fp_sqr_comba.c\"\n"
"\n"
"#if defined(TFM_SQR%d) && FP_SIZE >= %d\n"
"void fp_sqr_comba%d(fp_int *A, fp_int *B)\n"
"{\n"
"   fp_digit *a, b[%d], c0, c1, c2, sc0, sc1, sc2;\n"
"#ifdef TFM_ISO\n"
"   fp_word tt;\n"
"#endif\n"
"\n"
"   a = A->dp;\n"
"   COMBA_START;\n"
"\n"
"   /* clear carries */\n"
"   CLEAR_CARRY;\n"
"\n"
"   /* output 0 */\n"
"   SQRADD(a[0],a[0]);\n"
"   COMBA_STORE(b[0]);\n", N, N+N, N, N+N);

   for (x = 1; x < N+N-1; x++) {
printf(
"\n   /* output %d */\n"
"   CARRY_FORWARD;\n   ", x);

       for (f = y = 0; y < N; y++) {
           for (z = 0; z < N; z++) {
               if (z != y && z + y == x && y <= z) {
                  ++f;
               }
           }
       }

   if (f <= 2) {
       for (y = 0; y < N; y++) {
           for (z = 0; z < N; z++) {
               if (y<=z && (y+z)==x) {
                  if (y == z) {
                     printf("SQRADD(a[%d], a[%d]); ", y, y);
                  } else {
                     printf("SQRADD2(a[%d], a[%d]); ", y, z);
                  }
               }
           }
       }
   } else {
      // new method
      /* do evens first */
       f = 0;
       for (y = 0; y < N; y++) {
           for (z = 0; z < N; z++) {
               if (z != y && z + y == x && y <= z) {
                  if (f == 0) {
                     // first double
                     printf("SQRADDSC(a[%d], a[%d]); ", y, z);
                     f = 1;
                  } else {
                     printf("SQRADDAC(a[%d], a[%d]); ", y, z);
                  }
               }
           }
       }
       // forward the carry
       printf("SQRADDDB; ");
       if ((x&1) == 0) {
          // add the square
          printf("SQRADD(a[%d], a[%d]); ", x/2, x/2);
       }
    }
printf("\n   COMBA_STORE(b[%d]);\n", x);
   }
printf("   COMBA_STORE2(b[%d]);\n", N+N-1);

printf(
"   COMBA_FINI;\n"
"\n"
"   B->used = %d;\n"
"   B->sign = FP_ZPOS;\n"
"   memcpy(B->dp, b, %d * sizeof(fp_digit));\n"
"   fp_clamp(B);\n"
"}\n#endif\n\n\n"
"/* $Source$ */\n"
"/* $Revision$ */\n"
"/* $Date$ */\n"
, N+N, N+N);

  return 0;
}

/* $Source$ */
/* $Revision$ */
/* $Date$ */

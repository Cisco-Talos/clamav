#ifndef BIGNUM_H_
#define BIGNUM_H_

#define TFM_CHECK

#include "bignum_fast.h"
typedef fp_int mp_int;
#define mp_cmp fp_cmp
#define mp_toradix_n(a,b,c,d) fp_toradix_n(a,b,c,d)
#define mp_init(a) (fp_init(a), 0)
#define mp_add fp_add

#define mp_init_multi(a,b,c,d) (mp_init(a), mp_init(b), mp_init(c), 0)

#define mp_read_unsigned_bin(a,b,c) (fp_read_unsigned_bin(a, b, c), 0)

#define mp_div fp_div
#define mp_clear_multi(...)
#define mp_copy(a,b) (fp_copy(a,b), 0)
#define mp_unsigned_bin_size fp_unsigned_bin_size
#define mp_to_unsigned_bin(a,b) (fp_to_unsigned_bin(a,b), 0)
#define mp_read_radix fp_read_radix
#define mp_exptmod fp_exptmod
#define mp_get_int(a) ((a)->used > 0 ? (a)->dp[0] : 0)
#define mp_set_int(a, b) fp_set(a, b)
#define mp_mul_2d fp_mul_2d
#define mp_clear(x)
#endif

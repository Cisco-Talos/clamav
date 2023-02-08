/* This file is part of libmspack.
 * (C) 2003-2020 Stuart Caie.
 *
 * libmspack is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License (LGPL) version 2.1
 *
 * For further details, see the file COPYING.LIB distributed with libmspack
 */

#ifndef MSPACK_MACROS_H
#define MSPACK_MACROS_H 1

/* define LD and LU as printf-format for signed and unsigned long offsets */
#if HAVE_INTTYPES_H
# include <inttypes.h>
#else
# define PRId64 "lld"
# define PRIu64 "llu"
# define PRId32 "ld"
# define PRIu32 "lu"
#endif

#if SIZEOF_OFF_T >= 8
# define LD PRId64
# define LU PRIu64
#else
# define LD PRId32
# define LU PRIu32
#endif

/* endian-neutral reading of little-endian data */
#define __egi32(a,n) (((unsigned int) ((unsigned char *)(a))[n+3] << 24) | \
                      ((unsigned int) ((unsigned char *)(a))[n+2] << 16) | \
                      ((unsigned int) ((unsigned char *)(a))[n+1] <<  8) | \
                      ((unsigned int) ((unsigned char *)(a))[n]))
#define EndGetI64(a) (((unsigned long long int) __egi32(a,4) << 32) | __egi32(a,0))
#define EndGetI32(a) __egi32(a,0)
#define EndGetI16(a) ((((a)[1])<<8)|((a)[0]))

/* endian-neutral reading of big-endian data */
#define EndGetM32(a) (((unsigned int) ((unsigned char *)(a))[0] << 24) | \
                      ((unsigned int) ((unsigned char *)(a))[1] << 16) | \
                      ((unsigned int) ((unsigned char *)(a))[2] <<  8) | \
                      ((unsigned int) ((unsigned char *)(a))[3]))
#define EndGetM16(a) ((((a)[0])<<8)|((a)[1]))

/* D(("formatstring", args)) prints debug messages if DEBUG defined */
#if DEBUG
 /* http://gcc.gnu.org/onlinedocs/gcc/Function-Names.html */
# if __STDC_VERSION__ < 199901L
#  if __GNUC__ >= 2
#   define __func__ __FUNCTION__
#  else
#   define __func__ "<unknown>"
#  endif
# endif
# include <stdio.h>
# define D(x) do { printf("%s:%d (%s) ",__FILE__, __LINE__, __func__); \
                   printf x ; fputc('\n', stdout); fflush(stdout);} while (0);
#else
# define D(x)
#endif

#endif

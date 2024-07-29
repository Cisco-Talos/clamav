/* byteswap.h - Byte swapping
   Copyright (C) 2005, 2007, 2009-2024 Free Software Foundation, Inc.
   Written by Oskar Liljeblad <oskar@osk.mine.nu>, 2005.

   This file is free software: you can redistribute it and/or modify
   it under the terms of the GNU Lesser General Public License as
   published by the Free Software Foundation; either version 2.1 of the
   License, or (at your option) any later version.

   This file is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.  */

#ifndef _GL_BYTESWAP_H
#define _GL_BYTESWAP_H 1

/* This file uses _GL_INLINE.  */
#if !_GL_CONFIG_H_INCLUDED
 #error "Please include config.h first."
#endif

#include <stdint.h>

_GL_INLINE_HEADER_BEGIN
#ifndef _GL_BYTESWAP_INLINE
# define _GL_BYTESWAP_INLINE _GL_INLINE
#endif

#ifdef __cplusplus
extern "C" {
#endif

#if __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 8)
# define _GL_BYTESWAP_HAS_BUILTIN_BSWAP16 true
#elif defined __has_builtin
# if __has_builtin (__builtin_bswap16)
#  define _GL_BYTESWAP_HAS_BUILTIN_BSWAP16 true
# endif
#endif

#if __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 3)
# define _GL_BYTESWAP_HAS_BUILTIN_BSWAP32 true
# define _GL_BYTESWAP_HAS_BUILTIN_BSWAP64 true
#elif defined __has_builtin
# if __has_builtin (__builtin_bswap32)
#  define _GL_BYTESWAP_HAS_BUILTIN_BSWAP32 true
# endif
# if __has_builtin (__builtin_bswap64)
#  define _GL_BYTESWAP_HAS_BUILTIN_BSWAP64 true
# endif
#endif

/* Given an unsigned 16-bit argument X, return the value corresponding to
   X with reversed byte order.  */
_GL_BYTESWAP_INLINE uint_least16_t
bswap_16 (uint_least16_t x)
{
#ifdef _GL_BYTESWAP_HAS_BUILTIN_BSWAP16
  return __builtin_bswap16 (x);
#else
  uint_fast16_t mask = 0xff;
  return (  (x & mask << 8 * 1) >> 8 * 1
          | (x & mask << 8 * 0) << 8 * 1);
#endif
}

/* Given an unsigned 32-bit argument X, return the value corresponding to
   X with reversed byte order.  */
_GL_BYTESWAP_INLINE uint_least32_t
bswap_32 (uint_least32_t x)
{
#ifdef _GL_BYTESWAP_HAS_BUILTIN_BSWAP32
  return __builtin_bswap32 (x);
#else
  uint_fast32_t mask = 0xff;
  return (  (x & mask << 8 * 3) >> 8 * 3
          | (x & mask << 8 * 2) >> 8 * 1
          | (x & mask << 8 * 1) << 8 * 1
          | (x & mask << 8 * 0) << 8 * 3);
#endif
}

#ifdef UINT_LEAST64_MAX
/* Given an unsigned 64-bit argument X, return the value corresponding to
   X with reversed byte order.  */
_GL_BYTESWAP_INLINE uint_least64_t
bswap_64 (uint_least64_t x)
{
# ifdef _GL_BYTESWAP_HAS_BUILTIN_BSWAP64
  return __builtin_bswap64 (x);
# else
  uint_fast64_t mask = 0xff;
  return (  (x & mask << 8 * 7) >> 8 * 7
          | (x & mask << 8 * 6) >> 8 * 5
          | (x & mask << 8 * 5) >> 8 * 3
          | (x & mask << 8 * 4) >> 8 * 1
          | (x & mask << 8 * 3) << 8 * 1
          | (x & mask << 8 * 2) << 8 * 3
          | (x & mask << 8 * 1) << 8 * 5
          | (x & mask << 8 * 0) << 8 * 7);
# endif
}
#endif

#ifdef __cplusplus
}
#endif

_GL_INLINE_HEADER_END

#endif /* _GL_BYTESWAP_H */

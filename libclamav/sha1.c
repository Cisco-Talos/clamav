/*-
 * Copyright (c) 2001-2003 Allan Saddi <allan@saddi.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY ALLAN SADDI AND HIS CONTRIBUTORS ``AS IS''
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL ALLAN SADDI OR HIS CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * $Id: sha1.c 680 2003-07-25 21:57:38Z asaddi $
 */

/*
 * Define WORDS_BIGENDIAN if compiling on a big-endian architecture.
 *
 * Define SHA1_TEST to test the implementation using the NIST's
 * sample messages. The output should be:
 *
 *   a9993e36 4706816a ba3e2571 7850c26c 9cd0d89d
 *   84983e44 1c3bd26e baae4aa1 f95129e5 e54670f1
 *   34aa973c d4c4daa4 f61eeb2b dbad2731 6534016f
 */

#ifdef HAVE_CONFIG_H
#include "clamav-config.h"
#endif /* HAVE_CONFIG_H */

#if HAVE_INTTYPES_H
# include <inttypes.h>
#else
# if HAVE_STDINT_H
#  include <stdint.h>
# endif
#endif

#include <string.h>

#include "sha1.h"

#ifndef lint
static const char rcsid[] =
	"$Id: sha1.c 680 2003-07-25 21:57:38Z asaddi $";
#endif /* !lint */

#define ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

#define F_0_19(x, y, z) ((z) ^ ((x) & ((y) ^ (z))))
#define F_20_39(x, y, z) ((x) ^ (y) ^ (z))
#define F_40_59(x, y, z) (((x) & ((y) | (z))) | ((y) & (z)))
#define F_60_79(x, y, z) ((x) ^ (y) ^ (z))

#define DO_ROUND(F, K) { \
  temp = ROTL(a, 5) + F(b, c, d) + e + *(W++) + K; \
  e = d; \
  d = c; \
  c = ROTL(b, 30); \
  b = a; \
  a = temp; \
}

#define K_0_19 0x5a827999L
#define K_20_39 0x6ed9eba1L
#define K_40_59 0x8f1bbcdcL
#define K_60_79 0xca62c1d6L

#ifndef RUNTIME_ENDIAN

#if WORDS_BIGENDIAN == 1

#define BYTESWAP(x) (x)
#define BYTESWAP64(x) (x)

#else /* WORDS_BIGENDIAN */

#define BYTESWAP(x) ((ROTR((x), 8) & 0xff00ff00L) | \
		     (ROTL((x), 8) & 0x00ff00ffL))
#define BYTESWAP64(x) _byteswap64(x)

static inline uint64_t _byteswap64(uint64_t x)
{
  uint32_t a = x >> 32;
  uint32_t b = (uint32_t) x;
  return ((uint64_t) BYTESWAP(b) << 32) | (uint64_t) BYTESWAP(a);
}

#endif /* WORDS_BIGENDIAN */

#else /* !RUNTIME_ENDIAN */

#define BYTESWAP(x) _byteswap(sc->littleEndian, x)
#define BYTESWAP64(x) _byteswap64(sc->littleEndian, x)

#define _BYTESWAP(x) ((ROTR((x), 8) & 0xff00ff00L) | \
		      (ROTL((x), 8) & 0x00ff00ffL))
#define _BYTESWAP64(x) __byteswap64(x)

static inline uint64_t __byteswap64(uint64_t x)
{
  uint32_t a = x >> 32;
  uint32_t b = (uint32_t) x;
  return ((uint64_t) _BYTESWAP(b) << 32) | (uint64_t) _BYTESWAP(a);
}

static inline uint32_t _byteswap(int littleEndian, uint32_t x)
{
  if (!littleEndian)
    return x;
  else
    return _BYTESWAP(x);
}

static inline uint64_t _byteswap64(int littleEndian, uint64_t x)
{
  if (!littleEndian)
    return x;
  else
    return _BYTESWAP64(x);
}

static inline void setEndian(int *littleEndianp)
{
  union {
    uint32_t w;
    uint8_t b[4];
  } endian;

  endian.w = 1L;
  *littleEndianp = endian.b[0] != 0;
}

#endif /* !RUNTIME_ENDIAN */

static const uint8_t padding[64] = {
  0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

void
SHA1Init (SHA1Context *sc)
{
#ifdef RUNTIME_ENDIAN
  setEndian (&sc->littleEndian);
#endif /* RUNTIME_ENDIAN */

  sc->totalLength = 0LL;
  sc->hash[0] = 0x67452301L;
  sc->hash[1] = 0xefcdab89L;
  sc->hash[2] = 0x98badcfeL;
  sc->hash[3] = 0x10325476L;
  sc->hash[4] = 0xc3d2e1f0L;
  sc->bufferLength = 0L;
}

static void
burnStack (int size)
{
  char buf[128];

  memset (buf, 0, sizeof (buf));
  size -= sizeof (buf);
  if (size > 0)
    burnStack (size);
}

static void
SHA1Guts (SHA1Context *sc, const uint32_t *cbuf)
{
  uint32_t buf[80];
  uint32_t *W, *W3, *W8, *W14, *W16;
  uint32_t a, b, c, d, e, temp;
  int i;

  W = buf;

  for (i = 15; i >= 0; i--) {
    *(W++) = BYTESWAP(*cbuf);
    cbuf++;
  }

  W16 = &buf[0];
  W14 = &buf[2];
  W8 = &buf[8];
  W3 = &buf[13];

  for (i = 63; i >= 0; i--) {
    *W = *(W3++) ^ *(W8++) ^ *(W14++) ^ *(W16++);
    *W = ROTL(*W, 1);
    W++;
  }

  a = sc->hash[0];
  b = sc->hash[1];
  c = sc->hash[2];
  d = sc->hash[3];
  e = sc->hash[4];

  W = buf;

#ifndef SHA1_UNROLL
#define SHA1_UNROLL 20
#endif /* !SHA1_UNROLL */

#if SHA1_UNROLL == 1
  for (i = 19; i >= 0; i--)
    DO_ROUND(F_0_19, K_0_19);

  for (i = 19; i >= 0; i--)
    DO_ROUND(F_20_39, K_20_39);

  for (i = 19; i >= 0; i--)
    DO_ROUND(F_40_59, K_40_59);

  for (i = 19; i >= 0; i--)
    DO_ROUND(F_60_79, K_60_79);
#elif SHA1_UNROLL == 2
  for (i = 9; i >= 0; i--) {
    DO_ROUND(F_0_19, K_0_19);
    DO_ROUND(F_0_19, K_0_19);
  }

  for (i = 9; i >= 0; i--) {
    DO_ROUND(F_20_39, K_20_39);
    DO_ROUND(F_20_39, K_20_39);
  }

  for (i = 9; i >= 0; i--) {
    DO_ROUND(F_40_59, K_40_59);
    DO_ROUND(F_40_59, K_40_59);
  }

  for (i = 9; i >= 0; i--) {
    DO_ROUND(F_60_79, K_60_79);
    DO_ROUND(F_60_79, K_60_79);
  }
#elif SHA1_UNROLL == 4
  for (i = 4; i >= 0; i--) {
    DO_ROUND(F_0_19, K_0_19);
    DO_ROUND(F_0_19, K_0_19);
    DO_ROUND(F_0_19, K_0_19);
    DO_ROUND(F_0_19, K_0_19);
  }

  for (i = 4; i >= 0; i--) {
    DO_ROUND(F_20_39, K_20_39);
    DO_ROUND(F_20_39, K_20_39);
    DO_ROUND(F_20_39, K_20_39);
    DO_ROUND(F_20_39, K_20_39);
  }

  for (i = 4; i >= 0; i--) {
    DO_ROUND(F_40_59, K_40_59);
    DO_ROUND(F_40_59, K_40_59);
    DO_ROUND(F_40_59, K_40_59);
    DO_ROUND(F_40_59, K_40_59);
  }

  for (i = 4; i >= 0; i--) {
    DO_ROUND(F_60_79, K_60_79);
    DO_ROUND(F_60_79, K_60_79);
    DO_ROUND(F_60_79, K_60_79);
    DO_ROUND(F_60_79, K_60_79);
  }
#elif SHA1_UNROLL == 5
  for (i = 3; i >= 0; i--) {
    DO_ROUND(F_0_19, K_0_19);
    DO_ROUND(F_0_19, K_0_19);
    DO_ROUND(F_0_19, K_0_19);
    DO_ROUND(F_0_19, K_0_19);
    DO_ROUND(F_0_19, K_0_19);
  }

  for (i = 3; i >= 0; i--) {
    DO_ROUND(F_20_39, K_20_39);
    DO_ROUND(F_20_39, K_20_39);
    DO_ROUND(F_20_39, K_20_39);
    DO_ROUND(F_20_39, K_20_39);
    DO_ROUND(F_20_39, K_20_39);
  }

  for (i = 3; i >= 0; i--) {
    DO_ROUND(F_40_59, K_40_59);
    DO_ROUND(F_40_59, K_40_59);
    DO_ROUND(F_40_59, K_40_59);
    DO_ROUND(F_40_59, K_40_59);
    DO_ROUND(F_40_59, K_40_59);
  }

  for (i = 3; i >= 0; i--) {
    DO_ROUND(F_60_79, K_60_79);
    DO_ROUND(F_60_79, K_60_79);
    DO_ROUND(F_60_79, K_60_79);
    DO_ROUND(F_60_79, K_60_79);
    DO_ROUND(F_60_79, K_60_79);
  }
#elif SHA1_UNROLL == 10
  for (i = 1; i >= 0; i--) {
    DO_ROUND(F_0_19, K_0_19);
    DO_ROUND(F_0_19, K_0_19);
    DO_ROUND(F_0_19, K_0_19);
    DO_ROUND(F_0_19, K_0_19);
    DO_ROUND(F_0_19, K_0_19);
    DO_ROUND(F_0_19, K_0_19);
    DO_ROUND(F_0_19, K_0_19);
    DO_ROUND(F_0_19, K_0_19);
    DO_ROUND(F_0_19, K_0_19);
    DO_ROUND(F_0_19, K_0_19);
  }

  for (i = 1; i >= 0; i--) {
    DO_ROUND(F_20_39, K_20_39);
    DO_ROUND(F_20_39, K_20_39);
    DO_ROUND(F_20_39, K_20_39);
    DO_ROUND(F_20_39, K_20_39);
    DO_ROUND(F_20_39, K_20_39);
    DO_ROUND(F_20_39, K_20_39);
    DO_ROUND(F_20_39, K_20_39);
    DO_ROUND(F_20_39, K_20_39);
    DO_ROUND(F_20_39, K_20_39);
    DO_ROUND(F_20_39, K_20_39);
  }

  for (i = 1; i >= 0; i--) {
    DO_ROUND(F_40_59, K_40_59);
    DO_ROUND(F_40_59, K_40_59);
    DO_ROUND(F_40_59, K_40_59);
    DO_ROUND(F_40_59, K_40_59);
    DO_ROUND(F_40_59, K_40_59);
    DO_ROUND(F_40_59, K_40_59);
    DO_ROUND(F_40_59, K_40_59);
    DO_ROUND(F_40_59, K_40_59);
    DO_ROUND(F_40_59, K_40_59);
    DO_ROUND(F_40_59, K_40_59);
  }

  for (i = 1; i >= 0; i--) {
    DO_ROUND(F_60_79, K_60_79);
    DO_ROUND(F_60_79, K_60_79);
    DO_ROUND(F_60_79, K_60_79);
    DO_ROUND(F_60_79, K_60_79);
    DO_ROUND(F_60_79, K_60_79);
    DO_ROUND(F_60_79, K_60_79);
    DO_ROUND(F_60_79, K_60_79);
    DO_ROUND(F_60_79, K_60_79);
    DO_ROUND(F_60_79, K_60_79);
    DO_ROUND(F_60_79, K_60_79);
  }
#elif SHA1_UNROLL == 20
  DO_ROUND(F_0_19, K_0_19);
  DO_ROUND(F_0_19, K_0_19);
  DO_ROUND(F_0_19, K_0_19);
  DO_ROUND(F_0_19, K_0_19);
  DO_ROUND(F_0_19, K_0_19);
  DO_ROUND(F_0_19, K_0_19);
  DO_ROUND(F_0_19, K_0_19);
  DO_ROUND(F_0_19, K_0_19);
  DO_ROUND(F_0_19, K_0_19);
  DO_ROUND(F_0_19, K_0_19);
  DO_ROUND(F_0_19, K_0_19);
  DO_ROUND(F_0_19, K_0_19);
  DO_ROUND(F_0_19, K_0_19);
  DO_ROUND(F_0_19, K_0_19);
  DO_ROUND(F_0_19, K_0_19);
  DO_ROUND(F_0_19, K_0_19);
  DO_ROUND(F_0_19, K_0_19);
  DO_ROUND(F_0_19, K_0_19);
  DO_ROUND(F_0_19, K_0_19);
  DO_ROUND(F_0_19, K_0_19);

  DO_ROUND(F_20_39, K_20_39);
  DO_ROUND(F_20_39, K_20_39);
  DO_ROUND(F_20_39, K_20_39);
  DO_ROUND(F_20_39, K_20_39);
  DO_ROUND(F_20_39, K_20_39);
  DO_ROUND(F_20_39, K_20_39);
  DO_ROUND(F_20_39, K_20_39);
  DO_ROUND(F_20_39, K_20_39);
  DO_ROUND(F_20_39, K_20_39);
  DO_ROUND(F_20_39, K_20_39);
  DO_ROUND(F_20_39, K_20_39);
  DO_ROUND(F_20_39, K_20_39);
  DO_ROUND(F_20_39, K_20_39);
  DO_ROUND(F_20_39, K_20_39);
  DO_ROUND(F_20_39, K_20_39);
  DO_ROUND(F_20_39, K_20_39);
  DO_ROUND(F_20_39, K_20_39);
  DO_ROUND(F_20_39, K_20_39);
  DO_ROUND(F_20_39, K_20_39);
  DO_ROUND(F_20_39, K_20_39);

  DO_ROUND(F_40_59, K_40_59);
  DO_ROUND(F_40_59, K_40_59);
  DO_ROUND(F_40_59, K_40_59);
  DO_ROUND(F_40_59, K_40_59);
  DO_ROUND(F_40_59, K_40_59);
  DO_ROUND(F_40_59, K_40_59);
  DO_ROUND(F_40_59, K_40_59);
  DO_ROUND(F_40_59, K_40_59);
  DO_ROUND(F_40_59, K_40_59);
  DO_ROUND(F_40_59, K_40_59);
  DO_ROUND(F_40_59, K_40_59);
  DO_ROUND(F_40_59, K_40_59);
  DO_ROUND(F_40_59, K_40_59);
  DO_ROUND(F_40_59, K_40_59);
  DO_ROUND(F_40_59, K_40_59);
  DO_ROUND(F_40_59, K_40_59);
  DO_ROUND(F_40_59, K_40_59);
  DO_ROUND(F_40_59, K_40_59);
  DO_ROUND(F_40_59, K_40_59);
  DO_ROUND(F_40_59, K_40_59);

  DO_ROUND(F_60_79, K_60_79);
  DO_ROUND(F_60_79, K_60_79);
  DO_ROUND(F_60_79, K_60_79);
  DO_ROUND(F_60_79, K_60_79);
  DO_ROUND(F_60_79, K_60_79);
  DO_ROUND(F_60_79, K_60_79);
  DO_ROUND(F_60_79, K_60_79);
  DO_ROUND(F_60_79, K_60_79);
  DO_ROUND(F_60_79, K_60_79);
  DO_ROUND(F_60_79, K_60_79);
  DO_ROUND(F_60_79, K_60_79);
  DO_ROUND(F_60_79, K_60_79);
  DO_ROUND(F_60_79, K_60_79);
  DO_ROUND(F_60_79, K_60_79);
  DO_ROUND(F_60_79, K_60_79);
  DO_ROUND(F_60_79, K_60_79);
  DO_ROUND(F_60_79, K_60_79);
  DO_ROUND(F_60_79, K_60_79);
  DO_ROUND(F_60_79, K_60_79);
  DO_ROUND(F_60_79, K_60_79);
#else /* SHA1_UNROLL */
#error SHA1_UNROLL must be 1, 2, 4, 5, 10 or 20!
#endif

  sc->hash[0] += a;
  sc->hash[1] += b;
  sc->hash[2] += c;
  sc->hash[3] += d;
  sc->hash[4] += e;
}

void
SHA1Update (SHA1Context *sc, const void *vdata, uint32_t len)
{
  const uint8_t *data = vdata;
  uint32_t bufferBytesLeft;
  uint32_t bytesToCopy;
  int needBurn = 0;

#ifdef SHA1_FAST_COPY
  if (sc->bufferLength) {
    bufferBytesLeft = 64L - sc->bufferLength;

    bytesToCopy = bufferBytesLeft;
    if (bytesToCopy > len)
      bytesToCopy = len;

    memcpy (&sc->buffer.bytes[sc->bufferLength], data, bytesToCopy);

    sc->totalLength += bytesToCopy * 8L;

    sc->bufferLength += bytesToCopy;
    data += bytesToCopy;
    len -= bytesToCopy;

    if (sc->bufferLength == 64L) {
      SHA1Guts (sc, sc->buffer.words);
      needBurn = 1;
      sc->bufferLength = 0L;
    }
  }

  while (len > 63) {
    sc->totalLength += 512L;

    SHA1Guts (sc, data);
    needBurn = 1;

    data += 64L;
    len -= 64L;
  }

  if (len) {
    memcpy (&sc->buffer.bytes[sc->bufferLength], data, len);

    sc->totalLength += len * 8L;

    sc->bufferLength += len;
  }
#else /* SHA1_FAST_COPY */
  while (len) {
    bufferBytesLeft = 64L - sc->bufferLength;

    bytesToCopy = bufferBytesLeft;
    if (bytesToCopy > len)
      bytesToCopy = len;

    memcpy (&sc->buffer.bytes[sc->bufferLength], data, bytesToCopy);

    sc->totalLength += bytesToCopy * 8L;

    sc->bufferLength += bytesToCopy;
    data += bytesToCopy;
    len -= bytesToCopy;

    if (sc->bufferLength == 64L) {
      SHA1Guts (sc, sc->buffer.words);
      needBurn = 1;
      sc->bufferLength = 0L;
    }
  }
#endif /* SHA1_FAST_COPY */

  if (needBurn)
    burnStack (sizeof (uint32_t[86]) + sizeof (uint32_t *[5]) + sizeof (int));
}

void
SHA1Final (SHA1Context *sc, uint8_t hash[SHA1_HASH_SIZE])
{
  uint32_t bytesToPad;
  uint64_t lengthPad;
  int i;

  bytesToPad = 120L - sc->bufferLength;
  if (bytesToPad > 64L)
    bytesToPad -= 64L;

  lengthPad = BYTESWAP64(sc->totalLength);

  SHA1Update (sc, padding, bytesToPad);
  SHA1Update (sc, &lengthPad, 8L);

  if (hash) {
    for (i = 0; i < SHA1_HASH_WORDS; i++) {
#ifdef SHA1_FAST_COPY
      *((uint32_t *) hash) = BYTESWAP(sc->hash[i]);
#else /* SHA1_FAST_COPY */
      hash[0] = (uint8_t) (sc->hash[i] >> 24);
      hash[1] = (uint8_t) (sc->hash[i] >> 16);
      hash[2] = (uint8_t) (sc->hash[i] >> 8);
      hash[3] = (uint8_t) sc->hash[i];
#endif /* SHA1_FAST_COPY */
      hash += 4;
    }
  }
}

#ifdef SHA1_TEST

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int
main (int argc, char *argv[])
{
  SHA1Context foo;
  uint8_t hash[SHA1_HASH_SIZE];
  char buf[1000];
  int i;

  SHA1Init (&foo);
  SHA1Update (&foo, "abc", 3);
  SHA1Final (&foo, hash);

  for (i = 0; i < SHA1_HASH_SIZE;) {
    printf ("%02x", hash[i++]);
    if (!(i % 4))
      printf (" ");
  }
  printf ("\n");

  SHA1Init (&foo);
  SHA1Update (&foo,
		"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
		56);
  SHA1Final (&foo, hash);

  for (i = 0; i < SHA1_HASH_SIZE;) {
    printf ("%02x", hash[i++]);
    if (!(i % 4))
      printf (" ");
  }
  printf ("\n");

  SHA1Init (&foo);
  memset (buf, 'a', sizeof (buf));
  for (i = 0; i < 1000; i++)
    SHA1Update (&foo, buf, sizeof (buf));
  SHA1Final (&foo, hash);

  for (i = 0; i < SHA1_HASH_SIZE;) {
    printf ("%02x", hash[i++]);
    if (!(i % 4))
      printf (" ");
  }
  printf ("\n");

  exit (0);
}

#endif /* SHA1_TEST */

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
 * $Id: sha256.c 680 2003-07-25 21:57:49Z asaddi $
 */

/*
 * Define WORDS_BIGENDIAN if compiling on a big-endian architecture.
 *
 * Define SHA256_TEST to test the implementation using the NIST's
 * sample messages. The output should be:
 *
 *   ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 96177a9c b410ff61 f20015ad
 *   248d6a61 d20638b8 e5c02693 0c3e6039 a33ce459 64ff2167 f6ecedd4 19db06c1
 *   cdc76e5c 9914fb92 81a1c7e2 84d73e67 f1809a48 a497200e 046d39cc c7112cd0
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

#include "sha256.h"

#ifndef lint
static const char rcsid[] =
	"$Id: sha256.c 680 2003-07-25 21:57:49Z asaddi $";
#endif /* !lint */

#define ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

#define Ch(x, y, z) ((z) ^ ((x) & ((y) ^ (z))))
#define Maj(x, y, z) (((x) & ((y) | (z))) | ((y) & (z)))
#define SIGMA0(x) (ROTR((x), 2) ^ ROTR((x), 13) ^ ROTR((x), 22))
#define SIGMA1(x) (ROTR((x), 6) ^ ROTR((x), 11) ^ ROTR((x), 25))
#define sigma0(x) (ROTR((x), 7) ^ ROTR((x), 18) ^ ((x) >> 3))
#define sigma1(x) (ROTR((x), 17) ^ ROTR((x), 19) ^ ((x) >> 10))

#define DO_ROUND() { \
  t1 = h + SIGMA1(e) + Ch(e, f, g) + *(Kp++) + *(W++); \
  t2 = SIGMA0(a) + Maj(a, b, c); \
  h = g; \
  g = f; \
  f = e; \
  e = d + t1; \
  d = c; \
  c = b; \
  b = a; \
  a = t1 + t2; \
}

static const uint32_t K[64] = {
  0x428a2f98L, 0x71374491L, 0xb5c0fbcfL, 0xe9b5dba5L,
  0x3956c25bL, 0x59f111f1L, 0x923f82a4L, 0xab1c5ed5L,
  0xd807aa98L, 0x12835b01L, 0x243185beL, 0x550c7dc3L,
  0x72be5d74L, 0x80deb1feL, 0x9bdc06a7L, 0xc19bf174L,
  0xe49b69c1L, 0xefbe4786L, 0x0fc19dc6L, 0x240ca1ccL,
  0x2de92c6fL, 0x4a7484aaL, 0x5cb0a9dcL, 0x76f988daL,
  0x983e5152L, 0xa831c66dL, 0xb00327c8L, 0xbf597fc7L,
  0xc6e00bf3L, 0xd5a79147L, 0x06ca6351L, 0x14292967L,
  0x27b70a85L, 0x2e1b2138L, 0x4d2c6dfcL, 0x53380d13L,
  0x650a7354L, 0x766a0abbL, 0x81c2c92eL, 0x92722c85L,
  0xa2bfe8a1L, 0xa81a664bL, 0xc24b8b70L, 0xc76c51a3L,
  0xd192e819L, 0xd6990624L, 0xf40e3585L, 0x106aa070L,
  0x19a4c116L, 0x1e376c08L, 0x2748774cL, 0x34b0bcb5L,
  0x391c0cb3L, 0x4ed8aa4aL, 0x5b9cca4fL, 0x682e6ff3L,
  0x748f82eeL, 0x78a5636fL, 0x84c87814L, 0x8cc70208L,
  0x90befffaL, 0xa4506cebL, 0xbef9a3f7L, 0xc67178f2L
};

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
sha256_init (SHA256_CTX *sc)
{
#ifdef RUNTIME_ENDIAN
  setEndian (&sc->littleEndian);
#endif /* RUNTIME_ENDIAN */

  sc->totalLength = 0LL;
  sc->hash[0] = 0x6a09e667L;
  sc->hash[1] = 0xbb67ae85L;
  sc->hash[2] = 0x3c6ef372L;
  sc->hash[3] = 0xa54ff53aL;
  sc->hash[4] = 0x510e527fL;
  sc->hash[5] = 0x9b05688cL;
  sc->hash[6] = 0x1f83d9abL;
  sc->hash[7] = 0x5be0cd19L;
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
SHA256Guts (SHA256_CTX *sc, const uint32_t *cbuf)
{
  uint32_t buf[64];
  uint32_t *W, *W2, *W7, *W15, *W16;
  uint32_t a, b, c, d, e, f, g, h;
  uint32_t t1, t2;
  const uint32_t *Kp;
  int i;

  W = buf;

  for (i = 15; i >= 0; i--) {
    *(W++) = BYTESWAP(*cbuf);
    cbuf++;
  }

  W16 = &buf[0];
  W15 = &buf[1];
  W7 = &buf[9];
  W2 = &buf[14];

  for (i = 47; i >= 0; i--) {
    *(W++) = sigma1(*W2) + *(W7++) + sigma0(*W15) + *(W16++);
    W2++;
    W15++;
  }

  a = sc->hash[0];
  b = sc->hash[1];
  c = sc->hash[2];
  d = sc->hash[3];
  e = sc->hash[4];
  f = sc->hash[5];
  g = sc->hash[6];
  h = sc->hash[7];

  Kp = K;
  W = buf;

#ifndef SHA256_UNROLL
#define SHA256_UNROLL 4
#endif /* !SHA256_UNROLL */

#if SHA256_UNROLL == 1
  for (i = 63; i >= 0; i--)
    DO_ROUND();
#elif SHA256_UNROLL == 2
  for (i = 31; i >= 0; i--) {
    DO_ROUND(); DO_ROUND();
  }
#elif SHA256_UNROLL == 4
  for (i = 15; i >= 0; i--) {
    DO_ROUND(); DO_ROUND(); DO_ROUND(); DO_ROUND();
  }
#elif SHA256_UNROLL == 8
  for (i = 7; i >= 0; i--) {
    DO_ROUND(); DO_ROUND(); DO_ROUND(); DO_ROUND();
    DO_ROUND(); DO_ROUND(); DO_ROUND(); DO_ROUND();
  }
#elif SHA256_UNROLL == 16
  for (i = 3; i >= 0; i--) {
    DO_ROUND(); DO_ROUND(); DO_ROUND(); DO_ROUND();
    DO_ROUND(); DO_ROUND(); DO_ROUND(); DO_ROUND();
    DO_ROUND(); DO_ROUND(); DO_ROUND(); DO_ROUND();
    DO_ROUND(); DO_ROUND(); DO_ROUND(); DO_ROUND();
  }
#elif SHA256_UNROLL == 32
  for (i = 1; i >= 0; i--) {
    DO_ROUND(); DO_ROUND(); DO_ROUND(); DO_ROUND();
    DO_ROUND(); DO_ROUND(); DO_ROUND(); DO_ROUND();
    DO_ROUND(); DO_ROUND(); DO_ROUND(); DO_ROUND();
    DO_ROUND(); DO_ROUND(); DO_ROUND(); DO_ROUND();
    DO_ROUND(); DO_ROUND(); DO_ROUND(); DO_ROUND();
    DO_ROUND(); DO_ROUND(); DO_ROUND(); DO_ROUND();
    DO_ROUND(); DO_ROUND(); DO_ROUND(); DO_ROUND();
    DO_ROUND(); DO_ROUND(); DO_ROUND(); DO_ROUND();
  }
#elif SHA256_UNROLL == 64
  DO_ROUND(); DO_ROUND(); DO_ROUND(); DO_ROUND();
  DO_ROUND(); DO_ROUND(); DO_ROUND(); DO_ROUND();
  DO_ROUND(); DO_ROUND(); DO_ROUND(); DO_ROUND();
  DO_ROUND(); DO_ROUND(); DO_ROUND(); DO_ROUND();
  DO_ROUND(); DO_ROUND(); DO_ROUND(); DO_ROUND();
  DO_ROUND(); DO_ROUND(); DO_ROUND(); DO_ROUND();
  DO_ROUND(); DO_ROUND(); DO_ROUND(); DO_ROUND();
  DO_ROUND(); DO_ROUND(); DO_ROUND(); DO_ROUND();
  DO_ROUND(); DO_ROUND(); DO_ROUND(); DO_ROUND();
  DO_ROUND(); DO_ROUND(); DO_ROUND(); DO_ROUND();
  DO_ROUND(); DO_ROUND(); DO_ROUND(); DO_ROUND();
  DO_ROUND(); DO_ROUND(); DO_ROUND(); DO_ROUND();
  DO_ROUND(); DO_ROUND(); DO_ROUND(); DO_ROUND();
  DO_ROUND(); DO_ROUND(); DO_ROUND(); DO_ROUND();
  DO_ROUND(); DO_ROUND(); DO_ROUND(); DO_ROUND();
  DO_ROUND(); DO_ROUND(); DO_ROUND(); DO_ROUND();
#else
#error "SHA256_UNROLL must be 1, 2, 4, 8, 16, 32, or 64!"
#endif

  sc->hash[0] += a;
  sc->hash[1] += b;
  sc->hash[2] += c;
  sc->hash[3] += d;
  sc->hash[4] += e;
  sc->hash[5] += f;
  sc->hash[6] += g;
  sc->hash[7] += h;
}

void
sha256_update (SHA256_CTX *sc, const void *vdata, uint32_t len)
{
  const uint8_t *data = vdata;
  uint32_t bufferBytesLeft;
  uint32_t bytesToCopy;
  int needBurn = 0;
#ifdef SHA256_FAST_COPY
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
      SHA256Guts (sc, sc->buffer.words);
      needBurn = 1;
      sc->bufferLength = 0L;
    }
  }

  while (len > 63L) {
    sc->totalLength += 512L;

    SHA256Guts (sc, data);
    needBurn = 1;

    data += 64L;
    len -= 64L;
  }

  if (len) {
    memcpy (&sc->buffer.bytes[sc->bufferLength], data, len);

    sc->totalLength += len * 8L;

    sc->bufferLength += len;
  }
#else /* SHA256_FAST_COPY */
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
      SHA256Guts (sc, sc->buffer.words);
      needBurn = 1;
      sc->bufferLength = 0L;
    }
  }
#endif /* SHA256_FAST_COPY */

  if (needBurn)
    burnStack (sizeof (uint32_t[74]) + sizeof (uint32_t *[6]) + sizeof (int));
}

void
sha256_final (SHA256_CTX *sc, uint8_t hash[SHA256_HASH_SIZE])
{
  uint32_t bytesToPad;
  uint64_t lengthPad;
  int i;

  bytesToPad = 120L - sc->bufferLength;
  if (bytesToPad > 64L)
    bytesToPad -= 64L;

  lengthPad = BYTESWAP64(sc->totalLength);

  sha256_update (sc, padding, bytesToPad);
  sha256_update (sc, &lengthPad, 8L);

  if (hash) {
    for (i = 0; i < SHA256_HASH_WORDS; i++) {
#ifdef SHA256_FAST_COPY
      *((uint32_t *) hash) = BYTESWAP(sc->hash[i]);
#else /* SHA256_FAST_COPY */
      hash[0] = (uint8_t) (sc->hash[i] >> 24);
      hash[1] = (uint8_t) (sc->hash[i] >> 16);
      hash[2] = (uint8_t) (sc->hash[i] >> 8);
      hash[3] = (uint8_t) sc->hash[i];
#endif /* SHA256_FAST_COPY */
      hash += 4;
    }
  }
}

#ifdef SHA256_TEST

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int
main (int argc, char *argv[])
{
  SHA256_CTX foo;
  uint8_t hash[SHA256_HASH_SIZE];
  char buf[1000];
  int i;

  sha256_init (&foo);
  sha256_update (&foo, "abc", 3);
  sha256_final (&foo, hash);

  for (i = 0; i < SHA256_HASH_SIZE;) {
    printf ("%02x", hash[i++]);
    if (!(i % 4))
      printf (" ");
  }
  printf ("\n");

  sha256_init (&foo);
  sha256_update (&foo,
		"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
		56);
  sha256_final (&foo, hash);

  for (i = 0; i < SHA256_HASH_SIZE;) {
    printf ("%02x", hash[i++]);
    if (!(i % 4))
      printf (" ");
  }
  printf ("\n");

  sha256_init (&foo);
  memset (buf, 'a', sizeof (buf));
  for (i = 0; i < 1000; i++)
    sha256_update (&foo, buf, sizeof (buf));
  sha256_final (&foo, hash);

  for (i = 0; i < SHA256_HASH_SIZE;) {
    printf ("%02x", hash[i++]);
    if (!(i % 4))
      printf (" ");
  }
  printf ("\n");

  exit (0);
}

#endif /* SHA256_TEST */

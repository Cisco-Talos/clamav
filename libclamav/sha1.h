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
 * $Id: sha1.h 347 2003-02-23 22:11:49Z asaddi $
 */

#ifndef _SHA1_H
#define _SHA1_H

#if HAVE_INTTYPES_H
# include <inttypes.h>
#else
# if HAVE_STDINT_H
#  include <stdint.h>
# endif
#endif

#define SHA1_HASH_SIZE 20

/* Hash size in 32-bit words */
#define SHA1_HASH_WORDS 5

struct _SHA1Context {
  uint64_t totalLength;
  uint32_t hash[SHA1_HASH_WORDS];
  uint32_t bufferLength;
  union {
    uint32_t words[16];
    uint8_t bytes[64];
  } buffer;
#ifdef RUNTIME_ENDIAN
  int littleEndian;
#endif /* RUNTIME_ENDIAN */
};

typedef struct _SHA1Context SHA1Context;

#ifdef __cplusplus
extern "C" {
#endif

void SHA1Init (SHA1Context *sc);
void SHA1Update (SHA1Context *sc, const void *data, uint32_t len);
void SHA1Final (SHA1Context *sc, uint8_t hash[SHA1_HASH_SIZE]);

#ifdef __cplusplus
}
#endif

#endif /* _SHA1_H */

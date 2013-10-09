/* Sha256.h -- SHA-256 Hash
2010-06-11 : Igor Pavlov : Public domain */

#ifndef __CRYPTO_SHA256_H
#define __CRYPTO_SHA256_H

#include "Types.h"

EXTERN_C_BEGIN

#define SHA256_DIGEST_SIZE 32

#define __USE_CLAM_SHA256_FOR_7Z__

#ifndef __USE_CLAM_SHA256_FOR_7Z__
typedef struct
{
  UInt32 state[8];
  UInt64 count;
  Byte buffer[64];
} CSha256;

void Sha256_Init(CSha256 *p);
void Sha256_Update(CSha256 *p, const Byte *data, size_t size);
void Sha256_Final(CSha256 *p, Byte *digest);
#else
#include "../sha256.h"
#define CSha256 SHA256_CTX
#define Sha256_Init sha256_init
#define Sha256_Update sha256_update
#define Sha256_Final sha256_final
#endif
EXTERN_C_END

#endif

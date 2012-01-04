/* 7zCrc.h -- CRC32 calculation
2009-11-21 : Igor Pavlov : Public domain */

#ifndef __7Z_CRC_H
#define __7Z_CRC_H

#include "Types.h"

EXTERN_C_BEGIN

#define CRC_INIT_VAL 0xFFFFFFFF

UInt32 MY_FAST_CALL CrcUpdate(UInt32 crc, const void *data, size_t size);
UInt32 MY_FAST_CALL CrcCalc(const void *data, size_t size);

EXTERN_C_END

#endif

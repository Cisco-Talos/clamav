/* CpuArch.h -- CPU specific code
2010-10-26: Igor Pavlov : Public domain */

#ifndef __CPU_ARCH_H
#define __CPU_ARCH_H

#include "Types.h"
#include "others.h"

EXTERN_C_BEGIN

/*
MY_CPU_LE means that CPU is LITTLE ENDIAN.
If MY_CPU_LE is not defined, we don't know about that property of platform (it can be LITTLE ENDIAN).

MY_CPU_LE_UNALIGN means that CPU is LITTLE ENDIAN and CPU supports unaligned memory accesses.
If MY_CPU_LE_UNALIGN is not defined, we don't know about these properties of platform.
*/

#define GetUi16(p) (cli_readint16(p))
#define GetUi32(p) (cli_readint32(p))

#define GetUi64(p) (GetUi32(p) | ((UInt64)GetUi32(((const Byte *)(p)) + 4) << 32))

#define SetUi16(p, d) { UInt32 _x_ = (d); \
    ((Byte *)(p))[0] = (Byte)_x_; \
    ((Byte *)(p))[1] = (Byte)(_x_ >> 8); }

#define SetUi32(p, d) (cli_writeint32(p, d))

#define SetUi64(p, d) { UInt64 _x64_ = (d); \
    SetUi32(p, (UInt32)_x64_); \
    SetUi32(((Byte *)(p)) + 4, (UInt32)(_x64_ >> 32)); }

#define GetBe16(p) (((UInt16)((const Byte *)(p))[0] << 8) | ((const Byte *)(p))[1])

#endif

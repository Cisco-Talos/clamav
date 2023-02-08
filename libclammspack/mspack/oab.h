/* This file is part of libmspack.
 * © 2013 Intel Corporation
 *
 * libmspack is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License (LGPL) version 2.1
 *
 * For further details, see the file COPYING.LIB distributed with libmspack
 */

#ifndef MSPACK_OAB_H
#define MSPACK_OAB_H 1

#include <system.h>

/* generic OAB definitions */

/* OAB compression definitions */

struct msoab_compressor_p {
  struct msoab_compressor base;
  struct mspack_system *system;
  /* todo */
};

/* OAB decompression definitions */

struct msoab_decompressor_p {
  struct msoab_decompressor base;
  struct mspack_system *system;
  int buf_size;
  /* todo */
};

#define oabhead_VersionHi    (0x0000)
#define oabhead_VersionLo    (0x0004)
#define oabhead_BlockMax     (0x0008)
#define oabhead_TargetSize   (0x000c)
#define oabhead_SIZEOF       (0x0010)

#define oabblk_Flags         (0x0000)
#define oabblk_CompSize      (0x0004)
#define oabblk_UncompSize    (0x0008)
#define oabblk_CRC           (0x000c)
#define oabblk_SIZEOF        (0x0010)

#define patchhead_VersionHi  (0x0000)
#define patchhead_VersionLo  (0x0004)
#define patchhead_BlockMax   (0x0008)
#define patchhead_SourceSize (0x000c)
#define patchhead_TargetSize (0x0010)
#define patchhead_SourceCRC  (0x0014)
#define patchhead_TargetCRC  (0x0018)
#define patchhead_SIZEOF     (0x001c)

#define patchblk_PatchSize   (0x0000)
#define patchblk_TargetSize  (0x0004)
#define patchblk_SourceSize  (0x0008)
#define patchblk_CRC         (0x000c)
#define patchblk_SIZEOF      (0x0010)

#endif

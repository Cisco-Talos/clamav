/* This file is part of libmspack.
 * (C) 2003-2004 Stuart Caie.
 *
 * libmspack is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License (LGPL) version 2.1
 *
 * For further details, see the file COPYING.LIB distributed with libmspack
 */

#ifndef MSPACK_LIT_H
#define MSPACK_LIT_H 1

#include <lzx.h>
#include <des.h>
#include <sha.h>

/* generic LIT definitions */

/* LIT compression definitions */

struct mslit_compressor_p {
  struct mslit_compressor base;
  struct mspack_system *system;
  /* todo */
};

/* LIT decompression definitions */

struct mslit_decompressor_p {
  struct mslit_decompressor base;
  struct mspack_system *system;
  /* todo */
};

#endif

/* This file is part of libmspack.
 * (C) 2003-2004 Stuart Caie.
 *
 * libmspack is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License (LGPL) version 2.1
 *
 * For further details, see the file COPYING.LIB distributed with libmspack
 */

#ifndef MSPACK_HLP_H
#define MSPACK_HLP_H 1

#include <lzss.h>

/* generic HLP definitions */

/* HLP compression definitions */

struct mshlp_compressor_p {
  struct mshlp_compressor base;
  struct mspack_system *system;
  /* todo */
};

/* HLP decompression definitions */

struct mshlp_decompressor_p {
  struct mshlp_decompressor base;
  struct mspack_system *system;
  /* todo */
};

#endif

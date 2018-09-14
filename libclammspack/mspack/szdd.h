/* This file is part of libmspack.
 * (C) 2003-2004 Stuart Caie.
 *
 * libmspack is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License (LGPL) version 2.1
 *
 * For further details, see the file COPYING.LIB distributed with libmspack
 */

#ifndef MSPACK_SZDD_H
#define MSPACK_SZDD_H 1

#include <lzss.h>

/* input buffer size during decompression - not worth parameterising IMHO */
#define SZDD_INPUT_SIZE (2048)

/* SZDD compression definitions */

struct msszdd_compressor_p {
  struct msszdd_compressor base;
  struct mspack_system *system;
  int error;
};

/* SZDD decompression definitions */

struct msszdd_decompressor_p {
  struct msszdd_decompressor base;
  struct mspack_system *system;
  int error;
};

struct msszddd_header_p {
  struct msszddd_header base;
  struct mspack_file *fh;
};

#endif

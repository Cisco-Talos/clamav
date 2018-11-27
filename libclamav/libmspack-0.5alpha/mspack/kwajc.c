/* This file is part of libmspack.
 * (C) 2003-2004 Stuart Caie.
 *
 * libmspack is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License (LGPL) version 2.1
 *
 * For further details, see the file COPYING.LIB distributed with libmspack
 */

/* KWAJ compression implementation */

#include <system.h>
#include <kwaj.h>

struct mskwaj_compressor *
  mspack_create_kwaj_compressor(struct mspack_system *sys)
{
  (void) sys;
  /* todo */
  return NULL;
}

void mspack_destroy_kwaj_compressor(struct mskwaj_compressor *self) {
  (void) self;
  /* todo */
  return;
}

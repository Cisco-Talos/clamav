/*
 *  Copyright (C) 2007 aCaB <acab@clamav.net>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA 02110-1301, USA.
 */

#ifndef __NSIS_H
#define __NSIS_H

#include "cltypes.h"
#include "nsis_bzlib.h"
#include "LZMADecode.h"
#include "nsis_zlib.h"
#include "others.h"

struct nsis_st {
  int ifd;
  int ofd;
  off_t off;
  char *dir;
  uint32_t asz;
  uint32_t hsz;
  uint32_t fno;
  struct {
    uint32_t avail_in;
    unsigned char *next_in;
    uint32_t avail_out;
    unsigned char *next_out;
  } nsis;
  nsis_bzstream bz;
  lzma_stream lz;
  nsis_z_stream z;
  unsigned char *freeme;
  uint8_t comp;
  uint8_t solid;
  uint8_t freecomp;
  uint8_t eof;
  char ofn[1024];
};

int cli_nsis_unpack(struct nsis_st *, cli_ctx *);
void cli_nsis_free(struct nsis_st *);
#endif

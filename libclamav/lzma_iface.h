/*
 *  Copyright (C) 2007 Sourcefire Inc.
 *  Author: aCaB <acab@clamav.net>
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

/* a cleaner state interface to LZMA */

#ifndef __LZMA_IFACE_H
#define __LZMA_IFACE_H

/* DIRTY HACK TO COMPILE ON SOLARIS GCC 3.4.6 */
#define Byte BByte
/* DIRTY HACK TO COMPILE ON SOLARIS GCC 3.4.6 */

#include "LzmaStateDecode.h"
#include "cltypes.h"

typedef struct {
  CLzmaDecoderState state;
  const unsigned char *next_in;
  SizeT avail_in;
  unsigned char *next_out;
  SizeT avail_out;
  int initted;
  uint64_t usize;
} CLI_LZMA;

int cli_LzmaInit(CLI_LZMA *, uint64_t);
void cli_LzmaShutdown(CLI_LZMA *);
int cli_LzmaDecode(CLI_LZMA *);

#define LZMA_STREAM_END 2
#endif /* __LZMA_IFACE_H */

/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2008-2013 Sourcefire, Inc.
 *
 *  Authors: Alberto Wu
 * 
 *  Acknowledgements: Written from scratch based on specs from PKWARE:
 *                    http://www.pkware.com/documents/casestudies/APPNOTE.TXT
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

#ifndef __EXPLODE_H
#define __EXPLODE_H

#include "clamav-types.h"

enum {
  EXPLODE_EBUFF,
  EXPLODE_ESTREAM
};

#define EXPLODE_OK EXPLODE_EBUFF

enum XPL_STATE {
  GRABLITS,
  GRABLENS,
  GRABDISTS,
  EXPLODE,
  EXPLODE_LITCODES,
  EXPLODE_LITS,
  EXPLODE_BASEDIST,
  EXPLODE_DECODEDISTS,
  EXPLODE_DECODELENS,
  EXPLODE_DECODEEXTRA,
  EXPLODE_WBYTE,
  EXPLODE_BACKCOPY
};

struct xplstate {
  uint8_t *next_in;
  uint8_t *next_out;
  unsigned int got;
  unsigned int minlen;
  unsigned int mask;
  unsigned int cur;
  uint32_t lit_tree[256];
  uint32_t len_tree[64];
  uint32_t dist_tree[64];
  uint32_t bitmap;
  uint32_t avail_in;
  uint32_t avail_out;
  uint16_t backbytes;
  uint16_t backsize;
  uint8_t window[8192];
  enum XPL_STATE state;
  uint8_t bits;
  uint8_t largewin;
  uint8_t litcodes;
};

int explode_init(struct xplstate *, uint16_t);
int explode(struct xplstate *);
void explode_shutdown(void);

#endif /* __EXPLODE_H */

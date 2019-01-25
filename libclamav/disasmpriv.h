/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2008-2013 Sourcefire, Inc.
 *
 *  Authors: aCaB <acab@clamav.net>
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

#ifndef __DISASMPRIV_H
#define __DISASMPRIV_H

#include "disasm-common.h"

enum DIS_STATE {
  STATE_GETOP,
  STATE_CHECKDTYPE,
  STATE_CHECKSTYPE,
  STATE_DECODEX87,
  STATE_FINALIZE,
  STATE_COMPLETE,
  STATE_ERROR
};

struct DIS_ARGS {
  enum DIS_ACCESS access;
  enum DIS_SIZE size;
  enum X86REGS reg;
  union {
    uint8_t b;
    int8_t rb;
    uint16_t w;
    int16_t rw;
    uint32_t d;
    int32_t rd;
    /*    uint48_t f; FIXME */
    uint64_t q;
    int64_t rq;
    struct {
      enum X86REGS r1;  /* scaled */
      enum X86REGS r2;  /* added */
      uint8_t scale; /* r1 multiplier */
      int32_t disp;
    } marg;
  } arg;
};

/* FIXME: pack this thing and make macroes to access it in different compilers */
struct DISASMED {
  uint16_t table_op;
  uint16_t real_op;
  enum DIS_STATE state;
  uint32_t opsize;
  uint32_t adsize;
  uint32_t segment;
  uint8_t cur;
  struct DIS_ARGS args[3];
};

#endif

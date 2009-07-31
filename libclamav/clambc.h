/*
 *  ClamAV bytecode definitions.
 *
 *  Copyright (C) 2009 Sourcefire, Inc.
 *
 *  Authors: Török Edvin
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
#ifndef CLAMBC_H
#define CLAMBC_H

struct bytecode_metadata {
  unsigned long maxStack, maxMem;
  unsigned long maxTime;
  char *targetExclude;
};

#define BC_FUNC_LEVEL 1
#define BC_HEADER "ClamBC"

enum bc_opcode {
  OP_ADD=1,
  OP_SUB,
  OP_MUL,
  OP_UDIV,
  OP_SDIV,
  OP_UREM,
  OP_SREM,
  OP_SHL,
  OP_LSHR,
  OP_ASHR,
  OP_AND,
  OP_OR,
  OP_XOR,

  OP_TRUNC,
  OP_SEXT,
  OP_ZEXT,

  OP_BRANCH,
  OP_JMP,
  OP_RET,

  OP_ICMP_EQ,
  OP_ICMP_NE,
  OP_ICMP_UGT,
  OP_ICMP_UGE,
  OP_ICMP_ULT,
  OP_ICMP_ULE,
  OP_ICMP_SGT,
  OP_ICMP_SGE,
  OP_ICMP_SLE,
  OP_ICMP_SLT,
  OP_SELECT,
  OP_CALL_DIRECT,
  OP_CALL_API,
  OP_COPY,
  OP_GEP1,
  OP_GEP2,
  OP_GEPN,
  OP_STORE,
  OP_LOAD,
  OP_INVALID /* last */
};

static const unsigned char operand_counts[] = {
  0,
  /* ADD -> XOR */
  2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
  /* TRUNC -> ZEXT */
  1, 1, 1,
  /* BRANCH, JMP, RET */
  3, 1, 1,
  /* ICMP */
  2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
  /* SELECT */
  3,
  /* CALLs have variable number of operands */
  0, 0,
  /* OP_COPY */
  2,
  /* OP_GEP1, OP_GEP2, OP_GEPN, OP_STORE, OP_LOAD*/
  2, 3, 0, 2, 1
};

#define BC_START_TID 69

#endif

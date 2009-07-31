/*
 *  Load, verify and execute ClamAV bytecode.
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

#ifndef BYTECODE_PRIV_H
#define BYTECODE_PRIV_H

#include "type_desc.h"
typedef uint32_t operand_t;
typedef uint16_t bbid_t;
typedef uint16_t funcid_t;

struct cli_bc_callop {
    operand_t* ops;
    uint16_t* opsizes;
    uint8_t numOps;
    funcid_t funcid;
};

struct branch {
    operand_t condition;
    bbid_t br_true;
    bbid_t br_false;
};

struct cli_bc_cast {
    uint64_t mask;
    operand_t source;
    uint8_t size;/* 0: 1-bit, 1: 8b, 2: 16b, 3: 32b, 4: 64b */
};

typedef uint8_t interp_op_t;
struct cli_bc_inst {
    enum bc_opcode opcode;
    uint16_t type;
    interp_op_t interp_op;/* opcode for interpreter */
    operand_t dest;
    union {
	operand_t unaryop;
	struct cli_bc_cast cast;
	operand_t binop[2];
	operand_t three[3];
	struct cli_bc_callop ops;
	struct branch branch;
	bbid_t jump;
    } u;
};

struct cli_bc_bb {
    unsigned numInsts;
    struct cli_bc_inst *insts;
};

struct cli_bc_func {
    uint8_t numArgs;
    uint16_t numLocals;
    uint32_t numInsts;
    uint32_t numValues;/* without constants */
    uint32_t numConstants;
    uint32_t numBytes;/* stack size */
    uint16_t numBB;
    uint16_t *types;
    uint32_t insn_idx;
    struct cli_bc_bb *BB;
    struct cli_bc_inst *allinsts;
    uint64_t *constants;
};
#define MAX_OP ~0u
struct cli_bc_ctx {
    /* id and params of toplevel function called */
    const struct cli_bc *bc;
    const struct cli_bc_func *func;
    unsigned bytes;
    uint16_t *opsizes;
    char *values;
    operand_t *operands;
    uint16_t funcid;
    unsigned numParams;
};

int cli_vm_execute(const struct cli_bc *bc, struct cli_bc_ctx *ctx, const struct cli_bc_func *func, const struct cli_bc_inst *inst);
#endif

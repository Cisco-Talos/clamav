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
typedef uint32_t operand_t;
typedef uint16_t bbid_t;
typedef uint16_t funcid_t;

struct cli_bc_callop {
    operand_t* ops;
    uint8_t numOps;
    funcid_t funcid;
};

struct branch {
    operand_t condition;
    bbid_t br_true;
    bbid_t br_false;
};

#define MAX_OP (operand_t)(~0u)
#define CONSTANT_OP (MAX_OP-1)
#define ARG_OP (MAX_OP-1)
struct cli_bc_value {
    uint64_t v;
    operand_t ref;/* this has CONSTANT_OP value for constants, and ARG_op for arguments */
};

struct cli_bc_cast {
    operand_t source;
    uint64_t mask;
};
struct cli_bc_inst {
    enum bc_opcode opcode;
    uint16_t type;
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
    uint32_t numValues;//without constants
    uint32_t numConstants;
    uint16_t numBB;
    uint16_t *types;
    uint32_t insn_idx;
    struct cli_bc_bb *BB;
    struct cli_bc_inst *allinsts;
    struct cli_bc_value *constants;
};

struct cli_bc_ctx {
    /* id and params of toplevel function called */
    struct cli_bc *bc;
    struct cli_bc_func *func;
    struct cli_bc_value *values;
    operand_t *operands;
    uint16_t funcid;
    unsigned numParams;
};

int cli_vm_execute(const struct cli_bc *bc, struct cli_bc_ctx *ctx, const struct cli_bc_func *func, const struct cli_bc_inst *inst);
#endif

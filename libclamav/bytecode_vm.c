/*
 *  Execute ClamAV bytecode.
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
#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif
#include "clamav.h"
#include "others.h"
#include "bytecode.h"
#include "bytecode_priv.h"
#include "readdb.h"
#include <string.h>

/* These checks will also be done by the bytecode verifier, but for
 * debugging purposes we have explicit checks, these should never fail! */
#ifdef CL_DEBUG
static int bcfail(const char *msg, unsigned a, unsigned b,
		  const char *file, unsigned line)
{
    cli_errmsg("bytecode: check failed %s (%u and %u) at %s:%u\n", msg, a, b, file, line);
    return CL_EARG;
}
#define CHECK_FUNCID(funcid) do { if (funcid >= bc->num_func) return \
    bcfail("funcid out of bounds!",funcid, bc->num_func,__FILE__,__LINE__); } while(0)
#define CHECK_EQ(a, b) do { if (a != b) return \
    bcfail("Values "#a" and "#b" don't match!",a,b,__FILE__,__LINE__); } while(0)
#define CHECK_GT(a, b) do {if (a < b) return \
    bcfail("Condition failed "#a" > "#b,a,b, __FILE__, __LINE__); } while(0)
#else
#define CHECK_FUNCID(x)
#define CHECK_EQ(a,b)
#define CHECK_GT(a,b)
#endif

struct stack_entry {
    struct cli_bc_func *func;
    struct cli_bc_value *ret;
    struct cli_bc_bb *bb;
    unsigned bb_inst;
};

int cli_vm_execute(struct cli_bc *bc, struct cli_bc_ctx *ctx, struct cli_bc_func *func, struct cli_bc_inst *inst, struct cli_bc_value *value)
{
    unsigned i, stack_depth=0, bb_inst=0, stop=0;
    struct cli_bc_func *func2;
    struct stack_entry *stack = NULL;
    struct cli_bc_bb *bb = NULL;
    struct cli_bc_value *values = NULL;

    do {
	switch (inst->opcode) {
	    case OP_ADD:
		values->v = values[inst->u.binop[0]].v + values[inst->u.binop[1]].v;
		break;
	    case OP_SUB:
		values->v = values[inst->u.binop[0]].v - values[inst->u.binop[1]].v;
		break;
	    case OP_MUL:
		values->v = values[inst->u.binop[0]].v * values[inst->u.binop[1]].v;
		break;
	    case OP_AND:
		values->v = values[inst->u.binop[0]].v & values[inst->u.binop[1]].v;
		break;
	    case OP_OR:
		values->v = values[inst->u.binop[0]].v | values[inst->u.binop[1]].v;
		break;
	    case OP_XOR:
		values->v = values[inst->u.binop[0]].v ^ values[inst->u.binop[1]].v;
		break;
	    case OP_ZEXT:
	    case OP_TRUNC:
		values->v = values[inst->u.cast.source].v & values[inst->u.cast.mask].v;
		break;
	    case OP_RET:
		CHECK_GT(stack_depth, 0);
		stack_depth--;
		value = stack[stack_depth].ret;
		value->v = values[inst->u.unaryop].v;
		func = stack[stack_depth].func;
		values = func->values;
		if (!stack[stack_depth].bb) {
		    stop = CL_BREAK;
		    bb_inst--;
		    break;
		}
		bb = stack[stack_depth].bb;
		bb_inst = stack[stack_depth].bb_inst;
		inst = &bb->insts[bb_inst];
		break;
	    case OP_ICMP_EQ:
		value->v = values[inst->u.binop[0]].v == values[inst->u.binop[1]].v ? 1 : 0;
		break;
	    case OP_SELECT:
		values->v = values[inst->u.three[0]].v ?
		    values[inst->u.three[1]].v : values[inst->u.three[2]].v;
		break;
	    case OP_CALL_DIRECT:
		CHECK_FUNCID(inst->u.ops.funcid);
		func2 = &bc->funcs[inst->u.ops.funcid];
		CHECK_EQ(func2->numArgs, inst->u.ops.numOps);
		for (i=0;i<func2->numArgs;i++)
		    func2->values[i] = func->values[inst->u.ops.ops[i]];
		stack = cli_realloc2(stack, sizeof(*stack)*(stack_depth+1));
		if (!stack)
		    return CL_EMEM;
		stack[stack_depth].func = func;
		stack[stack_depth].ret = value;
		stack[stack_depth].bb = bb;
		stack[stack_depth].bb_inst = bb_inst;
		stack_depth++;
		func = func2;
		values = func->values;
		CHECK_GT(func->numBB, 0);
		bb = &func->BB[0];
		inst = &bb->insts[0];
		bb_inst = 0;
		continue;
	    default:
		cli_errmsg("Opcode %u is not implemented yet!\n", inst->opcode);
		stop = CL_EARG;
	}
	bb_inst++;
	inst++;
	value++;
	CHECK_GT(bb->numInsts, bb_inst);
    } while (stop == CL_SUCCESS);

    free(stack);
    return stop == CL_BREAK ? CL_SUCCESS : stop;
}

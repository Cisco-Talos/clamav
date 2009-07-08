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
#define CHECK_GT(a, b) do {if (a <= b) return \
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


/* Get the operand of a binary operator, upper bits
 * (beyond the size of the operand) may have random values.
 * Use this when the active bits of the result of a binop are the same
 * regardless of the state of the inactive (high) bits of their operands.
 * For example (a + b)&mask == ((a&mask) + (b&mask))
 * but (a / b)&mask != ((a&mask) / (b&mask))
 * */
#define BINOPNOMOD(i) (values[inst->u.binop[i]].v)
#define UNOPNOMOD(i) (values[inst->u.binop[i]].v)

/* get the operand of a binary operator, upper bits are cleared */
#define BINOP(i) (BINOPNOMOD(i)&((1 << inst->type)-1))
#define UNOP(x) (UNOPNOMOD(i)&((1 << inst->type)-1))

/* get the operand as a signed value.
 * Warning: this assumes that result type is same as operand type.
 * This is usually true, except for icmp_* and select.
 * For icmp_* we fix it up in the loader. */
#define SIGNEXT(a) CLI_SRS(((int64_t)(a)) << (64-inst->type), (64-inst->type))
#define BINOPS(i) SIGNEXT(BINOPNOMOD(i))

static void jump(struct cli_bc_func *func, uint16_t bbid, struct cli_bc_bb **bb, struct cli_bc_inst **inst,
		 struct cli_bc_value **value, unsigned *bb_inst)
{
    CHECK_GT(func->numBB, bbid);
    *bb = &func->BB[bbid];
    *inst = (*bb)->insts;
    *value = &func->values[*inst - func->allinsts];
    *bb_inst = 0;
}

int cli_vm_execute(struct cli_bc *bc, struct cli_bc_ctx *ctx, struct cli_bc_func *func, struct cli_bc_inst *inst)
{
    unsigned i, stack_depth=0, bb_inst=0, stop=0;
    struct cli_bc_func *func2;
    struct stack_entry *stack = NULL;
    struct cli_bc_bb *bb = NULL;
    struct cli_bc_value *values = func->values;
    struct cli_bc_value *value;

    do {
	value = &values[inst->dest];
	CHECK_GT(func->values + func->numArgs+func->numInsts+func->numConstants, value);
	switch (inst->opcode) {
	    case OP_ADD:
		value->v = BINOPNOMOD(0) + BINOPNOMOD(1);
		break;
	    case OP_SUB:
		value->v = BINOPNOMOD(0) - BINOPNOMOD(1);
		break;
	    case OP_MUL:
		value->v = BINOPNOMOD(0) * BINOPNOMOD(1);
		break;
	    case OP_UDIV:
		{
		    uint64_t d = BINOP(1);
		    if (UNLIKELY(!d))
			return CL_EBYTECODE;
		    value->v = BINOP(0) / d;
		    break;
		}
	    case OP_SDIV:
		{
		    int64_t a = BINOPS(0);
		    int64_t b = BINOPS(1);
		    if (UNLIKELY(b == 0 || (b == -1 && a == (-9223372036854775807LL-1LL))))
			return CL_EBYTECODE;
		    value->v = a / b;
		    break;
		}
	    case OP_UREM:
		{
		    uint64_t d = BINOP(1);
		    if (UNLIKELY(!d))
			return CL_EBYTECODE;
		    value->v = BINOP(0) % d;
		    break;
		}
	    case OP_SREM:
		{
		    int64_t a = BINOPS(0);
		    int64_t b = BINOPS(1);
		    if (UNLIKELY(b == 0 || (b == -1 && (a == -9223372036854775807LL-1LL))))
			return CL_EBYTECODE;
		    value->v = a % b;
		    break;
		}
	    case OP_SHL:
		value->v = BINOPNOMOD(0) << BINOP(1);
		break;
	    case OP_LSHR:
		value->v = BINOP(0) >> BINOP(1);
		break;
	    case OP_ASHR:
		{
		    int64_t v = BINOPS(0);
		    value->v = CLI_SRS(v, BINOP(1));
		    break;
		}
	    case OP_AND:
		value->v = BINOPNOMOD(0) & BINOPNOMOD(1);
		break;
	    case OP_OR:
		value->v = BINOPNOMOD(0) | BINOPNOMOD(1);
		break;
	    case OP_XOR:
		value->v = BINOPNOMOD(0) ^ BINOPNOMOD(1);
		break;
	    case OP_SEXT:
		value->v = SIGNEXT(values[inst->u.cast.source].v);
		break;
	    case OP_TRUNC:
		/* fall-through */
	    case OP_ZEXT:
		value->v = values[inst->u.cast.source].v & values[inst->u.cast.mask].v;
		break;
	    case OP_BRANCH:
		jump(func, (values[inst->u.branch.condition].v&1) ?
		     inst->u.branch.br_true : inst->u.branch.br_false,
		     &bb, &inst, &value, &bb_inst);
		continue;
	    case OP_JMP:
		jump(func, inst->u.jump, &bb, &inst, &value, &bb_inst);
		continue;
	    case OP_RET:
		CHECK_GT(stack_depth, 0);
		stack_depth--;
		value = stack[stack_depth].ret;
		func = stack[stack_depth].func;
		CHECK_GT(func->values + func->numArgs+func->numInsts+func->numConstants, value);
		CHECK_GT(value, &func->values[-1]);
		value->v = values[inst->u.unaryop].v;
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
		value->v = BINOP(0) == BINOP(1) ? 1 : 0;
		break;
	    case OP_ICMP_NE:
		value->v = BINOP(0) != BINOP(1) ? 1 : 0;
		break;
	    case OP_ICMP_UGT:
		value->v = BINOP(0) > BINOP(1) ? 1 : 0;
		break;
	    case OP_ICMP_UGE:
		value->v = BINOP(0) >= BINOP(1) ? 1 : 0;
		break;
	    case OP_ICMP_ULT:
		value->v = BINOP(0) < BINOP(1) ? 1 : 0;
		break;
	    case OP_ICMP_ULE:
		value->v = BINOP(0) <= BINOP(1) ? 1 : 0;
		break;
	    case OP_ICMP_SGT:
		value->v = BINOPS(0) > BINOPS(1) ? 1 : 0;
		break;
	    case OP_ICMP_SGE:
		value->v = BINOPS(0) >= BINOPS(1) ? 1 : 0;
		break;
	    case OP_ICMP_SLE:
		value->v = BINOPS(0) <= BINOPS(1) ? 1 : 0;
		break;
	    case OP_ICMP_SLT:
		value->v = BINOPS(0) < BINOPS(1) ? 1 : 0;
		break;
	    case OP_SELECT:
		value->v = (values[inst->u.three[0]].v&1) ?
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
		cli_dbgmsg("Executing %d\n", inst->u.ops.funcid);
		func = func2;
		values = func->values;
		CHECK_GT(func->numBB, 0);
		jump(func, 0, &bb, &inst, &value, &bb_inst);
		continue;
	    case OP_COPY:
		BINOPNOMOD(1) = BINOPNOMOD(0);
		break;
	    default:
		cli_errmsg("Opcode %u is not implemented yet!\n", inst->opcode);
		stop = CL_EARG;
	}
	bb_inst++;
	inst++;
	CHECK_GT(bb->numInsts, bb_inst);
    } while (stop == CL_SUCCESS);

    free(stack);
    return stop == CL_BREAK ? CL_SUCCESS : stop;
}

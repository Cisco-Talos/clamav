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
static int bcfail(const char *msg, long a, long b,
		  const char *file, unsigned line)
{
    cli_errmsg("bytecode: check failed %s (%lx and %lx) at %s:%u\n", msg, a, b, file, line);
    return CL_EARG;
}
#define CHECK_FUNCID(funcid) do { if (funcid >= bc->num_func) return \
    bcfail("funcid out of bounds!",funcid, bc->num_func,__FILE__,__LINE__); } while(0)
#define CHECK_EQ(a, b) do { if ((a) != (b)) return \
    bcfail("Values "#a" and "#b" don't match!",(a),(b),__FILE__,__LINE__); } while(0)
#define CHECK_GT(a, b) do {if ((a) <= (b)) return \
    bcfail("Condition failed "#a" > "#b,(a),(b), __FILE__, __LINE__); } while(0)
#else
#define CHECK_FUNCID(x)
#define CHECK_EQ(a,b)
#define CHECK_GT(a,b)
#endif

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
#define type2mask(t) (inst->type == 64 ? ~0ull : (1ull << inst->type)-1)
#define BINOP(i) (BINOPNOMOD(i)&type2mask(inst->type))
#define UNOP(x) (UNOPNOMOD(i)&typemask(inst->type))

/* get the operand as a signed value.
 * Warning: this assumes that result type is same as operand type.
 * This is usually true, except for icmp_* and select.
 * For icmp_* we fix it up in the loader. */
#define SIGNEXT(a, from) CLI_SRS(((int64_t)(a)) << (64-(from)), (64-(from)))
#define BINOPS(i) SIGNEXT(BINOPNOMOD(i), inst->type)

#define CASTOP (values[inst->u.cast.source].v& inst->u.cast.mask)

#undef always_inline
#define always_inline

static always_inline int jump(const struct cli_bc_func *func, uint16_t bbid, struct cli_bc_bb **bb, const struct cli_bc_inst **inst,
		unsigned *bb_inst)
{
    CHECK_GT(func->numBB, bbid);
    *bb = &func->BB[bbid];
    *inst = (*bb)->insts;
    *bb_inst = 0;
    return 0;
}

#define STACK_CHUNKSIZE 16384

struct stack_chunk {
    struct stack_chunk *prev;
    unsigned used;
    union {
	void *align;
	char data[STACK_CHUNKSIZE];
    } u;
};

struct stack {
    struct stack_chunk* chunk;
    uint16_t last_size;
};

static always_inline void* cli_stack_alloc(struct stack *stack, unsigned bytes)
{
    struct stack_chunk *chunk = stack->chunk;
    uint16_t last_size_off;

    /* last_size is stored after data */
    /* align bytes to pointer size */
    bytes = (bytes + sizeof(uint16_t) + sizeof(void*)) & ~(sizeof(void*)-1);
    last_size_off = bytes - 2;

    if (chunk && (chunk->used + bytes <= STACK_CHUNKSIZE)) {
	/* there is still room in this chunk */
	void *ret;

	*(uint16_t*)&chunk->u.data[chunk->used + last_size_off] = stack->last_size;
	stack->last_size = bytes/sizeof(void*);

	ret = chunk->u.data + chunk->used;
	chunk->used += bytes;
	return ret;
    }

    if(bytes >= STACK_CHUNKSIZE) {
	cli_errmsg("cli_stack_alloc: Attempt to allocate more than STACK_CHUNKSIZE bytes!\n");
	return NULL;
    }
    /* not enough room here, allocate new chunk */
    chunk = cli_malloc(sizeof(*stack->chunk));
    if (!chunk)
	return NULL;

    *(uint16_t*)&chunk->u.data[last_size_off] = stack->last_size;
    stack->last_size = bytes/sizeof(void*);

    chunk->used = bytes;
    chunk->prev = stack->chunk;
    stack->chunk = chunk;
    return chunk->u.data;
}

static always_inline void cli_stack_free(struct stack *stack, void *data)
{
    uint16_t last_size;
    struct stack_chunk *chunk = stack->chunk;
    if (!chunk) {
	cli_errmsg("cli_stack_free: stack empty!\n");
	return;
    }
    if ((chunk->u.data + chunk->used) != ((char*)data + stack->last_size*sizeof(void*))) {
	cli_errmsg("cli_stack_free: wrong free order: %p, expected %p\n",
		   data, chunk->u.data + chunk->used - stack->last_size*sizeof(void*));
	return;
    }
    last_size = *(uint16_t*)&chunk->u.data[chunk->used-2];
    if (chunk->used < stack->last_size*sizeof(void*)) {
	cli_errmsg("cli_stack_free: last_size is corrupt!\n");
	return;
    }
    chunk->used -= stack->last_size*sizeof(void*);
    stack->last_size = last_size;
    if (!chunk->used) {
	stack->chunk = chunk->prev;
	free(chunk);
    }
}

static void cli_stack_destroy(struct stack *stack)
{
    struct stack_chunk *chunk = stack->chunk;
    while (chunk) {
	stack->chunk = chunk->prev;
	free(chunk);
	chunk = stack->chunk;
    }
}

struct stack_entry {
    struct stack_entry *prev;
    const struct cli_bc_func *func;
    struct cli_bc_value *ret;
    struct cli_bc_bb *bb;
    unsigned bb_inst;
    struct cli_bc_value *values;
};

static always_inline struct stack_entry *allocate_stack(struct stack *stack,
							struct stack_entry *prev,
							const struct cli_bc_func *func,
							const struct cli_bc_func *func_old,
							struct cli_bc_value *ret,
							struct cli_bc_bb *bb,
							unsigned bb_inst)
{
    unsigned i;
    struct cli_bc_value *values;
    const unsigned numValues = func->numValues + func->numConstants;
    struct stack_entry *entry = cli_stack_alloc(stack, sizeof(*entry) + sizeof(*values)*numValues);
    if (!entry)
	return NULL;
    entry->prev = prev;
    entry->func = func_old;
    entry->ret = ret;
    entry->bb = bb;
    entry->bb_inst = bb_inst;
    /* we allocated room for values right after stack_entry! */
    entry->values = values = (struct cli_bc_value*)&entry[1];

    memcpy(&values[func->numValues], func->constants,
	   sizeof(*values)*func->numConstants);
    return entry;
}

static always_inline struct stack_entry *pop_stack(struct stack *stack,
						   struct stack_entry *stack_entry,
						   const struct cli_bc_func **func,
						   struct cli_bc_value **ret,
						   struct cli_bc_bb **bb,
						   unsigned *bb_inst)
{
    void *data;
    *func = stack_entry->func;
    *ret = stack_entry->ret;
    *bb = stack_entry->bb;
    *bb_inst = stack_entry->bb_inst;
    data = stack_entry;
    stack_entry = stack_entry->prev;
    cli_stack_free(stack, data);
    return stack_entry;
}

int cli_vm_execute(const struct cli_bc *bc, struct cli_bc_ctx *ctx, const struct cli_bc_func *func, const struct cli_bc_inst *inst)
{
    uint64_t tmp;
    unsigned i, stack_depth=0, bb_inst=0, stop=0 ;
    struct cli_bc_func *func2;
    struct stack stack;
    struct stack_entry *stack_entry = NULL;
    struct cli_bc_bb *bb = NULL;
    struct cli_bc_value *values = ctx->values;
    struct cli_bc_value *value, *old_values;

    memset(&stack, 0, sizeof(stack));
    do {
	value = &values[inst->dest];
	CHECK_GT(func->numValues+func->numConstants, value - values);
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
		    if (UNLIKELY(!d)) {
			cli_dbgmsg("bytecode attempted to execute udiv#0\n");
			return CL_EBYTECODE;
		    }
		    value->v = BINOP(0) / d;
		    break;
		}
	    case OP_SDIV:
		{
		    int64_t a = BINOPS(0);
		    int64_t b = BINOPS(1);
		    if (UNLIKELY(b == 0 || (b == -1 && a == (-9223372036854775807LL-1LL)))) {
			cli_dbgmsg("bytecode attempted to execute sdiv#0\n");
			return CL_EBYTECODE;
		    }
		    value->v = a / b;
		    break;
		}
	    case OP_UREM:
		{
		    uint64_t d = BINOP(1);
		    if (UNLIKELY(!d)) {
			cli_dbgmsg("bytecode attempted to execute urem#0\n");
			return CL_EBYTECODE;
		    }
		    value->v = BINOP(0) % d;
		    break;
		}
	    case OP_SREM:
		{
		    int64_t a = BINOPS(0);
		    int64_t b = BINOPS(1);
		    if (UNLIKELY(b == 0 || (b == -1 && (a == -9223372036854775807LL-1LL)))) {
			cli_dbgmsg("bytecode attempted to execute srem#0\n");
			return CL_EBYTECODE;
		    }
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
		/* mask is number of src bits here, not a mask! */
		value->v = SIGNEXT(values[inst->u.cast.source].v, inst->u.cast.mask);
		break;
	    case OP_TRUNC:
		/* fall-through */
	    case OP_ZEXT:
		value->v = CASTOP;
		break;
	    case OP_BRANCH:
		stop = jump(func, (values[inst->u.branch.condition].v&1) ?
			  inst->u.branch.br_true : inst->u.branch.br_false,
			  &bb, &inst, &bb_inst);
		continue;
	    case OP_JMP:
		stop = jump(func, inst->u.jump, &bb, &inst, &bb_inst);
		continue;
	    case OP_RET:
		CHECK_GT(stack_depth, 0);
		tmp = values[inst->u.unaryop].v;
		stack_entry = pop_stack(&stack, stack_entry, &func, &value, &bb,
					&bb_inst);
		values = stack_entry ? stack_entry->values : ctx->values;
		CHECK_GT(func->numValues+func->numConstants, value-values);
		CHECK_GT(value-values, -1);
		value->v = tmp;
		if (!bb) {
		    stop = CL_BREAK;
		    continue;
		}
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
		old_values = values;
		stack_entry = allocate_stack(&stack, stack_entry, func2, func, value,
					     bb, bb_inst);
		values = stack_entry->values;
//		cli_dbgmsg("Executing %d\n", inst->u.ops.funcid);
		for (i=0;i<func2->numArgs;i++)
		    values[i] = old_values[inst->u.ops.ops[i]];
		func = func2;
		CHECK_GT(func->numBB, 0);
		stop = jump(func, 0, &bb, &inst, &bb_inst);
		stack_depth++;
		continue;
	    case OP_COPY:
		BINOPNOMOD(1) = BINOPNOMOD(0);
		break;
	    default:
		cli_errmsg("Opcode %u is not implemented yet!\n", inst->opcode);
		stop = CL_EARG;
		break;
	}
	bb_inst++;
	inst++;
	CHECK_GT(bb->numInsts, bb_inst);
    } while (stop == CL_SUCCESS);

    cli_stack_destroy(&stack);
    return stop == CL_BREAK ? CL_SUCCESS : stop;
}

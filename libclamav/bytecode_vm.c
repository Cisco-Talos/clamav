/*
 *  Execute ClamAV bytecode.
 *
 *  Copyright (C) 2009-2010 Sourcefire, Inc.
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
#include "type_desc.h"
#include "readdb.h"
#include <string.h>

/* Enable this to catch more bugs in the RC phase */
#define CL_BYTECODE_DEBUG

/* These checks will also be done by the bytecode verifier, but for
 * debugging purposes we have explicit checks, these should never fail! */
#ifdef CL_BYTECODE_DEBUG
static int bcfail(const char *msg, long a, long b,
		  const char *file, unsigned line)
{
    cli_errmsg("bytecode: check failed %s (%lx and %lx) at %s:%u\n", msg, a, b, file, line);
    return CL_EARG;
}

#define CHECK_UNREACHABLE do { cli_dbgmsg("bytecode: unreachable executed!\n"); return CL_EBYTECODE; } while(0)
#define CHECK_FUNCID(funcid) do { if (funcid >= bc->num_func) return \
    bcfail("funcid out of bounds!",funcid, bc->num_func,__FILE__,__LINE__); } while(0)
#define CHECK_APIID(funcid) do { if (funcid >= cli_apicall_maxapi) return \
    bcfail("APIid out of bounds!",funcid, cli_apicall_maxapi,__FILE__,__LINE__); } while(0)
#define CHECK_EQ(a, b) do { if ((a) != (b)) return \
    bcfail("Values "#a" and "#b" don't match!",(a),(b),__FILE__,__LINE__); } while(0)
#define CHECK_GT(a, b) do {if ((a) <= (b)) return \
    bcfail("Condition failed "#a" > "#b,(a),(b), __FILE__, __LINE__); } while(0)
#define TRACE_R(x) cli_dbgmsg("bytecode trace: %u, read %llx\n", pc, (long long)x);
#define TRACE_W(x, w, p) cli_dbgmsg("bytecode trace: %u, write%d @%u %llx\n", pc, p, w, (long long)x);
#define TRACE_EXEC(id, dest, ty, stack) cli_dbgmsg("bytecode trace: executing %d, -> %u (%u); %u\n", id, dest, ty, stack)
#else
#define TRACE_R(x)
#define TRACE_W(x, w, p)
#define TRACE_EXEC(id, dest, ty, stack)
#define CHECK_UNREACHABLE return CL_EBYTECODE
#define CHECK_FUNCID(x);
#define CHECK_APIID(x);
#define CHECK_EQ(a,b)
#define CHECK_GT(a,b)
#endif

#define SIGNEXT(a, from) CLI_SRS(((int64_t)(a)) << (64-(from)), (64-(from)))

#ifdef CL_DEBUG
#undef always_inline
#define always_inline
#endif

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

/* type with largest alignment that we use (in general it is a long double, but
 * thats too big alignment for us) */
typedef uint64_t align_t;

static always_inline void* cli_stack_alloc(struct stack *stack, unsigned bytes)
{
    struct stack_chunk *chunk = stack->chunk;
    uint16_t last_size_off;

    /* last_size is stored after data */
    /* align bytes to pointer size */
    bytes = (bytes + sizeof(uint16_t) + sizeof(align_t)) & ~(sizeof(align_t)-1);
    last_size_off = bytes - 2;

    if (chunk && (chunk->used + bytes <= STACK_CHUNKSIZE)) {
	/* there is still room in this chunk */
	void *ret;

	*(uint16_t*)&chunk->u.data[chunk->used + last_size_off] = stack->last_size;
	stack->last_size = bytes/sizeof(align_t);

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
    stack->last_size = bytes/sizeof(align_t);

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
    if ((chunk->u.data + chunk->used) != ((char*)data + stack->last_size*sizeof(align_t))) {
	cli_errmsg("cli_stack_free: wrong free order: %p, expected %p\n",
		   data, chunk->u.data + chunk->used - stack->last_size*sizeof(align_t));
	return;
    }
    last_size = *(uint16_t*)&chunk->u.data[chunk->used-2];
    if (chunk->used < stack->last_size*sizeof(align_t)) {
	cli_errmsg("cli_stack_free: last_size is corrupt!\n");
	return;
    }
    chunk->used -= stack->last_size*sizeof(align_t);
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
    operand_t ret;
    struct cli_bc_bb *bb;
    unsigned bb_inst;
    char *values;
};

static always_inline struct stack_entry *allocate_stack(struct stack *stack,
							struct stack_entry *prev,
							const struct cli_bc_func *func,
							const struct cli_bc_func *func_old,
							operand_t ret,
							struct cli_bc_bb *bb,
							unsigned bb_inst)
{
    char *values;
    struct stack_entry *entry = cli_stack_alloc(stack, sizeof(*entry) + sizeof(*values)*func->numBytes);
    if (!entry)
	return NULL;
    entry->prev = prev;
    entry->func = func_old;
    entry->ret = ret;
    entry->bb = bb;
    entry->bb_inst = bb_inst;
    /* we allocated room for values right after stack_entry! */
    entry->values = values = (char*)&entry[1];

    memcpy(&values[func->numBytes - func->numConstants*8], func->constants,
	   sizeof(*values)*func->numConstants*8);
    return entry;
}

static always_inline struct stack_entry *pop_stack(struct stack *stack,
						   struct stack_entry *stack_entry,
						   const struct cli_bc_func **func,
						   operand_t *ret,
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


/*
 *
 * p, p+1, p+2, p+3 <- gt
    CHECK_EQ((p)&1, 0); 
    CHECK_EQ((p)&3, 0); 
    CHECK_EQ((p)&7, 0); 
*/
#define WRITE8(p, x) CHECK_GT(func->numBytes, p);\
    TRACE_W(x, p, 8);\
    *(uint8_t*)&values[p] = x
#define WRITE16(p, x) CHECK_GT(func->numBytes, p+1);\
    CHECK_EQ((p)&1, 0);\
    TRACE_W(x, p, 16);\
    *(uint16_t*)&values[p] = x
#define WRITE32(p, x) CHECK_GT(func->numBytes, p+3);\
    CHECK_EQ((p)&3, 0);\
    TRACE_W(x, p, 32);\
    *(uint32_t*)&values[p] = x
#define WRITE64(p, x) CHECK_GT(func->numBytes, p+7);\
    CHECK_EQ((p)&7, 0);\
    TRACE_W(x, p, 64);\
    *(uint64_t*)&values[p] = x
#define WRITEP(x, p) CHECK_GT(func->numBytes, p+PSIZE-1);\
    CHECK_EQ((p)&(PSIZE-1), 0);\
    TRACE_W(x, p, PSIZE*8);\
    *(void**)&values[p] = x

#define uint_type(n) uint##n##_t
#define READNfrom(maxBytes, from, x, n, p)\
    CHECK_GT((maxBytes), (p)+(n/8)-1);\
    x = *(uint_type(n)*)&(from)[(p)];\
    TRACE_R(x)

#define READN(x, n, p)\
 do {\
     if (p&0x80000000) {\
	 uint32_t pg = p&0x7fffffff;\
	 READNfrom(ctx->numGlobals, ctx->globals, x, n, p);\
     } else {\
	 READNfrom(func->numBytes, values, x, n, p);\
     }\
 } while (0)

#define READ1(x, p) READN(x, 8, p);\
    x = x&1
#define READ8(x, p) READN(x, 8, p)
#define READ16(x, p) READN(x, 16, p)
#define READ32(x, p) READN(x, 32, p)
#define READ64(x, p) READN(x, 64, p)

#define PSIZE sizeof(void*)
#define READP(x, p) CHECK_GT(func->numBytes, p+PSIZE-1);\
    CHECK_EQ((p)&(PSIZE-1), 0);\
    x = *(void**)&values[p];\
    TRACE_R(x)

#define READOLD8(x, p) CHECK_GT(func->numBytes, p);\
    x = *(uint8_t*)&old_values[p];\
    TRACE_R(x)
#define READOLD16(x, p) CHECK_GT(func->numBytes, p+1);\
    CHECK_EQ((p)&1, 0);\
    x = *(uint16_t*)&old_values[p];\
    TRACE_R(x)
#define READOLD32(x, p) CHECK_GT(func->numBytes, p+3);\
    CHECK_EQ((p)&3, 0);\
    x = *(uint32_t*)&old_values[p];\
    TRACE_R(x)
#define READOLD64(x, p) CHECK_GT(func->numBytes, p+7);\
    CHECK_EQ((p)&7, 0);\
    x = *(uint64_t*)&old_values[p];\
    TRACE_R(x)

#define BINOP(i) inst->u.binop[i]

#define DEFINE_BINOP_BC_HELPER(opc, OP, W0, W1, W2, W3, W4) \
    case opc*5: {\
		    uint8_t op0, op1, res;\
		    int8_t sop0, sop1;\
		    READ1(op0, BINOP(0));\
		    READ1(op1, BINOP(1));\
		    sop0 = op0; sop1 = op1;\
		    OP;\
		    W0(inst->dest, res);\
		    break;\
		}\
    case opc*5+1: {\
		    uint8_t op0, op1, res;\
		    int8_t sop0, sop1;\
		    READ8(op0, BINOP(0));\
		    READ8(op1, BINOP(1));\
		    sop0 = op0; sop1 = op1;\
		    OP;\
		    W1(inst->dest, res);\
		    break;\
		}\
    case opc*5+2: {\
		    uint16_t op0, op1, res;\
		    int16_t sop0, sop1;\
		    READ16(op0, BINOP(0));\
		    READ16(op1, BINOP(1));\
		    sop0 = op0; sop1 = op1;\
		    OP;\
		    W2(inst->dest, res);\
		    break;\
		}\
    case opc*5+3: {\
		    uint32_t op0, op1, res;\
		    int32_t sop0, sop1;\
		    READ32(op0, BINOP(0));\
		    READ32(op1, BINOP(1));\
		    sop0 = op0; sop1 = op1;\
		    OP;\
		    W3(inst->dest, res);\
		    break;\
		}\
    case opc*5+4: {\
		    uint64_t op0, op1, res;\
		    int64_t sop0, sop1;\
		    READ64(op0, BINOP(0));\
		    READ64(op1, BINOP(1));\
		    sop0 = op0; sop1 = op1;\
		    OP;\
		    W4(inst->dest, res);\
		    break;\
		}

#define DEFINE_BINOP(opc, OP) DEFINE_BINOP_BC_HELPER(opc, OP, WRITE8, WRITE8, WRITE16, WRITE32, WRITE64)
#define DEFINE_ICMPOP(opc, OP) DEFINE_BINOP_BC_HELPER(opc, OP, WRITE8, WRITE8, WRITE8, WRITE8, WRITE8)

#define CHECK_OP(cond, msg) if((cond)) { cli_dbgmsg(msg); stop = CL_EBYTECODE; break;}

#define DEFINE_CASTOP(opc, OP) \
    case opc*5: {\
		    uint8_t res;\
		    int8_t sres;\
		    OP;\
		    WRITE8(inst->dest, res);\
		    break;\
		}\
    case opc*5+1: {\
		    uint8_t res;\
		    int8_t sres;\
		    OP;\
		    WRITE8(inst->dest, res);\
		    break;\
		}\
    case opc*5+2: {\
		    uint16_t res;\
		    int16_t sres;\
		    OP;\
		    WRITE16(inst->dest, res);\
		    break;\
		}\
    case opc*5+3: {\
		    uint32_t res;\
		    int32_t sres;\
		    OP;\
		    WRITE32(inst->dest, res);\
		    break;\
		}\
    case opc*5+4: {\
		    uint64_t res;\
		    int64_t sres;\
		    OP;\
		    WRITE64(inst->dest, res);\
		    break;\
		}

#define DEFINE_OP(opc) \
    case opc*5: /* fall-through */\
    case opc*5+1: /* fall-through */\
    case opc*5+2: /* fall-through */\
    case opc*5+3: /* fall-through */\
    case opc*5+4:

#define CHOOSE(OP0, OP1, OP2, OP3, OP4) \
    switch (inst->u.cast.size) {\
	case 0: OP0; break;\
	case 1: OP1; break;\
	case 2: OP2; break;\
	case 3: OP3; break;\
	case 4: OP4; break;\
	default: CHECK_UNREACHABLE;\
    }

#define DEFINE_OP_BC_RET_N(OP, T, R0, W0) \
    case OP: {\
		T tmp;\
		R0(tmp, inst->u.unaryop);\
		CHECK_GT(stack_depth, 0);\
		stack_depth--;\
		stack_entry = pop_stack(&stack, stack_entry, &func, &i, &bb,\
					&bb_inst);\
		values = stack_entry ? stack_entry->values : ctx->values;\
		CHECK_GT(func->numBytes, i);\
		W0(i, tmp);\
		if (!bb) {\
		    stop = CL_BREAK;\
		    continue;\
		}\
		inst = &bb->insts[bb_inst];\
		break;\
	    }

static always_inline int check_sdivops(int64_t op0, int64_t op1)
{
    return op1 == 0 || (op0 == -1 && op1 ==  (-9223372036854775807LL-1LL));
}

int cli_vm_execute(const struct cli_bc *bc, struct cli_bc_ctx *ctx, const struct cli_bc_func *func, const struct cli_bc_inst *inst)
{
    unsigned i, j, stack_depth=0, bb_inst=0, stop=0, pc=0;
    struct cli_bc_func *func2;
    struct stack stack;
    struct stack_entry *stack_entry = NULL;
    struct cli_bc_bb *bb = NULL;
    char *values = ctx->values;
    char *old_values;

    memset(&stack, 0, sizeof(stack));
    do {
	pc++;
	switch (inst->interp_op) {
	    DEFINE_BINOP(OP_BC_ADD, res = op0 + op1);
	    DEFINE_BINOP(OP_BC_SUB, res = op0 - op1);
	    DEFINE_BINOP(OP_BC_MUL, res = op0 * op1);

	    DEFINE_BINOP(OP_BC_UDIV, CHECK_OP(op1 == 0, "bytecode attempted to execute udiv#0\n");
			 res=op0/op1);
	    DEFINE_BINOP(OP_BC_SDIV, CHECK_OP(check_sdivops(sop0, sop1), "bytecode attempted to execute sdiv#0\n");
			 res=sop0/sop1);
	    DEFINE_BINOP(OP_BC_UREM, CHECK_OP(op1 == 0, "bytecode attempted to execute urem#0\n");
			 res=op0 % op1);
	    DEFINE_BINOP(OP_BC_SREM, CHECK_OP(check_sdivops(sop0,sop1), "bytecode attempted to execute urem#0\n");
			 res=sop0 % sop1);

	    DEFINE_BINOP(OP_BC_SHL, CHECK_OP(op1 > inst->type, "bytecode attempted to execute shl greater than bitwidth\n");
			 res = op0 << op1);
	    DEFINE_BINOP(OP_BC_LSHR, CHECK_OP(op1 > inst->type, "bytecode attempted to execute lshr greater than bitwidth\n");
			 res = op0 >> op1);
	    DEFINE_BINOP(OP_BC_ASHR, CHECK_OP(op1 > inst->type, "bytecode attempted to execute ashr greater than bitwidth\n");
			 res = CLI_SRS(sop0, op1));

	    DEFINE_BINOP(OP_BC_AND, res = op0 & op1);
	    DEFINE_BINOP(OP_BC_OR, res = op0 | op1);
	    DEFINE_BINOP(OP_BC_XOR, res = op0 ^ op1);

	    DEFINE_CASTOP(OP_BC_SEXT,
			  CHOOSE(READ1(sres, inst->u.cast.source); res = sres ? ~0ull : 0,
				 READ8(sres, inst->u.cast.source); res=sres=SIGNEXT(sres, inst->u.cast.mask),
				 READ16(sres, inst->u.cast.source); res=sres=SIGNEXT(sres, inst->u.cast.mask),
				 READ32(sres, inst->u.cast.source); res=sres=SIGNEXT(sres, inst->u.cast.mask),
				 READ64(sres, inst->u.cast.source); res=sres=SIGNEXT(sres, inst->u.cast.mask)));
	    DEFINE_CASTOP(OP_BC_ZEXT,
			  CHOOSE(READ1(res, inst->u.cast.source),
				 READ8(res, inst->u.cast.source),
				 READ16(res, inst->u.cast.source),
				 READ32(res, inst->u.cast.source),
				 READ64(res, inst->u.cast.source)));
	    DEFINE_CASTOP(OP_BC_TRUNC,
			  CHOOSE(READ1(res, inst->u.cast.source),
				 READ8(res, inst->u.cast.source),
				 READ16(res, inst->u.cast.source),
				 READ32(res, inst->u.cast.source),
				 READ64(res, inst->u.cast.source)));

	    DEFINE_OP(OP_BC_BRANCH)
		stop = jump(func, (values[inst->u.branch.condition]&1) ?
			  inst->u.branch.br_true : inst->u.branch.br_false,
			  &bb, &inst, &bb_inst);
		continue;

	    DEFINE_OP(OP_BC_JMP)
		stop = jump(func, inst->u.jump, &bb, &inst, &bb_inst);
		continue;

	    DEFINE_OP_BC_RET_N(OP_BC_RET*5, uint8_t, READ1, WRITE8);
	    DEFINE_OP_BC_RET_N(OP_BC_RET*5+1, uint8_t, READ8, WRITE8);
	    DEFINE_OP_BC_RET_N(OP_BC_RET*5+2, uint16_t, READ16, WRITE16);
	    DEFINE_OP_BC_RET_N(OP_BC_RET*5+3, uint32_t, READ32, WRITE32);
	    DEFINE_OP_BC_RET_N(OP_BC_RET*5+4, uint64_t, READ64, WRITE64);

	    DEFINE_ICMPOP(OP_BC_ICMP_EQ, res = (op0 == op1));
	    DEFINE_ICMPOP(OP_BC_ICMP_NE, res = (op0 != op1));
	    DEFINE_ICMPOP(OP_BC_ICMP_UGT, res = (op0 > op1));
	    DEFINE_ICMPOP(OP_BC_ICMP_UGE, res = (op0 >= op1));
	    DEFINE_ICMPOP(OP_BC_ICMP_ULT, res = (op0 < op1));
	    DEFINE_ICMPOP(OP_BC_ICMP_ULE, res = (op0 <= op1));
	    DEFINE_ICMPOP(OP_BC_ICMP_SGT, res = (sop0 > sop1));
	    DEFINE_ICMPOP(OP_BC_ICMP_SGE, res = (sop0 >= sop1));
	    DEFINE_ICMPOP(OP_BC_ICMP_SLE, res = (sop0 <= sop1));
	    DEFINE_ICMPOP(OP_BC_ICMP_SLT, res = (sop0 < sop1));

	    case OP_BC_SELECT*5:
	    {
		uint8_t t0, t1, t2;
		READ1(t0, inst->u.three[0]);
		READ1(t1, inst->u.three[1]);
		READ1(t2, inst->u.three[2]);
		WRITE8(inst->dest, t0 ? t1 : t2);
		break;
	    }
	    case OP_BC_SELECT*5+1:
	    {
	        uint8_t t0, t1, t2;
		READ1(t0, inst->u.three[0]);
		READ8(t1, inst->u.three[1]);
		READ8(t2, inst->u.three[2]);
		WRITE8(inst->dest, t0 ? t1 : t2);
		break;
	    }
	    case OP_BC_SELECT*5+2:
	    {
	        uint8_t t0;
		uint16_t t1, t2;
		READ1(t0, inst->u.three[0]);
		READ16(t1, inst->u.three[1]);
		READ16(t2, inst->u.three[2]);
		WRITE16(inst->dest, t0 ? t1 : t2);
		break;
	    }
	    case OP_BC_SELECT*5+3:
	    {
	        uint8_t t0;
		uint32_t t1, t2;
		READ1(t0, inst->u.three[0]);
		READ32(t1, inst->u.three[1]);
		READ32(t2, inst->u.three[2]);
		WRITE32(inst->dest, t0 ? t1 : t2);
		break;
	    }
	    case OP_BC_SELECT*5+4:
	    {
	        uint8_t t0;
		uint64_t t1, t2;
		READ1(t0, inst->u.three[0]);
		READ64(t1, inst->u.three[1]);
		READ64(t2, inst->u.three[2]);
		WRITE64(inst->dest, t0 ? t1 : t2);
		break;
	    }

	    DEFINE_OP(OP_BC_CALL_API) {
		const struct cli_apicall *api = &cli_apicalls[inst->u.ops.funcid];
		int32_t res;
		CHECK_APIID(inst->u.ops.funcid);
		TRACE_EXEC(-inst->u.ops.funcid, inst->dest, inst->type, stack_depth);
	        switch (api->kind) {
		    case 0: {
			int32_t a, b, r;
			READ32(a, inst->u.ops.ops[0]);
			READ32(b, inst->u.ops.ops[1]);
			res = cli_apicalls0[api->idx](ctx, a, b);
			break;
		    }
		    case 1: {
			cli_errmsg("bytecode: type 1 apicalls not yet implemented!\n");
			stop = CL_EBYTECODE;
		/*	void *p;
			uint32_t u;
			p = ...;
			u = READ32(v, inst->u.ops.ops[1]);
			res =  cli_apicalls1[api->idx](p, u);
			break;*/
		    }
		    case 2: {
			int32_t a;
			READ32(a, inst->u.ops.ops[0]);
			res = cli_apicalls2[api->idx](ctx, a);
			break;
		    }
		    case 3: {
			cli_errmsg("bytecode: type 3 apicalls not yet implemented!\n");
			stop = CL_EBYTECODE;
		/*	void *p;
			uint32_t u;
			p = ...;
			u = READ32(v, inst->u.ops.ops[1]);
			res =  cli_apicalls1[api->idx](p, u);
			break;*/
			    }
		}
		WRITE32(inst->dest, res);
		break;
	    }

	    DEFINE_OP(OP_BC_CALL_DIRECT)
		CHECK_FUNCID(inst->u.ops.funcid);
		func2 = &bc->funcs[inst->u.ops.funcid];
		CHECK_EQ(func2->numArgs, inst->u.ops.numOps);
		old_values = values;
		stack_entry = allocate_stack(&stack, stack_entry, func2, func, inst->dest,
					     bb, bb_inst);
		if (!stack_entry) {
		    stop = CL_EMEM;
		    break;
		}
		values = stack_entry->values;
		TRACE_EXEC(inst->u.ops.funcid, inst->dest, inst->type, stack_depth);
		if (stack_depth > 10000) {
		    cli_errmsg("bytecode: stack depth exceeded\n");
		    stop = CL_EBYTECODE;
		    break;
		}
		j = 0;
		for (i=0;i<func2->numArgs;i++) {
		    switch (inst->u.ops.opsizes[i]) {
			case 1: {
			    uint8_t v;
			    READOLD8(v, inst->u.ops.ops[i]);
			    CHECK_GT(func2->numBytes, j);
			    values[j++] = v;
			    break;
			}
			case 2: {
			    uint16_t v;
			    READOLD16(v, inst->u.ops.ops[i]);
			    j = (j+1)&~1;
			    CHECK_GT(func2->numBytes, j);
			    *(uint16_t*)&values[j] = v;
			    j += 2;
			    break;
			}
			case 4: {
			    uint32_t v;
			    READOLD32(v, inst->u.ops.ops[i]);
			    j = (j+3)&~3;
			    CHECK_GT(func2->numBytes, j);
			    *(uint32_t*)&values[j] = v;
			    j += 4;
			    break;
			}
			case 8: {
			    uint64_t v;
			    READOLD64(v, inst->u.ops.ops[i]);
			    j = (j+7)&~7;
			    CHECK_GT(func2->numBytes, j);
			    *(uint64_t*)&values[j] = v;
			    j += 8;
			    break;
			}
		    }
		}
		func = func2;
		CHECK_GT(func->numBB, 0);
		stop = jump(func, 0, &bb, &inst, &bb_inst);
		stack_depth++;
		continue;

	    case OP_BC_COPY*5:
	    {
		uint8_t op;
		READ1(op, BINOP(0));
		WRITE8(BINOP(1), op);
		break;
	    }
	    case OP_BC_COPY*5+1:
	    {
		uint8_t op;
		READ8(op, BINOP(0));
		WRITE8(BINOP(1), op);
		break;
	    }
	    case OP_BC_COPY*5+2:
	    {
		uint16_t op;
		READ16(op, BINOP(0));
		WRITE16(BINOP(1), op);
		break;
	    }
	    case OP_BC_COPY*5+3:
	    {
		uint32_t op;
		READ32(op, BINOP(0));
		WRITE32(BINOP(1), op);
		break;
	    }
	    case OP_BC_COPY*5+4:
	    {
		uint64_t op;
		READ32(op, BINOP(0));
		WRITE32(BINOP(1), op);
		break;
	    }

	    case OP_BC_LOAD*5:
	    case OP_BC_LOAD*5+1:
	    {
		uint8_t *ptr;
		READP(ptr, inst->u.unaryop);
		WRITE8(inst->dest, (*ptr));
		break;
	    }
	    case OP_BC_LOAD*5+2:
	    {
		const union unaligned_16 *ptr;
		READP(ptr, inst->u.unaryop);
		WRITE16(inst->dest, (ptr->una_u16));
		break;
	    }
	    case OP_BC_LOAD*5+3:
	    {
		const union unaligned_32 *ptr;
		READP(ptr, inst->u.unaryop);
		if (!ptr) {
		    cli_dbgmsg("Bytecode attempted to load from null pointer!\n");
		    return CL_EBYTECODE;
		}
		WRITE32(inst->dest, (ptr->una_u32));
		break;
	    }
	    case OP_BC_LOAD*5+4:
	    {
		const union unaligned_64 *ptr;
		READP(ptr, inst->u.unaryop);
		WRITE64(inst->dest, (ptr->una_u64));
		break;
	    }

	    case OP_BC_STORE*5:
	    {
		uint8_t *ptr;
		uint8_t v;
		READP(ptr, BINOP(0));
		READ1(v, BINOP(1));
		*ptr = v;
		break;
	    }
	    case OP_BC_STORE*5+1:
	    {
		uint8_t *ptr;
		uint8_t v;
		READP(ptr, BINOP(0));
		READ8(v, BINOP(1));
		*ptr = v;
		break;
	    }
	    case OP_BC_STORE*5+2:
	    {
		union unaligned_16 *ptr;
		uint16_t v;
		READP(ptr, BINOP(0));
		READ16(v, BINOP(1));
		ptr->una_s16 = v;
		break;
	    }
	    case OP_BC_STORE*5+3:
	    {
		union unaligned_32 *ptr;
		uint32_t v;
		READP(ptr, BINOP(0));
		READ32(v, BINOP(1));
		ptr->una_u32 = v;
		break;
	    }
	    case OP_BC_STORE*5+4:
	    {
		union unaligned_64 *ptr;
		uint64_t v;
		READP(ptr, BINOP(0));
		READ64(v, BINOP(1));
		ptr->una_u64 = v;
		break;
	    }
	    DEFINE_OP(OP_BC_ISBIGENDIAN) {
		WRITE8(inst->dest, WORDS_BIGENDIAN);
		break;
	    }
	    /* TODO: implement OP_BC_GEP1, OP_BC_GEP2, OP_BC_GEPN */
	    default:
		cli_errmsg("Opcode %u of type %u is not implemented yet!\n",
			   inst->interp_op/5, inst->interp_op%5);
		stop = CL_EARG;
		continue;
	}
	bb_inst++;
	inst++;
	if (bb) {
	    CHECK_GT(bb->numInsts, bb_inst);
	}
    } while (stop == CL_SUCCESS);

    cli_stack_destroy(&stack);
    return stop == CL_BREAK ? CL_SUCCESS : stop;
}

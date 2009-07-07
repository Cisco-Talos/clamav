/*
 *  Load, and verify ClamAV bytecode.
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

struct cli_bc_ctx *cli_bytecode_context_alloc(void)
{
    struct cli_bc_ctx *ctx = cli_malloc(sizeof(*ctx));
    ctx->bc = NULL;
    ctx->func = NULL;
    ctx->values = NULL;
    ctx->operands = NULL;
    return ctx;
}

void cli_bytecode_context_destroy(struct cli_bc_ctx *ctx)
{
   cli_bytecode_context_clear(ctx);
   free(ctx);
}

int cli_bytecode_context_clear(struct cli_bc_ctx *ctx)
{
    free(ctx->values);
    free(ctx->operands);
    memset(ctx, 0, sizeof(ctx));
}

int cli_bytecode_context_setfuncid(struct cli_bc_ctx *ctx, struct cli_bc *bc, unsigned funcid)
{
    unsigned i;
    struct cli_bc_func *func;
    if (funcid >= bc->num_func) {
	cli_errmsg("bytecode: function ID doesn't exist: %u\n", funcid);
	return CL_EARG;
    }
    ctx->func = &bc->funcs[funcid];
    ctx->bc = bc;
    ctx->numParams = func->numArgs;
    ctx->funcid = funcid;
    ctx->values = cli_malloc(sizeof(*ctx->values)*func->numArgs);
    if (!ctx->values) {
	cli_errmsg("bytecode: error allocating memory for parameters\n");
	return CL_EMEM;
    }
    ctx->operands = cli_malloc(sizeof(*ctx->operands)*func->numArgs);
    if (!ctx->operands) {
	cli_errmsg("bytecode: error allocating memory for parameters\n");
	return CL_EMEM;
    }
    for (i=0;i<func->numArgs;i++) {
	ctx->values[i].ref = MAX_OP;
	ctx->operands[i] = i;
    }
    return CL_SUCCESS;
}

static inline int type_isint(uint16_t type)
{
    return type > 0 && type <= 64;
}

int cli_bytecode_context_setparam_int(struct cli_bc_ctx *ctx, unsigned i, uint64_t c)
{
    if (i >= ctx->numParams) {
	cli_errmsg("bytecode: param index out of bounds: %u\n", i);
	return CL_EARG;
    }
    if (!type_isint(ctx->func->types[i])) {
	cli_errmsg("bytecode: parameter type mismatch\n");
	return CL_EARG;
    }
    ctx->func->values[i].v = c;
    ctx->func->values[i].ref = CONSTANT_OP;
    return CL_SUCCESS;
}

int cli_bytecode_context_setparam_ptr(struct cli_bc_ctx *ctx, unsigned i, void *data, unsigned datalen)
{
    cli_errmsg("Pointer parameters are not implemented yet!\n");
    return CL_EARG;
}

static inline uint64_t readNumber(const unsigned char *p, unsigned *off, unsigned len, char *ok)
{
    uint64_t n=0;
    unsigned i, newoff, lim, p0 = p[*off], shift=0;

    lim = p0 - 0x60;
    if (lim > 0x10) {
	cli_errmsg("Invalid number type: %c\n", p0);
	*ok = 0;
	return 0;
    }
    newoff = *off +lim+1;
    if (newoff > len) {
	cli_errmsg("End of line encountered while reading number\n");
	*ok = 0;
	return 0;
    }

    if (p0 == 0x60) {
	*off = newoff;
	return 0;
    }

    for (i=*off+1;i < newoff; i++) {
	uint64_t v = p[i];
	if (UNLIKELY((v&0xf0) != 0x60)) {
	    cli_errmsg("Invalid number part: %c\n", (char)v);
	    *ok = 0;
	    return 0;
	}
	v &= 0xf;
	v <<= shift;
	n |= v;
	shift += 4;
    }
    *off = newoff;
    return n;
}

static inline funcid_t readFuncID(struct cli_bc *bc, unsigned char *p,
				  unsigned *off, unsigned len, char *ok)
{
    funcid_t id = readNumber(p, off, len, ok);
    if (id >= bc->num_func) {
	cli_errmsg("Called function out of range: %u >= %u\n", id, bc->num_func);
	*ok = 0;
	return ~0;
    }
    return id;
}

static inline operand_t readOperand(struct cli_bc_func *func, unsigned char *p,
				    unsigned *off, unsigned len, char *ok)
{
    uint64_t v;
    unsigned numValues = func->numArgs + func->numInsts + func->numConstants;
    if ((p[*off]&0xf0) == 0x40) {
	p[*off] |= 0x20;
	/* TODO: unique constants */
	func->values = cli_realloc2(func->values, (numValues+1)*sizeof(*func->values));
	if (!func->values) {
	    *ok = 0;
	    return MAX_OP;
	}
	func->numConstants++;
	func->values[numValues].v = readNumber(p, off, len, ok);
	func->values[numValues].ref = CONSTANT_OP;
	return numValues;
    }
    v = readNumber(p, off, len, ok);
    if (!*ok)
	return MAX_OP;
    if (v >= numValues) {
	cli_errmsg("Operand index exceeds bounds: %u >= %u!\n", (unsigned)v, (unsigned)numValues);
	*ok = 0;
	return MAX_OP;
    }
    return v;
}

static inline unsigned readFixedNumber(const unsigned char *p, unsigned *off,
				       unsigned len, char *ok, unsigned width)
{
    unsigned i, n=0, shift=0;
    unsigned newoff = *off + width;
    if (newoff > len) {
	cli_errmsg("Newline encountered while reading number\n");
	*ok = 0;
	return 0;
    }
    for (i=*off;i<newoff;i++) {
	unsigned v = p[i];
	if (UNLIKELY((v&0xf0) != 0x60)) {
	    cli_errmsg("Invalid number part: %c\n", v);
	    *ok = 0;
	    return 0;
	}
	v &= 0xf;
	v <<= shift;
	n |= v;
	shift += 4;
    }
    *off = newoff;
    return n;
}

static inline unsigned char *readData(const unsigned char *p, unsigned *off, unsigned len, char *ok, unsigned *datalen)
{
    unsigned char *dat, *q;
    unsigned l, newoff, i;
    if (p[*off] != '|') {
	cli_errmsg("Data start marker missing: %c\n", p[*off]);
	*ok = 0;
	return NULL;
    }
    (*off)++;
    l = readNumber(p, off, len, ok);
    if (!l)
	return NULL;
    newoff = *off + l;
    if (newoff > len) {
	cli_errmsg("Line ended while reading data\n");
	*ok = 0;
	return 0;
    }
    dat = cli_malloc(l);
    if (!dat) {
	cli_errmsg("Cannot allocate memory for data\n");
	*ok = 0;
	return NULL;
    }
    q = dat;
    for (i=*off;i<newoff;i++) {
	const unsigned char v = p[i];
	if (UNLIKELY((v&0xf0) != 0x60)) {
	    cli_errmsg("Invalid data part: %c\n", v);
	    *ok = 0;
	    return 0;
	}
	*q++ = v;
    }
    *off = newoff;
    *datalen = l;
    return dat;
}

static inline char *readString(const unsigned char *p, unsigned *off, unsigned len, char *ok)
{
    unsigned stringlen;
    char *str = (char*)readData(p, off, len, ok, &stringlen);
    if (*ok && stringlen && str[stringlen-1] != '\0') {
	free(str);
	*ok = 0;
	return NULL;
    }
    return str;
}
static int parseHeader(struct cli_bc *bc, unsigned char *buffer)
{
    uint64_t magic1;
    unsigned magic2;
    char ok = 1;
    unsigned offset, len, flevel;
    if (strncmp(buffer, BC_HEADER, sizeof(BC_HEADER)-1)) {
	cli_errmsg("Missing file magic in bytecode");
	return CL_EMALFDB;
    }
    offset = sizeof(BC_HEADER)-1;
    len = strlen((const char*)buffer);
    flevel = readNumber(buffer, &offset, len, &ok);
    if (!ok) {
	cli_errmsg("Unable to parse functionality level in bytecode header\n");
	return CL_EMALFDB;
    }
    if (flevel > BC_FUNC_LEVEL) {
	cli_dbgmsg("Skipping bytecode with functionality level: %u\n", flevel);
	return CL_BREAK;
    }
    // Optimistic parsing, check for error only at the end.
    bc->verifier = readNumber(buffer, &offset, len, &ok);
    bc->sigmaker = readString(buffer, &offset, len, &ok);
    bc->id = readNumber(buffer, &offset, len, &ok);
    bc->metadata.maxStack = readNumber(buffer, &offset, len, &ok);
    bc->metadata.maxMem = readNumber(buffer, &offset, len, &ok);
    bc->metadata.maxTime = readNumber(buffer, &offset, len, &ok);
    bc->metadata.targetExclude = readString(buffer, &offset, len, &ok);
    bc->num_func = readNumber(buffer, &offset, len, &ok);
    if (!ok) {
	cli_errmsg("Invalid bytecode header at %u\n", offset);
	return CL_EMALFDB;
    }
    magic1 = readNumber(buffer, &offset, len, &ok);
    magic2 = readFixedNumber(buffer, &offset, len, &ok, 2);
    if (!ok || magic1 != 0x53e5493e9f3d1c30ull || magic2 != 42) {
      unsigned long m0 = magic1 >> 32;
      unsigned long m1 = magic1;
      cli_errmsg("Magic numbers don't match: %lx%lx, %u\n", m0, m1, magic2);
      return CL_EMALFDB;
    }
    if (offset != len) {
	cli_errmsg("Trailing garbage in bytecode header: %d extra bytes\n",
		   len-offset);
	return CL_EMALFDB;
    }

    bc->funcs = cli_calloc(bc->num_func, sizeof(*bc->funcs));
    if (!bc->funcs) {
	cli_errmsg("Out of memory allocating %u functions\n", bc->num_func);
	return CL_EMEM;
    }
    return CL_SUCCESS;
}

static int parseFunctionHeader(struct cli_bc *bc, unsigned fn, unsigned char *buffer)
{
    char ok=1;
    unsigned offset, len, all_locals=0, i;
    struct cli_bc_func *func;

    if (fn >= bc->num_func) {
	cli_errmsg("Found more functions than declared: %u >= %u\n", fn,
		   bc->num_func);
	return CL_EMALFDB;
    }
    func = &bc->funcs[fn];
    len = strlen((const char*)buffer);

    if (buffer[0] != 'A') {
	cli_errmsg("Invalid function arguments header: %c\n", buffer[0]);
	return CL_EMALFDB;
    }
    offset = 1;
    func->numArgs = readFixedNumber(buffer, &offset, len, &ok, 1);
    if (buffer[offset] != 'L') {
	cli_errmsg("Invalid function locals header: %c\n", buffer[offset]);
	return CL_EMALFDB;
    }
    offset++;
    func->numLocals = readNumber(buffer, &offset, len, &ok);
    if (!ok) {
	cli_errmsg("Invalid number of arguments/locals\n");
	return CL_EMALFDB;
    }
    all_locals = func->numArgs + func->numLocals;
    func->types = cli_calloc(all_locals, sizeof(*func->types));
    if (!func->types) {
	cli_errmsg("Out of memory allocating function arguments\n");
	return CL_EMEM;
    }
    for (i=0;i<all_locals;i++) {
	func->types[i] = readNumber(buffer, &offset, len, &ok);
    }
    if (!ok) {
	cli_errmsg("Invalid local types\n");
	return CL_EMALFDB;
    }
    if (buffer[offset] != 'F') {
	cli_errmsg("Invalid function body header: %c\n", buffer[offset]);
	return CL_EMALFDB;
    }
    offset++;
    func->numInsts = readNumber(buffer, &offset, len, &ok);
    if (!ok ){
	cli_errmsg("Invalid instructions count\n");
	return CL_EMALFDB;
    }
    func->insn_idx = 0;
    func->numConstants=0;
    func->allinsts = cli_calloc(func->numInsts, sizeof(*func->allinsts));
    if (!func->allinsts) {
	cli_errmsg("Out of memory allocating instructions\n");
	return CL_EMEM;
    }
    func->values = cli_calloc(func->numInsts+func->numArgs, sizeof(*func->values));
    if (!func->values) {
	cli_errmsg("Out of memory allocating values\n");
	return CL_EMEM;
    }
    for (i=0;i<func->numArgs;i++) {
	func->values[i].v = 0xdeadbeef;
	func->values[i].ref = ARG_OP;
    }
    for(;i<func->numInsts+func->numArgs;i++) {
	func->values[i].v = 0xdeadbeef;
	func->values[i].ref = i-func->numArgs;
    }
    func->numBB = readNumber(buffer, &offset, len, &ok);
    if (!ok) {
	cli_errmsg("Invalid basic block count\n");
	return CL_EMALFDB;
    }
    func->BB = cli_calloc(func->numBB, sizeof(*func->BB));
    if (!func->BB) {
	cli_errmsg("Out of memory allocating basic blocks\n");
	return CL_EMEM;
    }
    return CL_SUCCESS;
}

static bbid_t readBBID(struct cli_bc_func *func, const unsigned char *buffer, unsigned *off, unsigned len, char *ok) {
    unsigned id = readNumber(buffer, off, len, ok);
    if (!id || id >= func->numBB) {
	cli_errmsg("Basic block ID out of range: %u\n", id);
	*ok = 0;
    }
    if (!*ok)
	return ~0;
    return id;
}

static int parseBB(struct cli_bc *bc, unsigned func, unsigned bb, unsigned char *buffer)
{
    char ok=1;
    unsigned offset, len, last = 0;
    struct cli_bc_bb *BB;
    struct cli_bc_func *bcfunc = &bc->funcs[func];
    struct cli_bc_inst inst;

    if (bb >= bcfunc->numBB) {
	cli_errmsg("Found too many basic blocks\n");
	return CL_EMALFDB;
    }

    BB = &bcfunc->BB[bb];
    len = strlen((const char*) buffer);
    if (buffer[0] != 'B') {
	cli_errmsg("Invalid basic block header: %c\n", buffer[0]);
	return CL_EMALFDB;
    }
    offset = 1;
    BB->numInsts = 0;
    BB->insts = &bcfunc->allinsts[bcfunc->insn_idx];
    while (!last) {
	unsigned numOp, i;
	if (buffer[offset] == 'T') {
	    last = 1;
	    offset++;
	    /* terminators are void */
	    inst.type = 0;
	} else {
	    inst.type = readNumber(buffer, &offset, len, &ok);
	}
	inst.opcode = readFixedNumber(buffer, &offset, len, &ok, 2);
	if (!ok) {
	    cli_errmsg("Invalid type or operand\n");
	    return CL_EMALFDB;
	}
	if (inst.opcode >= OP_INVALID) {
	    cli_errmsg("Invalid opcode: %u\n", inst.opcode);
	    return CL_EMALFDB;
	}
	switch (inst.opcode) {
	    case OP_JMP:
		inst.u.jump = readBBID(bcfunc, buffer, &offset, len, &ok);
		break;
	    case OP_BRANCH:
		inst.u.branch.condition = readOperand(bcfunc, buffer, &offset, len, &ok);
		inst.u.branch.br_true = readBBID(bcfunc, buffer, &offset, len, &ok);
		inst.u.branch.br_false = readBBID(bcfunc, buffer, &offset, len, &ok);
		break;
	    case OP_CALL_DIRECT:
		numOp = readFixedNumber(buffer, &offset, len, &ok, 1);
		if (ok) {
		    inst.u.ops.numOps = numOp;
		    inst.u.ops.ops = cli_calloc(numOp, sizeof(*inst.u.ops.ops));
		    if (!inst.u.ops.ops) {
			cli_errmsg("Out of memory allocating operands\n");
			return CL_EMALFDB;
		    }
		    inst.u.ops.funcid = readFuncID(bc, buffer, &offset, len, &ok);
		    for (i=0;i<numOp;i++) {
			inst.u.ops.ops[i] = readOperand(bcfunc, buffer, &offset, len, &ok);
		    }
		}
		break;
	    default:
		numOp = operand_counts[inst.opcode];
		switch (numOp) {
		    case 1:
			inst.u.unaryop = readOperand(bcfunc, buffer, &offset, len, &ok);
			break;
		    case 2:
			inst.u.binop[0] = readOperand(bcfunc, buffer, &offset, len, &ok);
			inst.u.binop[1] = readOperand(bcfunc, buffer, &offset, len, &ok);
			break;
		    case 3:
			inst.u.three[0] = readOperand(bcfunc, buffer, &offset, len, &ok);
			inst.u.three[1] = readOperand(bcfunc, buffer, &offset, len, &ok);
			inst.u.three[2] = readOperand(bcfunc, buffer, &offset, len, &ok);
			break;
		    default:
			cli_errmsg("Opcode with too many operands: %u?\n", numOp);
			ok = 0;
			break;
		}
	}
	if (!ok) {
	    cli_errmsg("Invalid instructions or operands\n");
	    return CL_EMALFDB;
	}
	if (bcfunc->insn_idx + BB->numInsts >= bcfunc->numInsts) {
	    cli_errmsg("More instructions than declared in total!\n");
	    return CL_EMALFDB;
	}
	BB->insts[BB->numInsts++] = inst;
    }
    if (bb+1 == bc->funcs[func].numBB) {
	if (buffer[offset] != 'E') {
	    cli_errmsg("Missing basicblock terminator, got: %c\n", buffer[offset]);
	    return CL_EMALFDB;
	}
	offset++;
    }
    cli_dbgmsg("Parsed %d instructions\n", BB->numInsts);
    if (offset != len) {
	cli_errmsg("Trailing garbage in basicblock: %d extra bytes\n",
		   len-offset);
	return CL_EMALFDB;
    }
    return CL_SUCCESS;
}

enum parse_state {
    PARSE_BC_HEADER=0,
    PARSE_FUNC_HEADER,
    PARSE_BB
};

int cli_bytecode_load(struct cli_bc *bc, FILE *f, struct cli_dbio *dbio)
{
    unsigned row = 0, current_func = 0, bb=0;
    char buffer[FILEBUFF];
    enum parse_state state = PARSE_BC_HEADER;

    if (!f && !dbio) {
	cli_errmsg("Unable to load bytecode (null file)\n");
	return CL_ENULLARG;
    }

    while (cli_dbgets(buffer, FILEBUFF, f, dbio)) {
	int rc;
	cli_chomp(buffer);
	row++;
	switch (state) {
	    case PARSE_BC_HEADER:
		rc = parseHeader(bc, (unsigned char*)buffer);
		if (rc == CL_BREAK) /* skip */
		    return CL_SUCCESS;
		if (rc != CL_SUCCESS) {
		    cli_errmsg("Error at bytecode line %u\n", row);
		    return rc;
		}
		state = PARSE_FUNC_HEADER;
		break;
	    case PARSE_FUNC_HEADER:
		rc = parseFunctionHeader(bc, current_func, (unsigned char*)buffer);
		if (rc != CL_SUCCESS) {
		    cli_errmsg("Error at bytecode line %u\n", row);
		    return rc;
		}
		bb = 0;
		state = PARSE_BB;
		break;
	    case PARSE_BB:
		rc = parseBB(bc, current_func, bb++, (unsigned char*)buffer);
		if (rc != CL_SUCCESS) {
		    cli_errmsg("Error at bytecode line %u\n", row);
		    return rc;
		}
		if (bb >= bc->funcs[current_func].numBB) {
		    state = PARSE_FUNC_HEADER;
		    current_func++;
		}
		break;
	}
    }
    cli_dbgmsg("Parsed %d functions\n", current_func);
    return CL_SUCCESS;
}

int cli_bytecode_run(struct cli_bc *bc, struct cli_bc_ctx *ctx)
{
    struct cli_bc_inst inst;
    struct cli_bc_func func;
    unsigned i;
    if (!ctx || !ctx->bc || !ctx->func || !ctx->values)
	return CL_ENULLARG;
    for (i=0;i<ctx->numParams;i++) {
	if (ctx->values[i].ref == MAX_OP) {
	    cli_errmsg("bytecode: parameter %u is uninitialized!\n", i);
	    return CL_EARG;
	}
    }
    memset(&func, 0, sizeof(func));
    func.values = ctx->values;

    inst.opcode = OP_CALL_DIRECT;
    inst.type = 0;/* TODO: support toplevel functions with return values */
    inst.u.ops.numOps = ctx->numParams;
    inst.u.ops.funcid = ctx->funcid;
    inst.u.ops.ops = ctx->operands;
    return cli_vm_execute_inst(ctx->bc, ctx, &func, &inst);
}

void cli_bytecode_destroy(struct cli_bc *bc)
{
    unsigned i, j, k;
    free(bc->sigmaker);
    free(bc->metadata.targetExclude);

    for (i=0;i<bc->num_func;i++) {
	struct cli_bc_func *f = &bc->funcs[i];
	free(f->types);

	for (j=0;j<f->numBB;j++) {
	    struct cli_bc_bb *BB = &f->BB[j];
	    for(k=0;k<BB->numInsts;k++) {
		struct cli_bc_inst *ii = &BB->insts[k];
		if (operand_counts[ii->opcode] > 3)
		    free(ii->u.ops.ops);
	    }
	}
	free(f->BB);
	free(f->allinsts);
	free(f->values);
    }
    free(bc->funcs);
}


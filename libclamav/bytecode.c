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
    ctx->opsizes = NULL;
    return ctx;
}

void cli_bytecode_context_destroy(struct cli_bc_ctx *ctx)
{
   cli_bytecode_context_clear(ctx);
   free(ctx);
}

int cli_bytecode_context_clear(struct cli_bc_ctx *ctx)
{
    free(ctx->opsizes);
    free(ctx->values);
    free(ctx->operands);
    memset(ctx, 0, sizeof(ctx));
    return CL_SUCCESS;
}

static unsigned typesize(const struct cli_bc *bc, uint16_t type)
{
    if (!type)
	return 0;
    if (type <= 8)
	return 1;
    if (type <= 16)
	return 2;
    if (type <= 32)
	return 4;
    if (type <= 64)
	return 8;
    return 0;
}

static unsigned typealign(const struct cli_bc *bc, uint16_t type)
{
    unsigned size = typesize(bc, type);
    return size ? size : 1;
}

int cli_bytecode_context_setfuncid(struct cli_bc_ctx *ctx, const struct cli_bc *bc, unsigned funcid)
{
    unsigned i, s=0;
    const struct cli_bc_func *func;
    if (funcid >= bc->num_func) {
	cli_errmsg("bytecode: function ID doesn't exist: %u\n", funcid);
	return CL_EARG;
    }
    func = ctx->func = &bc->funcs[funcid];
    ctx->bc = bc;
    ctx->numParams = func->numArgs;
    ctx->funcid = funcid;
    if (func->numArgs) {
	ctx->operands = cli_malloc(sizeof(*ctx->operands)*func->numArgs);
	if (!ctx->operands) {
	    cli_errmsg("bytecode: error allocating memory for parameters\n");
	    return CL_EMEM;
	}
	ctx->opsizes = cli_malloc(sizeof(*ctx->opsizes)*func->numArgs);
	for (i=0;i<func->numArgs;i++) {
	    unsigned al = typealign(bc, func->types[i]);
	    s = (s+al-1)&~(al-1);
	    ctx->operands[i] = s;
	    s += ctx->opsizes[i] = typesize(bc, func->types[i]);
	}
    }
    s += 8;/* return value */
    ctx->bytes = s;
    ctx->values = cli_malloc(s);
    if (!ctx->values) {
	cli_errmsg("bytecode: error allocating memory for parameters\n");
	return CL_EMEM;
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
    switch (ctx->opsizes[i]) {
	case 1:
	    ctx->values[ctx->operands[i]] = c;
	    break;
	case 2:
	    *(uint16_t*)&ctx->values[ctx->operands[i]] = c;
	    break;
	case 4:
	    *(uint32_t*)&ctx->values[ctx->operands[i]] = c;
	    break;
	case 8:
	    *(uint64_t*)&ctx->values[ctx->operands[i]] = c;
	    break;
    }
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
    funcid_t id = readNumber(p, off, len, ok)-1;
    if (*ok && id >= bc->num_func) {
	cli_errmsg("Called function out of range: %u >= %u\n", id, bc->num_func);
	*ok = 0;
	return ~0;
    }
    return id;
}

static inline funcid_t readAPIFuncID(struct cli_bc *bc, unsigned char *p,
				     unsigned *off, unsigned len, char *ok)
{
    funcid_t id = readNumber(p, off, len, ok)-1;
    if (*ok && !cli_bitset_test(bc->uses_apis, id)) {
	cli_errmsg("Called undeclared API function: %u\n", id);
	*ok = 0;
	return ~0;
    }
    return id;
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

static inline operand_t readOperand(struct cli_bc_func *func, unsigned char *p,
				    unsigned *off, unsigned len, char *ok)
{
    uint64_t v;
    if ((p[*off]&0xf0) == 0x40 || p[*off] == 0x50) {
	uint64_t *dest;
	uint16_t ty;
	p[*off] |= 0x20;
	/* TODO: unique constants */
	func->constants = cli_realloc2(func->constants, (func->numConstants+1)*sizeof(*func->constants));
	if (!func->constants) {
	    *ok = 0;
	    return MAX_OP;
	}
	v = readNumber(p, off, len, ok);
	dest = &func->constants[func->numConstants];
	/* Write the constant to the correct place according to its type.
	 * This is needed on big-endian machines, because constants are always
	 * read as u64, but accesed as one of these types: u8, u16, u32, u64 */
	*dest= 0;
	ty = 8*readFixedNumber(p, off, len, ok, 1);
	if (!ty) {
	    cli_errmsg("bytecode: void type constant is invalid!\n");
	    *ok = 0;
	    return MAX_OP;
	}
	if (ty <= 8)
	    *(uint8_t*)dest = v;
	else if (ty <= 16)
	    *(uint16_t*)dest = v;
	else if (ty <= 32)
	    *(uint32_t*)dest = v;
	else
	    *dest = v;
	return func->numValues + func->numConstants++;
    }
    v = readNumber(p, off, len, ok);
    if (!*ok)
	return MAX_OP;
    if (v >= func->numValues) {
	cli_errmsg("Operand index exceeds bounds: %u >= %u!\n", (unsigned)v, (unsigned)func->numValues);
	*ok = 0;
	return MAX_OP;
    }
    return v;
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
    if (!l) {
	*datalen = l;
	return NULL;
    }
    newoff = *off + 2*l;
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
    for (i=*off;i<newoff;i += 2) {
	const unsigned char v0 = p[i];
	const unsigned char v1 = p[i+1];
	if (UNLIKELY((v0&0xf0) != 0x60 || (v1&0xf0) != 0x60)) {
	    cli_errmsg("Invalid data part: %c%c\n", v0, v1);
	    *ok = 0;
	    return 0;
	}
	*q++ = (v0&0xf) | ((v1&0xf) << 4);
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
	str[stringlen-1] = '\0';
	cli_errmsg("bytecode: string missing \\0 terminator: %s\n", str);
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
    if (strncmp((const char*)buffer, BC_HEADER, sizeof(BC_HEADER)-1)) {
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
    bc->num_types = readNumber(buffer, &offset, len, &ok);
    bc->num_func = readNumber(buffer, &offset, len, &ok);
    bc->state = bc_loaded;
    bc->uses_apis = NULL;
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
    bc->types = cli_calloc(bc->num_types, sizeof(*bc->types));
    if (!bc->types) {
	cli_errmsg("Out of memory allocating %u types\n", bc->num_types);
	return CL_EMEM;
    }
    return CL_SUCCESS;
}

static uint16_t readTypeID(struct cli_bc *bc, unsigned char *buffer,
			   unsigned *offset, unsigned len, char *ok)
{
    uint64_t t = readNumber(buffer, offset, len, ok);
    if (!ok)
	return ~0;
    if (t >= bc->num_types + bc->start_tid) {
	cli_errmsg("Invalid type id: %llu\n", (unsigned long long)t);
	*ok = 0;
	return ~0;
    }
    return t;
}

static void parseType(struct cli_bc *bc, struct cli_bc_type *ty,
		      unsigned char *buffer, unsigned *off, unsigned len,
		      char *ok)
{
    unsigned j;

    ty->numElements = readFixedNumber(buffer, off, len, ok, 1);
    if (!ok) {
	cli_errmsg("Error parsing type\n");
	*ok = 0;
	return;
    }
    ty->containedTypes = cli_malloc(sizeof(*ty->containedTypes)*ty->numElements);
    if (!ty->containedTypes) {
	cli_errmsg("Out of memory allocating %u types\n", ty->numElements);
	*ok = 0;
	return;
    }
    for (j=0;j<ty->numElements;j++) {
	ty->containedTypes[j] = readTypeID(bc, buffer, off, len, ok);
    }
}

static uint16_t containedTy[] = {8,16,32,64};

#define NUM_STATIC_TYPES 4
static void add_static_types(struct cli_bc *bc)
{
    unsigned i;
    for (i=0;i<NUM_STATIC_TYPES;i++) {
	bc->types[i].kind = PointerType;
	bc->types[i].numElements = 1;
	bc->types[i].containedTypes = &containedTy[i];
    }
}

static int parseTypes(struct cli_bc *bc, unsigned char *buffer)
{
    unsigned i, offset = 1, len = strlen((const char*)buffer);
    char ok=1;

    if (buffer[0] != 'T') {
	cli_errmsg("Invalid function types header: %c\n", buffer[0]);
	return CL_EMALFDB;
    }
    bc->start_tid = readFixedNumber(buffer, &offset, len, &ok, 2);
    if (bc->start_tid != BC_START_TID) {
	cli_warnmsg("Type start id mismatch: %u != %u\n", bc->start_tid,
		    BC_START_TID);
	return CL_BREAK;
    }
    add_static_types(bc);
    for (i=(BC_START_TID - 64);i<bc->num_types;i++) {
	struct cli_bc_type *ty = &bc->types[i];
	uint8_t t = readFixedNumber(buffer, &offset, len, &ok, 1);
	if (!ok) {
	    cli_errmsg("Error reading type kind\n");
	    return CL_EMALFDB;
	}
	switch (t) {
	    case 1:
		ty->kind = FunctionType;
		parseType(bc, ty, buffer, &offset, len, &ok);
		if (!ok) {
		    cli_errmsg("Error parsing type %u\n", i);
		    return CL_EMALFDB;
		}
		break;
	    case 2:
	    case 3:
		ty->kind = (t == 2) ? StructType : PackedStructType;
		parseType(bc, ty, buffer, &offset, len, &ok);
		if (!ok) {
		    cli_errmsg("Error parsing type %u\n", i);
		    return CL_EMALFDB;
		}
		break;
	    case 4:
		ty->kind = ArrayType;
		/* number of elements of array, not subtypes! */
		ty->numElements = readNumber(buffer, &offset, len, &ok);
		if (!ok) {
		    cli_errmsg("Error parsing type %u\n", i);
		    return CL_EMALFDB;
		}
		/* fall-through */
	    case 5:
		if (t == 5) {
		    ty->kind = PointerType;
		    ty->numElements = 1;
		}
		ty->containedTypes = cli_malloc(sizeof(*ty->containedTypes));
		if (!ty->containedTypes) {
		    cli_errmsg("Out of memory allocating containedType\n");
		    return CL_EMALFDB;
		}
		ty->containedTypes[0] = readTypeID(bc, buffer, &offset, len, &ok);
		if (!ok) {
		    cli_errmsg("Error parsing type %u\n", i);
		    return CL_EMALFDB;
		}
		break;
	    default:
		cli_errmsg("Invalid type kind: %u\n", t);
		return CL_EMALFDB;
	}
    }
    return CL_SUCCESS;
}

/* checks whether the type described by tid is the same as the one described by
 * expectty. */
static int types_equal(const struct cli_bc *bc, uint16_t *apity2ty, uint16_t tid, uint16_t apitid)
{
    unsigned i;
    const struct cli_bc_type *ty = &bc->types[tid - 63];
    const struct cli_bc_type *apity = &cli_apicall_types[apitid];
    /* If we've already verified type equality, return.
     * Since we need to check equality of recursive types, we assume types are
     * equal while checking equality of contained types, unless proven
     * otherwise. */
     if (apity2ty[apitid] == tid + 1)
	return 1;
     apity2ty[apitid] = tid+1;

     if (ty->kind != apity->kind) {
	 cli_dbgmsg("bytecode: type kind mismatch: %u != %u\n", ty->kind, apity->kind);
	 return 0;
     }
     if (ty->numElements != apity->numElements) {
	 cli_dbgmsg("bytecode: type numElements mismatch: %u != %u\n", ty->numElements, apity->numElements);
	 return 0;
     }
    for (i=0;i<ty->numElements;i++) {
	if (apity->containedTypes[i] < BC_START_TID) {
	    if (ty->containedTypes[i] != apity->containedTypes[i])
		return 0;
	} else if (!types_equal(bc, apity2ty, ty->containedTypes[i], apity->containedTypes[i] - BC_START_TID))
	    return 0;
    }
    return 1;
}

static int parseApis(struct cli_bc *bc, unsigned char *buffer)
{
    unsigned i, offset = 1, len = strlen((const char*)buffer), maxapi, calls;
    char ok =1;
    uint16_t *apity2ty;/*map of api type to current bytecode type ID */

    if (buffer[0] != 'E') {
	cli_errmsg("bytecode: Invalid api header: %c\n", buffer[0]);
	return CL_EMALFDB;
    }

    maxapi = readNumber(buffer, &offset, len, &ok);
    if (!ok)
	return CL_EMALFDB;
    if (maxapi > cli_apicall_maxapi) {
	cli_dbgmsg("bytecode using API %u, but highest API known to libclamav is %u, skipping\n", maxapi, cli_apicall_maxapi);
	return CL_BREAK;
    }
    calls = readNumber(buffer, &offset, len, &ok);
    if (!ok)
	return CL_EMALFDB;
    if (calls > maxapi) {
	cli_errmsg("bytecode: attempting to describe more APIs than max: %u > %u\n", calls, maxapi);
	return CL_EMALFDB;
    }
    bc->uses_apis = cli_bitset_init();
    if (!bc->uses_apis) {
	cli_errmsg("Out of memory allocating apis bitset\n");
	return CL_EMEM;
    }
    apity2ty = cli_calloc(cli_apicall_maxtypes, sizeof(*cli_apicall_types));
    if (!apity2ty) {
	cli_errmsg("Out of memory allocating apity2ty\n");
	return CL_EMEM;
    }
    for (i=0;i < calls; i++) {
	unsigned id = readNumber(buffer, &offset, len, &ok);
	uint16_t tid = readTypeID(bc, buffer, &offset, len, &ok);
	char *name = readString(buffer, &offset, len, &ok);

	/* validate APIcall prototype */
	if (id > maxapi) {
	    cli_errmsg("bytecode: API id %u out of range, max %u\n", id, maxapi);
	    ok = 0;
	}
	/* API ids start from 1 */
	id--;
	if (ok && name && strcmp(cli_apicalls[id].name, name)) {
	    cli_errmsg("bytecode: API %u name mismatch: %s expected %s\n", id, name, cli_apicalls[id].name);
	    ok = 0;
	}
	if (ok && !types_equal(bc, apity2ty, tid, cli_apicalls[id].type)) {
	    cli_errmsg("bytecode: API %u prototype doesn't match\n", id);
	    ok = 0;
	}
	/* don't need the name anymore */
	free(name);
	if (!ok)
	    return CL_EMALFDB;

	/* APIcall is valid */
	cli_bitset_set(bc->uses_apis, id);
    }
    free(apity2ty); /* free temporary map */
    cli_dbgmsg("bytecode: Parsed %u APIcalls, maxapi %u\n", calls, maxapi);
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
    func->numValues = func->numArgs + func->numLocals;
    func->insn_idx = 0;
    func->numConstants=0;
    func->allinsts = cli_calloc(func->numInsts, sizeof(*func->allinsts));
    if (!func->allinsts) {
	cli_errmsg("Out of memory allocating instructions\n");
	return CL_EMEM;
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

/*
static uint16_t get_type(struct cli_bc_func *func, operand_t op)
{
    if (op >= func->numValues)
	return 64;
    return func->types[op];
}*/

static int parseBB(struct cli_bc *bc, unsigned func, unsigned bb, unsigned char *buffer)
{
    char ok=1;
    unsigned offset, len, i, last = 0;
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
	unsigned numOp;
	if (buffer[offset] == 'T') {
	    last = 1;
	    offset++;
	    /* terminators are void */
	    inst.type = 0;
	    inst.dest = 0;
	} else {
	    inst.type = readNumber(buffer, &offset, len, &ok);
	    inst.dest = readNumber(buffer, &offset, len, &ok);
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
	    case OP_RET:
		inst.type = readNumber(buffer, &offset, len, &ok);
		inst.u.unaryop = readOperand(bcfunc, buffer, &offset, len, &ok);
		break;
	    case OP_BRANCH:
		inst.u.branch.condition = readOperand(bcfunc, buffer, &offset, len, &ok);
		inst.u.branch.br_true = readBBID(bcfunc, buffer, &offset, len, &ok);
		inst.u.branch.br_false = readBBID(bcfunc, buffer, &offset, len, &ok);
		break;
	    case OP_CALL_API:/* fall-through */
	    case OP_CALL_DIRECT:
		numOp = readFixedNumber(buffer, &offset, len, &ok, 1);
		if (ok) {
		    inst.u.ops.numOps = numOp;
		    inst.u.ops.opsizes=NULL;
		    inst.u.ops.ops = cli_calloc(numOp, sizeof(*inst.u.ops.ops));
		    if (!inst.u.ops.ops) {
			cli_errmsg("Out of memory allocating operands\n");
			return CL_EMALFDB;
		    }
		    if (inst.opcode == OP_CALL_DIRECT)
			inst.u.ops.funcid = readFuncID(bc, buffer, &offset, len, &ok);
		    else
			inst.u.ops.funcid = readAPIFuncID(bc, buffer, &offset, len, &ok);
		    for (i=0;i<numOp;i++) {
			inst.u.ops.ops[i] = readOperand(bcfunc, buffer, &offset, len, &ok);
		    }
		}
		break;
	    case OP_ZEXT:
	    case OP_SEXT:
	    case OP_TRUNC:
		inst.u.cast.source = readOperand(bcfunc, buffer, &offset, len, &ok);
		inst.u.cast.mask = bcfunc->types[inst.u.cast.source];
		if (inst.u.cast.mask == 1)
		    inst.u.cast.size = 0;
		else if (inst.u.cast.mask <= 8)
		    inst.u.cast.size = 1;
		else if (inst.u.cast.mask <= 16)
		    inst.u.cast.size = 2;
		else if (inst.u.cast.mask <= 32)
		    inst.u.cast.size = 3;
		else if (inst.u.cast.mask <= 64)
		    inst.u.cast.size = 4;
		/* calculate mask */
		if (inst.opcode != OP_SEXT)
		    inst.u.cast.mask = inst.u.cast.mask != 64 ?
			(1ull<<inst.u.cast.mask)-1 :
			~0ull;
		break;
	    case OP_ICMP_EQ:
	    case OP_ICMP_NE:
	    case OP_ICMP_UGT:
	    case OP_ICMP_UGE:
	    case OP_ICMP_ULT:
	    case OP_ICMP_ULE:
	    case OP_ICMP_SGT:
	    case OP_ICMP_SGE:
	    case OP_ICMP_SLE:
	    case OP_ICMP_SLT:
		/* instruction type must be correct before readOperand! */
		inst.type = readNumber(buffer, &offset, len, &ok);
		/* fall-through */
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
	    cli_errmsg("More instructions than declared in total: %u > %u!\n",
		       bcfunc->insn_idx+BB->numInsts, bcfunc->numInsts);
	    return CL_EMALFDB;
	}
	inst.interp_op = inst.opcode*5;
	if (inst.type > 1) {
	    if (inst.type <= 8)
		inst.interp_op += 1;
	    else if (inst.type <= 16)
		inst.interp_op += 2;
	    else if (inst.type <= 32)
		inst.interp_op += 3;
	    else if (inst.type <= 64)
		inst.interp_op += 4;
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
    if (offset != len) {
	cli_errmsg("Trailing garbage in basicblock: %d extra bytes\n",
		   len-offset);
	return CL_EMALFDB;
    }
    bcfunc->numBytes = 0;
    bcfunc->insn_idx += BB->numInsts;
    return CL_SUCCESS;
}

enum parse_state {
    PARSE_BC_HEADER=0,
    PARSE_BC_TYPES,
    PARSE_BC_APIS,
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
		state = PARSE_BC_TYPES;
		break;
	    case PARSE_BC_TYPES:
		rc = parseTypes(bc, (unsigned char*)buffer);
		if (rc != CL_SUCCESS) {
		    cli_errmsg("Error at bytecode line %u\n", row);
		    return rc;
		}
		state = PARSE_BC_APIS;
		break;
	    case PARSE_BC_APIS:
		rc = parseApis(bc, (unsigned char*)buffer);
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
		    if (bc->funcs[current_func].insn_idx != bc->funcs[current_func].numInsts) {
			cli_errmsg("Parsed different number of instructions than declared: %u != %u\n",
				   bc->funcs[current_func].insn_idx, bc->funcs[current_func].numInsts);
			return CL_EMALFDB;
		    }
		    cli_dbgmsg("Parsed %u BBs, %u instructions\n",
			       bb, bc->funcs[current_func].numInsts);
		    state = PARSE_FUNC_HEADER;
		    current_func++;
		}
		break;
	}
    }
    cli_dbgmsg("Parsed %d functions\n", current_func);
    if (current_func != bc->num_func) {
	cli_errmsg("Loaded less functions than declared: %u vs. %u\n",
		   current_func, bc->num_func);
	return CL_EMALFDB;
    }
    return CL_SUCCESS;
}

int cli_bytecode_run(const struct cli_bc *bc, struct cli_bc_ctx *ctx)
{
    struct cli_bc_inst inst;
    struct cli_bc_func func;
    if (!ctx || !ctx->bc || !ctx->func)
	return CL_ENULLARG;
    if (ctx->numParams && (!ctx->values || !ctx->operands))
	return CL_ENULLARG;
    if (bc->state == bc_loaded) {
	cli_errmsg("bytecode has to be prepared either for interpreter or JIT!\n");
	return CL_EARG;
    }
    memset(&func, 0, sizeof(func));
    func.numInsts = 1;
    func.numValues = 1;
    func.numBytes = ctx->bytes;
    memset(ctx->values+ctx->bytes-8, 0, 8);

    inst.opcode = OP_CALL_DIRECT;
    inst.interp_op = OP_CALL_DIRECT*5;
    inst.dest = func.numArgs;
    inst.type = 0;
    inst.u.ops.numOps = ctx->numParams;
    inst.u.ops.funcid = ctx->funcid;
    inst.u.ops.ops = ctx->operands;
    inst.u.ops.opsizes = ctx->opsizes;
    return cli_vm_execute(ctx->bc, ctx, &func, &inst);
}

uint64_t cli_bytecode_context_getresult_int(struct cli_bc_ctx *ctx)
{
    return *(uint32_t*)ctx->values;/*XXX*/
//    return ctx->values[ctx->numParams];
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
		if (operand_counts[ii->opcode] > 3 ||
		    ii->opcode == OP_CALL_DIRECT || ii->opcode == OP_CALL_API) {
		    free(ii->u.ops.ops);
		    free(ii->u.ops.opsizes);
		}
	    }
	}
	free(f->BB);
	free(f->allinsts);
	free(f->constants);
    }
    free(bc->funcs);
    for (i=NUM_STATIC_TYPES;i<bc->num_types;i++) {
	if (bc->types[i].containedTypes)
	    free(bc->types[i].containedTypes);
    }
    free(bc->types);
    if (bc->uses_apis)
	cli_bitset_free(bc->uses_apis);
}

#define MAP(val) do { operand_t o = val; \
    if (o > totValues) {\
	cli_errmsg("bytecode: operand out of range: %u > %u, for instruction %u in function %u\n", o, totValues, j, i);\
	return CL_EBYTECODE;\
    }\
    val = map[o]; } while (0)

static int cli_bytecode_prepare_interpreter(struct cli_bc *bc)
{
    unsigned i, j, k;
    for (i=0;i<bc->num_func;i++) {
	struct cli_bc_func *bcfunc = &bc->funcs[i];
	unsigned totValues = bcfunc->numValues + bcfunc->numConstants;
	unsigned *map = cli_malloc(sizeof(*map)*totValues);
	for (j=0;j<bcfunc->numValues;j++) {
	    uint16_t ty = bcfunc->types[j];
	    unsigned align;
	    if (ty > 64) {
		cli_errmsg("Bytecode: non-integer types not yet implemented\n");
		return CL_EMALFDB;
	    }
	    align = typealign(bc, ty);
	    bcfunc->numBytes  = (bcfunc->numBytes + align-1)&(~(align-1));
	    map[j] = bcfunc->numBytes;
	    bcfunc->numBytes += typesize(bc, ty);
	}
	bcfunc->numBytes = (bcfunc->numBytes + 7)&~7;
	for (j=0;j<bcfunc->numConstants;j++) {
	    map[bcfunc->numValues+j] = bcfunc->numBytes;
	    bcfunc->numBytes += 8;
	}
	for (j=0;j<bcfunc->numInsts;j++) {
	    struct cli_bc_inst *inst = &bcfunc->allinsts[j];
	    inst->dest = map[inst->dest];
	    switch (inst->opcode) {
		case OP_ADD:
		case OP_SUB:
		case OP_MUL:
		case OP_UDIV:
		case OP_SDIV:
		case OP_UREM:
		case OP_SREM:
		case OP_SHL:
		case OP_LSHR:
		case OP_ASHR:
		case OP_AND:
		case OP_OR:
		case OP_XOR:
		case OP_ICMP_EQ:
		case OP_ICMP_NE:
		case OP_ICMP_UGT:
		case OP_ICMP_UGE:
		case OP_ICMP_ULT:
		case OP_ICMP_ULE:
		case OP_ICMP_SGT:
		case OP_ICMP_SGE:
		case OP_ICMP_SLT:
		case OP_ICMP_SLE:
		case OP_COPY:
		    MAP(inst->u.binop[0]);
		    MAP(inst->u.binop[1]);
		    break;
		case OP_SEXT:
		case OP_ZEXT:
		case OP_TRUNC:
		    MAP(inst->u.cast.source);
		    break;
		case OP_BRANCH:
		    MAP(inst->u.branch.condition);
		    break;
		case OP_JMP:
		    break;
		case OP_RET:
		    MAP(inst->u.unaryop);
		    break;
		case OP_SELECT:
		    MAP(inst->u.three[0]);
		    MAP(inst->u.three[1]);
		    MAP(inst->u.three[2]);
		    break;
		case OP_CALL_API:/* fall-through */
		case OP_CALL_DIRECT:
		{
		    struct cli_bc_func *target = NULL;
		    if (inst->opcode == OP_CALL_DIRECT) {
			target = &bc->funcs[inst->u.ops.funcid];
			if (inst->u.ops.funcid > bc->num_func) {
			    cli_errmsg("bytecode: called function out of range: %u > %u\n", inst->u.ops.funcid, bc->num_func);
			    return CL_EBYTECODE;
			}
			if (inst->u.ops.numOps != target->numArgs) {
			    cli_errmsg("bytecode: call operands don't match function prototype\n");
			    return CL_EBYTECODE;
			}
		    } else {
			/* APIs have 2 parameters always */
			if (inst->u.ops.numOps != 2) {
			    cli_errmsg("bytecode: call operands don't match function prototype\n");
			    return CL_EBYTECODE;
			}
		    }
		    if (inst->u.ops.numOps) {
			inst->u.ops.opsizes = cli_malloc(sizeof(*inst->u.ops.opsizes)*inst->u.ops.numOps);
			if (!inst->u.ops.opsizes) {
			    cli_errmsg("Out of memory when allocating operand sizes\n");
			    return CL_EMEM;
			}
		    } else
			inst->u.ops.opsizes = NULL;
		    for (k=0;k<inst->u.ops.numOps;k++) {
			MAP(inst->u.ops.ops[k]);
			if (inst->opcode == OP_CALL_DIRECT)
			    inst->u.ops.opsizes[k] = typesize(bc, target->types[k]);
			else
			    inst->u.ops.opsizes[k] = 32; /*XXX*/
		    }
		    break;
		}
		default:
		    cli_dbgmsg("Unhandled opcode: %d\n", inst->opcode);
		    return CL_EBYTECODE;
	    }
	}
	free(map);
    }
    bc->state = bc_interp;
    return CL_SUCCESS;
}

static int cli_bytecode_prepare_jit(struct cli_bc *bc)
{
    if (bc->state != bc_loaded) {
	cli_warnmsg("Cannot prepare for JIT, because it has already been converted to interpreter");
	return CL_EBYTECODE;
    }
    cli_warnmsg("JIT not yet implemented\n");
    return CL_EBYTECODE;
}

int cli_bytecode_prepare(struct cli_bc *bc)
{
    if (bc->state == bc_interp || bc->state == bc_jit)
	return CL_SUCCESS;
    if (cli_bytecode_prepare_jit(bc) == CL_SUCCESS)
	return CL_SUCCESS;
    return cli_bytecode_prepare_interpreter(bc);
}

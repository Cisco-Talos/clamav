/*
 *  Load, and verify ClamAV bytecode.
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

#include <assert.h>
#include <fcntl.h>
#include "dconf.h"
#include "clamav.h"
#include "others.h"
#include "pe.h"
#include "bytecode.h"
#include "bytecode_priv.h"
#include "readdb.h"
#include "scanners.h"
#include "bytecode_api.h"
#include "bytecode_api_impl.h"
#include <string.h>

/* dummy values */
static const uint32_t nomatch[64] = {
    0xdeadbeef, 0xdeaddead, 0xbeefdead, 0xdeaddead, 0xdeadbeef, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0
};
static const uint32_t nooffsets[64] = {
    CLI_OFF_NONE, CLI_OFF_NONE, CLI_OFF_NONE, CLI_OFF_NONE,
    CLI_OFF_NONE, CLI_OFF_NONE, CLI_OFF_NONE, CLI_OFF_NONE,
    CLI_OFF_NONE, CLI_OFF_NONE, CLI_OFF_NONE, CLI_OFF_NONE,
    CLI_OFF_NONE, CLI_OFF_NONE, CLI_OFF_NONE, CLI_OFF_NONE,
    CLI_OFF_NONE, CLI_OFF_NONE, CLI_OFF_NONE, CLI_OFF_NONE,
    CLI_OFF_NONE, CLI_OFF_NONE, CLI_OFF_NONE, CLI_OFF_NONE,
    CLI_OFF_NONE, CLI_OFF_NONE, CLI_OFF_NONE, CLI_OFF_NONE,
    CLI_OFF_NONE, CLI_OFF_NONE, CLI_OFF_NONE, CLI_OFF_NONE,
    CLI_OFF_NONE, CLI_OFF_NONE, CLI_OFF_NONE, CLI_OFF_NONE,
    CLI_OFF_NONE, CLI_OFF_NONE, CLI_OFF_NONE, CLI_OFF_NONE,
    CLI_OFF_NONE, CLI_OFF_NONE, CLI_OFF_NONE, CLI_OFF_NONE,
    CLI_OFF_NONE, CLI_OFF_NONE, CLI_OFF_NONE, CLI_OFF_NONE,
    CLI_OFF_NONE, CLI_OFF_NONE, CLI_OFF_NONE, CLI_OFF_NONE,
    CLI_OFF_NONE, CLI_OFF_NONE, CLI_OFF_NONE, CLI_OFF_NONE,
    CLI_OFF_NONE, CLI_OFF_NONE, CLI_OFF_NONE, CLI_OFF_NONE,
    CLI_OFF_NONE, CLI_OFF_NONE, CLI_OFF_NONE, CLI_OFF_NONE
};

static const uint16_t nokind;
static const uint32_t nofilesize;
static const struct cli_pe_hook_data nopedata;

static void context_safe(struct cli_bc_ctx *ctx)
{
    /* make sure these are never NULL */
    if (!ctx->hooks.kind)
	ctx->hooks.kind = &nokind;
    if (!ctx->hooks.match_counts)
	ctx->hooks.match_counts = nomatch;
    if (!ctx->hooks.match_offsets)
	ctx->hooks.match_counts = nooffsets;
    if (!ctx->hooks.filesize)
	ctx->hooks.filesize = &nofilesize;
    if (!ctx->hooks.pedata)
	ctx->hooks.pedata = &nopedata;
}

static int cli_bytecode_context_reset(struct cli_bc_ctx *ctx);
struct cli_bc_ctx *cli_bytecode_context_alloc(void)
{
    struct cli_bc_ctx *ctx = cli_calloc(1, sizeof(*ctx));
    ctx->bytecode_timeout = 60000;
    cli_bytecode_context_reset(ctx);
    return ctx;
}

void cli_bytecode_context_destroy(struct cli_bc_ctx *ctx)
{
   cli_bytecode_context_clear(ctx);
   free(ctx);
}

int cli_bytecode_context_getresult_file(struct cli_bc_ctx *ctx, char **tempfilename)
{
    int fd;
    *tempfilename = ctx->tempfile;
    fd  = ctx->outfd;
    ctx->tempfile = NULL;
    ctx->outfd = 0;
    return fd;
}

/* resets bytecode state, so you can run another bytecode with same ctx */
static int cli_bytecode_context_reset(struct cli_bc_ctx *ctx)
{
    unsigned i;

    free(ctx->opsizes);
    ctx->opsizes = NULL;

    free(ctx->values);
    ctx->values = NULL;

    free(ctx->operands);
    ctx->operands = NULL;

    if (ctx->outfd) {
	cli_ctx *cctx = ctx->ctx;
	cli_bcapi_extract_new(ctx, -1);
	if (ctx->outfd)
	    close(ctx->outfd);
	if (ctx->tempfile && (!cctx || !cctx->engine->keeptmp)) {
	    cli_unlink(ctx->tempfile);
	}
	free(ctx->tempfile);
	ctx->tempfile = NULL;
	ctx->outfd = 0;
    }
    if (ctx->jsnormdir) {
	char fullname[1025];
	cli_ctx *cctx = ctx->ctx;
	int fd, ret = CL_CLEAN;

	if (!ctx->found) {
	    snprintf(fullname, 1024, "%s"PATHSEP"javascript", ctx->jsnormdir);
	    fd = open(fullname, O_RDONLY|O_BINARY);
	    if(fd >= 0) {
		ret = cli_scandesc(fd, cctx, CL_TYPE_HTML, 0, NULL, AC_SCAN_VIR);
		if (ret == CL_CLEAN) {
		    lseek(fd, 0, SEEK_SET);
		    ret = cli_scandesc(fd, cctx, CL_TYPE_TEXT_ASCII, 0, NULL, AC_SCAN_VIR);
		}
		close(fd);
	    }
	}
	if (!cctx || !cctx->engine->keeptmp) {
	    cli_rmdirs(ctx->jsnormdir);
	}
	free(ctx->jsnormdir);
	if (ret != CL_CLEAN)
	    ctx->found = 1;
    }
    ctx->numParams = 0;
    ctx->funcid = 0;
    ctx->file_size = 0;
    ctx->off = 0;
    ctx->written = 0;
    ctx->jsnormwritten = 0;
#if USE_MPOOL
    if (ctx->mpool) {
	mpool_destroy(ctx->mpool);
	ctx->mpool = NULL;
    }
#else
    /*TODO: implement for no-mmap case too*/
#endif
    for (i=0;i<ctx->ninflates;i++)
	cli_bcapi_inflate_done(ctx, i);
    free(ctx->inflates);
    ctx->inflates = NULL;
    ctx->ninflates = 0;

    for (i=0;i<ctx->nbuffers;i++)
	cli_bcapi_buffer_pipe_done(ctx, i);
    free(ctx->buffers);
    ctx->buffers = NULL;
    ctx->nbuffers = 0;

    for (i=0;i<ctx->nhashsets;i++)
	cli_bcapi_hashset_done(ctx, i);
    free(ctx->hashsets);
    ctx->hashsets = NULL;
    ctx->nhashsets = 0;

    for (i=0;i<ctx->njsnorms;i++)
	cli_bcapi_jsnorm_done(ctx, i);
    free(ctx->jsnorms);
    ctx->jsnorms = NULL;
    ctx->njsnorms = 0;
    ctx->jsnormdir = NULL;

    for (i=0;i<ctx->nmaps;i++)
	cli_bcapi_map_done(ctx, i);
    free(ctx->maps);
    ctx->maps = NULL;
    ctx->nmaps = 0;

    ctx->containertype = CL_TYPE_ANY;
    return CL_SUCCESS;
}

int cli_bytecode_context_clear(struct cli_bc_ctx *ctx)
{
    cli_ctx *cctx = (cli_ctx*)ctx->ctx;
    cli_bytecode_context_reset(ctx);
    memset(ctx, 0, sizeof(*ctx));
    return CL_SUCCESS;
}

static unsigned typesize(const struct cli_bc *bc, uint16_t type)
{
    type &= 0x7fff;
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
    return bc->types[type-65].size;
}

static unsigned typealign(const struct cli_bc *bc, uint16_t type)
{
    type &= 0x7fff;
    if (type <= 64) {
	unsigned size = typesize(bc, type);
	return size ? size : 1;
    }
    return bc->types[type-65].align;
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
	    /* This is a global variable */
	    return 0x80000000 | v;
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

static inline char *readData(const unsigned char *p, unsigned *off, unsigned len, char *ok, unsigned *datalen)
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
    if (!l || !ok) {
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
    return (char*)dat;
}

static inline char *readString(const unsigned char *p, unsigned *off, unsigned len, char *ok)
{
    unsigned stringlen;
    char *str = readData(p, off, len, ok, &stringlen);
    if (*ok && stringlen && str[stringlen-1] != '\0') {
	str[stringlen-1] = '\0';
	cli_errmsg("bytecode: string missing \\0 terminator: %s\n", str);
	free(str);
	*ok = 0;
	return NULL;
    }
    return str;
}

static int parseHeader(struct cli_bc *bc, unsigned char *buffer, unsigned *linelength)
{
    uint64_t magic1;
    unsigned magic2;
    char ok = 1;
    unsigned offset, len, flevel;
    char *pos;

    if (strncmp((const char*)buffer, BC_HEADER, sizeof(BC_HEADER)-1)) {
	cli_errmsg("Missing file magic in bytecode");
	return CL_EMALFDB;
    }
    offset = sizeof(BC_HEADER)-1;
    len = strlen((const char*)buffer);
    bc->metadata.formatlevel = readNumber(buffer, &offset, len, &ok);
    if (!ok) {
	cli_errmsg("Unable to parse (format) functionality level in bytecode header\n");
	return CL_EMALFDB;
    }
    /* we support 2 bytecode formats */
    if (bc->metadata.formatlevel != BC_FORMAT_096 &&
	bc->metadata.formatlevel != BC_FORMAT_LEVEL) {
	cli_dbgmsg("Skipping bytecode with (format) functionality level: %u (current %u)\n", 
		   bc->metadata.formatlevel, BC_FORMAT_LEVEL);
	return CL_BREAK;
    }
    /* Optimistic parsing, check for error only at the end.*/
    bc->metadata.timestamp = readNumber(buffer, &offset, len, &ok);
    bc->metadata.sigmaker = readString(buffer, &offset, len, &ok);
    bc->metadata.targetExclude = readNumber(buffer, &offset, len, &ok);
    bc->kind = readNumber(buffer, &offset, len, &ok);
    bc->metadata.minfunc = readNumber(buffer, &offset, len, &ok);
    bc->metadata.maxfunc = readNumber(buffer, &offset, len, &ok);
    flevel = cl_retflevel();
    /* in 0.96 these 2 fields are unused / zero, in post 0.96 these mean
     * min/max flevel.
     * So 0 for min/max means no min/max
     * Note that post 0.96 bytecode/bytecode lsig needs format 7, because
     * 0.96 doesn't check lsig functionality level.
     */
    if ((bc->metadata.minfunc && bc->metadata.minfunc > flevel) ||
        (bc->metadata.maxfunc && bc->metadata.maxfunc < flevel)) {
      cli_dbgmsg("Skipping bytecode with (engine) functionality level %u-%u (current %u)\n",
                 bc->metadata.minfunc, bc->metadata.maxfunc, flevel);
      return CL_BREAK;
    }
    bc->metadata.maxresource = readNumber(buffer, &offset, len, &ok);
    bc->metadata.compiler = readString(buffer, &offset, len, &ok);
    bc->num_types = readNumber(buffer, &offset, len, &ok);
    bc->num_func = readNumber(buffer, &offset, len, &ok);
    bc->state = bc_loaded;
    bc->uses_apis = NULL;
    bc->dbgnodes = NULL;
    bc->dbgnode_cnt = 0;
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
    if (buffer[offset] != ':') {
	cli_errmsg("Expected : but found: %c\n", buffer[offset]);
	return CL_EMALFDB;
    }
    offset++;
    *linelength = strtol((const char*)buffer+offset, &pos, 10);
    if (*pos != '\0') {
	cli_errmsg("Invalid number: %s\n", buffer+offset);
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

static int parseLSig(struct cli_bc *bc, char *buffer)
{
    const char *prefix;
    char *vnames, *vend = strchr(buffer, ';');
    if (vend) {
	bc->lsig = cli_strdup(buffer);
	*vend++ = '\0';
	prefix = buffer;
	vnames = strchr(vend, '{');
    } else {
	/* Not a logical signature, but we still have a virusname */
	bc->lsig = NULL;
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

    ty->numElements = readNumber(buffer, off, len, ok);
    if (!*ok) {
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
	bc->types[i].kind = DPointerType;
	bc->types[i].numElements = 1;
	bc->types[i].containedTypes = &containedTy[i];
	bc->types[i].size = bc->types[i].align = 8;
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
    for (i=(BC_START_TID - 65);i<bc->num_types-1;i++) {
	struct cli_bc_type *ty = &bc->types[i];
	uint8_t t = readFixedNumber(buffer, &offset, len, &ok, 1);
	if (!ok) {
	    cli_errmsg("Error reading type kind\n");
	    return CL_EMALFDB;
	}
	switch (t) {
	    case 1:
		ty->kind = DFunctionType;
		ty->size = ty->align = sizeof(void*);
		parseType(bc, ty, buffer, &offset, len, &ok);
		if (!ok) {
		    cli_errmsg("Error parsing type %u\n", i);
		    return CL_EMALFDB;
		}
		if (!ty->numElements) {
		    cli_errmsg("Function with no return type? %u\n", i);
		    return CL_EMALFDB;
		}
		break;
	    case 2:
	    case 3:
		ty->kind = (t == 2) ? DPackedStructType : DStructType;
		ty->size = ty->align = 0;/* TODO:calculate size/align of structs */
		ty->align = 8;
		parseType(bc, ty, buffer, &offset, len, &ok);
		if (!ok) {
		    cli_errmsg("Error parsing type %u\n", i);
		    return CL_EMALFDB;
		}
		break;
	    case 4:
		ty->kind = DArrayType;
		/* number of elements of array, not subtypes! */
		ty->numElements = readNumber(buffer, &offset, len, &ok);
		if (!ok) {
		    cli_errmsg("Error parsing type %u\n", i);
		    return CL_EMALFDB;
		}
		/* fall-through */
	    case 5:
		if (t == 5) {
		    ty->kind = DPointerType;
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
		if (t == 5) {
		    ty->size = ty->align = sizeof(void*);
		} else {
		    ty->size = ty->numElements*typesize(bc, ty->containedTypes[0]);
		    ty->align = typealign(bc, ty->containedTypes[0]);
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
    const struct cli_bc_type *ty = &bc->types[tid - 65];
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
	    if (ty->containedTypes[i] != apity->containedTypes[i]) {
		cli_dbgmsg("bytecode: contained type mismatch: %u != %u\n",
			   ty->containedTypes[i], apity->containedTypes[i]);
		return 0;
	    }
	} else if (!types_equal(bc, apity2ty, ty->containedTypes[i], apity->containedTypes[i] - BC_START_TID))
	    return 0;
	if (ty->kind == DArrayType)
	    break;/* validated the contained type already */
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

static uint16_t type_components(struct cli_bc *bc, uint16_t id, char *ok)
{
    unsigned i, sum=0;
    const struct cli_bc_type *ty;
    if (id <= 64)
	return 1;
    ty = &bc->types[id-65];
    /* TODO: protect against recursive types */
    switch (ty->kind) {
	case DFunctionType:
	    cli_errmsg("bytecode: function type not accepted for constant: %u\n", id);
	    /* don't accept functions as constant initializers */
	    *ok = 0;
	    return 0;
	case DPointerType:
	    return 2;
	case DStructType:
	case DPackedStructType:
	    for (i=0;i<ty->numElements;i++) {
		sum += type_components(bc, ty->containedTypes[i], ok);
	    }
	    return sum;
	case DArrayType:
	    return type_components(bc, ty->containedTypes[0], ok)*ty->numElements;
	default:
	    *ok = 0;
	    return 0;
    }
}

static void readConstant(struct cli_bc *bc, unsigned i, unsigned comp,
			 unsigned char *buffer, unsigned *offset,
			 unsigned len, char *ok)
{
    unsigned j=0;
    if (*ok && buffer[*offset] == 0x40 &&
	buffer [*offset+1] == 0x60) {
	/* zero initializer */
	memset(bc->globals[i], 0, sizeof(*bc->globals[0])*comp);
	(*offset)+=2;
	return;
    }
    while (*ok && buffer[*offset] != 0x60) {
	if (j >= comp) {
	    cli_errmsg("bytecode: constant has too many subcomponents, expected %u\n", comp);
	    *ok = 0;
	    return;
	}
	buffer[*offset] |= 0x20;
	bc->globals[i][j++] = readNumber(buffer, offset, len, ok);
    }
    if (*ok && j != comp) {
	cli_errmsg("bytecode: constant has too few subcomponents: %u < %u\n", j, comp);
	*ok = 0;
    }
    (*offset)++;
}

/* parse constant globals with constant initializers */
static int parseGlobals(struct cli_bc *bc, unsigned char *buffer)
{
    unsigned i, offset = 1, len = strlen((const char*)buffer), numglobals;
    unsigned maxglobal;
    char ok=1;

    if (buffer[0] != 'G') {
	cli_errmsg("bytecode: Invalid globals header: %c\n", buffer[0]);
	return CL_EMALFDB;
    }
    maxglobal = readNumber(buffer, &offset, len, &ok);
    if (maxglobal > cli_apicall_maxglobal) {
	cli_dbgmsg("bytecode using global %u, but highest global known to libclamav is %u, skipping\n", maxglobal, cli_apicall_maxglobal);
	return CL_BREAK;
    }
    numglobals = readNumber(buffer, &offset, len, &ok);
    bc->globals = cli_calloc(numglobals, sizeof(*bc->globals));
    if (!bc->globals) {
	cli_errmsg("bytecode: OOM allocating memory for %u globals\n", numglobals);
	return CL_EMEM;
    }
    bc->globaltys = cli_calloc(numglobals, sizeof(*bc->globaltys));
    if (!bc->globaltys) {
	cli_errmsg("bytecode: OOM allocating memory for %u global types\n", numglobals);
	return CL_EMEM;
    }
    bc->num_globals = numglobals;
    if (!ok)
	return CL_EMALFDB;
    for (i=0;i<numglobals;i++) {
	unsigned comp;
	bc->globaltys[i] = readTypeID(bc, buffer, &offset, len, &ok);
	comp = type_components(bc, bc->globaltys[i], &ok);
	if (!ok)
	    return CL_EMALFDB;
	bc->globals[i] = cli_malloc(sizeof(*bc->globals[0])*comp);
	if (!bc->globals[i])
	    return CL_EMEM;
	readConstant(bc, i, comp, buffer, &offset, len, &ok);
    }
    if (!ok)
	return CL_EMALFDB;
    if (offset != len) {
	cli_errmsg("Trailing garbage in globals: %d extra bytes\n",
		   len-offset);
	return CL_EMALFDB;
    }
    return CL_SUCCESS;
}

static int parseMD(struct cli_bc *bc, unsigned char *buffer)
{
    unsigned offset = 1, len = strlen((const char*)buffer);
    unsigned numMD, i, b;
    char ok = 1;
    if (buffer[0] != 'D')
	return CL_EMALFDB;
    numMD = readNumber(buffer, &offset, len, &ok);
    if (!ok) {
	cli_errmsg("Unable to parse number of MD nodes\n");
	return CL_EMALFDB;
    }
    b = bc->dbgnode_cnt;
    bc->dbgnode_cnt += numMD;
    bc->dbgnodes = cli_realloc(bc->dbgnodes, bc->dbgnode_cnt * sizeof(*bc->dbgnodes));
    if (!bc->dbgnodes)
	return CL_EMEM;
    for (i=0;i<numMD;i++) {
	unsigned j;
	struct cli_bc_dbgnode_element* elts;
	unsigned el = readNumber(buffer, &offset, len, &ok);
	if (!ok) {
	    cli_errmsg("Unable to parse number of elements\n");
	    return CL_EMALFDB;
	}
	bc->dbgnodes[b+i].numelements = el;
	bc->dbgnodes[b+i].elements = elts = cli_calloc(el, sizeof(*elts));
	if (!elts)
	    return CL_EMEM;
	for (j=0;j<el;j++) {
	    if (buffer[offset] == '|') {
		elts[j].string = readData(buffer, &offset, len, &ok, &elts[j].len);
		if (!ok)
		    return CL_EMALFDB;
	    } else {
		elts[j].len = readNumber(buffer, &offset, len, &ok);
		if (!ok)
		    return CL_EMALFDB;
		if (elts[j].len) {
		    elts[j].constant = readNumber(buffer, &offset, len, &ok);
		}
		else
		    elts[j].nodeid = readNumber(buffer, &offset, len, &ok);
		if (!ok)
		    return CL_EMALFDB;
	    }
	}
    }
    cli_dbgmsg("bytecode: Parsed %u nodes total\n", bc->dbgnode_cnt);
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
    func->returnType = readTypeID(bc, buffer, &offset, len, &ok);
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
	if (readFixedNumber(buffer, &offset, len, &ok, 1))
	    func->types[i] |= 0x8000;
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
static int16_t get_optype(const struct cli_bc_func *bcfunc, operand_t op)
{
    if (op >= bcfunc->numArgs + bcfunc->numLocals)
	return 0;
    return bcfunc->types[op]&0x7fff;
}

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
	if (inst.opcode >= OP_BC_INVALID) {
	    cli_errmsg("Invalid opcode: %u\n", inst.opcode);
	    return CL_EMALFDB;
	}

	switch (inst.opcode) {
	    case OP_BC_JMP:
		inst.u.jump = readBBID(bcfunc, buffer, &offset, len, &ok);
		break;
	    case OP_BC_RET:
		inst.type = readNumber(buffer, &offset, len, &ok);
		inst.u.unaryop = readOperand(bcfunc, buffer, &offset, len, &ok);
		break;
	    case OP_BC_BRANCH:
		inst.u.branch.condition = readOperand(bcfunc, buffer, &offset, len, &ok);
		inst.u.branch.br_true = readBBID(bcfunc, buffer, &offset, len, &ok);
		inst.u.branch.br_false = readBBID(bcfunc, buffer, &offset, len, &ok);
		break;
	    case OP_BC_CALL_API:/* fall-through */
	    case OP_BC_CALL_DIRECT:
		numOp = readFixedNumber(buffer, &offset, len, &ok, 1);
		if (ok) {
		    inst.u.ops.numOps = numOp;
		    inst.u.ops.opsizes=NULL;
		    inst.u.ops.ops = cli_calloc(numOp, sizeof(*inst.u.ops.ops));
		    if (!inst.u.ops.ops) {
			cli_errmsg("Out of memory allocating operands\n");
			return CL_EMEM;
		    }
		    if (inst.opcode == OP_BC_CALL_DIRECT)
			inst.u.ops.funcid = readFuncID(bc, buffer, &offset, len, &ok);
		    else
			inst.u.ops.funcid = readAPIFuncID(bc, buffer, &offset, len, &ok);
		    for (i=0;i<numOp;i++) {
			inst.u.ops.ops[i] = readOperand(bcfunc, buffer, &offset, len, &ok);
		    }
		}
		break;
	    case OP_BC_ZEXT:
	    case OP_BC_SEXT:
	    case OP_BC_TRUNC:
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
		if (inst.opcode != OP_BC_SEXT)
		    inst.u.cast.mask = inst.u.cast.mask != 64 ?
			(1ull<<inst.u.cast.mask)-1 :
			~0ull;
		break;
	    case OP_BC_GEP1:
	    case OP_BC_GEPZ:
		inst.u.three[0] = readNumber(buffer, &offset, len, &ok);
		inst.u.three[1] = readOperand(bcfunc, buffer, &offset, len, &ok);
		inst.u.three[2] = readOperand(bcfunc, buffer, &offset, len, &ok);
		break;
	    case OP_BC_GEPN:
		numOp = readFixedNumber(buffer, &offset, len, &ok, 1);
		if (ok) {
		    inst.u.ops.numOps = numOp+2;
		    inst.u.ops.opsizes = NULL;
		    inst.u.ops.ops = cli_calloc(numOp+2, sizeof(*inst.u.ops.ops));
		    if (!inst.u.ops.ops) {
			cli_errmsg("Out of memory allocating operands\n");
			return CL_EMEM;
		    }
		    inst.u.ops.ops[0] = readNumber(buffer, &offset, len, &ok);
		    for (i=1;i<numOp+2;i++)
			inst.u.ops.ops[i] = readOperand(bcfunc, buffer, &offset, len, &ok);
		}
		break;
	    case OP_BC_ICMP_EQ:
	    case OP_BC_ICMP_NE:
	    case OP_BC_ICMP_UGT:
	    case OP_BC_ICMP_UGE:
	    case OP_BC_ICMP_ULT:
	    case OP_BC_ICMP_ULE:
	    case OP_BC_ICMP_SGT:
	    case OP_BC_ICMP_SGE:
	    case OP_BC_ICMP_SLE:
	    case OP_BC_ICMP_SLT:
		/* instruction type must be correct before readOperand! */
		inst.type = readNumber(buffer, &offset, len, &ok);
		/* fall-through */
	    default:
		numOp = operand_counts[inst.opcode];
		switch (numOp) {
		    case 0:
			break;
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
			cli_errmsg("Opcode %u with too many operands: %u?\n", inst.opcode, numOp);
			ok = 0;
			break;
		}
	}
	if (inst.opcode == OP_BC_STORE) {
	    int16_t t = get_optype(bcfunc, inst.u.binop[0]);
	    if (t)
		inst.type = t;
	}
	if (inst.opcode == OP_BC_COPY)
	    inst.type = get_optype(bcfunc, inst.u.binop[1]);
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
	    else if (inst.type <= 65)
		inst.interp_op += 4;
	    else {
		cli_dbgmsg("unknown inst type: %d\n", inst.type);
	    }
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
    if (buffer[offset] == 'D') {
	unsigned num;
	offset += 3;
	if (offset >= len)
	    return CL_EMALFDB;
	num = readNumber(buffer, &offset, len, &ok);
	if (!ok)
	    return CL_EMALFDB;
	if (num != bcfunc->numInsts) {
	    cli_errmsg("invalid number of dbg nodes, expected: %u, got: %u\n", bcfunc->numInsts, num);
	    return CL_EMALFDB;
	}
	bcfunc->dbgnodes = cli_malloc(num*sizeof(*bcfunc->dbgnodes));
	if (!bcfunc->dbgnodes)
	    return CL_EMEM;
	for (i=0;i<num;i++) {
	    bcfunc->dbgnodes[i] = readNumber(buffer, &offset, len, &ok);
	    if (!ok)
		return CL_EMALFDB;
	}
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
    PARSE_BC_TYPES=0,
    PARSE_BC_APIS,
    PARSE_BC_GLOBALS,
    PARSE_BC_LSIG,
    PARSE_MD_OPT_HEADER,
    PARSE_FUNC_HEADER,
    PARSE_BB
};

int cli_bytecode_load(struct cli_bc *bc, FILE *f, struct cli_dbio *dbio, int trust)
{
    unsigned row = 0, current_func = 0, bb=0;
    char *buffer;
    unsigned linelength=0;
    char firstbuf[FILEBUFF];
    enum parse_state state;
    int rc, end=0;

    memset(bc, 0, sizeof(*bc));
    cli_dbgmsg("Loading %s bytecode\n", trust ? "trusted" : "untrusted");
    bc->trusted = trust;
    if (!f && !dbio) {
	cli_errmsg("Unable to load bytecode (null file)\n");
	return CL_ENULLARG;
    }
    if (!cli_dbgets(firstbuf, FILEBUFF, f, dbio)) {
	cli_errmsg("Unable to load bytecode (empty file)\n");
	return CL_EMALFDB;
    }
    cli_chomp(firstbuf);
    rc = parseHeader(bc, (unsigned char*)firstbuf, &linelength);
    if (rc == CL_BREAK) {
	bc->state = bc_skip;
	return CL_SUCCESS;
    }
    if (rc != CL_SUCCESS) {
	cli_errmsg("Error at bytecode line %u\n", row);
	return rc;
    }
    buffer = cli_malloc(linelength);
    if (!buffer) {
	cli_errmsg("Out of memory allocating line of length %u\n", linelength);
	return CL_EMEM;
    }
    state = PARSE_BC_LSIG;
    while (cli_dbgets(buffer, linelength, f, dbio) && !end) {
	cli_chomp(buffer);
	row++;
	switch (state) {
	    case PARSE_BC_LSIG:
		rc = parseLSig(bc, buffer);
		if (rc == CL_BREAK) /* skip */ {
		    bc->state = bc_skip;
		    free(buffer);
		    return CL_SUCCESS;
		}
		if (rc != CL_SUCCESS) {
		    cli_errmsg("Error at bytecode line %u\n", row);
		    free(buffer);
		    return rc;
		}
		state = PARSE_BC_TYPES;
		break;
	    case PARSE_BC_TYPES:
		rc = parseTypes(bc, (unsigned char*)buffer);
		if (rc != CL_SUCCESS) {
		    cli_errmsg("Error at bytecode line %u\n", row);
		    free(buffer);
		    return rc;
		}
		state = PARSE_BC_APIS;
		break;
	    case PARSE_BC_APIS:
		rc = parseApis(bc, (unsigned char*)buffer);
		if (rc == CL_BREAK) /* skip */ {
		    bc->state = bc_skip;
		    free(buffer);
		    return CL_SUCCESS;
		}
		if (rc != CL_SUCCESS) {
		    cli_errmsg("Error at bytecode line %u\n", row);
		    free(buffer);
		    return rc;
		}
		state = PARSE_BC_GLOBALS;
		break;
	    case PARSE_BC_GLOBALS:
		rc = parseGlobals(bc, (unsigned char*)buffer);
		if (rc == CL_BREAK) /* skip */ {
		    bc->state = bc_skip;
		    free(buffer);
		    return CL_SUCCESS;
		}
		if (rc != CL_SUCCESS) {
		    cli_errmsg("Error at bytecode line %u\n", row);
		    free(buffer);
		    return rc;
		}
		state = PARSE_MD_OPT_HEADER;
		break;
	    case PARSE_MD_OPT_HEADER:
		if (buffer[0] == 'D') {
		    rc = parseMD(bc, (unsigned char*)buffer);
		    if (rc != CL_SUCCESS) {
			cli_errmsg("Error at bytecode line %u\n", row);
			free(buffer);
			return rc;
		    }
		    break;
		}
		/* fall-through */
	    case PARSE_FUNC_HEADER:
                if (*buffer == 'S') {
		    end = 1;
		    break;
		}
		rc = parseFunctionHeader(bc, current_func, (unsigned char*)buffer);
		if (rc != CL_SUCCESS) {
		    cli_errmsg("Error at bytecode line %u\n", row);
		    free(buffer);
		    return rc;
		}
		bb = 0;
		state = PARSE_BB;
		break;
	    case PARSE_BB:
		rc = parseBB(bc, current_func, bb++, (unsigned char*)buffer);
		if (rc != CL_SUCCESS) {
		    cli_errmsg("Error at bytecode line %u\n", row);
		    free(buffer);
		    return rc;
		}
		if (bb >= bc->funcs[current_func].numBB) {
		    if (bc->funcs[current_func].insn_idx != bc->funcs[current_func].numInsts) {
			cli_errmsg("Parsed different number of instructions than declared: %u != %u\n",
				   bc->funcs[current_func].insn_idx, bc->funcs[current_func].numInsts);
			free(buffer);
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
    free(buffer);
    cli_dbgmsg("Parsed %d functions\n", current_func);
    if (current_func != bc->num_func) {
	cli_errmsg("Loaded less functions than declared: %u vs. %u\n",
		   current_func, bc->num_func);
	return CL_EMALFDB;
    }
    return CL_SUCCESS;
}

int cli_bytecode_run(const struct cli_all_bc *bcs, const struct cli_bc *bc, struct cli_bc_ctx *ctx)
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
    context_safe(ctx);
    if (bc->state == bc_interp) {
	memset(&func, 0, sizeof(func));
	func.numInsts = 1;
	func.numValues = 1;
	func.numConstants = 0;
	func.numBytes = ctx->bytes;
	memset(ctx->values+ctx->bytes-8, 0, 8);

	inst.opcode = OP_BC_CALL_DIRECT;
	inst.interp_op = OP_BC_CALL_DIRECT*5;
	inst.dest = func.numArgs;
	inst.type = 0;
	inst.u.ops.numOps = ctx->numParams;
	inst.u.ops.funcid = ctx->funcid;
	inst.u.ops.ops = ctx->operands;
	inst.u.ops.opsizes = ctx->opsizes;
	cli_dbgmsg("Bytecode: executing in interpeter mode\n");
	return cli_vm_execute(ctx->bc, ctx, &func, &inst);
    }
    cli_dbgmsg("Bytecode: executing in JIT mode\n");
    return cli_vm_execute_jit(bcs, ctx, &bc->funcs[ctx->funcid]);
}

uint64_t cli_bytecode_context_getresult_int(struct cli_bc_ctx *ctx)
{
    return *(uint32_t*)ctx->values;/*XXX*/
}

void cli_bytecode_destroy(struct cli_bc *bc)
{
    unsigned i, j, k;
    free(bc->metadata.compiler);
    free(bc->metadata.sigmaker);

    if (bc->funcs) {
	for (i=0;i<bc->num_func;i++) {
	    struct cli_bc_func *f = &bc->funcs[i];
	    if (!f)
		continue;
	    free(f->types);

	    for (j=0;j<f->numBB;j++) {
		struct cli_bc_bb *BB = &f->BB[j];
		for(k=0;k<BB->numInsts;k++) {
		    struct cli_bc_inst *ii = &BB->insts[k];
		    if (operand_counts[ii->opcode] > 3 ||
			ii->opcode == OP_BC_CALL_DIRECT || ii->opcode == OP_BC_CALL_API) {
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
    }
    if (bc->types) {
	for (i=NUM_STATIC_TYPES;i<bc->num_types;i++) {
	    if (bc->types[i].containedTypes)
		free(bc->types[i].containedTypes);
	}
	free(bc->types);
    }

    if (bc->globals) {
	for (i=0;i<bc->num_globals;i++) {
	    free(bc->globals[i]);
	}
	free(bc->globals);
    }
    if (bc->dbgnodes) {
	for (i=0;i<bc->dbgnode_cnt;i++) {
	    for (j=0;j<bc->dbgnodes[i].numelements;j++) {
		struct cli_bc_dbgnode_element *el =  &bc->dbgnodes[i].elements[j];
		if (el && el->string)
		    free(el->string);
	    }
	}
	free(bc->dbgnodes);
    }
    free(bc->globaltys);
    if (bc->uses_apis)
	cli_bitset_free(bc->uses_apis);
    free(bc->lsig);
    free(bc->globalBytes);
}

#define MAP(val) do { operand_t o = val; \
    if (o & 0x80000000) {\
	o &= 0x7fffffff;\
	if (o > bc->num_globals) {\
	    cli_errmsg("bytecode: global out of range: %u > %u, for instruction %u in function %u\n",\
		       o, (unsigned)bc->num_globals, j, i);\
	    return CL_EBYTECODE;\
	}\
	val = 0x80000000 | gmap[o];\
	break;\
    }\
    if (o > totValues) {\
	cli_errmsg("bytecode: operand out of range: %u > %u, for instruction %u in function %u\n", o, totValues, j, i);\
	return CL_EBYTECODE;\
    }\
    val = map[o]; } while (0)

#define MAPPTR(val) {\
    if ((val < bcfunc->numValues) && bcfunc->types[val]&0x8000)\
      val = map[val] | 0x40000000;\
    else\
	MAP(val);\
}

static inline int64_t ptr_compose(int32_t id, uint32_t offset)
{
    uint64_t i = id;
    return (i << 32) | offset;
}

static inline int get_geptypesize(const struct cli_bc *bc, uint16_t tid)
{
  const struct cli_bc_type *ty;
  if (tid >= bc->num_types+65) {
    cli_errmsg("bytecode: typeid out of range %u >= %u\n", tid, bc->num_types);
    return -1;
  }
  if (tid <= 64) {
    cli_errmsg("bytecode: invalid type for gep (%u)\n", tid);
    return -1;
  }
  ty = &bc->types[tid - 65];
  if (ty->kind != DPointerType) {
    cli_errmsg("bytecode: invalid gep type, must be pointer: %u\n", tid);
    return -1;
  }
  return typesize(bc, ty->containedTypes[0]);
}

static int cli_bytecode_prepare_interpreter(struct cli_bc *bc)
{
    unsigned i, j, k;
    uint64_t *gmap;
    unsigned bcglobalid = cli_apicall_maxglobal - _FIRST_GLOBAL+2;
    bc->numGlobalBytes = 0;
    gmap = cli_malloc(bc->num_globals*sizeof(*gmap));
    if (!gmap)
	return CL_EMEM;
    for (j=0;j<bc->num_globals;j++) {
	uint16_t ty = bc->globaltys[j];
	unsigned align = typealign(bc, ty);
	assert(align);
	bc->numGlobalBytes  = (bc->numGlobalBytes + align-1)&(~(align-1));
	gmap[j] = bc->numGlobalBytes;
	bc->numGlobalBytes += typesize(bc, ty);
    }
    if (bc->numGlobalBytes) {
	bc->globalBytes = cli_calloc(1, bc->numGlobalBytes);
	if (!bc->globalBytes)
	    return CL_EMEM;
    } else
	bc->globalBytes = NULL;

    for (j=0;j<bc->num_globals;j++) {
	struct cli_bc_type *ty;
	if (bc->globaltys[j] < 65)
	    continue;
	ty = &bc->types[bc->globaltys[j]-65];
	switch (ty->kind) {
	    case DPointerType:
		{
		    uint64_t ptr;
		    if (bc->globals[j][1] >= _FIRST_GLOBAL) {
			ptr = ptr_compose(bc->globals[j][1] - _FIRST_GLOBAL + 1,
					    bc->globals[j][0]);
		    } else {
			if (bc->globals[j][1] > bc->num_globals)
			    continue;
			ptr = ptr_compose(bcglobalid,
					  gmap[bc->globals[j][1]] + bc->globals[j][0]);
		    }
		    *(uint64_t*)&bc->globalBytes[gmap[j]] = ptr;
		    break;
		}
	    case DArrayType:
		{
		    unsigned elsize, i, off = gmap[j];
		    /* TODO: support other than ints in arrays */
		    elsize = typesize(bc, ty->containedTypes[0]);
		    switch (elsize) {
			case 1:
			    for(i=0;i<ty->numElements;i++)
				bc->globalBytes[off+i] = bc->globals[j][i];
			    break;
			case 2:
			    for(i=0;i<ty->numElements;i++)
				*(uint16_t*)&bc->globalBytes[off+i*2] = bc->globals[j][i];
			    break;
			case 4:
			    for(i=0;i<ty->numElements;i++)
				*(uint32_t*)&bc->globalBytes[off+i*4] = bc->globals[j][i];
			    break;
			case 8:
			    for(i=0;i<ty->numElements;i++)
				*(uint64_t*)&bc->globalBytes[off+i*8] = bc->globals[j][i];
			    break;
			default:
			    cli_dbgmsg("interpreter: unsupported elsize: %u\n", elsize);
		    }
		    break;
		}
	    default:
		/*TODO*/
		if (!bc->globals[j][1])
		    continue; /* null */
		break;
	}
    }

    for (i=0;i<bc->num_func;i++) {
	struct cli_bc_func *bcfunc = &bc->funcs[i];
	unsigned totValues = bcfunc->numValues + bcfunc->numConstants + bc->num_globals;
	unsigned *map = cli_malloc(sizeof(*map)*totValues);
	if (!map)
	    return CL_EMEM;
	bcfunc->numBytes = 0;
	for (j=0;j<bcfunc->numValues;j++) {
	    uint16_t ty = bcfunc->types[j];
	    unsigned align;
	    align = typealign(bc, ty);
	    assert(align);
	    bcfunc->numBytes  = (bcfunc->numBytes + align-1)&(~(align-1));
	    map[j] = bcfunc->numBytes;
	    /* printf("%d -> %d, %u\n", j, map[j], typesize(bc, ty)); */
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
		case OP_BC_ADD:
		case OP_BC_SUB:
		case OP_BC_MUL:
		case OP_BC_UDIV:
		case OP_BC_SDIV:
		case OP_BC_UREM:
		case OP_BC_SREM:
		case OP_BC_SHL:
		case OP_BC_LSHR:
		case OP_BC_ASHR:
		case OP_BC_AND:
		case OP_BC_OR:
		case OP_BC_XOR:
		case OP_BC_ICMP_EQ:
		case OP_BC_ICMP_NE:
		case OP_BC_ICMP_UGT:
		case OP_BC_ICMP_UGE:
		case OP_BC_ICMP_ULT:
		case OP_BC_ICMP_ULE:
		case OP_BC_ICMP_SGT:
		case OP_BC_ICMP_SGE:
		case OP_BC_ICMP_SLT:
		case OP_BC_ICMP_SLE:
		case OP_BC_COPY:
		case OP_BC_STORE:
		    MAP(inst->u.binop[0]);
		    MAP(inst->u.binop[1]);
		    break;
		case OP_BC_SEXT:
		case OP_BC_ZEXT:
		case OP_BC_TRUNC:
		    MAP(inst->u.cast.source);
		    break;
		case OP_BC_BRANCH:
		    MAP(inst->u.branch.condition);
		    break;
		case OP_BC_JMP:
		    break;
		case OP_BC_RET:
		    MAP(inst->u.unaryop);
		    break;
		case OP_BC_SELECT:
		    MAP(inst->u.three[0]);
		    MAP(inst->u.three[1]);
		    MAP(inst->u.three[2]);
		    break;
		case OP_BC_CALL_API:/* fall-through */
		case OP_BC_CALL_DIRECT:
		{
		    struct cli_bc_func *target = NULL;
		    if (inst->opcode == OP_BC_CALL_DIRECT) {
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
			/* APIs have at most 2 parameters always */
			if (inst->u.ops.numOps > 5) {
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
			MAPPTR(inst->u.ops.ops[k]);
			if (inst->opcode == OP_BC_CALL_DIRECT)
			    inst->u.ops.opsizes[k] = typesize(bc, target->types[k]);
			else
			    inst->u.ops.opsizes[k] = 32; /*XXX*/
		    }
		    break;
		}
		case OP_BC_LOAD:
		    MAPPTR(inst->u.unaryop);
		    break;
		case OP_BC_GEP1:
		    if (inst->u.three[1]&0x80000000 ||
			bcfunc->types[inst->u.binop[1]]&0x8000) {
                      cli_errmsg("bytecode: gep1 of alloca is not allowed\n");
                      return CL_EBYTECODE;
                    }
		    MAP(inst->u.three[1]);
		    MAP(inst->u.three[2]);
                    inst->u.three[0] = get_geptypesize(bc, inst->u.three[0]);
                    if (inst->u.three[0] == -1)
                      return CL_EBYTECODE;
                    break;
		case OP_BC_GEPZ:
		    /*three[0] is the type*/
		    if (inst->u.three[1]&0x80000000 ||
			bcfunc->types[inst->u.three[1]]&0x8000)
			inst->interp_op = 5*(inst->interp_op/5);
		    else
			inst->interp_op = 5*(inst->interp_op/5)+3;
		    MAP(inst->u.three[1]);
		    MAP(inst->u.three[2]);
		    break;
		case OP_BC_GEPN:
		    /*TODO */
		    break;
		case OP_BC_MEMSET:
		case OP_BC_MEMCPY:
		case OP_BC_MEMMOVE:
		case OP_BC_MEMCMP:
		    MAPPTR(inst->u.three[0]);
		    MAPPTR(inst->u.three[1]);
		    MAP(inst->u.three[2]);
		    break;
		case OP_BC_RET_VOID:
		case OP_BC_ISBIGENDIAN:
		case OP_BC_ABORT:
		    /* no operands */
		    break;
		case OP_BC_BSWAP16:
		case OP_BC_BSWAP32:
		case OP_BC_BSWAP64:
		    MAP(inst->u.unaryop);
		    break;
		case OP_BC_PTRDIFF32:
		    MAPPTR(inst->u.binop[0]);
		    MAPPTR(inst->u.binop[1]);
		    break;
		case OP_BC_PTRTOINT64:
		    MAPPTR(inst->u.unaryop);
		    break;
		default:
		    cli_dbgmsg("Unhandled opcode: %d\n", inst->opcode);
		    return CL_EBYTECODE;
	    }
	}
	free(map);
    }
    free(gmap);
    bc->state = bc_interp;
    return CL_SUCCESS;
}

int cli_bytecode_prepare(struct cli_all_bc *bcs, unsigned dconfmask)
{
    unsigned i, interp = 0;
    int rc;
    if (cli_bytecode_prepare_jit(bcs) == CL_SUCCESS) {
	cli_dbgmsg("Bytecode: %u bytecode prepared with JIT\n", bcs->count);
	return CL_SUCCESS;
    }
    for (i=0;i<bcs->count;i++) {
	struct cli_bc *bc = &bcs->all_bcs[i];
	if (bc->state == bc_interp || bc->state == bc_jit)
	    continue;
	if (!(dconfmask & BYTECODE_INTERPRETER)) {
	    cli_warnmsg("Bytecode needs interpreter, but interpreter is disabled\n");
	    continue;
	}
	rc = cli_bytecode_prepare_interpreter(bc);
	interp++;
	if (rc != CL_SUCCESS)
	    return rc;
    }
    cli_dbgmsg("Bytecode: %u bytecode prepared with JIT, "
	       "%u prepared with interpreter\n", bcs->count-interp, interp);
    return CL_SUCCESS;
}

int cli_bytecode_init(struct cli_all_bc *allbc, unsigned dconfmask)
{
    memset(allbc, 0, sizeof(*allbc));
    return cli_bytecode_init_jit(allbc, dconfmask);
}

int cli_bytecode_done(struct cli_all_bc *allbc)
{
    return cli_bytecode_done_jit(allbc);
}

int cli_bytecode_context_setfile(struct cli_bc_ctx *ctx, fmap_t *map)
{
    ctx->fmap = map;
    ctx->file_size = map->len + map->offset;
    ctx->hooks.filesize = &ctx->file_size;
    return 0;
}

int cli_bytecode_runlsig(cli_ctx *cctx, const struct cli_all_bc *bcs, unsigned bc_idx, const char **virname, const uint32_t* lsigcnt, const uint32_t *lsigsuboff, fmap_t *map)
{
    int ret;
    struct cli_bc_ctx ctx;
    const struct cli_bc *bc = &bcs->all_bcs[bc_idx-1];

    if (bc->hook_lsig_id) {
	cli_dbgmsg("hook lsig id %d matched (bc %d)\n", bc->hook_lsig_id, bc->id);
	/* this is a bytecode for a hook, defer running it until hook is
	 * executed, so that it has all the info for the hook */
	if (cctx->hook_lsig_matches)
	    cli_bitset_set(cctx->hook_lsig_matches, bc->hook_lsig_id-1);
	return CL_SUCCESS;
    }
    memset(&ctx, 0, sizeof(ctx));
    cli_bytecode_context_setfuncid(&ctx, bc, 0);
    ctx.hooks.match_counts = lsigcnt;
    ctx.hooks.match_offsets = lsigsuboff;
    cli_bytecode_context_setctx(&ctx, cctx);
    cli_bytecode_context_setfile(&ctx, map);

    cli_dbgmsg("Running bytecode for logical signature match\n");
    ret = cli_bytecode_run(bcs, bc, &ctx);
    if (ret != CL_SUCCESS) {
	cli_warnmsg("Bytcode failed to run: %s\n", cl_strerror(ret));
	return CL_SUCCESS;
    }
    if (ctx.virname) {
	cli_dbgmsg("Bytecode found virus: %s\n", ctx.virname);
	if (virname)
	    *virname = ctx.virname;
	cli_bytecode_context_clear(&ctx);
	return CL_VIRUS;
    }
    ret = cli_bytecode_context_getresult_int(&ctx);
    cli_dbgmsg("Bytecode %u returned code: %u\n", bc->id, ret);
    cli_bytecode_context_clear(&ctx);
    return CL_SUCCESS;
}

int cli_bytecode_runhook(cli_ctx *cctx, const struct cl_engine *engine, struct cli_bc_ctx *ctx,
			 unsigned id, fmap_t *map, const char **virname)
{
    const unsigned *hooks = engine->hooks[id - _BC_START_HOOKS];
    unsigned i, hooks_cnt = engine->hooks_cnt[id - _BC_START_HOOKS];
    int ret;
    unsigned executed = 0;

    cli_bytecode_context_setfile(ctx, map);
    cli_dbgmsg("Bytecode executing hook id %u (%u hooks)\n", id, hooks_cnt);
    for (i=0;i < hooks_cnt;i++) {
	const struct cli_bc *bc = &engine->bcs.all_bcs[hooks[i]];
	if (bc->lsig) {
	    if (!cctx->hook_lsig_matches ||
		!cli_bitset_test(cctx->hook_lsig_matches, bc->hook_lsig_id-1))
		continue;
	    cli_dbgmsg("Bytecode: executing bytecode %u (lsig matched)\n" , bc->id);
	}
	cli_bytecode_context_setfuncid(ctx, bc, 0);
	ret = cli_bytecode_run(&engine->bcs, bc, ctx);
	executed++;
	if (ret != CL_SUCCESS) {
	    cli_warnmsg("Bytecode failed to run: %s\n", cl_strerror(ret));
	    continue;
	}
	if (ctx->virname) {
	    cli_dbgmsg("Bytecode found virus: %s\n", ctx->virname);
	    if (virname)
		*virname = ctx->virname;
	    cli_bytecode_context_clear(ctx);
	    return CL_VIRUS;
	}
	ret = cli_bytecode_context_getresult_int(ctx);
	/* TODO: use prefix here */
	cli_dbgmsg("Bytecode %u returned %u\n", bc->id, ret);
	if (!ret) {
	    char *tempfile;
	    int fd = cli_bytecode_context_getresult_file(ctx, &tempfile);
	    if (fd && fd != -1) {
		if (cctx && cctx->engine->keeptmp)
		    cli_dbgmsg("Bytecode %u unpacked file saved in %s\n",
			       bc->id, tempfile);
		else
		    cli_dbgmsg("Bytecode %u unpacked file\n", bc->id);
		lseek(fd, 0, SEEK_SET);
		cli_dbgmsg("***** Scanning unpacked file ******\n");
		ret = cli_magic_scandesc(fd, cctx);
		if (!cctx || !cctx->engine->keeptmp)
		    if (ftruncate(fd, 0) == -1)
			cli_dbgmsg("ftruncate failed on %d\n", fd);
		close(fd);
		if (!cctx || !cctx->engine->keeptmp) {
		    if (tempfile && cli_unlink(tempfile))
			ret = CL_EUNLINK;
		}
		free(tempfile);
		if (ret != CL_CLEAN) {
		    if (ret == CL_VIRUS)
			cli_dbgmsg("Scanning unpacked file by bytecode %u found a virus\n", bc->id);
		    cli_bytecode_context_clear(ctx);
		    return ret;
		}
		cli_bytecode_context_reset(ctx);
		continue;
	    }
	}
	cli_bytecode_context_reset(ctx);
    }
    if (executed)
	cli_dbgmsg("Bytecode: executed %u bytecodes for this hook\n", executed);
    else
	cli_dbgmsg("Bytecode: no logical signature matched, no bytecode executed\n");
    return CL_CLEAN;
}

int cli_bytecode_context_setpe(struct cli_bc_ctx *ctx, const struct cli_pe_hook_data *data, const struct cli_exe_section *sections)
{
    ctx->sections = sections;
    ctx->hooks.pedata = data;
    return 0;
}

void cli_bytecode_context_setctx(struct cli_bc_ctx *ctx, void *cctx)
{
    ctx->ctx = cctx;
    ctx->bytecode_timeout = ((cli_ctx*)cctx)->engine->bytecode_timeout;
}

void cli_bytecode_describe(const struct cli_bc *bc)
{
    char buf[128];
    int cols;
    unsigned i;
    time_t stamp;
    int had;

    if (!bc) {
	printf("(null bytecode)\n");
	return;
    }

    stamp = bc->metadata.timestamp;
    printf("Bytecode format functionality level: %u\n", bc->metadata.formatlevel);
    printf("Bytecode metadata:\n\tcompiler version: %s\n",
	   bc->metadata.compiler ? bc->metadata.compiler : "N/A");
    printf("\tcompiled on: %s",
	   cli_ctime(&stamp, buf, sizeof(buf)));
    printf("\tcompiled by: %s\n", bc->metadata.sigmaker ? bc->metadata.sigmaker : "N/A");
    /*TODO: parse and display arch name, also take it into account when
      JITing*/
    printf("\ttarget exclude: %d\n", bc->metadata.targetExclude);
    printf("\tbytecode type: ");
    switch (bc->kind) {
	case BC_GENERIC:
	    puts("generic, not loadable by clamscan/clamd");
	    break;
	case BC_LOGICAL:
	    puts("logical only");
	    break;
	case BC_PE_UNPACKER:
	    puts("PE hook");
	    break;
	default:
	    printf("Unknown (type %u)", bc->kind);
	    break;
    }
    /* 0 means no limit */
    printf("\tbytecode functionality level: %u - %u\n",
	   bc->metadata.minfunc, bc->metadata.maxfunc);
    printf("\tbytecode logical signature: %s\n",
	       bc->lsig ? bc->lsig : "<none>");
    printf("\tvirusname prefix: %s\n",
	   bc->vnameprefix);
    printf("\tvirusnames: %u\n", bc->vnames_cnt);
    printf("\tbytecode triggered on: ");
    switch (bc->kind) {
	case BC_GENERIC:
	    puts("N/A (loaded in clambc only)");
	    break;
	case BC_LOGICAL:
	    puts("files matching logical signature");
	    break;
	case BC_PE_UNPACKER:
	    if (bc->lsig)
		puts("PE files matching logical signature");
	    else
		puts("all PE files!");
	    break;
	default:
	    puts("N/A (unknown type)\n");
	    break;
    }
    printf("\tnumber of functions: %u\n\tnumber of types: %u\n",
	   bc->num_func, bc->num_types);
    printf("\tnumber of global constants: %u\n", (unsigned)bc->num_globals);
    printf("\tnumber of debug nodes: %u\n", bc->dbgnode_cnt);
    printf("\tbytecode APIs used:");
    cols = 0; /* remaining */
    had = 0;
    for (i=0;i<cli_apicall_maxapi;i++) {
	if (cli_bitset_test(bc->uses_apis, i)) {
	    unsigned len = strlen(cli_apicalls[i].name);
	    if (had)
		printf(",");
	    if (len > cols) {
		printf("\n\t");
		cols = 72;
	    }
	    printf(" %s", cli_apicalls[i].name);
	    had = 1;
	    cols -= len;
	}
    }
    printf("\n");
}

/*
 *  Load, and verify ClamAV bytecode.
 *
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2009-2013 Sourcefire, Inc.
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

#include <string.h>
#include <assert.h>
#include <fcntl.h>

#include "dconf.h"
#include "clamav.h"
#include "others.h"
#include "pe.h"
#include "bytecode.h"
#include "bytecode_priv.h"
#include "bytecode_detect.h"
#include "readdb.h"
#include "scanners.h"
#include "bytecode_api.h"
#include "bytecode_api_impl.h"
#include "builtin_bytecodes.h"
#if HAVE_JSON
#include "json.h"
#endif

#define MAX_BC 64
#define BC_EVENTS_PER_SIG 2
#define MAX_BC_SIGEVENT_ID MAX_BC*BC_EVENTS_PER_SIG

cli_events_t * g_sigevents = NULL;
unsigned int g_sigid;

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
	ctx->hooks.match_offsets = nooffsets;
    if (!ctx->hooks.filesize)
	ctx->hooks.filesize = &nofilesize;
    if (!ctx->hooks.pedata)
	ctx->hooks.pedata = &nopedata;
}

static int cli_bytecode_context_reset(struct cli_bc_ctx *ctx);
struct cli_bc_ctx *cli_bytecode_context_alloc(void)
{
    struct cli_bc_ctx *ctx = cli_calloc(1, sizeof(*ctx));
    if (!ctx) {
        cli_errmsg("Out of memory allocating cli_bytecode_context_reset\n");
        return NULL;
    }
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
		ret = cli_scandesc(fd, cctx, CL_TYPE_HTML, 0, NULL, AC_SCAN_VIR, NULL);
		if (ret == CL_CLEAN) {
		    if (lseek(fd, 0, SEEK_SET) == -1)
                cli_dbgmsg("cli_bytecode: call to lseek() has failed\n");
            else
                ret = cli_scandesc(fd, cctx, CL_TYPE_TEXT_ASCII, 0, NULL, AC_SCAN_VIR, NULL);
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
    /* don't touch fmap, file_size, and hooks, sections, ctx, timeout, pdf* */
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

#if HAVE_JSON
    free((json_object**)(ctx->jsonobjs));
    ctx->jsonobjs = NULL;
    ctx->njsonobjs = 0;
#endif

    ctx->containertype = CL_TYPE_ANY;
    return CL_SUCCESS;
}

int cli_bytecode_context_clear(struct cli_bc_ctx *ctx)
{
    cli_bytecode_context_reset(ctx);
    memset(ctx, 0, sizeof(*ctx));
    return CL_SUCCESS;
}

static unsigned typesize(const struct cli_bc *bc, uint16_t type)
{
    struct cli_bc_type *ty;
    unsigned j;

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
    ty = &bc->types[type-65];
    if (ty->size)
	return ty->size;
    switch (ty->kind) {
	case 2:
	case 3:
	    for (j=0;j<ty->numElements;j++)
		ty->size += typesize(bc, ty->containedTypes[j]);
	    break;
	case 4:
	    ty->size = ty->numElements * typesize(bc, ty->containedTypes[0]);
	    break;
	default:
	    break;
    }
    if (!ty->size && ty->kind != DFunctionType) {
	cli_warnmsg("type %d size is 0\n", type-65);
    }
    return ty->size;
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
	if (!ctx->opsizes) {
	    cli_errmsg("bytecode: error allocating memory for opsizes\n");
	    return CL_EMEM;
	}
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
    UNUSEDPARAM(ctx);
    UNUSEDPARAM(i);
    UNUSEDPARAM(data);
    UNUSEDPARAM(datalen);
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
	 * read as u64, but accessed as one of these types: u8, u16, u32, u64 */
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
	    free(dat);
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
    unsigned stringlen = 0;
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
	bc->hook_name = cli_strdup(buffer);
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
		    /* for interpreter, pointers 64-bit there */
		    ty->size = ty->align = 8;
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
    for (i=(BC_START_TID - 65);i<bc->num_types-1;i++) {
	struct cli_bc_type *ty = &bc->types[i];
	if (ty->kind == DArrayType) {
	    ty->size = ty->numElements*typesize(bc, ty->containedTypes[0]);
	    ty->align = typealign(bc, ty->containedTypes[0]);
	}
    }
    return CL_SUCCESS;
}

/* checks whether the type described by tid is the same as the one described by
 * apitid. */
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
	if (!ok) {
	    free(apity2ty); /* free temporary map */
	    return CL_EMALFDB;
	}

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
    if (!all_locals) {
	func->types = NULL;
    } else {
	func->types = cli_calloc(all_locals, sizeof(*func->types));
	if (!func->types) {
	    cli_errmsg("Out of memory allocating function arguments\n");
	    return CL_EMEM;
	}
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
		    if (!numOp) {
			inst.u.ops.ops = NULL;
		    } else {
			inst.u.ops.ops = cli_calloc(numOp, sizeof(*inst.u.ops.ops));
			if (!inst.u.ops.ops) {
			    cli_errmsg("Out of memory allocating operands\n");
			    return CL_EMEM;
			}
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
		uint32_t num;
	offset += 3;
	if (offset >= len)
	    return CL_EMALFDB;
	num = (uint32_t)readNumber(buffer, &offset, len, &ok);
	if (!ok)
	    return CL_EMALFDB;
	if (num != bcfunc->numInsts) {
	    cli_errmsg("invalid number of dbg nodes, expected: %u, got: %u\n", bcfunc->numInsts, num);
	    return CL_EMALFDB;
	}
	bcfunc->dbgnodes = cli_malloc(num*sizeof(*bcfunc->dbgnodes));
	if (!bcfunc->dbgnodes) {
        cli_errmsg("Unable to allocate memory for dbg nodes: %u\n", num * (uint32_t)sizeof(*bcfunc->dbgnodes));
	    return CL_EMEM;
    }
	for (i=0; (uint32_t)i < num; i++) {
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
    PARSE_BB,
    PARSE_SKIP
};

struct sigperf_elem {
    const char * bc_name;
    uint64_t usecs;
    unsigned long run_count;
    unsigned long match_count;
};

static int sigelem_comp(const void * a, const void * b)
{
    const struct sigperf_elem *ela = a;
    const struct sigperf_elem *elb = b;
    return elb->usecs/elb->run_count - ela->usecs/ela->run_count;
}

void cli_sigperf_print()
{
    struct sigperf_elem stats[MAX_BC], *elem = stats;
    int i, elems = 0, max_name_len = 0, name_len;

    if (!g_sigid || !g_sigevents) {
        cli_warnmsg("cli_sigperf_print: statistics requested but no bytecodes were loaded!\n");
        return;
    }

    memset(stats, 0, sizeof(stats));
    for (i=0;i<MAX_BC;i++) {
	union ev_val val;
	uint32_t count;
	const char * name = cli_event_get_name(g_sigevents, i*BC_EVENTS_PER_SIG);
	cli_event_get(g_sigevents, i*BC_EVENTS_PER_SIG, &val, &count);
	if (!count) {
	    if (name)
		cli_dbgmsg("No event triggered for %s\n", name);
	    continue;
	}
	if (name)
	name_len = strlen(name);
	else
		name_len = 0;
	if (name_len > max_name_len)
	    max_name_len = name_len;
	elem->bc_name = name?name:"\"noname\"";
	elem->usecs = val.v_int;
	elem->run_count = count;
	cli_event_get(g_sigevents, i*BC_EVENTS_PER_SIG+1, &val, &count);
	elem->match_count = count;
	elem++;
	elems++;
    }
    if (max_name_len < strlen("Bytecode name"))
        max_name_len = strlen("Bytecode name");

    cli_qsort(stats, elems, sizeof(struct sigperf_elem), sigelem_comp);

    elem = stats;
    /* name runs matches microsecs avg */
    cli_infomsg (NULL, "%-*s %*s %*s %*s %*s\n", max_name_len, "Bytecode name",
	    8, "#runs", 8, "#matches", 12, "usecs total", 9, "usecs avg");
    cli_infomsg (NULL, "%-*s %*s %*s %*s %*s\n", max_name_len, "=============",
	    8, "=====", 8, "========", 12, "===========", 9, "=========");
    while (elem->run_count) {
	cli_infomsg (NULL, "%-*s %*lu %*lu %*" PRIu64 " %*.2f\n", max_name_len, elem->bc_name,
		     8, elem->run_count, 8, elem->match_count, 
		12, elem->usecs, 9, (double)elem->usecs/elem->run_count);
	elem++;
    }
}

static void sigperf_events_init(struct cli_bc *bc)
{
    int ret;
    char * bc_name;

    if (!g_sigevents)
	g_sigevents = cli_events_new(MAX_BC_SIGEVENT_ID);

    if (!g_sigevents) {
	cli_errmsg("No memory for events table\n");
	return;
    }

    if (g_sigid > MAX_BC_SIGEVENT_ID - BC_EVENTS_PER_SIG - 1) {
	cli_errmsg("sigperf_events_init: events table full. Increase MAX_BC\n");
	return;
    }

    if (!(bc_name = bc->lsig)) {
	if (!(bc_name = bc->hook_name)) {
	    cli_dbgmsg("cli_event_define error for time event id %d\n", bc->sigtime_id);
	    return;
	}
    }

    cli_dbgmsg("sigperf_events_init(): adding sig ids starting %u for %s\n", g_sigid, bc_name);

    /* register time event */
    bc->sigtime_id = g_sigid;
    ret = cli_event_define(g_sigevents, g_sigid++, bc_name, ev_time, multiple_sum);
    if (ret) {
	cli_errmsg("sigperf_events_init: cli_event_define() error for time event id %d\n", bc->sigtime_id);
	bc->sigtime_id = MAX_BC_SIGEVENT_ID+1;
	return;
    }

    /* register match count */
    bc->sigmatch_id = g_sigid;
    ret = cli_event_define(g_sigevents, g_sigid++, bc_name, ev_int, multiple_sum);
    if (ret) {
	cli_errmsg("sigperf_events_init: cli_event_define() error for matches event id %d\n", bc->sigmatch_id);
	bc->sigmatch_id = MAX_BC_SIGEVENT_ID+1;
	return;
    }
}

void cli_sigperf_events_destroy()
{
    cli_events_free(g_sigevents);
}

int cli_bytecode_load(struct cli_bc *bc, FILE *f, struct cli_dbio *dbio, int trust, int sigperf)
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
    state = PARSE_BC_LSIG;
    if (rc == CL_BREAK) {
	const char *len = strchr(firstbuf, ':');
	bc->state = bc_skip;
	if (!linelength) {
	    linelength = len ? atoi(len+1) : 4096;
	}
	if (linelength < 4096)
	    linelength = 4096;
	cli_dbgmsg("line: %d\n", linelength);
	state = PARSE_SKIP;
	rc = CL_SUCCESS;
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
    while (cli_dbgets(buffer, linelength, f, dbio) && !end) {
	cli_chomp(buffer);
	row++;
	switch (state) {
	    case PARSE_BC_LSIG:
		rc = parseLSig(bc, buffer);
#if 0
DEAD CODE
		if (rc == CL_BREAK) /* skip */ { //FIXME: parseLSig always returns CL_SUCCESS
		    bc->state = bc_skip;
		    state = PARSE_SKIP;
		    continue;
		}
		if (rc != CL_SUCCESS) { //FIXME: parseLSig always returns CL_SUCCESS
		    cli_errmsg("Error at bytecode line %u\n", row);
		    free(buffer);
		    return rc;
		}
#endif
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
		    state = PARSE_SKIP;
		    continue;
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
		    state = PARSE_SKIP;
		    continue;
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
	    case PARSE_SKIP:
		/* stop at S (source code), readdb.c knows how to skip this one
		 * */
		if (buffer[0] == 'S')
		    end = 1;
		/* noop parse, but we need to use dbgets with dynamic buffer,
		 * otherwise we get 'Line too long for provided buffer' */
		break;
	}
    }
    free(buffer);
    cli_dbgmsg("Parsed %d functions\n", current_func);
    if (sigperf)
	sigperf_events_init(bc);
    if (current_func != bc->num_func && bc->state != bc_skip) {
	cli_errmsg("Loaded less functions than declared: %u vs. %u\n",
		   current_func, bc->num_func);
	return CL_EMALFDB;
    }
    return CL_SUCCESS;
}

static struct {
    enum bc_events id;
    const char *name;
    enum ev_type type;
    enum multiple_handling multiple;
} bc_events[] = {
    {BCEV_VIRUSNAME, "virusname", ev_string, multiple_last},
    {BCEV_EXEC_RETURNVALUE, "returnvalue", ev_int, multiple_last},
    {BCEV_WRITE, "bcapi_write", ev_data_fast, multiple_sum},
    {BCEV_OFFSET, "read offset", ev_int, multiple_sum},
    {BCEV_READ, "read data", ev_data_fast, multiple_sum},
    //{BCEV_READ, "read data", ev_data, multiple_concat},
    {BCEV_DBG_STR, "debug message", ev_data_fast, multiple_sum},
    {BCEV_DBG_INT, "debug int", ev_int, multiple_sum},
    {BCEV_MEM_1, "memmem 1", ev_data_fast, multiple_sum},
    {BCEV_MEM_2, "memmem 2", ev_data_fast, multiple_sum},
    {BCEV_FIND, "find", ev_data_fast, multiple_sum},
    {BCEV_EXTRACTED, "extracted files", ev_int, multiple_sum},
    {BCEV_READ_ERR, "read errors", ev_int, multiple_sum},
    {BCEV_DISASM_FAIL, "disasm fails", ev_int, multiple_sum},
    {BCEV_EXEC_TIME, "bytecode execute", ev_time, multiple_sum}
};

static int register_events(cli_events_t *ev)
{
    size_t i;
    for (i=0;i<sizeof(bc_events)/sizeof(bc_events[0]);i++) {
	if (cli_event_define(ev, bc_events[i].id, bc_events[i].name, bc_events[i].type,
			     bc_events[i].multiple) == -1)
	    return -1;
    }
    return 0;
}

int cli_bytecode_run(const struct cli_all_bc *bcs, const struct cli_bc *bc, struct cli_bc_ctx *ctx)
{
    int ret = CL_SUCCESS;
    struct cli_bc_inst inst;
    struct cli_bc_func func;
    cli_events_t *jit_ev = NULL, *interp_ev = NULL;

    int test_mode = 0;
    cli_ctx *cctx =(cli_ctx*)ctx->ctx;

    if (!ctx || !ctx->bc || !ctx->func)
	return CL_ENULLARG;
    if (ctx->numParams && (!ctx->values || !ctx->operands))
	return CL_ENULLARG;

    if (cctx && cctx->engine->bytecode_mode == CL_BYTECODE_MODE_TEST)
	test_mode = 1;

    if (bc->state == bc_loaded) {
	cli_errmsg("bytecode has to be prepared either for interpreter or JIT!\n");
	return CL_EARG;
    }
    if (bc->state == bc_disabled) {
	cli_dbgmsg("bytecode triggered but running bytecodes is disabled\n");
	return CL_SUCCESS;
    }
    if (cctx)
        cli_event_time_start(cctx->perf, PERFT_BYTECODE);
    ctx->env = &bcs->env;
    context_safe(ctx);
    if (test_mode) {
	jit_ev = cli_events_new(BCEV_LASTEVENT);
	interp_ev = cli_events_new(BCEV_LASTEVENT);
	if (!jit_ev || !interp_ev) {
	    cli_events_free(jit_ev);
	    cli_events_free(interp_ev);
	    return CL_EMEM;
	}
	if (register_events(jit_ev) == -1 ||
	    register_events(interp_ev) == -1) {
	    cli_events_free(jit_ev);
	    cli_events_free(interp_ev);
	    return CL_EBYTECODE_TESTFAIL;
	}
    }
    cli_event_time_start(g_sigevents, bc->sigtime_id);
    if (bc->state == bc_interp || test_mode) {
	ctx->bc_events = interp_ev;
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
	cli_dbgmsg("Bytecode %u: executing in interpreter mode\n", bc->id);

	ctx->on_jit = 0;

	cli_event_time_start(interp_ev, BCEV_EXEC_TIME);
	ret = cli_vm_execute(ctx->bc, ctx, &func, &inst);
	cli_event_time_stop(interp_ev, BCEV_EXEC_TIME);

	cli_event_int(interp_ev, BCEV_EXEC_RETURNVALUE, ret);
	cli_event_string(interp_ev, BCEV_VIRUSNAME, ctx->virname);

	/* need to be called here to catch any extracted but not yet scanned files
	*/
	if (ctx->outfd && (ret != CL_VIRUS || cctx->options->general & CL_SCAN_GENERAL_ALLMATCHES))
	    cli_bcapi_extract_new(ctx, -1);
    }
    if (bc->state == bc_jit || test_mode) {
	if (test_mode) {
	    ctx->off = 0;
	}
	ctx->bc_events = jit_ev;
	cli_dbgmsg("Bytecode %u: executing in JIT mode\n", bc->id);

	ctx->on_jit = 1;
	cli_event_time_start(jit_ev, BCEV_EXEC_TIME);
	ret = cli_vm_execute_jit(bcs, ctx, &bc->funcs[ctx->funcid]);
	cli_event_time_stop(jit_ev, BCEV_EXEC_TIME);

	cli_event_int(jit_ev, BCEV_EXEC_RETURNVALUE, ret);
	cli_event_string(jit_ev, BCEV_VIRUSNAME, ctx->virname);

	/* need to be called here to catch any extracted but not yet scanned files
	*/
	if (ctx->outfd && (ret != CL_VIRUS || cctx->options->general & CL_SCAN_GENERAL_ALLMATCHES))
	    cli_bcapi_extract_new(ctx, -1);
    }
    cli_event_time_stop(g_sigevents, bc->sigtime_id);
    if (ctx->virname)
	cli_event_count(g_sigevents, bc->sigmatch_id);

    if (test_mode) {
	unsigned interp_errors = cli_event_errors(interp_ev);
	unsigned jit_errors = cli_event_errors(jit_ev);
	unsigned interp_warns = 0, jit_warns = 0;
	int ok = 1;
	enum bc_events evid;

	if (interp_errors || jit_errors) {
	    cli_infomsg(cctx, "bytecode %d encountered %u JIT and %u interpreter errors\n",
			bc->id, interp_errors, jit_errors);
	    ok = 0;
	}
	if (!ctx->no_diff && cli_event_diff_all(interp_ev, jit_ev, NULL)) {
	    cli_infomsg(cctx, "bytecode %d execution different with JIT and interpreter, see --debug for details\n",
			bc->id);
	    ok = 0;
	}
	for (evid=BCEV_API_WARN_BEGIN+1;evid < BCEV_API_WARN_END;evid++) {
	    union ev_val v;
	    uint32_t count = 0;
	    cli_event_get(interp_ev, evid, &v, &count);
	    interp_warns += count;
	    count = 0;
	    cli_event_get(jit_ev, evid, &v, &count);
	    jit_warns += count;
	}
	if (interp_warns || jit_warns) {
	    cli_infomsg(cctx, "bytecode %d encountered %u JIT and %u interpreter warnings\n",
			bc->id, interp_warns, jit_warns);
	    ok = 0;
	}
	/*cli_event_debug(jit_ev, BCEV_EXEC_TIME);
        cli_event_debug(interp_ev, BCEV_EXEC_TIME);
	cli_event_debug(g_sigevents, bc->sigtime_id);*/
	if (!ok) {
	    cli_events_free(jit_ev);
	    cli_events_free(interp_ev);
	    return CL_EBYTECODE_TESTFAIL;
	}
    }
    cli_events_free(jit_ev);
    cli_events_free(interp_ev);
    if (cctx)
        cli_event_time_stop(cctx->perf, PERFT_BYTECODE);
    return ret;
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
    free(bc->hook_name);
    free(bc->globalBytes);
    memset(bc, 0, sizeof(*bc));
}

#define MAP(val) do { operand_t o = val; \
    if (o & 0x80000000) {\
	o &= 0x7fffffff;\
	if (o > bc->num_globals) {\
	    cli_errmsg("bytecode: global out of range: %u > %u, for instruction %u in function %u\n",\
		       o, (unsigned)bc->num_globals, j, i);\
	    free(map);\
	    free(gmap);\
	    return CL_EBYTECODE;\
	}\
	val = 0x80000000 | gmap[o];\
	break;\
    }\
    if (o >= totValues) {\
	cli_errmsg("bytecode: operand out of range: %u > %u, for instruction %u in function %u\n", o, totValues, j, i);\
	free(map);\
	free(gmap);\
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

static int calc_gepz(struct cli_bc *bc, struct cli_bc_func *func, uint16_t tid, operand_t op)
{
    unsigned off = 0, i;
    uint32_t *gepoff;
    const struct cli_bc_type *ty;
    if (tid >= bc->num_types + 65) {
	cli_errmsg("bytecode: typeid out of range %u >= %u\n", tid, bc->num_types);
	return -1;
    }
    if (tid <= 65) {
	cli_errmsg("bytecode: invalid type for gep (%u)\n", tid);
	return -1;
    }
    ty = &bc->types[tid - 65];
    if (ty->kind != DPointerType || ty->containedTypes[0] < 65) {
	cli_errmsg("bytecode: invalid gep type, must be pointer to nonint: %u\n", tid);
	return -1;
    }
    ty = &bc->types[ty->containedTypes[0] - 65];
    if (ty->kind != DStructType && ty->kind != DPackedStructType)
	return 0;
    gepoff = (uint32_t*)&func->constants[op - func->numValues];
    if (*gepoff >= ty->numElements) {
	cli_errmsg("bytecode: gep offset out of range: %d >= %d\n",(uint32_t)*gepoff, ty->numElements);
	return -1;
    }
    for (i=0;i<*gepoff;i++) {
	off += typesize(bc, ty->containedTypes[i]);
    }
    *gepoff = off;
    return 1;
}

static int cli_bytecode_prepare_interpreter(struct cli_bc *bc)
{
    unsigned i, j, k;
    uint64_t *gmap;
    unsigned bcglobalid = cli_apicall_maxglobal - _FIRST_GLOBAL+2;
    int ret=CL_SUCCESS;
    bc->numGlobalBytes = 0;
    gmap = cli_malloc(bc->num_globals*sizeof(*gmap));
    if (!gmap) {
        cli_errmsg("interpreter: Unable to allocate memory for global map: %zu\n", bc->num_globals*sizeof(*gmap));
        return CL_EMEM;
    }
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
	if (!bc->globalBytes) {
        cli_errmsg("interpreter: Unable to allocate memory for globalBytes: %u\n", bc->numGlobalBytes);
        free(gmap);
	    return CL_EMEM;
    }
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

    for (i=0;i<bc->num_func && ret == CL_SUCCESS;i++) {
	struct cli_bc_func *bcfunc = &bc->funcs[i];
	unsigned totValues = bcfunc->numValues + bcfunc->numConstants + bc->num_globals;
	unsigned *map = cli_malloc(sizeof(*map) * (size_t)totValues);
	if (!map) {
        cli_errmsg("interpreter: Unable to allocate memory for map: %zu\n", sizeof(*map) * (size_t)totValues);
        free(gmap);
	    return CL_EMEM;
    }
	bcfunc->numBytes = 0;
	for (j=0;j<bcfunc->numValues;j++) {
	    uint16_t ty = bcfunc->types[j];
	    unsigned align;
	    align = typealign(bc, ty);
	    assert(!ty || typesize(bc, ty));
	    assert(align);
	    bcfunc->numBytes  = (bcfunc->numBytes + align-1)&(~(align-1));
	    map[j] = bcfunc->numBytes;
	    /* printf("%d -> %d, %u\n", j, map[j], typesize(bc, ty)); */
	    bcfunc->numBytes += typesize(bc, ty);
	    /* TODO: don't allow size 0, it is always a bug! */
	}
	bcfunc->numBytes = (bcfunc->numBytes + 7)&~7;
	for (j=0;j<bcfunc->numConstants;j++) {
	    map[bcfunc->numValues+j] = bcfunc->numBytes;
	    bcfunc->numBytes += 8;
	}
	for (j=0;j<bcfunc->numInsts && ret == CL_SUCCESS;j++) {
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
			    ret = CL_EBYTECODE;
			}
			else if (inst->u.ops.numOps != target->numArgs) {
			    cli_errmsg("bytecode: call operands don't match function prototype\n");
			    ret = CL_EBYTECODE;
			}
		    } else {
			/* APIs have at most 2 parameters always */
			if (inst->u.ops.numOps > 5) {
			    cli_errmsg("bytecode: call operands don't match function prototype\n");
			    ret = CL_EBYTECODE;
			}
		    }
		    if (ret != CL_SUCCESS)
			break;
		    if (inst->u.ops.numOps > 0) {
			inst->u.ops.opsizes = cli_malloc(sizeof(*inst->u.ops.opsizes)*inst->u.ops.numOps);
			if (!inst->u.ops.opsizes) {
			    cli_errmsg("Out of memory when allocating operand sizes\n");
			    ret = CL_EMEM;
			    break;
			}
		    } else {
			inst->u.ops.opsizes = NULL;
			break;
		    }
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
                      ret = CL_EBYTECODE;
                    }
            if (ret != CL_SUCCESS)
                break;
		    MAP(inst->u.three[1]);
		    MAP(inst->u.three[2]);
                    inst->u.three[0] = get_geptypesize(bc, inst->u.three[0]);
                    if ((int)(inst->u.three[0]) == -1)
                      ret = CL_EBYTECODE;
                    break;
		case OP_BC_GEPZ:
		    /*three[0] is the type*/
		    if (inst->u.three[1]&0x80000000 ||
			bcfunc->types[inst->u.three[1]]&0x8000)
			inst->interp_op = 5*(inst->interp_op/5);
		    else
			inst->interp_op = 5*(inst->interp_op/5)+3;
		    MAP(inst->u.three[1]);
		    if (calc_gepz(bc, bcfunc, inst->u.three[0], inst->u.three[2]) == -1)
			ret = CL_EBYTECODE;
            if (ret == CL_SUCCESS)
		        MAP(inst->u.three[2]);
		    break;
/*		case OP_BC_GEPN:
		    *TODO 
		    break;*/
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
		    cli_warnmsg("Bytecode: unhandled opcode: %d\n", inst->opcode);
		    ret = CL_EBYTECODE;
	    }
	}
    if (map)
	    free(map);
    }
    free(gmap);
    bc->state = bc_interp;
    return ret;
}

static int add_selfcheck(struct cli_all_bc *bcs)
{
    struct cli_bc_func *func;
    struct cli_bc_inst *inst;
    struct cli_bc *bc;

    bcs->all_bcs = cli_realloc2(bcs->all_bcs, sizeof(*bcs->all_bcs)*(bcs->count+1));
    if (!bcs->all_bcs) {
	cli_errmsg("cli_loadcbc: Can't allocate memory for bytecode entry\n");
	return CL_EMEM;
    }
    bc = &bcs->all_bcs[bcs->count++];
    memset(bc, 0, sizeof(*bc));

    bc->trusted = 1;
    bc->num_globals = 1;
    bc->globals = cli_calloc(1, sizeof(*bc->globals));
    if (!bc->globals) {
	cli_errmsg("Failed to allocate memory for globals\n");
	return CL_EMEM;
    }
    bc->globals[0] = cli_calloc(1, sizeof(*bc->globals[0]));
    if (!bc->globals[0]) {
	cli_errmsg("Failed to allocate memory for globals\n");
	return CL_EMEM;
    }
    bc->globaltys = cli_calloc(1, sizeof(*bc->globaltys));
    if (!bc->globaltys) {
	cli_errmsg("Failed to allocate memory for globaltypes\n");
	return CL_EMEM;
    }
    bc->globaltys[0] = 32;
    *bc->globals[0] = 0;
    bc->id = ~0;
    bc->kind = 0;
    bc->num_types = 5;
    bc->num_func = 1;
    bc->funcs = cli_calloc(1, sizeof(*bc->funcs));
    if (!bc->funcs) {
	cli_errmsg("Failed to allocate memory for func\n");
	return CL_EMEM;
    }
    func = bc->funcs;
    func->numInsts = 2;
    func->numLocals = 1;
    func->numValues = 1;
    func->numConstants = 1;
    func->numBB = 1;
    func->returnType = 32;
    func->types = cli_calloc(1, sizeof(*func->types));
    if (!func->types) {
	cli_errmsg("Failed to allocate memory for types\n");
	return CL_EMEM;
    }
    func->types[0] = 32;
    func->BB = cli_calloc(1, sizeof(*func->BB));
    if (!func->BB) {
	cli_errmsg("Failed to allocate memory for BB\n");
	return CL_EMEM;
    }
    func->allinsts = cli_calloc(2, sizeof(*func->allinsts));
    if (!func->allinsts) {
	cli_errmsg("Failed to allocate memory for insts\n");
	return CL_EMEM;
    }
    func->BB->numInsts = 2;
    func->BB->insts = func->allinsts;
    func->constants = cli_calloc(1, sizeof(*func->constants));
    if (!func->constants) {
	cli_errmsg("Failed to allocate memory for constants\n");
	return CL_EMEM;
    }
    func->constants[0] = 0xf00d;
    inst = func->allinsts;

    inst->opcode = OP_BC_CALL_API;
    inst->u.ops.numOps = 1;
    inst->u.ops.opsizes = NULL;
    inst->u.ops.ops = cli_calloc(1, sizeof(*inst->u.ops.ops));
    if (!inst->u.ops.ops) {
	cli_errmsg("Failed to allocate memory for instructions\n");
	return CL_EMEM;
    }
    inst->u.ops.ops[0] = 1;
    inst->u.ops.funcid = 18; /* test2 */
    inst->dest = 0;
    inst->type = 32;
    inst->interp_op = inst->opcode* 5 + 3;

    inst = &func->allinsts[1];
    inst->opcode = OP_BC_RET;
    inst->type = 32;
    inst->u.unaryop = 0;
    inst->interp_op = inst->opcode* 5;

    bc->state = bc_loaded;
    return 0;
}

static int run_selfcheck(struct cli_all_bc *bcs)
{
    struct cli_bc_ctx *ctx;
    struct cli_bc *bc = &bcs->all_bcs[bcs->count-1];
    int rc;
    if (bc->state != bc_jit && bc->state != bc_interp) {
	cli_errmsg("Failed to prepare selfcheck bytecode\n");
	return CL_EBYTECODE;
    }
    ctx = cli_bytecode_context_alloc();
    if (!ctx) {
	cli_errmsg("Failed to allocate bytecode context\n");
	return CL_EMEM;
    }
    cli_bytecode_context_setfuncid(ctx, bc, 0);

    cli_dbgmsg("bytecode self test running\n");
    ctx->bytecode_timeout = 0;
    rc = cli_bytecode_run(bcs, bc, ctx);
    cli_bytecode_context_destroy(ctx);
    if (rc != CL_SUCCESS) {
	cli_errmsg("bytecode self test failed: %s\n",
		   cl_strerror(rc));
    } else {
	cli_dbgmsg("bytecode self test succeeded\n");
    }
    return rc;
}

static int selfcheck(int jit, struct cli_bcengine *engine)
{
    struct cli_all_bc bcs;
    int rc;

    memset(&bcs, 0, sizeof(bcs));
    bcs.all_bcs = NULL;
    bcs.count = 0;
    bcs.engine = engine;
    rc = add_selfcheck(&bcs);
    if (rc == CL_SUCCESS) {
	if (jit) {
	    if (!bcs.engine) {
		cli_dbgmsg("bytecode: JIT disabled\n");
		rc = CL_BREAK;/* no JIT - not fatal */
	    } else {
		rc = cli_bytecode_prepare_jit(&bcs);
	    }
	} else {
	    rc = cli_bytecode_prepare_interpreter(bcs.all_bcs);
	}
	if (rc == CL_SUCCESS)
	    rc = run_selfcheck(&bcs);
	if (rc == CL_BREAK)
	    rc = CL_SUCCESS;
    }
    cli_bytecode_destroy(bcs.all_bcs);
    free(bcs.all_bcs);
    cli_bytecode_done_jit(&bcs, 1);
    if (rc != CL_SUCCESS) {
	cli_errmsg("Bytecode: failed to run selfcheck in %s mode: %s\n",
		   jit ? "JIT" : "interpreter", cl_strerror(rc));
    }
    return rc;
}

static int set_mode(struct cl_engine *engine, enum bytecode_mode mode)
{
    if (engine->bytecode_mode == mode)
	return 0;
    if (engine->bytecode_mode == CL_BYTECODE_MODE_OFF) {
	cli_errmsg("bytecode: already turned off, can't turn it on again!\n");
	return -1;
    }
    cli_dbgmsg("Bytecode: mode changed to %d\n", mode);
    if (engine->bytecode_mode == CL_BYTECODE_MODE_TEST) {
	if (mode == CL_BYTECODE_MODE_OFF || have_clamjit) {
	    cli_errmsg("bytecode: in test mode but JIT/bytecode is about to be disabled: %d\n", mode);
	    engine->bytecode_mode = mode;
	    return -1;
	}
	return 0;
    }
    if (engine->bytecode_mode == CL_BYTECODE_MODE_JIT) {
	cli_errmsg("bytecode: in JIT mode but JIT is about to be disabled: %d\n", mode);
	engine->bytecode_mode = mode;
	return -1;
    }
    engine->bytecode_mode = mode;
    return 0;
}

/* runs the first bytecode of the specified kind, or the builtin one if no
 * bytecode of that kind is loaded */
static int run_builtin_or_loaded(struct cli_all_bc *bcs, uint8_t kind, const char* builtin_cbc, struct cli_bc_ctx *ctx, const char *desc)
{
    unsigned i, builtin = 0, rc = 0;
    struct cli_bc *bc = NULL;

    for (i=0;i<bcs->count;i++) {
	bc = &bcs->all_bcs[i];
	if (bc->kind == kind)
	    break;
    }
    if (i == bcs->count)
	bc = NULL;
    if (!bc) {
	/* no loaded bytecode found, load the builtin one! */
	struct cli_dbio dbio;
	bc = cli_calloc(1, sizeof(*bc));
	if (!bc) {
	    cli_errmsg("Out of memory allocating bytecode\n");
	    return CL_EMEM;
	}
	builtin = 1;

	memset(&dbio, 0, sizeof(dbio));
	dbio.usebuf = 1;
	dbio.bufpt = dbio.buf = (char*)builtin_cbc;
	dbio.bufsize = strlen(builtin_cbc)+1;
	if (!dbio.bufsize || dbio.bufpt[dbio.bufsize-2] != '\n') {
	    cli_errmsg("Invalid builtin bytecode: missing terminator\n");
	    free(bc);
	    return CL_EMALFDB;
	}

	rc = cli_bytecode_load(bc, NULL, &dbio, 1, 0);
	if (rc) {
	    cli_errmsg("Failed to load builtin %s bytecode\n", desc);
	    free(bc);
	    return rc;
	}
    }
    rc = cli_bytecode_prepare_interpreter(bc);
    if (rc) {
	cli_errmsg("Failed to prepare %s %s bytecode for interpreter: %s\n",
		   builtin ? "builtin" : "loaded", desc, cl_strerror(rc));
    }
    if (bc->state != bc_interp) {
	cli_errmsg("Failed to prepare %s %s bytecode for interpreter\n",
		   builtin ? "builtin" : "loaded", desc);
	rc = CL_EMALFDB;
    }
    if (!rc) {
	cli_bytecode_context_setfuncid(ctx, bc, 0);
	cli_dbgmsg("Bytecode: %s running (%s)\n", desc,
		   builtin ? "builtin" : "loaded");
	rc = cli_bytecode_run(bcs, bc, ctx);
    }
    if (rc) {
	cli_errmsg("Failed to execute %s %s bytecode: %s\n",builtin ? "builtin":"loaded",
		   desc, cl_strerror(rc));
    }
    if (builtin) {
	cli_bytecode_destroy(bc);
	free(bc);
    }
    return rc;
}

int cli_bytecode_prepare2(struct cl_engine *engine, struct cli_all_bc *bcs, unsigned dconfmask)
{
    unsigned i, interp = 0, jitok = 0, jitcount=0;
    int rc;
    struct cli_bc_ctx *ctx;

    if (!bcs->count) {
	cli_dbgmsg("No bytecodes loaded, not running builtin test\n");
	return CL_SUCCESS;
    }

    engine->bytecode_mode = CL_BYTECODE_MODE_AUTO;
    cli_detect_environment(&bcs->env);
    switch (bcs->env.arch) {
	case arch_i386:
	case arch_x86_64:
	    if (!(dconfmask & BYTECODE_JIT_X86)) {
		cli_dbgmsg("Bytecode: disabled on X86 via DCONF\n");
		if (set_mode(engine, CL_BYTECODE_MODE_INTERPRETER) == -1)
		    return CL_EBYTECODE_TESTFAIL;
	    }
	    break;
	case arch_ppc32:
	case arch_ppc64:
	    if (!(dconfmask & BYTECODE_JIT_PPC)) {
		cli_dbgmsg("Bytecode: disabled on PPC via DCONF\n");
		if (set_mode(engine, CL_BYTECODE_MODE_INTERPRETER) == -1)
		    return CL_EBYTECODE_TESTFAIL;
	    }
	    break;
	case arch_arm:
	    if (!(dconfmask & BYTECODE_JIT_ARM)) {
		cli_dbgmsg("Bytecode: disabled on ARM via DCONF\n");
		if (set_mode(engine, CL_BYTECODE_MODE_INTERPRETER) == -1)
		    return CL_EBYTECODE_TESTFAIL;
	    }
	    break;
	default:
	    cli_dbgmsg("Bytecode: JIT not supported on this architecture, falling back\n");
	    if (set_mode(engine, CL_BYTECODE_MODE_INTERPRETER) == -1)
		return CL_EBYTECODE_TESTFAIL;
	    break;
    }
    cli_dbgmsg("Bytecode: mode is %d\n", engine->bytecode_mode);

    ctx = cli_bytecode_context_alloc();
    if (!ctx) {
	cli_errmsg("Bytecode: failed to allocate bytecode context\n");
	return CL_EMEM;
    }
    rc = run_builtin_or_loaded(bcs, BC_STARTUP, builtin_bc_startup, ctx, "BC_STARTUP");
    if (rc != CL_SUCCESS) {
	cli_warnmsg("Bytecode: BC_STARTUP failed to run, disabling ALL bytecodes! Please report to https://bugzilla.clamav.net\n");
	ctx->bytecode_disable_status = 2;
    } else {
	cli_dbgmsg("Bytecode: disable status is %d\n", ctx->bytecode_disable_status);
	rc = cli_bytecode_context_getresult_int(ctx);
	/* check magic number, don't use 0 here because it is too easy for a
	 * buggy bytecode to return 0 */
	if ((unsigned int)rc != (unsigned int)0xda7aba5e) {
	    cli_warnmsg("Bytecode: selftest failed with code %08x. Please report to https://bugzilla.clamav.net\n",
			rc);
	    if (engine->bytecode_mode == CL_BYTECODE_MODE_TEST)
		return CL_EBYTECODE_TESTFAIL;
	}
    }
    switch (ctx->bytecode_disable_status) {
	case 1:
	    if (set_mode(engine, CL_BYTECODE_MODE_INTERPRETER) == -1)
		return CL_EBYTECODE_TESTFAIL;
	    break;
	case 2:
	    if (set_mode(engine, CL_BYTECODE_MODE_OFF) == -1)
		return CL_EBYTECODE_TESTFAIL;
	    break;
	default:
	    break;
    }
    cli_bytecode_context_destroy(ctx);


    if (engine->bytecode_mode != CL_BYTECODE_MODE_INTERPRETER &&
	engine->bytecode_mode != CL_BYTECODE_MODE_OFF) {
	selfcheck(1, bcs->engine);
	rc = cli_bytecode_prepare_jit(bcs);
	if (rc == CL_SUCCESS) {
	    jitok = 1;
	    cli_dbgmsg("Bytecode: %u bytecode prepared with JIT\n", bcs->count);
	    if (engine->bytecode_mode != CL_BYTECODE_MODE_TEST)
		return CL_SUCCESS;
	}
	if (engine->bytecode_mode == CL_BYTECODE_MODE_JIT) {
	    cli_errmsg("Bytecode: JIT required, but not all bytecodes could be prepared with JIT\n");
	    return CL_EMALFDB;
	}
	if (rc && engine->bytecode_mode == CL_BYTECODE_MODE_TEST) {
	    cli_errmsg("Bytecode: Test mode, but not all bytecodes could be prepared with JIT\n");
	    return CL_EBYTECODE_TESTFAIL;
	}
    } else {
	cli_bytecode_done_jit(bcs, 0);
    }

    if (!(dconfmask & BYTECODE_INTERPRETER)) {
	cli_dbgmsg("Bytecode: needs interpreter, but interpreter is disabled\n");
	if (set_mode(engine, CL_BYTECODE_MODE_OFF) == -1)
	    return CL_EBYTECODE_TESTFAIL;
    }

    if (engine->bytecode_mode == CL_BYTECODE_MODE_OFF) {
	for (i=0;i<bcs->count;i++)
	    bcs->all_bcs[i].state = bc_disabled;
	cli_dbgmsg("Bytecode: ALL bytecodes disabled\n");
	return CL_SUCCESS;
    }

    for (i=0;i<bcs->count;i++) {
	struct cli_bc *bc = &bcs->all_bcs[i];
	if (bc->state == bc_jit) {
	    jitcount++;
	    if (engine->bytecode_mode != CL_BYTECODE_MODE_TEST)
		continue;
	}
	if (bc->state == bc_interp) {
	    interp++;
	    continue;
	}
	rc = cli_bytecode_prepare_interpreter(bc);
	if (rc != CL_SUCCESS) {
	    bc->state = bc_disabled;
	    cli_warnmsg("Bytecode: %d failed to prepare for interpreter mode\n", bc->id);
	    return rc;
	}
	interp++;
    }
    cli_dbgmsg("Bytecode: %u bytecode prepared with JIT, "
	       "%u prepared with interpreter, %u total\n", jitcount, interp, bcs->count);
    return CL_SUCCESS;
}

int cli_bytecode_init(struct cli_all_bc *allbc)
{
    int ret;
    memset(allbc, 0, sizeof(*allbc));
    ret = cli_bytecode_init_jit(allbc, 0/*XXX*/);
    cli_dbgmsg("Bytecode initialized in %s mode\n",
	       allbc->engine ? "JIT" : "interpreter");
    allbc->inited = 1;
    return ret;
}

int cli_bytecode_done(struct cli_all_bc *allbc)
{
    return cli_bytecode_done_jit(allbc, 0);
}

int cli_bytecode_context_setfile(struct cli_bc_ctx *ctx, fmap_t *map)
{
    ctx->fmap = map;
    ctx->file_size = map->len + map->offset;
    ctx->hooks.filesize = &ctx->file_size;
    return 0;
}

int cli_bytecode_runlsig(cli_ctx *cctx, struct cli_target_info *tinfo,
			 const struct cli_all_bc *bcs, unsigned bc_idx,
			 const uint32_t* lsigcnt,
			 const uint32_t *lsigsuboff, fmap_t *map)
{
    int ret;
    struct cli_bc_ctx ctx;
    const struct cli_bc *bc = &bcs->all_bcs[bc_idx-1];
    struct cli_pe_hook_data pehookdata;

    if (bc_idx == 0) 
        return CL_ENULLARG;

    memset(&ctx, 0, sizeof(ctx));
    cli_bytecode_context_setfuncid(&ctx, bc, 0);
    ctx.hooks.match_counts = lsigcnt;
    ctx.hooks.match_offsets = lsigsuboff;
    cli_bytecode_context_setctx(&ctx, cctx);
    cli_bytecode_context_setfile(&ctx, map);
    if (tinfo && tinfo->status == 1) {
	ctx.sections = tinfo->exeinfo.section;
	memset(&pehookdata, 0, sizeof(pehookdata));
	pehookdata.offset = tinfo->exeinfo.offset;
	pehookdata.ep = tinfo->exeinfo.ep;
	pehookdata.nsections = tinfo->exeinfo.nsections;
	pehookdata.hdr_size = tinfo->exeinfo.hdr_size;
	ctx.hooks.pedata = &pehookdata;
	ctx.resaddr = tinfo->exeinfo.res_addr;
    }
    if (bc->hook_lsig_id) {
	cli_dbgmsg("hook lsig id %d matched (bc %d)\n", bc->hook_lsig_id, bc->id);
	/* this is a bytecode for a hook, defer running it until hook is
	 * executed, so that it has all the info for the hook */
	if (cctx->hook_lsig_matches)
	    cli_bitset_set(cctx->hook_lsig_matches, bc->hook_lsig_id-1);
	/* save match counts */
	memcpy(&ctx.lsigcnt, lsigcnt, 64*4);
	memcpy(&ctx.lsigoff, lsigsuboff, 64*4);
	cli_bytecode_context_clear(&ctx);
	return CL_SUCCESS;
    }

    cli_dbgmsg("Running bytecode for logical signature match\n");
    ret = cli_bytecode_run(bcs, bc, &ctx);
    if (ret != CL_SUCCESS) {
	cli_warnmsg("Bytecode %u failed to run: %s\n", bc->id, cl_strerror(ret));
	cli_bytecode_context_clear(&ctx);
	return CL_SUCCESS;
    }
    if (ctx.virname) {
        if (cctx->num_viruses == 0) {
            int rc;
            cli_dbgmsg("Bytecode found virus: %s\n", ctx.virname);
            if (!strncmp(ctx.virname, "BC.Heuristics", 13))
                rc = cli_append_possibly_unwanted(cctx, ctx.virname);
            else
                rc = cli_append_virus(cctx, ctx.virname);
            cli_bytecode_context_clear(&ctx);
            return rc;
        }
        else {
            return CL_VIRUS;
        }
    }
    ret = cli_bytecode_context_getresult_int(&ctx);
    cli_dbgmsg("Bytecode %u returned code: %u\n", bc->id, ret);
    cli_bytecode_context_clear(&ctx);
    return CL_SUCCESS;
}

int cli_bytecode_runhook(cli_ctx *cctx, const struct cl_engine *engine, struct cli_bc_ctx *ctx,
			 unsigned id, fmap_t *map)
{
    const unsigned *hooks = engine->hooks[id - _BC_START_HOOKS];
    unsigned i, hooks_cnt = engine->hooks_cnt[id - _BC_START_HOOKS];
    int ret;
    unsigned executed = 0, breakflag = 0, errorflag = 0;

    if (!cctx)
        return CL_ENULLARG;

    cli_dbgmsg("Bytecode executing hook id %u (%u hooks)\n", id, hooks_cnt);
    /* restore match counts */
    cli_bytecode_context_setfile(ctx, map);
    ctx->hooks.match_counts = ctx->lsigcnt;
    ctx->hooks.match_offsets = ctx->lsigoff;
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
	    cli_warnmsg("Bytecode %u failed to run: %s\n", bc->id, cl_strerror(ret));
	    errorflag = 1;
	    continue;
	}
	if (ctx->virname) {
	    cli_dbgmsg("Bytecode runhook found virus: %s\n", ctx->virname);
	    cli_append_virus(cctx, ctx->virname);
	    if (!(cctx->options->general & CL_SCAN_GENERAL_ALLMATCHES)) {
		cli_bytecode_context_clear(ctx);
		return CL_VIRUS;
	    }
	    cli_bytecode_context_reset(ctx);
	    continue;
	}
	ret = cli_bytecode_context_getresult_int(ctx);
	/* TODO: use prefix here */
	cli_dbgmsg("Bytecode %u returned %u\n", bc->id, ret);
	if (ret == 0xcea5e) {
	    cli_dbgmsg("Bytecode set BREAK flag in hook!\n");
	    breakflag = 1;
	}
	if (!ret) {
	    char *tempfile;
	    int fd = cli_bytecode_context_getresult_file(ctx, &tempfile);
	    if (fd && fd != -1) {
		if (cctx->engine->keeptmp)
		    cli_dbgmsg("Bytecode %u unpacked file saved in %s\n",
			       bc->id, tempfile);
		else
		    cli_dbgmsg("Bytecode %u unpacked file\n", bc->id);
		lseek(fd, 0, SEEK_SET);
		cli_dbgmsg("***** Scanning unpacked file ******\n");
		cctx->recursion++;
		ret = cli_magic_scandesc(fd, tempfile, cctx);
		cctx->recursion--;
		if (!cctx->engine->keeptmp)
		    if (ftruncate(fd, 0) == -1)
			cli_dbgmsg("ftruncate failed on %d\n", fd);
		close(fd);
		if (!cctx->engine->keeptmp) {
		    if (tempfile && cli_unlink(tempfile))
			ret = CL_EUNLINK;
		}
		free(tempfile);
		if (ret != CL_CLEAN) {
		    if (ret == CL_VIRUS) {
			cli_dbgmsg("Scanning unpacked file by bytecode %u found a virus\n", bc->id);
			if (cctx->options->general & CL_SCAN_GENERAL_ALLMATCHES) {
			    cli_bytecode_context_reset(ctx);
			    continue;
			}
			cli_bytecode_context_clear(ctx);
		    	return ret;
		    }
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
    if (errorflag && cctx->engine->bytecode_mode == CL_BYTECODE_MODE_TEST)
	return CL_EBYTECODE_TESTFAIL;
    return breakflag ? CL_BREAK : CL_CLEAN;
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
    printf("\tcompiled on: (%d) %s",
	   (uint32_t)stamp,
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
	case BC_STARTUP:
	    puts("run on startup (unique)");
	    break;
	case BC_LOGICAL:
	    puts("logical only");
	    break;
	case BC_PE_UNPACKER:
	    puts("PE unpacker hook");
	    break;
    case BC_PE_ALL:
        puts("all PE hook");
        break;
    case BC_PRECLASS:
        puts("preclass hook");
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
		puts("PE files matching logical signature (unpacked)");
	    else
		puts("all PE files! (unpacked)");
	    break;
	case BC_PDF:
	    puts("PDF files");
	    break;
	case BC_PE_ALL:
	    if (bc->lsig)
		puts("PE files matching logical signature");
	    else
		puts("all PE files!");
	    break;
	case BC_PRECLASS:
	    if (bc->lsig)
		puts("PRECLASS files matching logical signature");
	    else
		puts("all PRECLASS files!");
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
	    if (len > (unsigned int)cols) {
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

const char *bc_tystr[] = {
    "DFunctionType",
    "DPointerType",
    "DStructType",
    "DPackedStructType",
    "DArrayType"
};

const char *bc_opstr[] = {
    "OP_BC_NULL",
    "OP_BC_ADD", /* =1*/
    "OP_BC_SUB",
    "OP_BC_MUL",
    "OP_BC_UDIV",
    "OP_BC_SDIV",
    "OP_BC_UREM",
    "OP_BC_SREM",
    "OP_BC_SHL",
    "OP_BC_LSHR",
    "OP_BC_ASHR",
    "OP_BC_AND",
    "OP_BC_OR",
    "OP_BC_XOR",

    "OP_BC_TRUNC",
    "OP_BC_SEXT",
    "OP_BC_ZEXT",

    "OP_BC_BRANCH",
    "OP_BC_JMP",
    "OP_BC_RET",
    "OP_BC_RET_VOID",

    "OP_BC_ICMP_EQ",
    "OP_BC_ICMP_NE",
    "OP_BC_ICMP_UGT",
    "OP_BC_ICMP_UGE",
    "OP_BC_ICMP_ULT",
    "OP_BC_ICMP_ULE",
    "OP_BC_ICMP_SGT",
    "OP_BC_ICMP_SGE",
    "OP_BC_ICMP_SLE",
    "OP_BC_ICMP_SLT",
    "OP_BC_SELECT",
    "OP_BC_CALL_DIRECT",
    "OP_BC_CALL_API",
    "OP_BC_COPY",
    "OP_BC_GEP1",
    "OP_BC_GEPZ",
    "OP_BC_GEPN",
    "OP_BC_STORE",
    "OP_BC_LOAD",
    "OP_BC_MEMSET",
    "OP_BC_MEMCPY",
    "OP_BC_MEMMOVE",
    "OP_BC_MEMCMP",
    "OP_BC_ISBIGENDIAN",
    "OP_BC_ABORT",
    "OP_BC_BSWAP16",
    "OP_BC_BSWAP32",
    "OP_BC_BSWAP64",
    "OP_BC_PTRDIFF32",
    "OP_BC_PTRTOINT64",
    "OP_BC_INVALID" /* last */
};

extern unsigned cli_numapicalls;
static void cli_bytetype_helper(const struct cli_bc *bc, unsigned tid)
{
    unsigned i, j;
    const struct cli_bc_type *ty;

    if (tid & 0x8000) {
        printf("alloc ");
        tid &= 0x7fff;
    }

    if (tid < 65) {
        printf("i%d", tid);
        return;
    }

    i = tid - 65;
    if (i >= bc->num_types) {
        printf("invalid type");
        return;
    }
    ty = &bc->types[i];

    switch (ty->kind) {
    case DFunctionType:
        cli_bytetype_helper(bc, ty->containedTypes[0]);
        printf(" func ( ");
        for (j = 1; j < ty->numElements; ++j) {
            cli_bytetype_helper(bc, ty->containedTypes[0]);
            printf(" ");
        }
        printf(")");
        break;
    case DPointerType:
        cli_bytetype_helper(bc, ty->containedTypes[0]);
        printf("*");
        break;
    case DStructType:
    case DPackedStructType:
        printf("{ ");
        for (j = 0; j < ty->numElements; ++j) {
            cli_bytetype_helper(bc, ty->containedTypes[0]);
            printf(" ");
        }
        printf("}");
        break;
    case DArrayType:
        printf("[");
        printf("%d x ", ty->numElements);
        cli_bytetype_helper(bc, ty->containedTypes[0]);
        printf("]");
        break;
    default:
        printf("unhandled type kind %d, cannot parse", ty->kind);
        break;
    }

}

void cli_bytetype_describe(const struct cli_bc *bc)
{
    unsigned i, tid;

    printf("found %d extra types of %d total, starting at tid %d\n", 
           bc->num_types, 64+bc->num_types, bc->start_tid);

    printf("TID  KIND                INTERNAL\n");
    printf("------------------------------------------------------------------------\n");
    for (i = 0, tid = 65; i < bc->num_types-1; ++i, ++tid) {
        printf("%3d: %-20s", tid, bc_tystr[bc->types[i].kind]);
        cli_bytetype_helper(bc, tid);
        printf("\n");
    }
    printf("------------------------------------------------------------------------\n");
}

void cli_bytevalue_describe(const struct cli_bc *bc, unsigned funcid)
{
    unsigned i, total = 0;
    const struct cli_bc_func *func;

    if (funcid >= bc->num_func) {
        printf("bytecode diagnostic: funcid [%u] outside bytecode numfuncs [%u]\n",
               funcid, bc->num_func);
        return;
    }
    // globals
    printf("found a total of %zu globals\n", bc->num_globals);
    printf("GID  ID    VALUE\n");
    printf("------------------------------------------------------------------------\n");
    for (i = 0; i < bc->num_globals; ++i) {
        printf("%3u [%3u]: ", i, i);
        cli_bytetype_helper(bc, bc->globaltys[i]);
        printf(" unknown\n");
    }
    printf("------------------------------------------------------------------------\n");

    // arguments and local values
    func = &bc->funcs[funcid];
    printf("found %d values with %d arguments and %d locals\n",
           func->numValues, func->numArgs, func->numLocals);
    printf("VID  ID    VALUE\n");
    printf("------------------------------------------------------------------------\n");
    for (i = 0; i < func->numValues; ++i) {
        printf("%3u [%3u]: ", i, total++);
        cli_bytetype_helper(bc, func->types[i]);
        if (i < func->numArgs)
            printf("argument");
        printf("\n");
    }
    printf("------------------------------------------------------------------------\n");
    
    // constants
    printf("found a total of %d constants\n", func->numConstants);
    printf("CID  ID    VALUE\n");
    printf("------------------------------------------------------------------------\n");
    for (i = 0; i < func->numConstants; ++i) {
        printf("%3u [%3u]: " STDu64 "(0x" STDx64 ")\n", i, total++, func->constants[i], func->constants[i]);
    }
    printf("------------------------------------------------------------------------\n");
    printf("found a total of %u total values\n", total);
    printf("------------------------------------------------------------------------\n");
    return;
}

void cli_byteinst_describe(const struct cli_bc_inst *inst, unsigned *bbnum)
{
    unsigned j;
    char inst_str[256];
	const struct cli_apicall *api;

    if (inst->opcode > OP_BC_INVALID) {
        printf("opcode %u[%u] of type %u is not implemented yet!",
               inst->opcode, inst->interp_op/5, inst->interp_op%5);
        return;
    }

    snprintf(inst_str, sizeof(inst_str), "%-20s[%-3d/%3d/%3d]", bc_opstr[inst->opcode], 
             inst->opcode, inst->interp_op, inst->interp_op%inst->opcode);
    printf("%-35s", inst_str);
    switch (inst->opcode) {
        // binary operations
    case OP_BC_ADD:
        printf("%d = %d + %d", inst->dest, inst->u.binop[0], inst->u.binop[1]);
        break;
    case OP_BC_SUB:
        printf("%d = %d - %d", inst->dest, inst->u.binop[0], inst->u.binop[1]);
        break;
    case OP_BC_MUL:
        printf("%d = %d * %d", inst->dest, inst->u.binop[0], inst->u.binop[1]);
        break;
    case OP_BC_UDIV:
        printf("%d = %d / %d", inst->dest, inst->u.binop[0], inst->u.binop[1]);
        break;
    case OP_BC_SDIV:
        printf("%d = %d / %d", inst->dest, inst->u.binop[0], inst->u.binop[1]);
        break;
    case OP_BC_UREM:
        printf("%d = %d %% %d", inst->dest, inst->u.binop[0], inst->u.binop[1]);
        break;
    case OP_BC_SREM:
        printf("%d = %d %% %d", inst->dest, inst->u.binop[0], inst->u.binop[1]);
        break;
    case OP_BC_SHL:
        printf("%d = %d << %d", inst->dest, inst->u.binop[0], inst->u.binop[1]);
        break;
    case OP_BC_LSHR:
        printf("%d = %d >> %d", inst->dest, inst->u.binop[0], inst->u.binop[1]);
        break;
    case OP_BC_ASHR:
        printf("%d = %d >> %d", inst->dest, inst->u.binop[0], inst->u.binop[1]);
        break;
    case OP_BC_AND:
        printf("%d = %d & %d", inst->dest, inst->u.binop[0], inst->u.binop[1]);
        break;
    case OP_BC_OR:
        printf("%d = %d | %d", inst->dest, inst->u.binop[0], inst->u.binop[1]);
        break;
    case OP_BC_XOR:
        printf("%d = %d ^ %d", inst->dest, inst->u.binop[0], inst->u.binop[1]);
        break;

        // casting operations
    case OP_BC_TRUNC:
        printf("%d = %d trunc " STDx64, inst->dest, inst->u.cast.source, inst->u.cast.mask);
        break;
    case OP_BC_SEXT:
        printf("%d = %d sext " STDx64, inst->dest, inst->u.cast.source, inst->u.cast.mask);
        break;
    case OP_BC_ZEXT:
        printf("%d = %d zext " STDx64, inst->dest, inst->u.cast.source, inst->u.cast.mask);
        break;
        
        // control operations (termination instructions)
    case OP_BC_BRANCH:
        printf("br %d ? bb.%d : bb.%d", inst->u.branch.condition,
               inst->u.branch.br_true, inst->u.branch.br_false);
        (*bbnum)++;
        break;
    case OP_BC_JMP:
        printf("jmp bb.%d", inst->u.jump);
        (*bbnum)++;
        break;
    case OP_BC_RET:
        printf("ret %d", inst->u.unaryop);
        (*bbnum)++;
        break;
    case OP_BC_RET_VOID:
        printf("ret void");
        (*bbnum)++;
        break;

        // comparison operations
    case OP_BC_ICMP_EQ:
        printf("%d = (%d == %d)", inst->dest, inst->u.binop[0], inst->u.binop[1]);
        break;
    case OP_BC_ICMP_NE:
        printf("%d = (%d != %d)", inst->dest, inst->u.binop[0], inst->u.binop[1]);
        break;
    case OP_BC_ICMP_UGT:
        printf("%d = (%d > %d)", inst->dest, inst->u.binop[0], inst->u.binop[1]);
        break;
    case OP_BC_ICMP_UGE:
        printf("%d = (%d >= %d)", inst->dest, inst->u.binop[0], inst->u.binop[1]);
        break;
    case OP_BC_ICMP_ULT:
        printf("%d = (%d > %d)", inst->dest, inst->u.binop[0], inst->u.binop[1]);
        break;
    case OP_BC_ICMP_ULE:
        printf("%d = (%d >= %d)", inst->dest, inst->u.binop[0], inst->u.binop[1]);
        break;
    case OP_BC_ICMP_SGT:
        printf("%d = (%d > %d)", inst->dest, inst->u.binop[0], inst->u.binop[1]);
        break;
    case OP_BC_ICMP_SGE:
        printf("%d = (%d >= %d)", inst->dest, inst->u.binop[0], inst->u.binop[1]);
        break;
    case OP_BC_ICMP_SLE:
        printf("%d = (%d <= %d)", inst->dest, inst->u.binop[0], inst->u.binop[1]);
        break;
    case OP_BC_ICMP_SLT:
        printf("%d = (%d < %d)", inst->dest, inst->u.binop[0], inst->u.binop[1]);
        break;
    case OP_BC_SELECT:
        printf("%d = %d ? %d : %d)", inst->dest, inst->u.three[0], 
               inst->u.three[1], inst->u.three[2]);
        break;

        // function calling
    case OP_BC_CALL_DIRECT:
        printf("%d = call F.%d (", inst->dest, inst->u.ops.funcid);
        for (j = 0; j < inst->u.ops.numOps; ++j) {
            if (j == inst->u.ops.numOps-1) {
                printf("%d", inst->u.ops.ops[j]);
            }
            else {
                printf("%d, ", inst->u.ops.ops[j]);
            }
        }
        printf(")");
        break;
    case OP_BC_CALL_API:
        {
            if (inst->u.ops.funcid > cli_numapicalls) {
                printf("apicall FID %d not yet implemented!\n", inst->u.ops.funcid);
                break;
            }
            api = &cli_apicalls[inst->u.ops.funcid];
            switch (api->kind) {
            case 0:
                printf("%d = %s[%d] (%d, %d)", inst->dest, api->name,
                       inst->u.ops.funcid, inst->u.ops.ops[0], inst->u.ops.ops[1]);
                break;
            case 1:
                printf("%d = %s[%d] (p.%d, %d)", inst->dest, api->name,
                       inst->u.ops.funcid, inst->u.ops.ops[0], inst->u.ops.ops[1]);
                break;
            case 2:
                printf("%d = %s[%d] (%d)", inst->dest, api->name,
                       inst->u.ops.funcid, inst->u.ops.ops[0]);
                break;
            case 3:
                printf("p.%d = %s[%d] (%d)", inst->dest, api->name,
                       inst->u.ops.funcid, inst->u.ops.ops[0]);
                break;
            case 4:
                printf("%d = %s[%d] (p.%d, %d, %d, %d, %d)", inst->dest, api->name,
                       inst->u.ops.funcid, inst->u.ops.ops[0], inst->u.ops.ops[1],
                       inst->u.ops.ops[2], inst->u.ops.ops[3], inst->u.ops.ops[4]);
                break;
            case 5:
                printf("%d = %s[%d] ()", inst->dest, api->name,
                       inst->u.ops.funcid);
                break;
            case 6:
                printf("p.%d = %s[%d] (%d, %d)", inst->dest, api->name,
                       inst->u.ops.funcid, inst->u.ops.ops[0], inst->u.ops.ops[1]);
                break;
            case 7:
                printf("%d = %s[%d] (%d, %d, %d)", inst->dest, api->name,
                       inst->u.ops.funcid, inst->u.ops.ops[0], inst->u.ops.ops[1],
                       inst->u.ops.ops[2]);
                break;
            case 8:
                printf("%d = %s[%d] (p.%d, %d, p.%d, %d)", inst->dest, api->name,
                       inst->u.ops.funcid, inst->u.ops.ops[0], inst->u.ops.ops[1],
                       inst->u.ops.ops[2], inst->u.ops.ops[3]);
                break;
            case 9:
                printf("%d = %s[%d] (p.%d, %d, %d)", inst->dest, api->name,
                       inst->u.ops.funcid, inst->u.ops.ops[0], inst->u.ops.ops[1],
                       inst->u.ops.ops[2]);
                break;
            default:
                printf("type %u apicalls not yet implemented!\n", api->kind);
                break;
            }
        }
        break;

        // memory operations
    case OP_BC_COPY:
        printf("cp %d -> %d", inst->u.binop[0], inst->u.binop[1]);
        break;
    case OP_BC_GEP1:
        printf("%d = gep1 p.%d + (%d * %d)", inst->dest, inst->u.three[1],
               inst->u.three[2], inst->u.three[0]);
        break;
    case OP_BC_GEPZ:
        printf("%d = gepz p.%d + (%d)", inst->dest, 
               inst->u.three[1], inst->u.three[2]);
        break;
    case OP_BC_GEPN:
        printf("illegal opcode, impossible");
        break;
    case OP_BC_STORE:
        printf("store %d -> p.%d", inst->u.binop[0], inst->u.binop[1]);
        break;
    case OP_BC_LOAD:
        printf("load  %d <- p.%d", inst->dest, inst->u.unaryop);
        break;

        // llvm intrinsics
    case OP_BC_MEMSET:
        printf("%d = memset (p.%d, %d, %d)", inst->dest, inst->u.three[0],
               inst->u.three[1], inst->u.three[2]);
        break;
    case OP_BC_MEMCPY:
        printf("%d = memcpy (p.%d, p.%d, %d)", inst->dest, inst->u.three[0],
               inst->u.three[1], inst->u.three[2]);
        break;
    case OP_BC_MEMMOVE:
        printf("%d = memmove (p.%d, p.%d, %d)", inst->dest, inst->u.three[0],
               inst->u.three[1], inst->u.three[2]);
        break;
    case OP_BC_MEMCMP:
        printf("%d = memcmp (p.%d, p.%d, %d)", inst->dest, inst->u.three[0],
               inst->u.three[1], inst->u.three[2]);
        break;

        // utility operations
    case OP_BC_ISBIGENDIAN:
        printf("%d = isbigendian()", inst->dest);
        break;
    case OP_BC_ABORT:
        printf("ABORT!!");
        break;
    case OP_BC_BSWAP16:
        printf("%d = bswap16 %d", inst->dest, inst->u.unaryop);
        break;
    case OP_BC_BSWAP32:
        printf("%d = bswap32 %d", inst->dest, inst->u.unaryop);
        break;
    case OP_BC_BSWAP64:
        printf("%d = bswap64 %d", inst->dest, inst->u.unaryop);
        break;
    case OP_BC_PTRDIFF32:
        printf("%d = ptrdiff32 p.%d p.%d", inst->dest, inst->u.binop[0], inst->u.binop[1]);
        break;
    case OP_BC_PTRTOINT64:
        printf("%d = ptrtoint64 p.%d", inst->dest, inst->u.unaryop);
        break;
    case OP_BC_INVALID:  /* last */
        printf("INVALID!!");
        break;

    default:
        // redundant check
        printf("opcode %u[%u] of type %u is not implemented yet!",
               inst->opcode, inst->interp_op/5, inst->interp_op%5);
        break;
    }
}

void cli_bytefunc_describe(const struct cli_bc *bc, unsigned funcid)
{
    unsigned i, bbnum, bbpre;
    const struct cli_bc_func *func;

    if (funcid >= bc->num_func) {
        printf("bytecode diagnostic: funcid [%u] outside bytecode numfuncs [%u]\n",
               funcid, bc->num_func);
        return;
    }

    func = &bc->funcs[funcid];

    printf("FUNCTION ID: F.%d -> NUMINSTS %d\n", funcid, func->numInsts);
    printf("BB   IDX  OPCODE              [ID /IID/MOD]  INST\n");
    printf("------------------------------------------------------------------------\n");
    bbpre = 0; bbnum = 0;
    for (i = 0; i < func->numInsts; ++i) {
        if (bbpre != bbnum) {
            printf("\n");
            bbpre = bbnum;
        }

        printf("%3d  %3d  ", bbnum, i);
        cli_byteinst_describe(&func->allinsts[i], &bbnum);
        printf("\n");
    }
    printf("------------------------------------------------------------------------\n");
}

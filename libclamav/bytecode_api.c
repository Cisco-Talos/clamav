/*
 *  ClamAV bytecode internal API
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

#define _XOPEN_SOURCE 600
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include "cltypes.h"
#include "clambc.h"
#include "bytecode_priv.h"
#include "type_desc.h"
#include "bytecode_api.h"
#include "bytecode_api_impl.h"
#include "others.h"

uint32_t cli_bcapi_test0(struct cli_bc_ctx *ctx, struct foo* s, uint32_t u)
{
    return (s && s->nxt == s && u == 0xdeadbeef) ? 0x12345678 : 0x55;
}

uint32_t cli_bcapi_test1(struct cli_bc_ctx *ctx, uint32_t a, uint32_t b)
{
    return (a==0xf00dbeef && b==0xbeeff00d) ? 0x12345678 : 0x55;
}

int32_t cli_bcapi_read(struct cli_bc_ctx* ctx, uint8_t *data, int32_t size)
{
    if (!ctx->fmap)
	return -1;
    return fmap_readn(ctx->fmap, data, ctx->off, size);
}

int32_t cli_bcapi_seek(struct cli_bc_ctx* ctx, int32_t pos, uint32_t whence)
{
    off_t off;
    if (!ctx->fmap)
	return -1;
    switch (whence) {
	case 0:
	    off = pos;
	    break;
	case 1:
	    off = ctx->off + pos;
	    break;
	case 2:
	    off = ctx->file_size + pos;
	    break;
    }
    if (off < 0 || off > ctx->file_size)
	return -1;
    ctx->off = off;
    return off;
}

uint32_t cli_bcapi_debug_print_str(struct cli_bc_ctx *ctx, const uint8_t *str, uint32_t len)
{
    cli_dbgmsg("bytecode debug: %s\n", str);
    return 0;
}

uint32_t cli_bcapi_debug_print_uint(struct cli_bc_ctx *ctx, uint32_t a, uint32_t b)
{
    cli_dbgmsg("bytecode debug: %u\n", a);
    return 0;
}

/*TODO: compiler should make sure that only constants are passed here, and not
 * pointers to arbitrary locations that may not be valid when bytecode finishes
 * executing */
uint32_t cli_bcapi_setvirusname(struct cli_bc_ctx* ctx, const uint8_t *name, uint32_t len)
{
    ctx->virname = name;
    return 0;
}

uint32_t cli_bcapi_disasm_x86(struct cli_bc_ctx *ctx, struct DISASM_RESULT *res, uint32_t len)
{
    //TODO: call disasm_x86_wrap, which outputs a MARIO struct
}

/* TODO: field in ctx, id of last bytecode that called magicscandesc, reset
 * after hooks/other bytecodes are run. TODO: need a more generic solution
 * to avoid uselessly recursing on bytecode-unpacked files, but also a way to
 * override the limit if we need it in a special situation */
int32_t cli_bcapi_write(struct cli_bc_ctx *ctx, uint8_t*data, int32_t len)
{
    int32_t res;
    cli_ctx *cctx = (cli_ctx*)ctx->ctx;
    if (len < 0) {
	cli_warnmsg("Bytecode API: called with negative length!\n");
	return -1;
    }
    if (ctx->outfd == -1) {
	ctx->tempfile = cli_gentemp(cctx ? cctx->engine->tmpdir : NULL);
	if (!ctx->tempfile) {
	    cli_dbgmsg("Bytecode API: Unable to allocate memory for tempfile\n");
	    return -1;
	}
	ctx->outfd = open(ctx->tempfile, O_RDWR|O_CREAT|O_EXCL|O_TRUNC|O_BINARY, 0600);
	if (ctx->outfd == -1) {
	    cli_warnmsg("Bytecode API: Can't create file %s\n", ctx->tempfile);
	    free(ctx->tempfile);
	    return -1;
	}
    }
    if (cli_checklimits("bytecode api", cctx, ctx->written + len, 0, 0))
	return -1;
    res = cli_writen(ctx->outfd, data, len);
    if (res > 0) ctx->written += res;
    if (res == -1)
	    cli_dbgmsg("Bytecode API: write failed: %s\n", errno);
    return res;
}

uint32_t cli_bcapi_trace_scope(struct cli_bc_ctx *ctx, const const uint8_t *scope, uint32_t scopeid)
{
    if (LIKELY(!ctx->trace_mask))
	return 0;
    if ((ctx->trace_mask&BC_TRACE_FUNC) && (scope != ctx->scope)) {
	ctx->scope = scope;
	ctx->trace_mask |= BC_TRACE_TMP_FUNC;
    }
    if ((ctx->trace_mask&BC_TRACE_SCOPE) && (scopeid != ctx->scopeid)) {
	ctx->scopeid = scopeid;
	ctx->trace_mask |= BC_TRACE_TMP_SCOPE;
    }
}

uint32_t cli_bcapi_trace_source(struct cli_bc_ctx *ctx, const const uint8_t *file, uint32_t line)
{
    if (LIKELY(!ctx->trace_mask))
	return 0;
    if (ctx->trace_mask&BC_TRACE_TMP_FUNC) {
	cli_dbgmsg("[trace] Entering function %s (%s:%u:%u -> %s:%u)\n",
		   ctx->scope,
		   ctx->file ? ctx->file : "??", ctx->lastline,
		   ctx->lastcol, file ? file : "??", line);
	ctx->file = file;
	ctx->lastline = line;
	cli_bytecode_debug_printsrc(ctx);
    } else if (ctx->trace_mask&BC_TRACE_TMP_SCOPE) {
	cli_dbgmsg("[trace] Entering scope (%s:%u:%u -> %s:%u)\n",
		   ctx->file ? ctx->file : "??", ctx->lastline,
		   ctx->lastcol, file ? file : "??", line,
		   ctx->scope);
	ctx->file = file;
	ctx->lastline = line;
	cli_bytecode_debug_printsrc(ctx);
    } else {
	if (ctx->file != file || ctx->lastline != line) {
	    ctx->file = file;
	    ctx->lastline = line;
	    if (ctx->trace_mask&BC_TRACE_LINE)
		ctx->trace_mask |= BC_TRACE_TMP_SRC;
	}
    }
    ctx->trace_mask &= ~(BC_TRACE_TMP_FUNC|BC_TRACE_TMP_SCOPE);
    return 0;
}

uint32_t cli_bcapi_trace_op(struct cli_bc_ctx *ctx, const const uint8_t *op, uint32_t col)
{
    if (LIKELY(!ctx->trace_mask))
	return 0;
    if (ctx->lastcol != col) {
	ctx->lastcol = col;
	if (ctx->trace_mask&BC_TRACE_COL)
	    ctx->trace_mask |= BC_TRACE_TMP_SRC;
    }
    if ((ctx->trace_mask&BC_TRACE_OP) && op) {
	if (ctx->trace_mask&BC_TRACE_TMP_SRC) {
	    cli_dbgmsg("[trace] %s (@%s:%u:%u)\n",
		       op,
		       ctx->file ? ctx->file : "??", ctx->lastline, col);
	    cli_bytecode_debug_printsrc(ctx);
	    ctx->trace_mask &= ~BC_TRACE_TMP_SRC;
	} else
	    cli_dbgmsg("[trace] %s\n", op);
    }
    ctx->trace_mask |= BC_TRACE_TMP_OP;
    return 0;
}

uint32_t cli_bcapi_trace_value(struct cli_bc_ctx *ctx, const const uint8_t* name, uint32_t value)
{
    if (LIKELY(!ctx->trace_mask))
	return 0;
    if ((ctx->trace_mask&BC_TRACE_PARAM) && !(ctx->trace_mask&BC_TRACE_TMP_OP)) {
	if (name)
	    cli_dbgmsg("[trace] param %s = %u\n", name, value);
	ctx->trace_mask &= ~BC_TRACE_TMP_OP;
	return 0;
    }
    if ((ctx->trace_mask&BC_TRACE_VAL) && name) {
	if (ctx->trace_mask&BC_TRACE_TMP_SRC) {
	    cli_dbgmsg("[trace] %s = %u (@%s:%u:%u)\n",
		       name, value,
		       ctx->file ? ctx->file : "??",
		       ctx->lastline, ctx->lastcol);
	    cli_bytecode_debug_printsrc(ctx);
	} else {
	    cli_dbgmsg("[trace] %s = %u\n", name, value);
	}
    } else if (ctx->trace_mask&BC_TRACE_TMP_SRC) {
	cli_dbgmsg("[trace] %s:%u:%u\n",
		   ctx->file ? ctx->file : "??",
		   ctx->lastline, ctx->lastcol);
	cli_bytecode_debug_printsrc(ctx);
    }
    ctx->trace_mask &= ~(BC_TRACE_TMP_SRC|BC_TRACE_TMP_OP);
    return 0;
}

uint32_t cli_bcapi_trace_directory(struct cli_bc_ctx *ctx, const const uint8_t* dir, uint32_t dummy)
{
    if (LIKELY(!ctx->trace_mask))
	return 0;
    ctx->directory = dir;
}

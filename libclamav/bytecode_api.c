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

#ifdef HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include "cltypes.h"
#include "clambc.h"
#include "bytecode.h"
#include "bytecode_priv.h"
#include "type_desc.h"
#include "bytecode_api.h"
#include "bytecode_api_impl.h"
#include "others.h"
#include "pe.h"
#include "disasm.h"

uint32_t cli_bcapi_test0(struct cli_bc_ctx *ctx, struct foo* s, uint32_t u)
{
    return (s && s->nxt == s && u == 0xdeadbeef) ? 0x12345678 : 0x55;
}

uint32_t cli_bcapi_test1(struct cli_bc_ctx *ctx, uint32_t a, uint32_t b)
{
    return (a==0xf00dbeef && b==0xbeeff00d) ? 0x12345678 : 0x55;
}

uint32_t cli_bcapi_test2(struct cli_bc_ctx *ctx, uint32_t a)
{
    return a == 0xf00d ? 0xd00f : 0x5555;
}

int32_t cli_bcapi_read(struct cli_bc_ctx* ctx, uint8_t *data, int32_t size)
{
    int n;
    if (!ctx->fmap)
	return -1;
    if (size < 0) {
	cli_errmsg("bytecode: negative read size: %d\n", size);
	return -1;
    }
    n = fmap_readn(ctx->fmap, data, ctx->off, size);
    if (n <= 0)
	return n;
    ctx->off += n;
    return n;
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

uint32_t cli_bcapi_debug_print_uint(struct cli_bc_ctx *ctx, uint32_t a)
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
    int n;
    const char *buf;
    const char* next;
    if (!res || !ctx->fmap || ctx->off >= ctx->fmap->len)
	return -1;
    /* 32 should be longest instr we support decoding.
     * When we'll support mmx/sse instructions this should be updated! */
    n = MIN(32, ctx->fmap->len - ctx->off);
    buf = fmap_need_off_once(ctx->fmap, ctx->off, n);
    next = cli_disasm_one(buf, n, res, 0);
    if (!next)
	return -1;
    return ctx->off + next - buf;
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
	    cli_dbgmsg("Bytecode API: write failed: %d\n", errno);
    return res;
}

void cli_bytecode_context_set_trace(struct cli_bc_ctx* ctx, unsigned level,
				    bc_dbg_callback_trace trace,
				    bc_dbg_callback_trace_op trace_op,
				    bc_dbg_callback_trace_val trace_val,
				    bc_dbg_callback_trace_ptr trace_ptr)
{
    ctx->trace = trace;
    ctx->trace_op = trace_op;
    ctx->trace_val = trace_val;
    ctx->trace_ptr = trace_ptr;
    ctx->trace_level = level;
}

uint32_t cli_bcapi_trace_scope(struct cli_bc_ctx *ctx, const const uint8_t *scope, uint32_t scopeid)
{
    if (LIKELY(!ctx->trace_level))
	return 0;
    if (ctx->scope != (const char*)scope) {
	ctx->scope = (const char*)scope ? (const char*)scope : "?";
	ctx->scopeid = scopeid;
	ctx->trace_level |= 0x80;/* temporarely increase level to print params */
    } else if ((ctx->trace_level >= trace_scope) && ctx->scopeid != scopeid) {
	ctx->scopeid = scopeid;
	ctx->trace_level |= 0x40;/* temporarely increase level to print location */
    }
    return 0;
}

uint32_t cli_bcapi_trace_directory(struct cli_bc_ctx *ctx, const const uint8_t* dir, uint32_t dummy)
{
    if (LIKELY(!ctx->trace_level))
	return 0;
    ctx->directory = (const char*)dir ? (const char*)dir : "";
    return 0;
}

uint32_t cli_bcapi_trace_source(struct cli_bc_ctx *ctx, const const uint8_t *file, uint32_t line)
{
    if (LIKELY(ctx->trace_level < trace_line))
	return 0;
    if (ctx->file != (const char*)file || ctx->line != line) {
	ctx->col = 0;
	ctx->file =(const char*)file ? (const char*)file : "??";
	ctx->line = line;
    }
    return 0;
}

uint32_t cli_bcapi_trace_op(struct cli_bc_ctx *ctx, const const uint8_t *op, uint32_t col)
{
    if (LIKELY(ctx->trace_level < trace_col))
	return 0;
    if (ctx->trace_level&0xc0) {
	ctx->col = col;
	/* func/scope changed and they needed param/location event */
	ctx->trace(ctx, (ctx->trace_level&0x80) ? trace_func : trace_scope);
	ctx->trace_level &= ~0xc0;
    }
    if (LIKELY(ctx->trace_level < trace_col))
	return 0;
    if (ctx->col != col) {
	ctx->col = col;
	ctx->trace(ctx, trace_col);
    } else {
	ctx->trace(ctx, trace_line);
    }
    if (LIKELY(ctx->trace_level < trace_op))
	return 0;
    if (ctx->trace_op && op)
	ctx->trace_op(ctx, (const char*)op);
    return 0;
}

uint32_t cli_bcapi_trace_value(struct cli_bc_ctx *ctx, const const uint8_t* name, uint32_t value)
{
    if (LIKELY(ctx->trace_level < trace_val))
	return 0;
    if (ctx->trace_level&0x80) {
	if ((ctx->trace_level&0x7f) < trace_param)
	    return 0;
	ctx->trace(ctx, trace_param);
    }
    if (ctx->trace_val && name)
	ctx->trace_val(ctx, name, value);
    return 0;
}

uint32_t cli_bcapi_trace_ptr(struct cli_bc_ctx *ctx, const const uint8_t* ptr, uint32_t dummy)
{
    if (LIKELY(ctx->trace_level < trace_val))
	return 0;
    if (ctx->trace_level&0x80) {
	if ((ctx->trace_level&0x7f) < trace_param)
	    return 0;
	ctx->trace(ctx, trace_param);
    }
    if (ctx->trace_ptr)
	ctx->trace_ptr(ctx, ptr);
    return 0;
}

uint32_t cli_bcapi_pe_rawaddr(struct cli_bc_ctx *ctx, uint32_t rva)
{
  uint32_t ret;
  int err = 0;
  const struct cli_pe_hook_data *pe = ctx->hooks.pedata;
  ret = cli_rawaddr(rva, pe->exe_info.section, pe->exe_info.nsections, &err,
		    ctx->file_size, pe->hdr_size);
  if (err)
    return PE_INVALID_RVA;
  return ret;
}

static inline const char* cli_memmem(const char *haystack, unsigned hlen,
				     const unsigned char *needle, unsigned nlen)
{
    const char *p;
    unsigned char c;
    if (!needle || !haystack)
	return NULL;
    c = *needle++;
    if (nlen == 1)
	return memchr(haystack, c, hlen);

    while (hlen >= nlen) {
	p = haystack;
	haystack = memchr(haystack, c, hlen - nlen + 1);
	if (!haystack)
	    return NULL;
	p = haystack + 1;
	if (!memcmp(p, needle, nlen-1))
	    return haystack;
	hlen -= p - haystack;
	haystack = p;
    }
    return NULL;
}

int32_t cli_bcapi_file_find(struct cli_bc_ctx *ctx, const uint8_t* data, uint32_t len)
{
    char buf[4096];
    fmap_t *map = ctx->fmap;
    uint32_t off = ctx->off, newoff;
    int n;

    if (!map || len > sizeof(buf)/4 || len <= 0)
	return -1;
    for (;;) {
	const char *p;
	n = fmap_readn(map, buf, off, sizeof(buf));
	if ((unsigned)n < len)
	    return -1;
	p = cli_memmem(buf, n, data, len);
	if (p)
	    return off + p - buf;
	off += n-len;
    }
    return -1;
}

int32_t cli_bcapi_file_byteat(struct cli_bc_ctx *ctx, uint32_t off)
{
    unsigned char c;
    if (!ctx->fmap)
	return -1;
    if (fmap_readn(ctx->fmap, &c, off, 1) != 1)
	return -1;
    return c;
}

uint8_t* cli_bcapi_malloc(struct cli_bc_ctx *ctx, uint32_t size)
{
#if USE_MPOOL
    if (!ctx->mpool) {
	ctx->mpool = mpool_create();
	if (!ctx->mpool) {
	    cli_dbgmsg("bytecode: mpool_create failed!\n");
	    return NULL;
	}
    }
    return mpool_malloc(ctx->mpool, size);
#else
    /* TODO: implement using a list of pointers we allocated! */
    cli_errmsg("cli_bcapi_malloc not implemented for systems without mmap yet!\n");
    return NULL;
#endif
}


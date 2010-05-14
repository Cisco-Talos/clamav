/*
 *  ClamAV bytecode internal API
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
#include <math.h>
#include <ctype.h>
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
#include "scanners.h"
#include "jsparse/js-norm.h"
#include "hashtab.h"
#include "str.h"
#include "filetypes.h"

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
    if (size < 0 || size > CLI_MAX_ALLOCATION) {
	cli_warnmsg("bytecode: negative read size: %d\n", size);
	return -1;
    }
/*    cli_dbgmsg("read data at %d\n", ctx->off);*/
    n = fmap_readn(ctx->fmap, data, ctx->off, size);
    if (n <= 0) {
	cli_dbgmsg("bcapi_read: fmap_readn failed\n");
	return n;
    }
    ctx->off += n;
    return n;
}

int32_t cli_bcapi_seek(struct cli_bc_ctx* ctx, int32_t pos, uint32_t whence)
{
    off_t off;
    if (!ctx->fmap) {
	cli_dbgmsg("bcapi_seek: no fmap\n");
	return -1;
    }
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
	default:
	    cli_dbgmsg("bcapi_seek: invalid whence value\n");
	    return -1;
    }
    if (off < 0 || off > ctx->file_size) {
	cli_dbgmsg("bcapi_seek: out of file: %ld (max %d)\n",
		   off, ctx->file_size);
	return -1;
    }
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
    if (!cli_debug_flag)
	return 0;
    return fprintf(stderr, "%d", a);
}

/*TODO: compiler should make sure that only constants are passed here, and not
 * pointers to arbitrary locations that may not be valid when bytecode finishes
 * executing */
uint32_t cli_bcapi_setvirusname(struct cli_bc_ctx* ctx, const uint8_t *name, uint32_t len)
{
    ctx->virname = (const char*)name;
    return 0;
}

uint32_t cli_bcapi_disasm_x86(struct cli_bc_ctx *ctx, struct DISASM_RESULT *res, uint32_t len)
{
    int n;
    const unsigned char *buf;
    const unsigned char* next;
    if (!res || !ctx->fmap || ctx->off >= ctx->fmap->len)
	return -1;
    /* 32 should be longest instr we support decoding.
     * When we'll support mmx/sse instructions this should be updated! */
    n = MIN(32, ctx->fmap->len - ctx->off);
    buf = fmap_need_off_once(ctx->fmap, ctx->off, n);
    next = cli_disasm_one(buf, n, res, 0);
    if (!next) {
	cli_dbgmsg("bcapi_disasm: failed\n");
	return -1;
    }
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
    if (!ctx->outfd) {
	ctx->tempfile = cli_gentemp(cctx ? cctx->engine->tmpdir : NULL);
	if (!ctx->tempfile) {
	    cli_dbgmsg("Bytecode API: Unable to allocate memory for tempfile\n");
	    return -1;
	}
	ctx->outfd = open(ctx->tempfile, O_RDWR|O_CREAT|O_EXCL|O_TRUNC|O_BINARY, 0600);
	if (ctx->outfd == -1) {
	    ctx->outfd = 0;
	    cli_warnmsg("Bytecode API: Can't create file %s\n", ctx->tempfile);
	    free(ctx->tempfile);
	    return -1;
	}
	cli_dbgmsg("bytecode opened new tempfile: %s\n", ctx->tempfile);
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

uint32_t cli_bcapi_trace_scope(struct cli_bc_ctx *ctx, const uint8_t *scope, uint32_t scopeid)
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

uint32_t cli_bcapi_trace_directory(struct cli_bc_ctx *ctx, const uint8_t* dir, uint32_t dummy)
{
    if (LIKELY(!ctx->trace_level))
	return 0;
    ctx->directory = (const char*)dir ? (const char*)dir : "";
    return 0;
}

uint32_t cli_bcapi_trace_source(struct cli_bc_ctx *ctx, const uint8_t *file, uint32_t line)
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

uint32_t cli_bcapi_trace_op(struct cli_bc_ctx *ctx, const uint8_t *op, uint32_t col)
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

uint32_t cli_bcapi_trace_value(struct cli_bc_ctx *ctx, const uint8_t* name, uint32_t value)
{
    if (LIKELY(ctx->trace_level < trace_val))
	return 0;
    if (ctx->trace_level&0x80) {
	if ((ctx->trace_level&0x7f) < trace_param)
	    return 0;
	ctx->trace(ctx, trace_param);
    }
    if (ctx->trace_val && name)
	ctx->trace_val(ctx, (const char*)name, value);
    return 0;
}

uint32_t cli_bcapi_trace_ptr(struct cli_bc_ctx *ctx, const uint8_t* ptr, uint32_t dummy)
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
  unsigned err = 0;
  const struct cli_pe_hook_data *pe = ctx->hooks.pedata;
  ret = cli_rawaddr(rva, ctx->sections, pe->nsections, &err,
		    ctx->file_size, pe->hdr_size);
  if (err) {
    cli_dbgmsg("bcapi_pe_rawaddr invalid rva: %u\n", rva);
    return PE_INVALID_RVA;
  }
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
	hlen -= haystack+1 - p;
	p = haystack + 1;
	if (!memcmp(p, needle, nlen-1))
	    return haystack;
	haystack = p;
    }
    return NULL;
}

int32_t cli_bcapi_file_find(struct cli_bc_ctx *ctx, const uint8_t* data, uint32_t len)
{
    fmap_t *map = ctx->fmap;
    if (!map || len <= 0) {
	cli_dbgmsg("bcapi_file_find preconditions not met\n");
	return -1;
    }
    return cli_bcapi_file_find_limit(ctx, data, len, map->len);
}

int32_t cli_bcapi_file_find_limit(struct cli_bc_ctx *ctx , const uint8_t* data, uint32_t len, int32_t limit)
{
    char buf[4096];
    fmap_t *map = ctx->fmap;
    uint32_t off = ctx->off;
    int n;

    if (!map || len > sizeof(buf)/4 || len <= 0 || limit <= 0) {
	cli_dbgmsg("bcapi_file_find_limit preconditions not met\n");
	return -1;
    }
    for (;;) {
	const char *p;
	int32_t readlen = sizeof(buf);
	if (off + readlen > limit) {
	    readlen = limit - off;
	    if (readlen < 0)
		return -1;
	}
	n = fmap_readn(map, buf, off, readlen);
	if ((unsigned)n < len || n < 0)
	    return -1;
	p = cli_memmem(buf, n, data, len);
	if (p)
	    return off + p - buf;
	off += n;
    }
    return -1;
}

int32_t cli_bcapi_file_byteat(struct cli_bc_ctx *ctx, uint32_t off)
{
    unsigned char c;
    if (!ctx->fmap) {
	cli_dbgmsg("bcapi_file_byteat: no fmap\n");
	return -1;
    }
    if (fmap_readn(ctx->fmap, &c, off, 1) != 1) {
	cli_dbgmsg("bcapi_file_byteat: fmap_readn failed at %u\n", off);
	return -1;
    }
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
    return cli_malloc(size);
#endif
}

int32_t cli_bcapi_get_pe_section(struct cli_bc_ctx *ctx, struct cli_exe_section* section, uint32_t num)
{
    if (num < ctx->hooks.pedata->nsections) {
	memcpy(section, &ctx->sections[num], sizeof(*section));
	return 0;
    }
    return -1;
}

int32_t cli_bcapi_fill_buffer(struct cli_bc_ctx *ctx, uint8_t* buf,
			      uint32_t buflen, uint32_t filled,
			      uint32_t pos, uint32_t fill)
{
    int32_t res, remaining, tofill;
    if (!buf || !buflen || buflen > CLI_MAX_ALLOCATION || filled > buflen) {
	cli_dbgmsg("fill_buffer1\n");
	return -1;
    }
    if (ctx->off >= ctx->file_size) {
	cli_dbgmsg("fill_buffer2\n");
	return 0;
    }
    remaining = filled - pos;
    if (remaining) {
	if (!CLI_ISCONTAINED(buf, buflen, buf+pos, remaining)) {
	    cli_dbgmsg("fill_buffer3\n");
	    return -1;
	}
	memmove(buf, buf+pos, remaining);
    }
    tofill = buflen - remaining;
    if (!CLI_ISCONTAINED(buf, buflen, buf+remaining, tofill)) {
	cli_dbgmsg("fill_buffer4\n");
	return -1;
    }
    res = cli_bcapi_read(ctx, buf+remaining, tofill);
    if (res <= 0) {
	cli_dbgmsg("fill_buffer5\n");
	return res;
    }
    return remaining + res;
}

int32_t cli_bcapi_extract_new(struct cli_bc_ctx *ctx, int32_t id)
{
    cli_ctx *cctx;
    int res = -1;
    cli_dbgmsg("previous tempfile had %u bytes\n", ctx->written);
    if (!ctx->written)
	return 0;
    if (ctx->ctx && cli_updatelimits(ctx->ctx, ctx->written))
	return -1;
    ctx->written = 0;
    lseek(ctx->outfd, 0, SEEK_SET);
    cli_dbgmsg("bytecode: scanning extracted file %s\n", ctx->tempfile);
    cctx = (cli_ctx*)ctx->ctx;
    if (cctx) {
	cli_file_t current = cctx->container_type;
	if (ctx->containertype != CL_TYPE_ANY)
	    cctx->container_type = ctx->containertype;
	res = cli_magic_scandesc(ctx->outfd, cctx);
	cctx->container_type = current;
	if (res == CL_VIRUS)
	    ctx->found = 1;
    }
    if ((cctx && cctx->engine->keeptmp) ||
	(ftruncate(ctx->outfd, 0) == -1)) {

	close(ctx->outfd);
	if (!(cctx && cctx->engine->keeptmp) && ctx->tempfile)
	    cli_unlink(ctx->tempfile);
	free(ctx->tempfile);
	ctx->tempfile = NULL;
	ctx->outfd = 0;
    }
    cli_dbgmsg("bytecode: extracting new file with id %u\n", id);
    return res;
}

#define BUF 16
int32_t cli_bcapi_read_number(struct cli_bc_ctx *ctx, uint32_t radix)
{
    unsigned i;
    char *p;
    int32_t result;

    if ((radix != 10 && radix != 16) || !ctx->fmap)
	return -1;
    while ((p = fmap_need_off_once(ctx->fmap, ctx->off, BUF))) {
	for (i=0;i<BUF;i++) {
	    if (p[i] >= '0' && p[i] <= '9') {
		char *endptr;
		p = fmap_need_ptr_once(ctx->fmap, p+i, 16);
		if (!p)
		    return -1;
		result = strtoul(p, &endptr, radix);
		ctx->off += i + (endptr - p);
		return result;
	    }
	}
	ctx->off += BUF;
    }
    return -1;
}

int32_t cli_bcapi_hashset_new(struct cli_bc_ctx *ctx )
{
    unsigned  n = ctx->nhashsets+1;
    struct cli_hashset *s = cli_realloc(ctx->hashsets, sizeof(*ctx->hashsets)*n);
    if (!s)
	return -1;
    ctx->hashsets = s;
    ctx->nhashsets = n;
    s = &s[n-1];
    cli_hashset_init(s, 16, 80);
    return n-1;
}

static struct cli_hashset *get_hashset(struct cli_bc_ctx *ctx, int32_t id)
{
    if (id < 0 || id >= ctx->nhashsets || !ctx->hashsets)
	return NULL;
    return &ctx->hashsets[id];
}

int32_t cli_bcapi_hashset_add(struct cli_bc_ctx *ctx , int32_t id, uint32_t key)
{
    struct cli_hashset *s = get_hashset(ctx, id);
    if (!s)
	return -1;
    return cli_hashset_addkey(s, key);
}

int32_t cli_bcapi_hashset_remove(struct cli_bc_ctx *ctx , int32_t id, uint32_t key)
{
    struct cli_hashset *s = get_hashset(ctx, id);
    if (!s)
	return -1;
    return cli_hashset_removekey(s, key);
}

int32_t cli_bcapi_hashset_contains(struct cli_bc_ctx *ctx , int32_t id, uint32_t key)
{
    struct cli_hashset *s = get_hashset(ctx, id);
    if (!s)
	return -1;
    return cli_hashset_contains(s, key);
}

int32_t cli_bcapi_hashset_empty(struct cli_bc_ctx *ctx, int32_t id)
{
    struct cli_hashset *s = get_hashset(ctx, id);
    return !s->count;
}

int32_t cli_bcapi_hashset_done(struct cli_bc_ctx *ctx , int32_t id)
{
    struct cli_hashset *s = get_hashset(ctx, id);
    if (!s)
	return -1;
    cli_hashset_destroy(s);
    if (id == ctx->nhashsets-1) {
	ctx->nhashsets--;
	if (!ctx->nhashsets) {
	    free(ctx->hashsets);
	    ctx->hashsets = NULL;
	} else {
	    s = cli_realloc(ctx->hashsets, ctx->nhashsets*sizeof(*s));
	    if (s)
		ctx->hashsets = s;
	}
    }
    return 0;
}

int32_t cli_bcapi_buffer_pipe_new(struct cli_bc_ctx *ctx, uint32_t size)
{
    unsigned char *data;
    struct bc_buffer *b;
    unsigned n = ctx->nbuffers + 1;

    data = cli_calloc(1, size);
    if (!data)
	return -1;
    b = cli_realloc(ctx->buffers, sizeof(*ctx->buffers)*n);
    if (!b) {
	free(data);
	return -1;
    }
    ctx->buffers = b;
    ctx->nbuffers = n;
    b = &b[n-1];

    b->data = data;
    b->size = size;
    b->write_cursor = b->read_cursor = 0;
    return n-1;
}

int32_t cli_bcapi_buffer_pipe_new_fromfile(struct cli_bc_ctx *ctx , uint32_t at)
{
    struct bc_buffer *b;
    unsigned n = ctx->nbuffers + 1;

    if (at >= ctx->file_size)
	return -1;

    b = cli_realloc(ctx->buffers, sizeof(*ctx->buffers)*n);
    if (!b) {
	return -1;
    }
    ctx->buffers = b;
    ctx->nbuffers = n;
    b = &b[n-1];

    /* NULL data means read from file at pos read_cursor */
    b->data = NULL;
    b->size = 0;
    b->read_cursor = at;
    b->write_cursor = 0;
    return n-1;
}

static struct bc_buffer *get_buffer(struct cli_bc_ctx *ctx, int32_t id)
{
    if (!ctx->buffers || id < 0 || id >= ctx->nbuffers) {
	cli_dbgmsg("bytecode api: invalid buffer id %u\n", id);
	return NULL;
    }
    return &ctx->buffers[id];
}

uint32_t cli_bcapi_buffer_pipe_read_avail(struct cli_bc_ctx *ctx , int32_t id)
{
    struct bc_buffer *b = get_buffer(ctx, id);
    if (!b)
	return 0;
    if (b->data) {
	if (b->write_cursor <= b->read_cursor)
	    return 0;
	return b->write_cursor - b->read_cursor;
    }
    if (!ctx->fmap || b->read_cursor >= ctx->file_size)
	return 0;
    if (b->read_cursor + BUFSIZ <= ctx->file_size)
	return BUFSIZ;
    return ctx->file_size - b->read_cursor;
}

uint8_t* cli_bcapi_buffer_pipe_read_get(struct cli_bc_ctx *ctx , int32_t id, uint32_t size)
{
    struct bc_buffer *b = get_buffer(ctx, id);
    if (!b || size > cli_bcapi_buffer_pipe_read_avail(ctx, id) || !size)
	return NULL;
    if (b->data)
	return b->data + b->read_cursor;
    return fmap_need_off(ctx->fmap, b->read_cursor, size);
}

int32_t cli_bcapi_buffer_pipe_read_stopped(struct cli_bc_ctx *ctx , int32_t id, uint32_t amount)
{
    struct bc_buffer *b = get_buffer(ctx, id);
    if (!b)
	return -1;
    if (b->data) {
	if (b->write_cursor <= b->read_cursor)
	    return -1;
	if (b->read_cursor + amount > b->write_cursor)
	    b->read_cursor = b->write_cursor;
	else
	    b->read_cursor += amount;
	if (b->read_cursor >= b->size &&
	    b->write_cursor >= b->size)
	    b->read_cursor = b->write_cursor = 0;
	return 0;
    }
    b->read_cursor += amount;
    return 0;
}

uint32_t cli_bcapi_buffer_pipe_write_avail(struct cli_bc_ctx *ctx, int32_t id)
{
    struct bc_buffer *b = get_buffer(ctx, id);
    if (!b)
	return 0;
    if (!b->data)
	return 0;
    if (b->write_cursor >= b->size)
	return 0;
    return b->size - b->write_cursor;
}

uint8_t* cli_bcapi_buffer_pipe_write_get(struct cli_bc_ctx *ctx, int32_t id, uint32_t size)
{
    struct bc_buffer *b = get_buffer(ctx, id);
    if (!b || size > cli_bcapi_buffer_pipe_write_avail(ctx, id) || !size)
	return NULL;
    if (!b->data)
	return NULL;
    return b->data + b->write_cursor;
}

int32_t cli_bcapi_buffer_pipe_write_stopped(struct cli_bc_ctx *ctx , int32_t id, uint32_t size)
{
    struct bc_buffer *b = get_buffer(ctx, id);
    if (!b || !b->data)
	return -1;
    if (b->write_cursor + size >= b->size)
	b->write_cursor = b->size;
    else
	b->write_cursor += size;
    return 0;
}

int32_t cli_bcapi_buffer_pipe_done(struct cli_bc_ctx *ctx , int32_t id)
{
    struct bc_buffer *b = get_buffer(ctx, id);
    if (!b)
	return -1;
    free(b->data);
    b->data = NULL;
    return -0;
}

int32_t cli_bcapi_inflate_init(struct cli_bc_ctx *ctx, int32_t from, int32_t to, int32_t windowBits)
{
    int ret;
    z_stream stream;
    struct bc_inflate *b;
    unsigned n = ctx->ninflates + 1;
    if (!get_buffer(ctx, from) || !get_buffer(ctx, to)) {
	cli_dbgmsg("bytecode api: inflate_init: invalid buffers!\n");
	return -1;
    }
    memset(&stream, 0, sizeof(stream));
    ret = inflateInit2(&stream, windowBits);
    switch (ret) {
	case Z_MEM_ERROR:
	    cli_dbgmsg("bytecode api: inflateInit2: out of memory!\n");
	    return -1;
	case Z_VERSION_ERROR:
	    cli_dbgmsg("bytecode api: inflateinit2: zlib version error!\n");
	    return -1;
	case Z_STREAM_ERROR:
	    cli_dbgmsg("bytecode api: inflateinit2: zlib stream error!\n");
	    return -1;
	case Z_OK:
	    break;
	default:
	    cli_dbgmsg("bytecode api: inflateInit2: unknown error %d\n", ret);
	    return -1;
    }

    b = cli_realloc(ctx->inflates, sizeof(*ctx->inflates)*n);
    if (!b) {
	inflateEnd(&stream);
	return -1;
    }
    ctx->inflates = b;
    ctx->ninflates = n;
    b = &b[n-1];

    b->from = from;
    b->to = to;
    b->needSync = 0;
    memcpy(&b->stream, &stream, sizeof(stream));
    return n-1;
}

static struct bc_inflate *get_inflate(struct cli_bc_ctx *ctx, int32_t id)
{
    if (id < 0 || id >= ctx->ninflates || !ctx->inflates)
	return NULL;
    return &ctx->inflates[id];
}

int32_t cli_bcapi_inflate_process(struct cli_bc_ctx *ctx , int32_t id)
{
    int ret;
    unsigned avail_in_orig, avail_out_orig;
    struct bc_inflate *b = get_inflate(ctx, id);
    if (!b || b->from == -1 || b->to == -1)
	return -1;

    b->stream.avail_in = avail_in_orig =
	cli_bcapi_buffer_pipe_read_avail(ctx, b->from);

    b->stream.next_in = cli_bcapi_buffer_pipe_read_get(ctx, b->from,
						       b->stream.avail_in);

    b->stream.avail_out = avail_out_orig =
	cli_bcapi_buffer_pipe_write_avail(ctx, b->to);

    b->stream.next_out = cli_bcapi_buffer_pipe_write_get(ctx, b->to,
							 b->stream.avail_out);

    if (!b->stream.avail_in || !b->stream.avail_out || !b->stream.next_in || !b->stream.next_out)
	return -1;
    /* try hard to extract data, skipping over corrupted data */
    do {
	if (!b->needSync) {
	    ret = inflate(&b->stream, Z_NO_FLUSH);
	    if (ret == Z_DATA_ERROR) {
		cli_dbgmsg("bytecode api: inflate at %lu: %s, trying to recover\n", b->stream.total_in,
			   b->stream.msg);
		b->needSync = 1;
	    }
	}
	if (b->needSync) {
	    ret = inflateSync(&b->stream);
	    if (ret == Z_OK) {
		cli_dbgmsg("bytecode api: successfully recovered inflate stream\n");
		b->needSync = 0;
		continue;
	    }
	}
	break;
    } while (1);
    cli_bcapi_buffer_pipe_read_stopped(ctx, b->from, avail_in_orig - b->stream.avail_in);
    cli_bcapi_buffer_pipe_write_stopped(ctx, b->to, avail_out_orig - b->stream.avail_out);

    if (ret == Z_MEM_ERROR) {
	cli_dbgmsg("bytecode api: out of memory!\n");
	cli_bcapi_inflate_done(ctx, id);
	return ret;
    }
    if (ret == Z_STREAM_END) {
	cli_bcapi_inflate_done(ctx, id);
    }
    if (ret == Z_BUF_ERROR) {
	cli_dbgmsg("bytecode api: buffer error!\n");
    }

    return ret;
}

int32_t cli_bcapi_inflate_done(struct cli_bc_ctx *ctx , int32_t id)
{
    int ret;
    struct bc_inflate *b = get_inflate(ctx, id);
    if (!b || b->from == -1 || b->to == -1)
	return -1;
    ret = inflateEnd(&b->stream);
    if (ret == Z_STREAM_ERROR)
	cli_dbgmsg("bytecode api: inflateEnd: %s\n", b->stream.msg);
    b->from = b->to = -1;
    return ret;
}

int32_t cli_bcapi_bytecode_rt_error(struct cli_bc_ctx *ctx , int32_t id)
{
    int32_t line = id >> 8;
    int32_t col = id&0xff;
    cli_warnmsg("Bytecode runtime error at line %u, col %u\n", line, col);
    return 0;
}

int32_t cli_bcapi_jsnorm_init(struct cli_bc_ctx *ctx, int32_t from)
{
    struct parser_state *state;
    struct bc_jsnorm *b;
    unsigned  n = ctx->njsnorms + 1;
    if (!get_buffer(ctx, from)) {
	cli_dbgmsg("bytecode api: jsnorm_init: invalid buffers!\n");
	return -1;
    }
    state = cli_js_init();
    if (!state)
	return -1;
    b = cli_realloc(ctx->jsnorms, sizeof(*ctx->jsnorms)*n);
    if (!b) {
	cli_js_destroy(state);
	return -1;
    }
    ctx->jsnorms = b;
    ctx->njsnorms = n;
    b = &b[n-1];
    b->from = from;
    b->state = state;
    if (!ctx->jsnormdir) {
	cli_ctx *cctx = (cli_ctx*)ctx->ctx;
	ctx->jsnormdir = cli_gentemp(cctx ? cctx->engine->tmpdir : NULL);
	if (ctx->jsnormdir) {
	    if (mkdir(ctx->jsnormdir, 0700)) {
		cli_dbgmsg("js: can't create temp dir %s\n", ctx->jsnormdir);
		free(ctx->jsnormdir);
		return CL_ETMPDIR;
	    }
	}
    }
    return n-1;
}

static struct bc_jsnorm *get_jsnorm(struct cli_bc_ctx *ctx, int32_t id)
{
    if (id < 0 || id >= ctx->njsnorms || !ctx->jsnorms)
	return NULL;
    return &ctx->jsnorms[id];
}

int32_t cli_bcapi_jsnorm_process(struct cli_bc_ctx *ctx, int32_t id)
{
    unsigned avail;
    unsigned char *in;
    cli_ctx *cctx = ctx->ctx;
    struct bc_jsnorm *b = get_jsnorm(ctx, id);
    if (!b || b->from == -1 || !b->state)
	return -1;

    avail = cli_bcapi_buffer_pipe_read_avail(ctx, b->from);
    in = cli_bcapi_buffer_pipe_read_get(ctx, b->from, avail);
    if (!avail || !in)
	return -1;
    if (cctx && cli_checklimits("bytecode js api", cctx, ctx->jsnormwritten + avail, 0, 0))
	return -1;
    cli_bcapi_buffer_pipe_read_stopped(ctx, b->from, avail);
    cli_js_process_buffer(b->state, (char*)in, avail);
    return 0;
}

int32_t cli_bcapi_jsnorm_done(struct cli_bc_ctx *ctx , int32_t id)
{
    struct bc_jsnorm *b = get_jsnorm(ctx, id);
    if (!b || b->from == -1)
	return -1;
    if (ctx->ctx && cli_updatelimits(ctx->ctx, ctx->jsnormwritten))
	return -1;
    ctx->jsnormwritten = 0;
    cli_js_parse_done(b->state);
    cli_js_output(b->state, ctx->jsnormdir);
    cli_js_destroy(b->state);
    b->from = -1;
    return 0;
}

static inline double myround(double a)
{
    if (a < 0)
	return a-0.5;
    return a+0.5;
}

int32_t cli_bcapi_ilog2(struct cli_bc_ctx *ctx, uint32_t a, uint32_t b)
{
    double f;
    if (!b)
	return 0x7fffffff;
    /* log(a/b) is -32..32, so 2^26*32=2^31 covers the entire range of int32 */
    f = (1<<26)*log((double)a / b) / log(2);
    return (int32_t)myround(f);
}

int32_t cli_bcapi_ipow(struct cli_bc_ctx *ctx, int32_t a, int32_t b, int32_t c)
{
    if (!a && b < 0)
	return 0x7fffffff;
    return (int32_t)myround(c*pow(a,b));
}

uint32_t cli_bcapi_iexp(struct cli_bc_ctx *ctx, int32_t a, int32_t b, int32_t c)
{
    double f;
    if (!b)
	return 0x7fffffff;
    f= c*exp((double)a/b);
    return (uint32_t)myround(f);
}

int32_t cli_bcapi_isin(struct cli_bc_ctx *ctx, int32_t a, int32_t b, int32_t c)
{
    double f;
    if (!b)
	return 0x7fffffff;
    f = c*sin((double)a/b);
    return (int32_t)myround(f);
}

int32_t cli_bcapi_icos(struct cli_bc_ctx *ctx, int32_t a, int32_t b, int32_t c)
{
    double f;
    if (!b)
	return 0x7fffffff;
    f = c*cos((double)a/b);
    return (int32_t)myround(f);
}

int32_t cli_bcapi_memstr(struct cli_bc_ctx *ctx, const uint8_t* h, int32_t hs,
			 const uint8_t*n, int32_t ns)
{
    const uint8_t *s;
    if (!h || !n || hs < 0 || ns < 0)
	return -1;
    s = cli_memstr(h, hs, n, ns);
    if (!s)
	return -1;
    return s - h;
}

int32_t cli_bcapi_hex2ui(struct cli_bc_ctx *ctx, uint32_t ah, uint32_t bh)
{
    uint8_t result = 0;
    unsigned char in[2];
    in[0] = ah;
    in[1] = bh;

    if (cli_hex2str_to(in, &result, 2) == -1)
	return -1;
    return result;
}

int32_t cli_bcapi_atoi(struct cli_bc_ctx *ctx, const uint8_t* str, int32_t len)
{
    int32_t number = 0;
    const uint8_t *end = str + len;
    while (isspace(*str) && str < end) str++;
    if (str == end)
	return -1;/* all spaces */
    if (*str == '+') str++;
    if (str == end)
	return -1;/* all spaces and +*/
    if (*str == '-')
	return -1;/* only positive numbers */
    if (!isdigit(*str))
	return -1;
    while (isdigit(*str) && str < end) {
	number = number*10 + (*str - '0');
    }
    return number;
}

uint32_t cli_bcapi_debug_print_str_start(struct cli_bc_ctx *ctx , const uint8_t* s, uint32_t len)
{
    if (!s || len <= 0)
	return -1;
    cli_dbgmsg("bytecode debug: %.*s", len, s);
    return 0;
}

uint32_t cli_bcapi_debug_print_str_nonl(struct cli_bc_ctx *ctx , const uint8_t* s, uint32_t len)
{
    if (!s || len <= 0)
	return -1;
    if (!cli_debug_flag)
	return 0;
    return fwrite(s, 1, len, stderr);
}

uint32_t cli_bcapi_entropy_buffer(struct cli_bc_ctx *ctx , uint8_t* s, int32_t len)
{
    uint32_t probTable[256];
    unsigned i;
    double entropy = 0;
    double log2 = log(2);

    if (!s || len <= 0)
	return -1;
    memset(probTable, 0, sizeof(probTable));
    for (i=0;i<len;i++) {
	probTable[s[i]]++;
    }
    for (i=0;i<256;i++) {
	double p;
	if (!probTable[i])
	    continue;
	p = (double)probTable[i] / len;
	entropy += -p*log(p)/log2;
    }
    entropy *= 1<<26;
    return (uint32_t)entropy;
}

int32_t cli_bcapi_map_new(struct cli_bc_ctx *ctx, int32_t keysize, int32_t valuesize)
{
    unsigned n = ctx->nmaps+1;
    struct cli_map *s;
    if (!keysize)
	return -1;
    s = cli_realloc(ctx->maps, sizeof(*ctx->maps)*n);
    if (!s)
	return -1;
    ctx->maps = s;
    ctx->nmaps = n;
    s = &s[n-1];
    cli_map_init(s, keysize, valuesize, 16);
    return n-1;
}

static struct cli_map *get_hashtab(struct cli_bc_ctx *ctx, int32_t id)
{
    if (id < 0 || id >= ctx->nmaps || !ctx->maps)
	return NULL;
    return &ctx->maps[id];
}

int32_t cli_bcapi_map_addkey(struct cli_bc_ctx *ctx , const uint8_t* key, int32_t keysize, int32_t id)
{
    struct cli_map *s = get_hashtab(ctx, id);
    if (!s)
	return -1;
    return cli_map_addkey(s, key, keysize);
}

int32_t cli_bcapi_map_setvalue(struct cli_bc_ctx *ctx, const uint8_t* value, int32_t valuesize, int32_t id)
{
    struct cli_map *s = get_hashtab(ctx, id);
    if (!s)
	return -1;
    return cli_map_setvalue(s, value, valuesize);
}

int32_t cli_bcapi_map_remove(struct cli_bc_ctx *ctx , const uint8_t* key, int32_t keysize, int32_t id)
{
    struct cli_map *s = get_hashtab(ctx, id);
    if (!s)
	return -1;
    return cli_map_removekey(s, key, keysize);
}

int32_t cli_bcapi_map_find(struct cli_bc_ctx *ctx , const uint8_t* key, int32_t keysize, int32_t id)
{
    struct cli_map *s = get_hashtab(ctx, id);
    if (!s)
	return -1;
    return cli_map_find(s, key, keysize);
}

int32_t cli_bcapi_map_getvaluesize(struct cli_bc_ctx *ctx, int32_t id)
{
    struct cli_map *s = get_hashtab(ctx, id);
    if (!s)
	return -1;
    return cli_map_getvalue_size(s);
}

uint8_t* cli_bcapi_map_getvalue(struct cli_bc_ctx *ctx , int32_t id, int32_t valuesize)
{
    struct cli_map *s = get_hashtab(ctx, id);
    if (!s)
	return NULL;
    if (cli_map_getvalue_size(s) != valuesize)
	return NULL;
    return cli_map_getvalue(s);
}

int32_t cli_bcapi_map_done(struct cli_bc_ctx *ctx , int32_t id)
{
    struct cli_map *s = get_hashtab(ctx, id);
    if (!s)
	return -1;
    cli_map_delete(s);
    if (id == ctx->nmaps-1) {
	ctx->nmaps--;
	if (!ctx->nmaps) {
	    free(ctx->maps);
	    ctx->maps = NULL;
	} else {
	    s = cli_realloc(ctx->maps, ctx->nmaps*(sizeof(*s)));
	    if (s)
		ctx->maps = s;
	}
    }
    return 0;
}

uint32_t cli_bcapi_engine_functionality_level(struct cli_bc_ctx *ctx)
{
    return cl_retflevel();
}

uint32_t cli_bcapi_engine_dconf_level(struct cli_bc_ctx *ctx)
{
    return CL_FLEVEL_DCONF;
}

uint32_t cli_bcapi_engine_scan_options(struct cli_bc_ctx *ctx)
{
    cli_ctx *cctx = (cli_ctx*)ctx->ctx;
    return cctx->options;
}

uint32_t cli_bcapi_engine_db_options(struct cli_bc_ctx *ctx)
{
    cli_ctx *cctx = (cli_ctx*)ctx->ctx;
    return cctx->engine->dboptions;
}

int32_t cli_bcapi_extract_set_container(struct cli_bc_ctx *ctx, uint32_t ftype)
{
    if (ftype > CL_TYPE_IGNORED)
	return -1;
    ctx->containertype = ftype;
    return 0;
}

int32_t cli_bcapi_input_switch(struct cli_bc_ctx *ctx , int32_t extracted_file)
{
    fmap_t *map;
    if (ctx->extracted_file_input == extracted_file)
	return 0;
    if (!extracted_file) {
	cli_dbgmsg("bytecode api: input switched back to main file\n");
	ctx->fmap = ctx->save_map;
	ctx->extracted_file_input = 0;
	return 0;
    }
    if (ctx->outfd < 0)
	return -1;
    map = fmap(ctx->outfd, 0, 0);
    if (!map) {
	cli_warnmsg("can't mmap() extracted temporary file %s\n", ctx->tempfile);
	return -1;
    }
    ctx->save_map = ctx->fmap;
    cli_bytecode_context_setfile(ctx, map);
    ctx->extracted_file_input = 1;
    cli_dbgmsg("bytecode api: input switched to extracted file\n");
    return 0;
}

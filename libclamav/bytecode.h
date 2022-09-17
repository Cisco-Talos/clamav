/*
 *  Load, verify and execute ClamAV bytecode.
 *
 *  Copyright (C) 2013-2022 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
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
#ifndef BYTECODE_H
#define BYTECODE_H
#include "clamav-types.h"
#include "clambc.h"
#include <stdio.h>
#include "fmap.h"
#include "bytecode_detect.h"
#include "platform.h"

struct cli_dbio;
struct cli_bc_ctx;
struct cli_bc_func;
struct cli_bc_value;
struct cli_bc_inst;
struct cli_bc_type;
struct cli_bc_engine;
struct cli_bc_dbgnode;
struct bitset_tag;
struct cl_engine;

enum bc_state {
    bc_skip,
    bc_loaded,
    bc_jit,
    bc_interp,
    bc_disabled
};

struct cli_bc {
    struct bytecode_metadata metadata;
    unsigned id;
    unsigned kind;
    unsigned num_types;
    unsigned num_func;
    struct cli_bc_func *funcs;
    struct cli_bc_type *types;
    uint64_t **globals;
    uint16_t *globaltys;
    size_t num_globals;
    enum bc_state state;
    struct bitset_tag *uses_apis;
    char *lsig;
    char *vnameprefix;
    char **vnames;
    unsigned vnames_cnt;
    uint16_t start_tid;
    struct cli_bc_dbgnode *dbgnodes;
    unsigned dbgnode_cnt;
    unsigned hook_lsig_id;
    unsigned trusted;
    uint32_t numGlobalBytes;
    uint8_t *globalBytes;
    uint32_t sigtime_id, sigmatch_id;
    char *hook_name;
};

struct cli_all_bc {
    struct cli_bc *all_bcs;
    unsigned count;
    struct cli_bcengine *engine;
    struct cli_environment env;
    int inited;
};

struct cli_pe_hook_data;
struct cli_exe_section;
struct pdf_obj;
struct cli_bc_ctx *cli_bytecode_context_alloc(void);
/* FIXME: we can't include others.h because others.h includes us...*/
void cli_bytecode_context_setctx(struct cli_bc_ctx *ctx, void *cctx);
cl_error_t cli_bytecode_context_setfuncid(struct cli_bc_ctx *ctx, const struct cli_bc *bc, unsigned funcid);
cl_error_t cli_bytecode_context_setparam_int(struct cli_bc_ctx *ctx, unsigned i, uint64_t c);
cl_error_t cli_bytecode_context_setparam_ptr(struct cli_bc_ctx *ctx, unsigned i, void *data, unsigned datalen);
cl_error_t cli_bytecode_context_setfile(struct cli_bc_ctx *ctx, fmap_t *map);
cl_error_t cli_bytecode_context_setpe(struct cli_bc_ctx *ctx, const struct cli_pe_hook_data *data, const struct cli_exe_section *sections);
cl_error_t cli_bytecode_context_setpdf(struct cli_bc_ctx *ctx, unsigned phase, unsigned nobjs, struct pdf_obj **objs, uint32_t *pdf_flags, uint32_t pdfsize, uint32_t pdfstartoff);

/* returns file descriptor, sets tempfile. Caller takes ownership, and is
 * responsible for freeing/unlinking */
int cli_bytecode_context_getresult_file(struct cli_bc_ctx *ctx, char **tempfilename);
uint64_t cli_bytecode_context_getresult_int(struct cli_bc_ctx *ctx);
void cli_bytecode_context_destroy(struct cli_bc_ctx *ctx);

#ifdef __cplusplus
extern "C" {
#endif
extern LIBCLAMAV_EXPORT bool have_clamjit();
#ifdef __cplusplus
}
#endif
cl_error_t cli_bytecode_init(struct cli_all_bc *allbc);
cl_error_t cli_bytecode_load(struct cli_bc *bc, FILE *f, struct cli_dbio *dbio, int security, int sigperf);
cl_error_t cli_bytecode_prepare2(struct cl_engine *engine, struct cli_all_bc *allbc, unsigned dconfmask);
cl_error_t cli_bytecode_run(const struct cli_all_bc *bcs, const struct cli_bc *bc, struct cli_bc_ctx *ctx);
void cli_bytecode_destroy(struct cli_bc *bc);
cl_error_t cli_bytecode_done(struct cli_all_bc *allbc);

/* Bytecode IR descriptions */
void cli_bytecode_describe(const struct cli_bc *bc);
void cli_bytetype_describe(const struct cli_bc *bc);
void cli_bytevalue_describe(const struct cli_bc *bc, unsigned funcid);
void cli_byteinst_describe(const struct cli_bc_inst *inst, unsigned *bbnum);
void cli_bytefunc_describe(const struct cli_bc *bc, unsigned funcid);

/* Hooks */
struct cli_exe_info;
struct cli_ctx_tag;
struct cli_target_info;
cl_error_t cli_bytecode_runlsig(struct cli_ctx_tag *ctx, struct cli_target_info *info, const struct cli_all_bc *bcs, unsigned bc_idx, const uint32_t *lsigcnt, const uint32_t *lsigsuboff, fmap_t *map);
cl_error_t cli_bytecode_runhook(struct cli_ctx_tag *cctx, const struct cl_engine *engine, struct cli_bc_ctx *ctx, unsigned id, fmap_t *map);

#ifdef __cplusplus
extern "C" {
#endif

cl_error_t bytecode_init(void);
/* Bytecode internal debug API */
void cli_bytecode_debug(int argc, char **argv);
void cli_bytecode_printversion(void);
void cli_bytecode_debug_printsrc(const struct cli_bc_ctx *ctx);
void cli_printcxxver(void);

typedef void (*bc_dbg_callback_trace)(struct cli_bc_ctx *, unsigned event);
typedef void (*bc_dbg_callback_trace_op)(struct cli_bc_ctx *, const char *op);
typedef void (*bc_dbg_callback_trace_val)(struct cli_bc_ctx *, const char *name, uint32_t value);
typedef void (*bc_dbg_callback_trace_ptr)(struct cli_bc_ctx *, const void *val);
void cli_bytecode_context_set_trace(struct cli_bc_ctx *, unsigned level,
                                    bc_dbg_callback_trace,
                                    bc_dbg_callback_trace_op,
                                    bc_dbg_callback_trace_val,
                                    bc_dbg_callback_trace_ptr);
void cli_sigperf_print(void);
void cli_sigperf_events_destroy(void);
#ifdef __cplusplus
}
#endif

#endif

/*
 *  Load, verify and execute ClamAV bytecode.
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
#ifndef BYTECODE_H
#define BYTECODE_H
#include <stdio.h>
#include "clambc.h"

struct cli_dbio;
struct cli_bc_ctx;
struct cli_bc_func;
struct cli_bc_value;
struct cli_bc_inst;
struct cli_bc_type;
struct cli_bc_engine;
struct bitset_tag;
struct cl_engine;

enum bc_state {
    bc_skip,
    bc_loaded,
    bc_jit,
    bc_interp
};

struct cli_bc {
  unsigned verifier;
  char *sigmaker;
  unsigned id;
  unsigned kind;
  struct bytecode_metadata metadata;
  unsigned num_types;
  unsigned num_func;
  struct cli_bc_func *funcs;
  struct cli_bc_type *types;
  uint64_t **globals;
  uint16_t *globaltys;
  size_t num_globals;
  enum bc_state state;
  uint16_t start_tid;
  struct bitset_tag *uses_apis;
  char *lsig;
  char *vnameprefix;
  char **vnames;
  unsigned vnames_cnt;
};

struct cli_all_bc {
    struct cli_bc *all_bcs;
    unsigned count;
    struct cli_bcengine *engine;
};

struct cli_pe_hook_data;
struct cli_bc_ctx *cli_bytecode_context_alloc(void);
int cli_bytecode_context_setfuncid(struct cli_bc_ctx *ctx, const struct cli_bc *bc, unsigned funcid);
int cli_bytecode_context_setparam_int(struct cli_bc_ctx *ctx, unsigned i, uint64_t c);
int cli_bytecode_context_setparam_ptr(struct cli_bc_ctx *ctx, unsigned i, void *data, unsigned datalen);
int cli_bytecode_context_setfile(struct cli_bc_ctx *ctx, int fd);
int cli_bytecode_context_setpe(struct cli_bc_ctx *ctx, const struct cli_pe_hook_data *data);
int cli_bytecode_context_clear(struct cli_bc_ctx *ctx);
uint64_t cli_bytecode_context_getresult_int(struct cli_bc_ctx *ctx);
void cli_bytecode_context_destroy(struct cli_bc_ctx *ctx);

extern int have_clamjit;
int cli_bytecode_init(struct cli_all_bc *allbc);
int cli_bytecode_load(struct cli_bc *bc, FILE *f, struct cli_dbio *dbio);
int cli_bytecode_prepare(struct cli_all_bc *allbc);
int cli_bytecode_run(const struct cli_all_bc *bcs, const struct cli_bc *bc, struct cli_bc_ctx *ctx);
void cli_bytecode_destroy(struct cli_bc *bc);
int cli_bytecode_done(struct cli_all_bc *allbc);

/* Hooks */
struct cli_exe_info;
int cli_bytecode_runlsig(const struct cli_all_bc *bcs, const struct cli_bc* bc, const char **virname, const uint32_t* lsigcnt, int fd);
int cli_bytecode_runhook(const struct cl_engine *engine, struct cli_bc_ctx *ctx, unsigned id, int fd, const char **virname);

#ifdef __cplusplus
extern "C" {
#endif

void cli_bytecode_debug(int argc, char **argv);
int bytecode_init(void);

#ifdef __cplusplus
}
#endif

#endif

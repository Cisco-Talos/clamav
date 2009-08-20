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
#include "cltypes.h"
#include "others.h"

struct cli_dbio;
struct cli_bc_ctx;
struct cli_bc_func;
struct cli_bc_value;
struct cli_bc_inst;
struct cli_bc_type;

enum bc_state {
    bc_loaded,
    bc_jit,
    bc_interp
};

struct cli_bc {
  unsigned verifier;
  char *sigmaker;
  unsigned id;
  struct bytecode_metadata metadata;
  unsigned num_types;
  unsigned num_func;
  struct cli_bc_func *funcs;
  struct cli_bc_type *types;
  enum bc_state state;
  uint16_t start_tid;
  bitset_t *uses_apis;
};

struct cli_bc_ctx *cli_bytecode_context_alloc(void);
int cli_bytecode_context_setfuncid(struct cli_bc_ctx *ctx, const struct cli_bc *bc, unsigned funcid);
int cli_bytecode_context_setparam_int(struct cli_bc_ctx *ctx, unsigned i, uint64_t c);
int cli_bytecode_context_setparam_ptr(struct cli_bc_ctx *ctx, unsigned i, void *data, unsigned datalen);
int cli_bytecode_context_clear(struct cli_bc_ctx *ctx);
uint64_t cli_bytecode_context_getresult_int(struct cli_bc_ctx *ctx);
void cli_bytecode_context_destroy(struct cli_bc_ctx *ctx);

int cli_bytecode_load(struct cli_bc *bc, FILE *f, struct cli_dbio *dbio);
int cli_bytecode_prepare(struct cli_bc *bc);
int cli_bytecode_run(const struct cli_bc *bc, struct cli_bc_ctx *ctx);
void cli_bytecode_destroy(struct cli_bc *bc);

#endif

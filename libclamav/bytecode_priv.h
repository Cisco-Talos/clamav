/*
 *  Load, verify and execute ClamAV bytecode.
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

#ifndef BYTECODE_PRIV_H
#define BYTECODE_PRIV_H

#include <zlib.h>
#include "bytecode.h"
#include "type_desc.h"
#include "execs.h"
#include "bytecode_hooks.h"
#include "fmap.h"
#include "mpool.h"
#include "hashtab.h"

typedef uint32_t operand_t;
typedef uint16_t bbid_t;
typedef uint16_t funcid_t;

struct cli_bc_callop {
    operand_t* ops;
    uint16_t* opsizes;
    uint8_t numOps;
    funcid_t funcid;
};

struct branch {
    operand_t condition;
    bbid_t br_true;
    bbid_t br_false;
};

struct cli_bc_cast {
    uint64_t mask;
    operand_t source;
    uint8_t size;/* 0: 1-bit, 1: 8b, 2: 16b, 3: 32b, 4: 64b */
};

typedef uint8_t interp_op_t;
struct cli_bc_inst {
    enum bc_opcode opcode;
    uint16_t type;
    interp_op_t interp_op;/* opcode for interpreter */
    operand_t dest;
    union {
	operand_t unaryop;
	struct cli_bc_cast cast;
	operand_t binop[2];
	operand_t three[3];
	struct cli_bc_callop ops;
	struct branch branch;
	bbid_t jump;
    } u;
};

struct cli_bc_bb {
    unsigned numInsts;
    struct cli_bc_inst *insts;
};

struct cli_bc_func {
    uint8_t numArgs;
    uint16_t numLocals;
    uint32_t numInsts;
    uint32_t numValues;/* without constants */
    uint32_t numConstants;
    uint32_t numBytes;/* stack size */
    uint16_t numBB;
    uint16_t returnType;
    uint16_t *types;
    uint32_t insn_idx;
    struct cli_bc_bb *BB;
    struct cli_bc_inst *allinsts;
    uint64_t *constants;
    unsigned *dbgnodes;
};

struct cli_bc_dbgnode_element {
    unsigned nodeid;
    char *string;
    unsigned len;
    uint64_t constant;
};

struct cli_bc_dbgnode {
    unsigned numelements;
    struct cli_bc_dbgnode_element* elements;
};

#define MAX_OP ~0u
enum trace_level {
    trace_none=0,
    trace_func,
    trace_param,
    trace_scope,
    trace_line,
    trace_col,
    trace_op,
    trace_val
};

struct bc_buffer {
    unsigned char *data;
    unsigned size;
    unsigned write_cursor;
    unsigned read_cursor;
};

struct bc_inflate {
    z_stream stream;
    int32_t from;
    int32_t to;
    int8_t  needSync;
};

struct bc_jsnorm {
    struct parser_state *state;
    int32_t from;
};

struct cli_bc_ctx {
    uint8_t timeout;/* must be first byte in struct! */
    /* id and params of toplevel function called */
    const struct cli_bc *bc;
    const struct cli_bc_func *func;
    uint32_t bytecode_timeout;
    unsigned bytes;
    uint16_t *opsizes;
    char *values;
    operand_t *operands;
    uint16_t funcid;
    unsigned numParams;
    uint32_t file_size;
    off_t off;
    fmap_t *fmap;
    fmap_t *save_map;
    const char *virname;
    struct cli_bc_hooks hooks;
    const struct cli_exe_section *sections;
    int outfd;
    char *tempfile;
    void *ctx;
    unsigned written;
    unsigned filewritten;
    unsigned found;
    bc_dbg_callback_trace trace;
    bc_dbg_callback_trace_op trace_op;
    bc_dbg_callback_trace_val trace_val;
    bc_dbg_callback_trace_ptr trace_ptr;
    unsigned trace_level;
    const char *directory;
    const char *file;
    const char *scope;
    uint32_t scopeid;
    unsigned line;
    unsigned col;
    mpool_t *mpool;
    struct bc_inflate* inflates;
    unsigned ninflates;
    struct bc_buffer *buffers;
    unsigned nbuffers;
    struct cli_hashset *hashsets;
    unsigned nhashsets;
    struct bc_jsnorm* jsnorms;
    unsigned njsnorms;
    char *jsnormdir;
    unsigned jsnormwritten;
    struct cli_map *maps;
    unsigned nmaps;
    unsigned containertype;
    unsigned extracted_file_input;
};
struct cli_all_bc;
int cli_vm_execute(const struct cli_bc *bc, struct cli_bc_ctx *ctx, const struct cli_bc_func *func, const struct cli_bc_inst *inst);

#ifdef __cplusplus
extern "C" {
#endif

int cli_vm_execute_jit(const struct cli_all_bc *bcs, struct cli_bc_ctx *ctx, const struct cli_bc_func *func);
int cli_bytecode_prepare_jit(struct cli_all_bc *bc);
int cli_bytecode_init_jit(struct cli_all_bc *bc, unsigned dconfmask);
int cli_bytecode_done_jit(struct cli_all_bc *bc);

#ifdef __cplusplus
}
#endif
#endif

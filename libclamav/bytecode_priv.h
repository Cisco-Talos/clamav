/*
 *  Load, verify and execute ClamAV bytecode.
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
#include "events.h"

typedef uint32_t operand_t;
typedef uint16_t bbid_t;
typedef uint16_t funcid_t;

struct cli_bc_callop {
    operand_t* ops;
    uint16_t* opsizes;
    funcid_t funcid;
    uint8_t numOps;
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
    operand_t dest;
    interp_op_t interp_op;/* opcode for interpreter */
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
    unsigned len;
    char *string;
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

enum bc_events {
    BCEV_VIRUSNAME,
    BCEV_EXEC_RETURNVALUE,
    BCEV_WRITE,
    BCEV_OFFSET,
    BCEV_READ,
    BCEV_DBG_STR,
    BCEV_DBG_INT,
    BCEV_MEM_1,
    BCEV_MEM_2,
    BCEV_FIND,
    BCEV_EXTRACTED,
    BCEV_EXEC_TIME,
    /* API failures (that are not serious), count must be 0 for testmode */
    BCEV_API_WARN_BEGIN,
    BCEV_READ_ERR,
    BCEV_DISASM_FAIL,
    BCEV_API_WARN_END,
    /* real errors (write failure) are reported via cli_event_error_str */
    BCEV_LASTEVENT
};

struct cli_bc_ctx {
    uint8_t timeout;/* must be first byte in struct! */
    uint16_t funcid;
    unsigned numParams;
    /* id and params of toplevel function called */
    const struct cli_bc *bc;
    const struct cli_bc_func *func;
    uint32_t bytecode_timeout;
    unsigned bytes;
    uint16_t *opsizes;
    char *values;
    operand_t *operands;
    uint32_t file_size;
    int outfd;
    off_t off;
    fmap_t *fmap;
    fmap_t *save_map;
    const char *virname;
    struct cli_bc_hooks hooks;
    struct cli_exe_info exeinfo;
    uint32_t lsigcnt[64];
    uint32_t lsigoff[64];
    uint32_t pdf_nobjs;
    struct pdf_obj **pdf_objs;
    uint32_t* pdf_flags;
    uint32_t pdf_size;
    uint32_t pdf_startoff;
    unsigned pdf_phase;
    int32_t pdf_dumpedid;
    const struct cli_exe_section *sections;
    uint32_t resaddr;
    char *tempfile;
    void *ctx;
    unsigned written;
    unsigned filewritten;
    unsigned found;
    unsigned ninflates;
    bc_dbg_callback_trace trace;
    bc_dbg_callback_trace_op trace_op;
    bc_dbg_callback_trace_val trace_val;
    bc_dbg_callback_trace_ptr trace_ptr;
    const char *directory;
    const char *file;
    const char *scope;
    unsigned trace_level;
    uint32_t scopeid;
    unsigned line;
    unsigned col;
    mpool_t *mpool;
    struct bc_inflate* inflates;
    struct bc_buffer *buffers;
    unsigned nbuffers;
    unsigned nhashsets;
    unsigned njsnorms;
    unsigned jsnormwritten;
    struct cli_hashset *hashsets;
    struct bc_jsnorm* jsnorms;
    char *jsnormdir;
    struct cli_map *maps;
    unsigned nmaps;
    unsigned containertype;
    unsigned extracted_file_input;
    const struct cli_environment *env;
    unsigned bytecode_disable_status;
    cli_events_t *bc_events;
    int on_jit;
    int no_diff;
#if HAVE_JSON
    void **jsonobjs;
    unsigned njsonobjs;
#endif
};
struct cli_all_bc;
int cli_vm_execute(const struct cli_bc *bc, struct cli_bc_ctx *ctx, const struct cli_bc_func *func, const struct cli_bc_inst *inst);

#ifdef __cplusplus
extern "C" {
#endif

int cli_vm_execute_jit(const struct cli_all_bc *bcs, struct cli_bc_ctx *ctx, const struct cli_bc_func *func);
int cli_bytecode_prepare_jit(struct cli_all_bc *bc);
int cli_bytecode_init_jit(struct cli_all_bc *bc, unsigned dconfmask);
int cli_bytecode_done_jit(struct cli_all_bc *bc, int partial);

#ifdef __cplusplus
}
#endif
#endif

/*
 *  Execute ClamAV bytecode.
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

#include "clamav.h"
#include "others.h"
#include "bytecode.h"
#include "bytecode_priv.h"
#include "type_desc.h"
#include "readdb.h"
#include <string.h>
#ifndef _WIN32
#include <sys/time.h>
#endif
#include "bytecode_api_impl.h"
#include "disasm-common.h"

/* Enable this to catch more bugs in the RC phase */
#define CL_BYTECODE_SAFE

#ifdef CL_BYTECODE_SAFE
/* These checks will also be done by the bytecode verifier, but for
 * debugging purposes we have explicit checks, these should never fail! */
#ifdef CL_DEBUG
static int never_inline bcfail(const char *msg, long a, long b,
                  const char *file, unsigned line)
{
    cli_warnmsg("bytecode: check failed %s (%lx and %lx) at %s:%u\n", msg, a, b, file, line);
    return CL_EARG;
}
#else
#define bcfail(msg,a,b,f,l) CL_EBYTECODE
#endif

#define CHECK_FUNCID(funcid) do { if (funcid >= bc->num_func) return \
    bcfail("funcid out of bounds!",funcid, bc->num_func,__FILE__,__LINE__); } while(0)
#define CHECK_APIID(funcid) do { if (funcid >= cli_apicall_maxapi) return \
    bcfail("APIid out of bounds!",funcid, cli_apicall_maxapi,__FILE__,__LINE__); } while(0)
#define CHECK_EQ(a, b) do { if ((a) != (b)) return \
    bcfail("Values "#a" and "#b" don't match!",(a),(b),__FILE__,__LINE__); } while(0)
#define CHECK_GT(a, b) do {if ((a) <= (b)) return \
    bcfail("Condition failed "#a" > "#b,(a),(b), __FILE__, __LINE__); } while(0)

#else
static inline int bcfail(const char *msg, long a, long b,
                         const char *file, unsigned line) {}
#define CHECK_FUNCID(x);
#define CHECK_APIID(x);
#define CHECK_EQ(a,b)
#define CHECK_GT(a,b)
#endif
#if 0 /* too verbose, use #ifdef CL_DEBUG if needed */
#define CHECK_UNREACHABLE do { cli_dbgmsg("bytecode: unreachable executed!\n"); return CL_EBYTECODE; } while(0)
#define TRACE_PTR(ptr, s) cli_dbgmsg("bytecode trace: ptr %llx, +%x\n", ptr, s);
#define TRACE_R(x) cli_dbgmsg("bytecode trace: %u, read %llx\n", pc, (long long)x);
#define TRACE_W(x, w, p) cli_dbgmsg("bytecode trace: %u, write%d @%u %llx\n", pc, p, w, (long long)(x));
#define TRACE_EXEC(id, dest, ty, stack) cli_dbgmsg("bytecode trace: executing %d, -> %u (%u); %u\n", id, dest, ty, stack)
#define TRACE_API(s, dest, ty, stack) cli_dbgmsg("bytecode trace: executing %s, -> %u (%u); %u\n", s, dest, ty, stack)
#else
#define CHECK_UNREACHABLE return CL_EBYTECODE
#define TRACE_PTR(ptr, s)
#define TRACE_R(x)
#define TRACE_W(x, w, p)
#define TRACE_EXEC(id, dest, ty, stack)
#define TRACE_API(s, dest, ty, stack)
#endif

#define SIGNEXT(a, from) CLI_SRS(((int64_t)(a)) << (64-(from)), (64-(from)))

#ifdef CL_DEBUG
#undef always_inline
#define always_inline
#endif

static always_inline int jump(const struct cli_bc_func *func, uint16_t bbid, struct cli_bc_bb **bb, const struct cli_bc_inst **inst,
                unsigned *bb_inst)
{
    CHECK_GT(func->numBB, bbid);
    *bb = &func->BB[bbid];
    *inst = (*bb)->insts;
    *bb_inst = 0;
    return 0;
}

#define STACK_CHUNKSIZE 65536

struct stack_chunk {
    struct stack_chunk *prev;
    unsigned used;
    union {
        void *align;
        char data[STACK_CHUNKSIZE];
    } u;
};

struct stack {
    struct stack_chunk* chunk;
    uint16_t last_size;
};

/* type with largest alignment that we use (in general it is a long double, but
 * thats too big alignment for us) */
typedef uint64_t align_t;

static always_inline void* cli_stack_alloc(struct stack *stack, unsigned bytes)
{
    struct stack_chunk *chunk = stack->chunk;
    uint16_t last_size_off;

    /* last_size is stored after data */
    /* align bytes to pointer size */
    bytes = (bytes + sizeof(uint16_t) + sizeof(align_t)) & ~(sizeof(align_t)-1);
    last_size_off = bytes - 2;

    if (chunk && (chunk->used + bytes <= STACK_CHUNKSIZE)) {
        /* there is still room in this chunk */
        void *ret;

        *(uint16_t*)&chunk->u.data[chunk->used + last_size_off] = stack->last_size;
        stack->last_size = bytes/sizeof(align_t);

        ret = chunk->u.data + chunk->used;
        chunk->used += bytes;
        return ret;
    }

    if(bytes >= STACK_CHUNKSIZE) {
        cli_warnmsg("cli_stack_alloc: Attempt to allocate more than STACK_CHUNKSIZE bytes: %u!\n", bytes);
        return NULL;
    }
    /* not enough room here, allocate new chunk */
    chunk = cli_malloc(sizeof(*stack->chunk));
    if (!chunk) {
        cli_warnmsg("cli_stack_alloc: Unable to allocate memory for stack-chunk: bytes: %zu!\n", sizeof(*stack->chunk));
        return NULL;
    }

    *(uint16_t*)&chunk->u.data[last_size_off] = stack->last_size;
    stack->last_size = bytes/sizeof(align_t);

    chunk->used = bytes;
    chunk->prev = stack->chunk;
    stack->chunk = chunk;
    return chunk->u.data;
}

static always_inline void cli_stack_free(struct stack *stack, void *data)
{
    uint16_t last_size;
    struct stack_chunk *chunk = stack->chunk;
    if (!chunk) {
        cli_warnmsg("cli_stack_free: stack empty!\n");
        return;
    }
    if ((chunk->u.data + chunk->used) != ((char*)data + stack->last_size*sizeof(align_t))) {
        cli_warnmsg("cli_stack_free: wrong free order: %p, expected %p\n",
                   data, chunk->u.data + chunk->used - stack->last_size*sizeof(align_t));
        return;
    }
    last_size = *(uint16_t*)&chunk->u.data[chunk->used-2];
    if (chunk->used < stack->last_size*sizeof(align_t)) {
        cli_warnmsg("cli_stack_free: last_size is corrupt!\n");
        return;
    }
    chunk->used -= stack->last_size*sizeof(align_t);
    stack->last_size = last_size;
    if (!chunk->used) {
        stack->chunk = chunk->prev;
        free(chunk);
    }
}

static void cli_stack_destroy(struct stack *stack)
{
    struct stack_chunk *chunk = stack->chunk;
    while (chunk) {
        stack->chunk = chunk->prev;
        free(chunk);
        chunk = stack->chunk;
    }
}

struct stack_entry {
    struct stack_entry *prev;
    const struct cli_bc_func *func;
    operand_t ret;
    unsigned bb_inst;
    struct cli_bc_bb *bb;
    char *values;
};

static always_inline struct stack_entry *allocate_stack(struct stack *stack,
                                                        struct stack_entry *prev,
                                                        const struct cli_bc_func *func,
                                                        const struct cli_bc_func *func_old,
                                                        operand_t ret,
                                                        struct cli_bc_bb *bb,
                                                        unsigned bb_inst)
{
    char *values;
    struct stack_entry *entry = cli_stack_alloc(stack, sizeof(*entry) + sizeof(*values)*func->numBytes);
    if (!entry)
        return NULL;
    entry->prev = prev;
    entry->func = func_old;
    entry->ret = ret;
    entry->bb = bb;
    entry->bb_inst = bb_inst;
    /* we allocated room for values right after stack_entry! */
    entry->values = values = (char*)&entry[1];
    memcpy(&values[func->numBytes - func->numConstants*8], func->constants,
           sizeof(*values)*func->numConstants*8);
    return entry;
}

static always_inline struct stack_entry *pop_stack(struct stack *stack,
                                                   struct stack_entry *stack_entry,
                                                   const struct cli_bc_func **func,
                                                   operand_t *ret,
                                                   struct cli_bc_bb **bb,
                                                   unsigned *bb_inst)
{
    void *data;
    *func = stack_entry->func;
    *ret = stack_entry->ret;
    *bb = stack_entry->bb;
    *bb_inst = stack_entry->bb_inst;
    data = stack_entry;
    stack_entry = stack_entry->prev;
    cli_stack_free(stack, data);
    return stack_entry;
}


/*
 *
 * p, p+1, p+2, p+3 <- gt
    CHECK_EQ((p)&1, 0); 
    CHECK_EQ((p)&3, 0); 
    CHECK_EQ((p)&7, 0); 
*/
#define WRITE8(p, x) CHECK_GT(func->numBytes, p);\
    TRACE_W(x, p, 8);\
    *(uint8_t*)&values[p] = x
#define WRITE16(p, x) CHECK_GT(func->numBytes, p+1);\
    CHECK_EQ((p)&1, 0);\
    TRACE_W(x, p, 16);\
    *(uint16_t*)&values[p] = x
#define WRITE32(p, x) CHECK_GT(func->numBytes, p+3);\
    CHECK_EQ((p)&3, 0);\
    TRACE_W(x, p, 32);\
    *(uint32_t*)&values[p] = x
#define WRITE64(p, x) CHECK_GT(func->numBytes, p+7);\
    CHECK_EQ((p)&7, 0);\
    TRACE_W(x, p, 64);\
    *(uint64_t*)&values[p] = x
#define WRITEP(x, p) CHECK_GT(func->numBytes, p+PSIZE-1);\
    CHECK_EQ((p)&(PSIZE-1), 0);\
    TRACE_W(x, p, PSIZE*8);\
    *(void**)&values[p] = x

#define uint_type(n) uint##n##_t
#define READNfrom(maxBytes, from, x, n, p)\
    CHECK_GT((maxBytes), (p)+(n/8)-1);\
    CHECK_EQ((p)&(n/8-1), 0);\
    x = *(uint_type(n)*)&(from)[(p)];\
    TRACE_R(x)

#define READN(x, n, p)\
 do {\
     if (p&0x80000000) {\
         uint32_t pg = p&0x7fffffff;\
         if (!pg) {\
         x = 0;\
         } else {\
         READNfrom(bc->numGlobalBytes, bc->globalBytes, x, n, pg);\
         }\
     } else {\
         READNfrom(func->numBytes, values, x, n, p);\
     }\
 } while (0)

#define READ1(x, p) READN(x, 8, p);\
    x = x&1
#define READ8(x, p) READN(x, 8, p)
#define READ16(x, p) READN(x, 16, p)
#define READ32(x, p) READN(x, 32, p)
#define READ64(x, p) READN(x, 64, p)

#define PSIZE sizeof(int64_t)
#define READP(x, p, asize) { int64_t iptr__;\
    READN(iptr__, 64, p);\
    x = ptr_torealptr(&ptrinfos, iptr__, (asize));\
    if (!x) {\
        stop = CL_EBYTECODE;\
        break;\
    }\
    TRACE_R(x)\
}
#define READPOP(x, p, asize) {\
    if ((p)&0x40000000) {\
        unsigned ptr__ = (p)&0xbfffffff;\
        CHECK_GT(func->numBytes, ptr__);\
        TRACE_PTR(ptr__, asize);\
        x = (void*)&values[ptr__];\
    } else {\
        READP(x, p, asize)\
    }\
}

#define READOLD8(x, p) CHECK_GT(func->numBytes, p);\
    x = *(uint8_t*)&old_values[p];\
    TRACE_R(x)
#define READOLD16(x, p) CHECK_GT(func->numBytes, p+1);\
    CHECK_EQ((p)&1, 0);\
    x = *(uint16_t*)&old_values[p];\
    TRACE_R(x)
#define READOLD32(x, p) CHECK_GT(func->numBytes, p+3);\
    CHECK_EQ((p)&3, 0);\
    x = *(uint32_t*)&old_values[p];\
    TRACE_R(x)
#define READOLD64(x, p) CHECK_GT(func->numBytes, p+7);\
    CHECK_EQ((p)&7, 0);\
    x = *(uint64_t*)&old_values[p];\
    TRACE_R(x)

#define BINOP(i) inst->u.binop[i]

#define DEFINE_BINOP_BC_HELPER(opc, OP, W0, W1, W2, W3, W4) \
    case opc*5: {\
                    uint8_t op0, op1, res;\
                    int8_t sop0, sop1;\
                    READ1(op0, BINOP(0));\
                    READ1(op1, BINOP(1));\
                    sop0 = op0; sop1 = op1;\
                    OP;\
                    W0(inst->dest, res);\
                    break;\
                }\
    case opc*5+1: {\
                    uint8_t op0, op1, res;\
                    int8_t sop0, sop1;\
                    READ8(op0, BINOP(0));\
                    READ8(op1, BINOP(1));\
                    sop0 = op0; sop1 = op1;\
                    OP;\
                    W1(inst->dest, res);\
                    break;\
                }\
    case opc*5+2: {\
                    uint16_t op0, op1, res;\
                    int16_t sop0, sop1;\
                    READ16(op0, BINOP(0));\
                    READ16(op1, BINOP(1));\
                    sop0 = op0; sop1 = op1;\
                    OP;\
                    W2(inst->dest, res);\
                    break;\
                }\
    case opc*5+3: {\
                    uint32_t op0, op1, res;\
                    int32_t sop0, sop1;\
                    READ32(op0, BINOP(0));\
                    READ32(op1, BINOP(1));\
                    sop0 = op0; sop1 = op1;\
                    OP;\
                    W3(inst->dest, res);\
                    break;\
                }\
    case opc*5+4: {\
                    uint64_t op0, op1, res;\
                    int64_t sop0, sop1;\
                    READ64(op0, BINOP(0));\
                    READ64(op1, BINOP(1));\
                    sop0 = op0; sop1 = op1;\
                    OP;\
                    W4(inst->dest, res);\
                    break;\
                }

#define DEFINE_BINOP(opc, OP) DEFINE_BINOP_BC_HELPER(opc, OP, WRITE8, WRITE8, WRITE16, WRITE32, WRITE64)
#define DEFINE_ICMPOP(opc, OP) DEFINE_BINOP_BC_HELPER(opc, OP, WRITE8, WRITE8, WRITE8, WRITE8, WRITE8)

#define CHECK_OP(cond, msg) if((cond)) { cli_dbgmsg(msg); stop = CL_EBYTECODE; break;}

#define DEFINE_SCASTOP(opc, OP) \
    case opc*5: {\
                    uint8_t res;\
                    int8_t sres;\
                    OP;\
                    WRITE8(inst->dest, res);\
                    break;\
                }\
    case opc*5+1: {\
                    uint8_t res;\
                    int8_t sres;\
                    OP;\
                    WRITE8(inst->dest, res);\
                    break;\
                }\
    case opc*5+2: {\
                    uint16_t res;\
                    int16_t sres;\
                    OP;\
                    WRITE16(inst->dest, res);\
                    break;\
                }\
    case opc*5+3: {\
                    uint32_t res;\
                    int32_t sres;\
                    OP;\
                    WRITE32(inst->dest, res);\
                    break;\
                }\
    case opc*5+4: {\
                    uint64_t res;\
                    int64_t sres;\
                    OP;\
                    WRITE64(inst->dest, res);\
                    break;\
                }
#define DEFINE_CASTOP(opc, OP) DEFINE_SCASTOP(opc, OP; (void)sres)

#define DEFINE_OP(opc) \
    case opc*5: /* fall-through */\
    case opc*5+1: /* fall-through */\
    case opc*5+2: /* fall-through */\
    case opc*5+3: /* fall-through */\
    case opc*5+4:

#define CHOOSE(OP0, OP1, OP2, OP3, OP4) \
    switch (inst->u.cast.size) {\
        case 0: OP0; break;\
        case 1: OP1; break;\
        case 2: OP2; break;\
        case 3: OP3; break;\
        case 4: OP4; break;\
        default: CHECK_UNREACHABLE;\
    }

#define DEFINE_OP_BC_RET_N(OP, T, R0, W0) \
    case OP: {\
                operand_t ret;\
                T tmp;\
                R0(tmp, inst->u.unaryop);\
                CHECK_GT(stack_depth, 0);\
                stack_depth--;\
                stack_entry = pop_stack(&stack, stack_entry, &func, &ret, &bb,\
                                        &bb_inst);\
                values = stack_entry ? stack_entry->values : ctx->values;\
                CHECK_GT(func->numBytes, ret);\
                W0(ret, tmp);\
                if (!bb) {\
                    stop = CL_BREAK;\
                    continue;\
                }\
                stackid = ptr_register_stack(&ptrinfos, values, 0, func->numBytes)>>32;\
                inst = &bb->insts[bb_inst];\
                break;\
            }

struct ptr_info {
    uint8_t *base;
    uint32_t size;
};

struct ptr_infos {
    struct ptr_info *stack_infos;
    struct ptr_info *glob_infos;
    unsigned nstacks, nglobs;
};

static inline int64_t ptr_compose(int32_t id, uint32_t offset)
{
    uint64_t i = id;
    return (i << 32) | offset;
}

static inline int32_t ptr_diff32(int64_t ptr1, int64_t ptr2)
{
    int32_t ptrid1 = ptr1 >> 32;
    int32_t ptrid2 = ptr2 >> 32;
    if (ptrid1 != ptrid2) {
        (void)bcfail("difference of pointers not pointing to same object!", ptrid1, ptrid2, __FILE__, __LINE__);
        /* invalid diff */
        return 0x40000000;
    }
    return (uint32_t)ptr1 - (uint32_t)ptr2;
}

static inline int64_t ptr_register_stack(struct ptr_infos *infos,
                                         char *values,
                                         uint32_t off, uint32_t size)
{
    unsigned n = infos->nstacks + 1;
    struct ptr_info *sinfos = cli_realloc(infos->stack_infos,
                                          sizeof(*sinfos)*n);
    if (!sinfos)
        return 0;
    infos->stack_infos = sinfos;
    infos->nstacks = n;
    sinfos = &sinfos[n-1];
    sinfos->base = (uint8_t*)values + off;
    sinfos->size = size;
    return ptr_compose(-n, 0);
}

static inline int64_t ptr_register_glob_fixedid(struct ptr_infos *infos,
                                                void *values, uint32_t size, unsigned n)
{
    struct ptr_info *sinfos;
    if (n > infos->nglobs) {
        sinfos = cli_realloc(infos->glob_infos, sizeof(*sinfos)*n);
        if (!sinfos)
            return 0;
        memset(sinfos + infos->nglobs, 0, (n - infos->nglobs)*sizeof(*sinfos));
        infos->glob_infos = sinfos;
        infos->nglobs = n;
    }
    sinfos = &infos->glob_infos[n-1];
    if (!values)
        size = 0;
    sinfos->base = values;
    sinfos->size = size;
    cli_dbgmsg("bytecode: registered ctx variable at %p (+%u) id %u\n", values,
               size, n);
    return ptr_compose(n, 0);
}

static inline int64_t ptr_register_glob(struct ptr_infos *infos,
                                        void *values, uint32_t size)
{
    if (!values)
        return 0;
    return ptr_register_glob_fixedid(infos, values, size, infos->nglobs+1);
}

static inline void* ptr_torealptr(const struct ptr_infos *infos, int64_t ptr,
                                  uint32_t read_size)
{
    struct ptr_info *info;
    int32_t ptrid = ptr >> 32;
    uint32_t ptroff = (uint32_t)ptr;
    TRACE_PTR(ptr, read_size);
    if (UNLIKELY(!ptrid)) {
        (void)bcfail("nullptr", ptrid, 0, __FILE__, __LINE__);
        return NULL;
    }
    if (ptrid < 0) {
        ptrid = -ptrid-1;
        if (UNLIKELY((const unsigned int)ptrid >= infos->nstacks)) {
            (void)bcfail("ptr", ptrid, infos->nstacks, __FILE__, __LINE__);
            return NULL;
        }
        info = &infos->stack_infos[ptrid];
    } else {
        ptrid--;
        if (UNLIKELY((const unsigned int)ptrid >= infos->nglobs)) {
            (void)bcfail("ptr", ptrid, infos->nglobs, __FILE__, __LINE__);
            return NULL;
        }
        info = &infos->glob_infos[ptrid];
    }
    if (LIKELY(ptroff < info->size &&
        read_size <= info->size &&
        ptroff + read_size <= info->size)) {
        return info->base+ptroff;
    }

    (void)bcfail("ptr1", ptroff, info->size, __FILE__, __LINE__);
    (void)bcfail("ptr2", read_size, info->size, __FILE__, __LINE__);
    (void)bcfail("ptr3", ptroff+read_size, info->size, __FILE__, __LINE__);
    return NULL;
}

static always_inline int check_sdivops(int64_t op0, int64_t op1)
{
    return op1 == 0 || (op1 == -1 && op0 ==  (-9223372036854775807LL-1LL));
}

static unsigned globaltypesize(uint16_t id)
{
    const struct cli_bc_type *ty;
    if (id <= 64)
        return (id + 7)/8;
    if (id < 69)
        return 8; /* ptr */
    ty = &cli_apicall_types[id - 69];
    switch (ty->kind) {
        case DArrayType:
            return ty->numElements*globaltypesize(ty->containedTypes[0]);
        case DStructType:
        case DPackedStructType:
            {
                unsigned i, s = 0;
                for (i=0;i<ty->numElements;i++)
                    s += globaltypesize(ty->containedTypes[i]);
                return s;
            }
        default:
            return 0;
    }
}

/* TODO: fix the APIs too */
static struct {
    cli_apicall_pointer api;
    uint32_t override_size;
} apisize_override[] = {
    {(void*)cli_bcapi_disasm_x86, sizeof(struct DISASM_RESULT)},
    {(void*)cli_bcapi_get_pe_section, sizeof(struct cli_exe_section)},
};

int cli_vm_execute(const struct cli_bc *bc, struct cli_bc_ctx *ctx, const struct cli_bc_func *func, const struct cli_bc_inst *inst)
{
    size_t i;
    uint32_t j;
    unsigned stack_depth=0, bb_inst=0, stop=0, pc=0;
    struct cli_bc_func *func2;
    struct stack stack;
    struct stack_entry *stack_entry = NULL;
    struct cli_bc_bb *bb = NULL;
    char *values = ctx->values;
    char *old_values;
    struct ptr_infos ptrinfos;
    struct timeval tv0, tv1, timeout;
    int stackid = 0;

    memset(&ptrinfos, 0, sizeof(ptrinfos));
    memset(&stack, 0, sizeof(stack));
    for (i=0; i < (size_t)cli_apicall_maxglobal - _FIRST_GLOBAL; i++) {
        void *apiptr;
        uint32_t size;
        const struct cli_apiglobal *g = &cli_globals[i];
        void **apiglobal = (void**)(((char*)ctx) + g->offset);
        if (!apiglobal)
            continue;
        apiptr = *apiglobal;
        size = globaltypesize(g->type);
        ptr_register_glob_fixedid(&ptrinfos, apiptr, size, g->globalid - _FIRST_GLOBAL+1);
    }
    ptr_register_glob_fixedid(&ptrinfos, bc->globalBytes, bc->numGlobalBytes,
                              cli_apicall_maxglobal - _FIRST_GLOBAL + 2);

    gettimeofday(&tv0, NULL);
    timeout.tv_usec = tv0.tv_usec + ctx->bytecode_timeout*1000;
    timeout.tv_sec = tv0.tv_sec + timeout.tv_usec/1000000;
    timeout.tv_usec %= 1000000;

    do {
        pc++;
        if (!(pc % 5000)) {
            gettimeofday(&tv1, NULL);
            if (tv1.tv_sec > timeout.tv_sec ||
                (tv1.tv_sec == timeout.tv_sec &&
                 tv1.tv_usec > timeout.tv_usec)) {
                cli_warnmsg("Bytecode run timed out in interpreter after %u opcodes\n", pc);
                stop = CL_ETIMEOUT;
                break;
            }
        }
        switch (inst->interp_op) {
            DEFINE_BINOP(OP_BC_ADD, res = op0 + op1);
            DEFINE_BINOP(OP_BC_SUB, res = op0 - op1);
            DEFINE_BINOP(OP_BC_MUL, res = op0 * op1);

            DEFINE_BINOP(OP_BC_UDIV, CHECK_OP(op1 == 0, "bytecode attempted to execute udiv#0\n");
                         res=op0/op1);
            DEFINE_BINOP(OP_BC_SDIV, CHECK_OP(check_sdivops(sop0, sop1), "bytecode attempted to execute sdiv#0\n");
                         res=sop0/sop1);
            DEFINE_BINOP(OP_BC_UREM, CHECK_OP(op1 == 0, "bytecode attempted to execute urem#0\n");
                         res=op0 % op1);
            DEFINE_BINOP(OP_BC_SREM, CHECK_OP(check_sdivops(sop0,sop1), "bytecode attempted to execute urem#0\n");
                         res=sop0 % sop1);

            DEFINE_BINOP(OP_BC_SHL, CHECK_OP(op1 > inst->type, "bytecode attempted to execute shl greater than bitwidth\n");
                         res = op0 << op1);
            DEFINE_BINOP(OP_BC_LSHR, CHECK_OP(op1 > inst->type, "bytecode attempted to execute lshr greater than bitwidth\n");
                         res = op0 >> op1);
            DEFINE_BINOP(OP_BC_ASHR, CHECK_OP(op1 > inst->type, "bytecode attempted to execute ashr greater than bitwidth\n");
                         res = CLI_SRS(sop0, op1));

            DEFINE_BINOP(OP_BC_AND, res = op0 & op1);
            DEFINE_BINOP(OP_BC_OR, res = op0 | op1);
            DEFINE_BINOP(OP_BC_XOR, res = op0 ^ op1);

            DEFINE_SCASTOP(OP_BC_SEXT,
                          CHOOSE(READ1(sres, inst->u.cast.source); res = sres ? ~0 : 0,
                                 READ8(sres, inst->u.cast.source); res=sres=SIGNEXT(sres, inst->u.cast.mask),
                                 READ16(sres, inst->u.cast.source); res=sres=SIGNEXT(sres, inst->u.cast.mask),
                                 READ32(sres, inst->u.cast.source); res=sres=SIGNEXT(sres, inst->u.cast.mask),
                                 READ64(sres, inst->u.cast.source); res=sres=SIGNEXT(sres, inst->u.cast.mask)));
            DEFINE_CASTOP(OP_BC_ZEXT,
                          CHOOSE(READ1(res, inst->u.cast.source),
                                 READ8(res, inst->u.cast.source),
                                 READ16(res, inst->u.cast.source),
                                 READ32(res, inst->u.cast.source),
                                 READ64(res, inst->u.cast.source)));
            DEFINE_CASTOP(OP_BC_TRUNC,
                          CHOOSE(READ1(res, inst->u.cast.source),
                                 READ8(res, inst->u.cast.source),
                                 READ16(res, inst->u.cast.source),
                                 READ32(res, inst->u.cast.source),
                                 READ64(res, inst->u.cast.source)));

            DEFINE_OP(OP_BC_BRANCH)
                stop = jump(func, (values[inst->u.branch.condition]&1) ?
                          inst->u.branch.br_true : inst->u.branch.br_false,
                          &bb, &inst, &bb_inst);
                continue;

            DEFINE_OP(OP_BC_JMP)
                stop = jump(func, inst->u.jump, &bb, &inst, &bb_inst);
                continue;

            DEFINE_OP_BC_RET_N(OP_BC_RET*5, uint8_t, READ1, WRITE8);
            DEFINE_OP_BC_RET_N(OP_BC_RET*5+1, uint8_t, READ8, WRITE8);
            DEFINE_OP_BC_RET_N(OP_BC_RET*5+2, uint16_t, READ16, WRITE16);
            DEFINE_OP_BC_RET_N(OP_BC_RET*5+3, uint32_t, READ32, WRITE32);
            DEFINE_OP_BC_RET_N(OP_BC_RET*5+4, uint64_t, READ64, WRITE64);

            DEFINE_OP_BC_RET_N(OP_BC_RET_VOID*5, uint8_t, (void), (void));
            DEFINE_OP_BC_RET_N(OP_BC_RET_VOID*5+1, uint8_t, (void), (void));
            DEFINE_OP_BC_RET_N(OP_BC_RET_VOID*5+2, uint8_t, (void), (void));
            DEFINE_OP_BC_RET_N(OP_BC_RET_VOID*5+3, uint8_t, (void), (void));
            DEFINE_OP_BC_RET_N(OP_BC_RET_VOID*5+4, uint8_t, (void), (void));

            DEFINE_ICMPOP(OP_BC_ICMP_EQ, res = (op0 == op1));
            DEFINE_ICMPOP(OP_BC_ICMP_NE, res = (op0 != op1));
            DEFINE_ICMPOP(OP_BC_ICMP_UGT, res = (op0 > op1));
            DEFINE_ICMPOP(OP_BC_ICMP_UGE, res = (op0 >= op1));
            DEFINE_ICMPOP(OP_BC_ICMP_ULT, res = (op0 < op1));
            DEFINE_ICMPOP(OP_BC_ICMP_ULE, res = (op0 <= op1));
            DEFINE_ICMPOP(OP_BC_ICMP_SGT, res = (sop0 > sop1));
            DEFINE_ICMPOP(OP_BC_ICMP_SGE, res = (sop0 >= sop1));
            DEFINE_ICMPOP(OP_BC_ICMP_SLE, res = (sop0 <= sop1));
            DEFINE_ICMPOP(OP_BC_ICMP_SLT, res = (sop0 < sop1));

            case OP_BC_SELECT*5:
            {
                uint8_t t0, t1, t2;
                READ1(t0, inst->u.three[0]);
                READ1(t1, inst->u.three[1]);
                READ1(t2, inst->u.three[2]);
                WRITE8(inst->dest, t0 ? t1 : t2);
                break;
            }
            case OP_BC_SELECT*5+1:
            {
                uint8_t t0, t1, t2;
                READ1(t0, inst->u.three[0]);
                READ8(t1, inst->u.three[1]);
                READ8(t2, inst->u.three[2]);
                WRITE8(inst->dest, t0 ? t1 : t2);
                break;
            }
            case OP_BC_SELECT*5+2:
            {
                uint8_t t0;
                uint16_t t1, t2;
                READ1(t0, inst->u.three[0]);
                READ16(t1, inst->u.three[1]);
                READ16(t2, inst->u.three[2]);
                WRITE16(inst->dest, t0 ? t1 : t2);
                break;
            }
            case OP_BC_SELECT*5+3:
            {
                uint8_t t0;
                uint32_t t1, t2;
                READ1(t0, inst->u.three[0]);
                READ32(t1, inst->u.three[1]);
                READ32(t2, inst->u.three[2]);
                WRITE32(inst->dest, t0 ? t1 : t2);
                break;
            }
            case OP_BC_SELECT*5+4:
            {
                uint8_t t0;
                uint64_t t1, t2;
                READ1(t0, inst->u.three[0]);
                READ64(t1, inst->u.three[1]);
                READ64(t2, inst->u.three[2]);
                WRITE64(inst->dest, t0 ? t1 : t2);
                break;
            }

            DEFINE_OP(OP_BC_CALL_API) {
                const struct cli_apicall *api = &cli_apicalls[inst->u.ops.funcid];
                int32_t res32;
                int64_t res64;
                CHECK_APIID(inst->u.ops.funcid);
                TRACE_API(api->name, inst->dest, inst->type, stack_depth);
                switch (api->kind) {
                    case 0: {
                        int32_t a, b;
                        READ32(a, inst->u.ops.ops[0]);
                        READ32(b, inst->u.ops.ops[1]);
                        res32 = cli_apicalls0[api->idx](ctx, a, b);
                        WRITE32(inst->dest, res32);
                        break;
                    }
                    case 1: {
                        void* arg1;
                        unsigned arg2, arg1size;
                        READ32(arg2, inst->u.ops.ops[1]);
                        /* check that arg2 is size of arg1 */
                        arg1size = arg2;
                        for (i=0;i<sizeof(apisize_override)/sizeof(apisize_override[0]);i++) {
                            if (cli_apicalls1[api->idx] == apisize_override[i].api) {
                                arg1size = apisize_override[i].override_size;
                                break;
                            }
                        }
                        READPOP(arg1, inst->u.ops.ops[0], arg1size);
                        res32 = cli_apicalls1[api->idx](ctx, arg1, arg2);
                        WRITE32(inst->dest, res32);
                        break;
                    }
                    case 2: {
                        int32_t a;
                        READ32(a, inst->u.ops.ops[0]);
                        res32 = cli_apicalls2[api->idx](ctx, a);
                        WRITE32(inst->dest, res32);
                        break;
                    }
                    case 3: {
                        int32_t a;
                        void *resp;
                        READ32(a, inst->u.ops.ops[0]);
                        resp = cli_apicalls3[api->idx](ctx, a);
                        res64 = ptr_register_glob(&ptrinfos, resp, a);
                        WRITE64(inst->dest, res64);
                        break;
                    }
                    case 4: {
                        int32_t arg2, arg3, arg4, arg5;
                        void *arg1;
                        READ32(arg2, inst->u.ops.ops[1]);
                        /* check that arg2 is size of arg1 */
                        READP(arg1, inst->u.ops.ops[0], arg2);
                        READ32(arg3, inst->u.ops.ops[2]);
                        READ32(arg4, inst->u.ops.ops[3]);
                        READ32(arg5, inst->u.ops.ops[4]);
                        res32 = cli_apicalls4[api->idx](ctx, arg1, arg2, arg3, arg4, arg5);
                        WRITE32(inst->dest, res32);
                        break;
                    }
                    case 5: {
                        res32 = cli_apicalls5[api->idx](ctx);
                        WRITE32(inst->dest, res32);
                        break;
                    }
                    case 6: {
                        int32_t arg1, arg2;
                        void *resp;
                        READ32(arg1, inst->u.ops.ops[0]);
                        READ32(arg2, inst->u.ops.ops[1]);
                        resp = cli_apicalls6[api->idx](ctx, arg1, arg2);
                        res64 = ptr_register_glob(&ptrinfos, resp, arg2);
                        WRITE64(inst->dest, res64);
                        break;
                    }
                    case 7: {
                        int32_t arg1,arg2,arg3;
                        READ32(arg1, inst->u.ops.ops[0]);
                        READ32(arg2, inst->u.ops.ops[1]);
                        READ32(arg3, inst->u.ops.ops[2]);
                        res32 = cli_apicalls7[api->idx](ctx, arg1, arg2, arg3);
                        WRITE32(inst->dest, res32);
                        break;
                    }
                    case 8: {
                        int32_t arg2, arg4;
                        void *arg1, *arg3;
                        int32_t resp;
                        READ32(arg2, inst->u.ops.ops[1]);
                        /* check that arg2 is size of arg1 */
                        READP(arg1, inst->u.ops.ops[0], arg2);
                        READ32(arg4, inst->u.ops.ops[3]);
                        READP(arg3, inst->u.ops.ops[2], arg4);
                        resp = cli_apicalls8[api->idx](ctx, arg1, arg2, arg3, arg4);
                        WRITE32(inst->dest, resp);
                        break;
                    }
                    case 9: {
                        int32_t arg2, arg3;
                        void *arg1;
                        int32_t resp;
                        READ32(arg2, inst->u.ops.ops[1]);
                        /* check that arg2 is size of arg1 */
                        READP(arg1, inst->u.ops.ops[0], arg2);
                        READ32(arg3, inst->u.ops.ops[2]);
                        resp = cli_apicalls9[api->idx](ctx, arg1, arg2, arg3);
                        WRITE32(inst->dest, resp);
                        break;
                    };
                    default:
                        cli_warnmsg("bytecode: type %u apicalls not yet implemented!\n", api->kind);
                        stop = CL_EBYTECODE;
                }
                break;
            }

            DEFINE_OP(OP_BC_CALL_DIRECT)
                CHECK_FUNCID(inst->u.ops.funcid);
                func2 = &bc->funcs[inst->u.ops.funcid];
                CHECK_EQ(func2->numArgs, inst->u.ops.numOps);
                old_values = values;
                stack_entry = allocate_stack(&stack, stack_entry, func2, func, inst->dest,
                                             bb, bb_inst);
                if (!stack_entry) {
                    stop = CL_EMEM;
                    break;
                }
                values = stack_entry->values;
                /* TODO: unregister on ret */
                TRACE_EXEC(inst->u.ops.funcid, inst->dest, inst->type, stack_depth);
                if (stack_depth > 10000) {
                    cli_warnmsg("bytecode: stack depth exceeded\n");
                    stop = CL_EBYTECODE;
                    break;
                }
                j = 0;
                for (i=0;i<func2->numArgs;i++) {
                    switch (inst->u.ops.opsizes[i]) {
                        case 1: {
                            uint8_t v;
                            READOLD8(v, inst->u.ops.ops[i]);
                            CHECK_GT(func2->numBytes, j);
                            values[j++] = v;
                            break;
                        }
                        case 2: {
                            uint16_t v;
                            READOLD16(v, inst->u.ops.ops[i]);
                            j = (j+1)&~1;
                            CHECK_GT(func2->numBytes, j);
                            *(uint16_t*)&values[j] = v;
                            j += 2;
                            break;
                        }
                        case 4: {
                            uint32_t v;
                            READOLD32(v, inst->u.ops.ops[i]);
                            j = (j+3)&~3;
                            CHECK_GT(func2->numBytes, j);
                            *(uint32_t*)&values[j] = v;
                            j += 4;
                            break;
                        }
                        case 8: {
                            uint64_t v;
                            READOLD64(v, inst->u.ops.ops[i]);
                            j = (j+7)&~7;
                            CHECK_GT(func2->numBytes, j);
                            *(uint64_t*)&values[j] = v;
                            j += 8;
                            break;
                        }
                    }
                }
                func = func2;
                stackid = ptr_register_stack(&ptrinfos, values, 0, func->numBytes)>>32;
                CHECK_GT(func->numBB, 0);
                stop = jump(func, 0, &bb, &inst, &bb_inst);
                stack_depth++;
                continue;

            case OP_BC_COPY*5:
            {
                uint8_t op;
                READ1(op, BINOP(0));
                WRITE8(BINOP(1), op);
                break;
            }
            case OP_BC_COPY*5+1:
            {
                uint8_t op;
                READ8(op, BINOP(0));
                WRITE8(BINOP(1), op);
                break;
            }
            case OP_BC_COPY*5+2:
            {
                uint16_t op;
                READ16(op, BINOP(0));
                WRITE16(BINOP(1), op);
                break;
            }
            case OP_BC_COPY*5+3:
            {
                uint32_t op;
                READ32(op, BINOP(0));
                WRITE32(BINOP(1), op);
                break;
            }
            case OP_BC_COPY*5+4:
            {
                uint64_t op;
                READ64(op, BINOP(0));
                WRITE64(BINOP(1), op);
                break;
            }

            case OP_BC_LOAD*5:
            case OP_BC_LOAD*5+1:
            {
                uint8_t *ptr;
                READPOP(ptr, inst->u.unaryop, 1);
                WRITE8(inst->dest, (*ptr));
                break;
            }
            case OP_BC_LOAD*5+2:
            {
                const union unaligned_16 *ptr;
                READPOP(ptr, inst->u.unaryop, 2);
                WRITE16(inst->dest, (ptr->una_u16));
                break;
            }
            case OP_BC_LOAD*5+3:
            {
                const union unaligned_32 *ptr;
                READPOP(ptr, inst->u.unaryop, 4);
                WRITE32(inst->dest, (ptr->una_u32));
                break;
            }
            case OP_BC_LOAD*5+4:
            {
                const union unaligned_64 *ptr;
                READPOP(ptr, inst->u.unaryop, 8);
                WRITE64(inst->dest, (ptr->una_u64));
                break;
            }

            case OP_BC_STORE*5:
            {
                uint8_t *ptr;
                uint8_t v;
                READP(ptr, BINOP(1), 1);
                READ1(v, BINOP(0));
                *ptr = v;
                break;
            }
            case OP_BC_STORE*5+1:
            {
                uint8_t *ptr;
                uint8_t v;
                READP(ptr, BINOP(1), 1);
                READ8(v, BINOP(0));
                *ptr = v;
                break;
            }
            case OP_BC_STORE*5+2:
            {
                union unaligned_16 *ptr;
                uint16_t v;
                READP(ptr, BINOP(1), 2);
                READ16(v, BINOP(0));
                ptr->una_s16 = v;
                break;
            }
            case OP_BC_STORE*5+3:
            {
                union unaligned_32 *ptr;
                uint32_t v;
                READP(ptr, BINOP(1), 4);
                READ32(v, BINOP(0));
                ptr->una_u32 = v;
                break;
            }
            case OP_BC_STORE*5+4:
            {
                union unaligned_64 *ptr;
                uint64_t v;
                READP(ptr, BINOP(1), 8);
                READ64(v, BINOP(0));
                ptr->una_u64 = v;
                break;
            }
            DEFINE_OP(OP_BC_ISBIGENDIAN) {
                WRITE8(inst->dest, WORDS_BIGENDIAN);
                break;
            }
            DEFINE_OP(OP_BC_GEPZ) {
                int64_t ptr, iptr;
                int32_t off;
                READ32(off, inst->u.three[2]);

                // negative values checking, valid for intermediate GEP calculations
                if (off < 0) {
                    cli_dbgmsg("bytecode warning: found GEP with negative offset %d!\n", off);
                }

                if (!(inst->interp_op%5)) {
                    // how do negative offsets affect pointer initialization?
                    WRITE64(inst->dest, ptr_compose(stackid,
                                                    inst->u.three[1]+off));
                } else {
                    READ64(ptr, inst->u.three[1]);
                    off += (ptr & 0x00000000ffffffffULL);
                    iptr = (ptr & 0xffffffff00000000ULL) + (uint64_t)(off);
                    WRITE64(inst->dest, ptr+off);
                }
                break;
            }
            DEFINE_OP(OP_BC_MEMCMP) {
                int32_t arg3;
                void *arg1, *arg2;
                READ32(arg3, inst->u.three[2]);
                READPOP(arg1, inst->u.three[0], arg3);
                READPOP(arg2, inst->u.three[1], arg3);
                WRITE32(inst->dest, memcmp(arg1, arg2, arg3));
                break;
            }
            DEFINE_OP(OP_BC_MEMCPY) {
                int64_t arg3;
                void *arg1, *arg2;

                READ32(arg3, inst->u.three[2]);
                READPOP(arg1, inst->u.three[0], arg3);
                READPOP(arg2, inst->u.three[1], arg3);
                memcpy(arg1, arg2, (int32_t)arg3);
                break;
            }
            DEFINE_OP(OP_BC_MEMMOVE) {
                int64_t arg3;
                void *arg1, *arg2;

                READ64(arg3, inst->u.three[2]);
                READPOP(arg1, inst->u.three[0], arg3);
                READPOP(arg2, inst->u.three[1], arg3);
                memmove(arg1, arg2, (int32_t)arg3);
                break;
            }
            DEFINE_OP(OP_BC_MEMSET) {
                int64_t arg3;
                int32_t arg2;
                void *arg1;

                READ64(arg3, inst->u.three[2]);
                READPOP(arg1, inst->u.three[0], arg3);
                READ32(arg2, inst->u.three[1]);
                memset(arg1, arg2, (int32_t)arg3);
                break;
            }
            DEFINE_OP(OP_BC_BSWAP16) {
                int16_t arg1;
                READ16(arg1, inst->u.unaryop);
                WRITE16(inst->dest, cbswap16(arg1));
                break;
            }
            DEFINE_OP(OP_BC_BSWAP32) {
                int32_t arg1;
                READ32(arg1, inst->u.unaryop);
                WRITE32(inst->dest, cbswap32(arg1));
                break;
            }
            DEFINE_OP(OP_BC_BSWAP64) {
                int64_t arg1;
                READ64(arg1, inst->u.unaryop);
                WRITE64(inst->dest, cbswap64(arg1));
                break;
            }
            DEFINE_OP(OP_BC_PTRDIFF32) {
                int64_t ptr1, ptr2;
                if (BINOP(0)&0x40000000)
                    ptr1 = ptr_compose(stackid, BINOP(0)&0xbfffffff);
                else
                    READ64(ptr1, BINOP(0));
                if (BINOP(1)&0x40000000)
                    ptr2 = ptr_compose(stackid, BINOP(1)&0xbfffffff);
                else
                    READ64(ptr2, BINOP(1));
                WRITE32(inst->dest, ptr_diff32(ptr1, ptr2));
                break;
            }
            DEFINE_OP(OP_BC_PTRTOINT64) {
                int64_t ptr;
                if (inst->u.unaryop&0x40000000)
                    ptr = ptr_compose(stackid, inst->u.unaryop&0xbfffffff);
                else
                    READ64(ptr, BINOP(0));
                WRITE64(inst->dest, ptr);
                break;
            }
            DEFINE_OP(OP_BC_GEP1) {
                int64_t ptr, iptr;
                int32_t off;
                READ32(off, inst->u.three[2]);

                // negative values checking, valid for intermediate GEP calculations
                if (off < 0) {
                    cli_dbgmsg("bytecode warning: GEP with negative offset %d!\n", off);
                }

                if (!(inst->interp_op%5)) {
                    // how do negative offsets affect pointer initialization?
                    cli_dbgmsg("bytecode warning: untested case for GEP1\n");
                    off *= inst->u.three[0];
                    WRITE64(inst->dest, ptr_compose(stackid,
                                                    inst->u.three[1]+off));
                } else {
                    READ64(ptr, inst->u.three[1]);
                    off *= inst->u.three[0];
                    off += (ptr & 0x00000000ffffffff);
                    iptr = (ptr & 0xffffffff00000000) + (uint64_t)(off);
                    WRITE64(inst->dest, iptr);
                }
                break;
            }
            /* TODO: implement OP_BC_GEP1, OP_BC_GEP2, OP_BC_GEPN */
            default:
                cli_errmsg("Opcode %u of type %u is not implemented yet!\n",
                           inst->interp_op/5, inst->interp_op%5);
                stop = CL_EARG;
                continue;
        }
        bb_inst++;
        inst++;
        if (bb) {
            CHECK_GT(bb->numInsts, bb_inst);
        }
    } while (stop == CL_SUCCESS);
    if (cli_debug_flag) {
        gettimeofday(&tv1, NULL);
        tv1.tv_sec -= tv0.tv_sec;
        tv1.tv_usec -= tv0.tv_usec;
        cli_dbgmsg("interpreter bytecode run finished in %luus, after executing %u opcodes\n",
                   tv1.tv_sec*1000000 + tv1.tv_usec, pc);
    }
    if (stop == CL_EBYTECODE) {
        cli_event_error_str(ctx->bc_events, "interpreter finished with error\n");
        cli_dbgmsg("interpreter finished with error\n");
    }

    cli_stack_destroy(&stack);
    free(ptrinfos.stack_infos);
    free(ptrinfos.glob_infos);
    return stop == CL_BREAK ? CL_SUCCESS : stop;
}

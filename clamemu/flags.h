/*
 *
 *  ClamAV PE emulator
 *
 *  Copyright (C) 2010 - 2011, Sourcefire, Inc.
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
#ifndef FLAGS_H
#define FLAGS_H

enum eflags {
    bit_cf = 0,
    bit_pf = 2,
    bit_af = 4,
    bit_zf = 6,
    bit_sf = 7,
    bit_tf = 8,
    bit_if = 9,
    bit_df = 10,
    bit_of = 11,
    bit_iopl = 12,
    bit_nt = 14,
    bit_rf = 16,
    bit_vm = 17,
    bit_ac = 18,
    bit_vif = 19,
    bit_vip = 20,
    bit_id = 21
};

static const uint8_t pf_table[256] = {
    1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
    0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
    0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
    1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
    0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
    1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
    1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
    0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
    0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
    1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
    1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
    0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
    1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
    0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
    0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
    1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1
};
static const int inc_flags = (1 << bit_of) | (1 << bit_sf) | (1 << bit_zf)
    | (1 << bit_af) | (1 << bit_pf);
static const int arith_flags = (1 << bit_of) | (1 << bit_sf) | (1 << bit_zf)
    | (1 << bit_af) | (1 << bit_pf) | (1 << bit_cf);

struct access_desc {
    uint32_t rw_mask;/* mask after shifting */
    uint8_t  rw_shift;/* for AH/AL */
    uint8_t  carry_bit;
    uint8_t  sign_bit;/* carry_bit - 1 */
    uint8_t  sub;
};

/* TODO: make this portable to non-C99 compilers */
#define DEFINE_REGS(first, last, bits, shift) \
    [first ... last] = {(~0u >> (32 - bits)) << shift, shift, bits, bits - 1, first - REG_EAX}
#define REGIDX_INVALID (REG_EDI+1)
static const struct access_desc reg_masks [] = {
    DEFINE_REGS(REG_EAX, REG_EDI, 32, 0),
    DEFINE_REGS(REG_AX,  REG_DI,  16, 0),
    DEFINE_REGS(REG_AH,  REG_BH,   8, 8),
    DEFINE_REGS(REG_AL,  REG_BL,   8, 0),
};

#define MAXREG (sizeof(reg_masks) / sizeof(reg_masks[0]))
#define DISASM_CACHE_SIZE 256

typedef struct {
    uint32_t mask;
    uint8_t  shift;
    uint8_t  idx;
    uint8_t  carry_bit;
    uint8_t  sign_bit;
} desc_t;

struct dis_arg {
    desc_t scale_reg;
    desc_t add_reg;
    uint32_t scale;
    uint32_t displacement;
    enum DIS_SIZE access_size;
};

typedef struct dis_instr {
    enum X86OPS opcode;
    uint8_t operation_size;
    uint8_t address_size;
    uint8_t segment;
    uint8_t len;
    struct dis_arg arg[3];
    uint32_t va;
} instr_t;

struct cli_emu {
    emu_vmm_t *mem;
    uint32_t eip;
    uint32_t tick;
    uint32_t eflags;
    uint32_t eflags_def;
    uint32_t regs[MAXREG];
    struct dis_instr cached_disasm[DISASM_CACHE_SIZE];
    uint32_t reg_val[REG_EDI+2];
    uint32_t reg_def[REG_EDI+2];
    uint8_t prefix_repe;
    uint8_t prefix_repne;
    uint8_t in_seh;
};

static inline void calc_flags_inc(cli_emu_t *state, int32_t a, const desc_t *desc)
{
    uint8_t sign_bit = desc->sign_bit;
    uint8_t sf = (a >> sign_bit) & 1;
    uint8_t zf = (a & desc->mask) == 0;
    uint8_t of = zf;
    state->eflags = (state->eflags & ~inc_flags) |
	            (pf_table[(uint8_t)a] << bit_pf) |
		    //TODO: af
		    (zf << bit_zf) |
		    (sf << bit_sf) |
		    (of << bit_of)
		    ;
    state->eflags_def |= inc_flags;
}

static inline void calc_flags_dec(cli_emu_t *state, int32_t a, const desc_t *desc)
{
    uint8_t sign_bit = desc->sign_bit;
    uint8_t sf = (a >> sign_bit) & 1;
    uint8_t zf = (a & desc->mask) == 0;
    uint8_t of = ((a+1) & desc->mask) == 0;
    state->eflags = (state->eflags & ~inc_flags) |
	            (pf_table[(uint8_t)a] << bit_pf) |
		    //TODO: af
		    (zf << bit_zf) |
		    (sf << bit_sf) |
		    (of << bit_of)
		    ;
    state->eflags_def |= inc_flags;
}

static always_inline void calc_flags_addsub(cli_emu_t *state, uint32_t a, uint32_t b, const desc_t *desc, uint8_t is_sub)
{
    uint64_t result = is_sub ? (uint64_t)a - (uint64_t)b : (uint64_t)a + (uint64_t)b;

    uint8_t sign_bit = desc->sign_bit;
    uint8_t cf = ((result >> desc->carry_bit) & 1);
    uint8_t sf = ((result >> sign_bit) & 1);
    uint8_t zf = (result & desc->mask) == 0;

    uint8_t a_sign = (a >> sign_bit) & 1;
    uint8_t b_sign = ((b >> sign_bit) & 1) ^ is_sub;
    uint8_t of = (a_sign == b_sign) && (a_sign != sf);

    state->eflags = (state->eflags & ~arith_flags) |
	            (cf << bit_cf) |
	            (pf_table[(uint8_t)result] << bit_pf) |
		    //TODO: af
		    (zf << bit_zf) |
		    (sf << bit_sf) |
		    (of << bit_of);


    state->eflags_def |= arith_flags;
}

static always_inline void calc_flags_test(cli_emu_t *state, uint32_t result, const desc_t *desc)
{
    uint8_t sign_bit = desc->sign_bit;
    uint8_t sf = (result >> sign_bit) & 1;

    /* OF = 0, CF = 0, SF, ZF, PF modified */
    state->eflags = (state->eflags & ~arith_flags) |
	            (pf_table[(uint8_t)result] << bit_pf) |
		    (((result & desc->mask)  == 0) << bit_zf) |
		    (sf << bit_sf);

    /* AF is undef */
    state->eflags_def |= arith_flags & ~(1 << bit_af);
}
#endif

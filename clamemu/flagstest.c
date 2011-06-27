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
#include <stdint.h>
#include "disasm-common.h"
#include "vmm.h"
#include "emulator.h"
#include "others.h"
#include "flags.h"
#include <string.h>

static void print_flags(const char *msg, uint16_t flags)
{
    printf("\t%s %x [%s %s %s %s %s %s %s %s %s %s]\n",
	   msg,flags,
	   (flags & (1 << bit_of)) ? "OF": "  ",
	   (flags & (1 << bit_df)) ? "DF": "  ",
	   (flags & (1 << bit_if)) ? "IF": "  ",
	   (flags & (1 << bit_tf)) ? "TF": "  ",
	   (flags & (1 << bit_sf)) ? "SF": "  ",
	   (flags & (1 << bit_tf)) ? "TF": "  ",
	   (flags & (1 << bit_zf)) ? "ZF": "  ",
	   (flags & (1 << bit_af)) ? "AF": "  ",
	   (flags & (1 << bit_pf)) ? "PF": "  ",
	   (flags & (1 << bit_cf)) ? "CF": "  "
	   );
}

int main(void)
{
    int bad = 0;
    uint32_t a, b;
    desc_t desc;
    desc_t desc32;
    cli_emu_t state;
    memset(&state, 0, sizeof(state));

    desc.mask = reg_masks[REG_AL].rw_mask;
    desc.shift = reg_masks[REG_AL].rw_shift;
    desc.idx = 0;
    desc.carry_bit = reg_masks[REG_AL].carry_bit;
    desc.sign_bit = reg_masks[REG_AL].sign_bit;

    desc32.mask = reg_masks[REG_EAX].rw_mask;
    desc32.shift = reg_masks[REG_EAX].rw_shift;
    desc32.idx = 0;
    desc32.carry_bit = reg_masks[REG_EAX].carry_bit;
    desc32.sign_bit = reg_masks[REG_EAX].sign_bit;

    for (a=0;a<=255;a++) {
	for (b=0;b<=255;b++) {
	    uint16_t real_eflags;
	    uint8_t p0 = a, p1 = b;

	    state.eflags = 0;
	    calc_flags_addsub(&state, a, b, &desc, 0);
	    asm ("pushw $0\n"
		 "popfw\n"
		 "movb %1, %%al\n"
		 "movb %2, %%bl\n"
		 "addb %%al, %%bl\n"
		 "pushfw\n"
		 "popw %0\n"
		 : "=q" (real_eflags)
		 : "q" (p0), "q" (p1)
		 : "eax", "ebx");

	    real_eflags &= arith_flags;
	    state.eflags &= arith_flags;

	    real_eflags &= ~(1 << bit_af);
	    state.eflags &= ~(1 << bit_af);
	    if (real_eflags != state.eflags) {
		printf("mismatch: %x + %x:\n", a, b);
		print_flags("emu", state.eflags);
		print_flags("real", real_eflags);
		bad = 1;
	    }

	    state.eflags = 0;
	    calc_flags_addsub(&state, a, b, &desc, 1);
	    asm ("pushw $0\n"
		 "popfw\n"
		 "movb %1, %%al\n"
		 "movb %2, %%bl\n"
		 "subb %%bl, %%al\n"
		 "pushfw\n"
		 "popw %0\n"
		 : "=q" (real_eflags)
		 : "q" (p0), "q" (p1)
		 : "eax", "ebx");

	    real_eflags &= arith_flags;
	    state.eflags &= arith_flags;

	    real_eflags &= ~(1 << bit_af);
	    state.eflags &= ~(1 << bit_af);
	    if (real_eflags != state.eflags) {
		printf("mismatch: %x - %x:\n", a, b);
		print_flags("emu", state.eflags);
		print_flags("real", real_eflags);
		bad = 1;
	    }

	    uint32_t aa = (uint32_t)a << 24;
	    uint32_t bb = (uint32_t)b << 24;
	    state.eflags = 0;
	    calc_flags_addsub(&state, aa, bb, &desc32, 0);
	    asm ("pushw $0\n"
		 "popfw\n"
		 "movl %1, %%eax\n"
		 "movl %2, %%ebx\n"
		 "addl %%eax, %%ebx\n"
		 "pushfw\n"
		 "popw %0\n"
		 : "=q" (real_eflags)
		 : "q" (aa), "q" (bb)
		 : "eax", "ebx");

	    real_eflags &= arith_flags;
	    state.eflags &= arith_flags;

	    real_eflags &= ~(1 << bit_af);
	    state.eflags &= ~(1 << bit_af);
	    if (real_eflags != state.eflags) {
		printf("mismatch: %x + %x:\n", aa, bb);
		print_flags("emu", state.eflags);
		print_flags("real", real_eflags);
		bad = 1;
	    }

	    state.eflags = 0;
	    calc_flags_addsub(&state, aa, bb, &desc32, 1);
	    asm ("pushw $0\n"
		 "popfw\n"
		 "movl %1, %%eax\n"
		 "movl %2, %%ebx\n"
		 "subl %%ebx, %%eax\n"
		 "pushfw\n"
		 "popw %0\n"
		 : "=q" (real_eflags)
		 : "q" (aa), "q" (bb)
		 : "eax", "ebx");

	    real_eflags &= arith_flags;
	    state.eflags &= arith_flags;

	    real_eflags &= ~(1 << bit_af);
	    state.eflags &= ~(1 << bit_af);
	    if (real_eflags != state.eflags) {
		printf("mismatch: %x - %x:\n", aa, bb);
		print_flags("emu", state.eflags);
		print_flags("real", real_eflags);
		bad = 1;
	    }
	}
    }
    if (!bad)
	printf("test ok\n");
    return bad;
}

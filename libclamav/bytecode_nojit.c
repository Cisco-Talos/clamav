/*
 *  Load, and verify ClamAV bytecode.
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

#include <stdio.h>
#include <stdlib.h>

#include "bytecode.h"
#include "bytecode_priv.h"
#include "clamav.h"
#include "others.h"

int cli_bytecode_prepare_jit(struct cli_all_bc *bcs)
{
    unsigned i;
    for (i=0;i<bcs->count;i++) {
	if (bcs->all_bcs[i].state == bc_skip)
	    continue;
	if (bcs->all_bcs[i].state != bc_loaded &&
	    bcs->all_bcs[i].kind != BC_STARTUP) {
	    cli_warnmsg("Cannot prepare for JIT, because it has already been converted to interpreter\n");
	    return CL_EBYTECODE;
	}
    }
    cli_dbgmsg("Cannot prepare for JIT, LLVM is not compiled or not linked\n");
    return CL_EBYTECODE;
}

int cli_vm_execute_jit(const struct cli_all_bc *bcs, struct cli_bc_ctx *ctx, const struct cli_bc_func *func)
{
    UNUSEDPARAM(bcs);
    UNUSEDPARAM(ctx);
    UNUSEDPARAM(func);
    return CL_EBYTECODE;
}

int cli_bytecode_init_jit(struct cli_all_bc *allbc, unsigned dconfmask)
{
    UNUSEDPARAM(allbc);
    UNUSEDPARAM(dconfmask);
    return CL_SUCCESS;
}

int cli_bytecode_done_jit(struct cli_all_bc *allbc, int partial)
{
    UNUSEDPARAM(allbc);
    UNUSEDPARAM(partial);
    return CL_SUCCESS;
}

void cli_bytecode_debug(int argc, char **argv) {
  /* Empty */
    UNUSEDPARAM(argc);
    UNUSEDPARAM(argv);
}

int bytecode_init(void)
{
    return 0;
}

void cli_bytecode_debug_printsrc(const struct cli_bc_ctx *ctx) {
    /* Empty */
    UNUSEDPARAM(ctx);
}
void cli_bytecode_printversion(void) {
  printf("LLVM is not compiled or not linked\n");
}
int have_clamjit=0;
void cli_printcxxver()
{
    /* Empty */
}
void cli_detect_env_jit(struct cli_environment *env)
{
    /* Empty */
    UNUSEDPARAM(env);
}

/*
 *  Unit tests for bytecode functions. 
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
#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdio.h>

#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <check.h>
#include "../libclamav/clamav.h"
#include "../libclamav/others.h"
#include "../libclamav/bytecode.h"
#include "checks.h"

static void runtest(const char *file, uint64_t expected, int fail, int nojit)
{
    int rc;
    int fd = open_testfile(file);
    FILE *f;
    struct cli_bc bc;
    struct cli_bc_ctx *ctx;
    struct cli_all_bc bcs;
    uint64_t v;

    fail_unless(fd >= 0, "retmagic open failed");
    f = fdopen(fd, "r");
    fail_unless(!!f, "retmagic fdopen failed");

    cl_debug();

    if (!nojit) {
	rc = cli_bytecode_init(&bcs);
	fail_unless(rc == CL_SUCCESS, "cli_bytecode_init failed");
    } else {
	bcs.engine = NULL;
    }

    bcs.all_bcs = &bc;
    bcs.count = 1;

    rc = cli_bytecode_load(&bc, f, NULL, 1);
    fail_unless(rc == CL_SUCCESS, "cli_bytecode_load failed");
    fclose(f);

    rc = cli_bytecode_prepare(&bcs);
    fail_unless(rc == CL_SUCCESS, "cli_bytecode_prepare failed");

    if (have_clamjit && !nojit && nojit != -1) {
	fail_unless(bc.state == bc_jit, "preparing for JIT failed");
    }

    ctx = cli_bytecode_context_alloc();
    fail_unless(!!ctx, "cli_bytecode_context_alloc failed");

    cli_bytecode_context_setfuncid(ctx, &bc, 0);
    rc = cli_bytecode_run(&bcs, &bc, ctx);
    fail_unless_fmt(rc == fail, "cli_bytecode_run failed, expected: %u, have: %u\n",
		    fail, rc);

    if (rc == CL_SUCCESS) {
	v = cli_bytecode_context_getresult_int(ctx);
	fail_unless_fmt(v == expected, "Invalid return value from bytecode run, expected: %llx, have: %llx\n",
			expected, v);
    }
    cli_bytecode_context_destroy(ctx);
    cli_bytecode_destroy(&bc);
    cli_bytecode_done(&bcs);
}

START_TEST (test_retmagic)
{
    cl_init(CL_INIT_DEFAULT);
    runtest("input/retmagic.cbc", 0x1234f00d, CL_SUCCESS, 0);
    runtest("input/retmagic.cbc", 0x1234f00d, CL_SUCCESS, 1);
}
END_TEST

START_TEST (test_arith)
{
    cl_init(CL_INIT_DEFAULT);
    runtest("input/arith.cbc", 0xd5555555, CL_SUCCESS, 0);
    runtest("input/arith.cbc", 0xd5555555, CL_SUCCESS, 1);
}
END_TEST

START_TEST (test_apicalls)
{
    cl_init(CL_INIT_DEFAULT);
    runtest("input/apicalls.cbc", 0xf00d, CL_SUCCESS, 0);
    runtest("input/apicalls.cbc", 0xf00d, CL_SUCCESS, 1);
}
END_TEST

START_TEST (test_apicalls2)
{
    cl_init(CL_INIT_DEFAULT);
    if (have_clamjit)/*FIXME: should work with both */
    runtest("input/apicalls2.cbc", 0xf00d, CL_SUCCESS, 0);
/*    runtest("input/apicalls2.cbc", 0xf00d, CL_SUCCESS, 1); */
}
END_TEST

START_TEST (test_div0)
{
    cl_init(CL_INIT_DEFAULT);
    /* must not crash on div#0 but catch it */
    runtest("input/div0.cbc", 0, CL_EBYTECODE, 0);
    runtest("input/div0.cbc", 0, CL_EBYTECODE, 1);
}
END_TEST

START_TEST (test_lsig)
{
    cl_init(CL_INIT_DEFAULT);
    if (have_clamjit)/* FIXME: should work with both */
    runtest("input/lsig.cbc", 0, 0, 0);
  //runtest("input/lsig.cbc", 0, CL_EBYTECODE, 1);
}
END_TEST

Suite *test_bytecode_suite(void)
{
    Suite *s = suite_create("bytecode");
    TCase *tc_cli_arith = tcase_create("arithmetic");
    suite_add_tcase(s, tc_cli_arith);

    tcase_add_test(tc_cli_arith, test_retmagic);
    tcase_add_test(tc_cli_arith, test_arith);
    tcase_add_test(tc_cli_arith, test_apicalls);
    tcase_add_test(tc_cli_arith, test_apicalls2);
    tcase_add_test(tc_cli_arith, test_div0);
    tcase_add_test(tc_cli_arith, test_lsig);
    return s;
}

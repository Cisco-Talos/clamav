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

static void runtest(const char *file, uint64_t expected)
{
    int rc;
    int fd = open_testfile(file);
    FILE *f;
    struct cli_bc bc;
    struct cli_bc_ctx *ctx;
    uint64_t v;

    fail_unless(fd >= 0, "retmagic open failed");
    f = fdopen(fd, "r");
    fail_unless(!!f, "retmagic fdopen failed");

    cl_debug();

    rc = cli_bytecode_load(&bc, f, NULL);
    fail_unless(rc == CL_SUCCESS, "cli_bytecode_load failed");
    fclose(f);

    rc = cli_bytecode_prepare(&bc);
    fail_unless(rc == CL_SUCCESS, "cli_bytecode_prepare failed");

    ctx = cli_bytecode_context_alloc();
    fail_unless(!!ctx, "cli_bytecode_context_alloc failed");

    cli_bytecode_context_setfuncid(ctx, &bc, 0);
    rc = cli_bytecode_run(&bc, ctx);
    fail_unless(rc == CL_SUCCESS, "cli_bytecode_run failed");

    v = cli_bytecode_context_getresult_int(ctx);
    fail_unless_fmt(v == expected, "Invalid return value from bytecode run, expected: %llx, have: %llx\n",
		    expected, v);
    cli_bytecode_context_destroy(ctx);
    cli_bytecode_destroy(&bc);
}

START_TEST (test_retmagic)
{
    runtest("input/retmagic.cbc", 0x1234f00d);
}
END_TEST

START_TEST (test_arith)
{
    runtest("input/arith.cbc", 0xd5555555);
}
END_TEST

START_TEST (test_apicalls)
{
    runtest("input/apicalls.cbc", 0xf00d);
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
    return s;
}

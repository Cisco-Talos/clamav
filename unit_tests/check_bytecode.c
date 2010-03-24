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
#include <fcntl.h>
#include "../libclamav/clamav.h"
#include "../libclamav/others.h"
#include "../libclamav/bytecode.h"
#include "checks.h"
#include "../libclamav/dconf.h"
#include "../libclamav/bytecode_priv.h"
#include "../libclamav/pe.h"

static void runtest(const char *file, uint64_t expected, int fail, int nojit,
		    const char *infile, struct cli_pe_hook_data *pedata,
		    struct cli_exe_section *sections, const char *expectedvirname)
{
    fmap_t *map = NULL;
    int rc;
    int fd = open_testfile(file);
    FILE *f;
    struct cli_bc bc;
    cli_ctx cctx;
    struct cli_bc_ctx *ctx;
    struct cli_all_bc bcs;
    uint64_t v;

    memset(&cctx, 0, sizeof(cctx));

    fail_unless(fd >= 0, "retmagic open failed");
    f = fdopen(fd, "r");
    fail_unless(!!f, "retmagic fdopen failed");

    cl_debug();

    if (!nojit) {
	rc = cli_bytecode_init(&bcs, BYTECODE_ENGINE_MASK);
	fail_unless(rc == CL_SUCCESS, "cli_bytecode_init failed");
    } else {
	bcs.engine = NULL;
    }

    bcs.all_bcs = &bc;
    bcs.count = 1;

    rc = cli_bytecode_load(&bc, f, NULL, 1);
    fail_unless(rc == CL_SUCCESS, "cli_bytecode_load failed");
    fclose(f);

    rc = cli_bytecode_prepare(&bcs, BYTECODE_ENGINE_MASK);
    fail_unless(rc == CL_SUCCESS, "cli_bytecode_prepare failed");

    if (have_clamjit && !nojit && nojit != -1) {
	fail_unless(bc.state == bc_jit, "preparing for JIT failed");
    }

    ctx = cli_bytecode_context_alloc();
    /* small timeout, these bytecodes are fast! */
    ctx->bytecode_timeout = 10;
    fail_unless(!!ctx, "cli_bytecode_context_alloc failed");

    if (infile) {
	int fdin = open(infile, O_RDONLY);
	fail_unless(fdin >= 0, "failed to open infile");
	map = fmap(fdin, 0, 0);
	fail_unless(!!map, "unable to fmap infile");
	ctx->ctx = &cctx;
	if (pedata)
	    ctx->hooks.pedata = pedata;
	ctx->sections = sections;
	cli_bytecode_context_setfile(ctx, map);
    }

    cli_bytecode_context_setfuncid(ctx, &bc, 0);
    rc = cli_bytecode_run(&bcs, &bc, ctx);
    fail_unless_fmt(rc == fail, "cli_bytecode_run failed, expected: %u, have: %u\n",
		    fail, rc);

    if (rc == CL_SUCCESS) {
	v = cli_bytecode_context_getresult_int(ctx);
	fail_unless_fmt(v == expected, "Invalid return value from bytecode run, expected: %llx, have: %llx\n",
			expected, v);
    }
    if (infile && expectedvirname) {
	fail_unless(ctx->virname &&
		    !strcmp(ctx->virname, expectedvirname),
		    "Invalid virname, expected: %s\n", expectedvirname);
    }
    cli_bytecode_context_destroy(ctx);
    if (map)
	funmap(map);
    cli_bytecode_destroy(&bc);
    cli_bytecode_done(&bcs);
}

START_TEST (test_retmagic)
{
    cl_init(CL_INIT_DEFAULT);
    runtest("input/retmagic.cbc", 0x1234f00d, CL_SUCCESS, 0, NULL, NULL, NULL, NULL);
    runtest("input/retmagic.cbc", 0x1234f00d, CL_SUCCESS, 1, NULL, NULL, NULL, NULL);
}
END_TEST

START_TEST (test_arith)
{
    cl_init(CL_INIT_DEFAULT);
    runtest("input/arith.cbc", 0xd5555555, CL_SUCCESS, 0, NULL, NULL, NULL, NULL);
    runtest("input/arith.cbc", 0xd5555555, CL_SUCCESS, 1, NULL, NULL, NULL, NULL);
}
END_TEST

START_TEST (test_apicalls)
{
    cl_init(CL_INIT_DEFAULT);
    runtest("input/apicalls.cbc", 0xf00d, CL_SUCCESS, 0, NULL, NULL, NULL, NULL);
    runtest("input/apicalls.cbc", 0xf00d, CL_SUCCESS, 1, NULL, NULL, NULL, NULL);
}
END_TEST

START_TEST (test_apicalls2)
{
    cl_init(CL_INIT_DEFAULT);
    runtest("input/apicalls2.cbc", 0xf00d, CL_SUCCESS, 0, NULL, NULL, NULL, NULL);
    runtest("input/apicalls2.cbc", 0xf00d, CL_SUCCESS, 1, NULL, NULL, NULL, NULL);
}
END_TEST

START_TEST (test_div0)
{
    cl_init(CL_INIT_DEFAULT);
    /* must not crash on div#0 but catch it */
    runtest("input/div0.cbc", 0, CL_EBYTECODE, 0, NULL, NULL, NULL, NULL);
    runtest("input/div0.cbc", 0, CL_EBYTECODE, 1, NULL, NULL, NULL, NULL);
}
END_TEST

START_TEST (test_lsig)
{
    cl_init(CL_INIT_DEFAULT);
    runtest("input/lsig.cbc", 0, 0, 0, NULL, NULL, NULL, NULL);
    runtest("input/lsig.cbc", 0, 0, 1, NULL, NULL, NULL, NULL);
}
END_TEST

START_TEST (test_inf)
{
    cl_init(CL_INIT_DEFAULT);
    runtest("input/inf.cbc", 0, CL_ETIMEOUT, 0, NULL, NULL, NULL, NULL);
    runtest("input/inf.cbc", 0, CL_ETIMEOUT, 1, NULL, NULL, NULL, NULL);
}
END_TEST

START_TEST (test_matchwithread)
{
    struct cli_exe_section sect;
    struct cli_pe_hook_data pedata;
    cl_init(CL_INIT_DEFAULT);
    memset(&pedata, 0, sizeof(pedata));
    pedata.ep = 64;
    pedata.opt32.ImageBase = 0x400000;
    pedata.hdr_size = 0x400;
    pedata.nsections = 1;
    sect.rva = 4096;
    sect.vsz = 4096;
    sect.raw = 0;
    sect.rsz = 512;
    sect.urva = 4096;
    sect.uvsz = 4096;
    sect.uraw = 1;
    sect.ursz = 512;
    runtest("input/matchwithread.cbc", 0, 0, 0, "../test/clam.exe", &pedata,
	    &sect, "ClamAV-Test-File-detected-via-bytecode");
    runtest("input/matchwithread.cbc", 0, 0, 1, "../test/clam.exe", &pedata,
	    &sect, "ClamAV-Test-File-detected-via-bytecode");
}
END_TEST

START_TEST (test_pdf)
{
    cl_init(CL_INIT_DEFAULT);
    runtest("input/pdf.cbc", 0, 0, 0, NULL, NULL, NULL, NULL);
    runtest("input/pdf.cbc", 0, 0, 1, NULL, NULL, NULL, NULL);
}
END_TEST

START_TEST (test_bswap)
{
    cl_init(CL_INIT_DEFAULT);
    if (have_clamjit)
	runtest("input/bswap.cbc", 0xbeef, 0, 0, NULL, NULL, NULL, NULL);
//    runtest("input/bswap.cbc", 0xbeef, 0, 1, NULL, NULL, NULL, NULL);
}
END_TEST

START_TEST (test_inflate)
{
    cl_init(CL_INIT_DEFAULT);
    if (have_clamjit)
	runtest("input/inflate.cbc", 0xbeef, 0, 0, NULL, NULL, NULL, NULL);
//    runtest("input/inflate.cbc", 0xbeef, 0, 1, NULL, NULL, NULL, NULL);
}
END_TEST

Suite *test_bytecode_suite(void)
{
    Suite *s = suite_create("bytecode");
    TCase *tc_cli_arith = tcase_create("arithmetic");
    suite_add_tcase(s, tc_cli_arith);
#if 0
    tcase_add_test(tc_cli_arith, test_retmagic);
    tcase_add_test(tc_cli_arith, test_arith);
    tcase_add_test(tc_cli_arith, test_apicalls);
    tcase_add_test(tc_cli_arith, test_apicalls2);
    tcase_add_test(tc_cli_arith, test_div0);
    tcase_add_test(tc_cli_arith, test_lsig);
    tcase_add_test(tc_cli_arith, test_inf);
    tcase_add_test(tc_cli_arith, test_matchwithread);
    tcase_add_test(tc_cli_arith, test_pdf);
    tcase_add_test(tc_cli_arith, test_bswap);
#endif
    tcase_add_test(tc_cli_arith, test_inflate);
    return s;
}

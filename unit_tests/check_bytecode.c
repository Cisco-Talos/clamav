/*
 *  Unit tests for bytecode functions. 
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

#include <stdio.h>

#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <check.h>
#include <fcntl.h>
#include <errno.h>

#include "../libclamav/clamav.h"
#include "../libclamav/others.h"
#include "../libclamav/bytecode.h"
#include "checks.h"
#include "../libclamav/dconf.h"
#include "../libclamav/bytecode_priv.h"
#include "../libclamav/pe.h"
#ifdef CL_THREAD_SAFE
#include <pthread.h>
#endif

static void runtest(const char *file, uint64_t expected, int fail, int nojit,
		    const char *infile, struct cli_pe_hook_data *pedata,
		    struct cli_exe_section *sections, const char *expectedvirname,
		    int testmode)
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
    struct cl_engine *engine;
    int fdin = -1;
    char filestr[512];
    const char * virname = NULL;
    struct cl_scan_options options;

    memset(&cctx, 0, sizeof(cctx));
    memset(&options, 0, sizeof(struct cl_scan_options));
    cctx.options = &options;

    cctx.options->general |= CL_SCAN_GENERAL_ALLMATCHES;
    cctx.virname = &virname;
    cctx.engine = engine = cl_engine_new();
    fail_unless(!!cctx.engine, "cannot create engine");
    rc = cl_engine_compile(engine);
    fail_unless(!rc, "cannot compile engine");
    cctx.fmap = cli_calloc(sizeof(fmap_t*), engine->maxreclevel + 2);
    fail_unless(!!cctx.fmap, "cannot allocate fmap");

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

    rc = cli_bytecode_load(&bc, f, NULL, 1, 0);
    fail_unless(rc == CL_SUCCESS, "cli_bytecode_load failed");
    fclose(f);

    if (testmode && have_clamjit)
	engine->bytecode_mode = CL_BYTECODE_MODE_TEST;

    rc = cli_bytecode_prepare2(engine, &bcs, BYTECODE_ENGINE_MASK);
    fail_unless(rc == CL_SUCCESS, "cli_bytecode_prepare failed");

    if (have_clamjit && !nojit && nojit != -1 && !testmode) {
	fail_unless(bc.state == bc_jit, "preparing for JIT failed");
    }

    ctx = cli_bytecode_context_alloc();
    ctx->bytecode_timeout = fail == CL_ETIMEOUT ? 10 : 10000;
    fail_unless(!!ctx, "cli_bytecode_context_alloc failed");

    ctx->ctx = &cctx;
    if (infile) {
	snprintf(filestr, sizeof(filestr), OBJDIR"/%s", infile);
	fdin = open(filestr, O_RDONLY);
	if (fdin < 0 && errno == ENOENT)
	    fdin = open_testfile(infile);
	fail_unless(fdin >= 0, "failed to open infile");
	map = fmap(fdin, 0, 0);
	fail_unless(!!map, "unable to fmap infile");
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
    free(cctx.fmap);
    cl_engine_free(engine);
    if (fdin >= 0)
	close(fdin);
}

START_TEST (test_retmagic_jit)
{
    cl_init(CL_INIT_DEFAULT);
    runtest("input/retmagic.cbc", 0x1234f00d, CL_SUCCESS, 0, NULL, NULL, NULL, NULL, 0);
    runtest("input/retmagic.cbc", 0x1234f00d, CL_SUCCESS, 0, NULL, NULL, NULL, NULL, 1);
}
END_TEST

START_TEST (test_retmagic_int)
{
    cl_init(CL_INIT_DEFAULT);
    runtest("input/retmagic.cbc", 0x1234f00d, CL_SUCCESS, 1, NULL, NULL, NULL, NULL, 0);
}
END_TEST

START_TEST (test_arith_jit)
{
    cl_init(CL_INIT_DEFAULT);
    runtest("input/arith.cbc", 0xd5555555, CL_SUCCESS, 0, NULL, NULL, NULL, NULL, 0);
}
END_TEST

START_TEST (test_arith_int)
{
    cl_init(CL_INIT_DEFAULT);
    runtest("input/arith.cbc", 0xd5555555, CL_SUCCESS, 1, NULL, NULL, NULL, NULL, 0);
}
END_TEST

START_TEST (test_apicalls_jit)
{
    cl_init(CL_INIT_DEFAULT);
    runtest("input/apicalls.cbc", 0xf00d, CL_SUCCESS, 0, NULL, NULL, NULL, NULL, 0);
}
END_TEST

START_TEST (test_apicalls_int)
{
    runtest("input/apicalls.cbc", 0xf00d, CL_SUCCESS, 1, NULL, NULL, NULL, NULL, 0);
}
END_TEST

START_TEST (test_apicalls2_jit)
{
    cl_init(CL_INIT_DEFAULT);
    runtest("input/apicalls2.cbc", 0xf00d, CL_SUCCESS, 0, NULL, NULL, NULL, NULL, 0);
}
END_TEST

START_TEST (test_apicalls2_int)
{
    cl_init(CL_INIT_DEFAULT);
    runtest("input/apicalls2.cbc", 0xf00d, CL_SUCCESS, 1, NULL, NULL, NULL, NULL, 0);
}
END_TEST

START_TEST (test_div0_jit)
{
    cl_init(CL_INIT_DEFAULT);
    /* must not crash on div#0 but catch it */
    runtest("input/div0.cbc", 0, CL_EBYTECODE, 0, NULL, NULL, NULL, NULL, 0);
}
END_TEST

START_TEST (test_div0_int)
{
    cl_init(CL_INIT_DEFAULT);
    runtest("input/div0.cbc", 0, CL_EBYTECODE, 1, NULL, NULL, NULL, NULL, 0);
}
END_TEST

START_TEST (test_lsig_jit)
{
    cl_init(CL_INIT_DEFAULT);
    runtest("input/lsig.cbc", 0, 0, 0, NULL, NULL, NULL, NULL, 0);
}
END_TEST

START_TEST (test_lsig_int)
{
    runtest("input/lsig.cbc", 0, 0, 1, NULL, NULL, NULL, NULL, 0);
}
END_TEST

START_TEST (test_inf_jit)
{
    cl_init(CL_INIT_DEFAULT);
    runtest("input/inf.cbc", 0, CL_ETIMEOUT, 0, NULL, NULL, NULL, NULL, 0);
}
END_TEST

START_TEST (test_inf_int)
{
    cl_init(CL_INIT_DEFAULT);
    runtest("input/inf.cbc", 0, CL_ETIMEOUT, 1, NULL, NULL, NULL, NULL, 0);
}
END_TEST

START_TEST (test_matchwithread_jit)
{
    struct cli_exe_section sect;
    struct cli_pe_hook_data pedata;
    cl_init(CL_INIT_DEFAULT);
    memset(&pedata, 0, sizeof(pedata));
    pedata.ep = 64;
    cli_writeint32(&pedata.opt32.ImageBase, 0x400000);
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
	    &sect, "ClamAV-Test-File-detected-via-bytecode", 0);
}
END_TEST

START_TEST (test_matchwithread_int)
{
    struct cli_exe_section sect;
    struct cli_pe_hook_data pedata;
    cl_init(CL_INIT_DEFAULT);
    memset(&pedata, 0, sizeof(pedata));
    pedata.ep = 64;
    cli_writeint32(&pedata.opt32.ImageBase, 0x400000);
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
    runtest("input/matchwithread.cbc", 0, 0, 1, "../test/clam.exe", &pedata,
	    &sect, "ClamAV-Test-File-detected-via-bytecode", 0);
}
END_TEST


START_TEST (test_pdf_jit)
{
    cl_init(CL_INIT_DEFAULT);
    runtest("input/pdf.cbc", 0, 0, 0, NULL, NULL, NULL, NULL, 0);
}
END_TEST

START_TEST (test_pdf_int)
{
    cl_init(CL_INIT_DEFAULT);
    runtest("input/pdf.cbc", 0, 0, 1, NULL, NULL, NULL, NULL, 0);
}
END_TEST

START_TEST (test_bswap_jit)
{
    cl_init(CL_INIT_DEFAULT);
    runtest("input/bswap.cbc", 0xbeef, 0, 0, NULL, NULL, NULL, NULL, 0);
}
END_TEST

START_TEST (test_bswap_int)
{
    cl_init(CL_INIT_DEFAULT);
    runtest("input/bswap.cbc", 0xbeef, 0, 1, NULL, NULL, NULL, NULL, 0);
}
END_TEST

START_TEST (test_inflate_jit)
{
    cl_init(CL_INIT_DEFAULT);
    runtest("input/inflate.cbc", 0xbeef, 0, 1, NULL, NULL, NULL, NULL, 0);
}
END_TEST

START_TEST (test_inflate_int)
{
    cl_init(CL_INIT_DEFAULT);
    runtest("input/inflate.cbc", 0xbeef, 0, 0, NULL, NULL, NULL, NULL, 0);
}
END_TEST

START_TEST (test_api_extract_jit)
{
    cl_init(CL_INIT_DEFAULT);
    runtest("input/api_extract_7.cbc", 0xf00d, 0, 0, "input/apitestfile", NULL, NULL, NULL, 0);
}
END_TEST

START_TEST (test_api_files_jit)
{
    cl_init(CL_INIT_DEFAULT);
    runtest("input/api_files_7.cbc", 0xf00d, 0, 0, "input/apitestfile", NULL, NULL, NULL, 0);
}
END_TEST

START_TEST (test_apicalls2_7_jit)
{
    cl_init(CL_INIT_DEFAULT);
    runtest("input/apicalls2_7.cbc", 0xf00d, 0, 0, NULL, NULL, NULL, NULL, 0);
}
END_TEST

START_TEST (test_apicalls_7_jit)
{
    cl_init(CL_INIT_DEFAULT);
    runtest("input/apicalls_7.cbc", 0xf00d, 0, 0, NULL, NULL, NULL, NULL, 0);
}
END_TEST

START_TEST (test_arith_7_jit)
{
    cl_init(CL_INIT_DEFAULT);
    runtest("input/arith_7.cbc", 0xd55555dd, CL_SUCCESS, 0, NULL, NULL, NULL, NULL, 0);
}
END_TEST

START_TEST (test_debug_jit)
{
    cl_init(CL_INIT_DEFAULT);
    runtest("input/debug_7.cbc", 0xf00d, 0, 0, NULL, NULL, NULL, NULL, 0);
}
END_TEST

START_TEST (test_inf_7_jit)
{
    cl_init(CL_INIT_DEFAULT);
    runtest("input/inf_7.cbc", 0, CL_ETIMEOUT, 0, NULL, NULL, NULL, NULL, 0);
}
END_TEST

START_TEST (test_lsig_7_jit)
{
    cl_init(CL_INIT_DEFAULT);
    runtest("input/lsig_7.cbc", 0, 0, 0, NULL, NULL, NULL, NULL, 0);
}
END_TEST

START_TEST (test_retmagic_7_jit)
{
    cl_init(CL_INIT_DEFAULT);
    runtest("input/retmagic_7.cbc", 0x1234f00d, CL_SUCCESS, 0, NULL, NULL, NULL, NULL, 0);
}
END_TEST

START_TEST (test_testadt_jit)
{
    cl_init(CL_INIT_DEFAULT);
    runtest("input/testadt_7.cbc", 0xf00d, 0, 0, NULL, NULL, NULL, NULL, 0);
}
END_TEST

START_TEST (test_api_extract_int)
{
    cl_init(CL_INIT_DEFAULT);
    runtest("input/api_extract_7.cbc", 0xf00d, 0, 1, "input/apitestfile", NULL, NULL, NULL, 0);
}
END_TEST

START_TEST (test_api_files_int)
{
    cl_init(CL_INIT_DEFAULT);
    runtest("input/api_files_7.cbc", 0xf00d, 0, 1, "input/apitestfile", NULL, NULL, NULL, 0);
}
END_TEST

START_TEST (test_apicalls2_7_int)
{
    cl_init(CL_INIT_DEFAULT);
    runtest("input/apicalls2_7.cbc", 0xf00d, 0, 1, NULL, NULL, NULL, NULL, 0);
}
END_TEST

START_TEST (test_apicalls_7_int)
{
    cl_init(CL_INIT_DEFAULT);
    runtest("input/apicalls_7.cbc", 0xf00d, 0, 1, NULL, NULL, NULL, NULL, 0);
}
END_TEST

START_TEST (test_arith_7_int)
{
    cl_init(CL_INIT_DEFAULT);
    runtest("input/arith_7.cbc", 0xd55555dd, CL_SUCCESS, 1, NULL, NULL, NULL, NULL, 0);
}
END_TEST

START_TEST (test_debug_int)
{
    cl_init(CL_INIT_DEFAULT);
    runtest("input/debug_7.cbc", 0xf00d, 0, 1, NULL, NULL, NULL, NULL, 0);
}
END_TEST

START_TEST (test_inf_7_int)
{
    cl_init(CL_INIT_DEFAULT);
    runtest("input/inf_7.cbc", 0, CL_ETIMEOUT, 1, NULL, NULL, NULL, NULL, 0);
}
END_TEST

START_TEST (test_lsig_7_int)
{
    cl_init(CL_INIT_DEFAULT);
    runtest("input/lsig_7.cbc", 0, 0, 1, NULL, NULL, NULL, NULL, 0);
}
END_TEST

START_TEST (test_retmagic_7_int)
{
    cl_init(CL_INIT_DEFAULT);
    runtest("input/retmagic_7.cbc", 0x1234f00d, CL_SUCCESS, 1, NULL, NULL, NULL, NULL, 0);
}
END_TEST

START_TEST (test_testadt_int)
{
    cl_init(CL_INIT_DEFAULT);
    runtest("input/testadt_7.cbc", 0xf00d, 0, 1, NULL, NULL, NULL, NULL, 0);
}
END_TEST


static void runload(const char *dbname, struct cl_engine* engine, unsigned signoexp)
{
    const char * srcdir = getenv("srcdir");
    char *str;
    unsigned signo = 0;
    int rc;
    if(!srcdir) {
	/* when run from automake srcdir is set, but if run manually then not */
	srcdir = SRCDIR;
    }
    str = cli_malloc(strlen(dbname)+strlen(srcdir)+2);
    fail_unless(!!str, "cli_malloc");
    sprintf(str, "%s/%s", srcdir, dbname);

    rc = cl_load(str, engine, &signo, CL_DB_STDOPT);
    fail_unless_fmt(rc == CL_SUCCESS, "failed to load %s: %s\n",
		    dbname, cl_strerror(rc));
    fail_unless_fmt(signo == signoexp, "different number of signatures loaded, expected %u, got %u\n",
		    signoexp, signo);
    free(str);

    rc = cl_engine_compile(engine);
    fail_unless_fmt(rc == CL_SUCCESS, "failed to load %s: %s\n",
		    dbname, cl_strerror(rc));
}

START_TEST (test_load_bytecode_jit)
{
    struct cl_engine *engine;
    cl_init(CL_INIT_DEFAULT);
    engine = cl_engine_new();
    fail_unless(!!engine, "failed to create engine\n");

    runload("input/bytecode.cvd", engine, 5);

    cl_engine_free(engine);
}
END_TEST

START_TEST (test_load_bytecode_int)
{
    struct cl_engine *engine;
    cl_init(CL_INIT_DEFAULT);
    engine = cl_engine_new();
    engine->dconf->bytecode = BYTECODE_INTERPRETER;
    fail_unless(!!engine, "failed to create engine\n");

    runload("input/bytecode.cvd", engine, 5);

    cl_engine_free(engine);
}
END_TEST

#if defined(CL_THREAD_SAFE) && defined(C_LINUX) && ((__GLIBC__ << 16) + __GLIBC_MINOR__ >= (2 << 16) + 4)
#define DO_BARRIER
#endif

#ifdef DO_BARRIER
static pthread_barrier_t barrier;
static void* thread(void *arg)
{
    struct cl_engine *engine;
    engine = cl_engine_new();
    fail_unless(!!engine, "failed to create engine\n");
    /* run all cl_load at once, to maximize chance of a crash
     * in case of a race condition */
    pthread_barrier_wait(&barrier);
    runload("input/bytecode.cvd", engine, 5);
    cl_engine_free(engine);
    return NULL;
}

START_TEST (test_parallel_load)
{
#define N 5
    pthread_t threads[N];
    unsigned i;

    cl_init(CL_INIT_DEFAULT);
    pthread_barrier_init(&barrier, NULL, N);
    for (i=0;i<N;i++) {
	pthread_create(&threads[i], NULL, thread, NULL);
    }
    for (i=0;i<N;i++) {
	pthread_join(threads[i], NULL);
    }
    /* DB load used to crash due to 'static' variable in cache.c,
     * and also due to something wrong in LLVM 2.7.
     * Enabled the mutex around codegen in bytecode2llvm.cpp, and this test is
     * here to make sure it doesn't crash */
}
END_TEST
#endif

Suite *test_bytecode_suite(void)
{
    Suite *s = suite_create("bytecode");
    TCase *tc_cli_arith = tcase_create("arithmetic");
    suite_add_tcase(s, tc_cli_arith);
    tcase_set_timeout(tc_cli_arith, 20);
    tcase_add_test(tc_cli_arith, test_retmagic_jit);
    tcase_add_test(tc_cli_arith, test_arith_jit);
    tcase_add_test(tc_cli_arith, test_apicalls_jit);
    tcase_add_test(tc_cli_arith, test_apicalls2_jit);
    tcase_add_test(tc_cli_arith, test_div0_jit);
    tcase_add_test(tc_cli_arith, test_lsig_jit);
    tcase_add_test(tc_cli_arith, test_inf_jit);
    tcase_add_test(tc_cli_arith, test_matchwithread_jit);
    tcase_add_test(tc_cli_arith, test_pdf_jit);
    tcase_add_test(tc_cli_arith, test_bswap_jit);
    tcase_add_test(tc_cli_arith, test_inflate_jit);

    tcase_add_test(tc_cli_arith, test_arith_int);
    tcase_add_test(tc_cli_arith, test_apicalls_int);
    tcase_add_test(tc_cli_arith, test_apicalls2_int);
    tcase_add_test(tc_cli_arith, test_div0_int);
    tcase_add_test(tc_cli_arith, test_lsig_int);
    tcase_add_test(tc_cli_arith, test_inf_int);
    tcase_add_test(tc_cli_arith, test_matchwithread_int);
    tcase_add_test(tc_cli_arith, test_pdf_int);
    tcase_add_test(tc_cli_arith, test_bswap_int);
    tcase_add_test(tc_cli_arith, test_inflate_int);
    tcase_add_test(tc_cli_arith, test_retmagic_int);

    tcase_add_test(tc_cli_arith, test_api_extract_jit);
    tcase_add_test(tc_cli_arith, test_api_files_jit);
    tcase_add_test(tc_cli_arith, test_apicalls2_7_jit);
    tcase_add_test(tc_cli_arith, test_apicalls_7_jit);
    tcase_add_test(tc_cli_arith, test_apicalls_7_jit);
    tcase_add_test(tc_cli_arith, test_arith_7_jit);
    tcase_add_test(tc_cli_arith, test_debug_jit);
    tcase_add_test(tc_cli_arith, test_inf_7_jit);
    tcase_add_test(tc_cli_arith, test_lsig_7_jit);
    tcase_add_test(tc_cli_arith, test_retmagic_7_jit);
    tcase_add_test(tc_cli_arith, test_testadt_jit);

    tcase_add_test(tc_cli_arith, test_api_extract_int);
    tcase_add_test(tc_cli_arith, test_api_files_int);
    tcase_add_test(tc_cli_arith, test_apicalls2_7_int);
    tcase_add_test(tc_cli_arith, test_apicalls_7_int);
    tcase_add_test(tc_cli_arith, test_apicalls_7_int);
    tcase_add_test(tc_cli_arith, test_arith_7_int);
    tcase_add_test(tc_cli_arith, test_debug_int);
    tcase_add_test(tc_cli_arith, test_inf_7_int);
    tcase_add_test(tc_cli_arith, test_lsig_7_int);
    tcase_add_test(tc_cli_arith, test_retmagic_int);
    tcase_add_test(tc_cli_arith, test_testadt_int);

    tcase_add_test(tc_cli_arith, test_load_bytecode_jit);
    tcase_add_test(tc_cli_arith, test_load_bytecode_int);
#ifdef DO_BARRIER
    tcase_add_test(tc_cli_arith, test_parallel_load);
#endif

    return s;
}

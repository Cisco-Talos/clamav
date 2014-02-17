/*
 *  Copyright (C) 2008 Sourcefire, Inc.
 *
 *  Authors: Tomasz Kojm
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

#include <check.h>
#include <stdio.h>
#include <string.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include "libclamav/crypto.h"

#include "../libclamav/clamav.h"
#include "../libclamav/readdb.h"
#include "../libclamav/matcher.h"
#include "../libclamav/matcher-ac.h"
#include "../libclamav/matcher-bm.h"
#include "../libclamav/others.h"
#include "../libclamav/default.h"
#include "checks.h"

static const struct ac_testdata_s {
    const char *data;
    const char *hexsig;
    const char *virname;
} ac_testdata[] = {
    /* IMPORTANT: ac_testdata[i].hexsig should only match ac_testdata[i].data */
    { "daaaaaaaaddbbbbbcce", "64[4-4]61616161{2}6262[3-6]65", "Test_1" },
    { "ebbbbbbbbeecccccddf", "6262(6162|6364|6265|6465){2}6363", "Test_2" },
    { "aaaabbbbcccccdddddeeee", "616161*63636363*6565", "Test_3" },
    { "oprstuwxy","6f??727374????7879", "Test_4" },
    { "abdcabcddabccadbbdbacb", "6463{2-3}64646162(63|64|65)6361*6462????6261{-1}6362", "Test_5" },
    { "abcdefghijkabcdefghijk", "62????65666768*696a6b6162{2-3}656667[1-3]6b", "Test_6" },
    { "abcadbabcadbabcacb", "6?6164?26?62{3}?26162?361", "Test_7" },
    /* testcase for filter bug: it was checking only first 32 chars, and last
     * maxpatlen */
    { "\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1dddddddddddddddddddd5\1\1\1\1\1\1\1\1\1\1\1\1\1","6464646464646464646464646464646464646464(35|36)","Test_8"},

    { NULL, NULL, NULL}
};


static cli_ctx ctx;
static fmap_t *thefmap = NULL;
static const char *virname = NULL;
static void setup(void)
{
	struct cli_matcher *root;
	virname = NULL;
	thefmap = NULL;
	ctx.virname = &virname;
	ctx.fmap = &thefmap;
	ctx.engine = cl_engine_new();
	fail_unless(!!ctx.engine, "cl_engine_new() failed");
	root = (struct cli_matcher *) mpool_calloc(ctx.engine->mempool, 1, sizeof(struct cli_matcher));
	fail_unless(root != NULL, "root == NULL");
#ifdef USE_MPOOL
	root->mempool = ctx.engine->mempool;
#endif

	ctx.engine->root[0] = root;
}

static void teardown(void)
{
	cl_engine_free((struct cl_engine*)ctx.engine);
}

START_TEST (test_ac_scanbuff) {
	struct cli_ac_data mdata;
	struct cli_matcher *root;
	unsigned int i;
	int ret;

    root = ctx.engine->root[0];
    fail_unless(root != NULL, "root == NULL");
    root->ac_only = 1;

#ifdef USE_MPOOL
    root->mempool = mpool_create();
#endif
    ret = cli_ac_init(root, CLI_DEFAULT_AC_MINDEPTH, CLI_DEFAULT_AC_MAXDEPTH, 1);
    fail_unless(ret == CL_SUCCESS, "cli_ac_init() failed");


    for(i = 0; ac_testdata[i].data; i++) {
	ret = cli_parse_add(root, ac_testdata[i].virname, ac_testdata[i].hexsig, 0, 0, "*", 0, NULL, 0);
	fail_unless(ret == CL_SUCCESS, "cli_parse_add() failed");
    }

    ret = cli_ac_buildtrie(root);
    fail_unless(ret == CL_SUCCESS, "cli_ac_buildtrie() failed");

    ret = cli_ac_initdata(&mdata, root->ac_partsigs, 0, 0, CLI_DEFAULT_AC_TRACKLEN);
    fail_unless(ret == CL_SUCCESS, "cli_ac_initdata() failed");

    for(i = 0; ac_testdata[i].data; i++) {
	ret = cli_ac_scanbuff((const unsigned char*)ac_testdata[i].data, strlen(ac_testdata[i].data), &virname, NULL, NULL, root, &mdata, 0, 0, NULL, AC_SCAN_VIR, NULL);
	fail_unless_fmt(ret == CL_VIRUS, "cli_ac_scanbuff() failed for %s", ac_testdata[i].virname);
	fail_unless_fmt(!strncmp(virname, ac_testdata[i].virname, strlen(ac_testdata[i].virname)), "Dataset %u matched with %s", i, virname);

	ret = cli_scanbuff((const unsigned char*)ac_testdata[i].data, strlen(ac_testdata[i].data), 0, &ctx, 0, NULL);
	fail_unless_fmt(ret == CL_VIRUS, "cli_scanbuff() failed for %s", ac_testdata[i].virname);
	fail_unless_fmt(!strncmp(virname, ac_testdata[i].virname, strlen(ac_testdata[i].virname)), "Dataset %u matched with %s", i, virname);
    }

    cli_ac_freedata(&mdata);
}
END_TEST

START_TEST (test_bm_scanbuff) {
	struct cli_matcher *root;
	const char *virname = NULL;
	int ret;


    root = ctx.engine->root[0];
    fail_unless(root != NULL, "root == NULL");

#ifdef USE_MPOOL
    root->mempool = mpool_create();
#endif
    ret = cli_bm_init(root);
    fail_unless(ret == CL_SUCCESS, "cli_bm_init() failed");

    ret = cli_parse_add(root, "Sig1", "deadbabe", 0, 0, "*", 0, NULL, 0);
    fail_unless(ret == CL_SUCCESS, "cli_parse_add() failed");
    ret = cli_parse_add(root, "Sig2", "deadbeef", 0, 0, "*", 0, NULL, 0);
    fail_unless(ret == CL_SUCCESS, "cli_parse_add() failed");
    ret = cli_parse_add(root, "Sig3", "babedead", 0, 0, "*", 0, NULL, 0);
    fail_unless(ret == CL_SUCCESS, "cli_parse_add() failed");

    ret = cli_bm_scanbuff((const unsigned char*)"blah\xde\xad\xbe\xef", 12, &virname, NULL, root, 0, NULL, NULL, NULL);
    fail_unless(ret == CL_VIRUS, "cli_bm_scanbuff() failed");
    fail_unless(!strncmp(virname, "Sig2", 4), "Incorrect signature matched in cli_bm_scanbuff()\n");
}
END_TEST

START_TEST (test_ac_scanbuff_allscan) {
	struct cli_ac_data mdata;
	struct cli_matcher *root;
	unsigned int i;
	int ret;

    root = ctx.engine->root[0];
    fail_unless(root != NULL, "root == NULL");
    root->ac_only = 1;

#ifdef USE_MPOOL
    root->mempool = mpool_create();
#endif
    ret = cli_ac_init(root, CLI_DEFAULT_AC_MINDEPTH, CLI_DEFAULT_AC_MAXDEPTH, 1);
    fail_unless(ret == CL_SUCCESS, "cli_ac_init() failed");


    for(i = 0; ac_testdata[i].data; i++) {
	ret = cli_parse_add(root, ac_testdata[i].virname, ac_testdata[i].hexsig, 0, 0, "*", 0, NULL, 0);
	fail_unless(ret == CL_SUCCESS, "cli_parse_add() failed");
    }

    ret = cli_ac_buildtrie(root);
    fail_unless(ret == CL_SUCCESS, "cli_ac_buildtrie() failed");

    ret = cli_ac_initdata(&mdata, root->ac_partsigs, 0, 0, CLI_DEFAULT_AC_TRACKLEN);
    fail_unless(ret == CL_SUCCESS, "cli_ac_initdata() failed");

    ctx.options |= CL_SCAN_ALLMATCHES;
    for(i = 0; ac_testdata[i].data; i++) {
	ret = cli_ac_scanbuff((const unsigned char*)ac_testdata[i].data, strlen(ac_testdata[i].data), &virname, NULL, NULL, root, &mdata, 0, 0, NULL, AC_SCAN_VIR, NULL);
	fail_unless_fmt(ret == CL_VIRUS, "cli_ac_scanbuff() failed for %s", ac_testdata[i].virname);
	fail_unless_fmt(!strncmp(virname, ac_testdata[i].virname, strlen(ac_testdata[i].virname)), "Dataset %u matched with %s", i, virname);

	ret = cli_scanbuff((const unsigned char*)ac_testdata[i].data, strlen(ac_testdata[i].data), 0, &ctx, 0, NULL);
	fail_unless_fmt(ret == CL_VIRUS, "cli_scanbuff() failed for %s", ac_testdata[i].virname);
	fail_unless_fmt(!strncmp(virname, ac_testdata[i].virname, strlen(ac_testdata[i].virname)), "Dataset %u matched with %s", i, virname);
	if (ctx.num_viruses) {
	    free((void *)ctx.virname);
	    ctx.num_viruses = 0;
	    ctx.size_viruses = 0;
	}
     }

    cli_ac_freedata(&mdata);
}
END_TEST

START_TEST (test_bm_scanbuff_allscan) {
	struct cli_matcher *root;
	const char *virname = NULL;
	int ret;


    root = ctx.engine->root[0];
    fail_unless(root != NULL, "root == NULL");

#ifdef USE_MPOOL
    root->mempool = mpool_create();
#endif
    ret = cli_bm_init(root);
    fail_unless(ret == CL_SUCCESS, "cli_bm_init() failed");

    ret = cli_parse_add(root, "Sig1", "deadbabe", 0, 0, "*", 0, NULL, 0);
    fail_unless(ret == CL_SUCCESS, "cli_parse_add() failed");
    ret = cli_parse_add(root, "Sig2", "deadbeef", 0, 0, "*", 0, NULL, 0);
    fail_unless(ret == CL_SUCCESS, "cli_parse_add() failed");
    ret = cli_parse_add(root, "Sig3", "babedead", 0, 0, "*", 0, NULL, 0);
    fail_unless(ret == CL_SUCCESS, "cli_parse_add() failed");

    ret = cli_bm_scanbuff((const unsigned char*)"blah\xde\xad\xbe\xef", 12, &virname, NULL, root, 0, NULL, NULL, NULL);
    fail_unless(ret == CL_VIRUS, "cli_bm_scanbuff() failed");
    fail_unless(!strncmp(virname, "Sig2", 4), "Incorrect signature matched in cli_bm_scanbuff()\n");
}
END_TEST

Suite *test_matchers_suite(void)
{
    Suite *s = suite_create("matchers");
    TCase *tc_matchers;
    tc_matchers = tcase_create("matchers");
    suite_add_tcase(s, tc_matchers);
    tcase_add_checked_fixture (tc_matchers, setup, teardown);
    tcase_add_test(tc_matchers, test_ac_scanbuff);
    tcase_add_test(tc_matchers, test_bm_scanbuff);
    tcase_add_test(tc_matchers, test_ac_scanbuff_allscan);
    tcase_add_test(tc_matchers, test_bm_scanbuff_allscan);
    return s;
}

